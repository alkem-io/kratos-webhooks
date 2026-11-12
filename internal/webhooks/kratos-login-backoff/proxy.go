package kratosloginbackoff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"go.uber.org/zap"

	"github.com/alkem-io/kratos-webhooks/internal/middleware"
)

// kratosLoginBody is the identifier of a Kratos login POST.
type kratosLoginBody struct {
	Identifier string `json:"identifier"`
}

// NewLoginProxy creates an http.Handler that checks login backoff before proxying to Kratos.
func NewLoginProxy(kratosURL string, service *Service, logger *zap.Logger) http.Handler {
	target, err := url.Parse(kratosURL)
	if err != nil {
		logger.Fatal("invalid kratos internal URL", zap.Error(err), zap.String("url", kratosURL))
	}

	proxy := httputil.NewSingleHostReverseProxy(target) //nolint:gosec // target is from trusted config

	const maxLoginRequestBodyBytes int64 = 1 << 20 // 1 MiB

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		correlationID := middleware.GetCorrelationID(r.Context())

		// Only intercept POST requests (credential submissions)
		if r.Method != http.MethodPost {
			proxy.ServeHTTP(w, r) //nolint:gosec // proxy target is from trusted config
			return
		}

		// Read body so we can inspect it and still forward it (bounded to 1 MiB)
		bodyReader := http.MaxBytesReader(w, r.Body, maxLoginRequestBodyBytes)
		bodyBytes, err := io.ReadAll(bodyReader)
		_ = bodyReader.Close()
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
				return
			}
			logger.Warn("failed to read login request body, rejecting it",
				zap.Error(err),
				zap.String("correlation_id", correlationID),
			)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		identifier, method := extractLoginBody(bodyBytes, r.Header.Get("Content-Type"))
		clientIP := extractClientIP(r)

		result := service.CheckAndIncrement(r.Context(), BeforeLoginRequest{
			Identifier: identifier,
			ClientIP:   clientIP,
		}, correlationID)

		// Only a first step goes through uncounted: a second step (or a body
		// whose method could not be read) is refused rather than guessed at
		// without a bound. The block below logs it with reason "unavailable".
		if result.Uncounted && !isFirstStep(method) {
			result = CheckAndIncrementResult{
				Reason:            "unavailable",
				Message:           "Sign-in is temporarily unavailable. Try again shortly.",
				RetryAfterSeconds: result.RetryAfterSeconds,
			}
		}

		if !result.Allowed {
			logger.Warn("login proxy blocked request",
				zap.String("correlation_id", correlationID),
				zap.String("client_ip_prefix", ipPrefix(clientIP)),
				zap.String("reason", result.Reason),
				zap.Int64("retry_after_seconds", result.RetryAfterSeconds),
			)

			// Browser requests (native form POST): redirect to login page with lockout params
			if isBrowserRequest(r) {
				lockoutURL := fmt.Sprintf("/login?lockout=true&retry_after=%d", result.RetryAfterSeconds)
				http.Redirect(w, r, lockoutURL, http.StatusSeeOther)
				return
			}

			// API requests: return 429 JSON
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    429,
					"status":  "Too Many Requests",
					"reason":  result.Reason,
					"message": result.Message,
				},
			})
			return
		}

		// Set True-Client-Ip so Kratos after-login webhooks can access it via ctx.request_headers.
		// Kratos has a hardcoded header allowlist; True-Client-Ip is on it but X-Forwarded-For is not.
		// The inbound value is never trusted: Kratos always sees the address that was counted.
		if clientIP != "" {
			r.Header.Set("True-Client-Ip", clientIP)
		} else {
			r.Header.Del("True-Client-Ip")
		}

		// Restore body and proxy to Kratos
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
		proxy.ServeHTTP(w, r) //nolint:gosec // proxy target is from trusted config
	})
}

// extractLoginBody reads the identifier and the method from the one parse the
// media type names, as Kratos chooses its decoder: a form for
// application/x-www-form-urlencoded, JSON for application/json, nothing for
// any other type. The identifier keeps encoding/json's reading (any letter
// case, last member wins); the method is read strictly by soleMethod.
func extractLoginBody(body []byte, contentType string) (identifier, method string) {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	var members []member
	switch mediaType {
	case "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return "", ""
		}
		identifier = values.Get("identifier")
		for name, vs := range values {
			for _, v := range vs {
				members = append(members, member{name, v})
			}
		}
	case "application/json":
		var parsed kratosLoginBody
		if err := json.Unmarshal(body, &parsed); err != nil {
			return "", ""
		}
		identifier = parsed.Identifier
		members = jsonMembers(body)
	}
	return identifier, soleMethod(members)
}

type member struct{ name, value string }

// jsonMembers lists the top-level members of a JSON object body that
// json.Unmarshal has accepted, every occurrence of a name kept; a value that
// is not a string reads as "".
func jsonMembers(body []byte) []member {
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil
	}
	var members []member
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil
		}
		name, _ := tok.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil
		}
		var value string
		_ = json.Unmarshal(raw, &value)
		members = append(members, member{name, value})
	}
	return members
}

// soleMethod returns the value of the body's one member named "method". A
// body with no such member, with more than one in any letter case, or with
// one spelt in another case reads as no method: decoders disagree on which of
// those members counts, so the proxy does not guess.
func soleMethod(members []member) string {
	method, found := "", 0
	for _, m := range members {
		if !strings.EqualFold(m.name, "method") {
			continue
		}
		if m.name != "method" {
			return ""
		}
		method, found = m.value, found+1
	}
	if found != 1 {
		return ""
	}
	return method
}

// isFirstStep reports whether method is a first sign-in step, which the proxy
// forwards even when it could not count it.
func isFirstStep(method string) bool {
	switch method {
	case "password", "passkey", "oidc":
		return true
	}
	return false
}

// isBrowserRequest returns true if the request is from a browser (native form POST)
// rather than an API client. Browser requests accept text/html; API clients accept application/json.
func isBrowserRequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/html")
}

// extractClientIP gets the client IP from X-Forwarded-For as the edge delivers
// it, else from RemoteAddr. True-Client-Ip and X-Real-Ip are never read: a
// sender sets them freely, and the per-IP counter must not follow them.
// All candidate IPs are validated with net.ParseIP to ensure well-formed Redis keys.
func extractClientIP(r *http.Request) string {
	if ip := firstValidIP(r.Header.Get("X-Forwarded-For")); ip != "" {
		return ip
	}

	// Fall back to RemoteAddr — use net.SplitHostPort for IPv6 safety
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(strings.TrimSpace(r.RemoteAddr), "[]")
}

// firstValidIP splits a comma-separated header value and returns the first valid IP.
func firstValidIP(raw string) string {
	for _, part := range strings.Split(raw, ",") {
		ip := strings.Trim(strings.TrimSpace(part), "[]")
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}
