package kratosloginbackoff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"go.uber.org/zap"

	"github.com/alkem-io/kratos-webhooks/internal/middleware"
)

// kratosLoginBody represents the fields we need from a Kratos login POST.
type kratosLoginBody struct {
	Identifier string `json:"identifier"`
	Method     string `json:"method"`
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
		// without a bound.
		if result.Uncounted && !isFirstStep(method) {
			logger.Warn("login proxy refused a submission it could not count",
				zap.String("correlation_id", correlationID),
				zap.String("client_ip_prefix", ipPrefix(clientIP)),
			)
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

// extractLoginBody parses the identifier and the method from the request body:
// form-encoded when the content type says so, then JSON whatever it says. The
// method is the one from the parse that yielded the identifier, or else from
// the first parse that yields a method.
func extractLoginBody(body []byte, contentType string) (identifier, method string) {
	var parses []kratosLoginBody
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if values, err := url.ParseQuery(string(body)); err == nil {
			parses = append(parses, kratosLoginBody{Identifier: values.Get("identifier"), Method: values.Get("method")})
		}
	}
	var parsed kratosLoginBody
	if err := json.Unmarshal(body, &parsed); err == nil {
		parses = append(parses, parsed)
	}

	for _, p := range parses {
		if p.Identifier != "" {
			return p.Identifier, p.Method
		}
	}
	for _, p := range parses {
		if p.Method != "" {
			return "", p.Method
		}
	}
	return "", ""
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
