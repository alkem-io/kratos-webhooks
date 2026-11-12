package kratosloginbackoff_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/alkem-io/kratos-webhooks/internal/config"
	kratosloginbackoff "github.com/alkem-io/kratos-webhooks/internal/webhooks/kratos-login-backoff"
)

const passwordBody = `{"method":"password","identifier":"someone@example.org","password":"x"}`

// upstream stands in for Kratos and records what reaches it.
type upstream struct {
	*httptest.Server
	requests      int
	trueClientIPs []string
	bodies        []string
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.requests++
		u.trueClientIPs = append(u.trueClientIPs, r.Header.Get("True-Client-Ip"))
		u.bodies = append(u.bodies, string(body))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(u.Close)
	return u
}

// The two windows differ so a quoted wait shows which one it is.
const ipLockoutSeconds = 300

func newProxy(t *testing.T, mock *mockRedisHelper) (http.Handler, *upstream) {
	t.Helper()
	up := newUpstream(t)
	svc := kratosloginbackoff.NewServiceWithRedis(mock, &config.Config{
		LoginBackoffMaxIdentifierAttempts:    10,
		LoginBackoffMaxIPAttempts:            20,
		LoginBackoffIdentifierLockoutSeconds: 120,
		LoginBackoffIPLockoutSeconds:         ipLockoutSeconds,
	}, zap.NewNop())
	return kratosloginbackoff.NewLoginProxy(up.URL, svc, zap.NewNop()), up
}

func serve(proxy http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	return rec
}

func loginPost(body, contentType string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/self-service/login?flow=f", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func allowedMock() *mockRedisHelper {
	return &mockRedisHelper{
		incrementBothResult: [4]int64{1, 120, 1, 120},
		incrementIDResult:   [2]int64{1, 120},
		incrementIPResult:   [2]int64{1, 120},
	}
}

// The per-IP key never follows a header the sender sets: two submissions that
// differ only in True-Client-Ip or X-Real-Ip land on one counter.
func TestLoginProxy_SpoofedClientIPHeadersShareOneCounter(t *testing.T) {
	for _, header := range []string{"True-Client-Ip", "X-Real-Ip"} {
		t.Run(header, func(t *testing.T) {
			mock := allowedMock()
			proxy, _ := newProxy(t, mock)
			for _, spoofed := range []string{"198.51.100.1", "198.51.100.2"} {
				serve(proxy, loginPost(passwordBody, "application/json", map[string]string{
					header:            spoofed,
					"X-Forwarded-For": "203.0.113.7",
				}))
			}
			if len(mock.countedIPs) != 2 || mock.countedIPs[0] != "203.0.113.7" || mock.countedIPs[1] != "203.0.113.7" {
				t.Errorf("want both submissions counted on 203.0.113.7, got %q", mock.countedIPs)
			}
		})
	}
}

func TestLoginProxy_NoForwardedForCountsRemoteAddr(t *testing.T) {
	mock := allowedMock()
	proxy, _ := newProxy(t, mock)
	for _, header := range []string{"True-Client-Ip", "X-Real-Ip"} {
		req := loginPost(passwordBody, "application/json", map[string]string{header: "198.51.100.1"})
		req.RemoteAddr = "192.0.2.10:4321"
		serve(proxy, req)
	}
	if len(mock.countedIPs) != 2 || mock.countedIPs[0] != "192.0.2.10" || mock.countedIPs[1] != "192.0.2.10" {
		t.Errorf("want the remote address counted, got %q", mock.countedIPs)
	}
}

// Kratos' after-login hook reads True-Client-Ip, so the proxy sends the address
// it counted, never the inbound value, and none when it has no address.
func TestLoginProxy_OverwritesTrueClientIPTowardKratos(t *testing.T) {
	t.Run("counted address", func(t *testing.T) {
		proxy, up := newProxy(t, allowedMock())
		serve(proxy, loginPost(passwordBody, "application/json", map[string]string{
			"True-Client-Ip":  "198.51.100.1",
			"X-Forwarded-For": "203.0.113.7",
		}))
		if up.requests != 1 || up.trueClientIPs[0] != "203.0.113.7" {
			t.Errorf("want True-Client-Ip 203.0.113.7 upstream, got %q", up.trueClientIPs)
		}
	})
	t.Run("no address", func(t *testing.T) {
		proxy, up := newProxy(t, allowedMock())
		req := loginPost(passwordBody, "application/json", map[string]string{"True-Client-Ip": "198.51.100.1"})
		req.RemoteAddr = ""
		serve(proxy, req)
		if up.requests != 1 || up.trueClientIPs[0] != "" {
			t.Errorf("want no True-Client-Ip upstream, got %q", up.trueClientIPs)
		}
	})
}

func TestLoginProxy_GetIsForwardedUncounted(t *testing.T) {
	mock := allowedMock()
	proxy, up := newProxy(t, mock)
	serve(proxy, httptest.NewRequest(http.MethodGet, "/self-service/login/browser", nil))
	if up.requests != 1 {
		t.Errorf("want the GET forwarded, upstream saw %d", up.requests)
	}
	if len(mock.countedIPs) != 0 {
		t.Errorf("want no count for a GET, got %q", mock.countedIPs)
	}
}

func failingMock() *mockRedisHelper {
	err := errors.New("redis: connection refused")
	return &mockRedisHelper{incrementBothErr: err, incrementIDErr: err, incrementIPErr: err}
}

// While the counter store fails, a submission the proxy did not count is
// forwarded only when it is a first step; anything else, a second step
// included, is answered as a locked address is.
func TestLoginProxy_UncountedSecondStepIsRefused(t *testing.T) {
	refused := map[string][2]string{
		"totp":          {`{"method":"totp","totp_code":"000000"}`, "application/json"},
		"lookup_secret": {`{"method":"lookup_secret","lookup_secret":"abcd"}`, "application/json"},
		"webauthn":      {`{"method":"webauthn","webauthn_login":"{}"}`, "application/json"},
		"form totp":     {"method=totp&totp_code=000000", "application/x-www-form-urlencoded"},
		"no method":     {`{"totp_code":"000000"}`, "application/json"},
		"unparseable":   {"\x00not a body", "text/plain"},
		// Kratos decodes by media type; the proxy must read the same one parse.
		"form carrying json": {
			`{"method":"password","identifier":"a@b.c","password":"x","p":"&method=totp&totp_code=000000&q="}`,
			"application/x-www-form-urlencoded",
		},
		"json carrying form": {
			`{"method":"totp","totp_code":"000000","p":"&method=password&q="}`,
			"application/json; x=application/x-www-form-urlencoded",
		},
		// Decoders disagree on which of several "method" members counts.
		"method in another case": {`{"method":"totp","totp_code":"000000","METHOD":"password"}`, "application/json"},
		"method twice":           {`{"method":"totp","totp_code":"000000","method":"password"}`, "application/json"},
		"form method twice":      {"method=totp&totp_code=000000&method=password", "application/x-www-form-urlencoded"},
		// Not read: no Alkemio client posts multipart.
		"multipart": {
			"--b\r\nContent-Disposition: form-data; name=\"method\"\r\n\r\npassword\r\n--b--\r\n",
			"multipart/form-data; boundary=b",
		},
	}
	for name, c := range refused {
		t.Run(name+"/api", func(t *testing.T) {
			proxy, up := newProxy(t, failingMock())
			rec := serve(proxy, loginPost(c[0], c[1], nil))
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("want 429, got %d", rec.Code)
			}
			var resp struct {
				Error struct {
					Reason string `json:"reason"`
				} `json:"error"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Error.Reason != "unavailable" {
				t.Errorf("want reason unavailable, got %q", resp.Error.Reason)
			}
			if up.requests != 0 {
				t.Errorf("want nothing forwarded, upstream saw %d", up.requests)
			}
		})
		t.Run(name+"/browser", func(t *testing.T) {
			proxy, up := newProxy(t, failingMock())
			rec := serve(proxy, loginPost(c[0], c[1], map[string]string{"Accept": "text/html"}))
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("want 303, got %d", rec.Code)
			}
			want := fmt.Sprintf("/login?lockout=true&retry_after=%d", ipLockoutSeconds)
			if loc := rec.Header().Get("Location"); loc != want {
				t.Errorf("want redirect quoting the IP window, got %q", loc)
			}
			if up.requests != 0 {
				t.Errorf("want nothing forwarded, upstream saw %d", up.requests)
			}
		})
	}
}

func TestLoginProxy_UncountedFirstStepIsForwarded(t *testing.T) {
	for _, c := range [][2]string{
		{passwordBody, "application/json"},
		{passwordBody, "application/json; charset=utf-8"},
		{"method=password&identifier=a%40b.c&password=x", "application/x-www-form-urlencoded"},
		{`{"method":"passkey","passkey_login":"{}"}`, "application/json"},
		{`{"method":"oidc","provider":"x"}`, "application/json"},
	} {
		proxy, up := newProxy(t, failingMock())
		serve(proxy, loginPost(c[0], c[1], nil))
		if up.requests != 1 || up.bodies[0] != c[0] {
			t.Errorf("want %s (%s) forwarded intact, upstream saw %q", c[0], c[1], up.bodies)
		}
	}
}

// The identifier is counted from the parse the media type names.
func TestLoginProxy_CountsTheIdentifier(t *testing.T) {
	for _, c := range [][2]string{
		{passwordBody, "application/json"},
		{`{"method":"password","Identifier":"someone@example.org","password":"x"}`, "application/json"},
		{"method=password&identifier=someone%40example.org&password=x", "application/x-www-form-urlencoded"},
	} {
		mock := allowedMock()
		proxy, _ := newProxy(t, mock)
		serve(proxy, loginPost(c[0], c[1], nil))
		if len(mock.countedIdentifiers) != 1 || mock.countedIdentifiers[0] != "someone@example.org" {
			t.Errorf("%s (%s): want someone@example.org counted, got %q", c[0], c[1], mock.countedIdentifiers)
		}
	}
}

// The refusal is tied to "not counted", not to the method.
func TestLoginProxy_CountedSecondStepIsForwarded(t *testing.T) {
	proxy, up := newProxy(t, allowedMock())
	serve(proxy, loginPost(`{"method":"totp","totp_code":"000000"}`, "application/json", nil))
	if up.requests != 1 {
		t.Errorf("want the counted second step forwarded, upstream saw %d", up.requests)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestLoginProxy_UnreadableBodyIsRejected(t *testing.T) {
	proxy, up := newProxy(t, allowedMock())
	rec := serve(proxy, httptest.NewRequest(http.MethodPost, "/self-service/login?flow=f", failingReader{}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
	if up.requests != 0 {
		t.Errorf("want nothing forwarded, upstream saw %d", up.requests)
	}
}
