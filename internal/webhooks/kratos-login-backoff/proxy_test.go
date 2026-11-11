package kratosloginbackoff_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

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

func newProxy(t *testing.T, mock *mockRedisHelper) (http.Handler, *upstream) {
	t.Helper()
	up := newUpstream(t)
	return kratosloginbackoff.NewLoginProxy(up.URL, newTestService(t, mock), zap.NewNop()), up
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
