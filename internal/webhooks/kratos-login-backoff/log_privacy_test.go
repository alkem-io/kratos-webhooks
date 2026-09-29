package kratosloginbackoff_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/alkem-io/kratos-webhooks/internal/config"
	kratosloginbackoff "github.com/alkem-io/kratos-webhooks/internal/webhooks/kratos-login-backoff"
)

// No log line may contain a raw identifier (email) or a full client IP, on any
// path: every request shape (both, identifier only, IP only) through every
// outcome (allowed, blocked by identifier, blocked by IP, Redis error), the
// matching counter reset, and the login proxy's blocked-request line.
func TestLogsNeverContainEmailOrFullIP(t *testing.T) {
	const email, ip = "Someone@Example.org", "203.0.113.77"
	redisErr := errors.New("redis: connection refused")
	mocks := map[string]mockRedisHelper{
		"allowed": {incrementBothResult: [4]int64{1, 120, 1, 120},
			incrementIDResult: [2]int64{1, 120}, incrementIPResult: [2]int64{1, 120}},
		"blocked_identifier": {incrementBothResult: [4]int64{11, 90, 11, 90}, incrementIDResult: [2]int64{11, 90}},
		"blocked_ip":         {incrementBothResult: [4]int64{1, 120, 21, 90}, incrementIPResult: [2]int64{21, 90}},
		"redis_error": {incrementBothErr: redisErr, incrementIDErr: redisErr, incrementIPErr: redisErr,
			resetErr: redisErr},
	}
	inputs := map[string][2]string{"both": {email, ip}, "identifier_only": {email, ""}, "ip_only": {"", ip}}
	for m, mock := range mocks {
		for in, v := range inputs {
			t.Run(m+"/"+in, func(t *testing.T) {
				svc, logs := observedService(&mock)
				svc.CheckAndIncrement(context.Background(),
					kratosloginbackoff.BeforeLoginRequest{Identifier: v[0], ClientIP: v[1]}, "corr-1")
				svc.ResetCounters(context.Background(),
					kratosloginbackoff.AfterLoginRequest{IdentityID: "id-1", Email: v[0], ClientIP: v[1]}, "corr-1")
				assertNoPII(t, logs, email, ip)
				if v[0] != "" && logs.FilterFieldKey("identifier_hmac").Len() == 0 {
					t.Error("expected identifier_hmac on login log lines")
				}
			})
		}
	}
}

func TestLoginProxyBlockedLogHasNoPII(t *testing.T) {
	const email, ip = "Someone@Example.org", "203.0.113.77"
	svc, logs := observedService(&mockRedisHelper{incrementBothResult: [4]int64{11, 90, 11, 90}})
	proxy := kratosloginbackoff.NewLoginProxy("http://127.0.0.1:1", svc, zap.New(logs.core))
	req := httptest.NewRequest(http.MethodPost, "/self-service/login",
		strings.NewReader(`{"identifier":"`+email+`","method":"password"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 (blocked), got %d", rec.Code)
	}
	if logs.FilterMessage("login proxy blocked request").Len() == 0 {
		t.Fatal("expected the proxy's blocked-request log line")
	}
	assertNoPII(t, logs.ObservedLogs, email, ip)
}

// observed is the captured log output plus its core, so other components
// (the proxy) can log into the same stream.
type observed struct {
	*observer.ObservedLogs
	core zapcore.Core
}

func observedService(mock *mockRedisHelper) (*kratosloginbackoff.Service, observed) {
	core, logs := observer.New(zapcore.DebugLevel)
	cfg := &config.Config{
		LoginBackoffMaxIdentifierAttempts:    10,
		LoginBackoffMaxIPAttempts:            20,
		LoginBackoffIdentifierLockoutSeconds: 120,
		LoginBackoffIPLockoutSeconds:         120,
		LogIdentifierHashKey:                 "test-key",
	}
	return kratosloginbackoff.NewServiceWithRedis(mock, cfg, zap.New(core)), observed{logs, core}
}

// assertNoPII encodes every entry exactly as production does (JSON: message,
// every field of every type, error text) and checks the whole line.
func assertNoPII(t *testing.T, logs interface {
	All() []observer.LoggedEntry
	Len() int
}, email, ip string) {
	t.Helper()
	if logs.Len() == 0 {
		t.Fatal("expected log output")
	}
	enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	for _, entry := range logs.All() {
		buf, err := enc.EncodeEntry(entry.Entry, entry.Context)
		if err != nil {
			t.Fatalf("encode %q: %v", entry.Message, err)
		}
		line := buf.String()
		buf.Free()
		if strings.Contains(strings.ToLower(line), strings.ToLower(email)) || strings.Contains(line, "@") ||
			strings.Contains(line, ip) {
			t.Errorf("log line leaks PII: %s", line)
		}
	}
}
