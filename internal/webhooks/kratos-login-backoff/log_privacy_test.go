package kratosloginbackoff_test

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/alkem-io/kratos-webhooks/internal/config"
	kratosloginbackoff "github.com/alkem-io/kratos-webhooks/internal/webhooks/kratos-login-backoff"
)

// No log line may contain a raw identifier (email) or a full client IP,
// on any path: allowed, blocked by identifier, blocked by IP, counters reset.
func TestLogsNeverContainEmailOrFullIP(t *testing.T) {
	const email, ip = "Someone@Example.org", "203.0.113.77"
	mocks := map[string]*mockRedisHelper{
		"allowed":            {incrementBothResult: [4]int64{1, 120, 1, 120}},
		"blocked_identifier": {incrementBothResult: [4]int64{11, 90, 11, 90}},
		"blocked_ip":         {incrementBothResult: [4]int64{1, 120, 21, 90}},
	}
	for name, mock := range mocks {
		t.Run(name, func(t *testing.T) {
			svc, logs := observedService(mock)
			svc.CheckAndIncrement(context.Background(),
				kratosloginbackoff.BeforeLoginRequest{Identifier: email, ClientIP: ip}, "corr-1")
			svc.ResetCounters(context.Background(),
				kratosloginbackoff.AfterLoginRequest{IdentityID: "id-1", Email: email, ClientIP: ip}, "corr-1")
			assertNoPII(t, logs, email, ip)
		})
	}
}

func observedService(mock *mockRedisHelper) (*kratosloginbackoff.Service, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.DebugLevel)
	cfg := &config.Config{
		LoginBackoffMaxIdentifierAttempts:    10,
		LoginBackoffMaxIPAttempts:            20,
		LoginBackoffIdentifierLockoutSeconds: 120,
		LoginBackoffIPLockoutSeconds:         120,
		LogIdentifierHashKey:                 "test-key",
	}
	return kratosloginbackoff.NewServiceWithRedis(mock, cfg, zap.New(core)), logs
}

func assertNoPII(t *testing.T, logs *observer.ObservedLogs, email, ip string) {
	t.Helper()
	if logs.Len() == 0 {
		t.Fatal("expected log output")
	}
	for _, entry := range logs.All() {
		for k, v := range entry.ContextMap() {
			s, ok := v.(string)
			if !ok {
				continue
			}
			low := strings.ToLower(s)
			if strings.Contains(low, strings.ToLower(email)) || strings.Contains(s, "@") || strings.Contains(s, ip) {
				t.Errorf("%q: field %s leaks PII: %q", entry.Message, k, s)
			}
		}
	}
}

// Without a hash key the identifier_hash field is omitted, not logged empty.
func TestIdentifierHashOmittedWithoutKey(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	cfg := &config.Config{
		LoginBackoffMaxIdentifierAttempts:    10,
		LoginBackoffMaxIPAttempts:            20,
		LoginBackoffIdentifierLockoutSeconds: 120,
		LoginBackoffIPLockoutSeconds:         120,
	}
	svc := kratosloginbackoff.NewServiceWithRedis(
		&mockRedisHelper{incrementBothResult: [4]int64{1, 120, 1, 120}}, cfg, zap.New(core))
	svc.CheckAndIncrement(context.Background(),
		kratosloginbackoff.BeforeLoginRequest{Identifier: "someone@example.org", ClientIP: "203.0.113.77"}, "corr-1")
	svc.ResetCounters(context.Background(),
		kratosloginbackoff.AfterLoginRequest{IdentityID: "id-1", Email: "someone@example.org", ClientIP: "203.0.113.77"}, "corr-1")
	if logs.Len() == 0 {
		t.Fatal("expected log output")
	}
	for _, e := range logs.All() {
		if _, ok := e.ContextMap()["identifier_hash"]; ok {
			t.Errorf("%q: identifier_hash present without a key", e.Message)
		}
	}
}
