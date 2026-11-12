package kratosloginbackoff_test

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/alkem-io/kratos-webhooks/internal/config"
	kratosloginbackoff "github.com/alkem-io/kratos-webhooks/internal/webhooks/kratos-login-backoff"
)

// mockRedisHelper implements kratosloginbackoff.RedisHelper for testing.
type mockRedisHelper struct {
	incrementBothResult [4]int64
	incrementBothErr    error

	incrementIDResult [2]int64
	incrementIDErr    error

	incrementIPResult [2]int64
	incrementIPErr    error

	resetErr   error
	resetCalls []string

	// countedIPs records the address of every per-IP increment.
	countedIPs []string
	// countedIdentifiers records the identifier of every two-key increment.
	countedIdentifiers []string
}

func (m *mockRedisHelper) IncrementLoginAttempts(_ context.Context, identifier, ip string, _, _ int) (int64, int64, int64, int64, error) {
	m.countedIPs = append(m.countedIPs, ip)
	m.countedIdentifiers = append(m.countedIdentifiers, identifier)
	if m.incrementBothErr != nil {
		return 0, 0, 0, 0, m.incrementBothErr
	}
	return m.incrementBothResult[0], m.incrementBothResult[1], m.incrementBothResult[2], m.incrementBothResult[3], nil
}

func (m *mockRedisHelper) IncrementIdentifierAttempt(_ context.Context, _ string, _ int) (int64, int64, error) {
	if m.incrementIDErr != nil {
		return 0, 0, m.incrementIDErr
	}
	return m.incrementIDResult[0], m.incrementIDResult[1], nil
}

func (m *mockRedisHelper) IncrementIPAttempt(_ context.Context, ip string, _ int) (int64, int64, error) {
	m.countedIPs = append(m.countedIPs, ip)
	if m.incrementIPErr != nil {
		return 0, 0, m.incrementIPErr
	}
	return m.incrementIPResult[0], m.incrementIPResult[1], nil
}

func (m *mockRedisHelper) ResetLoginAttempts(_ context.Context, identifier string) error {
	m.resetCalls = append(m.resetCalls, identifier)
	return m.resetErr
}

func newTestService(t *testing.T, mock *mockRedisHelper) *kratosloginbackoff.Service {
	t.Helper()
	cfg := &config.Config{
		LoginBackoffMaxIdentifierAttempts:    10,
		LoginBackoffMaxIPAttempts:            20,
		LoginBackoffIdentifierLockoutSeconds: 120,
		LoginBackoffIPLockoutSeconds:         120,
	}
	return kratosloginbackoff.NewServiceWithRedis(mock, cfg, zap.NewNop())
}

func TestCheckAndIncrement_IdentifierLockout(t *testing.T) {
	mock := &mockRedisHelper{
		incrementBothResult: [4]int64{11, 95, 5, 117},
	}
	svc := newTestService(t, mock)

	result := svc.CheckAndIncrement(context.Background(), kratosloginbackoff.BeforeLoginRequest{
		Identifier: "user@example.com",
		ClientIP:   "192.168.1.1",
	}, "test-corr-id")

	if result.Allowed {
		t.Error("expected blocked after 11 attempts (threshold 10)")
	}
	if result.Reason != "identifier" {
		t.Errorf("expected reason=identifier, got %s", result.Reason)
	}
	if result.RetryAfterSeconds != 95 {
		t.Errorf("expected retry_after_seconds=95, got %d", result.RetryAfterSeconds)
	}
}

func TestCheckAndIncrement_IPLockout(t *testing.T) {
	mock := &mockRedisHelper{
		incrementBothResult: [4]int64{5, 100, 21, 110},
	}
	svc := newTestService(t, mock)

	result := svc.CheckAndIncrement(context.Background(), kratosloginbackoff.BeforeLoginRequest{
		Identifier: "user@example.com",
		ClientIP:   "192.168.1.1",
	}, "test-corr-id")

	if result.Allowed {
		t.Error("expected blocked after 21 IP attempts (threshold 20)")
	}
	if result.Reason != "ip" {
		t.Errorf("expected reason=ip, got %s", result.Reason)
	}
	if result.RetryAfterSeconds != 110 {
		t.Errorf("expected retry_after_seconds=110, got %d", result.RetryAfterSeconds)
	}
}

func TestCheckAndIncrement_LockoutPrecedence_D005(t *testing.T) {
	// Both locked: identifier has 95s remaining, IP has 110s remaining
	// D-005: report the one with longer remaining TTL (IP)
	mock := &mockRedisHelper{
		incrementBothResult: [4]int64{11, 95, 21, 110},
	}
	svc := newTestService(t, mock)

	result := svc.CheckAndIncrement(context.Background(), kratosloginbackoff.BeforeLoginRequest{
		Identifier: "user@example.com",
		ClientIP:   "192.168.1.1",
	}, "test-corr-id")

	if result.Allowed {
		t.Error("expected blocked")
	}
	if result.Reason != "ip" {
		t.Errorf("expected reason=ip (longer TTL), got %s", result.Reason)
	}
	if result.RetryAfterSeconds != 110 {
		t.Errorf("expected retry_after_seconds=110, got %d", result.RetryAfterSeconds)
	}
}

func TestCheckAndIncrement_LockoutPrecedence_IdentifierLonger(t *testing.T) {
	// Both locked: identifier has 115s remaining, IP has 90s remaining
	// D-005: report the one with longer remaining TTL (identifier)
	mock := &mockRedisHelper{
		incrementBothResult: [4]int64{11, 115, 21, 90},
	}
	svc := newTestService(t, mock)

	result := svc.CheckAndIncrement(context.Background(), kratosloginbackoff.BeforeLoginRequest{
		Identifier: "user@example.com",
		ClientIP:   "192.168.1.1",
	}, "test-corr-id")

	if result.Allowed {
		t.Error("expected blocked")
	}
	if result.Reason != "identifier" {
		t.Errorf("expected reason=identifier (longer TTL), got %s", result.Reason)
	}
	if result.RetryAfterSeconds != 115 {
		t.Errorf("expected retry_after_seconds=115, got %d", result.RetryAfterSeconds)
	}
}

// A successful login clears the identifier's counter and never the per-IP one:
// the IP counter lapses with its window, so a login cannot reopen its address's
// budget for further second-step guesses.
func TestResetCounters_ClearsIdentifierOnly(t *testing.T) {
	mock := &mockRedisHelper{}
	svc := newTestService(t, mock)

	resp := svc.ResetCounters(context.Background(), kratosloginbackoff.AfterLoginRequest{
		Email:    "User@Example.com",
		ClientIP: "192.168.1.1",
	}, "test-corr-id")

	if resp.Status != "success" {
		t.Errorf("expected status=success, got %s", resp.Status)
	}
	if resp.Message != "counters reset" {
		t.Errorf("expected message='counters reset', got %s", resp.Message)
	}
	if len(mock.resetCalls) != 1 || mock.resetCalls[0] != "user@example.com" {
		t.Errorf("expected one reset for the normalised identifier, got %q", mock.resetCalls)
	}
}

func TestResetCounters_IPOnly_Skipped(t *testing.T) {
	mock := &mockRedisHelper{}
	svc := newTestService(t, mock)

	resp := svc.ResetCounters(context.Background(), kratosloginbackoff.AfterLoginRequest{
		ClientIP: "192.168.1.1",
	}, "test-corr-id")

	if resp.Status != "skipped" {
		t.Errorf("expected status=skipped, got %s", resp.Status)
	}
	if len(mock.resetCalls) != 0 {
		t.Errorf("expected no reset call, got %q", mock.resetCalls)
	}
}

func TestCheckAndIncrement_FailOpenOnRedisError(t *testing.T) {
	mock := &mockRedisHelper{
		incrementBothErr: errors.New("redis connection refused"),
	}
	svc := newTestService(t, mock)

	result := svc.CheckAndIncrement(context.Background(), kratosloginbackoff.BeforeLoginRequest{
		Identifier: "user@example.com",
		ClientIP:   "192.168.1.1",
	}, "test-corr-id")

	if !result.Allowed {
		t.Error("expected fail-open (allowed=true) on Redis error")
	}
}

// Every arm that lets a submission through without counting it says so, and
// quotes the IP window as the wait.
func TestCheckAndIncrement_UncountedArms(t *testing.T) {
	redisErr := errors.New("redis connection refused")
	cases := map[string]kratosloginbackoff.BeforeLoginRequest{
		"both":            {Identifier: "user@example.com", ClientIP: "192.168.1.1"},
		"identifier_only": {Identifier: "user@example.com"},
		"ip_only":         {ClientIP: "192.168.1.1"},
		"neither":         {},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			mock := &mockRedisHelper{incrementBothErr: redisErr, incrementIDErr: redisErr, incrementIPErr: redisErr}
			cfg := &config.Config{
				LoginBackoffMaxIdentifierAttempts:    10,
				LoginBackoffMaxIPAttempts:            20,
				LoginBackoffIdentifierLockoutSeconds: 120,
				LoginBackoffIPLockoutSeconds:         300,
			}
			svc := kratosloginbackoff.NewServiceWithRedis(mock, cfg, zap.NewNop())

			result := svc.CheckAndIncrement(context.Background(), req, "test-corr-id")

			if !result.Allowed || !result.Uncounted {
				t.Errorf("want allowed and uncounted, got %+v", result)
			}
			if result.RetryAfterSeconds != 300 {
				t.Errorf("want retry_after = the IP window (300), got %d", result.RetryAfterSeconds)
			}
		})
	}
}

func TestCheckAndIncrement_CountedIsNotUncounted(t *testing.T) {
	svc := newTestService(t, &mockRedisHelper{incrementBothResult: [4]int64{1, 120, 1, 120}})

	result := svc.CheckAndIncrement(context.Background(), kratosloginbackoff.BeforeLoginRequest{
		Identifier: "user@example.com",
		ClientIP:   "192.168.1.1",
	}, "test-corr-id")

	if !result.Allowed || result.Uncounted {
		t.Errorf("want allowed and counted, got %+v", result)
	}
}

func TestCheckAndIncrement_IdentifierOnly(t *testing.T) {
	mock := &mockRedisHelper{
		incrementIDResult: [2]int64{3, 118},
	}
	svc := newTestService(t, mock)

	result := svc.CheckAndIncrement(context.Background(), kratosloginbackoff.BeforeLoginRequest{
		Identifier: "user@example.com",
	}, "test-corr-id")

	if !result.Allowed {
		t.Error("expected allowed=true")
	}
	if result.IdentifierAttempts != 3 {
		t.Errorf("expected identifier_attempts=3, got %d", result.IdentifierAttempts)
	}
	if result.IPAttempts != 0 {
		t.Errorf("expected ip_attempts=0, got %d", result.IPAttempts)
	}
}

func TestCheckAndIncrement_IPOnly(t *testing.T) {
	mock := &mockRedisHelper{
		incrementIPResult: [2]int64{5, 117},
	}
	svc := newTestService(t, mock)

	result := svc.CheckAndIncrement(context.Background(), kratosloginbackoff.BeforeLoginRequest{
		ClientIP: "192.168.1.1",
	}, "test-corr-id")

	if !result.Allowed {
		t.Error("expected allowed=true")
	}
	if result.IPAttempts != 5 {
		t.Errorf("expected ip_attempts=5, got %d", result.IPAttempts)
	}
	if result.IdentifierAttempts != 0 {
		t.Errorf("expected identifier_attempts=0, got %d", result.IdentifierAttempts)
	}
}

func TestCheckAndIncrement_NeitherProvided(t *testing.T) {
	mock := &mockRedisHelper{}
	svc := newTestService(t, mock)

	result := svc.CheckAndIncrement(context.Background(), kratosloginbackoff.BeforeLoginRequest{}, "test-corr-id")

	if !result.Allowed {
		t.Error("expected allowed=true when neither identifier nor IP provided")
	}
}

func TestResetCounters_NoIdentifierOrIP(t *testing.T) {
	mock := &mockRedisHelper{}
	svc := newTestService(t, mock)

	resp := svc.ResetCounters(context.Background(), kratosloginbackoff.AfterLoginRequest{}, "test-corr-id")

	if resp.Status != "skipped" {
		t.Errorf("expected status=skipped, got %s", resp.Status)
	}
	if resp.Message != "no identifier or IP provided" {
		t.Errorf("expected appropriate skip message, got %s", resp.Message)
	}
}

func TestResetCounters_FailOpenOnRedisError(t *testing.T) {
	mock := &mockRedisHelper{
		resetErr: errors.New("redis connection refused"),
	}
	svc := newTestService(t, mock)

	resp := svc.ResetCounters(context.Background(), kratosloginbackoff.AfterLoginRequest{
		Email:    "user@example.com",
		ClientIP: "192.168.1.1",
	}, "test-corr-id")

	if resp.Status != "success" {
		t.Errorf("expected status=success on Redis error (fail-open), got %s", resp.Status)
	}
}
