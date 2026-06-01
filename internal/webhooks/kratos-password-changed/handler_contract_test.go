package kratospasswordchanged_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/alkem-io/kratos-webhooks/internal/clients"
	kratospasswordchanged "github.com/alkem-io/kratos-webhooks/internal/webhooks/kratos-password-changed"
)

// mockPublisher records the last publish and can be configured to fail.
type mockPublisher struct {
	err         error
	calls       int
	lastQueue   string
	lastPattern string
	lastEvent   kratospasswordchanged.PasswordChangedEvent
}

func (m *mockPublisher) PublishToQueue(_ context.Context, queue, pattern string, event any) error {
	m.calls++
	m.lastQueue = queue
	m.lastPattern = pattern
	if e, ok := event.(kratospasswordchanged.PasswordChangedEvent); ok {
		m.lastEvent = e
	}
	return m.err
}

func setupTestHandler(pub *mockPublisher) *kratospasswordchanged.Handler {
	logger := zap.NewNop()
	service := kratospasswordchanged.NewService(pub, logger)
	return kratospasswordchanged.NewHandler(service, logger)
}

func postPasswordChanged(t *testing.T, handler *kratospasswordchanged.Handler, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/kratos/password-changed", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.HandlePasswordChanged(rec, req)
	return rec
}

func TestPasswordChanged_ValidPayloadPublishesAndReturns200(t *testing.T) {
	pub := &mockPublisher{}
	handler := setupTestHandler(pub)

	body, _ := json.Marshal(map[string]string{
		"identity_id": "550e8400-e29b-41d4-a716-446655440000",
		"flow_id":     "f1a2b3c4",
		"observed_at": "2026-06-01T10:30:45Z",
		"client_ip":   "203.0.113.7",
		"user_agent":  "Mozilla/5.0",
	})

	rec := postPasswordChanged(t, handler, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp kratospasswordchanged.WebhookResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != kratospasswordchanged.StatusSuccess {
		t.Errorf("expected status=success, got %q", resp.Status)
	}

	if pub.calls != 1 {
		t.Fatalf("expected exactly 1 publish, got %d", pub.calls)
	}
	if pub.lastQueue != clients.KratosEventsQueueName {
		t.Errorf("expected publish to queue %q, got %q", clients.KratosEventsQueueName, pub.lastQueue)
	}
	if pub.lastPattern != kratospasswordchanged.EventTypeUserPasswordChanged {
		t.Errorf("expected pattern %q, got %q", kratospasswordchanged.EventTypeUserPasswordChanged, pub.lastPattern)
	}

	ev := pub.lastEvent
	if ev.EventType != kratospasswordchanged.EventTypeUserPasswordChanged {
		t.Errorf("expected eventType=%q, got %q", kratospasswordchanged.EventTypeUserPasswordChanged, ev.EventType)
	}
	if ev.IdentityID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("unexpected identityId: %q", ev.IdentityID)
	}
	if ev.ObservedAt != "2026-06-01T10:30:45Z" {
		t.Errorf("expected observedAt passed through, got %q", ev.ObservedAt)
	}
	if ev.SourceFlowID != "f1a2b3c4" {
		t.Errorf("expected sourceFlowId=f1a2b3c4, got %q", ev.SourceFlowID)
	}
	if ev.Request.ClientIP != "203.0.113.7" {
		t.Errorf("expected clientIp=203.0.113.7, got %q", ev.Request.ClientIP)
	}
	if ev.Request.UserAgent != "Mozilla/5.0" {
		t.Errorf("expected userAgent=Mozilla/5.0, got %q", ev.Request.UserAgent)
	}
}

func TestPasswordChanged_DefaultsObservedAtWhenAbsent(t *testing.T) {
	pub := &mockPublisher{}
	handler := setupTestHandler(pub)

	body, _ := json.Marshal(map[string]string{
		"identity_id": "550e8400-e29b-41d4-a716-446655440000",
	})

	rec := postPasswordChanged(t, handler, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if pub.calls != 1 {
		t.Fatalf("expected exactly 1 publish, got %d", pub.calls)
	}
	if pub.lastEvent.ObservedAt == "" {
		t.Error("expected observedAt to be defaulted to now() when absent")
	}
}

func TestPasswordChanged_MissingIdentitySkipsAndReturns200(t *testing.T) {
	pub := &mockPublisher{}
	handler := setupTestHandler(pub)

	body, _ := json.Marshal(map[string]string{
		"flow_id": "f1a2b3c4",
	})

	rec := postPasswordChanged(t, handler, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp kratospasswordchanged.WebhookResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != kratospasswordchanged.StatusSkipped {
		t.Errorf("expected status=skipped, got %q", resp.Status)
	}
	if pub.calls != 0 {
		t.Errorf("expected no publish when identity missing, got %d", pub.calls)
	}
}

func TestPasswordChanged_MalformedJSONSkipsAndReturns200(t *testing.T) {
	pub := &mockPublisher{}
	handler := setupTestHandler(pub)

	rec := postPasswordChanged(t, handler, []byte("not json"))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on malformed input, got %d", rec.Code)
	}

	var resp kratospasswordchanged.WebhookResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != kratospasswordchanged.StatusSkipped {
		t.Errorf("expected status=skipped, got %q", resp.Status)
	}
	if pub.calls != 0 {
		t.Errorf("expected no publish on malformed input, got %d", pub.calls)
	}
}

func TestPasswordChanged_PublishFailureReturns200WithError(t *testing.T) {
	pub := &mockPublisher{err: errors.New("broker unreachable")}
	handler := setupTestHandler(pub)

	body, _ := json.Marshal(map[string]string{
		"identity_id": "550e8400-e29b-41d4-a716-446655440000",
	})

	rec := postPasswordChanged(t, handler, body)

	// Fail-open: still 200 to Kratos.
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on publish failure, got %d", rec.Code)
	}

	var resp kratospasswordchanged.WebhookResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != kratospasswordchanged.StatusError {
		t.Errorf("expected status=error, got %q", resp.Status)
	}
	if pub.calls != 1 {
		t.Errorf("expected 1 publish attempt, got %d", pub.calls)
	}
}

func TestPasswordChanged_ContentTypeJSON(t *testing.T) {
	pub := &mockPublisher{}
	handler := setupTestHandler(pub)

	body, _ := json.Marshal(map[string]string{
		"identity_id": "550e8400-e29b-41d4-a716-446655440000",
	})

	rec := postPasswordChanged(t, handler, body)

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}
