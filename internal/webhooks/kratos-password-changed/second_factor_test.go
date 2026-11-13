package kratospasswordchanged_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/alkem-io/kratos-webhooks/internal/clients"
	kratospasswordchanged "github.com/alkem-io/kratos-webhooks/internal/webhooks/kratos-password-changed"
)

const secondFactorBody = `{"identity_id":"550e8400-e29b-41d4-a716-446655440000",` +
	`"flow_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","client_ip":"203.0.113.7","user_agent":"x"}`

func postSecondFactorChanged(handler *kratospasswordchanged.Handler, query, body string) kratospasswordchanged.WebhookResponse {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/kratos/second-factor-changed"+query, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.HandleSecondFactorChanged(rec, req)
	var resp kratospasswordchanged.WebhookResponse
	if rec.Code != http.StatusOK || json.NewDecoder(rec.Body).Decode(&resp) != nil {
		return kratospasswordchanged.WebhookResponse{Status: "unexpected HTTP " + rec.Result().Status}
	}
	return resp
}

// publishedData is the event as it goes on the wire.
func publishedData(t *testing.T, pub *mockPublisher) map[string]any {
	t.Helper()
	raw, err := json.Marshal(pub.lastEvent)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSecondFactorChanged_PublishesForEachMethod(t *testing.T) {
	for _, method := range []string{"totp", "webauthn", "lookup_secret"} {
		t.Run(method, func(t *testing.T) {
			pub := &mockPublisher{}
			resp := postSecondFactorChanged(setupTestHandler(pub), "?method="+method, secondFactorBody)

			if resp.Status != kratospasswordchanged.StatusSuccess {
				t.Fatalf("want success, got %q", resp.Status)
			}
			if pub.calls != 1 || pub.lastQueue != clients.KratosEventsQueueName ||
				pub.lastPattern != kratospasswordchanged.EventTypeUserSecondFactorChanged {
				t.Fatalf("want one publish to %q as %q, got %d to %q as %q", clients.KratosEventsQueueName,
					kratospasswordchanged.EventTypeUserSecondFactorChanged, pub.calls, pub.lastQueue, pub.lastPattern)
			}
			data := publishedData(t, pub)
			want := map[string]string{
				"eventType":    "USER_SECOND_FACTOR_CHANGED",
				"identityId":   "550e8400-e29b-41d4-a716-446655440000",
				"sourceFlowId": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
				"method":       method,
			}
			for k, v := range want {
				if data[k] != v {
					t.Errorf("data.%s: want %q, got %v", k, v, data[k])
				}
			}
			if data["observedAt"] == "" || data["observedAt"] == nil {
				t.Error("want observedAt set")
			}
			req, _ := data["request"].(map[string]any)
			if req["clientIp"] != "203.0.113.7" || req["userAgent"] != "x" {
				t.Errorf("want request context carried, got %v", data["request"])
			}
		})
	}
}

func TestSecondFactorChanged_SkipsWithoutPublishing(t *testing.T) {
	cases := map[string][2]string{
		"no method":        {"", secondFactorBody},
		"password method":  {"?method=password", secondFactorBody},
		"unknown method":   {"?method=sms", secondFactorBody},
		"invalid json":     {"?method=totp", "not json"},
		"missing identity": {"?method=totp", `{"flow_id":"f"}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			pub := &mockPublisher{}
			resp := postSecondFactorChanged(setupTestHandler(pub), c[0], c[1])
			if resp.Status != kratospasswordchanged.StatusSkipped {
				t.Errorf("want skipped, got %q", resp.Status)
			}
			if pub.calls != 0 {
				t.Errorf("want nothing published, got %d", pub.calls)
			}
		})
	}
}

// A failed publish leaves no audit row, so its warning names the factor.
func TestSecondFactorChanged_PublishFailureReturnsError(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(core)
	pub := &mockPublisher{err: errors.New("broker unreachable")}
	handler := kratospasswordchanged.NewHandler(kratospasswordchanged.NewService(pub, logger), logger)

	resp := postSecondFactorChanged(handler, "?method=totp", secondFactorBody)
	if resp.Status != kratospasswordchanged.StatusError {
		t.Errorf("want error, got %q", resp.Status)
	}
	if logs.FilterMessageSnippet("publish failed").FilterField(zap.String("factor_method", "totp")).Len() != 1 {
		t.Error("want the publish failure logged with factor_method totp")
	}
}

// The password event is unchanged by the second-factor route: no method key,
// whatever the query says.
func TestPasswordChanged_PublishesNoMethod(t *testing.T) {
	pub := &mockPublisher{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/kratos/password-changed?method=totp",
		bytes.NewReader([]byte(secondFactorBody)))
	setupTestHandler(pub).HandlePasswordChanged(httptest.NewRecorder(), req)

	if pub.lastPattern != kratospasswordchanged.EventTypeUserPasswordChanged {
		t.Fatalf("want %q published, got %q", kratospasswordchanged.EventTypeUserPasswordChanged, pub.lastPattern)
	}
	if _, ok := publishedData(t, pub)["method"]; ok {
		t.Error("want no method key on the password event")
	}
}

// A skipped method is logged as received, bounded, so a misspelt route in an
// environment's values shows in the log.
func TestSecondFactorChanged_LogsTheSkippedMethod(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)
	handler := kratospasswordchanged.NewHandler(kratospasswordchanged.NewService(&mockPublisher{}, logger), logger)

	postSecondFactorChanged(handler, "?method=topt", secondFactorBody)
	postSecondFactorChanged(handler, "?method="+strings.Repeat("x", 100), secondFactorBody)

	if logs.FilterField(zap.String("factor_method", "topt")).Len() != 1 {
		t.Error("want the skipped method topt logged")
	}
	if logs.FilterField(zap.String("factor_method", strings.Repeat("x", 32))).Len() != 1 {
		t.Error("want a long method logged truncated to 32 bytes")
	}
}

// A factor change is never logged as a password change.
func TestSecondFactorChanged_LogsNameTheEvent(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)
	handler := kratospasswordchanged.NewHandler(kratospasswordchanged.NewService(&mockPublisher{}, logger), logger)

	postSecondFactorChanged(handler, "?method=totp", secondFactorBody)

	if logs.FilterField(zap.String("event_type", kratospasswordchanged.EventTypeUserSecondFactorChanged)).Len() == 0 {
		t.Error("want a log line naming USER_SECOND_FACTOR_CHANGED")
	}
	for _, e := range logs.All() {
		if strings.Contains(strings.ToLower(e.Message), "password") {
			t.Errorf("factor change logged as a password change: %q", e.Message)
		}
	}
}
