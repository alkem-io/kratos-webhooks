// Package kratospasswordchanged handles Ory Kratos post-password-change webhooks,
// publishing a USER_PASSWORD_CHANGED event onto the broker for the Alkemio server
// to consume. It mirrors the kratos-verification package.
package kratospasswordchanged

// Payload represents the incoming webhook payload from Kratos, emitted by the
// jsonnet body template on the `settings.after.password` hook. Fields are
// snake_case to match the Kratos request body.
type Payload struct {
	// IdentityID is the Kratos identity UUID (required).
	IdentityID string `json:"identity_id" apispec:"format=uuid"`
	// FlowID is the Kratos settings flow id (optional). Part of the idempotency key.
	FlowID string `json:"flow_id,omitempty"`
	// ObservedAt is when the change was observed (optional, RFC3339). Producer
	// defaults to publish-time now() (UTC) when Kratos omits it.
	ObservedAt string `json:"observed_at,omitempty" apispec:"format=date-time"`
	// ClientIP is the end-user IP, templated from Kratos request_headers (optional).
	ClientIP string `json:"client_ip,omitempty"`
	// UserAgent is the end-user user-agent, templated from Kratos request_headers (optional).
	UserAgent string `json:"user_agent,omitempty"`
}

// RequestContext carries the end-user request metadata reproduced in the audit record.
type RequestContext struct {
	ClientIP  string `json:"clientIp,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
}

// PasswordChangedEvent is the broker event payload (the `data` of the NestJS
// {pattern,data} envelope), matching contracts/password-changed-event.md.
type PasswordChangedEvent struct {
	EventType    string         `json:"eventType"`
	IdentityID   string         `json:"identityId"`
	ObservedAt   string         `json:"observedAt"`
	SourceFlowID string         `json:"sourceFlowId,omitempty"`
	Request      RequestContext `json:"request"`
}

// WebhookResponse is the HTTP response to Kratos.
type WebhookResponse struct {
	Status  string `json:"status" validate:"required,oneof=success skipped error"`
	Message string `json:"message,omitempty"`
}

// Event type constants.
const (
	// EventTypeUserPasswordChanged is the broker pattern and data.eventType.
	EventTypeUserPasswordChanged = "USER_PASSWORD_CHANGED" //nolint:gosec // not a credential
)

// Response status constants.
const (
	StatusSuccess = "success"
	StatusSkipped = "skipped"
	StatusError   = "error"
)
