// Package kratosloginbackoff handles login brute force protection webhooks.
package kratosloginbackoff

// BeforeLoginRequest is the incoming request to check and increment login attempt counters.
type BeforeLoginRequest struct {
	FlowID     string `json:"flow_id,omitempty" apispec:"format=uuid"`
	Identifier string `json:"identifier,omitempty" apispec:"format=email"`
	ClientIP   string `json:"client_ip,omitempty"`
}

// BeforeLoginAllowedResponse is returned when a login attempt is allowed.
type BeforeLoginAllowedResponse struct {
	Allowed            bool  `json:"allowed"`
	IdentifierAttempts int64 `json:"identifier_attempts" validate:"required,min=0"`
	IPAttempts         int64 `json:"ip_attempts" validate:"required,min=0"`
}

// BeforeLoginBlockedResponse is returned when a login attempt is blocked due to lockout.
type BeforeLoginBlockedResponse struct {
	Allowed           bool   `json:"allowed"`
	Reason            string `json:"reason" validate:"required,oneof=identifier ip"`
	Message           string `json:"message"`
	RetryAfterSeconds int64  `json:"retry_after_seconds" validate:"required,min=0"`
}

// AfterLoginRequest is the incoming request to reset counters after successful authentication.
type AfterLoginRequest struct {
	IdentityID string `json:"identity_id,omitempty" apispec:"format=uuid"`
	Email      string `json:"email,omitempty" apispec:"format=email"`
	ClientIP   string `json:"client_ip,omitempty"`
}

// AfterLoginResponse is returned after processing a successful login notification.
type AfterLoginResponse struct {
	Status  string `json:"status" validate:"required,oneof=success skipped"`
	Message string `json:"message,omitempty"`
}

// Response status constants.
const (
	StatusSuccess = "success"
	StatusSkipped = "skipped"
)
