// Package kratosverification handles Ory Kratos post-verification webhooks.
package kratosverification

// Payload represents the webhook payload from Kratos
// after successful email verification.
type Payload struct {
	IdentityID  string `json:"identity_id" apispec:"format=uuid"`
	Email       string `json:"email" apispec:"format=email"`
	DisplayName string `json:"display_name"`
	FirstName   string `json:"first_name"`
}

// UserPayload represents user information in notification events.
type UserPayload struct {
	ID        string      `json:"id"`
	FirstName string      `json:"firstName"`
	LastName  string      `json:"lastName"`
	Email     string      `json:"email"`
	Profile   ProfileInfo `json:"profile"`
	Type      string      `json:"type"`
}

// ProfileInfo contains profile display information.
type ProfileInfo struct {
	DisplayName string `json:"displayName"`
	URL         string `json:"url"`
}

// PlatformInfo contains platform configuration.
type PlatformInfo struct {
	URL string `json:"url"`
}

// UserSignupWelcomeEvent is the notification event for new user welcome emails.
type UserSignupWelcomeEvent struct {
	EventType   string        `json:"eventType"`
	TriggeredBy UserPayload   `json:"triggeredBy"`
	Recipients  []UserPayload `json:"recipients"`
	Platform    PlatformInfo  `json:"platform"`
	User        UserPayload   `json:"user"`
}

// WebhookResponse is the HTTP response to Kratos.
type WebhookResponse struct {
	Status  string `json:"status" validate:"required,oneof=success skipped error"`
	Message string `json:"message,omitempty"`
}

// Event type constants.
const (
	EventTypeUserSignUpWelcome = "USER_SIGN_UP_WELCOME" //nolint:gosec // not a credential
	UserType                   = "user"
)

// Response status constants.
const (
	StatusSuccess = "success"
	StatusSkipped = "skipped"
	StatusError   = "error"
)
