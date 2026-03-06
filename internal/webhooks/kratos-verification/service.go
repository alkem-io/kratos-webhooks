package kratosverification

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/alkem-io/kratos-webhooks/internal/clients"
)

// Service handles the business logic for Kratos verification webhooks.
type Service struct {
	redisClient    *clients.RedisClient
	rabbitMQClient *clients.RabbitMQClient
	platformURL    string
	logger         *zap.Logger
}

// NewService creates a new webhook service.
func NewService(redis *clients.RedisClient, rabbitmq *clients.RabbitMQClient, platformURL string, logger *zap.Logger) *Service {
	return &Service{
		redisClient:    redis,
		rabbitMQClient: rabbitmq,
		platformURL:    platformURL,
		logger:         logger,
	}
}

// ValidationError represents a payload validation error.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidatePayload validates the Kratos verification payload.
func (s *Service) ValidatePayload(payload *Payload) []ValidationError {
	var errors []ValidationError

	if strings.TrimSpace(payload.IdentityID) == "" {
		errors = append(errors, ValidationError{Field: "identity_id", Message: "required"})
	}
	if strings.TrimSpace(payload.Email) == "" {
		errors = append(errors, ValidationError{Field: "email", Message: "required"})
	}
	if strings.TrimSpace(payload.DisplayName) == "" {
		errors = append(errors, ValidationError{Field: "display_name", Message: "required"})
	}
	if strings.TrimSpace(payload.FirstName) == "" {
		errors = append(errors, ValidationError{Field: "first_name", Message: "required"})
	}

	return errors
}

// TransformToNotificationEvent converts a Kratos payload to a notification event.
func (s *Service) TransformToNotificationEvent(payload *Payload) UserSignupWelcomeEvent {
	user := UserPayload{
		ID:        payload.IdentityID,
		FirstName: payload.FirstName,
		LastName:  "", // Not provided by Kratos traits
		Email:     payload.Email,
		Profile: ProfileInfo{
			DisplayName: payload.DisplayName,
			URL:         fmt.Sprintf("%s/user/me", s.platformURL),
		},
		Type: UserType,
	}

	return UserSignupWelcomeEvent{
		EventType:   EventTypeUserSignUpWelcome,
		TriggeredBy: user,
		Recipients:  []UserPayload{user},
		Platform: PlatformInfo{
			URL: s.platformURL,
		},
		User: user,
	}
}

// CheckWelcomeSent checks if welcome email was already sent.
// Returns true if already sent, false if not.
// On Redis error, returns false (fail-open: allow potential duplicate).
func (s *Service) CheckWelcomeSent(ctx context.Context, identityID string, correlationID string) bool {
	sent, err := s.redisClient.IsWelcomeSent(ctx, identityID)
	if err != nil {
		s.logger.Warn("redis unavailable for idempotency check, proceeding with notification",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
			zap.String("identity_id", identityID),
		)
		return false // Fail-open: allow potential duplicate rather than blocking
	}
	return sent
}

// MarkWelcomeSent marks the welcome email as sent for an identity in Redis.
func (s *Service) MarkWelcomeSent(ctx context.Context, identityID string, correlationID string) {
	if err := s.redisClient.MarkWelcomeSent(ctx, identityID); err != nil {
		s.logger.Warn("failed to mark welcome as sent in redis",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
			zap.String("identity_id", identityID),
		)
	}
}

// PublishNotificationEvent publishes the notification event to RabbitMQ.
// Returns error on failure, but caller should still return HTTP 200 (fail-open semantics).
func (s *Service) PublishNotificationEvent(ctx context.Context, event UserSignupWelcomeEvent, correlationID string) error {
	err := s.rabbitMQClient.Publish(ctx, EventTypeUserSignUpWelcome, event)
	if err != nil {
		s.logger.Warn("failed to publish notification event",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
			zap.String("identity_id", event.TriggeredBy.ID),
		)
		// Return error to indicate failure but caller should still return HTTP 200
		return err
	}

	s.logger.Info("notification event published",
		zap.String("correlation_id", correlationID),
		zap.String("identity_id", event.TriggeredBy.ID),
		zap.String("event_type", event.EventType),
	)
	return nil
}
