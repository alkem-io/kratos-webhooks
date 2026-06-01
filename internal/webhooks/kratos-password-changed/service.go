package kratospasswordchanged

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/alkem-io/kratos-webhooks/internal/clients"
)

// Publisher publishes an event to a named broker queue using the NestJS
// {pattern,data} envelope. *clients.RabbitMQClient satisfies this interface.
type Publisher interface {
	// PublishToQueue publishes event to the named queue under the given pattern.
	PublishToQueue(ctx context.Context, queue, pattern string, event any) error
}

// Service handles the business logic for Kratos password-changed webhooks.
type Service struct {
	publisher Publisher
	logger    *zap.Logger
}

// NewService creates a new password-changed webhook service.
func NewService(publisher Publisher, logger *zap.Logger) *Service {
	return &Service{
		publisher: publisher,
		logger:    logger,
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

// ValidatePayload validates the incoming Kratos password-changed payload.
// Only identity_id is required; all other fields are optional.
func (s *Service) ValidatePayload(payload *Payload) []ValidationError {
	var errors []ValidationError

	if strings.TrimSpace(payload.IdentityID) == "" {
		errors = append(errors, ValidationError{Field: "identity_id", Message: "required"})
	}

	return errors
}

// TransformToEvent converts a Kratos payload into the broker event. When Kratos
// omits observed_at, the producer defaults it to publish-time now() in UTC RFC3339.
func (s *Service) TransformToEvent(payload *Payload) PasswordChangedEvent {
	observedAt := strings.TrimSpace(payload.ObservedAt)
	if observedAt == "" {
		observedAt = time.Now().UTC().Format(time.RFC3339)
	}

	return PasswordChangedEvent{
		EventType:    EventTypeUserPasswordChanged,
		IdentityID:   payload.IdentityID,
		ObservedAt:   observedAt,
		SourceFlowID: strings.TrimSpace(payload.FlowID),
		Request: RequestContext{
			ClientIP:  strings.TrimSpace(payload.ClientIP),
			UserAgent: strings.TrimSpace(payload.UserAgent),
		},
	}
}

// PublishEvent publishes the password-changed event to the dedicated
// alkemio-kratos-events queue. Returns error on failure, but the caller must
// still return HTTP 200 to Kratos (fail-open semantics).
func (s *Service) PublishEvent(ctx context.Context, event PasswordChangedEvent, correlationID string) error {
	err := s.publisher.PublishToQueue(ctx, clients.KratosEventsQueueName, EventTypeUserPasswordChanged, event)
	if err != nil {
		s.logger.Warn("failed to publish password-changed event",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
			zap.String("identity_id", event.IdentityID),
		)
		return err
	}

	s.logger.Info("password-changed event published",
		zap.String("correlation_id", correlationID),
		zap.String("identity_id", event.IdentityID),
		zap.String("event_type", event.EventType),
	)
	return nil
}
