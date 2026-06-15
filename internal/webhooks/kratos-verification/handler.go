package kratosverification

import (
	"encoding/json"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/alkem-io/kratos-webhooks/internal/middleware"
)

// Handler handles HTTP requests for Kratos verification webhooks.
type Handler struct {
	service *Service
	logger  *zap.Logger
}

// NewHandler creates a new webhook handler.
func NewHandler(service *Service, logger *zap.Logger) *Handler {
	return &Handler{
		service: service,
		logger:  logger,
	}
}

// HandleVerification handles POST /api/v1/webhooks/kratos/verification.
//
// It is the Ory Kratos post-verification webhook: it receives the webhook after
// a successful email verification in Ory Kratos and publishes a
// UserSignupWelcome notification event to RabbitMQ. The endpoint always returns
// HTTP 200 to Kratos, even when notification processing fails, so the
// verification flow is never blocked.
//
// The OpenAPI summary/description for this operation are set in apispec.yaml
// overrides — apispec v0.4.21 does not extract doc comments from methods
// (functions with a receiver), only from free functions.
func (h *Handler) HandleVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	correlationID := middleware.GetCorrelationID(ctx)

	h.logger.Info("webhook received",
		zap.String("correlation_id", correlationID),
	)

	// Parse request body
	var payload Payload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.logger.Warn("failed to decode webhook payload",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
		)
		h.respondJSON(w, WebhookResponse{
			Status:  StatusSkipped,
			Message: "invalid JSON payload",
		})
		return
	}

	// Validate payload
	validationErrors := h.service.ValidatePayload(&payload)
	if len(validationErrors) > 0 {
		missingFields := make([]string, len(validationErrors))
		for i, err := range validationErrors {
			missingFields[i] = err.Field
		}
		h.logger.Warn("missing required traits",
			zap.String("correlation_id", correlationID),
			zap.Strings("missing_fields", missingFields),
		)
		h.respondJSON(w, WebhookResponse{
			Status:  StatusSkipped,
			Message: "missing required traits: " + strings.Join(missingFields, ", "),
		})
		return
	}

	h.logger.Info("processing verification webhook",
		zap.String("correlation_id", correlationID),
		zap.String("identity_id", payload.IdentityID),
	)

	// Check idempotency (without marking yet)
	alreadySent := h.service.CheckWelcomeSent(ctx, payload.IdentityID, correlationID)
	if alreadySent {
		h.logger.Info("welcome email already sent for this identity",
			zap.String("correlation_id", correlationID),
			zap.String("identity_id", payload.IdentityID),
		)
		h.respondJSON(w, WebhookResponse{
			Status:  StatusSkipped,
			Message: "welcome email already sent for this identity",
		})
		return
	}

	// Transform to notification event
	event := h.service.TransformToNotificationEvent(&payload)

	// Publish to RabbitMQ
	err := h.service.PublishNotificationEvent(ctx, event, correlationID)
	if err != nil {
		// Fail-open: still return success to Kratos
		h.logger.Warn("notification publish failed, returning success to Kratos",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
			zap.String("identity_id", payload.IdentityID),
		)
		h.respondJSON(w, WebhookResponse{
			Status:  StatusError,
			Message: "notification queuing failed",
		})
		return
	}

	// Mark as sent only after successful publish
	h.service.MarkWelcomeSent(ctx, payload.IdentityID, correlationID)

	h.logger.Info("webhook processed successfully",
		zap.String("correlation_id", correlationID),
		zap.String("identity_id", payload.IdentityID),
		zap.String("status", StatusSuccess),
	)

	h.respondJSON(w, WebhookResponse{
		Status: StatusSuccess,
	})
}

func (h *Handler) respondJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(data)
}
