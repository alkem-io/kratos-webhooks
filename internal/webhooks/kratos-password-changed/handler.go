package kratospasswordchanged

import (
	"encoding/json"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/alkem-io/kratos-webhooks/internal/middleware"
)

// Handler handles HTTP requests for the Kratos password-changed webhook.
type Handler struct {
	service *Service
	logger  *zap.Logger
}

// NewHandler creates a new password-changed webhook handler.
func NewHandler(service *Service, logger *zap.Logger) *Handler {
	return &Handler{
		service: service,
		logger:  logger,
	}
}

// HandlePasswordChanged handles POST /api/v1/webhooks/kratos/password-changed.
//
// Trust boundary (FR-007): this endpoint carries NO application-layer
// authentication, mirroring the verification and login-backoff webhooks. It
// inherits the in-cluster trust posture — it is reachable only via the internal
// Service DNS name (no public Traefik/ingress route) and the caller is trusted
// to be a Kratos pod. Network reachability MUST be constrained at the cluster
// (NetworkPolicy) level.
//
// Fail-open: every path returns HTTP 200 so a downstream failure never blocks
// the user's Kratos settings flow.
func (h *Handler) HandlePasswordChanged(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	correlationID := middleware.GetCorrelationID(ctx)

	h.logger.Info("password-changed webhook received",
		zap.String("correlation_id", correlationID),
	)

	// Parse request body
	var payload Payload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.logger.Warn("failed to decode password-changed payload",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
		)
		h.respondJSON(w, WebhookResponse{
			Status:  StatusSkipped,
			Message: "invalid JSON payload",
		})
		return
	}

	// Validate payload (require identity_id)
	validationErrors := h.service.ValidatePayload(&payload)
	if len(validationErrors) > 0 {
		missingFields := make([]string, len(validationErrors))
		for i, err := range validationErrors {
			missingFields[i] = err.Field
		}
		h.logger.Warn("missing required fields",
			zap.String("correlation_id", correlationID),
			zap.Strings("missing_fields", missingFields),
		)
		h.respondJSON(w, WebhookResponse{
			Status:  StatusSkipped,
			Message: "missing required fields: " + strings.Join(missingFields, ", "),
		})
		return
	}

	h.logger.Info("processing password-changed webhook",
		zap.String("correlation_id", correlationID),
		zap.String("identity_id", payload.IdentityID),
	)

	// Transform to broker event (defaults observedAt when absent)
	event := h.service.TransformToEvent(&payload)

	// Publish to the dedicated broker queue
	if err := h.service.PublishEvent(ctx, event, correlationID); err != nil {
		// Fail-open: still return HTTP 200 to Kratos.
		h.logger.Warn("password-changed publish failed, returning success to Kratos",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
			zap.String("identity_id", payload.IdentityID),
		)
		h.respondJSON(w, WebhookResponse{
			Status:  StatusError,
			Message: "event publish failed",
		})
		return
	}

	h.logger.Info("password-changed webhook processed successfully",
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
