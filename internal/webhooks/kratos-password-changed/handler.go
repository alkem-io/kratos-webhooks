package kratospasswordchanged

import (
	"encoding/json"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/alkem-io/kratos-webhooks/internal/middleware"
)

// Handler handles HTTP requests for the Kratos settings webhooks.
type Handler struct {
	service *Service
	logger  *zap.Logger
}

// NewHandler creates a new settings webhook handler.
func NewHandler(service *Service, logger *zap.Logger) *Handler {
	return &Handler{
		service: service,
		logger:  logger,
	}
}

// HandlePasswordChanged handles POST /api/v1/webhooks/kratos/password-changed.
//
// Trust boundary: this endpoint carries NO application-layer authentication,
// mirroring the verification and login-backoff webhooks. It inherits the
// in-cluster trust posture — it is reachable only via the internal Service DNS
// name (no public Traefik/ingress route) and the caller is trusted to be a
// Kratos pod. Network reachability MUST be constrained at the cluster
// (NetworkPolicy) level.
//
// Fail-open: every path returns HTTP 200 so a downstream failure never blocks
// the user's Kratos settings flow.
func (h *Handler) HandlePasswordChanged(w http.ResponseWriter, r *http.Request) {
	h.handle(w, r, EventTypeUserPasswordChanged, "")
}

// HandleSecondFactorChanged handles
// POST /api/v1/webhooks/kratos/second-factor-changed?method=<totp|webauthn|lookup_secret>.
// The method travels in the query because Kratos' body template is shared with
// the password route. Any other method is skipped. Same trust boundary and
// fail-open contract as HandlePasswordChanged.
func (h *Handler) HandleSecondFactorChanged(w http.ResponseWriter, r *http.Request) {
	switch method := r.URL.Query().Get("method"); method {
	case "totp", "webauthn", "lookup_secret":
		h.handle(w, r, EventTypeUserSecondFactorChanged, method)
	default:
		const maxLoggedMethodBytes = 32
		h.logger.Warn("unsupported second-factor method, skipping",
			zap.String("correlation_id", middleware.GetCorrelationID(r.Context())),
			zap.String("event_type", EventTypeUserSecondFactorChanged),
			zap.String("factor_method", method[:min(len(method), maxLoggedMethodBytes)]),
		)
		h.respondJSON(w, WebhookResponse{
			Status:  StatusSkipped,
			Message: "unsupported method",
		})
	}
}

func (h *Handler) handle(w http.ResponseWriter, r *http.Request, eventType, method string) {
	ctx := r.Context()
	correlationID := middleware.GetCorrelationID(ctx)
	log := h.logger.With(
		zap.String("correlation_id", correlationID),
		zap.String("event_type", eventType),
	)

	log.Info("kratos settings webhook received")

	// Parse request body
	var payload Payload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Warn("failed to decode kratos settings payload", zap.Error(err))
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
		log.Warn("missing required fields", zap.Strings("missing_fields", missingFields))
		h.respondJSON(w, WebhookResponse{
			Status:  StatusSkipped,
			Message: "missing required fields: " + strings.Join(missingFields, ", "),
		})
		return
	}

	log = log.With(zap.String("identity_id", payload.IdentityID))
	log.Info("processing kratos settings webhook")

	// Transform to broker event (defaults observedAt when absent)
	event := h.service.TransformToEvent(&payload, eventType, method)

	// Publish to the dedicated broker queue
	if err := h.service.PublishEvent(ctx, event, correlationID); err != nil {
		// Fail-open: still return HTTP 200 to Kratos.
		log.Warn("kratos settings event publish failed, returning success to Kratos", zap.Error(err))
		h.respondJSON(w, WebhookResponse{
			Status:  StatusError,
			Message: "event publish failed",
		})
		return
	}

	log.Info("kratos settings webhook processed successfully", zap.String("outcome", StatusSuccess))

	h.respondJSON(w, WebhookResponse{
		Status: StatusSuccess,
	})
}

func (h *Handler) respondJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(data)
}
