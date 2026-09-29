// Package health provides health check endpoints.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/alkem-io/kratos-webhooks/internal/clients"
)

// Response is the response for liveness check.
type Response struct {
	Status    string `json:"status" validate:"required,oneof=ok degraded unhealthy"`
	Timestamp string `json:"timestamp" apispec:"format=date-time"`
}

// ReadinessResponse is the response for readiness check.
type ReadinessResponse struct {
	Status    string `json:"status" validate:"required,oneof=ok degraded unhealthy"`
	Redis     string `json:"redis" validate:"required,oneof=connected disconnected"`
	RabbitMQ  string `json:"rabbitmq" validate:"required,oneof=connected disconnected"`
	Timestamp string `json:"timestamp" apispec:"format=date-time"`
}

// Handlers holds dependencies for health check handlers.
type Handlers struct {
	redisClient    *clients.RedisClient
	rabbitMQClient *clients.RabbitMQClient
}

// NewHandlers creates a new health handlers instance.
func NewHandlers(redis *clients.RedisClient, rabbitmq *clients.RabbitMQClient) *Handlers {
	return &Handlers{
		redisClient:    redis,
		rabbitMQClient: rabbitmq,
	}
}

// LiveHandler handles GET /health/live.
func (h *Handlers) LiveHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := Response{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// ReadyHandler handles GET /health/ready.
func (h *Handlers) ReadyHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	redisStatus := "connected"
	rabbitMQStatus := "connected"
	overallStatus := "ok"

	// Check Redis
	if err := h.redisClient.Ping(ctx); err != nil {
		redisStatus = "disconnected"
		overallStatus = "unhealthy"
	}

	// Check RabbitMQ
	if err := h.rabbitMQClient.Ping(); err != nil {
		rabbitMQStatus = "disconnected"
		overallStatus = "unhealthy"
	}

	resp := ReadinessResponse{
		Status:    overallStatus,
		Redis:     redisStatus,
		RabbitMQ:  rabbitMQStatus,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if overallStatus == "unhealthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(resp)
}
