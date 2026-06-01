// Package main is the entrypoint for the webhook gateway server.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/alkem-io/kratos-webhooks/internal/clients"
	"github.com/alkem-io/kratos-webhooks/internal/config"
	"github.com/alkem-io/kratos-webhooks/internal/health"
	"github.com/alkem-io/kratos-webhooks/internal/middleware"
	kratosloginbackoff "github.com/alkem-io/kratos-webhooks/internal/webhooks/kratos-login-backoff"
	kratospasswordchanged "github.com/alkem-io/kratos-webhooks/internal/webhooks/kratos-password-changed"
	kratosverification "github.com/alkem-io/kratos-webhooks/internal/webhooks/kratos-verification"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger := config.MustNewLogger(cfg)
	defer func() { _ = logger.Sync() }()

	logger.Info("starting webhook gateway",
		zap.Int("port", cfg.Port),
		zap.String("log_level", cfg.LogLevel),
	)

	// Initialize Redis client
	redisClient, err := clients.NewRedisClient(cfg.RedisURL)
	if err != nil {
		logger.Fatal("failed to create redis client", zap.Error(err))
	}
	defer func() { _ = redisClient.Close() }()

	// Initialize RabbitMQ client
	rabbitMQClient, err := clients.NewRabbitMQClient(cfg.RabbitMQURL)
	if err != nil {
		logger.Fatal("failed to create rabbitmq client", zap.Error(err))
	}
	defer func() { _ = rabbitMQClient.Close() }()

	// Create router
	mux := http.NewServeMux()

	// Health endpoints
	healthHandlers := health.NewHandlers(redisClient, rabbitMQClient)
	mux.HandleFunc("GET /health/live", healthHandlers.LiveHandler)
	mux.HandleFunc("GET /health/ready", healthHandlers.ReadyHandler)

	// Webhook endpoints
	webhookService := kratosverification.NewService(redisClient, rabbitMQClient, cfg.PlatformURL, logger)
	webhookHandler := kratosverification.NewHandler(webhookService, logger)
	mux.HandleFunc("POST /api/v1/webhooks/kratos/verification", webhookHandler.HandleVerification)

	// Password-changed webhook: publishes a USER_PASSWORD_CHANGED event onto the
	// dedicated alkemio-kratos-events broker queue for the server to consume.
	passwordChangedService := kratospasswordchanged.NewService(rabbitMQClient, logger)
	passwordChangedHandler := kratospasswordchanged.NewHandler(passwordChangedService, logger)
	mux.HandleFunc("POST /api/v1/webhooks/kratos/password-changed", passwordChangedHandler.HandlePasswordChanged)

	// Login backoff endpoints
	// TODO: These webhook endpoints mutate lockout counters and should be restricted to
	// trusted callers only (Kratos pods). Enforce via Kubernetes NetworkPolicy at minimum;
	// consider adding application-layer auth (mTLS or shared API key) for defense in depth.
	loginBackoffService := kratosloginbackoff.NewService(redisClient, cfg, logger)
	loginBackoffHandler := kratosloginbackoff.NewHandler(loginBackoffService, logger)
	mux.HandleFunc("POST /api/v1/webhooks/kratos/login-backoff/before-login", loginBackoffHandler.HandleBeforeLogin)
	mux.HandleFunc("POST /api/v1/webhooks/kratos/login-backoff/after-login", loginBackoffHandler.HandleAfterLogin)

	// Login proxy: intercepts Kratos login submissions for backoff enforcement
	loginProxy := kratosloginbackoff.NewLoginProxy(cfg.KratosInternalURL, loginBackoffService, logger)
	mux.Handle("/self-service/login", loginProxy)
	mux.Handle("/self-service/login/", loginProxy)

	// Apply middleware chain
	var handler http.Handler = mux
	handler = middleware.Logging(logger)(handler)
	handler = middleware.Maintenance(cfg.MaintenanceMode, cfg.MaintenanceMessage, logger)(handler)
	handler = middleware.CorrelationID(cfg.CorrelationIDHeader)(handler)

	// Create server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("server listening", zap.String("addr", server.Addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server failed", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("server forced to shutdown", zap.Error(err))
	}

	logger.Info("server stopped")
}
