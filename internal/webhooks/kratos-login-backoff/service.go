package kratosloginbackoff

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/alkem-io/kratos-webhooks/internal/clients"
	"github.com/alkem-io/kratos-webhooks/internal/config"
)

// RedisHelper defines the Redis operations needed by the login backoff service.
type RedisHelper interface {
	// IncrementLoginAttempts atomically increments both identifier and IP counters.
	IncrementLoginAttempts(ctx context.Context, identifier, ip string, idTTLSeconds, ipTTLSeconds int) (int64, int64, int64, int64, error)
	// IncrementIdentifierAttempt atomically increments the identifier counter only.
	IncrementIdentifierAttempt(ctx context.Context, identifier string, ttlSeconds int) (int64, int64, error)
	// IncrementIPAttempt atomically increments the IP counter only.
	IncrementIPAttempt(ctx context.Context, ip string, ttlSeconds int) (int64, int64, error)
	// ResetLoginAttempts deletes both identifier and IP counter keys.
	ResetLoginAttempts(ctx context.Context, identifier, ip string) error
}

// Service handles the business logic for login backoff.
type Service struct {
	redisClient RedisHelper
	cfg         *config.Config
	logger      *zap.Logger
}

// NewService creates a new login backoff service using a concrete RedisClient.
func NewService(redisClient *clients.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		redisClient: redisClient,
		cfg:         cfg,
		logger:      logger,
	}
}

// NewServiceWithRedis creates a new login backoff service with the given RedisHelper.
// This constructor is intended for testing with mock implementations.
func NewServiceWithRedis(redisClient RedisHelper, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		redisClient: redisClient,
		cfg:         cfg,
		logger:      logger,
	}
}

// CheckAndIncrementResult holds the result of a check-and-increment operation.
type CheckAndIncrementResult struct {
	Allowed bool
	// Fields populated when allowed
	IdentifierAttempts int64
	IPAttempts         int64
	// Fields populated when blocked
	Reason            string
	Message           string
	RetryAfterSeconds int64
}

// CheckAndIncrement checks and increments login attempt counters.
// Returns allowed=true if under threshold, or blocked details if over threshold.
// Fails open on Redis errors (returns allowed=true).
func (s *Service) CheckAndIncrement(ctx context.Context, req BeforeLoginRequest, correlationID string) CheckAndIncrementResult {
	identifier := strings.ToLower(strings.TrimSpace(req.Identifier))
	ip := strings.TrimSpace(req.ClientIP)

	// Neither identifier nor IP provided - fail open
	if identifier == "" && ip == "" {
		s.logger.Warn("before-login request with no identifier or IP, allowing",
			zap.String("correlation_id", correlationID),
			zap.String("flow_id", req.FlowID),
		)
		return CheckAndIncrementResult{Allowed: true}
	}

	// Both identifier and IP provided
	if identifier != "" && ip != "" {
		return s.incrementBoth(ctx, identifier, ip, correlationID)
	}

	// Only identifier provided
	if identifier != "" {
		return s.incrementIdentifierOnly(ctx, identifier, correlationID)
	}

	// Only IP provided
	return s.incrementIPOnly(ctx, ip, correlationID)
}

func (s *Service) incrementBoth(ctx context.Context, identifier, ip, correlationID string) CheckAndIncrementResult {
	idCount, idRemaining, ipCount, ipRemaining, err := s.redisClient.IncrementLoginAttempts(
		ctx, identifier, ip,
		s.cfg.LoginBackoffIdentifierLockoutSeconds,
		s.cfg.LoginBackoffIPLockoutSeconds,
	)
	if err != nil {
		s.logger.Warn("redis error during login backoff check, failing open",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
			s.identifierHashField(identifier),
			zap.String("client_ip_prefix", ipPrefix(ip)),
		)
		return CheckAndIncrementResult{Allowed: true}
	}

	idLocked := idCount > int64(s.cfg.LoginBackoffMaxIdentifierAttempts)
	ipLocked := ipCount > int64(s.cfg.LoginBackoffMaxIPAttempts)

	if !idLocked && !ipLocked {
		s.logger.Info("login attempt allowed",
			zap.String("correlation_id", correlationID),
			s.identifierHashField(identifier),
			zap.String("client_ip_prefix", ipPrefix(ip)),
			zap.Int64("identifier_attempts", idCount),
			zap.Int64("ip_attempts", ipCount),
			zap.Int("identifier_threshold", s.cfg.LoginBackoffMaxIdentifierAttempts),
			zap.Int("ip_threshold", s.cfg.LoginBackoffMaxIPAttempts),
		)
		return CheckAndIncrementResult{
			Allowed:            true,
			IdentifierAttempts: idCount,
			IPAttempts:         ipCount,
		}
	}

	// D-005: when both locked, report the one with longer remaining TTL
	reason := "identifier"
	remaining := idRemaining
	if ipLocked && (!idLocked || ipRemaining > idRemaining) {
		reason = "ip"
		remaining = ipRemaining
	}

	message := lockoutMessage(reason, remaining)

	s.logger.Warn("login attempt blocked",
		zap.String("correlation_id", correlationID),
		s.identifierHashField(identifier),
		zap.String("client_ip_prefix", ipPrefix(ip)),
		zap.Int64("identifier_attempts", idCount),
		zap.Int64("ip_attempts", ipCount),
		zap.Int("identifier_threshold", s.cfg.LoginBackoffMaxIdentifierAttempts),
		zap.Int("ip_threshold", s.cfg.LoginBackoffMaxIPAttempts),
		zap.Int64("retry_after_seconds", remaining),
		zap.String("lockout_reason", reason),
	)

	return CheckAndIncrementResult{
		Allowed:           false,
		Reason:            reason,
		Message:           message,
		RetryAfterSeconds: remaining,
	}
}

func (s *Service) incrementIdentifierOnly(ctx context.Context, identifier, correlationID string) CheckAndIncrementResult {
	count, remaining, err := s.redisClient.IncrementIdentifierAttempt(
		ctx, identifier,
		s.cfg.LoginBackoffIdentifierLockoutSeconds,
	)
	if err != nil {
		s.logger.Warn("redis error during identifier backoff check, failing open",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
			s.identifierHashField(identifier),
		)
		return CheckAndIncrementResult{Allowed: true}
	}

	if count > int64(s.cfg.LoginBackoffMaxIdentifierAttempts) {
		s.logger.Warn("login attempt blocked",
			zap.String("correlation_id", correlationID),
			s.identifierHashField(identifier),
			zap.Int64("identifier_attempts", count),
			zap.Int("identifier_threshold", s.cfg.LoginBackoffMaxIdentifierAttempts),
			zap.Int64("retry_after_seconds", remaining),
			zap.String("lockout_reason", "identifier"),
		)
		return CheckAndIncrementResult{
			Allowed:           false,
			Reason:            "identifier",
			Message:           lockoutMessage("identifier", remaining),
			RetryAfterSeconds: remaining,
		}
	}

	s.logger.Info("login attempt allowed",
		zap.String("correlation_id", correlationID),
		s.identifierHashField(identifier),
		zap.Int64("identifier_attempts", count),
		zap.Int("identifier_threshold", s.cfg.LoginBackoffMaxIdentifierAttempts),
	)
	return CheckAndIncrementResult{
		Allowed:            true,
		IdentifierAttempts: count,
	}
}

func (s *Service) incrementIPOnly(ctx context.Context, ip, correlationID string) CheckAndIncrementResult {
	count, remaining, err := s.redisClient.IncrementIPAttempt(
		ctx, ip,
		s.cfg.LoginBackoffIPLockoutSeconds,
	)
	if err != nil {
		s.logger.Warn("redis error during IP backoff check, failing open",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
			zap.String("client_ip_prefix", ipPrefix(ip)),
		)
		return CheckAndIncrementResult{Allowed: true}
	}

	if count > int64(s.cfg.LoginBackoffMaxIPAttempts) {
		s.logger.Warn("login attempt blocked",
			zap.String("correlation_id", correlationID),
			zap.String("client_ip_prefix", ipPrefix(ip)),
			zap.Int64("ip_attempts", count),
			zap.Int("ip_threshold", s.cfg.LoginBackoffMaxIPAttempts),
			zap.Int64("retry_after_seconds", remaining),
			zap.String("lockout_reason", "ip"),
		)
		return CheckAndIncrementResult{
			Allowed:           false,
			Reason:            "ip",
			Message:           lockoutMessage("ip", remaining),
			RetryAfterSeconds: remaining,
		}
	}

	s.logger.Info("login attempt allowed",
		zap.String("correlation_id", correlationID),
		zap.String("client_ip_prefix", ipPrefix(ip)),
		zap.Int64("ip_attempts", count),
		zap.Int("ip_threshold", s.cfg.LoginBackoffMaxIPAttempts),
	)
	return CheckAndIncrementResult{
		Allowed:    true,
		IPAttempts: count,
	}
}

// ResetCounters resets login attempt counters after a successful login.
// Fails open on errors.
func (s *Service) ResetCounters(ctx context.Context, req AfterLoginRequest, correlationID string) AfterLoginResponse {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	ip := strings.TrimSpace(req.ClientIP)

	if email == "" && ip == "" {
		s.logger.Warn("after-login request with no email or IP, skipping reset",
			zap.String("correlation_id", correlationID),
			zap.String("identity_id", req.IdentityID),
		)
		return AfterLoginResponse{
			Status:  StatusSkipped,
			Message: "no identifier or IP provided",
		}
	}

	var resetFailed bool
	switch {
	case email != "" && ip != "":
		if err := s.redisClient.ResetLoginAttempts(ctx, email, ip); err != nil {
			resetFailed = true
			s.logger.Warn("redis error during counter reset, failing open",
				zap.Error(err),
				zap.String("correlation_id", correlationID),
				s.identifierHashField(email),
				zap.String("client_ip_prefix", ipPrefix(ip)),
			)
		}
	case email != "":
		if err := s.redisClient.ResetLoginAttempts(ctx, email, ""); err != nil {
			resetFailed = true
			s.logger.Warn("redis error during identifier counter reset, failing open",
				zap.Error(err),
				zap.String("correlation_id", correlationID),
				s.identifierHashField(email),
			)
		}
	default:
		if err := s.redisClient.ResetLoginAttempts(ctx, "", ip); err != nil {
			resetFailed = true
			s.logger.Warn("redis error during IP counter reset, failing open",
				zap.Error(err),
				zap.String("correlation_id", correlationID),
				zap.String("client_ip_prefix", ipPrefix(ip)),
			)
		}
	}

	if !resetFailed {
		s.logger.Info("login backoff counters reset",
			zap.String("correlation_id", correlationID),
			s.identifierHashField(email),
			zap.String("client_ip_prefix", ipPrefix(ip)),
			zap.String("event", "counters_reset"),
		)
	}

	return AfterLoginResponse{
		Status:  StatusSuccess,
		Message: "counters reset",
	}
}

// identifierHash is the log-safe pseudonym of an identifier (see logfields.go).
func (s *Service) identifierHash(identifier string) string {
	return identifierHash([]byte(s.cfg.LogIdentifierHashKey), identifier)
}

// identifierHashField is the identifier_hash log field, omitted entirely when
// there is no hash (no key configured or empty identifier).
func (s *Service) identifierHashField(identifier string) zap.Field {
	hash := s.identifierHash(identifier)
	if hash == "" {
		return zap.Skip()
	}
	return zap.String("identifier_hash", hash)
}

// lockoutMessage generates a human-readable lockout message.
func lockoutMessage(reason string, remainingSeconds int64) string {
	minutes := (remainingSeconds + 59) / 60 // round up
	if reason == "ip" {
		return fmt.Sprintf("Too many login attempts from this address. Try again in %d minutes.", minutes)
	}
	return fmt.Sprintf("Account temporarily locked due to too many failed attempts. Try again in %d minutes.", minutes)
}
