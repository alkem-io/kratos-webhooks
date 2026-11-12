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
	// ResetLoginAttempts deletes the identifier counter. A per-IP counter is
	// never deleted: it lapses with its window, so a successful login cannot
	// reopen its address's budget for further guesses at a second step.
	ResetLoginAttempts(ctx context.Context, identifier string) error
}

// Service handles the business logic for login backoff.
type Service struct {
	redisClient RedisHelper
	cfg         *config.Config
	logger      *zap.Logger
	hashKey     []byte
}

// minLogIdentifierHashKeyBytes is the shortest key used for identifier_hmac. A
// shorter key can be brute-forced from logged pseudonyms and a list of emails.
const minLogIdentifierHashKeyBytes = 32

// maxIdentifierLength is the longest email address (RFC 5321), the identifier
// a login names.
const maxIdentifierLength = 254

// NewService creates a new login backoff service using a concrete RedisClient.
func NewService(redisClient *clients.RedisClient, cfg *config.Config, logger *zap.Logger) *Service {
	return NewServiceWithRedis(redisClient, cfg, logger)
}

// NewServiceWithRedis creates a new login backoff service with the given RedisHelper.
// This constructor is intended for testing with mock implementations.
//
// LOG_IDENTIFIER_HASH_KEY is optional: without a usable key the service still
// runs and identifier_hmac is omitted from logs (never an unkeyed hash).
func NewServiceWithRedis(redisClient RedisHelper, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{
		redisClient: redisClient,
		cfg:         cfg,
		logger:      logger,
		hashKey:     logHashKey(cfg.LogIdentifierHashKey, logger),
	}
}

// logHashKey returns the key for identifier_hmac, or nil (field omitted) when
// it is unset or too short, with a warning so the gap is visible at startup.
func logHashKey(key string, logger *zap.Logger) []byte {
	switch {
	case key == "":
		logger.Warn("LOG_IDENTIFIER_HASH_KEY is not set: identifier_hmac is omitted from login-backoff logs")
		return nil
	case len(key) < minLogIdentifierHashKeyBytes:
		logger.Warn("LOG_IDENTIFIER_HASH_KEY is too short and is ignored: identifier_hmac is omitted from login-backoff logs",
			zap.Int("min_bytes", minLogIdentifierHashKeyBytes))
		return nil
	}
	return []byte(key)
}

// CheckAndIncrementResult holds the result of a check-and-increment operation.
type CheckAndIncrementResult struct {
	Allowed bool
	// Uncounted marks an allowed submission that was not counted;
	// RetryAfterSeconds then holds the IP window, for the proxy to quote.
	Uncounted bool
	// Fields populated when allowed
	IdentifierAttempts int64
	IPAttempts         int64
	// Fields populated when blocked
	Reason            string
	Message           string
	RetryAfterSeconds int64
}

// uncounted is the result for a submission let through without being counted.
func (s *Service) uncounted() CheckAndIncrementResult {
	return CheckAndIncrementResult{
		Allowed:           true,
		Uncounted:         true,
		RetryAfterSeconds: int64(s.cfg.LoginBackoffIPLockoutSeconds),
	}
}

// CheckAndIncrement checks and increments login attempt counters.
// Returns allowed=true if under threshold, or blocked details if over threshold.
// Fails open on Redis errors and when there is nothing to count on: the result
// is allowed and Uncounted. The login proxy acts on Uncounted by refusing any
// submission that is not a first step, so a second step is never guessed at
// unbounded while the counter store is down.
func (s *Service) CheckAndIncrement(ctx context.Context, req BeforeLoginRequest, correlationID string) CheckAndIncrementResult {
	identifier := normaliseIdentifier(req.Identifier)
	ip := strings.TrimSpace(req.ClientIP)

	// A longer identifier names no account. It is counted per IP only, so a
	// sender cannot make each submission write a counter key as large as the body.
	if len(identifier) > maxIdentifierLength {
		identifier = ""
	}

	// Neither identifier nor IP provided - fail open
	if identifier == "" && ip == "" {
		s.logger.Warn("before-login request with no identifier or IP, allowing",
			zap.String("correlation_id", correlationID),
			zap.String("flow_id", req.FlowID),
		)
		return s.uncounted()
	}

	log := s.logger.With(s.subjectFields(identifier, ip)...)

	// Both identifier and IP provided
	if identifier != "" && ip != "" {
		return s.incrementBoth(ctx, log, identifier, ip, correlationID)
	}

	// Only identifier provided
	if identifier != "" {
		return s.incrementIdentifierOnly(ctx, log, identifier, correlationID)
	}

	// Only IP provided
	return s.incrementIPOnly(ctx, log, ip, correlationID)
}

func (s *Service) incrementBoth(ctx context.Context, log *zap.Logger, identifier, ip, correlationID string) CheckAndIncrementResult {
	idCount, idRemaining, ipCount, ipRemaining, err := s.redisClient.IncrementLoginAttempts(
		ctx, identifier, ip,
		s.cfg.LoginBackoffIdentifierLockoutSeconds,
		s.cfg.LoginBackoffIPLockoutSeconds,
	)
	if err != nil {
		log.Warn("redis error during login backoff check, failing open",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
		)
		return s.uncounted()
	}

	idLocked := idCount > int64(s.cfg.LoginBackoffMaxIdentifierAttempts)
	ipLocked := ipCount > int64(s.cfg.LoginBackoffMaxIPAttempts)

	if !idLocked && !ipLocked {
		log.Info("login attempt allowed",
			zap.String("correlation_id", correlationID),
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

	log.Warn("login attempt blocked",
		zap.String("correlation_id", correlationID),
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

func (s *Service) incrementIdentifierOnly(ctx context.Context, log *zap.Logger, identifier, correlationID string) CheckAndIncrementResult {
	count, remaining, err := s.redisClient.IncrementIdentifierAttempt(
		ctx, identifier,
		s.cfg.LoginBackoffIdentifierLockoutSeconds,
	)
	if err != nil {
		log.Warn("redis error during identifier backoff check, failing open",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
		)
		return s.uncounted()
	}

	if count > int64(s.cfg.LoginBackoffMaxIdentifierAttempts) {
		log.Warn("login attempt blocked",
			zap.String("correlation_id", correlationID),
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

	log.Info("login attempt allowed",
		zap.String("correlation_id", correlationID),
		zap.Int64("identifier_attempts", count),
		zap.Int("identifier_threshold", s.cfg.LoginBackoffMaxIdentifierAttempts),
	)
	return CheckAndIncrementResult{
		Allowed:            true,
		IdentifierAttempts: count,
	}
}

func (s *Service) incrementIPOnly(ctx context.Context, log *zap.Logger, ip, correlationID string) CheckAndIncrementResult {
	count, remaining, err := s.redisClient.IncrementIPAttempt(
		ctx, ip,
		s.cfg.LoginBackoffIPLockoutSeconds,
	)
	if err != nil {
		log.Warn("redis error during IP backoff check, failing open",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
		)
		return s.uncounted()
	}

	if count > int64(s.cfg.LoginBackoffMaxIPAttempts) {
		log.Warn("login attempt blocked",
			zap.String("correlation_id", correlationID),
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

	log.Info("login attempt allowed",
		zap.String("correlation_id", correlationID),
		zap.Int64("ip_attempts", count),
		zap.Int("ip_threshold", s.cfg.LoginBackoffMaxIPAttempts),
	)
	return CheckAndIncrementResult{
		Allowed:    true,
		IPAttempts: count,
	}
}

// ResetCounters resets the identifier's attempt counter after a successful
// login; the per-IP counter is left to lapse with its window. Fails open on
// errors.
func (s *Service) ResetCounters(ctx context.Context, req AfterLoginRequest, correlationID string) AfterLoginResponse {
	email := normaliseIdentifier(req.Email)

	if email == "" {
		s.logger.Warn("after-login request with no email, skipping reset",
			zap.String("correlation_id", correlationID),
			zap.String("identity_id", req.IdentityID),
		)
		return AfterLoginResponse{
			Status:  StatusSkipped,
			Message: "no identifier or IP provided",
		}
	}

	log := s.logger.With(s.subjectFields(email, strings.TrimSpace(req.ClientIP))...)

	if err := s.redisClient.ResetLoginAttempts(ctx, email); err != nil {
		log.Warn("redis error during identifier counter reset, failing open",
			zap.Error(err),
			zap.String("correlation_id", correlationID),
		)
	} else {
		log.Info("login backoff counters reset",
			zap.String("correlation_id", correlationID),
			zap.String("action", "counters_reset"),
		)
	}

	return AfterLoginResponse{
		Status:  StatusSuccess,
		Message: "counters reset",
	}
}

// subjectFields are the only fields that describe who is logging in: a keyed
// pseudonym of the identifier and the network prefix of the IP, never the raw
// values. Every login log line gets them through logger.With, so no call site
// can log the identifier or IP itself. Empty inputs are omitted.
func (s *Service) subjectFields(identifier, ip string) []zap.Field {
	var fields []zap.Field
	if h := identifierHash(s.hashKey, identifier); h != "" {
		fields = append(fields, zap.String("identifier_hmac", h))
	}
	if p := ipPrefix(ip); p != "" {
		fields = append(fields, zap.String("client_ip_prefix", p))
	}
	return fields
}

// lockoutMessage generates a human-readable lockout message.
func lockoutMessage(reason string, remainingSeconds int64) string {
	minutes := (remainingSeconds + 59) / 60 // round up
	if reason == "ip" {
		return fmt.Sprintf("Too many login attempts from this address. Try again in %d minutes.", minutes)
	}
	return fmt.Sprintf("Account temporarily locked due to too many failed attempts. Try again in %d minutes.", minutes)
}
