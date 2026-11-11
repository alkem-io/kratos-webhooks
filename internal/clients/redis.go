// Package clients provides wrappers for external service clients.
package clients

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// WelcomeSentTTL is the TTL for welcome_sent keys (90 days).
	WelcomeSentTTL = 90 * 24 * time.Hour

	// LoginBackoffIdentifierPrefix is the Redis key prefix for per-identifier login attempt counters.
	LoginBackoffIdentifierPrefix = "login_backoff:id:"

	// LoginBackoffIPPrefix is the Redis key prefix for per-IP login attempt counters.
	LoginBackoffIPPrefix = "login_backoff:ip:"
)

// loginBackoffSingleKeyScript atomically increments a counter and sets TTL on first increment.
// Returns {count, remaining_ttl}.
var loginBackoffSingleKeyScript = redis.NewScript(`
local key = KEYS[1]
local ttl_seconds = tonumber(ARGV[1])
local count = redis.call('INCR', key)
if count == 1 then
    redis.call('EXPIRE', key, ttl_seconds)
end
local remaining = redis.call('TTL', key)
return {count, remaining}
`)

// loginBackoffTwoKeyScript atomically increments both identifier and IP counters.
// Returns {id_count, id_remaining, ip_count, ip_remaining}.
var loginBackoffTwoKeyScript = redis.NewScript(`
local id_key = KEYS[1]
local ip_key = KEYS[2]
local id_ttl = tonumber(ARGV[1])
local ip_ttl = tonumber(ARGV[2])

local id_count = redis.call('INCR', id_key)
if id_count == 1 then
    redis.call('EXPIRE', id_key, id_ttl)
end
local id_remaining = redis.call('TTL', id_key)

local ip_count = redis.call('INCR', ip_key)
if ip_count == 1 then
    redis.call('EXPIRE', ip_key, ip_ttl)
end
local ip_remaining = redis.call('TTL', ip_key)

return {id_count, id_remaining, ip_count, ip_remaining}
`)

// RedisClient wraps the Redis client with application-specific operations.
type RedisClient struct {
	client *redis.Client
}

// NewRedisClient creates a new Redis client from the connection URL.
func NewRedisClient(url string) (*RedisClient, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("failed to parse redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	return &RedisClient{client: client}, nil
}

// Ping checks connectivity to Redis.
func (c *RedisClient) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Close closes the Redis connection.
func (c *RedisClient) Close() error {
	return c.client.Close()
}

// IsWelcomeSent checks if the welcome_sent key exists for an identity.
// Returns true if already sent, false if not.
func (c *RedisClient) IsWelcomeSent(ctx context.Context, identityID string) (bool, error) {
	key := fmt.Sprintf("welcome_sent:%s", identityID)
	exists, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check welcome_sent key: %w", err)
	}
	return exists > 0, nil
}

// MarkWelcomeSent sets the welcome_sent key for an identity with TTL.
func (c *RedisClient) MarkWelcomeSent(ctx context.Context, identityID string) error {
	key := fmt.Sprintf("welcome_sent:%s", identityID)
	value := time.Now().UTC().Format(time.RFC3339)
	return c.client.Set(ctx, key, value, WelcomeSentTTL).Err()
}

// IncrementLoginAttempts atomically increments both identifier and IP login attempt counters.
// Returns (idCount, idRemaining, ipCount, ipRemaining, error).
func (c *RedisClient) IncrementLoginAttempts(ctx context.Context, identifier, ip string, idTTLSeconds, ipTTLSeconds int) (int64, int64, int64, int64, error) {
	idKey := LoginBackoffIdentifierPrefix + identifier
	ipKey := LoginBackoffIPPrefix + ip

	result, err := loginBackoffTwoKeyScript.Run(ctx, c.client,
		[]string{idKey, ipKey},
		idTTLSeconds, ipTTLSeconds,
	).Int64Slice()
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("failed to increment login attempts: %w", err)
	}

	return result[0], result[1], result[2], result[3], nil
}

// IncrementIdentifierAttempt atomically increments the identifier login attempt counter.
// Returns (count, remaining, error).
func (c *RedisClient) IncrementIdentifierAttempt(ctx context.Context, identifier string, ttlSeconds int) (int64, int64, error) {
	key := LoginBackoffIdentifierPrefix + identifier

	result, err := loginBackoffSingleKeyScript.Run(ctx, c.client,
		[]string{key},
		ttlSeconds,
	).Int64Slice()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to increment identifier attempt: %w", err)
	}

	return result[0], result[1], nil
}

// IncrementIPAttempt atomically increments the IP login attempt counter.
// Returns (count, remaining, error).
func (c *RedisClient) IncrementIPAttempt(ctx context.Context, ip string, ttlSeconds int) (int64, int64, error) {
	key := LoginBackoffIPPrefix + ip

	result, err := loginBackoffSingleKeyScript.Run(ctx, c.client,
		[]string{key},
		ttlSeconds,
	).Int64Slice()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to increment IP attempt: %w", err)
	}

	return result[0], result[1], nil
}

// ResetLoginAttempts deletes the identifier login attempt counter. A per-IP
// counter is never deleted; it lapses with its window. An empty identifier is
// skipped to avoid deleting the bare prefix key.
func (c *RedisClient) ResetLoginAttempts(ctx context.Context, identifier string) error {
	if identifier == "" {
		return nil
	}
	return c.client.Del(ctx, LoginBackoffIdentifierPrefix+identifier).Err()
}
