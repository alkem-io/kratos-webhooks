# Alkemio Kratos Webhooks

A Go HTTP service that receives webhooks from Ory Kratos and bridges them into the Alkemio platform's notification infrastructure. Handles post-verification welcome notifications, password-change observability, and login brute-force protection.

## Architecture

```
Ory Kratos ──POST──▶ Kratos Webhooks ──publish──▶ RabbitMQ (alkemio-notifications)
                           │              └─────▶ RabbitMQ (alkemio-kratos-events)
                           ├── Redis (idempotency + login rate limiting)
                           └── Structured logging (Zap)
```

Password-change events publish to a **dedicated** durable queue
`alkemio-kratos-events` (consumed by the server via `@nestjs/microservices`),
kept separate from `alkemio-notifications` so the two consumers do not steal
each other's messages.

The service follows **fail-open semantics**: webhook responses return HTTP 200 to avoid blocking Kratos flows, regardless of downstream failures. The login backoff endpoints are the exception — they return HTTP 403 when an account or IP is locked out.

## Project Structure

```
cmd/
  server/                                # Application entrypoint
configs/
  .env.example                           # Example environment variables
contracts/
  openapi.yaml                           # OpenAPI 3.0 specification
internal/
  clients/                               # Redis and RabbitMQ client wrappers
  config/                                # Configuration loading and logger setup
  health/                                # Kubernetes liveness and readiness probes
  middleware/                             # Correlation ID, logging, maintenance mode
  webhooks/
    kratos-verification/                 # Post-verification webhook handler
    kratos-password-changed/             # Post-password-change → broker event
    kratos-login-backoff/                # Login brute-force protection
manifests/                               # Kubernetes deployment manifests
```

## Prerequisites

- Go 1.24+
- Redis
- RabbitMQ
- Docker (optional)

## Getting Started

1. Clone the repository and install dependencies:

```bash
git clone https://github.com/alkem-io/kratos-webhooks.git
cd kratos-webhooks
go mod download
```

2. Copy the example config and adjust values:

```bash
cp configs/.env.example .env
```

3. Run the server:

```bash
make run
```

## Configuration

All configuration is driven by environment variables. See `configs/.env.example` for defaults.

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP server port |
| `LOG_LEVEL` | `info` | Logging level (`debug`, `info`, `warn`, `error`) |
| `LOG_FORMAT` | `json` | Log format (`json` or `console`) |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string (takes precedence over host/port) |
| `RABBITMQ_URL` | `amqp://guest:guest@localhost:5672/` | RabbitMQ connection string |
| `PLATFORM_URL` | `https://alkem.io` | Base Alkemio platform URL |
| `MAINTENANCE_MODE` | `false` | Enable maintenance mode (returns 503) |
| `MAINTENANCE_MESSAGE` | `Service under maintenance` | Maintenance response message |
| `CORRELATION_ID_HEADER` | `X-Request-ID` | HTTP header used for request tracing |
| `LOGIN_BACKOFF_MAX_IDENTIFIER_ATTEMPTS` | `10` | Failed login attempts before per-identifier lockout |
| `LOGIN_BACKOFF_MAX_IP_ATTEMPTS` | `20` | Login submissions from one IP inside the window before that IP is locked out. Successful submissions count too (a two-step sign-in is two), and a successful login never resets this counter |
| `LOGIN_BACKOFF_IDENTIFIER_LOCKOUT_SECONDS` | `120` | Lockout duration per identifier |
| `LOGIN_BACKOFF_IP_LOCKOUT_SECONDS` | `120` | Length of the per-IP window: the counter lapses when it ends, and an IP locked out stays locked until then |
| `LOG_IDENTIFIER_HASH_KEY` | _(empty)_ | Secret key (≥ 32 bytes, surrounding whitespace trimmed) for pseudonymising login identifiers in logs: `identifier_hmac` = first 16 hex of HMAC-SHA256 over `lower(trim(identifier))` (Go `strings.ToLower(strings.TrimSpace(x))`). Unset or shorter than 32 bytes: the service runs, logs a warning at startup, and omits `identifier_hmac`. Raw identifiers and full client IPs are never logged; IPs appear only as a network prefix (`client_ip_prefix`, /24 for IPv4, /32 for IPv6) |

## API Endpoints

### Webhooks

**POST** `/api/v1/webhooks/kratos/verification`

Receives Kratos post-verification payloads. Always returns HTTP 200.

```json
// Request
{
  "identity_id": "uuid",
  "email": "user@example.com",
  "display_name": "Jane Doe",
  "first_name": "Jane"
}

// Response
{
  "status": "success|skipped|error",
  "message": "optional explanation"
}
```

**POST** `/api/v1/webhooks/kratos/password-changed`

Receives the Kratos `settings.after.password` hook when a user changes their
password, and publishes a `USER_PASSWORD_CHANGED` event onto the dedicated
`alkemio-kratos-events` queue for the server to consume. Only `identity_id` is
required; `observed_at` defaults to publish-time `now()` (UTC) when absent.
Always returns HTTP 200 (fail-open). No application-layer auth — in-cluster
trust only (see the handler comment, FR-007).

```json
// Request
{
  "identity_id": "uuid",
  "flow_id": "uuid",
  "observed_at": "2026-06-01T10:30:45Z",
  "client_ip": "203.0.113.7",
  "user_agent": "Mozilla/5.0"
}

// Response
{
  "status": "success|skipped|error",
  "message": "optional explanation"
}
```

The published broker message follows
[`../agents-hq/specs/005-kratos-password-changed-queue/contracts/password-changed-event.md`](https://github.com/alkem-io)
(the cross-repo `USER_PASSWORD_CHANGED` contract).

**POST** `/api/v1/webhooks/kratos/second-factor-changed?method=<totp|webauthn|lookup_secret>`

Called by the Kratos `settings.after.totp`, `settings.after.webauthn` and
`settings.after.lookup_secret` hooks when a member enrols or removes a second
factor. Takes the password-changed request body above; the factor travels in
the `method` query parameter. Publishes a `USER_SECOND_FACTOR_CHANGED` event —
the password event's shape plus `"method": "totp|webauthn|lookup_secret"` —
onto the same `alkemio-kratos-events` queue. A missing or other `method`, invalid
JSON or a missing `identity_id` is `skipped`; a failed publish is `error`.
Always returns HTTP 200 (fail-open). In-cluster trust only, like the
password-changed route. This build must be live on an environment before that
environment's Kratos values name the route; until then the hooks get a `404`,
which Kratos ignores.

### Login Backoff

**POST** `/api/v1/webhooks/kratos/login-backoff/before-login`

Checks whether a login attempt should be allowed based on per-identifier and per-IP rate limits.

Returns HTTP 200 if allowed:

```json
// Request
{
  "flow_id": "uuid",
  "identifier": "user@example.com",
  "client_ip": "192.168.1.100"
}

// Response (allowed)
{
  "status": "allowed",
  "identifier_attempts": 2,
  "ip_attempts": 5
}
```

Returns HTTP 403 if locked out:

```json
{
  "status": "blocked",
  "reason": "identifier_locked|ip_locked",
  "retry_after_seconds": 120
}
```

**POST** `/api/v1/webhooks/kratos/login-backoff/after-login`

Resets the identifier's attempt counter after a successful login. The per-IP
counter is never reset: it lapses with its window, so a successful login cannot
reopen its address's budget. `client_ip` is accepted and used only for the
logged network prefix. Always returns HTTP 200.

```json
// Request
{
  "identity_id": "uuid",
  "email": "user@example.com",
  "client_ip": "192.168.1.100"
}
```

### Login Proxy

**POST** `/self-service/login`

Reverse proxy that intercepts login submissions to Kratos, enabling pre-login backoff checks inline with the login flow. Only `POST` submissions are counted.

The address it counts is the first valid entry of `X-Forwarded-For` as the edge
delivers it, else the connection's remote address — never an inbound
`True-Client-Ip` or `X-Real-Ip`, which a sender sets freely. It always overwrites
`True-Client-Ip` toward Kratos with that address (removing it when there is
none), so the after-login hook sees what was counted. The per-IP bound therefore
holds only if the edge does not pass a sender's own `X-Forwarded-For` chain
through.

When the proxy cannot count a submission (Redis error), it reads the body's
`method` from the one parse the media type names, as Kratos does: a form for
`application/x-www-form-urlencoded`, JSON for `application/json`, nothing for
any other type (a `multipart/form-data` body is not read). The body must carry
exactly one member named `method`, spelt in lower case; `password`, `passkey`
or `oidc` — a first step — is forwarded
uncounted, with the warning `redis error during … backoff check, failing open`
that an environment alerts on. Any other method, a second step
(`totp`, `webauthn`, `lookup_secret`) or a body with no readable method
(none, several, another letter case, another media type) included, is answered as a locked address is: a browser is redirected to
`/login?lockout=true&retry_after=<LOGIN_BACKOFF_IP_LOCKOUT_SECONDS>`, an API
client gets `429` with `error.reason` `unavailable`. While that warning fires,
no member with a second factor completes a sign-in. A request body that cannot
be read to its end is answered `400`.

### Health

| Endpoint | Method | Purpose |
|---|---|---|
| `/health/live` | GET | Kubernetes liveness probe (always 200) |
| `/health/ready` | GET | Kubernetes readiness probe (checks Redis and RabbitMQ) |

## Make Targets

```bash
make build          # Compile binary to ./bin/kratos-webhooks
make test           # Run tests with race detector
make lint           # Run golangci-lint
make run            # Run the server locally
make clean          # Remove build artifacts
make tidy           # Run go mod tidy
make docker-build   # Build Docker image
make docker-run     # Run Docker container
```

## Docker

The project uses a multi-stage build with a distroless runtime image for minimal attack surface:

```bash
make docker-build
make docker-run
```

The container runs as a non-root user and exposes port 8080.

## Middleware Stack

Applied in order:

1. **Correlation ID** — Extracts or generates a request trace ID
2. **Maintenance** — Returns 503 when maintenance mode is enabled (health endpoints are exempt)
3. **Logging** — Records request method, path, status code, and duration

## License

See [LICENSE](LICENSE) for details.
