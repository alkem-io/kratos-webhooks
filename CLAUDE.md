# kratos-webhooks Development Guidelines

> **Workspace context.** This repo is part of the Alkemio polyrepo at
> [alkem-io/agents-hq](https://github.com/alkem-io/agents-hq).
> Cross-repo (vertical) feature specs live there under `specs/NNN-*/`. When
> working on a `feat/NNN-...` branch in this repo, the matching workspace
> spec is the single source of truth.

Auto-generated from all feature plans. Last updated: 2026-01-26

## Active Technologies
- Go 1.24 + go.uber.org/zap (logging), github.com/redis/go-redis/v9 (Redis) - both existing, no new dependencies (002-login-backoff)
- Redis (existing client in `internal/clients/redis.go`) (002-login-backoff)

- Go 1.24 + go.uber.org/zap (logging), github.com/redis/go-redis/v9 (Redis), github.com/rabbitmq/amqp091-go (RabbitMQ), github.com/joho/godotenv (config) (001-kratos-verification-webhook)

## Project Structure

```text
cmd/
  server/          # Application entrypoint
configs/           # Environment config examples
contracts/         # OpenAPI specs
internal/
  config/          # Configuration loading
  health/          # Health check handlers
  middleware/      # HTTP middleware
  clients/         # Redis and RabbitMQ clients
  webhooks/        # Webhook handlers
```

## Commands

```bash
make build        # Build the binary
make test         # Run tests with race detector
make lint         # Run golangci-lint
make run          # Run the server locally
make docker-build # Build Docker image
make docker-run   # Run Docker container
make tidy         # Run go mod tidy
```

## Code Style

Go 1.24: Follow standard conventions

## Recent Changes
- 002-login-backoff: Uses Go 1.24 + go.uber.org/zap (logging) and github.com/redis/go-redis/v9 (Redis); no new dependencies introduced

- 001-kratos-verification-webhook: Added Go 1.24 + go.uber.org/zap (logging), github.com/redis/go-redis/v9 (Redis), github.com/rabbitmq/amqp091-go (RabbitMQ), github.com/joho/godotenv (config)

<!-- MANUAL ADDITIONS START -->

## Agent Guidelines

See [AGENTS.md](./AGENTS.md) for core engineering principles and patterns that all AI agents must follow.

<!-- MANUAL ADDITIONS END -->
