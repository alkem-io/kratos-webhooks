# Build a static binary on the patched Go maintenance release. Both base pins
# are multi-platform indexes so the native amd64 and arm64 release jobs work.
# Build stage
FROM golang:1.26.10-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /kratos-webhooks ./cmd/server

# Runtime stage
FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

WORKDIR /

COPY --from=builder /kratos-webhooks /kratos-webhooks

# NUMERIC, not the `nonroot:nonroot` name form. The kubelet cannot resolve a
# non-numeric image user, so any Pod setting `runAsNonRoot: true` fails with
# "image has non-numeric user (nonroot), cannot verify user is non-root" and
# the container never starts. 65532 is the UID `nonroot` maps to in distroless.
USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/kratos-webhooks"]
