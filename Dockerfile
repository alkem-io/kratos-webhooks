###############################################################################
# workspace#036-distroless-wave-1 — W1a (canary)
#
# Two-stage build producing a distroless, non-root runtime image:
#   1. builder — golang alpine; CGO_ENABLED=0 so the output is a genuinely
#                static ELF ("statically linked" / "not a dynamic executable").
#                Because nothing dynamic links against the builder's musl libc,
#                the builder's libc is irrelevant to the runtime.
#   2. runtime — gcr.io/distroless/static-debian13:nonroot: CA certificates and
#                tzdata only. No shell, no package manager, no libc consumer.
#
# Base images are pinned by digest (resolved via
# `docker buildx imagetools inspect <image>:<tag>`). Re-resolve and update both
# the tag *and* the digest together when bumping — the digests below were
# resolved 2026-08-05 and drift as upstream republishes the moving tags.
#
# This repo builds linux/amd64 AND linux/arm64 (build-release-docker-hub.yml
# runs a native-runner matrix: ubuntu-latest + ubuntu-24.04-arm). Both pins
# below are therefore TOP-LEVEL MANIFEST-LIST (OCI index) digests, verified to
# list both architectures. Pinning a per-architecture child digest would build
# on amd64 and break the arm64 runner.
#
#   golang:1.26-alpine   (OCI index; linux/amd64 + linux/arm64/v8 + others)
#     digest: sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2
#   gcr.io/distroless/static-debian13:nonroot   (OCI index; amd64 + arm64/v8 + others)
#     digest: sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
#
# Go toolchain note (deviation from the task's "two edits only"): the wave gate
# is ZERO FIXABLE HIGH/CRITICAL on the after-image. Trivy on the pre-change
# image reports the Debian 12 base with 0 OS vulnerabilities and 12 fixable
# HIGH entirely inside the compiled binary's Go stdlib (1.24.13) — the Go 1.24
# branch is EOL and NONE of those 12 advisories list a 1.24.x fixed version, so
# the debian12 -> debian13 swap alone cannot clear the gate. Building on the
# golang 1.26 toolchain rebuilds that stdlib and takes the image to 0/0.
# go.mod still declares `go 1.24` (the language level is unchanged); only the
# compiling toolchain moves.
#
# Verified: `go build`, `go vet` and `go test ./...` all pass on go1.26.5, and
# the resulting image answers HTTP 200 on /health/live and /health/ready — the
# two probes the k8s manifests declare.
###############################################################################

# Build stage
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

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

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/kratos-webhooks"]
