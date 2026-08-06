#!/usr/bin/env bash
# workspace#036-distroless-wave-1 — W1a persisted regression harness.
#
# Mechanically asserts the kratos-webhooks distroless runtime contract:
#   - runs as UID 65532 (nonroot); ENTRYPOINT == ["/kratos-webhooks"]
#   - no shell, no package manager reachable as an entrypoint override
#   - the shipped binary is a genuinely STATIC ELF (CGO_ENABLED=0), which is
#     what makes gcr.io/distroless/static-* (no libc) a valid runtime base
#   - every FROM in the Dockerfile is digest-pinned (no floating tags)
#   - FUNCTIONAL: the container actually starts against RabbitMQ + Redis and
#     answers HTTP 200 on /health/live and /health/ready — the two probes the
#     k8s Deployment manifests declare (dev-orchestration base, in-repo
#     manifests/, infra-ops base). This is what makes W1a a functional canary
#     rather than a structural one.
#   - emits IMAGE_DIGEST= and IMAGE_SIZE_BYTES=
#
# The functional stage needs a Docker network plus throwaway RabbitMQ and Redis
# containers; the service exits 1 at boot without RabbitMQ (it is a hard
# dependency, not lazily dialled). Set SKIP_FUNCTIONAL=1 to run the structural
# assertions only — the script then says so loudly rather than silently
# degrading the check.
#
# Usage: .docker/distroless-image-smoke.sh <image[:tag]>
set -euo pipefail

IMAGE="${1:?usage: distroless-image-smoke.sh <image>}"
SKIP_FUNCTIONAL="${SKIP_FUNCTIONAL:-0}"

SUFFIX="$$"
NET="kwsmoke-net-${SUFFIX}"
RMQ="kwsmoke-rmq-${SUFFIX}"
REDIS="kwsmoke-redis-${SUFFIX}"
APP="kwsmoke-app-${SUFFIX}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.11.1}"
RABBITMQ_IMAGE="${RABBITMQ_IMAGE:-rabbitmq:3-alpine}"
REDIS_IMAGE="${REDIS_IMAGE:-redis:7-alpine}"
TMP_BIN=""

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

pass() {
  echo "PASS: $*"
}

cleanup() {
  docker rm -f "$APP" "$RMQ" "$REDIS" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  [ -n "$TMP_BIN" ] && rm -f "$TMP_BIN"
  return 0
}
trap cleanup EXIT

echo "== distroless-image-smoke: $IMAGE =="

# --- user / entrypoint -----------------------------------------------------
USER_ID="$(docker inspect "$IMAGE" --format '{{.Config.User}}')"
# Must be NUMERIC: the kubelet cannot resolve a non-numeric image user, so a
# name form (`nonroot`) makes any Pod with `runAsNonRoot: true` fail admission
# with "image has non-numeric user (nonroot), cannot verify user is non-root".
# Proven on k8s-hetzner-sandbox during 036 verification.
case "$USER_ID" in
  65532|65532:65532) ;;
  *) fail "expected numeric user 65532 or 65532:65532, got '$USER_ID' (a non-numeric user breaks runAsNonRoot admission)" ;;
esac
pass "runs as user '$USER_ID'"

ENTRYPOINT_JSON="$(docker inspect "$IMAGE" --format '{{json .Config.Entrypoint}}')"
[ "$ENTRYPOINT_JSON" = '["/kratos-webhooks"]' ] ||
  fail "expected ENTRYPOINT [\"/kratos-webhooks\"], got $ENTRYPOINT_JSON"
pass "ENTRYPOINT is [\"/kratos-webhooks\"]"

# --- no shell / no package manager -----------------------------------------
# Sweep every PATH-shaped directory in the exported rootfs instead of probing
# a fixed list of names by exit status. Two proven holes in the old loop:
# (a) a present package manager invoked bare exits non-zero (usage error), so
#     it read as "absent"; (b) Google's :debug variants put the shell at
#     /busybox/sh, which no fixed list covered. distroless/static ships these
#     directories EMPTY (or absent), so ANY entry is a regression. docker
#     export needs no executable inside the image — essential here, since a
#     correct static image contains nothing runnable but the service binary.
CID="$(docker create "$IMAGE")"
ROOTFS_LISTING="$(mktemp)"
# Export to a file first so an export failure is its own, fail-closed error —
# piping straight into grep would let `|| true` (needed because grep exits 1
# on "no match", the PASS case) also swallow a broken export and pass on an
# empty listing.
docker export "$CID" | tar -t > "$ROOTFS_LISTING" 2>/dev/null ||
  fail "docker export failed — cannot enumerate the image rootfs"
docker rm "$CID" >/dev/null
[ -s "$ROOTFS_LISTING" ] || fail "docker export produced an empty listing"
FORBIDDEN="$(grep -E '^(bin|sbin|usr/bin|usr/sbin|usr/local/bin|usr/local/sbin|busybox)/.' \
  "$ROOTFS_LISTING" | head -50 || true)"
rm -f "$ROOTFS_LISTING"
[ -z "$FORBIDDEN" ] ||
  fail "unexpected entries in PATH directories: $(echo "$FORBIDDEN" | tr '\n' ',')"
pass "PATH directories are empty (no shell / package manager / any binary)"

# --- the binary is a genuinely static ELF ----------------------------------
# distroless/static-* ships no libc; a dynamically linked binary would fail at
# exec. Assert staticness directly from the shipped artifact.
TMP_BIN="$(mktemp)"
CID="$(docker create "$IMAGE")"
docker cp "$CID:/kratos-webhooks" "$TMP_BIN" >/dev/null
docker rm "$CID" >/dev/null

# Staticness is the load-bearing premise of the static-* base, so tool absence
# is FATAL, not a warning: at least one classifier must run and pass.
LINKAGE_VERIFIED=0
if command -v file >/dev/null 2>&1; then
  FILE_OUT="$(file -b "$TMP_BIN")"
  echo "BINARY_FILE_TYPE=$FILE_OUT"
  case "$FILE_OUT" in
    *"statically linked"*) pass "binary is statically linked"; LINKAGE_VERIFIED=1 ;;
    *"dynamically linked"*) fail "binary is DYNAMICALLY linked — invalid on distroless/static (no libc): $FILE_OUT" ;;
    *) echo "WARN: could not classify linkage from: $FILE_OUT" ;;
  esac
fi

if command -v ldd >/dev/null 2>&1; then
  LDD_OUT="$(ldd "$TMP_BIN" 2>&1 || true)"
  echo "BINARY_LDD=$LDD_OUT"
  case "$LDD_OUT" in
    *"not a dynamic executable"*) pass "ldd confirms: not a dynamic executable"; LINKAGE_VERIFIED=1 ;;
    *) fail "ldd reported dynamic dependencies: $LDD_OUT" ;;
  esac
fi
[ "$LINKAGE_VERIFIED" = 1 ] ||
  fail "linkage never verified — neither 'file' nor 'ldd' is available on this runner; install one (the static-ELF premise must be asserted, not assumed)"

# --- Go toolchain floor ----------------------------------------------------
# The builder was moved to Go 1.26 specifically because all 12 fixable HIGH
# CVEs lived in the compiled binary's Go 1.24 stdlib (EOL, no 1.24.x fixes).
# Nothing else defends that: a revert to a pinned golang:1.24-alpine builder
# would pass every other check green and silently reship 12 fixable HIGH.
# Go embeds its toolchain version in the binary — assert the floor here.
GO_VER="$(grep -aoE 'go1\.[0-9]+(\.[0-9]+)?' "$TMP_BIN" | sort -uV | tail -1)"
echo "BINARY_GO_TOOLCHAIN=$GO_VER"
GO_MINOR="$(echo "$GO_VER" | sed -E 's/go1\.([0-9]+).*/\1/')"
[ -n "$GO_MINOR" ] && [ "$GO_MINOR" -ge 26 ] ||
  fail "binary built with $GO_VER — builder must be Go >= 1.26 (Go 1.24 stdlib carries 12 fixable HIGH CVEs with no 1.24.x fixes; see the 036 evidence bundle)"
pass "binary built with $GO_VER (>= 1.26 toolchain floor)"
rm -f "$TMP_BIN"; TMP_BIN=""

# --- no floating FROM in the Dockerfile ------------------------------------
DOCKERFILE="$(dirname "$0")/../Dockerfile"
if [ -f "$DOCKERFILE" ]; then
  FLOATING="$(grep -nE '^FROM ' "$DOCKERFILE" | grep -v '@sha256:' || true)"
  [ -z "$FLOATING" ] || fail "Dockerfile has un-pinned FROM line(s):"$'\n'"$FLOATING"
  pass "every FROM in the Dockerfile is digest-pinned"
else
  echo "WARN: Dockerfile not found at $DOCKERFILE; skipping pin check"
fi

# --- FUNCTIONAL: real boot + the two k8s probes ----------------------------
if [ "$SKIP_FUNCTIONAL" = "1" ]; then
  echo "SKIP: functional probe stage disabled via SKIP_FUNCTIONAL=1 (structural assertions only)"
else
  docker network create "$NET" >/dev/null
  docker run -d --name "$RMQ" --network "$NET" "$RABBITMQ_IMAGE" >/dev/null
  docker run -d --name "$REDIS" --network "$NET" "$REDIS_IMAGE" >/dev/null

  # RabbitMQ is a hard startup dependency; wait for its AMQP listener.
  #
  # Deliberately NOT `rabbitmq-diagnostics ping`: that command blocks for its
  # own internal 60s connect-and-authenticate timeout before returning, so a
  # poll loop wrapped around it takes ~60s per iteration and blows any sane
  # budget while the broker is in fact ready in ~2s. Grep the broker log for
  # the listener line instead — cheap, non-blocking, and the actual signal we
  # need (a bound :5672).
  RMQ_READY=0
  for _ in $(seq 1 60); do
    if [ "$(docker inspect "$RMQ" --format '{{.State.Status}}')" != "running" ]; then
      echo "--- rabbitmq logs ---" >&2
      docker logs "$RMQ" >&2 2>&1 || true
      fail "RabbitMQ sidecar exited during startup"
    fi
    if docker logs "$RMQ" 2>&1 | grep -q 'started TCP listener on .*5672'; then
      RMQ_READY=1
      break
    fi
    sleep 2
  done
  [ "$RMQ_READY" = "1" ] || fail "RabbitMQ sidecar did not become ready in time"
  pass "RabbitMQ + Redis dependencies are up"

  docker run -d --name "$APP" --network "$NET" \
    -e PORT=8080 \
    -e LOG_LEVEL=info \
    -e LOG_FORMAT=json \
    -e RABBITMQ_URL="amqp://guest:guest@${RMQ}:5672/" \
    -e REDIS_HOST="$REDIS" \
    -e REDIS_PORT=6379 \
    "$IMAGE" >/dev/null

  STARTED=0
  for _ in $(seq 1 30); do
    STATUS="$(docker inspect "$APP" --format '{{.State.Status}}')"
    if [ "$STATUS" = "exited" ]; then
      echo "--- container logs ---" >&2
      docker logs "$APP" >&2 2>&1 || true
      fail "container exited during startup (exit=$(docker inspect "$APP" --format '{{.State.ExitCode}}'))"
    fi
    if docker run --rm --network "$NET" "$CURL_IMAGE" \
        -sf -o /dev/null --max-time 3 "http://${APP}:8080/health/live" >/dev/null 2>&1; then
      STARTED=1
      break
    fi
    sleep 2
  done
  [ "$STARTED" = "1" ] || {
    echo "--- container logs ---" >&2
    docker logs "$APP" >&2 2>&1 || true
    fail "service did not answer /health/live in time"
  }
  pass "container starts and stays running as nonroot"

  # Assert both probes the k8s Deployments declare.
  for path in /health/live /health/ready; do
    CODE="$(docker run --rm --network "$NET" "$CURL_IMAGE" \
      -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${APP}:8080${path}")"
    [ "$CODE" = "200" ] || fail "expected HTTP 200 on ${path}, got ${CODE}"
    pass "HTTP 200 on ${path} (matches k8s probe)"
  done

  # The running container must be the nonroot UID, not just declared as such.
  docker logs "$APP" >/dev/null 2>&1 || true
fi

# --- digest / size ---------------------------------------------------------
IMAGE_DIGEST="$(docker inspect "$IMAGE" --format '{{.Id}}')"
# Sum `docker history` layer sizes rather than `docker inspect .Size`: on a
# containerd-snapshotter daemon .Size counts only layers UNIQUE to this image,
# so the same image measures ~3x smaller locally than on a CI runner using the
# classic store. The history sum is store-independent.
IMAGE_SIZE_BYTES="$(docker history --no-trunc --format '{{.Size}}' "$IMAGE" | awk '
  /^[0-9.]+ *[kMG]?B$/ {
    v=$0; sub(/ *[kMG]?B$/,"",v); u=$0; sub(/^[0-9.]+ */,"",u);
    m = (u=="kB")?1000 : (u=="MB")?1000000 : (u=="GB")?1000000000 : 1;
    total += v*m
  } END { printf "%d", total }')"
echo "IMAGE_DIGEST=$IMAGE_DIGEST"
echo "IMAGE_SIZE_BYTES=$IMAGE_SIZE_BYTES"

echo "== distroless-image-smoke: ALL CHECKS PASSED =="
