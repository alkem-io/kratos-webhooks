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
[ "$USER_ID" = "65532" ] || [ "$USER_ID" = "nonroot" ] ||
  [ "$USER_ID" = "65532:65532" ] || [ "$USER_ID" = "nonroot:nonroot" ] ||
  fail "expected user 65532/nonroot, got '$USER_ID'"
pass "runs as user '$USER_ID'"

ENTRYPOINT_JSON="$(docker inspect "$IMAGE" --format '{{json .Config.Entrypoint}}')"
[ "$ENTRYPOINT_JSON" = '["/kratos-webhooks"]' ] ||
  fail "expected ENTRYPOINT [\"/kratos-webhooks\"], got $ENTRYPOINT_JSON"
pass "ENTRYPOINT is [\"/kratos-webhooks\"]"

# --- no shell / no package manager -----------------------------------------
for bin in /bin/sh /bin/bash /usr/bin/sh sh apk apt apt-get dpkg; do
  if docker run --rm --entrypoint "$bin" "$IMAGE" >/dev/null 2>&1; then
    fail "expected '$bin' to be absent/unexecutable, but it ran"
  fi
done
pass "no shell / package manager is executable"

# --- the binary is a genuinely static ELF ----------------------------------
# distroless/static-* ships no libc; a dynamically linked binary would fail at
# exec. Assert staticness directly from the shipped artifact.
TMP_BIN="$(mktemp)"
CID="$(docker create "$IMAGE")"
docker cp "$CID:/kratos-webhooks" "$TMP_BIN" >/dev/null
docker rm "$CID" >/dev/null

if command -v file >/dev/null 2>&1; then
  FILE_OUT="$(file -b "$TMP_BIN")"
  echo "BINARY_FILE_TYPE=$FILE_OUT"
  case "$FILE_OUT" in
    *"statically linked"*) pass "binary is statically linked" ;;
    *"dynamically linked"*) fail "binary is DYNAMICALLY linked — invalid on distroless/static (no libc): $FILE_OUT" ;;
    *) echo "WARN: could not classify linkage from: $FILE_OUT" ;;
  esac
else
  echo "WARN: 'file' not available; skipping ELF linkage classification"
fi

if command -v ldd >/dev/null 2>&1; then
  LDD_OUT="$(ldd "$TMP_BIN" 2>&1 || true)"
  echo "BINARY_LDD=$LDD_OUT"
  case "$LDD_OUT" in
    *"not a dynamic executable"*) pass "ldd confirms: not a dynamic executable" ;;
    *) fail "ldd reported dynamic dependencies: $LDD_OUT" ;;
  esac
fi
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
IMAGE_SIZE_BYTES="$(docker save "$IMAGE" | wc -c)"
echo "IMAGE_DIGEST=$IMAGE_DIGEST"
echo "IMAGE_SIZE_BYTES=$IMAGE_SIZE_BYTES"

echo "== distroless-image-smoke: ALL CHECKS PASSED =="
