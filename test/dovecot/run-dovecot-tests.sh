#!/usr/bin/env bash
set -euo pipefail

# Runs the EmailEngine live IMAP tests against a real IMAP4rev2 server
# (Dovecot 2.4+ in Docker). Opt-in via `npm run test:dovecot` - not part of the
# regular `npm test` run, which stays Docker-free. Needs a local Redis (the
# test database from config/test.toml is flushed, same as the integration
# tier). See README.md in this directory.
#
# Environment overrides:
#   EENGINE_DOVECOT_IMAGE     image to run (default dovecot/dovecot:2.4.4)
#   EENGINE_DOVECOT_PLATFORM  e.g. linux/amd64; defaults to the host platform.
#                             Note: forcing linux/amd64 on Apple Silicon does
#                             not work - Rosetta cannot start Dovecot's
#                             privilege-separated login processes.
#   EENGINE_DOVECOT_PORT      host port to publish (default 31143)

CONTAINER_NAME="emailengine-dovecot-test"
IMAGE="${EENGINE_DOVECOT_IMAGE:-dovecot/dovecot:2.4.4}"
PORT="${EENGINE_DOVECOT_PORT:-31143}"

# Empty unless a platform override was requested; --platform=value keeps it a
# single argument so plain ${PLATFORM_ARG:+...} expansion works under set -u
PLATFORM_ARG="${EENGINE_DOVECOT_PLATFORM:+--platform=$EENGINE_DOVECOT_PLATFORM}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_DIR"

cleanup() {
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

# Guard against a stale image cached for the wrong architecture: `docker run`
# without --platform silently reuses a local image even when its architecture
# does not match the host (e.g. an amd64 image left behind on an arm64 host),
# and Dovecot then fails to start with confusing emulation errors. Only applies
# when no explicit platform override was requested.
if [ -z "${EENGINE_DOVECOT_PLATFORM:-}" ] && docker image inspect "$IMAGE" >/dev/null 2>&1; then
    image_arch="$(docker image inspect --format '{{.Architecture}}' "$IMAGE" 2>/dev/null || true)"
    host_arch="$(docker version --format '{{.Server.Arch}}' 2>/dev/null || true)"
    if [ -n "$image_arch" ] && [ -n "$host_arch" ] && [ "$image_arch" != "$host_arch" ]; then
        echo "Local $IMAGE image is $image_arch but the Docker host is $host_arch - re-pulling for linux/$host_arch..."
        docker pull --platform "linux/$host_arch" "$IMAGE"
    fi
fi

docker run ${PLATFORM_ARG:+"$PLATFORM_ARG"} -d --name "$CONTAINER_NAME" \
    -e USER_PASSWORD=pass \
    -v "$SCRIPT_DIR/dovecot-test.conf:/etc/dovecot/conf.d/99-emailengine-test.conf:ro" \
    -p "127.0.0.1:$PORT:31143" \
    "$IMAGE" >/dev/null

echo "Waiting for Dovecot to accept IMAP connections on port $PORT..."
for i in $(seq 1 30); do
    if node -e "
        const net = require('net');
        const socket = net.connect(Number(process.argv[1]), '127.0.0.1');
        const bail = code => { socket.destroy(); process.exit(code); };
        socket.on('data', chunk => bail(chunk.toString().startsWith('* OK') ? 0 : 1));
        socket.on('error', () => bail(1));
        setTimeout(() => bail(1), 2000);
    " "$PORT" 2>/dev/null; then
        echo "Dovecot is ready"
        break
    fi
    if [ "$i" = 30 ]; then
        echo "Dovecot container did not become ready" >&2
        docker logs "$CONTAINER_NAME" >&2 || true
        exit 1
    fi
    sleep 1
done

# test/run-tests.js does the rest, as for the other tiers: refuses to start when the API port is
# already taken (a leftover test server would silently serve old code), flushes the test database,
# boots the server with the SMTP server and IMAP proxy enabled (test/dovecot/listener-settings.js),
# fails at once if it dies during boot, and runs the tests with the stall watchdog and
# --test-force-exit. The server log goes to a temp file whose tail is printed on failure.
NODE_ENV=test EENGINE_DOVECOT_PORT="$PORT" node test/run-tests.js dovecot
