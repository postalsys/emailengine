#!/bin/bash

set -e

export EENGINE_PORT=5678

# Keep the deprecated Document Store endpoints in the generated spec; they are only
# registered when the feature is enabled.
export EENGINE_DOCUMENT_STORE_ENABLED=true

# refuse to run if something is already listening on the port, otherwise the
# polling loop below would silently fetch swagger.json from a stale instance
if (exec 3<>"/dev/tcp/127.0.0.1/${EENGINE_PORT}") 2>/dev/null; then
    echo "Port ${EENGINE_PORT} is already in use" >&2
    exit 1
fi

node server.js > /dev/null 2>&1 &
SERVER_PID=$!

cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# poll until the API is up instead of relying on a fixed sleep
rm -f swagger.json.tmp
for i in $(seq 1 60); do
    if curl -fs --max-time 5 "http://127.0.0.1:${EENGINE_PORT}/swagger.json" -o swagger.json.tmp; then
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "Server exited before swagger.json could be fetched" >&2
        exit 1
    fi
    sleep 1
done

if [ ! -s swagger.json.tmp ]; then
    echo "Timed out waiting for swagger.json" >&2
    exit 1
fi

# only replace swagger.json if the download parses as JSON
node -e 'JSON.parse(require("fs").readFileSync("swagger.json.tmp", "utf-8"))'

mv swagger.json.tmp swagger.json
