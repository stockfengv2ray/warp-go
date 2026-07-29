#!/bin/sh
set -e

# warp-go stores registration in the working directory as reg.json.
# Volume is mounted at /data; STATE_FILE env overrides the default.
STATE_FILE="${STATE_FILE:-/data/reg.json}"
WORK_DIR="/app"

if [ ! -f "$STATE_FILE" ]; then
    echo "[entrypoint] No registration found at $STATE_FILE, registering..."
    cd "$WORK_DIR"
    /app/warp -reg
    if [ -f "$WORK_DIR/reg.json" ]; then
        mkdir -p "$(dirname "$STATE_FILE")"
        mv "$WORK_DIR/reg.json" "$STATE_FILE"
        echo "[entrypoint] Registration saved to $STATE_FILE"
    else
        echo "[entrypoint] ERROR: -reg did not produce reg.json"
        exit 1
    fi
else
    echo "[entrypoint] Registration found at $STATE_FILE"
fi

cp "$STATE_FILE" "$WORK_DIR/reg.json"

set -- /app/warp \
    -l "${SOCKS_LISTEN:-0.0.0.0:40000}" \
    -ip "${WARP_EDGE:-4}" \
    -transport "${WARP_TRANSPORT:-h2}"
if [ -n "${SOCKS_USER:-}" ] && [ -n "${SOCKS_PASS:-}" ]; then
    set -- "$@" -user "$SOCKS_USER" -pass "$SOCKS_PASS"
fi
case "${WARP_SELF_TEST:-1}" in
    1|true|TRUE|yes|YES) set -- "$@" -self-test ;;
esac

echo "[entrypoint] Starting warp-go SOCKS5 proxy (transport=${WARP_TRANSPORT:-h2})..."
exec "$@"
