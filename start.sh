#!/bin/bash
# Boot code-server for OpenHost.
#
# Topology:
#
#   browser → OpenHost outer Caddy (TLS termination)
#          → OpenHost router (subdomain vscode.<zone>, JWT-verifies
#                              and stamps X-OpenHost-Is-Owner)
#          → container :8080  (auth_proxy.py — auto-login sidecar)
#          → 127.0.0.1:8082   (code-server)
#
# Auth flow on first owner visit:
#
#   1. Owner browses vscode.<zone>/.  OpenHost router stamps
#      X-OpenHost-Is-Owner; forwards to :8080.
#   2. auth_proxy.py sees the header AND no
#      code-server-session cookie; reads the persisted password
#      and POSTs it to 127.0.0.1:8082/login.
#   3. code-server returns 302 + Set-Cookie:
#      code-server-session=<hash>.
#   4. auth_proxy.py 302's the browser back to the original URL
#      with that cookie attached.
#   5. Browser follows; subsequent requests carry the cookie and
#      pass through verbatim, including the WebSocket upgrade for
#      terminal / LSP traffic.
#
# Bootstrap:
#
#   * code-server's password is configured via $PASSWORD env var
#     (auth=password mode).  We generate a strong random one on
#     first boot and persist it to
#     $OPENHOST_APP_DATA_DIR/admin-credentials.txt.
#
# We use bash specifically (not /bin/sh) for `wait -n` and
# `[[ ... ]]`.

set -euo pipefail

PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/vscode}"
TEMP="${OPENHOST_APP_TEMP_DIR:-/tmp}"

# Persistent dirs.  code-server's --user-data-dir holds extensions
# + per-user settings; --extensions-dir is part of that surface.
# --config is a file path, not a dir.  workspace/ is the default
# folder shown in the tree on first launch.
CONFIG_DIR="$PERSIST/config"
DATA_DIR="$PERSIST/data"
EXTENSIONS_DIR="$PERSIST/extensions"
WORKSPACE_DIR="$PERSIST/workspace"
CRED_FILE="$PERSIST/admin-credentials.txt"

mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$EXTENSIONS_DIR" "$WORKSPACE_DIR"

# code-server's upstream image runs as user `coder` (uid 1000).
# Rootless podman uses uid remapping, so chown'ing to 1000 inside
# the container maps to a different uid outside — but inside the
# container it's still 1000, which is what code-server cares about.
chown -R 1000:1000 "$PERSIST" 2>/dev/null || true

# -----------------------------------------------------------------
# Generate / load password
# -----------------------------------------------------------------

if [[ ! -f "$CRED_FILE" ]]; then
    echo "[start.sh] First boot: generating code-server password"
    NEW_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)"
    umask 077
    cat > "$CRED_FILE" <<EOF
# code-server password, auto-generated on first boot.
# Used by auth_proxy.py to mint owner sessions on demand.
# Anyone who can read this file can log in to code-server (which
# means full RCE inside the container as user 'coder').
#
# To rotate: delete this file, restart the container; start.sh
# regenerates a fresh password.  Existing browser sessions
# (cookies on the device) survive rotation until they expire.
export VSCODE_PASSWORD='$NEW_PASSWORD'
EOF
    umask 022
    chown 1000:1000 "$CRED_FILE" 2>/dev/null || true
fi

# shellcheck disable=SC1090
source "$CRED_FILE"
export PASSWORD="$VSCODE_PASSWORD"

# -----------------------------------------------------------------
# code-server config
# -----------------------------------------------------------------
#
# Use --config so we can pin the bind address + auth method
# explicitly rather than relying on env vars only.  The config
# file lives under the persistent dir for transparency.
#
# bind-addr=127.0.0.1:8082 — loopback only; the auth-proxy is
#                            the only thing that talks to it.
# auth=password           — accept the $PASSWORD env var.
# cert=false              — TLS terminates at OpenHost's outer
#                            Caddy, not here.
CODE_CONFIG="$CONFIG_DIR/config.yaml"
cat > "$CODE_CONFIG" <<EOF
bind-addr: 127.0.0.1:8082
auth: password
cert: false
disable-telemetry: true
disable-update-check: true
EOF
chown 1000:1000 "$CODE_CONFIG" 2>/dev/null || true

# -----------------------------------------------------------------
# Launch code-server
# -----------------------------------------------------------------
#
# Run as the upstream `coder` user (uid 1000).  No gosu in the
# upstream image; use su.  --user-data-dir / --extensions-dir
# point at the persistent paths so extensions and settings survive
# container restarts.
echo "[start.sh] Starting code-server on 127.0.0.1:8082 (workspace=$WORKSPACE_DIR)"

# code-server reads $PASSWORD from the environment.  Pass through
# explicitly via su -c so it survives the privilege drop.
# HOME has to be set so code-server's --user-data-dir defaults
# play nicely if any code path falls through to it.
export HOME=/home/coder
su -s /bin/bash coder -c "PASSWORD='$PASSWORD' HOME=/home/coder /usr/bin/code-server \
    --config '$CODE_CONFIG' \
    --user-data-dir '$DATA_DIR' \
    --extensions-dir '$EXTENSIONS_DIR' \
    '$WORKSPACE_DIR'" &
CODE_PID=$!

# -----------------------------------------------------------------
# Launch auth-proxy
# -----------------------------------------------------------------

echo "[start.sh] Starting auth-proxy on 0.0.0.0:8080 -> 127.0.0.1:8082"
export AUTH_PROXY_LISTEN_PORT="${AUTH_PROXY_LISTEN_PORT:-8080}"
export AUTH_PROXY_UPSTREAM_HOST="127.0.0.1"
export AUTH_PROXY_UPSTREAM_PORT="8082"
export AUTH_PROXY_CRED_FILE="$CRED_FILE"
python3 /opt/openhost-vscode/auth_proxy.py &
PROXY_PID=$!

# Wait for code-server to bind its port.
for _ in $(seq 1 60); do
    if python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(0.5)
sys.exit(0 if s.connect_ex(('127.0.0.1', 8082)) == 0 else 1)
" 2>/dev/null; then
        echo "[start.sh] code-server is listening"
        break
    fi
    if ! kill -0 "$CODE_PID" 2>/dev/null; then
        wait "$CODE_PID" || true
        echo "[start.sh] code-server exited before binding 8082"
        exit 1
    fi
    sleep 1
done

# -----------------------------------------------------------------
# Supervision
# -----------------------------------------------------------------

trap 'kill -TERM "$CODE_PID" "$PROXY_PID" 2>/dev/null; wait' TERM INT

set +e
wait -n "$CODE_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] Child exited (code=$EXIT_CODE); shutting down"
kill -TERM "$CODE_PID" "$PROXY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
