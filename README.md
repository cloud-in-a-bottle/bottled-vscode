# openhost-vscode

[code-server](https://github.com/coder/code-server) (VS Code in the browser) packaged for OpenHost, with one-click SSO so the zone owner is auto-logged-in to a full VS Code workspace without ever seeing code-server's native password prompt.

Deploy this on your zone and you get:

- A **VS Code editor** at `https://vscode.<your-zone>/` (auto-logged-in via OpenHost SSO; only the zone owner can reach it).
- A persistent **workspace** at `$OPENHOST_APP_DATA_DIR/workspace/` — files survive container restarts and redeploys.
- Persistent **extensions and settings** under `$OPENHOST_APP_DATA_DIR/data/` and `$OPENHOST_APP_DATA_DIR/extensions/`.

## How auth works

Pattern B (auto-login sidecar):

1. Browser hits `https://vscode.<zone>/`. The OpenHost router verifies the owner's `zone_auth` cookie and stamps `X-OpenHost-Is-Owner: true` on the request.
2. `auth_proxy.py` (sidecar inside the container) sees the header AND no `code-server-session` cookie; reads the persisted password from `$OPENHOST_APP_DATA_DIR/admin-credentials.txt`, POSTs `password=<pw>` to code-server's `/login`, captures the resulting `Set-Cookie: code-server-session=<hash>`.
3. The sidecar 302's the browser back to its original URL with the cookie set.
4. From then on the cookie is sent on every request and the sidecar is a near-pass-through. WebSocket upgrades for the terminal / LSP traffic are forwarded bidirectionally.

The sidecar always strips client-supplied `X-OpenHost-Is-Owner` and `X-OpenHost-User` headers before forwarding upstream — defence in depth.

## Filesystem layout (inside the container)

```
$OPENHOST_APP_DATA_DIR/                # /data/app_data/vscode/
  config/
    config.yaml                        # code-server config (auth=password,
                                       # bind-addr=127.0.0.1:8082).
  data/                                # VS Code user data: history,
                                       # workspace state, IndexedDB.
  extensions/                          # Installed extensions (.vsix).
  workspace/                           # Default working directory.
  admin-credentials.txt                # Generated password.  Mode 0600.
```

## Configuration

Sensible defaults; you don't need to set any of these in normal use.

| Env var | Purpose | Default |
|---|---|---|
| `OPENHOST_APP_DATA_DIR` | Persistent data dir; injected by OpenHost. | `/data/app_data/vscode` |
| `AUTH_PROXY_LISTEN_PORT` | Sidecar port (the OpenHost-routed port). | `8080` |

To rotate the password: delete `$OPENHOST_APP_DATA_DIR/admin-credentials.txt` and restart the container; `start.sh` regenerates a fresh one.

## Hardening notes

- The container runs code-server as user `coder` (uid 1000), not root.
- The auth-proxy and the editor's HTTP listener are bound to `127.0.0.1` and a public port respectively; only the auth-proxy's port (8080) is accessible from outside the container, and OpenHost routes only owner-stamped traffic to it.
- code-server's `/login` is reachable directly inside the container — that's how the auth-proxy auto-logins. From outside the container, the OpenHost router gates everything behind owner SSO except `/healthz`.
- Anyone with the password can log in to code-server, which gives them full RCE inside the container as user `coder`. Treat the credentials file as you would the SSH private key for a server.
