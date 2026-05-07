# code-server packaged for OpenHost with one-click SSO.
#
# Layout:
#
#   /opt/openhost-vscode/
#     start.sh           — supervises code-server + auth-proxy sidecar
#     auth_proxy.py      — owner auto-login sidecar (Pattern B from
#                          the OpenHost SSO playbook; modelled on
#                          openhost-minio's auth_proxy.py)
#
# Auth flow:
#
#   1. Browser hits https://vscode.<zone>/.  OpenHost router stamps
#      X-OpenHost-Is-Owner: true and forwards to container :8080.
#   2. auth_proxy.py: if owner AND no code-server-session cookie
#      yet, POSTs the persisted password to code-server's POST /
#      (the login endpoint), captures Set-Cookie, and 302's the
#      browser back to the original URL with the cookie attached.
#   3. Subsequent requests carry the cookie and pass through
#      transparently, including the WebSocket upgrade VS Code uses
#      for terminals and the language server protocol.
#
# We base on codercom/code-server:latest so we inherit Coder's
# exact node version + bundled VS Code commit.  The upstream image
# runs as user `coder` (uid 1000); we override to root so we can
# install python3 for the auth-proxy and chown persistent dirs in
# start.sh, then drop back to coder for the actual code-server
# process via su.

FROM docker.io/codercom/code-server:latest

USER root

# python3 for the auth-proxy.  apt-get is available in the upstream
# image (it's Debian-based).  ca-certificates is already installed
# but pinning it doesn't cost anything.
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
        python3 \
        ca-certificates \
        tini \
 && rm -rf /var/lib/apt/lists/*

# All app files committed with mode 0755 in the git index.
COPY start.sh        /opt/openhost-vscode/start.sh
COPY auth_proxy.py   /opt/openhost-vscode/auth_proxy.py

# OpenHost-routed port.  code-server's port (8082) stays loopback.
EXPOSE 8080

# tini reaps zombies and forwards SIGTERM to start.sh's child set,
# matching the supervision model used by openhost-joplin /
# openhost-minio.
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/openhost-vscode/start.sh"]
