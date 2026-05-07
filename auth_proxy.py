"""OpenHost auto-login auth-proxy for code-server (VS Code in browser).

Sits between the OpenHost router and code-server.  When an
authenticated zone owner visits the editor for the first time on a
device, this proxy logs them in to code-server automatically using
the persisted password and sets the resulting
``code-server-session`` cookie on the browser.  After the cookie
is set, the proxy is a near-pass-through; subsequent requests
carry the cookie and reach code-server with no further proxy
involvement.

This mirrors openhost-minio's auth-proxy (Pattern B in the OpenHost
SSO playbook): the OpenHost router stamps
``X-OpenHost-Is-Owner: true`` on requests where the visitor's
``zone_auth`` JWT has been verified, and we use that header as the
trigger to mint an in-app session by calling the app's own login
endpoint.

code-server's login is a POST to ``/login`` (form-urlencoded
``password=<pw>``) that responds with a 302 + ``Set-Cookie:
code-server-session=<hashed_password>``.  We capture the cookie
and echo it on a 302 of our own back to the browser's original
target URL.

Auth model summary:

  * Anonymous (no zone_auth)            → router 302's to /login on
                                           parent zone before the
                                           request reaches us.
  * Owner, has code-server-session      → forward unchanged.
  * Owner, no code-server-session       → call /login with the
                                           persisted password,
                                           capture Set-Cookie, send
                                           a 302 with the cookie
                                           set.
  * Health probe (/healthz)             → forward unchanged
                                           regardless of headers.
                                           The OpenHost router pings
                                           it without a session.

WebSocket support is critical for code-server: VS Code uses
WebSockets for terminals (xterm.js), language server protocol
traffic, and the file watcher.  Without bidirectional WS
forwarding the editor SPA loads but is unusable.  Implementation
mirrors openhost-minio's ``_proxy_websocket`` / ``_websocket_pump``.

Defense in depth: ALWAYS strip any client-supplied
``X-OpenHost-Is-Owner`` / ``X-OpenHost-User`` before forwarding
upstream.

Implementation is adapted from openhost-minio/auth_proxy.py.
"""

from __future__ import annotations

import http.client
import logging
import os
import re
import selectors
import socket
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
USER_HEADER_NAME = "X-OpenHost-User"
CODE_SERVER_SESSION_COOKIE = "code-server-session"

HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Host",
        "Content-Length",
    )
)

ALWAYS_STRIP_HEADERS = frozenset(
    h.lower() for h in (OWNER_HEADER_NAME, USER_HEADER_NAME)
)

CLIENT_READ_TIMEOUT_SECONDS = 60

# 256 MiB body cap.  VS Code's editor SPA POSTs JSON RPC requests
# that are normally tiny (<KiB) but the file-upload code paths can
# push larger payloads.  256 MiB is plenty for editor traffic; large
# file IO inside the workspace happens via the WebSocket file watch
# protocol or terminal scp, not via this HTTP path.
MAX_BODY_BYTES = 256 * 1024 * 1024

# WebSocket streaming constants — VS Code's terminal + LSP traffic
# go over WS.  These constants size individual chunks (small for
# low latency) and total session lifetime (long, so a tmux session
# in the terminal panel stays open all day).
STREAM_CHUNK_BYTES = 64 * 1024
STREAM_TIMEOUT_SECONDS = 6 * 60 * 60  # 6h — a long workday's editing
HEADER_LINE_CAP = 64 * 1024

# code-server's login endpoint.  POST password=<pw> form-urlencoded
# at /login; on success returns 302 + Set-Cookie:
# code-server-session=<hashed_password>.  See coder/code-server
# src/node/routes/login.ts.
CODE_SERVER_LOGIN_PATH = "/login"

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    if not cookie_header:
        return {}
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        result.setdefault(name.strip(), value.strip())
    return result


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


def _read_password(cred_file: str) -> str | None:
    """Read VSCODE_PASSWORD from start.sh's persisted credentials file."""
    try:
        with open(cred_file, encoding="utf-8") as fh:
            content = fh.read()
    except FileNotFoundError:
        return None
    for line in content.splitlines():
        m = re.match(
            r"^\s*(?:export\s+)?VSCODE_PASSWORD\s*=\s*(.*?)\s*$", line
        )
        if not m:
            continue
        val = m.group(1)
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        return val
    return None


def _login_to_code_server(
    upstream_host: str,
    upstream_port: int,
    password: str,
) -> str | None:
    """POST password to code-server's /login and return Set-Cookie value.

    Returns None on failure — auto-login is best-effort; on failure
    the proxy falls through to a normal forward and the operator
    sees code-server's own password prompt (worst-case UX, not an
    error page).
    """
    payload = urllib.parse.urlencode({"password": password}).encode("utf-8")
    try:
        conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=10)
        conn.request(
            "POST",
            CODE_SERVER_LOGIN_PATH,
            body=payload,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(payload)),
            },
        )
        resp = conn.getresponse()
        try:
            resp.read()
        except (OSError, http.client.HTTPException):
            pass
    except (OSError, http.client.HTTPException) as exc:
        log.warning("auto-login: upstream POST %s failed: %s", CODE_SERVER_LOGIN_PATH, exc)
        return None
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass

    # code-server returns 302 to the original target on success
    # and re-renders /login with an error toast on failure.
    if not (300 <= resp.status < 400):
        log.warning(
            "auto-login: code-server returned status %d to login attempt",
            resp.status,
        )
        return None
    set_cookie = resp.getheader("Set-Cookie")
    if not set_cookie:
        log.warning("auto-login: code-server 3xx had no Set-Cookie")
        return None
    return set_cookie


class AuthProxyHandler(BaseHTTPRequestHandler):
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 8082
    cred_file: str = "/data/app_data/vscode/admin-credentials.txt"

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        # Suppress noisy /healthz log lines.
        path = getattr(self, "path", "")
        if path.startswith("/healthz"):
            return
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        # WebSocket upgrades bypass auto-login + body-buffering and
        # go straight to bidirectional forwarding.  By the time a
        # WS upgrade is requested, the SPA has already established
        # its session (cookie present), so no auto-login dance is
        # needed.
        if self._is_websocket_upgrade():
            self._proxy_websocket()
            return

        is_owner = self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        has_session = CODE_SERVER_SESSION_COOKIE in cookies

        accept = self.headers.get("Accept", "")
        is_html_navigation = (
            self.command == "GET" and "text/html" in accept.lower()
        )

        if is_owner and not has_session and is_html_navigation:
            if self._maybe_auto_login():
                return

        self._proxy()

    def _is_websocket_upgrade(self) -> bool:
        upgrade = self.headers.get("Upgrade", "").lower().strip()
        connection = self.headers.get("Connection", "").lower()
        connection_tokens = {t.strip() for t in connection.split(",")}
        return upgrade == "websocket" and "upgrade" in connection_tokens

    def _proxy_websocket(self) -> None:
        """Forward a WebSocket upgrade request bidirectionally."""
        ws_drop = ALWAYS_STRIP_HEADERS | frozenset({"host"})
        cleaned = _strip_headers(self.headers.items(), ws_drop)
        forwarded_host = self.headers.get("X-Forwarded-Host", "").strip()

        try:
            upstream_sock = socket.create_connection(
                (self.upstream_host, self.upstream_port),
                timeout=STREAM_TIMEOUT_SECONDS,
            )
        except OSError as exc:
            log.warning("upstream connect failed (websocket): %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        try:
            upstream_sock.settimeout(STREAM_TIMEOUT_SECONDS)
            host_header = forwarded_host or f"{self.upstream_host}:{self.upstream_port}"
            request_bytes = bytearray()
            request_bytes.extend(
                self._encode_header_bytes(
                    f"{self.command} {self.path} HTTP/1.1\r\n"
                )
            )
            request_bytes.extend(
                self._encode_header_bytes(f"Host: {host_header}\r\n")
            )
            for k, v in cleaned:
                request_bytes.extend(
                    self._encode_header_bytes(f"{k}: {v}\r\n")
                )
            request_bytes.extend(b"\r\n")
            try:
                upstream_sock.sendall(bytes(request_bytes))
            except OSError as exc:
                log.warning("websocket request send failed: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            response_buf = self._read_until_double_crlf(
                upstream_sock, max_bytes=HEADER_LINE_CAP
            )
            if response_buf is None:
                self._safe_send_error(502, "Bad Gateway")
                return
            head_bytes, tail_bytes = response_buf

            try:
                self.wfile.write(head_bytes)
                if tail_bytes:
                    self.wfile.write(tail_bytes)
                self.wfile.flush()
            except OSError as exc:
                log.debug("client disconnected during ws handshake: %s", exc)
                return

            if not head_bytes.startswith(b"HTTP/1.1 101"):
                first_line = head_bytes.split(b"\r\n", 1)[0].decode(
                    "latin-1", errors="replace"
                )
                log.info("upstream rejected websocket upgrade: %s", first_line)
                return

            self._websocket_pump(self.connection, upstream_sock)
        finally:
            try:
                upstream_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                upstream_sock.close()
            except OSError:
                pass

    @staticmethod
    def _read_until_double_crlf(
        sock: socket.socket, max_bytes: int
    ) -> tuple[bytes, bytes] | None:
        buf = bytearray()
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError as exc:
                log.info("websocket handshake recv failed: %s", exc)
                return None
            if not chunk:
                return None
            buf.extend(chunk)
            idx = buf.find(b"\r\n\r\n")
            if idx >= 0:
                head = bytes(buf[: idx + 4])
                tail = bytes(buf[idx + 4 :])
                return head, tail
            if len(buf) >= max_bytes:
                log.warning(
                    "websocket response head exceeds %d bytes; aborting",
                    max_bytes,
                )
                return None

    @staticmethod
    def _websocket_pump(
        client_sock: socket.socket, upstream_sock: socket.socket
    ) -> None:
        for s in (client_sock, upstream_sock):
            try:
                s.settimeout(None)
            except OSError:
                pass

        sel = selectors.DefaultSelector()
        try:
            sel.register(client_sock, selectors.EVENT_READ, "client")
            sel.register(upstream_sock, selectors.EVENT_READ, "upstream")
            while True:
                events = sel.select(timeout=STREAM_TIMEOUT_SECONDS)
                if not events:
                    log.info("websocket idle timeout; closing")
                    return
                for key, _ in events:
                    if key.data == "client":
                        src, dst = client_sock, upstream_sock
                        direction = "client->upstream"
                    else:
                        src, dst = upstream_sock, client_sock
                        direction = "upstream->client"
                    try:
                        chunk = src.recv(STREAM_CHUNK_BYTES)
                    except OSError as exc:
                        log.info("websocket %s recv failed: %s", direction, exc)
                        return
                    if not chunk:
                        log.debug("websocket %s EOF; closing", direction)
                        return
                    try:
                        dst.sendall(chunk)
                    except OSError as exc:
                        log.info("websocket %s sendall failed: %s", direction, exc)
                        return
        finally:
            try:
                sel.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("websocket selector close failed: %s", exc)

    @staticmethod
    def _encode_header_bytes(value: str) -> bytes:
        try:
            return value.encode("latin-1")
        except UnicodeEncodeError:
            log.warning("non-latin-1 header value, replacing offending bytes")
            return value.encode("latin-1", errors="replace")

    def _maybe_auto_login(self) -> bool:
        password = _read_password(self.cred_file)
        if password is None:
            log.warning(
                "auto-login: password file missing or unreadable at %s",
                self.cred_file,
            )
            return False

        set_cookie = _login_to_code_server(
            self.upstream_host, self.upstream_port, password
        )
        if set_cookie is None:
            return False

        target_path = self.path or "/"
        parsed = urllib.parse.urlparse(target_path)
        if parsed.scheme or parsed.netloc:
            target_path = "/"

        try:
            self.send_response(302)
            self.send_header("Location", target_path)
            self.send_header("Set-Cookie", set_cookie)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected during auto-login redirect: %s", exc)
            return False

        log.info(
            "auto-login: minted code-server session for owner; redirected to %s",
            target_path,
        )
        return True

    def _proxy(self) -> None:
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )

        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        if transfer_encoding and transfer_encoding != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported")
            return

        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > MAX_BODY_BYTES:
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            body = b""

        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=120
        )
        try:
            try:
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=False,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            try:
                payload = upstream.read(MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                try:
                    upstream.close()
                except Exception as close_exc:  # noqa: BLE001
                    log.debug("upstream.close() raised: %s", close_exc)
                return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("upstream.close() raised (ignored): %s", exc)
            if len(payload) > MAX_BODY_BYTES:
                self._safe_send_error(502, "upstream response too large")
                return

            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except OSError as exc:
                log.debug("client disconnected mid-response: %s", exc)
        finally:
            conn.close()


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 8082)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1").strip()
    cred_file = os.environ.get(
        "AUTH_PROXY_CRED_FILE",
        "/data/app_data/vscode/admin-credentials.txt",
    )

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port
    AuthProxyHandler.cred_file = cred_file

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (creds=%s)",
        listen_port,
        upstream_host,
        upstream_port,
        cred_file,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
