"""HTTP shell for the operator console: transport, sign-in, request checks, headers, files.

Everything the console displays was typed by attackers, so this layer is a security
component even though it only listens on loopback (reached through an SSH or SSM tunnel):

- Binding: loopback only, unless ``allow_non_loopback`` (a container binds 0.0.0.0 while
  the host publishes the port on loopback).
- Host: every request's ``Host`` must name localhost, 127.0.0.1 or [::1] (any port); this
  is the DNS-rebinding defence. Every POST also needs a matching ``http://`` ``Origin``.
- Sign-in: ``GET /?token=<token>`` sets an HttpOnly, SameSite=Strict session cookie. The
  cookie and the CSRF value are HMAC-SHA256 derivations of the token; the token itself is
  never stored in a cookie, returned by an endpoint or logged (except the one sign-in URL
  ``serve`` prints at start). Failed token attempts are throttled globally.
- POST: cookie, ``X-Winnie-CSRF``, ``[ui] actions`` on, JSON object body of at most 16 KiB.
- Responses: strict CSP and related headers on every response, JSON with ``<``, ``>``,
  ``&``, U+2028 and U+2029 escaped, static files from a fixed table (no filesystem lookup
  from the request path). Exceptions from ``routes`` become a bare 500.
"""

from __future__ import annotations

import hashlib
import hmac
import http
import http.server
import ipaddress
import json
import logging
import re
import secrets
import socket
import socketserver
import threading
import time
import urllib.parse
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Protocol

log = logging.getLogger("agents.ui")

COOKIE_NAME = "winnie_ui"
CSRF_HEADER = "X-Winnie-CSRF"
MIN_TOKEN_LENGTH = 24
MAX_BODY = 16384
MAX_QUERY_PARAMS = 32
MAX_QUERY_VALUE = 512
SOCKET_TIMEOUT = 15
THROTTLE_FAILURES = 10
THROTTLE_WINDOW = 60.0

JSON_TYPE = "application/json; charset=utf-8"
HTML_TYPE = "text/html; charset=utf-8"
STATIC_DIR = Path(__file__).resolve().parent / "static"
# URL path -> (file in STATIC_DIR, content type). Nothing else is ever read from disk.
STATIC_FILES: dict[str, tuple[str, str]] = {
    "/": ("index.html", HTML_TYPE),
    "/index.html": ("index.html", HTML_TYPE),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/favicon.svg": ("favicon.svg", "image/svg+xml"),
}

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Content-Security-Policy", CONTENT_SECURITY_POLICY),
)

# Shown at / without a session. No form and no script: the only way in is the logged link.
SIGNED_OUT_PAGE = (
    b"<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
    b"<title>Winnie console</title></head>\n<body><p>Not signed in. Open the sign-in link "
    b"printed in the server log.</p></body></html>\n"
)

_LOCAL_NAME = r"(?:localhost|127\.0\.0\.1|\[::1\])"
_HOST_RE = re.compile(_LOCAL_NAME + r"(?::(\d{1,5}))?", re.ASCII)
_ORIGIN_RE = re.compile(r"http://" + _LOCAL_NAME + r"(?::(\d{1,5}))?", re.ASCII)
_LENGTH_RE = re.compile(r"\d{1,9}", re.ASCII)
# Checked on the raw path, lower-cased. Any encoded dot, slash, backslash or NUL is refused
# outright rather than decoded and re-checked.
_BAD_PATH_PARTS = ("..", "//", "\\", "\x00", "%2e", "%2f", "%5c", "%00")


@dataclass(frozen=True)
class UiSettings:
    bind: str = "127.0.0.1"
    port: int = 8480
    actions: bool = False          # may POST routes change anything
    operator: str = ""             # label recorded with decisions
    allow_non_loopback: bool = False
    token: str = ""                # empty: generate one at start


class Routes(Protocol):
    """The data API. Receives only paths under ``/api/``; returns (status, JSON value)."""

    def get(self, path: str, query: dict[str, str]) -> tuple[int, object]: ...

    def post(self, path: str, body: dict) -> tuple[int, object]: ...


# ---- small pure helpers ----------------------------------------------------------------------

def encode_json(value: object) -> bytes:
    """Strict JSON, ASCII only, with markup characters escaped.

    ``ensure_ascii`` already writes U+2028 and U+2029 as escapes. ``<``, ``>`` and ``&`` can
    only occur inside strings in JSON text, so replacing them with escapes keeps it valid.
    """
    text = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    text = text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return text.encode("ascii")


def _port_ok(match: Optional[re.Match]) -> bool:
    return match is not None and (match.group(1) is None or int(match.group(1)) <= 65535)


def host_allowed(values: Optional[list[str]]) -> bool:
    """Exactly one Host header naming a loopback name (lower-casing is the only leniency)."""
    if not values or len(values) != 1:
        return False
    return _port_ok(_HOST_RE.fullmatch(values[0].strip(" \t").lower()))


def origin_allowed(values: Optional[list[str]]) -> bool:
    if not values or len(values) != 1:
        return False
    return _port_ok(_ORIGIN_RE.fullmatch(values[0].strip(" \t").lower()))


def parse_target(target: str) -> Optional[tuple[str, dict[str, str]]]:
    """Split a request target into a decoded path and query (last value wins); None if bad."""
    raw_path, _, raw_query = target.partition("?")
    if not raw_path.startswith("/"):
        return None  # absolute-form or asterisk targets
    if any(part in raw_path.lower() for part in _BAD_PATH_PARTS):
        return None
    try:
        path = urllib.parse.unquote(raw_path, errors="strict")
        pairs = urllib.parse.parse_qsl(raw_query, keep_blank_values=True, errors="strict",
                                       max_num_fields=MAX_QUERY_PARAMS)
    except ValueError:  # includes UnicodeDecodeError and too many fields
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        return None
    query: dict[str, str] = {}
    for key, value in pairs:
        if len(key) > MAX_QUERY_VALUE or len(value) > MAX_QUERY_VALUE:
            return None
        query[key] = value
    return path, query


def is_loopback(bind: str) -> bool:
    if bind.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(bind.strip("[]")).is_loopback
    except ValueError:
        return False


def _derive(token: str, label: str) -> str:
    return hmac.new(token.encode(), f"winnie-ui {label} v1".encode(), hashlib.sha256).hexdigest()


def _phrase(code: int) -> str:
    try:
        return http.HTTPStatus(code).phrase.lower()
    except ValueError:
        return "error"


def _reject_constant(name: str) -> object:
    raise ValueError(f"non-standard JSON constant {name}")


class _Reject(Exception):
    """A request refused with a short JSON error."""

    def __init__(self, status: int, error: str, headers: tuple[tuple[str, str], ...] = ()):
        super().__init__(error)
        self.status = status
        self.error = error
        self.headers = headers


# ---- server ----------------------------------------------------------------------------------

class UiServer(http.server.ThreadingHTTPServer):
    """The console's HTTP server. Built by ``build_server``; not serving until started."""

    daemon_threads = True
    allow_reuse_address = True
    allow_reuse_port = False  # another local process must not share the port

    def __init__(self, settings: UiSettings, routes: Routes, token: str):
        self.settings = settings
        self.routes = routes
        self._token = token
        self._session = _derive(token, "session")
        self._csrf = _derive(token, "csrf")
        self._failures: deque[float] = deque()
        self._lock = threading.Lock()
        self.clock: Callable[[], float] = time.monotonic  # replaceable in tests
        if ":" in settings.bind:
            self.address_family = socket.AF_INET6
        super().__init__((settings.bind.strip("[]"), settings.port), _Handler)

    @property
    def token(self) -> str:
        return self._token

    def server_bind(self) -> None:
        # HTTPServer.server_bind does a reverse lookup of the bind address; not needed.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = port

    def handle_error(self, request, client_address) -> None:
        # The default prints a traceback to stderr; keep it in the module's log instead.
        log.warning("connection error", exc_info=True)

    def check_token(self, given: str) -> str:
        """``ok``, ``bad`` or ``throttled``. Failures are counted globally over a window."""
        with self._lock:
            now = self.clock()
            while self._failures and now - self._failures[0] >= THROTTLE_WINDOW:
                self._failures.popleft()
            if len(self._failures) >= THROTTLE_FAILURES:
                return "throttled"
            if hmac.compare_digest(given.encode(), self._token.encode()):
                return "ok"
            self._failures.append(now)
            return "bad"

    def session_ok(self, value: str) -> bool:
        return hmac.compare_digest(value.encode(), self._session.encode())

    def csrf_ok(self, value: str) -> bool:
        return hmac.compare_digest(value.encode(), self._csrf.encode())


class _Handler(http.server.BaseHTTPRequestHandler):
    server: UiServer
    server_version = "winnie-ui"
    sys_version = ""
    protocol_version = "HTTP/1.0"  # one request per connection keeps the state simple
    timeout = SOCKET_TIMEOUT

    _headers_sent = False
    _body_read = False

    # -- stdlib hooks --

    def version_string(self) -> str:
        return self.server_version  # no Python name or version

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        if self.command not in ("GET", "HEAD", "POST"):
            self.close_connection = True
            self._send_json(405, {"error": "method not allowed"},
                            (("Allow", "GET, HEAD, POST"),))
            return False
        return True

    def send_error(self, code: int, message: Optional[str] = None,
                   explain: Optional[str] = None) -> None:
        # The stdlib version echoes the request line (which can hold the token) into the
        # body and the log; answer with the status phrase only.
        self.close_connection = True
        self._send_json(code, {"error": _phrase(code)})

    def end_headers(self) -> None:
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        super().end_headers()

    def log_request(self, code: object = "-", size: object = "-") -> None:
        log.info("%s %s %s", self.command or "-", self._log_path(), getattr(code, "value", code))

    def log_error(self, format: str, *args: object) -> None:
        log.info("request error on %s", self._log_path())  # args may carry the request line

    def log_message(self, format: str, *args: object) -> None:
        pass  # everything worth logging goes through log_request / log_error

    def do_GET(self) -> None:
        self._dispatch(self._handle_get)

    def do_HEAD(self) -> None:
        self._dispatch(self._handle_get)

    def do_POST(self) -> None:
        self._dispatch(self._handle_post)

    # -- plumbing --

    def _log_path(self) -> str:
        path = getattr(self, "path", None) or "-"
        path = path.split("?", 1)[0][:200]  # the query can carry the token
        return path.encode("ascii", "backslashreplace").decode("ascii")

    def _send(self, status: int, body: bytes, content_type: Optional[str],
              headers: tuple[tuple[str, str], ...] = ()) -> None:
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self._headers_sent = True
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _send_json(self, status: int, value: object,
                   headers: tuple[tuple[str, str], ...] = ()) -> None:
        self._send(status, encode_json(value), JSON_TYPE, headers)

    def _dispatch(self, handler: Callable[[], None]) -> None:
        try:
            handler()
        except _Reject as reject:
            if self.command == "POST" and not self._body_read:
                self._drain()
            self._send_json(reject.status, {"error": reject.error}, reject.headers)
        except Exception:
            log.exception("unhandled error on %s %s", self.command, self._log_path())
            if not self._headers_sent:
                self.close_connection = True
                self._send_json(500, {"error": "internal error"})

    def _drain(self) -> None:
        """Read a small refused body so closing the socket does not reset the connection
        before the client reads the answer. Bodies over the limit are never read."""
        self._body_read = True
        try:
            length = self._content_length()
        except _Reject:
            return
        try:
            self.rfile.read(length)
        except OSError:
            pass

    def _target(self) -> tuple[str, dict[str, str]]:
        if not host_allowed(self.headers.get_all("Host")):
            raise _Reject(421, "host not allowed")
        parsed = parse_target(self.path)
        if parsed is None:
            raise _Reject(400, "bad request path")
        return parsed

    def _cookie_ok(self) -> bool:
        for header in self.headers.get_all("Cookie") or []:
            for part in header.split(";"):
                name, sep, value = part.strip().partition("=")
                if sep and name == COOKIE_NAME and self.server.session_ok(value):
                    return True
        return False

    def _content_length(self) -> int:
        if self.headers.get_all("Transfer-Encoding"):
            raise _Reject(411, "content-length required")
        lengths = self.headers.get_all("Content-Length") or []
        if not lengths:
            raise _Reject(411, "content-length required")
        if len(lengths) != 1 or not _LENGTH_RE.fullmatch(lengths[0].strip()):
            raise _Reject(400, "bad content-length")
        length = int(lengths[0])
        if length > MAX_BODY:
            raise _Reject(413, "body too large")
        return length

    def _call_route(self, path: str, call: Callable[[], tuple[int, object]]) -> None:
        try:
            status, value = call()
            if isinstance(status, bool) or not isinstance(status, int) \
                    or not 200 <= status <= 599:
                raise ValueError(f"route returned status {status!r}")
            body = encode_json(value)
        except Exception:
            log.exception("route failed on %s %s", self.command, path[:200])
            self._send_json(500, {"error": "internal error"})
            return
        self._send(status, body, JSON_TYPE)

    # -- GET / HEAD --

    def _handle_get(self) -> None:
        path, query = self._target()
        if path == "/" and "token" in query:
            self._sign_in(query["token"])
            return
        if not self._cookie_ok():
            if path == "/":
                self._send(401, SIGNED_OUT_PAGE, HTML_TYPE)
                return
            raise _Reject(401, "not signed in")
        if path in STATIC_FILES:
            self._send_static(path)
        elif path == "/api/session":
            settings = self.server.settings
            self._send_json(200, {"csrf": self.server._csrf, "actions": settings.actions,
                                  "operator": settings.operator})
        elif path.startswith("/api/"):
            routes = self.server.routes
            self._call_route(path, lambda: routes.get(path, query))
        else:
            raise _Reject(404, "not found")

    def _sign_in(self, given: str) -> None:
        result = self.server.check_token(given)
        if result == "throttled":
            raise _Reject(429, "too many sign-in attempts")
        if result != "ok":
            raise _Reject(403, "bad token")
        # No Secure attribute: plain HTTP on loopback.
        cookie = f"{COOKIE_NAME}={self.server._session}; HttpOnly; SameSite=Strict; Path=/"
        self._send(303, b"", None, (("Location", "/"), ("Set-Cookie", cookie)))

    def _send_static(self, path: str) -> None:
        name, content_type = STATIC_FILES[path]
        try:
            body = (STATIC_DIR / name).read_bytes()  # read per request so edits show at once
        except OSError:
            log.warning("static file missing: %s", name)
            raise _Reject(404, "not found")
        self._send(200, body, content_type)

    # -- POST --

    def _handle_post(self) -> None:
        path, _ = self._target()
        if not origin_allowed(self.headers.get_all("Origin")):
            raise _Reject(403, "origin not allowed")
        if not self._cookie_ok():
            raise _Reject(401, "not signed in")
        csrf = self.headers.get_all(CSRF_HEADER) or []
        if len(csrf) != 1 or not self.server.csrf_ok(csrf[0].strip()):
            raise _Reject(403, "bad csrf token")
        if not self.server.settings.actions:
            raise _Reject(403, "read-only")
        if not path.startswith("/api/"):
            raise _Reject(404, "not found")
        content_types = self.headers.get_all("Content-Type") or []
        if len(content_types) != 1 \
                or content_types[0].split(";", 1)[0].strip().lower() != "application/json":
            raise _Reject(415, "content-type must be application/json")
        length = self._content_length()
        raw = self.rfile.read(length)
        self._body_read = True
        if len(raw) != length:
            raise _Reject(400, "short body")
        try:
            body = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
        except (ValueError, RecursionError):  # ValueError covers UnicodeDecodeError
            raise _Reject(400, "body must be a JSON object")
        if not isinstance(body, dict):
            raise _Reject(400, "body must be a JSON object")
        routes = self.server.routes
        self._call_route(path, lambda: routes.post(path, body))


# ---- entry points ----------------------------------------------------------------------------

def build_server(settings: UiSettings, routes: Routes) -> UiServer:
    """Validate settings, bind the socket and return the server (not yet serving)."""
    if not 0 <= settings.port <= 65535:
        raise ValueError(f"ui port out of range: {settings.port}")
    if not settings.allow_non_loopback and not is_loopback(settings.bind):
        raise ValueError(
            f"refusing to bind the operator console to non-loopback address {settings.bind!r}; "
            "bind 127.0.0.1 and reach it through an SSH or SSM tunnel, or set "
            "allow_non_loopback (only inside a container whose port is published on loopback)")
    if settings.token:
        if len(settings.token) < MIN_TOKEN_LENGTH:
            raise ValueError(f"ui token must be at least {MIN_TOKEN_LENGTH} characters")
        token = settings.token
    else:
        token = secrets.token_urlsafe(32)
    return UiServer(settings, routes, token)


def sign_in_url(server: UiServer) -> str:
    """The link the operator opens. An unspecified bind (container) is reached on loopback."""
    bind = server.settings.bind.strip("[]")
    if bind in ("0.0.0.0", ""):
        host = "127.0.0.1"
    elif bind == "::":
        host = "[::1]"
    elif ":" in bind:
        host = f"[{bind}]"
    else:
        host = bind
    port = server.server_address[1]
    return f"http://{host}:{port}/?token={urllib.parse.quote(server.token, safe='')}"


def serve(settings: UiSettings, routes: Routes) -> None:
    """Run the console until interrupted. Logs the sign-in URL once at start."""
    server = build_server(settings, routes)
    # The only place the token is ever written anywhere.
    log.info("operator console ready; sign in at %s", sign_in_url(server))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
