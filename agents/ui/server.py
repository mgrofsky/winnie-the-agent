"""HTTP shell for the operator console: transport, sign-in, request checks, headers, files.

Everything the console displays was typed by attackers, so this layer is a security
component even though it only listens on loopback (reached through an SSH or SSM tunnel):

- Binding: loopback only, unless ``allow_non_loopback`` (a container binds 0.0.0.0 while
  the host publishes the port on loopback). ``external_host`` does not relax this.
- Host: every request's ``Host`` must name localhost, 127.0.0.1 or [::1] (any port); this
  is the DNS-rebinding defence. Every POST also needs an ``Origin`` equal to
  ``"http://" + Host`` (lower-cased), so another local port or name cannot post.
- External name: ``external_host`` (empty by default) adds exactly one more accepted
  ``Host``, for a TLS-terminating reverse proxy on the same host that forwards to the
  loopback port. It is HTTPS only: a POST under it needs ``Origin`` equal to
  ``"https://" + Host``, its session cookie is ``Secure`` and its responses carry HSTS.
  Sessions are bound to the kind of name (loopback or external) they were issued for.
- No proxy trust: ``X-Forwarded-*``, ``Forwarded`` and any identity header a proxy adds
  are never read. The console cannot tell a proxied request from a direct one, so the
  token and session checks are the same for both; reach through the proxy is decided by
  whatever controls who can connect to the proxy.
- Sign-in: ``GET /?token=<token>`` sets an HttpOnly, SameSite=Strict session cookie. The
  cookie is ``<issued>.<HMAC(process key, kind, issued)>`` with a per-process random key, so
  it dies on restart and after ``SESSION_LIFETIME``; nothing is stored server-side. The CSRF
  value is an HMAC of the cookie value, so it belongs to one session. The token itself is
  never stored in a cookie, returned by an endpoint or logged (except the one sign-in line
  ``serve`` prints at start). The token is compared first, so a correct one always signs
  in; only failures are throttled (globally).
- POST: cookie, ``X-Winnie-CSRF``, ``[ui] actions`` on, JSON object body of at most 16 KiB
  read within ``BODY_DEADLINE``. A POST refused before its body is read is answered at once
  and the connection closed, so an unauthenticated client cannot hold a thread with a slow
  body. At most ``MAX_CONNECTIONS`` connections are served at once; the rest get a 503.
- Responses: strict CSP and related headers on every response, JSON with ``<``, ``>``,
  ``&``, U+2028 and U+2029 escaped, static files from a fixed table (no filesystem lookup
  from the request path). Exceptions from ``routes`` become a bare 500. HTTP/0.9 requests
  (which would get a body without headers) are closed without an answer.
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
from dataclasses import dataclass, replace
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
SESSION_LIFETIME = 12 * 3600     # seconds; the logged sign-in link works again after it
BODY_DEADLINE = 10.0             # seconds to receive a whole accepted POST body
LINGER_SECONDS = 0.5             # after refusing an unread POST, see linger() below
MAX_CONNECTIONS = 32             # connections served at once; more get a fixed 503

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
# Added only for requests under the external name, which the browser reaches over HTTPS.
# On loopback (plain HTTP) browsers ignore it, and it would pin nothing useful.
HSTS_HEADER = ("Strict-Transport-Security", "max-age=31536000")

# The kind of name a request arrived under; sessions are bound to it.
LOCAL = "local"
EXTERNAL = "external"

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
_SESSION_RE = re.compile(r"(\d{1,11})\.([0-9a-f]{64})", re.ASCII)
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_PORT_RE = re.compile(r"[1-9]\d{0,4}", re.ASCII)
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
    external_host: str = ""        # name[:port] a same-host HTTPS proxy is reached by


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


def normalize_external_host(value: str) -> str:
    """The ``external_host`` setting, lower-cased; ``""`` when unset. ValueError if invalid.

    One DNS name of two or more labels, optionally ``:port``. Anything that could widen
    what the Host check accepts is refused: IP literals, localhost, wildcards, a scheme, a
    path, a trailing dot. ``:443`` is dropped, since browsers leave the default port out of
    Host and Origin and the bare name already accepts ``name:443``."""
    text = value.strip()
    if not text:
        return ""
    shown = repr(text[:100])
    if not text.isascii():  # checked before lower(): some non-ASCII letters lower to ASCII
        raise ValueError(f"ui external_host {shown}: must be ASCII (use the punycode name)")
    host = text.lower()
    name, sep, port = host.partition(":")
    if sep and not _PORT_RE.fullmatch(port):
        raise ValueError(f"ui external_host {shown}: the port must be a number from 1 to 65535 "
                         "and nothing may follow it (no scheme, path or IPv6 literal)")
    if sep and int(port) > 65535:
        raise ValueError(f"ui external_host {shown}: port out of range")
    if len(name) > 253 or name.endswith("."):
        raise ValueError(f"ui external_host {shown}: must be a DNS name of at most 253 "
                         "characters with no trailing dot")
    labels = name.split(".")
    if len(labels) < 2 or not all(_DNS_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError(f"ui external_host {shown}: must be one DNS name such as "
                         "sensor.example-tailnet.ts.net (letters, digits and hyphens, at least "
                         "two labels; no scheme, path or wildcard)")
    if labels[-1].isdigit():
        raise ValueError(f"ui external_host {shown}: IP addresses are not allowed; use the "
                         "name the proxy's certificate is issued for")
    if labels[-1] == "localhost":
        raise ValueError(f"ui external_host {shown}: localhost names are already accepted")
    return name if port in ("", "443") else f"{name}:{port}"


def host_kind(values: Optional[list[str]], external_host: str = "") -> Optional[str]:
    """``LOCAL``, ``EXTERNAL`` or None for a request's Host headers.

    Exactly one Host header, naming a loopback name or exactly ``external_host`` (already
    normalized); lower-casing is the only leniency. With no port configured, ``name:443``
    is the same origin as ``name`` and is accepted too."""
    if not values or len(values) != 1:
        return None
    host = values[0].strip(" \t").lower()
    if _port_ok(_HOST_RE.fullmatch(host)):
        return LOCAL
    if external_host and (host == external_host or
                          (":" not in external_host and host == external_host + ":443")):
        return EXTERNAL
    return None


def host_allowed(values: Optional[list[str]], external_host: str = "") -> bool:
    return host_kind(values, external_host) is not None


def origin_allowed(values: Optional[list[str]], host: str) -> bool:
    """Exactly one loopback ``http://`` Origin, equal to ``"http://" + host`` (lower-cased).

    The allowlist alone would let a page on another loopback port or name (some other local
    service) post here; requiring the exact Host ties the request to this console's page."""
    if not values or len(values) != 1:
        return False
    origin = values[0].strip(" \t").lower()
    if not _port_ok(_ORIGIN_RE.fullmatch(origin)):
        return False
    return hmac.compare_digest(origin.encode(), ("http://" + host.strip(" \t").lower()).encode())


def external_origin_allowed(values: Optional[list[str]], host: str, external_host: str) -> bool:
    """For a request under the external name: exactly one Origin equal to ``"https://" +
    host``, or ``https://<name>`` when Host was ``<name>:443`` (browsers omit the default
    port). There is no plain-HTTP external origin."""
    if not values or len(values) != 1:
        return False
    origin = values[0].strip(" \t").lower()
    host = host.strip(" \t").lower()
    allowed = ["https://" + host]
    if ":" not in external_host and host == external_host + ":443":
        allowed.append("https://" + external_host)
    return origin in allowed


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


def _busy_response() -> bytes:
    body = encode_json({"error": "busy"})
    head = ["HTTP/1.0 503 Service Unavailable", "Server: winnie-ui",
            "Content-Type: " + JSON_TYPE, f"Content-Length: {len(body)}", "Connection: close"]
    head += [f"{name}: {value}" for name, value in SECURITY_HEADERS]
    return ("\r\n".join(head) + "\r\n\r\n").encode("ascii") + body


# Sent by the accept loop itself when every connection slot is taken: fixed bytes, no parsing.
BUSY_RESPONSE = _busy_response()


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
        # Session and CSRF values come from this key, never from the token: a fixed
        # WINNIE_UI_TOKEN must not give a cookie that survives a restart.
        self._key = secrets.token_bytes(32)
        self._failures: deque[float] = deque()
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        # Replaceable in tests: the throttle clock, the session clock and the body deadline.
        self.clock: Callable[[], float] = time.monotonic
        self.wall_clock: Callable[[], float] = time.time
        self.body_deadline = BODY_DEADLINE
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

    def process_request(self, request, client_address) -> None:
        # Runs on the accept loop. Over the cap, answer from fixed bytes and close rather
        # than start a thread, so a flood of idle connections cannot exhaust threads.
        if not self._slots.acquire(blocking=False):
            try:
                request.settimeout(1.0)
                request.sendall(BUSY_RESPONSE)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def check_token(self, given: str) -> str:
        """``ok``, ``bad`` or ``throttled``.

        The compare comes first, so a correct token always signs in; a global throttle
        that ran first would let anyone lock the operator out. Only failures are counted
        (globally, over a window), and failures past the limit get ``throttled``."""
        if hmac.compare_digest(given.encode(), self._token.encode()):
            return "ok"
        with self._lock:
            now = self.clock()
            while self._failures and now - self._failures[0] >= THROTTLE_WINDOW:
                self._failures.popleft()
            if len(self._failures) >= THROTTLE_FAILURES:
                return "throttled"
            self._failures.append(now)
            return "bad"

    def _mac(self, label: str, value: str) -> str:
        message = f"winnie-ui {label} v2 {value}".encode()
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def new_session(self, kind: str = LOCAL) -> str:
        """A cookie value: issue time (whole seconds) and an HMAC under the process key of
        that time and the kind of name it was issued under. The kind is not written out:
        the request's Host supplies it when the cookie comes back, so a loopback session
        cannot be replayed under the external name, or the reverse."""
        issued = str(int(self.wall_clock()))
        return f"{issued}.{self._mac('session', f'{kind} {issued}')}"

    def session_ok(self, value: str, kind: str = LOCAL) -> bool:
        """Issued by this process for this kind of name, unaltered, not from the future and
        not past its life."""
        match = _SESSION_RE.fullmatch(value)
        if match is None:
            return False
        issued, mac = match.groups()
        if not hmac.compare_digest(mac, self._mac("session", f"{kind} {issued}")):
            return False
        age = self.wall_clock() - int(issued)
        return 0 <= age < SESSION_LIFETIME

    def csrf_for(self, session: str) -> str:
        return self._mac("csrf", session)

    def csrf_ok(self, session: str, value: str) -> bool:
        return hmac.compare_digest(value.encode(), self.csrf_for(session).encode())


class _Handler(http.server.BaseHTTPRequestHandler):
    server: UiServer
    server_version = "winnie-ui"
    sys_version = ""
    protocol_version = "HTTP/1.0"  # one request per connection keeps the state simple
    timeout = SOCKET_TIMEOUT

    _headers_sent = False
    _body_read = False
    _kind: Optional[str] = None
    _kind_known = False

    # -- stdlib hooks --

    def version_string(self) -> str:
        return self.server_version  # no Python name or version

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        if self.request_version == "HTTP/0.9":
            # A two-word request line parses as HTTP/0.9, whose answer is a bare body with
            # no status line or security headers. Close without sending anything.
            self.close_connection = True
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
        if self.request_version == "HTTP/0.9":
            return  # would be a body without headers (see parse_request)
        self._send_json(code, {"error": _phrase(code)})

    def end_headers(self) -> None:
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        if self._host_kind() == EXTERNAL:
            self.send_header(*HSTS_HEADER)
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
            unread = self.command == "POST" and not self._body_read
            if unread:
                self.close_connection = True
            self._send_json(reject.status, {"error": reject.error}, reject.headers)
            if unread:
                self._linger()
        except Exception:
            log.exception("unhandled error on %s %s", self.command, self._log_path())
            if not self._headers_sent:
                self.close_connection = True
                self._send_json(500, {"error": "internal error"})

    def _linger(self) -> None:
        """After answering a POST whose body was never read: half-close, then discard what
        the client already sent for at most ``LINGER_SECONDS`` and ``MAX_BODY`` bytes.

        The answer is already on the wire, so a client that never sends its body is not
        waited on for it. Closing with unread bytes queued makes the kernel send a reset,
        which can make the client drop the answer before reading it; this short, bounded
        discard lets a well-behaved client read the answer and close first."""
        sock = self.connection
        try:
            self.wfile.flush()
            sock.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + LINGER_SECONDS
            budget = MAX_BODY
            while budget > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                data = sock.recv(min(4096, budget))
                if not data:
                    break
                budget -= len(data)
        except OSError:  # includes the timeout
            pass

    def _read_body(self, length: int) -> bytes:
        """Read ``length`` bytes within the server's body deadline (the socket timeout alone
        restarts on every byte, so a dribbled body could hold a thread for hours)."""
        deadline = time.monotonic() + self.server.body_deadline
        chunks: list[bytes] = []
        got = 0
        try:
            while got < length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _Reject(408, "request body too slow")
                self.connection.settimeout(min(remaining, SOCKET_TIMEOUT))
                try:
                    chunk = self.rfile.read1(length - got)
                except TimeoutError:
                    raise _Reject(408, "request body too slow")
                if not chunk:
                    break  # client closed early; reported as a short body
                chunks.append(chunk)
                got += len(chunk)
        finally:
            self.connection.settimeout(SOCKET_TIMEOUT)
        self._body_read = True
        return b"".join(chunks)

    def _host_kind(self) -> Optional[str]:
        """``LOCAL``, ``EXTERNAL`` or None, from the Host header alone (never a forwarded
        header). None until the headers are parsed, e.g. for a bad request line."""
        if not self._kind_known:
            headers = getattr(self, "headers", None)
            if headers is None:
                return None
            self._kind = host_kind(headers.get_all("Host"), self.server.settings.external_host)
            self._kind_known = True
        return self._kind

    def _target(self) -> tuple[str, dict[str, str]]:
        if self._host_kind() is None:
            raise _Reject(421, "host not allowed")
        parsed = parse_target(self.path)
        if parsed is None:
            raise _Reject(400, "bad request path")
        return parsed

    def _session(self) -> Optional[str]:
        """The first valid session cookie value, or None (expired and forged look the same)."""
        for header in self.headers.get_all("Cookie") or []:
            for part in header.split(";"):
                name, sep, value = part.strip().partition("=")
                if sep and name == COOKIE_NAME \
                        and self.server.session_ok(value, self._host_kind() or LOCAL):
                    return value
        return None

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
        session = self._session()
        if session is None:
            if path == "/":
                self._send(401, SIGNED_OUT_PAGE, HTML_TYPE)
                return
            raise _Reject(401, "not signed in")
        if path in STATIC_FILES:
            self._send_static(path)
        elif path == "/api/session":
            settings = self.server.settings
            self._send_json(200, {"csrf": self.server.csrf_for(session),
                                  "actions": settings.actions, "operator": settings.operator})
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
        # Secure only under the external name (HTTPS at the proxy); loopback is plain HTTP.
        # No Max-Age: the browser drops it at exit, and the server enforces SESSION_LIFETIME.
        kind = self._host_kind() or LOCAL
        secure = "Secure; " if kind == EXTERNAL else ""
        cookie = (f"{COOKIE_NAME}={self.server.new_session(kind)}; {secure}HttpOnly; "
                  "SameSite=Strict; Path=/")
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
        # Every refusal below happens before the body is read; _dispatch then answers at once
        # and closes, so a refused client cannot hold the thread by sending its body slowly.
        path, _ = self._target()
        origins, host = self.headers.get_all("Origin"), self.headers["Host"]
        if self._host_kind() == EXTERNAL:
            allowed = external_origin_allowed(origins, host, self.server.settings.external_host)
        else:
            allowed = origin_allowed(origins, host)
        if not allowed:
            raise _Reject(403, "origin not allowed")
        session = self._session()
        if session is None:
            raise _Reject(401, "not signed in")
        csrf = self.headers.get_all(CSRF_HEADER) or []
        if len(csrf) != 1 or not self.server.csrf_ok(session, csrf[0].strip()):
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
        raw = self._read_body(length)
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
    external = normalize_external_host(settings.external_host)
    if external != settings.external_host:
        settings = replace(settings, external_host=external)
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


def external_sign_in_url(server: UiServer) -> str:
    """The link through the same-host HTTPS proxy, or ``""`` when no external name is set."""
    if not server.settings.external_host:
        return ""
    token = urllib.parse.quote(server.token, safe="")
    return f"https://{server.settings.external_host}/?token={token}"


def serve(settings: UiSettings, routes: Routes) -> None:
    """Run the console until interrupted. Logs the sign-in URL(s) once at start."""
    server = build_server(settings, routes)
    # The only place the token is ever written anywhere: one line, both links.
    external = external_sign_in_url(server)
    if external:
        log.info("operator console ready; sign in at %s or %s", sign_in_url(server), external)
        log.warning("operator console is also reachable through a proxy as https://%s; whoever "
                    "can reach that proxy is held back only by the sign-in token",
                    server.settings.external_host)
    else:
        log.info("operator console ready; sign in at %s", sign_in_url(server))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
