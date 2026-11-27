"""Scenario-driven fake HTTP/1.1 server: login form, Basic/Bearer/API-key capture, a
small post-login site and JSON API built from ``scenario.services.http``.

Parser caps: request line 8 KB, 50 headers, 16 KB of header bytes, body 64 KB and only
with Content-Length (chunked is refused with 411). Keep-alive is allowed and bounded by
``conn.command()``. Every request is logged. Unknown routes under ``api_prefix`` may be
answered by the budgeted model (``llm_unknown_api_routes``) through a strict schema; the
fallback is a plain 404. Other unknown paths get a canned answer for the most-probed paths
(``CANNED_404``, lure files holding only issued tokens, the stack's own 403s), then for a
plain GET the budgeted model (``llm_unknown_paths``) with its answer cached per path, then
the stack's 404 page. Nothing here makes an outbound connection.

Web deception (all optional, configured by the scenario): decoy assets (bundles, source
maps, runtime config) served with their own type and cache headers, a per-source record of
which routes an asset or the OpenAPI document showed (``listeners.http_state``), per-source
``{marker:NAME}`` values recognised when presented back, and fixed local flows for username
checks, account recovery and activation. No flow makes a credential valid or issues a
session. Each request event carries the evidence keys listed in ``docs/architecture.md``.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import html
import json
import os
import re
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Literal, Optional
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from agents.budget import ip_key
from agents.llm import untrusted_block
from listeners.base import Conn, ConnClosed, ListenerContext, ServiceSettings, start_tcp
from listeners.ftp import AWS_CREDENTIALS_PATH, aws_profile
from listeners.http_state import http_state
from listeners.sqlfake import wire_text
from scenarios.schema import MARKER_RE
from scenarios.web_assets import app_name, asset_text

MAX_REQUEST_LINE = 8192
MAX_HEADERS = 50
MAX_HEADER_BYTES = 16384
MAX_BODY = 65536
MAX_LOG_BODY = 2048
MAX_SESSIONS = 10000
COOKIE_NAME = "session_id"
MAX_PAGE_CACHE = 512        # model answers kept per listener, least recently used dropped
MAX_MODEL_PATH = 200        # longer paths never reach the model

REASONS = {200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently", 302: "Found",
           400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
           405: "Not Allowed", 409: "Conflict", 411: "Length Required",
           413: "Request Entity Too Large", 414: "Request-URI Too Large", 422: "Unprocessable Entity",
           431: "Request Header Fields Too Large", 500: "Internal Server Error",
           501: "Not Implemented", 505: "HTTP Version Not Supported"}

USER_FIELDS = ("username", "user", "login", "email", "j_username", "userid", "user_name")
FLOW_TOKEN_FIELDS = ("token", "code", "reset_token", "activation_token", "key", "t")
# Evidence keys, in the order they are written (ahead of optional header and body fields,
# so the 32-key event cap never drops them).
EVIDENCE_KEYS = ("lure_id", "discovered_via", "discovered_age", "marker", "marker_src", "flow",
                 "flow_step", "object_id_count")
ASSET_TYPES = {"css": "text/css", "html": "text/html", "htm": "text/html", "txt": "text/plain",
               "json": "application/json", "js": "application/javascript",
               "mjs": "application/javascript", "map": "application/json",
               "svg": "image/svg+xml", "xml": "text/xml", "webmanifest": "application/manifest+json"}
ASSET_MTIME_BASE = 1_788_000_000    # asset Last-Modified times fall in the months after this
PASS_FIELDS = ("password", "pass", "pwd", "passwd", "j_password", "secret")

_SESSIONS: "weakref.WeakKeyDictionary[ListenerContext, OrderedDict[str, dict]]" = \
    weakref.WeakKeyDictionary()
# Per listener context: (method, path) -> (status, body, content type, rung). A 403 or 404
# is kept without a body and rendered per request as the stack's own page.
_PAGE_CACHE: "weakref.WeakKeyDictionary[ListenerContext, OrderedDict[tuple[str, str], tuple]]" = \
    weakref.WeakKeyDictionary()
# Per listener context: (scenario, {asset path: (asset, text)}, marker names), built once
# per scenario instead of once per connection.
_ASSETS: "weakref.WeakKeyDictionary[ListenerContext, tuple]" = weakref.WeakKeyDictionary()

# Unknown paths that every stack here answers with its 404: no scenario runs WordPress, PHP
# info pages, Spring Boot actuators or a separate /config.json.
CANNED_404 = frozenset({
    "/favicon.ico", "/wp-login.php", "/xmlrpc.php", "/phpinfo.php", "/actuator",
    "/actuator/health", "/actuator/env", "/admin", "/login", "/config.json"})
ROBOTS_TXT = b"User-agent: *\nDisallow: /\n"
GIT_HEAD = b"ref: refs/heads/main\n"
# Honeytoken kinds written to a served /.env, one NAME=value line each.
ENV_KINDS = ("db_password", "generic_password", "sip_trunk_password", "api_key", "bearer_token")
# Paths that never reach the model: hidden files, secrets, archives, code and static assets.
NO_MODEL_EXT = frozenset(
    "asp aspx bak bz2 cfg cgi conf config crt css csv db dll eot env exe gif gz htaccess "
    "htpasswd ico ini jar jpeg jpg js jsp key kdbx log map mp4 old orig p12 pem pfx php pl "
    "png properties py rar rb sh sql sqlite svg swp tar tgz toml ttf txt war webp woff woff2 "
    "xml yaml yml zip 7z".split())
# Path prefixes and file names of other stacks or of secrets that never reach the model.
NO_MODEL_PREFIX = ("/wp-", "/wordpress", "/actuator", "/phpmyadmin", "/pma", "/myadmin",
                   "/mysql", "/cgi-bin", "/etc/", "/proc/", "/vendor/", "/node_modules/",
                   "/server-status", "/server-info", "/console/h2", "/solr", "/jenkins")
NO_MODEL_NAMES = frozenset(
    "authorized_keys backup backups credentials docker-compose dump id_dsa id_ecdsa "
    "id_ed25519 id_rsa known_hosts passwd secrets shadow web.config".split())
UNSAFE_BODY = re.compile(
    r"<\s*(script|iframe|object|embed|meta|link|base|form|applet|frame)\b|javascript:|"
    r"\bon[a-z]{2,20}\s*=|-----BEGIN|AKIA[A-Z2-7]{16}|\b[sr]k_(live|test)_|"
    r"(password|passwd|secret|api[_-]?key|access[_-]?key|token)[\"']?\s*[:=]\s*[\"']?"
    r"[A-Za-z0-9+/_.-]{8,}", re.I)
URL_HOST = re.compile(r"(?:[a-z][a-z0-9+.-]*:)?//([A-Za-z0-9.-]{1,253})", re.I)


# Worked examples sent with a second model request (``ListenerContext.llm_json``).
HTTP_EXAMPLES = (
    'request: GET /api/v1/orders?limit=2\n'
    'answer: {"status": 200, "content_type": "application/json", "body": '
    '"{\\"items\\": [{\\"id\\": 1001, \\"status\\": \\"shipped\\"}, {\\"id\\": 1002, '
    '\\"status\\": \\"open\\"}], \\"total\\": 2}"}\n'
    'request: DELETE /api/v1/admin/users/7\n'
    'answer: {"status": 403, "content_type": "application/json", "body": '
    '"{\\"error\\": \\"forbidden\\"}"}')


# Worked examples for unknown paths outside the API prefix.
PAGE_EXAMPLES = (
    'request: GET /status\n'
    'answer: {"status": 200, "content_type": "text/plain", "body": "OK"}\n'
    'request: GET /internal/reports\n'
    'answer: {"status": 403, "content_type": "text/html", "body": ""}')


class LlmHttpAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal[200, 201, 400, 403, 404, 409, 422, 500]
    content_type: Literal["application/json", "text/plain"]
    body: str = Field(max_length=4096)


class LlmPageAnswer(LlmHttpAnswer):
    """The model's answer for an unknown path outside the API prefix: no redirects, no
    headers, three content types."""

    status: Literal[200, 403, 404, 500]
    content_type: Literal["text/html", "application/json", "text/plain"]


@dataclass
class Request:
    method: str
    target: str
    version: str
    path: str
    query: str
    headers: list[tuple[str, str]]
    body: bytes = b""
    absolute: bool = False

    def header(self, name: str) -> Optional[str]:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None


class HttpError(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass
class HttpCfg:
    server: str = "nginx"
    login_path: str = "/login"
    login_title: str = "Sign in"
    branding: str = ""
    org: str = ""
    hostname: str = "web01"
    domain: str = "example.com"
    pages: list = field(default_factory=list)
    routes: list = field(default_factory=list)
    api_prefix: Optional[str] = None
    api_key_header: str = "X-API-Key"
    openapi_path: Optional[str] = None
    openapi: Optional[dict] = None
    llm_unknown: bool = False
    llm_unknown_paths: bool = True
    assets: dict = field(default_factory=dict)          # path -> (HttpAsset, text)
    openapi_aliases: tuple = ()
    openapi_advertises: tuple = ()
    openapi_lure: str = "openapi"
    markers: frozenset = frozenset()                    # marker names used by the scenario
    accounts: frozenset = frozenset()                   # lowercased account names


DEFAULT_PAGES = [SimpleNamespace(path="/dashboard", title="Dashboard", requires_login=True,
                                 body_html="<h1>Dashboard</h1><p>Welcome back, {{user}}.</p>"
                                           "<p>No new notifications.</p>")]


def build_cfg(ctx: ListenerContext, settings: ServiceSettings) -> HttpCfg:
    scen = ctx.scenario
    svc = scen.scenario.services.http if scen is not None else None
    cfg = HttpCfg()
    if scen is not None:
        ident = scen.scenario.identity
        cfg.org, cfg.hostname, cfg.domain = ident.org_name, scen.hostname, ident.domain
    if svc is not None:
        cfg.server = settings.banner or svc.server_header or "nginx"
        cfg.login_path = svc.login_path
        cfg.login_title = svc.login_title
        cfg.branding = svc.branding
        cfg.pages = list(svc.pages)
        cfg.routes = list(svc.routes)
        cfg.api_prefix = svc.api_prefix
        cfg.api_key_header = svc.api_key_header
        cfg.openapi_path = svc.openapi_path
        cfg.openapi = svc.openapi
        cfg.llm_unknown = svc.llm_unknown_api_routes
        cfg.llm_unknown_paths = svc.llm_unknown_paths
        cached = _ASSETS.get(ctx)
        if cached is None or cached[0] is not scen:
            app = app_name(cfg.domain)
            cached = _ASSETS[ctx] = (scen, {a.path: (a, asset_text(a, svc, app))
                                            for a in svc.assets}, svc.marker_names())
        _, cfg.assets, cfg.markers = cached
        cfg.openapi_aliases = tuple(svc.openapi_aliases)
        cfg.openapi_advertises = tuple(svc.openapi_advertises)
        cfg.openapi_lure = svc.openapi_lure
    else:
        cfg.server = settings.banner or "nginx"
        cfg.pages = list(DEFAULT_PAGES)
    cfg.accounts = frozenset(u.lower() for u, _ in settings.accounts)
    return cfg


# ---- helpers ------------------------------------------------------------------------------

def server_token(server: str) -> str:
    return server.split()[0] if server.split() else "nginx"


def is_apache(server: str) -> bool:
    return server_token(server).lower().startswith("apache")


APACHE_MESSAGES = {403: "You don't have permission to access this resource.",
                   404: "The requested URL was not found on this server."}


def error_page(status: int, server: str, host: str = "localhost", port: int = 80) -> bytes:
    """The server's own error page: Apache's for a 403 or 404 behind an Apache Server
    header, nginx's otherwise."""
    if is_apache(server) and status in APACHE_MESSAGES:
        reason = REASONS[status]
        return (f'<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n'
                f"<title>{status} {reason}</title>\n</head><body>\n<h1>{reason}</h1>\n"
                f"<p>{html.escape(APACHE_MESSAGES[status], quote=False)}</p>\n<hr>\n"
                f"<address>{html.escape(server)} Server at {html.escape(host)} Port {port}"
                "</address>\n</body></html>\n").encode()
    title = f"{status} {REASONS.get(status, 'Error')}"
    return (f"<html>\r\n<head><title>{title}</title></head>\r\n<body>\r\n<center><h1>{title}"
            f"</h1></center>\r\n<hr><center>{html.escape(server_token(server))}</center>\r\n"
            "</body>\r\n</html>\r\n").encode()


def build_response(status: int, server: str, body: bytes = b"", content_type: str = "text/html",
                   headers: Optional[list[tuple[str, str]]] = None, keep_alive: bool = True,
                   head: bool = False) -> bytes:
    lines = [f"HTTP/1.1 {status} {REASONS.get(status, 'OK')}", f"Server: {server}",
             f"Date: {email.utils.formatdate(usegmt=True)}"]
    if body or status not in (204, 302, 301):
        lines.append(f"Content-Type: {content_type}")
    lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: keep-alive" if keep_alive else "Connection: close")
    for k, v in headers or []:
        lines.append(k + ": " + re.sub(r"[\r\n]", "", v))
    out = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")
    return out if head else out + body


def route_regex(template: str) -> re.Pattern:
    rx, pos = "", 0
    for m in re.finditer(r"\{([A-Za-z_][A-Za-z0-9_]{0,63})\}", template):
        rx += re.escape(template[pos:m.start()]) + f"(?P<{m.group(1)}>[^/]{{1,200}})"
        pos = m.end()
    rx += re.escape(template[pos:])
    return re.compile("^" + rx + "/?$")


def substitute(obj: Any, params: dict[str, str]) -> Any:
    if isinstance(obj, str):
        return re.sub(r"\{([A-Za-z_][A-Za-z0-9_]{0,63})\}",
                      lambda m: params.get(m.group(1), m.group(0)), obj)
    if isinstance(obj, list):
        return [substitute(x, params) for x in obj]
    if isinstance(obj, dict):
        return {k: substitute(v, params) for k, v in obj.items()}
    return obj


def json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, default=str, separators=(", ", ": ")).encode("utf-8")


def sessions(ctx: ListenerContext) -> OrderedDict:
    store = _SESSIONS.get(ctx)
    if store is None:
        store = OrderedDict()
        _SESSIONS[ctx] = store
    return store


def page_cache(ctx: ListenerContext) -> OrderedDict:
    store = _PAGE_CACHE.get(ctx)
    if store is None:
        store = OrderedDict()
        _PAGE_CACHE[ctx] = store
    return store


def model_may_answer(method: str, path: str) -> bool:
    """A plain GET of a short, printable path that names no hidden file, secret, archive,
    script or static asset."""
    if method != "GET" or len(path) > MAX_MODEL_PATH or path.lower().startswith(NO_MODEL_PREFIX):
        return False
    if not re.fullmatch(r"/[A-Za-z0-9/_.,~@+=-]*", path) or ".." in path or "//" in path:
        return False
    segments = [s for s in path.split("/") if s]
    if any(s.startswith(".") or s.endswith("~") for s in segments):
        return False
    last = segments[-1] if segments else ""
    if last.lower().split(".", 1)[0] in NO_MODEL_NAMES:
        return False
    return not ("." in last and last.rsplit(".", 1)[1].lower() in NO_MODEL_EXT)


def asset_type(asset) -> str:
    """The Content-Type a static file server sends for the asset."""
    if asset.kind == "bundle":
        return "application/javascript"
    if asset.kind == "source_map":
        return "application/json"
    ext = asset.path.rsplit("/", 1)[-1].rsplit(".", 1)
    ctype = ASSET_TYPES.get(ext[1].lower(), "application/octet-stream") if len(ext) == 2 else \
        "application/octet-stream"
    if asset.kind == "runtime_config" and ctype == "application/octet-stream":
        return "application/json"
    return ctype


def parse_cookies(value: Optional[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (value or "").split(";")[:50]:
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# ---- request parsing ----------------------------------------------------------------------

async def read_request(conn: Conn) -> Optional[Request]:
    req = await read_head(conn)
    if req is None or req.method == "CONNECT":
        return req
    if req.header("transfer-encoding") is not None:
        raise HttpError(411, "transfer_encoding")
    n = content_length(req)
    if n is not None:
        if n > MAX_BODY:
            raise HttpError(413, "body_too_large")
        if n:
            req.body = await conn.readexactly(n)
    return req


def content_length(req: Request) -> Optional[int]:
    """The declared body length; None when absent. Raises HttpError(400) when malformed or
    when several Content-Length headers disagree."""
    lengths = {v for k, v in req.headers if k.lower() == "content-length"}
    if len(lengths) > 1:
        raise HttpError(400, "content_length")
    if not lengths:
        return None
    cl = lengths.pop()
    if not re.fullmatch(r"\d{1,19}", cl):
        raise HttpError(400, "content_length")
    return int(cl)


async def read_head(conn: Conn) -> Optional[Request]:
    """Request line and headers (no body). Shared by the HTTP and S3 traps."""
    line = b""
    for _ in range(4):
        try:
            line = await conn.readline(max_bytes=MAX_REQUEST_LINE)
        except ConnClosed as exc:
            if exc.args and exc.args[0] == "max_line_bytes":
                raise HttpError(414, "request_line_too_long") from None
            raise
        if line:
            break
    if not line:
        return None
    try:
        text = line.decode("latin-1")
    except Exception:  # noqa: BLE001
        raise HttpError(400, "bad_request_line") from None
    parts = text.split(" ")
    if len(parts) != 3 or not re.fullmatch(r"[A-Z]{1,16}", parts[0]):
        raise HttpError(400, "bad_request_line")
    method, target, version = parts
    if not re.fullmatch(r"HTTP/1\.[01]", version):
        raise HttpError(505 if version.startswith("HTTP/") else 400, "bad_version")
    headers: list[tuple[str, str]] = []
    total = 0
    while True:
        try:
            raw = await conn.readline(max_bytes=MAX_REQUEST_LINE)
        except ConnClosed as exc:
            if exc.args and exc.args[0] == "max_line_bytes":
                raise HttpError(431, "header_too_long") from None
            raise
        if not raw:
            break
        total += len(raw)
        if len(headers) >= MAX_HEADERS or total > MAX_HEADER_BYTES:
            raise HttpError(431, "too_many_headers")
        h = raw.decode("latin-1")
        if ":" not in h or h[0] in " \t":
            raise HttpError(400, "bad_header")
        name, value = h.split(":", 1)
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}", name):
            raise HttpError(400, "bad_header")
        headers.append((name, value.strip()))
    req = Request(method, target, version, "/", "", headers)
    if method == "CONNECT":
        req.path = target[:200]
        return req
    try:
        if target.startswith("/"):
            split = urlsplit(target)
        elif re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", target):
            split = urlsplit(target)
            req.absolute = True
        elif target == "*" and method == "OPTIONS":
            split = urlsplit("/")
        else:
            raise HttpError(400, "bad_target")
        req.path = unquote(split.path or "/", errors="replace")
        req.query = split.query
    except ValueError:  # e.g. "//[x/": unbalanced IPv6 brackets in the authority
        raise HttpError(400, "bad_target") from None
    return req


# ---- the handler --------------------------------------------------------------------------

def source_key(conn: Conn) -> str:
    """The per-source state key: the address, IPv6 sources grouped per /64."""
    return ip_key(conn.src_ip)


class Exchange:
    """One request/response, with logging fields accumulated along the way."""

    def __init__(self, conn: Conn, cfg: HttpCfg, req: Request) -> None:
        self.conn = conn
        self.ctx = conn.ctx
        self.cfg = cfg
        self.req = req
        self.ua = req.header("user-agent")
        self.log: dict = {}
        self.user: Optional[str] = None
        self.schemes: set[str] = set()
        self.set_cookie: Optional[str] = None
        self.close = False
        self.state = http_state(self.ctx)
        self.key = source_key(conn)
        self.seq = self.state.next_seq(self.key)
        self.ev: dict = {}          # evidence keys (EVIDENCE_KEYS) for this request

    # ---- auth ---------------------------------------------------------------------------

    def _login(self, scheme: str, username: str, secret: str) -> bool:
        cache = self.conn.state.setdefault("http_auth", {})
        key = (scheme, username, secret)
        if key in cache:
            return cache[key]
        if len(cache) > 64:
            cache.clear()
        ok = self.conn.login(username, secret, client=self.ua,
                             data={"method": scheme, "path": self.req.path[:200]})
        cache[key] = ok
        return ok

    def authenticate(self) -> None:
        sid = parse_cookies(self.req.header("cookie")).get(COOKIE_NAME)
        if sid:
            store = sessions(self.ctx)
            sess = store.get(sid)
            if sess is not None:
                store.move_to_end(sid)
                self.schemes.add("session")
                self.user = sess["user"]
            else:
                self.log["stale_cookie"] = True
        auth = self.req.header("authorization")
        if auth:
            scheme, _, cred = auth.partition(" ")
            scheme_l = scheme.lower()
            self.log["auth_scheme"] = scheme_l[:20]
            if scheme_l == "basic":
                try:
                    decoded = base64.b64decode(cred.strip(), validate=False).decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    decoded = ""
                    self.log["auth_raw"] = cred[:200]
                if ":" in decoded:
                    user, _, pw = decoded.partition(":")
                else:   # a bare token: it is the secret, never a username
                    user, pw = "<basic>", decoded
                if decoded and self._login("basic", user, pw):
                    self.schemes.add("basic")
                    self.user = user
            elif scheme_l == "bearer":
                token = cred.strip()
                if token and self._login("bearer", "<bearer>", token):
                    self.schemes.add("bearer")
                    self.user = self.user or "<bearer>"
            else:
                self.log["auth_raw"] = auth[:200]
        key = self.req.header(self.cfg.api_key_header)
        if key:
            self.log["api_key_header"] = self.cfg.api_key_header
            if self._login("api_key", "<api_key>", key.strip()):
                self.schemes.add("api_key")
                self.user = self.user or "<api_key>"

    def allowed(self, required: str) -> bool:
        if required == "none":
            return True
        if required == "any":
            return bool(self.schemes)
        return required in self.schemes

    # ---- responses ----------------------------------------------------------------------

    def page_html(self, title: str, body: str, nav: bool = True) -> bytes:
        cfg = self.cfg
        org = html.escape(cfg.org or "Portal")
        links = ""
        if nav:
            links = " ".join(f'<a href="{html.escape(p.path)}">{html.escape(p.title)}</a>'
                             for p in cfg.pages if "{" not in p.path)
            links += ' <a href="/logout">Sign out</a>'
        who = f'<span class="who">{html.escape(self.user or "")}</span>' if nav and self.user else ""
        return (
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
            f"<title>{html.escape(title)} - {org}</title>\n"
            "<style>body{font-family:Arial,Helvetica,sans-serif;margin:0;background:#f4f6f8;color:#222}"
            "header{background:#1f3a5f;color:#fff;padding:12px 24px}header a{color:#cfe0f5;"
            "margin-right:14px;text-decoration:none}.who{float:right}main{padding:24px}"
            "table{border-collapse:collapse;background:#fff}td,th{border:1px solid #ccd;padding:6px 10px}"
            ".box{max-width:360px;margin:80px auto;background:#fff;padding:28px;border-radius:6px;"
            "box-shadow:0 1px 4px rgba(0,0,0,.15)}input{width:100%;padding:8px;margin:6px 0 14px;"
            "box-sizing:border-box}button{padding:9px 18px;background:#1f3a5f;color:#fff;border:0}"
            ".err{color:#b00020}</style>\n</head>\n<body>\n"
            + (f"<header><strong>{org}</strong> &nbsp; {links}{who}</header>\n" if nav else "")
            + f"<main>\n{body}\n</main>\n</body>\n</html>\n").encode("utf-8")

    def login_page(self, error: str = "") -> bytes:
        cfg = self.cfg
        err = f'<p class="err">{html.escape(error)}</p>' if error else ""
        brand = f"<p>{html.escape(cfg.branding)}</p>" if cfg.branding else ""
        body = (f'<div class="box"><h2>{html.escape(cfg.login_title)}</h2>{brand}{err}'
                f'<form method="post" action="{html.escape(cfg.login_path)}">'
                '<label for="username">Username</label>'
                '<input id="username" name="username" type="text" autocomplete="username">'
                '<label for="password">Password</label>'
                '<input id="password" name="password" type="password" '
                'autocomplete="current-password">'
                '<button type="submit">Sign in</button></form></div>')
        return self.page_html(cfg.login_title, body, nav=False)

    def render_page(self, page) -> bytes:
        subs = {"user": self.user or "", "org": self.cfg.org, "hostname": self.cfg.hostname,
                "domain": self.cfg.domain}
        body = re.sub(r"\{\{(user|org|hostname|domain)\}\}",
                      lambda m: html.escape(subs[m.group(1)]), page.body_html)
        return self.page_html(page.title, body)

    def first_page(self) -> str:
        for p in self.cfg.pages:
            if "{" not in p.path and p.path != self.cfg.login_path:
                return p.path
        return "/"

    def unauthorized_api(self) -> tuple[int, bytes, str, list]:
        realm = (self.cfg.org or "api").replace('"', "")
        return (401, json_bytes({"error": "unauthorized", "message": "Authentication required"}),
                "application/json", [("WWW-Authenticate", f'Basic realm="{realm}"')])

    def is_api_path(self) -> bool:
        p = self.cfg.api_prefix
        return bool(p) and (self.req.path == p or self.req.path.startswith(p.rstrip("/") + "/"))

    # ---- dispatch -----------------------------------------------------------------------

    async def respond(self) -> tuple[int, bytes, str, list]:
        req, cfg = self.req, self.cfg
        if req.method == "CONNECT" or (req.absolute and not self._same_host()):
            self.log.update({"signal": "http_proxy_attempt", "high_signal": True,
                             "route": "proxy"})
            self.close = True
            return 400, error_page(400, cfg.server), "text/html", []
        self.authenticate()
        self.recognise_marker()
        path = req.path
        method = "GET" if req.method == "HEAD" else req.method

        if path == cfg.login_path:
            self.log["route"] = "login"
            if method == "GET":
                return 200, self.login_page(), "text/html; charset=utf-8", []
            if method == "POST":
                return self.form_login()
            return 405, error_page(405, cfg.server), "text/html", []
        if path == "/logout":
            self.log["route"] = "logout"
            sid = parse_cookies(req.header("cookie")).get(COOKIE_NAME)
            if sid:
                sessions(self.ctx).pop(sid, None)
            return 302, b"", "text/html", [
                ("Location", cfg.login_path),
                ("Set-Cookie", f"{COOKIE_NAME}=deleted; Path=/; Max-Age=0; HttpOnly")]
        if cfg.openapi_path and (path == cfg.openapi_path or path in cfg.openapi_aliases) \
                and method == "GET":
            self.log["route"] = "openapi"
            if cfg.openapi_advertises:
                self.ev["lure_id"] = cfg.openapi_lure
                if req.method == "GET":
                    self.state.show(self.key, cfg.openapi_advertises, cfg.openapi_lure)
            return 200, json_bytes(cfg.openapi or self.generated_openapi()), "application/json", []
        for page in cfg.pages:
            if page.path == path and method == "GET":
                self.log["route"] = "page"
                if page.requires_login and not self.schemes:
                    return 302, b"", "text/html", [("Location", cfg.login_path)]
                return 200, self.render_page(page), "text/html; charset=utf-8", []
        matched_path = None
        for route in cfg.routes:
            m = route_regex(route.path).match(path)
            if not m:
                continue
            if matched_path is None:
                matched_path = route
            if route.method != method:
                continue
            self.log["route"] = route.path
            params = {k: wire_text(v, 200) for k, v in m.groupdict().items()}
            self.route_evidence(route, params)
            if not self.allowed(route.auth):
                return self.unauthorized_api()
            if route.flow:
                return self.run_flow(route, params)
            return self.serve_route(route, params)
        if matched_path is not None:
            self.log["route"] = "method_not_allowed"
            self.route_evidence(matched_path, {}, count_ids=False)
            return 405, json_bytes({"error": "method not allowed"}), "application/json", []
        asset = cfg.assets.get(path)
        if asset is not None:
            return self.serve_asset(*asset)
        if path == "/":
            self.log["route"] = "root"
            target = self.first_page() if self.schemes else cfg.login_path
            return 302, b"", "text/html", [("Location", target)]
        if self.is_api_path():
            self.log["route"] = "api_unknown"
            if not self.schemes:
                return self.unauthorized_api()
            if cfg.llm_unknown:
                ans = await self.ask_model()
                rung = self.ctx.take_llm_rung(self.conn.task_name)
                if ans is not None:
                    self.log["llm"] = True
                    self.log["rung"] = rung or "llm"
                    return ans
                self.log["rung"] = "fallback"
            return self.error(404)
        return await self.unknown_path(method)

    # ---- unknown paths outside the API prefix --------------------------------------------

    def error(self, status: int) -> tuple[int, bytes, str, list]:
        """The stack's error page, with Apache's address line built from the Host header."""
        host, port = self.cfg.hostname, 80
        m = re.fullmatch(r"([A-Za-z0-9.-]{1,253})(?::(\d{1,5}))?", self.req.header("host") or "")
        if m:
            host = m.group(1)
            port = int(m.group(2)) if m.group(2) and 0 < int(m.group(2)) < 65536 else 80
        ctype = "text/html; charset=iso-8859-1" if is_apache(self.cfg.server) and status in \
            APACHE_MESSAGES else "text/html"
        return status, error_page(status, self.cfg.server, host, port), ctype, []

    async def unknown_path(self, method: str) -> tuple[int, bytes, str, list]:
        canned = self.canned(method)
        if canned is not None:
            self.log["route"] = "canned"
            return canned
        self.log["route"] = "not_found"
        path = self.req.path
        if not (self.cfg.llm_unknown_paths and self.ctx.json_llm is not None
                and model_may_answer(method, path)):
            return self.error(404)
        self.log["route"] = "unknown_page"
        cache, key = page_cache(self.ctx), (method, path)
        hit = cache.get(key)
        if hit is None:
            ans = await self.ask_model(page=True)
            rung = self.ctx.take_llm_rung(self.conn.task_name) or "llm"
            hit = cache.get(key)    # an answer stored while this one was pending wins
            if hit is None:
                if ans is None:
                    hit = (404, None, None, "fallback")
                elif ans[0] in (403, 404):
                    hit = (ans[0], None, None, rung)
                else:
                    hit = (ans[0], ans[1], ans[2], rung)
                cache[key] = hit
                while len(cache) > MAX_PAGE_CACHE:
                    cache.popitem(last=False)
        else:
            cache.move_to_end(key)
            self.log["cache_hit"] = True
        status, body, ctype, rung = hit
        self.log["rung"] = rung
        if rung != "fallback":
            self.log["llm"] = True
        if body is None:
            return self.error(status)
        return status, body, ctype, []

    def canned(self, method: str) -> Optional[tuple[int, bytes, str, list]]:
        """Answers for the most-probed paths, or None. A lure file answers only when it
        holds a token this sensor issued; without one the path is the stack's 404."""
        path, apache = self.req.path, is_apache(self.cfg.server)
        if (path in CANNED_404 and not self.has_paths_under(path)) or \
                (not self.cfg.api_prefix and path.startswith("/api/v1/")):
            self.log["canned"] = "not_found"
            return self.error(404)
        if path in ("/server-status", "/cgi-bin/") and apache:
            self.log["canned"] = "forbidden"
            return self.error(403)
        if path.startswith("/cgi-bin/") or path in ("/server-status", "/cgi-bin"):
            self.log["canned"] = "not_found"
            return self.error(404)
        files = {"/robots.txt": lambda: (ROBOTS_TXT, []),
                 "/.env": self.lure_env,
                 "/.git/config": self.lure_git_config,
                 "/.git/HEAD": lambda: (GIT_HEAD, []) if self.lure_git_config()[0] else (b"", []),
                 AWS_CREDENTIALS_PATH: self.lure_aws}
        make = files.get(path)
        if make is None:
            return None
        body, names = make()
        if not body:
            self.log["canned"] = "not_found"
            return self.error(404)
        self.log["canned"] = "file"
        if method != "GET":     # a static file answers other methods with 405
            return 405, error_page(405, self.cfg.server), "text/html", []
        if names:
            self.log.update(lure=path, lure_tokens=",".join(names)[:200])
        ctype = "text/plain" if path == "/robots.txt" else "application/octet-stream"
        return 200, body, ctype, []

    def has_paths_under(self, path: str) -> bool:
        """True when a configured page, route, login or API path lies below ``path``, so
        the site treats it as a directory and not as a missing file."""
        cfg, prefix = self.cfg, path.rstrip("/") + "/"
        known = [p.path for p in cfg.pages] + [r.path for r in cfg.routes] + \
            [cfg.login_path, cfg.api_prefix or ""] + list(cfg.assets) + list(cfg.openapi_aliases)
        return any(k.startswith(prefix) for k in known)

    def scenario_tokens(self, kinds) -> list:
        """The scenario's honeytokens of ``kinds`` as issued now (never a legacy value)."""
        scen = self.ctx.scenario
        if scen is None:
            return []
        return [t for t in scen.honeytokens.values() if t.kind in kinds]

    def source_pair(self) -> Optional[tuple[str, str]]:
        """The per-source key pair, only for a source marked ``plant_token``."""
        entry = self.ctx.source(self.conn.src_ip)
        if entry is None or not entry.plant_token:
            return None
        return self.ctx.source_token(self.conn.src_ip)

    def lure_env(self) -> tuple[bytes, list[str]]:
        lines, names = [], []
        for t in self.scenario_tokens(ENV_KINDS):
            lines.append(f"{t.name.upper()}={t.value}")
            names.append(t.name)
        pair = self.source_pair()
        if pair is not None:
            lines += [f"AWS_ACCESS_KEY_ID={pair[0]}", f"AWS_SECRET_ACCESS_KEY={pair[1]}"]
            names.append("source_token")
        else:
            for t in self.scenario_tokens(("aws_access_key",))[:1]:
                lines.append(f"AWS_ACCESS_KEY_ID={t.value}")
                names.append(t.name)
        if not lines:
            return b"", []
        head = ["APP_ENV=production", f"APP_URL=https://{self.cfg.hostname}.{self.cfg.domain}"]
        return ("\n".join(head + lines) + "\n").encode(), names

    def lure_git_config(self) -> tuple[bytes, list[str]]:
        tokens = self.scenario_tokens(("bearer_token",)) or self.scenario_tokens(("api_key",))
        if not tokens:
            return b"", []
        t, host = tokens[0], self.cfg.hostname
        body = ("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
                "\tlogallrefupdates = true\n[remote \"origin\"]\n"
                f"\turl = https://oauth2:{t.value}@git.{self.cfg.domain}/ops/{host}.git\n"
                "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
                "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n")
        return body.encode(), [t.name]

    def lure_aws(self) -> tuple[bytes, list[str]]:
        pair = self.source_pair()
        if pair is None:
            return b"", []
        return aws_profile("default", *pair).encode(), ["source_token"]

    def _same_host(self) -> bool:
        try:
            host = urlsplit(self.req.target).hostname or ""
        except ValueError:
            return False
        local = {self.cfg.hostname, f"{self.cfg.hostname}.{self.cfg.domain}", "localhost",
                 str(self.conn.dst_ip)}
        return host in local

    def form_login(self) -> tuple[int, bytes, str, list]:
        fields = self.body_fields()
        self.log["form_keys"] = ",".join(sorted(fields))[:200]
        lower = {k.lower(): v for k, v in fields.items()}
        user = next((lower[k] for k in USER_FIELDS if k in lower), None)
        pw = next((lower[k] for k in PASS_FIELDS if k in lower), None)
        if user is None or pw is None:
            return 200, self.login_page("Please enter your username and password."), \
                "text/html; charset=utf-8", []
        ok = self.conn.login(user, pw, client=self.ua,
                             data={"method": "form", "path": self.req.path[:200]})
        if not ok:
            return 200, self.login_page("Invalid username or password."), \
                "text/html; charset=utf-8", []
        sid = os.urandom(16).hex()
        store = sessions(self.ctx)
        store[sid] = {"user": user, "ip": self.conn.src_ip}
        while len(store) > MAX_SESSIONS:
            store.popitem(last=False)
        self.user = user
        self.log["session_created"] = True
        return 302, b"", "text/html", [
            ("Location", self.first_page()),
            ("Set-Cookie", f"{COOKIE_NAME}={sid}; Path=/; HttpOnly; SameSite=Lax")]

    def serve_route(self, route, params: dict[str, str]) -> tuple[int, bytes, str, list]:
        status, body, ctype, headers = self._serve_route(route, params)
        if status < 400 and route is self.token_route():
            body = self.plant_token(body)
        return status, body, ctype, headers

    def token_route(self):
        """The first route whose path looks like configuration or settings, if any."""
        for r in self.cfg.routes:
            low = r.path.lower()
            if "config" in low or "settings" in low:
                return r
        return None

    def plant_token(self, body: bytes) -> bytes:
        """Sources marked ``plant_token`` get their own key pair in the config JSON."""
        entry = self.ctx.source(self.conn.src_ip)
        if entry is None or not entry.plant_token:
            return body
        key_id, secret = self.ctx.source_token(self.conn.src_ip)
        pair = {"aws_access_key_id": key_id, "aws_secret_access_key": secret}
        try:
            obj = json.loads(body)
        except ValueError:
            return body
        if isinstance(obj, dict):
            obj.update(pair)
        elif isinstance(obj, list):
            obj.append(pair)
        else:
            return body
        return json_bytes(obj)

    def _serve_route(self, route, params: dict[str, str]) -> tuple[int, bytes, str, list]:
        scen = self.ctx.scenario
        if route.list_from:
            rows: list = []
            if scen is not None:
                try:
                    cols, data = scen.lookup(route.list_from)
                    rows = [dict(zip(cols, r, strict=False)) for r in data[:route.list_limit]]
                except Exception:  # noqa: BLE001 - bad scenario data -> empty list
                    rows = []
            return route.status, json_bytes(rows), "application/json", []
        if route.item_from:
            value = params.get(route.item_key) if route.item_key in params else (
                list(params.values())[-1] if params else None)
            if scen is not None and value is not None:
                try:
                    cols, data = scen.lookup(route.item_from)
                except Exception:  # noqa: BLE001
                    cols, data = [], []
                if route.item_key in cols:
                    idx = cols.index(route.item_key)
                    for r in data:
                        if str(r[idx]) == value:
                            return route.status, json_bytes(dict(zip(cols, r, strict=False))), \
                                "application/json", []
            return 404, json_bytes({"error": "not found"}), "application/json", []
        if route.json_body is not None:
            # Markers first, from the scenario's own text, so a path parameter never names one.
            body = self.fill_markers(route.json_body) if self.cfg.markers else route.json_body
            return route.status, json_bytes(substitute(body, params)), "application/json", []
        return route.status, json_bytes({"status": "ok"}), "application/json", []

    # ---- web deception ------------------------------------------------------------------

    def fill_markers(self, obj: Any) -> Any:
        """``obj`` with each ``{marker:NAME}`` in its strings replaced by this source's value."""
        if isinstance(obj, str):
            if "{marker:" not in obj:
                return obj
            return MARKER_RE.sub(lambda m: self.state.marker(self.key, m.group(1))
                                 if m.group(1) in self.cfg.markers else m.group(0), obj)
        if isinstance(obj, list):
            return [self.fill_markers(x) for x in obj]
        if isinstance(obj, dict):
            return {k: self.fill_markers(v) for k, v in obj.items()}
        return obj

    def recognise_marker(self) -> None:
        """Note a marker issued by this listener in the target, body, Authorization, API-key
        header or Cookie, and whether it was issued to another source."""
        if not self.cfg.markers:
            return
        req = self.req
        auth = req.header("authorization")
        texts = [req.target, req.body[:MAX_BODY].decode("utf-8", "replace") if req.body else None,
                 auth, req.header(self.cfg.api_key_header), req.header("cookie")]
        scheme, _, cred = (auth or "").partition(" ")
        if scheme.lower() == "basic" and cred:
            try:    # a key tried as "-u key:" arrives base64 encoded
                texts.append(base64.b64decode(cred.strip()[:4096], validate=False)
                             .decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001
                pass
        hit = self.state.find_marker(texts)
        if hit is not None:
            self.ev["marker"] = hit[0]
            if hit[1] != self.key:
                self.ev["marker_src"] = True

    def route_evidence(self, route, params: dict[str, str], count_ids: bool = True) -> None:
        """Lure, discovery and object-ID evidence for a matched route."""
        if route.lure:
            self.ev["lure_id"] = route.lure
        found = self.state.discovery(self.key, route.path)
        if found is not None:
            self.ev["discovered_via"], self.ev["discovered_age"] = found
        if count_ids and route.lure and route.item_from:
            value = params.get(route.item_key) if route.item_key in params else (
                list(params.values())[-1] if params else None)
            if value is not None:
                self.ev["object_id_count"] = self.state.count_id(self.key, route.path, value)

    def serve_asset(self, asset, text: str) -> tuple[int, bytes, str, list]:
        """A decoy asset with its own type, ETag, Last-Modified and cache headers, like the
        server's static file handler. A GET records the routes it advertises as shown."""
        self.log["route"] = "asset"
        self.ev["lure_id"] = asset.lure
        if self.req.method not in ("GET", "HEAD"):
            return 405, error_page(405, self.cfg.server), "text/html", []
        if self.cfg.markers and "{marker:" in text:
            text = self.fill_markers(text)
        body = text.encode("utf-8")
        if self.req.method == "GET" and asset.advertises:
            self.state.show(self.key, asset.advertises, asset.lure)
        digest = hashlib.sha256(f"{self.cfg.hostname}|{asset.path}".encode()).digest()
        mtime = ASSET_MTIME_BASE + int.from_bytes(digest[:4], "big") % 7_000_000
        headers = [("Last-Modified", email.utils.formatdate(mtime, usegmt=True)),
                   ("ETag", f'"{mtime:x}-{len(body):x}"'),
                   ("Cache-Control", "no-cache" if asset.kind == "runtime_config"
                    else "public, max-age=31536000, immutable"),
                   ("Accept-Ranges", "bytes")]
        return 200, body, asset_type(asset), headers

    def request_fields(self) -> dict[str, str]:
        """Query and body fields (form or JSON object), keys lowercased, values capped."""
        fields: dict[str, str] = {}
        try:
            qs = parse_qs(self.req.query, keep_blank_values=True, max_num_fields=50)
            fields.update({k[:64].lower(): v[0][:256] for k, v in qs.items() if v})
        except ValueError:
            pass
        fields.update({k.lower(): v for k, v in self.body_fields().items()})
        return fields

    def body_fields(self) -> dict[str, str]:
        ctype = (self.req.header("content-type") or "").lower()
        fields: dict[str, str] = {}
        try:
            text = self.req.body.decode("utf-8", "replace")
            if "json" in ctype:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    fields = {str(k)[:64]: str(v)[:256] for k, v in list(obj.items())[:50]}
            else:
                qs = parse_qs(text, keep_blank_values=True, max_num_fields=50)
                fields = {k[:64]: v[0][:256] for k, v in qs.items() if v}
        except (ValueError, RecursionError):
            fields = {}
        return fields

    def run_flow(self, route, params: dict[str, str]) -> tuple[int, bytes, str, list]:
        """The fixed local reply of a multi-step flow. Nothing is sent anywhere, no
        credential becomes valid and no session is issued."""
        flow = route.flow
        self.ev["flow"] = flow
        fields = self.request_fields()
        fields.update({k.lower(): v for k, v in params.items()})
        if flow == "username_check":
            name = next((fields[k] for k in USER_FIELDS if fields.get(k)), None)
            if name is None:
                self.ev["flow_step"] = "missing"
                return 400, json_bytes({"error": "username is required"}), "application/json", []
            exists = name.strip().lower() in self.cfg.accounts
            self.ev["flow_step"] = "exists" if exists else "unknown"
            return route.status, json_bytes({"exists": exists}), "application/json", []
        if flow == "recovery_request":
            self.ev["flow_step"] = "requested"
            return route.status, json_bytes({
                "message": "If an account exists for that address, you will receive an email "
                           "with a link to reset your password."}), "application/json", []
        what = "password reset" if flow == "recovery_reset" else "activation"
        if not any(fields.get(k) for k in FLOW_TOKEN_FIELDS):
            self.ev["flow_step"] = "missing"
            return 400, json_bytes({"error": "token is required"}), "application/json", []
        self.ev["flow_step"] = "token_rejected"
        return 400, json_bytes({"error": "invalid_token",
                                "message": f"This {what} link is invalid or has expired."}), \
            "application/json", []

    def generated_openapi(self) -> dict:
        paths: dict = {}
        for r in self.cfg.routes:
            if r.hidden:
                continue
            entry = paths.setdefault(r.path, {})
            params = [{"name": n, "in": "path", "required": True, "schema": {"type": "string"}}
                      for n in re.findall(r"\{([A-Za-z_]\w*)\}", r.path)]
            entry[r.method.lower()] = {"summary": f"{r.method} {r.path}", "parameters": params,
                                       "responses": {str(r.status): {"description": "OK"}}}
        return {"openapi": "3.0.3",
                "info": {"title": f"{self.cfg.org or 'Service'} API", "version": "1.0.0"},
                "components": {"securitySchemes": {
                    "basicAuth": {"type": "http", "scheme": "basic"},
                    "bearerAuth": {"type": "http", "scheme": "bearer"},
                    "apiKey": {"type": "apiKey", "in": "header", "name": self.cfg.api_key_header}}},
                "paths": paths}

    async def ask_model(self, page: bool = False) -> Optional[tuple[int, bytes, str, list]]:
        """The model's answer for an unknown API route, or with ``page`` for an unknown path
        outside the API prefix. A page answer is shared by every client, so the model sees
        only the method and path, and a body with markup that runs, loads or redirects, or
        anything credential-shaped, is refused."""
        cfg = self.cfg
        req = self.req
        if page:
            pages = ", ".join(p.path for p in cfg.pages)[:1000]
            system = ("You emulate the web server of a decoy web application"
                      f"{' for ' + cfg.org if cfg.org else ''} (Server: {cfg.server}). Known "
                      f"pages: {pages}. Answer the HTTP request in the untrusted block as that "
                      'server would, as JSON {"status": <one of 200,403,404,500>, '
                      '"content_type": "text/html", "application/json" or "text/plain", '
                      '"body": "<response body, at most 4096 characters>"}. Plain, small, '
                      "static content only: no scripts, forms, links to other sites, "
                      "credentials, keys or tokens. Never add explanations.")
            payload = f"{req.method if req.method != 'HEAD' else 'GET'} {req.path[:MAX_MODEL_PATH]}"
            schema, examples = LlmPageAnswer, PAGE_EXAMPLES
        else:
            known = ", ".join(f"{r.method} {r.path}" for r in cfg.routes if not r.hidden)[:2000]
            system = ("You emulate the JSON REST API of a decoy web application"
                      f"{' for ' + cfg.org if cfg.org else ''}. Known routes: {known}. Answer the "
                      "HTTP request in the untrusted block as that API would, as JSON "
                      '{"status": <one of 200,201,400,403,404,409,422,500>, "content_type": '
                      '"application/json" or "text/plain", "body": "<response body, at most 4096 '
                      'characters>"}. Use small, plausible, invented data. Never add explanations.')
            payload = (f"{req.method} {req.path[:500]}{'?' + req.query[:500] if req.query else ''}\n"
                       f"body: {req.body[:1000].decode('utf-8', 'replace')}")
            schema, examples = LlmHttpAnswer, HTTP_EXAMPLES
        user = untrusted_block("HTTP request", payload, os.urandom(8).hex())
        try:
            raw = await self.ctx.llm_json(self.conn.task_name, self.conn.src_ip, system, user,
                                          schema, examples=examples)
        except Exception:  # noqa: BLE001
            return None
        ans = validate_http_answer(raw, schema)
        if ans is None:
            return None
        if page:
            if not self.safe_page_body(ans.body):
                return None
            if ans.content_type == "text/html":
                return ans.status, ans.body.encode("utf-8"), "text/html; charset=utf-8", []
        if ans.content_type == "application/json":
            try:
                parsed = json.loads(ans.body)
            except (ValueError, RecursionError):
                return None
            if not isinstance(parsed, (dict, list)):
                return None
            return ans.status, json_bytes(parsed), "application/json", []
        return ans.status, wire_text(ans.body, 4096).encode("utf-8"), "text/plain; charset=utf-8", []

    def safe_page_body(self, body: str) -> bool:
        """The body as written and as a browser reads it: character references decoded
        (twice, for a doubly encoded one), tabs and line breaks dropped and backslashes read
        as slashes, the way a URL attribute is parsed."""
        decoded = html.unescape(html.unescape(body))
        decoded = re.sub(r"[\t\r\n\x00]", "", decoded).replace("\\", "/")
        local = {self.cfg.hostname.lower(), self.cfg.domain.lower(), "localhost"}
        for text in (body, decoded):
            if UNSAFE_BODY.search(text):
                return False
            for m in URL_HOST.finditer(text):
                host = m.group(1).lower().rstrip(".")
                if host not in local and not host.endswith("." + self.cfg.domain.lower()):
                    return False
        return True


def validate_http_answer(raw: Any, schema: type[LlmHttpAnswer] = LlmHttpAnswer
                         ) -> Optional[LlmHttpAnswer]:
    if raw is None:
        return None
    try:
        if isinstance(raw, BaseModel):
            raw = raw.model_dump()
        return schema.model_validate(raw)
    except Exception:  # noqa: BLE001
        return None


async def handle(conn: Conn) -> None:
    settings = conn.ctx.service("http")
    cfg = build_cfg(conn.ctx, settings)
    while True:
        try:
            req = await read_request(conn)
        except ConnClosed:
            raise
        except Exception as exc:  # noqa: BLE001 - any parse failure is a plain 400
            if not isinstance(exc, HttpError):
                exc = HttpError(400, "parse_error")
            conn.emit("error", "Malformed HTTP request", data={"reason": exc.reason,
                                                               "status": exc.status})
            await conn.write(build_response(exc.status, cfg.server, error_page(exc.status, cfg.server),
                                            keep_alive=False))
            return
        if req is None:
            return
        if not conn.command():
            return
        ex = Exchange(conn, cfg, req)
        status, body, ctype, headers = await ex.respond()
        conn_hdr = (req.header("connection") or "").lower()
        keep = ("close" not in conn_hdr) if req.version == "HTTP/1.1" else ("keep-alive" in conn_hdr)
        keep = keep and not ex.close
        if ex.set_cookie:
            headers.append(("Set-Cookie", ex.set_cookie))
        await conn.write(build_response(status, cfg.server, body, ctype, headers, keep_alive=keep,
                                        head=req.method == "HEAD"))
        nreq = conn.state["http_req"] = conn.state.get("http_req", 0) + 1
        # Order matters: the event keeps its first 32 keys, so the request line, route and
        # evidence come before optional headers and body fields.
        data = {"method": req.method, "path": req.path[:500], "query": req.query[:500],
                "status": status, "host": req.header("host") or ""}
        for k in ("route", "rung"):
            if k in ex.log:
                data[k] = ex.log[k]
        data["seq"], data["req"] = ex.seq, nreq
        for k in EVIDENCE_KEYS:
            if k in ex.ev:
                data[k] = ex.ev[k]
        data["resp_type"] = ctype if body or status not in (204, 302, 301) else ""
        data["resp_bytes"] = 0 if req.method == "HEAD" else len(body)
        token = conn.ctx.honeytoken_in(req.target, req.body[:MAX_BODY].decode("utf-8", "replace"))
        if token:
            data["honeytoken"] = token
            data["high_signal"] = True
        data.update(ex.log)
        for k in ("referer", "x-forwarded-for", "content-type", "origin"):
            v = req.header(k)
            if v:
                data[k.replace("-", "_")] = v[:200]
        if req.body:
            data["body"] = req.body[:MAX_LOG_BODY].decode("utf-8", "replace")
            data["body_bytes"] = len(req.body)
        if req.absolute:
            data["absolute_uri"] = req.target[:500]
        if ".." in req.path or "%2e%2e" in req.target.lower():
            data["path_traversal"] = True
        conn.emit("command", f"{req.method} {req.path[:200]}", client=ex.ua, username=ex.user,
                  data=data)
        if req.body:
            conn.capture("http_body", req.body[:16_384])
        if not keep:
            return


async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    server = await start_tcp(ctx, "http", settings.port, handle)
    return [server]
