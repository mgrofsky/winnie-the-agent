"""Scenario-driven fake HTTP/1.1 server: login form, Basic/Bearer/API-key capture, a
small post-login site and JSON API built from ``scenario.services.http``.

Parser caps: request line 8 KB, 50 headers, 16 KB of header bytes, body 64 KB and only
with Content-Length (chunked is refused with 411). Keep-alive is allowed and bounded by
``conn.command()``. Every request is logged. Unknown routes under ``api_prefix`` may be
answered by the budgeted model (``llm_unknown_api_routes``) through a strict schema; the
fallback is a plain 404. Nothing here makes an outbound connection.
"""

from __future__ import annotations

import base64
import email.utils
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

from agents.llm import untrusted_block
from listeners.base import Conn, ConnClosed, ListenerContext, ServiceSettings, start_tcp
from listeners.sqlfake import wire_text

MAX_REQUEST_LINE = 8192
MAX_HEADERS = 50
MAX_HEADER_BYTES = 16384
MAX_BODY = 65536
MAX_LOG_BODY = 2048
MAX_SESSIONS = 10000
COOKIE_NAME = "session_id"

REASONS = {200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently", 302: "Found",
           400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
           405: "Not Allowed", 409: "Conflict", 411: "Length Required",
           413: "Request Entity Too Large", 414: "Request-URI Too Large", 422: "Unprocessable Entity",
           431: "Request Header Fields Too Large", 500: "Internal Server Error",
           501: "Not Implemented", 505: "HTTP Version Not Supported"}

USER_FIELDS = ("username", "user", "login", "email", "j_username", "userid", "user_name")
PASS_FIELDS = ("password", "pass", "pwd", "passwd", "j_password", "secret")

_SESSIONS: "weakref.WeakKeyDictionary[ListenerContext, OrderedDict[str, dict]]" = \
    weakref.WeakKeyDictionary()


class LlmHttpAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal[200, 201, 400, 403, 404, 409, 422, 500]
    content_type: Literal["application/json", "text/plain"]
    body: str = Field(max_length=4096)


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
    else:
        cfg.server = settings.banner or "nginx"
        cfg.pages = list(DEFAULT_PAGES)
    return cfg


# ---- helpers ------------------------------------------------------------------------------

def server_token(server: str) -> str:
    return server.split()[0] if server.split() else "nginx"


def error_page(status: int, server: str) -> bytes:
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


def parse_cookies(value: Optional[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (value or "").split(";")[:50]:
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# ---- request parsing ----------------------------------------------------------------------

async def read_request(conn: Conn) -> Optional[Request]:
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
    if req.header("transfer-encoding") is not None:
        raise HttpError(411, "transfer_encoding")
    lengths = {v for k, v in headers if k.lower() == "content-length"}
    if len(lengths) > 1:
        raise HttpError(400, "content_length")
    if lengths:
        cl = lengths.pop()
        if not re.fullmatch(r"\d{1,10}", cl):
            raise HttpError(400, "content_length")
        n = int(cl)
        if n > MAX_BODY:
            raise HttpError(413, "body_too_large")
        if n:
            req.body = await conn.readexactly(n)
    return req


# ---- the handler --------------------------------------------------------------------------

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
        if cfg.openapi_path and path == cfg.openapi_path and method == "GET":
            self.log["route"] = "openapi"
            return 200, json_bytes(cfg.openapi or self.generated_openapi()), "application/json", []
        for page in cfg.pages:
            if page.path == path and method == "GET":
                self.log["route"] = "page"
                if page.requires_login and not self.schemes:
                    return 302, b"", "text/html", [("Location", cfg.login_path)]
                return 200, self.render_page(page), "text/html; charset=utf-8", []
        matched_path = False
        for route in cfg.routes:
            m = route_regex(route.path).match(path)
            if not m:
                continue
            matched_path = True
            if route.method != method:
                continue
            self.log["route"] = route.path
            if not self.allowed(route.auth):
                return self.unauthorized_api()
            return self.serve_route(route, {k: wire_text(v, 200) for k, v in m.groupdict().items()})
        if matched_path:
            self.log["route"] = "method_not_allowed"
            return 405, json_bytes({"error": "method not allowed"}), "application/json", []
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
                if ans is not None:
                    self.log["llm"] = True
                    return ans
            return 404, error_page(404, cfg.server), "text/html", []
        self.log["route"] = "not_found"
        return 404, error_page(404, cfg.server), "text/html", []

    def _same_host(self) -> bool:
        try:
            host = urlsplit(self.req.target).hostname or ""
        except ValueError:
            return False
        local = {self.cfg.hostname, f"{self.cfg.hostname}.{self.cfg.domain}", "localhost",
                 str(self.conn.dst_ip)}
        return host in local

    def form_login(self) -> tuple[int, bytes, str, list]:
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
            return route.status, json_bytes(substitute(route.json_body, params)), \
                "application/json", []
        return route.status, json_bytes({"status": "ok"}), "application/json", []

    def generated_openapi(self) -> dict:
        paths: dict = {}
        for r in self.cfg.routes:
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

    async def ask_model(self) -> Optional[tuple[int, bytes, str, list]]:
        cfg = self.cfg
        known = ", ".join(f"{r.method} {r.path}" for r in cfg.routes)[:2000]
        system = ("You emulate the JSON REST API of a decoy web application"
                  f"{' for ' + cfg.org if cfg.org else ''}. Known routes: {known}. Answer the "
                  "HTTP request in the untrusted block as that API would, as JSON "
                  '{"status": <one of 200,201,400,403,404,409,422,500>, "content_type": '
                  '"application/json" or "text/plain", "body": "<response body, at most 4096 '
                  'characters>"}. Use small, plausible, invented data. Never add explanations.')
        req = self.req
        payload = (f"{req.method} {req.path[:500]}{'?' + req.query[:500] if req.query else ''}\n"
                   f"body: {req.body[:1000].decode('utf-8', 'replace')}")
        user = untrusted_block("HTTP request", payload, os.urandom(8).hex())
        try:
            raw = await self.ctx.llm_json(self.conn.task_name, self.conn.src_ip, system, user,
                                          LlmHttpAnswer)
        except Exception:  # noqa: BLE001
            return None
        ans = validate_http_answer(raw)
        if ans is None:
            return None
        if ans.content_type == "application/json":
            try:
                parsed = json.loads(ans.body)
            except (ValueError, RecursionError):
                return None
            if not isinstance(parsed, (dict, list)):
                return None
            return ans.status, json_bytes(parsed), "application/json", []
        return ans.status, wire_text(ans.body, 4096).encode("utf-8"), "text/plain; charset=utf-8", []


def validate_http_answer(raw: Any) -> Optional[LlmHttpAnswer]:
    if raw is None:
        return None
    try:
        if isinstance(raw, BaseModel):
            raw = raw.model_dump()
        return LlmHttpAnswer.model_validate(raw)
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
        data = {"method": req.method, "path": req.path[:500], "query": req.query[:500],
                "status": status, "host": req.header("host") or ""}
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
        token = conn.ctx.honeytoken_in(req.target, req.body[:MAX_BODY].decode("utf-8", "replace"))
        if token:
            data["honeytoken"] = token
            data["high_signal"] = True
        data.update(ex.log)
        conn.emit("command", f"{req.method} {req.path[:200]}", client=ex.ua, username=ex.user,
                  data=data)
        if req.body:
            conn.capture("http_body", req.body[:16_384])
        if not keep:
            return


async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    server = await start_tcp(ctx, "http", settings.port, handle)
    return [server]
