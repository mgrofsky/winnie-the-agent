"""Operator console HTTP shell: binding, Host/Origin, sign-in, throttle, CSRF, limits, headers."""

import hashlib
import hmac
import http.client
import json
import logging
import re
import secrets
import threading
import urllib.parse
from dataclasses import dataclass

import pytest

from agents.ui import server as ui
from agents.ui.server import STATIC_DIR, UiSettings, build_server

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
}
DEFAULT = object()


class FakeRoutes:
    def __init__(self):
        self.gets: list[tuple[str, dict]] = []
        self.posts: list[tuple[str, dict]] = []
        self.get_result: tuple[int, object] = (200, {"ok": True})
        self.post_result: tuple[int, object] = (201, {"done": True})
        self.error: Exception | None = None

    def get(self, path, query):
        self.gets.append((path, dict(query)))
        if self.error:
            raise self.error
        return self.get_result

    def post(self, path, body):
        self.posts.append((path, body))
        if self.error:
            raise self.error
        return self.post_result


@dataclass
class Response:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name):
        values = [v for k, v in self.headers if k.lower() == name.lower()]
        return values[0] if values else None

    def json(self):
        return json.loads(self.body)


class Console:
    def __init__(self, srv, routes):
        self.srv = srv
        self.routes = routes
        self.port = srv.server_address[1]
        self.cookie: str | None = None
        self.seen: list[Response] = []

    @property
    def host(self):
        return f"127.0.0.1:{self.port}"

    @property
    def origin(self):
        return f"http://{self.host}"

    def request(self, method, target, headers=None, body=None, host=DEFAULT, cookie=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            hdrs: list[tuple[str, str]] = []
            if host is DEFAULT:
                hdrs.append(("Host", self.host))
            elif isinstance(host, list):
                hdrs.extend(("Host", h) for h in host)
            elif host is not None:
                hdrs.append(("Host", host))
            if cookie and self.cookie:
                hdrs.append(("Cookie", f"winnie_ui={self.cookie}"))
            extra = dict(headers or {})
            if body is not None and "Content-Length" not in extra:
                extra["Content-Length"] = str(len(body))
            hdrs.extend((k, v) for k, v in extra.items() if v is not None)
            for name, value in hdrs:
                conn.putheader(name, value)
            conn.endheaders(body)
            resp = conn.getresponse()
            out = Response(resp.status, resp.getheaders(), resp.read())
        finally:
            conn.close()
        self.seen.append(out)
        return out

    def sign_in(self):
        resp = self.request("GET", "/?token=" + urllib.parse.quote(self.srv.token, safe=""))
        assert resp.status == 303, resp.body
        self.cookie = resp.header("Set-Cookie").split(";")[0].split("=", 1)[1]
        return resp

    def csrf(self):
        return self.request("GET", "/api/session").json()["csrf"]

    def post(self, path, payload=None, raw=None, **overrides):
        body = raw if raw is not None else json.dumps(payload or {}).encode()
        headers = {"Origin": self.origin, "X-Winnie-CSRF": self.csrf(),
                   "Content-Type": "application/json"}
        headers.update(overrides)
        return self.request("POST", path, headers=headers, body=body)


@pytest.fixture
def start():
    started = []

    def _start(routes=None, **settings):
        settings.setdefault("bind", "127.0.0.1")
        settings.setdefault("port", 0)
        settings.setdefault("token", secrets.token_urlsafe(32))
        routes = routes or FakeRoutes()
        srv = build_server(UiSettings(**settings), routes)
        thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05},
                                  daemon=True)
        thread.start()
        started.append((srv, thread))
        return Console(srv, routes)

    yield _start
    for srv, thread in started:
        srv.shutdown()
        srv.server_close()
        thread.join(5)


@pytest.fixture
def console(start):
    c = start()
    c.sign_in()
    return c


@pytest.fixture
def active(start):
    c = start(actions=True, operator="night shift")
    c.sign_in()
    return c


def assert_hardened(resp):
    for name, value in SECURITY_HEADERS.items():
        assert resp.header(name) == value, (resp.status, name)
    server = resp.header("Server") or ""
    assert "python" not in server.lower() and not re.search(r"\d", server)


# ---- headers ---------------------------------------------------------------------------------

def test_security_headers_on_success_and_every_error_class(start):
    routes = FakeRoutes()
    c = start(routes, actions=True)
    by_status = {}
    by_status[401] = c.request("GET", "/api/session")
    by_status[403] = c.request("GET", "/?token=" + "w" * 40)
    by_status[303] = c.sign_in()
    by_status[200] = c.request("GET", "/api/session")
    by_status[400] = c.request("GET", "/static/../server.py")
    by_status[404] = c.request("GET", "/nope")
    by_status[405] = c.request("PUT", "/")
    by_status[411] = c.request("POST", "/api/x", headers={
        "Origin": c.origin, "X-Winnie-CSRF": c.csrf(), "Content-Type": "application/json"})
    by_status[413] = c.request("POST", "/api/x", headers={
        "Origin": c.origin, "X-Winnie-CSRF": c.csrf(), "Content-Type": "application/json",
        "Content-Length": str(ui.MAX_BODY + 1)})
    by_status[415] = c.post("/api/x", {}, **{"Content-Type": "text/plain"})
    by_status[421] = c.request("GET", "/", host="evil.example")
    routes.error = RuntimeError("boom")
    by_status[500] = c.request("GET", "/api/x")
    c.srv.clock = lambda: 0.0
    for _ in range(ui.THROTTLE_FAILURES):
        c.request("GET", "/?token=bad")
    by_status[429] = c.request("GET", "/?token=bad")
    for status, resp in by_status.items():
        assert resp.status == status, (status, resp.body)
        assert_hardened(resp)
        if status != 303:
            assert resp.header("Content-Type") == "application/json; charset=utf-8"
    assert "Python" not in (by_status[200].header("Server") or "")


def test_json_responses_have_explicit_type(console):
    resp = console.request("GET", "/api/x")
    assert resp.header("Content-Type") == "application/json; charset=utf-8"


# ---- binding and token settings --------------------------------------------------------------

@pytest.mark.parametrize("bind", ["0.0.0.0", "::", "198.51.100.7", "10.0.0.5", "example.invalid"])
def test_non_loopback_bind_refused_without_flag(bind):
    with pytest.raises(ValueError, match="non-loopback"):
        build_server(UiSettings(bind=bind, port=0, token="t" * 32), FakeRoutes())


def test_non_loopback_bind_allowed_with_flag(monkeypatch):
    built = []
    monkeypatch.setattr(ui, "UiServer", lambda *args: built.append(args) or "server")
    settings = UiSettings(bind="0.0.0.0", port=0, allow_non_loopback=True, token="t" * 32)
    assert build_server(settings, FakeRoutes()) == "server"
    assert built[0][0] is settings


def test_localhost_name_is_loopback():
    srv = build_server(UiSettings(bind="localhost", port=0), FakeRoutes())
    srv.server_close()


def test_short_token_refused_without_echoing_it():
    short = "s" * (ui.MIN_TOKEN_LENGTH - 1)
    with pytest.raises(ValueError) as err:
        build_server(UiSettings(port=0, token=short), FakeRoutes())
    assert short not in str(err.value)
    srv = build_server(UiSettings(port=0, token="s" * ui.MIN_TOKEN_LENGTH), FakeRoutes())
    srv.server_close()


def test_token_generated_when_empty():
    a = build_server(UiSettings(port=0), FakeRoutes())
    b = build_server(UiSettings(port=0), FakeRoutes())
    try:
        assert len(a.token) >= ui.MIN_TOKEN_LENGTH and a.token != b.token
    finally:
        a.server_close()
        b.server_close()


def test_connection_settings():
    assert ui._Handler.timeout == 15
    assert ui.UiServer.daemon_threads is True


# ---- Host and Origin -------------------------------------------------------------------------

@pytest.mark.parametrize("host", [
    None, "", "evil.example", "evil.example:8480", "127.0.0.1.evil.example",
    "localhost.evil.example", "localhost.", "127.0.0.1.", "user@localhost", "localhost@evil.example",
    "localhost:abc", "localhost:99999", "localhost:", "127.0.0.2", "0.0.0.0", "[::1", "::1",
    "localhost localhost", "localhost:80:80", ["localhost", "evil.example"],
    ["localhost", "localhost"],
])
def test_bad_host_is_421(start, host):
    c = start()
    resp = c.request("GET", "/api/session", host=host)
    assert resp.status == 421
    assert resp.json() == {"error": "host not allowed"}
    assert_hardened(resp)


@pytest.mark.parametrize("host", ["localhost", "LOCALHOST:1", "127.0.0.1", "[::1]:8480", "[::1]"])
def test_loopback_hosts_accepted(start, host):
    c = start()
    assert c.request("GET", "/api/session", host=host).status == 401  # past the Host check


def test_rebinding_style_host_refused_even_when_signed_in(console):
    resp = console.request("GET", "/api/session", host=f"attacker.example:{console.port}")
    assert resp.status == 421
    assert "csrf" not in resp.body.decode()


def test_post_requires_local_origin(active):
    for origin in (None, "http://evil.example", "null", f"https://{active.host}",
                   f"http://{active.host}.evil.example", "http://localhost/"):
        resp = active.post("/api/decide", {"id": "x"}, Origin=origin)
        assert resp.status == 403, origin
        assert_hardened(resp)
    assert active.post("/api/decide", {}, Origin=f"http://localhost:{active.port}").status == 201
    assert len(active.routes.posts) == 1


# ---- sign-in ---------------------------------------------------------------------------------

def test_sign_in_sets_derived_cookie_and_redirects(start):
    c = start()
    resp = c.sign_in()
    assert resp.header("Location") == "/"
    cookie = resp.header("Set-Cookie")
    expected = hmac.new(c.srv.token.encode(), b"winnie-ui session v1", hashlib.sha256).hexdigest()
    assert cookie == f"winnie_ui={expected}; HttpOnly; SameSite=Strict; Path=/"
    assert "Secure" not in cookie and c.srv.token not in cookie
    page = c.request("GET", "/")
    assert page.status == 200 and page.header("Content-Type") == "text/html; charset=utf-8"
    assert page.body == (STATIC_DIR / "index.html").read_bytes()


def test_wrong_token_is_403_without_cookie(start):
    c = start()
    for bad in ("x" * 43, c.srv.token[:-1], c.srv.token + "x", "", "\u00e9" * 30):
        resp = c.request("GET", "/?token=" + urllib.parse.quote(bad))
        assert resp.status == 403
        assert resp.header("Set-Cookie") is None


def test_token_attempts_throttled_globally(start):
    c = start()
    now = [1000.0]
    c.srv.clock = lambda: now[0]
    for _ in range(ui.THROTTLE_FAILURES):
        assert c.request("GET", "/?token=wrong").status == 403
    assert c.request("GET", "/?token=wrong").status == 429
    good = "/?token=" + urllib.parse.quote(c.srv.token, safe="")
    assert c.request("GET", good).status == 429  # even the right token waits
    now[0] += ui.THROTTLE_WINDOW + 1
    assert c.request("GET", good).status == 303


def test_signed_out_root_page_has_no_form_or_script(start):
    c = start()
    resp = c.request("GET", "/")
    assert resp.status == 401
    assert resp.header("Content-Type") == "text/html; charset=utf-8"
    text = resp.body.decode().lower()
    assert "server log" in text
    for banned in ("<form", "<script", "<style", "style=", "<input", "http"):
        assert banned not in text
    assert_hardened(resp)


@pytest.mark.parametrize("path", ["/index.html", "/static/app.js", "/static/app.css",
                                  "/api/session", "/api/things"])
def test_cookie_required_for_static_and_api(start, path):
    c = start()
    resp = c.request("GET", path)
    assert resp.status == 401 and resp.json() == {"error": "not signed in"}
    c.cookie = "0" * 64
    assert c.request("GET", path).status == 401
    assert c.routes.gets == []


def test_session_endpoint(active):
    data = active.request("GET", "/api/session").json()
    assert data == {"csrf": data["csrf"], "actions": True, "operator": "night shift"}
    expected = hmac.new(active.srv.token.encode(), b"winnie-ui csrf v1", hashlib.sha256)
    assert data["csrf"] == expected.hexdigest()
    assert data["csrf"] not in (active.srv.token, active.cookie)
    assert active.routes.gets == []  # answered by the shell


def test_token_never_leaves_the_process(start, caplog):
    caplog.set_level(logging.DEBUG, logger="agents.ui")
    routes = FakeRoutes()
    c = start(routes, actions=True)
    token = c.srv.token
    c.request("GET", "/")
    c.request("GET", "/?token=" + "z" * 40)
    c.sign_in()
    c.request("GET", "/")
    c.request("GET", "/static/app.js")
    c.request("GET", "/api/x?q=1")
    c.request("GET", "/?token=" + token + "&x=1")
    c.request("GET", "/?token=" + token, host="evil.example")
    c.post("/api/decide", {"id": "x"})
    c.request("POST", "/?token=" + token, headers={"Origin": c.origin}, body=b"{}")
    routes.error = RuntimeError("route exploded")
    c.request("GET", "/api/x")
    csrf = hmac.new(token.encode(), b"winnie-ui csrf v1", hashlib.sha256).hexdigest()
    for resp in c.seen:
        blob = resp.body.decode("latin-1") + repr(resp.headers)
        assert token not in blob
        if resp.header("Set-Cookie") is None:
            assert c.cookie not in blob
    assert caplog.records
    for record in caplog.records:
        text = record.getMessage() + repr(record.args)
        for secret in (token, c.cookie, csrf, "token="):
            assert secret not in text


def test_bad_request_line_is_not_echoed(start, caplog):
    caplog.set_level(logging.DEBUG, logger="agents.ui")
    c = start()
    import socket

    with socket.create_connection(("127.0.0.1", c.port), timeout=5) as sock:
        sock.sendall(f"GET /?token={c.srv.token} HTTP/9.9\r\n\r\n".encode())
        data = b""
        while chunk := sock.recv(4096):
            data += chunk
    assert data.startswith(b"HTTP/1.0 505")
    assert c.srv.token.encode() not in data
    assert all(c.srv.token not in r.getMessage() for r in caplog.records)


def test_access_log_has_method_path_status_without_query(console, caplog):
    caplog.set_level(logging.INFO, logger="agents.ui")
    console.request("GET", "/api/items?search=abc")
    lines = [r.getMessage() for r in caplog.records if r.name == "agents.ui"]
    assert "GET /api/items 200" in lines
    assert not any("search" in line for line in lines)


def test_serve_logs_sign_in_url_once(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="agents.ui")
    monkeypatch.setattr(ui.UiServer, "serve_forever", lambda self, *a, **k: None)
    token = "q" * 32
    ui.serve(UiSettings(port=0, token=token), FakeRoutes())
    hits = [r.getMessage() for r in caplog.records if token in r.getMessage()]
    assert len(hits) == 1
    assert re.search(r"http://127\.0\.0\.1:\d+/\?token=" + token, hits[0])


def test_sign_in_url_for_container_bind():
    srv = ui.UiServer.__new__(ui.UiServer)
    srv.settings = UiSettings(bind="0.0.0.0", allow_non_loopback=True)
    srv._token = "a b" + "c" * 30
    srv.server_address = ("0.0.0.0", 8480)
    assert ui.sign_in_url(srv) == "http://127.0.0.1:8480/?token=a%20b" + "c" * 30


# ---- POST rules ------------------------------------------------------------------------------

def test_post_needs_cookie(active):
    csrf = active.csrf()
    active.cookie = None
    resp = active.request("POST", "/api/decide", headers={
        "Origin": active.origin, "X-Winnie-CSRF": csrf, "Content-Type": "application/json"},
        body=b"{}")
    assert resp.status == 401
    assert active.routes.posts == []


@pytest.mark.parametrize("csrf", [None, "", "0" * 64, "x"])
def test_post_needs_csrf(active, csrf):
    resp = active.post("/api/decide", {"id": "x"}, **{"X-Winnie-CSRF": csrf})
    assert resp.status == 403
    assert active.routes.posts == []


def test_post_rejects_wrong_content_type(active):
    for ctype in (None, "text/plain", "application/x-www-form-urlencoded", "multipart/form-data",
                  "application/jsonx"):
        assert active.post("/api/decide", {}, **{"Content-Type": ctype}).status == 415
    assert active.post("/api/decide", {}, **{"Content-Type": "Application/JSON; charset=utf-8"}
                       ).status == 201


def test_post_needs_content_length(active):
    headers = {"Origin": active.origin, "X-Winnie-CSRF": active.csrf(),
               "Content-Type": "application/json"}
    assert active.request("POST", "/api/decide", headers=headers).status == 411
    chunked = dict(headers, **{"Transfer-Encoding": "chunked"})
    assert active.request("POST", "/api/decide", headers=chunked).status == 411
    bad = dict(headers, **{"Content-Length": "-1"})
    assert active.request("POST", "/api/decide", headers=bad).status == 400
    assert active.routes.posts == []


def test_oversized_body_refused_without_reading(active):
    headers = {"Origin": active.origin, "X-Winnie-CSRF": active.csrf(),
               "Content-Type": "application/json", "Content-Length": str(ui.MAX_BODY + 1)}
    # No body is sent at all: the server must answer from the header alone.
    resp = active.request("POST", "/api/decide", headers=headers)
    assert resp.status == 413
    assert active.routes.posts == []


@pytest.mark.parametrize("raw", [b"[1, 2]", b"\"text\"", b"3", b"null", b"not json", b"{",
                                 b"\xff\xfe", b"{\"x\": NaN}", b"[" * 5000])
def test_post_body_must_be_json_object(active, raw):
    resp = active.post("/api/decide", raw=raw)
    assert resp.status == 400
    assert active.routes.posts == []


def test_read_only_mode_never_calls_routes_post(console):
    resp = console.post("/api/decide", {"id": "x"})
    assert resp.status == 403 and resp.json() == {"error": "read-only"}
    assert console.routes.posts == []
    assert console.request("GET", "/api/session").json()["actions"] is False


def test_actions_mode_calls_routes_post(active):
    active.routes.post_result = (202, {"queued": "abc"})
    resp = active.post("/api/decide", {"id": "x", "decision": "approve"})
    assert resp.status == 202 and resp.json() == {"queued": "abc"}
    assert active.routes.posts == [("/api/decide", {"id": "x", "decision": "approve"})]


def test_post_outside_api_is_404(active):
    assert active.post("/index.html", {}).status == 404
    assert active.routes.posts == []


# ---- routes ----------------------------------------------------------------------------------

def test_get_routes_receive_path_and_last_query_value(console):
    console.routes.get_result = (200, {"rows": []})
    resp = console.request("GET", "/api/items/a%20b?x=1&x=2&empty=")
    assert resp.status == 200 and resp.json() == {"rows": []}
    assert console.routes.gets == [("/api/items/a b", {"x": "2", "empty": ""})]


def test_query_limits(console):
    many = "&".join(f"k{i}=v" for i in range(ui.MAX_QUERY_PARAMS + 1))
    assert console.request("GET", "/api/items?" + many).status == 400
    ok = "&".join(f"k{i}=v" for i in range(ui.MAX_QUERY_PARAMS))
    assert console.request("GET", "/api/items?" + ok).status == 200
    assert console.request("GET", "/api/items?q=" + "a" * (ui.MAX_QUERY_VALUE + 1)).status == 400
    assert console.request("GET", "/api/items?q=" + "a" * ui.MAX_QUERY_VALUE).status == 200
    assert console.request("GET", "/api/items?q=%ff").status == 400


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_route_exception_is_bare_500(active, method, caplog):
    caplog.set_level(logging.ERROR, logger="agents.ui")
    active.routes.error = RuntimeError("secret detail from route")
    resp = (active.request("GET", "/api/x") if method == "GET"
            else active.post("/api/x", {"id": 1}))
    assert resp.status == 500
    assert resp.json() == {"error": "internal error"}
    assert b"Traceback" not in resp.body and b"secret detail" not in resp.body
    assert_hardened(resp)
    assert any(r.exc_info for r in caplog.records)


@pytest.mark.parametrize("result", [(200, {"x": object()}), (200, float("nan")), ("200", {}),
                                    (True, {}), (99, {}), None])
def test_bad_route_result_is_500(console, result):
    console.routes.get_result = result
    resp = console.request("GET", "/api/x")
    assert resp.status == 500 and resp.json() == {"error": "internal error"}


def test_json_escaping(console):
    value = {"text": "</script><b>&amp;\u2028\u2029", "k<": "\u00e9"}
    console.routes.get_result = (200, value)
    resp = console.request("GET", "/api/x")
    for raw in (b"<", b">", b"&", "\u2028".encode(), "\u2029".encode()):
        assert raw not in resp.body
    assert b"\\u003c/script\\u003e" in resp.body
    assert b"\\u2028" in resp.body and b"\\u2029" in resp.body and b"\\u0026" in resp.body
    assert all(b < 0x80 for b in resp.body)
    assert resp.json() == value


# ---- paths and static files ------------------------------------------------------------------

@pytest.mark.parametrize("target", [
    "/static/../server.py", "/static/%2e%2e/server.py", "/static/%2E%2E/server.py",
    "/static/.%2e/server.py", "/static//app.js", "/static\\app.js", "/static/%5capp.js",
    "/static/app.js%2f", "/static/app.js%00", "/api/..", "/api/x/../session", "/api/%2fetc",
    "http://evil.example/", "*", "/api/a%0ab",
])
def test_traversal_style_paths_are_400(console, target):
    resp = console.request("GET", target)
    assert resp.status == 400, target
    assert console.routes.gets == []


@pytest.mark.parametrize("path", ["/static/server.py", "/static/other.js", "/favicon.ico",
                                  "/api", "/static/", "/server.py", "/index.htm"])
def test_unknown_paths_are_404(console, path):
    resp = console.request("GET", path)
    assert resp.status == 404
    assert console.routes.gets == []


@pytest.mark.parametrize("path,name,ctype", [
    ("/", "index.html", "text/html; charset=utf-8"),
    ("/index.html", "index.html", "text/html; charset=utf-8"),
    ("/static/app.js", "app.js", "text/javascript; charset=utf-8"),
    ("/static/app.css", "app.css", "text/css; charset=utf-8"),
    ("/static/favicon.svg", "favicon.svg", "image/svg+xml"),
])
def test_static_files(console, path, name, ctype):
    resp = console.request("GET", path)
    assert resp.status == 200
    assert resp.header("Content-Type") == ctype
    assert resp.body == (STATIC_DIR / name).read_bytes()
    assert_hardened(resp)


def test_static_placeholders_have_no_inline_code_or_external_urls():
    html = (STATIC_DIR / "index.html").read_text()
    assert re.findall(r"<script[^>]*>", html) == ['<script src="/static/app.js" defer>']
    assert "<style" not in html and "style=" not in html and " on" not in html
    for name in ("index.html", "app.js", "app.css"):
        assert not re.search(r"(?i)\b(?:https?:)?//[a-z0-9]", (STATIC_DIR / name).read_text())


def test_head_works(console):
    size = len((STATIC_DIR / "app.js").read_bytes())
    resp = console.request("HEAD", "/static/app.js")
    assert resp.status == 200 and resp.body == b""
    assert resp.header("Content-Length") == str(size)
    assert_hardened(resp)
    assert console.request("HEAD", "/api/session").status == 200


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT",
                                    "FOO"])
def test_unknown_method_is_405(console, method):
    resp = console.request(method, "/api/x")
    assert resp.status == 405
    assert resp.header("Allow") == "GET, HEAD, POST"
    assert_hardened(resp)
    assert console.routes.gets == [] and console.routes.posts == []
