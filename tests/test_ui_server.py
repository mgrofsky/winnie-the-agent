"""Operator console HTTP shell: binding, Host/Origin, sign-in, throttle, CSRF, limits, headers."""

import hashlib
import hmac
import http.client
import json
import logging
import re
import secrets
import socket
import threading
import time
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
    assert active.post("/api/decide", {}, Origin=active.origin.upper()).status == 201
    assert len(active.routes.posts) == 1


def test_origin_must_equal_host(active):
    port = active.port
    for origin in (f"http://localhost:{port}", f"http://[::1]:{port}",
                   f"http://127.0.0.1:{port + 1 if port < 65535 else port - 1}",
                   "http://127.0.0.1", f"http://127.0.0.1:0{port}"):
        resp = active.post("/api/decide", {}, Origin=origin)
        assert resp.status == 403 and resp.json() == {"error": "origin not allowed"}, origin
    assert active.routes.posts == []
    # The same check with the browser on the localhost name: Host and Origin agree.
    host = f"localhost:{port}"
    headers = {"Origin": f"http://{host}", "X-Winnie-CSRF": active.csrf(),
               "Content-Type": "application/json"}
    assert active.request("POST", "/api/decide", headers=headers, body=b"{}",
                          host=host).status == 201
    headers["Origin"] = active.origin
    assert active.request("POST", "/api/decide", headers=headers, body=b"{}",
                          host=host).status == 403
    assert len(active.routes.posts) == 1


# ---- sign-in ---------------------------------------------------------------------------------

def test_sign_in_sets_session_cookie_and_redirects(start):
    c = start()
    c.srv.wall_clock = lambda: 1_700_000_000.5
    resp = c.sign_in()
    assert resp.header("Location") == "/"
    cookie = resp.header("Set-Cookie")
    value = cookie.split(";")[0].split("=", 1)[1]
    issued, mac = value.split(".")
    assert issued == "1700000000" and re.fullmatch(r"[0-9a-f]{64}", mac)
    assert cookie == f"winnie_ui={value}; HttpOnly; SameSite=Strict; Path=/"
    assert "Secure" not in cookie and "Max-Age" not in cookie and c.srv.token not in cookie
    # Not derivable from the token: the old token-only derivation does not match.
    for label in (b"winnie-ui session v1", b"winnie-ui session v2 1700000000"):
        assert mac != hmac.new(c.srv.token.encode(), label, hashlib.sha256).hexdigest()
    page = c.request("GET", "/")
    assert page.status == 200 and page.header("Content-Type") == "text/html; charset=utf-8"
    assert page.body == (STATIC_DIR / "index.html").read_bytes()


def test_wrong_token_is_403_without_cookie(start):
    c = start()
    for bad in ("x" * 43, c.srv.token[:-1], c.srv.token + "x", "", "\u00e9" * 30):
        resp = c.request("GET", "/?token=" + urllib.parse.quote(bad))
        assert resp.status == 403
        assert resp.header("Set-Cookie") is None


def test_failed_token_attempts_throttled_globally(start):
    c = start()
    now = [1000.0]
    c.srv.clock = lambda: now[0]
    for _ in range(ui.THROTTLE_FAILURES):
        assert c.request("GET", "/?token=wrong").status == 403
    assert c.request("GET", "/?token=wrong").status == 429
    good = "/?token=" + urllib.parse.quote(c.srv.token, safe="")
    assert c.request("GET", good).status == 303  # a correct token is never held back
    assert c.request("GET", "/?token=wrong").status == 429
    now[0] += ui.THROTTLE_WINDOW + 1
    assert c.request("GET", "/?token=wrong").status == 403


def test_correct_token_signs_in_after_many_failures(start):
    c = start()
    c.srv.clock = lambda: 5.0  # every failure inside one window
    statuses = {c.request("GET", "/?token=" + "w" * 40).status for _ in range(50)}
    assert statuses == {403, 429}
    resp = c.sign_in()
    assert resp.status == 303
    assert c.request("GET", "/api/session").status == 200


# ---- session lifetime and binding ------------------------------------------------------------

def test_session_rejected_after_restart_with_the_same_token(start):
    token = secrets.token_urlsafe(32)
    first = start(token=token)
    first.sign_in()
    assert first.request("GET", "/api/session").status == 200
    second = start(token=token)
    second.cookie = first.cookie
    resp = second.request("GET", "/api/session")
    assert resp.status == 401 and resp.json() == {"error": "not signed in"}
    assert second.request("GET", "/").status == 401
    second.sign_in()  # the same token still works as a sign-in link
    assert second.cookie != first.cookie
    assert second.request("GET", "/api/session").status == 200


def test_session_expires_after_its_lifetime(start):
    c = start(actions=True)
    now = [1_800_000_000.0]
    c.srv.wall_clock = lambda: now[0]
    c.sign_in()
    csrf = c.csrf()
    now[0] += ui.SESSION_LIFETIME - 1
    assert c.request("GET", "/api/session").status == 200
    now[0] += 1
    assert c.request("GET", "/api/session").status == 401
    assert c.request("GET", "/static/app.js").status == 401
    headers = {"Origin": c.origin, "X-Winnie-CSRF": csrf, "Content-Type": "application/json"}
    assert c.request("POST", "/api/decide", headers=headers, body=b"{}").status == 401
    assert c.routes.posts == []
    c.sign_in()  # the token link is reusable after expiry
    assert c.request("GET", "/api/session").status == 200


def test_tampered_or_future_issue_time_rejected(start):
    c = start()
    now = [1_800_000_000.0]
    c.srv.wall_clock = lambda: now[0]
    c.sign_in()
    good = c.cookie
    issued, mac = good.split(".")
    for forged in (f"{int(issued) + 3600}.{mac}", f"{int(issued) - 1}.{mac}", f"0{issued}.{mac}",
                   f"{issued}.{mac[:-1]}", f"{issued}.{mac.upper()}", f"{issued}{mac}",
                   f"{issued}.{mac}.1", mac, issued):
        c.cookie = forged
        assert c.request("GET", "/api/session").status == 401, forged
    # A genuine value issued "later" than now (clock went back) is refused too.
    c.cookie = good
    now[0] -= 10
    assert c.request("GET", "/api/session").status == 401
    now[0] += 10
    assert c.request("GET", "/api/session").status == 200


def test_csrf_is_bound_to_its_session(start):
    c = start(actions=True)
    now = [1_800_000_000.0]
    c.srv.wall_clock = lambda: now[0]
    c.sign_in()
    first_cookie, first_csrf = c.cookie, c.csrf()
    now[0] += 5
    c.sign_in()
    second_csrf = c.csrf()
    assert c.cookie != first_cookie and second_csrf != first_csrf
    resp = c.post("/api/decide", {}, **{"X-Winnie-CSRF": first_csrf})
    assert resp.status == 403 and resp.json() == {"error": "bad csrf token"}
    assert c.routes.posts == []
    assert c.post("/api/decide", {}, **{"X-Winnie-CSRF": second_csrf}).status == 201
    c.cookie = first_cookie
    assert c.post("/api/decide", {}, **{"X-Winnie-CSRF": second_csrf}).status == 403
    assert c.post("/api/decide", {}, **{"X-Winnie-CSRF": first_csrf}).status == 201
    assert len(c.routes.posts) == 2


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
    assert re.fullmatch(r"[0-9a-f]{64}", data["csrf"])
    assert data["csrf"] == active.srv.csrf_for(active.cookie)
    assert data["csrf"] not in (active.srv.token, active.cookie)
    assert data["csrf"] not in active.cookie
    assert active.routes.gets == []  # answered by the shell


def test_session_endpoint_carries_the_geoip_attribution(start):
    c = start(attribution="IP Geolocation by DB-IP")
    c.sign_in()
    data = c.request("GET", "/api/session").json()
    assert data["attribution"] == "IP Geolocation by DB-IP"


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
    csrf = c.srv.csrf_for(c.cookie)
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


@pytest.mark.parametrize("separator,escaped", [
    ("\u0085", r"\x85"), ("\u2028", r"\u2028"), ("\u2029", r"\u2029"),
])
def test_route_failure_escapes_unicode_line_separators(active, caplog, separator, escaped):
    caplog.set_level(logging.ERROR, logger="agents.ui")
    active.routes.error = RuntimeError("route failed")
    path = "/api/item" + urllib.parse.quote(separator)

    assert active.request("GET", path).status == 500
    lines = [r.getMessage() for r in caplog.records if r.name == "agents.ui"]
    assert lines
    assert all(separator not in line for line in lines)
    assert any(escaped in line for line in lines)


def test_access_log_escapes_raw_terminal_control(console, caplog):
    caplog.set_level(logging.INFO, logger="agents.ui")
    request = (f"GET /api/\x1b[31mitem HTTP/1.1\r\nHost: {console.host}\r\n\r\n").encode()
    with socket.create_connection(("127.0.0.1", console.port), timeout=5) as sock:
        sock.sendall(request)
        while sock.recv(4096):
            pass

    lines = [r.getMessage() for r in caplog.records if r.name == "agents.ui"]
    assert lines
    assert all("\x1b" not in line for line in lines)
    assert any(r"\x1b" in line for line in lines)


@pytest.mark.parametrize("control,escaped", [("\x1b", r"\x1b"), ("\x9b", r"\x9b")])
def test_rejected_method_escapes_terminal_control_in_access_log(console, caplog,
                                                                control, escaped):
    caplog.set_level(logging.INFO, logger="agents.ui")
    request = (f"BAD{control}[2J /api/items HTTP/1.1\r\n"
               f"Host: {console.host}\r\n\r\n").encode("latin-1")
    with socket.create_connection(("127.0.0.1", console.port), timeout=5) as sock:
        sock.sendall(request)
        response = b""
        while chunk := sock.recv(4096):
            response += chunk

    assert response.startswith(b"HTTP/1.0 405 ")
    lines = [r.getMessage() for r in caplog.records if r.name == "agents.ui"]
    assert lines
    assert all(control not in line for line in lines)
    assert any(escaped in line for line in lines)


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


# ---- slow bodies, connection cap, HTTP/0.9 ---------------------------------------------------

def raw_post_head(c, length, origin=DEFAULT, csrf=None, cookie=True):
    lines = ["POST /api/decide HTTP/1.0", f"Host: {c.host}", "Content-Type: application/json",
             f"Content-Length: {length}"]
    if origin is not None:
        lines.append(f"Origin: {c.origin if origin is DEFAULT else origin}")
    if cookie and c.cookie:
        lines.append(f"Cookie: winnie_ui={c.cookie}")
    if csrf:
        lines.append(f"X-Winnie-CSRF: {csrf}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def read_all(sock) -> bytes:
    data = b""
    try:
        while chunk := sock.recv(4096):
            data += chunk
    except ConnectionResetError:
        pass
    return data


@pytest.mark.parametrize("case", ["no session", "bad origin", "bad csrf", "read-only",
                                  "bad host"])
def test_refused_post_answered_without_waiting_for_the_body(start, case):
    c = start(actions=case != "read-only")
    c.sign_in()
    csrf = c.csrf()
    if case == "no session":
        head = raw_post_head(c, 4000, csrf=csrf, cookie=False)
    elif case == "bad origin":
        head = raw_post_head(c, 4000, origin="http://evil.example", csrf=csrf)
    elif case == "bad csrf":
        head = raw_post_head(c, 4000, csrf="0" * 64)
    elif case == "bad host":
        head = raw_post_head(c, 4000, csrf=csrf).replace(c.host.encode(), b"evil.example")
    else:
        head = raw_post_head(c, 4000, csrf=csrf)
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", c.port), timeout=2) as sock:
        sock.sendall(head)  # the declared 4000-byte body never comes
        data = read_all(sock)
    assert time.monotonic() - started < 1.5
    assert re.match(rb"HTTP/1\.0 (401|403|421) ", data), data[:80]
    assert c.routes.posts == []


def test_dribbled_body_cut_at_the_deadline(start):
    c = start(actions=True)
    c.sign_in()
    c.srv.body_deadline = 0.4
    body = b"{" + b" " * 98 + b"}"
    stop = threading.Event()
    with socket.create_connection(("127.0.0.1", c.port), timeout=3) as sock:
        sock.sendall(raw_post_head(c, len(body), csrf=c.csrf()))

        def dribble():
            for byte in body:
                if stop.wait(0.05):
                    return
                try:
                    sock.send(bytes([byte]))
                except OSError:
                    return

        sender = threading.Thread(target=dribble, daemon=True)
        started = time.monotonic()
        sender.start()
        data = read_all(sock)
        elapsed = time.monotonic() - started
        stop.set()
        sender.join(2)
    assert data.startswith(b"HTTP/1.0 408 "), data[:80]
    assert 0.3 < elapsed < 1.9
    assert c.routes.posts == []
    # A body that arrives in time is still accepted.
    assert c.post("/api/decide", {"id": "x"}).status == 201


def test_connection_cap(start, monkeypatch):
    monkeypatch.setattr(ui, "MAX_CONNECTIONS", 2)
    c = start()
    held = [socket.create_connection(("127.0.0.1", c.port), timeout=3) for _ in range(2)]
    try:
        # Each held connection sends half a request line, so its thread stays busy.
        for sock in held:
            sock.sendall(b"GET /api/x")
        deadline = time.monotonic() + 3
        while True:
            with socket.create_connection(("127.0.0.1", c.port), timeout=3) as extra:
                data = read_all(extra)
            if data or time.monotonic() > deadline:
                break
        assert data.startswith(b"HTTP/1.0 503 "), data[:80]
        head, _, body = data.partition(b"\r\n\r\n")
        assert json.loads(body) == {"error": "busy"}
        assert b"Content-Security-Policy: " in head and b"X-Frame-Options: DENY" in head
    finally:
        for sock in held:
            sock.close()
    # Slots come back once the held connections end.
    deadline = time.monotonic() + 3
    while c.request("GET", "/api/session").status != 401:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert all(c.request("GET", "/api/session").status == 401 for _ in range(5))


def test_http09_request_gets_no_bare_body(console):
    # A two-word GET would be answered HTTP/0.9 style (a body, no status line or headers).
    for line in (b"GET /\r\n", b"GET /api/session\r\n", b"GET /api/x\r\n"):
        with socket.create_connection(("127.0.0.1", console.port), timeout=3) as sock:
            sock.sendall(line)
            assert read_all(sock) == b"", line
    # Other unparseable lines get a normal error with a status line and headers.
    with socket.create_connection(("127.0.0.1", console.port), timeout=3) as sock:
        sock.sendall(b"POST /api/x\r\n")
        data = read_all(sock)
    assert data.startswith(b"HTTP/1.0 400 ") and b"Content-Security-Policy: " in data
    assert console.routes.gets == []


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


# ---- external name (same-host HTTPS proxy) ---------------------------------------------------

EXT = "sensor.example-tailnet.ts.net"
HSTS = "max-age=31536000"


def ext_sign_in(c, host=EXT):
    resp = c.request("GET", "/?token=" + urllib.parse.quote(c.srv.token, safe=""), host=host)
    assert resp.status == 303, resp.body
    return resp, resp.header("Set-Cookie").split(";")[0].split("=", 1)[1]


def ext_post(c, cookie, origin, host=EXT, csrf=None):
    c.cookie = cookie
    if csrf is None:
        csrf = c.request("GET", "/api/session", host=host).json()["csrf"]
    headers = {"Origin": origin, "X-Winnie-CSRF": csrf, "Content-Type": "application/json"}
    return c.request("POST", "/api/decide", headers=headers, body=b"{}", host=host)


@pytest.mark.parametrize("host", [EXT, EXT + ":443", "sensor.example-tailnet.ts.net:8443"])
def test_external_looking_host_is_421_when_the_setting_is_empty(start, host):
    c = start()
    resp = c.request("GET", "/?token=" + urllib.parse.quote(c.srv.token, safe=""), host=host)
    assert resp.status == 421 and resp.header("Set-Cookie") is None
    assert resp.header("Strict-Transport-Security") is None


def test_external_sign_in_sets_secure_cookie_and_hsts(start):
    c = start(external_host=EXT)
    resp, cookie = ext_sign_in(c)
    assert resp.header("Set-Cookie") == \
        f"winnie_ui={cookie}; Secure; HttpOnly; SameSite=Strict; Path=/"
    assert resp.header("Strict-Transport-Security") == HSTS
    assert_hardened(resp)
    c.cookie = cookie
    page = c.request("GET", "/", host=EXT)
    assert page.status == 200 and page.header("Strict-Transport-Security") == HSTS
    # Every external answer carries it, errors included.
    for resp in (c.request("GET", "/nope", host=EXT), c.request("PUT", "/", host=EXT),
                 c.request("GET", "/api/session", host=EXT, cookie=False)):
        assert resp.status in (404, 405, 401)
        assert resp.header("Strict-Transport-Security") == HSTS, resp.status


def test_loopback_sign_in_has_no_secure_or_hsts_with_the_setting_on(start):
    c = start(external_host=EXT)
    resp = c.sign_in()
    cookie = resp.header("Set-Cookie")
    assert cookie == f"winnie_ui={c.cookie}; HttpOnly; SameSite=Strict; Path=/"
    assert resp.header("Strict-Transport-Security") is None
    for resp in c.seen + [c.request("GET", "/api/session"), c.request("GET", "/nope"),
                          c.request("GET", "/", host="evil.example")]:
        assert resp.header("Strict-Transport-Security") is None


def test_external_post_needs_its_https_origin(start):
    c = start(external_host=EXT, actions=True)
    _, cookie = ext_sign_in(c)
    for origin in (f"http://{EXT}", f"https://{EXT}:443", f"https://{EXT}:8443",
                   f"https://{EXT}.", f"https://x.{EXT}", f"https://{EXT}/", "null", None,
                   f"http://127.0.0.1:{c.port}", f"https://127.0.0.1:{c.port}",
                   "https://example-tailnet.ts.net"):
        resp = ext_post(c, cookie, origin)
        assert resp.status == 403 and resp.json() == {"error": "origin not allowed"}, origin
        assert resp.header("Strict-Transport-Security") == HSTS
    assert c.routes.posts == []
    assert ext_post(c, cookie, f"https://{EXT}").status == 201
    assert ext_post(c, cookie, f"HTTPS://{EXT.upper()}").status == 201
    assert len(c.routes.posts) == 2


def test_external_origin_on_a_loopback_host_is_refused(start):
    c = start(external_host=EXT, actions=True)
    c.sign_in()
    for origin in (f"https://{EXT}", f"http://{EXT}"):
        resp = c.post("/api/decide", {}, Origin=origin)
        assert resp.status == 403 and resp.json() == {"error": "origin not allowed"}, origin
    assert c.post("/api/decide", {}).status == 201  # the loopback rule is unchanged
    assert len(c.routes.posts) == 1


def test_external_name_with_port_443(start):
    c = start(external_host=EXT, actions=True)
    _, cookie = ext_sign_in(c, host=EXT + ":443")
    host = EXT + ":443"
    assert ext_post(c, cookie, f"https://{EXT}", host=host).status == 201       # browsers
    assert ext_post(c, cookie, f"https://{EXT}:443", host=host).status == 201   # Host as sent
    assert ext_post(c, cookie, f"http://{EXT}", host=host).status == 403
    # The session belongs to the name, not to the spelling of its port.
    assert ext_post(c, cookie, f"https://{EXT}").status == 201
    assert c.request("GET", "/api/session", host=EXT + ":8443").status == 421


def test_configured_port_is_required_and_443_is_the_bare_name(start):
    c = start(external_host=EXT + ":8443", actions=True)
    assert c.srv.settings.external_host == EXT + ":8443"
    for host in (EXT, EXT + ":443", EXT + ":8444"):
        assert c.request("GET", "/api/session", host=host).status == 421, host
    _, cookie = ext_sign_in(c, host=EXT + ":8443")
    host = EXT + ":8443"
    assert ext_post(c, cookie, f"https://{EXT}", host=host).status == 403
    assert ext_post(c, cookie, f"https://{EXT}:8443", host=host).status == 201
    d = start(external_host=EXT.upper() + ":443")
    assert d.srv.settings.external_host == EXT
    assert d.request("GET", "/api/session", host=EXT).status == 401


@pytest.mark.parametrize("host", [
    "other.example-tailnet.ts.net", "example-tailnet.ts.net", "ts.net", "x." + EXT,
    EXT + ".evil.example", EXT[1:], EXT[:-1], "x" + EXT, EXT + "x", EXT + ".", EXT + ":",
    EXT + ":80", EXT + ":0443", EXT + ":443:443", "user@" + EXT, f"{EXT} {EXT}",
    [EXT, EXT], [EXT, "localhost"], ["localhost", EXT],
])
def test_other_names_are_421_with_the_setting_on(start, host):
    c = start(external_host=EXT)
    resp = c.request("GET", "/?token=" + urllib.parse.quote(c.srv.token, safe=""), host=host)
    assert resp.status == 421 and resp.header("Set-Cookie") is None, host
    assert resp.header("Strict-Transport-Security") is None


def test_external_host_header_is_case_insensitive(start):
    c = start(external_host=EXT)
    resp, cookie = ext_sign_in(c, host=EXT.upper())
    assert "Secure" in resp.header("Set-Cookie")
    c.cookie = cookie
    assert c.request("GET", "/api/session", host=EXT).status == 200
    assert c.request("GET", "/api/session", host="Sensor.Example-Tailnet.TS.net").status == 200


def test_sessions_are_bound_to_the_kind_of_name(start):
    c = start(external_host=EXT, actions=True)
    c.sign_in()
    local_cookie, local_csrf = c.cookie, c.csrf()
    _, ext_cookie = ext_sign_in(c)
    c.cookie = ext_cookie
    ext_csrf = c.request("GET", "/api/session", host=EXT).json()["csrf"]
    # A loopback cookie is not a session under the external name ...
    c.cookie = local_cookie
    assert c.request("GET", "/api/session", host=EXT).status == 401
    assert c.request("GET", "/", host=EXT).status == 401
    assert ext_post(c, local_cookie, f"https://{EXT}", csrf=local_csrf).status == 401
    # ... and an external cookie is not one on loopback.
    c.cookie = ext_cookie
    assert c.request("GET", "/api/session").status == 401
    headers = {"Origin": c.origin, "X-Winnie-CSRF": ext_csrf, "Content-Type": "application/json"}
    assert c.request("POST", "/api/decide", headers=headers, body=b"{}").status == 401
    assert c.routes.posts == []
    # Each still works where it was issued.
    assert c.request("GET", "/api/session", host=EXT).status == 200
    c.cookie = local_cookie
    assert c.request("GET", "/api/session").status == 200


FORWARDED_HEADERS = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Forwarded-Host": "localhost",
    "X-Forwarded-Proto": "http",
    "X-Forwarded-Port": "80",
    "X-Real-IP": "127.0.0.1",
    "Forwarded": "for=127.0.0.1;host=localhost;proto=http",
    "Tailscale-User-Login": "operator@example.com",
    "Tailscale-User-Name": "Operator",
    "Remote-User": "admin",
    "X-Remote-User": "admin",
    "X-Authenticated-User": "admin",
}


def test_forwarded_and_identity_headers_are_ignored(start):
    c = start(external_host=EXT, actions=True)
    token_target = "/?token=" + urllib.parse.quote(c.srv.token, safe="")
    # They do not make an unknown Host acceptable or stand in for one.
    for host in ("evil.example", None):
        assert c.request("GET", token_target, headers=FORWARDED_HEADERS,
                         host=host).status == 421
    # They do not sign anyone in or open the API without a cookie.
    assert c.request("GET", "/api/session", headers=FORWARDED_HEADERS, host=EXT).status == 401
    assert c.request("GET", "/api/session", headers=FORWARDED_HEADERS).status == 401
    # They do not turn an external sign-in into a loopback one, or the reverse.
    resp = c.request("GET", token_target, headers=FORWARDED_HEADERS, host=EXT)
    assert "Secure" in resp.header("Set-Cookie")
    assert resp.header("Strict-Transport-Security") == HSTS
    https_hint = {**FORWARDED_HEADERS, "X-Forwarded-Proto": "https",
                  "X-Forwarded-Host": EXT, "Forwarded": f"proto=https;host={EXT}"}
    resp = c.request("GET", token_target, headers=https_hint)
    assert "Secure" not in resp.header("Set-Cookie")
    assert resp.header("Strict-Transport-Security") is None
    # They do not change which Origin a POST needs.
    _, cookie = ext_sign_in(c)
    c.cookie = cookie
    csrf = c.request("GET", "/api/session", host=EXT).json()["csrf"]
    headers = {**FORWARDED_HEADERS, "Origin": f"http://127.0.0.1:{c.port}", "X-Winnie-CSRF": csrf,
               "Content-Type": "application/json"}
    assert c.request("POST", "/api/decide", headers=headers, body=b"{}", host=EXT).status == 403
    headers["Origin"] = f"https://{EXT}"
    assert c.request("POST", "/api/decide", headers=headers, body=b"{}", host=EXT).status == 201
    assert len(c.routes.posts) == 1


def test_server_never_reads_proxy_headers():
    """No string the server code uses (docstrings aside) names a proxy-added header."""
    import ast

    tree = ast.parse((STATIC_DIR.parent / "server.py").read_text())
    docstrings = {id(node.value) for node in ast.walk(tree)
                  if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)}
    strings = [node.value.lower() for node in ast.walk(tree)
               if isinstance(node, ast.Constant) and isinstance(node.value, str)
               and id(node) not in docstrings]
    assert "host" in strings  # the scan sees header names
    for name in ("forwarded", "x-real-ip", "tailscale", "remote-user", "x-user", "-user"):
        assert not [s for s in strings if name in s], name


@pytest.mark.parametrize("value", [
    "localhost", "LOCALHOST", "sensor.localhost", "127.0.0.1", "198.51.100.7", "[::1]", "::1",
    "[2001:db8::1]", "2001:db8::1", "0x7f.1", "sensor", "*.example-tailnet.ts.net",
    "sensor.*.ts.net", "https://" + EXT, "http://" + EXT, EXT + "/", EXT + "/console",
    EXT + "/?x=1", EXT + ".", EXT + ":", EXT + ":0", EXT + ":65536", EXT + ":99999",
    EXT + ":08443", EXT + ":http", EXT + ":443:443", "-sensor.example.net", "sensor-.example.net",
    "sensor..example.net", ".example.net", "sensor_one.example.net", "sens or.example.net",
    "sensör.example.net", "user@" + EXT, "x" * 64 + ".example.net",
    ".".join(["a" * 63] * 3 + ["a" * 62]), EXT + "#frag", EXT + "\\x",  # 254 characters
])
def test_invalid_external_host_refuses_to_start(value):
    with pytest.raises(ValueError, match="external_host"):
        build_server(UiSettings(port=0, token="t" * 32, external_host=value), FakeRoutes())


@pytest.mark.parametrize("value,expected", [
    ("", ""), ("  ", ""), (EXT, EXT), (" " + EXT.upper() + " ", EXT), (EXT + ":443", EXT),
    (EXT + ":8443", EXT + ":8443"), (EXT + ":1", EXT + ":1"), (EXT + ":65535", EXT + ":65535"),
    ("a.b", "a.b"), ("x" * 63 + ".example.net", "x" * 63 + ".example.net"),
    ("console-1.sensor-2.example.org", "console-1.sensor-2.example.org"),
    ("xn--snsor-cua.example.net", "xn--snsor-cua.example.net"),
    (".".join(["a" * 63] * 3 + ["a" * 61]), ".".join(["a" * 63] * 3 + ["a" * 61])),  # 253
])
def test_valid_external_host_is_normalized(value, expected):
    assert ui.normalize_external_host(value) == expected


def test_external_host_does_not_relax_the_bind_guard():
    for bind in ("0.0.0.0", "198.51.100.7", "::"):
        with pytest.raises(ValueError, match="non-loopback"):
            build_server(UiSettings(bind=bind, port=0, token="t" * 32, external_host=EXT),
                         FakeRoutes())


def test_serve_logs_both_links_once_and_a_warning(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="agents.ui")
    monkeypatch.setattr(ui.UiServer, "serve_forever", lambda self, *a, **k: None)
    token = "q" * 32
    ui.serve(UiSettings(port=0, token=token, external_host=EXT.upper()), FakeRoutes())
    hits = [r for r in caplog.records if token in r.getMessage()]
    assert len(hits) == 1 and hits[0].levelname == "INFO"
    line = hits[0].getMessage()
    assert re.search(r"http://127\.0\.0\.1:\d+/\?token=" + token, line)
    assert f"https://{EXT}/?token={token}" in line
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1 and EXT in warnings[0] and "proxy" in warnings[0]
    assert "token=" not in warnings[0]


def test_serve_logs_no_external_link_when_unset(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="agents.ui")
    monkeypatch.setattr(ui.UiServer, "serve_forever", lambda self, *a, **k: None)
    ui.serve(UiSettings(port=0, token="q" * 32), FakeRoutes())
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "https://" not in text and "proxy" not in text
    assert not [r for r in caplog.records if r.levelname == "WARNING"]
