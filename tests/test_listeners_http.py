"""Loopback tests for the scenario-driven fake HTTP listener (raw socket client)."""

import asyncio
import base64
import json

import pytest

from agents.budget import Budget
from agents.llm import LLMOutputError
from listeners import http
from listeners.base import ListenerContext, ServiceSettings
from listeners.events import EventWriter
from scenarios.loader import LoadedScenario
from scenarios.schema import LoginPolicy, Scenario

POLICY = LoginPolicy(accept="after_n", after_n_min=2, after_n_max=2)


def make_scenario(openapi=None) -> LoadedScenario:
    http_svc = {
        "enabled": True, "port": 0, "server_header": "nginx/1.24.0 (Ubuntu)",
        "login_path": "/portal/login", "login_title": "Northwind Patient Portal",
        "branding": "Authorized staff only. Activity is monitored.",
        "pages": [{"path": "/portal/home", "title": "Home",
                   "body_html": "<h1>Welcome {{user}}</h1><p>{{org}}</p>"},
                  {"path": "/status", "title": "Status", "body_html": "<p>OK</p>",
                   "requires_login": False}],
        "api_prefix": "/api",
        "api_key_header": "X-Api-Key",
        "routes": [
            {"path": "/api/v1/patients", "list_from": "clinic.patients", "list_limit": 2},
            {"path": "/api/v1/patients/{id}", "item_from": "clinic.patients", "item_key": "id"},
            {"path": "/api/v1/echo/{name}", "auth": "none", "json_body": {"hello": "{name}",
                                                                         "n": 1}},
            {"method": "POST", "path": "/api/v1/notes", "auth": "bearer", "status": 201,
             "json_body": {"id": 77, "status": "created"}},
        ],
        "openapi_path": "/api/openapi.json",
        "llm_unknown_api_routes": True,
        "accounts": [{"username": "apiuser", "password": "s3cret"}],
    }
    if openapi is not None:
        http_svc["openapi"] = openapi
    scn = Scenario.model_validate({
        "name": "t_portal", "title": "Test portal", "description": "test",
        "identity": {"org_name": "Northwind Clinic", "hostname": "web01",
                     "domain": "northwind.test", "internal_ips": ["10.20.0.6"],
                     "os_pretty_name": "Ubuntu 22.04.4 LTS", "kernel": "Linux web01 5.15.0-101-generic"},
        "services": {
            "http": http_svc,
            "postgres": {"enabled": False, "port": 0, "databases": [{"name": "clinic", "tables": [{
                "name": "patients",
                "columns": [{"name": "id", "type": "int"}, {"name": "full_name", "type": "text"}],
                "seed_rows": [[1, "Avery Hartwell"], [2, "Jordan Okonkwo"], [3, "Riley Lindqvist"]]}]}]},
        },
    })
    return LoadedScenario(scenario=scn, seed="t")


class RaisingLLM:
    def complete_json(self, system, user, schema):
        raise LLMOutputError("bad output")


class FixedLLM:
    def __init__(self, obj):
        self.obj = obj

    def complete_json(self, system, user, schema):
        return self.obj


async def start_server(json_llm=None, openapi=None):
    scen = make_scenario(openapi)
    ctx = ListenerContext(EventWriter(None), scenario=scen, bind_host="127.0.0.1",
                          budget=Budget() if json_llm else None, json_llm=json_llm)
    settings = ServiceSettings(name="http", enabled=True, port=0, policy=POLICY,
                               accounts=scen.accounts_for("http"))
    ctx.settings["http"] = settings
    servers = await http.start(ctx, settings)
    return ctx, servers, servers[0].sockets[0].getsockname()[1]


async def stop(servers):
    for s in servers:
        s.close()
        await s.wait_closed()


async def raw(port, data: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(data)
    await w.drain()
    if not data:
        w.write_eof()
    out = await asyncio.wait_for(r.read(), 5)
    w.close()
    return out


def parse(resp: bytes):
    head, _, body = resp.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(": ")
        headers.setdefault(k.lower(), v)
    return status, headers, body


async def req(port, method, path, headers=None, body=b""):
    lines = [f"{method} {path} HTTP/1.1", "Host: web01", "User-Agent: test-agent/1.0",
             "Connection: close"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    data = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
    return parse(await raw(port, data))


def basic(user, pw):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}


def events(ctx, event):
    return [e for e in ctx.writer.events if e["event"] == event]


async def settle():
    await asyncio.sleep(0.05)


async def test_login_form_capture_and_session():
    ctx, servers, port = await start_server()
    try:
        status, headers, _ = await req(port, "GET", "/portal/home")
        assert status == 302 and headers["location"] == "/portal/login"
        assert headers["server"] == "nginx/1.24.0 (Ubuntu)"
        status, _, body = await req(port, "GET", "/portal/login")
        assert status == 200 and b"Northwind Patient Portal" in body
        assert b"Authorized staff only" in body and b'name="password"' in body
        form = {"Content-Type": "application/x-www-form-urlencoded"}
        status, _, body = await req(port, "POST", "/portal/login", form,
                                    b"username=jdoe&password=Summer2025%21")
        assert status == 200 and b"Invalid username or password" in body
        status, headers, _ = await req(port, "POST", "/portal/login", form,
                                       b"username=%3Cb%3Ejdoe&password=Welcome1")
        assert status == 302 and headers["location"] == "/portal/home"
        cookie = headers["set-cookie"]
        assert cookie.startswith("session_id=") and "HttpOnly" in cookie
        sid = cookie.split(";")[0]
        status, _, body = await req(port, "GET", "/portal/home", {"Cookie": sid})
        assert status == 200 and b"Welcome &lt;b&gt;jdoe" in body and b"<b>jdoe" not in body
        status, _, body = await req(port, "GET", "/status")
        assert status == 200
        await settle()
    finally:
        await stop(servers)
    attempts = events(ctx, "auth_attempt")
    assert [(a["username"], a["password"], a["success"]) for a in attempts] == [
        ("jdoe", "Summer2025!", False), ("<b>jdoe", "Welcome1", True)]
    assert attempts[0]["client"] == "test-agent/1.0" and attempts[0]["data"]["method"] == "form"
    reqs = events(ctx, "command")
    assert any(e["data"]["path"] == "/portal/login" and e["data"]["method"] == "POST"
               and "password=Summer2025" in e["data"]["body"] for e in reqs)
    assert all(e["client"] == "test-agent/1.0" for e in reqs)


async def test_basic_bearer_and_api_key_capture():
    ctx, servers, port = await start_server()
    try:
        status, headers, body = await req(port, "GET", "/api/v1/patients")
        assert status == 401 and headers["www-authenticate"] == 'Basic realm="Northwind Clinic"'
        assert json.loads(body)["error"] == "unauthorized"
        status, _, body = await req(port, "GET", "/api/v1/patients", basic("apiuser", "s3cret"))
        assert status == 200
        assert json.loads(body) == [{"id": 1, "full_name": "Avery Hartwell"},
                                    {"id": 2, "full_name": "Jordan Okonkwo"}]
        status, _, _ = await req(port, "POST", "/api/v1/notes",
                                 {"Authorization": "Bearer opaque-abc123"}, b"{}")
        assert status == 401
        status, _, body = await req(port, "GET", "/api/v1/patients", {"X-Api-Key": "sk_live_zzz"})
        assert status == 200
        # the key that "worked" keeps working; a bearer route still needs a bearer token
        status, _, _ = await req(port, "POST", "/api/v1/notes", {"X-Api-Key": "sk_live_zzz"}, b"{}")
        assert status == 401
        await settle()
    finally:
        await stop(servers)
    attempts = [(a["username"], a["password"], a["success"], a["data"]["method"])
                for a in events(ctx, "auth_attempt")]
    assert ("apiuser", "s3cret", True, "basic") in attempts
    assert ("<bearer>", "opaque-abc123", False, "bearer") in attempts
    assert ("<api_key>", "sk_live_zzz", True, "api_key") in attempts


async def test_path_parameter_routes_and_openapi():
    ctx, servers, port = await start_server()
    try:
        auth = basic("apiuser", "s3cret")
        status, _, body = await req(port, "GET", "/api/v1/patients/3", auth)
        assert status == 200 and json.loads(body) == {"id": 3, "full_name": "Riley Lindqvist"}
        status, _, body = await req(port, "GET", "/api/v1/patients/999", auth)
        assert status == 404 and json.loads(body) == {"error": "not found"}
        status, headers, body = await req(port, "GET", '/api/v1/echo/%22%3Cx%3E%7Bname%7D')
        assert status == 200 and headers["content-type"] == "application/json"
        assert json.loads(body) == {"hello": '"<x>{name}', "n": 1}
        status, _, _ = await req(port, "DELETE", "/api/v1/patients/3", auth)
        assert status == 405
        status, _, body = await req(port, "GET", "/api/openapi.json")
        doc = json.loads(body)
        assert status == 200 and "/api/v1/patients/{id}" in doc["paths"]
        assert doc["paths"]["/api/v1/patients/{id}"]["get"]["parameters"][0]["name"] == "id"
        await settle()
    finally:
        await stop(servers)
    custom = {"openapi": "3.1.0", "info": {"title": "Northwind FHIR", "version": "4.0.1"},
              "paths": {}}
    ctx, servers, port = await start_server(openapi=custom)
    try:
        status, _, body = await req(port, "GET", "/api/openapi.json")
        assert json.loads(body) == custom
    finally:
        await stop(servers)


@pytest.mark.parametrize("llm,expect", [
    (RaisingLLM(), 404),
    (FixedLLM({"status": 302, "content_type": "text/html", "body": "<script>"}), 404),
    (FixedLLM(http.LlmHttpAnswer.model_construct(status=200, content_type="application/json",
                                                 body="not json {")), 404),
    (FixedLLM(http.LlmHttpAnswer(status=200, content_type="application/json",
                                 body='{"queue": "billing", "waiting": 3}')), 200),
])
async def test_unknown_api_route_model_and_fallback(llm, expect):
    ctx, servers, port = await start_server(json_llm=llm)
    try:
        status, headers, body = await req(port, "GET", "/api/v2/queues/billing",
                                          basic("apiuser", "s3cret"))
        assert status == expect
        if expect == 200:
            assert json.loads(body) == {"queue": "billing", "waiting": 3}
        else:
            assert b"<center><h1>404 Not Found</h1></center>" in body
        # unauthenticated unknown API route never reaches the model
        status, _, _ = await req(port, "GET", "/api/v2/anything")
        assert status == 401
        status, _, body = await req(port, "GET", "/wp-login.php")
        assert status == 404 and b"nginx/1.24.0" in body
        await settle()
    finally:
        await stop(servers)
    assert not events(ctx, "error")


async def test_keep_alive_bounded_by_command_cap():
    ctx, servers, port = await start_server()
    ctx.limits.max_commands_per_connection = 3
    try:
        one = b"GET /status HTTP/1.1\r\nHost: web01\r\n\r\n"
        out = await raw(port, one * 6)
        assert out.count(b"HTTP/1.1 200 OK") == 3
        await settle()
    finally:
        await stop(servers)
    assert any(e["data"].get("reason") == "max_commands_per_connection"
               for e in events(ctx, "limit"))


async def test_malformed_and_oversized_input_closes_cleanly():
    ctx, servers, port = await start_server()
    try:
        status, _, _ = parse(await raw(port, b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\n\r\n"))
        assert status == 414
        status, _, _ = parse(await raw(port, b"POST /portal/login HTTP/1.1\r\nHost: x\r\n"
                                             b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"))
        assert status == 411
        flood = b"".join(f"X-H{i}: v\r\n".encode() for i in range(60))
        status, _, _ = parse(await raw(port, b"GET / HTTP/1.1\r\n" + flood + b"\r\n"))
        assert status == 431
        status, _, _ = parse(await raw(port, b"POST /x HTTP/1.1\r\nContent-Length: 999999\r\n\r\n"))
        assert status == 413
        status, _, _ = parse(await raw(port, b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03\r\n\r\n"))
        assert status == 400
        status, _, _ = parse(await raw(port, b"GET /status HTTP/2.0\r\n\r\n"))
        assert status == 505
        status, _, _ = parse(await raw(port, b"GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n"))
        assert status == 400
        assert await raw(port, b"") == b""
        await settle()
    finally:
        await stop(servers)
    assert not [e for e in ctx.writer.events if e["message"] == "Handler error"]
    reasons = {e["data"].get("reason") for e in events(ctx, "error")}
    assert {"request_line_too_long", "transfer_encoding", "too_many_headers", "body_too_large",
            "bad_request_line", "bad_version"} <= reasons
    proxy = [e for e in events(ctx, "command") if e["data"].get("signal") == "http_proxy_attempt"]
    assert proxy and proxy[0]["data"]["high_signal"] is True


@pytest.mark.parametrize("target", [
    b"//[x/", b"/[::1", b"http://[x/", b"http://[::1/", b"/a?b=%ZZ", b"http://h:99999999999/",
    b"/%ff%fe%00", b"http://" + b"a" * 4000 + b"/",
])
async def test_unparseable_targets_get_400_not_a_dropped_connection(target):
    ctx, servers, port = await start_server()
    try:
        out = await raw(port, b"GET " + target + b" HTTP/1.1\r\nHost: web01\r\n"
                              b"Connection: close\r\n\r\n")
        assert out, "connection closed without a response"
        status, headers, body = parse(out)
        assert status in (400, 404, 302)
        await settle()
    finally:
        await stop(servers)
    assert not [e for e in ctx.writer.events if e["message"] == "Handler error"]


async def test_bracket_host_target_is_400():
    ctx, servers, port = await start_server()
    try:
        status, headers, body = parse(await raw(port, b"GET //[x/ HTTP/1.1\r\nHost: web01\r\n\r\n"))
        assert status == 400 and headers["connection"] == "close"
        assert b"<title>400 Bad Request</title>" in body
        await settle()
    finally:
        await stop(servers)
    assert any(e["data"].get("reason") == "bad_target" for e in events(ctx, "error"))


@pytest.mark.parametrize("value,status", [
    (b"99999999999999999999", 400), (b"-1", 400), (b"1e3", 400), (b"0x10", 400),
    (b"\xd9\xa3", 400), (b"65537", 413),
])
async def test_content_length_range(value, status):
    ctx, servers, port = await start_server()
    try:
        out = await raw(port, b"POST /portal/login HTTP/1.1\r\nHost: web01\r\nContent-Length: "
                        + value + b"\r\n\r\n")
        assert parse(out)[0] == status
        await settle()
    finally:
        await stop(servers)
    assert not [e for e in ctx.writer.events if e["message"] == "Handler error"]


async def test_basic_token_without_colon_is_logged_as_the_secret_not_the_username():
    ctx, servers, port = await start_server()
    token = base64.b64encode(b"NoColonApiToken42").decode()
    try:
        await req(port, "GET", "/api/v1/patients", {"Authorization": "Basic " + token})
        await settle()
    finally:
        await stop(servers)
    basics = [a for a in events(ctx, "auth_attempt") if a["data"]["method"] == "basic"]
    assert basics and all("NoColonApiToken42" not in (a.get("username") or "") for a in basics)
    assert any(a["password"] == "NoColonApiToken42" for a in basics)
