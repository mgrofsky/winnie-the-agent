"""Loopback tests for the scenario-driven fake HTTP listener (raw socket client)."""

import asyncio
import base64
import json
import re
import types

import pytest

from agents.budget import Budget
from agents.llm import LLMOutputError
from listeners import http
from listeners.base import ListenerContext, ServiceSettings
from listeners.events import EventWriter
from scenarios.loader import Honeytoken, LoadedScenario
from scenarios.schema import LoginPolicy, Scenario
from scenarios.tokens import honeytoken_value

POLICY = LoginPolicy(accept="after_n", after_n_min=2, after_n_max=2)


def make_scenario(openapi=None, tokens=(), **http_overrides) -> LoadedScenario:
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
    http_svc.update(http_overrides)
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
    issued = {name: Honeytoken(name, kind, honeytoken_value(kind, "t", "t_portal", name), ("x",))
              for name, kind in tokens}
    return LoadedScenario(scenario=scn, seed="t", honeytokens=issued)


class RaisingLLM:
    def complete_json(self, system, user, schema):
        raise LLMOutputError("bad output")


class FixedLLM:
    def __init__(self, obj):
        self.obj = obj

    def complete_json(self, system, user, schema):
        return self.obj


async def start_server(json_llm=None, openapi=None, tokens=(), **http_overrides):
    scen = make_scenario(openapi, tokens, **http_overrides)
    ctx = ListenerContext(EventWriter(None), scenario=scen, bind_host="127.0.0.1",
                          budget=Budget() if json_llm else None, json_llm=json_llm,
                          honeytokens=scen.recognised_tokens())
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


# ---- reply ladder: model, model with examples, 404 ---------------------------------------

class LadderLLM:
    """Scripted JSON model: exceptions are raised, dicts validated like a real client."""

    def __init__(self, *outputs, delay=0.0):
        self.outputs = list(outputs)
        self.systems = []
        self.delay = delay

    @property
    def calls(self):
        return len(self.systems)

    def complete_json(self, system, user, schema):
        import time

        from pydantic import ValidationError

        self.systems.append(system)
        if self.delay:
            time.sleep(self.delay)
        out = self.outputs.pop(0) if len(self.outputs) > 1 else self.outputs[0]
        if isinstance(out, BaseException):
            raise out
        try:
            return schema.model_validate(out)
        except ValidationError as exc:
            raise LLMOutputError("invalid") from exc


GOOD_API = {"status": 200, "content_type": "application/json", "body": '{"queue": "billing"}'}
BAD_API = {"status": 302, "content_type": "text/html", "body": "<script>"}


async def ladder_request(llm, **limits):
    ctx, servers, port = await start_server(json_llm=llm)
    for name, value in limits.items():
        setattr(ctx.limits, name, value)
    try:
        status, _, body = await req(port, "GET", "/api/v2/queues/billing",
                                    basic("apiuser", "s3cret"))
        await settle()
    finally:
        await stop(servers)
    rungs = [e["data"].get("rung") for e in events(ctx, "command")
             if e["data"].get("route") == "api_unknown"]
    return ctx, status, body, rungs


async def test_http_ladder_first_answer_good():
    llm = LadderLLM(GOOD_API)
    ctx, status, body, rungs = await ladder_request(llm)
    assert status == 200 and json.loads(body) == {"queue": "billing"}
    assert llm.calls == 1 and rungs == ["llm"]


async def test_http_ladder_second_answer_good_uses_examples():
    llm = LadderLLM(BAD_API, GOOD_API)
    ctx, status, body, rungs = await ladder_request(llm)
    assert status == 200 and llm.calls == 2 and rungs == ["llm_retry"]
    assert http.HTTP_EXAMPLES in llm.systems[1] and http.HTTP_EXAMPLES not in llm.systems[0]


async def test_http_ladder_both_bad_is_the_404_page_and_charges_twice():
    from agents.budget import OUTPUT_ESTIMATE_TOKENS

    llm = LadderLLM(BAD_API)
    ctx, status, body, rungs = await ladder_request(llm)
    assert status == 404 and b"404 Not Found" in body
    assert llm.calls == 2 and rungs == ["fallback"]
    assert ctx.budget.global_tokens >= 2 * OUTPUT_ESTIMATE_TOKENS


async def test_http_ladder_timeout_is_not_retried():
    llm = LadderLLM(GOOD_API, delay=0.5)
    ctx, status, _, rungs = await ladder_request(llm, llm_timeout=0.1)
    assert status == 404 and llm.calls == 1 and rungs == ["fallback"]


async def test_http_ladder_one_attempt_keeps_one_request():
    llm = LadderLLM(BAD_API, GOOD_API)
    ctx, status, _, rungs = await ladder_request(llm, llm_attempts=1)
    assert status == 404 and llm.calls == 1 and rungs == ["fallback"]


async def test_http_ladder_deadline_stops_the_second_attempt():
    now = [0.0]

    class Slow(LadderLLM):
        def complete_json(self, system, user, schema):
            now[0] += 11.5
            return super().complete_json(system, user, schema)

    llm = Slow(BAD_API, GOOD_API)
    ctx, servers, port = await start_server(json_llm=llm)
    ctx.llm_clock = lambda: now[0]
    try:
        status, _, _ = await req(port, "GET", "/api/v2/queues/billing", basic("apiuser", "s3cret"))
    finally:
        await stop(servers)
    assert status == 404 and llm.calls == 1


# ---- unknown paths outside the API prefix ---------------------------------------------------

class PageLLM:
    """Scripted page model that records what it was asked."""

    def __init__(self, out):
        self.out = out
        self.users = []

    @property
    def calls(self):
        return len(self.users)

    def complete_json(self, system, user, schema):
        self.users.append(user)
        return self.out


GOOD_PAGE = {"status": 200, "content_type": "text/html",
             "body": "<html><body><h1>Maintenance</h1><p>Back soon.</p></body></html>"}


def unknown_events(ctx, path):
    return [e["data"] for e in events(ctx, "command") if e["data"]["path"] == path]


CANNED_NOT_FOUND = ["/favicon.ico", "/wp-login.php", "/xmlrpc.php", "/phpinfo.php", "/actuator",
                    "/actuator/health", "/actuator/env", "/admin", "/login", "/config.json",
                    "/cgi-bin/", "/cgi-bin/test.cgi", "/server-status", "/.env", "/.git/config",
                    "/.git/HEAD", "/.aws/credentials"]


async def test_probed_paths_answer_canned_and_never_reach_the_model():
    llm = PageLLM(GOOD_PAGE)
    ctx, servers, port = await start_server(json_llm=llm)
    try:
        for path in CANNED_NOT_FOUND:
            status, headers, body = await req(port, "GET", path)
            assert status == 404, path
            assert b"<center><h1>404 Not Found</h1></center>" in body and b"nginx/1.24.0" in body
        status, headers, body = await req(port, "GET", "/robots.txt")
        assert status == 200 and body == b"User-agent: *\nDisallow: /\n"
        assert headers["content-type"] == "text/plain"
        status, _, _ = await req(port, "POST", "/robots.txt", body=b"a=1")
        assert status == 405
        await settle()
    finally:
        await stop(servers)
    assert llm.calls == 0
    assert all(d["route"] == "canned" for p in CANNED_NOT_FOUND for d in unknown_events(ctx, p))


async def test_probed_path_with_configured_paths_below_is_not_canned():
    llm = PageLLM(GOOD_PAGE)
    pages = [{"path": "/admin/users", "title": "Users", "body_html": "<p>x</p>"}]
    ctx, servers, port = await start_server(json_llm=llm, pages=pages)
    try:
        status, _, _ = await req(port, "GET", "/admin")
        assert status == 200
        await settle()
    finally:
        await stop(servers)
    assert llm.calls == 1 and unknown_events(ctx, "/admin")[0]["route"] == "unknown_page"


async def test_api_v1_without_an_api_prefix_is_the_404():
    llm = PageLLM(GOOD_PAGE)
    ctx, servers, port = await start_server(json_llm=llm, api_prefix=None, routes=[])
    try:
        status, _, body = await req(port, "GET", "/api/v1/users")
        assert status == 404 and b"404 Not Found" in body
    finally:
        await stop(servers)
    assert llm.calls == 0


async def test_lure_files_hold_only_issued_scenario_tokens():
    tokens = (("crm_db_password", "db_password"), ("ops_bearer", "bearer_token"),
              ("export_key", "aws_access_key"), ("host_key", "ssh_private_key_id"))
    ctx, servers, port = await start_server(tokens=tokens)
    issued = {t.name: t.value for t in ctx.scenario.honeytokens.values()}
    try:
        status, headers, body = await req(port, "GET", "/.env")
        text = body.decode()
        assert status == 200 and headers["content-type"] == "application/octet-stream"
        assert f"CRM_DB_PASSWORD={issued['crm_db_password']}\n" in text
        assert f"OPS_BEARER={issued['ops_bearer']}\n" in text
        assert f"AWS_ACCESS_KEY_ID={issued['export_key']}\n" in text
        assert issued["host_key"] not in text and "SECRET" not in text
        assert "APP_URL=https://web01.northwind.test" in text
        assert ctx.honeytoken_in(text) is not None
        status, _, body = await req(port, "GET", "/.git/config")
        assert status == 200
        assert f"url = https://oauth2:{issued['ops_bearer']}@git.northwind.test/" in body.decode()
        status, _, body = await req(port, "GET", "/.git/HEAD")
        assert status == 200 and body == b"ref: refs/heads/main\n"
        status, _, _ = await req(port, "GET", "/.aws/credentials")    # source not marked
        assert status == 404
        status, _, _ = await req(port, "POST", "/.env", body=b"x=1")
        assert status == 405
        await settle()
    finally:
        await stop(servers)
    env = unknown_events(ctx, "/.env")[0]
    assert env["lure"] == "/.env" and env["canned"] == "file"
    posted = [d for d in unknown_events(ctx, "/.env") if d["method"] == "POST"][0]
    assert "lure" not in posted and "lure_tokens" not in posted
    assert set(env["lure_tokens"].split(",")) == {"crm_db_password", "ops_bearer", "export_key"}
    assert unknown_events(ctx, "/.aws/credentials")[0]["canned"] == "not_found"


async def test_apache_stack_answers_with_apache_pages():
    ctx, servers, port = await start_server(server_header="Apache/2.4.62 (Debian)")
    try:
        status, headers, body = await req(port, "GET", "/server-status")
        assert status == 403 and headers["content-type"] == "text/html; charset=iso-8859-1"
        assert b"<h1>Forbidden</h1>" in body
        assert b"<address>Apache/2.4.62 (Debian) Server at web01 Port 80</address>" in body
        status, _, _ = await req(port, "GET", "/cgi-bin/")
        assert status == 403
        status, _, body = await req(port, "GET", "/cgi-bin/test.cgi")
        assert status == 404 and b"The requested URL was not found on this server." in body
        status, _, body = await req(port, "GET", "/nothing-here")
        assert status == 404 and b"<h1>Not Found</h1>" in body and b"<center>" not in body
    finally:
        await stop(servers)


async def test_cached_404_is_rendered_for_each_clients_host():
    out = {"status": 404, "content_type": "text/html", "body": "<p>model wrote this</p>"}
    llm = PageLLM(out)
    ctx, servers, port = await start_server(json_llm=llm, server_header="Apache/2.4.62 (Debian)")
    try:
        _, _, first = await req(port, "GET", "/maintenance")
        _, _, second = parse(await raw(port, b"GET /maintenance HTTP/1.1\r\nHost: "
                                             b"portal.northwind.test:8443\r\nConnection: close"
                                             b"\r\n\r\n"))
    finally:
        await stop(servers)
    assert llm.calls == 1
    assert b"Server at web01 Port 80" in first and b"model wrote this" not in first
    assert b"Server at portal.northwind.test Port 8443" in second


async def test_unknown_page_model_answer_is_cached_per_path():
    llm = PageLLM(GOOD_PAGE)
    ctx, servers, port = await start_server(json_llm=llm)
    try:
        for _ in range(2):
            status, headers, body = await req(port, "GET", "/maintenance?probe=1")
            assert status == 200 and b"<h1>Maintenance</h1>" in body
            assert headers["content-type"] == "text/html; charset=utf-8"
        status, headers, body = await req(port, "HEAD", "/maintenance")
        assert status == 200 and body == b""
        await settle()
    finally:
        await stop(servers)
    assert llm.calls == 1
    # The model sees the method and path only: never the query or a body.
    assert "GET /maintenance" in llm.users[0] and "probe" not in llm.users[0]
    logged = unknown_events(ctx, "/maintenance")
    assert [d["route"] for d in logged] == ["unknown_page"] * 3
    assert [d["rung"] for d in logged] == ["llm"] * 3 and [d.get("cache_hit") for d in logged] \
        == [None, True, True]


@pytest.mark.parametrize("out", [
    {"status": 200, "content_type": "text/html", "body": "<p>hi</p><script>x()</script>"},
    {"status": 200, "content_type": "text/html",
     "body": '<meta http-equiv="refresh" content="0;url=/x">'},
    {"status": 200, "content_type": "text/html", "body": '<a href="http://198.51.100.7/">x</a>'},
    {"status": 200, "content_type": "text/html", "body": '<p onclick="x()">x</p>'},
    {"status": 200, "content_type": "text/html",
     "body": '<a href="jav&#x61;script:alert(1)">Help</a>'},
    {"status": 200, "content_type": "text/html",
     "body": '<img src="https:&#47;&#47;evil.example/pixel">'},
    {"status": 200, "content_type": "text/html",
     "body": '<a href="java&amp;#9;script:x()">x</a>'},
    {"status": 200, "content_type": "text/html", "body": '<img src="/\\evil.example/p">'},
    {"status": 200, "content_type": "text/plain", "body": "password = Northwind2024x"},
    {"status": 302, "content_type": "text/html", "body": "moved"},
    {"status": 200, "content_type": "application/xml", "body": "<a/>"},
    {"status": 200, "content_type": "application/json", "body": "not json"},
])
async def test_unsafe_or_invalid_page_answer_is_the_cached_404(out):
    llm = PageLLM(out)
    ctx, servers, port = await start_server(json_llm=llm)
    try:
        for _ in range(2):
            status, _, body = await req(port, "GET", "/maintenance")
            assert status == 404 and b"<center><h1>404 Not Found</h1></center>" in body
        await settle()
    finally:
        await stop(servers)
    assert 1 <= llm.calls <= 2      # an invalid answer may be asked again once, then cached
    assert [d["rung"] for d in unknown_events(ctx, "/maintenance")] == ["fallback"] * 2


async def test_local_links_and_json_pass_the_page_filter():
    out = {"status": 200, "content_type": "application/json", "body": '{"status": "ok"}'}
    ctx, servers, port = await start_server(json_llm=PageLLM(out))
    try:
        status, headers, body = await req(port, "GET", "/healthz")
        assert status == 200 and json.loads(body) == {"status": "ok"}
    finally:
        await stop(servers)
    ctx, servers, port = await start_server(json_llm=PageLLM(
        {"status": 200, "content_type": "text/html",
         "body": '<a href="https://intranet.northwind.test/help">Help</a>'}))
    try:
        status, _, _ = await req(port, "GET", "/help")
        assert status == 200
    finally:
        await stop(servers)


@pytest.mark.parametrize("method,path", [
    ("GET", "/.htaccess"), ("GET", "/backup.sql"), ("GET", "/index.php"), ("GET", "/app.js"),
    ("GET", "/static/logo.png"), ("GET", "/.svn/entries"), ("GET", "/a/../b"),
    ("GET", "/" + "a" * 300), ("POST", "/maintenance"), ("PUT", "/maintenance"),
    ("GET", "/index.html~"), ("GET", "/cgi-bin/x"), ("GET", "/wp-admin/"),
    ("GET", "/actuator/heapdump"), ("GET", "/phpmyadmin/"), ("GET", "/id_rsa"),
    ("GET", "/backup"),
])
async def test_risky_paths_and_methods_never_reach_the_model(method, path):
    llm = PageLLM(GOOD_PAGE)
    ctx, servers, port = await start_server(json_llm=llm)
    try:
        status, _, _ = await req(port, method, path, body=b"a=1" if method != "GET" else b"")
        assert status == 404
    finally:
        await stop(servers)
    assert llm.calls == 0


async def test_scenario_can_turn_the_page_model_off():
    llm = PageLLM(GOOD_PAGE)
    ctx, servers, port = await start_server(json_llm=llm, llm_unknown_paths=False)
    try:
        status, _, _ = await req(port, "GET", "/maintenance")
        assert status == 404
        await settle()
    finally:
        await stop(servers)
    assert llm.calls == 0 and unknown_events(ctx, "/maintenance")[0]["route"] == "not_found"


async def test_page_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(http, "MAX_PAGE_CACHE", 2)
    llm = PageLLM(GOOD_PAGE)
    ctx, servers, port = await start_server(json_llm=llm)
    try:
        for path in ("/a", "/b", "/c", "/a"):
            await req(port, "GET", path)
    finally:
        await stop(servers)
    assert len(http.page_cache(ctx)) == 2 and llm.calls == 4


async def test_post_body_to_a_known_route_is_logged():
    ctx, servers, port = await start_server()
    try:
        status, _, _ = await req(port, "POST", "/api/v1/notes",
                                 {"Content-Type": "application/json"}, b'{"note": "hello"}')
        assert status == 401
        await settle()
    finally:
        await stop(servers)
    data = unknown_events(ctx, "/api/v1/notes")[0]
    assert data["body"] == '{"note": "hello"}' and data["body_bytes"] == 17


# ---- web deception: assets, discovery, markers, flows, evidence ----------------------------

EVIDENCE = {"lure_id", "discovered_via", "discovered_age", "marker", "marker_src", "flow",
            "flow_step", "object_id_count"}
ALWAYS = {"seq", "req", "resp_type", "resp_bytes"}


async def start_pack(name="dev_portal", seed="t", **limits):
    from listeners.base import Limits
    from scenarios.loader import load_scenario

    scen = load_scenario(name, seed=seed)
    ctx = ListenerContext(EventWriter(None), scenario=scen, bind_host="127.0.0.1", seed=seed,
                          honeytokens=scen.recognised_tokens(),
                          limits=Limits(rate_per_ip_per_minute=10_000, **limits))
    svc = scen.scenario.services.http
    settings = ServiceSettings(name="http", enabled=True, port=0, policy=svc.policy,
                               accounts=scen.accounts_for("http"))
    ctx.settings["http"] = settings
    servers = await http.start(ctx, settings)
    return ctx, servers, servers[0].sockets[0].getsockname()[1]


def assets_of(ctx) -> dict:
    return {a.kind if a.kind != "runtime_config" else a.path: a.path
            for a in ctx.scenario.scenario.services.http.assets}


def cmd(ctx, path, method=None) -> list:
    return [e["data"] for e in events(ctx, "command") if e["data"]["path"] == path
            and (method is None or e["data"]["method"] == method)]


def as_source(monkeypatch, holder: dict):
    """Requests are attributed to ``holder['key']`` instead of the loopback address."""
    monkeypatch.setattr(http, "source_key", lambda conn: holder["key"])


async def test_assets_are_served_with_their_type_and_cache_headers():
    ctx, servers, port = await start_pack()
    paths = assets_of(ctx)
    try:
        status, h, body = await req(port, "GET", paths["bundle"])
        assert status == 200 and h["content-type"] == "application/javascript"
        assert h["cache-control"] == "public, max-age=31536000, immutable"
        assert h["etag"].startswith('"') and h["etag"].endswith(f'-{len(body):x}"')
        assert "last-modified" in h
        assert body.rstrip().endswith(
            ("sourceMappingURL=" + paths["source_map"].rsplit("/", 1)[1]).encode())
        status, h, body = await req(port, "GET", paths["source_map"])
        assert status == 200 and h["content-type"] == "application/json"
        json.loads(body)
        status, h, body = await req(port, "GET", "/env.js")
        assert status == 200 and h["content-type"] == "application/javascript"
        assert h["cache-control"] == "no-cache" and body.startswith(b"window.__ENV__ = {")
        status, h, body = await req(port, "GET", "/assets/config.json")
        assert status == 200 and h["content-type"] == "application/json"
        status, h, body = await req(port, "HEAD", "/env.js")
        assert status == 200 and body == b"" and int(h["content-length"]) > 0
        status, _, _ = await req(port, "POST", "/env.js", body=b"x=1")
        assert status == 405
        await settle()
        data = cmd(ctx, paths["bundle"])[0]
        assert data["route"] == "asset" and data["lure_id"] == "main-bundle"
        assert data["resp_type"] == "application/javascript" and data["resp_bytes"] > 0
        head = cmd(ctx, "/env.js", "HEAD")[0]
        assert head["resp_bytes"] == 0 and "lure_id" in head
    finally:
        await stop(servers)


async def test_generated_bundle_map_and_config_name_the_advertised_routes():
    ctx, servers, port = await start_pack()
    paths = assets_of(ctx)
    try:
        _, _, bundle = await req(port, "GET", paths["bundle"])
        _, _, smap = await req(port, "GET", paths["source_map"])
        _, _, config = await req(port, "GET", "/assets/config.json")
    finally:
        await stop(servers)
    for path in ("/api/v1/projects", "/api/v1/auth/forgot-password",
                 "/api/internal/admin/settings"):
        assert f'"{path}"'.encode() in bundle
    assert b'"/api/v1/users/"+encodeURIComponent(e)' in bundle
    assert b'"/api/internal/export/"+encodeURIComponent(e)' in bundle
    doc = json.loads(smap)
    assert doc["version"] == 3 and doc["file"] == paths["bundle"].rsplit("/", 1)[1]
    source = "".join(doc["sourcesContent"])
    assert "`/api/v1/users/${encodeURIComponent(id)}`" in source
    assert "`/api/v1/auth/activate/${encodeURIComponent(token)}`" in source
    cfg = json.loads(config)
    assert {cfg["apiBase"] + p for p in cfg["endpoints"].values()} == {
        "/api/v1/projects", "/api/v1/projects/{id}"}


async def test_hidden_route_is_answered_but_left_out_of_the_generated_openapi():
    routes = [{"path": "/api/v1/status", "auth": "none", "json_body": {"ok": True}},
              {"path": "/api/v1/admin/export", "auth": "none", "hidden": True,
               "json_body": {"queued": True}}]
    ctx, servers, port = await start_server(routes=routes)
    try:
        _, _, body = await req(port, "GET", "/api/openapi.json")
        paths = json.loads(body)["paths"]
        assert "/api/v1/status" in paths and "/api/v1/admin/export" not in paths
        status, _, body = await req(port, "GET", "/api/v1/admin/export")
        assert status == 200 and json.loads(body) == {"queued": True}
    finally:
        await stop(servers)


async def test_hidden_route_is_not_named_to_the_model():
    seen = {}

    class Spy:
        def complete_json(self, system, user, schema):
            seen["system"] = system
            return {"status": 404, "content_type": "application/json", "body": "{}"}

    routes = [{"path": "/api/v1/status", "auth": "none", "json_body": {"ok": True}},
              {"path": "/api/v1/admin/export", "auth": "none", "hidden": True}]
    ctx, servers, port = await start_server(json_llm=Spy(), routes=routes)
    try:
        await req(port, "GET", "/api/v1/unknown", basic("apiuser", "s3cret"))
        await req(port, "GET", "/api/v1/unknown", basic("apiuser", "s3cret"))
    finally:
        await stop(servers)
    assert "/api/v1/status" in seen["system"] and "/api/v1/admin/export" not in seen["system"]


async def test_discovery_is_stamped_only_for_the_source_that_fetched_the_asset(monkeypatch):
    who = {"key": "198.51.100.7"}
    as_source(monkeypatch, who)
    ctx, servers, port = await start_pack()
    paths = assets_of(ctx)
    try:
        await req(port, "GET", "/api/v1/users/5")                 # before any asset
        await req(port, "GET", paths["bundle"])
        await req(port, "GET", "/api/v1/users/5")
        await req(port, "GET", "/swagger.json")                   # export route shown again
        await req(port, "GET", "/api/internal/export/users")
        who["key"] = "203.0.113.9"                                # never fetched anything
        await req(port, "GET", "/api/v1/users/5")
        await settle()
    finally:
        await stop(servers)
    before, after, other = cmd(ctx, "/api/v1/users/5")
    assert "discovered_via" not in before and before["lure_id"] == "user-item"
    assert after["discovered_via"] == "main-bundle" and isinstance(after["discovered_age"], int)
    assert "discovered_via" not in other
    export = cmd(ctx, "/api/internal/export/users")[0]
    assert export["discovered_via"] == "main-bundle"             # the first showing stays
    swagger = cmd(ctx, "/swagger.json")[0]
    assert swagger["route"] == "openapi" and swagger["lure_id"] == "openapi"


async def test_openapi_discovery_counts_only_the_advertised_paths(monkeypatch):
    who = {"key": "198.51.100.8"}
    as_source(monkeypatch, who)
    ctx, servers, port = await start_pack()
    try:
        await req(port, "GET", "/v3/api-docs")
        await req(port, "GET", "/api/internal/export/audit")
        await req(port, "GET", "/api/v1/users/7")                  # not in openapi_advertises
        await settle()
    finally:
        await stop(servers)
    assert cmd(ctx, "/api/internal/export/audit")[0]["discovered_via"] == "openapi"
    assert "discovered_via" not in cmd(ctx, "/api/v1/users/7")[0]


def env_values(body: bytes) -> dict:
    text = body.decode().strip()
    return json.loads(text[text.index("{"):text.rindex("}") + 1])


async def test_markers_differ_per_source_and_are_recognised_where_presented(monkeypatch):
    who = {"key": "198.51.100.20"}
    as_source(monkeypatch, who)
    ctx, servers, port = await start_pack()
    try:
        _, _, body_a = await req(port, "GET", "/env.js")
        _, _, again_a = await req(port, "GET", "/env.js")
        a = env_values(body_a)
        who["key"] = "203.0.113.30"
        _, _, body_b = await req(port, "GET", "/env.js")
        b = env_values(body_b)
        assert body_a == again_a
        for name in ("release", "oauthClientId", "publicApiKey"):
            assert a[name] != b[name] and "{marker" not in a[name]
        assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                            a["oauthClientId"])
        # B presents its own values, then A's, in each place a client can carry one.
        await req(port, "GET", f"/api/v1/projects?client_id={b['oauthClientId']}")
        await req(port, "GET", "/api/v1/health", {"Authorization": f"Bearer {a['publicApiKey']}"})
        await req(port, "GET", "/api/v1/health", {"X-Api-Key": a["publicApiKey"]})
        await req(port, "GET", "/api/v1/health", {"Cookie": f"rel={a['release']}"})
        await req(port, "POST", "/api/v1/auth/username",
                  {"Content-Type": "application/json"},
                  json.dumps({"username": "x", "client": a["oauthClientId"]}).encode())
        await settle()
    finally:
        await stop(servers)
    own = cmd(ctx, "/api/v1/projects")[0]
    assert own["marker"] == "client_id" and "marker_src" not in own
    health = cmd(ctx, "/api/v1/health")
    assert [(d["marker"], d["marker_src"]) for d in health] == [
        ("public_api_key", True), ("public_api_key", True), ("build", True)]
    posted = cmd(ctx, "/api/v1/auth/username")[0]
    assert posted["marker"] == "client_id" and posted["marker_src"] is True
    for d in health + [own, posted]:
        assert "honeytoken" not in d and "high_signal" not in d


async def test_marker_in_route_json_body_is_per_source_and_never_from_a_parameter(monkeypatch):
    who = {"key": "198.51.100.21"}
    as_source(monkeypatch, who)
    ctx, servers, port = await start_pack()
    try:
        _, _, one = await req(port, "GET", "/api/internal/export/users")
        _, _, minted = await req(port, "GET", "/api/internal/export/%7Bmarker:client_id%7D")
        who["key"] = "203.0.113.31"
        _, _, two = await req(port, "GET", "/api/internal/export/users")
    finally:
        await stop(servers)
    one, two, minted = json.loads(one), json.loads(two), json.loads(minted)
    assert one["job_id"] != two["job_id"] and one["download_path"].endswith(one["job_id"])
    assert minted["dataset"] == "{marker:client_id}"


async def test_flows_give_fixed_local_replies():
    ctx, servers, port = await start_pack()
    domain = ctx.scenario.scenario.identity.domain
    js = {"Content-Type": "application/json"}
    try:
        s1, _, b1 = await req(port, "POST", "/api/v1/auth/username", js,
                              json.dumps({"username": f"OPS@{domain}"}).encode())
        s2, _, b2 = await req(port, "POST", "/api/v1/auth/username", js,
                              json.dumps({"email": f"nobody@{domain}"}).encode())
        s3, _, _ = await req(port, "POST", "/api/v1/auth/username", js, b"{}")
        r1 = await req(port, "POST", "/api/v1/auth/forgot-password", js,
                       json.dumps({"email": f"ops@{domain}"}).encode())
        r2 = await req(port, "POST", "/api/v1/auth/forgot-password", js,
                       json.dumps({"email": "nobody@example.com"}).encode())
        s4, _, b4 = await req(port, "POST", "/api/v1/auth/reset-password",
                              {"Content-Type": "application/x-www-form-urlencoded"},
                              b"token=stale-link&password=pw")
        s5, _, b5 = await req(port, "GET", "/api/v1/auth/activate/stale-link")
        await settle()
    finally:
        await stop(servers)
    assert (s1, json.loads(b1)) == (200, {"exists": True})
    assert (s2, json.loads(b2)) == (200, {"exists": False})
    assert s3 == 400
    assert r1[0] == r2[0] == 202 and r1[2] == r2[2]
    assert s4 == 400 and json.loads(b4)["error"] == "invalid_token"
    assert s5 == 400 and "activation" in json.loads(b5)["message"]
    steps = [(d["flow"], d["flow_step"]) for d in (e["data"] for e in events(ctx, "command"))
             if "flow" in d]
    assert steps == [("username_check", "exists"), ("username_check", "unknown"),
                     ("username_check", "missing"), ("recovery_request", "requested"),
                     ("recovery_request", "requested"), ("recovery_reset", "token_rejected"),
                     ("activation", "token_rejected")]


async def test_no_flow_makes_a_login_succeed_or_issues_a_session():
    async def run(with_flows: bool):
        ctx, servers, port = await start_pack()
        domain = ctx.scenario.scenario.identity.domain
        user = f"ops@{domain}"
        cookies = []
        try:
            if with_flows:
                for path, body in (("/api/v1/auth/forgot-password", {"email": user}),
                                   ("/api/v1/auth/reset-password",
                                    {"token": "stale-link", "password": "pw-chosen"}),
                                   ("/api/v1/auth/username", {"username": user})):
                    _, h, _ = await req(port, "POST", path, {"Content-Type": "application/json"},
                                        json.dumps(body).encode())
                    cookies.append(h.get("set-cookie"))
                _, h, _ = await req(port, "GET", "/api/v1/auth/activate/stale-link")
                cookies.append(h.get("set-cookie"))
                assert not events(ctx, "auth_attempt") and not http.sessions(ctx)
            results = []
            for pw in ("pw-chosen", "pw-chosen"):
                status, h, _ = await req(port, "POST", "/signin",
                                         {"Content-Type": "application/x-www-form-urlencoded"},
                                         f"username={user}&password={pw}".encode())
                results.append((status, "set-cookie" in h))
            await settle()
            return results, cookies
        finally:
            await stop(servers)

    plain, _ = await run(False)
    after_flows, cookies = await run(True)
    assert cookies == [None] * 4
    assert after_flows == plain


async def test_object_ids_are_counted_per_source_on_lured_item_routes_only(monkeypatch):
    who = {"key": "198.51.100.40"}
    as_source(monkeypatch, who)
    ctx, servers, port = await start_pack()
    try:
        for i in (2001, 2002, 2002, 9999999):                  # a 404 is still an ID asked
            await req(port, "GET", f"/api/v1/projects/{i}")
        who["key"] = "203.0.113.41"
        await req(port, "GET", "/api/v1/projects/2003")
        await settle()
    finally:
        await stop(servers)
    counts = [d["object_id_count"] for d in (e["data"] for e in events(ctx, "command"))
              if d["path"].startswith("/api/v1/projects/")]
    assert counts == [1, 2, 2, 3, 1]
    ctx, servers, port = await start_server()
    try:
        await req(port, "GET", "/api/v1/patients/1", basic("apiuser", "s3cret"))
        await settle()
    finally:
        await stop(servers)
    assert not EVIDENCE & set(cmd(ctx, "/api/v1/patients/1")[0])


async def test_runtime_config_asset_never_gets_the_planted_key_pair(monkeypatch):
    ctx, servers, port = await start_pack()
    monkeypatch.setattr(ctx, "source", lambda ip: types.SimpleNamespace(
        plant_token=True, tarpit_ms=0, capture_more=False, budget_mode=None))
    try:
        _, _, config = await req(port, "GET", "/assets/config.json")
        _, _, env = await req(port, "GET", "/env.js")
        _, _, settings = await req(port, "GET", "/api/internal/admin/settings")
    finally:
        await stop(servers)
    key_id = ctx.source_token("127.0.0.1")[0]
    assert key_id.encode() not in config and key_id.encode() not in env
    assert b"aws_access_key_id" not in config


async def test_evidence_keys_survive_the_event_key_cap(monkeypatch):
    who = {"key": "198.51.100.50"}
    as_source(monkeypatch, who)
    # Twenty more log fields than any request sets today, so the cap really drops keys.
    plain_auth = http.Exchange.authenticate

    def padded(self):
        plain_auth(self)
        self.log.update({f"pad_{i:02d}": i for i in range(20)})

    monkeypatch.setattr(http.Exchange, "authenticate", padded)
    ctx, servers, port = await start_pack()
    paths = assets_of(ctx)
    try:
        _, _, env = await req(port, "GET", "/env.js")
        await req(port, "GET", paths["bundle"])
        await req(port, "GET", "/api/v1/projects/2001")
        marker = env_values(env)["publicApiKey"]
        # Every optional field at once, a marker from another source, a discovered,
        # lured item route.
        who["key"] = "203.0.113.51"
        await req(port, "GET", paths["bundle"])
        body = json.dumps({"q": marker, "pad": "x" * 100}).encode()
        target = f"http://localhost/api/v1/projects/2002/?k={marker}&p=..%2e%2e"
        await req(port, "GET", target, {
            "Referer": "http://web01/app", "X-Forwarded-For": "192.0.2.4",
            "Content-Type": "application/json", "Origin": "http://web01",
            "Authorization": "Digest x", "X-Api-Key": marker, "Cookie": "session_id=stale",
            "X-Extra": "1"}, body)
        await settle()
    finally:
        await stop(servers)
    data = events(ctx, "command")[-1]["data"]
    assert len(data) == 32 and "referer" not in data and "body" not in data
    must = {"method", "path", "query", "status", "host", "route", "lure_id", "discovered_via",
            "discovered_age", "marker", "marker_src", "object_id_count"} | ALWAYS
    assert must <= set(data), must - set(data)


async def test_shipped_pack_worst_case_request_keeps_every_key():
    ctx, servers, port = await start_pack("api_platform")
    try:
        await req(port, "POST", "http://localhost/v1/consumers/..%2e%2e?a=1", {
            "Referer": "http://web01/x", "X-Forwarded-For": "192.0.2.4",
            "Content-Type": "application/json", "Origin": "http://web01",
            "Authorization": "Digest x", "Cookie": "session_id=stale",
            ctx.scenario.scenario.services.http.api_key_header: "abcdefgh1234"},
            b'{"password": "x"}')
        await settle()
    finally:
        await stop(servers)
    data = events(ctx, "command")[-1]["data"]
    assert len(data) < 32
    assert {"referer", "x_forwarded_for", "content_type", "origin", "body", "body_bytes",
            "absolute_uri", "path_traversal", "auth_scheme", "auth_raw", "api_key_header",
            "stale_cookie", "route"} | ALWAYS <= set(data)


@pytest.mark.parametrize("name", ["api_platform", "bank", "contact_center", "healthcare", "saas",
                                  "sip_provider"])
async def test_shipped_packs_gain_only_the_always_present_keys(name):
    ctx, servers, port = await start_pack(name)
    svc = ctx.scenario.scenario.services.http
    paths = ["/", "/env.js", "/swagger.json", "/static/js/main.js", "/app.js.map"]
    if svc is not None:
        paths += [svc.login_path] + [re.sub(r"\{[^}]+\}", "1", r.path) for r in svc.routes]
        paths += [svc.openapi_path] if svc.openapi_path else []
    try:
        for p in paths:
            await req(port, "GET", p)
        await settle()
    finally:
        await stop(servers)
    commands = events(ctx, "command")
    assert len(commands) == len(paths)
    for i, e in enumerate(commands, 1):
        assert not EVIDENCE & set(e["data"]), (e["data"]["path"], EVIDENCE & set(e["data"]))
        assert ALWAYS <= set(e["data"]) and e["data"]["seq"] == i and e["data"]["req"] == 1


async def test_req_counts_requests_on_one_connection_and_seq_across_them():
    ctx, servers, port = await start_server()
    try:
        one = b"GET /status HTTP/1.1\r\nHost: web01\r\n\r\n"
        await raw(port, one + one + one.replace(b"\r\n\r\n", b"\r\nConnection: close\r\n\r\n"))
        await req(port, "GET", "/status")
        await settle()
    finally:
        await stop(servers)
    got = [(e["data"]["seq"], e["data"]["req"]) for e in events(ctx, "command")]
    assert got == [(1, 1), (2, 2), (3, 3), (4, 1)]
    redirect = [e["data"] for e in events(ctx, "command")]
    assert all(isinstance(d["resp_type"], str) for d in redirect)


async def test_marker_tried_as_basic_credentials_is_recognised(monkeypatch):
    who = {"key": "198.51.100.60"}
    as_source(monkeypatch, who)
    ctx, servers, port = await start_pack()
    try:
        _, _, env = await req(port, "GET", "/env.js")
        key = env_values(env)["publicApiKey"]
        await req(port, "GET", "/api/v1/projects", basic(key, ""))
        await settle()
    finally:
        await stop(servers)
    assert cmd(ctx, "/api/v1/projects")[0]["marker"] == "public_api_key"


async def test_wrong_method_on_a_shown_route_still_carries_its_discovery(monkeypatch):
    who = {"key": "198.51.100.61"}
    as_source(monkeypatch, who)
    ctx, servers, port = await start_pack()
    try:
        await req(port, "GET", assets_of(ctx)["bundle"])
        status, _, _ = await req(port, "DELETE", "/api/v1/users/9")
        await settle()
    finally:
        await stop(servers)
    data = cmd(ctx, "/api/v1/users/9")[0]
    assert status == 405 and data["route"] == "method_not_allowed"
    assert data["discovered_via"] == "main-bundle" and "object_id_count" not in data


async def test_app_shell_links_the_runtime_config_and_bundle():
    ctx, servers, port = await start_pack()
    try:
        status, _, page = await req(port, "GET", "/")
    finally:
        await stop(servers)
    srcs = re.findall(rb'<script[^>]*src="([^"]+)"', page)
    assert status == 200 and srcs == [b"/env.js", assets_of(ctx)["bundle"].encode()]


async def test_asset_text_is_built_once_per_scenario(monkeypatch):
    calls = []
    real = http.asset_text
    monkeypatch.setattr(http, "asset_text", lambda *a: calls.append(1) or real(*a))
    ctx, servers, port = await start_pack()
    try:
        for _ in range(3):
            await req(port, "GET", "/assets/config.json")
    finally:
        await stop(servers)
    assert len(calls) == len(ctx.scenario.scenario.services.http.assets)



async def test_dev_portal_documents_build_urls_the_trap_answers():
    """Every OpenAPI operation joined to its server URL, every runtime-config endpoint
    joined to apiBase, and the bundle's own URLs reach a configured route, never /api/api."""
    from urllib.parse import urlsplit

    ctx, servers, port = await start_pack()
    paths = assets_of(ctx)
    try:
        _, _, doc = await req(port, "GET", "/api/openapi.json")
        _, _, config = await req(port, "GET", "/assets/config.json")
        _, _, env = await req(port, "GET", "/env.js")
        _, _, bundle = await req(port, "GET", paths["bundle"])
        doc, config, env = json.loads(doc), json.loads(config), env_values(env)
        urls = []
        for server in doc["servers"]:
            base = urlsplit(server["url"]).path.rstrip("/")
            for path, ops in doc["paths"].items():
                urls += [(method.upper(), base + path) for method in ops]
        urls += [("GET", config["apiBase"] + p) for p in config["endpoints"].values()]
        urls += [("GET", env["apiBase"] + env["exportsPath"] + "/{dataset}")]
        urls += [("GET", p.decode() + "1") for p in re.findall(rb'"(/[^"]+/)"\+encode', bundle)]
        start = len(events(ctx, "command"))
        for method, url in urls:
            await req(port, method, re.sub(r"\{[^}]+\}", "1", url))
        await settle()
    finally:
        await stop(servers)
    routes = {r.path for r in ctx.scenario.scenario.services.http.routes}
    answered = [e["data"] for e in events(ctx, "command")[start:]]
    assert len(answered) == len(urls) >= 10
    for (method, url), data in zip(urls, answered):
        assert "/api/api" not in data["path"], url
        assert data["route"] in routes, (method, url, data["route"])
