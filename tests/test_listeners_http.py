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
