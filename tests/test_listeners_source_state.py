"""Per-source state honoured by the listeners: tarpit, planted tokens, capture level,
expiry and reload, budget mode. Loopback only, ephemeral ports."""

from __future__ import annotations

import asyncio
import base64
import datetime
import json
import os
import time
from typing import Optional

import pytest

from agents.budget import Budget, ip_key
from agents.source_state import (
    MAX_TARPIT_MS,
    SourceEntry,
    SourceState,
    new_entry,
    source_token,
    source_token_name,
    update,
)
from listeners import ftp, http, redis as redis_trap, sip, smtp, telnet
from listeners.base import CAPTURE_PARTS, Conn, Limits, ListenerContext, ServiceSettings
from listeners.events import EventWriter
from scenarios.loader import LoadedScenario
from scenarios.schema import LoginPolicy, Scenario

LOOP = "127.0.0.1"
OTHER = "203.0.113.5"      # a source that never connects; its token is reused from loopback
UNPLANTED = "198.51.100.9"
SEED = "test-seed"

FTP_SCENARIO = {
    "name": "unit_test", "title": "Unit", "description": "unit test scenario",
    "identity": {"org_name": "Example Org", "hostname": "pbx01", "domain": "example.test",
                 "internal_ips": ["10.0.0.5"], "os_pretty_name": "Debian GNU/Linux 12",
                 "kernel": "Linux pbx01 6.1.0-18-amd64 #1 SMP x86_64 GNU/Linux"},
    "services": {"ftp": {"enabled": True, "port": 0, "banner": "(vsFTPd 3.0.3)",
                         "retr_max_bytes": 4096,
                         "files": [{"path": "/voicemail/README.txt",
                                    "content": "Voicemail export folder\n"}]}},
}

REDIS_SCENARIO = {
    "name": "unit_test", "title": "Unit", "description": "unit test scenario",
    "identity": {"org_name": "Example Bank", "hostname": "cache01", "domain": "example.test",
                 "internal_ips": ["10.0.0.9"], "os_pretty_name": "Ubuntu 22.04.4 LTS",
                 "kernel": "Linux cache01 5.15.0 #1 SMP x86_64 GNU/Linux"},
    "services": {"redis": {"enabled": True, "port": 0, "version": "6.2.14", "keys": [
        {"key": "session:9f1c", "value": "{\"uid\": 7}"}]}},
}

HTTP_SCENARIO = {
    "name": "t_portal", "title": "Test portal", "description": "test",
    "identity": {"org_name": "Northwind Clinic", "hostname": "web01", "domain": "northwind.test",
                 "internal_ips": ["10.20.0.6"], "os_pretty_name": "Ubuntu 22.04.4 LTS",
                 "kernel": "Linux web01 5.15.0-101-generic"},
    "services": {"http": {
        "enabled": True, "port": 0, "api_prefix": "/api",
        "routes": [
            {"path": "/api/v1/status", "auth": "none", "json_body": {"ok": True}},
            {"path": "/api/v1/config", "auth": "none", "json_body": {"env": "prod"}},
            {"path": "/api/v1/settings", "auth": "none", "json_body": {"theme": "dark"}},
        ]}},
}


def write_state(path, **sources: dict) -> None:
    """Write per-source entries (keyword: IP with dots/colons replaced by '_')."""
    def mutate(st: SourceState) -> SourceState:
        for name, fields in sources.items():
            ip = name.replace("_", ".")
            e = new_entry(ip_key(ip))
            st.entries[e.key] = e.model_copy(update=fields)
        return st
    update(path, path.parent / "state", mutate)


def plain_state(path, entries: dict[str, dict]) -> None:
    path.write_text(json.dumps({"entries": entries}))


def fast_view(ctx: ListenerContext) -> None:
    ctx.source_state.check_every = 0.0


def events(writer, event=None):
    return [e for e in writer.events if event is None or e["event"] == event]


def captures(writer, label=None):
    return [e for e in events(writer, "command") if "capture_label" in e["data"]
            and (label is None or e["data"]["capture_label"] == label)]


class Ctl:
    def __init__(self, reader, writer) -> None:
        self.reader, self.writer = reader, writer

    @classmethod
    async def open(cls, port: int) -> "Ctl":
        r, w = await asyncio.open_connection(LOOP, port)
        c = cls(r, w)
        await c.line()
        return c

    async def line(self) -> str:
        return (await asyncio.wait_for(self.reader.readline(), 10)).decode().rstrip("\r\n")

    async def cmd(self, text: str) -> str:
        self.writer.write(text.encode() + b"\r\n")
        await self.writer.drain()
        return await self.line()

    async def lines_until(self, prefix: str) -> list[str]:
        out = []
        while True:
            line = await self.line()
            out.append(line)
            if line.startswith(prefix):
                return out

    async def pasv_port(self) -> int:
        resp = await self.cmd("PASV")
        nums = [int(x) for x in resp[resp.index("(") + 1:resp.index(")")].split(",")]
        return nums[4] * 256 + nums[5]

    async def retr(self, name: str) -> bytes:
        dport = await self.pasv_port()
        dr, dw = await asyncio.open_connection(LOOP, dport)
        first = await self.cmd(f"RETR {name}")
        assert first.startswith("150"), first
        data = await asyncio.wait_for(dr.read(), 5)
        dw.close()
        await self.line()
        return data

    async def nlst(self, arg: str = "") -> list[str]:
        dport = await self.pasv_port()
        dr, dw = await asyncio.open_connection(LOOP, dport)
        await self.cmd(f"NLST {arg}".strip())
        data = await asyncio.wait_for(dr.read(), 5)
        dw.close()
        await self.line()
        return data.decode().split()

    def close(self) -> None:
        self.writer.close()


@pytest.fixture
async def servers():
    started = []
    yield started
    for s in started:
        s.close()


def ftp_ctx(tmp_path, state: Optional[str], accept="all", limits=None):
    writer = EventWriter(None)
    ctx = ListenerContext(writer, limits=limits, bind_host=LOOP, seed=SEED,
                          scenario=LoadedScenario(scenario=Scenario.model_validate(FTP_SCENARIO),
                                                  seed="t"),
                          quarantine_dir=str(tmp_path / "quarantine"), source_state_path=state)
    fast_view(ctx)
    settings = ServiceSettings(name="ftp", enabled=True, port=0, banner="(vsFTPd 3.0.3)",
                               policy=LoginPolicy(accept=accept))
    ctx.settings["ftp"] = settings
    return ctx, settings, writer


async def start_ftp(servers, tmp_path, state, **kw):
    ctx, settings, writer = ftp_ctx(tmp_path, state, **kw)
    objs = await ftp.start(ctx, settings)
    servers.extend(objs)
    return ctx, writer, objs[0].sockets[0].getsockname()[1]


# ---- tarpit ----------------------------------------------------------------------------------

async def _banner_latency(port: int) -> float:
    t0 = time.monotonic()
    c = await Ctl.open(port)
    elapsed = time.monotonic() - t0
    c.close()
    return elapsed


async def test_tarpit_delays_tcp_responses(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"127_0_0_1": {"tarpit_ms": 400}})
    _, _, port = await start_ftp(servers, tmp_path, str(state))
    slow = await _banner_latency(port)
    assert 0.38 <= slow < 2.0

    _, _, port2 = await start_ftp(servers, tmp_path / "b", None)
    fast = await _banner_latency(port2)
    assert fast < 0.2


async def test_tarpit_bounded_and_never_past_session_end(tmp_path):
    ctx = ListenerContext(EventWriter(None), limits=Limits(session_timeout=10.0))
    key = ip_key(OTHER)
    # A hand-made out-of-range entry still yields at most MAX_TARPIT_MS.
    entry = SourceEntry.model_construct(**{**new_entry(key).model_dump(), "tarpit_ms": 60_000})
    ctx.source_state._state = SourceState.model_construct(entries={key: entry})
    assert ctx.tarpit_seconds(OTHER) == MAX_TARPIT_MS / 1000
    assert ctx.tarpit_seconds(UNPLANTED) == 0.0

    class W:
        def get_extra_info(self, name):
            return (OTHER, 5555) if name == "peername" else (LOOP, 21)

        def write(self, data):
            pass

        async def drain(self):
            pass

    conn = Conn(ctx, "ftp", asyncio.StreamReader(), W())
    conn.started = time.monotonic() - 9.7          # 0.3 s of session left
    t0 = time.monotonic()
    await conn.write(b"x")
    assert time.monotonic() - t0 < 0.6


async def test_tarpit_delays_sip_udp(tmp_path, servers, monkeypatch):
    state = tmp_path / "source_state.json"
    write_state(state, **{"127_0_0_1": {"tarpit_ms": 400}})

    async def latency(state_path):
        writer = EventWriter(None)
        ctx = ListenerContext(writer, bind_host=LOOP, seed=SEED, source_state_path=state_path)
        settings = ServiceSettings(name="sip", enabled=True, port=0)
        ctx.settings["sip"] = settings
        objs = await sip.start(ctx, settings)
        servers.extend(objs)
        udp = next(o for o in objs if not isinstance(o, asyncio.base_events.Server))
        port = udp.get_extra_info("sockname")[1]
        loop = asyncio.get_running_loop()
        q: asyncio.Queue = asyncio.Queue()

        class Client(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                q.put_nowait(data)

        transport, _ = await loop.create_datagram_endpoint(Client, remote_addr=(LOOP, port))
        servers.append(transport)
        msg = (f"OPTIONS sip:100@{LOOP} SIP/2.0\r\n"
               f"Via: SIP/2.0/UDP {LOOP}:5099;branch=z9hG4bK-1;rport\r\n"
               f"From: <sip:100@{LOOP}>;tag=aaa\r\nTo: <sip:100@{LOOP}>\r\n"
               "Call-ID: tarpit@client\r\nCSeq: 1 OPTIONS\r\nUser-Agent: friendly-scanner\r\n"
               "Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n").encode()
        t0 = time.monotonic()
        transport.sendto(msg)
        await asyncio.wait_for(q.get(), 3)
        elapsed = time.monotonic() - t0
        await asyncio.sleep(0.5)
        assert q.empty()                         # still exactly one response
        return elapsed

    assert 0.38 <= await latency(str(state)) < 2.0
    assert await latency(None) < 0.2


# ---- planted tokens ------------------------------------------------------------------------

async def test_ftp_serves_unique_planted_credentials(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"127_0_0_1": {"plant_token": True},
                          "203_0_113_5": {"plant_token": True}})
    ctx, writer, port = await start_ftp(servers, tmp_path, str(state))
    c = await Ctl.open(port)
    await c.cmd("USER a")
    assert (await c.cmd("PASS b")).startswith("230")
    assert ".aws" in await c.nlst("/")
    body = (await c.retr("/.aws/credentials")).decode()
    c.close()
    mine = source_token(SEED, ip_key(LOOP))
    other = source_token(SEED, ip_key(OTHER))
    assert mine != other
    assert f"aws_access_key_id = {mine[0]}" in body and f"aws_secret_access_key = {mine[1]}" in body
    assert other[0] not in body

    # The other source's tree holds its own key; an unplanted source gets no file.
    other_tree = ftp.build_tree(ctx, OTHER)
    assert other[0].encode() in other_tree.files["/.aws/credentials"].content
    assert "/.aws/credentials" not in ftp.build_tree(ctx, UNPLANTED).files


def test_ftp_appends_backup_profile_to_existing_credentials(tmp_path):
    state = tmp_path / "source_state.json"
    write_state(state, **{"203_0_113_5": {"plant_token": True}})
    scen = json.loads(json.dumps(FTP_SCENARIO))
    scen["services"]["ftp"]["files"].append(
        {"path": "/.aws/credentials",
         "content": "[default]\naws_access_key_id = AKIAEXISTING\naws_secret_access_key = x\n"})
    ctx = ListenerContext(EventWriter(None), seed=SEED, source_state_path=str(state),
                          scenario=LoadedScenario(scenario=Scenario.model_validate(scen), seed="t"))
    text = ftp.build_tree(ctx, OTHER).files["/.aws/credentials"].content.decode()
    assert "AKIAEXISTING" in text and "[backup]" in text
    assert source_token(SEED, ip_key(OTHER))[0] in text


async def test_ftp_login_with_other_sources_token_is_attributed(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"203_0_113_5": {"plant_token": True}})
    _, writer, port = await start_ftp(servers, tmp_path, str(state))
    key_id, secret = source_token(SEED, ip_key(OTHER))
    c = await Ctl.open(port)
    await c.cmd(f"USER {key_id}")
    await c.cmd("PASS whatever")
    c.close()
    c = await Ctl.open(port)
    await c.cmd("USER admin")
    await c.cmd(f"PASS {secret}")
    c.close()
    await asyncio.sleep(0.1)
    auths = events(writer, "auth_attempt")
    assert [a["data"].get("honeytoken") for a in auths] == [source_token_name(ip_key(OTHER))] * 2


class FakeConn:
    def __init__(self, ctx, ip):
        self.ctx, self.src_ip = ctx, ip


def redis_ctx(state: Optional[str]) -> ListenerContext:
    ctx = ListenerContext(EventWriter(None), bind_host=LOOP, seed=SEED, source_state_path=state,
                          scenario=LoadedScenario(scenario=Scenario.model_validate(REDIS_SCENARIO),
                                                  seed="t"))
    fast_view(ctx)
    return ctx


def test_redis_keyspace_holds_unique_token(tmp_path):
    state = tmp_path / "source_state.json"
    write_state(state, **{"127_0_0_1": {"plant_token": True},
                          "203_0_113_5": {"plant_token": True}})
    ctx = redis_ctx(str(state))
    settings = ServiceSettings(name="redis", enabled=True, port=0)
    a = redis_trap.RedisSession(FakeConn(ctx, LOOP), settings).dbs[0]
    b = redis_trap.RedisSession(FakeConn(ctx, OTHER), settings).dbs[0]
    n = redis_trap.RedisSession(FakeConn(ctx, UNPLANTED), settings).dbs[0]
    assert a["config:aws:access_key_id"][1] == source_token(SEED, ip_key(LOOP))[0]
    assert b["config:aws:access_key_id"][1] == source_token(SEED, ip_key(OTHER))[0]
    assert a["config:aws:secret_access_key"] != b["config:aws:secret_access_key"]
    assert "config:aws:access_key_id" not in n and "session:9f1c" in n


def resp_cmd(*args: str) -> bytes:
    out = f"*{len(args)}\r\n"
    for a in args:
        out += f"${len(a.encode())}\r\n{a}\r\n"
    return out.encode()


async def test_redis_get_token_and_auth_with_it_is_attributed(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"127_0_0_1": {"plant_token": True},
                          "203_0_113_5": {"plant_token": True}})
    ctx = redis_ctx(str(state))
    settings = ServiceSettings(name="redis", enabled=True, port=0,
                               policy=LoginPolicy(accept="all"), accounts=[("ops", "pw")])
    ctx.settings["redis"] = settings
    objs = await redis_trap.start(ctx, settings)
    servers.extend(objs)
    r, w = await asyncio.open_connection(LOOP, objs[0].sockets[0].getsockname()[1])
    w.write(resp_cmd("AUTH", "ops", "pw") + resp_cmd("GET", "config:aws:access_key_id"))
    await w.drain()
    assert await r.readline() == b"+OK\r\n"
    await r.readline()
    assert (await r.readline()).decode().strip() == source_token(SEED, ip_key(LOOP))[0]
    _, other_secret = source_token(SEED, ip_key(OTHER))
    w.write(resp_cmd("AUTH", "default", other_secret))
    await w.drain()
    await r.readline()
    w.close()
    auths = events(ctx.writer, "auth_attempt")
    assert auths[-1]["data"]["honeytoken"] == source_token_name(ip_key(OTHER))


def http_ctx(state: Optional[str]) -> tuple[ListenerContext, ServiceSettings]:
    scen = LoadedScenario(scenario=Scenario.model_validate(HTTP_SCENARIO), seed="t")
    ctx = ListenerContext(EventWriter(None), scenario=scen, bind_host=LOOP, seed=SEED,
                          source_state_path=state)
    fast_view(ctx)
    settings = ServiceSettings(name="http", enabled=True, port=0,
                               policy=LoginPolicy(accept="listed"), accounts=[("u", "p")])
    ctx.settings["http"] = settings
    return ctx, settings


async def http_req(port: int, data: bytes) -> bytes:
    r, w = await asyncio.open_connection(LOOP, port)
    w.write(data)
    await w.drain()
    out = await asyncio.wait_for(r.read(), 5)
    w.close()
    return out


async def test_http_config_route_carries_token_and_reuse_is_attributed(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"127_0_0_1": {"plant_token": True},
                          "203_0_113_5": {"plant_token": True}})
    ctx, settings = http_ctx(str(state))
    objs = await http.start(ctx, settings)
    servers.extend(objs)
    port = objs[0].sockets[0].getsockname()[1]

    def get(path):
        return f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode()

    body = (await http_req(port, get("/api/v1/config"))).partition(b"\r\n\r\n")[2]
    obj = json.loads(body)
    assert obj["env"] == "prod"
    assert obj["aws_access_key_id"] == source_token(SEED, ip_key(LOOP))[0]
    # Only the first config/settings route is changed.
    body = (await http_req(port, get("/api/v1/settings"))).partition(b"\r\n\r\n")[2]
    assert json.loads(body) == {"theme": "dark"}

    key_id, secret = source_token(SEED, ip_key(OTHER))
    cred = base64.b64encode(f"{key_id}:{secret}".encode()).decode()
    await http_req(port, (f"GET /api/v1/status HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {cred}"
                          "\r\nConnection: close\r\n\r\n").encode())
    auths = events(ctx.writer, "auth_attempt")
    assert auths and auths[-1]["data"]["honeytoken"] == source_token_name(ip_key(OTHER))


async def test_http_unplanted_source_gets_plain_config(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"203_0_113_5": {"plant_token": True}})
    ctx, settings = http_ctx(str(state))
    objs = await http.start(ctx, settings)
    servers.extend(objs)
    port = objs[0].sockets[0].getsockname()[1]
    out = await http_req(port, b"GET /api/v1/config HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert json.loads(out.partition(b"\r\n\r\n")[2]) == {"env": "prod"}


async def test_http_lure_files_carry_the_marked_sources_own_pair(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"127_0_0_1": {"plant_token": True}})
    ctx, settings = http_ctx(str(state))
    objs = await http.start(ctx, settings)
    servers.extend(objs)
    port = objs[0].sockets[0].getsockname()[1]

    async def get(path):
        out = await http_req(port, f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close"
                                   "\r\n\r\n".encode())
        return int(out.split(b" ", 2)[1]), out.partition(b"\r\n\r\n")[2].decode()

    key_id, secret = source_token(SEED, ip_key(LOOP))
    status, body = await get("/.aws/credentials")
    assert status == 200 and body.startswith("[default]\n")
    assert f"aws_access_key_id = {key_id}" in body and f"aws_secret_access_key = {secret}" in body
    status, body = await get("/.env")
    assert status == 200 and f"AWS_SECRET_ACCESS_KEY={secret}" in body
    status, _ = await get("/.git/config")       # no scenario token: the 404
    assert status == 404
    await asyncio.sleep(0.05)
    lures = [e["data"] for e in events(ctx.writer, "command") if e["data"].get("lure")]
    assert [d["lure_tokens"] for d in lures] == ["source_token", "source_token"]


async def test_http_unmarked_source_gets_no_lure_files(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"203_0_113_5": {"plant_token": True}})
    ctx, settings = http_ctx(str(state))
    objs = await http.start(ctx, settings)
    servers.extend(objs)
    port = objs[0].sockets[0].getsockname()[1]
    for path in ("/.aws/credentials", "/.env"):
        out = await http_req(port, f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close"
                                   "\r\n\r\n".encode())
        assert out.startswith(b"HTTP/1.1 404 ")


# ---- capture_more --------------------------------------------------------------------------

async def _post_body(state: Optional[str], servers, body: bytes):
    ctx, settings = http_ctx(state)
    objs = await http.start(ctx, settings)
    servers.extend(objs)
    port = objs[0].sockets[0].getsockname()[1]
    await http_req(port, (f"POST /api/v1/status HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}"
                          "\r\nConnection: close\r\n\r\n").encode() + body)
    await asyncio.sleep(0.05)
    return ctx.writer


async def test_capture_more_logs_long_http_body_in_parts(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"127_0_0_1": {"capture_more": True}})
    body = b"".join(b"%05d-" % i for i in range(5000))          # 30 KB
    writer = await _post_body(str(state), servers, body)
    caps = captures(writer, "http_body")
    assert len(caps) == 1
    data = caps[0]["data"]
    parts = [k for k in data if k.startswith("part_")]
    assert len(parts) == CAPTURE_PARTS and len(data) <= 32
    assert all(len(data[k]) <= 512 for k in parts)
    joined = "".join(data[f"part_{i:02d}"] for i in range(len(parts)))
    assert body.decode().startswith(joined) and len(joined) == CAPTURE_PARTS * 512
    assert "truncated" in caps[0]["message"]

    short = b"user=a&pass=\x01b"
    writer = await _post_body(str(state), servers, short)
    data = captures(writer, "http_body")[0]["data"]
    assert data["part_00"] == "user=a&pass=\\x01b" and "part_01" not in data


async def test_capture_more_off_for_other_sources(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"203_0_113_5": {"capture_more": True}})
    writer = await _post_body(str(state), servers, b"x" * 4000)
    assert captures(writer) == []
    writer = await _post_body(None, servers, b"x" * 4000)
    assert captures(writer) == []


async def test_capture_more_ftp_command_lines(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"127_0_0_1": {"capture_more": True}})
    _, writer, port = await start_ftp(servers, tmp_path, str(state))
    c = await Ctl.open(port)
    long_arg = "A" * 1500
    await c.cmd(f"USER {long_arg}")
    c.close()
    await asyncio.sleep(0.1)
    caps = captures(writer, "ftp_command")
    assert caps and "".join(v for k, v in caps[0]["data"].items()
                            if k.startswith("part_")) == f"USER {long_arg}"


async def test_capture_more_smtp_body(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"127_0_0_1": {"capture_more": True}})
    writer = EventWriter(None)
    ctx = ListenerContext(writer, bind_host=LOOP, seed=SEED, source_state_path=str(state))
    fast_view(ctx)
    settings = ServiceSettings(name="smtp", enabled=True, port=0)
    ctx.settings["smtp"] = settings
    objs = await smtp.start(ctx, settings)
    servers.extend(objs)
    c = await Ctl.open(objs[0].sockets[0].getsockname()[1])
    await c.cmd("HELO x")
    await c.cmd("MAIL FROM:<a@example.test>")
    assert (await c.cmd("RCPT TO:<postmaster>")).startswith("250")
    await c.cmd("DATA")
    lines = "\r\n".join("line %04d " % i + "z" * 40 for i in range(100))
    reply = await c.cmd(f"Subject: hi\r\n\r\n{lines}\r\n.")
    assert reply.startswith("250"), reply
    c.close()
    await asyncio.sleep(0.05)
    caps = captures(writer, "smtp_body")
    assert caps and "line 0099" in "".join(caps[0]["data"].values())


async def _telnet_session(state: Optional[str], servers, lines: list[str]):
    """Log in to the canned telnet shell and send ``lines``; returns the event writer."""
    writer = EventWriter(None)
    ctx = ListenerContext(writer, bind_host=LOOP, seed=SEED, source_state_path=state)
    fast_view(ctx)
    settings = ServiceSettings(name="telnet", enabled=True, port=0,
                               policy=LoginPolicy(accept="all"))
    ctx.settings["telnet"] = settings
    objs = await telnet.start(ctx, settings)
    servers.extend(objs)
    r, w = await asyncio.open_connection(LOOP, objs[0].sockets[0].getsockname()[1])

    async def until(marker: bytes) -> bytes:
        buf = b""
        while marker not in buf:
            chunk = await asyncio.wait_for(r.read(4096), 10)
            if not chunk:
                break
            buf += chunk
        return buf

    await until(b"login: ")
    w.write(b"root\r\n")
    await until(b"Password: ")
    w.write(b"hunter2-secret\r\n")
    await until(b"# ")
    for line in lines:
        w.write(line.encode() + b"\r\n")
        await until(b"# " if line != "exit" else b"logout")
    w.close()
    await asyncio.sleep(0.05)
    return writer


async def test_capture_more_telnet_post_login_lines(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"127_0_0_1": {"capture_more": True}})
    long_line = "echo " + "B" * 700
    writer = await _telnet_session(str(state), servers, ["whoami", long_line, "exit"])
    caps = captures(writer, "telnet_input")
    joined = ["".join(v for k, v in sorted(c["data"].items()) if k.startswith("part_"))
              for c in caps]
    assert joined == ["whoami", long_line, "exit"]
    assert "part_01" in caps[1]["data"]
    assert all(c["username"] == "root" for c in caps)
    assert not any("hunter2-secret" in json.dumps(c) for c in captures(writer))


async def test_capture_more_telnet_off_for_normal_source(tmp_path, servers):
    state = tmp_path / "source_state.json"
    write_state(state, **{"203_0_113_5": {"capture_more": True}})
    writer = await _telnet_session(str(state), servers, ["whoami", "exit"])
    assert [e["data"]["input"] for e in events(writer, "command")
            if "input" in e["data"]] == ["whoami", "exit"]
    assert captures(writer) == []


# ---- expiry and reload -----------------------------------------------------------------------

def _iso(dt: datetime.datetime) -> str:
    return dt.isoformat(timespec="seconds")


def test_expired_entries_ignored_and_reload_without_restart(tmp_path):
    state = tmp_path / "source_state.json"
    now = datetime.datetime.now(datetime.timezone.utc)
    past = {"key": OTHER, "tarpit_ms": 300, "plant_token": True,
            "updated_at": _iso(now - datetime.timedelta(hours=3)),
            "expires_at": _iso(now - datetime.timedelta(hours=1))}
    plain_state(state, {OTHER: past})
    ctx = ListenerContext(EventWriter(None), seed=SEED, source_state_path=str(state))
    fast_view(ctx)
    assert ctx.source(OTHER) is None
    assert ctx.tarpit_seconds(OTHER) == 0.0
    key_id, _ = source_token(SEED, OTHER)
    # Behaviour stops at expiry, but a token that was planted stays recognised: reuse
    # after expiry still identifies who took it.
    assert ctx.honeytoken_in(key_id) == source_token_name(OTHER)

    live = dict(past, expires_at=_iso(now + datetime.timedelta(hours=1)))
    plain_state(state, {OTHER: live})
    os.utime(state, (time.time() + 5, time.time() + 5))     # mtime surely differs
    assert ctx.source(OTHER) is not None
    assert ctx.tarpit_seconds(OTHER) == 0.3
    assert ctx.honeytoken_in(f"aws {key_id}") == source_token_name(OTHER)


# ---- FTP upload signal -------------------------------------------------------------------------

async def test_ftp_upload_carries_signal(tmp_path, servers):
    _, writer, port = await start_ftp(servers, tmp_path, None)
    c = await Ctl.open(port)
    await c.cmd("USER a")
    await c.cmd("PASS b")
    dport = await c.pasv_port()
    dr, dw = await asyncio.open_connection(LOOP, dport)
    assert (await c.cmd("STOR drop.sh")).startswith("150")
    dw.write(b"#!/bin/sh\necho hi\n")
    await dw.drain()
    dw.close()
    assert (await c.line()).startswith("226")
    c.close()
    ups = [e["data"] for e in events(writer, "command") if e["message"] == "FTP upload"]
    assert len(ups) == 1
    assert ups[0]["high_signal"] is True and ups[0]["signal"] == "ftp_upload"
    assert len(ups[0]["sha256"]) == 64


# ---- shallow budget mode ---------------------------------------------------------------------

class CountingLLM:
    calls = 0

    def complete_json(self, system, user, schema):
        CountingLLM.calls += 1
        return {"status": 200, "content_type": "application/json", "body": "{}"}


async def test_shallow_source_gets_protocol_fallback(tmp_path):
    state = tmp_path / "source_state.json"
    write_state(state, **{"127_0_0_1": {"budget_mode": "shallow"}})
    budget = Budget()
    if not hasattr(budget, "mode_provider"):
        pytest.xfail("budget mode_provider pending")
    ctx = ListenerContext(EventWriter(None), seed=SEED, budget=budget, json_llm=CountingLLM(),
                          source_state_path=str(state))
    budget.mode_provider = lambda key: (e.budget_mode if (e := ctx.source_state.get(key))
                                        else "normal")
    CountingLLM.calls = 0
    out = await ctx.llm_json("http-s1", LOOP, "sys", "user", http.LlmHttpAnswer)
    assert out is None and CountingLLM.calls == 0
    out = await ctx.llm_json("http-s2", OTHER, "sys", "user", http.LlmHttpAnswer)
    assert out is not None and CountingLLM.calls == 1
