"""Loopback tests for the fake MySQL listener (raw protocol client)."""

import asyncio
import hashlib
import os

from agents.budget import Budget
from agents.llm import LLMOutputError
from listeners import mysql
from listeners.base import ListenerContext, ServiceSettings
from listeners.events import EventWriter
from listeners.sqlfake import LlmSqlAnswer
from scenarios.loader import LoadedScenario
from scenarios.schema import LoginPolicy, Scenario

POLICY = LoginPolicy(accept="after_n", after_n_min=2, after_n_max=2)

PROTOCOL_41 = 0x200
SECURE = 0x8000
PLUGIN_AUTH = 0x80000
CONNECT_WITH_DB = 0x8
CONNECT_ATTRS = 0x100000
LENENC = 0x200000
DEPRECATE_EOF = 0x1000000


def make_scenario() -> LoadedScenario:
    scn = Scenario.model_validate({
        "name": "t_pbx", "title": "Test PBX", "description": "test",
        "identity": {"org_name": "Bluebird Telecom", "hostname": "pbx01",
                     "domain": "bluebird.test", "internal_ips": ["10.30.0.7"],
                     "os_pretty_name": "Debian GNU/Linux 12", "kernel": "Linux pbx01 6.1.0-18-amd64"},
        "services": {"mysql": {
            "enabled": True, "port": 0,
            "databases": [{"name": "asteriskcdrdb", "tables": [{
                "name": "cdr",
                "columns": [{"name": "uniqueid", "type": "varchar"}, {"name": "src", "type": "varchar"},
                            {"name": "dst", "type": "varchar"}, {"name": "duration", "type": "int"}],
                "seed_rows": [["1700000001.1", "101", "+12025550123", 64],
                              ["1700000002.2", "102", "+13125550144", 12]]}]}]}},
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


async def start_server(json_llm=None):
    ctx = ListenerContext(EventWriter(None), scenario=make_scenario(), bind_host="127.0.0.1",
                          budget=Budget() if json_llm else None, json_llm=json_llm)
    settings = ServiceSettings(name="mysql", enabled=True, port=0, policy=POLICY)
    ctx.settings["mysql"] = settings
    servers = await mysql.start(ctx, settings)
    return ctx, servers, servers[0].sockets[0].getsockname()[1]


async def stop(servers):
    for s in servers:
        s.close()
        await s.wait_closed()


def lenenc(b: bytes) -> bytes:
    assert len(b) < 251
    return bytes([len(b)]) + b


def native(pw: str, salt: bytes) -> bytes:
    h1 = hashlib.sha1(pw.encode()).digest()
    h3 = hashlib.sha1(salt + hashlib.sha1(h1).digest()).digest()
    return bytes(a ^ b for a, b in zip(h1, h3, strict=True))


def sha2(pw: str, salt: bytes) -> bytes:
    h1 = hashlib.sha256(pw.encode()).digest()
    h3 = hashlib.sha256(hashlib.sha256(h1).digest() + salt).digest()
    return bytes(a ^ b for a, b in zip(h1, h3, strict=True))


class Client:
    def __init__(self, r, w, flags):
        self.r, self.w, self.flags = r, w, flags

    async def packet(self):
        head = await asyncio.wait_for(self.r.readexactly(4), 5)
        n = int.from_bytes(head[:3], "little")
        return head[3], await self.r.readexactly(n)

    def send(self, seq, payload):
        self.w.write(len(payload).to_bytes(3, "little") + bytes([seq]) + payload)

    async def query(self, sql: str):
        self.send(0, b"\x03" + sql.encode())
        _, first = await self.packet()
        if first[0] in (0x00, 0xFF):
            return first, [], []
        ncols = first[0]
        cols = []
        for _ in range(ncols):
            _, cdef = await self.packet()
            pos = 0
            vals = []
            for _ in range(6):
                ln = cdef[pos]
                vals.append(cdef[pos + 1:pos + 1 + ln].decode())
                pos += 1 + ln
            cols.append(vals[4])
        if not self.flags & DEPRECATE_EOF:
            _, eof = await self.packet()
            assert eof[0] == 0xFE
        rows = []
        while True:
            _, p = await self.packet()
            if p[0] == 0xFE and len(p) < 9:
                return p, cols, rows
            pos, row = 0, []
            while pos < len(p):
                if p[pos] == 0xFB:
                    row.append(None)
                    pos += 1
                    continue
                ln = p[pos]
                assert ln < 251
                row.append(p[pos + 1:pos + 1 + ln].decode())
                pos += 1 + ln
            rows.append(row)


async def connect(port, user, password, db="", plugin="mysql_native_password",
                  flags=PROTOCOL_41 | SECURE | PLUGIN_AUTH | CONNECT_ATTRS | LENENC | DEPRECATE_EOF):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    c = Client(r, w, flags)
    _, hs = await c.packet()
    assert hs[0] == 0x0A
    vend = hs.index(b"\x00", 1)
    version = hs[1:vend].decode()
    pos = vend + 1 + 4
    salt1 = hs[pos:pos + 8]
    pos += 8 + 1
    caps = int.from_bytes(hs[pos:pos + 2], "little")
    pos += 2 + 1 + 2
    caps |= int.from_bytes(hs[pos:pos + 2], "little") << 16
    pos += 2 + 1 + 10
    salt = salt1 + hs[pos:pos + 12]
    assert not caps & 0x800, "CLIENT_SSL must not be offered"
    if db:
        flags |= CONNECT_WITH_DB
    c.flags = flags
    auth = (sha2 if plugin == "caching_sha2_password" else native)(password, salt) if password else b""
    attrs = lenenc(b"_client_name") + lenenc(b"libmysql") + lenenc(b"_client_version") + \
        lenenc(b"8.0.36") + lenenc(b"program_name") + lenenc(b"mysql")
    payload = (flags.to_bytes(4, "little") + (16777216).to_bytes(4, "little") + bytes([255])
               + b"\x00" * 23 + user.encode() + b"\x00" + lenenc(auth)
               + ((db.encode() + b"\x00") if db else b"") + plugin.encode() + b"\x00"
               + lenenc(attrs))
    c.send(1, payload)
    seq, resp = await c.packet()
    if resp[:2] == b"\x01\x03":
        seq, resp = await c.packet()
    return c, resp, version, salt


def events(ctx, event):
    return [e for e in ctx.writer.events if e["event"] == event]


async def test_after_n_password_recovered_then_session():
    ctx, servers, port = await start_server()
    try:
        c, resp, version, salt = await connect(port, "root", "123456")
        assert version == "8.0.36-0ubuntu0.22.04.1"
        assert resp[0] == 0xFF and int.from_bytes(resp[1:3], "little") == 1045
        assert b"Access denied for user 'root'@'127.0.0.1' (using password: YES)" in resp
        c.w.close()

        c, resp, _, _ = await connect(port, "root", "password", db="asteriskcdrdb")
        assert resp[0] == 0x00
        _, cols, rows = await c.query("SELECT @@version_comment LIMIT 1")
        assert cols == ["@@version_comment"] and rows == [["MySQL Community Server - GPL"]]   # host is Debian 12
        _, cols, rows = await c.query("SHOW DATABASES")
        assert cols == ["Database"] and ["asteriskcdrdb"] in rows and ["mysql"] in rows
        _, cols, rows = await c.query("SHOW TABLES")
        assert rows == [["cdr"]]
        _, cols, rows = await c.query("select * from cdr limit 1")
        assert cols == ["uniqueid", "src", "dst", "duration"]
        assert rows == [["1700000001.1", "101", "+12025550123", "64"]]
        _, cols, rows = await c.query("SELECT DATABASE(), USER()")
        assert rows == [["asteriskcdrdb", "root@127.0.0.1"]]
        first, _, _ = await c.query("UPDATE cdr SET dst='x' WHERE uniqueid='1'")
        assert first[0] == 0x00 and first[1] == 1
        err, _, _ = await c.query("SELECT * FROM cdr INTO OUTFILE '/var/www/html/s.php'")
        assert err[0] == 0xFF and int.from_bytes(err[1:3], "little") == 1290
        err, _, _ = await c.query("SELECT LOAD_FILE('/etc/passwd')")
        assert err[0] == 0xFF
        c.send(0, b"\x0e")
        _, pong = await c.packet()
        assert pong[0] == 0x00
        c.send(0, b"\x01")
        await c.w.drain()
        c.w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    attempts = events(ctx, "auth_attempt")
    assert [(a["username"], a["password"], a["success"]) for a in attempts] == [
        ("root", "123456", False), ("root", "password", True)]
    a = attempts[1]
    assert a["data"]["password_recovered"] is True and a["data"]["database"] == "asteriskcdrdb"
    assert len(a["data"]["salt"]) == 40 and len(a["data"]["auth_response"]) == 40
    assert a["client"] == "mysql libmysql 8.0.36"
    hs = [e for e in events(ctx, "command") if e["data"].get("high_signal")]
    assert [e["data"]["match"] for e in hs] == ["into_outfile", "load_file"]
    assert all(e["data"]["signal"] == "sql_exec_attempt" for e in hs)


async def test_caching_sha2_and_unrecovered_password():
    ctx, servers, port = await start_server()
    try:
        c, resp, _, _ = await connect(port, "admin", "Zq8!vT2#unguessable",
                                      plugin="caching_sha2_password")
        assert resp[0] == 0xFF
        c.w.close()
        c, resp, _, _ = await connect(port, "admin", "admin123", plugin="caching_sha2_password",
                                      flags=PROTOCOL_41 | SECURE | PLUGIN_AUTH | LENENC)
        assert resp[0] == 0x00
        _, cols, rows = await c.query("SELECT 1")
        assert rows == [["1"]]
        c.w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    attempts = events(ctx, "auth_attempt")
    assert attempts[0]["password"] == "<unrecovered>"
    assert attempts[0]["data"]["password_recovered"] is False
    assert attempts[1]["password"] == "admin123"
    assert attempts[1]["data"]["auth_plugin"] == "caching_sha2_password"


async def test_model_fallback_and_valid_answer():
    for llm, expect_rows in ((RaisingLLM(), False),
                             (FixedLLM({"columns": ["x"], "rows": [["y"]], "extra": 1}), False),
                             (FixedLLM(LlmSqlAnswer(columns=["calls"], rows=[[17]])), True)):
        ctx, servers, port = await start_server(json_llm=llm)
        try:
            await connect(port, "root", "1")
            c, resp, _, _ = await connect(port, "root", "2")
            assert resp[0] == 0x00
            first, cols, rows = await c.query("SELECT COUNT(DISTINCT src) AS calls FROM "
                                              "asteriskcdrdb.cdr GROUP BY dst HAVING 1")
            if expect_rows:
                assert cols == ["calls"] and rows == [["17"]]
            else:
                # the fail-safe: an empty result set with the select list's columns
                assert cols == ["calls"] and rows == []
            c.w.close()
            await asyncio.sleep(0.05)
        finally:
            await stop(servers)
        assert not events(ctx, "error")


async def test_malformed_and_oversized_input_closes_cleanly():
    ctx, servers, port = await start_server()
    try:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.wait_for(r.readexactly(4), 5)
        w.write(b"\xff\xff\xff\x01" + os.urandom(64))
        await asyncio.wait_for(r.read(), 5)
        w.close()
        r, w = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.wait_for(r.read(200), 5)
        w.write(b"\x10\x00\x00\x01" + b"\x00" * 16)  # short handshake response
        await asyncio.wait_for(r.read(), 5)
        w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    assert not [e for e in ctx.writer.events if e["message"] == "Handler error"]
    reasons = [e["data"].get("reason") for e in ctx.writer.events if e["event"] in ("error", "limit")]
    assert "packet_size" in reasons and "malformed" in reasons


async def handshake_reply(port, payload: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    head = await asyncio.wait_for(r.readexactly(4), 5)
    await r.readexactly(int.from_bytes(head[:3], "little"))
    w.write(len(payload).to_bytes(3, "little") + b"\x01" + payload)
    out = await asyncio.wait_for(r.read(), 5)
    w.close()
    return out


async def test_bad_lengths_in_handshake_get_bad_handshake_error():
    ctx, servers, port = await start_server()
    base = (PROTOCOL_41 | SECURE | PLUGIN_AUTH | LENENC | CONNECT_ATTRS).to_bytes(4, "little") \
        + (16777216).to_bytes(4, "little") + bytes([255]) + b"\x00" * 23 + b"root\x00"
    payloads = [
        b"\x00" * 16,                                              # short, no SSL flag
        base + b"\xfe" + b"\xff" * 8,                              # auth length 2^64-1
        base + b"\xfc\x00\x10" + b"x" * 10,                        # auth length past the end
        base + b"\x00" + b"mysql_native_password\x00" + b"\xfe" + b"\xff" * 8,  # attrs length
        base + b"\xff",                                            # invalid lenenc prefix
    ]
    try:
        for p in payloads:
            out = await handshake_reply(port, p)
            assert out[4] == 0xFF, out[:16]
            assert int.from_bytes(out[5:7], "little") == 1043
            assert out[7:13] == b"#08S01" and out[13:] == b"Bad handshake"
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    assert not [e for e in ctx.writer.events if e["message"] == "Handler error"]
    assert not events(ctx, "auth_attempt")
