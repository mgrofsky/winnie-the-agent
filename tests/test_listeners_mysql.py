"""Loopback tests for the fake MySQL listener (raw protocol client)."""

import asyncio
import hashlib
import os
import struct

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


# ---- prepared statements (binary protocol) ------------------------------------------------

T_TINY, T_LONG, T_DOUBLE, T_NULL, T_LONGLONG, T_DATETIME, T_BLOB, T_VAR_STRING = \
    0x01, 0x03, 0x05, 0x06, 0x08, 0x0C, 0xFC, 0xFD


def lenenc_bytes(b: bytes) -> bytes:
    if len(b) < 251:
        return bytes([len(b)]) + b
    return b"\xfc" + len(b).to_bytes(2, "little") + b


async def prepare(c, sql: str):
    """COM_STMT_PREPARE: (statement id, param count) or the ERR payload."""
    c.send(0, b"\x16" + sql.encode())
    _, first = await c.packet()
    if first[0] == 0xFF:
        return first, None
    assert first[0] == 0x00 and len(first) == 12
    stmt_id = int.from_bytes(first[1:5], "little")
    ncols = int.from_bytes(first[5:7], "little")
    nparams = int.from_bytes(first[7:9], "little")
    for _ in range(nparams):
        _, pdef = await c.packet()
        assert pdef[:4] == b"\x03def"
    if nparams and not c.flags & DEPRECATE_EOF:
        _, eof = await c.packet()
        assert eof[0] == 0xFE
    assert ncols == 0
    return stmt_id, nparams


def execute_packet(stmt_id: int, params: list, bind_types: bool = True) -> bytes:
    """COM_STMT_EXECUTE with (type, value) params; value None is NULL, bytes are lenenc."""
    out = b"\x17" + stmt_id.to_bytes(4, "little") + b"\x00" + (1).to_bytes(4, "little")
    if not params:
        return out
    bitmap = bytearray((len(params) + 7) // 8)
    values = b""
    for i, (t, v) in enumerate(params):
        if v is None:
            bitmap[i // 8] |= 1 << (i % 8)
        elif t == T_LONGLONG:
            values += v.to_bytes(8, "little", signed=True)
        elif t == T_LONG:
            values += v.to_bytes(4, "little", signed=True)
        elif t == T_DOUBLE:
            values += struct.pack("<d", v)
        elif t == T_DATETIME:
            values += bytes([7]) + v[0].to_bytes(2, "little") + bytes(v[1:])
        elif v == "LONG":
            pass
        else:
            values += lenenc_bytes(v)
    out += bytes(bitmap) + (b"\x01" + b"".join(bytes([t, 0]) for t, _ in params) if bind_types
                            else b"\x00")
    return out + values


async def binary_result(c):
    """Read a COM_STMT_EXECUTE reply: (first packet, columns [(name, type)], decoded rows)."""
    _, first = await c.packet()
    if first[0] in (0x00, 0xFF):
        return first, [], []
    cols = []
    for _ in range(first[0]):
        _, cdef = await c.packet()
        pos, vals = 0, []
        for _ in range(6):
            ln = cdef[pos]
            vals.append(cdef[pos + 1:pos + 1 + ln].decode())
            pos += 1 + ln
        ctype = cdef[pos + 1 + 2 + 4]
        flags = int.from_bytes(cdef[pos + 1 + 2 + 4 + 1:pos + 1 + 2 + 4 + 3], "little")
        assert not flags & 0x20, "signed columns must not carry UNSIGNED_FLAG"
        cols.append((vals[4], ctype))
    if not c.flags & DEPRECATE_EOF:
        _, eof = await c.packet()
        assert eof[0] == 0xFE
    rows = []
    while True:
        _, p = await c.packet()
        if p[0] == 0xFE and len(p) < 9:
            return p, cols, rows
        assert p[0] == 0x00
        nb = (len(cols) + 9) // 8
        bitmap, pos, row = p[1:1 + nb], 1 + nb, []
        for i, (_, ctype) in enumerate(cols):
            if bitmap[(i + 2) // 8] & (1 << ((i + 2) % 8)):
                row.append(None)
            elif ctype == T_LONGLONG:
                row.append(int.from_bytes(p[pos:pos + 8], "little", signed=True))
                pos += 8
            elif ctype == T_DOUBLE:
                row.append(struct.unpack("<d", p[pos:pos + 8])[0])
                pos += 8
            elif ctype == T_TINY:
                row.append(p[pos])
                pos += 1
            else:
                ln = p[pos]
                assert ln < 251
                row.append(p[pos + 1:pos + 1 + ln].decode())
                pos += 1 + ln
        assert pos == len(p)
        rows.append(row)


def sql_logs(ctx):
    return [e["data"]["statement"] for e in ctx.writer.events if e["message"] == "SQL statement"]


async def logged_in(port, flags=None):
    await connect(port, "root", "1")
    kw = {} if flags is None else {"flags": flags}
    c, resp, _, salt = await connect(port, "root", "2", db="asteriskcdrdb", **kw)
    assert resp[0] == 0x00
    return c, salt


async def test_prepared_statement_binds_parameters_and_returns_binary_rows():
    ctx, servers, port = await start_server()
    try:
        c, _ = await logged_in(port)
        stmt_id, nparams = await prepare(c, "SELECT src, duration FROM cdr WHERE uniqueid = ? "
                                         "/* ? */ AND src <> '?' -- ?\n")
        assert nparams == 1
        c.send(0, execute_packet(stmt_id, [(T_VAR_STRING, b"1700000001.1")]))
        end, cols, rows = await binary_result(c)
        assert cols == [("src", T_VAR_STRING), ("duration", T_LONGLONG)]
        assert rows == [["101", 64]]
        assert end[0] == 0xFE

        # Types bound once are reused when the next execute does not resend them.
        c.send(0, execute_packet(stmt_id, [(T_VAR_STRING, b"1700000002.2")], bind_types=False))
        _, _, rows = await binary_result(c)
        assert rows == [["102", 12]]

        stmt2, n2 = await prepare(c, "SELECT ? AS a, ? AS b, ? AS c, ? AS d, ? AS e")
        assert n2 == 5
        tricky = "a'b\\c;--#/*\x00?"
        c.send(0, execute_packet(stmt2, [(T_NULL, None), (T_LONGLONG, -7), (T_DOUBLE, 1.5),
                                         (T_DATETIME, (2024, 1, 2, 3, 4, 5)),
                                         (T_VAR_STRING, tricky.encode())]))
        _, cols, rows = await binary_result(c)
        assert [n for n, _ in cols] == ["a", "b", "c", "d", "e"]
        assert rows == [[None, -7, 1.5, "2024-01-02 03:04:05", "a'b\\c;--#/* ?"]]
        c.w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    logs = sql_logs(ctx)
    # Logged like COM_QUERY: one event per statement, comments stripped, parameters bound.
    assert logs == [
        "SELECT src, duration FROM cdr WHERE uniqueid = '1700000001.1'   AND src <> '?'",
        "SELECT src, duration FROM cdr WHERE uniqueid = '1700000002.2'   AND src <> '?'",
        # (the event writer escapes backslashes and control characters)
        r"SELECT NULL AS a, -7 AS b, 1.5 AS c, '2024-01-02 03:04:05' AS d, 'a''b\\c;--#/*\x00?' AS e"]
    prep = [e["data"] for e in events(ctx, "command") if e["message"] == "COM_STMT_PREPARE"]
    assert [(p["statement_id"], p["params"]) for p in prep] == [(1, 1), (2, 5)]


async def test_prepare_without_deprecate_eof_and_dangerous_bound_statement():
    ctx, servers, port = await start_server()
    try:
        c, _ = await logged_in(port, flags=PROTOCOL_41 | SECURE | PLUGIN_AUTH | LENENC)
        stmt_id, n = await prepare(c, "SELECT ? INTO OUTFILE ?")
        assert n == 2
        c.send(0, execute_packet(stmt_id, [(T_VAR_STRING, b"<?php system($_GET[c]); ?>"),
                                           (T_VAR_STRING, b"/var/www/html/s.php")]))
        err, _, _ = await binary_result(c)
        assert err[0] == 0xFF and int.from_bytes(err[1:3], "little") == 1290
        stmt_id, n = await prepare(c, "SELECT uniqueid FROM cdr WHERE duration > ?")
        c.send(0, execute_packet(stmt_id, [(T_LONG, 20)]))
        _, cols, rows = await binary_result(c)
        assert rows == [["1700000001.1"]]
        c.w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    hs = [e["data"] for e in events(ctx, "command") if e["data"].get("high_signal")]
    assert [d["match"] for d in hs] == ["into_outfile"]
    assert hs[0]["statement"] == "SELECT '<?php system($_GET[c]); ?>' INTO OUTFILE '/var/www/html/s.php'"


async def test_long_data_reset_close_and_statement_errors():
    ctx, servers, port = await start_server()
    try:
        c, _ = await logged_in(port)
        stmt_id, _ = await prepare(c, "SELECT ? AS v")
        for chunk in (b"hello ", b"world"):
            c.send(0, b"\x18" + stmt_id.to_bytes(4, "little") + b"\x00\x00" + chunk)  # no reply
        c.send(0, execute_packet(stmt_id, [(T_BLOB, "LONG")]))
        _, _, rows = await binary_result(c)
        assert rows == [["hello world"]]

        # Long data is consumed by the execute; RESET clears pending data and answers OK.
        c.send(0, b"\x18" + stmt_id.to_bytes(4, "little") + b"\x00\x00" + b"stale")
        c.send(0, b"\x1a" + stmt_id.to_bytes(4, "little"))
        _, ok = await c.packet()
        assert ok[0] == 0x00
        c.send(0, execute_packet(stmt_id, [(T_VAR_STRING, b"fresh")]))
        _, _, rows = await binary_result(c)
        assert rows == [["fresh"]]

        # Long data for a parameter the statement does not have fails the next execute.
        c.send(0, b"\x18" + stmt_id.to_bytes(4, "little") + b"\x05\x00" + b"x")
        c.send(0, execute_packet(stmt_id, [(T_VAR_STRING, b"y")]))
        err, _, _ = await binary_result(c)
        assert int.from_bytes(err[1:3], "little") == 1210
        assert err[9:] == b"Incorrect arguments to mysqld_stmt_send_long_data"

        # COM_STMT_CLOSE has no reply; the handle is gone afterwards.
        c.send(0, b"\x19" + stmt_id.to_bytes(4, "little"))
        c.send(0, execute_packet(stmt_id, []))
        err, _, _ = await binary_result(c)
        assert int.from_bytes(err[1:3], "little") == 1243
        assert err[9:] == f"Unknown prepared statement handler ({stmt_id}) given to " \
                          "mysqld_stmt_execute".encode()
        c.send(0, b"\x1a" + (999).to_bytes(4, "little"))
        _, err = await c.packet()
        assert err[9:] == b"Unknown prepared statement handler (999) given to mysqld_stmt_reset"

        # Parameters never typed, then a truncated execute: errors, and the session goes on.
        stmt_id, _ = await prepare(c, "SELECT ? + ?")
        c.send(0, execute_packet(stmt_id, [(T_LONG, 1), (T_LONG, 2)], bind_types=False))
        err, _, _ = await binary_result(c)
        assert err[9:] == b"Incorrect arguments to mysqld_stmt_execute"
        c.send(0, execute_packet(stmt_id, [(T_LONGLONG, 1), (T_LONGLONG, 2)])[:-5])
        err, _, _ = await binary_result(c)
        assert int.from_bytes(err[1:3], "little") == 1835
        assert err[9:] == b"Malformed communication packet."

        err, _ = await prepare(c, "SELECT 1; SELECT 2")
        assert int.from_bytes(err[1:3], "little") == 1064
        err, _ = await prepare(c, "  ")
        assert int.from_bytes(err[1:3], "little") == 1065
        c.send(0, b"\x0e")
        _, pong = await c.packet()
        assert pong[0] == 0x00
        c.w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    assert not [e for e in ctx.writer.events if e["message"] == "Handler error"]


async def test_prepared_statement_cap_and_reset_connection():
    ctx, servers, port = await start_server()
    try:
        c, _ = await logged_in(port)
        ids = []
        for _ in range(mysql.MAX_PREPARED):
            stmt_id, _ = await prepare(c, "SELECT 1")
            ids.append(stmt_id)
        assert ids == list(range(1, mysql.MAX_PREPARED + 1))
        err, _ = await prepare(c, "SELECT 1")
        assert int.from_bytes(err[1:3], "little") == 1461 and err[3:9] == b"#42000"
        c.send(0, b"\x1f")
        _, ok = await c.packet()
        assert ok[0] == 0x00
        c.send(0, execute_packet(ids[0], []))
        err, _, _ = await binary_result(c)
        assert int.from_bytes(err[1:3], "little") == 1243
        stmt_id, _ = await prepare(c, "SELECT 1")
        c.send(0, execute_packet(stmt_id, []))
        _, cols, rows = await binary_result(c)
        assert rows == [[1]]
        c.w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    assert any(e["data"].get("reason") == "max_prepared" for e in events(ctx, "limit"))


async def test_set_option_turns_on_multi_statements():
    ctx, servers, port = await start_server()
    try:
        c, _ = await logged_in(port)
        first, _, _ = await c.query("SELECT 1; SELECT 2")
        assert first[0] == 0xFF and int.from_bytes(first[1:3], "little") == 1064
        c.send(0, b"\x1b\x00\x00")
        _, ack = await c.packet()
        assert ack[0] == 0xFE
        end, _, rows = await c.query("SELECT 1; SELECT 2")
        assert rows == [["1"]] and int.from_bytes(end[3:5], "little") & 0x0008
        _, count = await c.packet()          # the second result set follows unasked
        assert count == b"\x01"
        await c.packet()                     # column definition
        _, row = await c.packet()
        assert row == b"\x012"
        _, end = await c.packet()
        assert end[0] == 0xFE and not int.from_bytes(end[3:5], "little") & 0x0008
        c.send(0, b"\x1b\x07\x00")
        _, err = await c.packet()
        assert int.from_bytes(err[1:3], "little") == 1047
        c.send(0, b"\x1b\x01\x00")
        await c.packet()
        first, _, _ = await c.query("SELECT 1; SELECT 2")
        assert first[0] == 0xFF
        c.w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)


def change_user_packet(user: str, auth: bytes, db: str = "",
                       plugin: str = "mysql_native_password") -> bytes:
    return (b"\x11" + user.encode() + b"\x00" + lenenc(auth) + db.encode() + b"\x00"
            + (255).to_bytes(2, "little") + plugin.encode() + b"\x00")


async def test_change_user_follows_the_login_policy():
    ctx, servers, port = await start_server()
    try:
        c, salt = await logged_in(port)
        stmt_id, _ = await prepare(c, "SELECT 1")
        # The pair the policy accepted logs in again; the session drops its statements.
        c.send(0, change_user_packet("root", native("2", salt)))
        seq, ok = await c.packet()
        assert seq == 1 and ok[0] == 0x00
        _, _, rows = await c.query("SELECT DATABASE(), USER()")
        assert rows == [[None, "root@127.0.0.1"]]
        c.send(0, execute_packet(stmt_id, []))
        err, _, _ = await binary_result(c)
        assert int.from_bytes(err[1:3], "little") == 1243
        # Any other user is refused, and the server closes the connection.
        c.send(0, change_user_packet("admin", native("2", salt), db="asteriskcdrdb"))
        _, resp = await c.packet()
        assert resp == b"\xff" + (1045).to_bytes(2, "little") + b"#28000" + \
            b"Access denied for user 'admin'@'127.0.0.1' (using password: YES)"
        assert await asyncio.wait_for(c.r.read(), 5) == b""
        c.w.close()

        c, salt = await logged_in(port)
        c.send(0, change_user_packet("root", sha2("2", salt), db="asteriskcdrdb",
                                     plugin="caching_sha2_password"))
        _, fast = await c.packet()
        _, ok = await c.packet()
        assert fast == b"\x01\x03" and ok[0] == 0x00
        _, _, rows = await c.query("SELECT DATABASE()")
        assert rows == [["asteriskcdrdb"]]
        c.send(0, b"\x11root")                                      # malformed
        _, err = await c.packet()
        assert int.from_bytes(err[1:3], "little") == 1047
        c.w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    attempts = [(a["username"], a["password"], a["success"], a["data"].get("command"))
                for a in events(ctx, "auth_attempt")]
    # "1" and "2" are not in the candidate list, so the accepted pair is root/<unrecovered>.
    u = "<unrecovered>"
    assert attempts == [("root", u, False, None), ("root", u, True, None),
                        ("root", u, True, "change_user"), ("admin", u, False, "change_user"),
                        ("root", u, True, None), ("root", u, True, None),
                        ("root", u, True, "change_user")]


def test_long_data_caps_per_statement_and_per_connection():
    emitted = []

    class StubConn:
        def emit(self, event, message, **kw):
            emitted.append((event, kw.get("data", {}).get("reason")))

    sess = mysql.Session(None, 0, b"", None)
    for i in range(1, 10):
        sess.stmts[i] = mysql.Prepared("SELECT ?", mysql.array("I", [7]))
    chunk = b"A" * (mysql.MAX_LONG_DATA + 100)
    for i in range(1, 10):
        mysql.stmt_long_data(StubConn(), sess, b"\x18" + i.to_bytes(4, "little") + b"\x00\x00" + chunk)
    kept = [len(sess.stmts[i].long_data.get(0, b"")) for i in range(1, 10)]
    assert kept == [mysql.MAX_LONG_DATA] * 8 + [0]
    assert sess.long_total == mysql.MAX_LONG_DATA_TOTAL
    assert emitted.count(("limit", "long_data")) == 9
    sess.drop(1)
    assert sess.long_total == mysql.MAX_LONG_DATA_TOTAL - mysql.MAX_LONG_DATA
    sess.clear_long_data(sess.stmts[2])
    assert sess.long_total == mysql.MAX_LONG_DATA_TOTAL - 2 * mysql.MAX_LONG_DATA


def test_placeholder_scan_follows_server_lexing():
    sql = "SELECT ?, '?', \"?\", `?`, 'it\\'s ?', 'a''?' -- ?\n # ?\n /* ? */ /*!50000 ? */ ?--?"
    marks = mysql.placeholders(sql)
    assert [sql[m] for m in marks] == ["?"] * 4
    assert len(mysql.placeholders("SELECT '" + "?" * 100)) == 0           # unterminated quote
    assert len(mysql.placeholders("?" * 70_000)) == mysql.MAX_PARAMS + 1   # scan stops at the cap
