"""Loopback tests for the fake MSSQL (TDS) listener with a minimal raw TDS client."""

import asyncio
import os
import struct

import pytest

from agents.budget import Budget
from agents.llm import LLMOutputError
from listeners import mssql
from listeners.base import ListenerContext, ServiceSettings
from listeners.events import EventWriter
from scenarios.loader import LoadedScenario
from scenarios.schema import LoginPolicy, Scenario

POLICY = LoginPolicy(accept="after_n", after_n_min=2, after_n_max=2)


def make_scenario() -> LoadedScenario:
    scn = Scenario.model_validate({
        "name": "t_bank", "title": "Test bank", "description": "test",
        "identity": {"org_name": "Harborline Savings", "hostname": "coredb01",
                     "domain": "harborline.test", "internal_ips": ["10.40.0.9"],
                     "os_pretty_name": "Ubuntu 20.04.6 LTS", "kernel": "Linux coredb01 5.4.0-170-generic"},
        "services": {"mssql": {
            "enabled": True, "port": 0,
            "databases": [{"name": "CoreBanking", "tables": [{
                "name": "accounts",
                "columns": [{"name": "account_id", "type": "int"},
                            {"name": "holder", "type": "varchar"}],
                "seed_rows": [[1001, "Morgan Pemberton"], [1002, "Casey Whitlock"]]}]}]}},
    })
    return LoadedScenario(scenario=scn, seed="t")


class RaisingLLM:
    def complete_json(self, system, user, schema):
        raise LLMOutputError("bad output")


async def start_server(json_llm=None):
    ctx = ListenerContext(EventWriter(None), scenario=make_scenario(), bind_host="127.0.0.1",
                          budget=Budget() if json_llm else None, json_llm=json_llm)
    settings = ServiceSettings(name="mssql", enabled=True, port=0, policy=POLICY)
    ctx.settings["mssql"] = settings
    servers = await mssql.start(ctx, settings)
    return ctx, servers, servers[0].sockets[0].getsockname()[1]


async def stop(servers):
    for s in servers:
        s.close()
        await s.wait_closed()


def tds_packet(ptype: int, payload: bytes) -> bytes:
    return bytes([ptype, 0x01]) + (len(payload) + 8).to_bytes(2, "big") + b"\x00\x00\x01\x00" + payload


def prelogin(encryption: int) -> bytes:
    opts = [(0x00, bytes([16, 0, 0x10, 0x00, 0, 0])), (0x01, bytes([encryption])),
            (0x02, b"\x00"), (0x03, (1234).to_bytes(4, "big"))]
    hlen = len(opts) * 5 + 1
    head, data = b"", b""
    for tok, val in opts:
        head += bytes([tok]) + (hlen + len(data)).to_bytes(2, "big") + len(val).to_bytes(2, "big")
        data += val
    return tds_packet(0x12, head + b"\xff" + data)


def login7(user: str, password: str, db: str = "", app: str = "sqlmap/1.8",
           host: str = "KALI", server: str = "coredb01", lib: str = "ODBC") -> bytes:
    values = [host, user, password, app, server, "", lib, "us_english", db]
    header_len = 94
    table, data = b"", b""
    for i, v in enumerate(values):
        raw = v.encode("utf-16-le")
        if i == 2:
            raw = mssql.obfuscate(raw)
        table += (header_len + len(data)).to_bytes(2, "little") + len(v).to_bytes(2, "little")
        data += raw
    tail = (header_len + len(data)).to_bytes(2, "little") + b"\x00\x00"
    table += b"\x00" * 6 + tail * 3 + b"\x00\x00\x00\x00"
    fixed_rest = ((0x74000004).to_bytes(4, "little") + (4096).to_bytes(4, "little")
                  + (7).to_bytes(4, "little") + (4242).to_bytes(4, "little") + b"\x00" * 4
                  + bytes([0xE0, 0x03, 0x00, 0x00]) + b"\x00" * 4 + (0x409).to_bytes(4, "little"))
    body = fixed_rest + table + data
    payload = (len(body) + 4).to_bytes(4, "little") + body
    assert len(payload) - len(data) == header_len
    return tds_packet(0x10, payload)


def sql_batch(text: str) -> bytes:
    all_headers = (22).to_bytes(4, "little") + (18).to_bytes(4, "little") + (2).to_bytes(2, "little") \
        + b"\x00" * 8 + (1).to_bytes(4, "little")
    return tds_packet(0x01, all_headers + text.encode("utf-16-le"))


async def read_reply(r) -> bytes:
    out = b""
    while True:
        head = await asyncio.wait_for(r.readexactly(8), 5)
        n = int.from_bytes(head[2:4], "big")
        out += await r.readexactly(n - 8)
        if head[1] & 0x01:
            return out


def parse_tokens(p: bytes) -> list:
    toks, pos, ncols = [], 0, 0
    while pos < len(p):
        t = p[pos]
        pos += 1
        if t in (0xAA, 0xAB, 0xAD, 0xE3):
            ln = int.from_bytes(p[pos:pos + 2], "little")
            body = p[pos + 2:pos + 2 + ln]
            pos += 2 + ln
            if t in (0xAA, 0xAB):
                mlen = int.from_bytes(body[6:8], "little")
                toks.append((t, int.from_bytes(body[:4], "little"),
                             body[8:8 + 2 * mlen].decode("utf-16-le")))
            else:
                toks.append((t, body))
        elif t in (0xFD, 0xFE, 0xFF):
            toks.append(({0xFD: "done", 0xFE: "doneproc", 0xFF: "doneinproc"}[t],
                         int.from_bytes(p[pos:pos + 2], "little"),
                         int.from_bytes(p[pos + 4:pos + 12], "little")))
            pos += 12
        elif t == 0x79:
            toks.append(("status", int.from_bytes(p[pos:pos + 4], "little", signed=True)))
            pos += 4
        elif t == 0xAC:
            ordinal = int.from_bytes(p[pos:pos + 2], "little")
            nlen = p[pos + 2]
            name = p[pos + 3:pos + 3 + 2 * nlen].decode("utf-16-le")
            pos += 3 + 2 * nlen
            assert p[pos] == 0x01                        # output parameter
            pos += 1 + 4 + 2                             # status, user type, flags
            assert p[pos:pos + 3] == b"\x26\x04\x04"
            toks.append(("retval", ordinal, name,
                         int.from_bytes(p[pos + 3:pos + 7], "little", signed=True)))
            pos += 7
        elif t == 0x81:
            ncols = int.from_bytes(p[pos:pos + 2], "little")
            pos += 2
            names = []
            for _ in range(ncols):
                pos += 4 + 2
                assert p[pos] == 0xE7
                pos += 1 + 2 + 5
                ln = p[pos]
                names.append(p[pos + 1:pos + 1 + 2 * ln].decode("utf-16-le"))
                pos += 1 + 2 * ln
            toks.append(("cols", names))
        elif t == 0xD1:
            row = []
            for _ in range(ncols):
                ln = int.from_bytes(p[pos:pos + 2], "little")
                pos += 2
                if ln == 0xFFFF:
                    row.append(None)
                else:
                    row.append(p[pos:pos + ln].decode("utf-16-le"))
                    pos += ln
            toks.append(("row", row))
        else:
            raise AssertionError(f"unexpected token {t:#x}")
    return toks


async def login(port, user, password, db=""):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(prelogin(0))
    reply = await read_reply(r)
    opts = mssql.parse_prelogin(reply)
    assert opts[0x01] == bytes([mssql.ENCRYPT_NOT_SUP])
    w.write(login7(user, password, db=db))
    return r, w, parse_tokens(await read_reply(r))


async def batch(r, w, text):
    w.write(sql_batch(text))
    return parse_tokens(await read_reply(r))


def events(ctx, event):
    return [e for e in ctx.writer.events if e["event"] == event]


def test_password_obfuscation_roundtrip():
    raw = "S3cr3t!Pässword".encode("utf-16-le")
    assert mssql.deobfuscate(mssql.obfuscate(raw)) == raw
    # Known vector from MS-TDS: 'a' (0x61 0x00) obfuscates to 0xB3 0xA5.
    assert mssql.obfuscate(b"a\x00") == b"\xb3\xa5"


async def test_after_n_then_session():
    ctx, servers, port = await start_server()
    try:
        r, w, toks = await login(port, "sa", "Password123")
        assert toks[0][0] == 0xAA and toks[0][1] == 18456
        assert toks[0][2] == "Login failed for user 'sa'."
        assert toks[-1][0] == "done" and toks[-1][1] & 0x0002
        w.close()

        r, w, toks = await login(port, "sa", "Spring2026!", db="CoreBanking")
        kinds = [t[0] for t in toks]
        assert 0xAD in kinds and 0xAA not in kinds and kinds[-1] == "done"
        ack = next(t[1] for t in toks if t[0] == 0xAD)
        assert ack[1:5] == bytes([0x74, 0, 0, 4]) and "Microsoft SQL Server".encode("utf-16-le") in ack

        toks = await batch(r, w, "SELECT @@VERSION")
        rows = [t[1] for t in toks if t[0] == "row"]
        assert rows[0][0].startswith("Microsoft SQL Server 2019")
        toks = await batch(r, w, "SELECT name FROM sys.databases")
        names = [t[1][0] for t in toks if t[0] == "row"]
        assert "master" in names and "CoreBanking" in names
        assert ("cols", ["name"]) in toks
        toks = await batch(r, w, "SELECT TOP 1 * FROM accounts")
        assert ("row", ["1001", "Morgan Pemberton"]) in toks
        toks = await batch(r, w, "EXEC master..xp_cmdshell 'whoami'")
        assert toks[0][0] == 0xAA and toks[0][1] == 229
        toks = await batch(r, w, "EXEC sp_configure 'show advanced options', 1; RECONFIGURE")
        assert toks[0][1] == 15247
        w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    attempts = events(ctx, "auth_attempt")
    assert [(a["username"], a["password"], a["success"]) for a in attempts] == [
        ("sa", "Password123", False), ("sa", "Spring2026!", True)]
    d = attempts[1]["data"]
    assert d["hostname"] == "KALI" and d["app_name"] == "sqlmap/1.8"
    assert d["client_interface"] == "ODBC" and d["database"] == "CoreBanking"
    assert d["server_name"] == "coredb01"
    hs = [e for e in events(ctx, "command") if e["data"].get("high_signal")]
    assert [e["data"]["match"] for e in hs] == ["xp_cmdshell", "sp_configure"]
    assert all(e["data"]["signal"] == "sql_exec_attempt" for e in hs)


async def test_unknown_query_with_failing_model_gets_the_fail_safe():
    ctx, servers, port = await start_server(json_llm=RaisingLLM())
    try:
        await login(port, "sa", "a")
        r, w, toks = await login(port, "sa", "b")
        toks = await batch(r, w, "SELECT * FROM accounts")
        assert toks[0] == (0xAA, 208, "Invalid object name 'accounts'.")  # master is current
        toks = await batch(r, w, "USE CoreBanking")
        assert toks[0][0] == 0xE3
        # A plausible read the model cannot answer: an empty result set, not an error.
        toks = await batch(r, w, "SELECT HASHBYTES('SHA1', holder) FROM accounts")
        assert toks[0] == ("cols", [""]) and not any(t[0] == "row" for t in toks)
        assert toks[-1][0] == "done" and not toks[-1][1] & 0x0002
        toks = await batch(r, w, "frobnicate accounts")
        assert toks[0][0] == 0xAA and toks[0][1] == 102
        assert toks[-1][0] == "done" and toks[-1][1] & 0x0002
        w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)


async def test_encryption_required_is_logged_and_closed():
    ctx, servers, port = await start_server()
    try:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(prelogin(1))
        reply = await read_reply(r)
        assert mssql.parse_prelogin(reply)[0x01] == bytes([mssql.ENCRYPT_NOT_SUP])
        assert await asyncio.wait_for(r.read(), 5) == b""
        w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    assert any(e["data"].get("request") == "tls_required" for e in events(ctx, "command"))
    assert not events(ctx, "auth_attempt")


async def test_malformed_input_closes_cleanly():
    ctx, servers, port = await start_server()
    try:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(prelogin(0))
        await read_reply(r)
        bad = bytearray(login7("sa", "x"))
        bad[8 + 40:8 + 42] = (60000).to_bytes(2, "little")  # username offset out of bounds
        w.write(bytes(bad))
        assert await asyncio.wait_for(r.read(), 5) == b""
        w.close()
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"\x12\x01\xff\xff\x00\x00\x01\x00" + os.urandom(100))
        assert await asyncio.wait_for(r.read(), 5) == b""
        w.close()
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"\x16\x03\x01\x02\x00\x01\x00\x01" + os.urandom(64))  # raw TLS ClientHello
        assert await asyncio.wait_for(r.read(), 5) == b""
        w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    assert not [e for e in ctx.writer.events if e["message"] == "Handler error"]
    reasons = [e["data"].get("reason") for e in ctx.writer.events if e["event"] in ("error", "limit")]
    assert "malformed" in reasons and "packet_size" in reasons


@pytest.mark.parametrize("text", ["plain", "café", "\U0001F600", "a\U0001F600b\U00010348",
                                  "\ud800lone", ""])
def test_varchar_lengths_count_utf16_units(text):
    raw = text.encode("utf-16-le", "replace")
    assert mssql.b_varchar(text) == bytes([len(raw) // 2]) + raw
    assert mssql.us_varchar(text) == (len(raw) // 2).to_bytes(2, "little") + raw


def test_varchar_truncation_keeps_surrogate_pairs_whole():
    s = "x" + "\U0001F600" * 200
    out = mssql.b_varchar(s)
    units = out[0]
    body = out[1:]
    assert len(body) == 2 * units and units <= 255
    assert body.decode("utf-16-le") == "x" + "\U0001F600" * 127
    out = mssql.us_varchar("\U0001F600" * 3000)
    units = int.from_bytes(out[:2], "little")
    assert units == 4000 and len(out) - 2 == 8000
    out = mssql.us_varchar("y" + "\U0001F600" * 3000)
    units = int.from_bytes(out[:2], "little")
    assert units == 3999 and out[2:].decode("utf-16-le") == "y" + "\U0001F600" * 1999


def test_row_values_fit_nvarchar_4000():
    tok = mssql.row_token(["\U0001F600" * 3000])
    n = int.from_bytes(tok[1:3], "little")
    assert n <= 8000 and len(tok) == 3 + n
    assert set(tok[3:].decode("utf-16-le")) == {"\U0001F600"}


def test_prelogin_reply_parses_positionally_like_common_clients():
    from listeners.mssql import ENCRYPT_NOT_SUP, prelogin_reply

    reply = prelogin_reply("15.0.4322")
    # Positional reading used by widely deployed clients: four 5-byte option headers and the
    # terminator, then VERSION (6 bytes) immediately followed by the ENCRYPTION byte.
    assert [reply[i] for i in (0, 5, 10, 15)] == [0x00, 0x01, 0x02, 0x03] and reply[20] == 0xFF
    assert reply[21 + 6] == ENCRYPT_NOT_SUP


# ---- RPC ----------------------------------------------------------------------------------

ALL_HEADERS = (22).to_bytes(4, "little") + (18).to_bytes(4, "little") + (2).to_bytes(2, "little") \
    + b"\x00" * 8 + (1).to_bytes(4, "little")
COLL = bytes([0x09, 0x04, 0xD0, 0x00, 0x34])


def bname(name: str) -> bytes:
    return bytes([len(name)]) + name.encode("utf-16-le")


def p_nvarchar(value, name: str = "", plp: bool = False) -> bytes:
    if value is None:
        return bname(name) + b"\x00\xe7" + (8000).to_bytes(2, "little") + COLL + b"\xff\xff"
    raw = value.encode("utf-16-le")
    if plp:
        chunks = b"".join(len(c).to_bytes(4, "little") + c for c in (raw[:6], raw[6:]) if c)
        return (bname(name) + b"\x00\xe7\xff\xff" + COLL + len(raw).to_bytes(8, "little")
                + chunks + b"\x00\x00\x00\x00")
    return bname(name) + b"\x00\xe7" + (8000).to_bytes(2, "little") + COLL \
        + len(raw).to_bytes(2, "little") + raw


def p_varchar(value: str, name: str = "") -> bytes:
    raw = value.encode("cp1252")
    return bname(name) + b"\x00\xa7" + (8000).to_bytes(2, "little") + COLL \
        + len(raw).to_bytes(2, "little") + raw


def p_int(value, name: str = "", status: int = 0) -> bytes:
    if value is None:
        return bname(name) + bytes([status]) + b"\x26\x04\x00"
    return bname(name) + bytes([status]) + b"\x26\x04\x04" + value.to_bytes(4, "little", signed=True)


def rpc_packet(proc, params: list[bytes]) -> bytes:
    if isinstance(proc, int):
        head = b"\xff\xff" + proc.to_bytes(2, "little")
    else:
        head = len(proc).to_bytes(2, "little") + proc.encode("utf-16-le")
    return tds_packet(0x03, ALL_HEADERS + head + b"\x00\x00" + b"".join(params))


async def rpc_call(r, w, proc, params):
    w.write(rpc_packet(proc, params))
    return parse_tokens(await read_reply(r))


def statements(ctx):
    return [e["data"]["statement"] for e in ctx.writer.events if e["message"] == "SQL statement"]


async def logged_in():
    ctx, servers, port = await start_server()
    await login(port, "sa", "a")
    r, w, _ = await login(port, "sa", "b", db="CoreBanking")
    return ctx, servers, r, w


async def test_sp_executesql_binds_parameters_and_ends_with_doneproc():
    ctx, servers, r, w = await logged_in()
    try:
        toks = await rpc_call(r, w, 10, [
            p_nvarchar("SELECT holder FROM accounts WHERE account_id = @P0 AND holder <> '@P0'"),
            p_nvarchar("@P0 int"), p_int(1001)])
        assert toks == [("cols", ["holder"]), ("row", ["Morgan Pemberton"]),
                        ("doneinproc", 0x0011, 1), ("status", 0), ("doneproc", 0, 0)]
        tricky = "x'; DROP TABLE accounts; --"
        toks = await rpc_call(r, w, "sys.sp_executesql", [
            p_nvarchar("SELECT @name AS v, @@SPID AS s", "@stmt", plp=True),
            p_nvarchar("@NAME nvarchar(100)", "@params"), p_nvarchar(tricky, "@NAME")])
        assert toks[0] == ("cols", ["v", "s"]) and toks[1][1][0] == tricky
        toks = await rpc_call(r, w, 10, [p_nvarchar("SELECT @a AS a, @b AS b"),
                                         p_nvarchar("@a int, @b nvarchar(10)"),
                                         p_int(None), p_nvarchar(None)])
        assert toks[1] == ("row", [None, None])
        w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    assert statements(ctx) == [
        "SELECT holder FROM accounts WHERE account_id = 1001 AND holder <> '@P0'",
        "SELECT N'x''; DROP TABLE accounts; --' AS v, @@SPID AS s",
        "SELECT NULL AS a, NULL AS b"]
    rpcs = [e["data"] for e in events(ctx, "command") if e["message"] == "RPC request"]
    assert [d["procedure"] for d in rpcs] == ["sp_executesql", "sys.sp_executesql", "sp_executesql"]
    # The activity view shows ``text`` as what the client sent.
    assert rpcs[0]["text"] == ("EXEC sp_executesql N'SELECT holder FROM accounts WHERE "
                               "account_id = @P0 AND holder <> ''@P0''', N'@P0 int', 1001")


async def test_prepare_execute_unprepare_and_prepexec():
    ctx, servers, r, w = await logged_in()
    try:
        toks = await rpc_call(r, w, 11, [p_int(None, "@handle", status=1),
                                         p_nvarchar("@P0 int"),
                                         p_nvarchar("SELECT holder FROM accounts WHERE account_id = @P0"),
                                         p_int(1)])
        assert toks == [("status", 0), ("retval", 0, "@handle", 1), ("doneproc", 0, 0)]
        toks = await rpc_call(r, w, 12, [p_int(1), p_int(1002)])
        assert ("row", ["Casey Whitlock"]) in toks and toks[-1] == ("doneproc", 0, 0)
        toks = await rpc_call(r, w, 15, [p_int(1)])
        assert toks == [("status", 0), ("doneproc", 0, 0)]
        toks = await rpc_call(r, w, 12, [p_int(1), p_int(1002)])
        assert toks == [(0xAA, 8179, "Could not find prepared statement with handle 1."),
                        ("doneproc", 0x0002, 0)]
        toks = await rpc_call(r, w, 13, [p_int(None, "", status=1), p_nvarchar("@P0 int"),
                                         p_nvarchar("SELECT holder FROM accounts WHERE account_id = @P0"),
                                         p_int(1001)])
        assert toks == [("cols", ["holder"]), ("row", ["Morgan Pemberton"]),
                        ("doneinproc", 0x0011, 1), ("status", 0), ("retval", 0, "", 2),
                        ("doneproc", 0, 0)]
        w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    assert statements(ctx) == ["SELECT holder FROM accounts WHERE account_id = 1002",
                               "SELECT holder FROM accounts WHERE account_id = 1001"]


async def test_rpc_argument_errors_and_other_procedures():
    ctx, servers, r, w = await logged_in()
    try:
        toks = await rpc_call(r, w, 10, [])
        assert toks[0][1:] == (201, "Procedure or function 'sp_executesql' expects parameter "
                                    "'@statement', which was not supplied.")
        toks = await rpc_call(r, w, 10, [p_varchar("SELECT 1")])
        assert toks[0][1:] == (214, "Procedure expects parameter '@statement' of type "
                                    "'ntext/nchar/nvarchar'.")
        toks = await rpc_call(r, w, 10, [p_nvarchar("SELECT @a, @b"), p_nvarchar("@a int, @b int"),
                                         p_int(1)])
        assert toks[0][1:] == (8178, "The parameterized query '(@a int, @b int)SELECT @a, @b' "
                                     "expects the parameter '@b', which was not supplied.")
        assert toks[-1] == ("doneproc", 0x0002, 0)
        toks = await rpc_call(r, w, 10, [p_nvarchar("SELECT @a"), p_nvarchar("@a int"),
                                         p_int(1), p_int(2)])
        assert toks[0][1:] == (8144, "Procedure or function sp_executesql has too many "
                                     "arguments specified.")
        toks = await rpc_call(r, w, "master..xp_cmdshell", [p_varchar("whoami")])
        assert toks == [(0xAA, 229, "The EXECUTE permission was denied on the object "
                                    "'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'."),
                        ("doneproc", 0x0002, 0)]
        toks = await rpc_call(r, w, "dbo.GetBalance", [p_int(1001, "@id")])
        assert toks[0][1:] == (229, "The EXECUTE permission was denied on the object "
                                    "'GetBalance', database 'CoreBanking', schema 'dbo'.")
        toks = await rpc_call(r, w, 2, [p_int(None, "", 1)])          # sp_cursoropen
        assert toks[0][1] == 229 and "'sp_cursoropen'" in toks[0][2]
        toks = await batch(r, w, "SELECT 1 AS one")
        assert ("row", ["1"]) in toks
        w.close()
        await asyncio.sleep(0.05)
    finally:
        await stop(servers)
    hs = [e["data"] for e in events(ctx, "command") if e["data"].get("high_signal")]
    assert [(d["match"], d["statement"]) for d in hs] == [("xp_cmdshell",
                                                           "EXEC master..xp_cmdshell 'whoami'")]


async def test_malformed_rpc_gets_protocol_error_and_close():
    ctx, servers, r, w = await logged_in()
    try:
        w.write(rpc_packet(10, [bname("") + b"\x00\x99\x01\x02"]))       # unknown type
        toks = parse_tokens(await read_reply(r))
        assert toks[0][1] == 4002
        assert await asyncio.wait_for(r.read(), 5) == b""
    finally:
        await stop(servers)
    assert any(e["data"].get("reason") == "malformed" for e in events(ctx, "error"))
    assert not [e for e in ctx.writer.events if e["message"] == "Handler error"]


async def test_too_many_rpc_parameters():
    ctx, servers, r, w = await logged_in()
    try:
        toks = await rpc_call(r, w, 10, [p_nvarchar("SELECT 1")] + [p_int(1)] * 2100)
        assert toks[0][1] == 8003 and toks[-1] == ("doneproc", 0x0002, 0)
        toks = await batch(r, w, "SELECT 1 AS one")
        assert ("row", ["1"]) in toks
        w.close()
    finally:
        await stop(servers)


def test_rpc_value_decoding():
    def lit(param: bytes) -> str:
        _, _, literal, pos = mssql.read_param_value(param, 0)
        assert pos == len(param)
        return literal

    assert lit(b"\x6d\x08\x08" + struct.pack("<d", 1e-5)) == "1.0e-05"
    assert lit(b"\x6a\x11\x0a\x02\x05\x00" + (12345).to_bytes(4, "little")) == "-123.45"
    assert lit(b"\x24\x10\x10" + bytes(range(16))) == "'03020100-0504-0706-0809-0A0B0C0D0E0F'"
    assert lit(b"\x28\x03" + (738885).to_bytes(3, "little")) == "'2024-01-01'"
    units = (3 * 3600 + 4 * 60 + 5) * 10 ** 7
    assert lit(b"\x2a\x07\x08" + units.to_bytes(5, "little") + (738885).to_bytes(3, "little")) \
        == "'2024-01-01 03:04:05.0000000'"
    assert lit(b"\x2b\x00\x08" + (3600).to_bytes(3, "little") + (738885).to_bytes(3, "little")
               + (-300).to_bytes(2, "little", signed=True)) == "'2023-12-31 20:00:00 -05:00'"
    assert lit(b"\x6f\x08\x08" + (45290).to_bytes(4, "little") + (300).to_bytes(4, "little")) \
        == "'2024-01-01 00:00:01.000'"
    assert lit(b"\x6e\x08\x08" + (0).to_bytes(4, "little") + (12345).to_bytes(4, "little")) == "1.2345"
    assert lit(b"\xa5\x10\x00\x02\x00\xde\xad") == "0xDEAD"
    big = 10 ** 37 + 7                                       # DECIMAL(38, 2) keeps every digit
    assert lit(b"\x6a\x11\x26\x02\x11\x01" + big.to_bytes(16, "little")) \
        == "100000000000000000000000000000000000.07"
    assert lit(b"\x68\x01\x01\x01") == "1"
    assert mssql.declared_names("@a int, @b decimal(10, 2) OUTPUT") == ["@a", "@b"]
    assert mssql.declared_names("") == [] and mssql.declared_names("a int") is None
    assert mssql.bind_names("SELECT @a, '@a', [@a], @A, @ab /* @a */ -- @a", {"@a": "1"}) \
        == "SELECT 1, '@a', [@a], 1, @ab /* @a */ -- @a"


def test_prepared_handles_are_capped_oldest_first():
    h = mssql.Handles()
    ids = [h.add("", f"SELECT {i}") for i in range(mssql.MAX_HANDLES + 1)]
    assert ids == list(range(1, mssql.MAX_HANDLES + 2))
    assert 1 not in h.stmts and len(h.stmts) == mssql.MAX_HANDLES
    assert h.stmts[mssql.MAX_HANDLES + 1] == ("", f"SELECT {mssql.MAX_HANDLES}")
