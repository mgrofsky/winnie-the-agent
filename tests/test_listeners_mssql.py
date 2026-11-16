"""Loopback tests for the fake MSSQL (TDS) listener with a minimal raw TDS client."""

import asyncio
import os

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
        elif t == 0xFD:
            toks.append(("done", int.from_bytes(p[pos:pos + 2], "little"),
                         int.from_bytes(p[pos + 4:pos + 12], "little")))
            pos += 12
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


async def test_unknown_query_with_failing_model_is_error_token():
    ctx, servers, port = await start_server(json_llm=RaisingLLM())
    try:
        await login(port, "sa", "a")
        r, w, toks = await login(port, "sa", "b")
        toks = await batch(r, w, "SELECT * FROM accounts")
        assert toks[0] == (0xAA, 208, "Invalid object name 'accounts'.")  # master is current
        toks = await batch(r, w, "USE CoreBanking")
        assert toks[0][0] == 0xE3
        toks = await batch(r, w, "SELECT HASHBYTES('SHA1', holder) FROM accounts")
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
