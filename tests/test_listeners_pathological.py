"""Every listener under pathological input: bounded time, and the shared loop stays live."""

import asyncio
import importlib
import time

import pytest

from listener_fuzz import hammer, repeats
from listeners.base import Limits, ListenerContext, ServiceSettings
from listeners.events import EventWriter
from scenarios.schema import LoginPolicy

pytestmark = pytest.mark.slow

PAYLOAD_BOUND = 3.0   # seconds per payload, including the 0.3 s idle drain
PROBE_BOUND = 1.0     # a fresh client must still be served this fast during the attack


async def _start(name, tmp_path):
    ctx = ListenerContext(EventWriter(None), bind_host="127.0.0.1",
                          limits=Limits(rate_per_ip_per_minute=10_000, max_connections_per_ip=64,
                                        max_connections_per_ip_per_service=64,
                                        pre_login_timeout=2, read_timeout=2),
                          quarantine_dir=str(tmp_path / "q"))
    settings = ServiceSettings(name, True, 0, policy=LoginPolicy(accept="all"))
    ctx.settings[name] = settings
    servers = await importlib.import_module(f"listeners.{name}").start(ctx, settings)
    port = next(s.sockets[0].getsockname()[1] for s in servers if getattr(s, "sockets", None))
    return ctx, servers, port


def _line(prefix: bytes, body: bytes, cap: int = 3900) -> bytes:
    return prefix + body[:cap] + b"\r\n"


CASES = {
    "ftp": dict(preamble=[b"USER a\r\n", b"PASS a\r\n"],
                payloads=[_line(b"NLST ", b"*a" * 2000), _line(b"LIST ", b"[" * 4000),
                          _line(b"CWD ", b"../" * 1300), _line(b"SIZE ", b"?" * 4000),
                          _line(b"PORT ", b"1," * 1950), _line(b"EPRT ", b"|" * 3900),
                          _line(b"EPRT |2|", b":" * 3900), _line(b"RMD ", b"/a" * 1950)]
                + repeats("*?[]%\\", 70_000)),
    "smtp": dict(preamble=[b"EHLO a\r\n"],
                 payloads=[_line(b"AUTH PLAIN ", b"=" * 4000), _line(b"MAIL FROM:", b"<" * 4000),
                           _line(b"RCPT TO:", b"@" * 4000),
                           _line(b"MAIL FROM:<a@b> ", b"SIZE=9 " * 550),
                           _line(b"ETRN ", b"@#" * 1950)] + repeats("<>@.=:", 70_000)),
    "redis": dict(probe_request=b"PING\r\n",
                  payloads=[_line(b"KEYS ", b"a*" * 1950 + b"b"),
                            _line(b"SCAN 0 MATCH ", b"*a" * 1950 + b" COUNT 10"),
                            _line(b"CONFIG GET ", b"*?" * 1950),
                            b"*3\r\n$4\r\nKEYS\r\n$60000\r\n" + b"a*" * 30000 + b"\r\n",
                            b"*3\r\n$4\r\nEVAL\r\n$60000\r\n"
                            + (b"return redis.call('get', KEYS[1]" * 2000)[:60000]
                            + b"\r\n$1\r\n0\r\n",
                            _line(b"EVAL \"", b"return KEYS[" * 300 + b"\" 0"),
                            _line(b"ZADD k ", b"1 a " * 900)]
                  + repeats("*?[]\\\r", 70_000)),
    "telnet": dict(payloads=[b"\xff\xfb" * 35_000, b"\xff\xfa" * 35_000, b"\xff" * 70_000]),
    "http": dict(probe_request=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
                 payloads=[_line(b"GET /", b"%" * 4000 + b" HTTP/1.1"),
                           b"GET / HTTP/1.1\r\nX: " + b"," * 8000 + b"\r\n\r\n",
                           b"GET //[x/ HTTP/1.1\r\n\r\n", b"GET /" + b"/" * 8000 + b" HTTP/1.1\r\n\r\n",
                           _line(b"GET /cgi-bin/", b"a/" * 1950 + b" HTTP/1.1"),
                           _line(b"GET /.git/", b"./" * 1950 + b" HTTP/1.1"),
                           _line(b"GET /api/v1/", b"%2e" * 1300 + b" HTTP/1.1"),
                           _line(b"GET /", b"a." * 1950 + b" HTTP/1.1")]
                 + repeats("%/?[]:;,\r", 70_000)),
    "s3": dict(probe_request=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
               payloads=[_line(b"GET /b/", b"%2e%2e/" * 500 + b" HTTP/1.1"),
                         b"GET /b?" + b"&a=" * 2600 + b" HTTP/1.1\r\n\r\n",
                         b"GET / HTTP/1.1\r\nAuthorization: AWS4-HMAC-SHA256 " + b"," * 7000
                         + b"\r\n\r\n",
                         b"GET / HTTP/1.1\r\nAuthorization: AWS4-HMAC-SHA256 Credential="
                         + b"/" * 7000 + b"\r\n\r\n",
                         b"GET /?list-type=2&continuation-token=" + b"A" * 7000
                         + b" HTTP/1.1\r\n\r\n",
                         b"GET /bucket.name/k HTTP/1.1\r\nHost: " + b"a." * 3500 + b"\r\n\r\n",
                         b"PUT /b/k HTTP/1.1\r\nContent-Length: 99999999999999\r\n\r\n",
                         b"PUT /b/k HTTP/1.1\r\nx-amz-copy-source: " + b"%2F" * 2000
                         + b"\r\n\r\n",
                         b"PUT /b/k HTTP/1.1\r\nx-amz-copy-source: " + b"?%3F" * 1700
                         + b"\r\n\r\n",
                         b"GET /b?uploads&key-marker=" + b"%7F" * 1200 + b"&upload-id-marker="
                         + b"%2F" * 1200 + b" HTTP/1.1\r\n\r\n",
                         b"PUT /b/k?tagging HTTP/1.1\r\nContent-Length: 60000\r\n\r\n"
                         + b"<Tag><Key>" * 6000]
               + repeats("%/?[]:;,&=\r", 70_000)),
    "mllp": dict(probe_request=b"\x0bMSH|^~\\&|A|B|C|D|20260101||ADT^A01|P1|P|2.5\r\x1c\r",
                 payloads=[b"\x0b" + b"|^~\\&" * 12_000 + b"\x1c\r", b"\x0b" * 60_000,
                           b"\x0b" + b"\r" * 60_000,
                           b"\x0bMSH|^~\\&|A|B|C|D|1||QBP^Q22^QBP_Q21|1|P|2.5\rQPD|"
                           + b"~^|" * 20_000 + b"\x1c\r",
                           b"\x0bMSH|^~\\&|A|B|C|D|1||QRY^A19|1|P|2.3\r"
                           + b"QRD|" * 20_000 + b"\x1c\r"]),
    "postgres": dict(probe=False, payloads=repeats("\x00\xff'", 70_000)),
    "mysql": dict(payloads=repeats("\x00\xff'%", 70_000)),
    "mssql": dict(probe=False, payloads=repeats("\x00\x12\x10\xff", 70_000)),
}


@pytest.mark.parametrize("name", sorted(CASES))
async def test_listener_survives_pathological_input(name, tmp_path):
    ctx, servers, port = await _start(name, tmp_path)
    case = dict(CASES[name])
    try:
        result = await hammer(port, case.pop("payloads"), **case)
    finally:
        for s in servers:
            s.close()
    assert result.worst_payload_seconds < PAYLOAD_BOUND, result
    assert result.worst_probe_seconds < PROBE_BOUND, result
    # Handlers must fail gracefully, not by blowing the stack.
    assert not any(e["event"] == "error" and e["data"].get("reason") == "RecursionError"
                   for e in ctx.writer.events)


# Lines for the Telnet trap's canned shell (``agents.shell``): ( ) groups and sh -c scripts.
SHELL_LINES = [
    _line(b"", b"(" * 3900),
    _line(b"", b"( " * 1000 + b"echo a" + b" )" * 1000),
    _line(b"", b"(echo a);" * 430),
    _line(b"", b"(busybox X; echo a) >/tmp/x;" * 140),
    _line(b"sh -c '", b"f() { f; }; f; " * 60 + b"'"),
    _line(b"sh -c 'echo $((", b"(" * 600 + b"1" + b")" * 600 + b"))'"),
    _line(b"sh -c 'echo $((", b"1*" * 120 + b"1))'"),
    _line(b"sh -c 'printf %s", b" a" * 60 + b"'"),
    _line(b"sh -c '", b"g() { :; :; :; :; :; :; :; :; }; h() { g; g; g; g; g; g; g; g; }; "
          + b"h; " * 20 + b"'"),
    _line(b"sh -c 'set -- ", b"a " * 60 + b"; echo \"$#|$1|$$\"'"),
    _line(b"", b"sh -c 'echo $$';" * 200),
    _line(b"echo ", b"\\" * 3900),
    _line(b"echo \"", b"\\\"" * 1900 + b"\""),
    _line(b"sh -c 'printf \"%s", b"\\\\" * 1000 + b"\" a'"),
]


async def test_telnet_canned_shell_survives_pathological_lines(tmp_path):
    ctx, servers, port = await _start("telnet", tmp_path)
    try:
        result = await hammer(port, SHELL_LINES, preamble=[b"root\r\n", b"root\r\n"])
    finally:
        for s in servers:
            s.close()
    assert result.worst_payload_seconds < PAYLOAD_BOUND, result
    assert result.worst_probe_seconds < PROBE_BOUND, result
    assert not any(e["event"] == "error" for e in ctx.writer.events)
    # each line reached the shell after the login
    assert sum(e["event"] == "command" for e in ctx.writer.events) >= len(SHELL_LINES)


SQL_STATEMENTS = [
    "SELECT * FROM users WHERE email LIKE '" + "%" * 50 + "!'",
    "SHOW VARIABLES LIKE '" + "%" * 50 + "!'",
    "/*!" * 21_845,
    "(" * 20_000 + "SELECT 1" + ")" * 20_000,
    "SELECT '" + "'" * 30_000,
    "SELECT " + "\\" * 30_000,
    "SELECT 1 " + "-- x\n" * 10_000,
    "CREATE USER " + "a," * 20_000 + "a",
    "GRANT " + "SELECT," * 4_000 + "SELECT ON t TO " + "u," * 10_000 + "u",
    "CREATE ROLE r; GRANT " + "r," * 20_000 + "r TO r",
    "CREATE TABLE t (a int, b text); INSERT INTO t VALUES " + "(1,'a')," * 7_000 + "(1,'a')",
    "CREATE TABLE t (a int); INSERT INTO t (a) VALUES (" + "(" * 20_000 + "1" + ")" * 20_000 + ")",
]


@pytest.mark.parametrize("dialect", ["postgres", "mysql", "mssql"])
async def test_sql_engine_bounded_on_pathological_statements(dialect):
    from listeners.sqlfake import FakeSql

    ctx = ListenerContext(EventWriter(None))

    class C:
        def __init__(self):
            self.ctx, self.task_name, self.src_ip, self.src_port = ctx, "t", "203.0.113.1", 1

        def emit(self, *a, **k):
            pass

    for stmt in SQL_STATEMENTS:
        engine = FakeSql(C(), dialect, "u", "appdb")
        start = time.perf_counter()
        try:
            await asyncio.wait_for(engine.run(stmt), 5)
        except asyncio.TimeoutError:
            pytest.fail(f"{dialect}: statement did not finish: {stmt[:40]!r}")
        assert time.perf_counter() - start < 0.5, (dialect, stmt[:40])


# ---- SQL wire parsers after login: prepared statements (MySQL) and RPC (MSSQL) ------------

def _my(seq: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "little") + bytes([seq]) + payload


def _my_login() -> bytes:
    flags = 0x200 | 0x8000 | 0x80000 | 0x200000          # PROTOCOL_41, SECURE, PLUGIN_AUTH, LENENC
    return _my(1, flags.to_bytes(4, "little") + (1 << 24).to_bytes(4, "little") + b"\xff"
               + b"\x00" * 23 + b"root\x00\x00mysql_native_password\x00")


def _exec(stmt_id: int, rest: bytes) -> bytes:
    return _my(0, b"\x17" + stmt_id.to_bytes(4, "little") + b"\x00\x01\x00\x00\x00" + rest)


def _prep(sql: bytes) -> bytes:
    return _my(0, b"\x16" + sql)


def _tds(ptype: int, payload: bytes) -> bytes:
    """One TDS message split into 32000-byte packets."""
    out, step = b"", 32000
    chunks = [payload[i:i + step] for i in range(0, len(payload), step)] or [b""]
    for i, c in enumerate(chunks):
        out += (bytes([ptype, 0x01 if i == len(chunks) - 1 else 0x00])
                + (len(c) + 8).to_bytes(2, "big") + b"\x00\x00\x01\x00" + c)
    return out


def _rpc(proc: int, params: bytes) -> bytes:
    headers = (22).to_bytes(4, "little") + (18).to_bytes(4, "little") + (2).to_bytes(2, "little") \
        + b"\x00" * 8 + (1).to_bytes(4, "little")
    return _tds(0x03, headers + b"\xff\xff" + proc.to_bytes(2, "little") + b"\x00\x00" + params)


def _rpc_calls(calls: list[bytes], sep: bytes = b"\xff", tail: bytes = b"") -> bytes:
    """One RPC request batching ``calls`` (each a ProcID 10 call body after its header)."""
    headers = (22).to_bytes(4, "little") + (18).to_bytes(4, "little") + (2).to_bytes(2, "little") \
        + b"\x00" * 8 + (1).to_bytes(4, "little")
    return _tds(0x03, headers + sep.join(b"\xff\xff\x0a\x00\x00\x00" + c for c in calls) + tail)


def _nv(text: str) -> bytes:
    raw = text.encode("utf-16-le")
    return b"\x00\x00\xe7" + (8000).to_bytes(2, "little") + b"\x09\x04\xd0\x00\x34" \
        + len(raw).to_bytes(2, "little") + raw


def _int(v: int) -> bytes:
    return b"\x00\x00\x26\x04\x04" + v.to_bytes(4, "little", signed=True)


def _mysql_wire_payloads() -> list[bytes]:
    many = b"SELECT " + b",".join([b"?"] * 30_000)
    return [
        # 30000 markers, then an execute whose types run past the end of the packet.
        _prep(many) + _exec(1, b"\x00" * 3750 + b"\x01" + b"\xfd\x00" * 100),
        # Every parameter claims a 2^64-1 byte string; unknown type bytes read as strings.
        _prep(b"SELECT ?, ?, ?") + _exec(1, b"\x00\x01" + b"\xee\x00\xfd\x00\x0c\x00"
                                          + b"\xfe" + b"\xff" * 8),
        # Bad temporal lengths, a parameter count mismatch, an execute with no types.
        _prep(b"SELECT ?") + _exec(1, b"\x00\x01\x0c\x00\x63" + b"\x00" * 99)
        + _exec(1, b"") + _exec(1, b"\x00\x00") + _exec(7, b"\x00"),
        # Long data far past the caps, then an execute that uses it.
        _prep(b"SELECT ? AS v") + b"".join(_my(0, b"\x18\x01\x00\x00\x00\x00\x00" + b"A" * 60_000)
                                           for _ in range(12)) + _exec(1, b"\x00\x01\xfc\x00"),
        # More statements than the cap, in one burst.
        b"".join(_prep(b"SELECT ?") for _ in range(200)),
        # Short and garbage commands.
        b"".join(_my(0, bytes([c])) for c in (0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1f) * 50),
        _my(0, b"\x11" + b"\xff" * 5000),
        _my(0, b"\x11root\x00\xff" + b"x" * 10),
        _my(0, b"\x11root\x00\x00\x00\x00\x00\x00\xfe" + b"\xff" * 8),
        # Quote and comment runs in a prepared statement.
        _prep(b"SELECT '" + b"\\'" * 30_000), _prep(b"SELECT " + b"/*" * 30_000),
        _prep(b"SELECT " + b"-- ?\n" * 12_000), _prep(b"SELECT `" + b"``" * 30_000),
    ]


def _mssql_wire_payloads() -> list[bytes]:
    stmt = _nv("SELECT " + ", ".join(f"@p{i}" for i in range(2000)))
    decl = _nv(", ".join(f"@p{i} int" for i in range(2000)))
    plp_tiny = (b"\x00\x00\xe7\xff\xff\x09\x04\xd0\x00\x34" + (10 ** 9).to_bytes(8, "little")
                + b"\x01\x00\x00\x00A" * 150_000 + b"\x00\x00\x00\x00")
    return [
        _rpc(10, stmt + decl + _int(7) * 2000),                  # 2000 bound parameters
        _rpc(10, stmt + decl),                                   # declared, none supplied
        _rpc(10, _nv("SELECT 1") + _int(1) * 2200),              # past the parameter limit
        _rpc(10, plp_tiny),                                      # 150000 one-byte PLP chunks
        _rpc(10, b"\x00\x00\xe7\xff\xff\x09\x04\xd0\x00\x34" + b"\xff" * 7 + b"\xfe"
             + b"\xff\xff\xff\xff"),                             # chunk length past the end
        _rpc(10, b"\xff\x00" + b"@\x00" * 10),                   # name length past the end
        _rpc(10, b"\x00\x00\x99"),                               # unknown type
        _rpc(10, b"\x00\x00\x6a\x11\x26\xff\x05\x01\x00"),       # bad scale
        _rpc(10, b"\x00\x00\x6f\x08\x08" + b"\xff" * 8),         # datetime out of range
        _rpc(12, _int(5) + _int(1)), _rpc(15, b""), _rpc(11, _int(0)),
        _tds(0x03, b"\x01"), _tds(0x03, b"\xff\xff"),
        _rpc(10, _nv("SELECT '" + "'" * 3000 + " @a") + _nv("@a int") + _int(1)),
        _rpc(10, _nv("SELECT " + "/*" * 3000 + " @a") + _nv("@a int") + _int(1)),
        # Batched calls: far past the call cap, a run of separators, trailing flags, a valid
        # call before a malformed one, and capped calls that each carry many parameters.
        _rpc_calls([b""] * 100_000),
        _rpc_calls([_nv("SELECT 1")], tail=b"\xff" * 50_000),
        _rpc_calls([_nv("SELECT 1")] * 3, sep=b"\xfe", tail=b"\xfe"),
        _rpc_calls([_nv("SELECT @a") + _nv("@a int") + _int(1), b"\x00\x00\x99"]),
        _rpc_calls([stmt + decl + _int(7) * 2000] * 10),
        _rpc_calls([_nv("SELECT 1") + _int(1) * 2099] * 20),
    ]


async def _mssql_login() -> bytes:
    import test_listeners_mssql as tm  # module import: its tests are not collected here
    return tm.login7("sa", "x")


@pytest.mark.parametrize("name", ["mysql", "mssql"])
async def test_sql_wire_parsers_survive_pathological_input(name, tmp_path):
    ctx, servers, port = await _start(name, tmp_path)
    if name == "mysql":
        case = dict(preamble=[_my_login()], payloads=_mysql_wire_payloads())
    else:
        case = dict(preamble=[await _mssql_login()], payloads=_mssql_wire_payloads(), probe=False)
    try:
        result = await hammer(port, case.pop("payloads"), **case)
    finally:
        for s in servers:
            s.close()
    assert result.worst_payload_seconds < PAYLOAD_BOUND, result
    assert result.worst_probe_seconds < PROBE_BOUND, result
    assert not [e for e in ctx.writer.events if e["message"] == "Handler error"], \
        [e["data"] for e in ctx.writer.events if e["message"] == "Handler error"]
    assert any(e["event"] == "auth_attempt" and e["success"] for e in ctx.writer.events)


def test_sql_wire_parsers_reject_every_truncation_cleanly():
    """Each prefix of a valid packet parses or raises the parser's own error, never another."""
    import random

    from listeners import mssql, mysql

    stmt = mysql.Prepared("SELECT ?, ?, ?, ?, ?", mysql.placeholders("SELECT ?, ?, ?, ?, ?"))
    # LONGLONG 5, DOUBLE (NULL in the bitmap), DATETIME, TIME, VAR_STRING.
    execute = (b"\x17\x01\x00\x00\x00\x00\x01\x00\x00\x00" + b"\x02" + b"\x01"
               + b"\x08\x00\x05\x00\x0c\x00\x0b\x00\xfd\x00"
               + (5).to_bytes(8, "little") + b"\x07\xe8\x07\x01\x02\x03\x04\x05"
               + b"\x08\x00" + b"\x00" * 4 + b"\x01\x02\x03" + b"\x03abc")
    change = b"\x11root\x00\x14" + b"x" * 20 + b"db\x00\xff\x00mysql_native_password\x00" \
        + b"\x0a\x03key\x05value\x00"
    rpc_body = (b"\xff\xff\x0a\x00\x00\x00" + _nv("SELECT @a") + _nv("@a int") + _int(3)
                + b"\x00\x00\xe7\xff\xff\x09\x04\xd0\x00\x34" + (4).to_bytes(8, "little")
                + b"\x04\x00\x00\x00a\x00b\x00\x00\x00\x00\x00")
    two_calls = rpc_body + b"\xff" + b"\xff\xff\x0c\x00\x00\x00" + _int(1) + _int(2) + b"\xfe"
    rng = random.Random(7)
    samples = []
    for good in (execute, change, rpc_body, two_calls):
        samples += [(good, good[:i]) for i in range(len(good))]
        for _ in range(300):
            bad = bytearray(good)
            for _ in range(rng.randint(1, 4)):
                bad[rng.randrange(len(bad))] = rng.randrange(256)
            samples.append((good, bytes(bad)))
    for good, data in samples:
        if good is execute:
            stmt.types = None
            try:
                mysql.parse_execute(data, stmt)
            except (ValueError, IndexError):
                pass
        elif good is change:
            try:
                mysql.parse_change_user(data, 0xFFFFFFFF)
            except (ValueError, IndexError):
                pass
        elif good is rpc_body:
            try:
                mssql.parse_rpc(data)
            except (mssql.RpcMalformed, mssql.TooManyParams, ValueError, OverflowError):
                pass
        else:
            for wide in (True, False):
                calls, problem = mssql.parse_rpc_batch(data, wide)
                assert problem in (None, "malformed", "too_many_params", "too_many_calls")
                assert sum(len(c.raw) for c in calls) <= len(data)
    stmt.types = None
    assert mysql.parse_execute(execute, stmt) == ["5", "NULL", "'2024-01-02 03:04:05'",
                                                  "'01:02:03'", "'abc'"]
    assert mysql.parse_change_user(change, 0xFFFFFFFF)["attrs"] == {"key": "value"}
    calls, problem = mssql.parse_rpc_batch(two_calls, True)
    assert problem is None
    assert [(c.name, len(c.params), c.no_exec) for c in calls] == [("sp_executesql", 4, False),
                                                                   ("sp_execute", 2, True)]
    assert [p.literal for p in mssql.parse_rpc(rpc_body)[1]] == ["N'SELECT @a'", "N'@a int'",
                                                                 "3", "N'ab'"]
