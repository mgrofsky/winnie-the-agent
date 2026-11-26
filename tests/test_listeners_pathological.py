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
                          _line(b"CWD ", b"../" * 1300), _line(b"SIZE ", b"?" * 4000)]
                + repeats("*?[]%\\", 70_000)),
    "smtp": dict(preamble=[b"EHLO a\r\n"],
                 payloads=[_line(b"AUTH PLAIN ", b"=" * 4000), _line(b"MAIL FROM:", b"<" * 4000),
                           _line(b"RCPT TO:", b"@" * 4000)] + repeats("<>@.=:", 70_000)),
    "redis": dict(probe_request=b"PING\r\n",
                  payloads=[_line(b"KEYS ", b"a*" * 1950 + b"b"),
                            _line(b"SCAN 0 MATCH ", b"*a" * 1950 + b" COUNT 10"),
                            _line(b"CONFIG GET ", b"*?" * 1950),
                            b"*3\r\n$4\r\nKEYS\r\n$60000\r\n" + b"a*" * 30000 + b"\r\n"]
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
                         b"PUT /b/k HTTP/1.1\r\nContent-Length: 99999999999999\r\n\r\n"]
               + repeats("%/?[]:;,&=\r", 70_000)),
    "mllp": dict(probe_request=b"\x0bMSH|^~\\&|A|B|C|D|20260101||ADT^A01|P1|P|2.5\r\x1c\r",
                 payloads=[b"\x0b" + b"|^~\\&" * 12_000 + b"\x1c\r", b"\x0b" * 60_000,
                           b"\x0b" + b"\r" * 60_000]),
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


SQL_STATEMENTS = [
    "SELECT * FROM users WHERE email LIKE '" + "%" * 50 + "!'",
    "SHOW VARIABLES LIKE '" + "%" * 50 + "!'",
    "/*!" * 21_845,
    "(" * 20_000 + "SELECT 1" + ")" * 20_000,
    "SELECT '" + "'" * 30_000,
    "SELECT " + "\\" * 30_000,
    "SELECT 1 " + "-- x\n" * 10_000,
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
