"""SMTP trap tests: AUTH capture, relay denial, message logging, no outbound sockets."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import socket

import pytest

from listeners import smtp
from listeners.base import ListenerContext, ServiceSettings
from listeners.events import EventWriter
from scenarios.schema import LoginPolicy


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


@pytest.fixture
async def smtp_server():
    servers = []

    async def _start(accept="after_n"):
        writer = EventWriter(None)
        ctx = ListenerContext(writer, bind_host="127.0.0.1", seed="test")
        settings = ServiceSettings(name="smtp", enabled=True, port=0,
                                   policy=LoginPolicy(accept=accept, after_n_min=2, after_n_max=2))
        ctx.settings["smtp"] = settings
        objs = await smtp.start(ctx, settings)
        servers.extend(objs)
        reader, w = await asyncio.open_connection("127.0.0.1", objs[0].sockets[0].getsockname()[1])
        return writer, reader, w

    yield _start
    for s in servers:
        s.close()


@pytest.fixture
def no_outbound(monkeypatch):
    """Returns arm(); after arm() any outbound connection attempt fails the test.

    The test client connects first, then arms, so every later connect would be the server's.
    """
    calls: list[str] = []

    def deny(name):
        def _deny(*a, **k):
            calls.append(name)
            raise AssertionError(f"outbound connection attempted via {name}")
        return _deny

    def arm() -> list[str]:
        monkeypatch.setattr(socket.socket, "connect", deny("socket.connect"))
        monkeypatch.setattr(socket.socket, "connect_ex", deny("socket.connect_ex"))
        monkeypatch.setattr(socket, "create_connection", deny("socket.create_connection"))
        monkeypatch.setattr(asyncio, "open_connection", deny("asyncio.open_connection"))
        monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "create_connection",
                            deny("loop.create_connection"))
        monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "sock_connect",
                            deny("loop.sock_connect"))
        return calls

    return arm


class Session:
    def __init__(self, reader, writer) -> None:
        self.reader, self.writer = reader, writer

    async def read(self) -> str:
        lines = []
        while True:
            line = (await asyncio.wait_for(self.reader.readline(), 3)).decode()
            lines.append(line)
            if len(line) < 4 or line[3] != "-":
                return "".join(lines)

    async def __call__(self, line: str) -> str:
        self.writer.write(line.encode() + b"\r\n")
        await self.writer.drain()
        return await self.read()


def events(writer, event):
    return [e for e in writer.events if e["event"] == event]


async def test_smtp_auth_fail_then_success_and_message(smtp_server, no_outbound):
    writer, reader, w = await smtp_server()
    calls = no_outbound()
    s = Session(reader, w)
    assert (await s.read()).startswith("220 mail.example.com ESMTP Postfix")
    ehlo = await s("EHLO scanner.example.net")
    assert "250-AUTH PLAIN LOGIN" in ehlo and ehlo.rstrip().endswith("250 SMTPUTF8")
    assert (await s("STARTTLS")).startswith("454")
    # AUTH LOGIN with continuation, wrong
    assert await s("AUTH LOGIN") == "334 VXNlcm5hbWU6\r\n"
    assert await s(b64("info@example.com")) == "334 UGFzc3dvcmQ6\r\n"
    assert (await s(b64("123456"))).startswith("535 5.7.8")
    # Before auth: relay denied and logged
    assert (await s("MAIL FROM:<spam@example.net>")).startswith("250")
    assert (await s("RCPT TO:<victim@example.org>")).startswith("554 5.7.1")
    assert (await s("RSET")).startswith("250")
    # AUTH PLAIN inline, accepted on the 2nd attempt
    assert (await s("AUTH PLAIN " + b64("\x00info@example.com\x00Summer2026"))).startswith("235")
    assert (await s("MAIL FROM:<info@example.com>")).startswith("250 2.1.0")
    assert (await s("RCPT TO:<target@example.org>")).startswith("250 2.1.5")
    assert (await s("RCPT TO:<postmaster@example.com>")).startswith("250 2.1.5")
    assert (await s("DATA")).startswith("354")
    body = "Subject: invoice\r\nFrom: info@example.com\r\n\r\nPlease pay\r\n..dot line\r\n"
    w.write(body.encode() + b".\r\n")
    await w.drain()
    queued = await s.read()
    assert queued.startswith("250 2.0.0 Ok: queued as ")
    assert (await s("QUIT")).startswith("221")
    assert calls == []

    attempts = events(writer, "auth_attempt")
    assert [(a["username"], a["password"], a["success"]) for a in attempts] == [
        ("info@example.com", "123456", False), ("info@example.com", "Summer2026", True)]
    assert attempts[0]["data"]["mechanism"] == "LOGIN" and attempts[0]["client"] == "scanner.example.net"
    relays = [e for e in events(writer, "command") if e["data"].get("signal") == "smtp_relay_attempt"]
    # Unauthenticated RCPT, authenticated RCPT, then the accepted outbound message itself.
    assert [r["data"]["authenticated"] for r in relays] == [False, True, True]
    assert all(r["data"]["high_signal"] for r in relays)
    msg = next(e for e in events(writer, "command") if e["data"].get("cmd") == "DATA"
               and "sha256" in e["data"])
    raw = "Subject: invoice\r\nFrom: info@example.com\r\n\r\nPlease pay\r\n.dot line\r\n".encode()
    assert msg["data"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert msg["data"]["size"] == len(raw)
    assert msg["data"]["subject"] == "invoice"
    assert msg["data"]["recipients"] == "target@example.org,postmaster@example.com"
    assert "Please pay" in msg["data"]["body_head"]


async def test_smtp_bad_base64_and_unknown_mech(smtp_server):
    writer, reader, w = await smtp_server(accept="none")
    s = Session(reader, w)
    await s.read()
    assert (await s("AUTH PLAIN x")).startswith("503")       # no EHLO yet
    await s("HELO x")
    assert (await s("AUTH PLAIN !!!notbase64")).startswith("501")
    assert (await s("AUTH CRAM-MD5")).startswith("535")
    assert (await s("AUTH LOGIN")).startswith("334")
    assert (await s("*")).startswith("501")
    assert (await s("DATA")).startswith("503")
    assert (await s("BLAH")).startswith("502")
    assert events(writer, "auth_attempt") == []


def test_every_high_signal_event_names_its_signal():
    """Playbooks match on signal names, so a high-signal event without one is invisible."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "listeners"
    for path in root.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Dict):
                keys = [k.value for k in node.keys if isinstance(k, ast.Constant)]
                if "high_signal" in keys:
                    assert "signal" in keys, f"{path.name}:{node.lineno} high_signal without signal"


async def test_auth_lines_pipelined_after_a_refused_auth_are_logged_as_secrets(smtp_server):
    """A client that pipelines AUTH LOGIN and its two base64 lines before EHLO gets 503 for
    AUTH; the next two lines are its credentials and must not land in data.input/cmd."""
    writer, reader, w = await smtp_server()
    s = Session(reader, w)
    await s.read()
    w.write(("AUTH LOGIN\r\n" + b64("info@example.com") + "\r\n" + b64("PipeSecret77")
             + "\r\nQUIT\r\n").encode())
    await w.drain()
    await asyncio.sleep(0.3)
    secret_b64 = b64("PipeSecret77")
    for e in writer.events:
        data = e.get("data") or {}
        assert secret_b64 not in str(data.get("input", "")) and secret_b64 not in str(data.get("cmd", ""))
    assert any(e.get("password") == secret_b64 for e in writer.events)
