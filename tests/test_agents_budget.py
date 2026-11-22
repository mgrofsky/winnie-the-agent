import asyncio
import json
import logging
import os
import stat
from configparser import ConfigParser
from types import SimpleNamespace

import asyncssh
import pytest

from agents import hooks
from agents.replycache import ReplyCache
from agents.budget import (
    CANNED_CONNECTION_REFUSED,
    CANNED_INTERACTIVE,
    OUTPUT_ESTIMATE_TOKENS,
    SUMMARY_SKIPPED,
    Budget,
    BudgetConfig,
    ip_key,
)


class CountingHistory:
    def __init__(self, reply="ok\n$ ", usage=None):
        self.calls = []
        self.reply = reply
        self.usage = usage

    async def ainvoke(self, payload, config=None):
        self.calls.append(payload)
        msg = payload["messages"][-1].content
        if "Examine the list" in msg:
            return SimpleNamespace(content="Judgement: BENIGN")
        if msg == "exit":
            return SimpleNamespace(content="YYY-END-OF-SESSION-YYY")
        return SimpleNamespace(content=self.reply, usage_metadata=self.usage)


@pytest.fixture(autouse=True)
def reset_hooks():
    hooks.reset()
    hooks.set_reply_cache(ReplyCache(max_entries=0))   # every call here reaches the model
    yield
    hooks.reset()


def _set_budget(**kw):
    budget = Budget(BudgetConfig(**kw))
    hooks.set_budget(budget)
    return budget


async def _call(history, sid="s1", ip="203.0.113.1", text="ls -la"):
    return await hooks.persona_invoke(history, session_id=sid, src_ip=ip, username="root",
                                      text=text, interactive=True,
                                      llm_config={"configurable": {"session_id": sid}})


# A call reserves about OUTPUT_ESTIMATE_TOKENS up front and is then charged its real usage
# (300). After one call, the next reservation (300 + ~514) no longer fits under CAP.
CAP = OUTPUT_ESTIMATE_TOKENS + 200


@pytest.mark.parametrize("limits,setup_calls,reason", [
    ({"max_commands_per_session": 2}, 2, "max_commands_per_session"),
    ({"max_tokens_per_session": CAP}, 1, "max_tokens_per_session"),
    ({"max_tokens_per_ip_per_day": CAP}, 1, "max_tokens_per_ip_per_day"),
    ({"max_tokens_per_day": CAP}, 1, "max_tokens_per_day"),
])
async def test_each_limit_triggers_canned_path_without_model_call(limits, setup_calls, reason, caplog):
    caplog.set_level("INFO")
    _set_budget(**limits)
    history = CountingHistory(usage={"total_tokens": 300})
    for _ in range(setup_calls):
        r = await _call(history)
        assert not getattr(r, "budget_exceeded", False)
    calls_before = len(history.calls)
    logger = logging.getLogger("budget-test")
    r = await hooks.persona_invoke(history, session_id="s1", src_ip="203.0.113.1", username="root",
                                   text="ls -la", interactive=True, llm_config={}, logger=logger,
                                   log_extra={"task_name": "s1"})
    assert r.budget_exceeded and r.content == CANNED_INTERACTIVE
    assert len(history.calls) == calls_before
    assert any(rec.getMessage() == "Budget exceeded" and rec.reason == reason for rec in caplog.records)


async def test_per_ip_limit_does_not_affect_other_ips():
    _set_budget(max_tokens_per_ip_per_day=CAP)
    history = CountingHistory(usage={"total_tokens": 300})
    await _call(history, sid="a", ip="203.0.113.1")
    assert (await _call(history, sid="b", ip="203.0.113.1")).budget_exceeded
    assert not getattr(await _call(history, sid="c", ip="203.0.113.2"), "budget_exceeded", False)


async def test_reservation_blocks_concurrent_overshoot():
    """Concurrent sessions reserve before calling, so in-flight calls cannot all pass."""
    per_call = OUTPUT_ESTIMATE_TOKENS + 1  # estimate for a 2-character input
    _set_budget(max_tokens_per_day=per_call * 3)
    gate = asyncio.Event()

    class SlowHistory(CountingHistory):
        async def ainvoke(self, payload, config=None):
            self.calls.append(payload)
            await gate.wait()
            return SimpleNamespace(content="x", usage_metadata={"total_tokens": 10})

    history = SlowHistory()
    tasks = [asyncio.create_task(_call(history, sid=f"s{i}", ip=f"203.0.113.{i}"))
             for i in range(10)]
    await asyncio.sleep(0.05)
    gate.set()
    results = await asyncio.gather(*tasks)
    assert len(history.calls) == 3  # only as many as the reserved estimates allow
    assert sum(1 for r in results if getattr(r, "budget_exceeded", False)) == 7


async def test_failed_call_keeps_its_reserved_charge():
    budget = _set_budget()

    class Boom:
        async def ainvoke(self, payload, config=None):
            raise RuntimeError("provider down")

    r = await _call(Boom())                       # degrades to a canned reply ...
    assert r.content == "root@srv01:~# "          # (ls -la, which the shell leaves to the model)
    assert budget.global_tokens >= OUTPUT_ESTIMATE_TOKENS   # ... and the charge is kept


def test_line_truncation_and_concurrency_caps():
    b = _set_budget(max_line_bytes=8, max_concurrent_sessions=2, max_concurrent_sessions_per_ip=1)
    assert hooks.clip_input("a" * 100) == "a" * 8
    assert hooks.clip_input("ééééé") == "éééé"  # never splits a UTF-8 character
    assert hooks.session_open("s1", "203.0.113.1") is None
    assert hooks.session_open("s2", "203.0.113.1") == CANNED_CONNECTION_REFUSED
    assert hooks.session_open("s3", "203.0.113.2") is None
    assert hooks.session_open("s4", "203.0.113.3") == CANNED_CONNECTION_REFUSED
    hooks.session_close("s1")
    assert hooks.session_open("s5", "203.0.113.1") is None
    assert b.open_sessions() == 2


def test_ipv6_sources_share_a_slash_64():
    assert ip_key("2001:db8:1:2:aaaa::1") == ip_key("2001:db8:1:2:ffff::9") == "2001:db8:1:2::/64"
    assert ip_key("2001:db8:1:3::1") != ip_key("2001:db8:1:2::1")
    assert ip_key("::ffff:203.0.113.5") == "203.0.113.5"
    _set_budget(max_concurrent_sessions_per_ip=1)
    assert hooks.session_open("a", "2001:db8:1:2::1") is None
    assert hooks.session_open("b", "2001:db8:1:2::2") == CANNED_CONNECTION_REFUSED


async def test_summary_skipped_without_model_commands_and_capped_per_ip(caplog):
    caplog.set_level("INFO")
    budget = _set_budget(max_tokens_per_ip_per_day=CAP)
    history = CountingHistory(usage={"total_tokens": 300})
    logger = logging.getLogger("budget-test")
    # A source reconnecting in a loop without running anything: no summary model calls.
    for i in range(5):
        sid = f"loop-{i}"
        assert budget.session_open(sid, "203.0.113.9") is None
        r = await hooks.summary_invoke(history, session_id=sid, src_ip="203.0.113.9", username="x",
                                       prompt="Examine the list", llm_config={}, logger=logger)
        assert r.content == SUMMARY_SKIPPED
        budget.session_close(sid)
    assert history.calls == []
    # A session that ran a command, but whose source is at its daily cap: no summary call.
    assert budget.session_open("s", "203.0.113.9") is None
    await _call(history, sid="s", ip="203.0.113.9")
    n = len(history.calls)
    r = await hooks.summary_invoke(history, session_id="s", src_ip="203.0.113.9", username="x",
                                   prompt="Examine the list", llm_config={}, logger=logger)
    assert r.content == SUMMARY_SKIPPED and len(history.calls) == n
    assert any(getattr(rec, "stage", None) == "session_summary" for rec in caplog.records)


async def test_summary_respects_global_daily_budget():
    budget = _set_budget(max_tokens_per_day=CAP)
    history = CountingHistory(usage={"total_tokens": 300})
    budget.session_open("s1", "203.0.113.1")
    await _call(history)
    n = len(history.calls)
    r = await hooks.summary_invoke(history, session_id="s1", src_ip="203.0.113.1", username="root",
                                   prompt="Examine the list", llm_config={})
    assert r.content == SUMMARY_SKIPPED and len(history.calls) == n


def test_daily_counters_survive_restart_and_are_shared(tmp_path):
    state = tmp_path / "budget_state.json"
    a = Budget(BudgetConfig(state_file=str(state)))
    b = Budget(BudgetConfig(state_file=str(state)))  # a second process on the same host
    ta = a.record("s", "203.0.113.1", "x" * 400, "y" * 400)
    tb = b.record("t", "203.0.113.2", "x" * 400, "y" * 400)
    total = json.loads(state.read_text())["global_tokens"]
    assert total == ta + tb  # b's read-modify-write saw a's spend
    assert b.global_tokens == ta + tb
    restarted = Budget(BudgetConfig(state_file=str(state)))
    assert restarted.global_tokens == total
    assert restarted.ip_tokens("203.0.113.1") > 0 and restarted.ip_tokens("203.0.113.2") > 0


@pytest.mark.parametrize("content", [
    '{"day": "TODAY", "global_tokens": NaN, "ip_tokens": {}}',
    '{"day": "TODAY", "global_tokens": Infinity, "ip_tokens": {}}',
    '{"day": "TODAY", "global_tokens": -5, "ip_tokens": {}}',
    '{"day": "TODAY", "global_tokens": 10, "ip_tokens": {"203.0.113.4": "lots"}}',
    '[1, 2, 3]',
    '{not json',
])
def test_malformed_state_starts_from_zero_with_warning(tmp_path, content, caplog):
    import datetime

    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    state = tmp_path / "budget_state.json"
    state.write_text(content.replace("TODAY", today))
    caplog.set_level("WARNING")
    b = Budget(BudgetConfig(state_file=str(state)))
    assert b.global_tokens == 0
    assert any("malformed" in r.getMessage() for r in caplog.records)
    b.record("s", "203.0.113.1", "x" * 40, "y")
    assert json.loads(state.read_text())["global_tokens"] > 0


def test_first_persist_error_is_logged_on_a_freshly_booted_host(tmp_path, caplog, monkeypatch):
    """The monotonic clock starts near zero at boot; the first error must still be logged."""
    import agents.budget as budget_module

    monkeypatch.setattr(budget_module.time, "monotonic", lambda: 5.0)
    ro = tmp_path / "ro"
    ro.mkdir()
    os.chmod(ro, stat.S_IRUSR | stat.S_IXUSR)
    try:
        caplog.set_level("ERROR")
        b = Budget(BudgetConfig(state_file=str(ro / "budget_state.json")))
        b.record("s", "203.0.113.1", "x" * 400, "y")
        assert any("BUDGET STATE NOT PERSISTED" in r.getMessage() for r in caplog.records)
    finally:
        os.chmod(ro, stat.S_IRWXU)


def test_unwritable_state_is_logged_loudly(tmp_path, caplog):
    ro = tmp_path / "ro"
    ro.mkdir()
    os.chmod(ro, stat.S_IRUSR | stat.S_IXUSR)
    try:
        caplog.set_level("ERROR")
        b = Budget(BudgetConfig(state_file=str(ro / "budget_state.json")))
        b.record("s", "203.0.113.1", "x" * 400, "y")
        assert b.global_tokens > 0  # still enforced in memory
        assert any("BUDGET STATE NOT PERSISTED" in r.getMessage() for r in caplog.records)
    finally:
        os.chmod(ro, stat.S_IRWXU)


def test_budget_config_state_file_defaults_to_data_dir(tmp_path):
    cp = ConfigParser()
    cp.read_string("[budget]\nmax_commands_per_session = 7\n")
    cfg = BudgetConfig.from_config(cp, "/read-only/config/dir", str(tmp_path))
    assert cfg.max_commands_per_session == 7
    assert cfg.state_file == str(tmp_path / "budget_state.json")
    assert BudgetConfig.from_config(ConfigParser(), "/x").max_line_bytes == 2048


# ---- through the real SSH server ---------------------------------------------------------

@pytest.fixture
def ssh_runtime(tmp_path, ssh_module):
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(str(tmp_path / "host_key"))
    ssh_module.config = ConfigParser()
    ssh_module.config["honeypot"] = {"log_file": str(tmp_path / "log.jsonl"), "sensor_name": "t"}
    ssh_module.config["ssh"] = {"listen_host": "127.0.0.1", "port": "0",
                                "host_priv_key": str(tmp_path / "host_key")}
    ssh_module.config["llm"] = {"system_prompt": ""}
    ssh_module.config["user_accounts"] = {"root": "*"}
    ssh_module.accounts = ssh_module.get_user_accounts()
    ssh_module.llm_sessions = {}
    ssh_module.configure_logging()
    return tmp_path / "log.jsonl"


def _events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


async def _serve(ssh_module):
    server = await ssh_module.start_server()
    return server, server.sockets[0].getsockname()[1]


async def test_ssh_command_limit_closes_with_canned_response(ssh_runtime, ssh_module):
    _set_budget(max_commands_per_session=2)
    history = CountingHistory()
    ssh_module.with_message_history = history
    server, port = await _serve(ssh_module)
    try:
        async with asyncssh.connect("127.0.0.1", port=port, username="root", password="x",
                                    known_hosts=None) as conn:
            proc = await conn.create_process(term_type="xterm")
            for cmd in ("ls", "id", "uname -a", "whoami"):
                proc.stdin.write(cmd + "\n")
            out = await asyncio.wait_for(proc.stdout.read(), timeout=5)
    finally:
        server.close()
        await server.wait_closed()
    assert "Resource temporarily unavailable" in out
    inputs = [p["messages"][-1].content for p in history.calls]
    assert "uname -a" not in inputs and "whoami" not in inputs   # model never saw them
    assert all("decoy_profile" in p for p in history.calls)
    for h in ssh_module.logger.handlers:
        h.flush()
    events = _events(ssh_runtime)
    assert any(e["message"] == "Budget exceeded" and e["reason"] == "max_commands_per_session"
               for e in events)
    assert sum(1 for e in events if e["message"] == "Session summary") == 1
    assert hooks.get_budget().open_sessions() == 0
    assert ssh_module.llm_sessions == {}  # chat history freed on close


async def test_ssh_concurrency_cap_refuses_without_model(ssh_runtime, ssh_module):
    _set_budget(max_concurrent_sessions_per_ip=0)
    history = CountingHistory()
    ssh_module.with_message_history = history
    server, port = await _serve(ssh_module)
    try:
        async with asyncssh.connect("127.0.0.1", port=port, username="root", password="x",
                                    known_hosts=None) as conn:
            result = await asyncio.wait_for(conn.run("id"), timeout=5)
    finally:
        server.close()
        await server.wait_closed()
    assert history.calls == []
    assert "Connection reset" in result.stdout


async def test_ssh_idle_timeout_frees_the_slot(ssh_runtime, ssh_module):
    _set_budget()
    ssh_module.config["ssh"]["idle_timeout"] = "0.3"
    history = CountingHistory()
    ssh_module.with_message_history = history
    server, port = await _serve(ssh_module)
    try:
        async with asyncssh.connect("127.0.0.1", port=port, username="root", password="x",
                                    known_hosts=None) as conn:
            proc = await conn.create_process(term_type="xterm")
            out = await asyncio.wait_for(proc.stdout.read(), timeout=5)  # sends nothing
    finally:
        server.close()
        await server.wait_closed()
    assert "auto-logout" in out
    for h in ssh_module.logger.handlers:
        h.flush()
    assert any(e["message"] == "Session timeout" and e["reason"] == "idle"
               for e in _events(ssh_runtime))
    assert hooks.get_budget().open_sessions() == 0
    assert ssh_module.llm_sessions == {}


async def test_ssh_absolute_session_timeout(ssh_runtime, ssh_module):
    _set_budget()
    ssh_module.config["ssh"]["idle_timeout"] = "10"
    ssh_module.config["ssh"]["session_timeout"] = "0.5"
    ssh_module.with_message_history = CountingHistory()
    server, port = await _serve(ssh_module)
    try:
        async with asyncssh.connect("127.0.0.1", port=port, username="root", password="x",
                                    known_hosts=None) as conn:
            proc = await conn.create_process(term_type="xterm")

            async def chatter():
                for _ in range(50):
                    proc.stdin.write("ls\n")
                    await asyncio.sleep(0.1)

            task = asyncio.create_task(chatter())
            out = await asyncio.wait_for(proc.stdout.read(), timeout=5)
            task.cancel()
    finally:
        server.close()
        await server.wait_closed()
    assert "auto-logout" in out
    for h in ssh_module.logger.handlers:
        h.flush()
    assert any(e["message"] == "Session timeout" and e["reason"] == "session"
               for e in _events(ssh_runtime))


# ---- provider failures degrade to canned shell replies ------------------------------------

class FailingHistory:
    def __init__(self):
        self.calls = 0

    async def ainvoke(self, payload, config=None):
        self.calls += 1
        raise ConnectionError("provider unreachable")


async def test_provider_error_keeps_session_alive_with_canned_replies(ssh_runtime, ssh_module):
    _set_budget()
    history = FailingHistory()
    ssh_module.with_message_history = history
    server, port = await _serve(ssh_module)
    try:
        async with asyncssh.connect("127.0.0.1", port=port, username="root", password="x",
                                    known_hosts=None) as conn:
            result = await asyncio.wait_for(conn.run("wget http://198.51.100.9/x"), timeout=5)
            proc = await conn.create_process(term_type="xterm")
            proc.stdin.write("whoami\n")
            proc.stdin.write_eof()
            out = await asyncio.wait_for(proc.stdout.read(), timeout=5)
    finally:
        server.close()
        await server.wait_closed()
    assert result.stdout.startswith("--") and result.stdout.endswith(
        "--  http://198.51.100.9/x\nConnecting to 198.51.100.9:80... failed: "
        "Network is unreachable.\n")
    assert "root@" in out and "whoami\r\nroot\r" in out      # whoami from the host profile
    for h in ssh_module.logger.handlers:
        h.flush()
    events = _events(ssh_runtime)
    assert any(e["message"] == "Model error" and e["error"] == "ConnectionError" for e in events)
    assert sum(1 for e in events if e["message"] == "Session summary") == 2   # one per session


def test_missing_provider_key_runs_persona_offline(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cp = ConfigParser()
    cp["llm"] = {"llm_provider": "anthropic"}
    hooks.init_runtime(cp, None, str(tmp_path))
    assert hooks._offline_reason == "ANTHROPIC_API_KEY not set"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    hooks.init_runtime(cp, None, str(tmp_path))
    assert hooks._offline_reason is None


async def test_offline_persona_never_calls_the_model():
    _set_budget()
    hooks.set_offline("no key")
    history = CountingHistory()
    r = await _call(history, text="cat /etc/passwd")
    assert history.calls == [] and r.content.startswith("root:x:0:0:root:/root:/bin/bash\r\n")
    r = await _call(history, text="frobnicate")
    assert r.content.startswith("-bash: frobnicate: command not found")
    assert (await _call(history, text="exit")).content == "YYY-END-OF-SESSION-YYY"


async def test_offline_canned_replies_do_not_charge_token_budgets():
    budget = _set_budget(max_tokens_per_session=CAP, max_tokens_per_ip_per_day=CAP,
                         max_tokens_per_day=CAP)
    hooks.set_offline("no key")
    history = CountingHistory()
    for i in range(50):
        r = await _call(history, text=f"cmd{i}")
        assert not getattr(r, "budget_exceeded", False)
        assert r.content.startswith(f"-bash: cmd{i}: command not found")
    assert history.calls == []
    assert budget.global_tokens == 0 and budget.ip_tokens("203.0.113.1") == 0
    r = await hooks.summary_invoke(history, session_id="s1", src_ip="203.0.113.1",
                                   username="root", prompt="Examine the list",
                                   llm_config={})
    assert r.content == SUMMARY_SKIPPED and history.calls == []
    assert budget.global_tokens == 0


async def test_offline_canned_replies_still_count_commands_per_session():
    _set_budget(max_commands_per_session=3)
    hooks.set_offline("no key")
    history = CountingHistory()
    for _ in range(3):
        assert not getattr(await _call(history), "budget_exceeded", False)
    r = await _call(history)
    assert r.budget_exceeded and r.content == CANNED_INTERACTIVE
    assert history.calls == []


@pytest.mark.parametrize("text,at_least", [
    ("文" * 1000, 1000),          # CJK: a tokenizer spends about one token per character or more
    ("ж" * 1000, 500),           # Cyrillic
    ("\U0001F600" * 100, 100),        # emoji
    ("a" * 1000, 250),                # ASCII keeps the four-characters-per-token estimate
], ids=["cjk", "cyrillic", "emoji", "ascii"])
def test_token_estimate_is_not_below_real_usage_for_non_ascii_text(text, at_least):
    from agents.budget import estimate_text_tokens

    assert estimate_text_tokens(text) >= at_least
    assert estimate_text_tokens("a" * 1000) == 250


def test_session_budget_charges_non_ascii_history_by_weight(tmp_path):
    from agents.budget import Budget, BudgetConfig

    b = Budget(BudgetConfig(state_file=str(tmp_path / "b.json"), max_tokens_per_session=1500))
    reason, _ = b.reserve("s1", "203.0.113.5", "a" * 1200, True)
    assert reason is None                       # 1,200 ASCII characters: about 300 tokens
    reason, _ = b.reserve("s2", "203.0.113.5", "\u6587" * 1200, True)
    assert reason is not None                   # 1,200 CJK characters exceed 1,500 tokens


# ---- atomic reservation across processes -----------------------------------------------------

# Each child builds its Budget (so its view of the day is already loaded and empty), then
# reports "ready" immediately before it asks for the exclusive lock and prints its result.
_RESERVE_WORKER = """
import fcntl, json, sys
import agents.budget as budget_module
from agents.budget import Budget, BudgetConfig

state_file, ip, sid, limits = sys.argv[1:5]
budget = Budget(BudgetConfig(state_file=state_file, **json.loads(limits)))
real_flock = fcntl.flock

def flock(handle, operation):
    if operation & fcntl.LOCK_EX:
        print("ready", flush=True)
    return real_flock(handle, operation)

fcntl.flock = flock
reason, res = budget.reserve(sid, ip, "ls")
print(json.dumps({"reason": reason, "tokens": res.tokens if res else None,
                  "commands": budget._sessions[sid].commands,
                  "session_tokens": budget._sessions[sid].tokens}), flush=True)
"""

ONE_RESERVATION = 1 + OUTPUT_ESTIMATE_TOKENS    # "ls" with an empty history
WAIT = 30                                       # seconds any step may take


def _contend(tmp_path, limits, ips):
    """Two processes reserve against one state file while the parent holds the sidecar lock.

    The parent takes the exclusive lock first and releases it only after both children have
    said they are about to ask for it, so both decide from a view loaded before either
    charge. Returns the state file and each child's result."""
    import fcntl
    import select
    import subprocess
    import sys
    import time
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    state = tmp_path / "budget_state.json"
    procs = []
    try:
        with open(str(state) + ".lock", "a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            for i, ip in enumerate(ips):
                procs.append(subprocess.Popen(
                    [sys.executable, "-c", _RESERVE_WORKER, str(state), ip, f"s{i}",
                     json.dumps(limits)],
                    cwd=root, stdout=subprocess.PIPE, text=True))
            deadline = time.monotonic() + WAIT
            for proc in procs:
                ready, _, _ = select.select([proc.stdout], [], [], max(0, deadline - time.monotonic()))
                assert ready, "a child never reached the lock"
                assert proc.stdout.readline().strip() == "ready"
            assert not state.exists(), "nothing may be decided before the lock is released"
        results = []                                    # lock released with the file closed
        for proc in procs:
            out, _ = proc.communicate(timeout=WAIT)
            assert proc.returncode == 0
            results.append(json.loads(out.strip().splitlines()[-1]))
        return state, results
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.kill()
            proc.communicate()


def _one_winner(results, reason):
    won = [r for r in results if r["reason"] is None]
    lost = [r for r in results if r["reason"] is not None]
    assert len(won) == 1 and len(lost) == 1 and lost[0]["reason"] == reason
    # The rejected request took neither tokens nor command allowance.
    assert lost[0]["tokens"] is None and lost[0]["commands"] == 0 and lost[0]["session_tokens"] == 0
    assert won[0]["commands"] == 1 and won[0]["session_tokens"] == ONE_RESERVATION


def test_two_processes_cannot_both_take_the_last_of_the_global_cap(tmp_path):
    state, results = _contend(tmp_path, {"max_tokens_per_day": ONE_RESERVATION + 100},
                              ["203.0.113.1", "203.0.113.2"])        # different sources
    _one_winner(results, "max_tokens_per_day")
    assert json.loads(state.read_text())["global_tokens"] == ONE_RESERVATION


def test_two_processes_cannot_both_take_the_last_of_a_source_cap(tmp_path):
    state, results = _contend(tmp_path, {"max_tokens_per_ip_per_day": ONE_RESERVATION + 100},
                              ["203.0.113.7", "203.0.113.7"])        # one shared source
    _one_winner(results, "max_tokens_per_ip_per_day")
    saved = json.loads(state.read_text())
    assert saved["global_tokens"] == ONE_RESERVATION
    assert saved["ip_tokens"] == {"203.0.113.7": ONE_RESERVATION}


def test_different_sources_do_not_share_a_source_cap(tmp_path):
    state, results = _contend(tmp_path, {"max_tokens_per_ip_per_day": ONE_RESERVATION + 100},
                              ["203.0.113.7", "203.0.113.8"])
    assert [r["reason"] for r in results] == [None, None]
    assert json.loads(state.read_text())["global_tokens"] == 2 * ONE_RESERVATION


def _break_replace(monkeypatch):
    import agents.budget as budget_module

    def fail(src, dst):
        raise PermissionError(13, "replace refused")

    monkeypatch.setattr(budget_module.os, "replace", fail)


def test_a_failed_atomic_replace_keeps_accepted_usage_and_leaves_no_temp_file(
        tmp_path, monkeypatch, caplog):
    state = tmp_path / "budget_state.json"
    budget = Budget(BudgetConfig(state_file=str(state), max_tokens_per_day=2 * ONE_RESERVATION + 10))
    _break_replace(monkeypatch)
    caplog.set_level("ERROR")
    assert budget.reserve("a", "203.0.113.1", "ls")[0] is None
    assert any("BUDGET STATE NOT PERSISTED" in r.getMessage() for r in caplog.records)
    assert not state.exists() and list(tmp_path.glob(".budget-*")) == []   # no temp file left
    # The lock opens and the file can be read again, yet the accepted charge is not forgotten:
    assert budget.reserve("b", "203.0.113.2", "ls")[0] is None
    assert budget.reserve("c", "203.0.113.3", "ls")[0] == "max_tokens_per_day"
    assert budget.global_tokens == 2 * ONE_RESERVATION
    assert list(tmp_path.glob(".budget-*")) == []


def test_unsaved_usage_is_added_back_to_an_older_file_once_writing_recovers(
        tmp_path, monkeypatch):
    state = tmp_path / "budget_state.json"
    budget = Budget(BudgetConfig(state_file=str(state)))
    other = Budget(BudgetConfig(state_file=str(state)))
    assert other.reserve("o", "203.0.113.9", "ls")[0] is None            # on disk
    with monkeypatch.context() as m:
        _break_replace(m)
        assert budget.reserve("a", "203.0.113.1", "ls")[0] is None       # accepted, unsaved
        assert budget.reserve("b", "203.0.113.1", "ls")[0] is None
    assert json.loads(state.read_text())["global_tokens"] == ONE_RESERVATION
    assert budget.reserve("c", "203.0.113.2", "ls")[0] is None           # writes recover
    saved = json.loads(state.read_text())
    assert saved["global_tokens"] == 4 * ONE_RESERVATION
    assert saved["ip_tokens"] == {"203.0.113.9": ONE_RESERVATION,
                                  "203.0.113.1": 2 * ONE_RESERVATION,
                                  "203.0.113.2": ONE_RESERVATION}
    assert list(tmp_path.glob(".budget-*")) == []


def test_reconciliation_survives_a_failed_write_too(tmp_path, monkeypatch):
    state = tmp_path / "budget_state.json"
    budget = Budget(BudgetConfig(state_file=str(state)))
    reason, res = budget.reserve("s", "203.0.113.1", "ls")
    with monkeypatch.context() as m:
        _break_replace(m)
        assert budget.commit(res, "ls", "out", usage_tokens=40) == 40    # -473 not saved
    assert budget.global_tokens == 40
    assert budget.reserve("t", "203.0.113.1", "ls")[0] is None           # reload + unsaved
    assert json.loads(state.read_text())["global_tokens"] == 40 + ONE_RESERVATION


def test_rejected_reservation_charges_nothing_in_process(tmp_path):
    state = tmp_path / "budget_state.json"
    config = BudgetConfig(state_file=str(state), max_tokens_per_day=ONE_RESERVATION + 100)
    a, b = Budget(config), Budget(config)
    assert a.reserve("a", "203.0.113.1", "ls")[0] is None
    before = state.read_text()
    reason, res = b.reserve("b", "203.0.113.2", "ls")     # b loaded its view before a charged
    assert (reason, res) == ("max_tokens_per_day", None)
    assert b._sessions["b"].tokens == 0 and b._sessions["b"].commands == 0
    assert state.read_text() == before                      # a refusal writes nothing
    assert b.global_tokens == ONE_RESERVATION               # but it did see the other's spend


def test_reservation_and_reconciliation_persist_across_restart(tmp_path):
    state = tmp_path / "budget_state.json"
    budget = Budget(BudgetConfig(state_file=str(state)))
    reason, res = budget.reserve("s", "203.0.113.1", "ls")
    assert reason is None and res.tokens == ONE_RESERVATION
    assert json.loads(state.read_text())["global_tokens"] == ONE_RESERVATION
    assert Budget(BudgetConfig(state_file=str(state))).global_tokens == ONE_RESERVATION
    assert budget.commit(res, "ls", "file1\n", usage_tokens=40) == 40
    restarted = Budget(BudgetConfig(state_file=str(state)))
    assert restarted.global_tokens == 40 and restarted.ip_tokens("203.0.113.1") == 40
    assert json.loads(state.read_text())["ip_tokens"] == {"203.0.113.1": 40}


def test_new_day_resets_counters_before_the_cap_is_checked(tmp_path):
    state = tmp_path / "budget_state.json"
    state.write_text(json.dumps({"day": "2000-01-01", "global_tokens": 10**9,
                                 "ip_tokens": {"203.0.113.1": 10**9}}))
    budget = Budget(BudgetConfig(state_file=str(state)))
    assert budget.reserve("s", "203.0.113.1", "ls")[0] is None
    assert json.loads(state.read_text())["global_tokens"] == ONE_RESERVATION


def test_unwritable_state_still_enforces_caps_in_memory(tmp_path):
    ro = tmp_path / "ro"
    ro.mkdir()
    os.chmod(ro, stat.S_IRUSR | stat.S_IXUSR)
    try:
        budget = Budget(BudgetConfig(state_file=str(ro / "budget_state.json"),
                                     max_tokens_per_day=ONE_RESERVATION + 100))
        assert budget.reserve("a", "203.0.113.1", "ls")[0] is None
        assert budget.global_tokens == ONE_RESERVATION        # charged once, not twice
        assert budget.reserve("b", "203.0.113.2", "ls")[0] == "max_tokens_per_day"
    finally:
        os.chmod(ro, stat.S_IRWXU)
