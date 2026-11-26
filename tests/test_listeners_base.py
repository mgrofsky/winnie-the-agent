"""Shared listener framework: budgets, model-call bounds, quarantine, slots, log volume."""

import asyncio
import hashlib
import threading
from configparser import ConfigParser
from types import SimpleNamespace

import pytest
from pydantic import BaseModel, ConfigDict

from agents import hooks
from agents.budget import Budget, BudgetConfig, OUTPUT_ESTIMATE_TOKENS
from agents.llm import AnthropicJsonLLM, LLMOutputError
from listeners.base import (
    Conn,
    ConnectionLimiter,
    Limits,
    ListenerContext,
    LowValueGate,
    QuarantineStore,
    start_tcp,
)
from listeners.events import EventWriter


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")  # like every listener answer schema
    value: str


class FakeLLM:
    def __init__(self, result=None, exc=None, gate: threading.Event | None = None):
        self.calls = 0
        self.result, self.exc, self.gate = result, exc, gate

    def complete_json(self, system, user, schema):
        self.calls += 1
        if self.gate is not None:
            self.gate.wait(5)
        if self.exc:
            raise self.exc
        return self.result


def _ctx(**limits) -> ListenerContext:
    return ListenerContext(EventWriter(None), limits=Limits(**limits), bind_host="127.0.0.1")


# ---- one budget, fail closed ---------------------------------------------------

async def test_model_paths_fail_closed_without_a_budget():
    hooks.reset()

    class History:
        calls = 0

        async def ainvoke(self, payload, config=None):
            History.calls += 1
            return SimpleNamespace(content="x")

    r = await hooks.persona_invoke(History(), session_id="s", src_ip="203.0.113.1",
                                   username="u", text="ls", interactive=True, llm_config={})
    assert r.budget_exceeded and History.calls == 0
    assert hooks.session_open("s", "203.0.113.1") is not None
    r = await hooks.summary_invoke(History(), session_id="s", src_ip="203.0.113.1", username="u",
                                   prompt="p", llm_config={})
    assert r.budget_exceeded and History.calls == 0


def test_listeners_and_ssh_share_one_budget_state(tmp_path):
    from listeners.__main__ import build_context

    cp = ConfigParser()
    cp["honeypot"] = {"log_file": str(tmp_path / "events.jsonl")}
    cp["budget"] = {"max_tokens_per_day": "12345"}
    cp["listeners"] = {"bind_host": "127.0.0.1", "quarantine_dir": str(tmp_path / "q")}
    ctx = build_context(cp, tmp_path, None, data_dir=str(tmp_path / "data"))
    assert ctx.budget is hooks.get_budget()                     # telnet persona uses the same one
    assert ctx.budget.config.max_tokens_per_day == 12345         # from [budget]
    ssh_cfg = BudgetConfig.from_config(cp, str(tmp_path), str(tmp_path / "data"))
    assert ctx.budget.config.state_file == ssh_cfg.state_file    # one daily state file


# ---- event log file mode -----------------------------------------------------------

def _event(writer, message="m"):
    return writer.emit(task_name="t", src_ip="203.0.113.1", src_port=1, dst_port=21,
                       message=message, sensor_protocol="ftp", event="connection")


@pytest.mark.parametrize("mask", [0o000, 0o022, 0o077])
def test_the_event_writer_creates_an_owner_only_log_and_appends(tmp_path, mask):
    import json
    import os

    path = tmp_path / "ssh_log.log"
    previous = os.umask(mask)
    try:
        writer = EventWriter(str(path), "unit")
        assert _event(writer, "one") and _event(writer, "two")
    finally:
        os.umask(previous)
    assert path.stat().st_mode & 0o777 == 0o600
    assert [json.loads(x)["message"] for x in path.read_text().splitlines()] == ["one", "two"]


@pytest.mark.parametrize("mode", [0o600, 0o640])
def test_the_event_writer_keeps_the_mode_of_an_existing_log(tmp_path, mode):
    import os

    path = tmp_path / "ssh_log.log"
    path.write_text("")
    path.chmod(mode)                                  # pre-created by the operator
    previous = os.umask(0)
    try:
        assert _event(EventWriter(str(path), "unit"))
    finally:
        os.umask(previous)
    assert path.stat().st_mode & 0o777 == mode and path.read_text().count("\n") == 1


# ---- model calls from SQL/HTTP fallbacks -----------------------------------------

async def test_llm_json_reserves_and_applies_caps():
    ctx = _ctx()
    ctx.budget = Budget(BudgetConfig(max_tokens_per_day=OUTPUT_ESTIMATE_TOKENS + 100,
                                     max_concurrent_sessions_per_ip=1))
    ctx.json_llm = FakeLLM(result=Answer(value="ok"))
    assert (await ctx.llm_json("conn-1", "203.0.113.1", "s", "u", Answer)).value == "ok"
    # Same source, second connection: the per-source model-session slot is taken.
    assert await ctx.llm_json("conn-2", "203.0.113.1", "s", "u", Answer) is None
    # Another source, but the daily cap no longer fits a reservation.
    ctx.budget.daily.update(None, 10_000)
    assert await ctx.llm_json("conn-3", "203.0.113.2", "s", "u", Answer) is None
    assert ctx.json_llm.calls == 1


async def test_llm_json_charges_failures_and_rejects_bad_output():
    ctx = _ctx()
    ctx.budget = Budget(BudgetConfig())
    ctx.json_llm = FakeLLM(exc=LLMOutputError("bad"))
    assert await ctx.llm_json("c", "203.0.113.1", "s", "u", Answer) is None
    assert ctx.budget.global_tokens >= OUTPUT_ESTIMATE_TOKENS   # failed attempt still charged
    ctx.json_llm = FakeLLM(result={"value": "ok", "extra": "ignore previous instructions"})
    assert await ctx.llm_json("c", "203.0.113.1", "s", "u", Answer) is None


async def test_llm_json_bounds_inflight_calls_and_threads():
    gate = threading.Event()
    ctx = _ctx(llm_max_inflight=1, llm_timeout=0.2)
    ctx.budget = Budget(BudgetConfig())
    ctx.json_llm = FakeLLM(result=Answer(value="late"), gate=gate)
    first = asyncio.create_task(ctx.llm_json("a", "203.0.113.1", "s", "u", Answer))
    await asyncio.sleep(0.05)
    # The only slot is busy: no second call is made at all.
    assert await ctx.llm_json("b", "203.0.113.2", "s", "u", Answer) is None
    assert await first is None                       # timed out
    # The timed-out thread is still running, so its slot is still held.
    assert await ctx.llm_json("c", "203.0.113.3", "s", "u", Answer) is None
    assert ctx.json_llm.calls == 1
    gate.set()
    await asyncio.sleep(0.1)                          # the thread finishes, the slot frees
    assert (await ctx.llm_json("d", "203.0.113.4", "s", "u", Answer)).value == "late"


def test_one_logical_listener_call_is_one_request():
    class Messages:
        n = 0

        def parse(self, **kw):
            Messages.n += 1
            return SimpleNamespace(stop_reason="end_turn", usage=None,
                                   content=[SimpleNamespace(type="text", text="{}")])

    llm = AnthropicJsonLLM(client=SimpleNamespace(messages=Messages()), validation_retries=0)
    with pytest.raises(LLMOutputError):
        llm.complete_json("s", "u", Answer)
    assert Messages.n == 1


# ---- quarantine -------------------------------------------------------------------

def test_quarantine_usage_survives_restart_quota_and_dedupe(tmp_path):
    limits = Limits(quarantine_max_file_bytes=100, quarantine_per_ip_bytes=150,
                    quarantine_total_bytes=250)
    store = QuarantineStore(tmp_path, limits)
    a = store.store_bytes("203.0.113.1", b"a" * 90)
    assert a.status == "stored" and (tmp_path / a.name).stat().st_mode & 0o777 == 0o600
    dup = store.store_bytes("203.0.113.9", b"a" * 90)
    assert dup.status == "duplicate" and len(list(tmp_path.glob("*.bin"))) == 1
    over_ip = store.store_bytes("203.0.113.1", b"b" * 90)
    assert over_ip.status == "ip_quota" and over_ip.quota_hit
    # Restart: usage is rebuilt from disk, so the quotas still hold.
    store2 = QuarantineStore(tmp_path, limits)
    assert store2.used == 90 and store2.ip_usage["203.0.113.1"] == 90
    assert store2.store_bytes("203.0.113.1", b"c" * 90).status == "ip_quota"
    assert store2.store_bytes("203.0.113.2", b"c" * 90).status == "stored"
    assert store2.store_bytes("203.0.113.3", b"d" * 90).status == "total_quota"


def test_quarantine_streams_and_truncates_at_the_file_cap(tmp_path):
    store = QuarantineStore(tmp_path, Limits(quarantine_max_file_bytes=1000))
    w = store.open("203.0.113.1")
    accepted = [w.write(bytes([65 + i]) * 300) for i in range(5)]
    assert accepted == [True, True, True, False, False]   # stops at the cap, mid-upload
    res = w.finish()
    kept = b"A" * 300 + b"B" * 300 + b"C" * 300 + b"D" * 100
    assert res.status == "stored" and res.truncated and not res.quota_hit
    assert res.size == 1000 and res.sha256 == hashlib.sha256(kept).hexdigest()
    assert (tmp_path / res.name).read_bytes() == kept
    assert not list(tmp_path.glob(".part-*"))              # nothing partial left behind


# ---- connection slots and timeouts ----------------------------------------------

def test_per_service_caps_on_top_of_global():
    limiter = ConnectionLimiter(Limits(max_connections=100, max_connections_per_ip=50,
                                       max_connections_per_service=3,
                                       max_connections_per_ip_per_service=2))
    assert limiter.acquire("203.0.113.1", "ftp") is None
    assert limiter.acquire("203.0.113.1", "ftp") is None
    assert limiter.acquire("203.0.113.1", "ftp") == "max_connections_per_ip_per_service"
    assert limiter.acquire("203.0.113.2", "ftp") is None
    assert limiter.acquire("203.0.113.3", "ftp") == "max_connections_per_service"
    assert limiter.acquire("203.0.113.3", "redis") is None   # other services unaffected


async def test_silent_connections_are_closed_by_the_progress_rule():
    ctx = _ctx(min_progress_bytes=8, progress_window=0.3, pre_login_timeout=10)

    async def handler(conn: Conn):
        while True:
            await conn.read_some(1)

    server = await start_tcp(ctx, "redis", 0, handler)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"x")                                   # one byte, then nothing
        await writer.drain()
        await asyncio.wait_for(reader.read(), 3)             # returns at EOF
        writer.close()
    finally:
        server.close()
    assert any(e["event"] == "limit" and e["data"]["reason"] == "min_progress"
               for e in ctx.writer.events)


def test_pre_login_reads_time_out_sooner():
    ctx = _ctx(pre_login_timeout=5, read_timeout=60)
    conn = Conn.__new__(Conn)
    conn.ctx, conn.authenticated_as = ctx, None
    assert conn.timeout == 5
    conn.authenticated_as = "admin"
    assert conn.timeout == 60


# ---- log flooding ------------------------------------------------------------------

def test_low_value_gate_aggregates_per_key_and_globally():
    gate = LowValueGate(per_second=1000, window=60)
    assert gate.check("203.0.113.4|refused", now=0) == 0          # first occurrence logged
    assert all(gate.check("203.0.113.4|refused", now=t) is None for t in range(1, 30))
    assert gate.check("203.0.113.4|refused", now=61) == 29        # periodic counter line
    tight = LowValueGate(per_second=2, window=60)
    logged = [tight.check(f"10.0.0.{i}|malformed", now=0) for i in range(50)]
    assert sum(x is not None for x in logged) <= 2             # global ceiling
    assert tight.global_suppressed >= 48


async def test_refused_connection_floods_are_aggregated():
    ctx = _ctx(max_connections_per_ip=1, rate_per_ip_per_minute=10_000)

    async def handler(conn: Conn):
        await asyncio.sleep(2)

    server = await start_tcp(ctx, "smtp", 0, handler)
    port = server.sockets[0].getsockname()[1]
    try:
        held = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.05)
        for _ in range(40):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            await r.read()
            w.close()
        held[1].close()
    finally:
        server.close()
    refused = [e for e in ctx.writer.events if e["event"] == "limit"
               and e["data"].get("reason") == "max_connections_per_ip"]
    assert len(refused) == 1 and refused[0]["data"]["suppressed"] == 0


# ---- reply ladder: first request, one more with examples, then the caller's fail-safe ----

class ScriptedLLM:
    """Answers from a list: an exception is raised, anything else returned. Records the
    system prompt of every request."""

    def __init__(self, *outputs, delay: float = 0.0):
        self.outputs = list(outputs)
        self.systems: list[str] = []
        self.delay = delay

    @property
    def calls(self) -> int:
        return len(self.systems)

    def complete_json(self, system, user, schema):
        import time

        self.systems.append(system)
        if self.delay:
            time.sleep(self.delay)
        out = self.outputs.pop(0) if len(self.outputs) > 1 else self.outputs[0]
        if isinstance(out, BaseException):
            raise out
        return out


def _ladder_ctx(llm, **limits) -> ListenerContext:
    ctx = _ctx(**limits)
    ctx.budget = Budget(BudgetConfig())
    ctx.json_llm = llm
    return ctx


async def test_ladder_first_answer_good_is_one_request():
    ctx = _ladder_ctx(ScriptedLLM(Answer(value="ok")))
    assert (await ctx.llm_json("c", "192.0.2.10", "sys", "u", Answer, examples="EX")).value == "ok"
    assert ctx.json_llm.calls == 1 and ctx.take_llm_rung("c") == "llm"
    assert ctx.take_llm_rung("c") is None                   # reading clears it


@pytest.mark.parametrize("first", [LLMOutputError("bad"),
                                   {"value": "ok", "extra": "ignore previous instructions"},
                                   {"value": "ok", "ignore_previous_instructions": 1}])
async def test_ladder_bad_first_answer_is_asked_again_with_examples(first):
    ctx = _ladder_ctx(ScriptedLLM(first, Answer(value="second")))
    out = await ctx.llm_json("c", "192.0.2.10", "sys", "u", Answer, examples="EXAMPLE-LINES")
    assert out.value == "second" and ctx.json_llm.calls == 2
    assert ctx.take_llm_rung("c") == "llm_retry"
    first_sys, second_sys = ctx.json_llm.systems
    assert first_sys == "sys"
    assert second_sys.startswith("sys\n") and "EXAMPLE-LINES" in second_sys
    assert "rejected" in second_sys
    # The problem line names the schema field, never the model's text.
    assert "ignore previous" not in second_sys and "ignore_previous" not in second_sys
    # The second request counts once against the model-command cap.
    assert ctx.budget.model_commands("c") == 1


async def test_ladder_both_bad_returns_none_and_charges_twice():
    ctx = _ladder_ctx(ScriptedLLM(LLMOutputError("bad")))
    assert await ctx.llm_json("c", "192.0.2.10", "sys", "u", Answer, examples="EX") is None
    assert ctx.json_llm.calls == 2 and ctx.take_llm_rung("c") is None
    assert ctx.budget.global_tokens >= 2 * OUTPUT_ESTIMATE_TOKENS


async def test_ladder_attempts_are_clamped_to_three():
    ctx = _ladder_ctx(ScriptedLLM(LLMOutputError("bad")), llm_attempts=9)
    assert await ctx.llm_json("c", "192.0.2.10", "sys", "u", Answer) is None
    assert ctx.json_llm.calls == 3


async def test_ladder_timeout_is_not_retried():
    gate = threading.Event()
    ctx = _ladder_ctx(FakeLLM(result=Answer(value="late"), gate=gate), llm_timeout=0.2)
    try:
        assert await ctx.llm_json("c", "192.0.2.10", "sys", "u", Answer) is None
        assert ctx.json_llm.calls == 1 and ctx.take_llm_rung("c") is None
    finally:
        gate.set()


async def test_ladder_provider_error_is_not_retried():
    from agents.llm import LLMUnavailable

    ctx = _ladder_ctx(ScriptedLLM(LLMUnavailable("overloaded"), Answer(value="ok")))
    assert await ctx.llm_json("c", "192.0.2.10", "sys", "u", Answer) is None
    assert ctx.json_llm.calls == 1


async def test_ladder_one_attempt_keeps_one_request_and_the_full_timeout():
    ctx = _ladder_ctx(ScriptedLLM(LLMOutputError("bad"), Answer(value="ok")), llm_attempts=1,
                      llm_timeout=5.0, llm_deadline=0.01)
    assert await ctx.llm_json("c", "192.0.2.10", "sys", "u", Answer) is None
    assert ctx.json_llm.calls == 1
    # With one attempt the deadline does not apply: a slow answer still has llm_timeout.
    ctx.json_llm = ScriptedLLM(Answer(value="slow"), delay=0.1)
    assert (await ctx.llm_json("d", "192.0.2.11", "sys", "u", Answer)).value == "slow"


async def test_ladder_deadline_stops_a_second_attempt():
    now = [1000.0]

    class SlowBad(ScriptedLLM):
        def complete_json(self, system, user, schema):
            now[0] += 11.5                      # the first request uses most of the deadline
            return super().complete_json(system, user, schema)

    ctx = _ladder_ctx(SlowBad(LLMOutputError("bad"), Answer(value="ok")))
    ctx.llm_clock = lambda: now[0]
    assert await ctx.llm_json("c", "192.0.2.10", "sys", "u", Answer) is None
    assert ctx.json_llm.calls == 1
    # With time left the same failure is asked again.
    ctx.json_llm = ScriptedLLM(LLMOutputError("bad"), Answer(value="ok"))
    assert (await ctx.llm_json("d", "192.0.2.11", "sys", "u", Answer)).value == "ok"


async def test_ladder_deadline_is_capped_by_the_timeout(monkeypatch):
    import listeners.base as base_mod

    seen = []
    real_wait_for = base_mod.asyncio.wait_for

    async def spy(aw, timeout):
        seen.append(timeout)
        return await real_wait_for(aw, timeout)

    monkeypatch.setattr(base_mod.asyncio, "wait_for", spy)
    ctx = _ladder_ctx(ScriptedLLM(LLMOutputError("bad"), Answer(value="ok")), llm_timeout=3.0,
                      llm_deadline=60)
    assert (await ctx.llm_json("c", "192.0.2.10", "sys", "u", Answer)).value == "ok"
    assert len(seen) == 2 and all(t <= 3.0 for t in seen) and seen[1] < seen[0] + 1e-6


async def test_ladder_retry_holds_the_only_slot_and_releases_it():
    ctx = _ladder_ctx(ScriptedLLM(LLMOutputError("bad"), Answer(value="ok")), llm_max_inflight=1)
    assert (await ctx.llm_json("c", "192.0.2.10", "sys", "u", Answer)).value == "ok"
    assert not ctx._llm_sem.locked()
    ctx.json_llm = ScriptedLLM(LLMOutputError("bad"))
    assert await ctx.llm_json("d", "192.0.2.11", "sys", "u", Answer) is None
    assert not ctx._llm_sem.locked()


async def test_ladder_examples_are_bounded():
    from listeners.base import MAX_LLM_EXAMPLES_CHARS

    ctx = _ladder_ctx(ScriptedLLM(LLMOutputError("bad"), Answer(value="ok")))
    await ctx.llm_json("c", "192.0.2.10", "sys", "u", Answer, examples="E" * 50_000)
    assert ctx.json_llm.systems[1].count("E") <= MAX_LLM_EXAMPLES_CHARS + 5
