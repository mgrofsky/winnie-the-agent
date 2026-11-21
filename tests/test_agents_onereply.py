"""One model reply per input line: the cut (agents.onereply) and where persona_invoke uses it."""

from __future__ import annotations

import json
import logging
import time
from types import SimpleNamespace

import pytest

from agents import hooks, onereply
from agents.budget import Budget, BudgetConfig
from agents.replycache import ReplyCache
from agents.sessions import parse_log
from agents.ui import activity

HOST = "srv01"
PROMPT = "root@srv01:~# "
IP = "203.0.113.30"


def cut(reply, text="whoami", interactive=True, viewer=False, built=False,
        hosts=(HOST,), current=PROMPT, user="root"):
    return onereply.one_reply(reply, text, interactive=interactive, hosts=hosts,
                              current_prompt=current, user=user, viewer=viewer,
                              text_built_before=built)


# ---- the rule: replies that are cut -----------------------------------------------------------

CUT = [
    # (input, reply, interactive, kept, reason)
    ("whoami", "root\nroot@srv01:~# ls\nbin  etc  notes.txt\nroot@srv01:~# ", True,
     "root\nroot@srv01:~# ", "next_command"),
    ("whoami", "root\r\nroot@srv01:~# ls\r\nbin\r\nroot@srv01:~# ", True,
     "root\r\nroot@srv01:~# ", "next_command"),
    # an invented command on the last line, nothing after it
    ("whoami", "root\nroot@srv01:~# ls", True, "root\nroot@srv01:~# ", "next_command"),
    # two bare prompts in a row
    ("whoami", "root\nroot@srv01:~# \nroot@srv01:~# ", True, "root\nroot@srv01:~# ",
     "extra_prompt"),
    # a prompt in the middle with nothing typed after it, then more output
    ("whoami", "root\nroot@srv01:~# \nbin  etc\nroot@srv01:~# ", True,
     "root\nroot@srv01:~# ", "extra_prompt"),
    # the attacker's own line echoed back, with and without a prompt in front
    ("whoami", "whoami\nroot\nroot@srv01:~# ", True, "root\nroot@srv01:~# ", "echo"),
    ("whoami", "root@srv01:~# whoami\r\nroot\r\nroot@srv01:~# ", True,
     "root\r\nroot@srv01:~# ", "echo"),
    # a reply that starts with a bare prompt
    ("whoami", "root@srv01:~# \nroot\nroot@srv01:~# ", True, "root\nroot@srv01:~# ", "echo"),
    # echo, then an invented round after the real one
    ("whoami", "root@srv01:~# whoami\nroot\nroot@srv01:~# id\nuid=0(root)\nroot@srv01:~# ", True,
     "root\nroot@srv01:~# ", "next_command"),
    # a reply that starts with an invented command: only the prompt is kept
    ("whoami", "root@srv01:~# ls\nbin\nroot@srv01:~# ", True, "root@srv01:~# ", "next_command"),
    # only the echoed line: kept as the prompt alone
    ("cd /tmp", "root@srv01:~# cd /tmp", True, "root@srv01:~# ", "next_command"),
    # cd moved the prompt; the invented round after it uses the new directory
    ("cd /tmp", "root@srv01:/tmp# ls\nx.sh\nroot@srv01:/tmp# ", True, "root@srv01:/tmp# ",
     "next_command"),
    # su changed the user
    ("su - deploy", "Last login: Mon Mar  2 09:14\ndeploy@srv01:~$ id\nuid=1001(deploy)\n"
     "deploy@srv01:~$ ", True, "Last login: Mon Mar  2 09:14\ndeploy@srv01:~$ ", "next_command"),
    # RHEL prompt
    ("whoami", "root\n[root@srv01 ~]# ls\nbin\n[root@srv01 ~]# ", True,
     "root\n[root@srv01 ~]# ", "next_command"),
    # coloured prompt
    ("whoami", "root\n\x1b[01;32mroot@srv01\x1b[00m:\x1b[01;34m~\x1b[00m# id\nuid=0\n"
     "\x1b[01;32mroot@srv01\x1b[00m:\x1b[01;34m~\x1b[00m# ", True,
     "root\n\x1b[01;32mroot@srv01\x1b[00m:\x1b[01;34m~\x1b[00m# ", "next_command"),
    # ssh to another box: its host is taken from the prompt the reply ends with
    ("ssh db02", "admin@db02's password: \nadmin@db02:~$ ls\nbackup.sql\nadmin@db02:~$ ", True,
     "admin@db02's password: \nadmin@db02:~$ ", "next_command"),
    # fenced reply with the echo inside the fence: the echo goes, the fence is left to
    # the fence stripper
    ("whoami", "```\nroot@srv01:~# whoami\nroot\nroot@srv01:~# \n```", True,
     "```\nroot\nroot@srv01:~# \n```", "echo"),
    # any host, when the prompt shows the session's own user
    ("uname -n", "build7\nroot@build7:~# id\nuid=0\nroot@srv01:~# ", True,
     "build7\nroot@build7:~# ", "next_command"),
    # exec: no prompt at all
    ("whoami", "root\nroot@srv01:~# ", False, "root\n", "prompt_in_exec"),
    ("whoami", "root\nroot@srv01:~# id\nuid=0(root)\n", False, "root\n", "next_command"),
    ("whoami", "whoami\nroot\n", False, "root\n", "echo"),
    # output without a newline runs into the prompt, as in a real shell
    ("printf root", "rootroot@srv01:~# ls\nbin\nroot@srv01:~# ", True,
     "rootroot@srv01:~# ", "next_command"),
    # the session opener (no input): an invented round after the MOTD
    ("", "Welcome to Ubuntu\nroot@srv01:~# uptime\n 10:00 up 3 days\nroot@srv01:~# ", True,
     "Welcome to Ubuntu\nroot@srv01:~# ", "next_command"),
]


@pytest.mark.parametrize("text,reply,interactive,kept,reason", CUT)
def test_reply_is_cut_to_one_round(text, reply, interactive, kept, reason):
    result = cut(reply, text, interactive=interactive)
    assert result is not None
    assert result.kept == kept
    assert result.reason == reason
    assert result.dropped == len(reply) - len(kept)


# ---- the rule: replies left whole ---------------------------------------------------------------

WHOLE = [
    # (input, reply, interactive, viewer, built)
    ("whoami", "root\nroot@srv01:~# ", True, False, False),
    ("whoami", "root\r\nroot@srv01:~# \r\n", True, False, False),
    ("whoami", "root@srv01:~# ", True, False, False),
    ("whoami", "root\n", False, False, False),
    ("logout", "YYY-END-OF-SESSION-YYY", True, False, False),
    # input that prints a prompt-shaped line itself
    ("echo 'root@srv01:~# id'", "root@srv01:~# id\nroot@srv01:~# ", True, False, False),
    ("echo $(whoami)", "root@srv01:~# id\nroot@srv01:~# ", True, False, False),
    ("printf 'root\\x40srv01:~# id'", "root@srv01:~# id\nroot@srv01:~# ", True, False, False),
    ("echo `id -un`", "root@srv01:~# \nroot@srv01:~# ", True, False, False),
    ("PS1='$USER@srv01:~# '", "root@srv01:~# \nroot@srv01:~# ", True, False, False),
    # file text that holds an old prompt from another directory
    ("cat /var/log/session.log", "root@srv01:/opt# make\nok\nroot@srv01:~# ", True, True, False),
    # any file text, once the session typed a line that could have written a prompt
    ("cat notes", "root@srv01:~# id\nuid=0\nroot@srv01:~# ", True, True, True),
    # a prompt for a host the session never showed
    ("last -f wtmp.txt", "admin@db02:~$ ls\nroot@srv01:~# ", True, False, False),
    # output that equals the input line, followed only by the prompt
    ("ls", "ls\nroot@srv01:/tmp# ", True, False, False),
    ("ls", "ls\n", False, False, False),
    # not a prompt shape: PS1 changed, heredoc continuation, history, a prompt mid-line
    ("PS1='> '", "> ", True, False, False),
    ("cat <<EOF", "> ", True, True, False),
    ("history", "    1  whoami\n    2  ls\nroot@srv01:~# ", True, False, False),
    ("whoami", "root\nroot@srv01:~#ls\nroot@srv01:~# ", True, False, False),
    # a script that prints a line ending in # or $
    ("cat run.sh", "#!/bin/sh\n# cleanup\nrm -f /tmp/x # done\nPRICE=5$\nroot@srv01:~# ",
     True, True, False),
    ("whoami", "", True, False, False),
]


@pytest.mark.parametrize("text,reply,interactive,viewer,built", WHOLE)
def test_reply_is_left_whole(text, reply, interactive, viewer, built):
    assert cut(reply, text, interactive=interactive, viewer=viewer, built=built) is None


def test_viewer_cuts_at_the_exact_current_prompt():
    reply = "line\nroot@srv01:~# ls\nbin\nroot@srv01:~# "
    assert cut(reply, "cat notes", viewer=True).kept == "line\nroot@srv01:~# "


def test_builds_text():
    for text in ("echo a@b", "echo $HOME", "echo ${x}", "echo $(id)", "echo `id`",
                 "printf '\\x41'", "printf %s"):
        assert onereply.builds_text(text), text
    for text in ("ls -la", "cat /etc/passwd", "awk '{print $4}' f", "uname -a; id"):
        assert not onereply.builds_text(text), text


def test_sample_is_short_and_escaped():
    reply = "root\nroot@srv01:~# " + "\x1b[31m" + "A" * 5000 + "\nroot@srv01:~# "
    result = cut(reply)
    assert len(result.sample) < 4 * onereply.MAX_SAMPLE
    assert "\x1b" not in result.sample and "\n" not in result.sample
    assert result.dropped == len(reply) - len(result.kept)


@pytest.mark.parametrize("hostile", [
    # many near-miss prompt prefixes, one per line
    ("a" * 31 + "@" + "b" * 63 + ":" + "/" * 256 + "\n") * 30_000,
    # one very long line
    "x" * 3_000_000,
    # a long run of blank lines between a leading bare prompt and its output
    PROMPT + "\n" * 300_000 + "root\n" + PROMPT,
    # many bare prompts in a row (each one ends the reply; only the first is looked at)
    (PROMPT + "\n") * 100_000 + "x",
    # colour codes without end in front of a prompt shape
    ("\x1b[" * 2000 + "root@srv01:~#x\n") * 200,
])
def test_long_hostile_reply_is_bounded(hostile):
    """Megabytes of hostile reply in well under the limit: a pass that went back over the
    reply per line would take minutes here."""
    start = time.perf_counter()
    cut(hostile)
    cut(hostile, interactive=False)
    assert time.perf_counter() - start < 5.0


# ---- persona_invoke --------------------------------------------------------------------------

class Chain:
    """Stands in for RunnableWithMessageHistory: answers from a table and, like it, adds
    the input and the reply to the session history."""

    def __init__(self, replies, default="ok\r\nroot@srv01:~# "):
        self.replies = replies
        self.default = default
        self.calls: list[str] = []
        self.store: dict = {}

    def get_session_history(self, session_id):
        from langchain_core.chat_history import InMemoryChatMessageHistory

        return self.store.setdefault(session_id, InMemoryChatMessageHistory())

    async def ainvoke(self, payload, config=None):
        from langchain_core.messages import AIMessage

        text = payload["messages"][-1].content
        self.calls.append(text)
        reply = self.replies.get(text, self.default)
        sid = config["configurable"]["session_id"]
        self.get_session_history(sid).add_messages([payload["messages"][-1],
                                                    AIMessage(content=reply)])
        return SimpleNamespace(content=reply, usage_metadata={"total_tokens": 50})


async def ask(chain, text, sid="s1", interactive=True, logger=None, counts=True):
    return await hooks.persona_invoke(chain, session_id=sid, src_ip=IP, username="root",
                                      text=text, interactive=interactive,
                                      llm_config={"configurable": {"session_id": sid}},
                                      logger=logger, log_extra={"task_name": sid},
                                      counts_as_command=counts)


INVENTED = "uid=0(root)\r\nroot@srv01:~# cat /etc/shadow\r\nroot:$6$x:19000::::::\r\nroot@srv01:~# "
KEPT = "uid=0(root)\r\nroot@srv01:~# "


@pytest.fixture(autouse=True)
def fresh_hooks():
    hooks.reset()
    hooks.set_budget(Budget(BudgetConfig()))
    hooks.set_local_replies(False)
    hooks.set_reply_cache(ReplyCache(max_entries=0))
    yield
    hooks.reset()


def _ai_texts(chain, sid="s1"):
    from langchain_core.messages import AIMessage

    return [m.content for m in chain.get_session_history(sid).messages
            if isinstance(m, AIMessage)]


async def test_cut_reply_is_what_is_sent_and_kept(caplog):
    caplog.set_level("INFO")
    chain = Chain({"id": INVENTED})
    r = await ask(chain, "id", logger=logging.getLogger("cut-test"))
    assert r.content == KEPT
    assert _ai_texts(chain) == [KEPT]
    assert hooks._session_prompts["s1"][0] == "root@srv01:~# "
    (rec,) = [rec for rec in caplog.records if rec.getMessage() == "Reply cut"]
    assert rec.task_name == "s1"
    assert rec.dropped_chars == len(INVENTED) - len(KEPT)
    assert rec.cut_reason == "next_command" and rec.cuts_in_session == 1
    assert rec.dropped_sample.startswith("cat /etc/shadow")
    assert len(rec.dropped_sample) <= 4 * onereply.MAX_SAMPLE
    assert r.reply_cut["dropped_chars"] == rec.dropped_chars
    assert "kept" not in r.reply_cut
    assert hooks.replies_cut() == 1


async def test_reply_without_the_pattern_is_unchanged_byte_for_byte(caplog):
    caplog.set_level("INFO")
    reply = "uid=0(root) gid=0(root)\r\nroot@srv01:/opt# make\r\nroot@srv01:~# "
    chain = Chain({"cat build.log": reply})
    r = await ask(chain, "cat build.log", logger=logging.getLogger("cut-test"))
    assert r.content == reply and not hasattr(r, "reply_cut")
    assert _ai_texts(chain) == [reply]
    assert not [rec for rec in caplog.records if rec.getMessage() == "Reply cut"]
    exec_reply = "uid=0(root)\n\n"
    chain = Chain({"id": exec_reply})
    r = await ask(chain, "id", sid="s2", interactive=False)
    assert r.content == exec_reply and not hasattr(r, "reply_cut")


async def test_noted_prompt_is_the_one_after_the_real_command():
    """An invented ``cd`` after the real one must not move the session: the offline shell
    and local answers start from the prompt that was kept."""
    hooks.set_budget(Budget(BudgetConfig(max_model_commands_per_session=1)))
    chain = Chain({"cd /tmp": "root@srv01:/tmp# cd /etc\r\nroot@srv01:/etc# "})
    r = await ask(chain, "cd /tmp")
    assert r.content == "root@srv01:/tmp# "
    assert hooks._session_prompts["s1"] == ("root@srv01:/tmp# ", "/tmp")
    r = await ask(chain, "pwd")             # past the model cap: the local shell answers
    assert r.model_capped and r.content == "/tmp\r\nroot@srv01:/tmp# "


async def test_exec_reply_is_cut_without_a_prompt():
    chain = Chain({"uname -a": "Linux srv01 5.15.0\nroot@srv01:~# id\nuid=0(root)\n"})
    r = await ask(chain, "uname -a", interactive=False)
    assert r.content == "Linux srv01 5.15.0\n"
    assert _ai_texts(chain) == ["Linux srv01 5.15.0\n"]


async def test_cache_holds_only_the_kept_text():
    cache = ReplyCache()
    hooks.set_reply_cache(cache)
    chain = Chain({"id": INVENTED})
    await ask(chain, "", counts=False)
    first = await ask(chain, "id")
    assert first.content == KEPT
    assert all("shadow" not in v for _, v in cache._items.values())
    await ask(chain, "", sid="s2", counts=False)
    second = await ask(chain, "id", sid="s2")
    assert getattr(second, "cached_reply", False) and second.content == KEPT
    assert chain.calls == ["", "id"]
    assert _ai_texts(chain, "s2")[-1] == KEPT


async def test_cut_runs_before_the_persona_break_check():
    """An invented round that steps out of character is dropped, not judged."""
    reply = "root\r\nroot@srv01:~# ask\r\nAs an AI language model I cannot\r\nroot@srv01:~# "
    chain = Chain({"whoami": reply})
    r = await ask(chain, "whoami")
    assert r.content == "root\r\nroot@srv01:~# "
    assert not getattr(r, "persona_break", False)


async def test_session_that_typed_a_prompt_keeps_its_file_text():
    chain = Chain({"echo 'root@srv01:~# id' > n": "root@srv01:~# ",
                   "cat n": "root@srv01:~# id\r\nroot@srv01:~# "})
    await ask(chain, "echo 'root@srv01:~# id' > n")
    r = await ask(chain, "cat n")
    assert r.content == "root@srv01:~# id\r\nroot@srv01:~# "
    hooks.session_close("s1")
    assert "s1" not in hooks._session_built


async def test_cuts_are_counted_per_session(caplog):
    caplog.set_level("INFO")
    chain = Chain({"id": INVENTED, "w": INVENTED})
    logger = logging.getLogger("cut-test")
    await ask(chain, "id", logger=logger)
    await ask(chain, "w", logger=logger)
    counts = [rec.cuts_in_session for rec in caplog.records if rec.getMessage() == "Reply cut"]
    assert counts == [1, 2] and hooks.replies_cut() == 2


# ---- the dropped text is never an input ----------------------------------------------

def test_reply_cut_record_is_not_an_input(tmp_path):
    base = {"level": "INFO", "task_name": "session-1", "src_ip": IP, "src_port": 50000,
            "dst_ip": "10.0.0.5", "dst_port": 22, "sensor_name": "t", "sensor_protocol": "ssh"}
    import base64

    def b64(s):
        return base64.b64encode(s.encode()).decode()

    recs = [dict(base, timestamp="2026-11-01T12:00:00.000+00:00",
                 message="SSH connection received"),
            dict(base, timestamp="2026-11-01T12:00:01.000+00:00", message="User input",
                 details=b64("id"), interactive=True),
            dict(base, timestamp="2026-11-01T12:00:02.000+00:00", message="Reply cut",
                 cut_reason="next_command", dropped_chars=40, cuts_in_session=1,
                 dropped_sample="cat /etc/shadow", details=b64("cat /etc/shadow")),
            dict(base, timestamp="2026-11-01T12:00:03.000+00:00", message="LLM response",
                 details=b64(KEPT), interactive=True),
            dict(base, timestamp="2026-11-01T12:00:04.000+00:00", message="SSH connection closed")]
    log = tmp_path / "log.jsonl"
    log.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
    parsed = parse_log(log)
    (session,) = parsed.sessions.values()
    assert session.commands == ["id"]
    assert all("shadow" not in c for camp in parsed.campaigns.values() for c in camp.commands)
    assert activity.classify(recs[2])[3] == "other"


def test_exec_output_glued_to_the_prompt_is_kept():
    cut = onereply.one_reply("helloroot@srv01:~# ", "printf hello", interactive=False,
                             hosts=("srv01",), current_prompt="root@srv01:~# ", user="root")
    assert cut is not None and cut.kept == "hello"
    cut = onereply.one_reply("a\nhelloroot@srv01:~# id\nuid=0\n", "printf 'a\\nhello'",
                             interactive=False, hosts=("srv01",),
                             current_prompt="root@srv01:~# ", user="root")
    assert cut is None      # the input has a backslash: left whole
    cut = onereply.one_reply("root@srv01:~# ", "true", interactive=False, hosts=("srv01",),
                             current_prompt="root@srv01:~# ", user="root")
    assert cut is not None and cut.kept == ""
