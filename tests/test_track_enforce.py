"""Two stages on a blocklist entry: approve tracks, enforce blocks. The tracked export, the
checks enforce runs again, unblock and expiry on both stages, and the off switch (old state
files and old outputs unchanged)."""

import datetime
import json

import pytest

from agents.addresses import public_for_tests
from agents.respond import (
    EnforceChanged,
    EnforceError,
    RespondSettings,
    approve,
    enforce,
    list_queue,
    peek_blocklist,
    queue_enforce_action,
    tracked_document,
    tracked_target,
    unblock,
    write_blocklist,
)

from test_respond import NOW, FakeConnectors, pb, rec, run, write

V6 = "2001:db8:1:2::7"
V6_KEY = "2001:db8:1:2::/64"


@pytest.fixture(autouse=True)
def documentation_ranges_are_public():
    with public_for_tests("198.51.100.0/24", "2001:db8::/32"):
        yield


def _dirs(tmp_path):
    return tmp_path / "state", tmp_path / "reports", tmp_path / "det"


def _queue(tmp_path, ip="198.51.100.34", rid="r1", name="block_pb", unverified=False,
           action="export_blocklist"):
    write(tmp_path / "reports", rec(rid=rid, ip=ip, unverified=unverified))
    run(tmp_path, [pb(name=name, steps=[{"action": action}])], queue_enforce=True)


def _approve_all(tmp_path, track=True, now=NOW, **kw):
    state, reports, det = _dirs(tmp_path)
    out = []
    for a in list_queue(state, now=now):
        out.append(approve(a["id"], state, reports, det, by="alice", now=now,
                           track_before_enforce=track, sensor="sensor-a", **kw))
    return out


def _tracked(tmp_path, ip="198.51.100.34", **kw):
    _queue(tmp_path, ip=ip)
    [a] = _approve_all(tmp_path, **kw)
    return a


def _enforce(tmp_path, target="198.51.100.34", **kw):
    state, reports, _ = _dirs(tmp_path)
    kw.setdefault("now", NOW)
    return enforce(target, state, reports, by="bob", sensor="sensor-a", **kw)


def _blocklist(tmp_path) -> list[str]:
    return (tmp_path / "reports" / "blocklist" / "approved.txt").read_text().split()


def _export(tmp_path) -> dict:
    return json.loads(tracked_target(tmp_path / "reports").read_text())


def _audits(tmp_path, kind):
    return [json.loads(p.read_text())[kind]
            for p in sorted((tmp_path / "reports" / "response").glob(f"*-{kind}-*.json"))]


# ---- stage transitions ---------------------------------------------------------------------

def test_approving_tracks_and_blocks_nothing(tmp_path):
    a = _tracked(tmp_path)
    assert a["status"] == "done"
    assert a["result"]["status"] == "tracked in tracked.json; nothing blocked"
    assert _blocklist(tmp_path) == []
    doc = _export(tmp_path)
    assert doc["entries"] == [{"address": "198.51.100.34", "status": "tracked",
                               "approved_at": NOW.isoformat(),
                               "expires_at": (NOW + datetime.timedelta(days=30)).isoformat()}]
    entry = peek_blocklist(tmp_path / "state", NOW)["198.51.100.34"]
    assert entry["status"] == "tracked" and entry["approval_id"] == a["id"]


def test_enforce_moves_one_tracked_entry_and_records_who_and_when(tmp_path):
    _tracked(tmp_path)
    later = NOW + datetime.timedelta(hours=2)
    conns = FakeConnectors()
    out = _enforce(tmp_path, connectors=conns, now=later)
    assert out["status"] == "enforced" and out["file"] == "approved.txt"
    assert out["connector"] == {"ok": True, "status": "sent"}
    assert conns.calls == [("block", "198.51.100.34", "block_pb")]
    assert _blocklist(tmp_path) == ["198.51.100.34"]
    assert _export(tmp_path)["entries"][0]["status"] == "enforced"
    entry = peek_blocklist(tmp_path / "state", later)["198.51.100.34"]
    assert entry["status"] == "enforced" and entry["enforced_by"] == "bob"
    assert entry["enforced_at"] == later.isoformat()
    [record] = _audits(tmp_path, "enforce")
    assert record["target"] == "198.51.100.34" and record["by"] == "bob"
    assert record["connector"]["status"] == "sent"


def test_enforce_without_the_block_connector_still_writes_the_file(tmp_path):
    _tracked(tmp_path)
    out = _enforce(tmp_path, connectors=FakeConnectors(enabled=()))
    assert out["connector"] == {"ok": None, "status": "not called: block connector disabled"}
    assert _blocklist(tmp_path) == ["198.51.100.34"]


def test_a_failed_connector_call_is_reported_and_the_entry_stays_enforced(tmp_path):
    from agents.connectors.base import ConnectorResult

    class Failing(FakeConnectors):
        def block(self, ip, reason):
            return ConnectorResult(False, "error: http_500")

    _tracked(tmp_path)
    out = _enforce(tmp_path, connectors=Failing())
    assert out["connector"] == {"ok": False, "status": "error: http_500"}
    assert _blocklist(tmp_path) == ["198.51.100.34"]


def test_ipv6_entries_are_tracked_and_enforced_by_their_64(tmp_path):
    _tracked(tmp_path, ip=V6)
    assert _export(tmp_path)["entries"][0]["address"] == V6_KEY
    _enforce(tmp_path, target="2001:db8:1:2::99")
    assert _blocklist(tmp_path) == [V6_KEY]


@pytest.mark.parametrize("fmt", ["plain", "csv", "nftables"])
def test_every_blocklist_format_lists_only_enforced_entries(tmp_path, fmt):
    target = tmp_path / "bl.out"
    for i, ip in enumerate(["198.51.100.34", "198.51.100.35"]):
        _queue(tmp_path, ip=ip, rid=f"r{i}", name=f"p{i}")
    _approve_all(tmp_path, blocklist_file=target, blocklist_format=fmt)
    _enforce(tmp_path, "198.51.100.35", blocklist_file=target, blocklist_format=fmt)
    text = target.read_text()
    assert "198.51.100.35" in text and "198.51.100.34" not in text
    assert {e["address"]: e["status"] for e in
            json.loads((tmp_path / "tracked.json").read_text())["entries"]} == \
        {"198.51.100.34": "tracked", "198.51.100.35": "enforced"}


def test_reapproving_an_enforced_entry_keeps_it_enforced(tmp_path):
    _tracked(tmp_path)
    _enforce(tmp_path)
    later = NOW + datetime.timedelta(days=2)
    _queue(tmp_path, rid="r2", name="again_pb")
    write(tmp_path / "reports", rec(rid="r2"))
    run(tmp_path, [pb(name="again_pb", steps=[{"action": "export_blocklist"}])],
        queue_enforce=True, now=later)
    [a] = _approve_all(tmp_path, now=later)
    assert a["result"]["status"].startswith("already enforced")
    entry = peek_blocklist(tmp_path / "state", later)["198.51.100.34"]
    assert entry["status"] == "enforced" and entry["enforced_by"] == "bob"
    assert entry["expires_at"] == (later + datetime.timedelta(days=30)).isoformat()


# ---- refusals ------------------------------------------------------------------------------

def test_enforcing_twice_or_an_unknown_address_is_refused_without_change(tmp_path):
    _tracked(tmp_path)
    _enforce(tmp_path)
    before = (tmp_path / "state" / "approved_blocklist.json").read_bytes()
    with pytest.raises(EnforceError, match="already enforced"):
        _enforce(tmp_path)
    with pytest.raises(EnforceError, match="not on the tracked list"):
        _enforce(tmp_path, "198.51.100.99")
    with pytest.raises(EnforceError, match="not an address"):
        _enforce(tmp_path, "nonsense")
    assert (tmp_path / "state" / "approved_blocklist.json").read_bytes() == before
    assert len(_audits(tmp_path, "enforce")) == 1


def test_enforce_rechecks_never_act_on(tmp_path):
    _tracked(tmp_path)
    with pytest.raises(EnforceError, match="never_act_on"):
        _enforce(tmp_path, never_act_on=("198.51.100.0/24",))
    assert _blocklist(tmp_path) == []
    assert peek_blocklist(tmp_path / "state", NOW)["198.51.100.34"]["status"] == "tracked"


def test_enforce_rechecks_that_the_address_is_public(tmp_path, monkeypatch):
    from agents import addresses

    _tracked(tmp_path)
    monkeypatch.setattr(addresses, "_TEST_PUBLIC", ())   # documentation ranges again
    with pytest.raises(EnforceError, match="non-global"):
        _enforce(tmp_path)
    assert _blocklist(tmp_path) == []


def test_enforce_rechecks_the_verified_source(tmp_path):
    _tracked(tmp_path)
    store = tmp_path / "state" / "approved_blocklist.json"
    data = json.loads(store.read_text())
    data["198.51.100.34"].pop("source_verified")
    store.write_text(json.dumps(data))
    with pytest.raises(EnforceError, match="not a verified source"):
        _enforce(tmp_path)


def test_enforce_refuses_when_the_approval_file_disagrees(tmp_path):
    a = _tracked(tmp_path)
    path = tmp_path / "state" / "approvals" / f"{a['id']}.json"
    data = json.loads(path.read_text())
    data["subject"] = "198.51.100.77"
    path.write_text(json.dumps(data))
    with pytest.raises(EnforceError, match="not a verified source"):
        _enforce(tmp_path)


def test_enforce_trusts_the_entry_once_its_approval_aged_out(tmp_path):
    a = _tracked(tmp_path)
    (tmp_path / "state" / "approvals" / f"{a['id']}.json").unlink()
    assert _enforce(tmp_path)["status"] == "enforced"


def test_an_unverified_source_is_never_tracked(tmp_path):
    _queue(tmp_path, unverified=True)
    assert list_queue(tmp_path / "state", now=NOW) == []   # never queued in the first place
    assert peek_blocklist(tmp_path / "state", NOW) == {}


def test_an_expired_tracked_entry_cannot_be_enforced(tmp_path):
    _tracked(tmp_path)
    with pytest.raises(EnforceError, match="not on the tracked list"):
        _enforce(tmp_path, now=NOW + datetime.timedelta(days=31))


# ---- expiry and unblock on both stages ---------------------------------------------------

def test_expiry_drops_both_stages_from_both_outputs(tmp_path):
    for i, ip in enumerate(["198.51.100.34", "198.51.100.35"]):
        _queue(tmp_path, ip=ip, rid=f"r{i}", name=f"p{i}")
    _approve_all(tmp_path)
    _enforce(tmp_path, "198.51.100.35")
    later = NOW + datetime.timedelta(days=31)
    run(tmp_path, [pb(name="noop_pb")], now=later, track_before_enforce=True)
    assert _blocklist(tmp_path) == []
    doc = _export(tmp_path)
    assert doc["entries"] == [] and doc["generated_at"] == later.isoformat()


def test_unblock_removes_a_tracked_and_an_enforced_entry(tmp_path):
    for i, ip in enumerate(["198.51.100.34", V6]):
        _queue(tmp_path, ip=ip, rid=f"r{i}", name=f"p{i}")
    _approve_all(tmp_path)
    _enforce(tmp_path, V6)
    state, reports, _ = _dirs(tmp_path)
    out = unblock("198.51.100.34", state, reports, now=NOW, track_before_enforce=True)
    assert out["removed"] == ["198.51.100.34"]
    assert [e["address"] for e in _export(tmp_path)["entries"]] == [V6_KEY]
    out = unblock(V6, state, reports, now=NOW, track_before_enforce=True)
    assert out["removed"] == [V6_KEY]
    assert _blocklist(tmp_path) == [] and _export(tmp_path)["entries"] == []


def test_every_respond_run_refreshes_the_export_while_tracking(tmp_path):
    _tracked(tmp_path)
    later = NOW + datetime.timedelta(hours=1)
    run(tmp_path, [pb(name="noop_pb")], now=later, track_before_enforce=True, sensor="sensor-a")
    doc = _export(tmp_path)
    assert doc["generated_at"] == later.isoformat() and doc["sensor"] == "sensor-a"
    assert [e["status"] for e in doc["entries"]] == ["tracked"]


# ---- the tracked export document ---------------------------------------------------------

def test_export_document_shape_is_sorted_and_carries_nothing_else():
    entries = {
        "198.51.100.9": {"approved_at": "2026-11-15T12:00:00+00:00",
                         "expires_at": "2026-12-15T12:00:00+00:00", "status": "tracked",
                         "approval_id": "a-0123456789ab", "playbook": "noisy_brute_force",
                         "source_verified": True},
        "198.51.100.10": {"approved_at": "2026-11-14T12:00:00+00:00",
                          "expires_at": "2026-12-14T12:00:00+00:00", "status": "enforced",
                          "enforced_by": "alice", "enforced_at": "2026-11-15T13:00:00+00:00"},
        "198.51.100.11": {"approved_at": "2026-11-13T12:00:00+00:00",
                          "expires_at": "2026-12-13T12:00:00+00:00"},
    }
    doc = tracked_document(entries, NOW, "lab sensor\n<1>")
    assert set(doc) == {"version", "generated_at", "sensor", "entries"}
    assert doc["version"] == 1 and doc["generated_at"] == NOW.isoformat()
    assert doc["sensor"] == "lab sensor1"
    assert [e["address"] for e in doc["entries"]] == ["198.51.100.10", "198.51.100.11",
                                                      "198.51.100.9"]
    assert [e["status"] for e in doc["entries"]] == ["enforced", "enforced", "tracked"]
    for e in doc["entries"]:
        assert set(e) == {"address", "status", "approved_at", "expires_at"}
    text = json.dumps(doc)
    for secret in ("alice", "a-0123456789ab", "noisy_brute_force", "source_verified"):
        assert secret not in text


def test_export_file_is_deterministic(tmp_path):
    from agents.respond import write_tracked

    entries = {"198.51.100.9": {"approved_at": "2026-11-15T12:00:00+00:00",
                                "expires_at": "2026-12-15T12:00:00+00:00", "status": "tracked"},
               "198.51.100.10": {"approved_at": "2026-11-14T12:00:00+00:00",
                                 "expires_at": "2026-12-14T12:00:00+00:00"}}
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    write_tracked(a, entries, NOW, "s")
    write_tracked(b, dict(reversed(list(entries.items()))), NOW, "s")
    assert a.read_bytes() == b.read_bytes()
    assert a.read_text().endswith("}\n")
    assert oct(a.stat().st_mode & 0o777) == "0o600"
    assert not list(tmp_path.glob(".*.tmp"))


def test_blocklist_file_may_not_be_named_like_the_export():
    import configparser

    cp = configparser.ConfigParser()
    cp.read_dict({"respond": {"blocklist_file": "/agents/reports/blocklist/tracked.json",
                              "track_before_enforce": "true"}})
    with pytest.raises(ValueError, match="tracked.json"):
        RespondSettings.from_config(cp["respond"])
    cp["respond"]["blocklist_file"] = "/x/approved.txt"
    assert RespondSettings.from_config(cp["respond"]).track_before_enforce is True


# ---- the off switch ----------------------------------------------------------------------

def test_switch_off_writes_exactly_what_it_did_before(tmp_path):
    """Approve with the switch off: the store holds only times, the file is as before, and
    no export is written."""
    _queue(tmp_path)
    [a] = _approve_all(tmp_path, track=False)
    assert a["result"]["status"] == "written to approved.txt"
    store = json.loads((tmp_path / "state" / "approved_blocklist.json").read_text())
    assert store == {"198.51.100.34": {"approved_at": NOW.isoformat(),
                                       "expires_at": (NOW + datetime.timedelta(days=30))
                                       .isoformat()}}
    assert _blocklist(tmp_path) == ["198.51.100.34"]
    assert not tracked_target(tmp_path / "reports").exists()
    run(tmp_path, [pb(name="noop_pb")], now=NOW + datetime.timedelta(hours=1))
    assert not tracked_target(tmp_path / "reports").exists()


@pytest.mark.parametrize("fmt", ["plain", "csv", "nftables"])
def test_old_state_files_load_as_enforced_and_keep_their_output(tmp_path, fmt):
    """A store written before stages existed (both legacy shapes) gives the same file."""
    state, reports, _ = _dirs(tmp_path)
    state.mkdir(parents=True)
    old = {"198.51.100.34": NOW.isoformat(),
           "198.51.100.35": {"approved_at": NOW.isoformat(),
                             "expires_at": (NOW + datetime.timedelta(days=5)).isoformat()}}
    (state / "approved_blocklist.json").write_text(json.dumps(old))
    expected = tmp_path / "expected.out"
    write_blocklist(expected, {"198.51.100.34": {"approved_at": NOW.isoformat(),
                                                 "expires_at": (NOW + datetime.timedelta(days=30))
                                                 .isoformat()},
                               "198.51.100.35": old["198.51.100.35"]}, fmt)
    target = tmp_path / "bl.out"
    unblock("198.51.100.99", state, reports, now=NOW, blocklist_file=target, blocklist_format=fmt)
    assert target.read_bytes() == expected.read_bytes()
    entries = peek_blocklist(state, NOW)
    assert all("status" not in v for v in entries.values())
    # Turning the switch on leaves them enforced.
    with pytest.raises(EnforceError, match="already enforced"):
        enforce("198.51.100.34", state, reports, now=NOW, blocklist_file=target)
    unblock("198.51.100.99", state, reports, now=NOW, blocklist_file=target, blocklist_format=fmt,
            track_before_enforce=True)
    assert target.read_bytes() == expected.read_bytes()
    assert {e["status"] for e in
            json.loads((tmp_path / "tracked.json").read_text())["entries"]} == {"enforced"}


def test_turning_the_switch_off_keeps_tracked_entries_out_of_the_file(tmp_path):
    _tracked(tmp_path)
    export = tracked_target(tmp_path / "reports").read_bytes()
    state, reports, _ = _dirs(tmp_path)
    unblock("198.51.100.99", state, reports, now=NOW + datetime.timedelta(days=1))
    assert _blocklist(tmp_path) == []
    assert peek_blocklist(state, NOW)["198.51.100.34"]["status"] == "tracked"
    assert tracked_target(reports).read_bytes() == export   # left as it was


# ---- CLI -----------------------------------------------------------------------------------

def _cli(tmp_path, monkeypatch, *argv, track=True):
    import agents.__main__ as cli

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cfg = tmp_path / "config.ini"
    cfg.write_text("[honeypot]\nsensor_name = lab-1\n"
                   f"[respond]\ntrack_before_enforce = {'true' if track else 'false'}\n")
    return cli.run([*argv, "--config", str(cfg), "--reports-dir", str(tmp_path / "reports"),
                    "--state-dir", str(tmp_path / "state"), "--detections-dir",
                    str(tmp_path / "det"), "--by", "carol"])


def test_cli_approve_tracks_and_enforce_blocks(tmp_path, monkeypatch):
    now = datetime.datetime.now(datetime.timezone.utc)
    write(tmp_path / "reports", rec())
    run(tmp_path, [pb(name="block_pb", steps=[{"action": "export_blocklist"}])],
        queue_enforce=True, now=now, lookback_hours=24 * 3650)
    [a] = list_queue(tmp_path / "state", now=now)
    out = _cli(tmp_path, monkeypatch, "approve", a["id"])
    assert out["approval"]["result"]["status"] == "tracked in tracked.json; nothing blocked"
    assert _export(tmp_path)["sensor"] == "lab-1"
    out = _cli(tmp_path, monkeypatch, "enforce", "198.51.100.34")
    assert out["enforce"]["status"] == "enforced"
    assert _blocklist(tmp_path) == ["198.51.100.34"]
    assert _audits(tmp_path, "enforce")[0]["by"] == "carol"
    out = _cli(tmp_path, monkeypatch, "enforce", "198.51.100.34")
    assert out["enforce"] == {"error": "198.51.100.34 is already enforced"}
    out = _cli(tmp_path, monkeypatch, "unblock", "198.51.100.34")
    assert out["unblock"]["removed"] == ["198.51.100.34"]
    assert _export(tmp_path)["entries"] == []


# ---- block_webhook approvals ---------------------------------------------------------------

def test_approving_block_webhook_while_tracking_tracks_and_calls_nothing(tmp_path):
    _queue(tmp_path, action="block_webhook")
    conns = FakeConnectors()
    [a] = _approve_all(tmp_path, connectors=conns)
    assert a["status"] == "done"
    assert a["result"]["status"] == "tracked in tracked.json; nothing blocked"
    assert conns.calls == []
    assert _blocklist(tmp_path) == []
    assert [e["status"] for e in _export(tmp_path)["entries"]] == ["tracked"]
    # Only enforce calls the block connector, once.
    out = _enforce(tmp_path, connectors=conns)
    assert out["connector"] == {"ok": True, "status": "sent"}
    assert conns.calls == [("block", "198.51.100.34", "block_pb")]
    assert _blocklist(tmp_path) == ["198.51.100.34"]


def test_approving_block_webhook_while_tracking_needs_no_connector(tmp_path):
    _queue(tmp_path, action="block_webhook")
    [a] = _approve_all(tmp_path, connectors=None)
    assert a["status"] == "done" and a["result"]["status"].startswith("tracked")


def test_approving_block_webhook_with_the_switch_off_calls_the_connector(tmp_path):
    _queue(tmp_path, action="block_webhook")
    conns = FakeConnectors()
    [a] = _approve_all(tmp_path, track=False, connectors=conns)
    assert a["status"] == "done" and a["result"] == {"ok": True, "status": "sent"}
    assert conns.calls == [("block", "198.51.100.34", "block_pb")]
    assert not tracked_target(tmp_path / "reports").exists()
    assert peek_blocklist(tmp_path / "state", NOW) == {}


def test_an_unverified_block_webhook_source_is_never_tracked(tmp_path):
    _queue(tmp_path, action="block_webhook")
    [queued] = list_queue(tmp_path / "state", now=NOW)
    path = tmp_path / "state" / "approvals" / f"{queued['id']}.json"
    path.write_text(json.dumps({**json.loads(path.read_text()), "unverified_source": True}))
    conns = FakeConnectors()
    [a] = _approve_all(tmp_path, connectors=conns)
    assert a["status"] == "failed" and conns.calls == []
    assert peek_blocklist(tmp_path / "state", NOW) == {}


# ---- a missing blocklist file is written again ---------------------------------------------

@pytest.mark.parametrize("track", [True, False])
def test_a_missing_blocklist_file_is_rewritten_by_the_next_run(tmp_path, track):
    _queue(tmp_path)
    _approve_all(tmp_path, track=track)
    if track:
        _enforce(tmp_path)
    blocklist_dir = tmp_path / "reports" / "blocklist"
    for p in blocklist_dir.iterdir():
        p.unlink()   # a new, empty volume mounted over the directory
    later = NOW + datetime.timedelta(hours=1)
    run(tmp_path, [pb(name="noop_pb")], now=later, track_before_enforce=track)
    assert _blocklist(tmp_path) == ["198.51.100.34"]
    assert tracked_target(tmp_path / "reports").exists() is track


def test_nothing_is_written_before_the_first_approval(tmp_path):
    run(tmp_path, [pb(name="noop_pb")])
    assert not (tmp_path / "reports" / "blocklist").exists()


def test_a_present_blocklist_file_is_left_alone_with_the_switch_off(tmp_path):
    _queue(tmp_path)
    _approve_all(tmp_path, track=False)
    path = tmp_path / "reports" / "blocklist" / "approved.txt"
    before = path.stat().st_mtime_ns, path.stat().st_ino
    run(tmp_path, [pb(name="noop_pb")], now=NOW + datetime.timedelta(hours=1))
    assert (path.stat().st_mtime_ns, path.stat().st_ino) == before


# ---- what the caller saw is re-checked under the lock --------------------------------------

def test_enforce_refuses_an_entry_that_changed_since_it_was_seen(tmp_path):
    _tracked(tmp_path)
    state, reports, _ = _dirs(tmp_path)
    seen = dict(peek_blocklist(state, NOW)["198.51.100.34"])
    # Removed and approved again in the same second: same times, a new approval.
    unblock("198.51.100.34", state, reports, now=NOW, track_before_enforce=True)
    playbook = pb(name="block_pb", steps=[{"action": "export_blocklist"}])
    _, aid = queue_enforce_action(state, playbook, rec(rid="r2"), playbook.steps[0], NOW, 72, {})
    approve(aid, state, reports, tmp_path / "det", by="alice", now=NOW,
            track_before_enforce=True)
    fresh = peek_blocklist(state, NOW)["198.51.100.34"]
    assert fresh["approved_at"] == seen["approved_at"]
    assert fresh["approval_id"] != seen["approval_id"]
    before = _blocklist(tmp_path), _export(tmp_path)
    expected = {k: seen.get(k) for k in ("approved_at", "expires_at", "approval_id", "status")}
    with pytest.raises(EnforceChanged):
        _enforce(tmp_path, expected=expected)
    assert (_blocklist(tmp_path), _export(tmp_path)) == before
    expected["approval_id"] = fresh["approval_id"]
    assert _enforce(tmp_path, expected=expected)["status"] == "enforced"
