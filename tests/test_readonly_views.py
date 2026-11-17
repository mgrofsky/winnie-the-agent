"""Read-only views (queue peek, daily call counter peek), the shared respond context in
agents.runtime, and the audit records written by reject and unblock."""

import datetime
import json
import logging
import os
import stat

import pytest

from test_respond import NOW, pb, rec, run, write

from agents import runtime
from agents.llm import DailyCallCounter
from agents.respond import (
    RespondSettings,
    apply_retention,
    approve,
    list_queue,
    peek_queue,
    reject,
    unblock,
)

pytestmark = pytest.mark.usefixtures("public_test_net")

H = datetime.timedelta(hours=1)


def tree(root):
    """Every path under ``root`` with its bytes (files) or None (directories)."""
    out = {}
    for dirpath, dirs, files in os.walk(root):
        for d in dirs:
            out[os.path.relpath(os.path.join(dirpath, d), root)] = None
        for f in files:
            p = os.path.join(dirpath, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root)] = fh.read()
    return out


def _queue(tmp_path, n=3):
    write(tmp_path / "reports", *[rec(rid=f"q{i}", ip=f"198.51.100.{i + 10}") for i in range(n)])
    run(tmp_path, [pb(steps=[{"action": "export_blocklist"}], max_runs_per_day=100)],
        queue_enforce=True)
    return list_queue(tmp_path / "state", now=NOW)


def _decided_mix(tmp_path):
    items = _queue(tmp_path, 4)
    state, reports = tmp_path / "state", tmp_path / "reports"
    reject(items[0]["id"], state, by="o", now=NOW)
    approve(items[1]["id"], state, reports, tmp_path / "det", by="o", now=NOW,
            blocklist_file=tmp_path / "bl.txt")
    return items


# ---- peek_queue ----------------------------------------------------------------------------

def test_peek_queue_matches_list_queue(tmp_path):
    _decided_mix(tmp_path)
    state = tmp_path / "state"
    for closed in (False, True):
        peeked = peek_queue(state, now=NOW + H, include_closed=closed)
        assert peeked == list_queue(state, now=NOW + H, include_closed=closed)
    statuses = sorted(a["status"] for a in peek_queue(state, now=NOW + H, include_closed=True))
    assert statuses == ["done", "pending", "pending", "rejected"]
    assert len(peek_queue(state, now=NOW + H)) == 2


def test_peek_queue_shows_overdue_as_expired_and_changes_nothing(tmp_path):
    _decided_mix(tmp_path)
    state, later = tmp_path / "state", NOW + 73 * H
    before = tree(tmp_path)
    assert peek_queue(state, now=later) == []
    peeked = peek_queue(state, now=later, include_closed=True)
    assert tree(tmp_path) == before                    # byte-for-byte and listing-for-listing
    assert sorted(a["status"] for a in peeked) == ["done", "expired", "expired", "rejected"]
    # list_queue really expires them; apart from the expiry time it records, they agree.
    listed = list_queue(state, now=later, include_closed=True)
    assert [{k: v for k, v in a.items() if k != "expired_at"} for a in listed] == peeked


def test_peek_queue_missing_directory_creates_nothing(tmp_path):
    before = tree(tmp_path)
    assert peek_queue(tmp_path / "state", include_closed=True) == []
    (tmp_path / "state").mkdir()
    assert peek_queue(tmp_path / "state", include_closed=True) == []
    assert tree(tmp_path) == {**before, "state": None}
    assert not (tmp_path / "state" / "approvals").exists()


def test_peek_queue_skips_junk(tmp_path):
    [good] = _queue(tmp_path, 1)
    adir = tmp_path / "state" / "approvals"
    exp = good["expires_at"]
    (adir / "a-0123456789abc.json").write_text(json.dumps({**good, "id": "x"}))  # 13 hex
    (adir / "a-zzzzzzzzzzzz.json").write_text(json.dumps(good))
    (adir / "a-bad000000001.json").write_text("{not json")
    (adir / "a-bad000000002.json").write_text(json.dumps([good]))
    (adir / "a-bad000000003.json").write_text(json.dumps({"status": "pending"}))
    (adir / "a-bad000000004.json").write_text(json.dumps({"status": "pending",
                                                          "expires_at": "tomorrow"}))
    (adir / "a-bad000000005.json").write_text(json.dumps({"status": "pending",
                                                          "expires_at": 17}))
    (adir / "a-bad000000006.json").write_bytes(b"\xff\xfe")
    (adir / "a-bad000000007.json").mkdir()
    out = peek_queue(tmp_path / "state", now=NOW, include_closed=True)
    assert out == [good] and exp


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_peek_queue_on_read_only_state(tmp_path):
    _decided_mix(tmp_path)
    state = tmp_path / "state"
    dirs = [state, state / "approvals"]
    for d in dirs:
        d.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        assert len(peek_queue(state, now=NOW + 73 * H, include_closed=True)) == 4
    finally:
        for d in dirs:
            d.chmod(0o755)


# ---- DailyCallCounter.peek -----------------------------------------------------------------

def _today():
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


def test_daily_counter_peek_missing_file_creates_nothing(tmp_path):
    counter = DailyCallCounter(tmp_path / "state" / "calls.json", limit=5)
    assert counter.peek() == {"day": _today(), "calls": 0, "limit": 5}
    assert list(tmp_path.iterdir()) == []


def test_daily_counter_peek_reads_the_count_without_taking(tmp_path):
    path = tmp_path / "calls.json"
    counter = DailyCallCounter(path, limit=5)
    assert counter.take() and counter.take()
    before = tree(tmp_path)
    assert counter.peek() == {"day": _today(), "calls": 2, "limit": 5}
    assert counter.peek()["calls"] == 2
    assert tree(tmp_path) == before


@pytest.mark.parametrize("content", [
    '{"day": "2001-01-01", "calls": 4}',     # another day
    "{broken",
    '[1, 2]',
    '{"day": "TODAY", "calls": -3}',
    '{"day": "TODAY", "calls": "4"}',
])
def test_daily_counter_peek_bad_or_stale_file_is_zero(tmp_path, content):
    path = tmp_path / "calls.json"
    path.write_text(content.replace("TODAY", _today()))
    before = tree(tmp_path)
    assert DailyCallCounter(path, limit=9).peek() == {"day": _today(), "calls": 0, "limit": 9}
    assert tree(tmp_path) == before


def test_daily_counter_peek_unreadable_file_is_zero(tmp_path):
    path = tmp_path / "calls.json"
    path.mkdir()                                   # a directory cannot be read as text
    assert DailyCallCounter(path, limit=1).peek()["calls"] == 0


def test_daily_counter_peek_memory_mode(tmp_path):
    counter = DailyCallCounter(None, limit=3)
    assert counter.peek() == {"day": _today(), "calls": 0, "limit": 3}
    counter.take()
    assert counter.peek()["calls"] == 1
    counter._day = "2001-01-01"                    # yesterday's count no longer applies
    assert counter.peek()["calls"] == 0


# ---- runtime: respond settings and connectors ----------------------------------------------

def test_respond_settings_from_config():
    from configparser import ConfigParser

    assert runtime.respond_settings(None) == RespondSettings.from_config({})
    cp = ConfigParser()
    cp.read_string("[respond]\nretention_days = 7.5\n")
    assert runtime.respond_settings(cp).retention_days == 7.5
    cp.read_string("[respond]\nretention_days = soon\n")
    with pytest.raises(ValueError):
        runtime.respond_settings(cp)


def test_respond_connectors_logs_config_errors(tmp_path, caplog, monkeypatch):
    import agents.connectors as conn_mod

    class Fake:
        def __init__(self, config, state_dir):
            self.state_dir = state_dir
            self.errors = ["[connector.webhook] bad url"]

    monkeypatch.setattr(conn_mod, "Connectors", Fake)
    with caplog.at_level(logging.ERROR, logger="agents"):
        conn = runtime.respond_connectors(None, str(tmp_path))
    assert conn.state_dir == tmp_path
    assert [(r.name, r.getMessage()) for r in caplog.records] == \
        [("agents", "connector config: [connector.webhook] bad url")]


# ---- audit records for reject and unblock --------------------------------------------------

def _records(tmp_path):
    return sorted((tmp_path / "reports" / "response").glob("*.json"))


def test_reject_writes_an_audit_record_only_with_reports_dir(tmp_path):
    a, b = _queue(tmp_path, 2)
    before = set(_records(tmp_path))
    out = reject(a["id"], tmp_path / "state", by="o", now=NOW)
    assert out["status"] == "rejected" and set(_records(tmp_path)) == before
    out = reject(b["id"], tmp_path / "state", by="ops<b>", now=NOW + H,
                 reports_dir=tmp_path / "reports")
    [new] = set(_records(tmp_path)) - before
    assert new.name == f"{(NOW + H).strftime('%Y%m%dT%H%M%SZ')}-{b['id']}.json"
    assert stat.S_IMODE(new.stat().st_mode) == 0o600
    body = json.loads(new.read_text())
    assert body == {"timestamp": (NOW + H).isoformat(timespec="seconds"), "approval": out}
    assert out["rejected_by"] == "opsb"


def test_unblock_writes_an_audit_record(tmp_path):
    [a] = _queue(tmp_path, 1)
    target = tmp_path / "bl.txt"
    approve(a["id"], tmp_path / "state", tmp_path / "reports", tmp_path / "det", by="o",
            now=NOW, blocklist_file=target)
    before = set(_records(tmp_path))
    out = unblock("198.51.100.0/24", tmp_path / "state", tmp_path / "reports",
                  blocklist_file=target, now=NOW + H, by="ops<script>")
    assert out == {"removed": ["198.51.100.10"], "entries": 0, "file": "bl.txt"}
    [new] = set(_records(tmp_path)) - before
    assert new.name.startswith(f"{(NOW + H).strftime('%Y%m%dT%H%M%SZ')}-unblock-")
    assert stat.S_IMODE(new.stat().st_mode) == 0o600
    assert json.loads(new.read_text()) == {
        "timestamp": (NOW + H).isoformat(timespec="seconds"),
        "unblock": {"target": "198.51.100.0/24", "removed": ["198.51.100.10"], "by": "opsscript"}}


def test_retention_prunes_reject_and_unblock_records(tmp_path):
    [a] = _queue(tmp_path, 1)
    reject(a["id"], tmp_path / "state", by="o", now=NOW, reports_dir=tmp_path / "reports")
    unblock("198.51.100.77", tmp_path / "state", tmp_path / "reports",
            blocklist_file=tmp_path / "bl.txt", now=NOW, by="o")
    names = [p.name for p in _records(tmp_path)]
    assert any(f"-{a['id']}.json" in n for n in names) and any("-unblock-" in n for n in names)
    apply_retention(tmp_path / "state", tmp_path / "reports", NOW + datetime.timedelta(days=40),
                    RespondSettings(retention_days=30))
    assert _records(tmp_path) == []


def test_cli_reject_and_unblock_record_who(tmp_path):
    import agents.__main__ as cli

    a, b = _queue(tmp_path, 2)
    target = tmp_path / "bl.txt"
    approve(b["id"], tmp_path / "state", tmp_path / "reports", tmp_path / "det", by="o",
            now=NOW, blocklist_file=target)
    cfg = tmp_path / "config.ini"
    cfg.write_text(f"[respond]\nblocklist_file = {target}\n")
    common = ["--config", str(cfg), "--reports-dir", str(tmp_path / "reports"),
              "--state-dir", str(tmp_path / "state"), "--by", "night-shift"]
    before = set(_records(tmp_path))
    out = cli.run(["reject", a["id"], *common])
    assert out["approval"]["status"] == "rejected"
    out = cli.run(["unblock", b["subject"], *common])
    assert out["unblock"]["removed"] == [b["subject"]]
    bodies = [json.loads(p.read_text()) for p in sorted(set(_records(tmp_path)) - before)]
    whos = sorted(x["approval"]["rejected_by"] if "approval" in x else x["unblock"]["by"]
                  for x in bodies)
    assert whos == ["night-shift", "night-shift"]
