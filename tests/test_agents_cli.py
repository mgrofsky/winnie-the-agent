import datetime
import json

import pytest
from agent_fakes import ssh_session, trap_event, write_log

import agents.__main__ as cli


def _setup(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    recs = ssh_session("session-a", "203.0.113.5", ["id"])
    recs += [trap_event("ftp", "auth_attempt", "192.0.2.4", f"f{i}", minutes=i, username="admin",
                        password=f"p{i}", success=False) for i in range(4)]
    # Shift the fixture two days into the past so sessions are idle and windows closed.
    first = datetime.datetime.fromisoformat(recs[0]["timestamp"])
    # Start at five past an hour so the events never straddle a campaign window boundary.
    old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)
           ).replace(minute=5, second=0, microsecond=0)
    for r in recs:
        r["timestamp"] = (old + (datetime.datetime.fromisoformat(r["timestamp"]) - first)).isoformat()
    write_log(tmp_path / "log.jsonl", recs)
    cfg = tmp_path / "config.ini"
    cfg.write_text("[honeypot]\nlog_file = log.jsonl\n[user_accounts]\nroot = *\n")
    (tmp_path / "overlay.json").write_text("{}\n")
    return ["--config", str(cfg), "--reports-dir", str(tmp_path / "reports"),
            "--detections-dir", str(tmp_path / "det"), "--overlay", str(tmp_path / "overlay.json"),
            "--data-dir", str(tmp_path / "data")]


def test_run_all_without_model_and_dry_run(tmp_path, monkeypatch):
    args = _setup(tmp_path, monkeypatch)
    cli.run(["run-all", "--dry-run", *args])
    assert not (tmp_path / "reports").exists() and not (tmp_path / "det").exists()

    summary = cli.run(["run-all", *args])
    assert summary["triage"]["deferred"] == []               # no model: deterministic records
    assert "session-a" in summary["triage"]["written"]
    assert len(summary["triage"]["written"]) == 2            # the SSH session and the FTP campaign
    assert summary["tune"]["changes"] == ["add_account ftp:admin"]   # tried 4 times
    assert '"username": "admin"' in (tmp_path / "overlay.json").read_text()
    assert (tmp_path / "config.ini").read_text().count("root = *") == 1  # config untouched
    assert (tmp_path / "det" / "pending" / "blocklist-candidates.csv").exists()
    assert list((tmp_path / "reports" / "daily").glob("*.md"))


def test_missing_log_on_a_new_sensor_is_nothing_to_do(tmp_path, caplog):
    cfg = tmp_path / "config.ini"
    cfg.write_text("[honeypot]\nlog_file = nope.jsonl\n")
    args = ["--config", str(cfg), "--no-llm", "--reports-dir", str(tmp_path / "r"),
            "--detections-dir", str(tmp_path / "det"), "--data-dir", str(tmp_path / "data"),
            "--overlay", str(tmp_path / "overlay.json")]
    with caplog.at_level("INFO"):
        assert cli.main(["triage", *args]) == 0
        summary = cli.run(["run-all", *args])
    assert "error" not in summary["triage"] and summary["triage"]["status"] == "no_log"
    assert summary["log_rotation"]["safe"] is True and summary["log_rotation"]["pending"] == []
    assert summary["log_rotation"]["log"] is None            # no file, nothing to rotate
    assert any("no event log yet" in r.getMessage() and r.levelname == "INFO"
               for r in caplog.records)
    assert not any(r.levelname in ("WARNING", "ERROR") for r in caplog.records)


def test_unreadable_log_is_still_an_error(tmp_path):
    (tmp_path / "logdir").mkdir()
    cfg = tmp_path / "config.ini"
    cfg.write_text("[honeypot]\nlog_file = logdir\n")
    args = ["triage", "--config", str(cfg), "--no-llm", "--reports-dir", str(tmp_path / "r")]
    assert cli.main(args) == 2
    assert "is a directory" in cli.run(args)["triage"]["error"]


def test_log_permission_denied_is_an_error(tmp_path):
    import os

    import pytest

    if os.geteuid() == 0:
        pytest.skip("root reads any file")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "log.jsonl").write_text("{}\n")
    locked.chmod(0o000)
    try:
        cfg = tmp_path / "config.ini"
        cfg.write_text(f"[honeypot]\nlog_file = {locked / 'log.jsonl'}\n")
        summary = cli.run(["triage", "--config", str(cfg), "--no-llm",
                           "--reports-dir", str(tmp_path / "r")])
        assert "permission denied" in summary["triage"]["error"]
    finally:
        locked.chmod(0o700)


def test_unwritable_state_dir_is_one_clear_error(tmp_path, monkeypatch, caplog, capsys):
    args = _setup(tmp_path, monkeypatch)
    blocked = tmp_path / "ro"
    blocked.mkdir()
    blocked.chmod(0o500)
    try:
        state = blocked / "state"
        for command in ("ship", "run-all", "respond", "triage"):
            caplog.clear()
            with caplog.at_level("ERROR"):
                assert cli.main([command, *args, "--state-dir", str(state)]) != 0, command
            out = json.loads(capsys.readouterr().err)
            assert set(out) == {"run_lock"}, command
            msg = out["run_lock"]["error"]
            assert str(state) in msg and "--state-dir" in msg
            errors = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
            assert errors == [msg] and "Traceback" not in msg
    finally:
        blocked.chmod(0o700)


def test_one_failing_stage_does_not_stop_the_others(tmp_path, monkeypatch):
    args = _setup(tmp_path, monkeypatch)
    (tmp_path / "log.jsonl").unlink()
    (tmp_path / "log.jsonl").mkdir()                       # triage fails reading a directory
    (tmp_path / "overlay.json").write_text("{broken")       # tuner refuses an invalid overlay
    summary = cli.run(["run-all", *args])
    assert "error" in summary["triage"]
    assert summary["digest"] == "written"
    assert summary["tune"]["errors"] and summary["tune"]["changes"] == []
    assert "rules" in summary["detect"]
    assert cli.main(["run-all", *args]) == 2


def test_unparseable_config_is_reported(tmp_path, monkeypatch):
    args = _setup(tmp_path, monkeypatch)
    (tmp_path / "config.ini").write_text("[user_accounts]\nbackup\n")
    summary = cli.run(["digest", *args])
    assert summary["config_error"].startswith("config not readable")
    assert summary["digest"] == "written"


def test_tune_history_and_rollback(tmp_path, monkeypatch):
    from agents.tuner import tune

    args = _setup(tmp_path, monkeypatch)
    proposed = {"kind": "add_account", "service": "ftp", "username": "backup", "password": "b"}
    tune(tmp_path / "overlay.json", tmp_path / "reports",
         state_dir=tmp_path / "reports" / "state" / "tuner", proposed=[proposed])
    hist = cli.run(["tune", "--history", *args])["history"]
    assert [h["n"] for h in hist] == [1] and hist[0]["changes"] == ["add_account ftp:backup"]
    cli.run(["tune", "--rollback", "1", *args])
    assert (tmp_path / "overlay.json").read_text() == "{}\n"


def test_honeytoken_registry_written_by_agents_from_the_frontend_seed(tmp_path, monkeypatch):
    from agents import runtime

    args = _setup(tmp_path, monkeypatch)
    cfg = tmp_path / "config.ini"
    cfg.write_text(cfg.read_text() + "[scenario]\nactive = sip_provider\n")
    cli.run(["digest", *args])
    assert not (tmp_path / "reports" / "honeytokens.json").exists()  # no seed yet: no registry
    assert not (tmp_path / "data" / runtime.SEED_FILE).exists()       # agents never create it
    seed = runtime.load_or_create_seed(tmp_path / "data")             # a front-end creates it
    cli.run(["digest", *args])
    registry = json.loads((tmp_path / "reports" / "honeytokens.json").read_text())
    assert registry["scenario"] == "sip_provider" and registry["tokens"]
    assert seed not in json.dumps(registry)


def test_second_respond_or_run_all_exits_while_one_holds_the_run_lock(tmp_path, monkeypatch, capsys):
    import fcntl

    args = _setup(tmp_path, monkeypatch)
    state = tmp_path / "reports" / "state"
    state.mkdir(parents=True)
    with open(state / "agents.lock", "a+") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for command in ("respond", "run-all"):
            assert cli.main([command, *args]) != 0
            summary = cli.run([command, *args])
            assert set(summary) == {"run_lock"}
            assert "another agents run holds" in summary["run_lock"]["error"]
        assert not (state / "respond_state.json").exists()
        assert not (tmp_path / "reports" / "sessions").exists()
    assert cli.main(["respond", *args]) == 0                 # lock released: runs normally
    assert (state / "respond_state.json").exists()


def test_run_all_says_when_rotating_the_log_would_lose_work(tmp_path, monkeypatch, caplog):
    args = _setup(tmp_path, monkeypatch)
    summary = cli.run(["run-all", *args])
    assert summary["log_rotation"]["safe"] is True and summary["log_rotation"]["pending"] == []
    assert summary["log_rotation"]["scope"] == "complete"
    triage = summary["log_rotation"]["readers"]["triage"]
    assert list(summary["log_rotation"]["readers"]) == ["triage"]
    assert triage["state"] == "confirmed" and triage["behind_bytes"] == 0
    assert triage["confirmed_offset"] == summary["log_rotation"]["log"]["complete_bytes"]
    assert triage["generation"] == summary["log_rotation"]["log"]["generation"]

    # A session still open (no close, recent) is not triaged yet: its lines must survive.
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    live = ssh_session("session-live", "203.0.113.9", ["uname -a"], closed=False)
    for r in live:
        r["timestamp"] = now
    with open(tmp_path / "log.jsonl", "a", encoding="utf-8") as f:
        for r in live:
            f.write(json.dumps(r) + "\n")
    with caplog.at_level("WARNING"):
        summary = cli.run(["run-all", *args])
    assert summary["log_rotation"]["safe"] is False
    assert any("triage" in p for p in summary["log_rotation"]["pending"])
    assert any("not safe to rotate" in r.getMessage() for r in caplog.records)


def test_ship_reports_unexported_events_as_pending(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text('{"a": 1}\n{"a": 2}\n')
    results = {"ship": {"objects": 3, "more_pending": True}}
    status = cli.log_rotation_status(results, log_path=log, state=tmp_path / "state",
                                     readers=["ship"])
    assert status["safe"] is False and any("ship" in p for p in status["pending"])


# ---- log rotation: every configured reader must confirm the same stable boundary ----------

class _FakeS3:
    def __init__(self, fail=False):
        self.puts = []
        self.fail = fail

    def put_object(self, **params):
        if self.fail:
            raise RuntimeError("boom")
        self.puts.append(params)
        return {}


def _export_setup(tmp_path, monkeypatch, enabled="true", readers="", fail=False):
    """The ``_setup`` sensor with the event export configured (fake client, loopback only)."""
    from agents import ship

    args = _setup(tmp_path, monkeypatch)
    cfg = tmp_path / "config.ini"
    cfg.write_text(cfg.read_text() + f"[connector.s3_events]\nenabled = {enabled}\n"
                   "bucket = example-honeypot-events\npasswords = drop\n"
                   + (f"[agents]\nlog_readers = {readers}\n" if readers else ""))
    s3 = _FakeS3(fail=fail)
    monkeypatch.setattr(ship, "default_client_factory", lambda _settings: s3)
    return args, s3


def _rotation(command, args):
    return cli.run([command, *args])["log_rotation"]


def _append_event(tmp_path):
    with open(tmp_path / "log.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(trap_event("ftp", "auth_attempt", "192.0.2.77", "late", minutes=0,
                                      username="admin", password="x", success=False)) + "\n")


def test_triage_only_lab_is_safe_once_triage_has_drained_the_log(tmp_path, monkeypatch):
    args = _setup(tmp_path, monkeypatch)                 # export not configured at all
    status = _rotation("triage", args)
    assert status["safe"] is True and status["pending"] == [] and status["scope"] == "complete"
    assert list(status["readers"]) == ["triage"]
    assert status["readers"]["triage"]["confirmed_offset"] == status["log"]["complete_bytes"] > 0


def test_both_enabled_readers_at_the_same_stable_boundary_are_safe(tmp_path, monkeypatch):
    args, s3 = _export_setup(tmp_path, monkeypatch)
    status = _rotation("run-all", args)
    assert s3.puts, "the export ran"
    assert status["safe"] is True and status["scope"] == "complete"
    boundary = status["log"]["complete_bytes"]
    assert {n: r["confirmed_offset"] for n, r in status["readers"].items()} == {
        "triage": boundary, "ship": boundary}
    assert all(r["state"] == "confirmed" for r in status["readers"].values())


def test_standalone_triage_is_not_safe_while_the_export_is_outstanding(tmp_path, monkeypatch):
    args, s3 = _export_setup(tmp_path, monkeypatch)
    status = _rotation("triage", args)
    assert status["safe"] is False and s3.puts == []
    assert status["readers"]["triage"]["state"] == "confirmed"
    assert status["readers"]["ship"]["state"] == "unconfirmed"
    assert any(p.startswith("ship:") for p in status["pending"])
    assert status["scope"] == "partial"


def test_standalone_shipping_is_not_safe_while_triage_is_outstanding(tmp_path, monkeypatch):
    args, s3 = _export_setup(tmp_path, monkeypatch)
    status = _rotation("ship", args)
    assert s3.puts, "everything was exported"
    assert status["readers"]["ship"]["state"] == "confirmed"
    assert status["safe"] is False and status["scope"] == "partial"
    assert status["readers"]["triage"]["state"] == "unconfirmed"
    assert any(p.startswith("triage:") for p in status["pending"])
    # Once triage has run on the same state, the same command can say both are done.
    assert _rotation("triage", args)["safe"] is True


def test_a_reader_listed_in_another_container_blocks_the_all_clear(tmp_path, monkeypatch):
    """The AWS agents container: export disabled here, enabled in the exporter container."""
    args, _ = _export_setup(tmp_path, monkeypatch, enabled="false", readers="triage, ship")
    status = _rotation("run-all", args)
    assert status["readers"]["triage"]["state"] == "confirmed"
    assert status["readers"]["ship"]["state"] == "unconfirmed"
    assert status["safe"] is False and status["scope"] == "partial"
    assert any("another container" in p for p in status["pending"])
    # The same run in a genuinely triage-only lab (nothing listed) is safe.
    lab = tmp_path / "lab"
    lab.mkdir()
    args, _ = _export_setup(lab, monkeypatch, enabled="false")
    assert _rotation("run-all", args)["safe"] is True


def test_a_disabled_or_failing_export_never_confirms(tmp_path, monkeypatch):
    args, _ = _export_setup(tmp_path, monkeypatch, enabled="false", readers="ship")
    status = _rotation("ship", args)                      # the export is disabled here
    assert status["safe"] is False
    assert any("disabled in this configuration" in p for p in status["pending"])

    failing = tmp_path / "failing"
    failing.mkdir()
    args, _ = _export_setup(failing, monkeypatch, fail=True)
    status = _rotation("run-all", args)
    assert status["readers"]["ship"]["state"] == "failed" and status["safe"] is False
    assert status["readers"]["triage"]["state"] == "confirmed"


def test_events_after_one_acknowledgment_make_the_log_unsafe_again(tmp_path, monkeypatch):
    args, _ = _export_setup(tmp_path, monkeypatch)
    assert _rotation("run-all", args)["safe"] is True
    _append_event(tmp_path)                                # new write after both confirmed
    status = _rotation("ship", args)                       # only the export acknowledges it
    assert status["readers"]["ship"]["state"] == "confirmed"
    assert status["readers"]["triage"]["state"] == "behind"
    assert status["readers"]["triage"]["behind_bytes"] > 0 and status["safe"] is False
    assert _rotation("run-all", args)["safe"] is True      # both caught up at the new boundary


def test_an_unfinished_line_at_the_end_of_the_log_is_not_safe(tmp_path, monkeypatch):
    args = _setup(tmp_path, monkeypatch)
    assert _rotation("triage", args)["safe"] is True
    with open(tmp_path / "log.jsonl", "a", encoding="utf-8") as f:
        f.write('{"timestamp": "2026-')                   # a writer is mid-line
    status = _rotation("triage", args)
    assert status["safe"] is False and any("unfinished line" in p for p in status["pending"])


def test_a_replaced_or_truncated_log_is_not_confirmed_by_the_old_cursor(tmp_path, monkeypatch):
    args, _ = _export_setup(tmp_path, monkeypatch)
    status = _rotation("run-all", args)
    assert status["safe"] is True
    log = tmp_path / "log.jsonl"
    state = tmp_path / "reports" / "state"
    readers = ["triage", "ship"]
    lines = log.read_text().splitlines(keepends=True)

    # Truncated in place (same inode): the cursors point past the end of the log.
    log.write_text("".join(lines[:1]))
    truncated = cli.log_rotation_status({}, log_path=log, state=state, readers=readers)
    assert truncated["safe"] is False
    assert {r["state"] for r in truncated["readers"].values()} == {"other_generation"}

    # Replaced by a new file (new inode) holding other events of about the same size.
    replacement = tmp_path / "replacement.jsonl"
    replacement.write_text("".join(l.replace("203.0.113", "203.0.114") for l in lines))
    replacement.replace(log)
    replaced = cli.log_rotation_status({}, log_path=log, state=state, readers=readers)
    assert replaced["safe"] is False
    assert {r["state"] for r in replaced["readers"].values()} == {"other_generation"}
    assert any("different log generation" in p for p in replaced["pending"])

    # An emptied log has nothing left to lose.
    log.write_text("")
    assert cli.log_rotation_status({}, log_path=log, state=state, readers=readers)["safe"] is True


def test_an_unknown_reader_name_is_never_confirmed(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text('{"a": 1}\n')
    status = cli.log_rotation_status({}, log_path=log, state=tmp_path, readers=["triage", "siem"])
    assert status["safe"] is False and any(p.startswith("siem:") for p in status["pending"])


def test_log_replaced_while_a_run_was_reading_is_not_claimed_by_the_new_file(tmp_path):
    """A reader confirms the file it read, not whatever file is there when it saves."""
    from agents.sessions import Cursor

    log = tmp_path / "log.jsonl"
    log.write_text('{"a": 1}\n' * 3)
    before = Cursor.sample(log)
    log.rename(tmp_path / "old.jsonl")
    log.write_text('{"b": 2}\n' * 3)                      # same size, a different file
    cursor = Cursor(tmp_path / "cursor.json")
    cursor.set_position(27, log, before)
    cursor.save()
    saved = Cursor(tmp_path / "cursor.json")
    assert saved.inode is None and saved.tail is None     # claims no file and no content
    assert saved.start_offset(log) == 0                   # the next run reads from the start


def test_log_truncated_and_regrown_in_place_during_a_run_is_not_claimed(tmp_path):
    from agents.sessions import Cursor

    log = tmp_path / "log.jsonl"
    log.write_text('{"a": 1}\n' * 3)
    before = Cursor.sample(log)
    log.write_text('{"b": 2}\n' * 3)                      # copytruncate and regrow: same inode
    assert Cursor.sample(log).inode == before.inode
    cursor = Cursor(tmp_path / "cursor.json")
    cursor.set_position(27, log, before)
    assert cursor.inode is None and cursor.tail is None


def _bump_mtime(path, seconds=1):
    """Move the modification time, so the test does not depend on timestamp granularity."""
    import os

    ns = path.stat().st_mtime_ns + seconds * 10**9
    os.utime(path, ns=(ns, ns))


def test_an_in_place_rewrite_after_the_pre_read_sample_is_not_blessed(tmp_path):
    from agents.rotation import rotation_status
    from agents.sessions import Cursor

    log = tmp_path / "log.jsonl"
    log.write_bytes(b"first\noldrow\n")
    before = Cursor.sample(log)
    log.write_bytes(b"first\nnewrow\n")                    # same inode, size and first line
    _bump_mtime(log)
    cursor = Cursor(tmp_path / "triage_cursor.json")
    cursor.set_position(before.end, log, before)
    cursor.save()
    saved = Cursor(tmp_path / "triage_cursor.json")
    assert saved.inode is None and saved.tail is None      # the new tail was not certified
    status = rotation_status({}, log, tmp_path, ["triage"])
    assert status["safe"] is False                         # the cursor claims no file
    assert status["readers"]["triage"]["state"] == "other_generation"


def test_even_with_a_coarse_clock_the_changed_boundary_window_is_caught(tmp_path):
    from agents.sessions import Cursor

    log = tmp_path / "log.jsonl"
    log.write_bytes(b"first\noldrow\n")
    before = Cursor.sample(log)
    log.write_bytes(b"first\nnewrow\n")                    # mtime left as the write set it
    cursor = Cursor(tmp_path / "cursor.json")
    cursor.set_position(before.end, log, before)
    assert cursor.tail is None


def test_append_only_progress_keeps_the_stamp(tmp_path):
    from agents.rotation import rotation_status
    from agents.sessions import Cursor

    log = tmp_path / "log.jsonl"
    log.write_bytes(b"first\nsecond\n")
    before = Cursor.sample(log)
    with open(log, "ab") as f:
        f.write(b"third\n")                                # a writer appends during the run
    cursor = Cursor(tmp_path / "triage_cursor.json")
    cursor.set_position(before.end, log, before)           # the reader handled up to `before`
    cursor.save()
    saved = Cursor(tmp_path / "triage_cursor.json")
    assert saved.inode == before.inode and saved.tail == before.tails[before.end]
    assert saved.start_offset(log) == before.end
    triage = rotation_status({}, log, tmp_path, ["triage"])["readers"]["triage"]
    assert triage["state"] == "behind" and triage["behind_bytes"] == 6
    cursor.set_position(before.end + 6, log, Cursor.sample(log))
    cursor.save()
    assert rotation_status({}, log, tmp_path, ["triage"])["safe"] is True


def test_copytruncate_and_regrow_past_the_old_size_is_not_blessed(tmp_path):
    from agents.sessions import Cursor

    log = tmp_path / "log.jsonl"
    log.write_bytes(b"first\nsecond\n")
    before = Cursor.sample(log)
    log.write_bytes(b"first\nother-second\nand more rows after the truncate\n")   # larger now
    cursor = Cursor(tmp_path / "cursor.json")
    cursor.set_position(before.end, log, before)
    assert cursor.inode is None and cursor.tail is None


def test_a_failed_pre_read_sample_certifies_nothing(tmp_path):
    from agents.sessions import Cursor

    log = tmp_path / "log.jsonl"
    log.write_bytes(b"first\nsecond\n")
    cursor = Cursor(tmp_path / "cursor.json")
    cursor.set_position(13, log, None)
    assert cursor.inode is None and cursor.tail is None and cursor.size is None
    assert cursor.start_offset(log) == 0


def _big_log(tmp_path, n=120):
    old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)
           ).replace(minute=5, second=0, microsecond=0)
    recs = []
    for i in range(n):
        rec = trap_event("ftp", "auth_attempt", "192.0.2.4", f"f{i}", username="admin",
                         password=f"pw{i:04d}", success=False)
        rec["timestamp"] = (old + datetime.timedelta(seconds=i)).isoformat()
        recs.append(rec)
    return write_log(tmp_path / "log.jsonl", recs)


def test_a_same_size_rewrite_away_from_the_first_line_and_the_tail_is_caught(
        tmp_path, monkeypatch):
    """The real readers confirmed this log. A line in the middle is then rewritten in place with
    the same size: the inode, first line and last 4 KiB are all unchanged, only the modification
    time moves."""
    from agents.sessions import Cursor, sample_log

    args, _ = _export_setup(tmp_path, monkeypatch)
    log = _big_log(tmp_path)
    assert _rotation("run-all", args)["safe"] is True
    state = tmp_path / "reports" / "state"
    data = log.read_bytes()
    sample = sample_log(log)
    spot = data.index(b"pw0040")
    covered = [(o - min(o, 4096), o) for o in sample.tails]
    assert not any(a <= spot < b for a, b in covered), "the edit must miss every sampled window"
    stat = log.stat()
    log.write_bytes(data.replace(b"pw0040", b"px0040"))
    after = log.stat()
    assert (after.st_ino, after.st_size) == (stat.st_ino, stat.st_size)
    _bump_mtime(log)
    assert Cursor(state / "triage_cursor.json").tail == sample_log(
        log, [Cursor(state / "triage_cursor.json").offset]).tails[
        Cursor(state / "triage_cursor.json").offset]                   # tail itself unchanged
    status = cli.log_rotation_status({}, log_path=log, state=state, readers=["triage", "ship"])
    assert status["safe"] is False
    assert {r["state"] for r in status["readers"].values()} == {"other_generation"}
    assert any("rewritten in place" in p for p in status["pending"])


def _middle_rewrite(log, old=b"pw0040", new=b"px0040"):
    """Rewrite one line in the middle in place: same inode and length, first line and last
    4 KiB untouched."""
    data = log.read_bytes()
    before = log.stat()
    log.write_bytes(data.replace(old, new))
    assert (log.stat().st_ino, log.stat().st_size) == (before.st_ino, before.st_size)
    _bump_mtime(log)


def test_triage_and_shipping_reread_after_a_same_length_middle_rewrite(tmp_path, monkeypatch):
    """Both readers must notice on entry, not only the rotation check: otherwise a reader reads
    0 bytes, re-stamps the new modification time and the rewrite is declared handled."""
    from agents.sessions import Cursor

    args, s3 = _export_setup(tmp_path, monkeypatch)
    log = _big_log(tmp_path)
    assert _rotation("run-all", args)["safe"] is True
    size = log.stat().st_size
    state = tmp_path / "reports" / "state"
    assert cli.run(["triage", *args])["triage"]["bytes_read"] == 0       # nothing new: resumes
    s3.puts.clear()

    _middle_rewrite(log, b'"f40"', b'"g40"')               # an externally visible field
    triage = cli.run(["triage", *args])
    assert triage["triage"]["bytes_read"] == size                          # read it all again
    assert triage["triage"]["written"] == [] and triage["triage"]["llm_calls"] == 0   # no replay
    assert triage["log_rotation"]["readers"]["triage"]["state"] == "confirmed"
    shipped = cli.run(["ship", *args])
    assert shipped["ship"]["start_offset"] == 0 and s3.puts
    uploaded = [json.loads(line) for p in s3.puts for line in p["Body"].decode().splitlines()]
    names = {event["detail"]["task_name"] for event in uploaded}
    assert "g40" in names and "f40" not in names           # the changed field was exported
    assert shipped["log_rotation"]["safe"] is True
    assert Cursor(state / "ship_cursor.json").offset == size


def _ssh_log(tmp_path, n=30):
    recs = []
    for i in range(n):
        recs += ssh_session(f"session-{i:04d}", f"203.0.113.{i + 1}", ["id", "uname -a"], start=i)
    first = datetime.datetime.fromisoformat(recs[0]["timestamp"])
    old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)
           ).replace(minute=5, second=0, microsecond=0)
    for r in recs:
        r["timestamp"] = (old + (datetime.datetime.fromisoformat(r["timestamp"]) - first)
                          ).isoformat()
    return write_log(tmp_path / "log.jsonl", recs)


def test_a_session_id_introduced_by_a_middle_rewrite_gets_its_record_before_safe(
        tmp_path, monkeypatch):
    """The rewrite changes one session id to another of the same length, so the log keeps its
    size, first line and tail. The new id was never handled: it must be triaged and exported
    before the log is declared safe to rotate, while the sessions that already have records
    are not triaged again."""
    args, s3 = _export_setup(tmp_path, monkeypatch)
    log = _ssh_log(tmp_path)
    first = cli.run(["run-all", *args])
    assert first["log_rotation"]["safe"] is True and len(first["triage"]["written"]) >= 30
    sessions = tmp_path / "reports" / "sessions"
    assert not (sessions / "session-0099.json").exists()
    s3.puts.clear()

    _middle_rewrite(log, b"session-0020", b"session-0099")
    second = cli.run(["run-all", *args])
    assert second["triage"]["written"] == ["session-0099"]               # only the new id
    assert second["triage"]["llm_calls"] == 0
    assert (sessions / "session-0099.json").exists()                     # its record exists ...
    assert second["log_rotation"]["safe"] is True                        # ... before safe
    uploaded = [json.loads(line) for p in s3.puts for line in p["Body"].decode().splitlines()]
    assert "session-0099" in {event["detail"]["task_name"] for event in uploaded}


def test_a_true_append_still_resumes_from_each_cursor(tmp_path, monkeypatch):
    args, s3 = _export_setup(tmp_path, monkeypatch)
    log = _big_log(tmp_path)
    assert _rotation("run-all", args)["safe"] is True
    offset = log.stat().st_size
    s3.puts.clear()
    with open(log, "ab") as f:
        f.write(log.read_bytes().splitlines(keepends=True)[-1])           # one more line
    added = log.stat().st_size - offset
    triage = cli.run(["triage", *args])
    assert triage["triage"]["bytes_read"] == added                         # only the new line
    shipped = cli.run(["ship", *args])
    assert shipped["ship"]["start_offset"] == offset and len(s3.puts) == 1
    assert shipped["log_rotation"]["safe"] is True


def test_start_offset_distrusts_a_same_size_file_with_a_new_modification_time(tmp_path):
    from agents.sessions import Cursor

    log = tmp_path / "log.jsonl"
    log.write_bytes(b"first\nsecond\n")
    cursor = Cursor(tmp_path / "cursor.json")
    cursor.set_position(13, log, Cursor.sample(log))
    assert cursor.start_offset(log) == 13
    _bump_mtime(log)
    assert cursor.start_offset(log) == 0                                   # same size, touched
    with open(log, "ab") as f:
        f.write(b"third\n")
    assert cursor.start_offset(log) == 13                                  # a true append resumes


def _bounded(fn, seconds=15):
    import threading

    box = {}
    worker = threading.Thread(target=lambda: box.update(result=fn()), daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), "the command blocked on the event log"
    return box["result"]


@pytest.mark.parametrize("command", ["triage", "ship", "run-all"])
def test_a_fifo_event_log_is_rejected_before_any_reader_opens_it(tmp_path, monkeypatch, command):
    import os

    args, s3 = _export_setup(tmp_path, monkeypatch)
    fifo = tmp_path / "events.fifo"
    os.mkfifo(fifo)
    summary = _bounded(lambda: cli.run([command, *args, "--log", str(fifo)]))
    errors = [summary[k]["error"] for k in ("triage", "ship") if k in summary]
    assert errors and all("not a regular file" in e for e in errors)
    if command == "run-all":
        assert len(errors) == 2                            # triage and the enabled export
    assert summary["log_rotation"]["safe"] is False and s3.puts == []


def test_event_log_state_rejects_non_regular_paths_and_keeps_its_other_messages(tmp_path):
    import os

    from agents.runtime import event_log_state

    fifo = tmp_path / "f"
    os.mkfifo(fifo)
    assert event_log_state(fifo) == ("error", f"event log path is not a regular file: {fifo}")
    assert event_log_state(tmp_path) == ("error", f"event log path is a directory: {tmp_path}")
    assert event_log_state(tmp_path / "none") == ("missing", None)
    ok = tmp_path / "ok.jsonl"
    ok.write_text("")
    assert event_log_state(ok) == ("ok", None)


def test_a_rewrite_during_the_pre_and_post_samples_fails_closed_at_equal_size(
        tmp_path, monkeypatch):
    import agents.rotation as rotation

    args = _setup(tmp_path, monkeypatch)
    assert _rotation("triage", args)["safe"] is True
    log = tmp_path / "log.jsonl"
    real = rotation.sample_log
    calls = []

    def rewriting(path, offsets=()):
        calls.append(1)
        sample = real(path, offsets)
        if len(calls) == 1:                                 # same size, same first line
            data = log.read_bytes()
            log.write_bytes(data[:-4] + b"ABC\n")
            _bump_mtime(log)
        return sample

    monkeypatch.setattr(rotation, "sample_log", rewriting)
    status = _rotation("triage", args)
    assert status["safe"] is False and any("moved" in p for p in status["pending"])


def test_a_legacy_triage_cursor_is_trusted_for_resume_and_causes_no_second_record(
        tmp_path, monkeypatch):
    """Rereading from the start would triage every old session again (a second record, and a
    model call each), so triage keeps resuming from a legacy cursor and just adds the stamp."""
    args = _setup(tmp_path, monkeypatch)
    first = cli.run(["triage", *args])
    assert first["triage"]["written"]
    path = tmp_path / "reports" / "state" / "triage_cursor.json"
    legacy = json.loads(path.read_text())
    for key in ("tail", "size", "mtime_ns"):
        legacy.pop(key)
    path.write_text(json.dumps(legacy))
    again = cli.run(["triage", *args])
    assert again["triage"]["written"] == [] and again["triage"]["llm_calls"] == 0
    assert json.loads(path.read_text())["tail"] is not None
    assert again["log_rotation"]["safe"] is True


def test_a_refused_stamp_keeps_the_ids_so_the_reread_makes_no_duplicates(tmp_path, monkeypatch):
    """When the pre-read sample failed, the cursor will restart from 0; the handled ids must
    survive that, or every session would be triaged a second time."""
    from agents.sessions import Cursor

    args = _setup(tmp_path, monkeypatch)
    real = Cursor.sample
    monkeypatch.setattr(Cursor, "sample", staticmethod(lambda *a, **k: None))
    first = cli.run(["triage", *args])
    assert first["triage"]["written"]
    monkeypatch.setattr(Cursor, "sample", staticmethod(real))
    again = cli.run(["triage", *args])                      # rereads from 0
    assert again["triage"]["written"] == [] and again["triage"]["llm_calls"] == 0
    assert again["log_rotation"]["safe"] is True


def _confirmed_setup(tmp_path, monkeypatch, **kw):
    args, s3 = _export_setup(tmp_path, monkeypatch, **kw)
    assert _rotation("run-all", args)["safe"] is True
    state = tmp_path / "reports" / "state"
    return args, state, tmp_path / "log.jsonl"


def test_a_same_size_rewrite_in_place_defeats_a_stale_matching_cursor(tmp_path, monkeypatch):
    args, state, log = _confirmed_setup(tmp_path, monkeypatch)
    before = log.stat()
    text = log.read_text()
    log.write_text(text.replace("203.0.113", "203.0.114").replace("192.0.2.4", "192.0.2.5"))
    after = log.stat()
    assert (after.st_ino, after.st_size) == (before.st_ino, before.st_size)
    status = cli.log_rotation_status({}, log_path=log, state=state, readers=["triage", "ship"])
    assert status["safe"] is False                          # same inode and size, other events
    assert {r["state"] for r in status["readers"].values()} == {"other_generation"}


def test_a_same_size_rewrite_of_only_the_tail_is_caught_when_the_first_line_is_kept(
        tmp_path, monkeypatch):
    args, state, log = _confirmed_setup(tmp_path, monkeypatch)
    lines = log.read_text().splitlines(keepends=True)
    last = lines[-1].replace("p3", "q3") if "p3" in lines[-1] else lines[-1][:-2] + "X\n"
    assert len(last) == len(lines[-1]) and last != lines[-1]
    log.write_text("".join(lines[:-1]) + last)
    status = cli.log_rotation_status({}, log_path=log, state=state, readers=["triage", "ship"])
    assert status["safe"] is False
    assert {r["state"] for r in status["readers"].values()} == {"other_generation"}
    assert any("rewritten in place" in p for p in status["pending"])   # first line unchanged


def test_a_cursor_from_an_older_version_resumes_but_confirms_nothing(tmp_path, monkeypatch):
    args, state, log = _confirmed_setup(tmp_path, monkeypatch)
    for name in ("triage_cursor.json", "ship_cursor.json"):      # drop the new field
        data = json.loads((state / name).read_text())
        data.pop("tail")
        (state / name).write_text(json.dumps(data))
    from agents.sessions import Cursor

    assert Cursor(state / "triage_cursor.json").start_offset(log) > 0   # still resumes
    status = cli.log_rotation_status({}, log_path=log, state=state, readers=["triage", "ship"])
    assert status["safe"] is False
    assert {r["state"] for r in status["readers"].values()} == {"unverified"}
    # One run of each reader writes the fingerprint and the log can be confirmed again.
    assert _rotation("run-all", args)["safe"] is True


def test_a_required_reader_disabled_here_is_not_confirmed_by_an_old_matching_cursor(
        tmp_path, monkeypatch):
    args, state, log = _confirmed_setup(tmp_path, monkeypatch)
    cfg = tmp_path / "config.ini"                              # export now off in this config,
    cfg.write_text(cfg.read_text().replace("enabled = true", "enabled = false")
                   + "[agents]\nlog_readers = triage, ship\n")  # but still a required reader
    status = _rotation("triage", args)
    assert status["safe"] is False and status["scope"] == "partial"
    assert status["readers"]["ship"]["state"] == "unconfirmed"      # its old cursor matches


def test_a_log_that_cannot_be_read_never_gets_an_all_clear(tmp_path, monkeypatch):
    args = _setup(tmp_path, monkeypatch)
    log = tmp_path / "log.jsonl"
    assert _rotation("triage", args)["safe"] is True
    log.chmod(0)
    try:
        import os

        if os.access(log, os.R_OK):
            pytest.skip("permissions are not enforced for this user")
        status = cli.log_rotation_status({}, log_path=log, state=tmp_path / "reports" / "state",
                                         readers=["triage"])
        assert status["safe"] is False and any("cannot be read" in p for p in status["pending"])
    finally:
        log.chmod(0o600)


def test_a_log_that_is_not_a_regular_file_never_gets_an_all_clear(tmp_path):
    (tmp_path / "logdir").mkdir()
    status = cli.log_rotation_status({}, log_path=tmp_path / "logdir", state=tmp_path,
                                     readers=["triage"])
    assert status["safe"] is False and any("not a regular file" in p for p in status["pending"])
    fifo = tmp_path / "fifo"
    import os

    os.mkfifo(fifo)
    status = cli.log_rotation_status({}, log_path=fifo, state=tmp_path, readers=["triage"])
    assert status["safe"] is False and any("not a regular file" in p for p in status["pending"])


def test_a_failed_triage_on_an_unreadable_log_is_not_an_all_clear(tmp_path):
    (tmp_path / "logdir").mkdir()
    cfg = tmp_path / "config.ini"
    cfg.write_text("[honeypot]\nlog_file = logdir\n")
    summary = cli.run(["triage", "--config", str(cfg), "--no-llm", "--reports-dir",
                       str(tmp_path / "r")])
    assert "is a directory" in summary["triage"]["error"]
    assert summary["log_rotation"]["safe"] is False
    assert any(p.startswith("triage:") for p in summary["log_rotation"]["pending"])


def test_a_failed_reader_blocks_even_a_missing_or_empty_log(tmp_path):
    log = tmp_path / "missing.jsonl"
    failed = {"ship": {"error": "[connector.s3_events]: bucket is missing"}}
    status = cli.log_rotation_status(failed, log_path=log, state=tmp_path, readers=["triage", "ship"])
    assert status["safe"] is False and status["log"] is None
    ok = cli.log_rotation_status({}, log_path=log, state=tmp_path, readers=["triage"])
    assert ok["safe"] is True                              # genuinely never created
    log.write_text("")
    assert cli.log_rotation_status(failed, log_path=log, state=tmp_path,
                                   readers=["triage", "ship"])["safe"] is False
    assert cli.log_rotation_status({}, log_path=log, state=tmp_path, readers=["triage"])["safe"]


def test_a_configuration_error_withholds_the_all_clear(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text("")
    for name in ("missing.ini", "broken.ini"):
        cfg = tmp_path / name
        if name == "broken.ini":
            cfg.write_text("[honeypot\nlog_file = nope\n")
        summary = cli.run(["triage", "--config", str(cfg), "--log", str(log), "--no-llm",
                           "--reports-dir", str(tmp_path / "r"),
                           "--detections-dir", str(tmp_path / "det"),
                           "--overlay", str(tmp_path / "overlay.json"),
                           "--data-dir", str(tmp_path / "data")])
        assert "config_error" in summary, name
        assert summary["log_rotation"]["safe"] is False, name
        assert any("configuration could not be read" in p
                   for p in summary["log_rotation"]["pending"]), name
    # With a log that has events the answer is also no, and the missing-log case too.
    status = cli.log_rotation_status({}, log_path=tmp_path / "gone.jsonl", state=tmp_path,
                                     readers=["triage"], config_error="bad")
    assert status["safe"] is False


def test_a_config_that_cannot_be_opened_is_a_configuration_error(tmp_path):
    """A directory or an unreadable file given as --config used to read as an empty config, so a
    nonempty --log was judged against triage alone and could be called safe."""
    import os

    log = tmp_path / "log.jsonl"
    log.write_text('{"a": 1}\n')
    unreadable = tmp_path / "unreadable.ini"
    unreadable.write_text("[connector.s3_events]\nenabled = true\n")
    unreadable.chmod(0)
    bad = {"directory": tmp_path / "conf.d", "unreadable": unreadable}
    (tmp_path / "conf.d").mkdir()
    try:
        for name, config in bad.items():
            if name == "unreadable" and os.access(config, os.R_OK):
                continue                                   # permissions are not enforced here
            summary = cli.run(["triage", "--config", str(config), "--log", str(log), "--no-llm",
                               "--reports-dir", str(tmp_path / "r"),
                               "--detections-dir", str(tmp_path / "det"),
                               "--overlay", str(tmp_path / "overlay.json"),
                               "--data-dir", str(tmp_path / "data")])
            assert summary["config_error"].startswith("config not readable"), name
            assert summary["log_rotation"]["safe"] is False, name
            assert any("configuration could not be read" in p
                       for p in summary["log_rotation"]["pending"]), name
    finally:
        unreadable.chmod(0o600)


def test_a_config_that_is_not_a_regular_readable_file_is_reported_by_the_loader(tmp_path):
    (tmp_path / "dir").mkdir()
    _cp, base, error = cli._load_config(str(tmp_path / "dir"))
    assert error and error.startswith("config not readable: ")
    assert base == (tmp_path).resolve()
    _cp, _base, error = cli._load_config(str(tmp_path / "absent.ini"))
    assert error == f"config not found: {tmp_path / 'absent.ini'}"
    good = tmp_path / "good.ini"
    good.write_text("[honeypot]\nlog_file = x.log\n")
    cp, _base, error = cli._load_config(str(good))
    assert error is None and cp["honeypot"]["log_file"] == "x.log"


def test_a_log_that_moves_between_the_two_samples_fails_closed(tmp_path, monkeypatch):
    import agents.rotation as rotation

    args = _setup(tmp_path, monkeypatch)
    assert _rotation("triage", args)["safe"] is True
    real = rotation.sample_log
    calls = []

    def moving(path, offsets=()):
        calls.append(1)
        sample = real(path, offsets)
        if len(calls) == 1:                                # a writer appends after the first look
            _append_event(tmp_path)
        return sample

    monkeypatch.setattr(rotation, "sample_log", moving)
    status = _rotation("triage", args)
    assert status["safe"] is False and any("moved" in p for p in status["pending"])
    assert len(calls) == 2


def test_the_boundary_counts_only_newline_complete_bytes(tmp_path):
    from agents.sessions import sample_log

    log = tmp_path / "log.jsonl"
    log.write_bytes(b'{"a": 1}\n{"b": 2}\n{"c"')
    sample = sample_log(log, [9])
    assert (sample.size, sample.end) == (22, 18)
    assert sample.tails[18] is not None and sample.tails[9] is not None
    assert sample.tails.get(22) is None
    log.write_bytes(b'no newline yet')
    assert sample_log(log).end == 0
    log.write_bytes(b"")
    assert sample_log(log).end == 0


def test_a_long_unfinished_line_fails_closed_without_scanning_the_file(tmp_path, monkeypatch):
    import agents.sessions as sessions

    monkeypatch.setattr(sessions, "MAX_PARTIAL_BYTES", 1024)
    log = tmp_path / "log.jsonl"
    log.write_bytes(b'{"a": 1}\n' + b"x" * 5000)
    with pytest.raises(OSError):
        sessions.sample_log(log)
    status = cli.log_rotation_status({}, log_path=log, state=tmp_path, readers=["triage"])
    assert status["safe"] is False and any("unreadable" in p or "cannot be read" in p
                                           for p in status["pending"])


def test_every_writing_command_waits_for_the_run_lock(tmp_path, monkeypatch):
    import fcntl

    args = _setup(tmp_path, monkeypatch)
    state = tmp_path / "reports" / "state"
    state.mkdir(parents=True)
    with open(state / "agents.lock", "a+") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for command in (["triage"], ["tune"], ["detect"], ["digest"], ["tune", "--rollback", "1"]):
            summary = cli.run([*command, *args])
            assert set(summary) == {"run_lock"}, command
        assert not (tmp_path / "reports" / "sessions").exists()
        assert not (tmp_path / "reports" / "daily").exists()
        assert not (tmp_path / "det").exists()
    assert "error" not in cli.run(["triage", *args])["triage"]      # released: runs normally
    assert "history" in cli.run(["tune", "--history", *args])       # read-only: no lock needed


# ---- ui -------------------------------------------------------------------------------------

def _ui_setup(tmp_path, monkeypatch, ui_section=""):
    args = _setup(tmp_path, monkeypatch)
    cfg = tmp_path / "config.ini"
    cfg.write_text(cfg.read_text() + ui_section)
    monkeypatch.delenv("WINNIE_UI_TOKEN", raising=False)
    return args


def _capture_serve(monkeypatch):
    from agents.ui import server

    seen = {}

    def fake_serve(settings, routes):
        seen["settings"], seen["routes"] = settings, routes

    monkeypatch.setattr(server, "serve", fake_serve)
    return seen


def test_ui_reads_its_section_and_flags_override(tmp_path, monkeypatch):
    args = _ui_setup(tmp_path, monkeypatch,
                     "[ui]\nport = 9001\nbind = ::1\nactions = false\noperator = alice\n")
    seen = _capture_serve(monkeypatch)
    assert cli.run(["ui", *args]) == {"ui": {"status": "stopped"}}
    s = seen["settings"]
    assert (s.port, s.bind, s.actions, s.operator, s.allow_non_loopback, s.token) == \
        (9001, "::1", False, "alice", False, "")
    cli.run(["ui", "--port", "0", "--bind", "127.0.0.1", "--actions", "--by", "bob",
             "--allow-non-loopback", *args])
    s = seen["settings"]
    assert (s.port, s.bind, s.actions, s.operator, s.allow_non_loopback) == \
        (0, "127.0.0.1", True, "bob", True)
    paths = seen["routes"].paths
    assert paths.reports == tmp_path / "reports" and paths.state == tmp_path / "reports" / "state"
    assert paths.log == tmp_path / "log.jsonl" and paths.data == tmp_path / "data"


def test_ui_defaults_without_a_section_and_token_only_from_the_environment(tmp_path, monkeypatch):
    args = _ui_setup(tmp_path, monkeypatch, "[ui]\ntoken = from-the-config-file-never-used\n")
    seen = _capture_serve(monkeypatch)
    cli.run(["ui", *args])
    s = seen["settings"]
    assert (s.port, s.bind, s.actions, s.operator, s.token) == (8480, "127.0.0.1", False, "", "")
    monkeypatch.setenv("WINNIE_UI_TOKEN", "e" * 32)
    cli.run(["ui", *args])
    assert seen["settings"].token == "e" * 32


def test_ui_takes_no_run_lock_builds_no_model_and_writes_nothing(tmp_path, monkeypatch):
    import fcntl

    args = _ui_setup(tmp_path, monkeypatch)
    _capture_serve(monkeypatch)
    monkeypatch.setattr(cli, "_llm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("llm")))
    monkeypatch.setattr(cli, "build_json_llm",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("llm")))
    state = tmp_path / "reports" / "state"
    state.mkdir(parents=True)
    with open(state / "agents.lock", "a+") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert cli.run(["ui", *args]) == {"ui": {"status": "stopped"}}
    assert sorted(p.name for p in state.iterdir()) == ["agents.lock"]
    assert not (tmp_path / "data").exists() and not (tmp_path / "det").exists()


def test_ui_logs_the_sign_in_link_exactly_once(tmp_path, monkeypatch, caplog):
    from agents.ui import server

    args = _ui_setup(tmp_path, monkeypatch)
    monkeypatch.setenv("WINNIE_UI_TOKEN", "t" * 40)

    def stop(self, *a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(server.UiServer, "serve_forever", stop)
    with caplog.at_level("INFO", logger="agents.ui"):
        assert cli.run(["ui", "--port", "0", *args]) == {"ui": {"status": "stopped"}}
    links = [r for r in caplog.records if "t" * 40 in r.getMessage()]
    assert len(links) == 1 and links[0].name == "agents.ui" and links[0].levelname == "INFO"
    assert "sign in at http://127.0.0.1:" in links[0].getMessage()


def test_ui_external_host_from_config_and_the_flag_wins(tmp_path, monkeypatch):
    args = _ui_setup(tmp_path, monkeypatch, "[ui]\nexternal_host = cfg.example-tailnet.ts.net\n")
    seen = _capture_serve(monkeypatch)
    cli.run(["ui", *args])
    assert seen["settings"].external_host == "cfg.example-tailnet.ts.net"
    cli.run(["ui", "--external-host", "flag.example-tailnet.ts.net", *args])
    assert seen["settings"].external_host == "flag.example-tailnet.ts.net"
    cli.run(["ui", "--external-host", "", *args])  # an empty flag turns it off
    assert seen["settings"].external_host == ""
    args = _ui_setup(tmp_path, monkeypatch)
    cli.run(["ui", *args])
    assert seen["settings"].external_host == ""


@pytest.mark.parametrize("value", ["localhost", "198.51.100.7", "https://sensor.example.net",
                                   "sensor.example.net/", "*.example.net", "sensor.example.net.",
                                   "sensor.example.net:0", "sensor"])
def test_ui_refuses_to_start_on_a_bad_external_host(tmp_path, monkeypatch, value):
    args = _ui_setup(tmp_path, monkeypatch)
    monkeypatch.setenv("WINNIE_UI_TOKEN", "t" * 40)
    result = cli.run(["ui", "--port", "0", "--external-host", value, *args])
    assert "external_host" in result["ui"]["error"] and "t" * 40 not in result["ui"]["error"]
    args = _ui_setup(tmp_path, monkeypatch, f"[ui]\nexternal_host = {value}\n")
    monkeypatch.setenv("WINNIE_UI_TOKEN", "t" * 40)
    assert "external_host" in cli.run(["ui", "--port", "0", *args])["ui"]["error"]
    assert cli.main(["ui", "--port", "0", *args]) == 2


def test_ui_external_host_does_not_relax_the_bind_guard(tmp_path, monkeypatch):
    args = _ui_setup(tmp_path, monkeypatch, "[ui]\nexternal_host = sensor.example.net\n")
    result = cli.run(["ui", "--bind", "0.0.0.0", "--port", "0", *args])
    assert "non-loopback" in result["ui"]["error"]


def test_ui_refuses_bad_settings_with_an_error(tmp_path, monkeypatch):
    args = _ui_setup(tmp_path, monkeypatch)
    result = cli.run(["ui", "--bind", "0.0.0.0", "--port", "0", *args])
    assert "non-loopback" in result["ui"]["error"]
    monkeypatch.setenv("WINNIE_UI_TOKEN", "short")
    result = cli.run(["ui", "--port", "0", *args])
    assert "at least" in result["ui"]["error"] and "short" not in result["ui"]["error"]
    assert cli.main(["ui", "--port", "0", *args]) == 2
    args = _ui_setup(tmp_path, monkeypatch, "[ui]\nport = eighty\n")
    assert "error" in cli.run(["ui", *args])["ui"]


@pytest.mark.parametrize("value,expected", [("200000", 200_000), ("2000000", 500_000),
                                            ("5", 1_000)])
def test_ui_activity_entries_are_clamped_to_the_documented_range(tmp_path, monkeypatch, value,
                                                                  expected):
    args = _ui_setup(tmp_path, monkeypatch, f"[ui]\nactivity_entries = {value}\n")
    seen = _capture_serve(monkeypatch)
    cli.run(["ui", *args])
    assert seen["routes"].events.max_entries == expected


def test_ui_passes_the_map_home_and_label(tmp_path, monkeypatch):
    args = _ui_setup(tmp_path, monkeypatch,
                     "[ui]\nmap_home = 51.5, -0.1\nmap_label = Lab \x1b[31msensor\n")
    seen = _capture_serve(monkeypatch)
    cli.run(["ui", *args])
    assert seen["routes"].map_home == (51.5, -0.1)
    assert seen["routes"].map_label == "Lab [31msensor"
    args = _ui_setup(tmp_path, monkeypatch)
    cli.run(["ui", *args])
    assert seen["routes"].map_home is None and seen["routes"].map_label == ""


@pytest.mark.parametrize("value", ["51.5", "91,0", "0,181", "nan,0", "inf,0", "a,b", "1,2,3",
                                   "1e2,0"])
def test_ui_refuses_to_start_on_a_bad_map_home(tmp_path, monkeypatch, value):
    args = _ui_setup(tmp_path, monkeypatch, f"[ui]\nmap_home = {value}\n")
    seen = _capture_serve(monkeypatch)
    result = cli.run(["ui", *args])
    assert "map_home" in result["ui"]["error"] and value not in result["ui"]["error"]
    assert "routes" not in seen
