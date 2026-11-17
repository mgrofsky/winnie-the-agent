import datetime
import json

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
    assert summary["log_rotation"] == {"safe": True, "pending": []}
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
    assert summary["log_rotation"] == {"safe": True, "pending": []}

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


def test_ship_reports_unexported_events_as_pending(monkeypatch):
    results = {"ship": {"objects": 3, "more_pending": True}}
    status = cli.log_rotation_status(results)
    assert status["safe"] is False and any("ship" in p for p in status["pending"])


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
