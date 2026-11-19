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
