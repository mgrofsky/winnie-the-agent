"""Event-log session index for transcript replay: incremental, rotation-aware, read-only."""

import json
import os
import threading

from agent_fakes import ssh_session, trap_event, write_log

from agents import sessions
from agents.ui import logindex
from agents.ui.logindex import SessionIndex


def _append(path, records, tail=b""):
    with open(path, "ab") as f:
        for r in records:
            f.write((json.dumps(r) + "\n").encode())
        f.write(tail)


def _index(path, **kw):
    kw.setdefault("min_interval", 0)
    return SessionIndex(path, **kw)


def test_index_maps_sessions_to_byte_ranges_and_skips_listeners(tmp_path):
    log = write_log(tmp_path / "log", ssh_session("session-a", "203.0.113.7", ["id"])
                    + [trap_event("ftp", "connection", "203.0.113.9", "session-ftp")]
                    + ssh_session("session-b", "203.0.113.8", ["uname -a", "w"], start=1))
    idx = _index(log)
    a, b = idx.range_of("session-a"), idx.range_of("session-b")
    assert a and b and a[1] <= b[0]
    assert idx.range_of("session-ftp") is None             # not an SSH line
    data = log.read_bytes()
    assert b[1] == len(data)
    assert all(json.loads(line)["task_name"] == "session-a"
               for line in data[a[0]:a[1]].splitlines())


def test_transcript_reuses_the_session_parser(tmp_path):
    log = write_log(tmp_path / "log", ssh_session("session-a", "203.0.113.7", ["id", "ls -la"]))
    t = _index(log).transcript("session-a")
    parsed = sessions.parse_log(log).sessions["session-a"]
    assert [x["text"] for x in t["turns"]] == [x.text for x in parsed.turns]
    assert [x["role"] for x in t["turns"]] == ["input", "response", "input", "response"]
    assert t["auth_attempts"] == [{"ts": parsed.auth_attempts[0].ts, "username": "root",
                                   "password": "toor", "success": True}]
    assert t["closed"] and t["src_ip"] == "203.0.113.7" and t["username"] == "root"


def test_transcript_reads_only_the_sessions_range(tmp_path, monkeypatch):
    log = write_log(tmp_path / "log", ssh_session("session-a", "203.0.113.7", ["id"])
                    + ssh_session("session-b", "203.0.113.8", ["w"], start=1))
    idx = _index(log)
    seen = []
    real = sessions.parse_log

    def spy(path, **kw):
        seen.append(kw)
        return real(path, **kw)

    monkeypatch.setattr(sessions, "parse_log", spy)
    t = idx.transcript("session-a")
    assert [x["text"] for x in t["turns"]][0] == "id"
    assert seen == [{"start_offset": 0, "end_offset": idx.range_of("session-a")[1]}]


def test_login_only_session_keeps_its_auth_attempts(tmp_path):
    log = write_log(tmp_path / "log", ssh_session("session-l", "203.0.113.7", []))
    t = _index(log).transcript("session-l")
    assert t["turns"] == [] and t["auth_attempts"][0]["username"] == "root"


def test_incremental_refresh_and_trailing_partial_line(tmp_path):
    log = tmp_path / "log"
    _append(log, ssh_session("session-a", "203.0.113.7", ["id"], closed=False))
    idx = _index(log)
    first = idx.range_of("session-a")
    # A half-written line is not consumed; once completed it extends the session.
    line = json.dumps(ssh_session("session-a", "203.0.113.7", [])[-1]).encode()
    _append(log, [], tail=line[:20])
    assert idx.range_of("session-a") == first
    assert idx.stats()["offset"] == first[1]
    _append(log, [], tail=line[20:] + b"\n")
    assert idx.range_of("session-a") == (first[0], os.path.getsize(log))
    assert idx.stats()["rebuilds"] == 0


def test_rotation_truncation_and_reused_inode_rebuild(tmp_path):
    log = tmp_path / "log"
    _append(log, ssh_session("session-a", "203.0.113.7", ["id", "w", "uptime"]))
    idx = _index(log)
    assert idx.range_of("session-a")
    # Rotation: a new file at the same path.
    os.replace(log, tmp_path / "log.1")
    _append(log, ssh_session("session-b", "203.0.113.8", ["id"]))
    assert idx.range_of("session-a") is None
    assert idx.range_of("session-b") == (0, log.stat().st_size)
    # Truncation in place (smaller than the indexed offset).
    with open(log, "wb"):
        pass
    _append(log, ssh_session("session-c", "203.0.113.9", []))
    assert idx.range_of("session-b") is None and idx.range_of("session-c")
    # Same inode, same or larger size, different first line: rebuilt from the head hash.
    big = b"".join((json.dumps(r) + "\n").encode()
                   for r in ssh_session("session-d", "203.0.113.10", ["x" * 400] * 5))
    with open(log, "r+b") as f:
        f.write(big)
    assert idx.range_of("session-c") is None and idx.range_of("session-d")
    assert idx.stats()["rebuilds"] == 3


def test_missing_log_and_no_log_configured(tmp_path):
    assert _index(tmp_path / "nope").range_of("session-a") is None
    assert _index(None).transcript("session-a") is None
    assert not (tmp_path / "nope").exists()


def test_memory_cap_keeps_the_most_recently_active_sessions(tmp_path):
    recs = []
    for i in range(5):
        recs += ssh_session(f"session-{i}", "203.0.113.7", ["id"], start=i)
    log = write_log(tmp_path / "log", recs)
    idx = _index(log, max_sessions=3)
    assert idx.range_of("session-0") is None and idx.range_of("session-1") is None
    assert all(idx.range_of(f"session-{i}") for i in (2, 3, 4))
    assert idx.stats()["sessions"] == 3


def test_a_refresh_reads_a_bounded_amount_and_catches_up_later(tmp_path):
    recs = []
    for i in range(20):
        recs += ssh_session(f"session-{i:02d}", "203.0.113.7", ["id"], start=i)
    log = write_log(tmp_path / "log", recs)
    idx = _index(log, max_bytes_per_refresh=2000)
    idx.refresh()
    assert not idx.caught_up and 0 < idx.stats()["offset"] < log.stat().st_size
    for _ in range(100):
        idx.refresh()
        if idx.caught_up:
            break
    assert idx.caught_up and idx.range_of("session-19")


def test_refresh_is_rate_limited(tmp_path):
    log = write_log(tmp_path / "log", ssh_session("session-a", "203.0.113.7", ["id"]))
    now = [100.0]
    idx = SessionIndex(log, min_interval=5, clock=lambda: now[0])
    assert idx.range_of("session-a")
    _append(log, ssh_session("session-b", "203.0.113.8", ["id"], start=1))
    assert idx.range_of("session-b") is None
    now[0] += 5
    assert idx.range_of("session-b")


def test_oversized_range_is_refused(tmp_path, monkeypatch):
    log = write_log(tmp_path / "log", ssh_session("session-a", "203.0.113.7", ["id"] * 3))
    monkeypatch.setattr(logindex, "MAX_RANGE_BYTES", 100)
    idx = _index(log)
    try:
        idx.transcript("session-a")
    except logindex.RangeTooLarge:
        pass
    else:
        raise AssertionError("expected RangeTooLarge")


def test_concurrent_refreshes_are_safe(tmp_path):
    recs = []
    for i in range(50):
        recs += ssh_session(f"session-{i:02d}", "203.0.113.7", ["id"], start=i)
    log = write_log(tmp_path / "log", recs)
    idx = _index(log)
    errors = []

    def worker():
        try:
            for i in range(50):
                assert idx.range_of(f"session-{i:02d}")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and idx.stats()["rebuilds"] == 0


def test_index_never_writes(tmp_path):
    log = write_log(tmp_path / "log", ssh_session("session-a", "203.0.113.7", ["id"]))
    before = sorted(os.listdir(tmp_path))
    os.chmod(tmp_path, 0o555)
    try:
        idx = _index(log)
        assert idx.transcript("session-a")
    finally:
        os.chmod(tmp_path, 0o755)
    assert sorted(os.listdir(tmp_path)) == before


def test_parse_log_end_offset_stops_before_later_lines(tmp_path):
    log = write_log(tmp_path / "log", ssh_session("session-a", "203.0.113.7", ["id"])
                    + ssh_session("session-b", "203.0.113.8", ["w"], start=1))
    whole = sessions.parse_log(log)
    end = whole.sessions["session-a"].last_offset
    part = sessions.parse_log(log, end_offset=end)
    assert set(part.sessions) == {"session-a"} and part.end_offset == end
