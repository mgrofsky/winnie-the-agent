"""Activity screen API: the event index (every service's event shapes, rotation,
truncation, the entry cap and the tail window), each filter, cursor pagination, the search
byte budget and its continue cursor, SSH base64 decoding, scrubbing and honeytoken masking,
the session view for a non-SSH service, and replies paired with a record's commands."""

import base64
import datetime
import json
import os

import pytest

from ui_fixture import HONEYTOKEN_VALUE, build_tree

from agents.ui import activity
from agents.ui.activity import EventIndex, classify, describe
from agents.ui.api import TEXT_CAP, Api, ApiPaths, pair_replies

UTC = datetime.timezone.utc
T0 = datetime.datetime(2026, 11, 18, 9, 0, tzinfo=UTC)


def at(minutes: float) -> str:
    return (T0 + datetime.timedelta(minutes=minutes)).isoformat(timespec="milliseconds")


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def listener(minute, protocol, task, event, src="198.51.100.30", message="", **kw):
    line = {"timestamp": at(minute), "task_name": task, "src_ip": src, "src_port": 40000,
            "dst_ip": "10.0.0.5", "dst_port": 1, "message": message or event,
            "sensor_protocol": protocol, "event": event, "transport": "tcp"}
    line.update(kw)
    return line


def ssh(minute, sid, message, src="198.51.100.40", **kw):
    line = {"timestamp": at(minute), "level": "INFO", "task_name": sid, "src_ip": src,
            "src_port": 50022, "dst_ip": "10.0.0.5", "dst_port": 22, "message": message,
            "sensor_name": "t", "sensor_protocol": "ssh"}
    line.update(kw)
    return line


SID = "session-00000000000000000000000000000001"

LINES = [
    ssh(0, SID, "SSH connection received"),
    ssh(0.1, SID, "Authentication failed", username="root", password="123456"),
    ssh(0.2, SID, "Authentication success", username="root", password="toor"),
    ssh(0.3, SID, "User input", details=b64("cat /etc/passwd"), interactive=True),
    ssh(0.4, SID, "LLM response", details=b64("root:x:0:0:root:/root:/bin/bash"),
        interactive=True),
    ssh(0.5, SID, "SSH connection closed"),
    listener(1, "telnet", "telnet-1", "connection"),
    listener(1.1, "telnet", "telnet-1", "auth_attempt", username="admin", password="admin",
             success=True),
    listener(1.2, "telnet", "telnet-1", "command", username="admin",
             data={"input": "busybox wget", "response": "wget: missing URL", "persona": False}),
    listener(1.3, "telnet", "telnet-1", "command", username="admin",
             data={"input": "uname -a", "persona": False}),
    listener(1.4, "telnet", "telnet-1", "close", data={"bytes_read": 99, "commands": 2}),
    listener(2, "http", "http-1", "command", src="198.51.100.31", message="POST /login",
             data={"method": "POST", "path": "/login", "query": "next=/", "status": 403,
                   "body": "user=a&pass=b"}),
    listener(3, "s3", "s3-1", "command", src="198.51.100.32", message="GetObject b/k",
             data={"operation": "GetObject", "method": "GET", "path": "/b/k", "query": "",
                   "status": 200, "bucket": "b", "key": "k"}),
    listener(3.1, "s3", "s3-1", "command", src="198.51.100.32", message="ListBuckets",
             data={"operation": "ListBuckets", "method": "GET", "path": "/", "query": "",
                   "status": 200}),
    listener(4, "postgres", "postgres-1", "command", src="198.51.100.33",
             message="SQL statement",
             data={"statement": "select version()", "result": "rows:1", "dialect": "pg"}),
    listener(4.1, "mysql", "mysql-1", "command", src="198.51.100.33", message="SQL statement",
             data={"statement": "drop table x", "result": "error:1051"}),
    listener(4.2, "mssql", "mssql-1", "command", src="198.51.100.33", message="RPC request",
             data={"payload": "00", "text": "exec xp_cmdshell 'whoami'"}),
    listener(5, "ftp", "ftp-1", "command", src="198.51.100.34", message="FTP command",
             username="anonymous", data={"input": "RETR backup.tar", "cmd": "RETR"}),
    listener(5.1, "ftp", "ftp-1", "command", src="198.51.100.34", message="FTP download",
             username="anonymous", data={"cmd": "RETR", "path": "/backup.tar", "size": 1024}),
    listener(6, "smtp", "smtp-1", "command", src="198.51.100.35", message="SMTP command",
             data={"input": "RCPT TO:<a@example.com>", "cmd": "RCPT"}),
    listener(6.1, "smtp", "smtp-1", "command", src="198.51.100.35",
             message="SMTP message accepted",
             data={"cmd": "DATA", "size": 300, "rcpt_count": 2, "mail_from": "x@example.com"}),
    listener(7, "redis", "redis-1", "command", src="198.51.100.36", message="Redis command",
             data={"cmd": "CONFIG", "input": "CONFIG SET dir /root/.ssh", "argc": 4}),
    listener(8, "sip", "sip-1", "register", src="198.51.100.37",
             message="SIP REGISTER rejected", username="100", success=False,
             data={"stage": "rejected"}),
    listener(8.1, "sip", "sip-1", "invite", src="198.51.100.37", message="SIP INVITE",
             data={"dialed": "900442071234567", "stage": "challenge"}),
    listener(8.2, "sip", "sip-1", "options", src="198.51.100.37", message="SIP OPTIONS",
             data={}),
    listener(9, "mllp", "mllp-1", "command", src="198.51.100.38", message="HL7 message",
             data={"copy": "MSH|^~\\&|APP", "size": 12}),
    listener(9.1, "mllp", "mllp-1", "limit", src="198.51.100.38", message="Line too long",
             data={"reason": "max_line_bytes"}),
    listener(9.2, "mysql", "mysql-2", "error", src="198.51.100.38",
             message="Short handshake response", data={"reason": "malformed"}),
]


def write_log(path, lines, mode="a"):
    with open(path, mode, encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")


@pytest.fixture
def tree(tmp_path):
    t = build_tree(tmp_path / "tree")
    write_log(t.log, LINES, mode="w")
    return t


@pytest.fixture
def api(tree):
    return Api(tree.api_paths(), cache_seconds=0)


def items(api, **query):
    status, body = api.get("/api/activity", {k: str(v) for k, v in query.items()})
    assert status == 200, body
    return body


def by_task(body):
    return [(i["session"], i["kind"]) for i in body["items"]]


# ---- the index: every service's event shapes ----------------------------------------------

EXPECTED = {
    ("ssh", "SSH connection received"): ("connection", None),
    ("ssh", "Authentication failed"): ("login", False),
    ("ssh", "Authentication success"): ("login", True),
    ("ssh", "User input"): ("input", None),
    ("ssh", "LLM response"): ("reply", None),
    ("ssh", "SSH connection closed"): ("close", None),
}


def test_every_service_line_gets_a_normalised_kind():
    kinds = [classify(line)[3] for line in LINES]
    assert kinds == ["connection", "login", "login", "input", "reply", "close",
                     "connection", "login", "input", "input", "close",
                     "request", "transfer", "request", "input", "input", "input",
                     "input", "transfer", "input", "transfer", "input",
                     "register", "call", "request", "input", "error", "error"]
    assert set(kinds) <= set(activity.KINDS)
    for line in LINES[:6]:
        _, src, service, kind, session, _, ok = classify(line)
        assert (kind, ok) == EXPECTED[("ssh", line["message"])]
        assert service == "ssh" and session == SID and src == "198.51.100.40"


def test_what_was_sent_and_answered_per_service():
    def d(i):
        _, _, service, kind, _, _, _ = classify(LINES[i])
        return describe(LINES[i], service, kind, TEXT_CAP)

    assert d(3)["sent"] == "cat /etc/passwd" and d(3)["answered"] is None   # base64 decoded
    assert d(4)["answered"] == "root:x:0:0:root:/root:/bin/bash"
    assert d(2)["password"] == "toor"
    assert (d(8)["sent"], d(8)["answered"]) == ("busybox wget", "wget: missing URL")
    assert d(9)["answered"] is None                                     # no reply logged
    assert d(10)["result"] == "99 bytes read, 2 commands"
    assert d(11)["sent"] == "POST /login?next=/\n\nuser=a&pass=b"
    assert d(11)["result"] == "HTTP 403" and d(11)["answered"] is None
    assert d(12)["result"] == "GetObject HTTP 200"
    assert (d(14)["sent"], d(14)["result"]) == ("select version()", "1 rows returned")
    assert d(15)["result"] == "error 1051"
    assert d(16)["sent"] == "exec xp_cmdshell 'whoami'" and d(16)["result"] is None
    assert d(17)["sent"] == "RETR backup.tar"
    assert d(18)["result"] == "FTP download /backup.tar (1024 bytes)"
    assert d(20)["result"] == "message accepted: 300 bytes to 2 recipients"
    assert d(21)["sent"] == "CONFIG SET dir /root/.ssh" and d(21)["answered"] is None
    assert d(22)["result"] == "stage: rejected"
    assert d(23)["sent"] == "SIP INVITE 900442071234567"
    assert d(25)["sent"] == "MSH|^~\\&|APP"
    assert d(26)["result"] == "max_line_bytes" and d(27)["result"] == "malformed"


def test_api_items_carry_the_fields_and_newest_first(api):
    body = items(api)
    assert len(body["items"]) == len(LINES)
    assert [i["offset"] for i in body["items"]] == sorted((i["offset"] for i in body["items"]),
                                                         reverse=True)
    login = next(i for i in body["items"] if i["kind"] == "login" and i["outcome"] == "failure")
    assert login["summary"] == "login root refused" and login["password"] == "123456"
    telnet = next(i for i in body["items"] if i["sent"] == "busybox wget")
    assert telnet["answered"] == "wget: missing URL" and telnet["answered_truncated"] is False
    assert telnet["service"] == "telnet" and telnet["session"] == "telnet-1"
    assert body["window"]["older_outside"] is False and body["window"]["caught_up"] is True
    assert body["facets"]["services"]["ssh"] == 6
    assert body["facets"]["kinds"]["login"] == 3
    assert len(body["facets"]["top_sources"]) <= activity.TOP_SOURCES


# ---- filters -------------------------------------------------------------------------------

@pytest.mark.parametrize("query,expected", [
    ({"service": "telnet"}, 5),
    ({"kind": "login"}, 3),
    ({"outcome": "failure"}, 2),        # the SSH failure and the SIP register refusal
    ({"outcome": "success"}, 2),
    ({"user": "anonymous"}, 2),
    ({"session": "telnet-1"}, 5),
    ({"src": "198.51.100.33"}, 3),
    ({"src": "198.51.100.32/31"}, 5),   # .32 and .33
    ({"from": at(4), "to": at(5.05)}, 4),
    ({"service": "sip", "kind": "call"}, 1),
])
def test_each_filter(api, query, expected):
    assert len(items(api, **query)["items"]) == expected


@pytest.mark.parametrize("query", [
    {"kind": "nap"}, {"outcome": "maybe"}, {"service": "SSH!"}, {"src": "x" * 65},
    {"src": "198.51.100.0/99"}, {"from": "yesterday"}, {"before": "-1"}, {"after": "1e3"},
    {"session": "../etc"}, {"q": "x" * 201}, {"q": "a\x1bb"}, {"per": "lots"},
])
def test_bad_filters_are_refused_without_echo(api, query):
    status, body = api.get("/api/activity", query)
    assert (status, body) == (400, {"error": "bad query"})


def test_free_text_searches_what_was_sent_and_answered(api):
    assert [i["kind"] for i in items(api, q="ROOT:X:0")["items"]] == ["reply"]   # decoded
    assert [i["service"] for i in items(api, q="missing url")["items"]] == ["telnet"]
    assert [i["service"] for i in items(api, q="xp_cmdshell")["items"]] == ["mssql"]
    body = items(api, q="nothing like this")
    assert body["items"] == [] and body["search"]["complete"] is True
    assert body["next_before"] is None


# ---- cursor pagination and the search budget ----------------------------------------------

def test_cursor_pagination_walks_every_event_once(api):
    seen, before = [], None
    while True:
        query = {"per": 4} if before is None else {"per": 4, "before": before}
        body = items(api, **query)
        seen += [i["offset"] for i in body["items"]]
        before = body["next_before"]
        if before is None:
            break
    assert len(seen) == len(LINES) == len(set(seen))
    assert seen == sorted(seen, reverse=True)


def test_search_stops_at_its_byte_budget_and_continues(api, monkeypatch):
    line_bytes = max(len(json.dumps(line)) + 1 for line in LINES)
    monkeypatch.setattr(activity, "SEARCH_BUDGET", line_bytes * 3)
    body = items(api, q="198.51.100")
    assert body["search"]["complete"] is False and body["next_before"] is not None
    assert body["search"]["searched_back_to"] is not None
    found = [i["offset"] for i in body["items"]]
    while body["next_before"] is not None:
        body = items(api, q="198.51.100", before=body["next_before"])
        found += [i["offset"] for i in body["items"]]
    assert len(found) == len(LINES) == len(set(found))
    assert body["search"]["complete"] is True


def test_new_events_are_counted_after_an_offset(api, tree):
    newest = items(api)["newest"]
    assert items(api, after=newest) == {"new": 0, "newest": newest, "approximate": False}
    write_log(tree.log, [listener(20, "telnet", "telnet-9", "connection"),
                         listener(20.1, "http", "http-9", "command",
                                  data={"method": "GET", "path": "/", "status": 200})])
    body = items(api, after=newest)
    assert body["new"] == 2 and body["newest"] > newest
    assert items(api, after=newest, service="http")["new"] == 1


# ---- rotation, truncation, the cap and the tail window ------------------------------------

def test_rotation_and_truncation_rebuild_the_index(tmp_path):
    log = tmp_path / "log"
    write_log(log, LINES[:5])
    idx = EventIndex(log, min_interval=0)
    assert idx.snapshot()[1]["entries"] == 5
    os.replace(log, tmp_path / "log.1")                 # rotated: a new file
    write_log(log, LINES[5:7])
    entries, info = idx.snapshot()
    assert info["entries"] == 2 and idx.rebuilds == 1
    with open(log, "w") as f:                           # truncated in place
        f.write(json.dumps(LINES[8]) + "\n")
    entries, info = idx.snapshot()
    assert info["entries"] == 1 and entries[0][activity.KIND] == "input"


def test_partial_and_malformed_lines_are_not_entries(tmp_path):
    log = tmp_path / "log"
    with open(log, "w") as f:
        f.write(json.dumps(LINES[0]) + "\nnot json\n\n[1]\n" + json.dumps(LINES[1])[:20])
    entries, _ = EventIndex(log, min_interval=0).snapshot()
    assert len(entries) == 1


def test_the_entry_cap_drops_the_oldest_and_says_so(tmp_path):
    log = tmp_path / "log"
    write_log(log, LINES)
    idx = EventIndex(log, max_entries=10, min_interval=0)
    entries, info = idx.snapshot()
    assert len(entries) <= 10 and info["older_outside"] is True and info["dropped"] > 0
    assert entries[-1][activity.OFF] == max(e[activity.OFF] for e in entries)
    assert entries[-1][activity.KIND] == "error"         # the newest line is kept


def test_a_fresh_index_starts_at_a_line_inside_the_tail(tmp_path):
    log = tmp_path / "log"
    write_log(log, LINES)
    size = log.stat().st_size
    idx = EventIndex(log, min_interval=0, tail_bytes=size // 3)
    entries, info = idx.snapshot()
    assert info["older_outside"] is True and 0 < len(entries) < len(LINES)
    raw = log.read_bytes()
    assert raw[entries[0][activity.OFF] - 1:entries[0][activity.OFF]] == b"\n"
    assert idx.start_offset >= size - size // 3


def test_one_refresh_reads_a_bounded_amount(tmp_path):
    log = tmp_path / "log"
    write_log(log, LINES)
    idx = EventIndex(log, min_interval=0, max_bytes_per_refresh=200, tail_bytes=None)
    entries, info = idx.snapshot()
    assert info["caught_up"] is False and len(entries) < len(LINES)
    for _ in range(len(LINES)):
        entries, info = idx.snapshot()
    assert info["caught_up"] is True and len(entries) == len(LINES)


def test_screen_says_when_the_log_is_gone(api, tree):
    tree.log.unlink()
    body = items(api)
    assert body["items"] == [] and body["window"]["entries"] == 0


# ---- scrubbing and masking -----------------------------------------------------------------

def test_controls_are_removed_and_long_fields_are_cut_and_flagged(api, tree):
    write_log(tree.log, [listener(30, "telnet", "telnet-h", "command",
                                  data={"input": "a\x1b[31mb‮\x00c",
                                        "response": "R" * 20_000})])
    item = items(api, session="telnet-h")["items"][0]
    assert item["sent"] == "a[31mbc"
    assert len(item["answered"]) == TEXT_CAP and item["answered_truncated"] is True


def test_honeytoken_values_are_masked_and_typed_passwords_shown(api, tree):
    write_log(tree.log, [
        listener(31, "telnet", "telnet-t", "auth_attempt", username="u",
                 password=HONEYTOKEN_VALUE, success=False),
        listener(31.1, "telnet", "telnet-t", "command",
                 data={"input": f"echo {HONEYTOKEN_VALUE}", "response": HONEYTOKEN_VALUE})])
    body = json.dumps(items(api, session="telnet-t"))
    assert HONEYTOKEN_VALUE not in body and HONEYTOKEN_VALUE[:2] + "......" in body
    login = items(api, kind="login", outcome="failure", service="ssh")["items"][0]
    assert login["password"] == "123456"
    # A search for the token still finds the line; the value is masked in what is shown.
    found = items(api, q=HONEYTOKEN_VALUE)
    assert found["items"] and HONEYTOKEN_VALUE not in json.dumps(found)


# ---- the session view ----------------------------------------------------------------------

def test_a_telnet_session_reads_in_order_with_its_replies(api):
    status, body = api.get("/api/activity/session/telnet-1", {})
    assert status == 200 and body["from"] == "index" and body["service"] == "telnet"
    assert [e["kind"] for e in body["events"]] == ["connection", "login", "input", "input",
                                                   "close"]
    assert body["events"][2]["answered"] == "wget: missing URL"
    assert body["events"][3]["answered"] is None
    assert body["src"] == "198.51.100.30" and body["record_id"] is None


def test_an_ssh_session_uses_the_transcript(api):
    status, body = api.get(f"/api/activity/session/{SID}", {})
    assert status == 200 and body["from"] == "transcript"
    kinds = [e["kind"] for e in body["events"]]
    assert kinds == ["login", "login", "input", "reply"]
    assert body["events"][2]["sent"] == "cat /etc/passwd"


def test_a_listener_session_links_to_its_campaign(tree):
    api = Api(tree.api_paths(), cache_seconds=0)
    status, body = api.get("/api/activity/session/redis-0001", {})
    assert status == 404                                   # the fixture log was replaced
    stamp = api.get(f"/api/records/{tree.ids['redis']}", {})[1]["record"]["first_seen"]
    with open(tree.log, "w") as f:
        f.write(json.dumps(listener(0, "redis", "redis-0001", "command",
                                    src="198.51.100.21", timestamp=stamp,
                                    data={"input": "INFO"})) + "\n")
    status, body = api.get("/api/activity/session/redis-0001", {})
    assert status == 200 and body["record_id"] == tree.ids["redis"]


@pytest.mark.parametrize("sid", ["../x", "a b", "x" * 200, "-lead"])
def test_bad_session_ids_are_not_found(api, sid):
    assert api.get(f"/api/activity/session/{sid}", {})[0] == 404


def test_activity_is_read_only(api, tree):
    before = {p: p.stat().st_mtime_ns for p in tree.root.rglob("*") if p.is_file()}
    items(api)
    items(api, q="root")
    api.get("/api/activity/session/telnet-1", {})
    after = {p: p.stat().st_mtime_ns for p in tree.root.rglob("*") if p.is_file()}
    assert before == after
    assert api.post("/api/activity", {})[0] == 404


def test_without_a_log_the_routes_answer_empty(tree):
    paths = tree.api_paths()
    api = Api(ApiPaths(**{**paths.__dict__, "log": None}), cache_seconds=0)
    body = items(api)
    assert body["items"] == [] and body["window"]["entries"] == 0


# ---- replies under each command ------------------------------------------------------------

def turns(*pairs):
    return [{"role": role, "text": text} for role, text in pairs]


def test_replies_pair_by_place_not_text():
    t = turns(("response", "banner"), ("input", "ls"), ("response", "a"), ("input", "ls"),
              ("response", "b"), ("response", "c"), ("input", "exit"))
    assert pair_replies(t) == ["a", "b\nc", None]


def test_repeated_identical_commands_keep_their_own_replies():
    t = turns(*[x for i in range(3) for x in (("input", "id"), ("response", f"r{i}"))])
    assert pair_replies(t) == ["r0", "r1", "r2"]


def test_a_missing_reply_is_none_not_the_next_one():
    t = turns(("input", "a"), ("input", "b"), ("response", "for b"))
    assert pair_replies(t) == [None, "for b"]


def test_replies_route_pairs_with_the_record_commands(tmp_path):
    tree = build_tree(tmp_path / "own")              # the fixture's own log
    api = Api(tree.api_paths(), cache_seconds=0)
    status, body = api.get(f"/api/records/{tree.ids['session_a']}/replies", {})
    assert status == 200
    replies = body["items"]
    assert [r["index"] for r in replies] == list(range(len(replies)))
    assert replies[0]["command"] == "uname -a" and replies[0]["recorded"] is True
    assert replies[0]["reply"].startswith("uname -a: done")
    assert all(HONEYTOKEN_VALUE not in (r["reply"] or "") for r in replies)
    assert api.get(f"/api/records/{tree.ids['ftp']}/replies", {})[0] == 404


def test_replies_route_says_when_no_reply_was_logged(tmp_path):
    tree = build_tree(tmp_path / "own")
    sid = tree.ids["session_b"]
    with open(tree.log, encoding="utf-8") as f:
        kept = [line for line in f if not (sid in line and "LLM response" in line)]
    tree.log.write_text("".join(kept), encoding="utf-8")
    api = Api(tree.api_paths(), cache_seconds=0)
    status, body = api.get(f"/api/records/{sid}/replies", {})
    assert status == 200
    assert [r["recorded"] for r in body["items"]] == [False, False]
    assert all(r["reply"] is None for r in body["items"])


@pytest.mark.slow
def test_a_large_log_is_indexed_within_its_bounds(tmp_path):
    import time

    log = tmp_path / "log"
    line = (json.dumps(listener(0, "http", "http-x", "command",
                                data={"method": "GET", "path": "/" + "a" * 200,
                                      "status": 404})) + "\n").encode()
    chunk = line * 4096
    with open(log, "wb") as f:
        while f.tell() < 300 * 1024 * 1024:
            f.write(chunk)
    idx = EventIndex(log, min_interval=0)
    started = time.monotonic()
    entries, info = idx.snapshot()
    assert time.monotonic() - started < 60
    assert len(entries) <= activity.DEFAULT_MAX_ENTRIES and info["older_outside"] is True
    assert idx.start_offset >= log.stat().st_size - activity.DEFAULT_TAIL_BYTES
    paths = ApiPaths(reports=tmp_path / "r", state=tmp_path / "s", data=tmp_path / "d",
                     detections=tmp_path / "x", overlay=tmp_path / "o.json",
                     source_state=tmp_path / "ss.json", log=log)
    api = Api(paths, cache_seconds=0)
    api.events = idx
    started = time.monotonic()
    body = items(api, q="no such text anywhere")
    assert time.monotonic() - started < 30
    assert body["search"]["complete"] is False and body["next_before"] is not None
