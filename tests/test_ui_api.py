"""Operator console data API: routes, filters, pagination, sanitising, ids before paths,
missing and corrupt data, no writes, caching, and two routes end to end through the server."""

import hashlib
import http.client
import json
import math
import os
import secrets
import stat
import threading
import urllib.parse

import pytest

import ui_fixture
from ui_fixture import (
    DETECTION_APPROVED,
    DETECTION_PENDING,
    HONEYTOKEN_NAME,
    HONEYTOKEN_VALUE,
    IMG,
    SCRIPT,
    TRAVERSAL_USER,
    build_tree,
)

from agents.ui import api as api_mod
from agents.ui import logindex
from agents.ui.api import Api, ApiPaths, LongText, clean_text, scrub, view_hash
from agents.ui.server import UiSettings, build_server

FORBIDDEN = {chr(c) for c in range(0x20) if chr(c) not in "\n\t"} | {chr(0x7F)} \
    | {chr(c) for c in range(0x80, 0xA0)} | {chr(c) for c in range(0x202A, 0x202F)} \
    | {chr(c) for c in range(0x2066, 0x206A)} | {"‎", "‏", "؜"}


@pytest.fixture
def tree(tmp_path):
    return build_tree(tmp_path / "tree")


@pytest.fixture
def api(tree):
    return Api(tree.api_paths(), cache_seconds=0)


def get(api, path, **query):
    return api.get(path, {k: str(v) for k, v in query.items()})


def ok(api, path, **query):
    status, body = get(api, path, **query)
    assert status == 200, (path, body)
    return body


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)


def all_requests(tree):
    """Every route, with good and bad inputs."""
    sa = tree.ids["session_a"]
    today = tree.now.date().isoformat()
    return [
        ("/api/overview", {}), ("/api/overview", {"window": "7d"}),
        ("/api/overview", {"window": "1y"}),
        ("/api/records", {}), ("/api/records", {"sort": "rank", "per": "2", "page": "2"}),
        ("/api/records", {"kind": "session", "protocol": "ssh", "judgement": "malicious",
                          "honeytoken": "1", "src": "198.51.100.7", "q": "script"}),
        ("/api/records", {"judgement": "evil"}), ("/api/records", {"page": "x"}),
        (f"/api/records/{sa}", {}), (f"/api/records/{tree.ids['ftp']}", {}),
        ("/api/records/../../etc/passwd", {}), ("/api/records/nope", {}),
        (f"/api/records/{sa}/transcript", {"per": "4"}),
        (f"/api/records/{tree.ids['session_b']}/transcript", {}),
        (f"/api/records/{tree.ids['ftp']}/transcript", {}),
        ("/api/queue", {}), ("/api/queue", {"all": "1"}), ("/api/queue", {"all": "yes"}),
        ("/api/blocklist", {}),
        ("/api/digests", {}), (f"/api/digests/{today}", {}), ("/api/digests/notes", {}),
        ("/api/digests/1999-01-01", {}),
        ("/api/decoy", {}), ("/api/playbooks", {}),
        ("/api/detections", {}), (f"/api/detections/pending/{DETECTION_PENDING}", {}),
        (f"/api/detections/approved/{DETECTION_APPROVED}", {}),
        ("/api/detections/pending/README.md", {}), ("/api/detections/other/x.yml", {}),
        ("/api/honeytokens", {}), ("/api/honeytokens", {"reveal": HONEYTOKEN_NAME}),
        ("/api/honeytokens", {"reveal": "missing"}), ("/api/honeytokens", {"reveal": "../x"}),
        ("/api/activity", {}), ("/api/activity", {"q": "script", "per": "3"}),
        ("/api/activity", {"service": "ssh", "kind": "input", "src": "198.51.100.0/24"}),
        ("/api/activity", {"outcome": "maybe"}), ("/api/activity", {"before": "x"}),
        ("/api/activity", {"after": "0"}),
        (f"/api/activity/session/{sa}", {}), ("/api/activity/session/redis-0001", {}),
        ("/api/activity/session/../x", {}),
        (f"/api/records/{sa}/replies", {}), (f"/api/records/{tree.ids['ftp']}/replies", {}),
        ("/api/nothing", {}), ("/api/", {}), ("/elsewhere", {}),
    ]


# ---- sanitising boundary ---------------------------------------------------------------------

def test_clean_text_removes_controls_and_bidi_but_keeps_markup_newlines_and_tabs():
    raw = "a\x00b\x1b[31mc\x07\x7f\x85\x9b‮d⁦e⁩‎f\ttab\nline<b>&\"'"
    assert clean_text(raw) == "ab[31mcdef\ttab\nline<b>&\"'"
    assert len(clean_text("x" * 10_000)) == api_mod.TEXT_CAP
    assert len(clean_text("\x1b" * 9_000 + "y" * 10)) == 0   # cut before cleaning: bounded


def test_scrub_walks_everything_keys_included():
    out = scrub({"k": ["‮x", ("t", 1, 2.5, math.nan, None, True)], "k\x1b": "dropped",
                 "long": LongText("z" * 300_000), "short": "z" * 300_000, "obj": object()})
    assert out["k"] == ["x", ["t", 1, 2.5, None, None, True]]
    assert "k\x1b" not in out and "dropped" not in out.values()
    assert len(out["long"]) == api_mod.LONG_TEXT_CAP and len(out["short"]) == api_mod.TEXT_CAP
    assert isinstance(out["obj"], str)
    deep = current = []
    for _ in range(100):
        current.append([])
        current = current[0]
    json.dumps(scrub(deep))   # depth-capped, still JSON


def test_hostile_values_come_back_as_plain_strings_without_controls(api, tree):
    seen = []
    for path, query in all_requests(tree):
        status, body = api.get(path, query)
        json.dumps(body, allow_nan=False)
        for s in strings(body):
            assert not FORBIDDEN & set(s), (path, s[:80])
            seen.append(s)
    blob = "\n".join(seen)
    for markup in (SCRIPT, IMG, TRAVERSAL_USER, "[31mred[0m", "echo txt.exe done"):
        assert markup in blob


def test_errors_are_fixed_texts_that_never_echo_input(api):
    for path in ("/api/records/<script>", "/api/digests/<img>", "/api/whatever<x>"):
        assert api.get(path, {}) == (404, {"error": "not found"})
    assert api.get("/api/records", {"judgement": "<script>"}) == (400, {"error": "bad query"})
    assert api.post("/api/queue/a-000000000000/approve", {"view_hash": "x"}) == \
        (404, {"error": "not found"})


def test_a_failing_route_is_a_bare_500(api, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret detail /etc/x")

    monkeypatch.setattr(api_mod, "peek_blocklist", boom)
    assert api.get("/api/blocklist", {}) == (500, {"error": "internal error"})


# ---- overview ---------------------------------------------------------------------------------

def test_overview(api, tree):
    day = ok(api, "/api/overview")
    assert day["window"] == "24h"
    assert day["totals"]["records"] == 4 and day["totals"]["sessions"] == 2
    assert day["totals"]["by_protocol"] == {"ftp": 1, "redis": 1, "ssh": 2}
    assert day["totals"]["by_judgement"] == {"BENIGN": 1, "SUSPICIOUS": 1, "MALICIOUS": 2}
    assert {s["src_ip"] for s in day["top_sources"]} == {"198.51.100.7", "198.51.100.8",
                                                        "198.51.100.20", "198.51.100.21"}
    assert [r["id"] for r in day["honeytoken_hits"]] == [tree.ids["session_a"]]
    assert day["approvals"]["pending"] == 1 and day["approvals"]["soonest_expiry"]
    week = ok(api, "/api/overview", window="7d")
    assert week["totals"]["records"] == 5 and week["totals"]["by_protocol"]["sip"] == 1
    assert get(api, "/api/overview", window="30d") == (400, {"error": "bad query"})


def test_overview_health(api, tree):
    h = ok(api, "/api/overview")["health"]
    assert h["event_log"]["state"] == "ok" and h["event_log"]["bytes"] > 0
    assert h["event_log"]["index"]["sessions"] == 2
    assert h["records_total"] == 5 and h["newest_record"]
    assert h["analyst_calls"] == {"day": tree.now.date().isoformat(), "calls": 7, "limit": 500}
    assert h["frontend_tokens"]["tokens"] == 123456
    assert {(x["protocol"], x["count"]) for x in h["sensor_limits"]} == {("http", 5), ("sip", 12)}
    assert h["size_alarm"] is None
    # Whitelisted fields only: the object key carries the configured bucket prefix.
    assert h["ship_failures"] and all(set(e) == {"timestamp", "event", "error", "lines"}
                                      for e in h["ship_failures"])
    assert "private-prefix" not in json.dumps(h)


def test_overview_never_names_configured_paths(tmp_path):
    secret_dir = tmp_path / "very-private-location"
    a = Api(ApiPaths(reports=secret_dir, state=secret_dir / "s", data=secret_dir,
                     detections=secret_dir, overlay=secret_dir / "o.json",
                     source_state=secret_dir / "ss.json", log=secret_dir / "log"),
            cache_seconds=0)
    for path, query in (("/api/overview", {}), ("/api/decoy", {}), ("/api/playbooks", {})):
        assert "very-private-location" not in json.dumps(a.get(path, query)[1])
    assert a.get("/api/overview", {})[1]["health"]["event_log"] == {"state": "missing"}


# ---- records ----------------------------------------------------------------------------------

def test_records_newest_first_and_ranked(api, tree):
    newest = ok(api, "/api/records")
    assert newest["total"] == 5 and newest["sort"] == "newest"
    assert newest["items"][0]["id"] == tree.ids["session_b"]
    assert newest["items"][-1]["id"] == tree.ids["sip"]
    ranked = ok(api, "/api/records", sort="rank")
    assert ranked["items"][0]["id"] == tree.ids["session_a"]   # honeytoken first
    assert get(api, "/api/records", sort="random")[0] == 400


@pytest.mark.parametrize("query,expected", [
    ({"kind": "campaign"}, {"ftp", "redis", "sip"}),
    ({"protocol": "SSH"}, {"session_a", "session_b"}),
    ({"judgement": "malicious"}, {"session_a", "redis"}),
    ({"honeytoken": "1"}, {"session_a"}),
    ({"honeytoken": "0", "kind": "session"}, {"session_b"}),
    ({"src": "198.51.100.20"}, {"ftp"}),
    ({"src": "203.0.113.51"}, {"sip"}),                   # one of a campaign's addresses
    ({"q": "<SCRIPT>"}, {"session_a"}),
    ({"q": "etc/passwd"}, {"session_b"}),
    ({"q": "198.51.100.9/x.sh"}, {"session_a"}),           # IOC values are searched
    ({"q": "nothing matches this"}, set()),
])
def test_record_filters(api, tree, query, expected):
    body = ok(api, "/api/records", **query, per=200)
    names = {k for k, v in tree.ids.items() if isinstance(v, str)}
    by_id = {tree.ids[k]: k for k in names}
    assert {by_id[i["id"]] for i in body["items"]} == expected and body["total"] == len(expected)


@pytest.mark.parametrize("query", [
    {"kind": "both"}, {"protocol": "s s h"}, {"judgement": "UNKNOWN"}, {"honeytoken": "yes"},
    {"src": "x" * 65}, {"q": "x" * 201}, {"page": "-1"}, {"per": "1e3"}, {"page": "0x10"},
])
def test_bad_filters_are_400(api, query):
    assert api.get("/api/records", query) == (400, {"error": "bad query"})


def test_pagination(api):
    first = ok(api, "/api/records", per=2)
    assert (first["total"], first["page"], first["per"], len(first["items"])) == (5, 1, 2, 2)
    last = ok(api, "/api/records", per=2, page=3)
    assert len(last["items"]) == 1
    beyond = ok(api, "/api/records", per=2, page=99)
    assert beyond["items"] == [] and beyond["total"] == 5
    assert ok(api, "/api/records", per=100000)["per"] == 200
    assert ok(api, "/api/records", page=0)["page"] == 1
    ids = [i["id"] for p in (1, 2, 3) for i in ok(api, "/api/records", per=2, page=p)["items"]]
    assert len(set(ids)) == 5


def test_record_detail(api, tree):
    body = ok(api, f"/api/records/{tree.ids['session_a']}")
    assert body["record"]["honeytokens"] == [HONEYTOKEN_NAME]
    assert body["approvals"] == [tree.ids["done"][0]]
    assert body["transcript_available"] is True
    camp = ok(api, f"/api/records/{tree.ids['redis']}")
    assert camp["approvals"] == [tree.ids["pending"]] and camp["transcript_available"] is False
    b = ok(api, f"/api/records/{tree.ids['session_b']}")
    assert set(b["approvals"]) == {tree.ids["done"][1], tree.ids["overdue"]}


@pytest.mark.parametrize("rid", ["..", ".hidden", "a/b", "a b", "x" * 201, "%2e%2e", "broken",
                                 "wrong-shape", "", "session-a\x00"])
def test_unknown_or_malformed_record_ids_are_404(api, rid):
    assert api.get(f"/api/records/{rid}", {}) == (404, {"error": "not found"})
    assert api.get(f"/api/records/{rid}/transcript", {})[0] == 404


def test_transcript(api, tree):
    body = ok(api, f"/api/records/{tree.ids['session_a']}/transcript", per=200)
    turns = body["turns"]["items"]
    assert body["turns"]["total"] == 12 and body["src_ip"] == "198.51.100.7"
    inputs = [t["text"] for t in turns if t["role"] == "input"]
    assert inputs[:4] == ["uname -a", SCRIPT, "[31mred[0m ]0;title", "echo txt.exe done"]
    long_turn = inputs[4]
    assert set(long_turn) == {"A"} and len(long_turn) == api_mod.TEXT_CAP
    assert [t["truncated"] for t in turns if t["role"] == "input"][4] is True
    assert body["auth_attempts"] == [{"ts": body["auth_attempts"][0]["ts"], "username": "root",
                                      "password": "toor", "success": True}]
    assert all(t["interactive"] is True for t in turns)
    page = ok(api, f"/api/records/{tree.ids['session_a']}/transcript", per=5, page=3)
    assert len(page["turns"]["items"]) == 2 and page["turns"]["page"] == 3


def test_transcript_masks_honeytoken_values(api, tree):
    # Masked as everywhere else in the console; only the honeytokens screen reveals one.
    with open(tree.log, "a", encoding="utf-8") as f:
        for line in ui_fixture.ssh_lines(tree.ids["session_a"], "198.51.100.7", tree.now,
                                         [("root", HONEYTOKEN_VALUE, False)], []):
            if line["message"].startswith("Auth"):
                f.write(json.dumps(line) + "\n")
    body = ok(api, f"/api/records/{tree.ids['session_a']}/transcript", per=200)
    assert HONEYTOKEN_VALUE not in json.dumps(body)
    inputs = [t["text"] for t in body["turns"]["items"] if t["role"] == "input"]
    assert inputs[5] == "aws s3 ls --profile " + HONEYTOKEN_VALUE[:2] + "......"
    assert body["auth_attempts"][-1]["password"] == HONEYTOKEN_VALUE[:2] + "......"


def test_transcript_of_traversal_username_session(api, tree):
    body = ok(api, f"/api/records/{tree.ids['session_b']}/transcript")
    assert [a["username"] for a in body["auth_attempts"]] == [TRAVERSAL_USER] * 2
    assert body["auth_attempts"][1]["password"] == IMG and body["username"] == TRAVERSAL_USER


def test_transcript_missing_from_log(api, tree):
    assert api.get(f"/api/records/{tree.ids['ftp']}/transcript", {}) == \
        (404, {"error": "not found"})
    os.replace(tree.log, tree.log.with_suffix(".1"))   # rotated away; nothing indexed yet
    assert api.get(f"/api/records/{tree.ids['session_a']}/transcript", {}) == \
        (404, {"error": "transcript not available"})
    assert ok(api, f"/api/records/{tree.ids['session_a']}")["transcript_available"] is False


def test_transcript_too_large(api, tree, monkeypatch):
    monkeypatch.setattr(logindex, "MAX_RANGE_BYTES", 100)
    assert api.get(f"/api/records/{tree.ids['session_a']}/transcript", {}) == \
        (422, {"error": "transcript too large"})


# ---- queue and blocklist ----------------------------------------------------------------------

def test_queue_pending_with_view_hash(api, tree):
    body = ok(api, "/api/queue")
    assert body["total"] == 1
    item = body["items"][0]
    assert item["approval"]["id"] == tree.ids["pending"]
    on_disk = json.loads((tree.state / "approvals" / f"{tree.ids['pending']}.json").read_text())
    # The hash covers the raw file, the served approval and the served record summary.
    canonical = json.dumps({"raw": on_disk, "approval": item["approval"],
                            "record": item["record"], "files": {}},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert item["view_hash"] == hashlib.sha256(canonical.encode()).hexdigest() \
        == view_hash(on_disk, item["approval"], item["record"]) \
        == api.view_of(tree.ids["pending"]).digest
    assert item["id"] == tree.ids["pending"] and item["can_decide_here"] is True
    assert item["undecidable_reason"] is None
    assert item["record"]["id"] == tree.ids["redis"]
    assert SCRIPT in item["approval"]["summary"]


def test_queue_all_includes_closed_and_overdue(api, tree):
    body = ok(api, "/api/queue", all=1)
    status = {i["approval"]["id"]: i["approval"]["status"] for i in body["items"]}
    assert status == {tree.ids["pending"]: "pending", tree.ids["rejected"]: "rejected",
                      tree.ids["done"][0]: "done", tree.ids["done"][1]: "done",
                      tree.ids["overdue"]: "expired"}
    hashes = {i["approval"]["id"]: i["view_hash"] for i in body["items"]}
    assert [k for k, v in hashes.items() if v] == [tree.ids["pending"]]


def test_view_hash_changes_with_the_approval(api, tree):
    path = tree.state / "approvals" / f"{tree.ids['pending']}.json"
    before = ok(api, "/api/queue")["items"][0]["view_hash"]
    data = json.loads(path.read_text())
    data["summary"] = "changed"
    path.write_text(json.dumps(data))
    os.utime(path.parent, None)
    assert ok(api, "/api/queue")["items"][0]["view_hash"] != before


def test_blocklist(api):
    body = ok(api, "/api/blocklist")
    assert {e["target"] for e in body["items"]} == {"198.51.100.7", "198.51.100.8"}
    assert all(e["approved_at"] and e["expires_at"] for e in body["items"])


def test_blocklist_hides_expired_entries_without_pruning_the_file(api, tree):
    store = tree.state / "approved_blocklist.json"
    data = json.loads(store.read_text())
    data["198.51.100.99"] = {"approved_at": "2020-01-01T00:00:00+00:00",
                             "expires_at": "2020-01-31T00:00:00+00:00"}
    data["198.51.100.98"] = "2020-01-01T00:00:00+00:00"          # legacy shape
    store.write_text(json.dumps(data))
    before = store.read_bytes()
    assert {e["target"] for e in ok(api, "/api/blocklist")["items"]} == \
        {"198.51.100.7", "198.51.100.8"}
    assert store.read_bytes() == before


# ---- digests, detections ----------------------------------------------------------------------

def test_digests(api, tree):
    days = ok(api, "/api/digests")["items"]
    today = tree.now.date().isoformat()
    assert days[0] == today and len(days) == 2
    body = ok(api, f"/api/digests/{today}")
    assert body["text"].startswith(f"# Honeypot digest {today}") and body["truncated"] is False


def test_long_digest_is_truncated(api, tree):
    day = "2026-01-02"
    (tree.reports / "daily" / f"{day}.md").write_text("d" * 300_000)
    body = ok(api, f"/api/digests/{day}")
    assert len(body["text"]) == api_mod.LONG_TEXT_CAP and body["truncated"] is True


def test_detections(api):
    assert ok(api, "/api/detections") == {"pending": [DETECTION_PENDING],
                                          "approved": [DETECTION_APPROVED]}
    body = ok(api, f"/api/detections/pending/{DETECTION_PENDING}")
    assert SCRIPT in body["text"] and body["truncated"] is False


@pytest.mark.parametrize("path", [
    "/api/digests/2026-1-1", "/api/digests/../daily", "/api/digests/2026-01-01.md",
    "/api/detections/pending/../../x.yml", "/api/detections/pending/README.md",
    "/api/detections/approved/0A1B2C3D-x.yml", "/api/detections/pending/0a1b2c3d-x.yaml",
    "/api/detections/rejected/0a1b2c3d-x.yml", "/api/detections/pending",
])
def test_bad_names_are_404(api, path):
    assert api.get(path, {}) == (404, {"error": "not found"})


def test_symlinks_out_of_their_directory_are_404(api, tree, tmp_path):
    outside = tmp_path / "outside.md"
    outside.write_text("secret outside the tree\n")
    (tree.reports / "daily" / "2026-02-02.md").symlink_to(outside)
    (tree.detections / "pending" / "deadbeef-link.yml").symlink_to(outside)
    assert api.get("/api/digests/2026-02-02", {}) == (404, {"error": "not found"})
    assert api.get("/api/detections/pending/deadbeef-link.yml", {}) == \
        (404, {"error": "not found"})


# ---- decoy, playbooks, honeytokens ------------------------------------------------------------

def test_decoy(api):
    body = ok(api, "/api/decoy")
    assert body["overlay"]["hostname"] == "build-07" and body["overlay_error"] is None
    assert body["history"][0]["changes"] == ["add_account ftp:backup"]
    assert body["tuner_runs"][0]["snapshot"] == 1 and SCRIPT in body["tuner_runs"][0]["rejected"][0]
    assert body["source_state"]["items"][0]["key"] == "198.51.100.7"
    assert body["source_state"]["items"][0]["tarpit_ms"] == 500


def test_decoy_says_when_each_source_was_last_seen(api, tree):
    body = ok(api, "/api/decoy")
    entry = body["source_state"]["items"][0]
    record = ok(api, f"/api/records/{tree.ids['session_a']}")["record"]
    assert entry["key"] == record["src_ip"] == "198.51.100.7"
    assert entry["last_seen"] == record["last_seen"][:19] + "+00:00"


def test_decoy_last_seen_is_none_for_a_source_without_records(tree):
    from agents.source_state import SourceState, new_entry

    entry = new_entry("2001:db8:5::/64", tree.now)
    tree.source_state.write_text(SourceState(entries={entry.key: entry}).model_dump_json())
    body = ok(Api(tree.api_paths(), cache_seconds=0), "/api/decoy")
    (item,) = body["source_state"]["items"]
    assert item["key"] == "2001:db8:5::/64" and item["last_seen"] is None


def test_playbooks(api):
    body = ok(api, "/api/playbooks")
    (pb,) = body["playbooks"]
    assert pb["name"] == "fixture_pb" and pb["enabled"] and pb["runs_today"] == 3
    assert pb["steps"] == [{"action": "tag_source", "tier": "local"},
                           {"action": "export_blocklist", "tier": "enforce"}]
    assert pb["when"] == {"signals": ["redis_takeover"]}
    assert len(body["errors"]) == 1 and body["errors"][0].startswith("broken.toml")
    assert body["engine"]["counts"]["fixture_pb"] == 3
    assert body["engine"]["cooldowns"]["items"][0]["key"] == "fixture_pb|198.51.100.21"


def test_honeytokens_masked_and_revealed_one_at_a_time(api):
    body = ok(api, "/api/honeytokens")
    tokens = {t["name"]: t for t in body["tokens"]["items"]}
    assert set(tokens) == {HONEYTOKEN_NAME, "db_password", "src_0123456789ab"}
    assert tokens[HONEYTOKEN_NAME]["value"] == HONEYTOKEN_VALUE[:2] + "......"
    assert tokens[HONEYTOKEN_NAME]["hits"] == 1
    assert tokens["src_0123456789ab"]["planted_for"] == "198.51.100.7"
    assert HONEYTOKEN_VALUE not in json.dumps(body)
    assert ok(api, "/api/honeytokens", reveal=HONEYTOKEN_NAME) == \
        {"name": HONEYTOKEN_NAME, "value": HONEYTOKEN_VALUE}
    assert get(api, "/api/honeytokens", reveal="nope") == (404, {"error": "not found"})
    assert get(api, "/api/honeytokens", reveal="a b") == (400, {"error": "bad query"})


# ---- missing and corrupt data -----------------------------------------------------------------

def test_fresh_deployment_answers_every_route_empty(tmp_path):
    root = tmp_path / "fresh"
    a = Api(ApiPaths(reports=root / "reports", state=root / "state", data=root / "data",
                     detections=root / "det", overlay=root / "overlay.json",
                     source_state=root / "ss.json", playbooks=root / "pb",
                     log=root / "log"), cache_seconds=0)
    assert ok(a, "/api/overview")["totals"]["records"] == 0
    assert ok(a, "/api/records")["items"] == []
    assert ok(a, "/api/queue", all=1)["items"] == []
    assert ok(a, "/api/blocklist")["items"] == []
    assert ok(a, "/api/digests")["items"] == []
    assert ok(a, "/api/detections") == {"pending": [], "approved": []}
    assert ok(a, "/api/decoy")["source_state"]["items"] == []
    assert ok(a, "/api/playbooks")["playbooks"] == []
    assert ok(a, "/api/honeytokens")["tokens"]["items"] == []
    assert not root.exists()


def test_corrupt_files_are_skipped(api, tree):
    for rel in ("reports/state/approved_blocklist.json", "reports/state/respond_state.json",
                "reports/state/analyst_calls.json", "data/budget_state.json",
                "reports/honeytokens.json", "decoy/overlay.json", "decoy/source_state.json",
                f"reports/state/approvals/{tree.ids['rejected']}.json",
                "reports/state/tuner/overlay-snapshots/000001.json"):
        (tree.root / rel).write_text("{corrupt")
    (tree.root / "reports/state/ship_events.jsonl").write_bytes(b"\xff\xfe\x00garbage\n")
    for path, query in all_requests(tree):
        assert api.get(path, query)[0] != 500, path
    assert ok(api, "/api/blocklist")["items"] == []
    assert ok(api, "/api/decoy")["overlay_error"] == "overlay file is not valid"
    assert ok(api, "/api/queue", all=1)["total"] == 4
    assert ok(api, "/api/overview")["health"]["analyst_calls"]["calls"] == 0


def test_wrong_shapes_are_skipped(api, tree):
    (tree.reports / "honeytokens.json").write_text(json.dumps({"tokens": {"a": 1}}))
    (tree.state / "respond_state.json").write_text(json.dumps({"processed": 5, "counts": []}))
    (tree.data / "budget_state.json").write_text(json.dumps([1, 2]))
    assert ok(api, "/api/honeytokens")["tokens"]["items"] == []
    assert ok(api, "/api/playbooks")["engine"]["counts"] == {}
    assert ok(api, "/api/overview")["health"]["frontend_tokens"]["tokens"] == 0


# ---- no writes --------------------------------------------------------------------------------

def snapshot(root):
    out = {}
    for dirpath, dirs, files in os.walk(root):
        for name in dirs + files:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            digest = None
            if stat.S_ISREG(st.st_mode):
                with open(p, "rb") as f:
                    digest = hashlib.sha256(f.read()).hexdigest()
            out[os.path.relpath(p, root)] = (stat.S_IFMT(st.st_mode), st.st_size,
                                             st.st_mtime_ns, digest)
    return out


def test_no_route_writes_anything(tree):
    api = Api(tree.api_paths(), cache_seconds=0)
    before = snapshot(tree.root)
    for _ in range(2):
        for path, query in all_requests(tree):
            api.get(path, query)
        api.post("/api/queue/a-000000000000/approve", {})
    assert snapshot(tree.root) == before


def test_every_route_answers_on_a_read_only_tree(tree):
    expected = {}
    probe = Api(tree.api_paths(), cache_seconds=0)
    for path, query in all_requests(tree):
        expected[(path, tuple(sorted(query.items())))] = probe.get(path, query)[0]
    before = snapshot(tree.root)
    os.system(f"chmod -R a-w '{tree.root}'")
    try:
        api = Api(tree.api_paths(), cache_seconds=0)
        for path, query in all_requests(tree):
            status, body = api.get(path, query)
            assert status == expected[(path, tuple(sorted(query.items())))], (path, body)
            assert status != 500
        assert ok(api, "/api/queue", all=1)["total"] == 5
    finally:
        os.system(f"chmod -R u+w '{tree.root}'")
    after = snapshot(tree.root)
    assert {k: v[:2] + v[3:] for k, v in after.items()} == \
        {k: v[:2] + v[3:] for k, v in before.items()}


# ---- caching ----------------------------------------------------------------------------------

def test_record_set_is_cached_until_the_directory_changes(tree):
    now = [1000.0]
    api = Api(tree.api_paths(), cache_seconds=3, clock=lambda: now[0])
    assert ok(api, "/api/records")["total"] == 5
    loads = api._records.loads
    for _ in range(5):
        now[0] += 10
        ok(api, "/api/records")
    assert api._records.loads == loads                    # unchanged: no re-parse
    src = tree.reports / "sessions" / f"{tree.ids['session_b']}.json"
    data = json.loads(src.read_text())
    data["id"] = "session-new"
    (tree.reports / "sessions" / "session-new.json").write_text(json.dumps(data))
    now[0] += 1
    assert ok(api, "/api/records")["total"] == 5          # within the interval
    now[0] += 3
    assert ok(api, "/api/records")["total"] == 6
    assert api._records.loads == loads + 1


# ---- end to end through the server -----------------------------------------------------------

def test_two_routes_end_to_end_through_the_server(tree):
    token = secrets.token_urlsafe(32)
    srv = build_server(UiSettings(port=0, token=token), Api(tree.api_paths(), cache_seconds=0))
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05},
                              daemon=True)
    thread.start()
    port = srv.server_address[1]

    def request(target, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        headers = {"Host": f"127.0.0.1:{port}"}
        if cookie:
            headers["Cookie"] = cookie
        conn.request("GET", target, headers=headers)
        resp = conn.getresponse()
        out = resp.status, resp.getheader("Set-Cookie"), resp.read()
        conn.close()
        return out

    try:
        status, set_cookie, _ = request("/?token=" + urllib.parse.quote(token, safe=""))
        assert status == 303
        cookie = set_cookie.split(";")[0]
        status, _, raw = request("/api/overview?window=7d", cookie)
        assert status == 200 and json.loads(raw)["totals"]["records"] == 5
        status, _, raw = request(f"/api/records/{tree.ids['session_a']}/transcript?per=4", cookie)
        assert status == 200
        assert b"<script>" not in raw and b"\\u003cscript\\u003e" in raw
        body = json.loads(raw)
        assert body["turns"]["items"][2]["text"] == SCRIPT
        assert request("/api/records/..%2f..%2fetc", cookie)[0] == 400
        assert request("/api/overview")[0] == 401
    finally:
        srv.shutdown()
        srv.server_close()


def test_fixture_runs_as_a_script(tmp_path):
    import subprocess
    import sys

    out = subprocess.run([sys.executable, ui_fixture.__file__, str(tmp_path / "seed")],
                         capture_output=True, text=True, timeout=60,
                         env={**os.environ, "WINNIE_DATA_DIR": str(tmp_path / "d")})
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["ids"]["session_a"].startswith("session-")
    assert (tmp_path / "seed" / "data" / "ssh_log.log").exists()


def test_pending_item_expires_in_the_view_without_a_file_change(tree):
    # The queue cache reloads only when the directory changes; time alone must still
    # move an overdue item out of the pending list and the overview count.
    import datetime

    later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
    api = Api(tree.api_paths(), cache_seconds=3600)
    assert tree.ids["pending"] in [i["approval"]["id"] for i in ok(api, "/api/queue")["items"]]
    api.now = lambda: later
    assert ok(api, "/api/queue")["items"] == []
    assert ok(api, "/api/overview")["approvals"]["pending"] == 0
    closed = {i["approval"]["id"]: i for i in ok(api, "/api/queue", all=1)["items"]}
    assert closed[tree.ids["pending"]]["approval"]["status"] == "expired"
    assert closed[tree.ids["pending"]]["view_hash"] is None


def _recon_record(tree):
    from agents.behaviours import BehaviourMatch
    from agents.indicators import IndicatorMatch
    from agents.triage import SeqEntry

    rec = ui_fixture._record(
        "campaign-http-198_51_100_77-20261101T1200", "campaign", "http", "198.51.100.77",
        tree.now, "BENIGN", commands=3,
        request_sequence=[SeqEntry(seq=1, at="2026-11-01T12:00:00+00:00", offset=0,
                                   method="GET", path="/static/app.js", status=200,
                                   lure="bundle", client="norma/0.4"),
                          SeqEntry(seq=2, at="2026-11-01T12:00:03+00:00", offset=3,
                                   method="GET", path="/api/admin/<b>x</b>", query="a=1",
                                   status=403, discovered_via="bundle")],
        indicator_matches=[IndicatorMatch(id="artex-ua-norma", framework="ARTEX",
                                          label="ARTEX default user agent", confidence="medium",
                                          count=2),
                           IndicatorMatch(id="gone-entry", label="removed", confidence="low",
                                          count=1)],
        behaviours=[BehaviourMatch(id="discovered-routes-used", label="agentic reconnaissance",
                                   confidence="medium", count=2, first_seq=2, last_seq=2)])
    path = tree.reports / "campaigns" / f"{rec.id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rec.model_dump_json())
    return rec


def test_record_carries_the_sequence_and_findings_with_provenance(tree):
    from agents.indicators import load_indicators

    rec = _recon_record(tree)
    body = ok(Api(tree.api_paths(), cache_seconds=0, indicators=load_indicators()),
              f"/api/records/{rec.id}")
    seq = body["record"]["request_sequence"]
    assert [e["path"] for e in seq] == ["/static/app.js", "/api/admin/<b>x</b>"]
    assert seq[1]["discovered_via"] == "bundle" and seq[1]["offset"] == 3
    f = body["findings"]
    assert f["like"] == ["ARTEX"] and f["behaviours"][0]["id"] == "discovered-routes-used"
    norma, gone = f["indicators"]
    assert norma["provenance"]["sources"][0].startswith("https://www.microsoft.com/")
    assert norma["provenance"]["reported"] == "2026-11-25"
    assert gone["provenance"] is None
    assert any("ARTEX-like" in line for line in f["lines"])
    # Without the indicator files the matches are still shown, with no provenance.
    bare = ok(Api(tree.api_paths(), cache_seconds=0), f"/api/records/{rec.id}")
    assert [m["provenance"] for m in bare["findings"]["indicators"]] == [None, None]


def test_record_without_findings_has_no_findings_key(api, tree):
    body = ok(api, f"/api/records/{tree.ids['redis']}")
    assert "findings" not in body and body["record"]["request_sequence"] == []
