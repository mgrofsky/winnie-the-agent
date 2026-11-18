"""Operator console against hostile files: every GET route survives each file it reads being
deeply nested, a list instead of an object, or an object with wrong-typed fields; oversize
and malformed event-log lines; symlinks out of their directories; and the response
boundary's caps."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from test_ui_api import all_requests
from ui_fixture import build_tree

from agents import respond, sessions, triage
from agents.llm import DailyCallCounter
from agents.tuner import history as tuner_history
from agents.ui import api as api_mod
from agents.ui import logindex
from agents.ui.api import Api

DEEP = "[" * 100_000 + "]" * 100_000
DEEP_OBJECT = '{"a":' * 50_000 + "1" + "}" * 50_000


@pytest.fixture
def tree(tmp_path):
    return build_tree(tmp_path / "tree")


def _swap(value):
    """A value of another JSON type."""
    if isinstance(value, bool):
        return "yes"
    if isinstance(value, (int, float)):
        return "x"
    if isinstance(value, str):
        return [1, {"a": None}]
    if isinstance(value, list):
        return {"a": [1]}
    if isinstance(value, dict):
        return ["a", 7]
    return {"x": []}


def wrong_top(value):
    """Every top-level field of an object given another type."""
    return {k: _swap(v) for k, v in value.items()} if isinstance(value, dict) else _swap(value)


def wrong_nested(value):
    """Every field one level down given another type (the shape above it kept)."""
    if not isinstance(value, dict):
        return _swap(value)
    out = {}
    for k, v in value.items():
        if isinstance(v, dict):
            out[k] = {kk: _swap(vv) for kk, vv in v.items()}
        elif isinstance(v, list):
            out[k] = [_swap(x) for x in v] or [None, "x", 3]
        else:
            out[k] = _swap(v)
    return out


def json_files(tree) -> list[str]:
    """Every JSON file a GET route reads, relative to the tree root."""
    root = tree.root
    picks = [
        f"reports/state/approvals/{tree.ids['pending']}.json",
        f"reports/state/approvals/{tree.ids['done'][0]}.json",
        "reports/state/approved_blocklist.json",
        "reports/state/respond_state.json",
        "reports/state/analyst_calls.json",
        "data/budget_state.json",
        "reports/honeytokens.json",
        "decoy/overlay.json",
        "decoy/source_state.json",
        "reports/state/tuner/overlay-snapshots/000001.json",
        f"reports/sensor/{tree.now.date().isoformat()}.json",
    ]
    for sub in ("sessions", "campaigns", "tuner"):
        picks += [str(p.relative_to(root)) for p in sorted((tree.reports / sub).glob("*.json"))
                  if p.name not in ("broken.json", "wrong-shape.json")]
    return picks


VARIANTS = {
    "deep": lambda text: DEEP,
    "deep_object": lambda text: DEEP_OBJECT,
    "list": lambda text: json.dumps([json.loads(text)]),
    "wrong_top": lambda text: json.dumps(wrong_top(json.loads(text))),
    "wrong_nested": lambda text: json.dumps(wrong_nested(json.loads(text))),
}


def assert_no_route_fails(tree, label):
    api = Api(tree.api_paths(), cache_seconds=0)
    for path, query in all_requests(tree):
        status, body = api.get(path, query)
        assert status != 500, (label, path, query, body)
        json.dumps(body, allow_nan=False)
    # A decision on a damaged approval is refused, never a crash.
    status, _ = api.post(f"/api/queue/{tree.ids['pending']}/approve", {"view_hash": "0" * 64})
    assert status in (400, 409), label


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_every_json_file_damaged_in_turn_never_fails_a_route(tmp_path, variant):
    count = len(json_files(build_tree(tmp_path / "probe")))
    for i in range(count):
        tree = build_tree(tmp_path / f"t{i}")   # approval ids differ per tree: index by role
        rel = json_files(tree)[i]
        path = tree.root / rel
        assert path.is_file(), rel
        path.write_text(VARIANTS[variant](path.read_text(encoding="utf-8")), encoding="utf-8")
        assert_no_route_fails(tree, (variant, rel))


@pytest.mark.parametrize("line", [DEEP, DEEP_OBJECT, "[1, 2]", '"text"', "{corrupt",
                                  json.dumps({"timestamp": [1], "task_name": {"a": 1},
                                              "sensor_protocol": ["ssh"], "src_ip": {},
                                              "message": 7, "details": [None]}),
                                  json.dumps({"timestamp": "2026-01-01T00:00:00",
                                              "task_name": "session-x", "sensor_protocol": "ssh",
                                              "message": "User input", "details": {"a": 1},
                                              "interactive": "yes", "username": [1]})])
@pytest.mark.parametrize("rel", ["data/ssh_log.log", "reports/state/ship_events.jsonl"])
def test_bad_lines_in_line_files_never_fail_a_route(tree, rel, line):
    path = tree.root / rel
    original = path.read_text(encoding="utf-8")
    path.write_text(line + "\n" + original + line + "\n", encoding="utf-8")
    assert_no_route_fails(tree, (rel, line[:40]))


def test_deeply_nested_playbook_file_is_a_listed_error(tree):
    (tree.playbooks / "deep.toml").write_text("a = " + "[" * 100_000 + "]" * 100_000 + "\n")
    assert_no_route_fails(tree, "playbook")
    status, body = Api(tree.api_paths(), cache_seconds=0).get("/api/playbooks", {})
    assert status == 200 and any(e.startswith("deep.toml") for e in body["errors"])


def test_sensor_pool_that_is_not_a_string_does_not_fail_the_overview(tree):
    day = tree.now.date().isoformat()
    path = tree.reports / "sensor" / f"{day}.json"
    path.write_text(json.dumps({"t1": ["sip", "inbound_drop", ["udp"], 3],
                                "t2": ["sip", "inbound_drop", {"a": 1}, 4],
                                "t3": ["http", "rate_limited", None, 5]}))
    status, body = Api(tree.api_paths(), cache_seconds=0).get("/api/overview", {})
    assert status == 200
    limits = {(x["protocol"], x["pool"]): x["count"] for x in body["health"]["sensor_limits"]}
    assert limits == {("sip", None): 7, ("http", None): 5}


# ---- the readers themselves ------------------------------------------------------------------

def test_engine_readers_treat_deep_nesting_as_corrupt(tmp_path):
    deep = tmp_path / "deep.json"
    deep.write_text(DEEP)
    assert respond._read_json(deep, {}) == {}
    assert api_mod._read_json(deep, {}) == {}
    assert DailyCallCounter(deep, 10).peek()["calls"] == 0
    assert triage.sensor_limit_totals(tmp_path, "x") == {}
    (tmp_path / "sensor").mkdir()
    (tmp_path / "sensor" / "x.json").write_text(DEEP)
    assert triage.sensor_limit_totals(tmp_path, "x") == {}
    for sub in ("sessions", "campaigns"):
        (tmp_path / sub).mkdir()
        (tmp_path / sub / "deep.json").write_text(DEEP)
    assert triage.load_records(tmp_path) == []
    snaps = tmp_path / "tuner" / "overlay-snapshots"
    snaps.mkdir(parents=True)
    (snaps / "000001.json").write_text(DEEP)
    (snaps / "000002.json").write_text("[1]")
    assert tuner_history(tmp_path / "tuner") == []
    log = tmp_path / "log"
    log.write_text(DEEP + "\n" + json.dumps({"a": 1}) + "\n")
    assert [rec for _, _, rec in sessions.iter_records(log)] == [None, {"a": 1}]
    assert sessions.parse_log(log).malformed == 2


# ---- the event-log index: bad and oversize lines -----------------------------------------------

def _session_lines(tree, sid: str, ip: str) -> list[str]:
    from ui_fixture import ssh_lines
    return [json.dumps(x) for x in ssh_lines(sid, ip, tree.now, [("root", "pw", True)],
                                             ["id", "uname -a"])]


def test_deep_line_is_skipped_and_the_offset_moves_past_it(tree):
    index = logindex.SessionIndex(tree.log, min_interval=0)
    index.refresh(force=True)
    before = index.stats()
    sid = "session-" + "c" * 32
    with open(tree.log, "a", encoding="utf-8") as f:
        f.write(DEEP + "\n")
        f.write("\n".join(_session_lines(tree, sid, "198.51.100.30")) + "\n")
    index.refresh(force=True)
    after = index.stats()
    assert after["offset"] == tree.log.stat().st_size > before["offset"]
    assert index.range_of(sid) is not None and after["rebuilds"] == before["rebuilds"]


def test_oversize_line_is_skipped_without_reading_it_whole(tree, monkeypatch):
    monkeypatch.setattr(logindex, "MAX_LINE_BYTES", 4096)
    monkeypatch.setattr(logindex, "SKIP_CHUNK", 1024)
    reads = []
    real_open = open

    class Spy:
        def __init__(self, f):
            self.f = f

        def readline(self, size=-1):
            assert size != -1 and size <= 4097, "a line was read without a limit"
            out = self.f.readline(size)
            reads.append(len(out))
            return out

        def __getattr__(self, name):
            return getattr(self.f, name)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.f.close()

    def spy_open(path, mode="r", *a, **k):
        f = real_open(path, mode, *a, **k)
        return Spy(f) if Path(path) == tree.log and "b" in mode else f

    sid_before, sid_after = "session-" + "d" * 32, "session-" + "e" * 32
    with open(tree.log, "a", encoding="utf-8") as f:
        f.write("\n".join(_session_lines(tree, sid_before, "198.51.100.31")) + "\n")
        f.write(json.dumps({"task_name": sid_before, "sensor_protocol": "ssh",
                            "pad": "x" * 200_000}) + "\n")
        f.write("\n".join(_session_lines(tree, sid_after, "198.51.100.32")) + "\n")
    monkeypatch.setattr("builtins.open", spy_open)
    index = logindex.SessionIndex(tree.log, min_interval=0)
    index.refresh(force=True)
    monkeypatch.setattr("builtins.open", real_open)
    assert max(reads) <= 4097
    assert index.stats()["offset"] == tree.log.stat().st_size
    start, end = index.range_of(sid_before)
    assert end - start < 4096 * 4   # the oversize line did not extend the session's range
    assert index.range_of(sid_after) is not None


def test_iter_lines_matches_iter_records_on_normal_lines_and_waits_on_a_partial_line(tmp_path):
    log = tmp_path / "log"
    lines = [json.dumps({"n": i}) for i in range(5)] + ["", "[1]", "{bad"]
    log.write_text("\n".join(lines) + "\n" + '{"partial": ')
    assert list(logindex.iter_lines(log)) == list(sessions.iter_records(log))
    big = tmp_path / "big"
    big.write_text("y" * 50 + "\n" + "z" * 50)   # an oversize line still being written
    assert list(logindex.iter_lines(big, max_line=10)) == [(0, 51, None)]


def test_oversize_line_in_a_session_range_still_replays(tree, monkeypatch):
    monkeypatch.setattr(logindex, "MAX_LINE_BYTES", 1024)
    with open(tree.log, "a", encoding="utf-8") as f:
        f.write(json.dumps({"pad": "x" * 5000}) + "\n")
    api = Api(tree.api_paths(), cache_seconds=0)
    status, body = api.get(f"/api/records/{tree.ids['session_a']}/transcript", {})
    assert status == 200 and body["turns"]["total"] == 12
