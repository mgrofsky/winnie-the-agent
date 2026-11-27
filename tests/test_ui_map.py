"""Map screen API (``/api/map``): the window and its delta by cursor, the cursor's log id, the
item and source caps with ``skipped``, positions only for unmasked sources, the destination
port, judgements from triage records, the sensor's place, and the counts."""

import dataclasses
import datetime
import json

import pytest

import ui_fixture
from ui_fixture import HONEYTOKEN_VALUE, MAP_PLACES, FakeGeo, build_tree, map_lines

from agents.ui import api as api_mod
from agents.ui.api import Api, parse_map_home

UTC = datetime.timezone.utc


def write_log(path, lines, mode="a"):
    with open(path, mode, encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")


@pytest.fixture
def tree(tmp_path):
    return build_tree(tmp_path / "tree")


def make(tree, lines=None, **kw):
    """An Api over ``tree`` whose clock is the tree's ``now``, with ``lines`` (default: 40 map
    lines over the last 40 seconds) appended to the log."""
    if lines is None:
        lines = map_lines(tree.now - datetime.timedelta(seconds=40), 40)
    write_log(tree.log, lines)
    kw.setdefault("geo", FakeGeo())
    return Api(tree.api_paths(), cache_seconds=0, now=lambda: tree.now, **kw)


def get(api, **query):
    if "after" in query and "log_id" not in query:
        query["log_id"] = api.events.snapshot()[1]["log_id"]
    status, body = api.get("/api/map", {k: str(v) for k, v in query.items()})
    assert status == 200, body
    return body


def test_window_load_is_the_window_oldest_first(tree):
    body = get(make(tree))
    items = body["items"]
    # 40 map lines; the fixture's own events are two hours old and outside every window.
    assert len(items) == 40 and body["skipped"] == 0 and body["window"] == "15m"
    assert [i["offset"] for i in items] == sorted(i["offset"] for i in items)
    assert body["newest"] == items[-1]["offset"] and body["log_id"]
    assert body["totals"]["events"] == 40
    first = items[0]
    assert set(first) >= {"offset", "time", "src", "service", "kind", "outcome", "username",
                          "summary", "place", "point", "dst_port"}
    assert body["located"] is True


@pytest.mark.parametrize("win,seconds", [("5m", 300), ("15m", 900), ("1h", 3600)])
def test_each_window_holds_only_its_own_events(tree, win, seconds):
    old = map_lines(tree.now - datetime.timedelta(seconds=seconds + 30), 5, seed=1)
    recent = map_lines(tree.now - datetime.timedelta(seconds=seconds - 60), 5, seed=2)
    body = get(make(tree, old + recent), window=win)
    assert len(body["items"]) == 5
    assert all(i["time"] >= (tree.now - datetime.timedelta(seconds=seconds)).isoformat()[:19]
               for i in body["items"])


def test_delta_by_cursor_returns_only_newer_events(tree):
    api = make(tree)
    first = get(api)
    write_log(tree.log, map_lines(tree.now - datetime.timedelta(seconds=5), 3, seed=9))
    delta = get(api, after=first["newest"], log_id=first["log_id"])
    assert len(delta["items"]) == 3 and delta["skipped"] == 0
    assert all(i["offset"] > first["newest"] for i in delta["items"])
    assert delta["totals"]["events"] == 43
    assert get(api, after=delta["newest"])["items"] == []


def test_a_cursor_from_another_log_is_refused(tree):
    api = make(tree)
    status, body = api.get("/api/map", {"after": "0", "log_id": "elsewhere.0"})
    assert status == 409 and body["log_id"] == api.events.snapshot()[1]["log_id"]
    status, _ = api.get("/api/map", {"after": "0"})
    assert status == 409


@pytest.mark.parametrize("query", [{"window": "1d"}, {"window": "<b>"}, {"after": "x"},
                                   {"after": "-1"}])
def test_bad_queries_are_400(tree, query):
    status, body = make(tree).get("/api/map", query)
    assert status == 400 and "<b>" not in json.dumps(body)


def test_caps_and_skipped(tree, monkeypatch):
    monkeypatch.setattr(api_mod, "MAP_ITEMS", 10)
    monkeypatch.setattr(api_mod, "MAP_SOURCES", 3)
    api = make(tree)
    body = get(api)
    assert len(body["items"]) == 10 and body["skipped"] == 30
    # The newest ten, and the window totals still count every event.
    assert body["totals"]["events"] == 40 and len(body["sources"]) == 3
    assert sum(s["events"] for s in body["sources"]) <= 40
    first = get(api, window="15m")
    write_log(tree.log, map_lines(tree.now - datetime.timedelta(seconds=2), 25, step=0.05,
                                  seed=4))
    delta = get(api, after=first["newest"], log_id=first["log_id"])
    assert len(delta["items"]) == 10 and delta["skipped"] == 15
    # The cursor is the log's newest offset, so the skipped events are not handed out again.
    assert get(api, after=delta["newest"])["items"] == []


def test_sources_are_placed_and_judged(tree):
    body = get(make(tree))
    by_src = {s["src"]: s for s in body["sources"]}
    for src, s in by_src.items():
        if src in MAP_PLACES:
            cc, country, city, point = MAP_PLACES[src]
            assert s["point"] == list(point) and s["country"] == cc
            assert s["place"] == f"{city}, {country}"
        else:
            assert s["point"] is None and s["country"] is None
    # The fixture's records judge these sources (the redis campaign MALICIOUS).
    if "198.51.100.21" in by_src:
        assert by_src["198.51.100.21"]["judgement"] == "MALICIOUS"
    countries = body["totals"]["countries"]
    assert len(countries) <= 10 and sum(countries.values()) <= 40
    assert list(countries.values()) == sorted(countries.values(), reverse=True)


def test_item_judgement_is_by_source_and_service(tree):
    t = tree.now - datetime.timedelta(seconds=10)
    lines = [
        {"timestamp": t.isoformat(), "task_name": "redis-9", "src_ip": "198.51.100.21",
         "dst_port": 6379, "sensor_protocol": "redis", "event": "command",
         "message": "command", "data": {"command": "INFO"}},
        {"timestamp": t.isoformat(), "task_name": "ftp-9", "src_ip": "198.51.100.21",
         "dst_port": 21, "sensor_protocol": "ftp", "event": "connection",
         "message": "connection"},
    ]
    items = get(make(tree, lines))["items"]
    assert items[0]["judgement"] == "MALICIOUS" and items[0]["dst_port"] == 6379
    assert "judgement" not in items[1]        # no ftp record for this source


@pytest.mark.parametrize("port,expected", [(22, 22), ("-", None), (0, None), (True, None),
                                           (70000, None), ("22", None)])
def test_destination_port_is_a_real_port_or_none(tree, port, expected):
    line = {"timestamp": (tree.now - datetime.timedelta(seconds=3)).isoformat(),
            "src_ip": "203.0.113.10", "dst_port": port, "sensor_protocol": "telnet",
            "event": "connection", "message": "connection", "task_name": "telnet-1"}
    [item] = get(make(tree, [line]))["items"]
    assert item["dst_port"] == expected


def test_a_masked_source_is_not_placed(tree):
    places = dict(MAP_PLACES)
    places[HONEYTOKEN_VALUE] = ("DE", "Germany", "Berlin", (52.5, 13.4))
    line = {"timestamp": (tree.now - datetime.timedelta(seconds=3)).isoformat(),
            "src_ip": HONEYTOKEN_VALUE, "dst_port": 23, "sensor_protocol": "telnet",
            "event": "connection", "message": "connection", "task_name": "telnet-1"}
    body = get(make(tree, [line], geo=FakeGeo(places)))
    [item] = body["items"]
    assert HONEYTOKEN_VALUE not in json.dumps(body)
    assert item["point"] is None and item["place"] is None
    assert body["sources"][0]["point"] is None and body["totals"]["countries"] == {"unknown": 1}


def test_summary_and_username_are_masked_and_cleaned(tree):
    t = (tree.now - datetime.timedelta(seconds=3)).isoformat()
    lines = [{"timestamp": t, "task_name": "telnet-1", "src_ip": "203.0.113.11",
              "dst_port": 23, "sensor_protocol": "telnet", "event": "command",
              "message": "command", "username": "root\x1b[31m",
              "data": {"input": f"echo {HONEYTOKEN_VALUE} ‮{ui_fixture.SCRIPT}"}}]
    [item] = get(make(tree, lines))["items"]
    assert HONEYTOKEN_VALUE not in item["summary"] and "‮" not in item["summary"]
    assert ui_fixture.SCRIPT in item["summary"] and "\x1b" not in item["username"]


def test_sensor_point_from_config_and_without_it(tree):
    body = get(make(tree, [], sensor="lab-1"))
    assert body["sensor"] == {"name": "lab-1", "label": "lab-1",
                              "point": list(api_mod.MAP_HOME_DEFAULT), "placed": False}
    body = get(make(tree, [], sensor="lab-1", map_home=(51.5, -0.1), map_label="London lab"))
    assert body["sensor"] == {"name": "lab-1", "label": "London lab", "point": [51.5, -0.1],
                              "placed": True}


def test_without_a_lookup_nothing_is_placed(tree):
    api = Api(tree.api_paths(), cache_seconds=0, now=lambda: tree.now)
    write_log(tree.log, map_lines(tree.now - datetime.timedelta(seconds=40), 40))
    body = get(api)
    assert body["located"] is False and len(body["items"]) == 40
    assert all(i["point"] is None and i["place"] is None for i in body["items"])
    assert body["totals"]["countries"] == {"unknown": 40}


def test_a_lookup_that_raises_places_nothing(tree):
    class Broken(FakeGeo):
        def point(self, address):
            raise RuntimeError("boom")

        def lookup(self, address):
            raise RuntimeError("boom")

    body = get(make(tree, geo=Broken()))
    assert len(body["items"]) == 40 and all(i["point"] is None for i in body["items"])


def test_per_minute_counts_cover_the_window(tree):
    body = get(make(tree), window="5m")
    minutes = body["totals"]["per_minute"]
    assert 5 <= len(minutes) <= 6 and sum(m["events"] for m in minutes) == 40
    assert minutes == sorted(minutes, key=lambda m: m["minute"])


def test_without_a_log_the_map_is_empty(tree):
    paths = dataclasses.replace(tree.api_paths(), log=None)
    body = get(Api(paths, cache_seconds=0, now=lambda: tree.now))
    assert body["items"] == [] and body["sources"] == [] and body["newest"] is None


def test_the_map_is_read_only(tree):
    api = make(tree)
    before = {p: p.stat().st_mtime_ns for p in tree.root.rglob("*") if p.is_file()}
    get(api)
    get(api, after=0)
    after = {p: p.stat().st_mtime_ns for p in tree.root.rglob("*") if p.is_file()}
    assert before == after


@pytest.mark.parametrize("text,expected", [("", None), ("  ", None), (None, None),
                                           ("51.5,-0.1", (51.5, -0.1)),
                                           (" -33.9 , 151.2 ", (-33.9, 151.2)),
                                           ("90,180", (90.0, 180.0))])
def test_map_home_parses(text, expected):
    assert parse_map_home(text) == expected


@pytest.mark.parametrize("text", ["51.5", "91,0", "0,-181", "nan,0", "inf,0", "1,2,3", "x,y",
                                  "1e1,0", "51.1234567,0"])
def test_bad_map_home_is_refused_without_echo(text):
    with pytest.raises(ValueError) as err:
        parse_map_home(text)
    assert text not in str(err.value)
