"""Operator console with two stages: the blocklist screen's status and sightings, Enforce
with its view hash and the shell's request protections, the approve dialog's mode, and the
screen as before when the switch is off."""

import json

import pytest

from test_ui_actions import (
    HOSTILE,
    OPERATOR,
    FakeConnectors,
    decide,
    queue_items,
    serve_api,   # noqa: F401 - fixture
    snapshot,
    tree,        # noqa: F401 - fixture
)

from agents.respond import RespondSettings
from agents.sightings import SightingsSettings
from agents.ui.api import Api

pytestmark = pytest.mark.usefixtures("public_test_net")

TRACK = RespondSettings(track_before_enforce=True)
TARGET = "198.51.100.21"   # the fixture's pending export_blocklist


def make_api(tree, conns=None, settings=TRACK, **kw):
    return Api(tree.api_paths(), settings=settings, cache_seconds=0, operator=OPERATOR,
               respond_settings=lambda: settings, sensor="sensor-a",
               connectors=(lambda: conns) if conns is not None else None, **kw)


def rows(api) -> dict:
    status, body = api.get("/api/blocklist", {})
    assert status == 200
    return {e["target"]: e for e in body["items"]}


def tracked_api(tree, conns=None, **kw):
    api = make_api(tree, conns, **kw)
    status, body = decide(api, tree.ids["pending"], "approve")
    assert status == 200 and body["approval"]["result"]["status"].startswith("tracked")
    return api


def enforce(api, target=TARGET, hash_=None):
    if hash_ is None:
        hash_ = rows(api)[target]["view_hash"]
    return api.post("/api/blocklist/enforce", {"target": target, "view_hash": hash_})


def write_sightings(tree, items, generated_at=None):
    generated_at = generated_at or tree.now.isoformat()
    (tree.state / "sightings.json").write_text(json.dumps(
        {"version": 1, "generated_at": generated_at, "sightings": items}))


def sighting(address=TARGET, **kw):
    base = {"address": address, "where": "prod-account", "service": "tcp/443",
            "first_seen": "2026-01-01T00:00:00Z", "last_seen": "2026-01-02T00:00:00Z",
            "count": 3, "source": "threat-list finding"}
    base.update(kw)
    return base


# ---- the blocklist screen ------------------------------------------------------------------

def test_switch_off_serves_the_list_as_before(tree):
    api = make_api(tree, settings=RespondSettings())
    status, body = api.get("/api/blocklist", {})
    assert "mode" not in body and "sightings" not in body
    for e in body["items"]:
        assert set(e) == {"target", "approved_at", "expires_at"}
    assert "mode" in api.get("/api/queue", {})[1]
    assert api.get("/api/queue", {})[1]["mode"] == {"track_before_enforce": False}


def test_tracked_entries_show_their_stage_and_a_view_hash(tree):
    api = tracked_api(tree)
    status, body = api.get("/api/blocklist", {})
    assert body["mode"] == {"track_before_enforce": True, "block_connector": False,
                            "blocklist_file": "approved.txt", "tracked_file": "tracked.json"}
    by = {e["target"]: e for e in body["items"]}
    assert by[TARGET]["status"] == "tracked" and len(by[TARGET]["view_hash"]) == 64
    # Entries approved by the fixture before the switch existed are enforced, no hash.
    assert by["198.51.100.7"]["status"] == "enforced" and "view_hash" not in by["198.51.100.7"]
    assert by[TARGET]["sightings"] == {"total": 0, "last_seen": None, "places": 0, "rows": []}
    assert body["sightings"]["state"] == "missing"
    assert api.get("/api/queue", {})[1]["mode"] == {"track_before_enforce": True}
    assert TARGET not in (tree.reports / "blocklist" / "approved.txt").read_text().split()


def test_sightings_are_shown_for_listed_addresses_only(tree):
    api = tracked_api(tree)
    write_sightings(tree, [sighting(), sighting(where="dr-account", count=4,
                                                last_seen="2026-01-03T00:00:00Z"),
                           sighting(address="198.51.100.99", where="unlisted")])
    by = rows(api)
    s = by[TARGET]["sightings"]
    assert s["total"] == 7 and s["places"] == 2 and s["last_seen"].startswith("2026-01-03")
    assert [r["where"] for r in s["rows"]] == ["dr-account", "prod-account"]
    assert set(s["rows"][0]) == {"where", "service", "count", "first_seen", "last_seen", "source"}
    assert "unlisted" not in json.dumps(api.get("/api/blocklist", {})[1])


def test_stale_and_refused_files_are_shown_not_hidden(tree):
    api = tracked_api(tree)
    write_sightings(tree, [sighting()], generated_at="2025-01-01T00:00:00Z")
    info = api.get("/api/blocklist", {})[1]["sightings"]
    assert info["state"] == "ok" and info["stale"] is True
    (tree.state / "sightings.json").write_text('{"version": 1, "sightings": "nope"}')
    body = api.get("/api/blocklist", {})[1]
    assert body["sightings"]["state"] == "invalid" and body["sightings"]["error"]
    assert {e["target"]: e for e in body["items"]}[TARGET]["sightings"]["total"] == 3


def test_hostile_sightings_text_is_served_as_clean_text(tree):
    api = tracked_api(tree)
    write_sightings(tree, [sighting(where="<img src=x onerror=alert(1)>‮",
                                    service="\x1b[2Jtcp")])
    row = rows(api)[TARGET]["sightings"]["rows"][0]
    assert row["where"] == "<img src=x onerror=alert(1)>"[:64]
    assert row["service"] == "[2Jtcp"


def test_a_custom_sightings_path(tree, tmp_path):
    path = tmp_path / "elsewhere.json"
    path.write_text(json.dumps({"version": 1, "generated_at": tree.now.isoformat(),
                                "sightings": [sighting()]}))
    api = tracked_api(tree, sightings=SightingsSettings(path=str(path)))
    assert rows(api)[TARGET]["sightings"]["total"] == 3


# ---- enforce -------------------------------------------------------------------------------

def test_enforce_blocks_and_calls_the_connector(tree):
    conns = FakeConnectors()
    api = tracked_api(tree, conns)
    assert api.get("/api/blocklist", {})[1]["mode"]["block_connector"] is True
    status, body = enforce(api)
    assert status == 200 and body["status"] == "enforced"
    assert body["connector"] == {"ok": True, "status": "sent"}
    assert conns.calls == [("block", TARGET, "fixture_pb")]
    assert TARGET in (tree.reports / "blocklist" / "approved.txt").read_text().split()
    row = rows(api)[TARGET]
    assert row["status"] == "enforced" and "view_hash" not in row and row["enforced_at"]
    [path] = (tree.reports / "response").glob("*-enforce-*.json")
    assert json.loads(path.read_text())["enforce"]["by"] == "ui:" + OPERATOR
    export = json.loads((tree.reports / "blocklist" / "tracked.json").read_text())
    assert {e["address"]: e["status"] for e in export["entries"]}[TARGET] == "enforced"
    assert export["sensor"] == "sensor-a"


def test_a_stale_view_or_a_second_enforce_changes_nothing(tree):
    api = tracked_api(tree)
    seen = rows(api)[TARGET]["view_hash"]
    assert enforce(api, hash_="0" * 64) == (409, {"error": "changed"})
    assert enforce(api, hash_=seen)[0] == 200
    before = snapshot(tree.root)
    assert enforce(api, hash_=seen) == (409, {"error": "changed"})
    assert enforce(api, "198.51.100.99", seen) == (409, {"error": "changed"})
    assert snapshot(tree.root) == before


def test_enforce_rechecks_never_act_on_with_fixed_text(tree):
    api = tracked_api(tree)
    blocked = make_api(tree, settings=RespondSettings(track_before_enforce=True,
                                                      never_act_on=("198.51.100.0/24",)))
    before = snapshot(tree.root)
    assert enforce(blocked, hash_=rows(api)[TARGET]["view_hash"]) == \
        (400, {"error": "refused: never_act_on"})
    assert snapshot(tree.root) == before


def test_bad_bodies_are_refused_without_echo(tree):
    api = tracked_api(tree)
    good = rows(api)[TARGET]["view_hash"]
    before = snapshot(tree.root)
    outs = []
    for value in HOSTILE + ("0.0.0.0/0", "198.51.100.0/24", ""):
        outs.append(api.post("/api/blocklist/enforce", {"target": value, "view_hash": good}))
        outs.append(api.post("/api/blocklist/enforce", {"target": TARGET, "view_hash": value}))
    outs.append(api.post("/api/blocklist/enforce", {"target": 5, "view_hash": good}))
    outs.append(api.post("/api/blocklist/enforce", {"target": TARGET}))
    for status, body in outs:
        assert status in (400, 409)
        for value in HOSTILE:
            assert value not in json.dumps(body)
    assert snapshot(tree.root) == before


def test_invalid_settings_refuse_enforce(tree):
    api = tracked_api(tree)
    hash_ = rows(api)[TARGET]["view_hash"]

    def broken():
        raise ValueError("bad")

    bad = Api(tree.api_paths(), settings=TRACK, cache_seconds=0, respond_settings=broken)
    status, body = bad.post("/api/blocklist/enforce", {"target": TARGET, "view_hash": hash_})
    assert status == 500 and body["error"].startswith("[respond] settings are invalid")


def test_unblock_removes_a_tracked_entry_from_the_export(tree):
    api = tracked_api(tree)
    status, body = api.post("/api/blocklist/unblock", {"target": TARGET})
    assert status == 200 and body["removed"] == [TARGET]
    export = json.loads((tree.reports / "blocklist" / "tracked.json").read_text())
    assert TARGET not in {e["address"] for e in export["entries"]}


# ---- through the server --------------------------------------------------------------------

def test_enforce_through_the_server_needs_the_usual_protections(tree, serve_api):
    api = tracked_api(tree, FakeConnectors())
    hash_ = rows(api)[TARGET]["view_hash"]
    ro = serve_api(api, actions=False)
    before = snapshot(tree.root)
    assert ro.post("/api/blocklist/enforce", {"target": TARGET, "view_hash": hash_}) == \
        (403, {"error": "read-only"})
    c = serve_api(api, actions=True)
    status, _, _ = c.request("POST", "/api/blocklist/enforce",
                             body=json.dumps({"target": TARGET, "view_hash": hash_}).encode(),
                             headers={"Content-Type": "application/json"})
    assert status == 403                               # no Origin, no CSRF token
    status, _, _ = c.request("POST", "/api/blocklist/enforce",
                             body=json.dumps({"target": TARGET, "view_hash": hash_}).encode(),
                             headers={"Content-Type": "application/json",
                                      "Origin": "http://evil.example",
                                      "X-Winnie-CSRF": c.get("/api/session")[1]["csrf"]})
    assert status == 403
    assert snapshot(tree.root) == before
    status, body = c.post("/api/blocklist/enforce", {"target": TARGET, "view_hash": hash_})
    assert status == 200 and body["status"] == "enforced"


def test_queue_card_still_decides_with_its_own_hash(tree):
    api = make_api(tree)
    item = queue_items(api)[tree.ids["pending"]]
    assert item["can_approve_here"] is True and item["view_hash"]
