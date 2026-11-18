"""What the queue shows is what a decision acts on: approvals served as an exact-key
projection, look-alike keys never standing in for the real ones, undecidable items refused
without calling respond, and a view_hash that covers the record summary and the detection
files a publish_detection approval names. Also the smaller response-boundary fixes:
invisible characters, size caps, symlinks, withheld transcripts and honeytoken masking."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from ui_fixture import DETECTION_PENDING, SCRIPT, build_tree

from agents import triage
from agents.playbooks import Playbook
from agents.respond import queue_enforce_action
from agents.ui import api as api_mod
from agents.ui import logindex
from agents.ui.api import Api, clean_text, scrub, scrub_flagged

pytestmark = pytest.mark.usefixtures("public_test_net")

UNDECIDABLE = api_mod.UNDECIDABLE
LRM = "‎"


@pytest.fixture
def tree(tmp_path):
    return build_tree(tmp_path / "tree")


def make_api(tree):
    return Api(tree.api_paths(), cache_seconds=0, operator="night shift")


def snapshot(root: Path) -> dict:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file() or p.is_symlink()}


def approval_path(tree, aid: str) -> Path:
    return tree.state / "approvals" / f"{aid}.json"


def read_raw(tree, aid: str) -> dict:
    return json.loads(approval_path(tree, aid).read_text())


def write_raw(tree, aid: str, raw: dict) -> None:
    """Rewrite an approval file keeping key order (look-alike keys stay where put)."""
    approval_path(tree, aid).write_text(json.dumps(raw, indent=2))


def items(api, all_=True) -> dict:
    status, body = api.get("/api/queue", {"all": "1" if all_ else "0", "per": "200"})
    assert status == 200, body
    return {i["id"]: i for i in body["items"]}


def decide(api, aid, verb, hash_):
    return api.post(f"/api/queue/{aid}/{verb}", {"view_hash": hash_})


def queue_publish(tree, files) -> str:
    record = next(r for r in triage.load_records(tree.reports) if r.id == tree.ids["redis"])
    pb = Playbook.model_validate({"name": "publish_pb", "when": {"signals": ["redis_takeover"]},
                                  "steps": [{"action": "publish_detection"}]})
    _, aid = queue_enforce_action(tree.state, pb, record, pb.steps[0], tree.now, 72,
                                  {"files": files}, summary="publish")
    assert aid
    return aid


def blocklisted(tree) -> list[str]:
    path = tree.reports / "blocklist" / "approved.txt"
    return path.read_text().split() if path.exists() else []


# ---- look-alike keys -----------------------------------------------------------------------

@pytest.mark.parametrize("lookalike_first", [False, True])
def test_lookalike_subject_key_never_shows_another_target(tree, lookalike_first):
    api = make_api(tree)
    aid = tree.ids["pending"]
    raw = read_raw(tree, aid)
    acted = raw["subject"]                      # what respond.approve reads: a["subject"]
    decoy = {"subject" + LRM: "198.51.100.99"}
    raw = {**decoy, **raw} if lookalike_first else {**raw, **decoy}
    write_raw(tree, aid, raw)
    item = items(api)[aid]
    assert item["approval"]["subject"] == acted
    assert "198.51.100.99" not in json.dumps(item)
    assert item["can_decide_here"] is True
    status, body = decide(api, aid, "approve", item["view_hash"])
    assert status == 200 and body["approval"]["status"] == "done", body
    assert acted in blocklisted(tree) and "198.51.100.99" not in blocklisted(tree)


def test_scrub_never_lets_a_cleaned_key_replace_another():
    out = scrub({"subject": "198.51.100.21", "subject" + LRM: "198.51.100.99",
                 "s​ubject": "x", "other\x1b": "y", "ok": 1})
    assert out == {"subject": "198.51.100.21", "ok": 1}
    out = scrub({"subject" + LRM: "198.51.100.99"})
    assert out == {}
    out, cut = scrub_flagged({1: "a", "1": "b"})   # non-string keys cannot collide either
    assert out == {"1": "a"} and cut is True


def test_served_approval_is_a_projection_of_named_fields(tree):
    api = make_api(tree)
    aid = tree.ids["pending"]
    raw = read_raw(tree, aid)
    write_raw(tree, aid, {**raw, "extra": SCRIPT, "params": {"unused": "x"},
                          "result": {"ok": True, "secret": "y"}})
    shown = items(api)[aid]["approval"]
    assert "extra" not in shown and shown["params"] == {} and shown["result"] == {"ok": True}
    assert set(shown) <= set(api_mod.APPROVAL_FIELDS) | {"params", "result"}


# ---- undecidable items: served without a hash, refused without calling respond ---------------

def _hidden(value):
    return value[:3] + LRM + value[3:]


UNDECIDABLE_EDITS = {
    "id_other_file": (lambda raw, tree: {**raw, "id": tree.ids["done"][0]}, api_mod.WHY_ID),
    "id_hidden_char": (lambda raw, tree: {**raw, "id": raw["id"] + LRM}, api_mod.WHY_ID),
    "id_missing": (lambda raw, tree: {k: v for k, v in raw.items() if k != "id"},
                   api_mod.WHY_ID),
    "action_unknown": (lambda raw, tree: {**raw, "action": "rm_rf"}, api_mod.WHY_ACTION),
    "action_hidden": (lambda raw, tree: {**raw, "action": _hidden(raw["action"])},
                      api_mod.WHY_ACTION),
    "subject_hidden": (lambda raw, tree: {**raw, "subject": raw["subject"] + LRM},
                       api_mod.WHY_SUBJECT),
    "subject_space": (lambda raw, tree: {**raw, "subject": " " + raw["subject"]},
                      api_mod.WHY_SUBJECT),
    "subject_network": (lambda raw, tree: {**raw, "subject": "198.51.100.0/24"},
                        api_mod.WHY_SUBJECT),
    "subject_v6_not_canonical": (lambda raw, tree: {**raw, "subject": "2001:DB8:0::/64"},
                                 api_mod.WHY_SUBJECT),
    "subject_word": (lambda raw, tree: {**raw, "subject": "unverified"}, api_mod.WHY_SUBJECT),
    "subject_list": (lambda raw, tree: {**raw, "subject": [raw["subject"]]},
                     api_mod.WHY_SUBJECT),
    "playbook_hidden": (lambda raw, tree: {**raw, "playbook": raw["playbook"] + "⁦"},
                        api_mod.WHY_PLAYBOOK),
    "params_list": (lambda raw, tree: {**raw, "params": ["x"]}, api_mod.WHY_PARAMS),
    "expiry_number": (lambda raw, tree: {**raw, "expires_at": 5}, None),
}


@pytest.mark.parametrize("name", sorted(UNDECIDABLE_EDITS))
def test_undecidable_item_has_no_hash_and_every_decision_changes_nothing(tree, name):
    edit, why = UNDECIDABLE_EDITS[name]
    api = make_api(tree)
    aid = tree.ids["pending"]
    good_hash = items(api)[aid]["view_hash"]
    write_raw(tree, aid, edit(read_raw(tree, aid), tree))
    listed = items(api)
    if why is None:
        assert aid not in listed   # skipped like peek_queue skips it
    else:
        item = listed[aid]
        assert item["view_hash"] is None and item["can_decide_here"] is False
        assert item["can_approve_here"] is False and item["undecidable_reason"] == why
    calls = []
    api_mod_approve, api_mod_reject = api_mod.approve, api_mod.reject
    try:
        api_mod.approve = lambda *a, **k: calls.append("approve")
        api_mod.reject = lambda *a, **k: calls.append("reject")
        before = snapshot(tree.root)
        for verb in ("approve", "reject"):
            for hash_ in (good_hash, "0" * 64):
                assert decide(api, aid, verb, hash_) == UNDECIDABLE
        assert snapshot(tree.root) == before and calls == []
    finally:
        api_mod.approve, api_mod.reject = api_mod_approve, api_mod_reject


@pytest.mark.parametrize("files", [["../x.yml"], [], "0a1b2c3d-x.yml", [5],
                                   [DETECTION_PENDING + LRM], [DETECTION_PENDING] * 51])
def test_publish_detection_with_bad_file_names_is_undecidable(tree, files):
    aid = queue_publish(tree, files)
    item = items(make_api(tree))[aid]
    assert item["undecidable_reason"] == api_mod.WHY_PARAMS and item["view_hash"] is None
    assert decide(make_api(tree), aid, "approve", "0" * 64) == UNDECIDABLE


@pytest.mark.parametrize("priority", ["urgent", ["high"], "high" + LRM])
def test_open_ticket_with_a_bad_priority_is_undecidable(tree, priority):
    record = next(r for r in triage.load_records(tree.reports) if r.id == tree.ids["redis"])
    pb = Playbook.model_validate({"name": "ticket_pb", "when": {"signals": ["redis_takeover"]},
                                  "steps": [{"action": "open_ticket"}]})
    _, aid = queue_enforce_action(tree.state, pb, record, pb.steps[0], tree.now, 72,
                                  {"priority": priority})
    item = items(make_api(tree))[aid]
    assert item["undecidable_reason"] == api_mod.WHY_PARAMS


def test_symlinked_detection_file_is_undecidable(tree, tmp_path):
    outside = tmp_path / "outside.yml"
    outside.write_text("title: outside\n")
    name = "deadbeef-linked.yml"
    (tree.detections / "pending" / name).symlink_to(outside)
    aid = queue_publish(tree, [name])
    item = items(make_api(tree))[aid]
    assert item["undecidable_reason"] == api_mod.WHY_FILES and item["view_hash"] is None


# ---- the hash covers what the card shows ----------------------------------------------------

def test_record_retriaged_between_view_and_decision_is_409(tree):
    api = make_api(tree)
    aid = tree.ids["pending"]
    seen = items(api)[aid]
    assert seen["record"]["judgement"] == "MALICIOUS"
    record = next(r for r in triage.load_records(tree.reports) if r.id == tree.ids["redis"])
    triage.write_record(record.model_copy(update={"judgement": triage.Judgement.BENIGN,
                                                  "narrative": "re-triaged"}), tree.reports)
    before = snapshot(tree.root)
    for verb in ("approve", "reject"):
        assert decide(api, aid, verb, seen["view_hash"]) == (409, {"error": "changed"})
    assert snapshot(tree.root) == before
    fresh = items(api)[aid]
    assert fresh["record"]["judgement"] == "BENIGN" and fresh["view_hash"] != seen["view_hash"]


def test_record_change_is_seen_even_inside_the_cache_interval(tree):
    clock = [0.0]
    api = Api(tree.api_paths(), cache_seconds=60, clock=lambda: clock[0])
    aid = tree.ids["pending"]
    seen = items(api)[aid]["view_hash"]
    record = next(r for r in triage.load_records(tree.reports) if r.id == tree.ids["redis"])
    triage.write_record(record.model_copy(update={"username": "changed"}), tree.reports)
    os.utime(tree.reports / "campaigns", ns=(1, 1))   # directory times are no help either
    assert decide(api, aid, "approve", seen) == (409, {"error": "changed"})


def test_detection_file_rewritten_between_view_and_decision_is_409(tree):
    api = make_api(tree)
    aid = queue_publish(tree, [DETECTION_PENDING])
    item = items(api)[aid]
    assert item["detection_files"] == [{"name": DETECTION_PENDING, "present": True}]
    assert item["can_decide_here"] is True
    pending = tree.detections / "pending" / DETECTION_PENDING
    pending.write_text(pending.read_text() + "  sel2: written after queueing\n")
    before = snapshot(tree.root)
    assert decide(api, aid, "approve", item["view_hash"]) == (409, {"error": "changed"})
    assert snapshot(tree.root) == before
    # Approved on the fresh view, the file on screen is the file published.
    item = items(api)[aid]
    shown = pending.read_bytes()
    status, body = decide(api, aid, "approve", item["view_hash"])
    assert status == 200 and body["approval"]["result"]["files"] == [DETECTION_PENDING]
    assert (tree.detections / "approved" / DETECTION_PENDING).read_bytes() == shown


def test_missing_detection_file_hashes_as_a_marker(tree):
    api = make_api(tree)
    aid = queue_publish(tree, [DETECTION_PENDING])
    seen = items(api)[aid]["view_hash"]
    (tree.detections / "pending" / DETECTION_PENDING).unlink()
    assert decide(api, aid, "approve", seen) == (409, {"error": "changed"})
    item = items(api)[aid]
    assert item["detection_files"] == [{"name": DETECTION_PENDING, "present": False}]
    assert item["view_hash"] == api.view_of(aid).digest != seen


def test_decision_answer_is_a_projection(tree):
    api = make_api(tree)
    aid = tree.ids["pending"]
    status, body = decide(api, aid, "reject", items(api)[aid]["view_hash"])
    assert status == 200
    assert set(body["approval"]) <= set(api_mod.APPROVAL_FIELDS) | {"params", "result"}
    assert body["approval"]["status"] == "rejected"


# ---- invisible characters ------------------------------------------------------------------

INVISIBLE = {
    "format_zero_width": "​‌‍⁠﻿",
    "format_soft_hyphen_and_marks": "­؜‎‏‪‮⁦⁩⁯",
    "format_other_planes": "\U000110bd\U0001bca0\U0001d173",
    "separators": "  ",
    "variation_selectors": "︀️\U000e0100\U000e01ef᠋᠏",
    "tag_block": "\U000e0000\U000e0001\U000e0020\U000e0041\U000e007f",
    "hangul_fillers": "ᅟᅠㅤﾠ",
}


@pytest.mark.parametrize("name", sorted(INVISIBLE))
def test_clean_text_strips_each_invisible_class(name):
    chars = INVISIBLE[name]
    assert clean_text("a" + "b".join(chars) + "z") == "a" + "b" * (len(chars) - 1) + "z"
    assert clean_text("tab\tnew\nline é中\U0001f600") == "tab\tnew\nline é中\U0001f600"


def test_no_route_returns_an_invisible_character(tree):
    planted = "".join(INVISIBLE.values())
    record = next(r for r in triage.load_records(tree.reports) if r.id == tree.ids["redis"])
    triage.write_record(record.model_copy(update={"narrative": f"x{planted}y",
                                                  "username": f"r{planted}oot"}), tree.reports)
    api = make_api(tree)
    for path in ("/api/records", f"/api/records/{tree.ids['redis']}", "/api/queue",
                 "/api/overview"):
        status, body = api.get(path, {})
        assert status == 200
        text = json.dumps(body, ensure_ascii=False)
        assert not set(planted) & set(text), path
    assert api.get(f"/api/records/{tree.ids['redis']}", {})[1]["record"]["username"] == "root"


# ---- size caps -----------------------------------------------------------------------------

def test_scrub_caps_lists_and_dicts_and_flags_it():
    out, cut = scrub_flagged({"l": list(range(api_mod.LIST_CAP + 5)),
                              "d": {f"k{i}": i for i in range(api_mod.DICT_CAP + 5)}})
    assert len(out["l"]) == api_mod.LIST_CAP and len(out["d"]) == api_mod.DICT_CAP and cut
    out, cut = scrub_flagged({"l": list(range(10)), "d": {"a": 1}})
    assert cut is False and len(out["l"]) == 10
    big = {f"k{i}": i for i in range(api_mod.DICT_CAP * 3)}
    assert len(scrub(big)) == api_mod.DICT_CAP


def test_route_answer_is_flagged_when_capped(tree):
    run = next((tree.reports / "tuner").glob("*.json"))
    data = json.loads(run.read_text())
    data["changes"] = [{"kind": "x"}] * (api_mod.LIST_CAP + 10)
    run.write_text(json.dumps(data))
    api = make_api(tree)
    status, body = api.get("/api/decoy", {})
    assert status == 200 and body["truncated"] is True
    assert len(body["tuner_runs"][0]["changes"]) == api_mod.LIST_CAP
    assert "truncated" not in api.get("/api/overview", {})[1]


# ---- symlinks ------------------------------------------------------------------------------

def test_symlinked_tuner_run_outside_its_directory_is_not_served(tree, tmp_path):
    outside = tmp_path / "outside-run.json"
    outside.write_text(json.dumps({"timestamp": "x", "snapshot": 9, "changes": ["outside"],
                                   "rejected": [], "commit": None}))
    (tree.reports / "tuner" / "29990101T000000Z-ffffff.json").symlink_to(outside)
    body = make_api(tree).get("/api/decoy", {})[1]
    assert [r["snapshot"] for r in body["tuner_runs"]] == [1]


def test_symlinked_record_outside_its_directory_is_not_loaded(tree, tmp_path):
    record = next(r for r in triage.load_records(tree.reports) if r.id == tree.ids["redis"])
    outside = tmp_path / "outside-record.json"
    outside.write_text(record.model_copy(update={"id": "campaign-outside-1"}).model_dump_json())
    (tree.reports / "campaigns" / "campaign-outside-1.json").symlink_to(outside)
    api = make_api(tree)
    assert api.get("/api/records/campaign-outside-1", {}) == (404, {"error": "not found"})
    assert api.get("/api/records", {})[1]["total"] == 5


# ---- withheld transcript -------------------------------------------------------------------

def test_record_says_up_front_that_a_large_transcript_is_withheld(tree, monkeypatch):
    monkeypatch.setattr(logindex, "MAX_RANGE_BYTES", 100)
    api = make_api(tree)
    sid = tree.ids["session_a"]
    body = api.get(f"/api/records/{sid}", {})[1]
    assert body["transcript_available"] is False
    assert "grep -F" in body["transcript_withheld"] and sid in body["transcript_withheld"]
    monkeypatch.setattr(logindex, "MAX_RANGE_BYTES", 32 * 1024 * 1024)
    body = api.get(f"/api/records/{sid}", {})[1]
    assert body["transcript_available"] is True and body["transcript_withheld"] is None


# ---- honeytoken masking --------------------------------------------------------------------

@pytest.mark.parametrize("value,masked", [("", "......"), ("a", "......"), ("ab", "......"),
                                          ("abcdefg", "......"), ("abcdefgh", "ab......"),
                                          ("wnt-backup-canary-value-1", "wn......")])
def test_mask_never_shows_a_whole_value(value, masked):
    assert api_mod._mask(value) == masked


def test_short_honeytoken_is_fully_masked_in_the_route(tree):
    path = tree.reports / "honeytokens.json"
    reg = json.loads(path.read_text())
    reg["tokens"].append({"name": "tiny", "kind": "pin", "value": "42"})
    path.write_text(json.dumps(reg))
    body = make_api(tree).get("/api/honeytokens", {})[1]
    tokens = {t["name"]: t for t in body["tokens"]["items"]}
    assert tokens["tiny"]["value"] == "......"
