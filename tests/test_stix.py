"""STIX 2.1 export (agents/stix.py): every bundle produced here is checked with the OASIS
validator (stix2-validator, a dev dependency) in strict mode."""

from __future__ import annotations

import configparser
import datetime
import hashlib
import json
import os
import socket

import pytest

from agents import stix
from agents.addresses import public_for_tests
from agents.triage import UNVERIFIED_SOURCE, TriageRecord

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
A, B, C = "198.51.100.7", "198.51.100.8", "198.51.100.9"
V6 = "2001:db8:0:1::5"
H1 = hashlib.sha256(b"stix test upload").hexdigest()


@pytest.fixture(autouse=True)
def _public():
    with public_for_tests("198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"):
        yield


def rec(ip, judgement="MALICIOUS", seen=NOW, protocol="ssh", rid=None, **kw):
    kw.setdefault("auth_successes", 1)
    return TriageRecord(kind="session" if protocol == "ssh" else "campaign",
                        id=rid or f"s-{ip}-{judgement}-{protocol}", protocol=protocol,
                        src_ip=ip, first_seen=(seen - datetime.timedelta(hours=1)).isoformat(),
                        last_seen=seen.isoformat(), intent="RECONNAISSANCE", stage="DISCOVERY",
                        skill="AUTOMATED", judgement=judgement, narrative="x", **kw)


def upload(directory, sha, src, at=NOW, name="u1"):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.bin.json").write_text(json.dumps(
        {"sha256": sha, "src": src, "size": 100, "stored_at": at.isoformat()}))


def approve(state_dir, key, approved, expires, status="tracked", verified=True):
    path = state_dir / "approved_blocklist.json"
    doc = json.loads(path.read_text()) if path.exists() else {}
    doc[key] = {"approved_at": approved.isoformat(), "expires_at": expires.isoformat(),
                "status": status, "approval_id": "a-0123456789ab"}
    if verified:
        doc[key]["source_verified"] = True
    state_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))


def settings(**kw):
    return stix.StixSettings(enabled=True, **kw)


def export(tmp_path, records, now=NOW, s=None, networks=(), **kw):
    reports, state = tmp_path / "reports", tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    q = tmp_path / "quarantine"
    out = stix.run_export(s or settings(), records, reports, state, list(networks),
                          uploads_dir=q if q.exists() else None, upload_cap=10_000, now=now, **kw)
    assert "error" not in out, out
    path = reports / "stix" / "bundle.json"
    body = path.read_bytes()
    bundle = json.loads(body)
    # Every bundle a test produces: every reference resolves, and it is within its caps.
    s = s or settings()
    assert stix.dangling_references(bundle["objects"]) == []
    assert len(body) <= s.max_bytes and len(bundle["objects"]) <= s.max_objects
    return out, body, bundle


def objects(bundle, kind):
    return [o for o in bundle["objects"] if o["type"] == kind]


def indicator_values(bundle):
    return sorted(o["pattern"] for o in objects(bundle, "indicator"))


# ---- the OASIS validator -------------------------------------------------------------------

# Check 103 asks for UUIDv4 in every SDO id. Section 2.9 makes UUIDv4 a SHOULD and allows
# another UUID version from a namespace that guarantees uniqueness; these ids are UUIDv5 in
# this project's own namespace so that a re-export is identical. Everything else is checked
# strictly (warnings count as errors).
UUID_V4_CHECK = "103"


def validate(body: bytes) -> list[str]:
    validator = pytest.importorskip("stix2validator",
                                    reason="stix2-validator (dev dependency) not installed")
    text = body.decode()
    res = validator.validate_string(text, validator.ValidationOptions(
        strict=True, version="2.1", disabled=UUID_V4_CHECK))
    problems = [str(e) for e in res.errors] + [str(w) for w in (res.warnings or [])]
    # Without the exception, check 103 is the only finding, and only on our own UUIDv5 ids.
    full = validator.validate_string(text, validator.ValidationOptions(strict=True,
                                                                       version="2.1"))
    for finding in [str(e) for e in full.errors] + [str(w) for w in (full.warnings or [])]:
        if "{103}" not in finding:
            problems.append(finding)
            continue
        object_id = finding.split(":", 1)[0]
        assert object_id.split("--", 1)[1][14] == "5", finding     # a UUIDv5
    return problems


def test_full_bundle_is_valid_and_has_each_object_kind(tmp_path):
    approve(tmp_path / "state", "2001:db8:0:1::/64", NOW - datetime.timedelta(days=1),
            NOW + datetime.timedelta(days=29))
    upload(tmp_path / "quarantine", H1, A)
    records = [rec(A, high_signal={"ftp_upload": 1}), rec(B, auth_successes=0), rec(V6)]
    out, body, bundle = export(tmp_path, records)
    assert validate(body) == []
    kinds = sorted({o["type"] for o in bundle["objects"]})
    assert kinds == ["file", "identity", "indicator", "ipv4-addr", "ipv6-addr",
                     "marking-definition", "observed-data", "sighting"]
    assert indicator_values(bundle) == sorted([
        f"[ipv4-addr:value = '{A}']", f"[file:hashes.'SHA-256' = '{H1}']",
        "[ipv6-addr:value ISSUBSET '2001:db8:0:1::/64']"])
    for o in objects(bundle, "indicator"):
        assert o["valid_until"] > o["valid_from"]
        assert o["pattern_type"] == "stix" and o["indicator_types"] == ["malicious-activity"]
    # B only connected: seen, never promoted.
    observed = {o["object_refs"][0] for o in objects(bundle, "observed-data")}
    b_id = stix.sco_id("ipv4-addr", B)
    assert b_id in observed and B not in json.dumps(objects(bundle, "indicator"))
    # Every SDO carries the sensor identity and the TLP marking from config (default amber).
    (identity,) = objects(bundle, "identity")
    for o in bundle["objects"]:
        if o["type"] not in ("identity", "marking-definition"):
            assert o["object_marking_refs"] == [stix.TLP_IDS["amber"]]
        if o["type"] in ("indicator", "observed-data", "sighting"):
            assert o["created_by_ref"] == identity["id"]
    assert out["indicators"] == 3 and out["sightings"] == 3


def test_the_validator_check_does_catch_problems(tmp_path):
    _, body, bundle = export(tmp_path, [rec(A)])
    (ind,) = objects(bundle, "indicator")
    ind["valid_until"] = ind["valid_from"]
    assert validate(json.dumps(bundle).encode())
    ind["valid_until"], ind["pattern"] = "2027-01-01T00:00:00.000Z", "[ipv4-addr:value = 1"
    assert validate(json.dumps(bundle).encode())


def test_sco_ids_follow_the_spec_and_match_the_stix2_library():
    stix2 = pytest.importorskip("stix2", reason="stix2 (dev dependency) not installed")
    assert stix.sco_id("ipv4-addr", A) == stix2.IPv4Address(value=A).id
    assert stix.sco_id("ipv6-addr", V6) == stix2.IPv6Address(value=V6).id
    assert stix.sco_id("file", H1) == stix2.File(hashes={"SHA-256": H1}).id


def test_tlp_objects_are_the_standard_ones():
    stix2 = pytest.importorskip("stix2", reason="stix2 (dev dependency) not installed")
    for level, lib in (("white", stix2.TLP_WHITE), ("green", stix2.TLP_GREEN),
                       ("amber", stix2.TLP_AMBER), ("red", stix2.TLP_RED)):
        ours = stix.tlp_object(level)
        theirs = json.loads(lib.serialize())
        assert ours == {**theirs, "created": ours["created"]}
        assert ours["created"].startswith(theirs["created"].rstrip("Z"))


# ---- determinism ---------------------------------------------------------------------------

def test_same_input_gives_the_same_bytes_and_unchanged_reexport_is_identical(tmp_path):
    records = [rec(A, high_signal={"download_execute": 1}), rec(B, auth_successes=0)]
    _, first, _ = export(tmp_path / "one", records)
    _, second, _ = export(tmp_path / "two", records)
    assert first == second
    # Same directory, an hour later, nothing new: byte-identical and the file is untouched.
    path = tmp_path / "one" / "reports" / "stix" / "bundle.json"
    mtime = path.stat().st_mtime_ns
    out, again, _ = export(tmp_path / "one", records, now=NOW + datetime.timedelta(hours=1))
    assert again == first and out["status"] == "unchanged" and path.stat().st_mtime_ns == mtime


def test_modified_moves_only_when_content_changes(tmp_path):
    _, _, b1 = export(tmp_path, [rec(A)])
    (i1,) = objects(b1, "indicator")
    later = NOW + datetime.timedelta(days=2)
    _, _, b2 = export(tmp_path, [rec(A), rec(A, seen=later, rid="second")], now=later)
    (i2,) = objects(b2, "indicator")
    assert i2["id"] == i1["id"] and i2["created"] == i1["created"]
    assert i2["modified"] > i1["modified"] and i2["valid_until"] > i1["valid_until"]
    assert i2["valid_from"] == i1["valid_from"]
    (o1,) = [o for o in objects(b1, "observed-data")]
    (o2,) = [o for o in objects(b2, "observed-data")]
    assert o2["created"] == o1["created"] and o2["number_observed"] == 2


# ---- promotion -----------------------------------------------------------------------------

def test_the_model_cannot_promote_and_can_hold_back(tmp_path):
    records = [rec(A, auth_successes=0),                       # MALICIOUS, did nothing
               rec(B, judgement="BENIGN"),                      # logged in, judged benign
               rec(C, judgement="SUSPICIOUS")]                  # logged in
    _, body, bundle = export(tmp_path, records)
    assert indicator_values(bundle) == [f"[ipv4-addr:value = '{C}']"]
    assert len(objects(bundle, "observed-data")) == 3          # all three were seen
    assert validate(body) == []


def test_unproven_udp_sources_are_never_in_the_bundle(tmp_path):
    records = [rec(A, protocol="sip", unverified_source=True,
                   high_signal={"sip_dialed_number": 3}),
               rec(UNVERIFIED_SOURCE, protocol="sip")]
    _, _, bundle = export(tmp_path, records)
    assert objects(bundle, "indicator") == [] and objects(bundle, "observed-data") == []
    assert A not in json.dumps(bundle)


def test_never_act_on_and_the_sensor_address_are_left_out(tmp_path):
    import ipaddress

    _, _, bundle = export(tmp_path, [rec(A), rec(B)],
                          networks=[ipaddress.ip_network("198.51.100.7/32")])
    text = json.dumps(bundle)
    assert A not in text and B in text


def test_operator_entries_need_a_window_and_a_verified_source(tmp_path):
    state = tmp_path / "state"
    # Tracked, not recorded as verified: no indicator.
    approve(state, A, NOW - datetime.timedelta(days=1), NOW + datetime.timedelta(days=5),
            verified=False)
    # Enforced (approved before the tracked stage existed): indicator with its own window.
    approve(state, B, NOW - datetime.timedelta(days=2), NOW + datetime.timedelta(days=28),
            status="enforced")
    # Expiry before approval: no supportable window, stays observed-data.
    approve(state, C, NOW + datetime.timedelta(days=9), NOW + datetime.timedelta(days=3))
    _, body, bundle = export(tmp_path, [rec(x, auth_successes=0) for x in (A, B, C)])
    (ind,) = objects(bundle, "indicator")
    assert ind["pattern"] == f"[ipv4-addr:value = '{B}']"
    assert ind["labels"] == ["operator-enforced"] and ind["confidence"] == 85
    assert ind["valid_from"] == stix.ts(NOW - datetime.timedelta(days=2))
    assert ind["valid_until"] == stix.ts(NOW + datetime.timedelta(days=28))
    assert len(objects(bundle, "observed-data")) == 3
    assert validate(body) == []


# ---- withdrawal and expiry -----------------------------------------------------------------

def test_unblock_revokes_and_the_old_id_is_never_live_again(tmp_path):
    from agents.respond import unblock

    state, reports = tmp_path / "state", tmp_path / "reports"
    approve(state, A, NOW - datetime.timedelta(days=1), NOW + datetime.timedelta(days=29),
            status="enforced")
    _, b0, b1 = export(tmp_path, [rec(A, auth_successes=0)])
    (i1,) = objects(b1, "indicator")
    assert "revoked" not in i1 and validate(b0) == []
    later = NOW + datetime.timedelta(hours=2)
    unblock(A, state, reports, now=later - datetime.timedelta(hours=1), by="test")
    _, body, b2 = export(tmp_path, [rec(A, auth_successes=0)], now=later)
    (i2,) = objects(b2, "indicator")
    assert i2["id"] == i1["id"] and i2["revoked"] is True and i2["modified"] > i1["modified"]
    assert i2["created"] == i1["created"] and objects(b2, "sighting") == []
    assert validate(body) == []
    # Re-exported unchanged: the revoked version is written as it was, nothing live.
    _, again, _ = export(tmp_path, [rec(A, auth_successes=0)], now=later + datetime.timedelta(hours=1))
    assert again == body
    # Dropped keep_days after the revocation; even then the old id never comes back live.
    gone = later + datetime.timedelta(days=31)
    _, body, b4 = export(tmp_path, [rec(A, seen=gone)], now=gone)
    ids = {o["id"]: o for o in objects(b4, "indicator")}
    assert i1["id"] not in ids and len(ids) == 1      # the rule promotes A anew, new id
    assert validate(body) == []


def test_unblock_wins_over_the_rule_while_the_withdrawal_stands(tmp_path):
    from agents.respond import unblock

    state, reports = tmp_path / "state", tmp_path / "reports"
    # A logged in (rule-promoted) and was also approved by the operator.
    approve(state, A, NOW - datetime.timedelta(days=1), NOW + datetime.timedelta(days=29),
            status="enforced")
    _, _, b1 = export(tmp_path, [rec(A)])
    (i1,) = objects(b1, "indicator")
    assert i1["labels"] == ["rule-promoted", "operator-enforced"]
    t1 = NOW + datetime.timedelta(hours=1)
    unblock(A, state, reports, now=t1, by="test")
    # The rule still promotes A (fresh activity), but the operator withdrew it.
    for hours in (2, 24, 24 * 20):
        now = NOW + datetime.timedelta(hours=hours)
        _, body, b = export(tmp_path, [rec(A, seen=now)], now=now)
        live = [o for o in objects(b, "indicator") if not o.get("revoked")]
        assert live == [], hours
        assert [o["id"] for o in objects(b, "indicator")] == [i1["id"]]
        assert validate(body) == []
    # After keep_days the withdrawal no longer stands: the rule may promote A, under a new id.
    now = t1 + datetime.timedelta(days=31)
    _, body, b = export(tmp_path, [rec(A, seen=now)], now=now)
    (live,) = [o for o in objects(b, "indicator") if not o.get("revoked")]
    assert live["id"] != i1["id"] and live["labels"] == ["rule-promoted"]
    assert validate(body) == []


def test_operator_reapproval_after_unblock_gets_a_new_id(tmp_path):
    from agents.respond import unblock

    state, reports = tmp_path / "state", tmp_path / "reports"
    approve(state, A, NOW - datetime.timedelta(days=1), NOW + datetime.timedelta(days=29),
            status="enforced")
    _, _, b1 = export(tmp_path, [rec(A, auth_successes=0)])
    (i1,) = objects(b1, "indicator")
    t1 = NOW + datetime.timedelta(hours=1)
    unblock(A, state, reports, now=t1, by="test")
    t2 = NOW + datetime.timedelta(hours=2)
    approve(state, A, t2, t2 + datetime.timedelta(days=30), status="enforced")
    _, body, b2 = export(tmp_path, [rec(A, auth_successes=0)], now=t2 + datetime.timedelta(minutes=5))
    by_id = {o["id"]: o for o in objects(b2, "indicator")}
    assert by_id[i1["id"]]["revoked"] is True
    (new_id,) = set(by_id) - {i1["id"]}
    assert "revoked" not in by_id[new_id]
    assert by_id[new_id]["valid_from"] == stix.ts(t2)
    (sighting,) = objects(b2, "sighting")
    assert sighting["sighting_of_ref"] == new_id
    assert validate(body) == []
    # A second withdrawal revokes the second id; a third approval gets a third id.
    t3 = t2 + datetime.timedelta(hours=1)
    unblock(A, state, reports, now=t3, by="test")
    t4 = t3 + datetime.timedelta(hours=1)
    approve(state, A, t4, t4 + datetime.timedelta(days=30), status="enforced")
    _, body, b3 = export(tmp_path, [rec(A, auth_successes=0)], now=t4 + datetime.timedelta(minutes=5))
    states = sorted((o["id"] in (i1["id"], new_id), bool(o.get("revoked")))
                    for o in objects(b3, "indicator"))
    assert states == [(False, False), (True, True), (True, True)]
    assert validate(body) == []


def test_natural_expiry_is_not_a_revocation(tmp_path):
    state = tmp_path / "state"
    approve(state, A, NOW - datetime.timedelta(days=1), NOW + datetime.timedelta(days=1),
            status="enforced")
    _, _, b1 = export(tmp_path, [rec(A, auth_successes=0)])
    # The entry expires on its own; the indicator stays as it was (valid_until says it all).
    later = NOW + datetime.timedelta(days=3)
    _, body, b2 = export(tmp_path, [], now=later)
    assert objects(b2, "indicator") == objects(b1, "indicator")
    assert validate(body) == []
    # Kept keep_days past valid_until, then dropped (expiry pruning).
    _, body, b3 = export(tmp_path, [], now=NOW + datetime.timedelta(days=40))
    assert objects(b3, "indicator") == [] and objects(b3, "observed-data") == []
    assert validate(body) == []
    # Approved again: not revoked before, so the same id comes back as a new version.
    t = NOW + datetime.timedelta(days=41)
    approve(state, A, t, t + datetime.timedelta(days=5), status="enforced")
    _, body, b4 = export(tmp_path, [rec(A, auth_successes=0, seen=t)], now=t)
    (i4,) = objects(b4, "indicator")
    assert i4["id"] == objects(b1, "indicator")[0]["id"] and "revoked" not in i4
    assert validate(body) == []


def test_rule_promoted_indicator_outlives_the_lookback_until_valid_until(tmp_path):
    _, _, b1 = export(tmp_path, [rec(A)])
    _, _, b2 = export(tmp_path, [rec(A)], now=NOW + datetime.timedelta(days=10))
    assert objects(b2, "indicator") == objects(b1, "indicator")
    assert objects(b2, "indicator")[0]["valid_until"] == stix.ts(NOW + datetime.timedelta(days=30))


def test_hashes_get_their_own_lifetime(tmp_path):
    upload(tmp_path / "quarantine", H1, A)
    _, _, bundle = export(tmp_path, [rec(A, high_signal={"ftp_upload": 1})],
                          s=settings(hash_lifetime_days=400, address_lifetime_days=10))
    until = {o["pattern"].split(":")[0]: o["valid_until"] for o in objects(bundle, "indicator")}
    assert until["[file"] == stix.ts(NOW + datetime.timedelta(days=400))
    assert until["[ipv4-addr"] == stix.ts(NOW + datetime.timedelta(days=10))


# ---- hostile input -------------------------------------------------------------------------

def test_patterns_escape_quotes_and_backslashes():
    assert stix.pattern_string("a'b\\c") == "'a\\'b\\\\c'"
    assert stix.pattern_string("\\'") == "'\\\\\\''"
    patterns = pytest.importorskip("stix2patterns.validator",
                                   reason="stix2-patterns (dev dependency) not installed")
    for value in ("a'b", "x\\y", "\\'", "''", "\\"):
        pattern = f"[file:name = {stix.pattern_string(value)}]"
        assert patterns.run_validator(pattern, stix_version="2.1") == [], pattern


@pytest.mark.parametrize("key", [
    "ipv4-addr|198.51.100.7' OR '1", "ipv4-addr|198.51.100.007", "ipv4-addr|10.0.0.1",
    "ipv6-addr|2001:DB8::5", "ipv6-addr|2001:db8::5/64", "file|" + "A" * 64, "file|x'",
    "url|http://198.51.100.7/", "ipv4-addr|198.51.100.0/24", "", None, 5])
def test_only_canonical_validated_values_become_keys(key):
    assert stix.parse_key(key) is None


def test_attacker_text_never_reaches_the_bundle(tmp_path):
    hostile = "x' OR '1'='1 \\ <script>"
    upload(tmp_path / "quarantine", H1, A)
    (tmp_path / "quarantine" / "bad.bin.json").write_text(json.dumps(
        {"sha256": hostile, "src": A, "size": 5, "stored_at": NOW.isoformat()}))
    records = [rec(A, username=hostile, command_sample=[hostile],
                   high_signal={"ftp_upload": 1, hostile[:20]: 1}, honeytokens=[hostile]),
               rec(B, auth_successes=0, protocol="http", rid=hostile[:30]),
               rec(f"{A}' OR '1", rid="bad-ip")]
    _, body, _ = export(tmp_path, records)
    text = body.decode()
    for piece in ("OR '1", "<script>", "\\\\ <", "x'"):
        assert piece not in text
    assert validate(body) == []


# ---- caps, files, state --------------------------------------------------------------------

def test_caps_keep_indicators_first(tmp_path):
    records = [rec(f"198.51.100.{i}", auth_successes=0) for i in range(1, 200)]
    records += [rec(f"203.0.113.{i}") for i in range(1, 5)]
    out, body, bundle = export(tmp_path, records, s=settings(max_objects=100))
    assert len(bundle["objects"]) <= 100 and out["groups_dropped_for_caps"] > 0
    assert len(objects(bundle, "indicator")) == 4 and len(objects(bundle, "sighting")) == 4
    assert validate(body) == []


def _sized(tmp_path, records, max_bytes):
    s = settings(max_bytes=max_bytes)
    return export(tmp_path, records, s=s)


def test_byte_cap_is_exact_at_and_one_below_the_limit(tmp_path):
    records = [rec(f"198.51.100.{i}", auth_successes=0) for i in range(1, 250)]
    records += [rec(f"203.0.113.{i}") for i in range(1, 4)]
    out, body, _ = _sized(tmp_path / "free", records, stix.BOUNDS["max_bytes"][1])
    full = len(body)
    assert full > 65536 and out["groups_dropped_for_caps"] == 0
    # Exactly at the limit: everything fits, same bytes.
    out, at, _ = _sized(tmp_path / "at", records, full)
    assert at == body and out["groups_dropped_for_caps"] == 0
    # One byte under: a whole group leaves, nothing partial, refs still close.
    out, under, bundle = _sized(tmp_path / "under", records, full - 1)
    assert len(under) <= full - 1 and out["groups_dropped_for_caps"] >= 1
    assert len(objects(bundle, "indicator")) == 3
    assert validate(under) == []


def test_a_group_that_does_not_fit_is_skipped_and_a_smaller_one_still_goes_in():
    state = stix.empty_state(stix.DEFAULT_IDENTITY)
    stamp = stix.ts(NOW)
    content = {"valid_from": stamp, "valid_until": stix.ts(NOW + datetime.timedelta(days=9)),
               "bases": ["tracked"], "classes": [], "protocol": ""}
    # An IPv6 /64 indicator whose sighting refers to ten /128 observations (big group), and a
    # single-address indicator (small group).
    state["indicators"]["ipv6-addr|2001:db8:0:1::/64"] = {
        "generation": 0, "content": content, "created": stamp, "modified": stamp, "seen": stamp}
    state["indicators"]["ipv4-addr|" + A] = {
        "generation": 0, "content": {**content, "valid_until": stix.ts(NOW + datetime.timedelta(days=5))},
        "created": stamp, "modified": stamp, "seen": stamp}
    obs = {"content": {"first": stamp, "last": stamp, "count": 1}, "created": stamp,
           "modified": stamp, "seen": stamp}
    for i in range(1, 11):
        state["observed"][f"ipv6-addr|2001:db8:0:1::{i:x}"] = obs
    state["observed"]["ipv4-addr|" + A] = obs
    # The /64 group (longer window, so first) is 22 objects; the IPv4 group is 4. With the
    # identity and the marking, 6 objects fit: the big group is left out whole, the small
    # one that comes after it still goes in.
    capped = stix.StixSettings(enabled=True, max_objects=6)
    body, objs, counts = stix.build_bundle(state, capped)
    stix.check_bundle(body, objs, capped)
    assert stix.dangling_references(objs) == []
    types = sorted(o["type"] for o in objs)
    assert counts["groups_dropped_for_caps"] >= 1
    assert "indicator" in types and len(body) <= capped.max_bytes
    # The big group was the one left out: the IPv4 indicator and its sighting are in.
    assert {o["pattern"] for o in objs if o["type"] == "indicator"} == {f"[ipv4-addr:value = '{A}']"}
    assert sum(1 for o in objs if o["type"] == "sighting") == 1
    assert validate(body) == []


def test_overlapping_v6_groups_under_a_tight_object_cap_never_dangle(tmp_path):
    state = tmp_path / "state"
    approve(state, "2001:db8:0:1::/64", NOW - datetime.timedelta(days=1),
            NOW + datetime.timedelta(days=29))
    records = [rec(f"2001:db8:0:1::{i:x}", auth_successes=0) for i in range(1, 12)]
    records += [rec(f"198.51.100.{i}", auth_successes=0) for i in range(1, 120)]
    for cap in (100, 101, 102, 103, 120):
        out, body, bundle = export(tmp_path / str(cap), records, s=settings(max_objects=cap))
        assert validate(body) == []


def test_the_writer_refuses_a_bundle_with_a_dangling_reference(tmp_path, monkeypatch):
    _, first, _ = export(tmp_path, [rec(A)])
    real = stix.sighting_object

    def broken(ids, name, ind, observed):
        obj = real(ids, name, ind, observed)
        obj["observed_data_refs"] = ["observed-data--" + "0" * 8 + "-0000-5000-8000-" + "a" * 12]
        return obj

    monkeypatch.setattr(stix, "sighting_object", broken)
    out = stix.run_export(settings(), [rec(A, seen=NOW + datetime.timedelta(hours=1))],
                          tmp_path / "reports", tmp_path / "state", [],
                          now=NOW + datetime.timedelta(hours=1))
    assert "unresolved references" in out["error"]
    assert (tmp_path / "reports" / "stix" / "bundle.json").read_bytes() == first


def test_references_are_found_at_any_depth():
    objs = [{"id": "a--1", "created_by_ref": "b--2",
             "granular_markings": [{"marking_ref": "c--3", "selectors": ["x"]}],
             "extensions": {"x": {"thing_refs": ["d--4"]}}}]
    assert stix.dangling_references(objs) == ["b--2", "c--3", "d--4"]
    objs += [{"id": i} for i in ("b--2", "c--3", "d--4")]
    assert stix.dangling_references(objs) == []


def test_randomised_small_inputs_with_tight_caps(tmp_path):
    import random

    from agents.respond import unblock

    rng = random.Random(20261121)
    for round_ in range(25):
        base = tmp_path / f"r{round_}"
        state, reports = base / "state", base / "reports"
        addresses = [f"198.51.100.{i}" for i in rng.sample(range(1, 250), rng.randint(1, 30))]
        addresses += [f"2001:db8:0:{rng.randint(1, 3)}::{rng.randint(1, 99):x}"
                      for _ in range(rng.randint(0, 8))]
        for addr in rng.sample(addresses, min(len(addresses), rng.randint(0, 6))):
            key = addr if ":" not in addr else str(
                __import__("ipaddress").ip_network(addr + "/64", strict=False))
            approve(state, key, NOW - datetime.timedelta(days=rng.randint(0, 5)),
                    NOW + datetime.timedelta(days=rng.randint(1, 40)),
                    status=rng.choice(["tracked", "enforced"]))
        if rng.random() < 0.6:
            upload(base / "quarantine", hashlib.sha256(str(round_).encode()).hexdigest(),
                   addresses[0])
        s = settings(max_objects=rng.choice([100, 101, 110, 150, 400]),
                     max_bytes=rng.choice([65536, 70000, 200000]),
                     keep_days=rng.randint(1, 5))
        now = NOW
        for step in range(4):
            records = [rec(a, seen=now, auth_successes=rng.choice([0, 1]),
                           high_signal=rng.choice([{}, {"ftp_upload": 1}]))
                       for a in addresses if rng.random() < 0.8]
            if step == 2 and rng.random() < 0.7:
                approved = json.loads((state / "approved_blocklist.json").read_text()) \
                    if (state / "approved_blocklist.json").exists() else {}
                if approved:
                    unblock(rng.choice(sorted(approved)), state, reports,
                            now=now - datetime.timedelta(minutes=1), by="test")
            out, body, _ = export(base, records, now=now, s=s)
            assert validate(body) == [], (round_, step)
            now += datetime.timedelta(days=rng.choice([0.1, 1, 3, 7]))


# ---- state ---------------------------------------------------------------------------------

def _state_file(tmp_path):
    return stix.state_path(tmp_path / "state", stix.DEFAULT_IDENTITY)


def test_files_are_owner_only(tmp_path):
    export(tmp_path, [rec(A)])
    bundle = tmp_path / "reports" / "stix" / "bundle.json"
    assert bundle.stat().st_mode & 0o777 == 0o600
    assert _state_file(tmp_path).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("damage", ["not json", "garbage entry", "bad version", "symlink",
                                    "live under revoked id", "generation lowered",
                                    "generation missing", "removed"])
def test_corrupt_or_lost_state_fails_closed_and_keeps_the_bundle(tmp_path, damage):
    from agents.respond import unblock

    state_dir, reports = tmp_path / "state", tmp_path / "reports"
    approve(state_dir, A, NOW - datetime.timedelta(days=1), NOW + datetime.timedelta(days=29),
            status="enforced")
    export(tmp_path, [rec(A)])
    later = NOW + datetime.timedelta(hours=2)
    unblock(A, state_dir, reports, now=later - datetime.timedelta(hours=1), by="test")
    _, revoked_body, b = export(tmp_path, [rec(A, seen=later)], now=later)
    (old,) = objects(b, "indicator")
    assert old["revoked"] is True
    path = _state_file(tmp_path)
    doc = json.loads(path.read_text())
    if damage == "not json":
        path.write_text("{not json")
    elif damage == "garbage entry":
        doc["observed"]["ipv4-addr|10.0.0.1"] = doc["observed"][f"ipv4-addr|{A}"]
        path.write_text(json.dumps(doc))
    elif damage == "bad version":
        path.write_text(json.dumps({**doc, "version": 2}))
    elif damage == "symlink":
        os.remove(path)
        os.symlink(reports / "stix" / "bundle.json", path)
    elif damage == "live under revoked id":
        name = next(iter(doc["revoked"]))
        doc["indicators"][f"ipv4-addr|{A}"] = {
            "generation": 0, "content": doc["revoked"][name]["content"],
            "created": doc["revoked"][name]["created"], "modified": doc["revoked"][name]["modified"],
            "seen": doc["revoked"][name]["modified"]}
        doc["generations"] = {}
        path.write_text(json.dumps(doc))
    elif damage == "generation lowered":
        doc["generations"] = {k: 0 for k in doc["generations"]}
        path.write_text(json.dumps(doc))
    elif damage == "generation missing":
        doc["generations"] = {}
        path.write_text(json.dumps(doc))
    else:
        os.remove(path)
    # Rule and operator would both promote A again now.
    approve(state_dir, A, later, later + datetime.timedelta(days=30), status="enforced")
    out = stix.run_export(settings(), [rec(A, seen=later)], reports, state_dir, [],
                          now=later + datetime.timedelta(hours=1))
    assert "error" in out and "nothing written" in out["error"]
    assert (reports / "stix" / "bundle.json").read_bytes() == revoked_body


def test_state_that_would_outgrow_the_load_limit_is_refused(tmp_path, monkeypatch):
    _, first, _ = export(tmp_path, [rec(A)])
    # Room for the state as it is, not for one more source.
    monkeypatch.setattr(stix, "MAX_STATE_BYTES", _state_file(tmp_path).stat().st_size + 10)
    out = stix.run_export(settings(), [rec(A), rec(B)], tmp_path / "reports",
                          tmp_path / "state", [], now=NOW + datetime.timedelta(hours=1))
    assert "size limit" in out["error"]
    assert (tmp_path / "reports" / "stix" / "bundle.json").read_bytes() == first


def test_another_identity_is_another_producer(tmp_path):
    _, _, b1 = export(tmp_path, [rec(A)])
    _, body, b2 = export(tmp_path, [rec(A)], s=settings(identity_name="Second sensor"))
    ids1 = {o["id"] for o in b1["objects"] if o["type"] not in ("ipv4-addr", "marking-definition")}
    ids2 = {o["id"] for o in b2["objects"] if o["type"] not in ("ipv4-addr", "marking-definition")}
    assert ids1.isdisjoint(ids2)
    assert stix.state_path(tmp_path / "state", "Second sensor").exists()
    assert validate(body) == []


def test_settings_are_off_by_default_and_checked():
    assert stix.StixSettings.from_config(configparser.ConfigParser()).enabled is False

    def cfg(text):
        cp = configparser.ConfigParser()
        cp.read_string(text)
        return cp

    assert not stix.StixSettings.from_config(cfg("[stix]\nenabled = false\n")).enabled
    with pytest.raises(stix.ConfigError):
        stix.StixSettings.from_config(cfg("[stix]\nenabled = maybe\n"))
    s = stix.StixSettings.from_config(cfg("[stix]\nenabled = true\ntlp = GREEN\n"))
    assert s.enabled and s.tlp == "green" and s.identity_name == "Honeypot sensor"
    for bad in ("tlp = clear", "identity_name = <x>", "output_file = relative/path",
                "max_objects = 5", "lookback_days = many", "url = https://example.com"):
        with pytest.raises(stix.ConfigError):
            stix.StixSettings.from_config(cfg(f"[stix]\nenabled = true\n{bad}\n"))


def _cli(tmp_path, command, text):
    from agents.__main__ import run as cli_run

    cfg_path = tmp_path / "config.ini"
    cfg_path.write_text(text)
    return cli_run([command, "--config", str(cfg_path), "--reports-dir",
                    str(tmp_path / "reports"), "--state-dir", str(tmp_path / "state"),
                    "--log", str(tmp_path / "x.log"), "--data-dir", str(tmp_path / "data"),
                    "--detections-dir", str(tmp_path / "detections"), "--no-llm"])


def test_cli_stix_and_run_all_write_the_file_and_open_no_socket(tmp_path, monkeypatch):
    from agents.triage import write_record

    reports = tmp_path / "reports"
    for r in (rec(A), rec(B, auth_successes=0)):
        write_record(r, reports)
    assert _cli(tmp_path, "stix", "")["stix"] == {"status": "disabled"}
    assert not (reports / "stix").exists()

    def no_socket(*a, **k):
        raise AssertionError("the STIX export opened a socket")

    monkeypatch.setattr(socket, "socket", no_socket)
    monkeypatch.setattr(socket, "create_connection", no_socket)
    out = _cli(tmp_path, "stix", "[stix]\nenabled = true\ntlp = green\n")["stix"]
    assert out["status"] == "written" and out["indicators"] >= 1, out
    body = (reports / "stix" / "bundle.json").read_bytes()
    assert validate(body) == []
    assert _cli(tmp_path, "run-all", "[stix]\nenabled = true\ntlp = green\n")["stix"][
        "status"] == "unchanged"
    assert (reports / "stix" / "bundle.json").read_bytes() == body


# ---- the unblock audit trail ---------------------------------------------------------------

def _promoted_and_approved(tmp_path):
    """A rule-promoted source the operator also approved; one live indicator written."""
    approve(tmp_path / "state", A, NOW - datetime.timedelta(days=1),
            NOW + datetime.timedelta(days=29), status="enforced")
    _, body, bundle = export(tmp_path, [rec(A)])
    (ind,) = objects(bundle, "indicator")
    assert "revoked" not in ind
    return body, ind


def test_a_failed_unblock_audit_leaves_the_blocklist_unchanged(tmp_path, monkeypatch):
    from agents import respond

    _promoted_and_approved(tmp_path)
    before = (tmp_path / "state" / "approved_blocklist.json").read_bytes()
    real = respond._atomic_json

    def failing(path, payload, mode=0o600):
        if "-unblock-" in path.name:
            raise OSError("disk full")
        return real(path, payload, mode)

    monkeypatch.setattr(respond, "_atomic_json", failing)
    with pytest.raises(OSError):
        respond.unblock(A, tmp_path / "state", tmp_path / "reports",
                        now=NOW + datetime.timedelta(hours=1), by="test")
    # No removal happened without its record: the entry is still approved.
    assert (tmp_path / "state" / "approved_blocklist.json").read_bytes() == before
    assert A in respond.peek_blocklist(tmp_path / "state", NOW + datetime.timedelta(hours=1))


def test_every_unblock_record_is_read_not_only_the_newest(tmp_path):
    from agents.respond import unblock

    _, ind = _promoted_and_approved(tmp_path)
    reports = tmp_path / "reports"
    # The real removal first, then 501 later records for other addresses.
    unblock(A, tmp_path / "state", reports, now=NOW + datetime.timedelta(minutes=10), by="t")
    for i in range(501):
        at = NOW + datetime.timedelta(minutes=20, seconds=i)
        (reports / "response" / f"{at.strftime('%Y%m%dT%H%M%SZ')}-unblock-{i:06x}.json"
         ).write_text(json.dumps({"timestamp": at.isoformat(),
                                  "unblock": {"target": "198.51.100.200",
                                              "removed": [], "by": "t"}}))
    later = NOW + datetime.timedelta(hours=2)
    _, body, bundle = export(tmp_path, [rec(A, seen=later)], now=later)
    assert [(o["id"], o.get("revoked")) for o in objects(bundle, "indicator")] == \
        [(ind["id"], True)]
    assert validate(body) == []


@pytest.mark.parametrize("damage", ["malformed", "not json", "unreadable", "too many",
                                    "future"])
def test_an_untrustworthy_audit_trail_stops_the_export(tmp_path, monkeypatch, damage):
    from agents.respond import unblock

    first, _ = _promoted_and_approved(tmp_path)
    reports = tmp_path / "reports"
    unblock(A, tmp_path / "state", reports, now=NOW + datetime.timedelta(minutes=10), by="t")
    (record,) = (reports / "response").glob("*-unblock-*.json")
    if damage == "malformed":
        record.write_text(json.dumps({"timestamp": "yesterday", "unblock": {"removed": [A]}}))
    elif damage == "not json":
        record.write_text("{trunc")
    elif damage == "unreadable":
        record.unlink()
        record.mkdir()
    elif damage == "future":
        # The clock went back after the unblock: the record is later than "now".
        doc = json.loads(record.read_text())
        doc["timestamp"] = (NOW + datetime.timedelta(days=1)).isoformat()
        record.write_text(json.dumps(doc))
    else:
        monkeypatch.setattr(stix, "MAX_AUDIT_FILES", 0)
    later = NOW + datetime.timedelta(hours=2)
    out = stix.run_export(settings(), [rec(A, seen=later)], reports, tmp_path / "state", [],
                          now=later)
    assert "unblock record" in out["error"] and "nothing written" in out["error"]
    assert (reports / "stix" / "bundle.json").read_bytes() == first
