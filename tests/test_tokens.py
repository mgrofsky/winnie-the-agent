"""Planted tokens: issued without a fixed marker, recognised by lookup, old formats kept for
recognition only."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from urllib.parse import unquote, urlsplit

import pytest

from agents.budget import ip_key
from agents.source_state import legacy_source_token, source_token
from scenarios.bait import Bait, Pins, iter_strings
from scenarios.check import check_text
from scenarios.loader import load_honeytoken_values, load_scenario, write_honeytokens
from scenarios.tokens import (
    KINDS,
    SCAN_LIMIT,
    TokenIndex,
    honeytoken_value,
    legacy_honeytoken_value,
    legacy_source_pair,
    source_pair,
)

SHIPPED = ["sip_provider", "contact_center", "bank", "healthcare", "saas", "api_platform"]
SEEDS = [f"seed-{i}" for i in range(300)]

# The real formats each kind imitates: length and alphabet, and only the real prefix.
FORMATS = {
    "aws_access_key": r"AKIA[A-Z2-7]{16}",
    "api_key": r"sk_test_[A-Za-z0-9]{24}",
    "bearer_token": r"[A-Za-z0-9_-]{43}",
    "sip_trunk_password": r"[A-Za-z0-9]{16}",
    "ssh_private_key_id": r"SHA256:[A-Za-z0-9+/]{43}",
    "db_password": r"[A-Za-z0-9]{10}[-._][0-9]{2}",
    "generic_password": r"[A-Za-z0-9]{10}[-._][0-9]{2}",
}
REAL_PREFIX = {"aws_access_key": "AKIA", "api_key": "sk_test_", "ssh_private_key_id": "SHA256:"}


@pytest.mark.parametrize("kind", KINDS)
def test_issued_tokens_have_the_real_format(kind):
    for seed in SEEDS[:50]:
        value = honeytoken_value(kind, seed, "sip_provider", "tok")
        assert re.fullmatch(FORMATS[kind], value), (kind, value)
        assert not value.startswith(("sk_live_", "rk_live_"))


@pytest.mark.parametrize("kind", KINDS)
def test_issued_tokens_carry_no_fixed_marker(kind):
    """Past the real format's own prefix, no position is constant across sensors, and none
    of the old markers appears."""
    values = [honeytoken_value(kind, s, "sip_provider", "tok") for s in SEEDS]
    start = len(REAL_PREFIX.get(kind, ""))
    for i in range(start, min(len(v) for v in values)):
        assert len({v[i] for v in values}) > 1, (kind, i)
    old = ("AKIA" + "FAKE", "sk_test_" + "hp_", "hp" + "t_", "Tr" + "k")
    assert not [v for v in values if v.startswith(old)]
    assert len(set(values)) == len(values)


def test_source_pairs_have_the_real_format_and_no_marker():
    pairs = [source_pair(s, "198.51.100.7") for s in SEEDS]
    for access, secret in pairs:
        assert re.fullmatch(r"AKIA[A-Z2-7]{16}", access)
        assert re.fullmatch(r"[A-Za-z0-9+/]{40}", secret)
    for i in range(4, 20):
        assert len({a[i] for a, _ in pairs}) > 1
    assert source_token("s", "k") == source_pair("s", "k")
    assert source_pair("s", "a") != source_pair("s", "b") != source_pair("t", "a")


# sha256 prefixes of what the earlier generators returned for seed "legacy-seed": the legacy
# functions must keep producing exactly these, or tokens already handed out are lost.
LEGACY = {
    "aws_access_key": "d41c5d4089486596",
    "api_key": "0216c450af99584c",
    "bearer_token": "497bfc2937bd1c3e",
    "db_password": "70f5d913459ee98e",
    "sip_trunk_password": "b98c45a35574c036",
    "generic_password": "8f748ec2f9eb7e41",
    "ssh_private_key_id": "8d07bc10bfb41553",
}


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


@pytest.mark.parametrize("kind", KINDS)
def test_legacy_formats_reproduce_what_old_sensors_issued(kind):
    old = legacy_honeytoken_value(kind, "legacy-seed", "sip_provider", f"tok_{kind}")
    assert _h(old) == LEGACY[kind]
    assert old != honeytoken_value(kind, "legacy-seed", "sip_provider", f"tok_{kind}")


def test_legacy_source_pair_reproduces_the_old_one():
    access, secret = legacy_source_pair("legacy-seed", "198.51.100.40")
    assert [_h(access), _h(secret)] == ["22c8c44082f9864b", "8f95bb3935911392"]
    # Only the key id changed; the secret an attacker may hold is the same.
    assert source_pair("legacy-seed", "198.51.100.40")[1] == secret
    assert legacy_source_token("legacy-seed", "198.51.100.40") == (access, secret)


# ---- the index ----------------------------------------------------------------------------

def test_index_finds_a_token_anywhere_in_bounded_text():
    index = TokenIndex({"Zq81kLmP0aXy-42": "db", "AKIA" + "Q" * 16: "aws"})
    assert index.find("Zq81kLmP0aXy-42") == "db"
    assert index.find("postgres://u:Zq81kLmP0aXy-42@h/db") == "db"
    assert index.find("aws_access_key_id=AKIA" + "Q" * 16 + "\n") == "aws"
    assert index.find("Zq81kLmP0aXy-4") is None          # a prefix is not the token
    assert index.find("nothing here") is None and index.find("") is None
    # Input past the scan limit is not looked at.
    assert index.find("x" * SCAN_LIMIT + "Zq81kLmP0aXy-42") is None
    assert index.find("x" * (SCAN_LIMIT - 20) + "Zq81kLmP0aXy-42") == "db"


def test_index_cost_does_not_grow_with_the_number_of_tokens():
    small = TokenIndex({honeytoken_value("bearer_token", s, "x", "t"): s for s in SEEDS[:5]})
    big = TokenIndex({honeytoken_value("bearer_token", f"s{i}", "x", "t"): str(i)
                      for i in range(50_000)})
    text = os.urandom(SCAN_LIMIT // 2).hex()

    def timed(index):
        start = time.perf_counter()
        for _ in range(5):
            assert index.find(text) is None
        return time.perf_counter() - start

    timed(small)
    assert timed(big) < timed(small) * 5 + 0.05


# ---- scenario honeytokens: issued, registered and recognised -------------------------------

def test_loaded_scenario_issues_new_values_and_recognises_old_ones(tmp_path):
    loaded = load_scenario("api_platform", seed="sensor-a")
    current = {t.name: t.value for t in loaded.honeytokens.values()}
    legacy = {t.name: t.value for t in loaded.legacy_honeytokens.values()}
    assert set(current) == set(legacy) and not set(current.values()) & set(legacy.values())
    # Old values are never served: not in the expanded scenario, not in the tables.
    blob = loaded.scenario.model_dump_json()
    for db in loaded.scenario.services.postgres.databases:
        for t in db.tables:
            blob += repr(loaded.table_rows(db.name, t.name)[1])
    assert all(v in blob for v in current.values())
    assert not [v for v in legacy.values() if v in blob]
    # Both are recognised, by the agents' registry and by the listeners' index.
    reg = tmp_path / "honeytokens.json"
    write_honeytokens(loaded, reg)
    index = TokenIndex(load_honeytoken_values(reg))
    for name in current:
        assert index.find(f"x {current[name]} y") == name
        assert index.find(f"x {legacy[name]} y") == name
    marked = [t for t in json.loads(reg.read_text())["tokens"] if t.get("legacy")]
    assert {t["value"] for t in marked} == set(legacy.values())


def test_listeners_recognise_current_and_legacy_tokens(tmp_path):
    from listeners.base import ListenerContext
    from listeners.events import EventWriter
    from test_listeners_source_state import write_state

    loaded = load_scenario("saas", seed="sensor-a")
    state = tmp_path / "source_state.json"
    write_state(state, **{"203_0_113_5": {"plant_token": True}})
    ctx = ListenerContext(EventWriter(None), seed="sensor-a", source_state_path=str(state),
                          honeytokens=loaded.recognised_tokens())
    ctx.source_state.check_every = 0.0
    for t in list(loaded.honeytokens.values()) + list(loaded.legacy_honeytokens.values()):
        assert ctx.honeytoken_in("user", f"Bearer {t.value}") == t.name
    key = ip_key("203.0.113.5")
    new_access, secret = source_token("sensor-a", key)
    old_access, _ = legacy_source_token("sensor-a", key)
    for value in (new_access, old_access, secret):
        assert ctx.honeytoken_in(f"aws_access_key_id = {value}") is not None
    # A key id this sensor never issued, of the same shape, is not a token.
    assert ctx.honeytoken_in("AKIA" + "B" * 16) is None


def test_respond_registers_the_legacy_key_id_for_detection_only(tmp_path):
    from agents.respond import register_source_tokens
    from agents.source_state import SourceState, new_entry

    state = SourceState()
    e = new_entry("198.51.100.40").model_copy(update={"plant_token": True})
    state.entries[e.key] = e
    register_source_tokens(tmp_path, state, "sensor-a")
    tokens = json.loads((tmp_path / "honeytokens.json").read_text())["tokens"]
    old_access, _ = legacy_source_token("sensor-a", e.key)
    access, secret = source_token("sensor-a", e.key)
    by_value = {t["value"]: t for t in tokens}
    assert by_value[old_access].get("legacy") is True
    assert not by_value[access].get("legacy") and not by_value[secret].get("legacy")


# ---- the checker -----------------------------------------------------------------------------

def test_checker_accepts_only_issued_aws_key_ids():
    issued = honeytoken_value("aws_access_key", "s", "x", "t")
    other = honeytoken_value("aws_access_key", "s", "x", "u")
    assert check_text(f"key {issued}", "acme.example", frozenset({issued})) == []
    assert any("AWS" in p for p in check_text(f"key {other}", "acme.example",
                                               frozenset({issued})))


# ---- credentials inside URLs -------------------------------------------------------------

_URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^\s\"'<>]+")


@pytest.mark.parametrize("name", SHIPPED)
def test_urls_with_credentials_parse_back_to_user_password_and_host(name):
    found = 0
    for seed in ("sensor-a", "sensor-b", "s3", "s4", "s5", "s6", "s7", "s8"):
        loaded = load_scenario(name, seed=seed)
        known = set(loaded.recognised_tokens()) | set(loaded.bait.values())
        for _, text in iter_strings(loaded.scenario.model_dump(mode="json")):
            for url in _URL_RE.findall(text):
                parts = urlsplit(url)
                if parts.password is None:
                    continue
                found += 1
                assert unquote(parts.password) in known, url
                assert parts.username and "@" not in parts.hostname
                assert url.split("@", 1)[1].startswith(parts.hostname), url
    if name in ("api_platform", "contact_center", "saas"):
        assert found


def test_url_template_round_trips_any_password():
    for seed in SEEDS:
        b = Bait(seed, "t_pack")
        text = "postgres://app:{{url:password:db}}@db.internal:5432/app"
        b.scan(text)
        url = b.expand_text(text)
        raw = b.expand_text("{{password:db}}")
        parts = urlsplit(url)
        assert (parts.username, unquote(parts.password), parts.hostname, parts.port) == \
            ("app", raw, "db.internal", 5432)


def test_url_template_of_a_honeytoken_keeps_the_value_recognisable():
    for seed in SEEDS[:50]:
        value = honeytoken_value("db_password", seed, "x", "db")
        b = Bait(seed, "t_pack", honeytokens={"db": value})
        b.scan("{{url:ht:db}}")
        # The issued alphabet needs no escaping, so the URL holds the token as issued.
        assert b.expand_text("{{url:ht:db}}") == value


# ---- pinned passwords --------------------------------------------------------------------

def test_pinned_password_survives_seed_changes_and_feeds_its_hash():
    doc = {"pw": "{{password:root:weak}}", "h": "{{sha1:root}}", "other": "{{password:x}}"}
    outs = []
    for seed in ("a", "b"):
        b = Bait(seed, "t_pack", Pins(passwords={"root": "Kept-Across-1"}))
        b.scan(doc)
        outs.append(b.expand(doc))
    assert outs[0]["pw"] == outs[1]["pw"] == "Kept-Across-1"
    assert outs[0]["h"] == hashlib.sha1(b"Kept-Across-1").hexdigest()
    assert outs[0]["other"] != outs[1]["other"]


def test_bait_table_pins_passwords_in_a_pack(tmp_path):
    from test_scenarios_bait import PACK, _pack

    text = PACK.replace('org_suffixes = ["Labs"]',
                        'org_suffixes = ["Labs"]\npasswords = { person1 = "Pinned!2024" }')
    for seed in ("a", "b"):
        loaded = load_scenario("t_pack", seed=seed, scenarios_dir=_pack(tmp_path, text))
        assert loaded.accounts_for("ftp")[0][1] == "Pinned!2024"


def test_bad_pinned_password_is_rejected(tmp_path):
    from pydantic import ValidationError

    from test_scenarios_bait import PACK, _pack

    text = PACK.replace('org_suffixes = ["Labs"]',
                        'org_suffixes = ["Labs"]\npasswords = { person1 = "" }')
    with pytest.raises(ValidationError, match="pinned password"):
        load_scenario("t_pack", seed="a", scenarios_dir=_pack(tmp_path, text))
