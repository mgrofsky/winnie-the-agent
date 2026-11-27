import datetime
import tomllib
from collections import Counter
from configparser import ConfigParser

import pytest
from pydantic import ValidationError

from agents.indicators import (
    DEFAULT_DIR,
    Indicator,
    IndicatorFile,
    IndicatorSet,
    from_config,
    load_indicators,
)
from agents.sessions import HttpRequest

T0 = datetime.datetime(2026, 11, 1, 12, 0, tzinfo=datetime.timezone.utc)
SRC = ["https://example.com/report"]


def ind(**kw):
    base = {"id": "x-1", "type": "user_agent", "match": "exact", "value": "Probe/1.0",
            "label": "probe", "confidence": "low", "sources": SRC, "reported": "2026-10-01"}
    base.update(kw)
    return Indicator.model_validate(base)


def req(path, query="", **kw):
    return HttpRequest(ts=T0, conn="c1", method="GET", path=path, query=query, **kw)


@pytest.mark.parametrize("bad", [
    {"id": "Bad Id"},
    {"type": "header"},
    {"match": "regex"},
    {"value": ""},
    {"value": "x" * 201},
    {"value": "a\nb"},
    {"confidence": "certain"},
    {"sources": []},
    {"sources": ["http://example.com/plain"]},
    {"sources": ["https://example.com/a b"]},
    {"reported": "26-10-01"},
    {"notes": "n" * 601},
    {"extra": "field"},
    {"type": "ipv4", "value": "192.0.2.1", "match": "prefix"},
    {"type": "ipv4", "value": "2001:db8::1"},
    {"type": "ipv6", "value": "192.0.2.1"},
    {"type": "ipv4", "value": "not-an-address"},
])
def test_schema_refuses(bad):
    with pytest.raises(ValidationError):
        ind(**bad)


def test_file_refuses_unknown_top_level_keys():
    with pytest.raises(ValidationError):
        IndicatorFile.model_validate({"indicators": [], "rules": []})


@pytest.mark.parametrize("match,value,ua,hit", [
    ("exact", "Probe/1.0", "Probe/1.0", True),
    ("exact", "Probe/1.0", "probe/1.0", True),          # user agents compare without case
    ("exact", "Probe/1.0", "Probe/1.0 extra", False),
    ("prefix", "probe/", "Probe/2.3 (x)", True),
    ("prefix", "probe/", "xProbe/2.3", False),
    ("contains", "probe", "Mozilla Probe/1", True),
    ("contains", "probe", "Mozilla", False),
])
def test_user_agent_matching(match, value, ua, hit):
    s = IndicatorSet([ind(match=match, value=value)])
    got = s.match(Counter({ua: 3}), [])
    assert (got[0].count == 3) if hit else got == []


def test_path_and_query_matching_is_case_sensitive_and_joins_the_query():
    s = IndicatorSet([
        ind(id="p-exact", type="path", value="/env.js"),
        ind(id="p-prefix", type="path", match="prefix", value="/packs/js/"),
        ind(id="p-contains", type="path", match="contains", value="/GenerateToken"),
        ind(id="q-exact", type="query", value="/swagger/?format=openapi"),
        ind(id="q-prefix", type="query", match="prefix", value="/sso?jwt="),
    ])
    reqs = [req("/env.js"), req("/ENV.JS"), req("/packs/js/main.js.map"), req("/packs/js/a.js"),
            req("/api/v2/GenerateToken"), req("/swagger/", "format=openapi"),
            req("/swagger/?format=openapi"), req("/sso", "jwt=e30.e30."), req("/sso")]
    got = {m.id: m.count for m in s.match(Counter(), reqs)}
    assert got == {"p-exact": 1, "p-prefix": 2, "p-contains": 1, "q-exact": 1, "q-prefix": 1}


def test_address_matching_is_exact_after_canonical_form():
    s = IndicatorSet([ind(id="a4", type="ipv4", value="192.0.2.7"),
                      ind(id="a6", type="ipv6", value="2001:db8::7")])
    got = {m.id for m in s.match(Counter(), [], ["192.0.2.7", "2001:0db8:0:0::7"])}
    assert got == {"a4", "a6"}
    assert s.match(Counter(), [], ["192.0.2.70", "2001:db8::70"]) == []


def test_matches_are_strongest_first_and_carry_no_provenance():
    s = IndicatorSet([ind(id="weak", value="a"), ind(id="strong", value="b",
                                                     confidence="medium", framework="FW")])
    got = s.match(Counter({"a": 9, "b": 1}), [])
    assert [m.id for m in got] == ["strong", "weak"]
    assert got[0].model_dump() == {"id": "strong", "framework": "FW", "label": "probe",
                                   "confidence": "medium", "count": 1}
    assert s.provenance("strong")["sources"] == SRC and s.provenance("gone") is None


def test_long_inputs_are_matched_in_linear_time():
    s = IndicatorSet([ind(match="contains", value="a" * 199 + "b"),
                      ind(id="p-1", type="path", match="contains", value="a" * 199 + "b")])
    big = "a" * 500
    assert s.match(Counter({big: 1}), [req(big)] * 300) == []


def test_shipped_file_holds_only_what_the_sources_state():
    raw = tomllib.loads((DEFAULT_DIR / "agentic-frameworks.toml").read_text())
    entries = {e["id"]: e for e in raw["indicators"]}
    s = load_indicators()
    assert s.errors == [] and len(s.entries) == len(entries)
    assert not any(e["type"] in ("ipv4", "ipv6") for e in entries.values())
    uas = {e["value"]: e for e in entries.values() if e["type"] == "user_agent"}
    assert set(uas) == {"artex-enrich/", "norma/", "ReconProbe/1.0"}
    assert uas["artex-enrich/"]["confidence"] == uas["norma/"]["confidence"] == "medium"
    assert uas["ReconProbe/1.0"]["confidence"] == "low"
    others = [e for e in entries.values() if e["type"] != "user_agent"]
    assert others and all(e["confidence"] == "low" and not e.get("framework") for e in others)
    for e in entries.values():
        assert e["sources"] and e["notes"]


def test_a_bad_file_is_left_out_whole_and_named(tmp_path):
    (tmp_path / "a.toml").write_text(
        '[[indicators]]\nid = "ok-1"\ntype = "path"\nvalue = "/x"\nlabel = "x"\n'
        'confidence = "low"\nsources = ["https://example.com/"]\nreported = "2026-01-01"\n')
    (tmp_path / "b.toml").write_text('[[indicators]]\nid = "bad"\n')
    (tmp_path / "c.toml").write_text("not toml [")
    (tmp_path / "d.toml").write_text(
        '[[indicators]]\nid = "ok-1"\ntype = "path"\nvalue = "/y"\nlabel = "y"\n'
        'confidence = "low"\nsources = ["https://example.com/"]\nreported = "2026-01-01"\n')
    s = load_indicators(tmp_path)
    assert [e.value for e in s.entries] == ["/x"]
    assert [e.split(":")[0] for e in s.errors] == ["b.toml", "c.toml", "d.toml"]


def test_config_turns_it_off_or_points_at_other_files(tmp_path):
    off = ConfigParser()
    off.read_string("[indicators]\nenabled = false\n")
    assert from_config(off) is None
    assert len(from_config(ConfigParser()).entries) == len(load_indicators().entries)
    (tmp_path / "mine.toml").write_text(
        '[[indicators]]\nid = "mine"\ntype = "ipv4"\nvalue = "192.0.2.9"\nlabel = "m"\n'
        'confidence = "high"\nsources = ["https://example.com/"]\nreported = "2026-01-01"\n')
    cp = ConfigParser()
    cp.read_string(f"[indicators]\nenabled = true\npath = {tmp_path}\n")
    assert [e.id for e in from_config(cp).entries] == ["mine"]
