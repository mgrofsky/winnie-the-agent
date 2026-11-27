"""Where a source address is: the offline lookup (both database shapes, off states, labels for
non-global addresses, hostile database text, reloads, the cache), the place stored on a
record, the digest's Who line, and the console's answers.

Database files are real ``.mmdb`` files built here (``mmdb_fixture``) and read with the
``maxminddb`` package when it is installed; the reader seam (``opener``) covers the rest.
Addresses: documentation ranges, the public resolvers the hygiene test allows (8.8.8.8,
8.8.4.4, 1.1.1.1) and the IPv6 resolver 2001:4860:4860::8888. Names, AS numbers (RFC 5398
documentation ASNs) and owners are made up.
"""

import builtins
import configparser
import datetime
import json
import logging
import os

import pytest

import ui_fixture
from agent_fakes import trap_event, write_log
from agents import enrich
from agents.enrich import GeoLookup, GeoSettings, non_global_label, parse_target
from agents.triage import (
    GeoInfo,
    TriageRecord,
    digest,
    geo_short,
    record_facts,
    run_triage,
    with_geo,
    write_record,
)
from agents.ui.api import Api
from mmdb_fixture import write_mmdb

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 1, 18, 0, tzinfo=UTC)
DAY = "2026-11-01"
BUILT = int(datetime.datetime(2026, 11, 3, 6, 0, tzinfo=UTC).timestamp())
V6 = "2001:4860:4860::8888"

# GeoLite2 City: subdivisions carry iso_code, city and country carry geoname_id.
GEOLITE_CITY = {
    "8.8.8.8/32": {
        "city": {"geoname_id": 1, "names": {"de": "Beispielstadt", "en": "Example City"}},
        "continent": {"code": "NA", "geoname_id": 2, "names": {"en": "North America"}},
        "country": {"geoname_id": 3, "iso_code": "US", "names": {"en": "United States",
                                                                  "fr": "États-Unis"}},
        "location": {"accuracy_radius": 1000, "latitude": 37.75, "longitude": -97.8,
                     "time_zone": "America/Chicago"},
        "registered_country": {"geoname_id": 3, "iso_code": "US",
                               "names": {"en": "United States"}},
        "subdivisions": [{"geoname_id": 4, "iso_code": "CA", "names": {"en": "California"}}],
    },
    "2001:4860::/32": {
        "country": {"geoname_id": 5, "iso_code": "DE", "names": {"en": "Germany"}},
        "city": {"geoname_id": 6, "names": {"en": "Frankfurt am Main"}},
    },
    # A country-less range (anycast): the registered country stands in.
    "1.1.1.1/32": {"registered_country": {"iso_code": "AU", "names": {"en": "Australia"}}},
}
# DB-IP Lite City: subdivisions have names only, the city has no geoname_id, names come in
# several languages and the country says whether it is in the EU.
DBIP_CITY = {
    "8.8.8.8/32": {
        "city": {"names": {"en": "Example City"}},
        "continent": {"code": "NA", "geoname_id": 2, "names": {"en": "North America",
                                                               "ja": "北アメリカ"}},
        "country": {"geoname_id": 3, "is_in_european_union": False, "iso_code": "US",
                    "names": {"en": "United States", "ko": "미국"}},
        "location": {"latitude": 37.75, "longitude": -97.8},
        "subdivisions": [{"names": {"en": "California"}}],
    },
    "2001:4860::/32": {
        "city": {"names": {"en": "Frankfurt am Main"}},
        "country": {"is_in_european_union": True, "iso_code": "DE", "names": {"en": "Germany"}},
        "subdivisions": [{"names": {"en": "Hesse"}}],
    },
}
# GeoLite2 ASN and DB-IP Lite ASN share these keys.
ASN = {
    "8.8.8.8/32": {"autonomous_system_number": 64500,
                   "autonomous_system_organization": "Example Transit"},
    "2001:4860::/32": {"autonomous_system_number": 64501,
                       "autonomous_system_organization": "Example Cloud"},
}


def _maxminddb():
    return pytest.importorskip("maxminddb")


def _lookup(tmp_path, city=GEOLITE_CITY, asn=ASN, **kw) -> GeoLookup:
    _maxminddb()
    city_path = write_mmdb(tmp_path / "city.mmdb", city, database_type="GeoLite2-City",
                           build_epoch=BUILT) if city is not None else None
    asn_path = write_mmdb(tmp_path / "asn.mmdb", asn, database_type="GeoLite2-ASN",
                          build_epoch=BUILT) if asn is not None else None
    return GeoLookup(GeoSettings(city_db=str(city_path) if city_path else None,
                                 asn_db=str(asn_path) if asn_path else None), **kw)


class FakeReader:
    def __init__(self, records, epoch=BUILT):
        self.records, self.calls, self.closed, self.epoch = records, 0, False, epoch

    def get(self, ip):
        self.calls += 1
        return self.records.get(ip)

    def metadata(self):
        return type("Meta", (), {"build_epoch": self.epoch})()

    def close(self):
        self.closed = True


def _fake(tmp_path, records, **kw):
    """A lookup over one location 'file' whose reader is ``FakeReader(records)``."""
    path = tmp_path / "fake.mmdb"
    path.write_bytes(b"x")
    readers = []

    def opener(p):
        readers.append(FakeReader(records))
        return readers[-1]

    return GeoLookup(GeoSettings(city_db=str(path)), opener=opener, **kw), readers


# ---- the two database shapes -----------------------------------------------------------------

def test_geolite2_shape(tmp_path):
    geo = _lookup(tmp_path)
    assert geo.enabled and geo.status.startswith("on: location city.mmdb (built 2026-11-03)")
    g = geo("8.8.8.8")
    assert (g.country_code, g.country, g.region, g.city) == \
        ("US", "United States", "California", "Example City")
    assert (g.asn, g.as_org) == (64500, "Example Transit")
    assert g.location_built == g.network_built == "2026-11-03"
    assert g.rdns is None
    assert geo_short(g) == "Example City, United States · AS64500 Example Transit"
    # The registered country stands in for a range with no country.
    assert geo_short(geo("1.1.1.1")) == "Australia"


def test_dbip_lite_shape(tmp_path):
    geo = _lookup(tmp_path, city=DBIP_CITY)
    g = geo("8.8.8.8")
    assert (g.country_code, g.country, g.region, g.city) == \
        ("US", "United States", "California", "Example City")
    assert geo_short(geo(V6)) == "Frankfurt am Main, Germany · AS64501 Example Cloud"
    assert geo("8.8.4.4") is None          # in no range: nothing known


def test_ipv6_networks_and_mapped_addresses(tmp_path):
    geo = _lookup(tmp_path)
    assert geo(V6).country_code == "DE"
    # A campaign's source is an IPv6 /64; its network address is looked up.
    assert geo("2001:4860:4860:1::/64").country_code == "DE"
    assert geo("::ffff:8.8.8.8").country_code == "US"
    assert geo("8.8.8.8/32").country_code == "US"
    # Wider than /24 or /48 has no single place.
    assert geo("8.8.8.8/16") is None and geo("2001:4860::/32") is None
    for junk in ("", "not an address", "8.8.8.8.8", "x" * 500, None, 42, ["8.8.8.8"]):
        assert geo(junk) is None


def test_only_one_database_is_enough(tmp_path):
    g = _lookup(tmp_path, city=None)("8.8.8.8")
    assert (g.asn, g.country) == (64500, "")
    assert geo_short(g) == "AS64500 Example Transit"
    g = _lookup(tmp_path, asn=None)("8.8.8.8")
    assert g.asn is None and geo_short(g) == "Example City, United States"


# ---- non-global addresses -----------------------------------------------------------------------

@pytest.mark.parametrize("address,label", [
    ("10.1.2.3", "private address"), ("192.168.0.1", "private address"),
    ("fd00::1", "private address"), ("127.0.0.1", "loopback address"),
    ("::1", "loopback address"), ("169.254.1.1", "link-local address"),
    ("fe80::1", "link-local address"), ("100.64.0.1", "shared address (CGNAT)"),
    ("203.0.113.7", "documentation address"), ("2001:db8::1", "documentation address"),
    ("224.0.0.1", "multicast address"), ("0.0.0.0", "unspecified address"),
    ("240.0.0.1", "reserved address"), ("::ffff:10.0.0.1", "private address"),
])
def test_non_global_addresses_are_labelled_without_a_lookup(tmp_path, address, label):
    geo, readers = _fake(tmp_path, {address: {"country": {"iso_code": "US"}}})
    assert geo(address) == GeoInfo(note=label)
    assert readers[0].calls == 0
    assert non_global_label(parse_target(address)) == label


def test_global_addresses_have_no_label():
    for address in ("8.8.8.8", "1.1.1.1", V6):
        assert non_global_label(parse_target(address)) is None


# ---- off states: never raise, one log line -------------------------------------------------------

def test_no_section_or_no_paths_is_off(caplog):
    caplog.set_level(logging.INFO, logger="agents.enrich")
    geo = enrich.from_config(configparser.ConfigParser())
    assert not geo.enabled and geo("8.8.8.8") is None
    assert [r.getMessage() for r in caplog.records] == \
        ["IP lookup: off: no database path set in [geoip]"]


def test_missing_package_is_off(tmp_path, monkeypatch, caplog):
    real_import = builtins.__import__

    def no_maxminddb(name, *args, **kwargs):
        if name == "maxminddb":
            raise ImportError("no module")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_maxminddb)
    caplog.set_level(logging.INFO, logger="agents.enrich")
    path = tmp_path / "city.mmdb"
    path.write_bytes(b"x")
    geo = GeoLookup(GeoSettings(city_db=str(path)))
    assert not geo.enabled and geo("8.8.8.8") is None
    assert geo.status == "off: the maxminddb package is not installed"
    assert "IP lookup: off: the maxminddb package is not installed" in caplog.text


def test_missing_or_garbage_files_are_off(tmp_path):
    _maxminddb()
    garbage = tmp_path / "garbage.mmdb"
    garbage.write_bytes(b"\x00not a database" * 50)
    geo = GeoLookup(GeoSettings(city_db=str(tmp_path / "absent.mmdb"), asn_db=str(garbage)))
    assert not geo.enabled
    assert "absent.mmdb missing or not readable" in geo.status
    assert "garbage.mmdb cannot be opened" in geo.status
    assert geo("8.8.8.8") is None


def test_a_reader_that_raises_answers_nothing(tmp_path):
    class Exploding(FakeReader):
        def get(self, ip):
            raise RuntimeError("corrupt")

        def metadata(self):
            raise RuntimeError("no metadata")

    path = tmp_path / "fake.mmdb"
    path.write_bytes(b"x")
    geo = GeoLookup(GeoSettings(city_db=str(path)), opener=lambda p: Exploding({}))
    assert geo.enabled and geo("8.8.8.8") is None
    assert geo.status == "on: location fake.mmdb"      # no build date without metadata


# ---- positions for the map -------------------------------------------------------------------

def test_point_is_rounded_to_one_decimal_in_both_shapes(tmp_path):
    geo = _lookup(tmp_path)
    assert geo.point("8.8.8.8") == (37.8, -97.8)
    assert geo.point(V6) is None                 # a range without a location
    assert geo.point("8.8.4.4") is None          # in no range
    (tmp_path / "dbip").mkdir()
    assert _lookup(tmp_path / "dbip", city=DBIP_CITY).point("8.8.8.8") == (37.8, -97.8)


@pytest.mark.parametrize("address", ["10.0.0.5", "127.0.0.1", "192.0.2.10", "198.51.100.7",
                                     "not an address", "", None, 7])
def test_point_is_none_for_non_global_or_bad_values(tmp_path, address):
    geo, readers = _fake(tmp_path, {"10.0.0.5": {"location": {"latitude": 1, "longitude": 2}}})
    assert geo.point(address) is None
    assert readers[0].calls == 0                 # no lookup for a non-global address


@pytest.mark.parametrize("location", [
    {"latitude": 91, "longitude": 0}, {"latitude": 0, "longitude": -181},
    {"latitude": float("nan"), "longitude": 0}, {"latitude": True, "longitude": 0},
    {"latitude": "1", "longitude": "2"}, {"longitude": 2}, "x", None])
def test_point_refuses_malformed_locations(tmp_path, location):
    geo, _ = _fake(tmp_path, {"8.8.8.8": {"location": location}})
    assert geo.point("8.8.8.8") is None


def test_point_without_a_location_database_or_with_a_failing_reader(tmp_path):
    assert GeoLookup(GeoSettings()).point("8.8.8.8") is None
    asn_only = _lookup(tmp_path, city=None)
    assert asn_only.point("8.8.8.8") is None

    class Exploding(FakeReader):
        def get(self, ip):
            raise RuntimeError("corrupt")

    path = tmp_path / "x.mmdb"
    path.write_bytes(b"x")
    geo = GeoLookup(GeoSettings(city_db=str(path)), opener=lambda p: Exploding({}))
    assert geo.point("8.8.8.8") is None


def test_points_are_cached_and_bounded(tmp_path):
    geo, readers = _fake(tmp_path, {"8.8.8.8": {"location": {"latitude": 1.26,
                                                             "longitude": 2.24}}},
                         cache_size=2)
    for _ in range(3):
        assert geo.point("8.8.8.8") == (1.3, 2.2)
    assert readers[0].calls == 1
    geo.point("8.8.4.4")
    geo.point("9.9.9.9")
    assert len(geo._points) == 2


def test_config_paths_and_attribution(tmp_path, caplog):
    cp = configparser.ConfigParser()
    cp.read_string("[geoip]\ncity_db = relative/city.mmdb\n")
    caplog.set_level(logging.INFO, logger="agents.enrich")
    assert not enrich.from_config(cp).enabled
    assert "[geoip] city_db must be an absolute path" in caplog.text
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_dict({"geoip": {"city_db": str(tmp_path / "c.mmdb"),
                            "attribution": "IP Geolocation by DB-IP\x1b[31m‮ " + "x" * 400}})
    s = GeoSettings.from_config(cp)
    assert s.attribution.startswith("IP Geolocation by DB-IP")
    assert len(s.attribution) <= enrich.ATTRIBUTION_MAX
    assert all(c.isprintable() for c in s.attribution)


# ---- database text is data --------------------------------------------------------------------

HOSTILE_RECORD = {
    "country": {"iso_code": "us", "names": {"en": "Evil\x1b[31mland‮\n" + "N" * 500}},
    "city": {"names": {"en": "<script>alert(1)</script>\x00"}},
    "subdivisions": [{"names": {"en": 7}}, "not a dict"],
    "autonomous_system_number": 2 ** 40,
    "autonomous_system_organization": "Owner​\x07" + "O" * 500,
}


def test_hostile_database_text_is_cleaned_and_clipped(tmp_path):
    geo, _ = _fake(tmp_path, {"8.8.8.8": HOSTILE_RECORD})
    g = geo("8.8.8.8")
    assert g.country_code == ""                         # not two capital letters
    # Control characters go (the escape byte of a terminal sequence becomes a space).
    assert g.country.startswith("Evil [31mland N") and len(g.country) == 64
    assert g.city == "<script>alert(1)</script>"        # text; the console makes text nodes
    assert g.region == ""
    for value in (g.country, g.city):
        assert all(c.isprintable() for c in value)


def test_hostile_network_records(tmp_path):
    asn_path = tmp_path / "asn.mmdb"
    asn_path.write_bytes(b"x")
    cases = {"8.8.8.8": HOSTILE_RECORD,
             "8.8.4.4": {"autonomous_system_number": "AS64502",
                         "autonomous_system_organization": ["not", "a", "string"]},
             "1.1.1.1": {"autonomous_system_number": True}}
    geo = GeoLookup(GeoSettings(asn_db=str(asn_path)), opener=lambda p: FakeReader(cases))
    g = geo("8.8.8.8")
    assert g.asn is None and g.as_org.startswith("Owner") and len(g.as_org) == 96
    assert all(c.isprintable() for c in g.as_org)
    assert geo("8.8.4.4").asn == 64502 and geo("8.8.4.4").as_org == ""
    assert geo("1.1.1.1") is None


@pytest.mark.parametrize("record", [None, [], "text", 5, {"country": "US"},
                                    {"country": {"names": "x"}}, {"subdivisions": {}}])
def test_malformed_records_answer_nothing(tmp_path, record):
    geo, _ = _fake(tmp_path, {"8.8.8.8": record})
    assert geo("8.8.8.8") is None


# ---- readers, cache, reload ---------------------------------------------------------------------

def test_answers_are_cached_and_bounded(tmp_path):
    geo, readers = _fake(tmp_path, {"8.8.8.8": GEOLITE_CITY["8.8.8.8/32"]}, cache_size=2)
    for _ in range(200):
        assert geo("8.8.8.8").country_code == "US"
    assert readers[0].calls == 1
    geo("8.8.4.4"), geo("1.1.1.1"), geo("8.8.8.8")    # 8.8.8.8 was pushed out
    assert readers[0].calls == 4 and len(geo._cache) == 2


def test_a_replaced_file_is_picked_up_without_a_restart(tmp_path):
    _maxminddb()
    clock = [0.0]
    city = write_mmdb(tmp_path / "city.mmdb", GEOLITE_CITY)
    geo = GeoLookup(GeoSettings(city_db=str(city)), clock=lambda: clock[0], recheck_seconds=60)
    assert geo("8.8.8.8").country == "United States"
    newer = write_mmdb(tmp_path / "city.new", {"8.8.8.8/32": {
        "country": {"iso_code": "CA", "names": {"en": "Canada"}}}}, build_epoch=BUILT + 86400)
    os.replace(newer, city)
    clock[0] = 30.0
    assert geo("8.8.8.8").country == "United States"      # not checked yet
    clock[0] = 61.0
    assert geo("8.8.8.8").country == "Canada"
    assert "(built 2026-11-04)" in geo.status
    # A file that goes away keeps the reader already open.
    os.remove(city)
    clock[0] = 200.0
    assert geo("8.8.8.8").country == "Canada"


def test_close_releases_readers(tmp_path):
    geo, readers = _fake(tmp_path, {})
    geo.close()
    assert readers[0].closed and not geo.enabled and geo("8.8.8.8") is None


# ---- on the record -------------------------------------------------------------------------------

PLACE = GeoInfo(country_code="DE", country="Germany", city="Frankfurt", asn=64500,
                as_org="Example Cloud", location_built="2026-11-03")
LATER = GeoInfo(country_code="FR", country="France", city="Paris")


def _toll_fraud(ip="198.51.100.7"):
    return [trap_event("sip", "invite", ip, f"s{i}", minutes=i * 0.1, client="examplesip",
                       data={"dialed": "0015550100", "registered": False}) for i in range(3)]


def test_triage_stores_the_place_on_the_record(tmp_path):
    log = write_log(tmp_path / "events.jsonl", _toll_fraud())
    asked = []

    def geo(address):
        asked.append(address)
        return PLACE

    result = run_triage(log, tmp_path / "reports", None, now=NOW, geo=geo)
    assert result["written"] and asked == ["198.51.100.7"]
    raw = json.loads(next((tmp_path / "reports" / "campaigns").glob("*.json")).read_text())
    assert raw["src_geo"] == {"note": "", "country_code": "DE", "country": "Germany",
                              "region": "", "city": "Frankfurt", "asn": 64500,
                              "as_org": "Example Cloud", "location_built": "2026-11-03",
                              "network_built": ""}           # no rdns until something sets it
    record = TriageRecord.model_validate(raw)
    assert record_facts(record)["who"][0] == \
        "198.51.100.7 · Frankfurt, Germany · AS64500 Example Cloud"


def test_without_a_lookup_the_record_file_is_as_before(tmp_path):
    log = write_log(tmp_path / "events.jsonl", _toll_fraud())
    run_triage(log, tmp_path / "a", None, now=NOW)
    run_triage(log, tmp_path / "b", None, now=NOW, geo=lambda a: None)
    files = [next((tmp_path / d / "campaigns").glob("*.json")).read_text() for d in "ab"]
    assert files[0] == files[1] and "src_geo" not in files[0]


def test_a_stored_place_is_kept_and_the_aggregate_is_not_looked_up():
    stored = TriageRecord(kind="session", id="s1", protocol="ssh", src_ip="198.51.100.7",
                          intent="RECONNAISSANCE", stage="DISCOVERY", skill="AUTOMATED",
                          judgement="BENIGN", narrative="x", src_geo=PLACE)
    assert with_geo(stored, lambda a: LATER).src_geo == PLACE
    agg = stored.model_copy(update={"src_ip": "unverified", "src_geo": None})
    assert with_geo(agg, lambda a: pytest.fail("looked up")).src_geo is None

    def boom(address):
        raise RuntimeError("x")

    assert with_geo(stored.model_copy(update={"src_geo": None}), boom).src_geo is None


def _structured(**kw):
    out = dict(kind="campaign", id="c1", protocol="sip", src_ip="198.51.100.7",
               first_seen=f"{DAY}T12:00:00+00:00", intent="TOLL_FRAUD", stage="IMPACT",
               skill="AUTOMATED", judgement="MALICIOUS", narrative="A paragraph.",
               headline="Toll fraud", actions=["Dialed out."], clients=["examplesip"])
    out.update(kw)
    return TriageRecord(**out)


def test_digest_who_line_carries_the_short_form(tmp_path):
    reports = tmp_path / "reports"
    write_record(_structured(src_geo=PLACE), reports)
    write_record(_structured(id="old", src_ip="198.51.100.9"), reports)
    text = digest(reports, day=DAY, dry_run=True, geo=lambda a: LATER)
    assert ('   - Who: `198.51.100.7 · Frankfurt, Germany · AS64500 Example Cloud`, '
            '`client "examplesip"`') in text
    # An old record gets a place looked up now.
    assert "   - Who: `198.51.100.9 · Paris, France`" in text
    # Without a lookup the digest is as before.
    plain = digest(reports, day=DAY, dry_run=True)
    assert "   - Who: `198.51.100.9`, " in plain


def test_digest_escapes_database_text(tmp_path):
    reports = tmp_path / "reports"
    evil = GeoInfo(city="`|**x**|<b>", country="Land")
    write_record(_structured(src_geo=evil), reports)
    text = digest(reports, day=DAY, dry_run=True)
    assert "   - Who: `198.51.100.7 · '\\|**x**\\|<b>, Land`" in text


# ---- the console ---------------------------------------------------------------------------------

PLACES = {
    "198.51.100.7": GeoInfo(country_code="DE", country="Germany", city="Frankfurt", asn=64500,
                            as_org="Example Cloud"),
    "198.51.100.8": GeoInfo(country_code="NL", country="Netherlands", asn=64501,
                            as_org="Example Hosting"),
    "198.51.100.21": GeoInfo(country_code="DE", country="Germany"),
}


@pytest.fixture
def tree(tmp_path):
    return ui_fixture.build_tree(tmp_path)


def _api(tree, geo=PLACES.get):
    return Api(tree.api_paths(), cache_seconds=0, geo=geo)


def _ok(api, path, **query):
    status, body = api.get(path, query)
    assert status == 200, (path, body)
    return body


def _keys(value, name="geo"):
    """Every occurrence of key ``name`` anywhere in ``value``."""
    if isinstance(value, dict):
        return [v for k, v in value.items() if k == name] + \
            [x for v in value.values() for x in _keys(v, name)]
    if isinstance(value, list):
        return [x for v in value for x in _keys(v, name)]
    return []


def test_with_the_lookup_off_answers_have_no_place(tree):
    api = Api(tree.api_paths(), cache_seconds=0)
    for path, query in (("/api/overview", {"window": "7d"}), ("/api/records", {}),
                        ("/api/queue", {"all": "1"}), ("/api/blocklist", {}),
                        ("/api/decoy", {}), ("/api/activity", {}),
                        (f"/api/records/{tree.ids['session_a']}", {})):
        body = _ok(api, path, **query)
        assert _keys(body) == [] and _keys(body, "geo_stored") == [], path
        assert "·" not in json.dumps(body, ensure_ascii=False), path


def test_record_page_old_record_is_looked_up_now(tree):
    body = _ok(_api(tree), f"/api/records/{tree.ids['session_a']}")
    assert body["geo"]["short"] == "Frankfurt, Germany · AS64500 Example Cloud"
    assert body["geo"]["country_code"] == "DE" and body["geo_stored"] is False
    assert body["layout"]["who"][0] == "198.51.100.7 · Frankfurt, Germany · AS64500 Example Cloud"
    assert body["record"]["src_geo"]["city"] == "Frankfurt"


def test_record_page_stored_place_wins(tree):
    rid = tree.ids["session_a"]
    path = tree.reports / "sessions" / f"{rid}.json"
    record = TriageRecord.model_validate_json(path.read_text())
    write_record(record.model_copy(update={"src_geo": LATER}), tree.reports)
    body = _ok(_api(tree), f"/api/records/{rid}")
    assert body["geo"]["short"] == "Paris, France" and body["geo_stored"] is True
    # Stored without a lookup configured: still shown.
    body = _ok(Api(tree.api_paths(), cache_seconds=0), f"/api/records/{rid}")
    assert body["geo"]["short"] == "Paris, France" and body["geo_stored"] is True


def test_records_list_overview_and_country_filter(tree):
    api = _api(tree)
    page = _ok(api, "/api/records")
    by_ip = {i["src_ip"]: i.get("geo") for i in page["items"]}
    assert by_ip["198.51.100.8"]["short"] == "Netherlands · AS64501 Example Hosting"
    assert by_ip["198.51.100.20"] is None
    assert page["geo"] is True
    de = _ok(api, "/api/records", country="de")
    assert {i["src_ip"] for i in de["items"]} == {"198.51.100.7", "198.51.100.21"}
    assert _ok(api, "/api/records", country="FR")["items"] == []
    for bad in ("DEU", "1A", "D", "<b"):
        assert api.get("/api/records", {"country": bad})[0] == 400
    top = {s["src_ip"]: s.get("geo") for s in _ok(api, "/api/overview", window="7d")["top_sources"]}
    assert top["198.51.100.21"]["short"] == "Germany" and top["198.51.100.20"] is None


def test_queue_card_place_never_enters_the_view_hash(tree):
    plain = {c["id"]: c for c in _ok(Api(tree.api_paths(), cache_seconds=0), "/api/queue",
                                     all="1")["items"]}
    placed = {c["id"]: c for c in _ok(_api(tree), "/api/queue", all="1")["items"]}
    pending = tree.ids["pending"]
    assert placed[pending]["geo"]["short"] == "Germany"
    assert placed[pending]["view_hash"] == plain[pending]["view_hash"] is not None
    # A database swap changes what is shown beside the card, not what a decision checks.
    swapped = _ok(_api(tree, geo=lambda a: LATER), "/api/queue")["items"][0]
    assert swapped["geo"]["short"] == "Paris, France"
    assert swapped["view_hash"] == plain[pending]["view_hash"]


def test_blocklist_decoy_and_activity_show_the_place(tree):
    api = _api(tree)
    items = {i["target"]: i for i in _ok(api, "/api/blocklist")["items"]}
    assert items["198.51.100.8"]["geo"]["country_code"] == "NL"
    decoy = _ok(api, "/api/decoy")["source_state"]["items"]
    assert decoy[0]["key"] == "198.51.100.7" and decoy[0]["geo"]["country"] == "Germany"
    rows = _ok(api, "/api/activity")["items"]
    assert any(r.get("geo", {}).get("country") == "Netherlands" for r in rows
               if r["src"] == "198.51.100.8")
    session = _ok(api, f"/api/activity/session/{tree.ids['session_b']}")
    assert session["geo"]["country_code"] == "NL"


def test_hostile_place_text_passes_the_response_boundary(tree):
    evil = GeoInfo(city="<img src=x onerror=1>", country="Land", as_org="Org")
    body = _ok(_api(tree, geo=lambda a: evil), f"/api/records/{tree.ids['session_a']}")
    assert body["geo"]["short"] == "<img src=x onerror=1>, Land · Org"   # text, never markup


def test_a_lookup_that_raises_does_not_break_the_console(tree):
    def boom(address):
        raise RuntimeError("database gone")

    api = _api(tree, geo=boom)
    for path in ("/api/records", f"/api/records/{tree.ids['session_a']}"):
        assert api.get(path, {})[0] == 200
