"""InternetDB answers delivered through the object store (agents/internetdb_delivered.py).

No network: the object store is a fake client, the clock is injected, and every address is
from a documentation range treated as public.
"""

from __future__ import annotations

import configparser
import datetime
import ipaddress
import json
import os

import pytest

from agents import internetdb as idb
from agents import internetdb_delivered as dl
from agents import objectstore
from agents.addresses import public_for_tests
from agents.triage import ShodanInfo, TriageRecord, load_records, run_triage, write_record

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
A, B, C, D = "198.51.100.7", "198.51.100.8", "198.51.100.9", "198.51.100.10"
V6 = "2001:db8::5"
BUCKET = "example-honeypot-events"
WANTED_KEY = "events/internetdb/wanted.json"
ANSWERS_KEY = "internetdb/answers.json"


@pytest.fixture(autouse=True)
def _public():
    with public_for_tests("198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"):
        yield


def rec(ip, judgement="MALICIOUS", rid=None, seen=NOW, **kw):
    return TriageRecord(kind="session", id=rid or f"s-{ip}-{judgement}", protocol="ssh",
                        src_ip=ip, last_seen=seen.isoformat(), intent="RECONNAISSANCE",
                        stage="DISCOVERY", skill="AUTOMATED", judgement=judgement,
                        narrative="x", **kw)


def cfg(internetdb=None, exchange=None) -> configparser.ConfigParser:
    cp = configparser.ConfigParser()
    data = {}
    if internetdb is not None:
        data[idb.SECTION] = internetdb
    if exchange is not None:
        data[dl.SECTION] = exchange
    cp.read_dict(data)
    return cp


DELIVERED = {"enabled": "true", "mode": "delivered"}
EXCHANGE = {"enabled": "true", "kind": "s3", "bucket": BUCKET, "wanted_key": WANTED_KEY,
            "answers_key": ANSWERS_KEY, "region": "us-east-1", "bucket_owner": "123456789012"}
SETTINGS = idb.InternetDbSettings.from_config(cfg(DELIVERED))
EXCH = dl.ExchangeSettings.from_config(cfg(DELIVERED, EXCHANGE))


def found(ip, at="2026-11-20T11:00:00Z", **kw):
    doc = {"ip": ip, "checked_at": at, "status": "found", "ports": [22, 80],
           "hostnames": ["a.example.net"], "tags": ["vpn"],
           "cpes": ["cpe:/a:openbsd:openssh:7.4"], "vulns": ["CVE-2017-15906"]}
    doc.update(kw)
    return doc


def answers(*items, **top) -> bytes:
    doc = {"version": 1, "generated_at": "2026-11-20T11:05:00Z", "answers": list(items)}
    doc.update(top)
    return json.dumps(doc).encode()


class Body:
    def __init__(self, data):
        self.data = data

    def read(self, amt=None):
        return self.data[:amt]

    def close(self):
        pass


class FakeS3:
    """One client for both operations; records every call."""

    def __init__(self, objects=None, get_exc=None, put_exc=None):
        self.objects = dict(objects or {})
        self.puts: list[dict] = []
        self.gets: list[dict] = []
        self.get_exc, self.put_exc = get_exc, put_exc

    def put_object(self, **params):
        if self.put_exc is not None:
            raise self.put_exc
        self.puts.append(params)
        self.objects[params["Key"]] = params["Body"]

    def get_object(self, **params):
        if self.get_exc is not None:
            raise self.get_exc
        self.gets.append(params)
        return {"Body": Body(self.objects[params["Key"]]),
                "ContentLength": len(self.objects[params["Key"]])}

    def __getattr__(self, name):
        raise AssertionError(f"S3 client used for {name}")


class NoSuchKey(Exception):
    response = {"Error": {"Code": "NoSuchKey", "Message": "x"}}


def write_wanted_file(path, addresses):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(dl.wanted_document(addresses, NOW))


def exchange(tmp_path, s3, now=NOW, networks=(), settings=SETTINGS, exch=EXCH, **kw):
    return dl.run_exchange(exch, settings, tmp_path / "blocklist" / dl.WANTED_FILE,
                           tmp_path / "answers" / "internetdb.json", tmp_path / "state",
                           list(networks), client_factory=lambda target: s3, now=now, **kw)


def held(tmp_path):
    return idb.load_state(tmp_path / "answers" / "internetdb.json")["entries"]


# ---- configuration -------------------------------------------------------------------------

def test_mode_defaults_to_direct_and_direct_is_unchanged():
    on = idb.InternetDbSettings.from_config(cfg({"enabled": "true"}))
    assert on.mode == "direct" and not on.delivered
    assert on == idb.InternetDbSettings(enabled=True)
    assert idb.InternetDbSettings.from_config(cfg({"enabled": "false", "mode": "delivered"})) \
        == idb.InternetDbSettings()


def test_delivered_settings_parse_and_are_bounded():
    s = idb.InternetDbSettings.from_config(cfg({**DELIVERED, "max_wanted": "50",
                                                "max_age_days": "10",
                                                "wanted_file": "/blocklist/w.json",
                                                "answers_file": "/internetdb/internetdb.json"}))
    assert s.delivered and s.max_wanted == 50 and s.max_age_days == 10.0
    assert str(s.answers_path("/state")) == "/internetdb/internetdb.json"
    assert str(dl.wanted_path(s, "/x")) == "/blocklist/w.json"
    assert str(dl.wanted_path(SETTINGS, "/x")) == "/x/internetdb_wanted.json"
    assert SETTINGS.max_wanted == 500
    for bad in ({"mode": "both"}, {"max_wanted": "501"}, {"max_wanted": "0"},
                {"wanted_file": "relative.json"}, {"answers_file": "x/y.json"},
                {"max_age_days": "91"}):
        with pytest.raises(idb.ConfigError):
            idb.InternetDbSettings.from_config(cfg({**DELIVERED, **bad}))


def test_answers_file_is_ignored_in_direct_mode():
    s = idb.InternetDbSettings.from_config(cfg({"enabled": "true", "answers_file": "/x/y.json"}))
    assert s.answers_path("/state") == idb.state_path("/state")


def test_exchange_settings():
    assert dl.ExchangeSettings.from_config(cfg()).enabled is False
    assert EXCH.enabled and EXCH.wanted.key == WANTED_KEY and EXCH.answers.key == ANSWERS_KEY
    assert EXCH.wanted.bucket_owner == "123456789012" and EXCH.max_entries == 1000
    with pytest.raises(dl.ConfigError, match="mode = delivered"):
        dl.ExchangeSettings.from_config(cfg({"enabled": "true"}, EXCHANGE))
    with pytest.raises(dl.ConfigError, match="mode = delivered"):
        dl.ExchangeSettings.from_config(cfg(None, EXCHANGE))
    for bad in ({"kind": "https"}, {"answers_key": WANTED_KEY}, {"wanted_key": ""},
                {"answers_key": "../x.json"}, {"max_bytes": "10"}, {"max_entries": "6000"},
                {"interval_minutes": "0"}, {"bucket": "Not_A_Bucket"}):
        with pytest.raises(dl.ConfigError):
            dl.ExchangeSettings.from_config(cfg(DELIVERED, {**EXCHANGE, **bad}))


def test_reader_reads_the_answers_file_in_delivered_mode(tmp_path):
    path = tmp_path / "answers" / "internetdb.json"
    idb.save_state(path, {"day": "", "day_count": 0, "backoff_until": None,
                          "backoff_minutes": 0,
                          "entries": {A: {"checked_at": NOW,
                                          "info": ShodanInfo(looked_up="2026-11-20",
                                                             ports=[22])}}}, 100)
    reader = idb.reader_from_config(cfg({**DELIVERED, "answers_file": str(path)}), tmp_path / "s")
    assert reader.info(A).ports == [22]


def test_run_lookup_never_asks_in_delivered_mode(tmp_path):
    class Boom:
        def request(self, *a, **k):
            pytest.fail("network")

    out = idb.run_lookup(SETTINGS, [rec(A)], [], tmp_path, transport=Boom(), now=NOW)
    assert "delivered" in out["status"] and not (tmp_path / idb.STATE_FILE).exists()


# ---- the wanted list -----------------------------------------------------------------------

def test_wanted_list_selection_format_and_bound(tmp_path):
    path = tmp_path / "blocklist" / dl.WANTED_FILE
    records = [rec(A), rec(B, "BENIGN"), rec(C, "SUSPICIOUS"), rec(D, honeytokens=["k"]),
               rec("10.0.0.5"), rec("198.51.100.40")]
    never = [ipaddress.ip_network("198.51.100.40/32")]
    out = dl.write_wanted(SETTINGS, records, never, path, now=NOW)
    assert out == {"wanted": 3, "left_out": 0, "status": "written"}
    doc = json.loads(path.read_text())
    # Addresses only, plus a version and a time: nothing about what a source did.
    assert set(doc) == {"version", "generated_at", "addresses"}
    assert doc["version"] == 1 and doc["generated_at"] == "2026-11-20T12:00:00+00:00"
    assert doc["addresses"] == idb.select_addresses(records, never, NOW, 7)
    assert doc["addresses"][0] == D and set(doc["addresses"]) == {A, C, D}
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert dl.parse_wanted(path.read_bytes(), [])[0] == doc["addresses"]


def test_wanted_list_is_capped(tmp_path):
    many = [rec(f"203.0.113.{i}") for i in range(1, 120)]
    s = idb.InternetDbSettings.from_config(cfg({**DELIVERED, "max_wanted": "100"}))
    path = tmp_path / dl.WANTED_FILE
    out = dl.write_wanted(s, many, [], path, now=NOW)
    assert out["wanted"] == 100 and out["left_out"] == 19
    assert len(json.loads(path.read_text())["addresses"]) == 100


def test_wanted_list_is_written_atomically(tmp_path, monkeypatch):
    path = tmp_path / dl.WANTED_FILE
    dl.write_wanted(SETTINGS, [rec(A)], [], path, now=NOW)
    before = path.read_bytes()

    def broken(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(dl.os, "replace", broken)
    out = dl.write_wanted(SETTINGS, [rec(B)], [], path, now=NOW)
    assert "cannot write" in out["error"]
    assert path.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir()] == [dl.WANTED_FILE]   # no temp file left


def test_wanted_dry_run_writes_nothing(tmp_path):
    out = dl.write_wanted(SETTINGS, [rec(A)], [], tmp_path / "w.json", now=NOW, dry_run=True)
    assert out["status"] == "would write" and not (tmp_path / "w.json").exists()


@pytest.mark.parametrize("body", [
    b"not json", b"[]", b'{"version": 2, "generated_at": "2026-11-20T12:00:00Z", "addresses": []}',
    b'{"version": true, "generated_at": "2026-11-20T12:00:00Z", "addresses": []}',
    b'{"version": 1, "addresses": []}',
    b'{"version": 1, "generated_at": "2026-11-20T12:00:00Z", "addresses": {}}',
    b'{"version": 1, "generated_at": "2026-11-20T12:00:00Z", "addresses": ["10.0.0.1"]}',
    b'{"version": 1, "generated_at": "2026-11-20T12:00:00Z", "addresses": ["198.51.100.0/24"]}',
    b'{"version": 1, "generated_at": "2026-11-20T12:00:00Z", "addresses": [" 198.51.100.7"]}',
    b'{"version": 1, "generated_at": "2026-11-20T12:00:00Z", "addresses": [7]}',
    b'{"version": 1, "generated_at": "2026-11-20T12:00:00Z", "addresses": ["198.51.100.7", '
    b'"198.51.100.7"]}',
    json.dumps({"version": 1, "generated_at": "2026-11-20T12:00:00Z",
                "addresses": [f"203.0.113.{i % 250 + 1}" for i in range(501)]}).encode(),
    b" " * (dl.MAX_WANTED_BYTES + 1),
])
def test_a_bad_wanted_list_is_refused(body):
    with pytest.raises(dl.InvalidDocument):
        dl.parse_wanted(body, [])


def test_never_act_on_is_applied_again_before_the_list_leaves(tmp_path):
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A, B])
    s3 = FakeS3({ANSWERS_KEY: answers()})
    exchange(tmp_path, s3, networks=[ipaddress.ip_network(f"{B}/32")])
    [put] = s3.puts
    assert json.loads(put["Body"])["addresses"] == [A]


# ---- the exchange: the wanted list out -----------------------------------------------------

def test_exchange_puts_one_key_and_gets_one_key(tmp_path):
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A, B])
    s3 = FakeS3({ANSWERS_KEY: answers(found(A), found(B, status="not_found"))})
    out = exchange(tmp_path, s3)
    assert out["status"] == "done" and out["put"] == "sent" and out["accepted"] == 2
    [put] = s3.puts
    assert put["Bucket"] == BUCKET and put["Key"] == WANTED_KEY
    assert put["ExpectedBucketOwner"] == "123456789012"
    assert put["ContentType"] == "application/json"
    assert [g["Key"] for g in s3.gets] == [ANSWERS_KEY]
    assert s3.gets[0]["ExpectedBucketOwner"] == "123456789012"
    assert held(tmp_path)[A]["info"].ports == [22, 80]
    assert held(tmp_path)[B]["info"].found is False


def test_the_wanted_list_is_put_again_only_when_it_changes_or_daily(tmp_path):
    path = tmp_path / "blocklist" / dl.WANTED_FILE
    write_wanted_file(path, [A])
    s3 = FakeS3({ANSWERS_KEY: answers()})
    exchange(tmp_path, s3)
    # A new generated_at but the same addresses: not sent again.
    path.write_bytes(dl.wanted_document([A], NOW + datetime.timedelta(hours=1)))
    assert exchange(tmp_path, s3, now=NOW + datetime.timedelta(hours=1))["put"] == "unchanged"
    write_wanted_file(path, [A, B])
    assert exchange(tmp_path, s3, now=NOW + datetime.timedelta(hours=2))["put"] == "sent"
    assert exchange(tmp_path, s3, now=NOW + datetime.timedelta(hours=27))["put"] == "sent"
    assert len(s3.puts) == 3


def test_a_failed_put_is_recorded_and_retried(tmp_path):
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A])
    s3 = FakeS3({ANSWERS_KEY: answers()}, put_exc=RuntimeError("down"))
    out = exchange(tmp_path, s3)
    assert "PutObject failed: RuntimeError" in out["error"]
    events = (tmp_path / "state" / "ship_events.jsonl").read_text()
    assert "internetdb_exchange_failed" in events
    s3.put_exc = None
    assert exchange(tmp_path, s3, now=NOW + datetime.timedelta(minutes=1))["put"] == "sent"


def test_no_wanted_list_yet_still_fetches(tmp_path):
    s3 = FakeS3({ANSWERS_KEY: answers(found(A))})
    out = exchange(tmp_path, s3)
    assert out["wanted"] == "no wanted list yet" and s3.puts == []
    # Nothing asked for and nothing held: the answer is dropped.
    assert out["dropped"] == 1 and held(tmp_path) == {}


def test_a_tampered_wanted_file_is_not_sent(tmp_path):
    path = tmp_path / "blocklist" / dl.WANTED_FILE
    path.parent.mkdir(parents=True)
    path.write_text('{"version": 1, "generated_at": "2026-11-20T12:00:00Z", '
                    '"addresses": ["198.51.100.7"], "sessions": ["secret"]}')
    s3 = FakeS3({ANSWERS_KEY: answers()})
    exchange(tmp_path, s3)
    # Rebuilt from the checked addresses: an extra key never leaves.
    assert set(json.loads(s3.puts[0]["Body"])) == {"version", "generated_at", "addresses"}
    path.write_text('{"version": 1, "addresses": "everything"}')
    out = exchange(tmp_path, s3, now=NOW + datetime.timedelta(hours=1))
    assert "wanted list is refused" in out["error"] and len(s3.puts) == 1


def _not_a_file(path, kind):
    """Put a FIFO, a symlink to a valid copy, or a directory at ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "symlink":
        real = path.parent / "real.json"
        real.write_bytes(dl.wanted_document([A], NOW))
        path.symlink_to(real)
    else:
        path.mkdir()


@pytest.mark.parametrize("kind", ["fifo", "symlink", "directory"])
def test_a_wanted_list_that_is_not_a_regular_file_is_unreadable_and_not_sent(tmp_path, kind):
    _not_a_file(tmp_path / "blocklist" / dl.WANTED_FILE, kind)
    s3 = FakeS3({ANSWERS_KEY: answers(found(A))})
    out = exchange(tmp_path, s3)    # a FIFO would block here with a plain open()
    assert out["error"].startswith("cannot read the wanted list (")
    assert s3.puts == [] and "wanted" not in out
    # The rest of the exchange runs as it does for any unreadable list.
    assert out["get"] == "fetched"


def test_an_oversize_wanted_list_is_refused_as_before(tmp_path):
    path = tmp_path / "blocklist" / dl.WANTED_FILE
    path.parent.mkdir(parents=True)
    path.write_bytes(b" " * (dl.MAX_WANTED_BYTES + 1))
    s3 = FakeS3({ANSWERS_KEY: answers()})
    out = exchange(tmp_path, s3)
    assert f"refused: larger than {dl.MAX_WANTED_BYTES} bytes" in out["error"]
    assert s3.puts == []


# ---- the exchange: the answers in ----------------------------------------------------------

def test_answers_for_addresses_never_asked_for_are_dropped(tmp_path):
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A])
    s3 = FakeS3({ANSWERS_KEY: answers(found(A), found(B), found("203.0.113.9"))})
    out = exchange(tmp_path, s3)
    assert out["accepted"] == 1 and out["dropped"] == 2
    assert set(held(tmp_path)) == {A}


def test_an_address_already_held_may_be_refreshed(tmp_path):
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A])
    s3 = FakeS3({ANSWERS_KEY: answers(found(A, at="2026-11-19T10:00:00Z"))})
    exchange(tmp_path, s3)
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [])
    s3.objects[ANSWERS_KEY] = answers(found(A, at="2026-11-20T10:00:00Z", ports=[443]))
    out = exchange(tmp_path, s3, now=NOW + datetime.timedelta(hours=1))
    assert out["accepted"] == 1 and held(tmp_path)[A]["info"].ports == [443]
    # An older or equal answer never replaces a newer one.
    s3.objects[ANSWERS_KEY] = answers(found(A, at="2026-11-20T09:00:00Z", ports=[25]))
    out = exchange(tmp_path, s3, now=NOW + datetime.timedelta(hours=2))
    assert out["not_newer"] == 1 and held(tmp_path)[A]["info"].ports == [443]


@pytest.mark.parametrize("bad", [
    "not an object",
    {"ip": A, "checked_at": "2026-11-20T11:00:00Z", "status": "maybe"},
    {"ip": A, "checked_at": "2026-11-20T11:00:00Z"},
    {"ip": A, "checked_at": "yesterday", "status": "not_found"},
    {"ip": A, "checked_at": "2026-11-20T13:00:00Z", "status": "not_found"},   # an hour ahead
    {"ip": A, "checked_at": "2026-09-01T00:00:00Z", "status": "not_found"},   # stale
    {"ip": A, "checked_at": None, "status": "not_found"},
    {"ip": A, "checked_at": "2" * 41, "status": "not_found"},
    {"ip": f" {A}", "checked_at": "2026-11-20T11:00:00Z", "status": "not_found"},
    {"ip": "198.51.100.0/24", "checked_at": "2026-11-20T11:00:00Z", "status": "not_found"},
    {"ip": "10.0.0.1", "checked_at": "2026-11-20T11:00:00Z", "status": "not_found"},
    {"ip": 7, "checked_at": "2026-11-20T11:00:00Z", "status": "not_found"},
    {**found(A), "ip": "198.051.100.7"},
])
def test_bad_answers_are_dropped(tmp_path, bad):
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A])
    s3 = FakeS3({ANSWERS_KEY: answers(bad, found(C))})
    out = exchange(tmp_path, s3)
    assert out["status"] == "done" and out["accepted"] == 0 and out["dropped"] == 2
    assert held(tmp_path) == {}


def test_found_answers_get_exactly_the_direct_checks(tmp_path):
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A])
    hostile = found(A, ports=[22, 0, 70000, "80", True, 22],
                    hostnames=["ok.example.net", "<script>", "a" * 300, "EVIL.Example.NET."],
                    tags=["vpn", "x y"], cpes=["cpe:/a:x:y", "nope"],
                    vulns=["CVE-2020-1234", "cve-2020-1"], extra={"deep": [1]})
    s3 = FakeS3({ANSWERS_KEY: answers(hostile)})
    exchange(tmp_path, s3)
    info = held(tmp_path)[A]["info"]
    direct = idb.sanitize(json.dumps({k: hostile[k] for k in dl.ANSWER_FIELDS}).encode(), A,
                          "2026-11-20")
    assert info == direct
    assert info.ports == [22] and info.hostnames == ["ok.example.net", "evil.example.net"]
    assert info.tags == ["vpn"] and info.cpes == ["cpe:/a:x:y"] and info.vulns == ["CVE-2020-1234"]
    assert info.looked_up == "2026-11-20"


def test_a_found_answer_over_the_direct_cap_is_dropped(tmp_path):
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A])
    big = found(A, hostnames=["a.example.net"] * 6000)
    s3 = FakeS3({ANSWERS_KEY: answers(big)})
    out = exchange(tmp_path, s3)
    assert out["dropped"] == 1 and held(tmp_path) == {}


@pytest.mark.parametrize("body", [
    b"\xff\xfe", b"not json", b"[1]", b'{"version": 2, "answers": []}',
    b'{"version": true, "answers": []}', b'{"version": 1, "answers": {}}',
    b'{"version": 1}', b"[" * 100000 + b"]" * 100000,
])
def test_a_hostile_answers_object_is_refused_whole_and_logged_once(tmp_path, body, caplog):
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A])
    s3 = FakeS3({ANSWERS_KEY: answers(found(A, at="2026-11-20T10:00:00Z"))})
    exchange(tmp_path, s3)
    before = (tmp_path / "answers" / "internetdb.json").read_bytes()
    s3.objects[ANSWERS_KEY] = body
    out = exchange(tmp_path, s3, now=NOW + datetime.timedelta(minutes=20))
    assert "answers object is refused" in out["error"]
    assert (tmp_path / "answers" / "internetdb.json").read_bytes() == before
    caplog.clear()
    out = exchange(tmp_path, s3, now=NOW + datetime.timedelta(minutes=40))
    assert "refused" in out["error"]
    assert not [r for r in caplog.records if "refused" in r.getMessage()]


def test_too_many_answers_or_too_large_is_refused(tmp_path):
    small = dl.ExchangeSettings.from_config(cfg(DELIVERED, {**EXCHANGE, "max_entries": "2",
                                                            "max_bytes": "2048"}))
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A, B, C])
    s3 = FakeS3({ANSWERS_KEY: answers(found(A), found(B), found(C))})
    out = exchange(tmp_path, s3, exch=small)
    assert "more than 2 answers" in out["error"] or "larger than" in out["error"]
    s3.objects[ANSWERS_KEY] = answers(found(A), padding="x" * 3000)
    out = exchange(tmp_path, s3, exch=small, now=NOW + datetime.timedelta(hours=1))
    assert "larger than 2048 bytes" in out["error"]
    assert held(tmp_path) == {}


def test_the_answers_object_is_read_with_a_cap(tmp_path):
    seen = {}

    class Capped(FakeS3):
        def get_object(self, **params):
            out = super().get_object(**params)
            body = out["Body"]

            class Spy:
                def read(self, amt=None):
                    seen["amt"] = amt
                    return body.read(amt)

            out["Body"] = Spy()
            out.pop("ContentLength")
            return out

    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A])
    exchange(tmp_path, Capped({ANSWERS_KEY: answers(found(A))}))
    assert seen["amt"] == dl.DEFAULT_MAX_BYTES + 1


def test_the_fetch_waits_for_its_interval(tmp_path):
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A])
    s3 = FakeS3({ANSWERS_KEY: answers(found(A))})
    exchange(tmp_path, s3)
    assert exchange(tmp_path, s3, now=NOW + datetime.timedelta(minutes=5))["get"] == "not due"
    assert exchange(tmp_path, s3, now=NOW + datetime.timedelta(minutes=16))["get"] == "fetched"
    # A clock that went back is not a reason to stop fetching.
    assert exchange(tmp_path, s3, now=NOW - datetime.timedelta(days=1))["get"] == "fetched"
    assert len(s3.gets) == 3


def test_no_answers_object_yet_is_not_an_error(tmp_path):
    s3 = FakeS3(get_exc=NoSuchKey())
    out = exchange(tmp_path, s3)
    assert out["get"] == "no answers object yet" and "error" not in out


def test_a_failed_get_is_recorded(tmp_path):
    s3 = FakeS3(get_exc=RuntimeError("AccessDenied"))
    out = exchange(tmp_path, s3)
    assert out["error"] == "GetObject failed: RuntimeError"


def test_answers_inside_never_act_on_are_dropped_even_when_held(tmp_path):
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A])
    s3 = FakeS3({ANSWERS_KEY: answers(found(A, at="2026-11-20T10:00:00Z"))})
    exchange(tmp_path, s3)
    s3.objects[ANSWERS_KEY] = answers(found(A, at="2026-11-20T11:00:00Z", ports=[443]))
    out = exchange(tmp_path, s3, now=NOW + datetime.timedelta(hours=1),
                   networks=[ipaddress.ip_network("198.51.100.0/24")])
    assert out["dropped"] == 1 and held(tmp_path)[A]["info"].ports == [22, 80]


def test_ipv6_answers(tmp_path):
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [V6])
    s3 = FakeS3({ANSWERS_KEY: answers(found(V6), found("2001:DB8::5"),
                                      found("2001:db8:0::5"))})
    out = exchange(tmp_path, s3)
    # Only the canonical spelling is accepted.
    assert out["accepted"] == 1 and out["dropped"] == 2
    assert held(tmp_path)[V6]["info"].ports == [22, 80]


def test_the_local_answers_stay_bounded(tmp_path):
    s = idb.InternetDbSettings.from_config(cfg({**DELIVERED, "max_entries": "100"}))
    addrs = [f"203.0.113.{i}" for i in range(1, 151)]
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, addrs)
    items = [found(a, at=f"2026-11-20T10:{i % 60:02d}:00Z") for i, a in enumerate(addrs)]
    s3 = FakeS3({ANSWERS_KEY: answers(*items)})
    exchange(tmp_path, s3, settings=s)
    assert len(held(tmp_path)) == 100


def test_dry_run_moves_nothing(tmp_path):
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A])
    s3 = FakeS3({ANSWERS_KEY: answers(found(A))})
    out = exchange(tmp_path, s3, dry_run=True)
    assert out["put"] == "would put" and out["get"] == "would get"
    assert s3.puts == s3.gets == [] and not (tmp_path / "state").exists()


def test_the_exchange_uses_one_object_guard_per_operation(tmp_path, monkeypatch):
    built = []

    def factory(op):
        def make(target):
            built.append((op, target.key))
            return FakeS3({ANSWERS_KEY: answers()})
        return make

    monkeypatch.setattr(objectstore, "guarded_client_factory", factory)
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, [A])
    dl.run_exchange(EXCH, SETTINGS, tmp_path / "blocklist" / dl.WANTED_FILE,
                    tmp_path / "a.json", tmp_path / "state", [], now=NOW)
    assert built == [("PutObject", WANTED_KEY), ("GetObject", ANSWERS_KEY)]


def test_the_module_never_asks_internetdb():
    from pathlib import Path

    source = Path(dl.__file__).read_text()
    for needle in ("UrlTransport", "_request", "internetdb.shodan.io", "urllib", "socket"):
        assert needle not in source, needle


# ---- the reader path and the stored record -------------------------------------------------

def test_triage_and_the_record_work_from_delivered_answers(tmp_path):
    from test_enrich import NOW as ENRICH_NOW, _toll_fraud, write_log

    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, ["198.51.100.7"])
    s3 = FakeS3({ANSWERS_KEY: answers(found("198.51.100.7", ports=[5060]))})
    exchange(tmp_path, s3)
    cp = cfg({**DELIVERED, "answers_file": str(tmp_path / "answers" / "internetdb.json")})
    reader = idb.reader_from_config(cp, tmp_path / "unused-state")
    log = write_log(tmp_path / "events.jsonl", _toll_fraud())
    run_triage(log, tmp_path / "reports", None, now=ENRICH_NOW, shodan=reader)
    [record] = [r for r in load_records(tmp_path / "reports") if r.src_shodan is not None]
    assert record.src_shodan.ports == [5060] and record.src_shodan.looked_up == "2026-11-20"


def test_the_console_shows_delivered_answers(tmp_path):
    import ui_fixture
    from agents.ui.api import Api

    tree = ui_fixture.build_tree(tmp_path / "tree")
    write_wanted_file(tmp_path / "blocklist" / dl.WANTED_FILE, ["198.51.100.7"])
    exchange(tmp_path, FakeS3({ANSWERS_KEY: answers(found("198.51.100.7"))}))
    cp = cfg({**DELIVERED, "answers_file": str(tmp_path / "answers" / "internetdb.json")})
    api = Api(tree.api_paths(), cache_seconds=0, shodan=idb.reader_from_config(cp, tmp_path))
    status, body = api.get(f"/api/records/{tree.ids['session_a']}", {})
    assert status == 200 and body["shodan"]["looked_up"] == "2026-11-20"


# ---- the CLI -------------------------------------------------------------------------------

def _cli(tmp_path, command, text):
    from agents.__main__ import run as cli_run

    cfg_path = tmp_path / "config.ini"
    cfg_path.write_text(text)
    return cli_run([command, "--config", str(cfg_path), "--reports-dir",
                    str(tmp_path / "reports"), "--state-dir", str(tmp_path / "state"),
                    "--log", str(tmp_path / "x.log"), "--data-dir", str(tmp_path / "data"),
                    "--detections-dir", str(tmp_path / "detections"),
                    "--no-llm"])


def test_cli_run_all_writes_the_wanted_list_and_never_asks(tmp_path, monkeypatch):
    monkeypatch.setattr(idb, "_request", lambda *a: pytest.fail("network"))
    write_record(rec(A, seen=datetime.datetime.now(UTC)), tmp_path / "reports")
    out = _cli(tmp_path, "run-all", f"[{idb.SECTION}]\nenabled = true\nmode = delivered\n"
                                    f"[respond]\nnever_act_on = {B}\n")
    assert out["internetdb"]["wanted"]["status"] == "written"
    assert "exchange" not in out["internetdb"]
    doc = json.loads((tmp_path / "reports" / "blocklist" / dl.WANTED_FILE).read_text())
    assert doc["addresses"] == [A]


def test_cli_ship_moves_the_files_and_writes_no_wanted_list(tmp_path, monkeypatch):
    monkeypatch.setattr(idb, "_request", lambda *a: pytest.fail("network"))
    s3 = FakeS3({ANSWERS_KEY: answers(found(A))})
    monkeypatch.setattr(objectstore, "guarded_client_factory", lambda op: lambda target: s3)
    wanted = tmp_path / "bl" / "w.json"
    write_wanted_file(wanted, [A])
    answers_file = tmp_path / "idb" / "internetdb.json"
    text = (f"[{idb.SECTION}]\nenabled = true\nmode = delivered\nwanted_file = {wanted}\n"
            f"answers_file = {answers_file}\n[{dl.SECTION}]\n" +
            "".join(f"{k} = {v}\n" for k, v in EXCHANGE.items()))
    out = _cli(tmp_path, "ship", text)
    assert "wanted" not in out["internetdb"]
    assert out["internetdb"]["exchange"]["accepted"] == 1
    assert idb.InternetDbReader(answers_file).info(A).ports == [22, 80]
    assert json.loads(s3.puts[0]["Body"])["addresses"] == [A]


def test_cli_exchange_config_error_is_reported(tmp_path):
    out = _cli(tmp_path, "ship", f"[{idb.SECTION}]\nenabled = true\nmode = delivered\n"
                                 f"[{dl.SECTION}]\nenabled = true\nkind = https\n")
    assert "kind must be s3" in out["internetdb"]["exchange"]["error"]
