"""Sightings: strict validation of an untrusted document, the console's reader (last good
copy, stale marker, log once), grouping by listed address, and the fetch (one guarded
GetObject or one GET, interval, replace only with a valid copy)."""

import configparser
import datetime
import json
import logging
from pathlib import Path

import pytest

from agents import objectstore, sightings
from agents.ship import OperationRefused

from test_connectors import FakeTransport, public_resolver

pytestmark = pytest.mark.usefixtures("public_test_net")

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.datetime(2026, 11, 18, 9, 0, tzinfo=datetime.timezone.utc)


def item(**kw) -> dict:
    base = {"address": "198.51.100.7", "where": "prod-account", "service": "tcp/443",
            "first_seen": "2026-11-17T22:10:00Z", "last_seen": "2026-11-18T08:55:00Z",
            "count": 14, "source": "threat-list finding"}
    base.update(kw)
    return base


def doc(*items, generated_at="2026-11-18T09:00:00Z", **kw) -> dict:
    return {"version": 1, "generated_at": generated_at, "sightings": list(items), **kw}


def body(d) -> bytes:
    return json.dumps(d).encode()


# ---- validation ----------------------------------------------------------------------------

def test_a_valid_document_parses():
    d = sightings.parse(body(doc(item(), item(address="2001:db8:1:2::9", count=0))))
    assert d.generated_at == NOW
    a, b = d.sightings
    assert (a.key, a.where, a.service, a.count, a.source) == \
        ("198.51.100.7", "prod-account", "tcp/443", 14, "threat-list finding")
    assert b.key == "2001:db8:1:2::/64"


@pytest.mark.parametrize("bad", [
    b"not json", b"[]", b"\xff\xfe", body({"version": 2, "generated_at": "2026-11-18T09:00:00Z",
                                           "sightings": []}),
    body({"version": True, "generated_at": "2026-11-18T09:00:00Z", "sightings": []}),
    body(doc(generated_at="yesterday")), body(doc(generated_at=12)),
    body({"version": 1, "generated_at": "2026-11-18T09:00:00Z", "sightings": {}}),
    body(doc("x")),
    body(doc(item(address="example.com"))), body(doc(item(address="198.51.100.0/24"))),
    body(doc(item(address="fe80::1%eth0"))), body(doc(item(address=7))),
    body(doc(item(count=-1))), body(doc(item(count="14"))), body(doc(item(count=True))),
    body(doc(item(count=1.5))), body(doc(item(count=10 ** 13))),
    body(doc(item(where=["a"]))), body(doc(item(service=None))), body(doc(item(source="x" * 300))),
    body(doc(item(first_seen="2026-11-19T00:00:00Z"))), body(doc(item(last_seen="soon"))),
    body(doc(item(first_seen="2" * 50))),
])
def test_wrong_shapes_and_types_refuse_the_whole_file(bad):
    with pytest.raises(sightings.InvalidSightings):
        sightings.parse(bad)


def test_size_and_entry_caps():
    big = body(doc(*[item() for _ in range(20)]))
    with pytest.raises(sightings.InvalidSightings, match="larger than"):
        sightings.parse(big, max_bytes=len(big) - 1)
    with pytest.raises(sightings.InvalidSightings, match="more than 19"):
        sightings.parse(big, max_entries=19)
    assert len(sightings.parse(big, max_entries=20).sightings) == 20


def test_strings_are_stripped_of_control_and_invisible_characters_and_capped():
    nasty = "a\x1b[31mb‮c​d\ne f" + "g" * 100
    s = sightings.parse(body(doc(item(where=nasty, service="<b>tcp</b>"))))
    [one] = s.sightings
    assert one.where.startswith("a[31mbcd e f") and len(one.where) == sightings.FIELD_CAP
    assert one.service == "<b>tcp</b>"   # kept as text; the console never renders it as HTML
    for c in one.where:
        assert c.isprintable()


def test_unknown_keys_are_ignored_and_missing_labels_are_empty():
    d = doc(item(extra="ignored"))
    del d["sightings"][0]["where"]
    [one] = sightings.parse(body(d)).sightings
    assert one.where == "" and "extra" not in one.to_dict()


def test_naive_timestamps_are_utc():
    [one] = sightings.parse(body(doc(item(first_seen="2026-11-17T22:10:00",
                                          last_seen="2026-11-17T23:00:00")))).sightings
    assert one.first_seen.tzinfo is not None and one.first_seen.hour == 22


def test_sightings_of_unlisted_addresses_are_ignored():
    d = sightings.parse(body(doc(item(), item(address="198.51.100.8"),
                                 item(address="2001:db8:1:2::1"))))
    groups = sightings.by_address(d, ["198.51.100.7", "2001:db8:1:2::/64"])
    assert set(groups) == {"198.51.100.7", "2001:db8:1:2::/64"}
    assert sightings.by_address(None, ["198.51.100.7"]) == {}


# ---- the console's reader ------------------------------------------------------------------

def _reader(tmp_path, **kw):
    return sightings.SightingsReader(tmp_path / "sightings.json",
                                     sightings.SightingsSettings(**kw))


def test_missing_file(tmp_path):
    view = _reader(tmp_path).read(NOW)
    assert view["state"] == "missing" and view["doc"] is None and view["stale"] is False


def test_fresh_and_stale(tmp_path):
    (tmp_path / "sightings.json").write_bytes(body(doc(item())))
    reader = _reader(tmp_path, stale_hours=48)
    view = reader.read(NOW + datetime.timedelta(hours=1))
    assert view["state"] == "ok" and view["stale"] is False and view["age_hours"] == 1.0
    view = reader.read(NOW + datetime.timedelta(hours=49))
    assert view["state"] == "ok" and view["stale"] is True and view["doc"] is not None


def test_a_refused_file_keeps_the_last_good_copy_and_is_logged_once(tmp_path, caplog):
    path = tmp_path / "sightings.json"
    path.write_bytes(body(doc(item())))
    reader = _reader(tmp_path)
    assert reader.read(NOW)["state"] == "ok"
    path.write_bytes(body(doc(item(count=-5))) + b" ")
    with caplog.at_level(logging.WARNING, logger="agents.sightings"):
        for _ in range(3):
            view = reader.read(NOW)
    assert view["state"] == "invalid" and "count" in view["error"]
    assert view["doc"].sightings[0].count == 14
    assert caplog.text.count("sightings file refused") == 1


def test_the_reader_never_writes(tmp_path):
    reader = _reader(tmp_path / "nowhere")
    reader.read(NOW)
    assert not (tmp_path / "nowhere").exists()


def test_settings():
    cp = configparser.ConfigParser()
    assert sightings.SightingsSettings.from_config(cp).file("/s") == Path("/s/sightings.json")
    cp.read_dict({"sightings": {"path": "/x/s.json", "max_bytes": "2048", "max_entries": "10",
                                "stale_hours": "1.5"}})
    s = sightings.SightingsSettings.from_config(cp)
    assert (s.file("/s"), s.max_bytes, s.max_entries, s.stale_hours) == \
        (Path("/x/s.json"), 2048, 10, 1.5)
    for key, value in (("path", "rel.json"), ("max_bytes", "10"), ("max_bytes", "1e99"),
                       ("max_entries", "0"), ("stale_hours", "x")):
        bad = configparser.ConfigParser()
        bad.read_dict({"sightings": {key: value}})
        with pytest.raises(sightings.ConfigError):
            sightings.SightingsSettings.from_config(bad)


# ---- fetch ---------------------------------------------------------------------------------

class Body:
    def __init__(self, data):
        self.data, self.closed, self.asked = data, False, None

    def read(self, amt=None):
        self.asked = amt
        return self.data[:amt]

    def close(self):
        self.closed = True


class FakeS3:
    def __init__(self, data=b"", exc=None, length=None):
        self.gets: list[dict] = []
        self.data, self.exc, self.length = data, exc, length
        self.body = None

    def get_object(self, **params):
        if self.exc is not None:
            raise self.exc
        self.gets.append(params)
        self.body = Body(self.data)
        out = {"Body": self.body}
        if self.length is not None:
            out["ContentLength"] = self.length
        return out

    def __getattr__(self, name):
        raise AssertionError(f"S3 client used for {name}; only get_object is allowed")


def _fetch_cp(**opts):
    cp = configparser.ConfigParser()
    cp.read_dict({sightings.SECTION: {"enabled": "true", **opts}})
    return sightings.FetchSettings.from_config(cp)


def _s3():
    return _fetch_cp(kind="s3", bucket="example-honeypot-events", key="sightings/s.json",
                     bucket_owner="123456789012")


def _run(tmp_path, fetch, client=None, now=NOW, **kw):
    return sightings.run_fetch(fetch, sightings.SightingsSettings(**kw.pop("local", {})),
                               tmp_path / "state", client_factory=lambda t: client,
                               resolver=public_resolver, now=now, **kw)


def _local(tmp_path) -> dict:
    return json.loads((tmp_path / "state" / "sightings.json").read_text())


def test_fetch_is_off_by_default(tmp_path):
    assert sightings.FetchSettings.from_config(configparser.ConfigParser()).enabled is False
    assert _run(tmp_path, sightings.FetchSettings()) == {"status": "disabled"}


def test_s3_fetch_gets_one_object_and_writes_a_clean_copy(tmp_path):
    s3 = FakeS3(body(doc(item(where="a\x07b"), extra=1)))
    res = _run(tmp_path, _s3(), s3)
    assert res == {"kind": "s3", "status": "fetched", "sightings": 1}
    assert s3.gets == [{"Bucket": "example-honeypot-events", "Key": "sightings/s.json",
                        "ExpectedBucketOwner": "123456789012"}]
    assert s3.body.closed and s3.body.asked == sightings.DEFAULT_MAX_BYTES + 1
    local = _local(tmp_path)
    assert local["sightings"][0]["where"] == "ab" and "extra" not in local


def test_fetch_runs_at_most_once_per_interval(tmp_path):
    s3 = FakeS3(body(doc(item())))
    _run(tmp_path, _s3(), s3)
    assert _run(tmp_path, _s3(), s3, now=NOW + datetime.timedelta(minutes=5))["status"] == "not due"
    assert _run(tmp_path, _s3(), s3, now=NOW + datetime.timedelta(minutes=16))["status"] == "fetched"
    assert len(s3.gets) == 2


def test_an_invalid_fetched_copy_keeps_the_last_good_file_and_logs_once(tmp_path, caplog):
    _run(tmp_path, _s3(), FakeS3(body(doc(item()))))
    good = (tmp_path / "state" / "sightings.json").read_bytes()
    bad = FakeS3(body(doc(item(address="not-an-ip"))))
    with caplog.at_level(logging.ERROR, logger="agents.sightings"):
        for i in range(1, 4):
            res = _run(tmp_path, _s3(), bad, now=NOW + datetime.timedelta(minutes=20 * i))
    assert res["error"].startswith("fetched document refused") and "kept" in res
    assert (tmp_path / "state" / "sightings.json").read_bytes() == good
    assert caplog.text.count("fetched document refused") == 1


def test_an_oversized_object_is_refused_before_reading(tmp_path):
    s3 = FakeS3(body(doc(item())), length=10 ** 9)
    res = _run(tmp_path, _s3(), s3)
    assert "larger than" in res["error"] and s3.body.asked is None
    s3 = FakeS3(b"x" * 5000)
    res = _run(tmp_path, _s3(), s3, local={"max_bytes": 2048},
               now=NOW + datetime.timedelta(hours=1))
    assert "larger than" in res["error"]
    assert not (tmp_path / "state" / "sightings.json").exists()


def test_a_failed_get_is_reported_without_the_message(tmp_path):
    class ClientError(Exception):
        response = {"Error": {"Code": "NoSuchKey", "Message": "secret details"}}

    res = _run(tmp_path, _s3(), FakeS3(exc=ClientError("secret details")))
    assert res["error"] == "GetObject failed: ClientError: NoSuchKey"


def test_https_fetch_is_one_get_with_a_raised_cap(tmp_path):
    transport = FakeTransport(body=body(doc(item())))
    calls = []

    def request(method, url, headers, data, timeout, address, max_bytes=None):
        calls.append((method, url, data, max_bytes))
        return 200, transport.body

    transport.request = request
    fetch = _fetch_cp(kind="https", url="https://intel.example.com/sightings")
    res = sightings.run_fetch(fetch, sightings.SightingsSettings(), tmp_path / "state",
                              transport=transport, resolver=public_resolver, now=NOW)
    assert res["status"] == "fetched"
    assert calls == [("GET", "https://intel.example.com/sightings", None,
                      sightings.DEFAULT_MAX_BYTES)]


class CappedTransport(FakeTransport):
    def request(self, method, url, headers, body, timeout, address, max_bytes=None):
        return super().request(method, url, headers, body, timeout, address)


def test_https_fetch_failure(tmp_path):
    fetch = _fetch_cp(kind="https", url="https://intel.example.com/sightings")
    res = sightings.run_fetch(fetch, sightings.SightingsSettings(), tmp_path / "state",
                              transport=CappedTransport(status=301), resolver=public_resolver,
                              now=NOW)
    assert res["error"] == "GET failed: error: redirect_301"


@pytest.mark.parametrize("opts", [{"kind": "ftp"}, {"kind": "s3", "bucket": "b", "key": "k"},
                                  {"kind": "s3", "bucket": "example-b", "key": "../k"},
                                  {"kind": "https", "url": "http://x.example.com"},
                                  {"kind": "https", "url": "https://x.example.com",
                                   "interval_minutes": "0"}])
def test_bad_fetch_settings(opts):
    with pytest.raises(sightings.ConfigError):
        _fetch_cp(**opts)


@pytest.mark.parametrize("op", ["PutObject", "ListObjectsV2", "HeadBucket", "DeleteObject"])
def test_the_fetch_client_is_guarded_to_get_object_of_one_key(op):
    class Model:
        def __init__(self, name):
            self.name = name

    guard = objectstore.OneObjectGuard("GetObject", "example-b", "s/s.json")
    guard.before_parameters(params={"Bucket": "example-b", "Key": "s/s.json"},
                            model=Model("GetObject"))
    with pytest.raises(OperationRefused):
        guard.before_call(model=Model(op))
    with pytest.raises(OperationRefused):
        guard.before_parameters(params={"Bucket": "example-b", "Key": "s/other.json"},
                                model=Model("GetObject"))


def test_the_sightings_module_only_ever_calls_get_object():
    import re

    source = (ROOT / "agents" / "sightings.py").read_text(encoding="utf-8")
    assert "put_object" not in source and "delete_object" not in source
    store = (ROOT / "agents" / "objectstore.py").read_text(encoding="utf-8")
    assert set(re.findall(r"client\.([a-z_]+)\(", store)) == {"put_object", "get_object"}


def test_ship_command_fetches_sightings(tmp_path, monkeypatch):
    import agents.__main__ as cli

    s3 = FakeS3(body(doc(item())))
    monkeypatch.setattr(objectstore, "guarded_client_factory", lambda op: lambda target: s3)
    cfg = tmp_path / "config.ini"
    cfg.write_text("[connector.sightings]\nenabled = true\nkind = s3\n"
                   "bucket = example-honeypot-events\nkey = sightings/s.json\n")
    out = cli.run(["ship", "--config", str(cfg), "--reports-dir", str(tmp_path / "reports"),
                   "--state-dir", str(tmp_path / "state"), "--data-dir", str(tmp_path / "data")])
    assert out["sightings_fetch"]["status"] == "fetched"
    assert _local(tmp_path)["sightings"][0]["address"] == "198.51.100.7"


# ---- timestamps at the edge of the calendar ------------------------------------------------

EDGE_TIMES = ["9999-12-31T23:59:59-23:00", "0001-01-01T00:00:00+10:00"]


@pytest.mark.parametrize("value", EDGE_TIMES)
@pytest.mark.parametrize("field", ["generated_at", "first_seen", "last_seen"])
def test_out_of_range_timestamps_are_refused_not_raised(value, field):
    d = doc(item(**{field: value})) if field != "generated_at" else doc(item(), generated_at=value)
    with pytest.raises(sightings.InvalidSightings, match="not a timestamp"):
        sightings.parse(body(d))


@pytest.mark.parametrize("value", EDGE_TIMES)
def test_the_reader_shows_an_out_of_range_file_as_refused(tmp_path, value):
    path = tmp_path / "sightings.json"
    reader = _reader(tmp_path)
    path.write_bytes(body(doc(item(last_seen=value))))
    for _ in range(2):   # a second read of the same copy is still refused, not "ok"
        view = reader.read(NOW)
        assert view["state"] == "invalid" and "not a timestamp" in view["error"]
        assert view["doc"] is None


def test_any_failure_while_checking_is_a_refusal_and_not_remembered_as_good(tmp_path,
                                                                            monkeypatch):
    path = tmp_path / "sightings.json"
    path.write_bytes(body(doc(item())))
    reader = _reader(tmp_path)

    def broken(*a, **kw):
        raise ArithmeticError("boom")

    monkeypatch.setattr(sightings, "parse", broken)
    for _ in range(2):
        view = reader.read(NOW)
        assert view["state"] == "invalid" and "ArithmeticError" in view["error"]
        assert "boom" not in view["error"] and view["doc"] is None
    monkeypatch.undo()
    path.write_bytes(body(doc(item(count=3))))
    view = reader.read(NOW)
    assert view["state"] == "ok" and view["doc"].sightings[0].count == 3


@pytest.mark.parametrize("value", EDGE_TIMES)
def test_a_fetched_out_of_range_copy_is_refused_and_the_state_is_written(tmp_path, value):
    _run(tmp_path, _s3(), FakeS3(body(doc(item()))))
    good = (tmp_path / "state" / "sightings.json").read_bytes()
    later = NOW + datetime.timedelta(minutes=20)
    res = _run(tmp_path, _s3(), FakeS3(body(doc(item(first_seen=value)))), now=later)
    assert res["error"].startswith("fetched document refused") and "kept" in res
    assert (tmp_path / "state" / "sightings.json").read_bytes() == good
    st = json.loads((tmp_path / "state" / sightings.FETCH_STATE_FILE).read_text())
    assert st["attempted_at"] == later.isoformat(timespec="seconds") and st["refused_sha256"]


def test_any_failure_while_checking_a_fetched_copy_never_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(sightings, "parse", lambda *a, **kw: 1 / 0)
    res = _run(tmp_path, _s3(), FakeS3(body(doc(item()))))
    assert res["error"] == "fetched document refused: could not be checked (ZeroDivisionError)"
    assert (tmp_path / "state" / sightings.FETCH_STATE_FILE).exists()
    assert not (tmp_path / "state" / "sightings.json").exists()


@pytest.mark.parametrize("attempted", ["2026-11-18T08:59:00", "garbage", 12, None,
                                       "9999-12-31T23:59:59-23:00"])
def test_a_naive_or_malformed_attempted_at_means_the_fetch_is_due(tmp_path, attempted):
    state = tmp_path / "state"
    state.mkdir()
    (state / sightings.FETCH_STATE_FILE).write_text(json.dumps({"attempted_at": attempted}))
    res = _run(tmp_path, _s3(), FakeS3(body(doc(item()))))
    assert res["status"] == "fetched"
    st = json.loads((state / sightings.FETCH_STATE_FILE).read_text())
    assert st["attempted_at"] == NOW.isoformat(timespec="seconds")


def test_an_unwritable_state_directory_never_raises(tmp_path):
    (tmp_path / "state").write_text("a file where the directory should be")
    res = _run(tmp_path, _s3(), FakeS3(body(doc(item()))))
    assert "error" in res and "status" not in res
