"""The exporter asks InternetDB itself: [connector.internetdb_exchange] kind = lookup
(agents/internetdb_lookup_exchange.py).

No real network: the HTTP layer is a fake, the resolver answers documentation addresses
treated as public, and the clock is injected.
"""

from __future__ import annotations

import configparser
import datetime
import json
import os
import socket

import pytest

from agents import internetdb as idb
from agents import internetdb_delivered as dl
from agents import internetdb_lookup_exchange as lx
from agents import objectstore
from agents.addresses import public_for_tests
from agents.connectors.base import DestinationError
from agents.triage import write_record
from test_internetdb import NOT_FOUND, Clock, Fake, answer, rec

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
A, B, C, D = "198.51.100.7", "198.51.100.8", "198.51.100.9", "198.51.100.10"
V6 = "2001:db8::5"
EDGE1, EDGE2, EDGE3 = "203.0.113.80", "203.0.113.81", "203.0.113.82"


@pytest.fixture(autouse=True)
def _public():
    with public_for_tests("198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"):
        yield


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
LOOKUP = {"enabled": "true", "kind": "lookup"}
SETTINGS = idb.InternetDbSettings.from_config(cfg(DELIVERED))
EXCH = dl.ExchangeSettings.from_config(cfg(DELIVERED, LOOKUP))


def dns(*addresses):
    def resolve(host, port, proto=0):
        assert host == idb.HOST and port == 443
        return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", (a, port)) for a in addresses]
    return resolve


def write_wanted(tmp_path, addresses, **extra):
    path = tmp_path / "blocklist" / dl.WANTED_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = json.loads(dl.wanted_document(addresses, NOW))
    doc.update(extra)
    path.write_text(json.dumps(doc))
    return path


def answers_path(tmp_path):
    return tmp_path / "answers" / "internetdb.json"


def run(tmp_path, fake, *, exch=EXCH, settings=SETTINGS, now=NOW, clock=None, networks=(),
        resolver=None, **kw):
    clock = clock or Clock()
    return lx.run_lookup_exchange(exch, settings, tmp_path / "blocklist" / dl.WANTED_FILE,
                                  answers_path(tmp_path), tmp_path / "state", list(networks),
                                  transport=fake, resolver=resolver or dns(EDGE1), now=now,
                                  clock=clock, sleep=clock.sleep, **kw)


def held(tmp_path):
    return idb.load_state(answers_path(tmp_path))["entries"]


def asked(fake):
    return [c["url"].rsplit("/", 1)[1] for c in fake.calls]


# ---- configuration -------------------------------------------------------------------------

def test_settings():
    assert EXCH.enabled and EXCH.kind == "lookup" and EXCH.addresses_file is None
    assert EXCH.wanted is None and EXCH.answers is None
    pinned = dl.ExchangeSettings.from_config(
        cfg(DELIVERED, {**LOOKUP, "addresses_file": "/egress/internetdb-addresses"}))
    assert pinned.addresses_file == "/egress/internetdb-addresses"
    with pytest.raises(dl.ConfigError, match="absolute"):
        dl.ExchangeSettings.from_config(cfg(DELIVERED, {**LOOKUP, "addresses_file": "x"}))
    with pytest.raises(dl.ConfigError, match="kind must be s3 or lookup"):
        dl.ExchangeSettings.from_config(cfg(DELIVERED, {**LOOKUP, "kind": "https"}))
    with pytest.raises(dl.ConfigError, match="mode = delivered"):
        dl.ExchangeSettings.from_config(cfg({"enabled": "true"}, LOOKUP))
    # The s3 kind still parses exactly as before and is the default.
    s3 = dl.ExchangeSettings.from_config(cfg(DELIVERED, {
        "enabled": "true", "bucket": "example-honeypot-events",
        "wanted_key": "events/internetdb/wanted.json", "answers_key": "internetdb/answers.json"}))
    assert s3.kind == "s3" and s3.addresses_file is None and s3.wanted is not None


def test_the_destination_cannot_be_configured():
    # No key names a host or URL; an unknown key in [connector.internetdb] is refused.
    with pytest.raises(idb.ConfigError):
        idb.InternetDbSettings.from_config(cfg({**DELIVERED, "url": "https://example.net/"}))
    exch = dl.ExchangeSettings.from_config(cfg(DELIVERED, {**LOOKUP, "host": "example.net",
                                                           "bucket": "example-bucket"}))
    assert exch == dl.ExchangeSettings(enabled=True, kind="lookup")


def test_each_runner_refuses_the_other_kind(tmp_path):
    assert dl.run_exchange(EXCH, SETTINGS, tmp_path / "w", tmp_path / "a", tmp_path / "s",
                           []) == {"status": "not an object store exchange"}
    s3 = dl.ExchangeSettings(enabled=True)
    assert lx.run_lookup_exchange(s3, SETTINGS, tmp_path / "w", tmp_path / "a",
                                  tmp_path / "s", []) == {"status": "not a lookup exchange"}
    assert lx.run_lookup_exchange(dl.ExchangeSettings(), SETTINGS, tmp_path / "w",
                                  tmp_path / "a", tmp_path / "s", []) == {"status": "disabled"}
    assert not (tmp_path / "s").exists()


# ---- the request ---------------------------------------------------------------------------

def test_request_shape_and_the_answers_file(tmp_path):
    write_wanted(tmp_path, [A, B])
    fake = Fake({A: (200, answer(A)), B: NOT_FOUND})
    out = run(tmp_path, fake)
    assert out["status"] == "done" and out["wanted"] == 2 and out["delivered"] == 2
    assert out["lookup"]["found"] == 1 and out["lookup"]["not_found"] == 1
    for call, addr in zip(fake.calls, (A, B)):
        assert call["method"] == "GET" and call["body"] is None
        assert call["url"] == f"https://internetdb.shodan.io/{addr}"
        assert call["headers"] == {"User-Agent": "internetdb-client/1",
                                   "Accept": "application/json"}
        assert call["timeout"] == 5.0 and call["max_bytes"] == 64 * 1024
        assert call["address"] == EDGE1
    reader = idb.InternetDbReader(answers_path(tmp_path))
    assert reader.info(A).ports == [22, 80] and reader.info(A).found
    assert reader.info(B).found is False
    # The exporter's own state is separate from the file the agents read.
    assert set(idb.load_state(tmp_path / "state" / lx.STATE_FILE)["entries"]) == {A, B}


def test_the_answer_is_sanitised_like_a_direct_one(tmp_path):
    write_wanted(tmp_path, [A])
    hostile = answer(A, hostnames=["ok.example.net", "<script>.example.net", "x" * 600],
                     ports=[22, 0, 70000, "80", True], tags=["vpn", "Bad Tag"],
                     vulns=["CVE-2024-1234", "not-a-cve"], extra={"nested": [1] * 10})
    run(tmp_path, Fake({A: (200, hostile)}))
    info = held(tmp_path)[A]["info"]
    assert info == idb.sanitize(hostile, A, "2026-11-20")
    assert info.hostnames == ["ok.example.net"] and info.ports == [22]


@pytest.mark.parametrize("body", [b"not json", b"[]", json.dumps({"ip": B}).encode(),
                                  b"{" * 100000])
def test_an_answer_that_is_not_kept_is_not_delivered_and_not_asked_again_soon(tmp_path, body):
    write_wanted(tmp_path, [A])
    out = run(tmp_path, Fake({A: (200, body)}))
    assert out["lookup"]["refused"] == 1 and out["delivered"] == 0
    assert A not in held(tmp_path)
    fake = Fake({A: (200, answer(A))})
    assert run(tmp_path, fake, now=NOW + datetime.timedelta(days=1))["lookup"]["status"] \
        == "nothing due"
    assert fake.calls == []


# ---- the wanted list is untrusted ----------------------------------------------------------

HOSTILE_WANTED = [
    b"",
    b"not json",
    b"\xff\xfe",
    b"[" * 50000 + b"]" * 50000,
    json.dumps(["198.51.100.7"]).encode(),
    json.dumps({"version": 2, "generated_at": "2026-11-20T12:00:00Z",
                "addresses": [A]}).encode(),
    json.dumps({"version": True, "generated_at": "2026-11-20T12:00:00Z",
                "addresses": [A]}).encode(),
    json.dumps({"version": 1, "addresses": [A]}).encode(),
    json.dumps({"version": 1, "generated_at": "2026-11-20T12:00:00Z",
                "addresses": f"{A}"}).encode(),
    json.dumps({"version": 1, "generated_at": "2026-11-20T12:00:00Z",
                "addresses": [A, A]}).encode(),
    json.dumps({"version": 1, "generated_at": "2026-11-20T12:00:00Z",
                "addresses": [A, "10.0.0.1"]}).encode(),
    json.dumps({"version": 1, "generated_at": "2026-11-20T12:00:00Z",
                "addresses": [A, "2001:DB8::5"]}).encode(),
    json.dumps({"version": 1, "generated_at": "2026-11-20T12:00:00Z",
                "addresses": [f"{A}/../../admin"]}).encode(),
    json.dumps({"version": 1, "generated_at": "2026-11-20T12:00:00Z",
                "addresses": [f"{A}?key=x"]}).encode(),
    json.dumps({"version": 1, "generated_at": "2026-11-20T12:00:00Z",
                "addresses": ["example.net"]}).encode(),
    json.dumps({"version": 1, "generated_at": "2026-11-20T12:00:00Z",
                "addresses": [{"ip": A}]}).encode(),
    json.dumps({"version": 1, "generated_at": "2026-11-20T12:00:00Z",
                "addresses": [f"198.51.100.{i % 250}" for i in range(501)]}).encode(),
    b" " * (64 * 1024 + 1),
]


@pytest.mark.parametrize("body", HOSTILE_WANTED)
def test_a_hostile_wanted_list_asks_nothing(tmp_path, body):
    path = write_wanted(tmp_path, [])
    path.write_bytes(body)
    fake = Fake({A: (200, answer(A))})
    out = run(tmp_path, fake)
    assert fake.calls == [] and out["status"] == "error"
    assert "wanted list is refused" in out["error"]
    assert not answers_path(tmp_path).exists()
    assert not (tmp_path / "state" / lx.STATE_FILE).exists()
    # Recorded once in the export's event file, like the other exchange errors.
    events = (tmp_path / "state" / "ship_events.jsonl").read_text().splitlines()
    assert json.loads(events[-1])["event"] == "internetdb_exchange_failed"


def test_a_fifo_or_a_link_in_place_of_the_wanted_list_neither_blocks_nor_is_followed(tmp_path):
    path = write_wanted(tmp_path, [A])
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(elsewhere)
    fake = Fake()
    out = run(tmp_path, fake)
    assert fake.calls == [] and "cannot read the wanted list" in out["error"]
    path.unlink()
    os.mkfifo(path)
    out = run(tmp_path, fake)   # would hang here if the FIFO were opened for a blocking read
    assert fake.calls == [] and "cannot read the wanted list (NotRegularFile)" in out["error"]


def test_other_keys_in_the_wanted_list_are_ignored_and_never_sent(tmp_path):
    write_wanted(tmp_path, [A], url="https://example.net/", headers={"X-Key": "v"},
                 extra=["198.51.100.9"])
    fake = Fake()
    run(tmp_path, fake)
    assert asked(fake) == [A]
    assert all(c["url"].startswith(idb.BASE_URL) and c["headers"] == fake.calls[0]["headers"]
               for c in fake.calls)


def test_never_act_on_is_applied_to_the_wanted_list(tmp_path):
    import ipaddress

    write_wanted(tmp_path, [A, B, V6])
    fake = Fake()
    out = run(tmp_path, fake, networks=[ipaddress.ip_network("198.51.100.8/32"),
                                        ipaddress.ip_network("2001:db8::/48")])
    assert asked(fake) == [A] and out["wanted"] == 1


def test_no_wanted_list_yet_asks_nothing_and_is_not_an_error(tmp_path):
    fake = Fake()
    out = run(tmp_path, fake)
    assert out == {"kind": "lookup", "wanted": "no wanted list yet", "status": "done"}
    assert fake.calls == [] and not (tmp_path / "state").exists()


def test_an_empty_wanted_list_asks_nothing(tmp_path):
    write_wanted(tmp_path, [])
    fake = Fake()
    out = run(tmp_path, fake)
    assert out["wanted"] == 0 and "lookup" not in out and fake.calls == []


def test_ipv6_addresses(tmp_path):
    write_wanted(tmp_path, [V6])
    fake = Fake({V6: (200, answer(V6))})
    out = run(tmp_path, fake)
    assert asked(fake) == [V6] and out["delivered"] == 1


# ---- pacing, caps, cache, back-off ---------------------------------------------------------

def test_per_run_cap_and_pacing(tmp_path):
    addresses = [f"198.51.100.{i}" for i in range(1, 11)]
    write_wanted(tmp_path, addresses)
    settings = idb.InternetDbSettings(enabled=True, mode="delivered", max_per_run=4)
    clock = Clock()
    fake = Fake()
    out = run(tmp_path, fake, settings=settings, clock=clock)
    # Most important first (the list's order), one at a time, a second apart.
    assert asked(fake) == addresses[:4]
    assert clock.sleeps == [1.0, 1.0, 1.0]
    assert out["lookup"]["due"] == 10 and out["delivered"] == 4


def test_per_day_cap_and_the_next_day(tmp_path):
    addresses = [f"198.51.100.{i}" for i in range(1, 11)]
    write_wanted(tmp_path, addresses)
    settings = idb.InternetDbSettings(enabled=True, mode="delivered", max_per_run=4,
                                      max_per_day=6)
    fake = Fake()
    run(tmp_path, fake, settings=settings)
    run(tmp_path, fake, settings=settings, now=NOW + datetime.timedelta(hours=1))
    assert len(fake.calls) == 6
    out = run(tmp_path, fake, settings=settings, now=NOW + datetime.timedelta(hours=2))
    assert out["lookup"]["status"] == "daily cap reached" and len(fake.calls) == 6
    run(tmp_path, fake, settings=settings, now=NOW + datetime.timedelta(days=1))
    assert len(fake.calls) == 10


def test_cache_including_not_found(tmp_path):
    write_wanted(tmp_path, [A, B])
    fake = Fake({A: (200, answer(A)), B: NOT_FOUND})
    run(tmp_path, fake)
    out = run(tmp_path, fake, now=NOW + datetime.timedelta(days=6, hours=23))
    assert len(fake.calls) == 2 and out["lookup"]["status"] == "nothing due"
    run(tmp_path, fake, now=NOW + datetime.timedelta(days=7))
    assert asked(fake) == [A, B, A, B]
    assert held(tmp_path)[A]["checked_at"] == NOW + datetime.timedelta(days=7)


@pytest.mark.parametrize("failure", [(429, b""), (500, b""), (503, b"x"), (301, b""),
                                     OSError("unreachable"), socket.timeout("t"),
                                     ConnectionRefusedError("firewall")])
def test_a_failure_stops_backs_off_and_is_quiet(tmp_path, failure):
    write_wanted(tmp_path, [A, B, C])
    fake = Fake({A: (200, answer(A)), B: failure})
    out = run(tmp_path, fake)
    assert asked(fake) == [A, B]
    assert out["status"] == "done" and "error" not in out
    assert out["lookup"]["status"] == "stopped" and out["lookup"]["backoff_minutes"] == 15
    # What was answered before the failure is delivered.
    assert out["delivered"] == 1 and A in held(tmp_path)
    later = run(tmp_path, fake, now=NOW + datetime.timedelta(minutes=10))
    assert later["lookup"]["status"] == "backing off" and len(fake.calls) == 2
    again = run(tmp_path, fake, now=NOW + datetime.timedelta(minutes=16))
    assert again["lookup"]["backoff_minutes"] == 30 and asked(fake)[2:] == [B]


def test_an_unresolvable_name_is_quiet(tmp_path):
    write_wanted(tmp_path, [A])

    def fails(host, port, proto=0):
        raise socket.gaierror("no dns")

    out = run(tmp_path, Fake(), resolver=fails)
    assert out["lookup"]["stopped"] == "request failed (DestinationError)"


def test_the_lookup_state_is_bounded(tmp_path):
    settings = idb.InternetDbSettings(enabled=True, mode="delivered", max_entries=100,
                                      max_per_run=1000, max_per_day=20000,
                                      min_interval_seconds=1.0)
    for start in (0, 120, 240):
        write_wanted(tmp_path, [f"198.51.100.{i % 250}" if i < 250 else f"203.0.113.{i - 250}"
                                for i in range(start, start + 120)])
        run(tmp_path, Fake(), settings=settings, now=NOW + datetime.timedelta(hours=start))
    assert len(idb.load_state(tmp_path / "state" / lx.STATE_FILE)["entries"]) == 100
    assert len(held(tmp_path)) == 100


def test_a_tampered_answers_file_does_not_change_what_is_asked(tmp_path):
    # The answers file is what the agents read; the cache is the exporter's own file.
    write_wanted(tmp_path, [A])
    fake = Fake({A: (200, answer(A))})
    run(tmp_path, fake)
    answers_path(tmp_path).write_text('{"version": 1, "day": "2026-11-20", "day_count": 0, '
                                      '"entries": {}}')
    out = run(tmp_path, fake, now=NOW + datetime.timedelta(hours=1))
    assert len(fake.calls) == 1 and out["lookup"]["status"] == "nothing due"
    # The answers already held are delivered again.
    assert out["delivered"] == 1 and held(tmp_path)[A]["info"].ports == [22, 80]


# ---- the answers file is the s3 path's -----------------------------------------------------

def test_the_answers_file_is_identical_to_the_object_store_path(tmp_path):
    from test_internetdb_delivered import EXCHANGE, FakeS3

    write_wanted(tmp_path / "lookup", [A, B])
    run(tmp_path / "lookup", Fake({A: (200, answer(A)), B: NOT_FOUND}))
    by_lookup = answers_path(tmp_path / "lookup").read_bytes()

    # The same answers as a producer would write them, through the s3 path.
    write_wanted(tmp_path / "s3", [A, B])
    produced = {"version": 1, "generated_at": "2026-11-20T12:00:00Z", "answers": [
        {"ip": A, "checked_at": "2026-11-20T12:00:00Z", "status": "found",
         **json.loads(answer(A))},
        {"ip": B, "checked_at": "2026-11-20T12:00:00Z", "status": "not_found"}]}
    s3 = FakeS3({EXCHANGE["answers_key"]: json.dumps(produced).encode()})
    exch = dl.ExchangeSettings.from_config(cfg(DELIVERED, EXCHANGE))
    dl.run_exchange(exch, SETTINGS, tmp_path / "s3" / "blocklist" / dl.WANTED_FILE,
                    answers_path(tmp_path / "s3"), tmp_path / "s3" / "state", [],
                    client_factory=lambda target: s3, now=NOW)
    assert by_lookup == answers_path(tmp_path / "s3").read_bytes()


def test_the_answers_document_is_the_producer_format(tmp_path):
    write_wanted(tmp_path, [A, B, C])
    run(tmp_path, Fake({A: (200, answer(A)), B: NOT_FOUND, C: (200, b"nope")}))
    state = idb.load_state(tmp_path / "state" / lx.STATE_FILE)
    doc = json.loads(lx.answers_document(state, [A, B, C], NOW))
    assert doc["version"] == 1 and [a["ip"] for a in doc["answers"]] == [A, B]
    assert doc["answers"][1] == {"ip": B, "checked_at": "2026-11-20T12:00:00+00:00",
                                 "status": "not_found"}


# ---- pinned addresses (the AWS host firewall's list) ---------------------------------------

def pinned_exch(tmp_path, text):
    path = tmp_path / "egress" / "internetdb-addresses"
    path.parent.mkdir(parents=True, exist_ok=True)
    if text is not None:
        path.write_text(text)
    return dl.ExchangeSettings(enabled=True, kind="lookup", addresses_file=str(path))


def test_with_pinned_addresses_only_those_are_connected_to(tmp_path):
    write_wanted(tmp_path, [A, B])
    exch = pinned_exch(tmp_path, f"{EDGE2}\n{EDGE3}\n")
    fake = Fake()
    out = run(tmp_path, fake, exch=exch, resolver=dns(EDGE1, EDGE3, EDGE2))
    assert out["pinned"] == 2
    # The first address the name resolves to that the firewall allows.
    assert [c["address"] for c in fake.calls] == [EDGE3, EDGE3]


def test_a_name_that_moved_uses_the_first_pinned_address(tmp_path):
    write_wanted(tmp_path, [A])
    exch = pinned_exch(tmp_path, f"{EDGE2}\n{EDGE3}\n")
    fake = Fake()
    run(tmp_path, fake, exch=exch, resolver=dns(EDGE1))
    assert [c["address"] for c in fake.calls] == [EDGE2]

    def fails(host, port, proto=0):
        raise socket.gaierror("no dns")

    write_wanted(tmp_path, [B])
    run(tmp_path, fake, exch=exch, resolver=fails)
    assert fake.calls[-1]["address"] == EDGE2


@pytest.mark.parametrize("text", [None, "", "not an address\n", "10.0.0.1\n127.0.0.1\n",
                                  f"{V6}\n", "0.0.0.0\n"])
def test_no_usable_pinned_address_asks_nothing(tmp_path, text):
    write_wanted(tmp_path, [A])
    fake = Fake()
    out = run(tmp_path, fake, exch=pinned_exch(tmp_path, text))
    assert fake.calls == [] and out["pinned"] == 0
    assert "no pinned InternetDB address" in out["error"]


def test_the_pinned_file_is_read_with_care(tmp_path):
    path = tmp_path / "addresses"
    lines = ["# comment", f" {EDGE1} ", EDGE1, "203.0.113.083", "10.0.0.1", V6,
             f"{EDGE2};reboot", EDGE2] + [f"198.51.100.{i}" for i in range(1, 20)]
    path.write_text("\n".join(lines) + "\n")
    got = lx.read_pinned(path)
    assert got[:2] == [EDGE1, EDGE2] and len(got) == lx.MAX_PINNED
    path.write_text(f"{EDGE1}\n" + " " * lx.MAX_PINNED_BYTES)
    with pytest.raises(dl.InvalidDocument):
        lx.read_pinned(path)


def test_the_pinned_resolver_refuses_an_empty_list():
    with pytest.raises(DestinationError):
        idb.pin_address(idb.HOST, 443, resolver=lx.pinned_resolver([], dns(EDGE1)))


# ---- dry run and the CLI -------------------------------------------------------------------

def test_dry_run_asks_and_writes_nothing(tmp_path):
    write_wanted(tmp_path, [A, B, C])
    fake = Fake()
    out = run(tmp_path, fake, dry_run=True)
    assert out["dry_run"] and out["status"] == "dry run"
    assert out["lookup"]["status"] == "would look up" and out["lookup"]["addresses"] == 3
    assert fake.calls == [] and not (tmp_path / "state").exists()
    assert not answers_path(tmp_path).exists()


def _cli(tmp_path, command, text, *extra):
    from agents.__main__ import run as cli_run

    cfg_path = tmp_path / "config.ini"
    cfg_path.write_text(text)
    return cli_run([command, "--config", str(cfg_path), "--reports-dir",
                    str(tmp_path / "reports"), "--state-dir", str(tmp_path / "state"),
                    "--log", str(tmp_path / "x.log"), "--data-dir", str(tmp_path / "data"),
                    "--no-llm", *extra])


def _ship_config(tmp_path, exchange_text):
    wanted = tmp_path / "bl" / "w.json"
    answers = tmp_path / "idb" / "internetdb.json"
    return (wanted, answers,
            f"[{idb.SECTION}]\nenabled = true\nmode = delivered\nwanted_file = {wanted}\n"
            f"answers_file = {answers}\n" + exchange_text)


def _fake_request(calls, answers):
    def request(address, base_url, transport, resolver):
        calls.append((address, base_url))
        return answers.get(address, NOT_FOUND)
    return request


def test_cli_ship_looks_up_and_the_agents_read_it(tmp_path, monkeypatch):
    calls: list = []
    monkeypatch.setattr(idb, "_request", _fake_request(calls, {A: (200, answer(A))}))
    monkeypatch.setattr(idb.time, "sleep", lambda s: None)
    wanted, answers, text = _ship_config(tmp_path, f"[{dl.SECTION}]\nenabled = true\n"
                                                   "kind = lookup\n")
    wanted.parent.mkdir(parents=True)
    wanted.write_bytes(dl.wanted_document([A, B], NOW))
    out = _cli(tmp_path, "ship", text)
    assert calls == [(A, idb.BASE_URL), (B, idb.BASE_URL)]
    assert out["internetdb"]["exchange"]["delivered"] == 2
    assert "wanted" not in out["internetdb"]
    assert idb.InternetDbReader(answers).info(A).ports == [22, 80]
    assert (tmp_path / "state" / lx.STATE_FILE).exists()


def test_cli_ship_dry_run_reports_how_many(tmp_path, monkeypatch):
    monkeypatch.setattr(idb, "_request", lambda *a: pytest.fail("network"))
    wanted, answers, text = _ship_config(tmp_path, f"[{dl.SECTION}]\nenabled = true\n"
                                                   "kind = lookup\n")
    wanted.parent.mkdir(parents=True)
    wanted.write_bytes(dl.wanted_document([A, B], NOW))
    out = _cli(tmp_path, "ship", text, "--dry-run")
    assert out["internetdb"]["exchange"]["lookup"]["addresses"] == 2
    assert not answers.exists() and not (tmp_path / "state" / lx.STATE_FILE).exists()


def test_cli_run_all_on_the_agents_side_is_unchanged(tmp_path, monkeypatch):
    # The agents container's config: delivered mode, the exchange off (kind = lookup set
    # or not). It writes the wanted list and never asks.
    monkeypatch.setattr(idb, "_request", lambda *a: pytest.fail("network"))
    write_record(rec(A, seen=datetime.datetime.now(UTC)), tmp_path / "reports")
    base = f"[{idb.SECTION}]\nenabled = true\nmode = delivered\n"
    outs = []
    for extra in ("", f"[{dl.SECTION}]\nenabled = false\nkind = lookup\n"):
        out = _cli(tmp_path, "run-all", base + extra)
        outs.append(out["internetdb"])
    assert outs[0] == outs[1]
    assert outs[0]["wanted"]["status"] == "written" and "exchange" not in outs[0]


def test_cli_ship_with_the_s3_kind_or_the_section_off_is_unchanged(tmp_path, monkeypatch):
    # kind = s3 still goes through run_exchange, exactly as before; the lookup module is
    # not called.
    from test_internetdb_delivered import EXCHANGE, FakeS3, answers as s3_answers, found

    monkeypatch.setattr(idb, "_request", lambda *a: pytest.fail("network"))
    monkeypatch.setattr(lx, "run_lookup_exchange", lambda *a, **k: pytest.fail("lookup"))
    s3 = FakeS3({EXCHANGE["answers_key"]: s3_answers(found(A))})
    monkeypatch.setattr(objectstore, "guarded_client_factory", lambda op: lambda target: s3)
    wanted, answers, text = _ship_config(
        tmp_path, f"[{dl.SECTION}]\n" + "".join(f"{k} = {v}\n" for k, v in EXCHANGE.items()))
    wanted.parent.mkdir(parents=True)
    wanted.write_bytes(dl.wanted_document([A], NOW))
    out = _cli(tmp_path, "ship", text)
    assert out["internetdb"]["exchange"]["accepted"] == 1
    assert "kind" not in out["internetdb"]["exchange"]
    (tmp_path / "off").mkdir()
    off = _cli(tmp_path / "off", "ship", _ship_config(tmp_path / "off", "")[2])
    assert off["internetdb"] == {"mode": "delivered"}
