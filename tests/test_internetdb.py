"""Shodan InternetDB details for source addresses (agents/internetdb.py).

No real network: the HTTP layer is a fake, the resolver answers a documentation address
treated as public, and the clock is injected.
"""

from __future__ import annotations

import configparser
import datetime
import json
import socket

import pytest

import ui_fixture
from agents import internetdb as idb
from agents.addresses import public_for_tests
from agents.connectors.http import DeadlineExceeded, ResponseTooLarge, UrlTransport
from agents.triage import (
    ShodanInfo,
    TriageRecord,
    load_records,
    run_triage,
    shodan_short,
    with_shodan,
    write_record,
)
from agents.ui.api import Api

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
TODAY = "2026-11-20"
A, B, C, D = "198.51.100.7", "198.51.100.8", "198.51.100.9", "198.51.100.10"


@pytest.fixture(autouse=True)
def _public():
    with public_for_tests("198.51.100.0/24", "203.0.113.0/24"):
        yield


def resolver(host, port, proto=0):
    assert host == idb.HOST and port == 443
    return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", ("203.0.113.80", port))]


def answer(addr, **kw):
    doc = {"ip": addr, "ports": [22, 80], "hostnames": ["a.example.net"], "tags": ["vpn"],
           "cpes": ["cpe:/a:openbsd:openssh:7.4"], "vulns": ["CVE-2017-15906"]}
    doc.update(kw)
    return json.dumps(doc).encode()


NOT_FOUND = (404, b'{"detail":"No information available"}')


class Fake:
    """Answers per address: (status, body) or an exception; anything else is a 404."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.calls = []

    def request(self, method, url, headers, body, timeout, address, max_bytes=None):
        self.calls.append({"method": method, "url": url, "headers": dict(headers),
                           "body": body, "timeout": timeout, "address": address,
                           "max_bytes": max_bytes})
        got = self.answers.get(url.rsplit("/", 1)[1], NOT_FOUND)
        if isinstance(got, BaseException):
            raise got
        return got


class Clock:
    def __init__(self):
        self.t = 100.0
        self.sleeps = []
        self.starts = []

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.t += seconds


def rec(ip, judgement="MALICIOUS", rid=None, seen=NOW, **kw):
    return TriageRecord(kind="session", id=rid or f"s-{ip}-{judgement}", protocol="ssh",
                        src_ip=ip, last_seen=seen.isoformat(), intent="RECONNAISSANCE",
                        stage="DISCOVERY", skill="AUTOMATED", judgement=judgement,
                        narrative="x", **kw)


ON = idb.InternetDbSettings(enabled=True)


def run(tmp_path, records, fake, settings=ON, now=NOW, clock=None, networks=(), **kw):
    clock = clock or Clock()
    return idb.run_lookup(settings, records, list(networks), tmp_path, transport=fake,
                          resolver=resolver, now=now, clock=clock, sleep=clock.sleep, **kw)


def entries(tmp_path):
    return idb.load_state(idb.state_path(tmp_path))["entries"]


# ---- the request -----------------------------------------------------------------------------

def test_request_shape(tmp_path):
    fake = Fake({A: (200, answer(A))})
    out = run(tmp_path, [rec(A)], fake)
    assert out["found"] == 1 and out["status"] == "done"
    [call] = fake.calls
    assert call["method"] == "GET" and call["body"] is None
    assert call["url"] == f"https://internetdb.shodan.io/{A}"
    # Only a generic user agent and Accept: no key, cookie or anything about the source.
    assert call["headers"] == {"User-Agent": "internetdb-client/1", "Accept": "application/json"}
    assert call["timeout"] == 5.0 and call["max_bytes"] == 64 * 1024
    assert call["address"] == "203.0.113.80"          # the pinned, checked address


def test_the_destination_is_not_configurable():
    for key in ("url", "host", "base_url"):
        cp = configparser.ConfigParser()
        cp.read_dict({idb.SECTION: {"enabled": "true", key: "https://elsewhere.example"}})
        with pytest.raises(idb.ConfigError, match="destination is fixed"):
            idb.InternetDbSettings.from_config(cp)


def test_a_resolver_answer_that_is_not_public_is_refused(tmp_path):
    def private(host, port, proto=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", ("10.1.2.3", port))]

    fake = Fake({A: (200, answer(A))})
    out = idb.run_lookup(ON, [rec(A)], [], tmp_path, transport=fake, resolver=private,
                         now=NOW, clock=Clock(), sleep=lambda s: None)
    assert fake.calls == [] and out["stopped"].startswith("request failed")


def test_settings(tmp_path):
    assert idb.InternetDbSettings.from_config(None).enabled is False
    cp = configparser.ConfigParser()
    cp.read_dict({idb.SECTION: {"enabled": "false"}})
    assert idb.InternetDbSettings.from_config(cp).enabled is False
    cp.read_dict({idb.SECTION: {"enabled": "true"}})
    s = idb.InternetDbSettings.from_config(cp)
    assert (s.max_per_run, s.max_per_day, s.cache_days, s.min_interval_seconds) == \
        (100, 2000, 7.0, 1.0)
    for key, bad in (("max_per_run", "0"), ("max_per_day", "x"), ("cache_days", "0.5"),
                     ("min_interval_seconds", "0.1"), ("max_entries", "10"),
                     ("enabled", "maybe")):
        cp2 = configparser.ConfigParser()
        cp2.read_dict({idb.SECTION: {"enabled": "true", key: bad}})
        with pytest.raises(idb.ConfigError):
            idb.InternetDbSettings.from_config(cp2)


# ---- the answer is data ----------------------------------------------------------------------

def test_a_clean_answer_is_kept_as_it_is():
    info = idb.sanitize(answer(A), A, TODAY)
    assert info == ShodanInfo(looked_up=TODAY, ports=[22, 80], hostnames=["a.example.net"],
                              tags=["vpn"], cpes=["cpe:/a:openbsd:openssh:7.4"],
                              vulns=["CVE-2017-15906"])
    assert shodan_short(info) == "ports 22, 80 · tags vpn · 1 known CVE · host a.example.net"


def test_ports_must_be_integers_in_range():
    info = idb.sanitize(answer(A, ports=[0, 1, 65535, 65536, -1, "22", 22.0, True, None, [80],
                                         443, 443]), A, TODAY)
    assert info.ports == [1, 443, 65535]
    many = idb.sanitize(answer(A, ports=list(range(1, 200))), A, TODAY)
    assert many.ports == list(range(1, 51))


@pytest.mark.parametrize("bad", [
    "<script>alert(1)</script>.example", "a b.example", "a_b.example", "-a.example",
    "a-.example", "a..example", " a.example",
    "\u202eevil.example", "ex\u00e4mple.net", "a.example\n",
    "x" * 64 + ".example", ("a" * 60 + ".") * 5, "", ".", 7, None, ["a.example"],
])
def test_hostnames_strict_charset_and_length(bad):
    info = idb.sanitize(answer(A, hostnames=[bad, "ok.example.net"]), A, TODAY)
    assert info.hostnames == ["ok.example.net"]


def test_hostnames_are_lowered_deduplicated_and_capped():
    names = ["Mail.Example.NET.", "mail.example.net"] + [f"h{i}.example.net" for i in range(20)]
    info = idb.sanitize(answer(A, hostnames=names), A, TODAY)
    assert info.hostnames[0] == "mail.example.net" and len(info.hostnames) == 10
    longest = ".".join(["a" * 63] * 3) + "." + "b" * 61               # 253 characters
    assert idb.sanitize(answer(A, hostnames=[longest]), A, TODAY).hostnames == [longest]
    assert idb.sanitize(answer(A, hostnames=[longest + "c"]), A, TODAY).hostnames == []


def test_tags_cpes_and_vulns():
    info = idb.sanitize(answer(
        A,
        tags=["vpn", "Self-Signed", "<b>x</b>", "a" * 41, "has space", "", 3] +
             [f"t{i}" for i in range(30)],
        cpes=["cpe:/a:f5:nginx", "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*",
              "cpe:/a:x\"><img>", "not-a-cpe", "cpe:/" + "a" * 200],
        vulns=["CVE-2017-15906", "cve-2021-44228", "CVE-2021-44228000", "CVE-21-1",
               "CVE-2017-15906", "<CVE-2020-1234>", 2020] +
              [f"CVE-2020-{i:04d}" for i in range(100)]), A, TODAY)
    assert info.tags[:2] == ["vpn", "self-signed"] and len(info.tags) == 20
    assert all(t.isascii() and " " not in t and "<" not in t for t in info.tags)
    assert info.cpes == ["cpe:/a:f5:nginx", "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"]
    assert info.vulns[0] == "CVE-2017-15906" and len(info.vulns) == 50
    assert "cve-2021-44228" not in info.vulns and "CVE-2021-44228000" not in info.vulns
    assert shodan_short(info).startswith("ports 22, 80 · tags vpn, self-signed, t0, t1 +16 · 50+")


@pytest.mark.parametrize("body", [
    b"not json", b"[1, 2]", b'"text"', b"\xff\xfe", b"{" * 100000,
    json.dumps({"ports": [22]}).encode(),                         # no ip
    answer("198.51.100.99"),                                       # another address
    answer(A, ip=["x"]),
])
def test_an_answer_that_is_not_for_the_address_is_refused(body):
    with pytest.raises(idb.BadAnswer):
        idb.sanitize(body, A, TODAY)


def test_wrong_types_for_whole_fields_leave_them_empty():
    info = idb.sanitize(answer(A, ports="22,80", hostnames={"a": 1}, tags=None, cpes=7,
                               vulns="CVE-2017-15906", extra={"deep": [1] * 10}), A, TODAY)
    assert (info.ports, info.hostnames, info.tags, info.cpes, info.vulns) == ([], [], [], [], [])
    assert shodan_short(info) == "nothing listed"


def test_hostile_answer_end_to_end_is_dropped_item_by_item(tmp_path):
    body = answer(A, hostnames=["<img src=x onerror=1>", "evil\x1b[31m.example", "ok.example"],
                  tags=["javascript:alert(1)"], vulns=["CVE-2020-0001 <b>"])
    run(tmp_path, [rec(A)], Fake({A: (200, body)}))
    info = entries(tmp_path)[A]["info"]
    assert info.hostnames == ["ok.example"] and info.tags == [] and info.vulns == []


# ---- statuses and failures -------------------------------------------------------------------

def test_404_is_cached_as_no_data(tmp_path):
    fake = Fake()
    out = run(tmp_path, [rec(A)], fake)
    assert out["not_found"] == 1
    info = entries(tmp_path)[A]["info"]
    assert info.found is False and shodan_short(info) == "no data"
    # Cached: the next run asks nothing.
    assert run(tmp_path, [rec(A)], fake)["status"] == "nothing due" and len(fake.calls) == 1


@pytest.mark.parametrize("status", [429, 500, 502, 503, 301, 302, 403, 422])
def test_rate_limit_server_error_and_redirect_stop_and_back_off(tmp_path, status):
    fake = Fake({A: (status, b"<html>slow down</html>"), B: (200, answer(B))})
    out = run(tmp_path, [rec(A), rec(B, "SUSPICIOUS")], fake)
    assert out["stopped"] == f"HTTP {status}" and out["backoff_minutes"] == 15
    assert len(fake.calls) == 1 and entries(tmp_path) == {}
    # Within the back-off nothing is sent; after it, the run resumes.
    later = NOW + datetime.timedelta(minutes=10)
    assert run(tmp_path, [rec(A)], fake, now=later)["status"] == "backing off"
    assert len(fake.calls) == 1
    out = run(tmp_path, [rec(A)], fake, now=NOW + datetime.timedelta(minutes=16))
    assert out["backoff_minutes"] == 30                       # doubled after a second failure
    fake.answers[A] = (200, answer(A))
    out = run(tmp_path, [rec(A)], fake, now=NOW + datetime.timedelta(minutes=50))
    assert out["status"] == "done"
    assert idb.load_state(idb.state_path(tmp_path))["backoff_minutes"] == 0


def test_a_back_off_far_in_the_future_is_ignored(tmp_path):
    path = idb.state_path(tmp_path)
    path.write_text(json.dumps({"version": 1, "backoff_until": "2030-01-01T00:00:00+00:00",
                                "backoff_minutes": 60, "entries": {}}))
    assert run(tmp_path, [rec(A)], Fake())["looked_up"] == 1


def test_back_off_is_capped_at_a_day(tmp_path):
    fake = Fake({A: (503, b"")})
    now = NOW
    for _ in range(12):
        out = run(tmp_path, [rec(A)], fake, now=now)
        now += datetime.timedelta(minutes=out["backoff_minutes"] + 1)
    assert out["backoff_minutes"] == 24 * 60


@pytest.mark.parametrize("exc", [TimeoutError(), DeadlineExceeded(), socket.timeout(),
                                 ConnectionRefusedError(), OSError("unreachable")])
def test_timeouts_and_unreachable_are_quiet(tmp_path, exc):
    fake = Fake({A: exc})
    out = run(tmp_path, [rec(A), rec(B, "SUSPICIOUS")], fake)
    assert out["stopped"].startswith("request failed") and len(fake.calls) == 1
    assert entries(tmp_path) == {}


def test_oversize_answer_is_not_kept_and_not_asked_again_soon(tmp_path):
    fake = Fake({A: ResponseTooLarge(), B: (200, answer(B))})
    out = run(tmp_path, [rec(A), rec(B, "SUSPICIOUS")], fake)
    assert out["refused"] == 1 and out["found"] == 1
    got = entries(tmp_path)
    assert got[A]["info"] is None and got[B]["info"] is not None
    reader = idb.InternetDbReader(idb.state_path(tmp_path))
    assert reader.info(A) is None and reader.info(B).ports == [22, 80]


class _Resp:
    def __init__(self, status, body):
        self.status, self._body = status, body

    def read(self, n):
        out, self._body = self._body[:n], self._body[n:]
        return out


class _Conn:
    """A stand-in for the pinned HTTPS connection under the real UrlTransport."""
    opened = []

    def __init__(self, status, body):
        self.status, self.body = status, body
        self.requests = []

    def __call__(self, host, port, address, timeout, context):
        _Conn.opened.append((host, port, address))
        return self

    def request(self, method, target, body=None, headers=None):
        self.requests.append((method, target, headers))

    def getresponse(self):
        return _Resp(self.status, self.body)

    def close(self):
        pass


def test_real_transport_caps_the_body_and_follows_no_redirect(tmp_path):
    big = _Conn(200, b"{" + b" " * (70 * 1024) + b"}")
    out = run(tmp_path, [rec(A)], UrlTransport(connection_factory=big))
    assert out["refused"] == 1 and entries(tmp_path)[A]["info"] is None
    hop = _Conn(302, b"")
    _Conn.opened.clear()
    out = run(tmp_path / "r", [rec(A)], UrlTransport(connection_factory=hop))
    assert out["stopped"] == "HTTP 302"
    assert _Conn.opened == [(idb.HOST, 443, "203.0.113.80")]     # one connection, no follow
    assert hop.requests[0][:2] == ("GET", f"/{A}")


# ---- caps and pacing -------------------------------------------------------------------------

def test_per_run_cap_and_pacing(tmp_path):
    ips = [f"198.51.100.{i}" for i in range(20, 30)]
    fake = Fake({ip: (200, answer(ip)) for ip in ips})
    clock = Clock()
    out = run(tmp_path, [rec(ip) for ip in ips], fake,
              settings=idb.InternetDbSettings(enabled=True, max_per_run=4), clock=clock)
    assert out["looked_up"] == 4 and out["due"] == 10 and len(fake.calls) == 4
    # One at a time, a full second apart (the clock does not move on its own).
    assert clock.sleeps == [1.0, 1.0, 1.0]


def test_pacing_does_not_wait_when_time_already_passed(tmp_path):
    class Slow(Fake):
        def __init__(self, clock, *a):
            super().__init__(*a)
            self.clock = clock

        def request(self, *a, **kw):
            self.clock.t += 1.5
            return super().request(*a, **kw)

    clock = Clock()
    run(tmp_path, [rec(A), rec(B)], Slow(clock), clock=clock)
    assert clock.sleeps == []


def test_per_day_cap_across_runs_and_the_next_day(tmp_path):
    ips = [f"198.51.100.{i}" for i in range(40, 50)]
    fake = Fake()
    settings = idb.InternetDbSettings(enabled=True, max_per_run=4, max_per_day=6)
    records = [rec(ip) for ip in ips]
    assert run(tmp_path, records, fake, settings=settings)["looked_up"] == 4
    assert run(tmp_path, records, fake, settings=settings)["looked_up"] == 2
    assert run(tmp_path, records, fake, settings=settings)["status"] == "daily cap reached"
    assert len(fake.calls) == 6
    tomorrow = NOW + datetime.timedelta(days=1)
    assert run(tmp_path, records, fake, settings=settings, now=tomorrow)["looked_up"] == 4


def test_cache_expiry(tmp_path):
    fake = Fake({A: (200, answer(A))})
    run(tmp_path, [rec(A)], fake)
    six = NOW + datetime.timedelta(days=6, hours=23)
    assert run(tmp_path, [rec(A, seen=six)], fake, now=six)["status"] == "nothing due"
    seven = NOW + datetime.timedelta(days=7)
    out = run(tmp_path, [rec(A, seen=seven)], fake, now=seven)
    assert out["looked_up"] == 1 and len(fake.calls) == 2
    assert entries(tmp_path)[A]["info"].looked_up == "2026-11-27"


def test_new_addresses_come_before_refreshes(tmp_path):
    fake = Fake()
    run(tmp_path, [rec(A)], fake)
    later = NOW + datetime.timedelta(days=8)
    one = idb.InternetDbSettings(enabled=True, max_per_run=1)
    run(tmp_path, [rec(A, seen=later), rec(B, "SUSPICIOUS", seen=later)], fake,
        settings=one, now=later)
    assert fake.calls[-1]["url"].endswith(B)


def test_dry_run_sends_and_writes_nothing(tmp_path):
    fake = Fake()
    out = run(tmp_path, [rec(A), rec(B)], fake, dry_run=True)
    assert out == {**out, "status": "would look up", "addresses": 2}
    assert fake.calls == [] and not idb.state_path(tmp_path).exists()


def test_feature_off_does_nothing(tmp_path):
    fake = Fake()
    assert run(tmp_path, [rec(A)], fake, settings=idb.InternetDbSettings()) == \
        {"status": "disabled"}
    assert fake.calls == [] and not idb.state_path(tmp_path).exists()
    assert idb.reader_from_config(None, tmp_path) is None
    cp = configparser.ConfigParser()
    cp.read_dict({idb.SECTION: {"enabled": "true", "url": "https://x.example"}})
    assert idb.reader_from_config(cp, tmp_path) is None


# ---- the bounded file ------------------------------------------------------------------------

def test_state_file_is_bounded_oldest_first(tmp_path):
    state = idb.load_state(idb.state_path(tmp_path))
    for i in range(150):
        state["entries"][f"198.51.100.{i}"] = {
            "checked_at": NOW - datetime.timedelta(minutes=150 - i),
            "info": ShodanInfo(looked_up=TODAY, found=False)}
    idb.save_state(idb.state_path(tmp_path), state, 100)
    kept = entries(tmp_path)
    assert len(kept) == 100 and "198.51.100.49" not in kept and "198.51.100.50" in kept
    assert oct(idb.state_path(tmp_path).stat().st_mode & 0o777) == "0o600"


def test_a_run_keeps_the_file_within_max_entries(tmp_path):
    settings = idb.InternetDbSettings(enabled=True, max_entries=100, max_per_run=1000)
    ips = [f"198.51.100.{i}" for i in range(1, 121)]
    run(tmp_path, [rec(ip) for ip in ips], Fake(), settings=settings)
    assert len(entries(tmp_path)) == 100


def test_a_tampered_file_is_checked_entry_by_entry(tmp_path):
    path = idb.state_path(tmp_path)
    good = {"checked_at": NOW.isoformat(), "info": {"looked_up": TODAY, "ports": [22]}}
    path.write_text(json.dumps({"version": 1, "day": TODAY, "day_count": 3, "entries": {
        A: good,
        B: {"checked_at": NOW.isoformat(),
            "info": {"looked_up": TODAY, "hostnames": ["<img src=x onerror=1>"]}},
        C: {"checked_at": "yesterday", "info": {"looked_up": TODAY}},
        "10.0.0.1": good, "not an address": good, "198.51.100.010": good,
        D: {"checked_at": NOW.isoformat(), "info": {"looked_up": TODAY, "ports": [70000]}},
    }}))
    reader = idb.InternetDbReader(path)
    assert reader.info(A).ports == [22]
    assert [reader.info(x) for x in (B, C, D, "10.0.0.1")] == [None] * 4
    path.write_text("{garbage")
    assert reader.info(A) is None
    path.unlink()
    assert reader.info(A) is None


def test_the_reader_never_raises_and_maps_addresses(tmp_path):
    run(tmp_path, [rec(A)], Fake({A: (200, answer(A))}))
    reader = idb.InternetDbReader(idb.state_path(tmp_path))
    assert reader(f"::ffff:{A}").ports == [22, 80]
    for odd in (None, 7, "", "x" * 100, "198.51.100.0/24", f"{A}%eth0"):
        assert reader.info(odd) is None


# ---- which addresses -------------------------------------------------------------------------

def test_address_selection():
    old = NOW - datetime.timedelta(days=8)
    records = [
        rec(A, "BENIGN"),                                         # not interesting
        rec(B, "BENIGN", honeytokens=["aws_backup_key"]),         # a honeytoken: interesting
        rec(C, "SUSPICIOUS", unverified_source=True),             # may be forged
        rec("10.0.0.5", "MALICIOUS"),                             # private
        rec("100.64.0.9", "MALICIOUS"),                           # shared (CGNAT)
        rec("192.0.2.1", "MALICIOUS"),                            # documentation, not public
        rec("198.51.100.30", "MALICIOUS", seen=old),              # outside the window
        rec("198.51.100.40", "MALICIOUS"),                        # never_act_on
        rec("198.51.100.50", "SUSPICIOUS"),
        rec(f"::ffff:{D}", "MALICIOUS"),                          # IPv4-mapped
        rec("unverified", "MALICIOUS"),
        rec("198.51.100.50", "MALICIOUS", rid="again"),           # once only
    ]
    import ipaddress
    chosen = idb.select_addresses(records, [ipaddress.ip_network("198.51.100.40/32")], NOW, 7)
    assert set(chosen) == {B, D, "198.51.100.50"}
    assert chosen.index(B) == 0                                   # honeytokens rank first
    assert len(chosen) == len(set(chosen))


def test_campaign_networks_are_not_looked_up():
    assert idb.lookup_address("2001:db8::/64") is None
    assert idb.lookup_address("198.51.100.0/24") is None
    assert idb.lookup_address(A) == A


# ---- stored on the record --------------------------------------------------------------------

def test_with_shodan_fills_only_missing_and_never_raises():
    info = ShodanInfo(looked_up=TODAY, ports=[22])
    later = ShodanInfo(looked_up="2026-11-27", ports=[443])
    r = rec(A)
    assert with_shodan(r, lambda a: info).src_shodan == info
    stored = r.model_copy(update={"src_shodan": info})
    assert with_shodan(stored, lambda a: later).src_shodan == info
    assert with_shodan(r, None).src_shodan is None
    agg = r.model_copy(update={"src_ip": "unverified"})
    assert with_shodan(agg, lambda a: pytest.fail("looked up")).src_shodan is None

    def boom(address):
        raise RuntimeError("x")

    assert with_shodan(r, boom).src_shodan is None


def test_record_file_stores_the_answer_and_is_unchanged_without_it(tmp_path):
    info = ShodanInfo(looked_up=TODAY, ports=[22], tags=["vpn"])
    write_record(rec(A), tmp_path / "a")
    write_record(with_shodan(rec(A), lambda a: None), tmp_path / "b")
    write_record(with_shodan(rec(A), lambda a: info), tmp_path / "c")
    files = [next((tmp_path / d / "sessions").glob("*.json")).read_text() for d in "abc"]
    assert files[0] == files[1] and "src_shodan" not in files[0]
    raw = json.loads(files[2])["src_shodan"]
    assert raw == {"looked_up": TODAY, "found": True, "ports": [22], "hostnames": [],
                   "tags": ["vpn"], "cpes": [], "vulns": []}
    assert load_records(tmp_path / "c")[0].src_shodan == info


def test_triage_reads_the_file_when_it_writes_a_record(tmp_path):
    from test_enrich import NOW as ENRICH_NOW, _toll_fraud, write_log

    log = write_log(tmp_path / "events.jsonl", _toll_fraud())
    asked = []

    def reader(address):
        asked.append(address)
        return ShodanInfo(looked_up=TODAY, ports=[5060])

    run_triage(log, tmp_path / "reports", None, now=ENRICH_NOW, shodan=reader)
    raw = json.loads(next((tmp_path / "reports" / "campaigns").glob("*.json")).read_text())
    assert asked == ["198.51.100.7"] and raw["src_shodan"]["ports"] == [5060]


# ---- the console -----------------------------------------------------------------------------

@pytest.fixture
def tree(tmp_path):
    return ui_fixture.build_tree(tmp_path)


def _keys(value, name):
    if isinstance(value, dict):
        return [v for k, v in value.items() if k == name] + \
            [x for v in value.values() for x in _keys(v, name)]
    if isinstance(value, list):
        return [x for v in value for x in _keys(v, name)]
    return []


def _ok(api, path, **query):
    status, body = api.get(path, query)
    assert status == 200, (path, body)
    return body


KNOWN = {"198.51.100.7": ShodanInfo(looked_up=TODAY, ports=[22, 80, 8080], tags=["vpn"],
                                    vulns=["CVE-2017-15906", "CVE-2018-15473", "CVE-2016-6210"],
                                    hostnames=["a.example.net"]),
         "198.51.100.21": ShodanInfo(looked_up=TODAY, found=False)}


def test_console_off_has_no_shodan_keys(tree):
    api = Api(tree.api_paths(), cache_seconds=0)
    for path, query in (("/api/overview", {"window": "7d"}), ("/api/records", {}),
                        ("/api/queue", {"all": "1"}), ("/api/decoy", {}),
                        (f"/api/records/{tree.ids['session_a']}", {})):
        body = _ok(api, path, **query)
        assert _keys(body, "shodan") == [] and _keys(body, "src_shodan") == [], path


def test_console_record_page_live_and_stored(tree):
    api = Api(tree.api_paths(), cache_seconds=0, shodan=KNOWN.get)
    rid = tree.ids["session_a"]
    body = _ok(api, f"/api/records/{rid}")
    assert body["shodan"]["short"] == \
        "ports 22, 80, 8080 · tags vpn · 3 known CVEs · host a.example.net"
    assert body["shodan"]["looked_up"] == TODAY and body["shodan_stored"] is False
    assert "src_shodan" not in body["record"]
    stored = ShodanInfo(looked_up="2026-11-01", ports=[443])
    path = tree.reports / "sessions" / f"{rid}.json"
    record = TriageRecord.model_validate_json(path.read_text())
    write_record(record.model_copy(update={"src_shodan": stored}), tree.reports)
    body = _ok(api, f"/api/records/{rid}")
    assert body["shodan"]["ports"] == [443] and body["shodan_stored"] is True
    assert body["record"]["src_shodan"]["looked_up"] == "2026-11-01"


def test_console_sources_views(tree):
    api = Api(tree.api_paths(), cache_seconds=0, shodan=KNOWN.get)
    top = {s["src_ip"]: s.get("shodan") for s in
           _ok(api, "/api/overview", window="7d")["top_sources"]}
    assert top["198.51.100.7"]["ports"] == [22, 80, 8080]
    assert top["198.51.100.21"]["short"] == "no data" and top["198.51.100.20"] is None
    decoy = _ok(api, "/api/decoy")["source_state"]["items"]
    assert decoy[0]["key"] == "198.51.100.7" and decoy[0]["shodan"]["tags"] == ["vpn"]


def test_console_answers_never_enter_summaries_or_view_hashes(tree):
    plain = _ok(Api(tree.api_paths(), cache_seconds=0), "/api/queue", all="1")["items"]
    known = _ok(Api(tree.api_paths(), cache_seconds=0, shodan=KNOWN.get), "/api/queue",
                all="1")["items"]
    assert [c["view_hash"] for c in plain] == [c["view_hash"] for c in known]
    assert _keys(known, "shodan") == []
    records = _ok(Api(tree.api_paths(), cache_seconds=0, shodan=KNOWN.get), "/api/records")
    assert _keys(records, "shodan") == []


def test_console_reader_that_raises_is_harmless(tree):
    def boom(address):
        raise RuntimeError("gone")

    api = Api(tree.api_paths(), cache_seconds=0, shodan=boom)
    for path, query in (("/api/overview", {"window": "7d"}), ("/api/decoy", {}),
                        (f"/api/records/{tree.ids['session_a']}", {})):
        assert _keys(_ok(api, path, **query), "shodan") == []


def test_the_page_uses_text_nodes_and_credits_shodan():
    from pathlib import Path

    js = (Path(__file__).resolve().parents[1] / "agents/ui/static/app.js").read_text()
    start = js.index("function shodanNode")
    body = js[start:js.index("\n  }\n", start)]
    assert "innerHTML" not in body and "insertAdjacentHTML" not in body
    assert "Data from Shodan InternetDB." in body and "looked_up" in body


# ---- the run ---------------------------------------------------------------------------------

def test_cli_ship_runs_the_lookup_with_never_act_on(tmp_path, monkeypatch):
    from agents.__main__ import run as cli_run

    reports = tmp_path / "reports"
    write_record(rec(A), reports)
    write_record(rec(B, "SUSPICIOUS"), reports)
    cfg = tmp_path / "config.ini"
    cfg.write_text(f"[{idb.SECTION}]\nenabled = true\n[respond]\nnever_act_on = {B}\n")
    sent = []

    def fake_request(address, base_url, transport, resolver):
        assert base_url == idb.BASE_URL
        sent.append(address)
        return 200, answer(address)

    monkeypatch.setattr(idb, "_request", fake_request)
    monkeypatch.setattr(idb.time, "sleep", lambda s: None)
    # The records were seen "now"; the CLI uses the real clock.
    for r in (rec(A, seen=datetime.datetime.now(UTC)),
              rec(B, "SUSPICIOUS", seen=datetime.datetime.now(UTC))):
        write_record(r, reports)
    results = cli_run(["ship", "--config", str(cfg), "--reports-dir", str(reports),
                       "--state-dir", str(tmp_path / "state"), "--log", str(tmp_path / "x.log"),
                       "--data-dir", str(tmp_path / "data")])
    assert results["internetdb"]["found"] == 1 and sent == [A]
    assert idb.InternetDbReader(idb.state_path(tmp_path / "state")).info(A).ports == [22, 80]


def test_cli_ship_with_the_feature_off_has_no_lookup(tmp_path, monkeypatch):
    from agents.__main__ import run as cli_run

    monkeypatch.setattr(idb, "_request", lambda *a: pytest.fail("network"))
    cfg = tmp_path / "config.ini"
    cfg.write_text("[agents]\n")
    results = cli_run(["ship", "--config", str(cfg), "--reports-dir", str(tmp_path / "r"),
                       "--state-dir", str(tmp_path / "s"), "--log", str(tmp_path / "x.log"),
                       "--data-dir", str(tmp_path / "data")])
    assert "internetdb" not in results


def test_cli_bad_never_act_on_means_no_lookups(tmp_path, monkeypatch):
    from agents.__main__ import run as cli_run

    monkeypatch.setattr(idb, "_request", lambda *a: pytest.fail("network"))
    cfg = tmp_path / "config.ini"
    cfg.write_text(f"[{idb.SECTION}]\nenabled = true\n[respond]\nnever_act_on = nonsense\n")
    results = cli_run(["ship", "--config", str(cfg), "--reports-dir", str(tmp_path / "r"),
                       "--state-dir", str(tmp_path / "s"), "--log", str(tmp_path / "x.log"),
                       "--data-dir", str(tmp_path / "data")])
    assert "no lookups" in results["internetdb"]["error"]
