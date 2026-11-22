"""The reference producer for delivered InternetDB answers (deploy/aws/internetdb_lookup.py).

A fake HTTP layer and a fake object store; documentation addresses treated as public.
"""

from __future__ import annotations

import ast
import datetime
import importlib.util
import ipaddress
import json
import sys
from pathlib import Path

import pytest

from agents import internetdb_delivered as dl
from agents import triage
from agents.addresses import public_for_tests

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "aws" / "internetdb_lookup.py"
spec = importlib.util.spec_from_file_location("internetdb_lookup", SCRIPT)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
A, B, C = "198.51.100.7", "198.51.100.8", "198.51.100.9"


@pytest.fixture(autouse=True)
def _public(monkeypatch):
    nets = ("198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
    monkeypatch.setattr(lk, "TEST_PUBLIC", tuple(ipaddress.ip_network(n) for n in nets))
    with public_for_tests(*nets):
        yield


def wanted(*addresses):
    return dl.wanted_document(list(addresses), NOW)


def shodan(ip, **kw):
    doc = {"ip": ip, "ports": [22, 80], "hostnames": ["a.example.net"], "tags": ["vpn"],
           "cpes": ["cpe:/a:openbsd:openssh:7.4"], "vulns": ["CVE-2017-15906"]}
    doc.update(kw)
    return 200, json.dumps(doc).encode()


class Http:
    def __init__(self, answers=None):
        self.answers = answers or {}
        self.asked = []

    def __call__(self, ip):
        self.asked.append(ip)
        got = self.answers.get(ip, (404, b'{"detail":"No information available"}'))
        if isinstance(got, BaseException):
            raise got
        return got


class Clock:
    def __init__(self):
        self.t = 0.0
        self.sleeps = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


def lookup(wanted_body, previous=None, http=None, now=NOW, **kw):
    clock = Clock()
    return lk.lookup(wanted_body, previous, now=now, fetch=http or Http(), clock=clock,
                     sleep=clock.sleep, **kw)


def sensor_accepts(body, asked, now=NOW):
    accepted, counts = dl.check_answers(body, set(asked), {}, [], now, 30)
    return accepted, counts


# ---- stands alone --------------------------------------------------------------------------

def test_imports_only_the_standard_library_and_boto3_lazily():
    tree = ast.parse(SCRIPT.read_text())
    top = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            top |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            top.add((node.module or "").split(".")[0])
    assert top <= set(sys.stdlib_module_names) | {"__future__"}, top
    nested = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)
              for a in n.names}
    assert nested - top == {"boto3"}
    assert "import agents" not in SCRIPT.read_text() and "from agents" not in SCRIPT.read_text()


def test_rules_match_the_sensor():
    assert lk.HOSTNAME_PATTERN == triage.HOSTNAME_PATTERN
    assert lk.TAG_PATTERN == triage.SHODAN_TAG_PATTERN
    assert lk.CPE_PATTERN == triage.CPE_PATTERN
    assert lk.CVE_PATTERN == triage.CVE_PATTERN
    assert (lk.PORTS_MAX, lk.HOSTNAMES_MAX, lk.HOSTNAME_LEN, lk.TAGS_MAX, lk.TAG_LEN,
            lk.CPES_MAX, lk.CPE_LEN, lk.VULNS_MAX) == (
        triage.SHODAN_PORTS_MAX, triage.SHODAN_HOSTNAMES_MAX, triage.SHODAN_HOSTNAME_LEN,
        triage.SHODAN_TAGS_MAX, triage.SHODAN_TAG_LEN, triage.SHODAN_CPES_MAX,
        triage.SHODAN_CPE_LEN, triage.SHODAN_VULNS_MAX)
    assert lk.MAX_WANTED == dl.MAX_WANTED and lk.MAX_ANSWERS_BYTES == dl.DEFAULT_MAX_BYTES
    assert lk.HOST == "internetdb.shodan.io" and lk.USER_AGENT == "internetdb-client/1"


# ---- the lookup ----------------------------------------------------------------------------

def test_answers_round_trip_through_the_sensor_checks():
    http = Http({A: shodan(A), B: shodan(B, hostnames=["<x>", "B.Example.NET."], ports=[0, 25])})
    body, summary = lookup(wanted(A, B, C), http=http)
    assert summary == {"wanted": 3, "due": 3, "found": 2, "not_found": 1, "refused": 0,
                       "asked": 3, "status": "done", "answers": 3}
    assert http.asked == [A, B, C]
    accepted, counts = sensor_accepts(body, [A, B, C])
    assert counts["dropped"] == 0 and counts["accepted"] == 3
    assert accepted[A]["info"].ports == [22, 80]
    assert accepted[B]["info"].hostnames == ["b.example.net"] and accepted[B]["info"].ports == [25]
    assert accepted[C]["info"].found is False
    doc = json.loads(body)
    assert doc["version"] == 1 and doc["generated_at"] == "2026-11-20T12:00:00Z"
    assert [a["ip"] for a in doc["answers"]] == [A, B, C]


def test_fresh_answers_are_not_asked_again_and_stale_ones_are():
    first, _ = lookup(wanted(A, B), http=Http({A: shodan(A)}))
    http = Http()
    later = NOW + datetime.timedelta(days=1)
    second, summary = lookup(wanted(A, B, C), first, http=http, now=later)
    assert http.asked == [C] and summary["due"] == 1
    assert {a["ip"] for a in json.loads(second)["answers"]} == {A, B, C}
    http = Http()
    lookup(wanted(A, B, C), second, http=http, now=NOW + datetime.timedelta(days=7, hours=1))
    assert set(http.asked) == {A, B}       # C was answered a day later: still fresh


def test_answers_follow_the_wanted_list():
    first, _ = lookup(wanted(A, B), http=Http({A: shodan(A)}))
    second, _ = lookup(wanted(A), first, http=Http())
    assert [a["ip"] for a in json.loads(second)["answers"]] == [A]


def test_pacing_and_caps():
    http = Http()
    addrs = [f"203.0.113.{i}" for i in range(1, 11)]
    clock = Clock()
    body, summary = lk.lookup(wanted(*addrs), None, now=NOW, fetch=http, clock=clock,
                              sleep=clock.sleep, limits={"MAX_PER_RUN": 4})
    assert summary["asked"] == 4 and len(clock.sleeps) == 3
    assert all(s == pytest.approx(1.0) for s in clock.sleeps)
    # The day's cap carries over between runs.
    body, summary = lookup(wanted(*addrs), body, http=Http(),
                           limits={"MAX_PER_RUN": 100, "MAX_PER_DAY": 6})
    assert summary["asked"] == 2
    body, summary = lookup(wanted(*addrs), body, http=Http(),
                           now=NOW + datetime.timedelta(days=1), limits={"MAX_PER_DAY": 6})
    assert summary["asked"] == 4


@pytest.mark.parametrize("failure", [(429, b""), (503, b""), (301, b""), (500, b"x"),
                                     TimeoutError(), OSError("tls")])
def test_a_failure_stops_the_run_and_backs_off(failure):
    http = Http({A: shodan(A), B: failure})
    body, summary = lookup(wanted(A, B, C), http=http)
    assert http.asked == [A, B] and summary["status"] == "stopped"
    assert summary["backoff_minutes"] == 15
    producer = json.loads(body)["producer"]
    assert producer["backoff_until"] == "2026-11-20T12:15:00Z"
    http2 = Http()
    _, summary = lookup(wanted(A, B, C), body, http=http2, now=NOW + datetime.timedelta(minutes=5))
    assert http2.asked == [] and summary["status"] == "backing off"
    body3, summary = lookup(wanted(A, B, C), body, http=Http({B: failure}),
                            now=NOW + datetime.timedelta(minutes=20))
    assert summary["backoff_minutes"] == 30


def test_a_bad_answer_is_not_kept_and_not_asked_again_soon():
    http = Http({A: (200, b"not json"), B: shodan(C), C: (200, b"x" * (lk.MAX_BODY + 1))})
    body, summary = lookup(wanted(A, B, C), http=http)
    assert summary["refused"] == 3 and json.loads(body)["answers"] == []
    http2 = Http()
    lookup(wanted(A, B, C), body, http=http2, now=NOW + datetime.timedelta(hours=1))
    assert http2.asked == []


def test_stops_when_lambda_time_runs_out():
    left = iter([100.0, 100.0, 10.0])
    http = Http()
    _, summary = lookup(wanted(A, B, C), http=http, remaining=lambda: next(left))
    assert http.asked == [A, B] and summary["status"] == "out of time"


@pytest.mark.parametrize("body", [
    None, b"nope", b'{"version": 2, "addresses": []}',
    b'{"version": 1, "addresses": ["10.0.0.1"]}',
    b'{"version": 1, "addresses": ["198.51.100.7", "198.51.100.7"]}',
    b'{"version": 1, "addresses": [" 198.51.100.7"]}',
    json.dumps({"version": 1, "addresses": [f"203.0.113.{i}" for i in range(1, 255)] +
                [f"198.51.100.{i}" for i in range(1, 255)]}).encode(),
])
def test_a_bad_wanted_list_is_refused(body):
    with pytest.raises(lk.Refused):
        lookup(body)


def test_a_hostile_previous_object_starts_empty_or_drops_entries():
    prev = json.dumps({"version": 1, "answers": [
        {"ip": A, "checked_at": "2026-11-20T11:00:00Z", "status": "found", "ports": [22]},
        {"ip": B, "checked_at": "2099-01-01T00:00:00Z", "status": "not_found"},
        {"ip": "10.0.0.1", "checked_at": "2026-11-20T11:00:00Z", "status": "not_found"},
        "junk"], "producer": {"day_count": "many", "backoff_minutes": True,
                              "refused": ["x"]}}).encode()
    http = Http()
    body, summary = lookup(wanted(A, B), prev, http=http)
    assert http.asked == [B] and summary["status"] == "done"
    for junk in (b"[", b"[]", b'{"version": 1, "answers": 5}', b"x" * (lk.MAX_ANSWERS_BYTES + 1)):
        http = Http()
        lookup(wanted(A), junk, http=http)
        assert http.asked == [A]


# ---- stores and entry points ---------------------------------------------------------------

class FakeClient:
    def __init__(self, objects=None):
        self.objects = dict(objects or {})
        self.calls = []

    def get_object(self, **p):
        self.calls.append(("get", p))
        if p["Key"] not in self.objects:
            err = Exception("missing")
            err.response = {"Error": {"Code": "NoSuchKey"}}
            raise err

        class Body:
            def __init__(s, data):
                s.data = data

            def read(s, n):
                return s.data[:n]

            def close(s):
                pass

        return {"Body": Body(self.objects[p["Key"]])}

    def put_object(self, **p):
        self.calls.append(("put", p))
        self.objects[p["Key"]] = p["Body"]


def test_run_with_s3_store_touches_two_keys_only(monkeypatch):
    client = FakeClient({"events/internetdb/wanted.json": wanted(A)})
    w = lk.S3Store("example-bucket", "events/internetdb/wanted.json", "123456789012", client)
    a = lk.S3Store("example-bucket", "internetdb/answers.json", "123456789012", client)
    monkeypatch.setattr(lk, "fetch", Http({A: shodan(A)}))
    clock = Clock()
    summary = lk.run(w, a, now=NOW, fetch=Http({A: shodan(A)}), clock=clock, sleep=clock.sleep)
    assert summary["found"] == 1
    assert [(op, p["Key"]) for op, p in client.calls] == [
        ("get", "events/internetdb/wanted.json"), ("get", "internetdb/answers.json"),
        ("put", "internetdb/answers.json")]
    assert all(p["ExpectedBucketOwner"] == "123456789012" for _, p in client.calls)
    assert sensor_accepts(client.objects["internetdb/answers.json"], [A])[1]["accepted"] == 1


def test_run_without_a_wanted_list_writes_nothing():
    client = FakeClient()
    w = lk.S3Store("b-1", "w.json", None, client)
    a = lk.S3Store("b-1", "a.json", None, client)
    assert lk.run(w, a)["status"] == "no wanted list yet"
    assert [op for op, _ in client.calls] == ["get"]


def test_command_line_with_files(tmp_path, monkeypatch, capsys):
    (tmp_path / "w.json").write_bytes(wanted(A))
    monkeypatch.setattr(lk, "fetch", Http({A: shodan(A)}))
    monkeypatch.setattr(lk.time, "sleep", lambda s: None)
    code = lk.main(["--wanted-file", str(tmp_path / "w.json"),
                    "--answers-file", str(tmp_path / "a.json")])
    assert code == 0 and json.loads(capsys.readouterr().out)["found"] == 1
    doc = json.loads((tmp_path / "a.json").read_text())
    assert doc["answers"][0]["ip"] == A
    (tmp_path / "w.json").write_text("junk")
    assert lk.main(["--wanted-file", str(tmp_path / "w.json"),
                    "--answers-file", str(tmp_path / "a.json")]) == 1


def test_lambda_handler_reads_its_settings_from_the_environment(monkeypatch):
    calls = FakeClient({"events/internetdb/wanted.json": wanted(A, B)})
    real = lk.S3Store
    monkeypatch.setattr(lk, "S3Store",
                        lambda b, k, o, client=None: real(b, k, o, client or calls))
    monkeypatch.setattr(lk, "fetch", Http({A: shodan(A)}))
    monkeypatch.setattr(lk.time, "sleep", lambda s: None)
    for k, v in {"BUCKET": "example-bucket", "WANTED_KEY": "events/internetdb/wanted.json",
                 "ANSWERS_KEY": "internetdb/answers.json",
                 "EXPECTED_BUCKET_OWNER": "123456789012", "MAX_PER_RUN": "1"}.items():
        monkeypatch.setenv(k, v)

    class Context:
        def get_remaining_time_in_millis(self):
            return 600_000

    summary = lk.handler({"BUCKET": "ignored-from-event"}, Context())
    assert summary["asked"] == 1 and summary["found"] == 1
    assert {p["Bucket"] for _, p in calls.calls} == {"example-bucket"}
    assert {p["ExpectedBucketOwner"] for _, p in calls.calls} == {"123456789012"}
    monkeypatch.setenv("MAX_PER_RUN", "5000")
    with pytest.raises(ValueError):
        lk.handler({}, Context())
