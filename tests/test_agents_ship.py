"""Event export to S3: key layout, cursor, budgets, failure handling and password handling.

Every test uses an injected fake S3 client; no real client is created or imported.
"""

from __future__ import annotations

import ast
import configparser
import datetime
import json
import os
import re
from pathlib import Path

import pytest
from agent_fakes import ssh_session, trap_event, write_log

import agents.__main__ as cli
from agents import ship
from listeners.events import ListenerEvent

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.datetime(2026, 11, 2, 7, 30, 15, tzinfo=datetime.timezone.utc)
SEED = "0123456789abcdef0123456789abcdef"


class FakeS3:
    """Records PutObject calls. Any other attribute access fails the test."""

    def __init__(self, fail_on: tuple[int, ...] = (), exc: Exception | None = None) -> None:
        self.puts: list[dict] = []
        self.fail_on = fail_on
        self.exc = exc
        self.calls = 0

    def put_object(self, **params):
        self.calls += 1
        if self.calls in self.fail_on:
            raise self.exc or RuntimeError("boom")
        self.puts.append(params)
        return {}

    def __getattr__(self, name):
        raise AssertionError(f"S3 client used for {name}; only put_object is allowed")


class ClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": "details that are not logged"}}


class Factory:
    def __init__(self, client) -> None:
        self.client = client
        self.created = 0

    def __call__(self, settings):
        self.created += 1
        return self.client


def _cp(**opts) -> configparser.ConfigParser:
    cp = configparser.ConfigParser()
    cp.read_dict({"connector.s3_events": {"enabled": "true", "bucket": "example-honeypot-events",
                                           **{k: str(v) for k, v in opts.items()}}})
    return cp


def _settings(**opts) -> ship.ShipSettings:
    return ship.ShipSettings.from_config(_cp(**opts))


def _ftp(n: int, password: str = "hunter2") -> list[dict]:
    return [trap_event("ftp", "auth_attempt", "192.0.2.4", f"f{i}", minutes=i,
                       username="admin", password=password, success=False) for i in range(n)]


def _run(tmp_path, settings, client=None, log=None, **kw):
    log = log or tmp_path / "log.jsonl"
    factory = Factory(client if client is not None else FakeS3())
    res = ship.run_ship(settings, str(log), tmp_path / "state", seed=kw.pop("seed", SEED),
                        sensor=kw.pop("sensor", "sensor-a"), client_factory=factory,
                        now=kw.pop("now", NOW), **kw)
    return res, factory


def _lines(put: dict) -> list[dict]:
    body = put["Body"]
    assert body.endswith(b"\n")
    return [json.loads(x) for x in body.decode().splitlines()]


# ---- configuration ---------------------------------------------------------------------------

def test_export_is_off_by_default_and_a_disabled_export_creates_no_client(tmp_path):
    assert ship.ShipSettings.from_config(configparser.ConfigParser()).enabled is False
    cp = configparser.ConfigParser()
    cp.read_dict({"connector.s3_events": {"enabled": "false", "bucket": "example-honeypot-events"}})
    settings = ship.ShipSettings.from_config(cp)
    write_log(tmp_path / "log.jsonl", _ftp(3))
    res, factory = _run(tmp_path, settings)
    assert res == {"status": "disabled"} and factory.created == 0
    assert not (tmp_path / "state").exists()


def test_settings_defaults():
    s = _settings()
    assert (s.prefix, s.source, s.layout, s.passwords) == ("events/", "aws.honeypot", "wrapped", "hash")
    assert (s.max_events_per_object, s.max_objects_per_run, s.max_bytes_per_object) == \
        (5000, 50, 5 * 1024 * 1024)
    assert s.region is None and s.bucket_owner is None


@pytest.mark.parametrize("opts", [
    {"bucket": ""}, {"bucket": "Bad_Bucket"}, {"prefix": "../up/"}, {"prefix": "/abs/"},
    {"layout": "nested"}, {"passwords": "rot13"}, {"region": "not a region"},
    {"bucket_owner": "12345"}, {"source": "has space"}, {"max_events_per_object": "0"},
    {"max_objects_per_run": "lots"}, {"max_bytes_per_object": "10"}, {"timeout": "120"},
])
def test_invalid_settings_are_refused_without_echoing_values(opts):
    with pytest.raises(ship.ConfigError) as err:
        _settings(**opts)
    for value in opts.values():
        if value and not value.isdigit():
            assert value not in str(err.value)


def test_prefix_gets_a_trailing_slash():
    assert _settings(prefix="honeypot/events").prefix == "honeypot/events/"
    assert _settings(prefix="").prefix == ""


def test_the_s3_section_is_not_reported_as_an_unknown_connector(tmp_path):
    from agents.connectors import Connectors

    assert Connectors(_cp(), tmp_path).errors == []


# ---- objects ---------------------------------------------------------------------------------

def test_wrapped_objects_use_the_documented_key_layout(tmp_path):
    write_log(tmp_path / "log.jsonl", _ftp(3))
    s3 = FakeS3()
    res, _ = _run(tmp_path, _settings(bucket_owner="123456789012"), s3)
    assert res["objects"] == 1 and res["events"] == 3
    (put,) = s3.puts
    epoch = int(NOW.timestamp())
    assert re.fullmatch(rf"events/2026/11/02/07-{epoch}-sensor-a-0-[0-9a-f]{{8}}\.jsonl",
                        put["Key"])
    assert put["Bucket"] == "example-honeypot-events"
    assert put["ExpectedBucketOwner"] == "123456789012"
    lines = _lines(put)
    assert [set(x) for x in lines] == [{"source", "detail"}] * 3
    assert lines[0]["source"] == "aws.honeypot"
    assert lines[0]["detail"]["task_name"] == "f0"


def test_flat_layout_writes_the_event_itself_and_owner_is_optional(tmp_path):
    write_log(tmp_path / "log.jsonl", _ftp(2))
    s3 = FakeS3()
    _run(tmp_path, _settings(layout="flat", passwords="clear"), s3)
    (put,) = s3.puts
    assert "ExpectedBucketOwner" not in put
    assert [x["task_name"] for x in _lines(put)] == ["f0", "f1"]
    assert _lines(put)[0]["password"] == "hunter2"


def test_runs_in_the_same_second_never_reuse_a_key(tmp_path):
    log = write_log(tmp_path / "log.jsonl", _ftp(1))
    s3 = FakeS3()
    _run(tmp_path, _settings(), s3)
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(_ftp(2)[1]) + "\n")
    _run(tmp_path, _settings(), s3)                 # same NOW, same sensor, n = 0 again
    keys = [p["Key"] for p in s3.puts]
    assert len(keys) == 2 and len(set(keys)) == 2
    epoch = int(NOW.timestamp())
    for key in keys:
        assert re.fullmatch(rf"events/2026/11/02/07-{epoch}-sensor-a-0-[0-9a-f]{{8}}\.jsonl", key)


def test_objects_split_on_event_and_byte_limits(tmp_path):
    write_log(tmp_path / "log.jsonl", _ftp(7))
    s3 = FakeS3()
    res, _ = _run(tmp_path, _settings(max_events_per_object=3), s3)
    assert [len(_lines(p)) for p in s3.puts] == [3, 3, 1]
    assert [p["Key"].rsplit("-", 2)[1] for p in s3.puts] == ["0", "1", "2"]

    one = len(s3.puts[0]["Body"]) // 3
    (tmp_path / "state" / ship.CURSOR_FILE).unlink()
    s3 = FakeS3()
    _run(tmp_path, _settings(max_bytes_per_object=max(1024, one * 2 + 10)), s3)
    assert all(len(p["Body"]) <= max(1024, one * 2 + 10) for p in s3.puts)
    assert sum(len(_lines(p)) for p in s3.puts) == 7


def test_only_complete_lines_are_shipped_and_the_rest_waits(tmp_path):
    log = write_log(tmp_path / "log.jsonl", _ftp(2))
    partial = json.dumps(_ftp(3)[2])
    with open(log, "a", encoding="utf-8") as f:
        f.write(partial[:40])
    s3 = FakeS3()
    _run(tmp_path, _settings(), s3)
    assert len(_lines(s3.puts[0])) == 2
    with open(log, "a", encoding="utf-8") as f:
        f.write(partial[40:] + "\n")
    s3 = FakeS3()
    _run(tmp_path, _settings(), s3)
    assert [x["detail"]["task_name"] for x in _lines(s3.puts[0])] == ["f2"]


def test_malformed_lines_are_skipped_and_counted(tmp_path):
    write_log(tmp_path / "log.jsonl", _ftp(1), extra_lines=["not json", "[1, 2]", ""])
    s3 = FakeS3()
    res, _ = _run(tmp_path, _settings(), s3)
    assert res["skipped_malformed"] == 2 and res["events"] == 1
    s3 = FakeS3()
    res, factory = _run(tmp_path, _settings(), s3)
    assert res["objects"] == 0 and factory.created == 0


def test_nothing_new_creates_no_client(tmp_path):
    write_log(tmp_path / "log.jsonl", [])
    res, factory = _run(tmp_path, _settings())
    assert res["objects"] == 0 and factory.created == 0


# ---- cursor and delivery ---------------------------------------------------------------------

def test_cursor_advances_only_after_a_successful_put(tmp_path):
    log = write_log(tmp_path / "log.jsonl", _ftp(4))
    s3 = FakeS3()
    _run(tmp_path, _settings(), s3)
    assert len(s3.puts) == 1
    s3 = FakeS3()
    res, factory = _run(tmp_path, _settings(), s3)
    assert res["objects"] == 0 and factory.created == 0          # nothing re-sent
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(_ftp(5)[4]) + "\n")
    s3 = FakeS3()
    _run(tmp_path, _settings(), s3)
    assert [x["detail"]["task_name"] for x in _lines(s3.puts[0])] == ["f4"]


def test_a_log_replaced_during_a_run_is_not_claimed_by_the_cursor(tmp_path):
    from agents.sessions import Cursor

    log = write_log(tmp_path / "log.jsonl", _ftp(3))

    class Swapping(FakeS3):
        def put_object(self, **params):
            result = super().put_object(**params)
            log.rename(tmp_path / "old.jsonl")             # rotated while the run is shipping
            write_log(log, _ftp(3, password="other1"))     # a new file of about the same size
            return result

    _run(tmp_path, _settings(), Swapping())
    cursor = Cursor(tmp_path / "state" / ship.CURSOR_FILE)
    assert cursor.inode is None and cursor.tail is None    # confirms no file and no content
    s3 = FakeS3()
    _run(tmp_path, _settings(), s3)                        # the next run starts the new file
    assert [x["detail"]["task_name"] for p in s3.puts for x in _lines(p)] == ["f0", "f1", "f2"]


def test_the_cursor_records_the_boundary_it_shipped_to(tmp_path):
    from agents.sessions import Cursor, sample_log

    log = write_log(tmp_path / "log.jsonl", _ftp(3))
    _run(tmp_path, _settings(), FakeS3())
    cursor = Cursor(tmp_path / "state" / ship.CURSOR_FILE)
    sample = sample_log(log, [cursor.offset])
    assert cursor.offset == sample.end == log.stat().st_size
    assert cursor.tail == sample.tails[cursor.offset] is not None
    assert cursor.start_offset(log) == cursor.offset


def test_a_legacy_cursor_at_the_end_of_the_log_recovers_without_new_events(tmp_path):
    """A cursor from before the fingerprint, exactly at EOF: the next successful run sends the
    log once more (delivery is at least once), records the fingerprint, and is then stable."""
    from agents.rotation import rotation_status
    from agents.sessions import Cursor

    log = write_log(tmp_path / "log.jsonl", _ftp(3))
    _run(tmp_path, _settings(), FakeS3())
    path = tmp_path / "state" / ship.CURSOR_FILE
    legacy = json.loads(path.read_text())
    for key in ("tail", "size", "mtime_ns"):
        legacy.pop(key)
    path.write_text(json.dumps(legacy))
    assert Cursor(path).offset == log.stat().st_size                      # exactly at EOF
    status = rotation_status({}, log, tmp_path / "state", ["ship"])
    assert status["safe"] is False and status["readers"]["ship"]["state"] == "unverified"

    s3 = FakeS3()
    res, _ = _run(tmp_path, _settings(), s3)                              # no new events
    assert res["start_offset"] == 0
    assert [x["detail"]["task_name"] for p in s3.puts for x in _lines(p)] == ["f0", "f1", "f2"]
    assert Cursor(path).tail is not None
    assert rotation_status({}, log, tmp_path / "state", ["ship"])["safe"] is True
    s3 = FakeS3()
    _run(tmp_path, _settings(), s3)
    assert s3.puts == []                                                  # stable afterwards


def test_a_ship_run_whose_pre_read_sample_failed_certifies_nothing(tmp_path, monkeypatch):
    from agents.sessions import Cursor

    write_log(tmp_path / "log.jsonl", _ftp(3))
    monkeypatch.setattr(Cursor, "sample", staticmethod(lambda *a, **k: None))
    s3 = FakeS3()
    _run(tmp_path, _settings(), s3)
    assert len(s3.puts) == 1                                              # it still shipped
    cursor = Cursor(tmp_path / "state" / ship.CURSOR_FILE)
    assert cursor.inode is None and cursor.tail is None


def test_a_log_rewritten_in_place_during_a_run_is_not_claimed_by_the_cursor(tmp_path):
    from agents.sessions import Cursor

    log = write_log(tmp_path / "log.jsonl", _ftp(3))

    class Rewriting(FakeS3):
        def put_object(self, **params):
            result = super().put_object(**params)
            data = log.read_bytes()
            log.write_bytes(data.replace(b"hunter2", b"hunter3"))        # same size and inode
            return result

    _run(tmp_path, _settings(), Rewriting())
    cursor = Cursor(tmp_path / "state" / ship.CURSOR_FILE)
    assert cursor.inode is None and cursor.tail is None


def test_a_failed_put_is_recorded_and_the_lines_are_sent_again(tmp_path, caplog):
    write_log(tmp_path / "log.jsonl", _ftp(5))
    s3 = FakeS3(fail_on=(2,), exc=ClientError("AccessDenied"))
    res, _ = _run(tmp_path, _settings(max_events_per_object=2), s3)
    assert res["objects"] == 1 and res["error"] == "PutObject failed: ClientError: AccessDenied"
    assert "details that are not logged" not in caplog.text
    events = [json.loads(x) for x in
              (tmp_path / "state" / ship.EVENTS_FILE).read_text().splitlines()]
    assert events[-1]["event"] == "s3_put_failed" and events[-1]["error"].endswith("AccessDenied")

    s3 = FakeS3()
    res, _ = _run(tmp_path, _settings(max_events_per_object=2), s3)
    shipped = [x["detail"]["task_name"] for p in s3.puts for x in _lines(p)]
    assert shipped == ["f2", "f3", "f4"]                       # at least once, from the failure


def test_a_client_that_cannot_be_created_is_a_reported_failure(tmp_path):
    write_log(tmp_path / "log.jsonl", _ftp(1))

    def broken(settings):
        raise RuntimeError("no credentials")

    res = ship.run_ship(_settings(), str(tmp_path / "log.jsonl"), tmp_path / "state",
                        seed=SEED, sensor="s", client_factory=broken, now=NOW)
    assert res["error"] == "PutObject failed: RuntimeError" and res["objects"] == 0


def test_run_budget_stops_and_the_next_run_continues(tmp_path):
    write_log(tmp_path / "log.jsonl", _ftp(5))
    s3 = FakeS3()
    res, _ = _run(tmp_path, _settings(max_events_per_object=1, max_objects_per_run=2), s3)
    assert res["objects"] == 2 and res["more_pending"] is True
    s3 = FakeS3()
    res, _ = _run(tmp_path, _settings(max_events_per_object=1, max_objects_per_run=2), s3)
    assert [x["detail"]["task_name"] for p in s3.puts for x in _lines(p)] == ["f2", "f3"]


def test_a_rotated_log_is_shipped_from_the_start(tmp_path):
    log = write_log(tmp_path / "log.jsonl", _ftp(3))
    _run(tmp_path, _settings(), FakeS3())
    os.rename(log, tmp_path / "log.jsonl.1")
    write_log(tmp_path / "log.jsonl", _ftp(1, password="x"))
    s3 = FakeS3()
    _run(tmp_path, _settings(), s3)
    assert [x["detail"]["task_name"] for x in _lines(s3.puts[0])] == ["f0"]


def test_dry_run_reports_keys_without_a_client_or_cursor(tmp_path):
    write_log(tmp_path / "log.jsonl", _ftp(3))
    res, factory = _run(tmp_path, _settings(), dry_run=True)
    assert res["objects"] == 1 and res["keys"][0].startswith("events/2026/11/02/07-")
    assert factory.created == 0 and not (tmp_path / "state" / ship.CURSOR_FILE).exists()


# ---- passwords -------------------------------------------------------------------------------

def test_hash_is_salted_per_sensor_and_stable_within_one(tmp_path):
    k1, k2 = ship.password_key(SEED), ship.password_key("f" * 32)
    h = ship.hash_secret(k1, "hunter2")
    assert h == ship.hash_secret(k1, "hunter2") and h != ship.hash_secret(k2, "hunter2")
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", h)
    import hashlib

    assert h[len("sha256:"):] != hashlib.sha256(b"hunter2").hexdigest()


def test_hash_mode_without_a_sensor_seed_ships_nothing(tmp_path):
    write_log(tmp_path / "log.jsonl", _ftp(1))
    res, factory = _run(tmp_path, _settings(), seed=None)
    assert "sensor seed" in res["error"] and factory.created == 0


def _event(protocol, event="auth_attempt", **fields):
    return trap_event(protocol, event, "192.0.2.9", "t1", **fields)


SECRET_CASES = [
    ("ssh login", ssh_session("s1", "192.0.2.1", [], password="sshpw1")[1], [("password",)]),
    ("ftp PASS", _event("ftp", password="ftppw1"), [("password",)]),
    ("ftp PASS line", _event("ftp", "command", data={"cmd": "PASS", "input": "PASS ftppw1\\x0d"}),
     [("data", "input")]),
    ("smtp AUTH", _event("smtp", password="smtppw1", data={"mechanism": "PLAIN"}), [("password",)]),
    ("redis AUTH", _event("redis", password="redispw1"), [("password",)]),
    ("redis HELLO AUTH", _event("redis", "command",
                                data={"cmd": "HELLO", "input": "HELLO 3 AUTH u redispw1"}),
     [("data", "input")]),
    ("redis CONFIG requirepass", _event("redis", "command", data={
        "cmd": "CONFIG", "input": "CONFIG SET requirepass redispw1"}), [("data", "input")]),
    ("http form", _event("http", password="httppw1", data={"method": "form"}), [("password",)]),
    ("http body", _event("http", "command", data={"method": "POST",
                                                  "body": "user=a&password=httppw1"}),
     [("data", "body")]),
    ("http raw authorization", _event("http", "command", data={"auth_raw": "NTLM abcdef"}),
     [("data", "auth_raw")]),
    ("http captured body", _event("http", "command", data={
        "capture_label": "http_body", "part_00": "{\"password\": \"httppw1\"}"}),
     [("data", "part_00")]),
    ("ftp captured PASS", _event("ftp", "command", data={
        "capture_label": "ftp_command", "part_00": "PASS ftppw1\\x0d\\x0a"}),
     [("data", "part_00")]),
    ("sip register", _event("sip", password="sippw1", data={"response": "a" * 32,
                                                            "nonce": "n"}),
     [("password",), ("data", "response")]),
    ("sip invite", _event("sip", "invite", data={"auth_password": "sippw1"}),
     [("data", "auth_password")]),
    ("mysql", _event("mysql", password="<unrecovered>", data={"auth_response": "ab" * 20,
                                                              "salt": "00"}),
     [("password",), ("data", "auth_response")]),
    ("postgres", _event("postgres", password="pgpw1", data={"md5_response": "md5abc",
                                                            "param_password": "pgpw2"}),
     [("password",), ("data", "md5_response"), ("data", "param_password")]),
    ("mssql", _event("mssql", password="sqlpw1"), [("password",)]),
    ("telnet", _event("telnet", password="telpw1"), [("password",)]),
]


def _get(rec, path):
    return rec[path[0]] if len(path) == 1 else rec["data"].get(path[1])


@pytest.mark.parametrize("name,rec,paths", SECRET_CASES, ids=[c[0] for c in SECRET_CASES])
def test_every_password_field_is_hashed_or_dropped(name, rec, paths):
    key = ship.password_key(SEED)
    hashed = ship.protect(rec, "hash", key)
    dropped = ship.protect(rec, "drop", key)
    for path in paths:
        original = _get(rec, path)
        assert _get(hashed, path) == ship.hash_secret(key, original)
        container = dropped if len(path) == 1 else dropped["data"]
        assert path[-1] not in container
    assert ship.protect(rec, "clear", key) == rec


def test_non_secret_fields_are_left_alone():
    rec = _event("redis", "command", data={"cmd": "CONFIG", "input": "CONFIG SET dir /tmp",
                                           "honeytoken": "aws-key-1",
                                           "password_recovered": True})
    assert ship.protect(rec, "hash", ship.password_key(SEED)) == rec
    blank = ssh_session("s1", "192.0.2.1", [], password="")[1]
    assert ship.protect(blank, "hash", ship.password_key(SEED))["password"] == ""


def test_shipped_objects_never_contain_the_clear_password(tmp_path):
    recs = [c[1] for c in SECRET_CASES]
    write_log(tmp_path / "log.jsonl", recs)
    s3 = FakeS3()
    _run(tmp_path, _settings(), s3)
    body = b"".join(p["Body"] for p in s3.puts).decode()
    for secret in ("sshpw1", "ftppw1", "smtppw1", "redispw1", "httppw1", "sippw1", "pgpw1",
                   "pgpw2", "sqlpw1", "telpw1"):
        assert secret not in body


# Field names that look like a secret but are not one. A new password-like field must be
# added either to ship.SECRET_FIELDS or here, with the reason.
KNOWN_NOT_SECRET = {
    "auth": "PostgreSQL authentication method name; S3 signature scheme name",
    "auth_malformed": "S3: which part of an Authorization header failed to parse",
    "access_key_id": "S3 access key id, the public half of a key pair (also the username)",
    "key": "S3 object key (a file name)",
    "max_keys": "S3 listing page size",
    "auth_plugin": "MySQL plugin name", "client_plugin": "MySQL plugin name",
    "auth_scheme": "SIP Authorization scheme name",
    "auth_switched": "bool", "auth_uri": "SIP digest URI",
    "auth_username": "user name", "authenticated": "bool",
    "body_bytes": "length", "body_head": "start of an SMTP message body (mail content)",
    "nonce": "server nonce", "cnonce": "client nonce", "nonce_verified": "bool",
    "salt": "server-chosen salt", "password_recovered": "bool",
    "honeytoken": "token name, not its value",
    "budget_exceeded": "bool",
    "api_key_header": "name of the API key header; the key itself is the password field",
    "form_keys": "names of the submitted form fields, not their values",
}
LOOKS_SECRET = re.compile(r"(?i)pass|pwd|secret|token|cred|auth|response|digest|body|"
                          r"scramble|salt|nonce|key|hash")
DATA_NAMES = {"data", "fields", "common", "extra"}


def _key(node):
    if isinstance(node, ast.Subscript):
        node = node.value
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.Constant):
        return node.values[0].value + "*"
    return None


def _event_field_names() -> set[str]:
    """Top-level event fields and every data key the front-ends write."""
    names = set(ListenerEvent.model_fields)
    for path in sorted((ROOT / "listeners").glob("*.py")) + [ROOT / "SSH" / "ssh_server.py"]:
        for n in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(n, (ast.Assign, ast.AnnAssign)) and isinstance(n.value, ast.Dict):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                if any(isinstance(t, ast.Name) and t.id in DATA_NAMES for t in targets):
                    names.update(k for k in map(_key, n.value.keys) if k)
            elif isinstance(n, ast.Call):
                func = n.func
                for kw in n.keywords:
                    if kw.arg == "data" and isinstance(kw.value, ast.Dict):
                        names.update(k for k in map(_key, kw.value.keys) if k)
                if isinstance(func, ast.Attribute) and func.attr == "update" and \
                        isinstance(func.value, ast.Name) and func.value.id in DATA_NAMES:
                    names.update(kw.arg for kw in n.keywords if kw.arg)
                    for arg in n.args:
                        if isinstance(arg, ast.Dict):
                            names.update(k for k in map(_key, arg.keys) if k)
                if isinstance(func, ast.Name) and func.id == "merge_log_extra":
                    names.update(kw.arg for kw in n.keywords if kw.arg)
            elif isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Store):
                owner = n.value
                if (isinstance(owner, ast.Name) and owner.id in DATA_NAMES) or \
                        (isinstance(owner, ast.Attribute) and owner.attr == "log"):
                    key = _key(n.slice)
                    if key:
                        names.add(key)
    return names


def test_field_scan_finds_the_known_password_fields():
    names = _event_field_names()
    assert {"password", "auth_password", "auth_response", "md5_response", "body", "input",
            "response", "part_*", "param_*", "attr_*"} <= names


def test_every_password_like_event_field_is_classified():
    listed = {r.field.split(".", 1)[-1] for r in ship.SECRET_FIELDS}
    unclassified = sorted(n for n in _event_field_names() if LOOKS_SECRET.search(n)
                          and n not in listed and n not in KNOWN_NOT_SECRET
                          and n not in ship.NOT_SECRET_KEYS)
    assert unclassified == [], "classify these in ship.SECRET_FIELDS or KNOWN_NOT_SECRET"


# ---- client ----------------------------------------------------------------------------------

class _Model:
    def __init__(self, name):
        self.name = name


@pytest.mark.parametrize("op", ["GetObject", "ListObjectsV2", "HeadBucket", "HeadObject",
                                "DeleteObject", "DeleteObjects"])
def test_client_hook_refuses_everything_but_put_object(op):
    ship.refuse_other_operations(model=_Model("PutObject"))
    with pytest.raises(ship.OperationRefused):
        ship.refuse_other_operations(model=_Model(op))


def test_default_factory_sets_timeouts_retries_and_the_hook():
    calls = {}

    class Events:
        def register(self, event, handler):
            calls["hook"] = (event, handler)

    class Client:
        meta = type("Meta", (), {"events": Events()})()

    class Session:
        def client(self, service, **kw):
            calls["client"] = (service, kw)
            return Client()

    ship.default_client_factory(_settings(region="us-east-1", timeout="7"), session=Session())
    service, kw = calls["client"]
    assert service == "s3" and kw["region_name"] == "us-east-1" and kw["use_ssl"] is True
    cfg = kw["config"]
    assert cfg.connect_timeout == 7 and cfg.read_timeout == 7
    assert cfg.retries == {"total_max_attempts": ship.MAX_ATTEMPTS, "mode": "standard"}
    assert calls["hook"] == ("before-call.s3", ship.refuse_other_operations)


def test_the_export_only_ever_calls_put_object():
    source = (ROOT / "agents" / "ship.py").read_text(encoding="utf-8")
    calls = set(re.findall(r"client\.([a-z_]+)\(", source))
    assert calls == {"put_object"}
    for op in ("get_object", "list_objects", "head_object", "head_bucket", "delete_object"):
        assert op not in source


# ---- CLI -------------------------------------------------------------------------------------

def _cli_setup(tmp_path, monkeypatch, enabled=True):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    write_log(tmp_path / "log.jsonl", _ftp(3))
    cfg = tmp_path / "config.ini"
    cfg.write_text("[honeypot]\nlog_file = log.jsonl\nsensor_name = lab sensor/1\n"
                   f"[scenario]\nseed = {SEED}\n"
                   f"[connector.s3_events]\nenabled = {'true' if enabled else 'false'}\n"
                   "bucket = example-honeypot-events\n")
    (tmp_path / "overlay.json").write_text("{}\n")
    s3 = FakeS3()
    factory = Factory(s3)
    monkeypatch.setattr(ship, "default_client_factory", factory)
    args = ["--config", str(cfg), "--reports-dir", str(tmp_path / "reports"),
            "--detections-dir", str(tmp_path / "det"), "--overlay", str(tmp_path / "overlay.json"),
            "--data-dir", str(tmp_path / "data")]
    return args, s3, factory


def test_ship_command_puts_objects_named_for_the_sensor(tmp_path, monkeypatch):
    args, s3, _ = _cli_setup(tmp_path, monkeypatch)
    summary = cli.run(["ship", *args])
    assert summary["ship"]["objects"] == 1
    assert re.search(r"-lab-sensor-1-0-[0-9a-f]{8}\.jsonl$", s3.puts[0]["Key"])
    assert (tmp_path / "reports" / "state" / ship.CURSOR_FILE).exists()


def test_ship_dry_run_makes_no_call(tmp_path, monkeypatch):
    args, s3, factory = _cli_setup(tmp_path, monkeypatch)
    summary = cli.run(["ship", "--dry-run", *args])
    assert summary["ship"]["objects"] == 1 and factory.created == 0 and s3.puts == []


def test_ship_command_with_the_export_disabled(tmp_path, monkeypatch):
    args, _, factory = _cli_setup(tmp_path, monkeypatch, enabled=False)
    assert cli.run(["ship", *args])["ship"] == {"status": "disabled"}
    summary = cli.run(["run-all", *args])
    assert "ship" not in summary and factory.created == 0


def test_run_all_ships_last_and_a_failure_does_not_stop_the_other_stages(tmp_path, monkeypatch):
    args, s3, _ = _cli_setup(tmp_path, monkeypatch)
    s3.fail_on, s3.exc = (1,), ClientError("SlowDown")
    summary = cli.run(["run-all", *args])
    assert [k for k in summary if k != "log_rotation"][-1] == "ship"   # last stage
    assert summary["ship"]["error"].endswith("SlowDown")
    assert "error" not in summary["triage"] and "error" not in summary["respond"]
    assert cli.main(["run-all", *args]) == 0                   # resent and stored this time
    assert len(s3.puts) == 1


def test_ship_honours_the_run_lock(tmp_path, monkeypatch):
    from agents.respond import run_lock

    args, s3, _ = _cli_setup(tmp_path, monkeypatch)
    with run_lock(tmp_path / "reports" / "state"):
        summary = cli.run(["ship", *args])
    assert "run_lock" in summary and s3.puts == []


SECRETS_IN_FREE_TEXT = [
    ("http", {"query": "user=admin&password=Hunter2pw&x=1"}, "Hunter2pw"),
    ("http", {"query": "api_key=AKfreeTextKey9"}, "AKfreeTextKey9"),
    ("http", {"query": "access_token=tok3nValue77"}, "tok3nValue77"),
    ("http", {"absolute_uri": "http://admin:S3cretUri@10.0.0.5/x"}, "S3cretUri"),
    ("http", {"referer": "https://bob:RefPass99@example.test/login?token=RefTok55"}, "RefPass99"),
    ("http", {"referer": "https://example.test/login?token=RefTok55"}, "RefTok55"),
    ("sip", {"uri": "sip:1001:SipSecret1@pbx.example"}, "SipSecret1"),
    ("sip", {"from": "<sip:1001:SipFrom2@pbx.example>;tag=1"}, "SipFrom2"),
    ("sip", {"to": "<sip:1001:SipTo3@pbx.example>"}, "SipTo3"),
    ("sip", {"contact": "<sip:1001:SipContact4@198.51.100.2:5060>"}, "SipContact4"),
    ("redis", {"cmd": "ACL", "input": "ACL SETUSER bob on >AclSecret5 ~* +@all"}, "AclSecret5"),
    ("redis", {"cmd": "EVAL", "input": "MULTI AUTH default RedisAuth6"}, "RedisAuth6"),
]


@pytest.mark.parametrize("protocol,data,secret", SECRETS_IN_FREE_TEXT)
@pytest.mark.parametrize("mode", ["hash", "drop"])
def test_secrets_inside_free_text_fields_are_not_exported_in_clear(protocol, data, secret, mode):
    rec = trap_event(protocol, "command", "203.0.113.5", f"{protocol}-1", data=dict(data))
    out = ship.protect(rec, mode, ship.password_key(SEED))
    assert secret not in json.dumps(out)
    if mode == "hash":
        assert ship.HASH_PREFIX in json.dumps(out)


def test_missing_log_is_nothing_to_ship_and_an_unreadable_one_is_an_error(tmp_path):
    res = ship.run_ship(_settings(), str(tmp_path / "missing.jsonl"), tmp_path / "state",
                        seed=SEED, sensor="s", client_factory=lambda _s: FakeS3(), now=NOW)
    assert res == {"status": "no_log", "objects": 0, "more_pending": False}
    (tmp_path / "dir.jsonl").mkdir()
    res = ship.run_ship(_settings(), str(tmp_path / "dir.jsonl"), tmp_path / "state",
                        seed=SEED, sensor="s", client_factory=lambda _s: FakeS3(), now=NOW)
    assert "is a directory" in res["error"]


def test_ship_command_on_a_new_sensor_reports_nothing_to_do(tmp_path, monkeypatch):
    args, s3, _ = _cli_setup(tmp_path, monkeypatch)
    (tmp_path / "log.jsonl").unlink()
    summary = cli.run(["ship", *args])
    assert summary["ship"]["status"] == "no_log" and "error" not in summary["ship"]
    assert summary["log_rotation"]["safe"] is True and s3.puts == []
    assert cli.main(["ship", *args]) == 0
