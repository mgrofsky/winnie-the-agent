"""Tracked export transport: [connector.tracked_export] settings, the one-object S3 client
guard, PutObject and HTTPS sends with fakes, send-on-change, failures that never stop a
run, and the token file shared by the HTTP connectors."""

import configparser
import datetime
import json
import re
from pathlib import Path

import pytest

from agents import objectstore, tracked
from agents.connectors.http import InvalidSecret, SecretMissing, read_secret_file
from agents.respond import write_tracked
from agents.ship import OperationRefused

from test_connectors import FakeTransport, public_resolver

pytestmark = pytest.mark.usefixtures("public_test_net")

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.datetime(2026, 11, 15, 12, 0, tzinfo=datetime.timezone.utc)
TOKEN = "tr4cked-token-value-XYZ"
ENTRIES = {"198.51.100.7": {"approved_at": "2026-11-15T12:00:00+00:00",
                            "expires_at": "2026-12-15T12:00:00+00:00", "status": "tracked"}}


class FakeS3:
    """Records put_object calls; any other attribute access fails the test."""

    def __init__(self, exc=None):
        self.puts: list[dict] = []
        self.exc = exc

    def put_object(self, **params):
        if self.exc is not None:
            raise self.exc
        self.puts.append(params)
        return {}

    def __getattr__(self, name):
        raise AssertionError(f"S3 client used for {name}; only put_object is allowed")


class ClientError(Exception):
    def __init__(self, code):
        super().__init__("details that are not logged")
        self.response = {"Error": {"Code": code, "Message": "details that are not logged"}}


def _cp(**opts) -> configparser.ConfigParser:
    cp = configparser.ConfigParser()
    cp.read_dict({tracked.SECTION: {"enabled": "true", **{k: str(v) for k, v in opts.items()}}})
    return cp


def _s3(**opts) -> tracked.ExportSettings:
    base = {"kind": "s3", "bucket": "example-honeypot-events", "key": "events/tracked/t.json"}
    return tracked.ExportSettings.from_config(_cp(**{**base, **opts}))


def _https(**opts) -> tracked.ExportSettings:
    base = {"kind": "https", "url": "https://intel.example.com/api/tracked"}
    return tracked.ExportSettings.from_config(_cp(**{**base, **opts}))


def _file(tmp_path, entries=ENTRIES, now=NOW) -> Path:
    path = tmp_path / "reports" / "blocklist" / "tracked.json"
    write_tracked(path, entries, now, "sensor-a")
    return path


def _send(tmp_path, settings, client=None, **kw):
    created = []

    def factory(target):
        created.append(target)
        return client if client is not None else FakeS3()

    res = tracked.run_export(settings, tmp_path / "reports" / "blocklist" / "tracked.json",
                             tmp_path / "state", client_factory=factory, now=NOW,
                             resolver=public_resolver, **kw)
    return res, created


# ---- settings ------------------------------------------------------------------------------

def test_off_by_default_and_when_disabled(tmp_path):
    assert tracked.ExportSettings.from_config(configparser.ConfigParser()).enabled is False
    assert tracked.ExportSettings.from_config(_cp(enabled="false", kind="nonsense")).enabled is False
    res, created = _send(tmp_path, tracked.ExportSettings())
    assert res == {"status": "disabled"} and created == []


@pytest.mark.parametrize("opts", [
    {"kind": "ftp"},
    {"kind": "s3", "bucket": "Bad_Bucket", "key": "k.json"},
    {"kind": "s3", "bucket": "example-bucket", "key": ""},
    {"kind": "s3", "bucket": "example-bucket", "key": "../escape.json"},
    {"kind": "s3", "bucket": "example-bucket", "key": "/abs.json"},
    {"kind": "s3", "bucket": "example-bucket", "key": "a//b.json"},
    {"kind": "s3", "bucket": "example-bucket", "key": "a b.json"},
    {"kind": "s3", "bucket": "example-bucket", "key": "k.json", "region": "auto"},
    {"kind": "s3", "bucket": "example-bucket", "key": "k.json", "bucket_owner": "12"},
    {"kind": "s3", "bucket": "example-bucket", "key": "k.json", "timeout": "99"},
    {"kind": "s3", "bucket": "example-bucket", "key": "k.json",
     "endpoint_url": "http://s3.example.com"},
    {"kind": "s3", "bucket": "example-bucket", "key": "k.json",
     "endpoint_url": "https://10.0.0.5"},
    {"kind": "s3", "bucket": "example-bucket", "key": "k.json",
     "endpoint_url": "https://user:pw@s3.example.com"},
    {"kind": "s3", "bucket": "example-bucket", "key": "k.json",
     "endpoint_url": "https://s3.example.com/?x=1"},
    {"kind": "s3", "bucket": "example-bucket", "key": "k.json", "file": "relative/tracked.json"},
    {"kind": "https", "url": "http://intel.example.com/x"},
    {"kind": "https", "url": "https://intel.example.com/x", "method": "DELETE"},
    {"kind": "https", "url": "https://intel.example.com/x", "secret_env": "A",
     "secret_file": "/run/secrets/t"},
    {"kind": "https", "url": "https://intel.example.com/x", "secret_file": "relative"},
])
def test_invalid_settings_are_refused_without_echoing_values(opts):
    with pytest.raises(tracked.ConfigError) as exc:
        tracked.ExportSettings.from_config(_cp(**opts))
    for value in opts.values():
        if len(value) >= 6:
            assert value not in str(exc.value)


def test_other_stores_take_an_endpoint_and_their_own_region_names():
    s = _s3(endpoint_url="https://s3.example.com", region="auto")
    assert s.s3.endpoint_url == "https://s3.example.com" and s.s3.region == "auto"
    s = _s3(endpoint_url="https://10.0.0.5:9000", allow_private="true")
    assert s.s3.endpoint_url == "https://10.0.0.5:9000"


def test_the_sections_are_not_reported_as_unknown_connectors(tmp_path):
    from agents.connectors import Connectors

    cp = configparser.ConfigParser()
    cp.read_dict({"connector.tracked_export": {"enabled": "false"},
                  "connector.sightings": {"enabled": "false"}})
    assert Connectors(cp, tmp_path).errors == []


# ---- S3 ------------------------------------------------------------------------------------

def test_s3_puts_the_file_as_is_to_one_key(tmp_path):
    path = _file(tmp_path)
    s3 = FakeS3()
    res, created = _send(tmp_path, _s3(bucket_owner="123456789012", region="us-east-1"), s3)
    assert res == {"kind": "s3", "entries": 1, "bytes": len(path.read_bytes()), "status": "sent"}
    [put] = s3.puts
    assert put == {"Bucket": "example-honeypot-events", "Key": "events/tracked/t.json",
                   "Body": path.read_bytes(), "ContentType": "application/json",
                   "ExpectedBucketOwner": "123456789012"}
    assert created[0].region == "us-east-1"


def test_an_unchanged_file_is_not_sent_again_and_a_change_is(tmp_path):
    _file(tmp_path)
    s3 = FakeS3()
    _send(tmp_path, _s3(), s3)
    res, created = _send(tmp_path, _s3(), s3)
    assert res["status"] == "unchanged" and created == [] and len(s3.puts) == 1
    _file(tmp_path, entries={})                         # a removal or an expiry
    res, _ = _send(tmp_path, _s3(), s3)
    assert res["status"] == "sent" and len(s3.puts) == 2
    assert json.loads(s3.puts[1]["Body"])["entries"] == []


def test_a_failed_put_is_logged_recorded_and_sent_again_next_run(tmp_path, caplog):
    _file(tmp_path)
    res, _ = _send(tmp_path, _s3(), FakeS3(exc=ClientError("AccessDenied")))
    assert res["error"] == "PutObject failed: ClientError: AccessDenied"
    assert "details that are not logged" not in caplog.text
    [event] = [json.loads(x) for x in (tmp_path / "state" / "ship_events.jsonl").read_text()
               .splitlines()]
    assert event["event"] == "tracked_export_failed" and "AccessDenied" in event["error"]
    s3 = FakeS3()
    res, _ = _send(tmp_path, _s3(), s3)
    assert res["status"] == "sent" and len(s3.puts) == 1


def test_a_client_that_cannot_be_built_is_a_reported_failure(tmp_path):
    _file(tmp_path)

    def broken(target):
        raise RuntimeError("no credentials anywhere")

    res = tracked.run_export(_s3(), tmp_path / "reports" / "blocklist" / "tracked.json",
                             tmp_path / "state", client_factory=broken, now=NOW)
    assert res["error"] == "PutObject failed: RuntimeError"


def test_no_file_yet_is_nothing_to_send(tmp_path):
    res, created = _send(tmp_path, _s3())
    assert res["status"] == "no_file" and created == []


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"version": 2, "entries": []}',
                                  b'{"version": 1, "entries": [{"address": "x"}]}',
                                  b"\xff\xfe"])
def test_a_file_that_is_not_a_tracked_export_never_leaves(tmp_path, body):
    path = tmp_path / "reports" / "blocklist" / "tracked.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(body)
    res, created = _send(tmp_path, _s3())
    assert res["error"] == "the local file is not a tracked export" and created == []


def test_an_oversized_file_never_leaves(tmp_path, monkeypatch):
    monkeypatch.setattr(tracked, "MAX_DOCUMENT_BYTES", 64)
    _file(tmp_path)
    res, created = _send(tmp_path, _s3())
    assert "larger than" in res["error"] and created == []


@pytest.mark.parametrize("kind", ["fifo", "symlink", "directory"])
def test_a_tracked_export_that_is_not_a_regular_file_is_unreadable(tmp_path, kind):
    import os

    path = tmp_path / "reports" / "blocklist" / "tracked.json"
    path.parent.mkdir(parents=True)
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "symlink":
        real = tmp_path / "elsewhere.json"
        write_tracked(real, ENTRIES, NOW, "sensor-a")
        path.symlink_to(real)
    else:
        path.mkdir()
    res, created = _send(tmp_path, _s3())    # a FIFO would block here with a plain open()
    assert res["error"].startswith("cannot read the tracked export (") and created == []
    assert (tmp_path / "state" / "ship_events.jsonl").exists()


def test_a_normal_tracked_export_is_sent_byte_for_byte(tmp_path):
    path = _file(tmp_path)
    s3 = FakeS3()
    res, _ = _send(tmp_path, _s3(), s3)
    assert res["status"] == "sent" and s3.puts[0]["Body"] == path.read_bytes()


def test_file_setting_reads_another_path(tmp_path):
    other = tmp_path / "mounted" / "tracked.json"
    write_tracked(other, ENTRIES, NOW, "s")
    s3 = FakeS3()
    res, _ = _send(tmp_path, _s3(file=str(other)), s3)
    assert res["status"] == "sent" and s3.puts[0]["Body"] == other.read_bytes()


def test_dry_run_sends_nothing(tmp_path):
    _file(tmp_path)
    res, created = _send(tmp_path, _s3(), dry_run=True)
    assert res["status"] == "would send" and created == []
    assert not (tmp_path / "state" / tracked.STATE_FILE).exists()


# ---- the client guard ----------------------------------------------------------------------

class _Model:
    def __init__(self, name):
        self.name = name


@pytest.mark.parametrize("op", ["GetObject", "ListObjectsV2", "HeadBucket", "HeadObject",
                                "DeleteObject", "PutObjectAcl", "CopyObject"])
def test_put_guard_refuses_every_other_operation(op):
    guard = objectstore.OneObjectGuard("PutObject", "example-bucket", "a/t.json")
    guard.before_call(model=_Model("PutObject"))
    with pytest.raises(OperationRefused):
        guard.before_call(model=_Model(op))
    with pytest.raises(OperationRefused):
        guard.before_parameters(params={"Bucket": "example-bucket", "Key": "a/t.json"},
                                model=_Model(op))


@pytest.mark.parametrize("params", [{"Bucket": "example-bucket", "Key": "a/other.json"},
                                    {"Bucket": "other-bucket", "Key": "a/t.json"},
                                    {"Bucket": "example-bucket"}, {}, None])
def test_guard_refuses_any_other_bucket_or_key(params):
    guard = objectstore.OneObjectGuard("PutObject", "example-bucket", "a/t.json")
    guard.before_parameters(params={"Bucket": "example-bucket", "Key": "a/t.json"},
                            model=_Model("PutObject"))
    with pytest.raises(OperationRefused):
        guard.before_parameters(params=params, model=_Model("PutObject"))


def test_guarded_factory_reuses_the_ship_client_with_both_hooks_and_the_endpoint():
    calls = {"hooks": []}

    class Events:
        def register(self, event, handler):
            calls["hooks"].append(event)

    class Client:
        meta = type("Meta", (), {"events": Events()})()

    class Session:
        def client(self, service, **kw):
            calls["client"] = (service, kw)
            return Client()

    target = objectstore.S3Target.validate("example-bucket", "a/t.json", "auto", "",
                                           "https://s3.example.com", "7")
    objectstore.guarded_client_factory("PutObject")(target, session=Session())
    service, kw = calls["client"]
    assert service == "s3" and kw["endpoint_url"] == "https://s3.example.com"
    assert kw["region_name"] == "auto" and kw["use_ssl"] is True
    assert kw["config"].connect_timeout == 7 and kw["config"].read_timeout == 7
    assert calls["hooks"] == ["before-parameter-build.s3", "before-call.s3"]


def test_the_export_module_only_ever_calls_put_object():
    source = (ROOT / "agents" / "tracked.py").read_text(encoding="utf-8")
    assert set(re.findall(r"client\.([a-z_]+)\(", source)) <= {"put_object"}
    for op in ("get_object", "list_objects", "delete_object", "head_"):
        assert op not in source


# ---- HTTPS ---------------------------------------------------------------------------------

def test_https_sends_one_put_of_the_document_with_the_token_from_a_file(tmp_path):
    path = _file(tmp_path)
    secret = tmp_path / "token"
    secret.write_text(TOKEN + "\n")
    transport = FakeTransport()
    settings = _https(secret_file=str(secret))
    res = tracked.run_export(settings, path, tmp_path / "state", transport=transport,
                             resolver=public_resolver, now=NOW)
    assert res["status"] == "sent"
    [call] = transport.calls
    assert call["method"] == "PUT" and call["url"] == "https://intel.example.com/api/tracked"
    assert call["body"] == path.read_bytes() and call["address"] == "198.51.100.34"
    assert call["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert call["headers"]["Content-Type"] == "application/json"
    assert TOKEN not in json.dumps(res)


def test_https_post_and_a_header_token_from_the_environment(tmp_path, monkeypatch):
    path = _file(tmp_path)
    monkeypatch.setenv("WINNIE_TRACKED_TOKEN", TOKEN)
    transport = FakeTransport()
    settings = _https(method="post", secret_env="WINNIE_TRACKED_TOKEN", header="X-Api-Key")
    tracked.run_export(settings, path, tmp_path / "state", transport=transport,
                       resolver=public_resolver, now=NOW)
    assert transport.calls[0]["method"] == "POST"
    assert transport.calls[0]["headers"]["X-Api-Key"] == TOKEN


@pytest.mark.parametrize("status,error", [(302, "error: redirect_302"), (500, "error: http_500")])
def test_https_failures_are_recorded_and_retried(tmp_path, status, error):
    path = _file(tmp_path)
    res = tracked.run_export(_https(), path, tmp_path / "state",
                             transport=FakeTransport(status=status), resolver=public_resolver,
                             now=NOW)
    assert res["error"] == f"PUT failed: {error}"
    transport = FakeTransport()
    res = tracked.run_export(_https(), path, tmp_path / "state", transport=transport,
                             resolver=public_resolver, now=NOW)
    assert res["status"] == "sent" and len(transport.calls) == 1


def test_https_missing_token_file_is_an_error_without_a_call(tmp_path):
    path = _file(tmp_path)
    transport = FakeTransport()
    res = tracked.run_export(_https(secret_file=str(tmp_path / "missing")), path,
                             tmp_path / "state", transport=transport, resolver=public_resolver,
                             now=NOW)
    assert res["error"] == "PUT failed: error: secret_missing" and transport.calls == []


def test_secret_file_reading_rules(tmp_path):
    p = tmp_path / "t"
    p.write_text("abc\r\n")
    assert read_secret_file(str(p)) == "abc"
    for bad, exc in ((b"a\nb", InvalidSecret), (b"x" * 5000, InvalidSecret),
                     (b"\xff", InvalidSecret), (b"\n", SecretMissing), (b"a\x00b", InvalidSecret)):
        p.write_bytes(bad)
        with pytest.raises(exc):
            read_secret_file(str(p))


# ---- CLI -----------------------------------------------------------------------------------

def _cli(tmp_path, monkeypatch, section, *argv):
    import agents.__main__ as cli

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cfg = tmp_path / "config.ini"
    cfg.write_text("[honeypot]\nlog_file = log.jsonl\n" + section)
    return cli.run([*argv, "--config", str(cfg), "--reports-dir", str(tmp_path / "reports"),
                    "--state-dir", str(tmp_path / "state"), "--detections-dir",
                    str(tmp_path / "det"), "--data-dir", str(tmp_path / "data")])


S3_SECTION = ("[connector.tracked_export]\nenabled = true\nkind = s3\n"
              "bucket = example-honeypot-events\nkey = events/tracked/t.json\n")


def test_ship_command_sends_the_tracked_export(tmp_path, monkeypatch):
    _file(tmp_path)
    s3 = FakeS3()
    monkeypatch.setattr(objectstore, "guarded_client_factory", lambda op: lambda target: s3)
    out = _cli(tmp_path, monkeypatch, S3_SECTION, "ship")
    assert out["ship"] == {"status": "disabled"}
    assert out["tracked_export"]["status"] == "sent" and len(s3.puts) == 1


def test_a_failed_export_does_not_stop_run_all(tmp_path, monkeypatch):
    _file(tmp_path)
    monkeypatch.setattr(objectstore, "guarded_client_factory",
                        lambda op: lambda target: FakeS3(exc=ClientError("AccessDenied")))
    out = _cli(tmp_path, monkeypatch, S3_SECTION, "run-all", "--no-llm")
    assert out["tracked_export"]["error"].startswith("PutObject failed")
    assert "respond" in out and "error" not in out["respond"]


def test_a_bad_section_is_reported_and_nothing_is_sent(tmp_path, monkeypatch):
    out = _cli(tmp_path, monkeypatch, "[connector.tracked_export]\nenabled = true\nkind = ftp\n",
               "ship")
    assert out["tracked_export"] == {"error": "[connector.tracked_export]: kind must be s3 or https"}


def test_a_new_generated_at_alone_is_not_sent_until_the_daily_refresh(tmp_path):
    _file(tmp_path)
    s3 = FakeS3()
    _send(tmp_path, _s3(), s3)
    _file(tmp_path, now=NOW + datetime.timedelta(hours=1))   # the next respond run
    res, created = _send(tmp_path, _s3(), s3)
    assert res["status"] == "unchanged" and created == []
    later = NOW + datetime.timedelta(hours=tracked.REFRESH_HOURS, minutes=1)
    res = tracked.run_export(_s3(), tmp_path / "reports" / "blocklist" / "tracked.json",
                             tmp_path / "state", client_factory=lambda t: s3, now=later)
    assert res["status"] == "sent" and len(s3.puts) == 2
