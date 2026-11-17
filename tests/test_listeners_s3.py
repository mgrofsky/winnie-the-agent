"""S3-compatible trap: unit tests for parsing and listing, loopback tests with boto3 and a
raw socket client. Everything runs on 127.0.0.1; boto3 never sees a real endpoint or the
user's AWS configuration."""

import asyncio
import hashlib
import os
import socket
import threading
import time
import urllib.error
import urllib.request

import boto3
import pytest
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from agents import ship
from listeners import s3
from listeners.base import Limits, ListenerContext, ServiceSettings
from listeners.events import EventWriter
from scenarios.loader import LoadedScenario, generate_honeytoken
from scenarios.schema import HoneytokenSpec, LoginPolicy, Scenario

SEED = "s3-test-seed"
# Key-shaped literals are assembled at runtime so the repository never holds one whole.
LISTED_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
LISTED_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
OTHER_KEY = "AKIA" + "Z" * 16
REGION = "us-east-1"


def scenario_dict() -> dict:
    return {
        "name": "t_store", "title": "Test storage", "description": "test",
        "identity": {"org_name": "Northwind Voice", "hostname": "stor01",
                     "domain": "northwind.test", "internal_ips": ["10.20.0.6"],
                     "os_pretty_name": "Ubuntu 22.04.4 LTS",
                     "kernel": "Linux stor01 5.15.0-101-generic"},
        "services": {
            "s3": {
                "enabled": True, "port": 0,
                "accounts": [{"username": LISTED_KEY, "password": LISTED_SECRET},
                             {"username": "AKIA" + "ANYSECRET" + "OKEXAMPLE"[:7], "password": "*"}],
                "buckets": [
                    {"name": "nw-call-recordings", "objects": [
                        {"key": "2026/11/03/rec-{n:05d}.wav", "count": 40, "size": 480_000,
                         "content_type": "audio/wav"},
                        {"key": "2026/11/04/rec-{n:05d}.wav", "count": 20, "size": 480_000,
                         "content_type": "audio/wav"},
                        {"key": "index.txt", "text": "recordings index\n"},
                        {"key": "archive/full-2026-10.tar.gz", "size": 50_000_000,
                         "content_type": "application/gzip"},
                        {"key": "exports/cdr.log", "size": 300_000, "content_type": "text/plain"},
                    ]},
                    {"name": "nw-config-backup", "objects": [
                        {"key": ".env", "text": "AWS_ACCESS_KEY_ID={{ht:backup_key}}\n",
                         "content_type": "text/plain"},
                        {"key": "exports/customers.csv", "table": "crm.customers",
                         "content_type": "text/csv"},
                    ]},
                    {"name": "nw-public-assets", "public_list": True, "public_read": True,
                     "objects": [{"key": "logo.txt", "text": "northwind\n"}]},
                    {"name": "nw-big", "objects": [
                        {"key": "k/{n:05d}.bin", "count": 10_000, "size": 100}]},
                    {"name": "nw-eu", "region": "eu-west-1", "objects": [
                        {"key": "a.txt", "text": "eu\n"}]},
                ],
            },
            "postgres": {"enabled": False, "port": 0, "databases": [{"name": "crm", "tables": [{
                "name": "customers",
                "columns": [{"name": "id", "type": "int"}, {"name": "full_name", "type": "text"}],
                "seed_rows": [[1, "Avery Hartwell"], [2, "Jordan Okonkwo"]]}]}]},
        },
        "honeytokens": [{"name": "backup_key", "kind": "aws_access_key",
                         "planted_in": ["s3 nw-config-backup/.env"]}],
    }


def make_scenario(seed: str = SEED) -> LoadedScenario:
    raw = scenario_dict()
    spec = HoneytokenSpec.model_validate(raw["honeytokens"][0])
    from scenarios.loader import Honeytoken, _substitute

    tok = Honeytoken("backup_key", "aws_access_key", generate_honeytoken(spec, seed, "t_store"),
                     ("s3",))
    scn = Scenario.model_validate(_substitute(raw, {"backup_key": tok}))
    return LoadedScenario(scenario=scn, seed=seed, honeytokens={"backup_key": tok})


def make_ctx(tmp_path, accept="listed", seed=SEED, **limits) -> ListenerContext:
    scen = make_scenario(seed)
    ctx = ListenerContext(EventWriter(None), seed=seed, scenario=scen, bind_host="127.0.0.1",
                          limits=Limits(**limits),
                          quarantine_dir=str(tmp_path / "quarantine"),
                          honeytokens={t.value: t.name for t in scen.honeytokens.values()})
    ctx.settings["s3"] = ServiceSettings(name="s3", enabled=True, port=0,
                                         policy=LoginPolicy(accept=accept),
                                         accounts=scen.accounts_for("s3"))
    return ctx


class Server:
    """The listener on its own event loop in a thread, so blocking boto3 calls can run."""

    def __init__(self, ctx: ListenerContext) -> None:
        self.ctx = ctx
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        fut = asyncio.run_coroutine_threadsafe(
            s3.start(ctx, ctx.settings["s3"]), self.loop)
        self.servers = fut.result(5)
        self.port = self.servers[0].sockets[0].getsockname()[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        async def shutdown():
            for srv in self.servers:
                srv.close()
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        asyncio.run_coroutine_threadsafe(shutdown(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()

    def settle(self, quiet: float = 0.03, limit: float = 2.0) -> None:
        """Events are written after the response is sent: wait until the log is quiet."""
        deadline = time.monotonic() + limit
        n = -1
        while time.monotonic() < deadline:
            current = len(self.ctx.writer.events)
            if current == n:
                return
            n = current
            time.sleep(quiet)

    def events(self, event=None) -> list[dict]:
        self.settle()
        return [e for e in list(self.ctx.writer.events) if event is None or e["event"] == event]

    def commands(self, op=None) -> list[dict]:
        return [e for e in self.events("command") if op is None or e["data"].get("operation") == op]

    def client(self, key=LISTED_KEY, secret=LISTED_SECRET, style="path", unsigned=False,
               region=REGION, **extra):
        cfg = Config(s3={"addressing_style": style}, retries={"max_attempts": 1},
                     connect_timeout=5, read_timeout=10,
                     signature_version=UNSIGNED if unsigned else "s3v4", **extra)
        kwargs = {} if unsigned else {"aws_access_key_id": key, "aws_secret_access_key": secret}
        return boto3.client("s3", endpoint_url=self.endpoint, region_name=region, config=cfg,
                            **kwargs)

    def raw(self, request: bytes, timeout: float = 5.0) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as sock:
            sock.sendall(request)
            out = b""
            while True:
                try:
                    chunk = sock.recv(65536)
                except (socket.timeout, ConnectionError):
                    break
                if not chunk:
                    break
                out += chunk
        return out


@pytest.fixture(autouse=True)
def no_aws_config(monkeypatch, tmp_path):
    for var in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ENDPOINT_URL",
                "AWS_ENDPOINT_URL_S3", "AWS_REGION", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


@pytest.fixture
def server(tmp_path):
    srv = Server(make_ctx(tmp_path))
    yield srv
    srv.close()


def error_code(exc: ClientError) -> str:
    return exc.response["Error"]["Code"]


# ---- unit: auth parsing -------------------------------------------------------------------

def _req(method="GET", target="/", headers=()):
    from listeners.http import Request
    from urllib.parse import unquote, urlsplit

    split = urlsplit(target)
    return Request(method, target, "HTTP/1.1", unquote(split.path), split.query, list(headers))


def test_parse_sigv4_header():
    auth = ("AWS4-HMAC-SHA256 Credential=" + LISTED_KEY + "/20261116/eu-west-1/s3/aws4_request, "
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" + "a" * 64)
    info = s3.parse_auth(_req(headers=[("Authorization", auth)]), {})
    assert info.scheme == "sigv4" and info.access_key_id == LISTED_KEY
    assert info.region == "eu-west-1" and info.service == "s3"
    assert info.signed_headers == ["host", "x-amz-content-sha256", "x-amz-date"]
    assert info.malformed is None


def test_parse_sigv4_query_v2_header_v2_query_and_anonymous():
    q = {"X-Amz-Algorithm": "AWS4-HMAC-SHA256",
         "X-Amz-Credential": LISTED_KEY + "/20261116/us-east-1/s3/aws4_request",
         "X-Amz-Date": "20261116T000000Z", "X-Amz-Expires": "3600",
         "X-Amz-SignedHeaders": "host", "X-Amz-Signature": "b" * 64,
         "X-Amz-Security-Token": "tok"}
    info = s3.parse_auth(_req(), q)
    assert (info.scheme, info.access_key_id, info.region, info.security_token) == \
        ("sigv4_query", LISTED_KEY, "us-east-1", "tok")
    info = s3.parse_auth(_req(headers=[("Authorization", f"AWS {LISTED_KEY}:c2lnbmF0dXJl")]), {})
    assert (info.scheme, info.access_key_id) == ("sigv2", LISTED_KEY)
    info = s3.parse_auth(_req(), {"AWSAccessKeyId": LISTED_KEY, "Signature": "x",
                                  "Expires": "2000000000"})
    assert (info.scheme, info.access_key_id) == ("sigv2_query", LISTED_KEY)
    assert s3.parse_auth(_req(), {}).scheme == "anonymous"


@pytest.mark.parametrize("value", ["AWS4-HMAC-SHA256 garbage", "AWS4-HMAC-SHA256 Credential=" +
                                   "x" * 300 + "/a/b/c/d, SignedHeaders=host, Signature=ab",
                                   "AWS nocolon", "Weird scheme"])
def test_parse_malformed_auth(value):
    info = s3.parse_auth(_req(headers=[("Authorization", value)]), {})
    assert info.malformed is not None
    assert info.access_key_id is None or len(info.access_key_id) <= 128


def test_bucket_and_key_from_host_and_path():
    known = {"nw-call-recordings", "my.dotted.bucket"}
    assert s3.split_target("127.0.0.1:9000", "/nw-call-recordings/a/b.wav", known) == \
        ("nw-call-recordings", "a/b.wav", "path")
    assert s3.split_target("nw-call-recordings.s3.example.test", "/a/b.wav", known) == \
        ("nw-call-recordings", "a/b.wav", "virtual")
    assert s3.split_target("my.dotted.bucket.storage.example.test:9000", "/k", known) == \
        ("my.dotted.bucket", "k", "virtual")
    assert s3.split_target("unknown.s3.amazonaws.com", "/k", known) == ("unknown", "k", "virtual")
    assert s3.split_target("s3.amazonaws.com", "/b/", known) == ("b", "", "path")
    assert s3.split_target("localhost", "/", known) == (None, "", "path")


@pytest.mark.parametrize("header,size,expected", [
    ("bytes=0-9", 100, (0, 9)), ("bytes=90-", 100, (90, 99)), ("bytes=-10", 100, (90, 99)),
    ("bytes=95-200", 100, (95, 99)), ("bytes=100-", 100, "invalid"), ("bytes=5-1", 100, None),
    ("items=0-1", 100, None), ("bytes=0-1,5-6", 100, None), ("bytes=-0", 100, "invalid"),
])
def test_parse_range(header, size, expected):
    assert s3.parse_range(header, size) == expected


def test_listing_is_deterministic_per_seed(tmp_path):
    a = s3.catalog(make_ctx(tmp_path / "a")).bucket("nw-call-recordings")
    b = s3.catalog(make_ctx(tmp_path / "b")).bucket("nw-call-recordings")
    c = s3.catalog(make_ctx(tmp_path / "c", seed="another")).bucket("nw-call-recordings")
    key = "2026/11/03/rec-00007.wav"
    assert a.keys == b.keys == c.keys
    assert a.meta(key) == b.meta(key)
    assert a.meta(key).etag != c.meta(key).etag


def test_filler_is_random_access_and_never_allocates_paper_size(tmp_path):
    bucket = s3.catalog(make_ctx(tmp_path)).bucket("nw-call-recordings")
    meta = bucket.meta("archive/full-2026-10.tar.gz")
    assert meta.size == 50_000_000
    head = b"".join(bucket.body(meta, 0, 200_000))
    assert head[:2] == b"\x1f\x8b"
    assert b"".join(bucket.body(meta, 70_000, 70_100)) == head[70_000:70_100]
    text = bucket.meta("exports/cdr.log")
    full = b"".join(bucket.body(text, 0, 2000))
    assert b"".join(bucket.body(text, 1234, 1500)) == full[1234:1500]
    assert full.count(b"\n") > 10
    wav = b"".join(bucket.body(bucket.meta("2026/11/03/rec-00001.wav"), 0, 64))
    assert wav[:4] == b"RIFF" and wav[8:12] == b"WAVE"


def test_chunked_decoder_rejects_abuse():
    assert s3.parse_chunk_size(b"400;chunk-signature=" + b"a" * 64) == 1024
    assert s3.parse_chunk_size(b"0") == 0
    for bad in (b"", b"zz", b"f" * 20, b"-1", b"10 ;x", b"1" * 9 + b";"):
        assert s3.parse_chunk_size(bad) is None


# ---- loopback: listing --------------------------------------------------------------------

def test_list_buckets_and_owner(server):
    out = server.client().list_buckets()
    names = [b["Name"] for b in out["Buckets"]]
    assert names == sorted(names) and "nw-call-recordings" in names
    assert out["Owner"]["ID"] and len(out["Owner"]["ID"]) == 64
    cmd = server.commands("ListBuckets")[-1]
    assert cmd["sensor_protocol"] == "s3" and cmd["username"] == LISTED_KEY
    assert cmd["data"]["access_key_id"] == LISTED_KEY and cmd["data"]["region"] == REGION
    assert cmd["data"]["signal"] == "s3_list"


def test_list_objects_prefix_delimiter_v1_and_v2(server):
    c = server.client()
    out = c.list_objects_v2(Bucket="nw-call-recordings", Delimiter="/")
    assert [p["Prefix"] for p in out["CommonPrefixes"]] == ["2026/", "archive/", "exports/"]
    assert [o["Key"] for o in out["Contents"]] == ["index.txt"]
    out = c.list_objects_v2(Bucket="nw-call-recordings", Prefix="2026/11/", Delimiter="/")
    assert [p["Prefix"] for p in out["CommonPrefixes"]] == ["2026/11/03/", "2026/11/04/"]
    out = c.list_objects(Bucket="nw-call-recordings", Prefix="2026/11/04/", MaxKeys=5)
    assert len(out["Contents"]) == 5 and out["IsTruncated"] is True
    nxt = c.list_objects(Bucket="nw-call-recordings", Prefix="2026/11/04/",
                         Marker=out["Contents"][-1]["Key"])
    assert len(nxt["Contents"]) == 15
    ev = server.commands("ListObjectsV2")[-1]["data"]
    assert ev["bucket"] == "nw-call-recordings" and ev["prefix"] == "2026/11/"


def test_ten_thousand_keys_paginate_at_one_thousand(server):
    pages = list(server.client().get_paginator("list_objects_v2").paginate(Bucket="nw-big"))
    sizes = [len(p["Contents"]) for p in pages]
    assert sizes == [1000] * 10
    keys = [o["Key"] for p in pages for o in p["Contents"]]
    assert len(set(keys)) == 10_000 and keys == sorted(keys)
    out = server.client().list_objects_v2(Bucket="nw-big", MaxKeys=50_000)
    assert out["KeyCount"] == 1000 and out["MaxKeys"] == 1000


def test_url_encoding_type_and_bad_continuation_token(server):
    c = server.client()
    out = c.list_objects_v2(Bucket="nw-call-recordings", Prefix="2026/11/03/", MaxKeys=1,
                            EncodingType="url")
    assert out["Contents"][0]["Key"] == "2026/11/03/rec-00000.wav"
    with pytest.raises(ClientError) as exc:
        c.list_objects_v2(Bucket="nw-call-recordings", ContinuationToken="!!!not-a-token")
    assert error_code(exc.value) == "InvalidArgument"


def test_bucket_location_acl_policy(server):
    c = server.client()
    assert c.get_bucket_location(Bucket="nw-call-recordings")["LocationConstraint"] is None
    acl = c.get_bucket_acl(Bucket="nw-public-assets")
    assert any(g["Grantee"].get("URI", "").endswith("AllUsers") for g in acl["Grants"])
    policy = c.get_bucket_policy(Bucket="nw-public-assets")["Policy"]
    assert '"Principal": "*"' in policy and "s3:GetObject" in policy
    assert c.head_bucket(Bucket="nw-config-backup")["ResponseMetadata"]["HTTPStatusCode"] == 200
    with pytest.raises(ClientError) as exc:
        c.head_bucket(Bucket="no-such-bucket-here")
    assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404


def test_region_redirect_for_a_bucket_in_another_region(server):
    out = server.client().list_objects_v2(Bucket="nw-eu")
    assert [o["Key"] for o in out["Contents"]] == ["a.txt"]


def test_virtual_hosted_style_request(server):
    raw = server.raw(b"GET /?list-type=2 HTTP/1.1\r\nHost: nw-public-assets.s3.example.test\r\n"
                     b"Connection: close\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 200") and b"<Key>logo.txt</Key>" in raw


# ---- loopback: objects --------------------------------------------------------------------

def test_get_text_table_and_honeytoken_object(server):
    c = server.client()
    env = c.get_object(Bucket="nw-config-backup", Key=".env")["Body"].read().decode()
    token = server.ctx.scenario.honeytokens["backup_key"].value
    assert token in env and "{{ht:" not in env
    csv = c.get_object(Bucket="nw-config-backup", Key="exports/customers.csv")["Body"].read()
    assert csv.splitlines()[0] == b"id,full_name" and b"Avery Hartwell" in csv
    head = c.head_object(Bucket="nw-config-backup", Key=".env")
    assert head["ContentLength"] == len(env) and head["ETag"].strip('"') == \
        hashlib.md5(env.encode()).hexdigest()
    ev = server.commands("GetObject")[-1]
    assert ev["data"]["key"] == "exports/customers.csv" and ev["data"]["bytes_out"] == len(csv)
    assert ev["data"]["signal"] == "s3_download"
    with pytest.raises(ClientError) as exc:
        c.get_object(Bucket="nw-config-backup", Key="nope.txt")
    assert error_code(exc.value) == "NoSuchKey"
    with pytest.raises(ClientError) as exc:
        c.get_object(Bucket="nope-bucket", Key="x")
    assert error_code(exc.value) == "NoSuchBucket"


def test_ranged_get(server):
    c = server.client()
    full = c.get_object(Bucket="nw-call-recordings", Key="exports/cdr.log")["Body"].read()
    part = c.get_object(Bucket="nw-call-recordings", Key="exports/cdr.log", Range="bytes=100-199")
    assert part["ContentRange"] == f"bytes 100-199/{len(full)}"
    assert part["Body"].read() == full[100:200]
    tail = c.get_object(Bucket="nw-call-recordings", Key="exports/cdr.log", Range="bytes=-50")
    assert tail["Body"].read() == full[-50:]
    with pytest.raises(ClientError) as exc:
        c.get_object(Bucket="nw-call-recordings", Key="index.txt", Range="bytes=5000-")
    assert error_code(exc.value) == "InvalidRange"
    assert server.commands("GetObject")[-2]["data"]["range"] == "bytes=-50"


def test_large_object_download_is_capped(server):
    raw = server.raw(b"GET /nw-public-assets/logo.txt HTTP/1.1\r\nHost: x\r\n"
                     b"Connection: close\r\n\r\n", timeout=2)
    assert raw.startswith(b"HTTP/1.1 200")
    c = server.client()
    head = c.head_object(Bucket="nw-call-recordings", Key="archive/full-2026-10.tar.gz")
    assert head["ContentLength"] == 50_000_000
    first = c.get_object(Bucket="nw-call-recordings", Key="archive/full-2026-10.tar.gz",
                         Range="bytes=0-1023")["Body"].read()
    assert len(first) == 1024 and first[:2] == b"\x1f\x8b"
    # A full download stops at get_max_bytes and the connection is closed.
    signer = server.client()
    url = signer.generate_presigned_url("get_object", Params={
        "Bucket": "nw-call-recordings", "Key": "archive/full-2026-10.tar.gz"}, ExpiresIn=300)
    got = 0
    with pytest.raises(Exception):
        with urllib.request.urlopen(url, timeout=10) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                got += len(chunk)
            if got < 50_000_000:
                raise IOError("short read")
    ev = server.commands("GetObject")[-1]["data"]
    assert ev["truncated"] is True and ev["bytes_out"] == s3.DEFAULT_GET_MAX


def test_presigned_get_scrubs_the_signature(server):
    url = server.client().generate_presigned_url(
        "get_object", Params={"Bucket": "nw-config-backup", "Key": ".env"}, ExpiresIn=300)
    assert "X-Amz-Signature=" in url
    signature = url.split("X-Amz-Signature=")[1].split("&")[0]
    with urllib.request.urlopen(url, timeout=5) as resp:
        assert resp.status == 200 and b"AWS_ACCESS_KEY_ID=" in resp.read()
    ev = server.commands("GetObject")[-1]
    assert ev["data"]["auth"] == "sigv4_query" and ev["username"] == LISTED_KEY
    assert signature not in str(server.events())


def test_presigned_url_with_session_token_is_scrubbed_on_export(server):
    c = boto3.client("s3", endpoint_url=server.endpoint, region_name=REGION,
                     aws_access_key_id=LISTED_KEY, aws_secret_access_key=LISTED_SECRET,
                     aws_session_token="FQoGZXIvYXdzEXAMPLEsessiontoken",
                     config=Config(s3={"addressing_style": "path"}, signature_version="s3v4"))
    url = c.generate_presigned_url("get_object", Params={"Bucket": "nw-config-backup",
                                                         "Key": ".env"}, ExpiresIn=300)
    with urllib.request.urlopen(url, timeout=5) as resp:
        resp.read()
    ev = server.commands("GetObject")[-1]
    assert ev["data"]["security_token"] == "FQoGZXIvYXdzEXAMPLEsessiontoken"
    shipped = ship.protect(ev, "hash", b"k" * 32)
    assert "FQoGZXIvYXdzEXAMPLEsessiontoken" not in str(shipped)
    assert "FQoGZXIvYXdzEXAMPLEsessiontoken" not in str(ship.protect(ev, "drop", None))


def test_expired_presigned_url_is_denied(server):
    url = server.client().generate_presigned_url(
        "get_object", Params={"Bucket": "nw-config-backup", "Key": ".env"}, ExpiresIn=1)
    time.sleep(1.2)
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(url, timeout=5)
    assert exc.value.code == 403 and b"Request has expired" in exc.value.read()


# ---- loopback: auth -----------------------------------------------------------------------

def test_anonymous_access_only_to_public_buckets(server):
    anon = server.client(unsigned=True)
    assert [o["Key"] for o in anon.list_objects_v2(Bucket="nw-public-assets")["Contents"]] == \
        ["logo.txt"]
    assert anon.get_object(Bucket="nw-public-assets", Key="logo.txt")["Body"].read() == \
        b"northwind\n"
    for call in (lambda: anon.list_objects_v2(Bucket="nw-config-backup"),
                 lambda: anon.get_object(Bucket="nw-config-backup", Key=".env"),
                 lambda: anon.list_buckets()):
        with pytest.raises(ClientError) as exc:
            call()
        assert error_code(exc.value) == "AccessDenied"
    ev = server.commands("GetObject")[0]
    assert ev["data"]["auth"] == "anonymous" and "access_key_id" not in ev["data"]


def test_bad_signature_and_unknown_key(server):
    with pytest.raises(ClientError) as exc:
        server.client(secret="wrong-secret").list_buckets()
    assert error_code(exc.value) == "SignatureDoesNotMatch"
    with pytest.raises(ClientError) as exc:
        server.client(key=OTHER_KEY, secret="whatever").list_buckets()
    assert error_code(exc.value) == "InvalidAccessKeyId"
    auths = server.events("auth_attempt")
    assert [a["success"] for a in auths] == [False, False]
    assert auths[0]["data"]["reason"] == "signature_mismatch"
    assert "password" not in auths[0]


def test_secretless_listed_key_and_policy_all(tmp_path):
    srv = Server(make_ctx(tmp_path, accept="all"))
    try:
        assert srv.client(key=OTHER_KEY, secret="anything").list_buckets()["Buckets"]
        any_key = "AKIA" + "ANYSECRET" + "OKEXAMPLE"[:7]
        assert srv.client(key=any_key, secret="x").list_buckets()["Buckets"]
        # One auth_attempt per credential per connection, one command per request.
        c = srv.client(key=OTHER_KEY, secret="anything")
        c.list_buckets()
        c.list_buckets()
        assert len([a for a in srv.events("auth_attempt") if a["username"] == OTHER_KEY]) == 2
    finally:
        srv.close()


def test_after_n_is_keyed_on_the_access_key(tmp_path):
    ctx = make_ctx(tmp_path, accept="after_n")
    ctx.settings["s3"].policy = LoginPolicy(accept="after_n", after_n_min=2, after_n_max=2)
    srv = Server(ctx)
    try:
        with pytest.raises(ClientError):
            srv.client(key="AKIA" + "B" * 16, secret="x").list_buckets()
        assert srv.client(key="AKIA" + "C" * 16, secret="x").list_buckets()["Buckets"]
        with pytest.raises(ClientError):   # only the key that "worked" keeps working
            srv.client(key="AKIA" + "D" * 16, secret="x").list_buckets()
        assert srv.client(key="AKIA" + "C" * 16, secret="y").list_buckets()["Buckets"]
    finally:
        srv.close()


def test_planted_key_raises_the_high_signal_whatever_the_policy(tmp_path):
    srv = Server(make_ctx(tmp_path, accept="listed"))
    try:
        token = srv.ctx.scenario.honeytokens["backup_key"].value
        out = srv.client(key=token, secret="whatever").list_buckets()
        assert out["Buckets"]                     # a planted key "works" (not a listed account)
        auth = srv.events("auth_attempt")[-1]
        assert auth["success"] is True and auth["data"]["honeytoken"] == "backup_key"
        cmd = srv.commands("ListBuckets")[-1]["data"]
        assert cmd["high_signal"] is True and cmd["honeytoken"] == "backup_key"
        assert cmd["signal"] == "s3_planted_key"
    finally:
        srv.close()
    srv = Server(make_ctx(tmp_path / "none", accept="none"))
    try:
        token = srv.ctx.scenario.honeytokens["backup_key"].value
        with pytest.raises(ClientError) as exc:    # policy "none" refuses every key ...
            srv.client(key=token, secret="whatever").list_buckets()
        assert error_code(exc.value) == "InvalidAccessKeyId"
        cmd = srv.commands("ListBuckets")[-1]["data"]   # ... and the signal is still raised
        assert cmd["high_signal"] is True and cmd["signal"] == "s3_planted_key"
    finally:
        srv.close()


def test_source_marked_plant_token_sees_its_own_credentials(tmp_path):
    from agents.source_state import new_entry, update, SourceState
    from agents.budget import ip_key

    state = tmp_path / "source_state.json"

    def mutate(st: SourceState) -> SourceState:
        e = new_entry(ip_key("127.0.0.1"))
        st.entries[e.key] = e.model_copy(update={"plant_token": True})
        return st

    update(state, tmp_path / "state", mutate)
    scen = make_scenario()
    ctx = make_ctx(tmp_path)
    ctx = ListenerContext(EventWriter(None), seed=SEED, scenario=scen, bind_host="127.0.0.1",
                          quarantine_dir=str(tmp_path / "q2"), source_state_path=str(state))
    ctx.source_state.check_every = 0.0
    ctx.settings["s3"] = ServiceSettings(name="s3", enabled=True, port=0,
                                         policy=LoginPolicy(accept="listed"),
                                         accounts=scen.accounts_for("s3"))
    srv = Server(ctx)
    try:
        c = srv.client()
        keys = [o["Key"] for o in c.list_objects_v2(Bucket="nw-config-backup")["Contents"]]
        assert ".aws/credentials" in keys
        body = c.get_object(Bucket="nw-config-backup", Key=".aws/credentials")["Body"].read()
        key_id, _secret = ctx.source_token("127.0.0.1")
        assert key_id.encode() in body
        # Using that key against the trap is the planted-token signal.
        srv.client(key=key_id, secret="x").list_buckets()
        assert srv.commands("ListBuckets")[-1]["data"]["signal"] == "s3_planted_key"
    finally:
        srv.close()


# ---- loopback: uploads --------------------------------------------------------------------

def _quarantined(ctx) -> list:
    return sorted(p for p in ctx.quarantine.dir.glob("*.bin"))


def test_put_object_goes_to_quarantine_and_lists_for_that_source_only(server):
    c = server.client()
    data = b"#!/bin/sh\necho planted\n" * 100
    put = c.put_object(Bucket="nw-config-backup", Key="tools/x.sh", Body=data)
    assert put["ETag"].strip('"') == hashlib.md5(data).hexdigest()
    files = _quarantined(server.ctx)
    assert len(files) == 1 and files[0].read_bytes() == data
    keys = [o["Key"] for o in c.list_objects_v2(Bucket="nw-config-backup")["Contents"]]
    assert "tools/x.sh" in keys
    assert c.head_object(Bucket="nw-config-backup", Key="tools/x.sh")["ContentLength"] == len(data)
    assert c.get_object(Bucket="nw-config-backup", Key="tools/x.sh")["Body"].read() == data
    ev = server.commands("PutObject")[-1]["data"]
    assert ev["signal"] == "s3_upload" and ev["high_signal"] is True and ev["stored"] is True
    assert ev["sha256"] == hashlib.sha256(data).hexdigest() and ev["size"] == len(data)
    c.delete_object(Bucket="nw-config-backup", Key="tools/x.sh")
    keys = [o["Key"] for o in c.list_objects_v2(Bucket="nw-config-backup")["Contents"]]
    assert "tools/x.sh" not in keys
    # Another source never sees the upload.
    view = s3.catalog(server.ctx).listing_keys("nw-config-backup", "198.51.100.7")
    assert "tools/x.sh" not in view


def test_delete_of_a_scenario_object_pretends_to_succeed(server):
    c = server.client()
    c.delete_object(Bucket="nw-config-backup", Key=".env")
    keys = [o["Key"] for o in c.list_objects_v2(Bucket="nw-config-backup")["Contents"]]
    assert ".env" not in keys
    out = c.delete_objects(Bucket="nw-call-recordings", Delete={"Objects": [
        {"Key": "index.txt"}, {"Key": "exports/cdr.log"}]})
    assert sorted(d["Key"] for d in out["Deleted"]) == ["exports/cdr.log", "index.txt"]
    assert server.commands("DeleteObjects")[-1]["data"]["delete_count"] == 2


def test_put_over_the_cap_is_truncated_like_ftp(tmp_path):
    srv = Server(make_ctx(tmp_path, quarantine_max_file_bytes=65_536))
    try:
        data = os.urandom(200_000)
        with pytest.raises(Exception):
            srv.client().put_object(Bucket="nw-config-backup", Key="big.bin", Body=data)
        files = _quarantined(srv.ctx)
        assert len(files) == 1 and files[0].read_bytes() == data[:65_536]
        ev = srv.commands("PutObject")[-1]["data"]
        assert ev["truncated"] is True and ev["reason"] == "quarantine_max_file_bytes"
        assert ev["size"] == 65_536
    finally:
        srv.close()


def test_expect_continue_and_aws_chunked_payload(server):
    payload = b"hello chunked world " * 1000
    chunks = [payload[:8192], payload[8192:]]
    body = b""
    for ch in chunks:
        body += f"{len(ch):x};chunk-signature={'a' * 64}\r\n".encode() + ch + b"\r\n"
    body += b"0;chunk-signature=" + b"a" * 64 + b"\r\n\r\n"
    any_key = "AKIA" + "ANYSECRET" + "OKEXAMPLE"[:7]
    auth = (f"AWS4-HMAC-SHA256 Credential={any_key}/20261116/us-east-1/s3/aws4_request, "
            "SignedHeaders=host;x-amz-date, Signature=" + "c" * 64)
    head = (f"PUT /nw-config-backup/chunked.txt HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\n"
            "x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r\n"
            "Content-Encoding: aws-chunked\r\n"
            f"x-amz-decoded-content-length: {len(payload)}\r\n"
            f"Content-Length: {len(body)}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n")
    with socket.create_connection(("127.0.0.1", server.port), timeout=5) as sock:
        sock.sendall(head.encode())
        interim = sock.recv(100)
        assert interim.startswith(b"HTTP/1.1 100 Continue")
        sock.sendall(body)
        final = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            final += chunk
    assert final.startswith(b"HTTP/1.1 200"), final[:200]
    assert _quarantined(server.ctx)[0].read_bytes() == payload


def test_expect_continue_is_not_sent_when_the_request_is_refused(server):
    head = (b"PUT /nw-config-backup/x HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n"
            b"Expect: 100-continue\r\n\r\n")
    raw = server.raw(head, timeout=2)
    assert raw.startswith(b"HTTP/1.1 403") and b"100 Continue" not in raw
    assert b"<Code>AccessDenied</Code>" in raw and _quarantined(server.ctx) == []


def test_multipart_upload_stores_parts(server):
    c = server.client()
    mpu = c.create_multipart_upload(Bucket="nw-config-backup", Key="dump.sql")
    uid = mpu["UploadId"]
    parts = []
    for n, chunk in enumerate([b"a" * 70_000, b"b" * 1000], start=1):
        r = c.upload_part(Bucket="nw-config-backup", Key="dump.sql", UploadId=uid,
                          PartNumber=n, Body=chunk)
        parts.append({"PartNumber": n, "ETag": r["ETag"]})
    done = c.complete_multipart_upload(Bucket="nw-config-backup", Key="dump.sql",
                                       UploadId=uid, MultipartUpload={"Parts": parts})
    assert done["ETag"].strip('"').endswith("-2")
    assert len(_quarantined(server.ctx)) == 2
    head = c.head_object(Bucket="nw-config-backup", Key="dump.sql")
    assert head["ContentLength"] == 71_000
    ev = server.commands("UploadPart")[-1]["data"]
    assert ev["upload_id"] == uid and ev["part_number"] == 2 and ev["signal"] == "s3_upload"
    with pytest.raises(ClientError) as exc:
        c.upload_part(Bucket="nw-config-backup", Key="dump.sql", UploadId="nope",
                      PartNumber=1, Body=b"x")
    assert error_code(exc.value) == "NoSuchUpload"


def test_copy_and_bucket_level_writes_are_denied(server):
    c = server.client()
    for call in (lambda: c.copy_object(Bucket="nw-config-backup", Key="c",
                                       CopySource="nw-config-backup/.env"),
                 lambda: c.create_bucket(Bucket="new-bucket-here"),
                 lambda: c.delete_bucket(Bucket="nw-config-backup")):
        with pytest.raises(ClientError) as exc:
            call()
        assert error_code(exc.value) == "AccessDenied"
    raw = server.raw(b"PATCH /nw-config-backup/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 405") and b"MethodNotAllowed" in raw


# ---- limits and hostile input -------------------------------------------------------------

def test_oversized_headers_are_refused(server):
    raw = server.raw(b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: " + b"a" * 20_000 + b"\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 400") and b"RequestHeaderSectionTooLarge" in raw
    raw = server.raw(b"GET / HTTP/1.1\r\n" + b"X-A: b\r\n" * 60 + b"\r\n")
    assert raw.startswith(b"HTTP/1.1 400")


def test_huge_declared_content_length(server):
    any_key = "AKIA" + "ANYSECRET" + "OKEXAMPLE"[:7]
    auth = (f"AWS4-HMAC-SHA256 Credential={any_key}/20261116/us-east-1/s3/aws4_request, "
            "SignedHeaders=host, Signature=" + "c" * 64)
    req = (f"PUT /nw-config-backup/x HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\n"
           "Content-Length: 999999999999999999\r\n\r\n").encode()
    raw = server.raw(req + b"x" * 1000, timeout=2)
    assert raw.startswith(b"HTTP/1.1 400") and b"EntityTooLarge" in raw
    assert _quarantined(server.ctx) == []
    raw = server.raw(b"GET /nw-public-assets/logo.txt HTTP/1.1\r\nHost: x\r\n"
                     b"Content-Length: 10000000\r\n\r\n", timeout=2)
    assert raw.startswith(b"HTTP/1.1 400") and b"MaxMessageLengthExceeded" in raw


@pytest.mark.parametrize("body", [
    b"fffffffffffffffffffff;chunk-signature=x\r\n",           # size field too long
    b"7fffffff;chunk-signature=x\r\n" + b"a" * 100,            # larger than the declared body
    b"zz\r\n",                                                   # not hex
    b"5;" + b"x" * 9000 + b"\r\n",                               # endless chunk extension
    b"5\r\nhelloXX",                                             # missing CRLF after data
    (b"1\r\na\r\n" * 3000) + b"0\r\n\r\n",                       # tiny-chunk framing overhead
], ids=["long-size", "past-length", "not-hex", "long-extension", "no-crlf", "tiny-chunks"])
def test_aws_chunked_abuse(server, body):
    any_key = "AKIA" + "ANYSECRET" + "OKEXAMPLE"[:7]
    auth = (f"AWS4-HMAC-SHA256 Credential={any_key}/20261116/us-east-1/s3/aws4_request, "
            "SignedHeaders=host, Signature=" + "c" * 64)
    req = (f"PUT /nw-config-backup/abuse HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\n"
           "Content-Encoding: aws-chunked\r\n"
           "x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    raw = server.raw(req + body, timeout=3)
    assert raw.startswith(b"HTTP/1.1 "), raw[:100]
    # The listener keeps serving.
    assert server.raw(b"GET /nw-public-assets/logo.txt HTTP/1.1\r\nHost: x\r\n"
                      b"Connection: close\r\n\r\n").startswith(b"HTTP/1.1 200")


def test_transfer_encoding_chunked_is_refused(server):
    raw = server.raw(b"PUT /nw-config-backup/x HTTP/1.1\r\nHost: x\r\n"
                     b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 411") and b"MissingContentLength" in raw


def test_path_traversal_keys_never_touch_the_filesystem(server, tmp_path):
    c = server.client()
    with pytest.raises(ClientError) as exc:
        c.get_object(Bucket="nw-config-backup", Key="../../../etc/passwd")
    assert error_code(exc.value) == "NoSuchKey"
    raw = server.raw(b"GET /nw-config-backup/%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: x\r\n"
                     b"Connection: close\r\n\r\n")
    assert b"HTTP/1.1 403" in raw or b"HTTP/1.1 404" in raw
    c.put_object(Bucket="nw-config-backup", Key="../../../../tmp/evil.sh", Body=b"x")
    names = [p.name for p in server.ctx.quarantine.dir.iterdir()]
    assert all(n.endswith((".bin", ".json")) and "evil" not in n for n in names)
    assert any(e["data"].get("path_traversal") for e in server.commands("GetObject"))
    assert any(e["data"].get("path_traversal") for e in server.commands("PutObject"))


def test_bulk_download_signal(server):
    c = server.client()
    for n in range(s3.BULK_DOWNLOAD_COUNT):
        c.get_object(Bucket="nw-call-recordings", Key=f"2026/11/03/rec-{n:05d}.wav",
                     Range="bytes=0-99")["Body"].read()
    bulk = [e for e in server.commands("GetObject") if e["data"].get("signal") == "s3_bulk_download"]
    assert len(bulk) == 1 and bulk[0]["data"]["high_signal"] is True


def test_every_request_logs_one_command_event_with_the_s3_fields(server):
    c = server.client()
    c.list_buckets()
    c.get_object(Bucket="nw-public-assets", Key="logo.txt")["Body"].read()
    for ev in server.events("command"):
        assert ev["sensor_protocol"] == "s3"
        for field in ("method", "path", "status", "operation", "request_id"):
            assert field in ev["data"], (field, ev)
    assert server.commands("GetObject")[-1]["data"]["bucket"] == "nw-public-assets"
