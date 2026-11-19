"""Event export: ship the JSON-lines event log to an S3 bucket.

Runs only in the agents process (front-ends never connect out), off by default::

    [connector.s3_events]
    enabled = false
    bucket = example-honeypot-events
    prefix = events/
    #region = us-east-1
    #bucket_owner = 123456789012
    source = aws.honeypot
    layout = wrapped        ; wrapped | flat
    passwords = hash        ; hash | clear | drop
    max_events_per_object = 5000
    max_objects_per_run = 50
    max_bytes_per_object = 5242880
    timeout = 10

Object keys are ``<prefix>YYYY/MM/DD/HH-<epoch>-<sensor>-<n>-<random>.jsonl`` where the
date, hour and epoch are the time of the run in UTC, ``n`` counts objects within the run and
``<random>`` is 8 random hex digits, so two runs in the same second never share a key. Each
object holds one JSON object per line, newline terminated. ``wrapped`` lines are
``{"source": <source>, "detail": <event>}``; ``flat`` lines are the event itself.

Delivery is at least once. A cursor in the state directory (same rotation checks as the
triage cursor: inode, first-line hash, newline before the offset) records how far the log
has been shipped. It advances only after a successful ``PutObject``, so a failed or
interrupted run sends the same lines again next time. Only complete lines are shipped.

The client is created on the first put and only ever calls ``PutObject``: a hook on the
client refuses every other operation, including the ``HeadBucket`` that the S3 region
redirect can issue on its own, because the intended bucket policy is write-only.
Credentials come from the default chain (instance role or environment), never from config.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import socket
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from agents.sessions import Cursor, iter_records

log = logging.getLogger("agents.ship")

SECTION = "connector.s3_events"
CURSOR_FILE = "ship_cursor.json"
EVENTS_FILE = "ship_events.jsonl"
MAX_EVENTS_FILE_BYTES = 1024 * 1024
MAX_KEYS_REPORTED = 50

DEFAULT_PREFIX = "events/"
DEFAULT_SOURCE = "aws.honeypot"
DEFAULT_MAX_EVENTS = 5000
DEFAULT_MAX_OBJECTS = 50
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 30.0
MAX_ATTEMPTS = 2
HASH_PREFIX = "sha256:"
SALT_LABEL = b"winnie-s3-events-password-v1|"

_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_PREFIX_RE = re.compile(r"^[A-Za-z0-9!_.*'()/=-]{0,256}$")
_SOURCE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z0-9]+){2,3}$")
_OWNER_RE = re.compile(r"^[0-9]{12}$")
_SENSOR_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


class ConfigError(ValueError):
    """Load-time problem. Messages never include configured values."""


class OperationRefused(RuntimeError):
    """The S3 client was asked for an operation other than PutObject."""


# ---- password-carrying fields ------------------------------------------------------------

def _data_upper(rec: dict, key: str) -> str:
    data = rec.get("data")
    value = data.get(key) if isinstance(data, dict) else None
    return value.upper() if isinstance(value, str) else ""


def _redis_secret_command(rec: dict) -> bool:
    cmd = _data_upper(rec, "cmd")
    if cmd in ("AUTH", "HELLO", "MIGRATE"):
        return True
    text = _data_upper(rec, "input")
    return cmd == "CONFIG" and ("REQUIREPASS" in text or "MASTERAUTH" in text)


def _captured_secret(rec: dict) -> bool:
    label = _data_upper(rec, "capture_label")
    if label == "HTTP_BODY":
        return True
    return label == "FTP_COMMAND" and _data_upper(rec, "part_00").lstrip().startswith("PASS")


@dataclass(frozen=True)
class SecretField:
    """One place an event can carry a submitted password or secret.

    ``protocol`` is a ``sensor_protocol`` value or ``*``. ``field`` is ``password`` (the
    top-level field) or ``data.<key>``; a key ending in ``*`` matches by prefix. ``when``
    limits the rule to matching events.
    """

    protocol: str
    field: str
    reason: str
    when: Optional[Callable[[dict], bool]] = None


SECRET_FIELDS: tuple[SecretField, ...] = (
    SecretField("*", "password", "auth attempts on every protocol: SSH, Telnet, FTP PASS, "
                "SMTP AUTH, Redis AUTH, HTTP basic, bearer and form logins, SIP, MySQL, "
                "PostgreSQL and MSSQL (submitted or recovered password)"),
    SecretField("sip", "data.auth_password", "password recovered from an INVITE digest"),
    SecretField("sip", "data.response", "REGISTER digest response; with realm and nonce it "
                "can be cracked offline"),
    SecretField("mysql", "data.auth_response", "scrambled password; with the salt it can be "
                "cracked offline"),
    SecretField("postgres", "data.md5_response", "MD5 password response; with the salt it "
                "can be cracked offline"),
    SecretField("http", "data.body", "form and API request bodies carry login fields"),
    SecretField("http", "data.auth_raw", "Authorization header value that could not be "
                "parsed (undecodable basic credentials or an unknown scheme)"),
    SecretField("s3", "data.security_token", "X-Amz-Security-Token of a temporary credential "
                "(header or presigned URL); request signatures are never logged"),
    SecretField("ftp", "data.input", "the raw PASS command line",
                when=lambda rec: _data_upper(rec, "cmd") == "PASS"),
    SecretField("redis", "data.input", "AUTH, HELLO ... AUTH, MIGRATE ... AUTH and CONFIG SET "
                "requirepass or masterauth carry passwords", when=_redis_secret_command),
    SecretField("*", "data.part_*", "captured HTTP bodies and FTP PASS lines",
                when=_captured_secret),
)

# Data keys whose name looks like a secret but whose value is not one. Every other data key
# matching PASSWORD_KEY_RE (including client-named ones such as PostgreSQL startup
# parameters and MySQL connection attributes) is treated as a secret.
NOT_SECRET_KEYS = frozenset({
    "password_recovered",   # bool: whether the trap recovered the password
    "honeytoken",           # name of the planted token that was used, not its value
})

PASSWORD_KEY_RE = re.compile(r"(?i)(pass|pwd|secret|token|cred|auth_resp|md5_resp|scramble)")


def _secret_paths(rec: dict) -> list[tuple[str, Optional[str]]]:
    """(container, key) pairs to protect in ``rec``: ("top", "password") or ("data", key)."""
    protocol = str(rec.get("sensor_protocol", ""))
    data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
    out: list[tuple[str, Optional[str]]] = []
    for rule in SECRET_FIELDS:
        if rule.protocol not in ("*", protocol):
            continue
        if rule.when is not None and not rule.when(rec):
            continue
        if rule.field == "password":
            out.append(("top", "password"))
            continue
        key = rule.field[len("data."):]
        if key.endswith("*"):
            out += [("data", k) for k in data if k.startswith(key[:-1])]
        elif key in data:
            out.append(("data", key))
    out += [("data", k) for k in data
            if k not in NOT_SECRET_KEYS and PASSWORD_KEY_RE.search(k)]
    return list(dict.fromkeys(out))


# Secrets inside free text, scrubbed in every string field of an event (hash or drop mode):
# group 1 is kept, group 2 is the secret.
FREE_TEXT_SECRETS: tuple[tuple[str, re.Pattern], ...] = (
    # URL query or form parameters named like a secret: ?password=, &api_key=, ;jsessionid=
    ("*", re.compile(r"(?i)((?:^|[?&;])[\w.\-\[\]]*(?:pass|pwd|secret|token|key|auth|cred|sig|"
                     r"session)[\w.\-\[\]]*=)([^&#\s;]+)")),
    # URL userinfo: scheme://user:secret@host
    ("*", re.compile(r"(?i)(\b[a-z][a-z0-9+.\-]*://[^/\s:@]*:)([^@\s/]+)(?=@)")),
    # SIP URI userinfo: sip:user:secret@host
    ("*", re.compile(r"(?i)(\bsips?:[^:@\s;<>]+:)([^@\s;<>]+)(?=@)")),
    # Redis ACL SETUSER rules (lines naming SETUSER): >password adds one, <password removes one
    ("redis_acl", re.compile(r"((?:^|\s)[<>])(\S+)")),
    # Redis AUTH [user] password, anywhere in a command line
    ("redis", re.compile(r"(?i)(\bAUTH2?\s+(?:\S+\s+)?)(\S+)")),
)


def _scrub_text(text: str, protocol: str, replace: Callable[[str], str]) -> str:
    scopes = {"*", protocol}
    if protocol == "redis" and "SETUSER" in text.upper():
        scopes.add("redis_acl")
    for scope, pattern in FREE_TEXT_SECRETS:
        if scope in scopes:
            text = pattern.sub(lambda m: m.group(1) + replace(m.group(2)), text)
    return text


def password_key(seed: str) -> bytes:
    """Per-sensor key for password hashing, derived from the sensor seed."""
    return hashlib.sha256(SALT_LABEL + seed.encode("utf-8")).digest()


def hash_secret(key: bytes, value: str) -> str:
    return HASH_PREFIX + hmac.new(key, value.encode("utf-8", "surrogatepass"),
                                  hashlib.sha256).hexdigest()


def protect(rec: dict, mode: str, key: Optional[bytes]) -> dict:
    """A copy of ``rec`` with every password-carrying field hashed, dropped or kept.

    Only non-empty strings are hashed; an empty password stays empty (it reveals nothing
    and is itself a useful signal).
    """
    if mode == "clear":
        return rec
    out = dict(rec)
    if isinstance(out.get("data"), dict):
        out["data"] = dict(out["data"])
    for container, k in _secret_paths(rec):
        target = out if container == "top" else out["data"]
        if k not in target:
            continue
        if mode == "drop":
            del target[k]
        elif isinstance(target[k], str) and target[k]:
            target[k] = hash_secret(key, target[k])
    protocol = str(rec.get("sensor_protocol", ""))

    def replace(secret: str) -> str:
        return "" if mode == "drop" else hash_secret(key, secret)

    for container in (out, out.get("data") if isinstance(out.get("data"), dict) else {}):
        for k, v in container.items():
            if isinstance(v, str) and v and not v.startswith(HASH_PREFIX):
                container[k] = _scrub_text(v, protocol, replace)
    return out


# ---- settings ------------------------------------------------------------------------------

@dataclass(frozen=True)
class ShipSettings:
    enabled: bool = False
    bucket: str = ""
    prefix: str = DEFAULT_PREFIX
    region: Optional[str] = None
    bucket_owner: Optional[str] = None
    source: str = DEFAULT_SOURCE
    layout: str = "wrapped"
    passwords: str = "hash"
    max_events_per_object: int = DEFAULT_MAX_EVENTS
    max_objects_per_run: int = DEFAULT_MAX_OBJECTS
    max_bytes_per_object: int = DEFAULT_MAX_BYTES
    timeout: float = DEFAULT_TIMEOUT

    @classmethod
    def from_config(cls, config) -> "ShipSettings":
        """Read ``[connector.s3_events]``. Missing section: disabled. Raises ConfigError."""
        if config is None or not config.has_section(SECTION):
            return cls()
        sec = config[SECTION]
        try:
            enabled = sec.getboolean("enabled", fallback=False)
        except ValueError:
            raise ConfigError("enabled must be true or false") from None
        if not enabled:
            return cls()
        bucket = sec.get("bucket", "").strip()
        if not _BUCKET_RE.fullmatch(bucket) or ".." in bucket:
            raise ConfigError("bucket is missing or not a valid bucket name")
        prefix = sec.get("prefix", DEFAULT_PREFIX).strip()
        if not _PREFIX_RE.fullmatch(prefix) or prefix.startswith("/") or ".." in prefix \
                or "//" in prefix:
            raise ConfigError("prefix contains characters outside the allowed set")
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        region = sec.get("region", "").strip() or None
        if region is not None and not _REGION_RE.fullmatch(region):
            raise ConfigError("region is not a valid region name")
        owner = sec.get("bucket_owner", "").strip() or None
        if owner is not None and not _OWNER_RE.fullmatch(owner):
            raise ConfigError("bucket_owner must be a 12-digit account id")
        source = sec.get("source", DEFAULT_SOURCE).strip()
        if not _SOURCE_RE.fullmatch(source):
            raise ConfigError("source must be 1-64 letters, digits, '.', '_' or '-'")
        layout = sec.get("layout", "wrapped").strip().lower()
        if layout not in ("wrapped", "flat"):
            raise ConfigError("layout must be wrapped or flat")
        passwords = sec.get("passwords", "hash").strip().lower()
        if passwords not in ("hash", "clear", "drop"):
            raise ConfigError("passwords must be hash, clear or drop")

        def _int(name: str, default: int, lo: int, hi: int) -> int:
            try:
                value = int(sec.get(name, str(default)))
            except ValueError:
                raise ConfigError(f"{name} must be an integer") from None
            if not lo <= value <= hi:
                raise ConfigError(f"{name} must be between {lo} and {hi}")
            return value

        try:
            timeout = float(sec.get("timeout", str(DEFAULT_TIMEOUT)))
        except ValueError:
            raise ConfigError("timeout must be a number") from None
        if not 0 < timeout <= MAX_TIMEOUT:
            raise ConfigError(f"timeout must be above 0 and at most {MAX_TIMEOUT:g}")
        return cls(enabled=True, bucket=bucket, prefix=prefix, region=region,
                   bucket_owner=owner, source=source, layout=layout, passwords=passwords,
                   max_events_per_object=_int("max_events_per_object", DEFAULT_MAX_EVENTS,
                                              1, 100_000),
                   max_objects_per_run=_int("max_objects_per_run", DEFAULT_MAX_OBJECTS,
                                            1, 10_000),
                   max_bytes_per_object=_int("max_bytes_per_object", DEFAULT_MAX_BYTES,
                                             1024, 64 * 1024 * 1024),
                   timeout=timeout)


def sensor_label(config) -> str:
    """The sensor name for object keys: ``[honeypot] sensor_name`` (else the host name, as
    the SSH front-end does), restricted to letters, digits, '.', '_' and '-'."""
    name = ""
    if config is not None and config.has_section("honeypot"):
        name = config["honeypot"].get("sensor_name", "").strip()
    name = name or socket.gethostname()
    return _SENSOR_UNSAFE.sub("-", name).strip("-.")[:64] or "sensor"


# ---- client --------------------------------------------------------------------------------

def refuse_other_operations(model=None, **_kwargs) -> None:
    """``before-call.s3`` hook: anything but PutObject raises before a request is sent."""
    name = getattr(model, "name", None)
    if name != "PutObject":
        raise OperationRefused(f"S3 operation {str(name)[:40]} is not allowed")


def s3_client(region: Optional[str], timeout: float, hooks: tuple, endpoint_url=None,
              session=None):
    """An S3 client from the default credential chain with timeouts, limited retries and
    ``hooks`` ((event, handler) pairs) registered. ``endpoint_url`` points it at an
    S3-compatible store instead of AWS. Imports boto3 only when called."""
    from botocore.config import Config

    if session is None:
        import boto3

        session = boto3.session.Session()
    cfg = Config(connect_timeout=timeout, read_timeout=timeout,
                 retries={"total_max_attempts": MAX_ATTEMPTS, "mode": "standard"},
                 tcp_keepalive=False)
    kw = {"endpoint_url": endpoint_url} if endpoint_url else {}
    client = session.client("s3", region_name=region, config=cfg, use_ssl=True, **kw)
    for event, handler in hooks:
        client.meta.events.register(event, handler)
    return client


def default_client_factory(settings: ShipSettings, session=None):
    """The event export's client: PutObject only."""
    return s3_client(settings.region, settings.timeout,
                     (("before-call.s3", refuse_other_operations),), session=session)


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if code:
            return f"{type(exc).__name__}: {str(code)[:64]}"
    return type(exc).__name__


# ---- run -----------------------------------------------------------------------------------

@dataclass
class _Batch:
    lines: list[bytes] = field(default_factory=list)
    size: int = 0
    end: int = 0


def object_key(settings: ShipSettings, now: datetime.datetime, sensor: str, n: int) -> str:
    now = now.astimezone(datetime.timezone.utc)
    return (f"{settings.prefix}{now:%Y/%m/%d}/{now:%H}-{int(now.timestamp())}-"
            f"{sensor}-{n}-{secrets.token_hex(4)}.jsonl")


def _encode(rec: dict, settings: ShipSettings, key: Optional[bytes]) -> bytes:
    rec = protect(rec, settings.passwords, key)
    if settings.layout == "wrapped":
        rec = {"source": settings.source, "detail": rec}
    return (json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
        "utf-8", "backslashreplace")


def _record_event(state_dir: Path, event: dict) -> None:
    """Append a failure event to the export's own event file (bounded)."""
    path = state_dir / EVENTS_FILE
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > MAX_EVENTS_FILE_BYTES:
            keep = path.read_bytes()[-MAX_EVENTS_FILE_BYTES // 2:]
            keep = keep[keep.find(b"\n") + 1:]
            fd, tmp = tempfile.mkstemp(dir=state_dir, prefix=".ship-events-", suffix=".tmp")
            with os.fdopen(fd, "wb") as f:
                f.write(keep)
            os.replace(tmp, path)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except OSError as exc:
        log.error("cannot record export event: %s", type(exc).__name__)


def run_ship(settings: ShipSettings, log_path, state_dir, *, seed: Optional[str],
             sensor: str, dry_run: bool = False, client_factory=None,
             now: Optional[datetime.datetime] = None) -> dict:
    """Ship complete log lines past the cursor, at most ``max_objects_per_run`` objects.

    Never raises for S3 failures: the error is recorded as an event, logged and returned
    in the summary, and the cursor stays at the last object that was stored.
    """
    if not settings.enabled:
        return {"status": "disabled"}
    state_dir = Path(state_dir)
    from agents.runtime import event_log_state

    log_state, log_error = event_log_state(log_path)
    if log_state == "missing":
        log.info("no event log yet at %s; nothing to export", log_path)
        return {"status": "no_log", "objects": 0, "more_pending": False}
    if log_error:
        return {"error": log_error}
    key = None
    if settings.passwords == "hash":
        if not seed:
            return {"error": "passwords = hash needs the sensor seed, which is not available; "
                             "nothing shipped"}
        key = password_key(seed)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    factory = client_factory or default_client_factory
    cursor = Cursor(state_dir / CURSOR_FILE)
    start = cursor.start_offset(log_path)
    summary: dict = {"objects": 0, "events": 0, "bytes": 0, "skipped_malformed": 0,
                     "skipped_oversized": 0, "more_pending": False, "keys": [],
                     "start_offset": start}
    client = None

    def put(batch: _Batch) -> bool:
        nonlocal client
        n = summary["objects"]
        obj_key = object_key(settings, now, sensor, n)
        body = b"".join(batch.lines)
        if not dry_run:
            params = {"Bucket": settings.bucket, "Key": obj_key, "Body": body,
                      "ContentType": "application/x-ndjson"}
            if settings.bucket_owner:
                params["ExpectedBucketOwner"] = settings.bucket_owner
            try:
                if client is None:
                    client = factory(settings)
                client.put_object(**params)
            except Exception as exc:  # noqa: BLE001 - a failed export never stops a run
                code = _error_code(exc)
                summary["error"] = f"PutObject failed: {code}"
                log.error("event export: PutObject failed (%s); %d object(s) stored this run, "
                          "the rest is sent next run", code, n)
                _record_event(state_dir, {
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "event": "s3_put_failed", "key": obj_key, "error": code,
                    "lines": len(batch.lines)})
                return False
            cursor.set_position(batch.end, log_path)
            cursor.save()
        summary["objects"] += 1
        summary["events"] += len(batch.lines)
        summary["bytes"] += len(body)
        if len(summary["keys"]) < MAX_KEYS_REPORTED:
            summary["keys"].append(obj_key)
        return True

    batch = _Batch()
    stopped = False
    for _start, end, rec in iter_records(log_path, start):
        if rec is None:
            summary["skipped_malformed"] += 1
            batch.end = end
            continue
        if not rec:
            batch.end = end
            continue
        line = _encode(rec, settings, key)
        if len(line) > settings.max_bytes_per_object:
            summary["skipped_oversized"] += 1
            batch.end = end
            continue
        if batch.lines and (len(batch.lines) >= settings.max_events_per_object
                            or batch.size + len(line) > settings.max_bytes_per_object):
            if not put(batch):
                return summary
            batch = _Batch(end=batch.end)
            if summary["objects"] >= settings.max_objects_per_run:
                summary["more_pending"] = True
                stopped = True
                break
        batch.lines.append(line)
        batch.size += len(line)
        batch.end = end
    if not stopped:
        if batch.lines:
            if not put(batch):
                return summary
        elif batch.end > start and not dry_run:
            # Only skipped lines since the last object: move past them.
            cursor.set_position(batch.end, log_path)
            cursor.save()
    summary["dry_run"] = dry_run
    return summary
