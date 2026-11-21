"""Give confirmed indicators back to the community as an AlienVault OTX pulse.

Off by default. Two halves, which may run in different processes, as with the delivered
InternetDB lookups:

1. **Candidates, written by ``run-all``** (it has the triage records; on AWS the agents
   container, which has no egress and no key). One small local file, by default
   ``otx_candidates.json`` next to the blocklist file (as ``tracked.json`` is)::

       {"version": 1, "generated_at": "2026-11-21T12:00:00+00:00",
        "indicators": [
          {"type": "IPv4", "indicator": "198.51.100.7", "protocol": "ssh",
           "classes": ["logged_in", "download_execute"], "last_seen": "2026-11-21T11:40:02+00:00"},
          {"type": "FileHash-SHA256", "indicator": "<64 hex digits>", "protocol": "ftp",
           "classes": ["ftp_upload"], "last_seen": "2026-11-21T11:41:10+00:00"}]}

   Addresses, hashes, fixed names and timestamps only.

2. **The submission, run by ``ship``** (on AWS the exporter, the one process with egress).
   It reads that file with the care the InternetDB wanted list gets (a regular file only,
   a size cap, every field checked, the whole file refused on any problem), and adds what
   it has not sent before to one pulse per UTC day.

Which sources: a triage record seen in the last ``lookback_days`` whose source address is
proven (not ``unverified_source``: a completed TCP exchange or a SIP nonce round trip) and
that did something past probing, by facts the code counted, never by model output:

- ``logged_in``: an accepted login, or an accepted SIP REGISTER (``auth_successes``);
- ``honeytoken``: used a planted credential;
- one of ``ACTIVE_SIGNALS``: the high-signal events triage already counts for running
  commands, uploading, taking a service over, relaying mail or placing calls.

The model's judgement can only hold a source back (a record it judged BENIGN is not
submitted), never put one forward.

What is sent: the IPv4 address of such a source when it is global unicast, and (with
``hashes = true``) the SHA-256 of files from such a source that the quarantine kept whole.
The hash is the one the front-end computed while storing the upload, read from the
quarantine's own metadata, never a hash named in attacker text. Nothing else: no URL,
domain, command, password, user name, user agent or other attacker text. Titles and
descriptions are built from fixed strings and the checked protocol and class names only.

Never sent: an address inside ``[respond] never_act_on`` (the operator's addresses and the
allow-list), a non-global address, the sensor's own address (``[listeners]
ftp_pasv_address``, which the AWS bootstrap sets to the Elastic IP), an unproven UDP source,
and IPv6 addresses (not in this version). The exclusion is ``respond.source_refusal``,
applied when the candidates are written and again when they are read.

The request: fixed host ``otx.alienvault.com`` (configuration cannot point it elsewhere),
HTTPS with certificate and name checks, no redirects followed, no proxy, a 15 s deadline,
a 1 MB answer cap. ``POST /api/v1/pulses/create`` the first time in a UTC day, ``PATCH
/api/v1/pulses/<id>`` with ``{"indicators": {"add": [...]}}`` after that, the key in the
``X-OTX-API-KEY`` header (the paths, header, body shape and indicator type names are those
of the official OTX Python SDK). At most ``max_per_run`` indicators per run (one request)
and ``max_per_day`` per UTC day. A 429, a 5xx, a redirect, a refused key, any other
unexpected status or a network failure stops the run and backs off (15 minutes, doubling
up to a day). The answer is untrusted: only the new pulse's id is read from it, and only
when it is 24 letters or digits.

``dry_run = true`` (the default, even with ``enabled = true``) writes what would be sent
to ``<state-dir>/otx_dry_run.json`` and sends nothing. Sending needs ``enabled = true`` and
``dry_run = false``.

The key comes from the environment variable ``secret_env`` names or the file
``secret_file`` names, as other connectors take credentials. It is read only when a
request is about to be sent and is never logged or written to the state, the dry-run
file, the events or an error message.

State (``<state-dir>/otx_state.json``): the day's pulse id, the day's count, the back-off,
and every indicator sent (at most ``max_entries``, oldest dropped first), so nothing is
sent twice. One event per run with the counts goes to the export's event file. Failures
never raise and never stop the other stages.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import logging
import os
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlsplit

from agents.budget import ip_key
from agents.connectors.base import pin_address
from agents.connectors.http import (
    ConfigError as HttpConfigError,
)
from agents.connectors.http import (
    InvalidSecret,
    ResponseTooLarge,
    SecretMissing,
    UrlTransport,
    parse_env_name,
    read_secret,
)
from agents.internetdb import lookup_address
from agents.internetdb_delivered import (
    InvalidDocument,
    _atomic_write,
    _read_capped,
    _timestamp,
)
from agents.localfile import read_regular
from agents.respond import source_refusal
from agents.sessions import TRAP_PROTOCOLS
from agents.ship import _record_event
from agents.triage import (
    SIGNAL_ACTIONS,
    UNVERIFIED_SOURCE,
    Judgement,
    TriageRecord,
    rank,
)

log = logging.getLogger("agents.otx")
UTC = datetime.timezone.utc

SECTION = "connector.otx"
HOST = "otx.alienvault.com"
BASE_URL = f"https://{HOST}"
CREATE_PATH = "/api/v1/pulses/create"
PULSE_PATH = "/api/v1/pulses/"
KEY_HEADER = "X-OTX-API-KEY"
USER_AGENT = "winnie-otx/1"
TIMEOUT = 15.0
MAX_BODY = 1024 * 1024
BACKOFF_FIRST_MINUTES = 15
BACKOFF_MAX_MINUTES = 24 * 60

CANDIDATES_FILE = "otx_candidates.json"
STATE_FILE = "otx_state.json"
DRY_RUN_FILE = "otx_dry_run.json"
VERSION = 1
MAX_CANDIDATES = 1000
MAX_CANDIDATES_BYTES = 256 * 1024
MAX_STATE_BYTES = 8 * 1024 * 1024
# Quarantine metadata files looked at per run, and the size of one.
MAX_UPLOADS_SCANNED = 5000
MAX_SIDECAR_BYTES = 4096

IPV4 = "IPv4"
SHA256 = "FileHash-SHA256"
TYPES = (IPV4, SHA256)
PROTOCOLS = ("ssh",) + tuple(sorted(TRAP_PROTOCOLS))
# High-signal events that mean the source did something past probing. Left out on purpose:
# ftp_active_mode and http_proxy_attempt, which scanners send as probes.
ACTIVE_SIGNALS = ("download_execute", "persistence", "credential_file_read", "hardware_recon",
                  "redis_takeover", "sql_exec_attempt", "sql_cred_dump", "smtp_relay_attempt",
                  "sip_dialed_number", "s3_bulk_download", "s3_upload", "s3_planted_key",
                  "ftp_upload", "quarantine_quota")
CLASSES = {"logged_in": "Logged in or registered",
           "honeytoken": "Used a planted credential",
           **{name: SIGNAL_ACTIONS[name] for name in ACTIVE_SIGNALS}}
UPLOAD_SIGNALS = ("ftp_upload", "s3_upload")
TLPS = ("white", "green", "amber", "red")

DEFAULTS = {"max_per_run": 200, "max_per_day": 1000, "expiration_days": 30,
            "lookback_days": 7.0, "max_entries": 20000}
BOUNDS = {"max_per_run": (1, 500), "max_per_day": (1, 5000), "expiration_days": (1, 365),
          "lookback_days": (1.0, 30.0), "max_entries": (100, 100000)}
DEFAULT_PULSE_NAME = "Honeypot sources"
DEFAULT_DESCRIPTION = ("Source addresses and uploaded file hashes seen by a honeypot sensor. "
                       "Each source completed a connection and did more than probe.")
DEFAULT_TAGS = ("honeypot",)
KNOWN_KEYS = {"enabled", "submit", "dry_run", "hashes", "secret_env", "secret_file",
              "pulse_name", "description", "tags", "tlp", "public", "candidates_file",
              "addresses_file", *DEFAULTS}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PULSE_ID_RE = re.compile(r"^[0-9A-Za-z]{24}$")
_PULSE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,47}$")
_DESCRIPTION_RE = re.compile(r"^[A-Za-z0-9 .,;:()'/_-]{1,500}$")
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TS_CAP = 40


class ConfigError(ValueError):
    """Load-time problem. Messages never include configured values."""


# ---- settings ------------------------------------------------------------------------------

@dataclass(frozen=True)
class OtxSettings:
    enabled: bool = False
    # false: this process only writes the candidates (the agents container on AWS).
    submit: bool = True
    dry_run: bool = True
    hashes: bool = True
    secret_env: Optional[str] = None
    secret_file: Optional[str] = None
    pulse_name: str = DEFAULT_PULSE_NAME
    description: str = DEFAULT_DESCRIPTION
    tags: tuple = DEFAULT_TAGS
    tlp: str = "green"
    public: bool = False
    max_per_run: int = DEFAULTS["max_per_run"]
    max_per_day: int = DEFAULTS["max_per_day"]
    expiration_days: int = DEFAULTS["expiration_days"]
    lookback_days: float = DEFAULTS["lookback_days"]
    max_entries: int = DEFAULTS["max_entries"]
    candidates_file: Optional[str] = None
    addresses_file: Optional[str] = None

    @classmethod
    def from_config(cls, config) -> "OtxSettings":
        """Read ``[connector.otx]``. Missing or disabled: off. Raises ConfigError. There is
        no key for the destination: it is fixed in code."""
        if config is None or not config.has_section(SECTION):
            return cls()
        sec = config[SECTION]

        def flag(name: str, default: bool) -> bool:
            try:
                return sec.getboolean(name, fallback=default)
            except ValueError:
                raise ConfigError(f"{name} must be true or false") from None

        enabled = flag("enabled", False)
        unknown = sorted(k for k in sec.keys() if k not in KNOWN_KEYS
                         and k not in config.defaults())
        if unknown:
            raise ConfigError("unknown setting (the destination is fixed and cannot be set)")
        if not enabled:
            return cls()

        def num(name: str):
            default = DEFAULTS[name]
            lo, hi = BOUNDS[name]
            try:
                value = type(default)(sec.get(name, str(default)).strip())
            except ValueError:
                raise ConfigError(f"{name} must be a number") from None
            if not lo <= value <= hi:
                raise ConfigError(f"{name} must be between {lo} and {hi}")
            return value

        try:
            secret_env = parse_env_name(sec, "secret_env")
        except HttpConfigError as exc:
            raise ConfigError(str(exc)) from None
        files = {}
        for name in ("secret_file", "candidates_file", "addresses_file"):
            value = sec.get(name, "").strip() or None
            if value is not None and (not os.path.isabs(value) or len(value) > 4096):
                raise ConfigError(f"{name} must be an absolute path")
            files[name] = value
        if secret_env and files["secret_file"]:
            raise ConfigError("set secret_env or secret_file, not both")
        submit, dry_run = flag("submit", True), flag("dry_run", True)
        if submit and not dry_run and not (secret_env or files["secret_file"]):
            raise ConfigError("sending needs secret_env or secret_file")
        pulse_name = sec.get("pulse_name", DEFAULT_PULSE_NAME).strip()
        if not _PULSE_NAME_RE.fullmatch(pulse_name):
            raise ConfigError("pulse_name must be 1-48 letters, digits, spaces, '.', '_' or '-'")
        description = sec.get("description", DEFAULT_DESCRIPTION).strip()
        if not _DESCRIPTION_RE.fullmatch(description):
            raise ConfigError("description must be 1-500 plain characters")
        raw_tags = sec.get("tags", ",".join(DEFAULT_TAGS))
        tags = tuple(dict.fromkeys(t for t in re.split(r"[\s,]+", raw_tags) if t))
        if len(tags) > 10 or any(not _TAG_RE.fullmatch(t) for t in tags):
            raise ConfigError("tags must be at most 10 lower-case words")
        tlp = sec.get("tlp", "green").strip().lower()
        if tlp not in TLPS:
            raise ConfigError("tlp must be white, green, amber or red")
        public = flag("public", False)
        if public and tlp in ("amber", "red"):
            raise ConfigError("a public pulse cannot be TLP amber or red")
        return cls(enabled=True, submit=submit, dry_run=dry_run, hashes=flag("hashes", True),
                   secret_env=secret_env, pulse_name=pulse_name, description=description,
                   tags=tags, tlp=tlp, public=public, **files,
                   max_per_run=num("max_per_run"), max_per_day=num("max_per_day"),
                   expiration_days=num("expiration_days"),
                   lookback_days=num("lookback_days"), max_entries=num("max_entries"))


def candidates_path(settings: OtxSettings, default_dir) -> Path:
    """The candidates file: ``candidates_file`` or ``otx_candidates.json`` in
    ``default_dir`` (the blocklist file's directory)."""
    if settings.candidates_file:
        return Path(settings.candidates_file)
    return Path(default_dir) / CANDIDATES_FILE


def own_networks(config) -> list:
    """The sensor's own address as a network to exclude: ``[listeners] ftp_pasv_address``
    when it is an address. Empty otherwise."""
    if config is None or not config.has_section("listeners"):
        return []
    raw = config["listeners"].get("ftp_pasv_address", "").strip()
    try:
        return [ipaddress.ip_network(raw)] if raw else []
    except ValueError:
        return []


def quarantine_dir(config, base, data_dir_arg) -> Path:
    """Where the front-ends keep uploads: ``<data-dir>/quarantine`` when a data directory
    was given (the container layout), else ``[listeners] quarantine_dir``, else the
    repository's ``quarantine``, exactly as the listeners choose it."""
    if data_dir_arg:
        return Path(data_dir_arg) / "quarantine"
    from agents import REPO_ROOT

    raw = ""
    if config is not None and config.has_section("listeners"):
        raw = config["listeners"].get("quarantine_dir", "").strip()
    if not raw:
        return REPO_ROOT / "quarantine"
    path = Path(raw)
    return path if path.is_absolute() else Path(base) / path


def max_file_bytes(config) -> int:
    """The quarantine's per-file cap (``[listeners] quarantine_max_file_bytes``): a file of
    this size may have been cut, so its hash is not the upload's."""
    from listeners.base import Limits

    section = config["listeners"] if config is not None and config.has_section("listeners") \
        else None
    try:
        return Limits.from_section(section).quarantine_max_file_bytes
    except ValueError:
        return Limits().quarantine_max_file_bytes


# ---- selection (run-all) -------------------------------------------------------------------

def classes_of(r: TriageRecord) -> list[str]:
    """What the source did past probing, from counted facts only."""
    out = []
    if r.auth_successes > 0:
        out.append("logged_in")
    if r.honeytokens:
        out.append("honeytoken")
    out += [name for name in ACTIVE_SIGNALS if r.high_signal.get(name)]
    return out


def eligible(r: TriageRecord) -> bool:
    """A proven source that did something past probing; the model can only veto."""
    if r.unverified_source or r.src_ip == UNVERIFIED_SOURCE:
        return False
    if r.judgement == Judgement.BENIGN or r.protocol not in PROTOCOLS:
        return False
    return bool(classes_of(r))


def _seen(r: TriageRecord) -> Optional[datetime.datetime]:
    return _timestamp(r.last_seen or r.first_seen)


def _allowed_source(key: str, networks: list) -> bool:
    try:
        return source_refusal(key, networks) is None
    except ValueError:
        return False


def read_uploads(directory, cap: int, since: datetime.datetime,
                 limit: int = MAX_UPLOADS_SCANNED) -> list[dict]:
    """The quarantine's metadata files (``<name>.bin.json``, written by the front-ends when
    they stored an upload): ``{"sha256", "src", "stored_at"}`` for each whole file stored
    since ``since``. A file whose size reaches ``cap`` may have been cut and is left out;
    anything malformed is skipped."""
    out: list[dict] = []
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return out
    for name in names[:limit]:
        if not name.endswith(".bin.json") or name.startswith("."):
            continue
        try:
            body = read_regular(Path(directory) / name, MAX_SIDECAR_BYTES)
            if len(body) > MAX_SIDECAR_BYTES:
                continue
            meta = json.loads(body.decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError, RecursionError):
            continue
        if not isinstance(meta, dict):
            continue
        sha, src, size = meta.get("sha256"), meta.get("src"), meta.get("size")
        at = _timestamp(meta.get("stored_at"))
        if not (isinstance(sha, str) and _SHA256_RE.fullmatch(sha) and isinstance(src, str)
                and len(src) <= 64 and isinstance(size, int) and not isinstance(size, bool)
                and 0 < size < cap and at is not None and at >= since):
            continue
        out.append({"sha256": sha, "src": src, "stored_at": at})
    return out


def _iso(dt: datetime.datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def select_candidates(records: Iterable[TriageRecord], networks: list,
                      now: datetime.datetime, lookback_days: float,
                      uploads: Iterable[dict] = (), hashes: bool = True) -> list[dict]:
    """The indicators to offer, most important source first, each once, at most
    ``MAX_CANDIDATES``. ``networks`` is ``never_act_on`` plus the sensor's own address."""
    since = now - datetime.timedelta(days=lookback_days)
    recent = [r for r in records if eligible(r) and (s := _seen(r)) is not None
              and s >= since]
    by_key: dict = {}
    order: list = []

    def add(kind: str, value: str, r: TriageRecord, seen: datetime.datetime,
            protocol: Optional[str] = None) -> None:
        key = (kind, value)
        item = by_key.get(key)
        if item is None:
            item = {"type": kind, "indicator": value, "protocol": protocol or r.protocol,
                    "classes": [], "last_seen": seen}
            by_key[key] = item
            order.append(key)
        for c in classes_of(r):
            if c not in item["classes"]:
                item["classes"].append(c)
        item["last_seen"] = max(item["last_seen"], seen)

    sources: dict = {}
    for r in rank(recent):
        key = ip_key(r.src_ip)
        if not _allowed_source(key, networks):
            continue
        seen = _seen(r)
        sources.setdefault(key, []).append(r)
        addr = lookup_address(r.src_ip)
        if addr is not None and ":" not in addr and ip_key(addr) == key:
            add(IPV4, addr, r, seen)
    if hashes:
        for up in sorted(uploads, key=lambda u: u["stored_at"]):
            for r in sources.get(up["src"], []):
                protocol = next((s.split("_")[0] for s in UPLOAD_SIGNALS if r.high_signal.get(s)),
                                r.protocol)
                add(SHA256, up["sha256"], r, up["stored_at"], protocol)
    items = [by_key[k] for k in order][:MAX_CANDIDATES]
    return [{**i, "classes": [c for c in CLASSES if c in i["classes"]],
             "last_seen": _iso(i["last_seen"])} for i in items]


def candidates_document(items: list[dict], now: datetime.datetime) -> bytes:
    return (json.dumps({"version": VERSION, "generated_at": _iso(now), "indicators": items},
                       separators=(",", ":")) + "\n").encode()


def fit_candidates(items: list[dict], now: datetime.datetime,
                   budget: int = MAX_CANDIDATES_BYTES) -> tuple[list[dict], int]:
    """``(kept, dropped)``: the items whose document fits ``budget`` bytes, the size the
    reader accepts. When they do not all fit, addresses are kept before hashes, and within
    each the most recently seen first; the kept items stay in their original order."""
    if len(candidates_document(items, now)) <= budget:
        return items, 0
    room = budget - len(candidates_document([], now))
    # Addresses first; within a type, newest first (UTC ISO timestamps sort as text).
    order = []
    for kind in (IPV4, SHA256):
        order += sorted((i for i in range(len(items)) if items[i]["type"] == kind),
                        key=lambda i: items[i]["last_seen"], reverse=True)
    chosen: set = set()
    for i in order:
        size = len(json.dumps(items[i], separators=(",", ":")).encode()) + (1 if chosen else 0)
        if size <= room:
            chosen.add(i)
            room -= size
    kept = [item for i, item in enumerate(items) if i in chosen]
    while kept and len(candidates_document(kept, now)) > budget:
        kept.pop()                       # not reached: the sizes above are exact
    return kept, len(items) - len(kept)


def write_candidates(settings: OtxSettings, records: Iterable[TriageRecord], networks: list,
                     path, *, uploads_dir=None, cap: int = 0,
                     now: Optional[datetime.datetime] = None, dry_run: bool = False) -> dict:
    """Write the candidates file atomically (run-all). ``uploads_dir`` is the quarantine,
    read only when ``hashes`` is on; ``cap`` its per-file limit."""
    now = now or datetime.datetime.now(UTC)
    since = now - datetime.timedelta(days=settings.lookback_days)
    uploads = read_uploads(uploads_dir, cap, since) if settings.hashes and uploads_dir \
        and cap > 0 else []
    items = select_candidates(records, networks, now, settings.lookback_days, uploads,
                              settings.hashes)
    items, dropped = fit_candidates(items, now)
    if dropped:
        log.warning("OTX: %d candidates left out to keep the file under %d bytes", dropped,
                    MAX_CANDIDATES_BYTES)
    summary = {"candidates": len(items), "dropped_for_size": dropped,
               "addresses": sum(1 for i in items if i["type"] == IPV4),
               "hashes": sum(1 for i in items if i["type"] == SHA256)}
    if dry_run:
        return {**summary, "status": "would write", "dry_run": True}
    try:
        _atomic_write(Path(path), candidates_document(items, now))
    except OSError as exc:
        summary["error"] = f"cannot write the OTX candidates ({type(exc).__name__})"
        log.error("OTX: %s", summary["error"])
        return summary
    return {**summary, "status": "written"}


# ---- the candidates file (ship) ------------------------------------------------------------

def _check_item(item) -> tuple[str, str, str, list, str]:
    if not isinstance(item, dict):
        raise InvalidDocument("an indicator is not an object")
    kind, value = item.get("type"), item.get("indicator")
    if kind == IPV4:
        if not isinstance(value, str) or lookup_address(value) != value or ":" in value:
            raise InvalidDocument("an IPv4 indicator is not one global address")
    elif kind == SHA256:
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise InvalidDocument("a hash indicator is not 64 lower-case hex digits")
    else:
        raise InvalidDocument("an indicator type is not IPv4 or FileHash-SHA256")
    protocol = item.get("protocol")
    if protocol not in PROTOCOLS:
        raise InvalidDocument("an indicator protocol is not a known one")
    classes = item.get("classes")
    if not isinstance(classes, list) or not classes or len(classes) > len(CLASSES) \
            or any(c not in CLASSES for c in classes) or len(set(classes)) != len(classes):
        raise InvalidDocument("indicator classes must be distinct known names")
    seen = _timestamp(item.get("last_seen"))
    if seen is None:
        raise InvalidDocument("last_seen is not a timestamp")
    return kind, value, protocol, list(classes), _iso(seen)


def parse_candidates(body: bytes, networks: list) -> tuple[list[dict], int]:
    """``(candidates, excluded)``. The file came from a process that reads attacker text:
    anything but a well-formed file is refused whole, and an address inside ``networks``
    (or any address no action may target) is dropped before it can leave."""
    if len(body) > MAX_CANDIDATES_BYTES:
        raise InvalidDocument(f"larger than {MAX_CANDIDATES_BYTES} bytes")
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise InvalidDocument("not JSON") from None
    if not isinstance(doc, dict) or doc.get("version") != VERSION \
            or isinstance(doc.get("version"), bool):
        raise InvalidDocument("not a version 1 candidates file")
    if _timestamp(doc.get("generated_at")) is None:
        raise InvalidDocument("generated_at is not a timestamp")
    items = doc.get("indicators")
    if not isinstance(items, list) or len(items) > MAX_CANDIDATES:
        raise InvalidDocument(f"indicators must be a list of at most {MAX_CANDIDATES}")
    out: list[dict] = []
    seen: set = set()
    excluded = 0
    for item in items:
        kind, value, protocol, classes, last_seen = _check_item(item)
        if (kind, value) in seen:
            raise InvalidDocument("an indicator is listed twice")
        seen.add((kind, value))
        if kind == IPV4 and not _allowed_source(value, networks):
            excluded += 1
            continue
        out.append({"type": kind, "indicator": value, "protocol": protocol,
                    "classes": classes, "last_seen": last_seen})
    return out, excluded


# ---- what is sent --------------------------------------------------------------------------

def indicator_body(c: dict, now: datetime.datetime, expiration_days: int) -> dict:
    """One OTX indicator built from fixed strings and the checked names only."""
    did = "; ".join(CLASSES[name] for name in c["classes"])
    proto = c["protocol"].upper()
    if c["type"] == IPV4:
        title = f"Honeypot source over {proto}"
        text = f"Source address seen on a honeypot over {proto}. {did}."
    else:
        title = f"File uploaded to a honeypot over {proto}"
        text = f"SHA-256 of a file a honeypot source uploaded over {proto}. The source: {did}."
    expires = (now + datetime.timedelta(days=expiration_days)).astimezone(UTC)
    return {"indicator": c["indicator"], "type": c["type"], "title": title,
            "description": text, "expiration": expires.strftime("%Y-%m-%dT%H:%M:%S")}


def pulse_name(settings: OtxSettings, day: str) -> str:
    return f"{settings.pulse_name} {day}"


def create_body(settings: OtxSettings, day: str, indicators: list[dict]) -> dict:
    return {"name": pulse_name(settings, day), "description": settings.description,
            "public": settings.public, "TLP": settings.tlp, "tags": list(settings.tags),
            "references": [], "indicators": indicators}


def append_body(indicators: list[dict]) -> dict:
    return {"indicators": {"add": indicators}}


def sent_key(kind: str, value: str) -> str:
    return f"{kind}|{value}"


def _valid_sent_key(key) -> bool:
    if not isinstance(key, str) or "|" not in key or len(key) > 100:
        return False
    kind, value = key.split("|", 1)
    if kind == IPV4:
        return lookup_address(value) == value and ":" not in value
    return kind == SHA256 and bool(_SHA256_RE.fullmatch(value))


def pulse_id_from(body: bytes) -> Optional[str]:
    """The id of a created pulse, or None. Nothing else in the answer is read."""
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    value = doc.get("id") if isinstance(doc, dict) else None
    return value if isinstance(value, str) and _PULSE_ID_RE.fullmatch(value) else None


# ---- state ---------------------------------------------------------------------------------

def _parse_time(value) -> Optional[datetime.datetime]:
    if not isinstance(value, str) or len(value) > _TS_CAP:
        return None
    return _timestamp(value)


def load_state(path: Path) -> dict:
    """The state file checked field by field; anything unreadable starts empty."""
    out: dict = {"day": "", "day_count": 0, "pulse_day": "", "pulse_id": None,
                 "backoff_until": None, "backoff_minutes": 0, "sent": {}}
    try:
        body = read_regular(path, MAX_STATE_BYTES)
        if len(body) > MAX_STATE_BYTES:
            raise ValueError("too large")
        doc = json.loads(body.decode("utf-8"))
    except FileNotFoundError:
        return out
    except (OSError, ValueError, UnicodeDecodeError, RecursionError) as exc:
        log.warning("OTX state unreadable (%s); starting empty", type(exc).__name__)
        return out
    if not isinstance(doc, dict) or doc.get("version") != VERSION:
        return out
    for name in ("day", "pulse_day"):
        if isinstance(doc.get(name), str) and _DAY_RE.fullmatch(doc[name]):
            out[name] = doc[name]
    count = doc.get("day_count")
    if isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= 10 ** 6:
        out["day_count"] = count
    pid = doc.get("pulse_id")
    if isinstance(pid, str) and _PULSE_ID_RE.fullmatch(pid) and out["pulse_day"]:
        out["pulse_id"] = pid
    else:
        out["pulse_day"] = ""
    out["backoff_until"] = _parse_time(doc.get("backoff_until"))
    minutes = doc.get("backoff_minutes")
    if isinstance(minutes, int) and not isinstance(minutes, bool) \
            and 0 <= minutes <= BACKOFF_MAX_MINUTES:
        out["backoff_minutes"] = minutes
    sent = doc.get("sent")
    if isinstance(sent, dict):
        for key, at in sent.items():
            when = _parse_time(at)
            if _valid_sent_key(key) and when is not None:
                out["sent"][key] = when
    return out


def _state_bytes(state: dict, sent: dict) -> bytes:
    until = state.get("backoff_until")
    doc = {"version": VERSION, "day": state["day"], "day_count": state["day_count"],
           "pulse_day": state["pulse_day"] if state["pulse_id"] else "",
           "pulse_id": state["pulse_id"],
           "backoff_until": _iso(until) if until else None,
           "backoff_minutes": state["backoff_minutes"],
           "sent": {k: _iso(v) for k, v in sent.items()}}
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()


def save_state(path: Path, state: dict, max_entries: int) -> int:
    """Bounded and written atomically, owner only. The oldest sent indicators are dropped
    first: beyond ``max_entries``, and then until the file is no larger than what
    ``load_state`` reads, so a saved state is never refused on the next load (which would
    send everything again). Returns how many were dropped."""
    sent = state["sent"]
    # Newest first; among equal times the one recorded later counts as newer.
    newest = [k for _, k in sorted(enumerate(sent), key=lambda p: (sent[p[1]], p[0]),
                                   reverse=True)]
    dropped = newest[max_entries:]
    newest = newest[:max_entries]
    room = MAX_STATE_BYTES - len(_state_bytes(state, {}))
    keep = 0
    for key in newest:
        size = len(json.dumps(key)) + 1 + len(json.dumps(_iso(sent[key]))) + (1 if keep else 0)
        if size > room:
            break
        room -= size
        keep += 1
    dropped += newest[keep:]
    for key in dropped:
        del sent[key]
    body = _state_bytes(state, sent)
    while len(body) > MAX_STATE_BYTES and sent:    # not reached: the sizes above are exact
        del sent[min(sent, key=lambda k: sent[k])]
        dropped.append(None)
        body = _state_bytes(state, sent)
    if dropped:
        log.info("OTX: %d oldest sent indicators dropped from the state", len(dropped))
    _atomic_write(path, body)
    return len(dropped)


# ---- the run (ship) ------------------------------------------------------------------------

def _key(settings: OtxSettings) -> str:
    value = read_secret(settings.secret_env, settings.secret_file)
    if value is None:
        raise SecretMissing()
    if not _KEY_RE.fullmatch(value):
        raise InvalidSecret()
    return value


def _event(state_dir: Path, now: datetime.datetime, summary: dict) -> None:
    keys = ("status", "candidates", "sent", "failed", "skipped", "dry_run", "pulse",
            "stopped", "backoff_minutes", "error")
    _record_event(state_dir, {"timestamp": _iso(now), "event": "otx_submit",
                              **{k: summary[k] for k in keys if k in summary}})


def run_submit(settings: OtxSettings, candidates_file, state_dir, networks: list, *,
               cli_dry_run: bool = False, transport=None, resolver=None,
               now: Optional[datetime.datetime] = None, base_url: str = BASE_URL) -> dict:
    """Add the candidates not sent before to today's pulse, within the caps and back-off.
    ``cli_dry_run`` (``--dry-run``) writes nothing at all. ``transport``, ``resolver`` and
    ``base_url`` exist for tests only (configuration has no way to set them). Never raises
    for request or file failures."""
    if not settings.enabled:
        return {"status": "disabled"}
    if not settings.submit:
        return {"status": "not submitted from this process (submit = false)"}
    state_dir = Path(state_dir)
    now = now or datetime.datetime.now(UTC)
    dry = settings.dry_run or cli_dry_run
    summary: dict = {"candidates": 0, "sent": 0, "failed": 0,
                     "skipped": {"already_sent": 0, "excluded": 0, "hashes_off": 0,
                                 "over_cap": 0},
                     "dry_run": dry}

    def finish(status: str, error: Optional[str] = None) -> dict:
        summary["status"] = status
        if error:
            summary["error"] = error
            log.error("OTX: %s", error)
        if not cli_dry_run:
            _event(state_dir, now, summary)
        return summary

    try:
        candidates, excluded = parse_candidates(
            _read_capped(Path(candidates_file), MAX_CANDIDATES_BYTES), networks)
    except FileNotFoundError:
        return finish("no candidates file yet")
    except OSError as exc:
        return finish("error", f"cannot read the candidates ({type(exc).__name__})")
    except InvalidDocument as exc:
        return finish("error", f"the candidates file is refused: {str(exc)[:100]}")
    summary["candidates"] = len(candidates) + excluded
    summary["skipped"]["excluded"] = excluded
    if not settings.hashes:
        summary["skipped"]["hashes_off"] = sum(1 for c in candidates if c["type"] == SHA256)
        candidates = [c for c in candidates if c["type"] != SHA256]

    path = state_dir / STATE_FILE
    state = load_state(path)
    today = now.astimezone(UTC).date().isoformat()
    if state["day"] != today:
        state["day"], state["day_count"] = today, 0
    pulse_id = state["pulse_id"] if state["pulse_day"] == today else None
    due = [c for c in candidates if sent_key(c["type"], c["indicator"]) not in state["sent"]]
    summary["skipped"]["already_sent"] = len(candidates) - len(due)
    room = max(0, min(settings.max_per_run, settings.max_per_day - state["day_count"]))
    batch = due[:room]
    summary["skipped"]["over_cap"] = len(due) - len(batch)
    if not batch:
        return finish("daily cap reached" if due else "nothing new")
    indicators = [indicator_body(c, now, settings.expiration_days) for c in batch]
    if pulse_id is None:
        method, url = "POST", base_url + CREATE_PATH
        body = create_body(settings, today, indicators)
    else:
        method, url = "PATCH", base_url + PULSE_PATH + pulse_id
        body = append_body(indicators)

    if dry:
        summary["would_send"] = len(batch)
        if cli_dry_run:
            return finish("dry run")
        preview = {"generated_at": _iso(now), "request": f"{method} {url}",
                   "body": body}
        try:
            _atomic_write(state_dir / DRY_RUN_FILE,
                          (json.dumps(preview, indent=1) + "\n").encode())
        except OSError as exc:
            return finish("error", f"cannot write the dry-run file ({type(exc).__name__})")
        return finish("dry run: written, nothing sent")

    until = state["backoff_until"]
    if until is not None and now < until <= now + datetime.timedelta(minutes=BACKOFF_MAX_MINUTES):
        summary["until"] = _iso(until)
        return finish("backing off")
    try:
        key = _key(settings)
    except (SecretMissing, InvalidSecret) as exc:
        why = "missing" if isinstance(exc, SecretMissing) else "not a valid key"
        return finish("error", f"API key {why}; nothing sent")

    if settings.addresses_file:
        from agents.internetdb_lookup_exchange import pinned_resolver, read_pinned

        try:
            pinned = read_pinned(settings.addresses_file)
        except (OSError, InvalidDocument):
            pinned = []
        if not pinned:
            return finish("error", "no pinned OTX address (the host firewall has none yet); "
                                   "nothing sent")
        resolver = pinned_resolver(pinned, resolver or socket.getaddrinfo)

    stopped: Optional[str] = None
    status = 0
    answer = b""
    too_large = False
    try:
        host = urlsplit(base_url).hostname or ""
        address = pin_address(host, 443) if resolver is None else \
            pin_address(host, 443, resolver=resolver)
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json",
                   "Content-Type": "application/json", KEY_HEADER: key}
        transport = transport if transport is not None else UrlTransport()
        status, answer = transport.request(method, url, headers,
                                           json.dumps(body, separators=(",", ":")).encode(),
                                           TIMEOUT, address, max_bytes=MAX_BODY)
        status = int(status)
    except ResponseTooLarge:
        # Only a 2xx answer is read in full, so the request was accepted.
        status, too_large = 200, True
    except Exception as exc:  # noqa: BLE001 - unreachable, timeout, TLS, DNS
        # The type only: a message could carry a header value.
        stopped = f"request failed ({type(exc).__name__})"

    if stopped is None and 200 <= status < 300:
        for c in batch:
            state["sent"][sent_key(c["type"], c["indicator"])] = now
        state["day_count"] += len(batch)
        state["backoff_minutes"], state["backoff_until"] = 0, None
        summary["sent"] = len(batch)
        if method == "POST":
            new_id = None if too_large else pulse_id_from(answer or b"")
            state["pulse_day"], state["pulse_id"] = (today, new_id) if new_id else ("", None)
            summary["pulse"] = "created" if new_id else "created; id not kept (answer refused)"
        else:
            summary["pulse"] = "appended"
    elif stopped is None and status == 404 and method == "PATCH":
        # The day's pulse is gone (deleted on OTX): the next run creates a new one.
        state["pulse_day"], state["pulse_id"] = "", None
        summary["failed"] = len(batch)
        stopped = "pulse not found; a new one is created next run"
    else:
        summary["failed"] = len(batch)
        if stopped is None:
            stopped = f"HTTP {status}"
        minutes = min(BACKOFF_MAX_MINUTES,
                      max(BACKOFF_FIRST_MINUTES, state["backoff_minutes"] * 2))
        state["backoff_minutes"] = minutes
        state["backoff_until"] = now + datetime.timedelta(minutes=minutes)
        summary["backoff_minutes"] = minutes
    if stopped is not None:
        summary["stopped"] = stopped
        log.warning("OTX submission stopped: %s", stopped)
    try:
        save_state(path, state, settings.max_entries)
    except OSError as exc:
        return finish("error", f"cannot write the OTX state ({type(exc).__name__})")
    if stopped is not None:
        return finish("stopped", stopped)
    return finish("done")
