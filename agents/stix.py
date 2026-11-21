"""STIX 2.1 export: what the sensor saw, and the sources and files that passed promotion, as
one bundle in a local file. Off by default (``[stix] enabled``); no network connection and no
credential. ``python -m agents stix`` writes it, and so does ``run-all`` when it is enabled.

What goes in (OASIS STIX 2.1, docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html):

- one ``identity`` for the sensor (``identity_class: system``, name from config) and the
  standard TLP ``marking-definition`` chosen in config (section 7.2.1, "TLP Marking Object
  Type"), embedded; every other object carries both.
- ``observed-data`` with its ``ipv4-addr`` / ``ipv6-addr`` / ``file`` object for what was
  merely seen: each proven source address in the last ``lookback_days`` (not inside
  ``[respond] never_act_on``, not the sensor's own address, global only), and each whole
  file the quarantine stored in that window (by SHA-256).
- ``indicator`` only for what passed a promotion rule already in the code:
  - the OTX connector's selection (``agents.otx.select_candidates``, called, not copied): a
    proven source that did more than probe, by counted facts; the model's verdict can only
    hold one back; IPv4 addresses and the SHA-256 of files those sources uploaded;
  - an operator-approved entry of the blocklist store (tracked or enforced; a tracked entry
    only when recorded as a verified source).
  A ``sighting`` ties each live indicator to the observed-data it was built from.
  An unproven UDP source is never in the bundle, as an indicator or as observed-data.

Indicators: ``pattern_type: stix`` with the validated value escaped for the pattern grammar
(section 9: backslash and apostrophe); ``valid_from`` (where the indicator first became
valid) always; ``valid_until`` strictly later, from the source's own expiry (the blocklist
entry's ``expires_at``) or from the last sighting plus ``address_lifetime_days`` /
``hash_lifetime_days``. An approved entry without a usable window gets no indicator. Review
state is ``labels`` (``rule-promoted``, ``operator-tracked``, ``operator-enforced``) with a
fixed ``confidence`` per label; ``indicator_types`` is ``malicious-activity``. Names and
descriptions are fixed text and code-set names only; no attacker text is ever written.

Identifiers: UUIDv5. Cyber-observable objects use the spec's namespace over their ID
contributing properties (sections 2.9 and 3.4). Every other id is in this project's
namespace over the identity name, the type and the value, so a re-export is identical and
two identities never share an id. A state file per identity keeps ``created`` and moves
``modified`` only when content changes.

Withdrawal: when the operator removes an address from the blocklist (``python -m agents
unblock``, recorded in ``reports/response``) after its indicator was last written, that
indicator is ``revoked``, whatever promoted it. Revocation is permanent (section 3.6: "later
versions of that object MUST NOT be created"), so that id is never written live again: the
value gets a new generation, and a later indicator for it has a new id. While the withdrawal
stands (``keep_days`` from the unblock) the automatic rule cannot promote the value again;
an operator approving it again after the unblock can, under the new id. Natural expiry is
not a revocation: ``valid_until`` says it, and the object stays as it was. Expired and
revoked objects leave the bundle ``keep_days`` after they ended; the generation of a value
that was ever revoked stays in the state.

Fail closed: an existing state file that cannot be read or holds anything malformed, a
missing state file next to a bundle this identity wrote, a state that would be larger than
the next run may read, or a bundle whose references do not all resolve, stops the export
with an error. Nothing is written and the previous bundle stays. Recovery is in
docs/portable-formats.md ("When the state is lost"). The bundle is capped by object count
and by its exact size in bytes; whole groups are left out, never part of one. Files are
written atomically, owner only.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from agents import otx
from agents.budget import ip_key
from agents.internetdb import lookup_address
from agents.internetdb_delivered import _atomic_write, _timestamp
from agents.localfile import read_regular
from agents.respond import (
    ENFORCED,
    TRACKED,
    entry_status,
    non_global,
    peek_blocklist,
    source_refusal,
)
from agents.triage import UNVERIFIED_SOURCE, TriageRecord

log = logging.getLogger("agents.stix")
UTC = datetime.timezone.utc

SECTION = "stix"
VERSION = 1
DEFAULT_FILE = Path("stix") / "bundle.json"
# Section 2.9: the namespace for cyber-observable object ids.
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
# This project's namespace for every other id (never the SCO namespace, as 2.9 requires).
PROJECT_NAMESPACE = uuid.UUID("80134e96-2fba-4bcb-904c-2ace51ac2871")
# The identity's own timestamps: fixed, so the object never changes while its name does not.
IDENTITY_CREATED = "2026-11-21T00:00:00.000Z"

# Section 7.2.1 ("TLP Marking Object Type"): the only TLP marking definitions STIX 2.1
# permits, verbatim.
TLP_IDS = {"white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
           "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
           "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
           "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"}

LABELS = {"rule": "rule-promoted", "tracked": "operator-tracked", "enforced": "operator-enforced"}
CONFIDENCE = {"rule": 50, "tracked": 70, "enforced": 85}
BASES = tuple(LABELS)
OPERATOR_BASES = ("tracked", "enforced")

DEFAULTS = {"lookback_days": 7.0, "address_lifetime_days": 30, "hash_lifetime_days": 365,
            "keep_days": 30, "max_objects": 5000, "max_bytes": 8 * 1024 * 1024}
BOUNDS = {"lookback_days": (1.0, 30.0), "address_lifetime_days": (1, 365),
          "hash_lifetime_days": (1, 3650), "keep_days": (1, 365),
          "max_objects": (100, 50000), "max_bytes": (65536, 64 * 1024 * 1024)}
KNOWN_KEYS = {"enabled", "output_file", "identity_name", "tlp", "hashes", *DEFAULTS}
DEFAULT_IDENTITY = "Honeypot sensor"
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_GENERATION = 10 ** 6
MAX_AUDIT_FILES = 500
MAX_AUDIT_BYTES = 64 * 1024
MAX_SIGHTING_REFS = 10

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UNBLOCK_FILE_RE = re.compile(r"^\d{8}T\d{6}Z-unblock-[0-9a-f]{6}\.json$")


class ConfigError(ValueError):
    """Load-time problem. Messages never include configured values."""


class ExportRefused(RuntimeError):
    """The export stopped before writing anything; the message says why."""


@dataclass(frozen=True)
class StixSettings:
    enabled: bool = False
    output_file: Optional[str] = None
    identity_name: str = DEFAULT_IDENTITY
    tlp: str = "amber"
    hashes: bool = True
    lookback_days: float = DEFAULTS["lookback_days"]
    address_lifetime_days: int = DEFAULTS["address_lifetime_days"]
    hash_lifetime_days: int = DEFAULTS["hash_lifetime_days"]
    keep_days: int = DEFAULTS["keep_days"]
    max_objects: int = DEFAULTS["max_objects"]
    max_bytes: int = DEFAULTS["max_bytes"]

    @classmethod
    def from_config(cls, config) -> "StixSettings":
        """Read ``[stix]``. Missing or disabled: off. Raises ConfigError."""
        if config is None or not config.has_section(SECTION):
            return cls()
        sec = config[SECTION]

        def flag(name: str, default: bool) -> bool:
            try:
                return sec.getboolean(name, fallback=default)
            except ValueError:
                raise ConfigError(f"{name} must be true or false") from None

        unknown = sorted(k for k in sec.keys() if k not in KNOWN_KEYS
                         and k not in config.defaults())
        if unknown:
            raise ConfigError("unknown setting")
        if not flag("enabled", False):
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

        output = sec.get("output_file", "").strip() or None
        if output is not None and (not os.path.isabs(output) or len(output) > 4096):
            raise ConfigError("output_file must be an absolute path")
        name = sec.get("identity_name", DEFAULT_IDENTITY).strip()
        if not _NAME_RE.fullmatch(name):
            raise ConfigError("identity_name must be 1-64 letters, digits, spaces, '.', '_' "
                              "or '-'")
        tlp = sec.get("tlp", "amber").strip().lower()
        if tlp not in TLP_IDS:
            raise ConfigError("tlp must be white, green, amber or red")
        return cls(enabled=True, output_file=output, identity_name=name, tlp=tlp,
                   hashes=flag("hashes", True), lookback_days=num("lookback_days"),
                   address_lifetime_days=num("address_lifetime_days"),
                   hash_lifetime_days=num("hash_lifetime_days"), keep_days=num("keep_days"),
                   max_objects=num("max_objects"), max_bytes=num("max_bytes"))


def output_path(settings: StixSettings, reports_dir) -> Path:
    return Path(settings.output_file) if settings.output_file else \
        Path(reports_dir) / DEFAULT_FILE


def state_path(state_dir, identity_name: str) -> Path:
    """One state file per identity: another name is another producer with its own ids."""
    tag = hashlib.sha256(identity_name.encode()).hexdigest()[:12]
    return Path(state_dir) / f"stix_state-{tag}.json"


# ---- identifiers, timestamps, patterns ------------------------------------------------------

def _canonical(value) -> str:
    """RFC 8785 for the small objects used here (strings and integers only): sorted keys, no
    whitespace, non-ASCII kept as is."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sco_id(kind: str, value: str) -> str:
    """Deterministic SCO id (sections 2.9, 3.4) from the ID contributing properties: ``value``
    for addresses, one hash for a file (SHA-256, the only one known here)."""
    props = {"hashes": {"SHA-256": value}} if kind == "file" else {"value": value}
    return f"{kind}--{uuid.uuid5(SCO_NAMESPACE, _canonical(props))}"


def sdo_id(identity_name: str, kind: str, name: str) -> str:
    return f"{kind}--{uuid.uuid5(PROJECT_NAMESPACE, f'{identity_name}|{kind}|{name}')}"


def indicator_name(key: str, generation: int) -> str:
    """What an indicator's id is derived from: the value, and from the first revocation on,
    the generation."""
    return key if generation == 0 else f"{key}#{generation}"


def ts(dt: datetime.datetime) -> str:
    """A STIX timestamp: UTC with the Z designation, to the millisecond (section 3.2 requires
    millisecond precision for ``created`` and ``modified``; used for every timestamp)."""
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse_ts(value) -> Optional[datetime.datetime]:
    if not isinstance(value, str) or len(value) > 40:
        return None
    return _timestamp(value)


def pattern_string(value: str) -> str:
    """A STIX pattern string literal (section 9): backslash and apostrophe escaped."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def pattern_for(kind: str, value: str) -> str:
    if kind == "ipv4-addr":
        return f"[ipv4-addr:value = {pattern_string(value)}]"
    if kind == "ipv6-addr":
        op = "ISSUBSET" if "/" in value else "="
        return f"[ipv6-addr:value {op} {pattern_string(value)}]"
    return f"[file:hashes.'SHA-256' = {pattern_string(value)}]"


def parse_key(key) -> Optional[tuple[str, str]]:
    """``(sco type, value)`` for a key in one of the canonical forms written here (one global
    address, an IPv6 /64, a lower-case SHA-256), or None."""
    if not isinstance(key, str) or "|" not in key or len(key) > 120:
        return None
    kind, value = key.split("|", 1)
    if kind == "file":
        return (kind, value) if _SHA256_RE.fullmatch(value) else None
    if kind not in ("ipv4-addr", "ipv6-addr"):
        return None
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return None
    if net.version != (4 if kind == "ipv4-addr" else 6) or non_global(str(net)):
        return None
    if net.version == 4 and net.prefixlen != 32 or \
            net.version == 6 and net.prefixlen not in (64, 128):
        return None    # one address, or an IPv6 /64 (how the blocklist keys IPv6 sources)
    text = str(net.network_address) if net.num_addresses == 1 else str(net)
    return (kind, value) if text == value else None


def blocklist_key(key: str) -> str:
    """The blocklist's key for an object key (the address, or the IPv6 /64)."""
    parsed = parse_key(key)
    return parsed[1] if parsed else ""


def _address_key(value: str) -> Optional[str]:
    addr = lookup_address(value)
    if addr is None:
        return None
    key = ("ipv6-addr|" if ":" in addr else "ipv4-addr|") + addr
    return key if parse_key(key) else None


def _network_key(key: str) -> Optional[str]:
    """A blocklist key (IPv4 address or IPv6 /64) as an object key."""
    try:
        net = ipaddress.ip_network(key, strict=True)
    except ValueError:
        return None
    if net.version == 4:
        out = f"ipv4-addr|{net.network_address}" if net.prefixlen == 32 else None
    else:
        out = f"ipv6-addr|{net.network_address}" if net.prefixlen == 128 else f"ipv6-addr|{net}"
    return out if out and parse_key(out) else None


# ---- what is current -----------------------------------------------------------------------

def observed_now(records: Iterable[TriageRecord], uploads: Iterable[dict], networks: list,
                 now: datetime.datetime, lookback_days: float) -> dict[str, dict]:
    """``{key: {first, last, count}}`` for proven source addresses and stored files seen in
    the window."""
    since = now - datetime.timedelta(days=lookback_days)
    out: dict[str, dict] = {}

    def add(key, first, last, count):
        item = out.setdefault(key, {"first": first, "last": last, "count": 0})
        item["first"] = min(item["first"], first)
        item["last"] = max(item["last"], last)
        item["count"] = min(item["count"] + count, 999_999_999)

    for r in records:
        if r.unverified_source or r.src_ip == UNVERIFIED_SOURCE:
            continue
        last = _timestamp(r.last_seen or r.first_seen)
        if last is None or last < since or last > now:
            continue
        first = min(_timestamp(r.first_seen) or last, last)
        try:
            if source_refusal(ip_key(r.src_ip), networks) is not None:
                continue
        except ValueError:
            continue
        key = _address_key(r.src_ip)
        if key is not None:
            add(key, first, last, max(1, r.connections) if r.kind == "campaign" else 1)
    for up in uploads:
        at = up["stored_at"]
        if since <= at <= now:
            add(f"file|{up['sha256']}", at, at, 1)
    return out


def indicators_now(candidates: Iterable[dict], approved: dict, networks: list,
                   settings: StixSettings) -> dict[str, dict]:
    """``{key: {valid_from, valid_until, bases, classes, protocol, approved_at}}`` for what
    passed promotion now. ``candidates`` are the OTX selection's items; ``approved`` the live
    blocklist entries. ``approved_at`` is the latest operator approval, or None."""
    out: dict[str, dict] = {}

    def add(key, start, end, basis, classes=(), protocol=""):
        if end <= start:
            return
        item = out.setdefault(key, {"valid_from": start, "valid_until": end, "bases": set(),
                                    "classes": [], "protocol": protocol, "approved_at": None})
        item["valid_from"] = min(item["valid_from"], start)
        item["valid_until"] = max(item["valid_until"], end)
        item["bases"].add(basis)
        item["protocol"] = item["protocol"] or protocol
        if basis in OPERATOR_BASES:
            item["approved_at"] = max(item["approved_at"] or start, start)
        for c in classes:
            if c not in item["classes"]:
                item["classes"].append(c)

    for c in candidates:
        seen = _parse_ts(c.get("last_seen"))
        classes = [x for x in c.get("classes", []) if x in otx.CLASSES]
        protocol = c.get("protocol") if c.get("protocol") in otx.PROTOCOLS else ""
        if seen is None:
            continue
        if c.get("type") == otx.IPV4:
            key = _address_key(str(c.get("indicator")))
            days = settings.address_lifetime_days
        elif c.get("type") == otx.SHA256 and _SHA256_RE.fullmatch(str(c.get("indicator"))):
            key = f"file|{c['indicator']}"
            days = settings.hash_lifetime_days
        else:
            continue
        if key is not None:
            add(key, seen, seen + datetime.timedelta(days=days), "rule", classes, protocol)
    for raw_key, entry in approved.items():
        status = entry_status(entry)
        if status == TRACKED and entry.get("source_verified") is not True:
            continue
        try:
            if source_refusal(raw_key, networks) is not None:
                continue
        except ValueError:
            continue
        key = _network_key(raw_key)
        start, end = _parse_ts(entry.get("approved_at")), _parse_ts(entry.get("expires_at"))
        if key is None or start is None or end is None:
            continue   # no supportable window: the address stays observed-data only
        add(key, start, end, "enforced" if status == ENFORCED else "tracked")
    for item in out.values():
        item["bases"] = sorted(item["bases"], key=BASES.index)
        item["classes"] = [c for c in otx.CLASSES if c in item["classes"]]
    return out


def unblocked(reports_dir, now: datetime.datetime) -> dict[str, datetime.datetime]:
    """``{blocklist key: latest time}`` of the operator's removals recorded in
    ``reports/response`` (``*-unblock-*.json``, the newest ``MAX_AUDIT_FILES``)."""
    out: dict[str, datetime.datetime] = {}
    directory = Path(reports_dir) / "response"
    try:
        names = sorted(n for n in os.listdir(directory) if _UNBLOCK_FILE_RE.fullmatch(n))
    except OSError:
        return out
    for name in names[-MAX_AUDIT_FILES:]:
        try:
            body = read_regular(directory / name, MAX_AUDIT_BYTES)
            doc = json.loads(body.decode("utf-8")) if len(body) <= MAX_AUDIT_BYTES else None
        except (OSError, ValueError, UnicodeDecodeError, RecursionError):
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("unblock"), dict):
            continue
        when = _parse_ts(doc.get("timestamp"))
        removed = doc["unblock"].get("removed")
        if when is None or when > now or not isinstance(removed, list):
            continue
        for key in removed[:10000]:
            if isinstance(key, str) and len(key) <= 64:
                out[key] = max(out.get(key, when), when)
    return out


# ---- state ---------------------------------------------------------------------------------
#
# {"version": 1, "identity": name,
#  "indicators": {key: {"generation", "content", "created", "modified", "seen"}},   live
#  "revoked": {"<key>#<generation>": {"content", "created", "modified", "revoked"}},
#  "withdrawn": {key: time of the unblock},
#  "generations": {key: generation the next indicator for the value gets},
#  "observed": {key: {"content", "created", "modified", "seen"}}}

def _fingerprint(content: dict) -> str:
    return hashlib.sha256(_canonical(content).encode()).hexdigest()


def _indicator_content(item: dict) -> dict:
    return {"valid_from": ts(item["valid_from"]), "valid_until": ts(item["valid_until"]),
            "bases": list(item["bases"]), "classes": list(item["classes"]),
            "protocol": item["protocol"]}


def _observed_content(item: dict) -> dict:
    return {"first": ts(item["first"]), "last": ts(item["last"]), "count": item["count"]}


def empty_state(identity: str) -> dict:
    return {"identity": identity, "indicators": {}, "revoked": {}, "withdrawn": {},
            "generations": {}, "observed": {}}


class StateError(ExportRefused):
    """The state file exists but cannot be trusted."""


def _bad(what: str):
    raise StateError(f"STIX state {what}")


def _need_ts(value, what: str) -> str:
    dt = _parse_ts(value)
    if dt is None or ts(dt) != value:
        _bad(f"has a bad timestamp in {what}")
    return value


def _check_indicator_content(c, what: str) -> dict:
    if not isinstance(c, dict) or set(c) != {"valid_from", "valid_until", "bases", "classes",
                                             "protocol"}:
        _bad(f"has a bad indicator in {what}")
    _need_ts(c["valid_from"], what)
    _need_ts(c["valid_until"], what)
    if c["valid_until"] <= c["valid_from"]:
        _bad(f"has an empty validity window in {what}")
    if not isinstance(c["bases"], list) or not c["bases"] or \
            any(b not in BASES for b in c["bases"]):
        _bad(f"has a bad review state in {what}")
    if not isinstance(c["classes"], list) or any(x not in otx.CLASSES for x in c["classes"]):
        _bad(f"has a bad class in {what}")
    if c["protocol"] != "" and c["protocol"] not in otx.PROTOCOLS:
        _bad(f"has a bad protocol in {what}")
    return c


def _check_observed_content(c, what: str) -> dict:
    if not isinstance(c, dict) or set(c) != {"first", "last", "count"}:
        _bad(f"has a bad observation in {what}")
    _need_ts(c["first"], what)
    _need_ts(c["last"], what)
    count = c["count"]
    if c["last"] < c["first"] or not isinstance(count, int) or isinstance(count, bool) \
            or not 1 <= count <= 999_999_999:
        _bad(f"has a bad observation in {what}")
    return c


def _check_generation(value, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or \
            not 0 <= value <= MAX_GENERATION:
        _bad(f"has a bad generation in {what}")
    return value


def load_state(path: Path, identity: str) -> dict:
    """The state, checked in full. No file: empty. A file that cannot be read, or anything
    in it that is not exactly as written here, raises StateError: nothing is dropped
    quietly, so no revocation can be forgotten."""
    try:
        body = read_regular(path, MAX_STATE_BYTES)
    except FileNotFoundError:
        return empty_state(identity)
    except OSError as exc:
        raise StateError(f"STIX state cannot be read ({type(exc).__name__})") from None
    if len(body) > MAX_STATE_BYTES:
        _bad("is larger than the limit")
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        _bad("is not valid JSON")
    expected = {"version", "identity", "indicators", "revoked", "withdrawn", "generations",
                "observed"}
    if not isinstance(doc, dict) or set(doc) != expected or doc["version"] != VERSION:
        _bad("is not in the expected format")
    if doc["identity"] != identity:
        _bad("belongs to another identity")
    for name in expected - {"version", "identity"}:
        if not isinstance(doc[name], dict):
            _bad(f"has a bad {name} section")
    out = empty_state(identity)
    for key, e in doc["indicators"].items():
        if parse_key(key) is None or not isinstance(e, dict) or \
                set(e) != {"generation", "content", "created", "modified", "seen"}:
            _bad("has a bad live indicator")
        _check_generation(e["generation"], "indicators")
        _check_indicator_content(e["content"], "indicators")
        for f in ("created", "modified", "seen"):
            _need_ts(e[f], "indicators")
        if e["modified"] < e["created"]:
            _bad("has modified before created")
        out["indicators"][key] = e
    for name, e in doc["revoked"].items():
        key, _, gen = name.rpartition("#")
        if parse_key(key) is None or not gen.isdigit() or str(int(gen)) != gen or \
                not isinstance(e, dict) or \
                set(e) != {"content", "created", "modified", "revoked"}:
            _bad("has a bad revoked indicator")
        _check_generation(int(gen), "revoked")
        _check_indicator_content(e["content"], "revoked")
        for f in ("created", "modified", "revoked"):
            _need_ts(e[f], "revoked")
        if e["modified"] < e["created"]:
            _bad("has modified before created")
        out["revoked"][name] = e
    for key, value in doc["withdrawn"].items():
        if parse_key(key) is None:
            _bad("has a bad withdrawal")
        out["withdrawn"][key] = _need_ts(value, "withdrawn")
    for key, value in doc["generations"].items():
        if parse_key(key) is None:
            _bad("has a bad generation key")
        out["generations"][key] = _check_generation(value, "generations")
    for key, e in doc["observed"].items():
        if parse_key(key) is None or not isinstance(e, dict) or \
                set(e) != {"content", "created", "modified", "seen"}:
            _bad("has a bad observation")
        _check_observed_content(e["content"], "observed")
        for f in ("created", "modified", "seen"):
            _need_ts(e[f], "observed")
        if e["modified"] < e["created"]:
            _bad("has modified before created")
        out["observed"][key] = e
    # Every revoked generation is below the value's next generation, so no later indicator
    # can be issued under a revoked id; a live indicator's generation is never one that was
    # revoked.
    for name in out["revoked"]:
        key, _, gen = name.rpartition("#")
        if out["generations"].get(key, 0) < int(gen) + 1:
            _bad("has a revoked indicator newer than the value's generation")
    for key, e in out["indicators"].items():
        if f"{key}#{e['generation']}" in out["revoked"] or \
                e["generation"] < out["generations"].get(key, 0):
            _bad("has a live indicator under a revoked id")
    return out


def state_bytes(state: dict) -> bytes:
    doc = {"version": VERSION, **state}
    return (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()


def reconcile_indicators(state: dict, current: dict[str, dict], now: datetime.datetime,
                         keep_days: int, removals: dict[str, datetime.datetime]) -> dict:
    """Bring the indicators up to date. Order matters: withdrawals first (so a value the
    operator removed is revoked even when the rule still promotes it), then what is
    current, then what has ended."""
    stamp = ts(now)
    keep = datetime.timedelta(days=keep_days)
    live, revoked = state["indicators"], state["revoked"]
    withdrawn, generations = state["withdrawn"], state["generations"]
    counts = {"new": 0, "changed": 0, "revoked": 0, "suppressed": 0, "dropped": 0}
    # 1. Withdrawals recorded since each live indicator was last written.
    for key, removed_at in removals.items():
        obj_key = _network_key(key)
        if obj_key is None:
            continue
        if removed_at + keep >= now:
            previous = _parse_ts(withdrawn.get(obj_key))
            if previous is None or removed_at > previous:
                withdrawn[obj_key] = ts(removed_at)
        e = live.get(obj_key)
        if e is not None and removed_at >= _parse_ts(e["seen"]):
            gen = e["generation"]
            revoked[f"{obj_key}#{gen}"] = {"content": e["content"], "created": e["created"],
                                           "modified": max(stamp, e["modified"]),
                                           "revoked": stamp}
            generations[obj_key] = gen + 1
            del live[obj_key]
            counts["revoked"] += 1
    # 2. What is current.
    for key, item in current.items():
        held = _parse_ts(withdrawn.get(key))
        if held is not None and now < held + keep and not (
                item["approved_at"] is not None and item["approved_at"] > held):
            counts["suppressed"] += 1      # the operator's withdrawal stands
            continue
        e = live.get(key)
        if e is not None:
            first = _parse_ts(e["content"]["valid_from"])
            content = _indicator_content({**item, "valid_from": min(first, item["valid_from"])})
            if _fingerprint(e["content"]) != _fingerprint(content):
                e.update(content=content, modified=max(stamp, e["modified"]))
                counts["changed"] += 1
            e["seen"] = stamp
        else:
            live[key] = {"generation": generations.get(key, 0),
                         "content": _indicator_content(item), "created": stamp,
                         "modified": stamp, "seen": stamp}
            counts["new"] += 1
    # 3. What has ended: kept keep_days, then dropped. Generations stay.
    for key in [k for k in live if k not in current]:
        if _parse_ts(live[key]["content"]["valid_until"]) + keep < now:
            del live[key]
            counts["dropped"] += 1
    for name in list(revoked):
        if _parse_ts(revoked[name]["revoked"]) + keep < now:
            del revoked[name]
            counts["dropped"] += 1
    for key in list(withdrawn):
        if _parse_ts(withdrawn[key]) + keep < now:
            del withdrawn[key]
    return counts


def reconcile_observed(state: dict, current: dict[str, dict], now: datetime.datetime,
                       keep_days: int) -> dict:
    stamp = ts(now)
    entries = state["observed"]
    counts = {"new": 0, "changed": 0, "dropped": 0}
    for key, item in current.items():
        content = _observed_content(item)
        e = entries.get(key)
        if e is None:
            entries[key] = {"content": content, "created": stamp, "modified": stamp,
                            "seen": stamp}
            counts["new"] += 1
            continue
        if _fingerprint(e["content"]) != _fingerprint(content):
            e.update(content=content, modified=max(stamp, e["modified"]))
            counts["changed"] += 1
        e["seen"] = stamp
    keep = datetime.timedelta(days=keep_days)
    for key in [k for k in entries if k not in current]:
        if _parse_ts(entries[key]["content"]["last"]) + keep < now:
            del entries[key]
            counts["dropped"] += 1
    return counts


# ---- objects -------------------------------------------------------------------------------

def tlp_object(level: str) -> dict:
    return {"type": "marking-definition", "spec_version": "2.1", "id": TLP_IDS[level],
            "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
            "name": f"TLP:{level.upper()}", "definition": {"tlp": level}}


def identity_object(name: str) -> dict:
    return {"type": "identity", "spec_version": "2.1", "id": sdo_id(name, "identity", ""),
            "created": IDENTITY_CREATED, "modified": IDENTITY_CREATED, "name": name,
            "identity_class": "system",
            "description": "A honeypot sensor. It records connections to decoy services."}


class _Ids:
    def __init__(self, settings: StixSettings):
        self.name = settings.identity_name
        self.identity = sdo_id(self.name, "identity", "")
        self.tlp = TLP_IDS[settings.tlp]

    def sdo(self, kind: str, name: str) -> str:
        return sdo_id(self.name, kind, name)

    def common(self, kind: str, name: str, entry: dict) -> dict:
        return {"type": kind, "spec_version": "2.1", "id": self.sdo(kind, name),
                "created": entry["created"], "modified": entry["modified"],
                "created_by_ref": self.identity, "object_marking_refs": [self.tlp]}


def indicator_object(ids: _Ids, key: str, name: str, entry: dict, revoked: bool) -> dict:
    kind, value = parse_key(key)
    c = entry["content"]
    what = "File uploaded to a honeypot" if kind == "file" else "Honeypot source address"
    did = "; ".join(otx.CLASSES[x] for x in c["classes"])
    over = f" over {c['protocol'].upper()}" if c["protocol"] else ""
    review = ", ".join(LABELS[b] for b in c["bases"])
    text = (f"SHA-256 of a file a proven honeypot source uploaded{over}."
            if kind == "file" else f"Source address seen by a honeypot sensor{over}.")
    if did:
        text += f" The source: {did}."
    text += f" Review: {review}."
    obj = {**ids.common("indicator", name, entry), "name": what, "description": text,
           "indicator_types": ["malicious-activity"], "pattern": pattern_for(kind, value),
           "pattern_type": "stix", "pattern_version": "2.1", "valid_from": c["valid_from"],
           "valid_until": c["valid_until"], "labels": [LABELS[b] for b in c["bases"]],
           "confidence": max(CONFIDENCE[b] for b in c["bases"])}
    if revoked:
        obj["revoked"] = True
    return obj


def sco_object(ids: _Ids, key: str) -> dict:
    kind, value = parse_key(key)
    obj = {"type": kind, "spec_version": "2.1", "id": sco_id(kind, value),
           "object_marking_refs": [ids.tlp]}
    if kind == "file":
        obj["hashes"] = {"SHA-256": value}
    else:
        obj["value"] = value
    return obj


def observed_object(ids: _Ids, key: str, entry: dict) -> dict:
    kind, value = parse_key(key)
    c = entry["content"]
    return {**ids.common("observed-data", key, entry), "first_observed": c["first"],
            "last_observed": c["last"], "number_observed": c["count"],
            "object_refs": [sco_id(kind, value)]}


def sighting_object(ids: _Ids, name: str, ind: dict, observed: list[tuple[str, dict]]) -> dict:
    created = max([ind["created"]] + [e["created"] for _, e in observed])
    modified = max([ind["modified"]] + [e["modified"] for _, e in observed])
    return {"type": "sighting", "spec_version": "2.1", "id": ids.sdo("sighting", name),
            "created": created, "modified": modified, "created_by_ref": ids.identity,
            "object_marking_refs": [ids.tlp], "sighting_of_ref": ids.sdo("indicator", name),
            "observed_data_refs": sorted(ids.sdo("observed-data", k) for k, _ in observed),
            "where_sighted_refs": [ids.identity],
            "first_seen": min(e["content"]["first"] for _, e in observed),
            "last_seen": max(e["content"]["last"] for _, e in observed),
            "count": min(sum(e["content"]["count"] for _, e in observed), 999_999_999)}


def _observed_for(key: str, observed: dict) -> list[tuple[str, dict]]:
    kind, value = parse_key(key)
    if key in observed:
        return [(key, observed[key])]
    if kind != "ipv6-addr" or "/" not in value:
        return []
    net = ipaddress.ip_network(value)
    out = []
    for k in sorted(observed):
        k_kind, k_value = parse_key(k)
        if k_kind == "ipv6-addr" and "/" not in k_value and ipaddress.ip_address(k_value) in net:
            out.append((k, observed[k]))
            if len(out) >= MAX_SIGHTING_REFS:
                break
    return out


def references(obj) -> list[str]:
    """Every reference an object carries: the value of any property ending in ``_ref`` or
    ``_refs``, at any depth (granular markings, extensions, SCO properties included)."""
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.endswith("_ref") and isinstance(v, str):
                out.append(v)
            elif k.endswith("_refs") and isinstance(v, list):
                out += [x for x in v if isinstance(x, str)]
                out += [r for x in v if not isinstance(x, str) for r in references(x)]
            else:
                out += references(v)
    elif isinstance(obj, list):
        for v in obj:
            out += references(v)
    return out


def dangling_references(objects: list[dict]) -> list[str]:
    """References that do not resolve to an object in ``objects``. The bundle embeds its TLP
    marking definition, so there is no exception: every reference must resolve."""
    ids = {o.get("id") for o in objects if isinstance(o, dict)}
    return sorted({r for o in objects for r in references(o) if r not in ids})


def _line(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True)


def _serialize(bundle_id: str, objects: list[dict]) -> bytes:
    """The bundle as JSON, one object per line, objects in a fixed order. Its size is exactly
    ``_size(bundle_id, [lines])``, which the caps rely on."""
    lines = [_line(o) for o in sorted(objects, key=lambda o: (_ORDER.get(o["type"], 9),
                                                              o["id"]))]
    return (_prefix(bundle_id) + ",\n".join(lines) + _SUFFIX).encode()


def _prefix(bundle_id: str) -> str:
    return '{"id": "' + bundle_id + '", "objects": [\n'


_SUFFIX = '\n], "type": "bundle"}\n'
_ORDER = {"identity": 0, "marking-definition": 1, "indicator": 2, "sighting": 3,
          "observed-data": 4, "ipv4-addr": 5, "ipv6-addr": 5, "file": 5}


def build_bundle(state: dict, settings: StixSettings) -> tuple[bytes, list[dict], dict]:
    """The bundle from the state, within ``max_objects`` and exactly ``max_bytes``.

    Objects come in groups, each complete on its own: a live indicator with its sighting and
    the observed-data and SCOs that sighting refers to; a revoked indicator; an
    observed-data with its SCO. Groups are taken in order (operator-approved indicators,
    then rule-promoted, latest window first; then revoked ones; then observations, most
    recent first). A group is taken only if everything in it that is not already in fits;
    only then are its objects counted as present. A group that does not fit is left out
    whole and later, smaller groups are still tried."""
    ids = _Ids(settings)
    base = [identity_object(settings.identity_name), tlp_object(settings.tlp)]
    bundle_id = ids.sdo("bundle", "")
    groups: list[list[dict]] = []

    def rank(item):
        key, e = item
        approved = any(b in OPERATOR_BASES for b in e["content"]["bases"])
        return (0 if approved else 1, _neg(e["content"]["valid_until"]), key)

    for key, e in sorted(state["indicators"].items(), key=rank):
        name = indicator_name(key, e["generation"])
        group = [indicator_object(ids, key, name, e, revoked=False)]
        refs = _observed_for(key, state["observed"])
        if refs:
            group.append(sighting_object(ids, name, e, refs))
            for k, oe in refs:
                group += [observed_object(ids, k, oe), sco_object(ids, k)]
        groups.append(group)
    for name, e in sorted(state["revoked"].items(), key=lambda i: (_neg(i[1]["revoked"]), i[0])):
        key = name.rpartition("#")[0]
        gen = int(name.rpartition("#")[2])
        groups.append([indicator_object(ids, key, indicator_name(key, gen), e, revoked=True)])
    for key, e in sorted(state["observed"].items(),
                         key=lambda i: (_neg(i[1]["content"]["last"]), i[0])):
        groups.append([observed_object(ids, key, e), sco_object(ids, key)])

    present: dict[str, dict] = {o["id"]: o for o in base}
    size = len(_prefix(bundle_id)) + len(_SUFFIX) + sum(len(_line(o)) for o in base) + \
        2 * (len(base) - 1)
    dropped = 0
    for group in groups:
        fresh: dict[str, dict] = {}
        for o in group:
            if o["id"] not in present:
                fresh.setdefault(o["id"], o)
        cost = sum(len(_line(o)) + 2 for o in fresh.values())      # ",\n" before each
        if len(present) + len(fresh) > settings.max_objects or size + cost > settings.max_bytes:
            dropped += 1
            continue
        present.update(fresh)
        size += cost
    objects = list(present.values())
    body = _serialize(bundle_id, objects)
    counts = {"objects": len(objects), "groups_dropped_for_caps": dropped,
              "indicators": sum(1 for o in objects if o["type"] == "indicator"),
              "revoked": sum(1 for o in objects if o.get("revoked")),
              "observed_data": sum(1 for o in objects if o["type"] == "observed-data"),
              "sightings": sum(1 for o in objects if o["type"] == "sighting"),
              "bytes": len(body)}
    return body, objects, counts


def _neg(stamp: str) -> tuple:
    """Sort key that puts later STIX timestamps first."""
    return tuple(-ord(ch) for ch in stamp)


def check_bundle(body: bytes, objects: list[dict], settings: StixSettings) -> None:
    """The last check before writing: within both caps, and every reference resolves."""
    if len(body) > settings.max_bytes or len(objects) > settings.max_objects:
        raise ExportRefused("STIX bundle would exceed its cap")
    dangling = dangling_references(objects)
    if dangling:
        raise ExportRefused(f"STIX bundle has {len(dangling)} unresolved references")


def _bundle_identity(path: Path) -> Optional[str]:
    """The identity id of the bundle at ``path`` (None when there is no file). Raises
    ExportRefused when a file is there but cannot be read as a bundle."""
    try:
        body = read_regular(path, BOUNDS["max_bytes"][1])
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ExportRefused(f"existing STIX bundle cannot be read ({type(exc).__name__})") \
            from None
    try:
        doc = json.loads(body.decode("utf-8"))
        return next(o["id"] for o in doc["objects"] if o.get("type") == "identity")
    except (ValueError, UnicodeDecodeError, RecursionError, KeyError, TypeError,
            AttributeError, StopIteration):
        raise ExportRefused("existing STIX bundle is not one this export wrote") from None


# ---- the run -------------------------------------------------------------------------------

def run_export(settings: StixSettings, records: list[TriageRecord], reports_dir, state_dir,
               networks: list, *, uploads_dir=None, upload_cap: int = 0,
               now: Optional[datetime.datetime] = None, ttl_days: float = 30.0,
               dry_run: bool = False) -> dict:
    """Write the state, then the bundle. ``networks`` is ``never_act_on`` plus the sensor's
    own address, as for OTX. Never sends anything anywhere. On any refusal nothing is
    written and the summary carries ``error``."""
    now = (now or datetime.datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    out_path = output_path(settings, reports_dir)
    spath = state_path(state_dir, settings.identity_name)
    summary: dict = {"file": out_path.name}
    try:
        state = load_state(spath, settings.identity_name)
        if not spath.exists() and \
                _bundle_identity(out_path) == sdo_id(settings.identity_name, "identity", ""):
            raise ExportRefused("STIX state is missing but a bundle from this identity exists")
        since = now - datetime.timedelta(days=settings.lookback_days)
        uploads = otx.read_uploads(uploads_dir, upload_cap, since) \
            if settings.hashes and uploads_dir and upload_cap > 0 else []
        candidates = otx.select_candidates(records, networks, now, settings.lookback_days,
                                           uploads, settings.hashes)
        approved = peek_blocklist(state_dir, now, ttl_days)
        before = state_bytes(state)
        summary["indicator_changes"] = reconcile_indicators(
            state, indicators_now(candidates, approved, networks, settings), now,
            settings.keep_days, unblocked(reports_dir, now))
        summary["observed_changes"] = reconcile_observed(
            state, observed_now(records, uploads, networks, now, settings.lookback_days), now,
            settings.keep_days)
        after = state_bytes(state)
        if len(after) > MAX_STATE_BYTES:
            raise ExportRefused("STIX state would exceed its size limit; lower lookback_days "
                                "or keep_days")
        body, objects, counts = build_bundle(state, settings)
        check_bundle(body, objects, settings)
    except ExportRefused as exc:
        summary["error"] = f"{exc}; nothing written, the previous bundle is unchanged"
        log.error("STIX: %s", summary["error"])
        return summary
    summary.update(counts)
    if dry_run:
        return {**summary, "status": "would write", "dry_run": True}
    try:
        if after != before or not spath.exists():
            _atomic_write(spath, after)
        try:
            current = read_regular(out_path, len(body))
        except OSError:
            current = b""
        if current != body:
            _atomic_write(out_path, body)
            summary["status"] = "written"
        else:
            summary["status"] = "unchanged"
    except OSError as exc:
        summary["error"] = f"cannot write the STIX export ({type(exc).__name__})"
        log.error("STIX: %s", summary["error"])
    return summary
