"""Response engine: run playbooks on new triage records; approval queue for enforce actions.

Everything here is deterministic code. The model never chooses actions. Notifications and
approval summaries are built from structured, code-computed fields (playbook, signals,
counts, protocol, source, IOC lists); the model-written narrative is left out unless
``[respond] include_narrative = true``, and then it is labelled untrusted with mention and
markup characters removed. Human-facing outputs (chat, email, tickets) defang URLs,
domains and addresses; the SIEM output keeps raw values.

- ``run_respond``: match each new record against enabled playbooks (cooldown per source,
  daily cap per playbook), then run the steps in order:
  local -> per-source state (one snapshot + atomic replace per run);
  notify -> enabled connectors only (otherwise recorded as inert), within per-playbook and
  per-connector caps;
  enforce -> written to the approval queue (only when ``[respond] queue_enforce`` is on),
  never executed here.
- ``approve`` / ``reject``: decide one queued action. Approvals expire. Approving takes a
  lock and moves the approval to ``executing`` atomically before running it, so two
  concurrent approvals cannot both execute. A rejection (or an expiry) suppresses the same
  (playbook, source, action) for a configurable period.
- ``unblock``: remove an address or network from the approved blocklist. Blocklist entries
  also expire on their own (default 30 days).
- Every run is recorded as JSON in ``reports/response/``. ``dry_run`` writes nothing and
  calls nothing; it returns what would happen.

Per-source gates, checked for every tier (local, notify, enforce):
- a source seen only over UDP without a nonce round trip (``unverified_source``) gets no
  action and no notification naming it; the run is recorded only;
- a non-global address (loopback, private, link-local, CGNAT, multicast, reserved,
  unspecified; IPv6 keys by their /64) or one inside ``[respond] never_act_on`` gets no
  action;
- when most records in the window come from one non-global address (a proxy hiding the
  real clients), per-source local and enforce actions are refused for the whole run.

Notify caps: each connector's daily cap keeps a reserved share that only priority
playbooks may use, and each playbook has its own daily cap per connector. A notification
dropped by a cap is recorded in the run, and one "N notifications suppressed" notice is
sent per connector at most once per period, when capacity allows.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime
import fcntl
import getpass
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Optional

import yaml

from agents.addresses import is_public
from agents.budget import ip_key
from agents.connectors.base import Notification
from agents.playbooks import (
    Playbook,
    derive_facts,
    load_playbooks,
    matches,
    tier_of,
)
from agents.source_state import (
    SourceEntry,
    SourceState,
    new_entry,
    legacy_source_token,
    source_token,
    source_token_name,
    update as update_source_state,
    valid_source_key,
)
from agents.triage import IocType, TriageRecord, load_records

log = logging.getLogger(__name__)
UTC = datetime.timezone.utc
SAFE_CHARS = re.compile(r"[^A-Za-z0-9 .,:;()_/@#+=%?&'-]")
# Removed from model-written text before it may appear in a notification.
MARKUP_CHARS = re.compile(r"[@#*_~`|<>\[\]{}!\\]")
APPROVAL_ID_RE = r"a-[0-9a-f]{12}"
DETECTION_FILE_RE = r"[0-9a-f]{8}-[a-z0-9-]{1,60}\.yml"
RESPONSE_FILE_RE = re.compile(r"^(\d{8}T\d{6}Z)-")
DEFAULT_APPROVAL_TTL_HOURS = 72
DEFAULT_LOOKBACK_HOURS = 48
MAX_PROCESSED = 100_000
CGNAT = ipaddress.ip_network("100.64.0.0/10")
NOTICE_PLAYBOOK = "notify_suppressed"


def sanitize(value: object, cap: int) -> str:
    text = SAFE_CHARS.sub("", str(value))
    return re.sub(r"\s+", " ", text).strip()[:cap]


def _now() -> datetime.datetime:
    return datetime.datetime.now(UTC)


def _iso(dt: datetime.datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse(ts: str) -> datetime.datetime:
    dt = datetime.datetime.fromisoformat(ts)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _atomic_json(path: Path, payload, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _read_json(path: Path, default):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, type(default)) else default
    except (OSError, ValueError, RecursionError):
        return default


def _truthy(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


# ---- settings ----------------------------------------------------------------------------

@dataclasses.dataclass
class RespondSettings:
    """``[respond]`` options. Every field is also a ``run_respond`` keyword."""

    approval_ttl_hours: float = float(DEFAULT_APPROVAL_TTL_HOURS)
    lookback_hours: float = float(DEFAULT_LOOKBACK_HOURS)
    queue_enforce: bool = False
    include_narrative: bool = False
    never_act_on: tuple[str, ...] = ()
    proxy_threshold: float = 0.5
    proxy_min_records: int = 20
    notify_max_per_playbook: int = 50
    notify_reserved_share: float = 0.25
    notify_default_cap: int = 200
    suppressed_notice_minutes: float = 60.0
    blocklist_file: Optional[str] = None
    blocklist_format: str = "plain"
    blocklist_ttl_days: float = 30.0
    reject_suppress_hours: float = 168.0
    expired_suppress_hours: float = 24.0
    snapshot_keep: int = 200
    snapshot_keep_days: float = 7.0
    retention_days: float = 30.0
    size_alarm_mb: float = 500.0

    def networks(self) -> list:
        """``never_act_on`` parsed; raises ValueError on a bad entry."""
        out = []
        for item in self.never_act_on:
            try:
                out.append(ipaddress.ip_network(str(item).strip(), strict=False))
            except ValueError:
                raise ValueError(f"never_act_on: not an address or network: {str(item)[:64]!r}") \
                    from None
        return out

    @classmethod
    def from_config(cls, section) -> "RespondSettings":
        """Build from a ``[respond]`` section (missing keys keep their defaults)."""
        kw: dict = {}
        for f in dataclasses.fields(cls):
            if section is None or f.name not in section:
                continue
            raw = str(section.get(f.name, "")).strip()
            default = f.default
            try:
                if f.name == "never_act_on":
                    kw[f.name] = tuple(x for x in re.split(r"[\s,]+", raw) if x)
                elif f.name == "blocklist_file":
                    kw[f.name] = raw or None
                elif isinstance(default, bool):
                    kw[f.name] = _truthy(raw)
                elif isinstance(default, int):
                    kw[f.name] = int(raw)
                elif isinstance(default, float):
                    kw[f.name] = float(raw)
                else:
                    kw[f.name] = raw
            except ValueError:
                raise ValueError(f"[respond] {f.name} has an invalid value") from None
        settings = cls(**kw)
        settings.networks()
        if not 0 <= settings.notify_reserved_share < 1:
            raise ValueError("[respond] notify_reserved_share must be >= 0 and < 1")
        if not 0 < settings.proxy_threshold <= 1:
            raise ValueError("[respond] proxy_threshold must be > 0 and <= 1")
        return settings


# ---- source gates ------------------------------------------------------------------------

def non_global(key: str) -> bool:
    """True for addresses no action may target. IPv6 keys are /64 networks and are judged
    by their network address (``::1`` becomes ``::/64``, which is unspecified)."""
    net = ipaddress.ip_network(key, strict=False)
    addr = net.network_address
    if addr.version == 4 and addr in CGNAT:
        return True
    return not is_public(str(addr))


def source_refusal(key: str, networks: list) -> Optional[str]:
    """Why no per-source action may target ``key``, or None."""
    if not valid_source_key(key):
        return "no source key"
    if non_global(key):
        return "non-global source"
    net = ipaddress.ip_network(key, strict=False)
    if any(net.version == n.version and net.overlaps(n) for n in networks):
        return "never_act_on"
    return None


def detect_proxy(records: list[TriageRecord], threshold: float, min_records: int) -> Optional[dict]:
    """A single non-global address behind most records means a proxy hides the clients."""
    if len(records) < max(1, min_records):
        return None
    counts = Counter(ip_key(r.src_ip) for r in records)
    for key, n in counts.most_common():
        if n / len(records) <= threshold:
            return None
        try:
            if valid_source_key(key) and non_global(key):
                return {"address": key, "records": n, "window_records": len(records),
                        "share": round(n / len(records), 3)}
        except ValueError:
            continue
    return None


# ---- engine state ------------------------------------------------------------------------

class EngineState:
    """Processed record ids, per-source cooldowns, per-playbook daily counts, notify ledger."""

    def __init__(self, state_dir: Path) -> None:
        self.path = state_dir / "respond_state.json"
        data = _read_json(self.path, {})
        self.processed: dict[str, str] = {str(k): str(v) for k, v in dict(data.get("processed", {})).items()}
        self.cooldowns: dict[str, str] = {str(k): str(v) for k, v in dict(data.get("cooldowns", {})).items()}
        self.day: str = str(data.get("day", ""))
        self.counts: dict[str, int] = {str(k): int(v) for k, v in dict(data.get("counts", {})).items()
                                       if isinstance(v, int)}
        notify = data.get("notify") if isinstance(data.get("notify"), dict) else {}

        def ints(name: str) -> dict[str, int]:
            raw = notify.get(name) if isinstance(notify.get(name), dict) else {}
            return {str(k): int(v) for k, v in raw.items() if isinstance(v, int) and v >= 0}

        self.sent = ints("sent")                        # connector -> sends today
        self.by_playbook = ints("by_playbook")          # "playbook|connector" -> sends today
        self.suppressed = ints("suppressed")            # connector -> dropped, not yet reported
        raw_last = notify.get("last_notice") if isinstance(notify.get("last_notice"), dict) else {}
        self.last_notice: dict[str, str] = {str(k): str(v) for k, v in raw_last.items()}

    def roll(self, now: datetime.datetime) -> None:
        today = now.date().isoformat()
        if today != self.day:
            self.day, self.counts, self.sent, self.by_playbook = today, {}, {}, {}

    def save(self, now: datetime.datetime) -> None:
        cutoff = now - datetime.timedelta(days=30)
        self.processed = {k: v for k, v in self.processed.items() if _parse(v) >= cutoff}
        if len(self.processed) > MAX_PROCESSED:
            self.processed = dict(sorted(self.processed.items(), key=lambda kv: kv[1])[-MAX_PROCESSED:])
        self.cooldowns = {k: v for k, v in self.cooldowns.items() if _parse(v) >= cutoff}
        _atomic_json(self.path, {"processed": self.processed, "cooldowns": self.cooldowns,
                                 "day": self.day, "counts": self.counts,
                                 "notify": {"sent": self.sent, "by_playbook": self.by_playbook,
                                            "suppressed": self.suppressed,
                                            "last_notice": self.last_notice}})


def _connector_cap(connectors, name: str, settings: RespondSettings) -> int:
    fn = getattr(connectors, "daily_cap", None)
    cap = fn(name) if callable(fn) else None
    return cap if isinstance(cap, int) and cap >= 0 else settings.notify_default_cap


def _notify_refusal(st: EngineState, pb: Playbook, name: str, cap: int,
                    settings: RespondSettings) -> Optional[str]:
    if st.by_playbook.get(f"{pb.name}|{name}", 0) >= settings.notify_max_per_playbook:
        return "playbook cap"
    total = st.sent.get(name, 0)
    if total >= cap:
        return "connector cap"
    reserved = math.ceil(cap * settings.notify_reserved_share)
    if not pb.priority and total >= cap - reserved:
        return "reserved for priority playbooks"
    return None


# ---- notifications -----------------------------------------------------------------------

def strip_markup(value: object, cap: int) -> str:
    """Model-written text reduced to plain words: no mentions, markup or control chars."""
    return sanitize(MARKUP_CHARS.sub(" ", str(value)), cap)


def structured_summary(pb: Playbook, record: TriageRecord, include_narrative: bool = False,
                       cap: int = 300) -> str:
    """One line built only from code-computed fields."""
    signals = ", ".join(sorted(sanitize(s, 40) for s in record.high_signal)) or "none"
    iocs = Counter(i.type.value for i in record.iocs)
    text = (f"{pb.name}: {record.kind} over {sanitize(record.protocol, 16)} from "
            f"{sanitize(record.src_ip, 64)}, judgement {record.judgement.value}, "
            f"stage {record.stage.value}; signals: {signals}; attempts {record.auth_attempts}, "
            f"connections {record.connections}, commands {record.commands}")
    if record.honeytokens:
        text += f"; honeytoken used ({len(record.honeytokens)})"
    if iocs:
        text += "; iocs: " + ", ".join(f"{k} {v}" for k, v in sorted(iocs.items()))
    text = sanitize(text, cap)
    if include_narrative and record.narrative:
        label = "; untrusted model narrative: "
        room = cap - len(text) - len(label)
        if room > 20:
            text += label + strip_markup(record.narrative, room)
    return text[:cap]


def build_notification(pb: Playbook, record: TriageRecord, include: list[str],
                       tags: list[str], include_narrative: bool = False) -> Notification:
    details: dict = {"attempts": record.auth_attempts, "connections": record.connections,
                     "signals": sorted(sanitize(s, 40) for s in record.high_signal)[:10]}
    if record.honeytokens:
        details["honeytokens"] = [sanitize(n, 64) for n in record.honeytokens[:10]]
    if "dialed_numbers" in include:
        details["dialed_numbers"] = [sanitize(n, 32) for n, _ in record.credentials.dialed_numbers[:10]]
    if "hashes" in include:
        details["hashes"] = [sanitize(i.value, 64) for i in record.iocs
                             if i.type in (IocType.MD5, IocType.SHA1, IocType.SHA256)][:10]
    if "urls" in include:
        details["urls"] = [sanitize(i.value, 200) for i in record.iocs if i.type == IocType.URL][:10]
    if "credentials" in include:
        details["usernames"] = [sanitize(u, 64) for u, _ in record.credentials.top_usernames[:10]]
    if "tags" in include:
        details["tags"] = [sanitize(t, 32) for t in tags[:8]]
    return Notification(
        playbook=pb.name,
        title=sanitize(f"{pb.name}: {record.judgement.value} {record.protocol} from {record.src_ip}", 160),
        summary=structured_summary(pb, record, include_narrative),
        record_id=sanitize(record.id, 200), source=sanitize(record.src_ip, 64),
        protocol=sanitize(record.protocol, 16), judgement=record.judgement.value,
        stage=record.stage.value, details=details,
        source_verified=not record.unverified_source)


def suppressed_notice(connector: str, count: int, since: Optional[str]) -> Notification:
    return Notification(
        playbook=NOTICE_PLAYBOOK, title=f"{count} notifications suppressed",
        summary=sanitize(f"{count} notifications to {connector} were dropped by notify caps"
                         + (f" since {since}" if since else "")
                         + "; each one is listed in reports/response.", 300),
        record_id="", source="", protocol="", judgement="", stage="",
        details={"suppressed": count, "connector": connector}, source_verified=None)


def matching_detections(record: TriageRecord, detections_dir: Path) -> list[str]:
    """Draft files in pending/ whose recorded provenance (``related_records``) includes this
    record. Overlap with attacker-supplied values alone never selects a draft."""
    out = []
    for path in sorted((detections_dir / "pending").glob("*.yml")):
        if not re.fullmatch(DETECTION_FILE_RE, path.name):
            continue
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            related = rule.get("related_records")
        except (OSError, yaml.YAMLError, AttributeError):
            continue
        if isinstance(related, list) and record.id in {str(r) for r in related}:
            out.append(path.name)
    return out[:20]


# ---- approvals ---------------------------------------------------------------------------

def _approvals_dir(state_dir: Path) -> Path:
    return state_dir / "approvals"


@contextlib.contextmanager
def _locked(state_dir: Path):
    """Exclusive lock over the approval queue, its index and the approved blocklist."""
    adir = _approvals_dir(state_dir)
    adir.mkdir(parents=True, exist_ok=True)
    with open(adir / ".lock", "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


class RunLocked(RuntimeError):
    """Another agents run that writes (triage, respond, digest, tune, detect, ship or
    run-all) holds the run lock."""


@contextlib.contextmanager
def run_lock(state_dir: Path):
    """Exclusive, non-blocking lock held for a whole respond, run-all or ship run, so engine
    state, source state and snapshot numbering are never updated by two runs at once.
    Raises RunLocked when another run holds it."""
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / "agents.lock"
    with open(path, "a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RunLocked(f"another agents run holds {path}; exiting") from None
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _index_path(state_dir: Path) -> Path:
    return _approvals_dir(state_dir) / "index.json"


def _rebuild_index(state_dir: Path) -> dict:
    """One scan of the queue, used only when the index file does not exist yet."""
    pending: dict = {}
    for path in _approvals_dir(state_dir).glob("a-*.json"):
        a = _read_json(path, {})
        if a.get("status") == "pending" and re.fullmatch(APPROVAL_ID_RE, str(a.get("id", ""))):
            params = a.get("params") if isinstance(a.get("params"), dict) else {}
            pending[_dedup_key(str(a.get("action", "")), str(a.get("subject", "")), params)] = \
                {"id": a["id"], "expires_at": str(a.get("expires_at", ""))}
    return {"pending": pending, "suppressed": {}}


def _load_index(state_dir: Path) -> dict:
    if not _index_path(state_dir).exists():
        return _rebuild_index(state_dir)
    idx = _read_json(_index_path(state_dir), {})
    pending = idx.get("pending") if isinstance(idx.get("pending"), dict) else {}
    suppressed = idx.get("suppressed") if isinstance(idx.get("suppressed"), dict) else {}
    return {"pending": {str(k): v for k, v in pending.items() if isinstance(v, dict) and
                        re.fullmatch(APPROVAL_ID_RE, str(v.get("id", "")))},
            "suppressed": {str(k): v for k, v in suppressed.items() if isinstance(v, dict)}}


def _save_index(state_dir: Path, idx: dict, now: datetime.datetime) -> None:
    idx["suppressed"] = {k: v for k, v in idx["suppressed"].items()
                         if _parse(str(v.get("until", _iso(now)))) > now}
    _atomic_json(_index_path(state_dir), idx)


def _dedup_key(action: str, subject: str, params: dict) -> str:
    return f"{action}|{subject}|{json.dumps(params, sort_keys=True)}"


def _suppress_key(playbook: str, subject: str, action: str) -> str:
    return f"{playbook}|{subject}|{action}"


def _close_in_index(idx: dict, a: dict, now: datetime.datetime, reason: Optional[str],
                    hours: float) -> None:
    """Drop ``a`` from the pending index; with ``reason`` also suppress re-queueing."""
    idx["pending"] = {k: v for k, v in idx["pending"].items() if v.get("id") != a.get("id")}
    if reason and hours > 0:
        key = _suppress_key(str(a.get("playbook", "")), str(a.get("subject", "")),
                            str(a.get("action", "")))
        idx["suppressed"][key] = {"until": _iso(now + datetime.timedelta(hours=hours)),
                                  "reason": reason, "approval_id": a.get("id")}


def _expire(path: Path, a: dict, idx: dict, now: datetime.datetime, hours: float) -> None:
    a["status"] = "expired"
    a["expired_at"] = _iso(now)
    _atomic_json(path, a)
    _close_in_index(idx, a, now, "expired", hours)


def queue_enforce_action(state_dir: Path, pb: Playbook, record: TriageRecord, step,
                         now: datetime.datetime, ttl_hours: float, params: dict,
                         summary: str = "",
                         expired_suppress_hours: float = 24.0) -> tuple[str, Optional[str]]:
    """Queue one enforce action. Returns (status, approval id). An identical pending
    request (same action, subject and parameters) is not queued twice; a recently rejected
    or expired one for the same (playbook, source, action) is suppressed. Lookups use the
    pending index, not a scan of every approval file."""
    subject = ip_key(record.src_ip)
    with _locked(state_dir):
        idx = _load_index(state_dir)
        dkey = _dedup_key(step.action, subject, params)
        hit = idx["pending"].get(dkey)
        if hit is not None:
            if _parse(str(hit.get("expires_at", _iso(now)))) > now:
                return f"already queued: {hit['id']}", hit["id"]
            path = _approvals_dir(state_dir) / f"{hit['id']}.json"
            a = _read_json(path, {})
            if a.get("status") == "pending":
                _expire(path, a, idx, now, expired_suppress_hours)
            else:
                _close_in_index(idx, {"id": hit["id"]}, now, None, 0)
        sup = idx["suppressed"].get(_suppress_key(pb.name, subject, step.action))
        if sup is not None and _parse(str(sup.get("until", _iso(now)))) > now:
            _save_index(state_dir, idx, now)
            return f"suppressed: {sanitize(sup.get('reason', ''), 16)}", None
        aid = "a-" + secrets.token_hex(6)
        expires = _iso(now + datetime.timedelta(hours=ttl_hours))
        payload = {
            "id": aid, "status": "pending", "action": step.action, "tier": "enforce",
            "playbook": pb.name, "record_id": record.id, "subject": subject,
            "unverified_source": record.unverified_source, "params": params,
            "created_at": _iso(now), "expires_at": expires, "summary": summary[:300],
        }
        _atomic_json(_approvals_dir(state_dir) / f"{aid}.json", payload)
        idx["pending"][dkey] = {"id": aid, "expires_at": expires}
        _save_index(state_dir, idx, now)
    return f"queued for approval: {aid}", aid


def list_queue(state_dir: os.PathLike | str, now: Optional[datetime.datetime] = None,
               include_closed: bool = False, expired_suppress_hours: float = 24.0) -> list[dict]:
    state_dir = Path(state_dir)
    now = now or _now()
    out = []
    with _locked(state_dir):
        idx = _load_index(state_dir)
        changed = False
        for path in sorted(_approvals_dir(state_dir).glob("a-*.json")):
            a = _read_json(path, {})
            if a.get("status") == "pending" and _parse(a["expires_at"]) <= now:
                _expire(path, a, idx, now, expired_suppress_hours)
                changed = True
            if include_closed or a.get("status") == "pending":
                out.append(a)
        if changed:
            _save_index(state_dir, idx, now)
    return out


def peek_queue(state_dir: os.PathLike | str, now: Optional[datetime.datetime] = None,
               include_closed: bool = False) -> list[dict]:
    """What ``list_queue`` returns, as a pure read for a read-only state directory: no lock,
    no directory, index or approval file is created or changed. An overdue pending item is
    returned as an ``expired`` copy (a closed item). Unreadable or malformed files are
    skipped."""
    adir = _approvals_dir(Path(state_dir))
    now = now or _now()
    out = []
    try:
        paths = sorted(adir.glob("a-*.json"))
    except OSError:
        return []
    for path in paths:
        if not re.fullmatch(APPROVAL_ID_RE + r"\.json", path.name):
            continue
        a = _read_json(path, {})
        try:
            expires = _parse(str(a["expires_at"]))
        except (KeyError, TypeError, ValueError):
            continue
        if a.get("status") == "pending" and expires <= now:
            a = {**a, "status": "expired"}
        if include_closed or a.get("status") == "pending":
            out.append(a)
    return out


class ApprovalError(ValueError):
    pass


def _load_approval(state_dir: Path, aid: str) -> tuple[Path, dict]:
    if not re.fullmatch(APPROVAL_ID_RE, aid or ""):
        raise ApprovalError("bad approval id")
    path = _approvals_dir(state_dir) / f"{aid}.json"
    if not path.exists():
        raise ApprovalError(f"no such approval {aid}")
    return path, _read_json(path, {})


# ---- blocklist ---------------------------------------------------------------------------

NFT_TABLE = "inet winnie"
NFT_SET_V4 = "winnie_block_v4"
NFT_SET_V6 = "winnie_block_v6"
NFT_CHUNK = 500


def _entry_times(value) -> tuple[str, str]:
    if isinstance(value, dict):
        return str(value.get("approved_at", "")), str(value.get("expires_at", ""))
    return str(value), ""


def write_blocklist(path: Path, entries: dict, fmt: str) -> None:
    """Write the full approved blocklist in a firewall-consumable format (nothing is pushed).

    ``entries`` maps an IPv4 address or IPv6 /64 to its approval time, or to a dict with
    ``approved_at`` and ``expires_at``. ``nftables`` output is a complete ``nft -f`` file:
    a table with one IPv4 and one IPv6 interval set, both flushed and refilled, so removed
    and expired entries disappear on reload."""
    rows = sorted(entries.items())
    if fmt == "nftables":
        v4 = [k for k, _ in rows if ipaddress.ip_network(k, strict=False).version == 4]
        v6 = [k for k, _ in rows if ipaddress.ip_network(k, strict=False).version == 6]
        lines = ["#!/usr/sbin/nft -f",
                 "# Approved blocklist written by the winnie response engine. Load with nft -f.",
                 f"table {NFT_TABLE} {{",
                 f"\tset {NFT_SET_V4} {{", "\t\ttype ipv4_addr", "\t\tflags interval", "\t}",
                 f"\tset {NFT_SET_V6} {{", "\t\ttype ipv6_addr", "\t\tflags interval", "\t}",
                 "}",
                 f"flush set {NFT_TABLE} {NFT_SET_V4}",
                 f"flush set {NFT_TABLE} {NFT_SET_V6}"]
        for name, items in ((NFT_SET_V4, v4), (NFT_SET_V6, v6)):
            for i in range(0, len(items), NFT_CHUNK):
                lines.append(f"add element {NFT_TABLE} {name} {{ {', '.join(items[i:i + NFT_CHUNK])} }}")
        text = "\n".join(lines) + "\n"
    elif fmt == "csv":
        text = "ip,approved_at,expires_at\n" + "".join(
            f"{k},{_entry_times(v)[0]},{_entry_times(v)[1]}\n" for k, v in rows)
    else:
        text = "".join(f"{k}\n" for k, _ in rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def _blocklist_store(state_dir: Path) -> Path:
    return state_dir / "approved_blocklist.json"


def _blocklist_target(reports_dir: Path, blocklist_file) -> Path:
    return Path(blocklist_file) if blocklist_file else reports_dir / "blocklist" / "approved.txt"


def _load_blocklist(state_dir: Path, now: datetime.datetime,
                    ttl_days: float) -> tuple[dict, bool]:
    """Live entries (expired ones dropped) and whether anything was dropped or upgraded."""
    raw = _read_json(_blocklist_store(state_dir), {})
    live, changed = {}, False
    for key, value in raw.items():
        approved, expires = _entry_times(value)
        try:
            if not expires:
                expires = _iso(_parse(approved) + datetime.timedelta(days=ttl_days))
                changed = True
            if _parse(expires) <= now:
                changed = True
                continue
        except ValueError:
            changed = True
            continue
        live[key] = {"approved_at": approved, "expires_at": expires}
    return live, changed


def peek_blocklist(state_dir: os.PathLike | str, now: Optional[datetime.datetime] = None,
                   ttl_days: float = 30.0) -> dict:
    """Live approved blocklist entries, {key: {approved_at, expires_at}}, as a pure read for
    a read-only state directory: no lock, and expired or legacy entries are left on disk
    (the next writer prunes them)."""
    entries, _ = _load_blocklist(Path(state_dir), now or _now(), ttl_days)
    return entries


def _write_blocklist_files(state_dir: Path, reports_dir: Path, entries: dict, blocklist_file,
                           fmt: str) -> Path:
    _atomic_json(_blocklist_store(state_dir), entries)
    target = _blocklist_target(reports_dir, blocklist_file)
    write_blocklist(target, entries, fmt)
    return target


def unblock(target: str, state_dir: os.PathLike | str, reports_dir: os.PathLike | str,
            blocklist_file: Optional[os.PathLike | str] = None, blocklist_format: str = "plain",
            now: Optional[datetime.datetime] = None, ttl_days: float = 30,
            by: Optional[str] = None) -> dict:
    """Remove an address (its IPv4 address or IPv6 /64 key) or every entry inside a
    network from the approved blocklist, then rewrite the blocklist file. An audit record
    goes to ``<reports_dir>/response``."""
    state_dir, reports_dir = Path(state_dir), Path(reports_dir)
    now = now or _now()
    value = str(target).strip()
    if "/" in value:
        net = ipaddress.ip_network(value, strict=False)
    else:
        net = ipaddress.ip_network(ip_key(str(ipaddress.ip_address(value))), strict=False)
    with _locked(state_dir):
        entries, _ = _load_blocklist(state_dir, now, ttl_days)
        removed = []
        for key in list(entries):
            k = ipaddress.ip_network(key, strict=False)
            if k.version == net.version and (k == net or k.subnet_of(net)):
                removed.append(key)
                del entries[key]
        path = _write_blocklist_files(state_dir, reports_dir, entries, blocklist_file,
                                      blocklist_format)
    # "unblock" never matches APPROVAL_ID_RE, so this cannot overwrite an approval record;
    # the leading stamp keeps it under apply_retention.
    _atomic_json(reports_dir / "response" /
                 f"{now.strftime('%Y%m%dT%H%M%SZ')}-unblock-{secrets.token_hex(3)}.json",
                 {"timestamp": _iso(now),
                  "unblock": {"target": sanitize(value, 64), "removed": sorted(removed),
                              "by": sanitize(by or getpass.getuser(), 64)}})
    return {"removed": sorted(removed), "entries": len(entries), "file": path.name}


# ---- approve / reject --------------------------------------------------------------------

def approve(aid: str, state_dir: os.PathLike | str, reports_dir: os.PathLike | str,
            detections_dir: os.PathLike | str, connectors=None, by: Optional[str] = None,
            blocklist_file: Optional[os.PathLike | str] = None, blocklist_format: str = "plain",
            now: Optional[datetime.datetime] = None, blocklist_ttl_days: float = 30.0,
            expired_suppress_hours: float = 24.0, never_act_on: tuple[str, ...] = ()) -> dict:
    """Execute one queued enforce action after re-checking it. Returns the approval.

    The pending -> executing transition happens under the queue lock, so only one of
    several concurrent approvals of the same id executes."""
    state_dir, reports_dir, detections_dir = Path(state_dir), Path(reports_dir), Path(detections_dir)
    now = now or _now()
    with _locked(state_dir):
        path, a = _load_approval(state_dir, aid)
        if a.get("status") != "pending":
            raise ApprovalError(f"{aid} is {a.get('status')}, not pending")
        idx = _load_index(state_dir)
        if _parse(a["expires_at"]) <= now:
            _expire(path, a, idx, now, expired_suppress_hours)
            _save_index(state_dir, idx, now)
            raise ApprovalError(f"{aid} expired at {a['expires_at']}")
        a["status"] = "executing"
        a["approved_by"] = sanitize(by or getpass.getuser(), 64)
        a["approved_at"] = _iso(now)
        _atomic_json(path, a)
        _close_in_index(idx, a, now, None, 0)
        _save_index(state_dir, idx, now)

    subject = str(a.get("subject", ""))
    verified = not a.get("unverified_source") and valid_source_key(subject)
    reason = source_refusal(subject, RespondSettings(never_act_on=tuple(never_act_on)).networks()) \
        if verified else None
    if not verified:
        result = {"ok": False, "status": "refused: subject is not a verified source"}
    elif reason:
        result = {"ok": False, "status": f"refused: {reason}"}
    else:
        action = a.get("action")
        if action == "export_blocklist":
            with _locked(state_dir):
                entries, _ = _load_blocklist(state_dir, now, blocklist_ttl_days)
                entries[subject] = {"approved_at": _iso(now), "expires_at": _iso(
                    now + datetime.timedelta(days=blocklist_ttl_days))}
                target = _write_blocklist_files(state_dir, reports_dir, entries, blocklist_file,
                                                blocklist_format)
            result = {"ok": True, "status": f"written to {target.name}", "entries": len(entries)}
        elif action == "publish_detection":
            moved = []
            for name in a.get("params", {}).get("files", []):
                src = detections_dir / "pending" / name
                if re.fullmatch(DETECTION_FILE_RE, name) and src.exists():
                    (detections_dir / "approved").mkdir(parents=True, exist_ok=True)
                    shutil.move(str(src), str(detections_dir / "approved" / name))
                    moved.append(name)
            result = {"ok": bool(moved), "status": f"published {len(moved)}", "files": moved}
        elif action == "open_ticket":
            payload = {"title": f"{a['playbook']}: {subject}", "summary": a.get("summary", ""),
                       "priority": a.get("params", {}).get("priority", "medium"),
                       "source": subject, "record_id": a.get("record_id", "")}
            r = connectors.open_ticket(payload) if connectors is not None else None
            result = {"ok": bool(r and r.ok), "status": r.status if r else "connector unavailable"}
        elif action == "block_webhook":
            r = connectors.block(subject, a["playbook"]) if connectors is not None else None
            result = {"ok": bool(r and r.ok), "status": r.status if r else "connector unavailable"}
        else:
            result = {"ok": False, "status": f"unknown action {action}"}
    a["status"] = "done" if result["ok"] else "failed"
    a["result"] = result
    _atomic_json(path, a)
    _atomic_json(reports_dir / "response" / f"{now.strftime('%Y%m%dT%H%M%SZ')}-{aid}.json",
                 {"timestamp": _iso(now), "approval": a})
    return a


def reject(aid: str, state_dir: os.PathLike | str, by: Optional[str] = None,
           now: Optional[datetime.datetime] = None, suppress_hours: float = 168,
           reports_dir: Optional[os.PathLike | str] = None) -> dict:
    """Reject one queued action. The same (playbook, source, action) is not queued again
    for ``suppress_hours``. With ``reports_dir``, an audit record goes to its ``response``
    directory, as for an approval."""
    state_dir = Path(state_dir)
    now = now or _now()
    with _locked(state_dir):
        path, a = _load_approval(state_dir, aid)
        if a.get("status") != "pending":
            raise ApprovalError(f"{aid} is {a.get('status')}, not pending")
        a.update(status="rejected", rejected_by=sanitize(by or getpass.getuser(), 64),
                 rejected_at=_iso(now))
        _atomic_json(path, a)
        idx = _load_index(state_dir)
        _close_in_index(idx, a, now, "rejected", suppress_hours)
        _save_index(state_dir, idx, now)
    if reports_dir is not None:
        _atomic_json(Path(reports_dir) / "response" /
                     f"{now.strftime('%Y%m%dT%H%M%SZ')}-{aid}.json",
                     {"timestamp": _iso(now), "approval": a})
    return a


# ---- per-source token registry ----------------------------------------------------------

def register_source_tokens(reports_dir: Path, state: SourceState, seed: str) -> None:
    """Add every planted per-source token to the honeytoken registry so triage attributes
    reuse to the exact source it was given to."""
    path = reports_dir / "honeytokens.json"
    reg = _read_json(path, {})
    # Keep every token planted before (even if its entry expired): reuse later is still
    # attributable. Planted tokens are deterministic, so re-adding one is idempotent.
    tokens = [t for t in reg.get("tokens", []) if isinstance(t, dict)]
    known = {t.get("value") for t in tokens}
    for key, entry in sorted(state.entries.items()):
        if not entry.plant_token:
            continue
        access, secret = source_token(seed, key)
        old_access, _ = legacy_source_token(seed, key)
        for value, kind, legacy in ((access, "aws_access_key", False),
                                    (secret, "generic_password", False),
                                    (old_access, "aws_access_key", True)):
            if value in known:
                continue
            entry = {"name": source_token_name(key), "kind": kind, "value": value,
                     "planted_in": ["per-source fake data"], "planted_for": key}
            if legacy:
                # The key id earlier versions planted for this source: recognised, never
                # planted again.
                entry["legacy"] = True
            tokens.append(entry)
    reg["tokens"] = tokens
    reg.setdefault("note", "Fake secrets planted in decoy data. Any use of one is a top-priority signal.")
    _atomic_json(path, reg, mode=0o644)


# ---- local actions -----------------------------------------------------------------------

def _later(a: Optional[str], b: str) -> str:
    return b if a is None or _parse(b) > _parse(a) else a


def _apply_local(entries: dict, step, record: TriageRecord, pb: Playbook,
                 now: datetime.datetime) -> str:
    """Apply one local step. Each effect gets its own expiry (the step's ``hours``); the
    entry expires with its last effect. The most recent budget-mode step wins, so a later
    ``shallow`` overrides an earlier ``deep`` and the reverse."""
    key = ip_key(record.src_ip)
    old = entries.get(key)
    if old is None or old.expired(now):
        old = new_entry(key, now, 1)
        base = old
    else:
        base = old.effective(now)
    until = _iso(now + datetime.timedelta(hours=getattr(step, "hours", 24)))
    # Effects written before per-effect expiry existed last as long as the entry did.
    fill = old.expires_at
    upd: dict = {
        "updated_at": _iso(now),
        "expires_at": _later(old.expires_at, until),
        "tarpit_until": (base.tarpit_until or fill) if base.tarpit_ms else None,
        "mode_until": (base.mode_until or fill) if base.budget_mode != "normal" else None,
        "capture_until": (base.capture_until or fill) if base.capture_more else None,
        "token_until": (base.token_until or fill) if base.plant_token else None,
        "tag_until": {t: base.tag_until.get(t, fill) for t in base.tags},
    }
    if step.action == "tarpit":
        upd["tarpit_ms"] = max(base.tarpit_ms, step.delay_ms)
        upd["tarpit_until"] = _later(upd["tarpit_until"], until)
    elif step.action in ("deepen", "shallow"):
        mode = "deep" if step.action == "deepen" else "shallow"
        upd["mode_until"] = _later(upd["mode_until"], until) if base.budget_mode == mode else until
        upd["budget_mode"] = mode
    elif step.action == "plant_token":
        upd["plant_token"] = True
        upd["token_until"] = _later(upd["token_until"], until)
    elif step.action == "tag_source":
        tags = [t for t in base.tags if t != step.tag] + [step.tag]
        tags = tags[-8:]
        upd["tags"] = tags
        upd["tag_until"] = {t: upd["tag_until"].get(t, until) for t in tags}
        upd["tag_until"][step.tag] = _later(base.tag_until.get(step.tag) if step.tag in base.tags
                                            else None, until)
    elif step.action == "capture_more":
        upd["capture_more"] = True
        upd["capture_until"] = _later(upd["capture_until"], until)
    if pb.name not in base.reasons:
        upd["reasons"] = (base.reasons + [pb.name])[-8:]
    entries[key] = base.model_copy(update=upd)
    return "applied"


# ---- retention ---------------------------------------------------------------------------

def _dir_bytes(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                continue
    return total


def apply_retention(state_dir: Path, reports_dir: Path, now: datetime.datetime,
                    settings: RespondSettings) -> dict:
    """Age out closed approvals and run records older than ``retention_days``. Decided
    approvals are judged by file time (no file is read); pending ones are kept."""
    cutoff = now - datetime.timedelta(days=settings.retention_days)
    removed_approvals = removed_runs = 0
    adir = _approvals_dir(state_dir)
    if adir.exists():
        with _locked(state_dir):
            pending = {v["id"] for v in _load_index(state_dir)["pending"].values()}
            for path in adir.glob("a-*.json"):
                if path.stem in pending:
                    continue
                try:
                    if path.stat().st_mtime < cutoff.timestamp():
                        path.unlink()
                        removed_approvals += 1
                except OSError:
                    continue
    rdir = reports_dir / "response"
    if rdir.exists():
        for path in rdir.glob("*.json"):
            m = RESPONSE_FILE_RE.match(path.name)
            if not m:
                continue
            try:
                stamp = datetime.datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
                if stamp < cutoff:
                    path.unlink()
                    removed_runs += 1
            except (ValueError, OSError):
                continue
    return {"approvals_removed": removed_approvals, "run_records_removed": removed_runs}


def size_alarm(state_dir: Path, reports_dir: Path, settings: RespondSettings) -> Optional[dict]:
    limit = int(settings.size_alarm_mb * 1024 * 1024)
    used = (_dir_bytes(_approvals_dir(state_dir)) + _dir_bytes(reports_dir / "response")
            + _dir_bytes(state_dir / "source-state-snapshots"))
    if used <= limit:
        return None
    log.warning("response state size %d bytes exceeds the alarm threshold of %d bytes "
                "(approvals, run records, source-state snapshots)", used, limit)
    return {"bytes": used, "limit_bytes": limit}


# ---- main run ----------------------------------------------------------------------------

def _refused(reason: str) -> str:
    return f"refused: {reason}"


@dataclasses.dataclass
class _Run:
    """What one respond run shares between its steps."""
    settings: RespondSettings
    reports_dir: Path
    state_dir: Path
    detections_dir: Path
    connectors: object
    scenario_name: Optional[str]
    seed: Optional[str]
    dry_run: bool
    now: datetime.datetime
    st: EngineState
    proxy: Optional[dict] = None
    runs: list = dataclasses.field(default_factory=list)
    local_ops: list = dataclasses.field(default_factory=list)  # (step, record, playbook)


def run_respond(reports_dir: os.PathLike | str, state_dir: os.PathLike | str,
                detections_dir: os.PathLike | str, source_state_file: os.PathLike | str,
                connectors=None, playbooks: Optional[list[Playbook]] = None,
                scenario_name: Optional[str] = None, seed: Optional[str] = None,
                dry_run: bool = False, now: Optional[datetime.datetime] = None,
                settings: Optional[RespondSettings] = None, **options) -> dict:
    """Run enabled playbooks on new records. ``options`` override fields of ``settings``
    (for example ``queue_enforce=True``)."""
    settings = dataclasses.replace(settings or RespondSettings(), **options)
    networks = settings.networks()
    if playbooks is None:
        playbooks, errors = load_playbooks()
    else:
        errors = []
    playbooks = [pb for pb in playbooks if pb.enabled]
    run = _Run(settings=settings, reports_dir=Path(reports_dir), state_dir=Path(state_dir),
               detections_dir=Path(detections_dir), connectors=connectors,
               scenario_name=scenario_name, seed=seed, dry_run=dry_run, now=now or _now(),
               st=EngineState(Path(state_dir)))
    run.st.roll(run.now)

    window = _records_in_window(run.reports_dir, run.now, settings.lookback_hours)
    run.proxy = _proxy_check(window, settings)
    for record in window:
        if record.id not in run.st.processed:
            _respond_to_record(run, record, playbooks, networks)

    notices = [] if dry_run else _send_suppressed_notices(connectors, run.st, settings, run.now)
    snapshot = _apply_local_ops(run, source_state_file)
    retention, alarm = _finish(run)
    runs = run.runs
    return {"runs": [r for r in runs if "steps" in r], "skipped": [r for r in runs if "skipped" in r],
            "playbook_errors": errors, "source_state_snapshot": snapshot, "dry_run": dry_run,
            "proxy_suspected": run.proxy, "suppressed_notices": notices,
            "suppressed_pending": {k: v for k, v in run.st.suppressed.items() if v},
            "retention": retention, "size_alarm": alarm}


def _records_in_window(reports_dir: Path, now: datetime.datetime,
                       lookback_hours: float) -> list[TriageRecord]:
    """Records seen within the lookback; older history is not acted on."""
    since = now - datetime.timedelta(hours=lookback_hours)
    window = []
    for record in load_records(reports_dir):
        stamp = record.last_seen or record.first_seen
        if stamp and _parse(stamp) < since:
            continue
        window.append(record)
    return window


def _proxy_check(window: list[TriageRecord], settings: RespondSettings) -> Optional[dict]:
    proxy = detect_proxy(window, settings.proxy_threshold, settings.proxy_min_records)
    if proxy is not None:
        log.warning("%d of %d records in the window come from the non-global address %s: a "
                    "proxy may be hiding client addresses; per-source actions are refused "
                    "for this run", proxy["records"], proxy["window_records"], proxy["address"])
    return proxy


def _source_gate(record: TriageRecord, key: str, networks) -> Optional[str]:
    """Why no per-source action may touch this record's source, or None."""
    if record.unverified_source:
        return "unverified source"
    try:
        return source_refusal(key, networks)
    except ValueError:
        return "no source key"


def _respond_to_record(run: _Run, record: TriageRecord, playbooks: list[Playbook],
                       networks) -> None:
    facts = derive_facts(record, run.scenario_name)
    key = ip_key(record.src_ip)
    gate = _source_gate(record, key, networks)
    for pb in playbooks:
        if matches(pb.when, record, facts):
            _run_playbook(run, pb, record, facts, key, gate)
    if not run.dry_run:
        run.st.processed[record.id] = _iso(run.now)


def _limit_reason(run: _Run, pb: Playbook, cooldown_key: str) -> Optional[str]:
    st = run.st
    if cooldown_key in st.cooldowns and run.now - _parse(st.cooldowns[cooldown_key]) < \
            datetime.timedelta(minutes=pb.cooldown_minutes):
        return "cooldown"
    if st.counts.get(pb.name, 0) >= pb.max_runs_per_day:
        return "daily cap"
    return None


def _run_playbook(run: _Run, pb: Playbook, record: TriageRecord, facts, key: str,
                  gate: Optional[str]) -> None:
    ck = f"{pb.name}|{key}"
    skipped = _limit_reason(run, pb, ck)
    if skipped is not None:
        run.runs.append({"playbook": pb.name, "record_id": record.id, "skipped": skipped})
        return
    summary = structured_summary(pb, record, run.settings.include_narrative)
    steps_out = [_run_step(run, pb, record, facts, gate, summary, i, step)
                 for i, step in enumerate(pb.steps)]
    now = run.now
    result = {"timestamp": _iso(now), "playbook": pb.name, "dry_run": run.dry_run,
              "trigger": _trigger(record, key), "summary": summary, "steps": steps_out}
    run.runs.append(result)
    if not run.dry_run:
        run.st.cooldowns[ck] = _iso(now)
        run.st.counts[pb.name] = run.st.counts.get(pb.name, 0) + 1
        _atomic_json(run.reports_dir / "response" /
                     f"{now.strftime('%Y%m%dT%H%M%SZ')}-{pb.name}-{secrets.token_hex(3)}.json",
                     result)


def _trigger(record: TriageRecord, key: str) -> dict:
    return {"record_id": record.id, "kind": record.kind, "protocol": record.protocol,
            "source": key, "judgement": record.judgement.value, "stage": record.stage.value,
            "signals": sorted(record.high_signal), "honeytoken": bool(record.honeytokens),
            "source_verified": not record.unverified_source}


def _run_step(run: _Run, pb: Playbook, record: TriageRecord, facts, gate: Optional[str],
              summary, index: int, step) -> dict:
    """Execute (or plan) one playbook step and return its status entry."""
    tier = tier_of(step)
    out = {"index": index, "action": step.action, "tier": tier}
    if gate is not None:
        out["status"] = _refused(gate)
    elif step.only_if is not None and not matches(step.only_if, record, facts):
        out["status"] = "skipped: condition"
    elif run.proxy is not None and (tier != "notify" or step.action == "enrich"):
        out["status"] = _refused("proxy suspected")
    elif tier == "local":
        if step.action == "plant_token" and not run.seed:
            out["status"] = "skipped: no sensor seed"
        else:
            run.local_ops.append((step, record, pb))
            out["status"] = "planned" if run.dry_run else "applied"
    elif step.action == "enrich":
        _enrich_step(run, record, out)
    elif tier == "notify":
        out["status"], out["connectors"] = "done", _notify_step(
            run.connectors, pb, record, step, run.st, run.settings, run.dry_run)
    else:  # enforce: never executed here
        _enforce_step(run, pb, record, step, summary, out)
    return out


def _enrich_step(run: _Run, record: TriageRecord, out: dict) -> None:
    connectors = run.connectors
    if connectors is None or not connectors.enabled("enrich"):
        out["status"] = "inert: connector disabled"
    elif run.dry_run:
        out["status"] = "planned"
    else:
        r = connectors.enrich(record.src_ip)
        out["status"], out["result"] = r.status, r.data


def _enforce_step(run: _Run, pb: Playbook, record: TriageRecord, step, summary,
                  out: dict) -> None:
    """Enforcement is only ever queued for a person to approve, never run here."""
    settings = run.settings
    if not settings.queue_enforce:
        out["status"] = "inert: enforcement queue not enabled"
        return
    if run.dry_run:
        out["status"] = "would queue for approval"
        return
    params: dict = {}
    if step.action == "publish_detection":
        params["files"] = matching_detections(record, run.detections_dir)
        if not params["files"]:
            out["status"] = "skipped: no matching draft"
            return
    if step.action == "open_ticket":
        params["priority"] = step.priority
    status, aid = queue_enforce_action(
        run.state_dir, pb, record, step, run.now, settings.approval_ttl_hours,
        params, summary, settings.expired_suppress_hours)
    out["status"] = status
    if aid:
        out["approval_id"] = aid


def _apply_local_ops(run: _Run, source_state_file) -> Optional[int]:
    """Apply every planned local step in one source-state update; returns the snapshot."""
    if not run.local_ops or run.dry_run:
        return None
    # Latest observed behaviour last, so its budget mode wins.
    local_ops = sorted(run.local_ops, key=lambda op: op[1].last_seen or op[1].first_seen or "")
    now = run.now

    def mutate(state: SourceState) -> SourceState:
        entries: dict[str, SourceEntry] = dict(state.entries)
        for step, record, pb in local_ops:
            _apply_local(entries, step, record, pb, now)
        return SourceState(entries=entries)

    new_state, snapshot = update_source_state(
        source_state_file, run.state_dir, mutate, now,
        keep_snapshots=run.settings.snapshot_keep, keep_days=run.settings.snapshot_keep_days)
    if run.seed:
        register_source_tokens(run.reports_dir, new_state, run.seed)
    return snapshot


def _finish(run: _Run) -> tuple[dict, Optional[dict]]:
    """Save engine state, refresh the blocklist files, apply retention, check sizes."""
    if run.dry_run:
        return {}, None
    settings, now = run.settings, run.now
    run.st.save(now)
    with _locked(run.state_dir):
        entries, changed = _load_blocklist(run.state_dir, now, settings.blocklist_ttl_days)
        if changed:
            _write_blocklist_files(run.state_dir, run.reports_dir, entries,
                                   settings.blocklist_file, settings.blocklist_format)
    retention = apply_retention(run.state_dir, run.reports_dir, now, settings)
    alarm = size_alarm(run.state_dir, run.reports_dir, settings)
    return retention, alarm


def _notify_step(connectors, pb: Playbook, record: TriageRecord, step, st: EngineState,
                settings: RespondSettings, dry_run: bool) -> list[dict]:
    """Send one notify step through each listed connector within the caps. A notification
    a cap drops is counted for the suppressed notice and recorded here."""
    sent = []
    for name in step.connectors:
        if connectors is None or not connectors.enabled(name):
            sent.append({"connector": name, "status": "inert: connector disabled"})
            continue
        if dry_run:
            sent.append({"connector": name, "status": "planned"})
            continue
        cap = _connector_cap(connectors, name, settings)
        refusal = _notify_refusal(st, pb, name, cap, settings)
        if refusal is None:
            tags = [s.tag for s in pb.steps if s.action == "tag_source"]
            n = build_notification(pb, record, step.include, tags, settings.include_narrative)
            r = connectors.notify(name, n)
            if r.status == "cap_reached":
                refusal = "connector cap"
            else:
                st.sent[name] = st.sent.get(name, 0) + 1
                pk = f"{pb.name}|{name}"
                st.by_playbook[pk] = st.by_playbook.get(pk, 0) + 1
                sent.append({"connector": name, "status": r.status})
        if refusal is not None:
            st.suppressed[name] = st.suppressed.get(name, 0) + 1
            sent.append({"connector": name, "status": f"suppressed: {refusal}"})
    return sent


def _send_suppressed_notices(connectors, st: EngineState, settings: RespondSettings,
                             now: datetime.datetime) -> list[dict]:
    """At most one notice per connector per period, sent when capacity allows; it may use
    the reserved share. Undelivered counts carry over to the next run."""
    out = []
    period = datetime.timedelta(minutes=settings.suppressed_notice_minutes)
    for name, count in sorted(st.suppressed.items()):
        if count <= 0 or connectors is None or not connectors.enabled(name):
            continue
        last = st.last_notice.get(name)
        if last and now - _parse(last) < period:
            continue
        if st.sent.get(name, 0) >= _connector_cap(connectors, name, settings):
            out.append({"connector": name, "count": count, "status": "waiting for capacity"})
            continue
        r = connectors.notify(name, suppressed_notice(name, count, last))
        out.append({"connector": name, "count": count, "status": r.status})
        if r.ok:
            st.sent[name] = st.sent.get(name, 0) + 1
            st.suppressed[name] = 0
            st.last_notice[name] = _iso(now)
        else:
            log.warning("suppressed-notifications notice to %s not delivered: %s", name, r.status)
    return out
