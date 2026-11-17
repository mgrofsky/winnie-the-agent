"""Data API for the operator console (the ``Routes`` object ``server`` calls).

Everything returned here was typed by attackers or derived from it. The rules:

- GET never writes. Only loaders that are pure reads are called (``peek_queue``, ``peek_blocklist``,
  ``DailyCallCounter.peek``, ``EngineState``'s constructor, ...); files without such a
  loader are read directly. No lock file, directory, cursor or counter is created.
- Ids before paths. A request path component reaches the filesystem only after matching a
  strict pattern, and the final path must resolve inside its base directory. Record ids
  are looked up in the parsed record set and never become a path. Anything else is a 404.
- One sanitising boundary. ``Api.get`` passes its whole answer through ``scrub``, which
  removes control and bidi characters from every string (keys included) and caps lengths,
  so a field added later cannot skip it.
- Missing or corrupt data is normal: a fresh deployment answers with empty lists.
- Bounded work: the record set and the queue are cached and re-read only when a cheap
  directory signature changes; the event log is indexed incrementally (``logindex``).
- Errors are ``{"error": <fixed text>}``; request input and exception text are never
  echoed.
- POST (approve, reject, unblock) runs only for a signed-in operator with ``[ui] actions``
  on (the shell checks that). It calls ``respond.approve`` / ``reject`` / ``unblock`` with
  the arguments the CLI passes, so every gate stays in one place. A decision names the
  ``view_hash`` the operator saw; a different approval on disk is a 409 and nothing changes.
"""

from __future__ import annotations

import datetime
import getpass
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from agents import triage
from agents.llm import DailyCallCounter
from agents.playbooks import PLAYBOOKS_DIR, load_playbooks, tier_of
from agents.respond import (
    APPROVAL_ID_RE,
    DETECTION_FILE_RE,
    ApprovalError,
    EngineState,
    RespondSettings,
    approve,
    peek_blocklist,
    peek_queue,
    reject,
    size_alarm,
    unblock,
)
from agents.runtime import event_log_state
from agents.source_state import load as load_source_state
from agents.triage import JUDGEMENT_RANK, Judgement, TriageRecord, load_records, rank
from agents.tuner import history as tuner_history
from agents.ui.logindex import DEFAULT_MAX_SESSIONS, RangeTooLarge, SessionIndex
from scenarios.loader import load_overlay

log = logging.getLogger(__name__)
UTC = datetime.timezone.utc

TEXT_CAP = 4_000
LONG_TEXT_CAP = 200_000
KEY_CAP = 200
MAX_DEPTH = 32
DEFAULT_PER = 50
MAX_PER = 200
MAX_PAGE = 1_000_000
CACHE_SECONDS = 3.0
SLOW_CACHE_SECONDS = 60.0
SHIP_TAIL_BYTES = 64 * 1024
SHIP_TAIL_EVENTS = 10
TOP_SOURCES = 10
HONEYTOKEN_HITS = 20
TUNER_RECORDS = 20
MAX_TUNER_FILE = 1024 * 1024
MAX_JSON_FILE = 16 * 1024 * 1024
WINDOWS = {"24h": datetime.timedelta(hours=24), "7d": datetime.timedelta(days=7)}

# Every C0 control except \t and \n, DEL, C1 controls, and the bidi/direction marks
# (ALM, LRM, RLM, LRE..RLO, LRI..PDI) that can make text render other than it reads.
_STRIP_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f؜‎‏‪-‮"
                       "⁦-⁩]")
# The record id shape triage.write_record produces (its _safe_filename alphabet).
RECORD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}")
DAY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
DETECTION_RE = re.compile(DETECTION_FILE_RE)
TOKEN_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
PROTOCOL_RE = re.compile(r"[a-z0-9]{1,16}")
TUNER_FILE_RE = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{6}\.json")
APPROVAL_RE = re.compile(APPROVAL_ID_RE)
VIEW_HASH_RE = re.compile(r"[0-9a-f]{64}")
DECIDE_RE = re.compile(r"queue/([^/]+)/(approve|reject)")
MAX_TARGET = 64
ERROR_CAP = 200
# Approved actions that send through a connector, and the connector each one needs.
CONNECTOR_FOR = {"open_ticket": "ticket", "block_webhook": "block_webhook"}

NOT_FOUND = (404, {"error": "not found"})
BAD_QUERY = (400, {"error": "bad query"})
CHANGED = (409, {"error": "changed"})
BAD_VIEW_HASH = (400, {"error": "view_hash must be the 64-character hex value from the queue"})
BAD_TARGET = (400, {"error": "target must be an IP address or network"})
NO_CONNECTOR = (400, {"error": "connector not available here; approve with the CLI in the "
                               "agents container"})
BAD_SETTINGS = (500, {"error": "[respond] settings are invalid; nothing was changed (see the "
                               "server log)"})


# ---- sanitising boundary -------------------------------------------------------------------

class LongText(str):
    """A string allowed the long cap (a digest or detection file)."""


def clean_text(value: str, cap: int = TEXT_CAP) -> str:
    """Control and bidi characters removed (``\\n`` and ``\\t`` kept), then capped. The
    input is cut first so a huge string costs no more than a capped one."""
    return _STRIP_RE.sub("", value[:cap * 2])[:cap]


def scrub(value: object, depth: int = 0) -> object:
    """The response boundary: every string cleaned, numbers made JSON-safe, any other type
    turned into cleaned text. Applied to the whole answer, so no field can skip it."""
    if depth > MAX_DEPTH:
        return None
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return clean_text(value, LONG_TEXT_CAP if isinstance(value, LongText) else TEXT_CAP)
    if isinstance(value, dict):
        return {clean_text(str(k), KEY_CAP): scrub(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(v, depth + 1) for v in value]
    return clean_text(str(value))


def view_hash(approval: dict) -> str:
    """SHA-256 over the canonical JSON of an approval as read from disk. The approve and
    reject calls send it back, so a decision is only made on what the operator saw."""
    text = json.dumps(approval, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      default=str)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


# ---- small helpers -------------------------------------------------------------------------

class _BadQuery(Exception):
    pass


def _int(query: dict[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = query.get(name)
    if raw is None or raw == "":
        return default
    if not re.fullmatch(r"\d{1,9}", raw):
        raise _BadQuery
    return max(low, min(high, int(raw)))


def paginate(items: list, query: dict[str, str]) -> dict:
    page = _int(query, "page", 1, 1, MAX_PAGE)
    per = _int(query, "per", DEFAULT_PER, 1, MAX_PER)
    start = (page - 1) * per
    return {"total": len(items), "page": page, "per": per, "items": items[start:start + per]}


def _parse_ts(value: object) -> Optional[datetime.datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _inside(base: Path, name: str) -> Optional[Path]:
    """``base / name`` when it resolves to a direct child of ``base``; else None."""
    path = base / name
    try:
        if path.resolve().parent != base.resolve():
            return None
    except (OSError, RuntimeError):
        return None
    return path


def _read_text(path: Path, cap: int) -> Optional[tuple[str, bool]]:
    """(text, truncated) of at most ``cap`` characters, or None when unreadable."""
    try:
        with open(path, "rb") as f:
            raw = f.read(cap * 4 + 1)
            more = f.read(1) != b""
    except OSError:
        return None
    text = raw.decode("utf-8", errors="replace")
    return text[:cap], more or len(text) > cap


def _read_json(path: Path, default):
    """Parsed JSON of the expected type, or ``default`` (missing, oversized, corrupt)."""
    try:
        if path.stat().st_size > MAX_JSON_FILE:
            return default
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default
    return data if isinstance(data, type(default)) else default


def _list_names(directory: Path, pattern: re.Pattern) -> list[str]:
    try:
        with os.scandir(directory) as it:
            return sorted(e.name for e in it if pattern.fullmatch(e.name) and e.is_file())
    except OSError:
        return []


def _signature(dirs: tuple[Path, ...]) -> tuple:
    """Entry count and newest mtime per directory, from one scandir pass each."""
    sig = []
    for d in dirs:
        try:
            dir_mtime = d.stat().st_mtime_ns
            count, newest = 0, 0
            with os.scandir(d) as it:
                for entry in it:
                    count += 1
                    try:
                        newest = max(newest, entry.stat(follow_symlinks=False).st_mtime_ns)
                    except OSError:
                        continue
        except OSError:
            sig.append(None)
            continue
        sig.append((dir_mtime, count, newest))
    return tuple(sig)


class _DirCache:
    """A value loaded from some directories, re-loaded only when their signature changes,
    checked at most every ``min_interval`` seconds."""

    def __init__(self, dirs: tuple[Path, ...], load: Callable[[], object], min_interval: float,
                 clock: Callable[[], float]) -> None:
        self.dirs, self.load, self.min_interval, self.clock = dirs, load, min_interval, clock
        self._lock = threading.Lock()
        self._value: object = None
        self._sig: object = None
        self._checked = float("-inf")
        self.loads = 0

    def get(self):
        with self._lock:
            now = self.clock()
            if self._value is None or now - self._checked >= self.min_interval:
                self._checked = now
                sig = _signature(self.dirs)
                if self._value is None or sig != self._sig:
                    self._value = self.load()
                    self._sig = sig
                    self.loads += 1
            return self._value

    def invalidate(self) -> None:
        """Check the signature on the next ``get`` (after this process wrote)."""
        with self._lock:
            self._checked = float("-inf")


@dataclass
class _Records:
    newest: list[TriageRecord]               # newest first
    ranked: list[TriageRecord]               # triage.rank order
    by_id: dict[str, TriageRecord]
    stamps: dict[str, Optional[datetime.datetime]]


def _stamp(r: TriageRecord) -> Optional[datetime.datetime]:
    return _parse_ts(r.last_seen) or _parse_ts(r.first_seen)


def _summary(r: TriageRecord) -> dict:
    return {"id": r.id, "kind": r.kind, "protocol": r.protocol, "src_ip": r.src_ip,
            "first_seen": r.first_seen, "last_seen": r.last_seen,
            "judgement": r.judgement.value, "stage": r.stage.value, "intent": r.intent.value,
            "skill": r.skill.value, "username": r.username, "commands": r.commands,
            "auth_attempts": r.auth_attempts, "auth_successes": r.auth_successes,
            "connections": r.connections, "honeytokens": list(r.honeytokens),
            "high_signal": sum(r.high_signal.values()), "llm_used": r.llm_used,
            "unverified_source": r.unverified_source, "narrative": r.narrative[:300]}


def _haystack(r: TriageRecord) -> str:
    parts = [r.id, r.src_ip, r.username or "", r.narrative, *r.command_sample,
             *(i.value for i in r.iocs), *r.honeytokens, *r.src_addresses]
    parts += [u for u, _ in r.credentials.top_usernames]
    return "\n".join(parts).lower()


def _mask(value: str) -> str:
    return value[:2] + "......"


# ---- the API -------------------------------------------------------------------------------

@dataclass(frozen=True)
class ApiPaths:
    """Where the API reads. None of these is ever written."""

    reports: Path
    state: Path
    data: Path
    detections: Path
    overlay: Path
    source_state: Path
    playbooks: Path = PLAYBOOKS_DIR
    log: Optional[Path] = None
    budget_state: Optional[Path] = None   # default <data>/budget_state.json


@dataclass
class ApiLimits:
    """Numbers shown next to today's counts (caps, not secrets)."""

    analyst_calls_per_day: int = 500
    frontend_tokens_per_day: Optional[int] = None
    index_sessions: int = DEFAULT_MAX_SESSIONS


@dataclass
class Api:
    """The console's routes. Thread-safe; build once and share.

    ``respond_settings`` and ``connectors`` are what the CLI's approve / reject / unblock
    use (``runtime.respond_settings`` and ``runtime.respond_connectors``). The settings are
    re-read on every decision so a bad ``[respond]`` refuses it instead of falling back to
    defaults; without the callable, ``settings`` is used. ``operator`` is the ``[ui]``
    label; decisions are recorded as ``ui:<operator>`` (the OS user when it is empty)."""

    paths: ApiPaths
    settings: RespondSettings = field(default_factory=RespondSettings)
    limits: ApiLimits = field(default_factory=ApiLimits)
    cache_seconds: float = CACHE_SECONDS
    clock: Callable[[], float] = time.monotonic
    now: Callable[[], datetime.datetime] = lambda: datetime.datetime.now(UTC)
    operator: str = ""
    respond_settings: Optional[Callable[[], RespondSettings]] = None
    connectors: Optional[Callable[[], object]] = None

    def __post_init__(self) -> None:
        self._connectors_lock = threading.Lock()
        self._connectors_built = False
        self._connectors_value: object = None
        p = self.paths
        self._records = _DirCache((p.reports / "sessions", p.reports / "campaigns"),
                                  self._load_records, self.cache_seconds, self.clock)
        self._queue = _DirCache((p.state / "approvals",), self._load_queue,
                                self.cache_seconds, self.clock)
        self.index = SessionIndex(p.log, max_sessions=self.limits.index_sessions,
                                  min_interval=self.cache_seconds, clock=self.clock)
        self._alarm_lock = threading.Lock()
        self._alarm: tuple[float, object] = (float("-inf"), None)
        self._routes: list[tuple[re.Pattern, Callable]] = [
            (re.compile(r"overview"), self.overview),
            (re.compile(r"records"), self.records),
            (re.compile(r"records/([^/]+)"), self.record),
            (re.compile(r"records/([^/]+)/transcript"), self.transcript),
            (re.compile(r"queue"), self.queue),
            (re.compile(r"blocklist"), self.blocklist),
            (re.compile(r"digests"), self.digests),
            (re.compile(r"digests/([^/]+)"), self.digest),
            (re.compile(r"decoy"), self.decoy),
            (re.compile(r"playbooks"), self.playbooks),
            (re.compile(r"detections"), self.detections),
            (re.compile(r"detections/([^/]+)/([^/]+)"), self.detection),
            (re.compile(r"honeytokens"), self.honeytokens),
        ]

    # -- Routes protocol --

    def get(self, path: str, query: dict[str, str]) -> tuple[int, object]:
        status, value = self._dispatch(path, query)
        return status, scrub(value)

    def post(self, path: str, body: dict) -> tuple[int, object]:
        status, value = self._dispatch_post(path, body)
        return status, scrub(value)

    def _dispatch_post(self, path: str, body: dict) -> tuple[int, object]:
        if not path.startswith("/api/"):
            return NOT_FOUND
        rest = path[len("/api/"):]
        m = DECIDE_RE.fullmatch(rest)
        if m is None and rest != "blocklist/unblock":
            return NOT_FOUND
        try:
            if m is not None:
                return self._decide(m.group(1), m.group(2), body)
            return self._unblock(body)
        except Exception:  # noqa: BLE001 - details go to the log, never to the client
            log.exception("api action failed")
            return 500, {"error": "internal error"}

    def _dispatch(self, path: str, query: dict[str, str]) -> tuple[int, object]:
        if not path.startswith("/api/"):
            return NOT_FOUND
        rest = path[len("/api/"):]
        for pattern, handler in self._routes:
            m = pattern.fullmatch(rest)
            if m is None:
                continue
            try:
                return handler(query, *m.groups())
            except _BadQuery:
                return BAD_QUERY
            except Exception:  # noqa: BLE001 - a bad file must not take the console down
                log.exception("api route failed")
                return 500, {"error": "internal error"}
        return NOT_FOUND

    # -- loaders --

    def _load_records(self) -> _Records:
        records = load_records(self.paths.reports)
        stamps = {r.id: _stamp(r) for r in records}
        floor = datetime.datetime.min.replace(tzinfo=UTC)
        newest = sorted(records, key=lambda r: stamps[r.id] or floor, reverse=True)
        return _Records(newest=newest, ranked=rank(records), by_id={r.id: r for r in records},
                        stamps=stamps)

    def _load_queue(self) -> list[dict]:
        items = peek_queue(self.paths.state, now=self.now(), include_closed=True)
        return sorted(items, key=lambda a: str(a.get("created_at", "")), reverse=True)

    def _record_id(self, raw: str) -> Optional[TriageRecord]:
        if not RECORD_ID_RE.fullmatch(raw):
            return None
        return self._records.get().by_id.get(raw)

    def _engine(self) -> Optional[EngineState]:
        try:
            return EngineState(self.paths.state)   # the constructor only reads
        except (TypeError, ValueError, AttributeError):
            return None

    def _size_alarm(self):
        """``respond.size_alarm`` walks three directories; refreshed once a minute."""
        with self._alarm_lock:
            at, value = self._alarm
            now = self.clock()
            if now - at >= SLOW_CACHE_SECONDS:
                value = size_alarm(self.paths.state, self.paths.reports, self.settings)
                self._alarm = (now, value)
            return value

    # -- routes --

    def overview(self, query: dict[str, str]) -> tuple[int, object]:
        window = query.get("window") or "24h"
        if window not in WINDOWS:
            raise _BadQuery
        now = self.now()
        since = now - WINDOWS[window]
        recs = self._records.get()
        inside = [r for r in recs.newest
                  if recs.stamps[r.id] is not None and recs.stamps[r.id] >= since]
        by_protocol = Counter(r.protocol for r in inside)
        by_judgement = Counter(r.judgement.value for r in inside)
        sources: Counter = Counter(r.src_ip for r in inside)
        worst: dict[str, Judgement] = {}
        for r in inside:
            seen = worst.get(r.src_ip)
            if seen is None or JUDGEMENT_RANK[r.judgement] > JUDGEMENT_RANK[seen]:
                worst[r.src_ip] = r.judgement
        hits = [_summary(r) for r in inside if r.honeytokens][:HONEYTOKEN_HITS]
        pending = [a for a in self._queue.get() if a.get("status") == "pending"]
        expiries = sorted(str(a.get("expires_at", "")) for a in pending if a.get("expires_at"))
        return 200, {
            "window": window, "since": since.isoformat(timespec="seconds"),
            "totals": {"records": len(inside),
                       "sessions": sum(1 for r in inside if r.kind == "session"),
                       "campaigns": sum(1 for r in inside if r.kind == "campaign"),
                       "by_protocol": dict(sorted(by_protocol.items())),
                       "by_judgement": {j.value: by_judgement.get(j.value, 0)
                                        for j in Judgement}},
            "top_sources": [{"src_ip": ip, "records": n, "worst": worst[ip].value}
                            for ip, n in sources.most_common(TOP_SOURCES)],
            "honeytoken_hits": hits,
            "approvals": {"pending": len(pending),
                          "soonest_expiry": expiries[0] if expiries else None},
            "health": self._health(recs, now),
        }

    def _health(self, recs: _Records, now: datetime.datetime) -> dict:
        p = self.paths
        log_state, _ = event_log_state(p.log)   # the message names the path: not returned
        log_info: dict = {"state": log_state}
        if log_state == "ok":
            try:
                log_info["bytes"] = os.stat(p.log).st_size
            except OSError:
                pass
            self.index.refresh()
            log_info["index"] = self.index.stats()
        stamps = [s for s in recs.stamps.values() if s is not None]
        counter = DailyCallCounter(p.state / "analyst_calls.json",
                                   self.limits.analyst_calls_per_day).peek()
        today = now.date().isoformat()
        budget = _read_json(p.budget_state or p.data / "budget_state.json", {})
        tokens = budget.get("global_tokens") if budget.get("day") == today else 0
        limits = triage.sensor_limit_totals(p.reports, today)
        return {
            "event_log": log_info,
            "newest_record": max(stamps).isoformat(timespec="seconds") if stamps else None,
            "records_total": len(recs.newest),
            "analyst_calls": counter,
            "frontend_tokens": {"day": today,
                                "tokens": tokens if isinstance(tokens, int) and tokens >= 0 else 0,
                                "limit": self.limits.frontend_tokens_per_day},
            "sensor_limits": [{"protocol": proto, "reason": reason, "pool": pool, "count": n}
                              for (proto, reason, pool), n in limits.most_common()],
            "size_alarm": self._size_alarm(),
            "ship_failures": self._ship_failures(),
        }

    def _ship_failures(self) -> list[dict]:
        path = self.paths.state / "ship_events.jsonl"
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - SHIP_TAIL_BYTES))
                raw = f.read(SHIP_TAIL_BYTES)
        except OSError:
            return []
        lines = raw.split(b"\n")
        if size > SHIP_TAIL_BYTES:
            lines = lines[1:]   # the first one is probably cut
        out = []
        for line in reversed(lines):
            try:
                ev = json.loads(line.decode("utf-8", errors="replace"))
            except ValueError:
                continue
            if isinstance(ev, dict):
                # Whitelisted fields: the object key carries the configured bucket prefix.
                out.append({k: ev.get(k) for k in ("timestamp", "event", "error", "lines")})
            if len(out) >= SHIP_TAIL_EVENTS:
                break
        return out

    def records(self, query: dict[str, str]) -> tuple[int, object]:
        recs = self._records.get()
        sort = query.get("sort") or "newest"
        if sort not in ("newest", "rank"):
            raise _BadQuery
        items = recs.ranked if sort == "rank" else recs.newest
        kind = query.get("kind") or ""
        if kind:
            if kind not in ("session", "campaign"):
                raise _BadQuery
            items = [r for r in items if r.kind == kind]
        protocol = (query.get("protocol") or "").lower()
        if protocol:
            if not PROTOCOL_RE.fullmatch(protocol):
                raise _BadQuery
            items = [r for r in items if r.protocol == protocol]
        judgement = (query.get("judgement") or "").upper()
        if judgement:
            if judgement not in {j.value for j in Judgement}:
                raise _BadQuery
            items = [r for r in items if r.judgement.value == judgement]
        honeytoken = query.get("honeytoken") or ""
        if honeytoken:
            if honeytoken not in ("0", "1"):
                raise _BadQuery
            items = [r for r in items if bool(r.honeytokens) == (honeytoken == "1")]
        src = query.get("src") or ""
        if src:
            if len(src) > 64:
                raise _BadQuery
            items = [r for r in items if r.src_ip == src or src in r.src_addresses]
        q = (query.get("q") or "").strip().lower()
        if q:
            if len(q) > 200:
                raise _BadQuery
            items = [r for r in items if q in _haystack(r)]
        page = paginate(items, query)
        page["items"] = [_summary(r) for r in page["items"]]
        page["sort"] = sort
        return 200, page

    def record(self, query: dict[str, str], rid: str) -> tuple[int, object]:
        r = self._record_id(rid)
        if r is None:
            return NOT_FOUND
        approvals = [a.get("id") for a in self._queue.get() if a.get("record_id") == r.id]
        return 200, {"record": r.model_dump(mode="json"), "approvals": approvals,
                     "transcript_available": self._has_transcript(r)}

    def _has_transcript(self, r: TriageRecord) -> bool:
        return r.kind == "session" and r.protocol == "ssh" and self.index.range_of(r.id) is not None

    def transcript(self, query: dict[str, str], rid: str) -> tuple[int, object]:
        r = self._record_id(rid)
        if r is None or r.kind != "session" or r.protocol != "ssh":
            return NOT_FOUND
        try:
            t = self.index.transcript(r.id)
        except RangeTooLarge:
            return 422, {"error": "transcript too large"}
        if t is None:
            return 404, {"error": "transcript not available"}
        turns = [{**turn, "truncated": len(turn["text"]) > TEXT_CAP} for turn in t["turns"]]
        t["turns"] = paginate(turns, query)
        return 200, t

    def queue(self, query: dict[str, str]) -> tuple[int, object]:
        everything = query.get("all") or "0"
        if everything not in ("0", "1"):
            raise _BadQuery
        items = self._queue.get()
        if everything == "0":
            items = [a for a in items if a.get("status") == "pending"]
        page = paginate(items, query)
        by_id = self._records.get().by_id
        out = []
        for a in page["items"]:
            r = by_id.get(str(a.get("record_id", "")))
            # Only an untouched pending item can be decided; peek_queue hands an overdue
            # one back as an "expired" copy, which is no longer what is on disk.
            out.append({"approval": a,
                        "view_hash": view_hash(a) if a.get("status") == "pending" else None,
                        "can_approve_here": self._can_approve_here(a),
                        "record": _summary(r) if r is not None else None})
        page["items"] = out
        return 200, page

    def blocklist(self, query: dict[str, str]) -> tuple[int, object]:
        entries = peek_blocklist(self.paths.state, self.now(), self.settings.blocklist_ttl_days)
        items = sorted(({"target": k, **v} for k, v in entries.items()),
                       key=lambda e: e["approved_at"], reverse=True)
        return 200, paginate(items, query)

    def digests(self, query: dict[str, str]) -> tuple[int, object]:
        names = _list_names(self.paths.reports / "daily", re.compile(r"\d{4}-\d{2}-\d{2}\.md"))
        return 200, paginate([n[:-3] for n in reversed(names)], query)

    def digest(self, query: dict[str, str], day: str) -> tuple[int, object]:
        if not DAY_RE.fullmatch(day):
            return NOT_FOUND
        path = _inside(self.paths.reports / "daily", f"{day}.md")
        got = _read_text(path, LONG_TEXT_CAP) if path is not None else None
        if got is None:
            return NOT_FOUND
        text, truncated = got
        return 200, {"day": day, "text": LongText(text), "truncated": truncated}

    def detections(self, query: dict[str, str]) -> tuple[int, object]:
        base = self.paths.detections
        return 200, {kind: _list_names(base / kind, DETECTION_RE)
                     for kind in ("pending", "approved")}

    def detection(self, query: dict[str, str], kind: str, name: str) -> tuple[int, object]:
        if kind not in ("pending", "approved") or not DETECTION_RE.fullmatch(name):
            return NOT_FOUND
        path = _inside(self.paths.detections / kind, name)
        got = _read_text(path, LONG_TEXT_CAP) if path is not None else None
        if got is None:
            return NOT_FOUND
        text, truncated = got
        return 200, {"kind": kind, "name": name, "text": LongText(text), "truncated": truncated}

    def decoy(self, query: dict[str, str]) -> tuple[int, object]:
        p = self.paths
        try:
            overlay: Optional[dict] = load_overlay(p.overlay).model_dump(mode="json")
            overlay_error = None
        except (OSError, ValueError):
            overlay, overlay_error = None, "overlay file is not valid"
        tuner_runs = []
        for name in reversed(_list_names(p.reports / "tuner", TUNER_FILE_RE)[-TUNER_RECORDS:]):
            path = p.reports / "tuner" / name
            try:
                if path.stat().st_size > MAX_TUNER_FILE:
                    continue
            except OSError:
                continue
            data = _read_json(path, {})
            if data:
                tuner_runs.append({"file": name, "timestamp": data.get("timestamp"),
                                   "snapshot": data.get("snapshot"),
                                   "changes": data.get("changes") or [],
                                   "rejected": data.get("rejected") or [],
                                   "commit": data.get("commit")})
        state = load_source_state(p.source_state)
        entries = sorted((e.model_dump(mode="json") for e in state.entries.values()),
                         key=lambda e: e["updated_at"], reverse=True)
        return 200, {"overlay": overlay, "overlay_error": overlay_error,
                     "history": list(reversed(tuner_history(p.state / "tuner")))[:50],
                     "tuner_runs": tuner_runs, "source_state": paginate(entries, query)}

    def playbooks(self, query: dict[str, str]) -> tuple[int, object]:
        pbs, errors = load_playbooks(self.paths.playbooks)
        engine = self._engine()
        today = self.now().date().isoformat()
        counts = engine.counts if engine is not None and engine.day == today else {}
        items = [{"name": pb.name, "enabled": pb.enabled, "priority": pb.priority,
                  "description": pb.description, "cooldown_minutes": pb.cooldown_minutes,
                  "max_runs_per_day": pb.max_runs_per_day,
                  "runs_today": counts.get(pb.name, 0),
                  "when": pb.when.model_dump(mode="json", exclude_defaults=True),
                  "steps": [{"action": st.action, "tier": tier_of(st)} for st in pb.steps]}
                 for pb in pbs]
        cooldowns = sorted(({"key": k, "at": v} for k, v in
                            (engine.cooldowns.items() if engine is not None else [])),
                           key=lambda c: c["at"], reverse=True)
        return 200, {"playbooks": items, "errors": errors,
                     "engine": {"day": engine.day if engine is not None else None,
                                "counts": counts,
                                "notify_sent": engine.sent if engine is not None
                                and engine.day == today else {},
                                "cooldowns": paginate(cooldowns, query)}}

    def honeytokens(self, query: dict[str, str]) -> tuple[int, object]:
        reveal = query.get("reveal") or ""
        if reveal and not TOKEN_NAME_RE.fullmatch(reveal):
            raise _BadQuery
        registry = _read_json(self.paths.reports / "honeytokens.json", {})
        raw = registry.get("tokens") if isinstance(registry.get("tokens"), list) else []
        hits: Counter = Counter()
        for r in self._records.get().newest:
            hits.update(set(r.honeytokens))
        tokens = []
        for t in raw:
            if not isinstance(t, dict) or not isinstance(t.get("name"), str) \
                    or not isinstance(t.get("value"), str):
                continue
            planted = t.get("planted_in") if isinstance(t.get("planted_in"), list) else []
            tokens.append({"name": t["name"], "kind": str(t.get("kind", "")),
                           "planted_in": [str(x) for x in planted][:50],
                           "planted_for": t.get("planted_for"),
                           "legacy": t.get("legacy") is True,
                           "hits": hits.get(t["name"], 0), "value": t["value"]})
        if reveal:
            match = next((t for t in tokens if t["name"] == reveal), None)
            if match is None:
                return NOT_FOUND
            return 200, {"name": match["name"], "value": match["value"]}
        for t in tokens:
            t["value"] = _mask(t["value"])
        return 200, {"scenario": registry.get("scenario"), "tokens": paginate(tokens, query)}

    # -- decisions --

    def _connectors(self):
        """The ``Connectors`` object, built once (building sends nothing), or None."""
        with self._connectors_lock:
            if not self._connectors_built:
                self._connectors_built = True
                if self.connectors is not None:
                    try:
                        self._connectors_value = self.connectors()
                    except Exception:  # noqa: BLE001 - no connectors is a working state
                        log.exception("building connectors failed; connector actions are off")
            return self._connectors_value

    def _can_approve_here(self, approval: dict) -> bool:
        """Whether approving would run the action here rather than consume the approval: a
        connector action needs that connector enabled in this process."""
        if approval.get("status") != "pending":
            return False
        name = CONNECTOR_FOR.get(str(approval.get("action", "")))
        if name is None:
            return True
        conns = self._connectors()
        return conns is not None and bool(conns.enabled(name))

    def _decision_settings(self) -> Optional[RespondSettings]:
        if self.respond_settings is None:
            return self.settings
        try:
            return self.respond_settings()
        except ValueError as exc:
            log.error("refusing a console decision: %s", str(exc)[:200])
            return None

    def _by(self) -> str:
        """``ui:<operator>``; never from the request. ``respond`` sanitises it as for the CLI."""
        name = self.operator.strip()
        if not name:
            try:
                name = getpass.getuser()
            except (OSError, KeyError):   # a container user without a passwd entry
                name = "unknown"
        return "ui:" + name

    def _decide(self, aid: str, verb: str, body: dict) -> tuple[int, object]:
        if not APPROVAL_RE.fullmatch(aid):
            return NOT_FOUND
        path = self.paths.state / "approvals" / f"{aid}.json"
        if not path.is_file():
            return NOT_FOUND
        given = body.get("view_hash")
        if not isinstance(given, str) or not VIEW_HASH_RE.fullmatch(given):
            return BAD_VIEW_HASH
        settings = self._decision_settings()
        if settings is None:
            return BAD_SETTINGS
        # The same parse the queue route hashes (peek_queue reads the file as JSON). The
        # status and expiry are re-checked by respond under its lock; this only makes sure
        # the operator decided on what is on disk now.
        current = _read_json(path, {})
        if not hmac.compare_digest(view_hash(current).encode(), given.encode()):
            return CHANGED
        state, reports = self.paths.state, self.paths.reports
        try:
            if verb == "reject":
                result = reject(aid, state, by=self._by(),
                                suppress_hours=settings.reject_suppress_hours,
                                reports_dir=reports)
            else:
                conns = self._connectors()
                needed = CONNECTOR_FOR.get(str(current.get("action", "")))
                if needed is not None and (conns is None or not conns.enabled(needed)):
                    # approve would mark it executing and then failed: refuse, keep it pending.
                    return NO_CONNECTOR
                result = approve(aid, state, reports, self.paths.detections, connectors=conns,
                                 by=self._by(), blocklist_file=settings.blocklist_file,
                                 blocklist_format=settings.blocklist_format,
                                 blocklist_ttl_days=settings.blocklist_ttl_days,
                                 expired_suppress_hours=settings.expired_suppress_hours,
                                 never_act_on=settings.never_act_on)
        except ApprovalError as exc:
            # Fixed text from respond: the validated id and status / expiry read from disk.
            return 400, {"error": clean_text(str(exc), ERROR_CAP)}
        finally:
            self._queue.invalidate()
        return 200, {"approval": result}

    def _unblock(self, body: dict) -> tuple[int, object]:
        raw = body.get("target")
        if not isinstance(raw, str) or len(raw) > MAX_TARGET:
            return BAD_TARGET
        value = raw.strip()
        if "%" in value:   # scoped IPv6 addresses are never blocklist keys
            return BAD_TARGET
        try:
            target = str(ipaddress.ip_network(value, strict=False)) if "/" in value \
                else str(ipaddress.ip_address(value))
        except ValueError:
            return BAD_TARGET
        settings = self._decision_settings()
        if settings is None:
            return BAD_SETTINGS
        try:
            result = unblock(target, self.paths.state, self.paths.reports,
                             blocklist_file=settings.blocklist_file,
                             blocklist_format=settings.blocklist_format,
                             ttl_days=settings.blocklist_ttl_days, by=self._by())
        except ValueError:
            return BAD_TARGET
        return 200, result
