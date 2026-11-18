"""Data API for the operator console (the ``Routes`` object ``server`` calls).

Everything returned here was typed by attackers or derived from it. The rules:

- GET never writes. Only loaders that are pure reads are called (``peek_blocklist``,
  ``DailyCallCounter.peek``, ``EngineState``'s constructor, ...); files without such a
  loader (approvals, tuner runs) are read directly. No lock file, directory, cursor or
  counter is created.
- Ids before paths. A request path component reaches the filesystem only after matching a
  strict pattern, and the final path must resolve inside its base directory. Record ids
  are looked up in the parsed record set and never become a path. Anything else is a 404.
- One sanitising boundary. ``Api.get`` passes its whole answer through ``scrub``, which
  removes control, format and other invisible characters from every string, drops any key
  that cleaning would change, and caps string, list and dict sizes, so a field added later
  cannot skip it.
- What is shown is what is acted on. An approval is served as a projection of named fields
  read by exact key, and is decidable here only when every value the engine acts on is
  already in its exact, clean form (``undecidable_reason``).
- Missing or corrupt data is normal: a fresh deployment answers with empty lists.
- Bounded work: the record set and the queue are cached and re-read only when a cheap
  directory signature changes; the event log is indexed incrementally (``logindex``).
- Errors are ``{"error": <fixed text>}``; request input and exception text are never
  echoed.
- POST (approve, reject, unblock) runs only for a signed-in operator with ``[ui] actions``
  on (the shell checks that). It calls ``respond.approve`` / ``reject`` / ``unblock`` with
  the arguments the CLI passes, so every gate stays in one place. A decision names the
  ``view_hash`` the operator saw (the raw approval, what the card showed and, for
  ``publish_detection``, the files it names); any difference now is a 409 and nothing
  changes.
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
import stat
import sys
import threading
import time
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from pydantic import ValidationError

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
    reject,
    size_alarm,
    unblock,
)
from agents.runtime import event_log_state
from agents.source_state import load as load_source_state
from agents.source_state import valid_source_key
from agents.triage import JUDGEMENT_RANK, Judgement, TriageRecord, rank
from agents.tuner import history as tuner_history
from agents.ui import logindex
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
# Size caps of the response boundary: a hostile file cannot make any route's body unbounded.
LIST_CAP = 2_000
DICT_CAP = 500


def _strip_pattern() -> re.Pattern:
    """Characters that make text render other than it reads, or not at all: every C0
    control except \\t and \\n, DEL, C1 controls, every format character (category Cf:
    bidi marks and overrides, zero-width characters, soft hyphen, tag characters, ...),
    the line and paragraph separators, variation selectors, the whole tag block and the
    Hangul fillers that render as blank space. Built from ``unicodedata`` once at import
    (about 1.1M lookups, a few tens of milliseconds)."""
    points = set(range(0x00, 0x09)) | set(range(0x0B, 0x20)) | set(range(0x7F, 0xA0))
    points |= {c for c in range(sys.maxunicode + 1) if unicodedata.category(chr(c)) == "Cf"}
    points |= {0x2028, 0x2029, 0x115F, 0x1160, 0x3164, 0xFFA0}
    points |= set(range(0x180B, 0x1810))      # Mongolian free variation selectors
    points |= set(range(0xFE00, 0xFE10))      # variation selectors 1-16
    points |= set(range(0xE0100, 0xE01F0))    # variation selectors 17-256
    points |= set(range(0xE0000, 0xE0080))    # tag block, unassigned code points included
    ranges, start, prev = [], None, None
    for c in sorted(points):
        if start is None:
            start = prev = c
        elif c == prev + 1:
            prev = c
        else:
            ranges.append((start, prev))
            start = prev = c
    ranges.append((start, prev))
    body = "".join(f"\\U{a:08x}" if a == b else f"\\U{a:08x}-\\U{b:08x}" for a, b in ranges)
    return re.compile(f"[{body}]")


_STRIP_RE = _strip_pattern()
# The record id shape triage.write_record produces (its _safe_filename alphabet).
RECORD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}")
DAY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
DETECTION_RE = re.compile(DETECTION_FILE_RE)
TOKEN_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
PROTOCOL_RE = re.compile(r"[a-z0-9]{1,16}")
TUNER_FILE_RE = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{6}\.json")
APPROVAL_RE = re.compile(APPROVAL_ID_RE)
APPROVAL_FILE_RE = re.compile(APPROVAL_ID_RE + r"\.json")
RECORD_FILE_RE = re.compile(r"[^.].*\.json")   # what triage.load_records globs (*.json)
VIEW_HASH_RE = re.compile(r"[0-9a-f]{64}")
DECIDE_RE = re.compile(r"queue/([^/]+)/(approve|reject)")
MAX_TARGET = 64
ERROR_CAP = 200
# Approved actions that send through a connector, and the connector each one needs.
CONNECTOR_FOR = {"open_ticket": "ticket", "block_webhook": "block_webhook"}
# Actions respond.approve executes, and the params keys each one reads.
PARAMS_USED: dict[str, tuple[str, ...]] = {"export_blocklist": (), "publish_detection": ("files",),
                                           "open_ticket": ("priority",), "block_webhook": ()}
TICKET_PRIORITIES = ("low", "medium", "high")
MAX_DETECTION_FILES = 50
# Approval fields served, each read by exact key from the file as parsed.
APPROVAL_FIELDS = ("id", "status", "action", "tier", "playbook", "record_id", "subject",
                   "unverified_source", "created_at", "expires_at", "summary", "approved_by",
                   "approved_at", "rejected_by", "rejected_at", "expired_at")
RESULT_FIELDS = ("ok", "status", "files", "entries")
# Stand-in digest of a detection file named by an approval that is not in pending/.
MISSING_FILE = "missing"

NOT_FOUND = (404, {"error": "not found"})
BAD_QUERY = (400, {"error": "bad query"})
CHANGED = (409, {"error": "changed"})
BAD_VIEW_HASH = (400, {"error": "view_hash must be the 64-character hex value from the queue"})
BAD_TARGET = (400, {"error": "target must be an IP address or network"})
NO_CONNECTOR = (400, {"error": "connector not available here; approve with the CLI in the "
                               "agents container"})
BAD_SETTINGS = (500, {"error": "[respond] settings are invalid; nothing was changed (see the "
                               "server log)"})
UNDECIDABLE = (400, {"error": "this item cannot be decided in the console; nothing was "
                              "changed. Decide it with the CLI (python -m agents approve or "
                              "reject <id>) after checking the file"})
# Why an approval is not decidable here (fixed texts; never built from the file).
WHY_ID = "its id does not match its file name"
WHY_ACTION = "its action is not one the engine runs"
WHY_SUBJECT = "its target is not an address or /64 in the exact form the engine acts on"
WHY_PLAYBOOK = "its playbook name is missing or contains hidden characters"
WHY_PARAMS = "its parameters are not in the exact form the engine acts on"
WHY_EXPIRY = "its expiry time is missing or malformed"
WHY_FILES = "a detection file it names is not a regular file inside detections/pending"
WHY_UNREADABLE = "the file cannot be read in full"


# ---- sanitising boundary -------------------------------------------------------------------

class LongText(str):
    """A string allowed the long cap (a digest or detection file)."""


def clean_text(value: str, cap: int = TEXT_CAP) -> str:
    """Invisible and control characters removed (``\\n`` and ``\\t`` kept), then capped.
    The input is cut first so a huge string costs no more than a capped one."""
    return _STRIP_RE.sub("", value[:cap * 2])[:cap]


class _Scrubber:
    """One pass of ``scrub``; ``cut`` records whether anything was dropped or capped."""

    def __init__(self) -> None:
        self.cut = False

    def __call__(self, value: object, depth: int = 0) -> object:
        if depth > MAX_DEPTH:
            self.cut = True
            return None
        if value is None or isinstance(value, bool) or isinstance(value, int):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        if isinstance(value, str):
            return clean_text(value, LONG_TEXT_CAP if isinstance(value, LongText) else TEXT_CAP)
        if isinstance(value, dict):
            return self._dict(value, depth)
        if isinstance(value, (list, tuple)):
            if len(value) > LIST_CAP:
                self.cut = True
            return [self(v, depth + 1) for v in value[:LIST_CAP]]
        return clean_text(str(value))

    def _dict(self, value: dict, depth: int) -> dict:
        # A key that cleaning would change is dropped, never renamed: renaming could make
        # "subject‎" replace "subject", so the page would show one value while the
        # engine reads the other. Dropping also means no two keys can become one.
        out: dict = {}
        for k, v in value.items():
            if len(out) >= DICT_CAP:
                self.cut = True
                break
            key = k if isinstance(k, str) else str(k)
            if key in out or clean_text(key, KEY_CAP) != key:
                self.cut = True
                continue
            out[key] = self(v, depth + 1)
        return out


def scrub_flagged(value: object) -> tuple[object, bool]:
    """``scrub`` and whether it dropped a key or cut a list, dict or nesting level."""
    s = _Scrubber()
    out = s(value)
    return out, s.cut


def scrub(value: object) -> object:
    """The response boundary: every string cleaned and capped, numbers made JSON-safe, any
    other type turned into cleaned text, keys that cleaning would change dropped, lists
    and dicts capped (``LIST_CAP``, ``DICT_CAP``). Applied to the whole answer, so no field
    can skip it."""
    return _Scrubber()(value)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      default=str)


def view_hash(raw: dict, approval: dict, record: Optional[dict],
              files: Optional[dict[str, str]] = None) -> str:
    """SHA-256 over what a decision depends on: the approval as parsed from disk, the
    approval and record summary as served (after ``scrub``) and, for ``publish_detection``,
    the SHA-256 of each named pending file. The approve and reject calls send it back, so a
    decision is only made on what the operator saw. Raises ValueError or RecursionError
    when ``raw`` cannot be serialised (such an item is not decidable here)."""
    text = _canonical({"raw": raw, "approval": approval, "record": record,
                       "files": files or {}})
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def project_approval(raw: dict) -> dict:
    """The served approval: named fields read by exact key, never the whole object, so a
    look-alike key cannot stand in for one the engine reads. Only the params the action
    uses are served (all of them are what it acts on)."""
    out = {k: raw[k] for k in APPROVAL_FIELDS if k in raw}
    params = raw.get("params")
    if isinstance(params, dict):
        used = PARAMS_USED.get(raw.get("action"), ()) if isinstance(raw.get("action"), str) \
            else ()
        out["params"] = {k: params[k] for k in used if k in params}
    result = raw.get("result")
    if isinstance(result, dict):
        out["result"] = {k: result[k] for k in RESULT_FIELDS if k in result}
    return out


def _clean_same(value: object, cap: int = TEXT_CAP) -> bool:
    """A string that the response boundary would serve unchanged."""
    return isinstance(value, str) and clean_text(value, cap) == value


def _exact_source_key(value: object) -> bool:
    """``value`` is a source key (IPv4 address or IPv6 /64) in the exact canonical text
    ``ip_key`` writes, so the target shown is byte for byte the target acted on."""
    if not isinstance(value, str) or not _clean_same(value, MAX_TARGET) \
            or not valid_source_key(value):
        return False
    try:
        canon = str(ipaddress.ip_network(value, strict=True)) if "/" in value \
            else str(ipaddress.ip_address(value))
    except ValueError:
        return False
    return canon == value


def undecidable_reason(stem: str, raw: dict) -> Optional[str]:
    """None when every value ``respond.approve`` / ``reject`` act on is in its exact clean
    form, so the card shows what would be acted on; else a fixed reason. ``stem`` is the
    file name without ``.json``: the id a decision is sent to."""
    aid = raw.get("id")
    if not isinstance(aid, str) or aid != stem or not APPROVAL_RE.fullmatch(aid):
        return WHY_ID
    action = raw.get("action")
    if not isinstance(action, str) or action not in PARAMS_USED:
        return WHY_ACTION
    if not _exact_source_key(raw.get("subject")):
        return WHY_SUBJECT
    playbook = raw.get("playbook")
    if not _clean_same(playbook, KEY_CAP) or not playbook:
        return WHY_PLAYBOOK
    if _parse_ts(raw.get("expires_at")) is None:
        return WHY_EXPIRY
    params = raw.get("params", {})
    if not isinstance(params, dict):
        return WHY_PARAMS
    if action == "publish_detection":
        files = params.get("files")
        if not isinstance(files, list) or not 0 < len(files) <= MAX_DETECTION_FILES \
                or not all(isinstance(n, str) and DETECTION_RE.fullmatch(n) for n in files):
            return WHY_PARAMS
    if action == "open_ticket" and params.get("priority", "medium") not in TICKET_PRIORITIES:
        return WHY_PARAMS
    return None


def _file_digest(base: Path, name: str) -> Optional[str]:
    """SHA-256 of ``base/name`` read in chunks, ``MISSING_FILE`` when it does not exist,
    or None when it is not a regular file directly inside ``base`` (a symlink out, a
    directory): the engine would move such an entry without the console seeing it."""
    path = _inside(base, name)
    if path is None:
        return None
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return MISSING_FILE
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


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
    except (OSError, ValueError, RecursionError):
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


@dataclass(frozen=True)
class _Approval:
    """One approval file: its name without ``.json`` (the id a decision is sent to, already
    matching ``APPROVAL_ID_RE``) and its content as parsed."""

    stem: str
    raw: dict

    def status_at(self, now: datetime.datetime) -> object:
        """The status, with an overdue pending item judged expired (as ``peek_queue``)."""
        status = self.raw.get("status")
        if status == "pending":
            expires = _parse_ts(self.raw.get("expires_at"))
            if expires is not None and expires <= now:
                return "expired"
        return status


@dataclass(frozen=True)
class _View:
    shown: dict                      # the served approval projection (status as on disk)
    record: Optional[dict]           # the served record summary, or None
    reason: Optional[str]            # why it is not decidable here, or None
    files: dict[str, str]            # publish_detection: name -> SHA-256 or MISSING_FILE
    digest: Optional[str]            # the view_hash, when decidable


def _bounded(value: object) -> object:
    """``scrub``, with ``"truncated": true`` added to a dict answer when a list, dict or
    nesting level was cut or a key dropped (as routes flag a cut string)."""
    out, cut = scrub_flagged(value)
    if cut and isinstance(out, dict):
        out["truncated"] = True
    return out


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


MASK = "......"
MASK_PREFIX_MIN = 8   # shorter values show nothing: two characters would be most of them


def _mask(value: str) -> str:
    """A honeytoken value hidden: its first two characters only when it is long enough
    that they give little away, otherwise nothing at all."""
    return value[:2] + MASK if len(value) >= MASK_PREFIX_MIN else MASK


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
        return status, _bounded(value)

    def post(self, path: str, body: dict) -> tuple[int, object]:
        status, value = self._dispatch_post(path, body)
        return status, _bounded(value)

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
        records = []
        # triage.load_records' files, each kept inside its directory as the digest and
        # detection routes are (a symlink out of reports/sessions is not followed).
        for sub in ("sessions", "campaigns"):
            base = self.paths.reports / sub
            for name in _list_names(base, RECORD_FILE_RE):
                path = _inside(base, name)
                try:
                    if path is None or path.stat().st_size > MAX_JSON_FILE:
                        continue
                    records.append(TriageRecord.model_validate_json(
                        path.read_text(encoding="utf-8")))
                except (OSError, ValidationError, ValueError, RecursionError):
                    log.warning("skipping invalid record %s", name[:80])
        stamps = {r.id: _stamp(r) for r in records}
        floor = datetime.datetime.min.replace(tzinfo=UTC)
        newest = sorted(records, key=lambda r: stamps[r.id] or floor, reverse=True)
        return _Records(newest=newest, ranked=rank(records), by_id={r.id: r for r in records},
                        stamps=stamps)

    def _load_queue(self) -> list[_Approval]:
        """Every approval file, as ``peek_queue`` lists them (a pure read; a file without a
        parseable ``expires_at`` is skipped), keeping each file's name for decisions."""
        adir = self.paths.state / "approvals"
        items = []
        for name in _list_names(adir, APPROVAL_FILE_RE):
            raw = _read_json(adir / name, {})
            if _parse_ts(raw.get("expires_at")) is not None:
                items.append(_Approval(name[:-len(".json")], raw))
        return sorted(items, key=lambda a: str(a.raw.get("created_at", "")), reverse=True)

    def _queue_now(self) -> list[_Approval]:
        """The cached queue; callers judge expiry at request time (``status_at``): the cache
        only reloads when the directory changes, and an item can pass its expiry without
        any file changing."""
        return self._queue.get()

    def _view(self, item: _Approval, by_id: dict[str, TriageRecord]) -> _View:
        """What the queue serves for ``item`` and its ``view_hash``, from the file as it is
        on disk. The queue route and a decision both call this, so they hash alike."""
        raw = item.raw
        shown = scrub(project_approval(raw))
        rid = raw.get("record_id")
        r = by_id.get(rid) if isinstance(rid, str) else None
        record = scrub(_summary(r)) if r is not None else None
        reason = undecidable_reason(item.stem, raw)
        files = self._detection_files(raw) if reason is None else {}
        if files is None:
            reason, files = WHY_FILES, {}
        digest = None
        if reason is None:
            try:
                digest = view_hash(raw, shown, record, files)
            except (ValueError, TypeError, RecursionError):
                reason = WHY_UNREADABLE
        return _View(shown, record, reason, files, digest)

    def _card(self, item: _Approval, now: datetime.datetime,
              by_id: dict[str, TriageRecord]) -> dict:
        """One queue entry: the served approval, the record summary shown beside it, the
        detection files it names, and a ``view_hash`` when it can be decided here now."""
        v = self._view(item, by_id)
        status = item.status_at(now)
        # Only an untouched pending item can be decided; one past its expiry is shown as
        # expired (it is still pending on disk, and respond would refuse it).
        decidable = v.reason is None and status == "pending"
        out = {"id": item.stem, "approval": {**v.shown, "status": scrub(status)},
               "view_hash": v.digest if decidable else None,
               "can_decide_here": decidable,
               "can_approve_here": decidable and self._connector_ready(item.raw),
               "undecidable_reason": v.reason,
               "record": v.record}
        if item.raw.get("action") == "publish_detection" and v.reason is None:
            out["detection_files"] = [{"name": n, "present": d != MISSING_FILE}
                                      for n, d in v.files.items()]
        return out

    def _detection_files(self, raw: dict) -> Optional[dict[str, str]]:
        """{name: SHA-256 or MISSING_FILE} for the pending files a ``publish_detection``
        approval names ({} for other actions), or None when one is not a regular file
        inside detections/pending. Names were checked by ``undecidable_reason``."""
        if raw.get("action") != "publish_detection":
            return {}
        out = {}
        for name in raw["params"]["files"]:
            digest = _file_digest(self.paths.detections / "pending", name)
            if digest is None:
                return None
            out[name] = digest
        return out

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
        pending = [a.raw for a in self._queue_now() if a.status_at(now) == "pending"]
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
            except (ValueError, RecursionError):
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
        approvals = [a.stem for a in self._queue_now() if a.raw.get("record_id") == r.id]
        out = {"record": r.model_dump(mode="json"), "approvals": approvals,
               "transcript_available": False, "transcript_withheld": None}
        span = self.index.range_of(r.id) if r.kind == "session" and r.protocol == "ssh" \
            else None
        if span is not None and span[1] - span[0] > logindex.MAX_RANGE_BYTES:
            # Said up front, rather than offering a transcript that then answers 422. The id
            # matched RECORD_ID_RE, so it is safe to quote in the command.
            out["transcript_withheld"] = (
                f"This session's lines span more than "
                f"{logindex.MAX_RANGE_BYTES // (1024 * 1024)} MiB of the event log, so the "
                f"console does not replay it. Read it on the host with: "
                f"grep -F '\"{r.id}\"' <event log>")
        else:
            out["transcript_available"] = span is not None
        return 200, out

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
        now = self.now()
        items = self._queue_now()
        if everything == "0":
            items = [a for a in items if a.status_at(now) == "pending"]
        page = paginate(items, query)
        by_id = self._records.get().by_id
        page["items"] = [self._card(a, now, by_id) for a in page["items"]]
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
            path = _inside(p.reports / "tuner", name)   # no symlink out of the directory
            try:
                if path is None or path.stat().st_size > MAX_TUNER_FILE:
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

    def _connector_ready(self, approval: dict) -> bool:
        """Whether approving would run the action here rather than consume the approval: a
        connector action needs that connector enabled in this process."""
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
        current = self.view_of(aid)
        if current.reason is not None:
            # Approve and reject alike: reject also acts on the raw subject, playbook and
            # action (its suppression key), so it could be misdirected the same way.
            return UNDECIDABLE
        if current.digest is None or \
                not hmac.compare_digest(current.digest.encode(), given.encode()):
            return CHANGED
        state, reports = self.paths.state, self.paths.reports
        try:
            if verb == "reject":
                result = reject(aid, state, by=self._by(),
                                suppress_hours=settings.reject_suppress_hours,
                                reports_dir=reports)
            else:
                conns = self._connectors()
                needed = CONNECTOR_FOR.get(str(current.shown.get("action", "")))
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
        return 200, {"approval": project_approval(result) if isinstance(result, dict) else None}

    def view_of(self, aid: str) -> _View:
        """The view of approval ``aid`` as the queue would serve it now, read fresh from disk
        (the record set's signature is re-checked first, so a record re-triaged since the
        page loaded changes the hash). ``aid`` must already match ``APPROVAL_ID_RE``. The
        status and expiry are re-checked by respond under its lock; this makes sure the
        operator decided on what is on disk now."""
        raw = _read_json(self.paths.state / "approvals" / f"{aid}.json", {})
        self._records.invalidate()
        return self._view(_Approval(aid, raw), self._records.get().by_id)

    # One fixed answer for every refused unblock: the console removes single listed entries,
    # and a range (which can empty the whole list in one click) is a CLI decision.
    UNBLOCK_REFUSED = (400, {"error": "target must be one blocklist entry exactly as listed; "
                                      "unblock a range with the CLI (python -m agents unblock)"})

    def _unblock(self, body: dict) -> tuple[int, object]:
        """Remove exactly one listed entry. ``target`` must parse (``ipaddress``) to a value
        equal to an existing key; covering networks such as 0.0.0.0/0 are refused here."""
        raw = body.get("target")
        if not isinstance(raw, str) or len(raw) > MAX_TARGET:
            return self.UNBLOCK_REFUSED
        wanted = self._unblock_network(raw.strip())
        if wanted is None:
            return self.UNBLOCK_REFUSED
        settings = self._decision_settings()
        if settings is None:
            return BAD_SETTINGS
        entries = peek_blocklist(self.paths.state, self.now(), settings.blocklist_ttl_days)
        key = next((k for k in entries if self._unblock_network(k) == wanted), None)
        if key is None:
            return self.UNBLOCK_REFUSED
        try:
            # respond.unblock also removes entries inside the given network; keys are single
            # addresses or IPv6 /64s, so for an exact key that is only the key itself.
            result = unblock(key, self.paths.state, self.paths.reports,
                             blocklist_file=settings.blocklist_file,
                             blocklist_format=settings.blocklist_format,
                             ttl_days=settings.blocklist_ttl_days, by=self._by())
        except ValueError:
            return self.UNBLOCK_REFUSED
        return 200, result

    @staticmethod
    def _unblock_network(value: str):
        """``value`` as an ``ip_network`` (an address is its /32 or /128), or None. Host bits
        set under a prefix are refused rather than masked, so 198.51.100.7/24 is no key."""
        if "%" in value:   # scoped IPv6 addresses are never blocklist keys
            return None
        try:
            return ipaddress.ip_network(value, strict=True)
        except ValueError:
            return None
