"""Raw activity for the operator console: every event-log line, any service, filterable.

``EventIndex`` tails the event log with ``logindex.LogTail`` (the same rotation checks and
per-refresh read cap as the session index) and keeps one small entry per line: byte
offset, length, time, source, service, a normalised event kind, session id, username and
success flag (the strings cut at ``SRC_CAP``, ``SESSION_CAP`` and ``USER_CAP``, and
interned). The entry count is capped (oldest dropped first) and a fresh index starts at
the last ``tail_bytes`` of the log, so memory stays bounded on a large log and the screen
can say when older lines exist outside the window. Nothing is written.

Structured filters run on the entries alone. What a line sent and what the honeypot
answered are read back from disk only for the lines shown, or, for a free-text search,
for candidate lines, under one byte budget per request (``READ_BUDGET``); a request that
runs out of budget returns what it read and a cursor to continue from. Cursors are byte
offsets and only mean something for the log they came from, so every snapshot carries a
``log_id`` that changes when the index is rebuilt (rotation, truncation) or the process
restarts.

Normalised kinds (one filter for every service):
connection, login, input, reply, request, transfer, register, call, error, close, other.

SSH lines carry no ``event``; they are told apart by ``message``, with the typed input and
the decoy's reply in base64 ``details`` (decoded here as ``sessions`` decodes them).
Listener lines carry ``event`` and per-service ``data``. Only what the line holds is
shown: where a service logs a status or result code and not the reply itself, that is
what is shown, and no reply is made up.

Everything read here was written by attackers. It is data; the API's ``scrub`` cleans and
caps every string before it is served.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Callable, Optional

from agents import sessions
from agents.ui.logindex import MAX_BYTES_PER_REFRESH, MAX_LINE_BYTES, LogTail

DEFAULT_MAX_ENTRIES = 200_000
# The most ``[ui] activity_entries`` accepts. Measured worst case (every entry with its own
# source, session id and username, each at its cap): about 0.55 KiB an entry, so about
# 115 MiB of process memory at the default and 275 MiB at this maximum
# (``tests/test_ui_activity.py`` checks the per-entry size).
MAX_ENTRIES = 500_000
MIN_ENTRIES = 1_000
# A fresh index starts this far from the end of the log (and catches up in one refresh).
DEFAULT_TAIL_BYTES = MAX_BYTES_PER_REFRESH
# Bytes of log lines one request reads back (a page, a search, a session view or a
# record's replies) before it stops and says so (a free-text search hands back a cursor).
READ_BUDGET = 16 * 1024 * 1024
PAGE_SIZE = 100
MAX_PAGE_SIZE = 200
SESSION_EVENTS = 2_000
TOP_SOURCES = 10
TOP_SERVICES = 50
# Distinct keys a facet counter holds before it drops its least counted half.
FACET_KEYS = 4_096
SUMMARY_CAP = 200
FIELD_CAP = 512
SESSION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
# Per-entry string caps: the longest IPv6 text form, a session id well past the sensor's
# own (``session-`` and 32 hex digits, or ``<service>-<n>``), and a username.
SRC_CAP = 46
SESSION_CAP = 64
USER_CAP = 64
SERVICE_RE = re.compile(r"[a-z0-9]{1,16}")

KINDS = ("connection", "login", "input", "reply", "request", "transfer", "register", "call",
         "error", "close", "other")

# Entry fields (a tuple per line keeps the index small).
OFF, LEN, TS, SRC, SERVICE, KIND, SESSION, USER, OK = range(9)

SSH_KINDS = {
    "SSH connection received": "connection",
    "Authentication success": "login",
    "Authentication failed": "login",
    "User input": "input",
    "LLM response": "reply",
    "SSH connection closed": "close",
    "Session timeout": "close",
    "SSH connection error": "error",
    "Budget exceeded": "error",
}
EVENT_KINDS = {"connection": "connection", "auth_attempt": "login", "close": "close",
               "error": "error", "limit": "error", "register": "register", "invite": "call",
               "options": "request"}
REQUEST_SERVICES = {"http", "s3", "sip"}
S3_TRANSFERS = {"GetObject", "PutObject", "PostObject", "UploadPart", "UploadPartCopy",
                "CopyObject", "CompleteMultipartUpload"}
SQL_SERVICES = {"postgres", "mysql", "mssql"}


def _same(text: str) -> str:
    return text


def _cap(value, limit: int = FIELD_CAP, mask: Callable[[str], str] = _same) -> Optional[str]:
    """``value`` as text, masked whole and only then cut (a value cut first could keep part
    of a honeytoken that straddles the cut)."""
    if value is None:
        return None
    return mask(value if isinstance(value, str) else str(value))[:limit]


def _ts(value) -> Optional[float]:
    dt = sessions._ts(value)
    if dt is None:
        return None
    try:
        return dt.timestamp()
    except (OverflowError, OSError, ValueError):
        return None


def classify(rec: dict) -> tuple:
    """(ts, src, service, kind, session, username, success) of one parsed line."""
    service = rec.get("sensor_protocol")
    service = service.lower()[:16] if isinstance(service, str) else ""
    if not SERVICE_RE.fullmatch(service):
        service = "unknown"
    data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
    message = rec.get("message")
    success = rec.get("success") if isinstance(rec.get("success"), bool) else None
    if service == sessions.SSH_PROTOCOL and "event" not in rec:
        kind = SSH_KINDS.get(message, "other") if isinstance(message, str) else "other"
        if kind == "login":
            success = message == "Authentication success"
    else:
        event = rec.get("event")
        kind = EVENT_KINDS.get(event, "") if isinstance(event, str) else ""
        if not kind:
            kind = _command_kind(service, message, data) if event == "command" else "other"
        if kind not in ("login", "register"):
            success = None
    task = rec.get("task_name")
    session = task[:SESSION_CAP] if isinstance(task, str) and task not in ("", "-") else None
    src = rec.get("src_ip")
    src = src[:SRC_CAP] if isinstance(src, str) and src not in ("", "-") else None
    user = rec.get("username")
    user = user[:USER_CAP] if isinstance(user, str) and user else None
    return _ts(rec.get("timestamp")), src, service, kind, session, user, success


def _command_kind(service: str, message, data: dict) -> str:
    text = message if isinstance(message, str) else ""
    if service == "ftp" and text.startswith(("FTP download", "FTP upload")):
        return "transfer"
    if service == "smtp" and text.startswith("SMTP message accepted"):
        return "transfer"
    if service == "s3" and (data.get("operation") in S3_TRANSFERS
                            or text.startswith("S3 upload")):
        return "transfer"
    if service in REQUEST_SERVICES:
        return "request"
    return "input"


# ---- what a line sent and what was answered ------------------------------------------------

def _sql_result(value) -> Optional[str]:
    if not isinstance(value, str):
        return None
    head, _, tail = value.partition(":")
    if head == "rows":
        return f"{tail} rows returned"
    if head == "ok":
        return f"ok, {tail} rows affected"
    if head == "error":
        return f"error {tail}"
    return value


def _join(*parts) -> Optional[str]:
    out = [p for p in parts if isinstance(p, str) and p]
    return " ".join(out) if out else None


def describe(rec: dict, service: str, kind: str, cap: int,
             mask: Callable[[str], str] = _same) -> dict:
    """``sent``, ``answered`` and ``result`` (each None when the line has none), plus the
    password of a login line. Every text is passed whole through ``mask`` and then cut, at
    ``2 * cap`` for the long fields (the caller flags anything over ``cap`` as truncated,
    as the transcript does)."""
    limit = cap * 2

    def c(value, n: int = FIELD_CAP) -> Optional[str]:
        return _cap(value, n, mask)

    data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
    message = c(rec.get("message"), 300)
    sent = answered = result = None
    if service == sessions.SSH_PROTOCOL and "event" not in rec:
        if kind == "input":
            sent = c(sessions._b64(rec.get("details")), limit)
        elif kind == "reply":
            answered = c(sessions._b64(rec.get("details")), limit)
        elif kind in ("error", "close") and rec.get("reason") is not None:
            result = c(rec.get("reason"), 200)
    elif kind == "close":
        if "bytes_read" in data or "commands" in data:
            result = f"{c(data.get('bytes_read'), 20)} bytes read, " \
                     f"{c(data.get('commands'), 20)} commands"
    elif kind == "error":
        result = c(data.get("reason"), 200)
    elif service == "http":
        target = c(data.get("path"), limit) or ""
        query = c(data.get("query"), limit)
        sent = _join(c(data.get("method"), 16), target + ("?" + query if query else ""))
        body = c(data.get("body"), limit)
        if sent and body:
            sent = f"{sent}\n\n{body}"
        if data.get("status") is not None:
            result = f"HTTP {c(data.get('status'), 8)}"
    elif service == "s3":
        target = c(data.get("path"), limit) or ""
        query = c(data.get("query"), limit)
        sent = _join(c(data.get("method"), 16), target + ("?" + query if query else ""))
        if data.get("status") is not None:
            result = _join(c(data.get("operation"), 64), f"HTTP {c(data.get('status'), 8)}")
    elif service == "sip":
        sent = _join(message, c(data.get("dialed"), 64))
        if data.get("stage") is not None:
            result = f"stage: {c(data.get('stage'), 32)}"
    elif "capture_label" in data:
        parts = [data[k] for k in sorted(data) if k.startswith("part_")
                 and isinstance(data[k], str)]
        sent = c("".join(parts), limit) or None
    elif service == "ftp" and kind == "transfer":
        size = data.get("size")
        result = _join(message, c(data.get("path"), 500),
                       f"({c(size, 20)} bytes)" if size is not None else None)
    elif service == "smtp" and kind == "transfer":
        result = f"message accepted: {c(data.get('size'), 20)} bytes to " \
                 f"{c(data.get('rcpt_count'), 8)} recipients"
    else:
        for key in ("input", "statement", "text", "copy", "command"):
            value = data.get(key)
            if isinstance(value, str) and value:
                sent = c(value, limit)
                break
        if service == "telnet" and isinstance(data.get("response"), str):
            answered = c(data["response"], limit)
        if service in SQL_SERVICES:
            result = _sql_result(c(data.get("result"), 200))
    out = {"message": message, "sent": sent, "answered": answered, "result": result}
    if kind == "login":
        password = rec.get("password")
        out["password"] = c(password) if password is not None else None
    return out


def summary(kind: str, user: Optional[str], success: Optional[bool], details: dict) -> str:
    if kind == "login":
        verdict = "accepted" if success else "refused" if success is False else ""
        return _join("login", user or "(no username)", verdict) or "login"
    for key in ("sent", "answered", "result", "message"):
        value = details.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().split("\n", 1)[0][:SUMMARY_CAP]
    return kind


# ---- the index -----------------------------------------------------------------------------

class EventIndex(LogTail):
    """One small entry per event-log line, newest last. Thread-safe."""

    def __init__(self, path: Optional[os.PathLike | str], max_entries: int = DEFAULT_MAX_ENTRIES,
                 min_interval: float = 2.0, max_bytes_per_refresh: int = MAX_BYTES_PER_REFRESH,
                 clock: Callable[[], float] = time.monotonic,
                 tail_bytes: Optional[int] = DEFAULT_TAIL_BYTES) -> None:
        super().__init__(path, min_interval, max_bytes_per_refresh, clock, tail_bytes)
        self.max_entries = max(1, int(max_entries))
        self._entries: list[tuple] = []
        self._strings: dict[str, str] = {}
        self.dropped = 0
        self.generation = 0
        # Offsets handed out as cursors are only meaningful for one log as indexed: a
        # cursor carries ``log_id`` (this process's nonce and the rebuild count), and one
        # from another process or from before a rotation or truncation is refused.
        self._nonce = secrets.token_hex(4)

    def _clear(self) -> None:
        self._entries = []
        self._strings = {}
        self.dropped = 0
        self.generation += 1

    def _intern(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if len(self._strings) > 100_000:
            self._strings = {}
        return self._strings.setdefault(value, value)

    def _consume(self, start: int, end: int, rec: Optional[dict]) -> None:
        if not rec:   # blank or malformed: not an event
            return
        ts, src, service, kind, session, user, success = classify(rec)
        it = self._intern
        self._entries.append((start, end - start, ts, it(src), it(service), it(kind),
                              it(session), it(user), success))
        over = len(self._entries) - self.max_entries
        if over > 0:
            # Dropped in batches so a steady stream does not shift the list every line.
            batch = max(over, self.max_entries // 20)
            del self._entries[:batch]
            self.dropped += batch
        self.generation += 1

    # -- queries --

    def snapshot(self) -> tuple[list[tuple], dict]:
        """The entries (a list that is only appended to or replaced, never edited in place
        once handed out) and the window's state."""
        self.refresh()
        with self._lock:
            entries = list(self._entries)
            info = {"entries": len(entries), "max_entries": self.max_entries,
                    "older_outside": self.start_offset > 0 or self.dropped > 0,
                    "dropped": self.dropped, "caught_up": self.caught_up,
                    "generation": (self.rebuilds, self.generation),
                    "log_id": f"{self._nonce}.{self.rebuilds}"}
        return entries, info


def read_cost(entry: tuple) -> int:
    """Bytes ``read_line`` reads for ``entry`` (none for a line too long to read)."""
    return 0 if entry[LEN] > MAX_LINE_BYTES + 1 else entry[LEN]


def read_line(f, entry: tuple) -> Optional[dict]:
    """The parsed line of ``entry`` read back from the open log, or None when it is no
    longer there whole (rotated, truncated) or too long to read."""
    if entry[LEN] > MAX_LINE_BYTES + 1:
        return None
    f.seek(entry[OFF])
    raw = f.read(entry[LEN])
    if len(raw) != entry[LEN] or not raw.endswith(b"\n"):
        return None
    try:
        rec = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return None
    return rec if isinstance(rec, dict) else None


# ---- filters -------------------------------------------------------------------------------

class Filters:
    """Structured filters over entries. Built from already-validated values."""

    def __init__(self, since: Optional[float] = None, until: Optional[float] = None,
                 src: Optional[str] = None, service: Optional[str] = None,
                 kind: Optional[str] = None, outcome: Optional[str] = None,
                 username: Optional[str] = None, session: Optional[str] = None) -> None:
        self.since, self.until = since, until
        self.service, self.kind, self.username, self.session = service, kind, username, session
        self.success = None if outcome is None else outcome == "success"
        self.network = None
        self.src = None
        if src:
            if "/" in src:
                self.network = ipaddress.ip_network(src, strict=False)
            else:
                self.src = src
        self._in_network: dict[str, bool] = {}

    def _source(self, src: Optional[str]) -> bool:
        if self.src is not None:
            return src == self.src
        if src is None:
            return False
        hit = self._in_network.get(src)
        if hit is None:
            try:
                hit = ipaddress.ip_address(src) in self.network
            except ValueError:
                hit = False
            if len(self._in_network) < 100_000:
                self._in_network[src] = hit
        return hit

    def match(self, e: tuple) -> bool:
        if self.since is not None and (e[TS] is None or e[TS] < self.since):
            return False
        if self.until is not None and (e[TS] is None or e[TS] > self.until):
            return False
        if self.service is not None and e[SERVICE] != self.service:
            return False
        if self.kind is not None and e[KIND] != self.kind:
            return False
        if self.success is not None and e[OK] is not self.success:
            return False
        if self.username is not None and e[USER] != self.username:
            return False
        if self.session is not None and e[SESSION] != self.session:
            return False
        if (self.src is not None or self.network is not None) and not self._source(e[SRC]):
            return False
        return True


def before_index(entries: list[tuple], before: Optional[int]) -> int:
    """Index of the first entry at or after byte offset ``before`` (len when None)."""
    if before is None:
        return len(entries)
    return bisect.bisect_left(entries, before, key=lambda e: e[OFF])


class TopCounter:
    """Counts keys in at most ``cap`` counters. When full, the least counted half is
    dropped (``pruned`` says so), so attacker-chosen values cannot grow it without limit
    and keys seen often (real services, busy sources) stay. Counts of a key that was
    dropped and seen again are low by what was dropped."""

    def __init__(self, cap: int = FACET_KEYS) -> None:
        self.cap = max(2, cap)
        self.counts: dict[str, int] = {}
        self.pruned = False

    def add(self, key: str) -> None:
        counts = self.counts
        n = counts.get(key)
        if n is not None:
            counts[key] = n + 1
            return
        if len(counts) >= self.cap:
            keep = sorted(counts.items(), key=lambda kv: -kv[1])[:self.cap // 2]
            self.counts = counts = dict(keep)
            self.pruned = True
        counts[key] = 1

    def top(self, n: int) -> list[tuple[str, int]]:
        return sorted(self.counts.items(), key=lambda kv: (-kv[1], kv[0]))[:n]


def facets(entries: list[tuple], cap: int = FACET_KEYS) -> dict:
    """Services, event kinds and sources in the window, each the most counted first and
    capped (``TOP_SERVICES``, every kind, ``TOP_SOURCES``)."""
    services, kinds, sources = TopCounter(cap), TopCounter(cap), TopCounter(cap)
    for e in entries:
        services.add(e[SERVICE])
        kinds.add(e[KIND])
        if e[SRC] is not None:
            sources.add(e[SRC])
    return {"services": dict(services.top(TOP_SERVICES)),
            "kinds": dict(kinds.top(len(KINDS))),
            "top_sources": [{"src": s, "events": n} for s, n in sources.top(TOP_SOURCES)],
            "approximate": services.pruned or kinds.pruned or sources.pruned}


def open_log(path: Optional[Path]):
    """The log opened for reading, or None."""
    if path is None:
        return None
    try:
        return open(path, "rb")
    except OSError:
        return None
