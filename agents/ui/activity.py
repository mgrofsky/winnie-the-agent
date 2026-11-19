"""Raw activity for the operator console: every event-log line, any service, filterable.

``EventIndex`` tails the event log with ``logindex.LogTail`` (the same rotation checks and
per-refresh read cap as the session index) and keeps one small entry per line: byte
offset, length, time, source, service, a normalised event kind, session id, username and
success flag. The entry count is capped (oldest dropped first) and a fresh index starts at
the last ``tail_bytes`` of the log, so memory stays bounded on a large log and the screen
can say when older lines exist outside the window. Nothing is written.

Structured filters run on the entries alone. What a line sent and what the honeypot
answered are read back from disk only for the lines shown, or, for a free-text search,
for candidate lines under a byte budget per request; a search that runs out of budget
returns a cursor to continue from and the time it searched back to.

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
import time
from pathlib import Path
from typing import Callable, Optional

from agents import sessions
from agents.ui.logindex import MAX_BYTES_PER_REFRESH, MAX_LINE_BYTES, LogTail

DEFAULT_MAX_ENTRIES = 200_000
# A fresh index starts this far from the end of the log (and catches up in one refresh).
DEFAULT_TAIL_BYTES = MAX_BYTES_PER_REFRESH
# Bytes of log lines a free-text search reads per request before it hands back a cursor.
SEARCH_BUDGET = 16 * 1024 * 1024
PAGE_SIZE = 100
MAX_PAGE_SIZE = 200
SESSION_EVENTS = 2_000
TOP_SOURCES = 10
SUMMARY_CAP = 200
FIELD_CAP = 512
SESSION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
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


def _cap(value, limit: int = FIELD_CAP) -> Optional[str]:
    if value is None:
        return None
    return (value if isinstance(value, str) else str(value))[:limit]


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
    session = task[:128] if isinstance(task, str) and task not in ("", "-") else None
    src = rec.get("src_ip")
    src = src[:64] if isinstance(src, str) and src not in ("", "-") else None
    user = rec.get("username")
    user = user[:64] if isinstance(user, str) and user else None
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


def describe(rec: dict, service: str, kind: str, cap: int) -> dict:
    """``sent``, ``answered`` and ``result`` (each None when the line has none), plus the
    password of a login line. Text fields are cut at ``2 * cap`` here (the caller flags
    anything over ``cap`` as truncated, as the transcript does)."""
    limit = cap * 2
    data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
    message = _cap(rec.get("message"), 300)
    sent = answered = result = None
    if service == sessions.SSH_PROTOCOL and "event" not in rec:
        if kind == "input":
            sent = sessions._b64(rec.get("details"))[:limit]
        elif kind == "reply":
            answered = sessions._b64(rec.get("details"))[:limit]
        elif kind in ("error", "close") and rec.get("reason") is not None:
            result = _cap(rec.get("reason"), 200)
    elif kind == "close":
        if "bytes_read" in data or "commands" in data:
            result = f"{_cap(data.get('bytes_read'), 20)} bytes read, " \
                     f"{_cap(data.get('commands'), 20)} commands"
    elif kind == "error":
        result = _cap(data.get("reason"), 200)
    elif service == "http":
        target = _cap(data.get("path"), limit) or ""
        query = _cap(data.get("query"), limit)
        sent = _join(_cap(data.get("method"), 16), target + ("?" + query if query else ""))
        body = _cap(data.get("body"), limit)
        if sent and body:
            sent = f"{sent}\n\n{body}"
        if data.get("status") is not None:
            result = f"HTTP {_cap(data.get('status'), 8)}"
    elif service == "s3":
        target = _cap(data.get("path"), limit) or ""
        query = _cap(data.get("query"), limit)
        sent = _join(_cap(data.get("method"), 16), target + ("?" + query if query else ""))
        if data.get("status") is not None:
            result = _join(_cap(data.get("operation"), 64),
                           f"HTTP {_cap(data.get('status'), 8)}")
    elif service == "sip":
        sent = _join(message, _cap(data.get("dialed"), 64))
        if data.get("stage") is not None:
            result = f"stage: {_cap(data.get('stage'), 32)}"
    elif "capture_label" in data:
        parts = [data[k] for k in sorted(data) if k.startswith("part_")
                 and isinstance(data[k], str)]
        sent = "".join(parts)[:limit] or None
    elif service == "ftp" and kind == "transfer":
        path = _cap(data.get("path"), 500)
        size = data.get("size")
        result = _join(message, path, f"({_cap(size, 20)} bytes)" if size is not None else None)
    elif service == "smtp" and kind == "transfer":
        result = f"message accepted: {_cap(data.get('size'), 20)} bytes to " \
                 f"{_cap(data.get('rcpt_count'), 8)} recipients"
    else:
        for key in ("input", "statement", "text", "copy", "command"):
            value = data.get(key)
            if isinstance(value, str) and value:
                sent = value[:limit]
                break
        if service == "telnet" and isinstance(data.get("response"), str):
            answered = data["response"][:limit]
        if service in SQL_SERVICES:
            result = _sql_result(data.get("result"))
    out = {"message": message, "sent": sent, "answered": answered, "result": result}
    if kind == "login":
        password = rec.get("password")
        out["password"] = _cap(password, FIELD_CAP) if password is not None else None
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
                    "generation": (self.rebuilds, self.generation)}
        return entries, info


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


def facets(entries: list[tuple]) -> dict:
    services: dict[str, int] = {}
    kinds: dict[str, int] = {}
    sources: dict[str, int] = {}
    for e in entries:
        services[e[SERVICE]] = services.get(e[SERVICE], 0) + 1
        kinds[e[KIND]] = kinds.get(e[KIND], 0) + 1
        if e[SRC] is not None:
            sources[e[SRC]] = sources.get(e[SRC], 0) + 1
    top = sorted(sources.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_SOURCES]
    return {"services": dict(sorted(services.items())),
            "kinds": {k: kinds[k] for k in KINDS if k in kinds},
            "top_sources": [{"src": s, "events": n} for s, n in top]}


def open_log(path: Optional[Path]):
    """The log opened for reading, or None."""
    if path is None:
        return None
    try:
        return open(path, "rb")
    except OSError:
        return None
