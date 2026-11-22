"""In-memory indexes of the event log for the console: ``LogTail`` (incremental tailing,
shared with ``activity.EventIndex``) and ``SessionIndex`` (SSH sessions, for transcript
replay).

No transcript is stored anywhere: an SSH session's turns exist only as base64 ``details``
on its event-log lines. The index maps each ``session-*`` task name to the byte range that
holds its lines (first line start, last line end). It is extended from the last offset on
each refresh and rebuilt when the log is rotated or truncated, detected as
``sessions.Cursor`` does (inode, a hash of the first line, size below the offset, no
newline just before the offset). It never writes anything: no cursor file, no lock file.

Replay reads only a session's range and runs it through ``sessions.parse_log``, so the
turns shown are exactly what triage saw. Memory is capped (the most recently active
``max_sessions`` sessions are kept) and so is the work done by one refresh. Lines are read
with a length limit (``MAX_LINE_BYTES``): a longer line is skipped in chunks, never held
whole, and like a malformed line it is passed over with the offset moving past it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Callable, Iterator, Optional

from agents import sessions

log = logging.getLogger(__name__)

DEFAULT_MAX_SESSIONS = 20_000
# One refresh reads at most this much new log; a backlog is caught up over later refreshes,
# so no single request waits on a full read of a large log.
MAX_BYTES_PER_REFRESH = 64 * 1024 * 1024
# A session whose lines are spread over more than this is not replayed (the range would
# be read whole, interleaved with every other connection of that period).
MAX_RANGE_BYTES = 32 * 1024 * 1024
HEAD_BYTES = sessions.Cursor.HEAD_BYTES
# A log line longer than this (newline excluded) is skipped by the index without being
# read into memory whole. Real event-log lines are a few KiB at most.
MAX_LINE_BYTES = 1024 * 1024
SKIP_CHUNK = 64 * 1024


class RangeTooLarge(Exception):
    """The session's lines span more of the log than ``MAX_RANGE_BYTES``."""


def _parse_line(raw: bytes) -> Optional[dict]:
    """A line as ``sessions.iter_records`` parses it: {} when blank, None when malformed
    (bad JSON, nesting too deep for the parser, not an object)."""
    if not raw.strip():
        return {}
    try:
        obj = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return None
    return obj if isinstance(obj, dict) else None


def iter_lines(path: os.PathLike | str, start_offset: int = 0,
               max_line: Optional[int] = None) -> Iterator[tuple[int, int, Optional[dict]]]:
    """Yield (start, end, record) for complete lines from ``start_offset``, as
    ``sessions.iter_records`` does, except that a line longer than ``max_line`` (default
    ``MAX_LINE_BYTES``) is read past in ``SKIP_CHUNK`` pieces and yielded as malformed
    (None). A trailing partial line (still being written) is not consumed."""
    limit = MAX_LINE_BYTES if max_line is None else max_line
    with open(path, "rb") as f:
        f.seek(start_offset)
        pos = start_offset
        while True:
            raw = f.readline(limit + 1)
            if not raw:
                return
            start, pos = pos, pos + len(raw)
            if raw.endswith(b"\n"):
                yield start, pos, _parse_line(raw)
                continue
            if len(raw) <= limit:
                return   # a partial last line: wait for the rest
            del raw
            while True:
                chunk = f.readline(SKIP_CHUNK)
                if not chunk:
                    return   # an oversize line still being written: not consumed yet
                pos += len(chunk)
                if chunk.endswith(b"\n"):
                    break
            yield start, pos, None


def _head(f) -> Optional[str]:
    f.seek(0)
    first = f.readline(HEAD_BYTES)
    return hashlib.sha256(first).hexdigest() if first else None


def _session_task(rec: Optional[dict]) -> Optional[str]:
    """The task name of an SSH session line, cut as ``parse_log`` cuts it; else None."""
    if not rec:
        return None
    # parse_log compares str(value)[:16]; no non-string JSON value prints as "ssh", so
    # only strings need the comparison (and a large nested value is never printed).
    protocol = rec.get("sensor_protocol")
    if not isinstance(protocol, str) or protocol[:16].lower() != sessions.SSH_PROTOCOL:
        return None
    task = rec.get("task_name")
    if not isinstance(task, str) or not task.startswith("session-"):
        return None
    return sessions._cap(task, 128)


class LogTail:
    """Incremental, read-only tailing of the event log, shared by the console's indexes.

    Each refresh reads complete lines from the last offset (at most
    ``max_bytes_per_refresh`` of them) and hands each to ``_consume``. Rotation or
    truncation (new inode, a different first line, a size below the offset, or no newline
    just before the offset) resets the index through ``_clear`` and starts again. With
    ``tail_bytes``, a fresh index starts at the first line inside the last ``tail_bytes``
    of the log instead of at its start (``start_offset`` says where). Nothing is written.
    Subclasses hold ``_lock`` while reading their own state."""

    def __init__(self, path: Optional[os.PathLike | str], min_interval: float = 2.0,
                 max_bytes_per_refresh: int = MAX_BYTES_PER_REFRESH,
                 clock: Callable[[], float] = time.monotonic,
                 tail_bytes: Optional[int] = None) -> None:
        self.path = Path(path) if path else None
        self.min_interval = min_interval
        self.max_bytes_per_refresh = max(1, int(max_bytes_per_refresh))
        self.clock = clock
        self.tail_bytes = None if tail_bytes is None else max(0, int(tail_bytes))
        self._lock = threading.Lock()
        self._offset = 0
        self._identity: Optional[tuple[int, int]] = None
        self._head: Optional[str] = None
        self._checked = float("-inf")
        self.start_offset = 0
        self.rebuilds = 0
        self.caught_up = True

    # -- for subclasses --

    def _clear(self) -> None:
        raise NotImplementedError

    def _consume(self, start: int, end: int, rec: Optional[dict]) -> None:
        raise NotImplementedError

    # -- maintenance --

    def _reset(self) -> None:
        self._clear()
        self._offset = 0
        self._identity = None
        self._head = None
        self.start_offset = 0
        self.rebuilds += 1

    def refresh(self, force: bool = False) -> None:
        """Read new complete lines (rate-limited unless ``force``)."""
        if self.path is None:
            return
        with self._lock:
            now = self.clock()
            if not force and now - self._checked < self.min_interval:
                return
            self._checked = now
            try:
                self._refresh_locked()
            except OSError as exc:
                log.warning("event log index: cannot read the log (%s)",
                            exc.strerror or type(exc).__name__)

    def _refresh_locked(self) -> None:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            if self._offset:
                self._reset()
            self.caught_up = True
            return
        identity = (st.st_dev, st.st_ino)
        with open(self.path, "rb") as f:
            head = _head(f)
            stale = self._offset > 0 and (identity != self._identity or st.st_size < self._offset
                                          or head != self._head)
            if not stale and self._offset > 0:
                f.seek(self._offset - 1)
                stale = f.read(1) != b"\n"
            if stale:
                self._reset()
            if self._offset == 0 and self.tail_bytes is not None \
                    and st.st_size > self.tail_bytes:
                self._offset = self.start_offset = _line_start(f, st.st_size - self.tail_bytes)
        self._identity, self._head = identity, head
        if st.st_size <= self._offset:
            self.caught_up = True
            return
        limit = self._offset + self.max_bytes_per_refresh
        offset = self._offset
        self.caught_up = True  # unless the loop stops at the limit; a partial line waits
        for start, end, rec in iter_lines(self.path, self._offset):
            if start >= limit:
                self.caught_up = False
                break
            offset = end
            self._consume(start, end, rec)
        self._offset = offset


def _line_start(f, pos: int) -> int:
    """The start of the first line at or after ``pos``: ``pos`` itself when a newline is
    just before it, else just past the next newline (read past in chunks)."""
    if pos <= 0:
        return 0
    f.seek(pos - 1)
    if f.read(1) == b"\n":
        return pos
    while True:
        chunk = f.readline(SKIP_CHUNK)
        if not chunk:
            return pos
        pos += len(chunk)
        if chunk.endswith(b"\n"):
            return pos


class SessionIndex(LogTail):
    """Session id -> (start, end) byte range in the event log. Thread-safe."""

    def __init__(self, path: Optional[os.PathLike | str], max_sessions: int = DEFAULT_MAX_SESSIONS,
                 min_interval: float = 2.0, max_bytes_per_refresh: int = MAX_BYTES_PER_REFRESH,
                 clock: Callable[[], float] = time.monotonic) -> None:
        super().__init__(path, min_interval, max_bytes_per_refresh, clock)
        self.max_sessions = max(1, int(max_sessions))
        self._ranges: OrderedDict[str, list[int]] = OrderedDict()

    def _clear(self) -> None:
        self._ranges.clear()

    def _consume(self, start: int, end: int, rec: Optional[dict]) -> None:
        task = _session_task(rec)
        if task is None:
            return
        span = self._ranges.get(task)
        if span is None:
            self._ranges[task] = [start, end]
            if len(self._ranges) > self.max_sessions:
                self._ranges.popitem(last=False)
        else:
            span[1] = end
            self._ranges.move_to_end(task)

    # -- queries --

    def range_of(self, sid: str) -> Optional[tuple[int, int]]:
        self.refresh()
        with self._lock:
            span = self._ranges.get(sid)
            return (span[0], span[1]) if span else None

    def stats(self) -> dict:
        with self._lock:
            return {"sessions": len(self._ranges), "offset": self._offset,
                    "caught_up": self.caught_up, "rebuilds": self.rebuilds}

    def transcript(self, sid: str, max_bytes: Optional[int] = None) -> Optional[dict]:
        """Auth attempts and turns of one session, or None when the index has no lines for
        it. Raises ``RangeTooLarge``. With ``max_bytes``, only the lines that start in the
        first ``max_bytes`` of the range are read, and ``cut`` says whether that left any
        out; ``read_bytes`` is the length of the range read."""
        span = self.range_of(sid)
        if span is None or self.path is None:
            return None
        start, end = span
        if end - start > MAX_RANGE_BYTES:
            raise RangeTooLarge(sid)
        cut = max_bytes is not None and end - start > max_bytes
        if cut:
            end = start + max(1, max_bytes)
        try:
            parsed = sessions.parse_log(self.path, start_offset=start, end_offset=end)
        except OSError:
            return None
        s = parsed.sessions.get(sid)
        if s is None:
            # A finished login-only connection is folded into its campaign by parse_log;
            # its authentication attempts are still kept per task.
            auth = [a for _, a in parsed.ssh_auth.get(sid, [])]
            if not auth:
                return None  # the range no longer holds this session (rotated meanwhile)
            return {"id": sid, "src_ip": None, "start": None, "end": None, "closed": True,
                    "username": next((a.username for a in auth if a.success), None),
                    "auth_attempts": [_auth(a) for a in auth], "turns": [], "cut": cut,
                    "read_bytes": end - start}
        return {"id": sid, "cut": cut, "read_bytes": end - start, "src_ip": s.src_ip,
                "start": s.start.isoformat() if s.start else None,
                "end": s.end.isoformat() if s.end else None, "closed": s.closed,
                "username": s.username, "auth_attempts": [_auth(a) for a in s.auth_attempts],
                "turns": [{"ts": t.ts if isinstance(t.ts, str) else None, "role": t.role,
                           "text": t.text,
                           "interactive": t.interactive if isinstance(t.interactive, bool)
                           else None} for t in s.turns]}


def _auth(a: sessions.AuthAttempt) -> dict:
    return {"ts": a.ts if isinstance(a.ts, str) else None, "username": a.username,
            "password": a.password, "success": a.success}
