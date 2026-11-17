"""In-memory index of SSH sessions in the event log, for transcript replay in the console.

No transcript is stored anywhere: an SSH session's turns exist only as base64 ``details``
on its event-log lines. The index maps each ``session-*`` task name to the byte range that
holds its lines (first line start, last line end). It is extended from the last offset on
each refresh and rebuilt when the log is rotated or truncated, detected as
``sessions.Cursor`` does (inode, a hash of the first line, size below the offset, no
newline just before the offset). It never writes anything: no cursor file, no lock file.

Replay reads only a session's range and runs it through ``sessions.parse_log``, so the
turns shown are exactly what triage saw. Memory is capped (the most recently active
``max_sessions`` sessions are kept) and so is the work done by one refresh.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Callable, Optional

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


class RangeTooLarge(Exception):
    """The session's lines span more of the log than ``MAX_RANGE_BYTES``."""


def _head(f) -> Optional[str]:
    f.seek(0)
    first = f.readline(HEAD_BYTES)
    return hashlib.sha256(first).hexdigest() if first else None


def _session_task(rec: Optional[dict]) -> Optional[str]:
    """The task name of an SSH session line, cut as ``parse_log`` cuts it; else None."""
    if not rec:
        return None
    if sessions._cap(rec.get("sensor_protocol", ""), 16).lower() != sessions.SSH_PROTOCOL:
        return None
    task = rec.get("task_name")
    if not isinstance(task, str) or not task.startswith("session-"):
        return None
    return sessions._cap(task, 128)


class SessionIndex:
    """Session id -> (start, end) byte range in the event log. Thread-safe."""

    def __init__(self, path: Optional[os.PathLike | str], max_sessions: int = DEFAULT_MAX_SESSIONS,
                 min_interval: float = 2.0, max_bytes_per_refresh: int = MAX_BYTES_PER_REFRESH,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.path = Path(path) if path else None
        self.max_sessions = max(1, int(max_sessions))
        self.min_interval = min_interval
        self.max_bytes_per_refresh = max(1, int(max_bytes_per_refresh))
        self.clock = clock
        self._lock = threading.Lock()
        self._ranges: OrderedDict[str, list[int]] = OrderedDict()
        self._offset = 0
        self._identity: Optional[tuple[int, int]] = None
        self._head: Optional[str] = None
        self._checked = float("-inf")
        self.rebuilds = 0
        self.caught_up = True

    # -- maintenance --

    def _reset(self) -> None:
        self._ranges.clear()
        self._offset = 0
        self._identity = None
        self._head = None
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
            if self._ranges or self._offset:
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
        self._identity, self._head = identity, head
        if st.st_size <= self._offset:
            self.caught_up = True
            return
        limit = self._offset + self.max_bytes_per_refresh
        offset = self._offset
        self.caught_up = True  # unless the loop stops at the limit; a partial line waits
        for start, end, rec in sessions.iter_records(self.path, self._offset):
            if start >= limit:
                self.caught_up = False
                break
            offset = end
            task = _session_task(rec)
            if task is None:
                continue
            span = self._ranges.get(task)
            if span is None:
                self._ranges[task] = [start, end]
                if len(self._ranges) > self.max_sessions:
                    self._ranges.popitem(last=False)
            else:
                span[1] = end
                self._ranges.move_to_end(task)
        self._offset = offset

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

    def transcript(self, sid: str) -> Optional[dict]:
        """Auth attempts and turns of one session, or None when the index has no lines for
        it. Raises ``RangeTooLarge``."""
        span = self.range_of(sid)
        if span is None or self.path is None:
            return None
        start, end = span
        if end - start > MAX_RANGE_BYTES:
            raise RangeTooLarge(sid)
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
                    "auth_attempts": [_auth(a) for a in auth], "turns": []}
        return {"id": sid, "src_ip": s.src_ip,
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
