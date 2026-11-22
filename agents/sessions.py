"""Parse the JSON-lines honeypot log into SSH sessions and trap-protocol campaigns.

- SSH connections where the attacker typed at least one command become a ``Session``
  (per-session LLM triage).
- Everything else (listener events for sip/ftp/telnet/postgres/..., and SSH connections
  that never got past login) is aggregated into a ``Campaign``: one per source IP, per
  protocol, per time window. Brute forcers make thousands of connections; they must
  not become thousands of LLM calls.

Every value read here is attacker-controlled. It is length-capped on the way in and is
only ever treated as data.

Progress is tracked by a high-water mark (``Cursor``): the byte offset before which every
item has been handled, plus a small set of handled items that extend past it. Each run
reads only from that offset, so the log is never re-read from the start.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import errno
import hashlib
import json
import os
import re
import stat
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from agents.budget import ip_key

MAX_FIELD = 512
MAX_COMMAND = 4096
MAX_COMMANDS_KEPT = 500
MAX_POST_LOGIN_KEPT = 200
MAX_DISTINCT = 1_000              # distinct keys per campaign counter (usernames, dialed, ...)
MAX_CONNECTIONS_KEPT = 10_000     # connection ids kept per campaign; the rest are only counted
MAX_ADDRESSES_KEPT = 20           # individual source addresses kept per campaign (IPv6 /64)
# Campaigns per protocol and window for sources seen only over UDP and not verified (their
# addresses may be forged). Events of further such sources share one aggregate campaign.
MAX_UNVERIFIED_CAMPAIGNS = 1_000
UNVERIFIED_SOURCE = "unverified"
UTC = datetime.timezone.utc

SSH_PROTOCOL = "ssh"
TRAP_PROTOCOLS = {"sip", "ftp", "telnet", "postgres", "mysql", "mssql", "redis", "smtp",
                  "http", "mllp", "s3"}


def _cap(value, limit: int = MAX_FIELD) -> str:
    text = "" if value is None else str(value)
    return text[:limit]


def _ts(value) -> Optional[datetime.datetime]:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _b64(value) -> str:
    if not isinstance(value, str):
        return ""
    try:
        return base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return ""


@dataclass
class AuthAttempt:
    ts: Optional[str]
    username: str
    password: str
    success: Optional[bool]


@dataclass
class Turn:
    ts: Optional[str]
    role: str  # "input" | "response"
    text: str
    interactive: Optional[bool] = None


@dataclass
class Session:
    session_id: str
    protocol: str = SSH_PROTOCOL
    src_ip: str = "-"
    src_port: str = "-"
    sensor_name: str = "-"
    start: Optional[datetime.datetime] = None
    end: Optional[datetime.datetime] = None
    username: Optional[str] = None
    auth_attempts: list[AuthAttempt] = field(default_factory=list)
    turns: list[Turn] = field(default_factory=list)
    summary: Optional[str] = None
    judgement: Optional[str] = None
    closed: bool = False
    budget_events: list[str] = field(default_factory=list)
    first_offset: int = 0
    last_offset: int = 0

    @property
    def commands(self) -> list[str]:
        return [t.text for t in self.turns if t.role == "input"]

    @property
    def responses(self) -> list[str]:
        return [t.text for t in self.turns if t.role == "response"]

    def has_activity(self) -> bool:
        return any(t.role == "input" and t.text.strip() for t in self.turns)

    def is_finished(self, now: datetime.datetime, idle: datetime.timedelta) -> bool:
        return self.closed or (self.end is not None and now - self.end > idle)


@dataclass
class Campaign:
    campaign_id: str
    protocol: str
    src_ip: str
    window_start: datetime.datetime
    window_end: datetime.datetime
    first_seen: Optional[datetime.datetime] = None
    last_seen: Optional[datetime.datetime] = None
    connections: set = field(default_factory=set)
    attempts: int = 0
    successes: int = 0
    usernames: Counter = field(default_factory=Counter)
    passwords: Counter = field(default_factory=Counter)
    pairs: Counter = field(default_factory=Counter)
    clients: Counter = field(default_factory=Counter)
    sip_extensions: Counter = field(default_factory=Counter)
    dialed: Counter = field(default_factory=Counter)
    commands: list[str] = field(default_factory=list)
    post_login: list[str] = field(default_factory=list)
    high_signal: Counter = field(default_factory=Counter)
    honeytokens: set = field(default_factory=set)
    events: int = 0
    transports: set = field(default_factory=set)
    source_verified: bool = False       # TCP, or answered our SIP nonce over UDP
    first_offset: int = -1
    last_offset: int = 0
    extra_connections: int = 0          # connections counted but not kept in ``connections``
    # Individual addresses behind ``src_ip`` (an IPv6 /64 groups many): a sample and a count.
    addresses: set = field(default_factory=set)
    extra_addresses: int = 0

    def add_address(self, ip: str) -> None:
        if ip in self.addresses or ip in ("-", ""):
            return
        if len(self.addresses) < MAX_ADDRESSES_KEPT:
            self.addresses.add(ip)
        else:
            self.extra_addresses += 1

    @property
    def unverified_source(self) -> bool:
        """Seen only over UDP and never proved it can receive our packets (spoofable)."""
        return self.transports == {"udp"} and not self.source_verified

    def add_connection(self, task: str) -> None:
        if task in self.connections:
            return
        if len(self.connections) < MAX_CONNECTIONS_KEPT:
            self.connections.add(task)
        else:
            self.extra_connections += 1

    def connection_count(self) -> int:
        return len(self.connections) + self.extra_connections

    def span(self, start: int, end: int) -> None:
        if self.first_offset < 0 or start < self.first_offset:
            self.first_offset = start
        self.last_offset = max(self.last_offset, end)

    def is_finished(self, now: datetime.datetime, grace: datetime.timedelta) -> bool:
        return now > self.window_end + grace


@dataclass
class ParsedLog:
    sessions: dict[str, Session]
    campaigns: dict[str, Campaign]
    malformed: int = 0
    lines: int = 0
    ssh_auth: dict = field(default_factory=dict)
    start_offset: int = 0
    end_offset: int = 0
    window_minutes: int = 60
    # Sensor-level limit lines (no source address): inbound drops, suppression summaries.
    sensor_limits: list = field(default_factory=list)


def _window(ts: datetime.datetime, minutes: int) -> tuple[datetime.datetime, datetime.datetime]:
    epoch = int(ts.timestamp())
    size = minutes * 60
    start = epoch - epoch % size
    return (datetime.datetime.fromtimestamp(start, UTC),
            datetime.datetime.fromtimestamp(start + size, UTC))


def _safe_id_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", value)[:64] or "x"


def _campaign_id(protocol: str, ip: str, start: datetime.datetime) -> str:
    return f"campaign-{protocol}-{_safe_id_part(ip)}-{start.strftime('%Y%m%dT%H%M')}"


def unverified_campaign_id(protocol: str, window_start: datetime.datetime) -> str:
    """Id of the one aggregate campaign for unverified UDP sources in a window."""
    return _campaign_id(protocol, UNVERIFIED_SOURCE, window_start)


def _campaign_for(campaigns: dict[str, Campaign], protocol: str, ip: str,
                  ts: datetime.datetime, window_minutes: int,
                  unverified_counts: Optional[dict] = None) -> Campaign:
    """The campaign for (protocol, ip, window). With ``unverified_counts`` the event is from
    an unverified UDP source: once ``MAX_UNVERIFIED_CAMPAIGNS`` such campaigns exist for the
    window, a new source joins the window's aggregate campaign instead."""
    start, end = _window(ts, window_minutes)
    address, ip = ip, ip_key(ip)   # IPv6 sources group by /64, like every per-source control
    cid = _campaign_id(protocol, ip, start)
    camp = campaigns.get(cid)
    if camp is None and unverified_counts is not None:
        key = (protocol, start)
        if unverified_counts.get(key, 0) >= MAX_UNVERIFIED_CAMPAIGNS:
            ip, cid = UNVERIFIED_SOURCE, unverified_campaign_id(protocol, start)
            camp = campaigns.get(cid)
        else:
            unverified_counts[key] = unverified_counts.get(key, 0) + 1
    if camp is None:
        camp = Campaign(campaign_id=cid, protocol=protocol, src_ip=ip, window_start=start,
                        window_end=end)
        campaigns[cid] = camp
    camp.add_address(address)
    return camp


def _bump(counter: Counter, key, n: int = 1) -> None:
    """Count ``key``; a new key is added only while the counter is under ``MAX_DISTINCT``."""
    if key in counter or len(counter) < MAX_DISTINCT:
        counter[key] += n


def merge_campaign(into: Campaign, other: Campaign) -> None:
    """Add ``other``'s counts to ``into`` (same bounds as parsing)."""
    if other.first_seen and (into.first_seen is None or other.first_seen < into.first_seen):
        into.first_seen = other.first_seen
    if other.last_seen and (into.last_seen is None or other.last_seen > into.last_seen):
        into.last_seen = other.last_seen
    for task in other.connections:
        into.add_connection(task)
    into.extra_connections += other.extra_connections
    into.attempts += other.attempts
    into.successes += other.successes
    into.events += other.events
    for name in ("usernames", "passwords", "pairs", "clients", "sip_extensions", "dialed",
                 "high_signal"):
        mine = getattr(into, name)
        for key, n in getattr(other, name).items():
            _bump(mine, key, n)
    into.commands.extend(other.commands[:max(0, MAX_COMMANDS_KEPT - len(into.commands))])
    into.post_login.extend(other.post_login[:max(0, MAX_POST_LOGIN_KEPT - len(into.post_login))])
    into.honeytokens |= other.honeytokens
    for address in other.addresses:
        into.add_address(address)
    into.extra_addresses += other.extra_addresses
    into.transports |= other.transports
    into.source_verified = into.source_verified and other.source_verified
    if other.first_offset >= 0:
        into.span(other.first_offset, other.last_offset)


def _touch(camp: Campaign, ts: datetime.datetime) -> None:
    camp.events += 1
    if camp.first_seen is None or ts < camp.first_seen:
        camp.first_seen = ts
    if camp.last_seen is None or ts > camp.last_seen:
        camp.last_seen = ts


def iter_records(path: os.PathLike | str, start_offset: int = 0
                 ) -> Iterable[tuple[int, int, Optional[dict]]]:
    """Yield (start, end, record) for complete lines from ``start_offset``; record is None
    for malformed lines. A trailing partial line (still being written) is not consumed."""
    with open(path, "rb") as f:
        f.seek(start_offset)
        pos = start_offset
        for raw in f:
            start, pos = pos, pos + len(raw)
            if not raw.endswith(b"\n"):
                return
            if not raw.strip():
                yield start, pos, {}
                continue
            try:
                obj = json.loads(raw.decode("utf-8", errors="replace"))
            except (ValueError, RecursionError):
                yield start, pos, None
                continue
            yield start, pos, obj if isinstance(obj, dict) else None


def _fold_login_only(parsed: "ParsedLog", s: Session,
                     auth: list[tuple[datetime.datetime, AuthAttempt]]) -> None:
    """Move a finished SSH connection that never ran a command into its campaign."""
    camp = _campaign_for(parsed.campaigns, SSH_PROTOCOL, s.src_ip, s.start, parsed.window_minutes)
    _touch(camp, s.start)
    if s.end:
        _touch(camp, s.end)
    camp.add_connection(s.session_id)
    camp.transports.add("tcp")
    camp.source_verified = True
    camp.span(s.first_offset, s.last_offset)
    for _, a in auth:
        camp.attempts += 1
        _bump(camp.usernames, a.username)
        _bump(camp.passwords, a.password)
        _bump(camp.pairs, (a.username, a.password))
        if a.success:
            camp.successes += 1
    parsed.sessions.pop(s.session_id, None)


MAX_SENSOR_LIMITS = 10_000   # sensor-level limit lines kept per parse


def _sensor_limit(parsed: "ParsedLog", task: str, ts: datetime.datetime, protocol: str,
                  event, data: dict) -> None:
    count = data.get("dropped", data.get("count"))
    if event != "limit" or not isinstance(count, int) or isinstance(count, bool) or count <= 0:
        return
    if len(parsed.sensor_limits) >= MAX_SENSOR_LIMITS:
        return
    pool = data.get("pool")
    parsed.sensor_limits.append({
        "task": task, "day": ts.date().isoformat(), "protocol": protocol,
        "reason": _cap(data.get("reason", "limit"), 64),
        "pool": _cap(pool, 16) if isinstance(pool, str) else None, "count": count})


def parse_log(path: os.PathLike | str, window_minutes: int = 60,
              start_offset: int = 0, end_offset: Optional[int] = None) -> ParsedLog:
    """Parse complete lines from ``start_offset``; with ``end_offset``, only lines that
    start before it (the console replays one session's byte range this way)."""
    sessions: dict[str, Session] = {}
    campaigns: dict[str, Campaign] = {}
    ssh_auth: dict[str, list[tuple[datetime.datetime, AuthAttempt]]] = {}
    conn_success: set[str] = set()       # listener task_names with a successful login
    sip_registered: set[str] = set()     # src IPs with an accepted SIP registration
    unverified_counts: dict = {}         # (protocol, window) -> unverified UDP campaigns
    parsed = ParsedLog(sessions, campaigns, start_offset=start_offset,
                       end_offset=start_offset, window_minutes=window_minutes)

    for start, end, rec in iter_records(path, start_offset):
        if end_offset is not None and start >= end_offset:
            break
        parsed.end_offset = end
        if rec == {}:
            continue  # blank line
        parsed.lines += 1
        if rec is None:
            parsed.malformed += 1
            continue
        ts = _ts(rec.get("timestamp"))
        task = rec.get("task_name")
        protocol = _cap(rec.get("sensor_protocol", ""), 16).lower()
        if ts is None or not isinstance(task, str) or not task or task == "-":
            parsed.malformed += 1
            continue
        task = _cap(task, 128)
        ip = _cap(rec.get("src_ip", "-"), 64)

        if protocol == SSH_PROTOCOL:
            message = rec.get("message")
            if not task.startswith("session-"):
                continue
            s = sessions.get(task)
            if s is None:
                s = Session(session_id=task, src_ip=ip, src_port=_cap(rec.get("src_port"), 8),
                            sensor_name=_cap(rec.get("sensor_name"), 64), first_offset=start)
                sessions[task] = s
            s.last_offset = end
            if s.src_ip in ("-", "") and ip not in ("-", ""):
                s.src_ip = ip
            s.start = ts if s.start is None or ts < s.start else s.start
            s.end = ts if s.end is None or ts > s.end else s.end
            if message in ("User attempting to authenticate", "Authentication success",
                           "Authentication failed"):
                if message == "User attempting to authenticate":
                    continue
                attempt = AuthAttempt(ts=rec.get("timestamp"), username=_cap(rec.get("username")),
                                      password=_cap(rec.get("password")),
                                      success=message == "Authentication success")
                s.auth_attempts.append(attempt)
                ssh_auth.setdefault(task, []).append((ts, attempt))
                if attempt.success:
                    s.username = attempt.username
            elif message == "User input":
                s.turns.append(Turn(rec.get("timestamp"), "input",
                                    _b64(rec.get("details"))[:MAX_COMMAND],
                                    rec.get("interactive")))
            elif message == "LLM response":
                s.turns.append(Turn(rec.get("timestamp"), "response",
                                    _b64(rec.get("details"))[:MAX_COMMAND],
                                    rec.get("interactive")))
            elif message == "Session summary":
                s.summary = _cap(rec.get("details"), 4000)
                j = rec.get("judgement")
                s.judgement = j if j in ("BENIGN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN") else None
                s.closed = True
            elif message in ("SSH connection closed", "SSH connection error"):
                s.closed = True
            elif message == "Budget exceeded":
                s.budget_events.append(_cap(rec.get("reason"), 64))
            continue

        event = rec.get("event")
        data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
        if protocol in TRAP_PROTOCOLS and ip in ("-", ""):
            # Listener-wide lines belong to no campaign; their counts go to the digest.
            _sensor_limit(parsed, task, ts, protocol, event, data)
            continue
        if protocol not in TRAP_PROTOCOLS:
            continue
        transport = "udp" if rec.get("transport") == "udp" else "tcp"
        verifies = transport == "tcp" or data.get("nonce_verified") is True \
            or data.get("source_verified") is True
        camp = _campaign_for(campaigns, protocol, ip, ts, window_minutes,
                             None if verifies else unverified_counts)
        _touch(camp, ts)
        camp.span(start, end)
        camp.add_connection(task)
        camp.transports.add(transport)
        if verifies:
            camp.source_verified = True
        client = rec.get("client")
        if client:
            _bump(camp.clients, _cap(client, 200))
        if data.get("honeytoken"):
            camp.honeytokens.add(_cap(data.get("honeytoken"), 64))
        if data.get("high_signal") is True:
            _bump(camp.high_signal, _cap(data.get("signal", event), 64))
        username = rec.get("username")
        password = rec.get("password")
        if event == "auth_attempt":
            # Credentials are counted only from auth_attempt events (a SIP REGISTER with
            # Authorization also produces one), so nothing is double counted.
            user = _cap(username)
            pw = _cap(password) if password is not None else "<unknown>"
            camp.attempts += 1
            _bump(camp.usernames, user)
            _bump(camp.passwords, pw)
            _bump(camp.pairs, (user, pw))
            if protocol == "sip":
                _bump(camp.sip_extensions, user)
            if rec.get("success") is True:
                camp.successes += 1
                conn_success.add(task)
                if protocol == "sip":
                    sip_registered.add(ip)
        elif event == "invite":
            dialed = _cap(data.get("dialed", ""), 64)
            if dialed:
                _bump(camp.dialed, dialed)
            _bump(camp.high_signal, "sip_dialed_number")
            line = f"INVITE {dialed}"
            if len(camp.commands) < MAX_COMMANDS_KEPT:
                camp.commands.append(line)
            if (ip in sip_registered or data.get("registered") is True) \
                    and len(camp.post_login) < MAX_POST_LOGIN_KEPT:
                camp.post_login.append(line)
        elif event == "command":
            text = _cap(data.get("input") or data.get("command") or data.get("path")
                        or rec.get("message"), MAX_COMMAND)
            if len(camp.commands) < MAX_COMMANDS_KEPT:
                camp.commands.append(text)
            if task in conn_success and len(camp.post_login) < MAX_POST_LOGIN_KEPT:
                camp.post_login.append(text)

    # Closed SSH connections that never ran a command are login-only: fold them into
    # campaigns. Open ones stay sessions until they finish (see ``pending``).
    parsed.ssh_auth = ssh_auth
    for sid, s in list(sessions.items()):
        if not s.has_activity() and s.start is not None and s.closed:
            _fold_login_only(parsed, s, ssh_auth.get(sid, []))
    return parsed


# ---- cursor ------------------------------------------------------------------------------

TAIL_BYTES = 4096            # content fingerprint window ending at a boundary
MAX_PARTIAL_BYTES = 1 << 20  # longest unfinished last line a sample will look back over


class NotRegularFile(OSError):
    """The log path names something other than a regular file (directory, pipe, device)."""


@dataclass(frozen=True)
class LogSample:
    """What one open and one ``fstat`` of the log showed, all from the same descriptor.

    ``end`` is the offset just past the last newline: only bytes before it are complete
    lines. ``tails`` maps each requested offset, ``end`` and a few checkpoints spread over
    the file to a hash of the (at most 4096) bytes before it, or None when the offset is past
    ``end``: bytes that already exist never change in an append-only log, so the same offsets
    hash the same later. ``mtime_ns`` is the modification time to the nanosecond: a rewrite
    that leaves the size unchanged moves it. ``generation`` is an opaque id of this log file
    (its inode and first-line hash)."""
    inode: int
    size: int
    head: Optional[str]
    end: int
    tails: dict
    mtime_ns: int = 0

    @property
    def generation(self) -> str:
        return log_generation(self.inode, self.head)


def log_generation(inode: Optional[int], head: Optional[str]) -> str:
    return hashlib.sha256(f"{inode}:{head or ''}".encode()).hexdigest()[:16]


def sample_log(path: os.PathLike | str, offsets: Iterable[int] = ()) -> LogSample:
    """Sample the log through a single descriptor. Raises ``FileNotFoundError`` when it is
    missing, ``NotRegularFile`` for a directory or pipe, and ``OSError`` for anything else
    (permission, or no line end in the last MAX_PARTIAL_BYTES)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise NotRegularFile(errno.EINVAL, "not a regular file", str(path))
        size = st.st_size
        first = os.pread(fd, Cursor.HEAD_BYTES, 0)
        line = first[: first.find(b"\n") + 1] if b"\n" in first else first
        head = hashlib.sha256(line).hexdigest() if line else None
        end = _end_of_lines(fd, size, str(path))
        tails = {}
        for offset in {*offsets, end, end // 4, end // 2, 3 * end // 4}:
            n = min(offset, TAIL_BYTES)
            data = os.pread(fd, n, offset - n) if 0 <= offset <= end else b""
            tails[offset] = hashlib.sha256(data).hexdigest() if len(data) == n and \
                0 <= offset <= end else None
        return LogSample(st.st_ino, size, head, end, tails, st.st_mtime_ns)
    finally:
        os.close(fd)


def rewritten(before: LogSample, after: LogSample) -> bool:
    """Whether ``after`` can not be ``before`` plus appended lines: another file, a shorter
    one, a changed first line, a same-size file with a new modification time, or any
    sampled window whose bytes differ (a copytruncate that was regrown, an in-place edit)."""
    if after.inode != before.inode or after.size < before.size:
        return True
    if before.head is not None and after.head != before.head:
        return True
    if after.size == before.size and after.mtime_ns != before.mtime_ns:
        return True
    return any(after.tails.get(offset) != digest
               for offset, digest in before.tails.items() if digest is not None)


def _end_of_lines(fd: int, size: int, path: str) -> int:
    floor = max(0, size - MAX_PARTIAL_BYTES)
    pos = size
    while pos > floor:
        start = max(floor, pos - 65536)
        i = os.pread(fd, pos - start, start).rfind(b"\n")
        if i >= 0:
            return start + i + 1
        pos = start
    if floor == 0:
        return 0                       # no newline anywhere: nothing complete yet
    raise OSError(errno.EFBIG, "no line end in the last 1 MiB", path)


class Cursor:
    """High-water mark over the log.

    ``offset``: every item whose first line is before it has been handled. ``done``: ids
    handled whose lines extend to or past ``offset`` (bounded by the active region, not by
    log size). The log's inode, a hash of its first line and the newline just before
    ``offset`` are checked on resume; on rotation or truncation reading restarts from 0
    (``done`` still prevents repeats). The first-line hash catches a rotated log whose new
    file reuses the old inode number. ``tail`` hashes the (at most 4096) bytes before
    ``offset`` as they were when the cursor was saved, so a log rewritten in place with the
    same size no longer matches; a cursor saved by an older version has no ``tail`` and is
    resumed as before, but never counts as a confirmation for rotation until its reader
    runs again.
    """

    HEAD_BYTES = 4096

    @classmethod
    def _head(cls, log_path: os.PathLike | str) -> Optional[str]:
        try:
            with open(log_path, "rb") as f:
                first = f.readline(cls.HEAD_BYTES)
        except OSError:
            return None
        return hashlib.sha256(first).hexdigest() if first else None

    @staticmethod
    def sample(log_path: os.PathLike | str, offsets: Iterable[int] = ()) -> Optional[LogSample]:
        """``sample_log``, or None when the log cannot be sampled (reader run start)."""
        try:
            return sample_log(log_path, offsets)
        except OSError:
            return None

    MAX_DONE = 200_000
    MAX_FAILED = 1_000

    def __init__(self, path: os.PathLike | str) -> None:
        self.path = Path(path)
        self.offset = 0
        self.inode: Optional[int] = None
        self.head: Optional[str] = None
        self.tail: Optional[str] = None
        self.size: Optional[int] = None        # size and mtime when saved: see rewritten()
        self.mtime_ns: Optional[int] = None
        self.done: dict[str, int] = {}
        self.failed: list[str] = []
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self.offset = int(data.get("offset", 0))
                self.inode = data.get("inode")
                self.head = data.get("head")
                tail = data.get("tail")
                self.tail = tail if isinstance(tail, str) else None
                size, mtime = data.get("size"), data.get("mtime_ns")
                self.size = size if isinstance(size, int) and not isinstance(size, bool) else None
                self.mtime_ns = mtime if isinstance(mtime, int) and not isinstance(mtime, bool) \
                    else None
                self.done = {str(k): int(v) for k, v in dict(data.get("done", {})).items()}
                self.failed = [str(x) for x in data.get("failed", [])][-self.MAX_FAILED:]
            except (OSError, ValueError, TypeError, AttributeError):
                self.offset, self.inode, self.done, self.failed = 0, None, {}, []
                self.head = self.tail = self.size = self.mtime_ns = None

    def start_offset(self, log_path: os.PathLike | str) -> int:
        try:
            st = os.stat(log_path)
        except OSError:
            return 0
        if self.offset <= 0 or self.inode != st.st_ino or st.st_size < self.offset:
            return 0
        if self.size == st.st_size and self.mtime_ns is not None \
                and self.mtime_ns != st.st_mtime_ns:
            return 0      # same length but modified since saved: rewritten in place, read it all
        if self.head is not None and self.head != self._head(log_path):
            return 0
        with open(log_path, "rb") as f:
            f.seek(self.offset - 1)
            if f.read(1) != b"\n":
                return 0
        if self.tail is not None:             # content just before the offset must be unchanged
            found = self.sample(log_path, [self.offset])
            if found is None or found.tails.get(self.offset) != self.tail:
                return 0
        return self.offset

    def adopt_handled(self, parsed: ParsedLog, before: Optional[LogSample], recorded) -> None:
        """Before a reread from the start of the same file (it was rewritten at the same
        length, so ``start_offset`` refused the offset): an item that ends at or before the
        old offset and whose record ``recorded(kind, id)`` already exists was handled, and is
        not triaged again (a second model call each). That is the only evidence taken. An
        item without a record, for instance a session id the rewrite introduced, is
        processed: replaying is the conservative side. A different file, or one whose first
        line changed, is a new generation and is read in full."""
        if self.offset > 0 and before is not None and self.inode == before.inode \
                and self.head == before.head:
            for s in parsed.sessions.values():
                if s.last_offset <= self.offset and recorded("session", s.session_id):
                    self.done.setdefault(s.session_id, s.last_offset)
            for c in parsed.campaigns.values():
                if c.last_offset <= self.offset and recorded("campaign", c.campaign_id):
                    self.done.setdefault(c.campaign_id, c.last_offset)

    def seen_session(self, sid: str) -> bool:
        return sid in self.done

    def seen_campaign(self, cid: str) -> bool:
        return cid in self.done

    def mark(self, item_id: str, last_offset: int, failed: bool = False) -> None:
        self.done[item_id] = last_offset
        if failed:
            self.failed.append(item_id)
            self.failed = self.failed[-self.MAX_FAILED:]

    def _stamp(self, log_path: os.PathLike | str, before: Optional[LogSample]) -> None:
        """Record which log, and what content, the offset belongs to.

        ``before`` is the sample the run took before it read; None means that sample failed,
        and then nothing is certified. The log now must be ``before`` plus appended lines
        (``rewritten``): then the fingerprint stored is of bytes the pre-read sample already
        covered or that were appended after it. If the file was replaced, truncated or
        rewritten, the offset does not describe the file now there: the cursor keeps no
        inode, so the next run starts from the beginning (``done`` prevents repeats), and no
        fingerprint, so it confirms nothing for rotation."""
        after = None if before is None else self.sample(log_path, [self.offset, *before.tails])
        if after is None or rewritten(before, after):
            self.inode = self.head = self.tail = self.size = self.mtime_ns = None
            return
        self.inode, self.head = after.inode, after.head
        self.tail = after.tails[self.offset]
        self.size, self.mtime_ns = after.size, after.mtime_ns

    def advance(self, parsed: ParsedLog, log_path: os.PathLike | str,
                before: Optional[LogSample]) -> None:
        """Move the high-water mark past everything handled and prune ``done``."""
        firsts = [s.first_offset for s in parsed.sessions.values() if s.session_id not in self.done]
        firsts += [c.first_offset for c in parsed.campaigns.values()
                   if c.campaign_id not in self.done and c.first_offset >= 0]
        self.offset = min(firsts) if firsts else parsed.end_offset
        self._stamp(log_path, before)
        # last_offset is exclusive: an item ending at or before the mark has no lines
        # left to read, so it can never reappear. Not so when the stamp was refused: the
        # next run rereads from 0, so keep every handled id (no second record or model call).
        if self.inode is not None:
            self.done = {k: v for k, v in self.done.items() if v > self.offset}
        if len(self.done) > self.MAX_DONE:
            keep = sorted(self.done.items(), key=lambda kv: kv[1])[-self.MAX_DONE:]
            self.done = dict(keep)

    def set_position(self, offset: int, log_path: os.PathLike | str,
                     before: Optional[LogSample]) -> None:
        """Set the high-water mark to ``offset`` (the end of a complete line) and record the
        log's identity for the rotation checks in ``start_offset``."""
        self.offset = offset
        self._stamp(log_path, before)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"offset": self.offset, "inode": self.inode, "head": self.head,
                   "tail": self.tail, "size": self.size, "mtime_ns": self.mtime_ns,
                   "done": self.done, "failed": self.failed}
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".cursor-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, self.path)


def pending(parsed: ParsedLog, cursor: Cursor, now: Optional[datetime.datetime] = None,
            session_idle_minutes: int = 120, campaign_grace_minutes: int = 10
            ) -> tuple[list[Session], list[Campaign]]:
    """Ended, unprocessed sessions and finished, unprocessed campaigns, oldest first."""
    now = now or datetime.datetime.now(UTC)
    idle = datetime.timedelta(minutes=session_idle_minutes)
    grace = datetime.timedelta(minutes=campaign_grace_minutes)
    # Login-only connections that ended by going idle join their campaign now.
    for sid, s in list(parsed.sessions.items()):
        if not s.has_activity() and s.start is not None and s.is_finished(now, idle):
            _fold_login_only(parsed, s, parsed.ssh_auth.get(sid, []))
    sessions = [s for s in parsed.sessions.values()
                if s.has_activity() and not cursor.seen_session(s.session_id)
                and s.is_finished(now, idle)]
    campaigns = [c for c in parsed.campaigns.values()
                 if not cursor.seen_campaign(c.campaign_id) and c.is_finished(now, grace)]
    sessions.sort(key=lambda s: s.start or now)
    campaigns.sort(key=lambda c: c.window_start)
    return sessions, campaigns
