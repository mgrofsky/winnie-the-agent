"""Shared framework for every listener: config, hard limits, login policy, TCP runner.

Contract for service modules (``listeners/<proto>.py``):

    async def handle(conn: Conn) -> None          # TCP services
    def build(ctx: ListenerContext) -> ...         # optional, for UDP (SIP)

A handler reads with ``conn.readline()`` / ``conn.readexactly()``, writes with
``conn.write()``, logs with ``conn.emit(event, message, **fields)``, decides logins with
``conn.login(username, password)``, and calls ``conn.command()`` once per command (returns
False when the per-connection command cap is hit). Exceptions never escape: the runner
catches everything at this process boundary, logs an ``error`` event and closes.

No listener makes an outbound connection, executes anything, or writes attacker bytes
anywhere except the capped quarantine directory and the log.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import json
import logging
import os
import tempfile
import time
from collections import OrderedDict, deque
from configparser import ConfigParser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Optional, TypeVar

from pydantic import BaseModel, ValidationError

from agents.budget import ip_key
from agents.llm import LLMOutputError
from agents.source_state import MAX_TARPIT_MS, SourceEntry, SourceStateView, \
    legacy_source_token, source_token, source_token_name
from scenarios.tokens import TokenIndex
from listeners.events import MAX_DATA_KEYS, MAX_VALUE_CHARS, EventWriter, clean, new_task_name
from scenarios.schema import LoginPolicy

T = TypeVar("T", bound=BaseModel)

MAX_LLM_ATTEMPTS = 3
MAX_LLM_EXAMPLES_CHARS = 2000      # worked examples a caller adds to a second request
MIN_LLM_ATTEMPT_SECONDS = 1.0      # a second request starts only with this much time left
MAX_LLM_RUNGS = 10_000             # sessions whose last answering rung is kept

SERVICES = ("sip", "ftp", "telnet", "postgres", "mysql", "mssql", "redis", "smtp", "http", "mllp",
            "s3")
DEFAULT_PORTS = {"sip": 5060, "ftp": 2121, "telnet": 2323, "postgres": 5432, "mysql": 3306,
                 "mssql": 1433, "redis": 6379, "smtp": 2525, "http": 8080, "mllp": 2575,
                 "s3": 9000}


CAPTURE_PARTS = MAX_DATA_KEYS - 1      # one key is the label
CAPTURE_MAX_BYTES = 16_384


def capture_parts(text: str) -> tuple[list[str], bool]:
    """Split ``text`` into at most ``CAPTURE_PARTS`` parts whose escaped form fits the event
    value cap, so nothing is cut by the event model. Returns (parts, truncated)."""
    parts: list[str] = []
    cur: list[str] = []
    width = 0
    for ch in text:
        w = len(clean(ch, 8))
        if width + w > MAX_VALUE_CHARS:
            parts.append("".join(cur))
            cur, width = [], 0
            if len(parts) >= CAPTURE_PARTS:
                return parts, True
        cur.append(ch)
        width += w
    if cur:
        parts.append("".join(cur))
    return parts, False


class ConnClosed(Exception):
    """Raised inside a handler to end the connection (EOF, timeout, limit)."""


@dataclass
class Limits:
    read_timeout: float = 60.0          # max wait for any single read after login
    pre_login_timeout: float = 20.0     # max wait for any single read before login
    session_timeout: float = 600.0      # max lifetime of one connection
    max_line_bytes: int = 4096
    max_conn_bytes: int = 1_048_576     # bytes read per connection (FTP uploads: quarantine caps)
    max_connections: int = 256          # all TCP services together
    max_connections_per_ip: int = 8     # one source across all services
    max_connections_per_service: int = 64
    max_connections_per_ip_per_service: int = 4
    min_progress_bytes: int = 8         # a connection must send this much ...
    progress_window: float = 30.0       # ... within this many seconds, or it is closed
    rate_per_ip_per_minute: int = 60    # new TCP connections / UDP requests
    udp_responses_per_ip_per_minute: int = 20
    udp_responses_per_second: int = 50  # all UDP sources together
    udp_requests_per_second: int = 200  # inbound UDP datagrams, all sources, before parsing
    # Bytes a UDP response may exceed its request by. 0 (default) means a response is never
    # larger than the request; minimal REGISTERs then get no 401 at all.
    sip_udp_slack_bytes: int = 0
    low_value_events_per_second: int = 20  # refused connections, malformed datagrams, ...
    unverified_events_per_second: int = 20  # lines from unverified (possibly forged) UDP sources
    max_commands_per_connection: int = 500
    quarantine_max_file_bytes: int = 5_242_880
    quarantine_total_bytes: int = 104_857_600
    quarantine_per_ip_bytes: int = 20_971_520
    ftp_pasv_accept_timeout: float = 30.0   # an unused passive listener closes after this
    ftp_pasv_per_ip: int = 2                # open passive listeners per source
    llm_max_inflight: int = 4           # concurrent model calls from SQL/HTTP/Redis fallbacks
    llm_timeout: float = 20.0
    llm_attempts: int = 2               # requests per model answer, 1 to 3 (see llm_json)
    llm_deadline: float = 12.0          # seconds for all attempts together, at most llm_timeout

    @classmethod
    def from_section(cls, section) -> "Limits":
        out = cls()
        if section is None:
            return out
        for name, default in cls().__dict__.items():
            if name in section:
                value = float(section.get(name)) if isinstance(default, float) else int(section.get(name))
                if value < 0:
                    raise ValueError(f"[listeners] {name} must be >= 0")
                setattr(out, name, value)
        return out


class SlidingRate:
    """Per-key events-per-60s limiter with bounded memory."""

    def __init__(self, per_minute: int, max_keys: int = 50_000) -> None:
        self.per_minute = per_minute
        self.max_keys = max_keys
        self._hits: OrderedDict[str, deque] = OrderedDict()

    def allow(self, key: str, now: Optional[float] = None) -> bool:
        key = ip_key(key)  # IPv6 sources share one bucket per /64; other keys unchanged
        now = time.monotonic() if now is None else now
        q = self._hits.get(key)
        if q is None:
            q = deque()
            self._hits[key] = q
            if len(self._hits) > self.max_keys:
                self._hits.popitem(last=False)
        else:
            self._hits.move_to_end(key)
        while q and now - q[0] > 60.0:
            q.popleft()
        if len(q) >= self.per_minute:
            return False
        q.append(now)
        return True

    def remaining(self, key: str, now: Optional[float] = None) -> int:
        """Events ``key`` may still have in the current 60 s window (nothing is used)."""
        q = self._hits.get(ip_key(key))
        now = time.monotonic() if now is None else now
        used = sum(1 for t in q if now - t <= 60.0) if q else 0
        return max(0, self.per_minute - used)


class TokenBucket:
    """Global events-per-second limiter (e.g. all UDP responses together)."""

    def __init__(self, per_second: float, burst: Optional[float] = None) -> None:
        self.rate = float(per_second)
        self.capacity = float(burst if burst is not None else max(1.0, per_second))
        self.tokens = self.capacity
        self.last: Optional[float] = None

    def allow(self, now: Optional[float] = None) -> bool:
        now = time.monotonic() if now is None else now
        elapsed = 0.0 if self.last is None else max(0.0, now - self.last)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class LowValueGate:
    """Aggregates repetitive low-value log lines (refused connections, malformed datagrams).

    Per key (``"<source>|<protocol>|<reason>"``): the first occurrence is logged, then at
    most one line per ``window`` seconds carrying the number suppressed in between. On top,
    an events-per-second ceiling per pool: ``unverified`` (UDP sources that never completed
    a nonce round trip, which can be forged) and ``default`` (everything else), so a forged
    flood cannot use up the budget of real sources. Suppressed events are never lost
    silently: a count surfaces in the next line logged for its key, or ``sweep`` returns it
    (keys whose source never returned, keys evicted from memory, lines the ceiling refused)
    for a periodic summary line.
    """

    POOLS = ("default", "unverified")

    def __init__(self, per_second: float, window: float = 60.0, max_keys: int = 50_000,
                 unverified_per_second: Optional[float] = None) -> None:
        self.buckets = {"default": TokenBucket(per_second),
                        "unverified": TokenBucket(unverified_per_second
                                                  if unverified_per_second is not None
                                                  else per_second)}
        self.window = window
        self.max_keys = max_keys
        # key -> [last_logged, suppressed, pool]
        self._state: OrderedDict[str, list] = OrderedDict()
        self._evicted: dict[tuple[str, str], int] = {}   # (protocol, pool) -> count
        self.global_suppressed = 0

    @staticmethod
    def _protocol(key: str) -> str:
        parts = key.split("|")
        return parts[1] if len(parts) > 2 else "-"

    def check(self, key: str, now: Optional[float] = None,
              pool: str = "default") -> Optional[int]:
        """None: do not log. Otherwise log, attaching the returned count as ``suppressed``."""
        now = time.monotonic() if now is None else now
        st = self._state.get(key)
        due = st is None or (now - st[0] >= self.window and st[1] > 0)
        if st is None:
            st = [now - self.window, 0, pool]
            self._state[key] = st
            if len(self._state) > self.max_keys:
                old_key, old = self._state.popitem(last=False)
                if old[1]:
                    k = (self._protocol(old_key), old[2])
                    self._evicted[k] = self._evicted.get(k, 0) + old[1]
        else:
            self._state.move_to_end(key)
        if not due or not self.buckets[pool].allow(now):
            st[1] += 1
            if due:
                self.global_suppressed += 1
            return None
        suppressed, st[0], st[1] = st[1], now, 0
        return suppressed

    def sweep(self, now: Optional[float] = None) -> dict[tuple[str, str], int]:
        """Counts not yet reported by a line of their own, per (protocol, pool): keys idle
        for a full window, evicted keys and lines the ceiling refused. Resets what it returns."""
        now = time.monotonic() if now is None else now
        totals, self._evicted = dict(self._evicted), {}
        for key, st in self._state.items():
            if st[1] and now - st[0] >= self.window:
                k = (self._protocol(key), st[2])
                totals[k] = totals.get(k, 0) + st[1]
                st[1] = 0
        return totals


class ConnectionLimiter:
    """Global, per-source, per-service and per-source-per-service connection slots."""

    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.total = 0
        self.per_ip: dict[str, int] = {}
        self.per_service: dict[str, int] = {}
        self.per_ip_service: dict[tuple[str, str], int] = {}
        self.rate = SlidingRate(limits.rate_per_ip_per_minute)

    def acquire(self, ip: str, service: str = "-") -> Optional[str]:
        ip = ip_key(ip)
        if not self.rate.allow(ip):
            return "rate_per_ip_per_minute"
        if self.total >= self.limits.max_connections:
            return "max_connections"
        if self.per_ip.get(ip, 0) >= self.limits.max_connections_per_ip:
            return "max_connections_per_ip"
        if self.per_service.get(service, 0) >= self.limits.max_connections_per_service:
            return "max_connections_per_service"
        if self.per_ip_service.get((ip, service), 0) >= self.limits.max_connections_per_ip_per_service:
            return "max_connections_per_ip_per_service"
        self.total += 1
        self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
        self.per_service[service] = self.per_service.get(service, 0) + 1
        self.per_ip_service[(ip, service)] = self.per_ip_service.get((ip, service), 0) + 1
        return None

    @staticmethod
    def _dec(d: dict, key) -> None:
        n = d.get(key, 0) - 1
        if n > 0:
            d[key] = n
        else:
            d.pop(key, None)

    def release(self, ip: str, service: str = "-") -> None:
        ip = ip_key(ip)
        self.total = max(0, self.total - 1)
        self._dec(self.per_ip, ip)
        self._dec(self.per_service, service)
        self._dec(self.per_ip_service, (ip, service))


class LoginTracker:
    """Implements accept = all | listed | after_n | none, stable per source IP.

    after_n: the k-th attempt from an IP succeeds, k drawn from [min, max] by a hash of
    (seed, service, ip). Once an IP has "found" a credential for a service, only that
    credential keeps working for it. Listed accounts always succeed (unless 'none').
    """

    def __init__(self, seed: str, max_keys: int = 100_000) -> None:
        self.seed = seed
        self.max_keys = max_keys
        self._state: OrderedDict[tuple[str, str], dict] = OrderedDict()

    def _entry(self, service: str, ip: str) -> dict:
        key = (service, ip)
        st = self._state.get(key)
        if st is None:
            st = {"attempts": 0, "found": None}
            self._state[key] = st
            if len(self._state) > self.max_keys:
                self._state.popitem(last=False)
        else:
            self._state.move_to_end(key)
        return st

    def threshold(self, service: str, ip: str, policy: LoginPolicy) -> int:
        digest = hashlib.sha256(f"{self.seed}|{service}|{ip}".encode()).digest()
        span = policy.after_n_max - policy.after_n_min + 1
        return policy.after_n_min + int.from_bytes(digest[:4], "big") % span

    def decide(self, service: str, ip: str, username: str, password: str,
               policy: LoginPolicy, accounts: list[tuple[str, str]]) -> bool:
        if policy.accept == "none":
            return False
        for user, pw in accounts:
            if user == username and (pw == "*" or pw == password):
                return True
        st = self._entry(service, ip)
        st["attempts"] += 1
        if st["found"] is not None:
            return st["found"] == (username, password)
        if policy.accept == "all":
            return True
        if policy.accept == "listed":
            return False
        if st["attempts"] >= self.threshold(service, ip, policy):
            st["found"] = (username, password)
            return True
        return False


@dataclass
class ServiceSettings:
    name: str
    enabled: bool
    port: int
    banner: Optional[str] = None
    version: Optional[str] = None
    policy: LoginPolicy = field(default_factory=LoginPolicy)
    accounts: list[tuple[str, str]] = field(default_factory=list)
    auth_method: Optional[str] = None   # e.g. postgres: "md5" | "cleartext" ([listeners] <svc>_auth)


class ListenerContext:
    """Everything a handler needs. Built once per process by ``build_context``."""

    def __init__(self, writer: EventWriter, limits: Optional[Limits] = None,
                 seed: str = "winnie", scenario=None, settings: Optional[dict] = None,
                 quarantine_dir: Optional[str] = None, budget=None, json_llm=None,
                 honeytokens: Optional[dict[str, str]] = None, bind_host: str = "127.0.0.1",
                 persona_history=None, source_state_path: Optional[str] = None,
                 persona_sessions=None) -> None:
        self.writer = writer
        self.limits = limits or Limits()
        self.seed = seed
        self.scenario = scenario            # scenarios.loader.LoadedScenario or None
        self.settings: dict[str, ServiceSettings] = settings or {}
        self.quarantine_dir = quarantine_dir
        self.quarantine_used = 0
        self.budget = budget                # agents.budget.Budget or None (LLM disabled)
        self.json_llm = json_llm            # agents.llm.JsonLLM or None (LLM disabled)
        self.honeytokens = honeytokens or {}  # {value: name}
        self.bind_host = bind_host
        self.persona_history = persona_history  # telnet persona (RunnableWithMessageHistory)
        self.persona_sessions = persona_sessions  # its per-session chat histories, freed on close
        # Per-source treatment written by the agents (tarpit, planted token, capture level).
        # A view on no path never has entries.
        self.source_state = SourceStateView(source_state_path)
        self._token_cache: dict[str, tuple[str, str]] = {}
        self.limiter = ConnectionLimiter(self.limits)
        self.logins = LoginTracker(seed)
        self.udp_rate = SlidingRate(self.limits.rate_per_ip_per_minute)
        self.udp_resp_rate = SlidingRate(self.limits.udp_responses_per_ip_per_minute)
        self.udp_global = TokenBucket(self.limits.udp_responses_per_second)
        self.gate = LowValueGate(self.limits.low_value_events_per_second,
                                 unverified_per_second=self.limits.unverified_events_per_second)
        self.quarantine = QuarantineStore(quarantine_dir, self.limits) if quarantine_dir else None
        self.ftp_pasv_ports: Optional[tuple[int, int]] = None   # (first, last); None = ephemeral
        self.ftp_pasv_address: Optional[str] = None             # None = control conn's local addr
        self.ftp_pasv_open: dict[str, int] = {}                 # source key -> open passive listeners
        self._llm_sem = asyncio.Semaphore(max(1, self.limits.llm_max_inflight))
        self._llm_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, self.limits.llm_max_inflight), thread_name_prefix="llm")
        self.llm_clock: Callable[[], float] = time.monotonic
        # session id -> "llm" or "llm_retry": the request that gave the last answer
        self.llm_rungs: OrderedDict[str, str] = OrderedDict()

    def report_suppressed(self, now: Optional[float] = None) -> list[dict]:
        """Write one sensor-level line per protocol and pool for log lines the gate
        suppressed and has not reported yet. Returns the lines written (tests)."""
        before = len(self.writer.events)
        for (protocol, pool), count in sorted(self.gate.sweep(now).items()):
            # Gate keys are "<source>|<service>|<reason>", so protocol is a service name.
            self.writer.emit(task_name=new_task_name(protocol), src_ip="-", src_port=0,
                             dst_port=0, message=f"Suppressed {count} low-value log lines",
                             sensor_protocol=protocol,
                             event="limit", level="WARNING",
                             data={"reason": "suppressed_summary", "pool": pool,
                                   "count": count, "period_seconds": int(self.gate.window)})
        return self.writer.events[before:]

    def service(self, name: str) -> ServiceSettings:
        s = self.settings.get(name)
        if s is None:
            s = ServiceSettings(name=name, enabled=True, port=0)
            self.settings[name] = s
        return s

    def source(self, ip: str) -> Optional[SourceEntry]:
        """The live (unexpired) per-source entry for ``ip``, or None."""
        try:
            return self.source_state.get(ip)
        except Exception:  # noqa: BLE001 - a bad address or state file means "no entry"
            return None

    def source_token(self, ip: str) -> tuple[str, str]:
        """(access_key_id, secret) planted for this source."""
        return self.source_token_for_key(ip_key(ip))

    def source_token_for_key(self, key: str) -> tuple[str, str]:
        pair = self._token_cache.get(key)
        if pair is None:
            if len(self._token_cache) > 20_000:
                self._token_cache.clear()
            pair = self._token_cache[key] = source_token(self.seed, key)
        return pair

    def planted_tokens(self) -> dict[str, str]:
        """{value: name} for every token currently planted for a source (key id and secret),
        plus the pair earlier versions planted for the same source (recognised, never
        planted again). Rebuilt only when the source-state file is reloaded."""
        if self.source_state.path is None:
            return {}
        self.source_state._refresh()
        state = self.source_state._state
        # Keyed on the loaded state object: rebuilt only when the file is reloaded. Tokens of
        # expired entries stay recognised; a key reused after expiry is still a strong signal.
        stamp = id(state)
        if getattr(self, "_planted_stamp", None) != stamp:
            out: dict[str, str] = {}
            for entry in state.entries.values():
                if entry.plant_token:
                    name = source_token_name(entry.key)
                    for value in legacy_source_token(self.seed, entry.key):
                        out[value] = name
                    for value in self.source_token_for_key(entry.key):
                        out[value] = name
            self._planted_map, self._planted_stamp = out, stamp
            self._token_index = None
        return self._planted_map

    def token_index(self) -> TokenIndex:
        """Scenario honeytokens and per-source tokens, indexed for lookup."""
        planted = self.planted_tokens()
        index = getattr(self, "_token_index", None)
        if index is None or getattr(self, "_index_tokens", None) is not self.honeytokens:
            index = TokenIndex(self.honeytokens)
            index.update(planted)
            self._token_index, self._index_tokens = index, self.honeytokens
        return index

    def honeytoken_in(self, *values: Optional[str]) -> Optional[str]:
        """The name of a token this sensor issued found in any of ``values``. Recognised by
        lookup, one probe per position of a bounded prefix of each value."""
        values = tuple(v for v in values if v)
        if not values:
            return None
        return self.token_index().find_any(values)

    def tarpit_seconds(self, ip: str) -> float:
        entry = self.source(ip)
        if entry is None or entry.tarpit_ms <= 0:
            return 0.0
        return min(entry.tarpit_ms, MAX_TARPIT_MS) / 1000.0

    def take_llm_rung(self, session_id: str) -> Optional[str]:
        """Which request gave the session's last ``llm_json`` answer ("llm" for the first,
        "llm_retry" for a later one), or None when the last call gave no answer. Reading it
        clears it."""
        return self.llm_rungs.pop(session_id, None)

    async def llm_json(self, session_id: str, ip: str, system: str, user: str,
                       schema: type[T], examples: str = "") -> Optional[T]:
        """Budgeted, schema-validated model call. Returns None on any failure or limit;
        the caller must then render a believable protocol error.

        - The connection takes a model-session slot (same concurrency caps as SSH sessions).
        - The estimated cost is reserved before each request; failed and timed-out requests
          keep it.
        - At most ``llm_max_inflight`` calls run at once, in a dedicated bounded thread pool;
          when all slots are busy the call is not made. A call holds its slot across its
          requests. A timed-out call keeps its slot until its thread really finishes, so
          threads can never pile up.
        - Up to ``llm_attempts`` requests (1 to 3). When an answer fails schema validation
          (the client's or the re-validation here), the next request adds ``examples`` (at
          most ``MAX_LLM_EXAMPLES_CHARS``) and one line naming the problem to the system
          prompt. A timeout or provider error ends the call. With more than one attempt,
          all requests share ``llm_deadline`` seconds (at most ``llm_timeout``; 0 means
          ``llm_timeout``), and a later request starts only with ``MIN_LLM_ATTEMPT_SECONDS``
          left. A later request does not count as another model command.
        - ``take_llm_rung(session_id)`` gives the request that answered.
        """
        self.llm_rungs.pop(session_id, None)
        if self.json_llm is None or self.budget is None:
            return None
        if self.budget.session_commands(session_id) is None:
            if self.budget.session_open(session_id, ip) is not None:
                return None
        if self._llm_sem.locked() or self.budget.model_cap_reached(session_id, ip):
            return None
        reason, reservation = self.budget.reserve(session_id, ip, system + user)
        if reason is not None:
            return None
        attempts = min(MAX_LLM_ATTEMPTS, max(1, int(self.limits.llm_attempts)))
        timeout = self.limits.llm_timeout
        deadline = None
        if attempts > 1:
            budget_seconds = self.limits.llm_deadline
            deadline = self.llm_clock() + (min(budget_seconds, timeout) if budget_seconds > 0
                                           else timeout)
        examples = (examples or "")[:MAX_LLM_EXAMPLES_CHARS]
        prompt = system
        await self._llm_sem.acquire()
        fut: Optional[asyncio.Future] = None
        try:
            loop = asyncio.get_running_loop()
            for attempt in range(attempts):
                wait = timeout
                if deadline is not None:
                    left = deadline - self.llm_clock()
                    if left <= 0 or (attempt and left < MIN_LLM_ATTEMPT_SECONDS):
                        return None
                    wait = min(timeout, left)
                if attempt:
                    prompt = _retry_system(system, examples, problem)
                    reason, reservation = self.budget.reserve(session_id, ip, prompt + user,
                                                              counts_as_command=False)
                    if reason is not None:
                        return None
                fut = loop.run_in_executor(self._llm_pool, self.json_llm.complete_json,
                                           prompt, user, schema)
                try:
                    result = await asyncio.wait_for(asyncio.shield(fut), timeout=wait)
                except (LLMOutputError, ValidationError) as exc:
                    problem = _llm_problem(exc, schema)
                    continue
                except Exception:  # noqa: BLE001 - a timeout or provider failure ends the call
                    return None
                try:
                    # Never trust the client's object type: re-validate strictly against the schema.
                    raw = result.model_dump() if isinstance(result, BaseModel) else result
                    result = schema.model_validate(raw)
                except Exception as exc:  # noqa: BLE001 - invalid output may be asked again
                    problem = _llm_problem(exc, schema)
                    continue
                self.budget.commit(reservation, prompt + user, result.model_dump_json())
                self.llm_rungs[session_id] = "llm" if attempt == 0 else "llm_retry"
                while len(self.llm_rungs) > MAX_LLM_RUNGS:
                    self.llm_rungs.popitem(last=False)
                return result
            return None
        finally:
            # A request still running (timed out, or the caller was cancelled) keeps the
            # slot until its thread ends.
            if fut is not None and not fut.done():
                fut.add_done_callback(lambda _f: self._llm_sem.release())
            else:
                self._llm_sem.release()


def _llm_problem(exc: BaseException, schema: type[BaseModel]) -> str:
    """One line naming why an answer was rejected: the schema's own field name and
    pydantic's error type, never text from the model (an unexpected key is named only as
    an extra field)."""
    if isinstance(exc, ValidationError):
        errors = exc.errors()
        if errors:
            kind = "".join(c for c in str(errors[0].get("type", "")) if c.isalnum() or c == "_")
            loc = errors[0].get("loc", ())
            field_name = loc[0] if loc and loc[0] in schema.model_fields else None
            where = f"field {field_name}" if field_name else "the answer"
            return f"{where} failed validation ({kind[:40] or 'invalid'})"
    return "the answer was not JSON matching the schema"


def _retry_system(system: str, examples: str, problem: str) -> str:
    """The system prompt for a later request: the original, the problem, the examples."""
    note = (f"\n\nYour previous answer was rejected: {problem}. Answer again with JSON that "
            "matches the schema exactly, nothing else.")
    if examples:
        note += f"\nExamples of correct answers:\n{examples}"
    return system + note


class Conn:
    def __init__(self, ctx: ListenerContext, protocol: str, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter) -> None:
        self.ctx = ctx
        self.protocol = protocol
        self.reader = reader
        self.writer = writer
        self.task_name = new_task_name(protocol)
        peer = writer.get_extra_info("peername") or ("-", "-")
        sock = writer.get_extra_info("sockname") or ("-", "-")
        self.src_ip, self.src_port = str(peer[0]), peer[1]
        self.dst_ip, self.dst_port = str(sock[0]), sock[1]
        self.bytes_read = 0
        self.commands = 0
        self.authenticated_as: Optional[str] = None
        self.state: dict = {}
        self.started = time.monotonic()

    # ---- logging -------------------------------------------------------------------------

    def emit(self, event: str, message: str, **fields) -> None:
        self.ctx.writer.emit(task_name=self.task_name, src_ip=self.src_ip, src_port=self.src_port,
                             dst_ip=self.dst_ip, dst_port=self.dst_port, message=message,
                             sensor_protocol=self.protocol, event=event, transport="tcp", **fields)

    def capture(self, label: str, data: bytes | str) -> bool:
        """Fuller logging for sources marked ``capture_more``: one ``command`` event holding
        ``capture_label`` and the content in up to ``CAPTURE_PARTS`` parts of at most 512
        escaped characters each. Returns False (and logs nothing) for other sources."""
        entry = self.ctx.source(self.src_ip)
        if entry is None or not entry.capture_more:
            return False
        if isinstance(data, bytes):
            data = data[:CAPTURE_MAX_BYTES].decode("utf-8", errors="backslashreplace")
        parts, truncated = capture_parts(data)
        fields: dict = {"capture_label": clean(label, 64)}
        for i, part in enumerate(parts):
            fields[f"part_{i:02d}"] = part
        self.emit("command", "Captured content" + (" (truncated)" if truncated else ""),
                  username=self.authenticated_as, data=fields)
        return True

    # ---- reading -------------------------------------------------------------------------

    def _count(self, n: int) -> None:
        self.bytes_read += n
        if self.bytes_read > self.ctx.limits.max_conn_bytes:
            self.emit("limit", "Connection byte limit", data={"reason": "max_conn_bytes"})
            raise ConnClosed("max_conn_bytes")

    def count_bytes(self, n: int) -> None:
        """Charge bytes received on a side channel (e.g. an FTP data connection)."""
        self._count(n)

    @property
    def timeout(self) -> float:
        """Shorter reads before login than after."""
        limits = self.ctx.limits
        return limits.pre_login_timeout if self.authenticated_as is None else limits.read_timeout

    async def readline(self, max_bytes: Optional[int] = None, strip: bool = True) -> bytes:
        limit = max_bytes or self.ctx.limits.max_line_bytes
        try:
            line = await asyncio.wait_for(self.reader.readuntil(b"\n"),
                                          timeout=self.timeout)
        except asyncio.LimitOverrunError:
            self.emit("limit", "Line too long", data={"reason": "max_line_bytes"})
            raise ConnClosed("max_line_bytes") from None
        except asyncio.IncompleteReadError as exc:
            if not exc.partial:
                raise ConnClosed("eof") from None
            line = exc.partial
        except (asyncio.TimeoutError, ConnectionError):
            raise ConnClosed("timeout") from None
        self._count(len(line))
        if len(line) > limit:
            self.emit("limit", "Line too long", data={"reason": "max_line_bytes"})
            raise ConnClosed("max_line_bytes")
        return line.rstrip(b"\r\n") if strip else line

    async def readexactly(self, n: int) -> bytes:
        if n < 0 or n > self.ctx.limits.max_conn_bytes:
            self.emit("limit", "Packet too large", data={"reason": "packet_size", "size": n})
            raise ConnClosed("packet_size")
        try:
            data = await asyncio.wait_for(self.reader.readexactly(n),
                                          timeout=self.timeout)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            raise ConnClosed("eof") from None
        self._count(len(data))
        return data

    async def read_some(self, n: int = 4096) -> bytes:
        try:
            data = await asyncio.wait_for(self.reader.read(n), timeout=self.timeout)
        except (asyncio.TimeoutError, ConnectionError):
            raise ConnClosed("timeout") from None
        if not data:
            raise ConnClosed("eof")
        self._count(len(data))
        return data

    # ---- writing -------------------------------------------------------------------------

    async def write(self, data: bytes | str) -> None:
        if isinstance(data, str):
            data = data.encode("utf-8")
        delay = self.ctx.tarpit_seconds(self.src_ip)
        if delay > 0:
            # Never past the connection's own lifetime.
            remaining = self.ctx.limits.session_timeout - (time.monotonic() - self.started)
            if remaining > 0:
                await asyncio.sleep(min(delay, remaining))
        try:
            self.writer.write(data)
            await asyncio.wait_for(self.writer.drain(), timeout=self.timeout)
        except (asyncio.TimeoutError, ConnectionError):
            raise ConnClosed("write") from None

    # ---- policy --------------------------------------------------------------------------

    def command(self) -> bool:
        self.commands += 1
        if self.commands > self.ctx.limits.max_commands_per_connection:
            self.emit("limit", "Command limit", data={"reason": "max_commands_per_connection"})
            return False
        return True

    def login(self, username: str, password: str, **extra) -> bool:
        """Decide a login under the service's policy and log one auth_attempt event."""
        svc = self.ctx.service(self.protocol)
        ok = self.ctx.logins.decide(self.protocol, self.src_ip, username, password,
                                    svc.policy, svc.accounts)
        data = dict(extra.pop("data", {}) or {})
        token = self.ctx.honeytoken_in(username, password)
        if token:
            data["honeytoken"] = token
        self.emit("auth_attempt", "Authentication attempt", username=username,
                  password=password, success=ok, data=data, **extra)
        if ok:
            self.authenticated_as = username
        return ok


Handler = Callable[[Conn], Awaitable[None]]


async def start_tcp(ctx: ListenerContext, protocol: str, port: int, handler: Handler,
                    host: Optional[str] = None) -> asyncio.base_events.Server:
    async def _watch_progress(conn: Conn, task: asyncio.Task) -> None:
        # Close connections that send almost nothing for too long (slow-drip slot holding).
        window = ctx.limits.progress_window
        if window <= 0:
            return
        started = time.monotonic()
        while not task.done():
            await asyncio.sleep(min(1.0, window / 4))
            if conn.bytes_read >= ctx.limits.min_progress_bytes:
                return
            if time.monotonic() - started >= window:
                conn.emit("limit", "No progress", data={"reason": "min_progress",
                                                        "bytes_read": conn.bytes_read})
                task.cancel()
                return

    async def _client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = Conn(ctx, protocol, reader, writer)
        refused = ctx.limiter.acquire(conn.src_ip, protocol)
        if refused:
            suppressed = ctx.gate.check(f"{ip_key(conn.src_ip)}|{protocol}|{refused}")
            if suppressed is not None:
                conn.emit("limit", "Connection refused by limit",
                          data={"reason": refused, "suppressed": suppressed})
            writer.close()
            return
        conn.emit("connection", "Connection received")
        task = asyncio.ensure_future(handler(conn))
        watchdog = asyncio.ensure_future(_watch_progress(conn, task))
        try:
            await asyncio.wait_for(task, timeout=ctx.limits.session_timeout)
        except (ConnClosed, asyncio.TimeoutError, asyncio.CancelledError):
            if not task.done():
                task.cancel()
        except Exception as exc:  # noqa: BLE001 - process boundary: never crash the listener
            conn.emit("error", "Handler error", level="WARNING",
                      data={"reason": type(exc).__name__})
        finally:
            watchdog.cancel()
            ctx.limiter.release(conn.src_ip, protocol)
            if ctx.budget is not None:
                ctx.budget.session_close(conn.task_name)
            conn.emit("close", "Connection closed",
                      data={"bytes_read": conn.bytes_read, "commands": conn.commands})
            try:
                writer.close()
            except Exception:  # noqa: BLE001, S110 - best-effort cleanup
                pass

    return await asyncio.start_server(_client, host=host or ctx.bind_host, port=port,
                                      limit=max(ctx.limits.max_line_bytes * 2, 65536),
                                      reuse_address=True)


# ---- quarantine (FTP STOR etc.) -----------------------------------------------------------

@dataclass
class QuarantineResult:
    status: str                 # stored | duplicate | ip_quota | total_quota | disabled | error
    sha256: Optional[str] = None
    size: int = 0
    name: Optional[str] = None
    quota_hit: bool = False     # a quota (not the per-file cap) stopped the capture
    truncated: bool = False     # cut at the per-file cap; sha256 and size are of what was kept


class QuarantineWriter:
    """Streams one upload to disk, enforcing the per-file cap and quotas while reading.
    An upload over the per-file cap is cut at the cap and the part kept is stored."""

    def __init__(self, store: "QuarantineStore", ip: str) -> None:
        self.store = store
        self.ip = ip_key(ip)
        self.size = 0
        self.hasher = hashlib.sha256()
        self.failed: Optional[str] = None
        self.truncated = False
        fd, self.tmp = tempfile.mkstemp(dir=store.dir, prefix=".part-", suffix=".tmp")
        os.fchmod(fd, 0o600)
        self.f = os.fdopen(fd, "wb")

    def write(self, chunk: bytes) -> bool:
        """Append a chunk. False once a limit is hit and the caller should stop reading:
        at the per-file cap the part up to the cap is kept; over a quota the upload is
        discarded at ``finish``."""
        if self.failed or self.truncated:
            return False
        limits = self.store.limits
        room = limits.quarantine_max_file_bytes - self.size
        if len(chunk) > room:
            chunk, self.truncated = chunk[:max(0, room)], True
        new = self.size + len(chunk)
        if self.store.ip_usage.get(self.ip, 0) + new > limits.quarantine_per_ip_bytes:
            self.failed = "ip_quota"
        elif self.store.used + new > limits.quarantine_total_bytes:
            self.failed = "total_quota"
        if self.failed:
            return False
        self.f.write(chunk)
        self.hasher.update(chunk)
        self.size = new
        return not self.truncated

    def finish(self) -> QuarantineResult:
        self.f.close()
        sha = self.hasher.hexdigest()
        if self.failed:
            os.unlink(self.tmp)
            return QuarantineResult(self.failed, None, self.size,
                                    quota_hit=self.failed in ("ip_quota", "total_quota"))
        if sha in self.store.hashes:
            os.unlink(self.tmp)
            return QuarantineResult("duplicate", sha, self.size, self.store.hashes[sha],
                                    truncated=self.truncated)
        name = os.urandom(16).hex() + ".bin"
        os.replace(self.tmp, self.store.dir / name)
        meta = {"sha256": sha, "size": self.size, "src": self.ip,
                "stored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        fd = os.open(self.store.dir / (name + ".json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(meta, f)
        self.store.record(sha, name, self.size, self.ip)
        return QuarantineResult("stored", sha, self.size, name, truncated=self.truncated)

    def abort(self) -> None:
        try:
            self.f.close()
            os.unlink(self.tmp)
        except OSError:
            pass


class QuarantineStore:
    """Capped store for attacker uploads: random names, mode 0600, never read back or run.

    Usage, per-source usage and known hashes are rebuilt from disk at start, so a restart
    does not grant a fresh quota. Identical uploads are stored once (deduped by SHA-256).
    """

    def __init__(self, directory: os.PathLike | str, limits: Limits) -> None:
        self.dir = Path(directory)
        self.limits = limits
        self.used = 0
        self.ip_usage: dict[str, int] = {}
        self.hashes: dict[str, str] = {}
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        for part in self.dir.glob(".part-*.tmp"):
            part.unlink(missing_ok=True)  # interrupted uploads from a previous run
        for path in self.dir.glob("*.bin"):
            try:
                size = path.stat().st_size
                meta_path = path.with_name(path.name + ".json")
                meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
                sha = meta.get("sha256") or hashlib.sha256(path.read_bytes()).hexdigest()
                self.record(sha, path.name, size, str(meta.get("src", "-")))
            except (OSError, ValueError, AttributeError):
                continue

    def record(self, sha: str, name: str, size: int, ip: str) -> None:
        self.hashes[sha] = name
        self.used += size
        self.ip_usage[ip] = self.ip_usage.get(ip, 0) + size

    def open(self, ip: str) -> QuarantineWriter | QuarantineResult:
        if self.used >= self.limits.quarantine_total_bytes:
            return QuarantineResult("total_quota", quota_hit=True)
        if self.ip_usage.get(ip_key(ip), 0) >= self.limits.quarantine_per_ip_bytes:
            return QuarantineResult("ip_quota", quota_hit=True)
        try:
            return QuarantineWriter(self, ip)
        except OSError:
            return QuarantineResult("error")

    def store_bytes(self, ip: str, data: bytes) -> QuarantineResult:
        w = self.open(ip)
        if isinstance(w, QuarantineResult):
            return w
        w.write(data)
        return w.finish()


# ---- config -------------------------------------------------------------------------------

def parse_port_range(value: str) -> Optional[tuple[int, int]]:
    """'30000-30019' -> (30000, 30019); '' -> None. Raises ValueError on bad input."""
    value = (value or "").strip()
    if not value:
        return None
    first, _, last = value.partition("-")
    lo, hi = int(first), int(last or first)
    if not (1 <= lo <= hi <= 65535) or hi - lo > 1000:
        raise ValueError(f"bad port range {value!r}")
    return lo, hi


def resolve_settings(config: ConfigParser, scenario=None) -> dict[str, ServiceSettings]:
    """Scenario defaults, overridden per service by [listeners] <svc>_enabled/_port/_accept."""
    section = config["listeners"] if "listeners" in config else {}
    out: dict[str, ServiceSettings] = {}
    for name in SERVICES:
        svc = getattr(scenario.scenario.services, name, None) if scenario else None
        enabled = bool(svc.enabled) if svc is not None else False
        port = svc.port if svc is not None else DEFAULT_PORTS[name]
        policy = scenario.policy_for(name) if scenario else LoginPolicy()
        accounts = scenario.accounts_for(name) if scenario else []
        s = ServiceSettings(name=name, enabled=enabled, port=port,
                            banner=getattr(svc, "banner", None), version=getattr(svc, "version", None),
                            policy=policy, accounts=accounts)
        if f"{name}_enabled" in section:
            s.enabled = str(section.get(f"{name}_enabled")).strip().lower() in ("1", "true", "yes", "on")
        if f"{name}_port" in section:
            s.port = int(section.get(f"{name}_port"))
        if f"{name}_auth" in section:
            method = str(section.get(f"{name}_auth")).strip().lower()
            if method not in ("md5", "cleartext"):
                raise ValueError(f"[listeners] {name}_auth must be md5 or cleartext")
            s.auth_method = method
        if f"{name}_accept" in section:
            s.policy = LoginPolicy(accept=section.get(f"{name}_accept").strip(),
                                   after_n_min=s.policy.after_n_min, after_n_max=s.policy.after_n_max)
        out[name] = s
    return out


def default_seed(config: ConfigParser, data_dir: Optional[os.PathLike | str] = None) -> str:
    """The sensor seed: ``[scenario] seed`` if set, else a random seed created once in the
    data directory (mode 0600). Never derived from the sensor name or hostname."""
    from agents import runtime

    seed = runtime.sensor_seed(config, data_dir or runtime.data_dir(config))
    if seed is None:
        # Fake data still needs a seed; this one is random and lasts only this process.
        logging.getLogger(__name__).error(
            "no persistent sensor seed available; using a per-process random seed "
            "(fake data and honeytokens will change on restart)")
        seed = os.urandom(32).hex()
    return seed
