"""Spend and concurrency limits for model calls, enforced in code.

Attackers can try to burn money, so every model call is checked here first. When a limit
is hit the caller does not call the model; it returns a canned response.

- Per-session counters (commands, tokens) and concurrency are in memory.
- Daily counters (global and per source) live in a small JSON state file updated
  read-modify-write under an exclusive file lock, so several processes on one host (SSH
  server, listeners) share one daily cap and a restart does not reset the day.
- Tokens are reserved (charged) before the call from an estimate and corrected afterwards,
  so concurrent sessions cannot overshoot a cap by more than one estimate's error. Failed
  and timed-out calls keep their reserved charge.
- IPv6 sources are keyed on their /64.
- Per-source mode from the response playbooks (``mode_provider``): ``shallow`` refuses all
  model calls for that source (canned replies); ``deep`` doubles its per-session and
  per-source limits. The global daily cap never changes.
"""

from __future__ import annotations

import datetime
import fcntl
import ipaddress
import json
import logging
import math
import os
import tempfile
import time
from configparser import ConfigParser
from dataclasses import dataclass, field
from typing import Optional

CANNED_INTERACTIVE = "-bash: fork: retry: Resource temporarily unavailable\r\n"
CANNED_NON_INTERACTIVE = "bash: fork: Resource temporarily unavailable\n"
CANNED_CONNECTION_REFUSED = "ssh_exchange_identification: read: Connection reset by peer\r\n"
SUMMARY_SKIPPED = "Summary skipped: no model-backed commands or budget exhausted. Judgement: UNKNOWN"

OUTPUT_ESTIMATE_TOKENS = 512    # reserved per call for the response
MAX_IP_ENTRIES = 20_000         # bound on per-source daily entries in the state file

log = logging.getLogger(__name__)


def ip_key(ip: str) -> str:
    """Per-source key: the address for IPv4, the /64 for IPv6."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip[:64]
    if addr.version == 6:
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


@dataclass
class BudgetConfig:
    max_line_bytes: int = 2048
    max_commands_per_session: int = 200
    max_tokens_per_session: int = 400_000
    max_tokens_per_ip_per_day: int = 1_000_000
    max_tokens_per_day: int = 3_000_000
    max_concurrent_sessions: int = 20
    max_concurrent_sessions_per_ip: int = 3
    state_file: Optional[str] = None

    @classmethod
    def from_config(cls, config: ConfigParser, base_dir: str,
                    data_dir: Optional[str] = None) -> "BudgetConfig":
        """Build from ``[budget]``. A relative ``state_file`` resolves under ``data_dir``
        (the writable data directory) when given, else under ``base_dir``."""
        section = config["budget"] if "budget" in config else {}
        defaults = cls()
        values: dict = {}
        for name in ("max_line_bytes", "max_commands_per_session", "max_tokens_per_session",
                     "max_tokens_per_ip_per_day", "max_tokens_per_day",
                     "max_concurrent_sessions", "max_concurrent_sessions_per_ip"):
            raw = section.get(name) if name in section else None
            value = int(raw) if raw is not None else getattr(defaults, name)
            if value < 0:
                raise ValueError(f"[budget] {name} must be >= 0")
            values[name] = value
        state_file = str(section.get("state_file", "budget_state.json")).strip()
        if state_file and not os.path.isabs(state_file):
            state_file = os.path.join(data_dir or base_dir, state_file)
        values["state_file"] = state_file or None
        return cls(**values)


def text_units(text: str) -> int:
    """Length in ASCII-character units: an ASCII character is 1, any other character twice
    its UTF-8 size (a CJK character 6, so 1.5 tokens), which keeps estimates for non-ASCII
    text at or above what common tokenizers charge for it."""
    if text.isascii():
        return len(text)
    return sum(1 if c.isascii() else 2 * len(c.encode("utf-8", "surrogatepass")) for c in text)


def estimate_tokens(units: int) -> int:
    """Tokens for ``units`` ASCII-character units (``text_units``), four per token."""
    return max(1, int(units) // 4)


def estimate_text_tokens(text: str) -> int:
    return estimate_tokens(text_units(text))


def count_message_tokens(messages) -> int:
    """History trim counter: LangChain's approximate count (four characters per token plus
    per-message overhead) raised by the extra weight of non-ASCII text."""
    from langchain_core.messages.utils import count_tokens_approximately

    base = count_tokens_approximately(messages)
    extra = 0
    for m in messages:
        content = m.content if isinstance(m.content, str) else str(m.content)
        extra += text_units(content) - len(content)
    return base + extra // 4


def _today() -> str:
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


def _valid_count(value) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool) and value >= 0) or (
        isinstance(value, float) and math.isfinite(value) and value >= 0 and value.is_integer())


class DailyState:
    """{day, global_tokens, ip_tokens} shared through a locked JSON file (or memory only)."""

    def __init__(self, path: Optional[str]) -> None:
        self.path = path
        self.day = _today()
        self.global_tokens = 0
        self.ip_tokens: dict[str, int] = {}
        self._last_error_log = float("-inf")

    def _error(self, message: str, *args) -> None:
        now = time.monotonic()
        if now - self._last_error_log > 60:
            self._last_error_log = now
            log.error(message, *args)

    def _parse(self, text: str) -> tuple[int, dict[str, int]]:
        data = json.loads(text) if text.strip() else {}
        if not isinstance(data, dict):
            raise ValueError("state is not an object")
        if data.get("day") != _today():
            return 0, {}
        g = data.get("global_tokens", 0)
        ips = data.get("ip_tokens", {})
        if not _valid_count(g) or not isinstance(ips, dict):
            raise ValueError("invalid counters")
        out: dict[str, int] = {}
        for k, v in ips.items():
            if not isinstance(k, str) or not _valid_count(v):
                raise ValueError("invalid per-source counter")
            out[k] = int(v)
        return int(g), out

    def update(self, ip: Optional[str], delta: int) -> None:
        """Add ``delta`` tokens (may be negative) and refresh the in-memory view."""
        today = _today()
        if today != self.day:
            self.day, self.global_tokens, self.ip_tokens = today, 0, {}
        if not self.path:
            self._apply(ip, delta)
            return
        try:
            directory = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(directory, exist_ok=True)
            with open(self.path + ".lock", "a+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    text = open(self.path, encoding="utf-8").read() if os.path.exists(self.path) else ""
                    try:
                        self.global_tokens, self.ip_tokens = self._parse(text)
                    except (ValueError, TypeError):
                        log.warning("budget state %s is malformed; starting the day from zero",
                                    self.path)
                        self.global_tokens, self.ip_tokens = 0, {}
                    self.day = today
                    self._apply(ip, delta)
                    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".budget-", suffix=".tmp")
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        json.dump({"day": self.day, "global_tokens": self.global_tokens,
                                   "ip_tokens": self.ip_tokens}, f)
                    os.replace(tmp, self.path)
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
        except OSError as exc:
            # Limits are still enforced in memory, but the day will reset on restart and
            # other processes will not see this spend. Make that loud.
            self._apply(ip, delta)
            self._error("BUDGET STATE NOT PERSISTED: cannot write %s (%s); daily caps reset "
                        "on restart and are not shared across processes", self.path, exc)

    def refresh(self) -> None:
        """Re-read the shared file (other processes' spend). Never writes or creates files."""
        today = _today()
        if today != self.day:
            self.day, self.global_tokens, self.ip_tokens = today, 0, {}
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                try:
                    text = f.read()
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
            self.global_tokens, self.ip_tokens = self._parse(text)
        except (ValueError, TypeError):
            log.warning("budget state %s is malformed; starting the day from zero", self.path)
            self.global_tokens, self.ip_tokens = 0, {}
        except OSError as exc:
            self._error("cannot read budget state %s: %s", self.path, exc)

    def _apply(self, ip: Optional[str], delta: int) -> None:
        self.global_tokens = max(0, self.global_tokens + delta)
        if ip is not None:
            self.ip_tokens[ip] = max(0, self.ip_tokens.get(ip, 0) + delta)
            if len(self.ip_tokens) > MAX_IP_ENTRIES:
                smallest = sorted(self.ip_tokens.items(), key=lambda kv: kv[1])
                for k, _ in smallest[: len(self.ip_tokens) - MAX_IP_ENTRIES]:
                    self.ip_tokens.pop(k, None)


@dataclass
class _SessionState:
    ip: str
    commands: int = 0
    tokens: int = 0
    history_chars: int = 0
    registered: bool = False


@dataclass
class Reservation:
    session_id: str
    ip: str
    tokens: int
    counts_as_command: bool


@dataclass
class Budget:
    config: BudgetConfig = field(default_factory=BudgetConfig)

    def __post_init__(self) -> None:
        # key -> "normal" | "deep" | "shallow"; set by entry points from per-source state.
        self.mode_provider = None
        self._sessions: dict[str, _SessionState] = {}
        self._open_by_ip: dict[str, int] = {}
        self.daily = DailyState(self.config.state_file)
        self.daily.refresh()

    # ---- input --------------------------------------------------------------------------

    def clip(self, text: str) -> str:
        limit = self.config.max_line_bytes
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) <= limit:
            return text
        return encoded[:limit].decode("utf-8", errors="ignore")

    # ---- sessions -----------------------------------------------------------------------

    def session_open(self, session_id: str, ip: str) -> Optional[str]:
        """Admit a session or return the reason it was refused."""
        key = ip_key(ip)
        if sum(self._open_by_ip.values()) >= self.config.max_concurrent_sessions:
            return "max_concurrent_sessions"
        if self._open_by_ip.get(key, 0) >= self.config.max_concurrent_sessions_per_ip:
            return "max_concurrent_sessions_per_ip"
        self._open_by_ip[key] = self._open_by_ip.get(key, 0) + 1
        self._sessions[session_id] = _SessionState(ip=key, registered=True)
        return None

    def session_close(self, session_id: str) -> None:
        state = self._sessions.pop(session_id, None)
        if state is None or not state.registered:
            return
        remaining = self._open_by_ip.get(state.ip, 0) - 1
        if remaining > 0:
            self._open_by_ip[state.ip] = remaining
        else:
            self._open_by_ip.pop(state.ip, None)

    def _session(self, session_id: str, ip: str) -> _SessionState:
        state = self._sessions.get(session_id)
        if state is None:  # not admitted via session_open (direct callers, tests)
            state = _SessionState(ip=ip_key(ip))
            self._sessions[session_id] = state
        return state

    def session_commands(self, session_id: str) -> Optional[int]:
        """Model-backed commands so far, or None if the session was never admitted."""
        state = self._sessions.get(session_id)
        return state.commands if state is not None and state.registered else None

    # ---- model calls --------------------------------------------------------------------

    def mode(self, key: str) -> str:
        if self.mode_provider is None:
            return "normal"
        try:
            mode = self.mode_provider(key)
        except Exception:  # noqa: BLE001 - a broken state view must not lift limits
            return "normal"
        return mode if mode in ("normal", "deep", "shallow") else "normal"

    def _limit_reason(self, state: _SessionState, counts_as_command: bool,
                      extra_tokens: int = 0) -> Optional[str]:
        mode = self.mode(state.ip)
        if mode == "shallow":
            return "shallow_source"
        factor = 2 if mode == "deep" else 1
        if counts_as_command and state.commands >= self.config.max_commands_per_session * factor:
            return "max_commands_per_session"
        session_cap = self.config.max_tokens_per_session * factor
        if state.tokens + extra_tokens > session_cap or state.tokens >= session_cap:
            return "max_tokens_per_session"
        ip_cap = self.config.max_tokens_per_ip_per_day * factor
        ip_used = self.daily.ip_tokens.get(state.ip, 0)
        if ip_used >= ip_cap or ip_used + extra_tokens > ip_cap:
            return "max_tokens_per_ip_per_day"
        if self.daily.global_tokens >= self.config.max_tokens_per_day or \
                self.daily.global_tokens + extra_tokens > self.config.max_tokens_per_day:
            return "max_tokens_per_day"
        return None

    def estimate(self, session_id: str, ip: str, input_text: str) -> int:
        state = self._session(session_id, ip)
        return estimate_tokens(state.history_chars + text_units(input_text)) + OUTPUT_ESTIMATE_TOKENS

    def reserve(self, session_id: str, ip: str, input_text: str,
                counts_as_command: bool = True) -> tuple[Optional[str], Optional[Reservation]]:
        """Check every cap against the estimated cost and charge the estimate up front."""
        state = self._session(session_id, ip)
        est = self.estimate(session_id, ip, input_text)
        self.daily.refresh()
        reason = self._limit_reason(state, counts_as_command, est)
        if reason is not None:
            return reason, None
        if counts_as_command:
            state.commands += 1
        state.tokens += est
        self.daily.update(state.ip, est)
        return None, Reservation(session_id, state.ip, est, counts_as_command)

    def count_command(self, session_id: str, ip: str) -> Optional[str]:
        """Count a command answered without a model (canned reply). Only the per-session
        command cap and the source's mode apply; no tokens are charged."""
        state = self._session(session_id, ip)
        mode = self.mode(state.ip)
        if mode == "shallow":
            return "shallow_source"
        factor = 2 if mode == "deep" else 1
        if state.commands >= self.config.max_commands_per_session * factor:
            return "max_commands_per_session"
        state.commands += 1
        return None

    def commit(self, res: Reservation, input_text: str, output_text: str,
               usage_tokens: Optional[int] = None) -> int:
        """Replace the reserved estimate with the actual cost. Returns tokens charged."""
        state = self._sessions.get(res.session_id) or _SessionState(ip=res.ip)
        state.history_chars += text_units(input_text) + text_units(output_text)
        if usage_tokens is not None and usage_tokens > 0:
            actual = int(usage_tokens)
        else:
            # The whole session history is resent each call, so estimate from it.
            actual = estimate_tokens(state.history_chars)
        delta = actual - res.tokens
        state.tokens = max(0, state.tokens + delta)
        if delta:
            self.daily.update(res.ip, delta)
        return actual

    def record(self, session_id: str, ip: str, input_text: str, output_text: str,
               usage_tokens: Optional[int] = None, counts_as_command: bool = True) -> int:
        """Charge a call that was not reserved (reserve + commit in one step)."""
        state = self._session(session_id, ip)
        if counts_as_command:
            state.commands += 1
        res = Reservation(session_id, state.ip, 0, counts_as_command)
        return self.commit(res, input_text, output_text, usage_tokens)

    # ---- introspection ------------------------------------------------------------------

    @property
    def global_tokens(self) -> int:
        return self.daily.global_tokens

    def ip_tokens(self, ip: str) -> int:
        return self.daily.ip_tokens.get(ip_key(ip), 0)

    def open_sessions(self) -> int:
        return sum(self._open_by_ip.values())
