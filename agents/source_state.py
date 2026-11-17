"""Per-source state: how this honeypot treats one attacker (written by agents, read by
the front-ends).

Same mechanism as the overlay: a fenced schema (no free text), one atomic replace per
change after a numbered snapshot, entries that expire, and a hard bound on size. Each
effect (tags, tarpit, budget mode, capture, planted token) carries its own expiry; the
entry expires when its last effect does. Over the size bound, entries are evicted by
priority: plain tags and tarpits first, planted tokens last. Snapshots are pruned to the
last ``keep_snapshots`` plus anything younger than ``keep_days``. The file
lives next to the overlay (``$WINNIE_SOURCE_STATE``, default ``<repo>/decoy/source_state.json``);
in containers that is the overlay volume, written by agents and read-only for front-ends.

Front-ends use ``SourceStateView`` (mtime reload, expired entries ignored).
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Callable, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from agents import REPO_ROOT
from agents.budget import ip_key
from scenarios.tokens import legacy_source_pair, source_pair

SOURCE_STATE_ENV = "WINNIE_SOURCE_STATE"
TAG_RE = r"[a-z][a-z0-9_]{1,31}"
PLAYBOOK_NAME_RE = r"[a-z][a-z0-9_]{1,40}"
MAX_ENTRIES = 10_000
MAX_TARPIT_MS = 5_000
DEFAULT_TTL_HOURS = 72
DEFAULT_KEEP_SNAPSHOTS = 200
DEFAULT_KEEP_DAYS = 7
UTC = datetime.timezone.utc

log = logging.getLogger(__name__)


def source_state_path(override: Optional[os.PathLike | str] = None) -> Path:
    if override:
        return Path(override)
    if os.environ.get(SOURCE_STATE_ENV):
        return Path(os.environ[SOURCE_STATE_ENV])
    return REPO_ROOT / "decoy" / "source_state.json"


def _now() -> datetime.datetime:
    return datetime.datetime.now(UTC)


def _parse(ts: str) -> datetime.datetime:
    dt = datetime.datetime.fromisoformat(ts)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def valid_source_key(value: str) -> bool:
    """An IPv4 address or an IPv6 /64, exactly as ``ip_key`` produces it."""
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=True)
            return net.version == 6 and net.prefixlen == 64
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceEntry(Strict):
    key: str
    tags: list[str] = Field(default_factory=list, max_length=8)
    tarpit_ms: int = Field(default=0, ge=0, le=MAX_TARPIT_MS)
    budget_mode: Literal["normal", "deep", "shallow"] = "normal"
    capture_more: bool = False
    plant_token: bool = False
    reasons: list[str] = Field(default_factory=list, max_length=8)   # playbook names
    updated_at: str
    expires_at: str
    # Per-effect expiry. None means the effect lasts as long as the entry.
    tarpit_until: Optional[str] = None
    mode_until: Optional[str] = None
    capture_until: Optional[str] = None
    token_until: Optional[str] = None
    tag_until: dict[str, str] = Field(default_factory=dict, max_length=8)

    @field_validator("key")
    @classmethod
    def _key(cls, v: str) -> str:
        if not valid_source_key(v):
            raise ValueError("source key must be an IPv4 address or an IPv6 /64")
        return v

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str]) -> list[str]:
        for t in v:
            if not re.fullmatch(TAG_RE, t):
                raise ValueError(f"bad tag {t!r}")
        return v

    @field_validator("reasons")
    @classmethod
    def _reasons(cls, v: list[str]) -> list[str]:
        for t in v:
            if not re.fullmatch(PLAYBOOK_NAME_RE, t):
                raise ValueError(f"bad reason {t!r}")
        return v

    @field_validator("updated_at", "expires_at", "tarpit_until", "mode_until", "capture_until",
                     "token_until")
    @classmethod
    def _ts(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            _parse(v)
        return v

    @field_validator("tag_until")
    @classmethod
    def _tag_until(cls, v: dict[str, str]) -> dict[str, str]:
        for t, ts in v.items():
            if not re.fullmatch(TAG_RE, t):
                raise ValueError(f"bad tag {t!r}")
            _parse(ts)
        return v

    def expired(self, now: Optional[datetime.datetime] = None) -> bool:
        return _parse(self.expires_at) <= (now or _now())

    def effective(self, now: Optional[datetime.datetime] = None) -> "SourceEntry":
        """This entry with every effect whose own expiry has passed switched off."""
        now = now or _now()

        def gone(ts: Optional[str]) -> bool:
            return ts is not None and _parse(ts) <= now

        updates: dict = {}
        if self.tarpit_ms and gone(self.tarpit_until):
            updates["tarpit_ms"] = 0
        if self.budget_mode != "normal" and gone(self.mode_until):
            updates["budget_mode"] = "normal"
        if self.capture_more and gone(self.capture_until):
            updates["capture_more"] = False
        if self.plant_token and gone(self.token_until):
            updates["plant_token"] = False
        tags = [t for t in self.tags if not gone(self.tag_until.get(t))]
        if tags != self.tags:
            updates["tags"] = tags
        return self.model_copy(update=updates) if updates else self

    def priority(self) -> int:
        """Eviction priority: higher survives longer (planted tokens last)."""
        if self.plant_token:
            return 3
        if self.capture_more or self.budget_mode == "deep":
            return 2
        if self.budget_mode == "shallow":
            return 1
        return 0


class SourceState(Strict):
    entries: dict[str, SourceEntry] = Field(default_factory=dict)

    @field_validator("entries")
    @classmethod
    def _bounded(cls, v: dict) -> dict:
        if len(v) > MAX_ENTRIES:
            raise ValueError("too many source entries")
        for k, e in v.items():
            if k != e.key:
                raise ValueError("entry key mismatch")
        return v


# ---- per-source honeytoken ---------------------------------------------------------------

def source_token_name(key: str) -> str:
    return "src_" + hashlib.sha256(key.encode()).hexdigest()[:12]


def source_token(seed: str, key: str) -> tuple[str, str]:
    """(access_key_id, secret) unique to one source, derived from the sensor seed.

    The real AWS format with no fixed marker; the seed-derived secret is what makes the pair
    useless anywhere but here (see ``scenarios.tokens``). Only someone who read this
    source's fake data can know it, so reuse identifies exactly which source took it."""
    return source_pair(seed, key)


def legacy_source_token(seed: str, key: str) -> tuple[str, str]:
    """The pair earlier versions planted for ``key``; recognised, never planted again."""
    return legacy_source_pair(seed, key)


# ---- store (agents side) -------------------------------------------------------------------

def load(path: os.PathLike | str) -> SourceState:
    p = Path(path)
    if not p.exists():
        return SourceState()
    try:
        return SourceState.model_validate_json(p.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError):
        log.error("source state %s is invalid; treating as empty", p)
        return SourceState()


def _atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _prune_entries(entries: dict[str, SourceEntry],
                   now: Optional[datetime.datetime] = None) -> dict[str, SourceEntry]:
    now = now or _now()
    live = {k: e for k, e in entries.items() if not e.expired(now)}
    if len(live) > MAX_ENTRIES:
        keep = sorted(live.values(),
                      key=lambda e: (e.effective(now).priority(), _parse(e.expires_at)))[-MAX_ENTRIES:]
        live = {e.key: e for e in keep}
    return live


def prune(state: SourceState, now: Optional[datetime.datetime] = None) -> SourceState:
    """Drop expired entries; if still over the bound, evict the lowest-priority entries
    (plain tags and tarpits before planted tokens), soonest-expiring first."""
    return SourceState(entries=_prune_entries(state.entries, now))


def prune_snapshots(snaps: Path, keep_snapshots: int = DEFAULT_KEEP_SNAPSHOTS,
                    keep_days: float = DEFAULT_KEEP_DAYS) -> int:
    """Delete snapshots that are neither among the last ``keep_snapshots`` nor younger
    than ``keep_days``. Returns how many were removed."""
    numbered = sorted((int(p.stem), p) for p in snaps.glob("*.json") if p.stem.isdigit())
    cutoff = time.time() - keep_days * 86400
    removed = 0
    for _, p in numbered[:-keep_snapshots] if keep_snapshots > 0 else numbered:
        try:
            if p.stat().st_mtime < cutoff:
                p.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def update(path: os.PathLike | str, state_dir: os.PathLike | str,
           mutate: Callable[[SourceState], SourceState], now: Optional[datetime.datetime] = None,
           dry_run: bool = False, keep_snapshots: int = DEFAULT_KEEP_SNAPSHOTS,
           keep_days: float = DEFAULT_KEEP_DAYS) -> tuple[SourceState, Optional[int]]:
    """Apply ``mutate`` to the current state; snapshot, validate, prune, atomic replace.
    Returns (new state, snapshot number or None when nothing changed / dry run)."""
    path, state_dir = Path(path), Path(state_dir)
    before_text = path.read_text(encoding="utf-8") if path.exists() else None
    current = load(path)
    mutated = mutate(current.model_copy(deep=True))
    # Validate every entry, enforce expiry and the size bound, then build the state.
    entries = {k: SourceEntry.model_validate(e.model_dump()) for k, e in mutated.entries.items()}
    new = SourceState(entries=_prune_entries(entries, now))
    if new == current or dry_run:
        return new, None
    snaps = state_dir / "source-state-snapshots"
    snaps.mkdir(parents=True, exist_ok=True)
    n = max((int(p.stem) for p in snaps.glob("*.json") if p.stem.isdigit()), default=0) + 1
    _atomic_write(snaps / f"{n:06d}.json", json.dumps({"n": n, "previous": before_text}), 0o600)
    _atomic_write(path, new.model_dump_json(indent=2) + "\n")
    prune_snapshots(snaps, keep_snapshots, keep_days)
    return new, n


def new_entry(key: str, now: Optional[datetime.datetime] = None,
              ttl_hours: int = DEFAULT_TTL_HOURS) -> SourceEntry:
    now = now or _now()
    return SourceEntry(key=key, updated_at=now.isoformat(timespec="seconds"),
                       expires_at=(now + datetime.timedelta(hours=ttl_hours)).isoformat(timespec="seconds"))


# ---- view (front-end side) -----------------------------------------------------------------

class SourceStateView:
    """Read-only, mtime-reloaded view used by SSH and the listeners. Never writes."""

    def __init__(self, path: Optional[os.PathLike | str], check_every: float = 2.0) -> None:
        self.path = Path(path) if path else None
        self.check_every = check_every
        self._mtime: Optional[float] = None
        self._checked = float("-inf")
        self._state = SourceState()

    def _refresh(self) -> None:
        now = time.monotonic()
        if self.path is None or now - self._checked < self.check_every:
            return
        self._checked = now
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            self._state, self._mtime = SourceState(), None
            return
        if mtime != self._mtime:
            self._mtime = mtime
            self._state = load(self.path)

    def get(self, ip: str) -> Optional[SourceEntry]:
        self._refresh()
        entry = self._state.entries.get(ip_key(ip))
        if entry is None or entry.expired():
            return None
        return entry.effective()

    def entries(self) -> list[SourceEntry]:
        self._refresh()
        return [e.effective() for e in self._state.entries.values() if not e.expired()]
