"""Sightings: where else in the operator's environment a listed address was seen.

The operator's environment produces one JSON document, by whatever means::

    {"version": 1, "generated_at": "2026-11-18T09:00:00Z",
     "sightings": [{"address": "198.51.100.7", "where": "prod-account",
                    "service": "tcp/443", "first_seen": "2026-11-17T22:10:00Z",
                    "last_seen": "2026-11-18T08:55:00Z", "count": 14,
                    "source": "threat-list finding"}]}

The console shows them next to the blocklist entry they name. They are display only:
nothing here or anywhere else acts on a sighting.

Everything in the file is untrusted. ``parse`` checks it strictly and the whole file is
refused on the first problem: size cap, entry count cap, exact types, valid addresses
(an IPv6 address is matched by its /64, like every source key), parseable timestamps with
``first_seen <= last_seen``, a non-negative integer count, and short string fields with
control and other invisible characters removed. Unknown keys are ignored. A refused file
never replaces a good one: the console keeps showing the last good copy it read and logs
the problem once, and a fetch keeps the local file it has.

Configuration::

    [sightings]
    #path = <state-dir>/sightings.json
    max_bytes = 1048576
    max_entries = 5000
    stale_hours = 48

    [connector.sightings]     ; optional fetch, off by default
    enabled = false
    kind = s3                 ; s3 (GetObject of one fixed key) | https (GET)
    interval_minutes = 15

The fetch writes the local file atomically, and only after the fetched copy passed
``parse``.
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
import threading
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from agents.budget import ip_key
from agents.connectors.base import ConnectorResult, DestinationError
from agents.connectors.http import ConfigError as HttpConfigError
from agents.connectors.http import EndpointConfig, HttpEndpoint, UrlTransport, load_endpoint
from agents.objectstore import ConfigError as StoreConfigError
from agents.objectstore import ObjectTooLarge, S3Target, error_code, get_object
from agents.ship import _record_event

log = logging.getLogger("agents.sightings")
UTC = datetime.timezone.utc

SIGHTINGS = "sightings"
SECTION = "connector.sightings"
DEFAULT_FILE = "sightings.json"
FETCH_STATE_FILE = "sightings_fetch_state.json"
KINDS = ("s3", "https")
DEFAULT_MAX_BYTES = 1024 * 1024
MAX_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_ENTRIES = 5000
MAX_MAX_ENTRIES = 100_000
DEFAULT_STALE_HOURS = 48.0
DEFAULT_INTERVAL_MINUTES = 15.0
FIELD_CAP = 64
MAX_COUNT = 10 ** 12
_TS_CAP = 40


class ConfigError(ValueError):
    """Load-time problem. Messages never include configured values."""


class InvalidSightings(ValueError):
    """The document was refused. Messages are fixed text plus an entry index."""


# ---- settings ------------------------------------------------------------------------------

@dataclass(frozen=True)
class SightingsSettings:
    path: Optional[str] = None            # default <state-dir>/sightings.json
    max_bytes: int = DEFAULT_MAX_BYTES
    max_entries: int = DEFAULT_MAX_ENTRIES
    stale_hours: float = DEFAULT_STALE_HOURS

    def file(self, state_dir) -> Path:
        return Path(self.path) if self.path else Path(state_dir) / DEFAULT_FILE

    @classmethod
    def from_config(cls, config) -> "SightingsSettings":
        """Read ``[sightings]``; missing keys keep their defaults. Raises ConfigError."""
        if config is None or not config.has_section(SIGHTINGS):
            return cls()
        local = config[SIGHTINGS]
        path = local.get("path", "").strip() or None
        if path is not None and not os.path.isabs(path):
            raise ConfigError("[sightings] path must be an absolute path")

        def _num(name: str, default, lo, hi, kind=int):
            try:
                value = kind(local.get(name, str(default)).strip())
            except ValueError:
                raise ConfigError(f"[sightings] {name} must be a number") from None
            if not lo <= value <= hi:
                raise ConfigError(f"[sightings] {name} must be between {lo} and {hi}")
            return value

        return cls(path=path,
                   max_bytes=_num("max_bytes", DEFAULT_MAX_BYTES, 1024, MAX_MAX_BYTES),
                   max_entries=_num("max_entries", DEFAULT_MAX_ENTRIES, 1, MAX_MAX_ENTRIES),
                   stale_hours=_num("stale_hours", DEFAULT_STALE_HOURS, 0.1, 24 * 365.0, float))


@dataclass(frozen=True)
class FetchSettings:
    enabled: bool = False
    kind: str = ""
    interval_minutes: float = DEFAULT_INTERVAL_MINUTES
    s3: Optional[S3Target] = None
    https: Optional[EndpointConfig] = None

    @classmethod
    def from_config(cls, config) -> "FetchSettings":
        """Read ``[connector.sightings]``. Missing or disabled: off. Raises ConfigError."""
        if config is None or not config.has_section(SECTION):
            return cls()
        fetch = config[SECTION]
        try:
            enabled = fetch.getboolean("enabled", fallback=False)
        except ValueError:
            raise ConfigError("enabled must be true or false") from None
        if not enabled:
            return cls()
        kind = fetch.get("kind", "").strip().lower()
        if kind not in KINDS:
            raise ConfigError("kind must be s3 or https")
        try:
            interval = float(fetch.get("interval_minutes", str(DEFAULT_INTERVAL_MINUTES)))
        except ValueError:
            raise ConfigError("interval_minutes must be a number") from None
        if not 1 <= interval <= 24 * 60:
            raise ConfigError("interval_minutes must be between 1 and 1440")
        try:
            if kind == "s3":
                return cls(enabled=True, kind=kind, interval_minutes=interval,
                           s3=S3Target.validate(
                               fetch.get("bucket", ""), fetch.get("key", ""),
                               fetch.get("region", ""), fetch.get("bucket_owner", ""),
                               fetch.get("endpoint_url", ""), fetch.get("timeout", ""),
                               fetch.get("allow_private", "")))
            return cls(enabled=True, kind=kind, interval_minutes=interval,
                       https=load_endpoint(fetch, "sightings"))
        except (StoreConfigError, HttpConfigError, DestinationError) as exc:
            raise ConfigError(str(exc)) from None


# ---- validation ----------------------------------------------------------------------------

def clean(value: str, cap: int = FIELD_CAP) -> str:
    """Control, format and other invisible characters removed, whitespace collapsed, capped."""
    out = []
    for c in value:
        category = unicodedata.category(c)
        if c in "\t\r\n" or category in ("Zl", "Zp"):
            out.append(" ")
        elif not category.startswith("C"):
            out.append(c)
    return re.sub(r"\s+", " ", "".join(out)).strip()[:cap]


def _timestamp(value, where: str) -> datetime.datetime:
    if not isinstance(value, str) or not value or len(value) > _TS_CAP:
        raise InvalidSightings(f"{where}: not a timestamp")
    try:
        dt = datetime.datetime.fromisoformat(value.strip())
        # A time at the edge of the calendar with an offset that moves it past year 1 or
        # 9999 overflows on conversion; it is not a timestamp either.
        return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC)
    except (ValueError, OverflowError):
        raise InvalidSightings(f"{where}: not a timestamp") from None


def _address_key(value, where: str) -> str:
    """The source key of a sighting: the address for IPv4, the /64 for IPv6."""
    if not isinstance(value, str) or not value or len(value) > 64 or "%" in value:
        raise InvalidSightings(f"{where}: not an address")
    try:
        if "/" in value:
            net = ipaddress.ip_network(value.strip(), strict=True)
            if (net.version, net.prefixlen) not in ((4, 32), (6, 64), (6, 128)):
                raise ValueError
            return ip_key(str(net.network_address))
        return ip_key(str(ipaddress.ip_address(value.strip())))
    except ValueError:
        raise InvalidSightings(f"{where}: not an address") from None


def _text(item: dict, name: str, where: str) -> str:
    value = item.get(name, "")
    if not isinstance(value, str) or len(value) > 4 * FIELD_CAP:
        raise InvalidSightings(f"{where}: {name} must be a short string")
    return clean(value)


@dataclass(frozen=True)
class Sighting:
    key: str
    where: str
    service: str
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    count: int
    source: str

    def to_dict(self) -> dict:
        return {"address": self.key, "where": self.where, "service": self.service,
                "first_seen": self.first_seen.isoformat(timespec="seconds"),
                "last_seen": self.last_seen.isoformat(timespec="seconds"),
                "count": self.count, "source": self.source}


@dataclass(frozen=True)
class SightingsDoc:
    generated_at: datetime.datetime
    sightings: tuple[Sighting, ...]

    def to_dict(self) -> dict:
        return {"version": 1, "generated_at": self.generated_at.isoformat(timespec="seconds"),
                "sightings": [s.to_dict() for s in self.sightings]}


def parse(body: bytes, max_bytes: int = DEFAULT_MAX_BYTES,
          max_entries: int = DEFAULT_MAX_ENTRIES) -> SightingsDoc:
    """The validated document, or InvalidSightings on the first problem."""
    if len(body) > max_bytes:
        raise InvalidSightings(f"larger than {max_bytes} bytes")
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise InvalidSightings("not JSON") from None
    if not isinstance(doc, dict) or doc.get("version") != 1 or isinstance(doc.get("version"), bool):
        raise InvalidSightings("not a version 1 sightings document")
    generated = _timestamp(doc.get("generated_at"), "generated_at")
    items = doc.get("sightings")
    if not isinstance(items, list):
        raise InvalidSightings("sightings must be a list")
    if len(items) > max_entries:
        raise InvalidSightings(f"more than {max_entries} sightings")
    out = []
    for i, item in enumerate(items):
        where = f"sighting {i}"
        if not isinstance(item, dict):
            raise InvalidSightings(f"{where}: not an object")
        count = item.get("count")
        if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= MAX_COUNT:
            raise InvalidSightings(f"{where}: count must be a non-negative integer")
        first = _timestamp(item.get("first_seen"), f"{where}: first_seen")
        last = _timestamp(item.get("last_seen"), f"{where}: last_seen")
        if first > last:
            raise InvalidSightings(f"{where}: first_seen is after last_seen")
        out.append(Sighting(key=_address_key(item.get("address"), where),
                            where=_text(item, "where", where),
                            service=_text(item, "service", where),
                            first_seen=first, last_seen=last, count=count,
                            source=_text(item, "source", where)))
    return SightingsDoc(generated_at=generated, sightings=tuple(out))


def _read_capped(path: Path, max_bytes: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(max_bytes + 1)


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    # Owner only: the file says where an address was seen elsewhere, and only the sensor's
    # own processes (one user) read it.
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ---- reading for the console ---------------------------------------------------------------

@dataclass
class _Cache:
    signature: Optional[tuple] = None
    good: Optional[SightingsDoc] = None
    error: Optional[str] = None
    logged: set = field(default_factory=set)


class SightingsReader:
    """Reads the local file for display. Pure read: nothing is created or written. The file
    is parsed again only when its size, time or inode changes; a refused file keeps the
    last good copy on show and is logged once."""

    def __init__(self, path: Path, settings: SightingsSettings) -> None:
        self.path, self.settings = Path(path), settings
        self._lock = threading.Lock()
        self._cache = _Cache()

    def read(self, now: datetime.datetime) -> dict:
        """``{"state", "error", "generated_at", "age_hours", "stale", "doc"}``; ``state`` is
        ``ok``, ``missing`` or ``invalid`` (then ``doc`` is the last good copy, if any)."""
        with self._lock:
            try:
                st = os.stat(self.path)
                signature = (st.st_ino, st.st_size, st.st_mtime_ns)
            except OSError:
                return self._view(None, "missing", None, now)
            c = self._cache
            if signature != c.signature:
                # The outcome is worked out first and stored with its signature after, so
                # a failure part way can never leave this copy remembered as a good read.
                good, error = c.good, None
                try:
                    good = parse(_read_capped(self.path, self.settings.max_bytes),
                                 self.settings.max_bytes, self.settings.max_entries)
                except InvalidSightings as exc:
                    error = str(exc)[:200]
                except OSError as exc:
                    error = f"cannot read the file ({type(exc).__name__})"
                except Exception as exc:  # noqa: BLE001 - any other failure is a refusal
                    error = f"refused: the file could not be checked ({type(exc).__name__})"
                c.signature, c.good, c.error = signature, good, error
                if c.error and signature not in c.logged:
                    c.logged = {signature}
                    log.warning("sightings file refused (%s); showing the last good copy",
                                c.error)
            return self._view(c.good, "invalid" if c.error else "ok", c.error, now)

    def _view(self, doc: Optional[SightingsDoc], state: str, error: Optional[str],
              now: datetime.datetime) -> dict:
        out: dict = {"state": state, "error": error, "generated_at": None, "age_hours": None,
                     "stale": False, "stale_hours": self.settings.stale_hours, "doc": doc}
        if doc is not None:
            age = (now - doc.generated_at).total_seconds() / 3600
            out.update(generated_at=doc.generated_at.isoformat(timespec="seconds"),
                       age_hours=round(age, 2), stale=age > self.settings.stale_hours)
        return out


def by_address(doc: Optional[SightingsDoc], keys) -> dict[str, list[Sighting]]:
    """Sightings grouped by listed key; sightings of any other address are ignored."""
    wanted = set(keys)
    out: dict[str, list[Sighting]] = {}
    if doc is None:
        return out
    for s in doc.sightings:
        if s.key in wanted:
            out.setdefault(s.key, []).append(s)
    return out


# ---- fetch ---------------------------------------------------------------------------------

def _fetch_state(state_dir: Path) -> dict:
    try:
        data = json.loads((state_dir / FETCH_STATE_FILE).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _https_get(cfg: EndpointConfig, state_dir: Path, transport, resolver,
               max_bytes: int) -> bytes:
    got: dict = {}

    def keep(data: bytes) -> ConnectorResult:
        got["body"] = data
        return ConnectorResult(True, "fetched")

    endpoint = HttpEndpoint(cfg, state_dir, transport if transport is not None else UrlTransport(),
                            resolver)
    result = endpoint.perform("GET", cfg.url, None, on_body=keep, max_bytes=max_bytes)
    if not result.ok:
        raise RuntimeError(f"GET failed: {result.status[:80]}")
    return got.get("body", b"")


def run_fetch(fetch: FetchSettings, local: SightingsSettings, state_dir, *,
              dry_run: bool = False, client_factory=None, transport=None, resolver=None,
              now: Optional[datetime.datetime] = None) -> dict:
    """Fetch the sightings document at most once per ``interval_minutes`` and replace the
    local file only with a copy that passed ``parse``. Never raises for fetch failures."""
    if not fetch.enabled:
        return {"status": "disabled"}
    state_dir = Path(state_dir)
    now = now or datetime.datetime.now(UTC)
    st = _fetch_state(state_dir)
    try:
        last = datetime.datetime.fromisoformat(str(st.get("attempted_at", "")))
        # A time in the future (a clock that jumped back, or a bad file) is not a reason
        # to stop fetching.
        if datetime.timedelta(0) <= now - last < datetime.timedelta(minutes=fetch.interval_minutes):
            return {"status": "not due", "kind": fetch.kind}
    except (ValueError, TypeError, OverflowError):
        pass   # missing, malformed or naive: treat the fetch as due
    if dry_run:
        return {"status": "would fetch", "kind": fetch.kind, "dry_run": True}
    summary: dict = {"kind": fetch.kind}
    new_state = {"attempted_at": now.isoformat(timespec="seconds"),
                 "refused_sha256": st.get("refused_sha256")}
    try:
        if fetch.kind == "s3":
            body = get_object(fetch.s3, local.max_bytes, client_factory)
        else:
            body = _https_get(fetch.https, state_dir, transport, resolver, local.max_bytes)
    except ObjectTooLarge:
        summary["error"] = f"the sightings object is larger than {local.max_bytes} bytes"
    except Exception as exc:  # noqa: BLE001 - a failed fetch never stops a run
        summary["error"] = (str(exc)[:100] if isinstance(exc, RuntimeError)
                            else f"GetObject failed: {error_code(exc)}")
    else:
        try:
            doc = parse(body, local.max_bytes, local.max_entries)
        except Exception as exc:  # noqa: BLE001 - anything parse raises is a refusal
            digest = hashlib.sha256(body if isinstance(body, bytes) else b"").hexdigest()
            why = str(exc)[:120] if isinstance(exc, InvalidSightings) \
                else f"could not be checked ({type(exc).__name__})"
            summary["error"] = f"fetched document refused: {why}"
            summary["kept"] = "the last good local file"
            if st.get("refused_sha256") == digest:
                summary["logged"] = False   # the same bad copy as before: logged once already
            new_state["refused_sha256"] = digest
        else:
            # Compact, and checked against the reader's own limit: a copy the console would
            # refuse must never replace a good one.
            text = json.dumps(doc.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"
            try:
                if len(text.encode("utf-8")) > local.max_bytes:
                    raise InvalidSightings(
                        f"the document is larger than {local.max_bytes} bytes once normalised")
                _atomic_write(local.file(state_dir), text)
            except InvalidSightings as exc:
                summary["error"] = f"fetched document refused: {str(exc)[:120]}"
                summary["kept"] = "the last good local file"
            except OSError as exc:
                summary["error"] = f"cannot write the local file ({type(exc).__name__})"
            else:
                new_state["refused_sha256"] = None
                summary.update(status="fetched", sightings=len(doc.sightings))
    try:
        _atomic_write(state_dir / FETCH_STATE_FILE, json.dumps(new_state) + "\n")
    except OSError as exc:
        summary.setdefault("error", f"cannot write the fetch state ({type(exc).__name__})")
    if "error" in summary and summary.pop("logged", True):
        log.error("sightings fetch: %s", summary["error"])
        _record_event(state_dir, {"timestamp": now.isoformat(timespec="seconds"),
                                  "event": "sightings_fetch_failed",
                                  "error": summary["error"]})
    return summary
