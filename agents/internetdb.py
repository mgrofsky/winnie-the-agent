"""What Shodan InternetDB already knows about a source address: open ports, host names,
tags, CPEs and known vulnerability ids.

``https://internetdb.shodan.io/<ip>`` answers without a key from data Shodan collected on
its own schedule (refreshed weekly), so the source never sees our lookup. The lookup runs
in the agents process, as one more optional connector of the exchange step that also
fetches sightings, never in a honeypot container. Results go to one local file
(``<state-dir>/internetdb.json``) that triage reads when it writes a record and the console
reads for display. No new connection between containers.

What is sent: one HTTPS GET per address, the address in the path and nothing else. No
cookies, no key, a generic user agent, no data about what the source did. The host is fixed
here (configuration cannot point it elsewhere), the certificate is verified, redirects are
not followed, each call has a 5 s deadline and the answer is capped at 64 KB.

Which addresses: single global unicast source addresses of triage records seen in the last
``lookback_days`` that were judged SUSPICIOUS or MALICIOUS or used a honeytoken, most
important first (``triage.rank``). Never an unverified UDP source, a non-global address or
one inside ``[respond] never_act_on``.

Pacing: one request at a time, at least ``min_interval_seconds`` apart, at most
``max_per_run`` per run and ``max_per_day`` per UTC day. Answers (including "no
information") are kept ``cache_days``. A 429, a 5xx, a redirect, any other unexpected
status or a network failure stops the run and backs off (15 minutes, doubling up to a day).
The file keeps at most ``max_entries`` addresses, oldest dropped first.

The answer is untrusted: host names are attacker-influenced. Every value is checked
against a strict pattern and bound (``triage.ShodanInfo``) and anything else is dropped;
an answer that is not a JSON object for the address asked about is not kept. It is display
only: nothing acts on it and it is never put in a model prompt.

Configuration::

    [connector.internetdb]    ; off by default
    enabled = false
    max_per_run = 100
    max_per_day = 2000
    cache_days = 7
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import logging
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import urlsplit

from pydantic import ValidationError

from agents.addresses import is_public
from agents.budget import ip_key
from agents.connectors.base import pin_address
from agents.connectors.http import ResponseTooLarge, UrlTransport
from agents.triage import (
    CPE_PATTERN,
    CVE_PATTERN,
    HOSTNAME_PATTERN,
    SHODAN_CPE_LEN,
    SHODAN_CPES_MAX,
    SHODAN_HOSTNAME_LEN,
    SHODAN_HOSTNAMES_MAX,
    SHODAN_PORTS_MAX,
    SHODAN_TAG_LEN,
    SHODAN_TAG_PATTERN,
    SHODAN_TAGS_MAX,
    SHODAN_VULNS_MAX,
    UNVERIFIED_SOURCE,
    Judgement,
    ShodanInfo,
    TriageRecord,
    rank,
)

log = logging.getLogger("agents.internetdb")
UTC = datetime.timezone.utc

SECTION = "connector.internetdb"
STATE_FILE = "internetdb.json"
HOST = "internetdb.shodan.io"
BASE_URL = f"https://{HOST}/"
USER_AGENT = "internetdb-client/1"
TIMEOUT = 5.0
MAX_BODY = 64 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
BACKOFF_FIRST_MINUTES = 15
BACKOFF_MAX_MINUTES = 24 * 60

DEFAULTS = {"max_per_run": 100, "max_per_day": 2000, "cache_days": 7.0,
            "lookback_days": 7.0, "min_interval_seconds": 1.0, "max_entries": 5000}
BOUNDS = {"max_per_run": (1, 1000), "max_per_day": (1, 20000), "cache_days": (1.0, 90.0),
          "lookback_days": (1.0, 90.0), "min_interval_seconds": (1.0, 60.0),
          "max_entries": (100, 20000)}
KNOWN_KEYS = {"enabled", *DEFAULTS}

_HOSTNAME_RE = re.compile(HOSTNAME_PATTERN)
_TAG_RE = re.compile(SHODAN_TAG_PATTERN)
_CPE_RE = re.compile(CPE_PATTERN)
_CVE_RE = re.compile(CVE_PATTERN)
# Raw strings longer than this are not looked at, whatever they hold.
_RAW_CAP = 512
# Items looked at per list before the rest is ignored (a list of a million is not read).
_ITEMS_CAP = 1000


class ConfigError(ValueError):
    """Load-time problem. Messages never include configured values."""


class BadAnswer(ValueError):
    """The answer was not kept. Fixed text only."""


# ---- settings ------------------------------------------------------------------------------

@dataclass(frozen=True)
class InternetDbSettings:
    enabled: bool = False
    max_per_run: int = DEFAULTS["max_per_run"]
    max_per_day: int = DEFAULTS["max_per_day"]
    cache_days: float = DEFAULTS["cache_days"]
    lookback_days: float = DEFAULTS["lookback_days"]
    min_interval_seconds: float = DEFAULTS["min_interval_seconds"]
    max_entries: int = DEFAULTS["max_entries"]

    @classmethod
    def from_config(cls, config) -> "InternetDbSettings":
        """Read ``[connector.internetdb]``. Missing or disabled: off. Raises ConfigError.
        There is no key for the destination: it is fixed in code."""
        if config is None or not config.has_section(SECTION):
            return cls()
        sec = config[SECTION]
        try:
            enabled = sec.getboolean("enabled", fallback=False)
        except ValueError:
            raise ConfigError("enabled must be true or false") from None
        unknown = sorted(k for k in sec.keys() if k not in KNOWN_KEYS
                         and k not in config.defaults())
        if unknown:
            # e.g. url or host: the destination is not configurable.
            raise ConfigError("unknown setting (the destination is fixed and cannot be set)")
        if not enabled:
            return cls()
        def num(name: str, raw: Optional[str]):
            default = DEFAULTS[name]
            lo, hi = BOUNDS[name]
            try:
                value = type(default)((raw if raw is not None else str(default)).strip())
            except ValueError:
                raise ConfigError(f"{name} must be a number") from None
            if not lo <= value <= hi:
                raise ConfigError(f"{name} must be between {lo} and {hi}")
            return value

        return cls(enabled=True,
                   max_per_run=num("max_per_run", sec.get("max_per_run")),
                   max_per_day=num("max_per_day", sec.get("max_per_day")),
                   cache_days=num("cache_days", sec.get("cache_days")),
                   lookback_days=num("lookback_days", sec.get("lookback_days")),
                   min_interval_seconds=num("min_interval_seconds",
                                            sec.get("min_interval_seconds")),
                   max_entries=num("max_entries", sec.get("max_entries")))


# ---- the answer ----------------------------------------------------------------------------

def _strings(value, pattern: re.Pattern, cap: int, limit: int, *, lower: bool = False,
             strip_dot: bool = False) -> list[str]:
    """The items of ``value`` that are strings matching ``pattern``, deduplicated, in order,
    at most ``limit``. Anything else is dropped."""
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value[:_ITEMS_CAP]:
        if not isinstance(item, str) or len(item) > _RAW_CAP:
            continue
        # No trimming: surrounding whitespace means the item is dropped, not repaired.
        s = item
        if lower:
            s = s.lower()
        if strip_dot and s.endswith("."):
            s = s[:-1]
        if not s or len(s) > cap or not pattern.fullmatch(s) or s in out:
            continue
        out.append(s)
        if len(out) >= limit:
            break
    return out


def _ports(value) -> list[int]:
    if not isinstance(value, list):
        return []
    found = set()
    for item in value[:_ITEMS_CAP]:
        if isinstance(item, int) and not isinstance(item, bool) and 1 <= item <= 65535:
            found.add(item)
    return sorted(found)[:SHODAN_PORTS_MAX]


def sanitize(body: bytes, address: str, day: str) -> ShodanInfo:
    """The kept part of a 200 answer for ``address``, or BadAnswer. Each list keeps only
    items of the right type and pattern, within its bound."""
    if len(body) > MAX_BODY:
        raise BadAnswer("answer larger than the cap")
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise BadAnswer("answer is not JSON") from None
    if not isinstance(doc, dict):
        raise BadAnswer("answer is not an object")
    ip = doc.get("ip")
    try:
        if not isinstance(ip, str) or len(ip) > 64 or \
                ipaddress.ip_address(ip.strip()) != ipaddress.ip_address(address):
            raise ValueError
    except ValueError:
        raise BadAnswer("answer is for another address") from None
    try:
        return ShodanInfo(
            looked_up=day, found=True, ports=_ports(doc.get("ports")),
            hostnames=_strings(doc.get("hostnames"), _HOSTNAME_RE, SHODAN_HOSTNAME_LEN,
                               SHODAN_HOSTNAMES_MAX, lower=True, strip_dot=True),
            tags=_strings(doc.get("tags"), _TAG_RE, SHODAN_TAG_LEN, SHODAN_TAGS_MAX,
                          lower=True),
            cpes=_strings(doc.get("cpes"), _CPE_RE, SHODAN_CPE_LEN, SHODAN_CPES_MAX),
            vulns=_strings(doc.get("vulns"), _CVE_RE, 20, SHODAN_VULNS_MAX))
    except ValidationError:
        # Not reachable with the filters above; refuse rather than keep something odd.
        raise BadAnswer("answer did not validate") from None


# ---- addresses -----------------------------------------------------------------------------

def lookup_address(value: str) -> Optional[str]:
    """``value`` as the address to ask about, or None: one global unicast address (an
    IPv4-mapped IPv6 address becomes its IPv4 address); networks and anything else, None."""
    if not isinstance(value, str) or not value or len(value) > 64 or "/" in value \
            or "%" in value:
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    text = str(addr)
    return text if is_public(text) else None


def _seen(r: TriageRecord) -> Optional[datetime.datetime]:
    raw = r.last_seen or r.first_seen
    if not raw:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def interesting(r: TriageRecord) -> bool:
    """A record whose source is worth a lookup: judged SUSPICIOUS or MALICIOUS, or it used
    a honeytoken; never an unverified UDP source."""
    if r.unverified_source or r.src_ip == UNVERIFIED_SOURCE:
        return False
    return r.judgement in (Judgement.SUSPICIOUS, Judgement.MALICIOUS) or bool(r.honeytokens)


def select_addresses(records: Iterable[TriageRecord], networks: list,
                     now: datetime.datetime, lookback_days: float) -> list[str]:
    """Addresses to look up, most important first, each once. ``networks`` is ``[respond]
    never_act_on`` parsed; an address inside one is never chosen."""
    since = now - datetime.timedelta(days=lookback_days)
    recent = [r for r in records if interesting(r) and (s := _seen(r)) is not None
              and s >= since]
    out: list[str] = []
    for r in rank(recent):
        addr = lookup_address(r.src_ip)
        if addr is None or addr in out:
            continue
        net = ipaddress.ip_network(ip_key(addr), strict=False)
        if any(net.version == n.version and net.overlaps(n) for n in networks):
            continue
        out.append(addr)
    return out


# ---- the local file ------------------------------------------------------------------------

def state_path(state_dir) -> Path:
    return Path(state_dir) / STATE_FILE


def _parse_time(value) -> Optional[datetime.datetime]:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        dt = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _entry(raw) -> Optional[dict]:
    """One stored entry checked again: ``{"checked_at": datetime, "info": ShodanInfo or
    None}`` (None: the answer was not kept), or None for an entry that does not check."""
    if not isinstance(raw, dict):
        return None
    at = _parse_time(raw.get("checked_at"))
    if at is None:
        return None
    if raw.get("bad") is True:
        return {"checked_at": at, "info": None}
    try:
        return {"checked_at": at, "info": ShodanInfo.model_validate(raw.get("info"))}
    except (ValidationError, TypeError):
        return None


def load_state(path: Path) -> dict:
    """The state file checked entry by entry; anything unreadable starts empty."""
    out: dict = {"day": "", "day_count": 0, "backoff_until": None, "backoff_minutes": 0,
                 "entries": {}}
    try:
        with open(path, "rb") as f:
            body = f.read(MAX_FILE_BYTES + 1)
        if len(body) > MAX_FILE_BYTES:
            raise ValueError("too large")
        doc = json.loads(body.decode("utf-8"))
    except FileNotFoundError:
        return out
    except (OSError, ValueError, UnicodeDecodeError, RecursionError) as exc:
        log.warning("InternetDB file unreadable (%s); starting empty", type(exc).__name__)
        return out
    if not isinstance(doc, dict) or doc.get("version") != 1:
        return out
    day = doc.get("day")
    if isinstance(day, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
        out["day"] = day
    count = doc.get("day_count")
    if isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= 10 ** 6:
        out["day_count"] = count
    out["backoff_until"] = _parse_time(doc.get("backoff_until"))
    minutes = doc.get("backoff_minutes")
    if isinstance(minutes, int) and not isinstance(minutes, bool) \
            and 0 <= minutes <= BACKOFF_MAX_MINUTES:
        out["backoff_minutes"] = minutes
    entries = doc.get("entries")
    if isinstance(entries, dict):
        for key, raw in entries.items():
            addr = lookup_address(key) if isinstance(key, str) else None
            if addr is None or addr != key:
                continue
            e = _entry(raw)
            if e is not None:
                out["entries"][addr] = e
    return out


def _dump(state: dict) -> str:
    entries = {}
    for addr, e in state["entries"].items():
        item: dict = {"checked_at": e["checked_at"].isoformat(timespec="seconds")}
        if e["info"] is None:
            item["bad"] = True
        else:
            item["info"] = e["info"].model_dump(mode="json")
        entries[addr] = item
    until = state.get("backoff_until")
    return json.dumps({"version": 1, "day": state["day"], "day_count": state["day_count"],
                       "backoff_until": until.isoformat(timespec="seconds") if until else None,
                       "backoff_minutes": state["backoff_minutes"], "entries": entries},
                      sort_keys=True, separators=(",", ":")) + "\n"


def bound(state: dict, max_entries: int) -> int:
    """Drop the oldest entries beyond ``max_entries``; returns how many were dropped."""
    entries = state["entries"]
    extra = len(entries) - max_entries
    if extra <= 0:
        return 0
    oldest = sorted(entries, key=lambda a: entries[a]["checked_at"])[:extra]
    for addr in oldest:
        del entries[addr]
    return len(oldest)


def save_state(path: Path, state: dict, max_entries: int) -> None:
    """Bounded by count, then by size (oldest first), and written atomically, owner only."""
    bound(state, max_entries)
    text = _dump(state)
    while len(text.encode("utf-8")) > MAX_FILE_BYTES and state["entries"]:
        bound(state, max(0, len(state["entries"]) - max(1, len(state["entries"]) // 10)))
        text = _dump(state)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---- reading for triage and the console ----------------------------------------------------

class InternetDbReader:
    """Reads the local file for display and for triage. Pure read, never raises; parsed
    again only when the file's size, time or inode changes."""

    def __init__(self, path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._signature: Optional[tuple] = None
        self._entries: dict = {}

    def _load(self) -> dict:
        with self._lock:
            try:
                st = os.stat(self.path)
                signature = (st.st_ino, st.st_size, st.st_mtime_ns)
            except OSError:
                self._signature, self._entries = None, {}
                return self._entries
            if signature != self._signature:
                try:
                    entries = load_state(self.path)["entries"]
                except Exception:  # noqa: BLE001 - display only; a bad file shows nothing
                    entries = {}
                self._signature, self._entries = signature, entries
            return self._entries

    def info(self, value: object) -> Optional[ShodanInfo]:
        """What the file holds for ``value`` (an address), or None."""
        try:
            addr = lookup_address(value) if isinstance(value, str) else None
            if addr is None:
                return None
            e = self._load().get(addr)
            return e["info"] if e is not None else None
        except Exception:  # noqa: BLE001 - never raises into a caller
            return None

    __call__ = info


# ---- the lookup ----------------------------------------------------------------------------

def _request(address: str, base_url: str, transport, resolver) -> tuple[int, bytes]:
    """One GET of ``base_url + address`` to a pinned, public address of the fixed host."""
    host = urlsplit(base_url).hostname or ""
    pinned = pin_address(host, 443) if resolver is None else \
        pin_address(host, 443, resolver=resolver)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    status, body = transport.request("GET", base_url + address, headers, None, TIMEOUT,
                                     pinned, max_bytes=MAX_BODY)
    return int(status), body or b""


def run_lookup(settings: InternetDbSettings, records: Iterable[TriageRecord], networks: list,
               state_dir, *, dry_run: bool = False, transport=None, resolver=None,
               now: Optional[datetime.datetime] = None,
               clock: Callable[[], float] = time.monotonic,
               sleep: Callable[[float], None] = time.sleep,
               base_url: str = BASE_URL) -> dict:
    """Look up the chosen addresses not answered in the last ``cache_days``, within the
    caps, and update the local file. ``base_url`` exists for tests only (configuration has
    no way to set it). Never raises for lookup failures."""
    if not settings.enabled:
        return {"status": "disabled"}
    now = now or datetime.datetime.now(UTC)
    path = state_path(state_dir)
    state = load_state(path)
    summary: dict = {"looked_up": 0, "found": 0, "not_found": 0, "refused": 0}
    until = state["backoff_until"]
    # A back-off further away than the longest one (a clock that jumped back, a bad file)
    # is ignored rather than stopping lookups for good.
    if until is not None and now < until <= now + datetime.timedelta(minutes=BACKOFF_MAX_MINUTES):
        summary["status"] = "backing off"
        summary["until"] = until.isoformat(timespec="seconds")
        return summary
    today = now.date().isoformat()
    if state["day"] != today:
        state["day"], state["day_count"] = today, 0
    fresh = datetime.timedelta(days=settings.cache_days)
    due = [a for a in select_addresses(records, networks, now, settings.lookback_days)
           if a not in state["entries"]
           or now - state["entries"][a]["checked_at"] >= fresh
           or state["entries"][a]["checked_at"] > now]
    # Never looked up first, then the oldest answers.
    due.sort(key=lambda a: (a in state["entries"],
                            state["entries"][a]["checked_at"] if a in state["entries"]
                            else now))
    room = min(settings.max_per_run, settings.max_per_day - state["day_count"])
    summary["due"] = len(due)
    if room <= 0:
        summary["status"] = "daily cap reached"
        return summary
    batch = due[:room]
    if dry_run:
        summary.update(status="would look up", addresses=len(batch), dry_run=True)
        return summary
    if not batch:
        summary["status"] = "nothing due"
        return summary
    transport = transport if transport is not None else UrlTransport()
    last_start: Optional[float] = None
    stopped: Optional[str] = None
    for addr in batch:
        if last_start is not None:
            wait = last_start + settings.min_interval_seconds - clock()
            if wait > 0:
                sleep(wait)
        last_start = clock()
        state["day_count"] += 1
        summary["looked_up"] += 1
        try:
            status, body = _request(addr, base_url, transport, resolver)
        except ResponseTooLarge:
            log.warning("InternetDB answer not kept: larger than %d bytes", MAX_BODY)
            state["entries"][addr] = {"checked_at": now, "info": None}
            summary["refused"] += 1
            continue
        except Exception as exc:  # noqa: BLE001 - unreachable, timeout, TLS, DNS
            stopped = f"request failed ({type(exc).__name__})"
            break
        if status == 200:
            try:
                info = sanitize(body, addr, today)
            except BadAnswer as exc:
                log.warning("InternetDB answer not kept: %s", exc)
                state["entries"][addr] = {"checked_at": now, "info": None}
                summary["refused"] += 1
            else:
                state["entries"][addr] = {"checked_at": now, "info": info}
                summary["found"] += 1
            state["backoff_minutes"] = 0
        elif status == 404:
            state["entries"][addr] = {"checked_at": now,
                                      "info": ShodanInfo(looked_up=today, found=False)}
            summary["not_found"] += 1
            state["backoff_minutes"] = 0
        else:
            # 429, 5xx, a redirect (never followed) or anything else unexpected.
            stopped = f"HTTP {status}"
            break
    if stopped is not None:
        minutes = min(BACKOFF_MAX_MINUTES,
                      max(BACKOFF_FIRST_MINUTES, state["backoff_minutes"] * 2))
        state["backoff_minutes"] = minutes
        state["backoff_until"] = now + datetime.timedelta(minutes=minutes)
        summary["stopped"] = stopped
        summary["backoff_minutes"] = minutes
        log.warning("InternetDB lookups stopped: %s; next try in %d minutes", stopped, minutes)
    else:
        state["backoff_until"] = None
    try:
        save_state(path, state, settings.max_entries)
    except OSError as exc:
        summary["error"] = f"cannot write the local file ({type(exc).__name__})"
        log.error("InternetDB: %s", summary["error"])
    summary.setdefault("status", "stopped" if stopped else "done")
    return summary


def reader_from_config(config, state_dir) -> Optional[InternetDbReader]:
    """The reader for triage and the console when ``[connector.internetdb]`` is enabled,
    else None (the feature is off and nothing is shown or stored). Never raises."""
    try:
        settings = InternetDbSettings.from_config(config)
    except ConfigError as exc:
        log.warning("[%s]: %s; InternetDB details are off", SECTION, exc)
        return None
    except Exception:  # noqa: BLE001 - a bad config never stops triage or the console
        return None
    return InternetDbReader(state_path(state_dir)) if settings.enabled else None
