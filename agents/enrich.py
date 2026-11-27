"""Where a source address is: country, region, city and network owner, from files on disk.

The honeypot's containers have no internet access, so this makes no network call of any
kind (no web lookup, no DNS). It reads MaxMind-format ``.mmdb`` files the operator puts on
disk with the optional ``maxminddb`` package: one for location, one for the network (AS
number and owner). Both free sources work, MaxMind GeoLite2 City / ASN and DB-IP Lite City /
ASN; their field names differ slightly and both shapes are read (``_location``,
``_network``).

- Off is normal. With the package missing, no path set, or a file missing or unreadable,
  the lookup answers None and everything else works as before. One log line at start says
  which. Nothing here raises into a caller.
- Non-global addresses (private, loopback, link-local, shared CGNAT space, documentation,
  multicast, reserved) are labelled without a lookup.
- Everything read from a file is data: names are cleaned with ``triage.clean_text`` (control
  and format characters removed, clipped), the country code must be two capital letters and
  the AS number an unsigned 32-bit integer, or they are dropped.
- Readers stay open and answers are cached (bounded LRU), so a page of 200 addresses costs
  a few hundred dictionary hits. A replaced file is picked up without a restart: its
  modification time, size and inode are checked at most every ``recheck_seconds``. Replace
  files by renaming a new copy into place (an in-place overwrite of a memory-mapped file
  can give garbled answers until the next check).

``point(address)`` gives the City record's latitude and longitude, rounded to one decimal
(city level), for the console's map. It is not stored on triage records.

Reverse DNS (a PTR name) needs a live query and is not done here; ``GeoInfo.rdns`` is left
for it.
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Optional

from agents.triage import GEO_NAME_MAX, GEO_ORG_MAX, GeoInfo, clean_text

log = logging.getLogger("agents.enrich")

SECTION = "geoip"
CACHE_SIZE = 4096
RECHECK_SECONDS = 60.0
ATTRIBUTION_MAX = 200
# A network wider than these has no single place; it is not looked up.
MIN_PREFIX = {4: 24, 6: 48}

_SHARED = ipaddress.ip_network("100.64.0.0/10")
_DOCUMENTATION = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20"))


class ConfigError(ValueError):
    """``[geoip]`` is malformed. Messages never include configured values."""


@dataclass(frozen=True)
class GeoSettings:
    city_db: Optional[str] = None
    asn_db: Optional[str] = None
    attribution: str = ""

    @classmethod
    def from_config(cls, config) -> "GeoSettings":
        """Read ``[geoip]``; missing section or keys mean off. Raises ConfigError."""
        if config is None or not config.has_section(SECTION):
            return cls()
        local = config[SECTION]
        paths = {}
        for key in ("city_db", "asn_db"):
            value = local.get(key, "").strip() or None
            if value is not None and not os.path.isabs(value):
                raise ConfigError(f"[geoip] {key} must be an absolute path")
            paths[key] = value
        return cls(attribution=clean_text(local.get("attribution", ""), ATTRIBUTION_MAX),
                   **paths)


# ---- addresses ------------------------------------------------------------------------------

def non_global_label(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Optional[str]:
    """A short label for an address no database places, or None for a global one."""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.version == 4 and ip in _SHARED:
        return "shared address (CGNAT)"
    if any(ip.version == n.version and ip in n for n in _DOCUMENTATION):
        return "documentation address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_private:
        return "private address"
    if not ip.is_global:
        return "reserved address"
    return None


def parse_target(value: object) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """The address to look up for ``value``: an address, or a network no wider than a /24
    (IPv4) or /48 (IPv6), as campaign sources (an IPv6 /64) and blocklist entries are."""
    if not isinstance(value, str) or not 2 <= len(value) <= 64:
        return None
    text = value.strip()
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            if net.prefixlen < MIN_PREFIX[net.version]:
                return None
            ip = net.network_address
        else:
            ip = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


# ---- reading the two record shapes ------------------------------------------------------------

def _name(node: object) -> str:
    """English name of a GeoLite2 / DB-IP node (``{"names": {"en": ...}}``), else the first
    name given."""
    if not isinstance(node, dict):
        return ""
    names = node.get("names")
    if not isinstance(names, dict):
        return ""
    value = names.get("en")
    if not isinstance(value, str) or not value.strip():
        value = next((v for v in names.values() if isinstance(v, str) and v.strip()), "")
    return clean_text(value, GEO_NAME_MAX)


def _country_code(node: object) -> str:
    code = node.get("iso_code") if isinstance(node, dict) else None
    return code if isinstance(code, str) and len(code) == 2 and code.isascii() \
        and code.isalpha() and code.isupper() else ""


def _location(rec: object) -> dict:
    """GeoLite2 City and DB-IP Lite City records: ``country.iso_code``, ``country.names``,
    ``subdivisions[0].names`` (GeoLite2 adds ``iso_code``, DB-IP Lite has names only),
    ``city.names`` (GeoLite2 adds ``geoname_id``). A record without a country (an anycast
    or satellite range) falls back to ``registered_country``."""
    if not isinstance(rec, dict):
        return {}
    country = rec.get("country")
    if not isinstance(country, dict):
        country = rec.get("registered_country")
    subs = rec.get("subdivisions")
    region = _name(subs[0]) if isinstance(subs, list) and subs else ""
    return {"country_code": _country_code(country), "country": _name(country),
            "region": region, "city": _name(rec.get("city"))}


def _point(rec: object) -> Optional[tuple[float, float]]:
    """``location.latitude`` and ``location.longitude`` of a City record (both shapes), rounded
    to one decimal (city level, about 11 km), or None when either is missing or out of
    range."""
    loc = rec.get("location") if isinstance(rec, dict) else None
    if not isinstance(loc, dict):
        return None
    lat, lon = loc.get("latitude"), loc.get("longitude")
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (lat, lon)):
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):   # also refuses NaN
        return None
    return (round(float(lat), 1), round(float(lon), 1))


def _asn(value: object) -> Optional[int]:
    if isinstance(value, str):
        text = value.strip().upper()
        text = text[2:] if text.startswith("AS") else text
        value = int(text) if text.isdigit() and len(text) <= 10 else None
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value < 2 ** 32 else None


def _network(rec: object) -> dict:
    """GeoLite2 ASN and DB-IP Lite ASN records (the same keys; DB-IP's metadata says
    ``compat=GeoLite2-ASN``): ``autonomous_system_number`` and
    ``autonomous_system_organization``. A number written as ``"AS64500"`` is accepted."""
    if not isinstance(rec, dict):
        return {}
    return {"asn": _asn(rec.get("autonomous_system_number")),
            "as_org": clean_text(rec.get("autonomous_system_organization"), GEO_ORG_MAX)}


# ---- open files -----------------------------------------------------------------------------

def _maxminddb_opener() -> Optional[Callable[[str], object]]:
    try:
        import maxminddb   # optional: pip install 'winnie-the-agent[geoip]'
    except ImportError:
        return None
    return lambda path: maxminddb.open_database(path)


def _built(reader: object) -> str:
    try:
        epoch = reader.metadata().build_epoch
        if isinstance(epoch, int) and not isinstance(epoch, bool) and 0 < epoch < 2 ** 40:
            return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).date().isoformat()
    except Exception:  # noqa: BLE001, S110 - metadata is optional
        pass
    return ""


class _Db:
    """One database file: its reader, and the stat it was opened at."""

    def __init__(self, role: str, path: str, opener: Callable[[str], object]) -> None:
        self.role, self.path, self.opener = role, path, opener
        self.reader: object = None
        self.stat: Optional[tuple] = None
        self.built = ""
        self.problem = ""

    @staticmethod
    def _stat(path: str) -> Optional[tuple]:
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def refresh(self) -> bool:
        """Open the file, or reopen it when it changed. Returns whether the reader changed.
        A file that is gone or will not open keeps the reader already open, if any."""
        st = self._stat(self.path)
        if st is None:
            self.problem = "missing or not readable"
            return False
        if st == self.stat and self.reader is not None:
            return False
        try:
            reader = self.opener(self.path)
        except Exception as exc:  # noqa: BLE001 - a bad file turns this database off
            self.problem = f"cannot be opened ({type(exc).__name__})"
            self.stat = st   # not retried until the file changes again
            return False
        old, self.reader, self.stat = self.reader, reader, st
        self.built, self.problem = _built(reader), ""
        if old is not None:
            log.info("IP lookup: %s database %s reloaded", self.role, os.path.basename(self.path))
            _close(old)
        return True

    def get(self, ip: str) -> object:
        if self.reader is None:
            return None
        try:
            return self.reader.get(ip)
        except Exception:  # noqa: BLE001 - a garbled file answers nothing, never raises
            return None

    def describe(self) -> str:
        name = os.path.basename(self.path)[:80]
        if self.reader is None:
            return f"{self.role} {name} {self.problem or 'not open'}"
        return f"{self.role} {name}" + (f" (built {self.built})" if self.built else "")


def _close(reader: object) -> None:
    try:
        reader.close()
    except Exception:  # noqa: BLE001, S110 - best-effort cleanup
        pass


class GeoLookup:
    """``lookup(address) -> GeoInfo | None``; also callable. Thread-safe, never raises.

    ``opener`` (path -> reader with ``get`` and ``metadata``) is a test seam; the default
    uses ``maxminddb.open_database``, and is None when the package is not installed."""

    def __init__(self, settings: Optional[GeoSettings] = None, *,
                 opener: Optional[Callable[[str], object]] = None,
                 cache_size: int = CACHE_SIZE, recheck_seconds: float = RECHECK_SECONDS,
                 clock: Callable[[], float] = time.monotonic, log_status: bool = True) -> None:
        self.settings = settings or GeoSettings()
        self.attribution = self.settings.attribution
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, Optional[GeoInfo]] = OrderedDict()
        self._points: OrderedDict[str, Optional[tuple[float, float]]] = OrderedDict()
        self._cache_size = max(1, cache_size)
        self._recheck = recheck_seconds
        self._clock = clock
        self._dbs: list[_Db] = []
        self._checked = float("-inf")
        self.reason = ""
        wanted = [(role, path) for role, path in (("location", self.settings.city_db),
                                                  ("network", self.settings.asn_db)) if path]
        if not wanted:
            self.reason = "no database path set in [geoip]"
        else:
            opener = opener if opener is not None else _maxminddb_opener()
            if opener is None:
                self.reason = "the maxminddb package is not installed"
            else:
                self._dbs = [_Db(role, path, opener) for role, path in wanted]
                with self._lock:
                    self._refresh(force=True)
        if log_status:
            log.info("IP lookup: %s", self.status)

    # -- state --

    @property
    def enabled(self) -> bool:
        return any(db.reader is not None for db in self._dbs)

    @property
    def status(self) -> str:
        """One line: on (with each file and its build date) or off and why."""
        if not self._dbs:
            return f"off: {self.reason}"
        parts = "; ".join(db.describe() for db in self._dbs)
        return ("on: " if self.enabled else "off: ") + parts

    def _refresh(self, force: bool = False) -> None:
        now = self._clock()
        if not force and now - self._checked < self._recheck:
            return
        self._checked = now
        if any([db.refresh() for db in self._dbs]):
            self._cache.clear()
            self._points.clear()

    def close(self) -> None:
        with self._lock:
            for db in self._dbs:
                if db.reader is not None:
                    _close(db.reader)
                    db.reader = None
            self._cache.clear()
            self._points.clear()

    # -- lookups --

    def __call__(self, address: object) -> Optional[GeoInfo]:
        return self.lookup(address)

    def lookup(self, address: object) -> Optional[GeoInfo]:
        """Where ``address`` (an address, or a network no wider than /24 or /48) is, or
        None when the lookup is off, the value is not an address, or nothing is known."""
        if not self._dbs:
            return None
        try:
            ip = parse_target(address)
            if ip is None:
                return None
            key = str(ip)
            with self._lock:
                self._refresh()
                if not self.enabled:
                    return None
                if key in self._cache:
                    self._cache.move_to_end(key)
                    return self._cache[key]
                found = self._find(ip)
                self._cache[key] = found
                if len(self._cache) > self._cache_size:
                    self._cache.popitem(last=False)
                return found
        except Exception:  # noqa: BLE001 - never raise into a caller
            log.debug("IP lookup failed", exc_info=True)
            return None

    def point(self, address: object) -> Optional[tuple[float, float]]:
        """``(latitude, longitude)`` of ``address`` from the location database, rounded to one
        decimal, or None when the lookup is off, the address is not global, or the file has
        no position for it. Cached like ``lookup``; never raises."""
        if not self._dbs:
            return None
        try:
            ip = parse_target(address)
            if ip is None or non_global_label(ip) is not None:
                return None
            key = str(ip)
            with self._lock:
                self._refresh()
                if not self.enabled:
                    return None
                if key in self._points:
                    self._points.move_to_end(key)
                    return self._points[key]
                found = None
                for db in self._dbs:
                    if db.role == "location" and db.reader is not None:
                        found = _point(db.get(key))
                self._points[key] = found
                if len(self._points) > self._cache_size:
                    self._points.popitem(last=False)
                return found
        except Exception:  # noqa: BLE001 - never raise into a caller
            log.debug("IP position lookup failed", exc_info=True)
            return None

    def _find(self, ip) -> Optional[GeoInfo]:
        label = non_global_label(ip)
        if label is not None:
            return GeoInfo(note=label)
        fields: dict = {}
        for db in self._dbs:
            if db.reader is None:
                continue
            got = db.get(str(ip))
            if db.role == "location":
                fields.update(_location(got))
                if got:
                    fields["location_built"] = db.built
            else:
                fields.update(_network(got))
                if got:
                    fields["network_built"] = db.built
        info = GeoInfo(**{k: v for k, v in fields.items() if v not in ("", None)})
        return None if info.empty else info


def from_config(config, **kwargs) -> GeoLookup:
    """The lookup ``[geoip]`` describes. A malformed section is logged and leaves it off."""
    try:
        settings = GeoSettings.from_config(config)
    except ConfigError as exc:
        log.warning("IP lookup: off: %s", exc)
        return GeoLookup(GeoSettings(), log_status=False, **kwargs)
    return GeoLookup(settings, **kwargs)
