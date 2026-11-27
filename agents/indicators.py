"""Indicator lists: data with provenance, matched against a campaign's clients and requests.

An indicator file (``detections/indicators/*.toml``) holds ``[[indicators]]`` entries. Each
names what it matches (``type``: ``user_agent``, ``path``, ``query``, ``ipv4``, ``ipv6``),
how (``match``: ``exact``, ``prefix``, ``contains``), the value, the framework and label it
stands for, a confidence, and where the fact comes from (``sources``, ``reported``,
``notes``).

Matching is plain string comparison in linear time over values that are already capped:
no regular expression is built from a data file. A ``query`` entry is compared with the
request's path and query joined by ``?``. An address entry matches only exactly.

A match is reported on the record (``indicator_matches``) and nowhere else: it never
changes the record's judgement, high-signal counts, blocklist reasons or exports.
"""

from __future__ import annotations

import ipaddress
import logging
import tomllib
from collections import Counter
from pathlib import Path
from typing import Iterable, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, \
    model_validator

from agents import REPO_ROOT

log = logging.getLogger("agents.indicators")

DEFAULT_DIR = REPO_ROOT / "detections" / "indicators"
ID_PATTERN = r"^[a-z0-9][a-z0-9_.-]{1,63}$"
DAY_PATTERN = r"^\d{4}-\d{2}-\d{2}$"
VALUE_MAX = 200
MAX_ENTRIES = 1_000            # across all files
MAX_FILE_BYTES = 1 << 20
MAX_MATCHES = 20               # matches kept per record

Confidence = Literal["low", "medium", "high"]
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Indicator(Strict):
    id: str = Field(pattern=ID_PATTERN)
    type: Literal["user_agent", "path", "query", "ipv4", "ipv6"]
    match: Literal["exact", "prefix", "contains"] = "exact"
    value: str = Field(min_length=1, max_length=VALUE_MAX)
    framework: str = Field(default="", pattern=r"^([A-Za-z0-9][A-Za-z0-9 ._-]{0,39})?$")
    label: str = Field(min_length=1, max_length=120)
    confidence: Confidence
    sources: list[str] = Field(min_length=1, max_length=5)
    reported: str = Field(pattern=DAY_PATTERN)
    notes: str = Field(default="", max_length=600)

    @field_validator("sources")
    @classmethod
    def _sources(cls, v: list[str]) -> list[str]:
        for url in v:
            if not url.startswith("https://") or len(url) > 300 or any(
                    c.isspace() or ord(c) < 32 for c in url):
                raise ValueError(f"source must be an https URL: {url[:60]!r}")
        return v

    @field_validator("value")
    @classmethod
    def _value(cls, v: str) -> str:
        if any(ord(c) < 32 or ord(c) == 127 for c in v):
            raise ValueError("value has a control character")
        return v

    @model_validator(mode="after")
    def _address(self) -> "Indicator":
        if self.type in ("ipv4", "ipv6"):
            if self.match != "exact":
                raise ValueError("an address indicator matches only exactly")
            try:
                addr = ipaddress.ip_address(self.value)
            except ValueError as exc:
                raise ValueError(f"not an address: {self.value[:60]!r}") from exc
            if addr.version != (4 if self.type == "ipv4" else 6):
                raise ValueError(f"{self.type} value is an IPv{addr.version} address")
        return self


class IndicatorFile(Strict):
    indicators: list[Indicator] = Field(default_factory=list, max_length=MAX_ENTRIES)


class IndicatorMatch(Strict):
    """One indicator a record matched: its id, what it stands for and how many times."""
    id: str = Field(pattern=ID_PATTERN)
    framework: str = Field(default="", max_length=40)
    label: str = Field(max_length=120)
    confidence: Confidence
    count: int = Field(ge=1)


def _hit(ind: Indicator, value: str) -> bool:
    if ind.type == "user_agent":
        value, want = value.casefold(), ind.value.casefold()
    else:
        want = ind.value
    if ind.match == "exact":
        return value == want
    if ind.match == "prefix":
        return value.startswith(want)
    return want in value


def _canonical_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value.split("%", 1)[0]))
    except ValueError:
        return None


class IndicatorSet:
    """The loaded entries (in file order) and the errors of files or entries left out."""

    def __init__(self, entries: Iterable[Indicator] = (), errors: Iterable[str] = ()):
        self.entries = list(entries)
        self.errors = list(errors)
        self.by_id = {e.id: e for e in self.entries}

    def match(self, clients: Counter, requests: Iterable, addresses: Iterable[str] = ()
              ) -> list[IndicatorMatch]:
        """Matches over a campaign's full client counter, its requests (``HttpRequest``)
        and its source addresses, strongest first."""
        requests = list(requests)
        canon = {c for c in (_canonical_ip(a) for a in addresses) if c}
        counts: Counter = Counter()
        for ind in self.entries:
            n = 0
            if ind.type == "user_agent":
                n = sum(k for v, k in clients.items() if isinstance(v, str) and _hit(ind, v))
            elif ind.type == "path":
                n = sum(1 for r in requests if _hit(ind, r.path))
            elif ind.type == "query":
                n = sum(1 for r in requests if r.query and _hit(ind, r.target))
            elif _canonical_ip(ind.value) in canon:
                n = 1
            if n:
                counts[ind.id] = n
        out = [IndicatorMatch(id=i.id, framework=i.framework, label=i.label,
                              confidence=i.confidence, count=counts[i.id])
               for i in self.entries if counts[i.id]]
        out.sort(key=lambda m: (-CONFIDENCE_RANK[m.confidence], -m.count, m.id))
        return out[:MAX_MATCHES]

    def provenance(self, ind_id: str) -> Optional[dict]:
        """Where an entry's fact comes from, for display; None when the id is not loaded."""
        ind = self.by_id.get(ind_id)
        if ind is None:
            return None
        return {"type": ind.type, "match": ind.match, "value": ind.value,
                "sources": list(ind.sources), "reported": ind.reported, "notes": ind.notes}


def load_file(path: Path) -> list[Indicator]:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("file too large")
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    return IndicatorFile.model_validate(raw).indicators


def load_indicators(directory: Optional[Path] = None) -> IndicatorSet:
    """Every valid ``*.toml`` file under ``directory`` (sorted by name). A file that does
    not load is left out whole and named in ``errors``; a repeated id keeps the first."""
    entries: list[Indicator] = []
    errors: list[str] = []
    seen: set[str] = set()
    root = Path(directory or DEFAULT_DIR)
    paths = sorted(root.glob("*.toml")) if root.is_dir() else [root] if root.is_file() else []
    for path in paths:
        try:
            loaded = load_file(path)
        except (OSError, ValueError, tomllib.TOMLDecodeError, ValidationError,
                RecursionError) as exc:
            errors.append(f"{path.name}: {str(exc)[:300]}")
            continue
        for ind in loaded:
            if ind.id in seen:
                errors.append(f"{path.name}: repeated id {ind.id}")
                continue
            if len(entries) >= MAX_ENTRIES:
                errors.append(f"{path.name}: more than {MAX_ENTRIES} entries")
                break
            seen.add(ind.id)
            entries.append(ind)
    return IndicatorSet(entries, errors)


def _on(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def from_config(cp, repo_root: Path = REPO_ROOT) -> Optional[IndicatorSet]:
    """The ``[indicators]`` set: None when ``enabled`` is off. ``path`` is a directory of
    TOML files or one file, relative to the repository; empty means the shipped files."""
    section = cp["indicators"] if "indicators" in cp else {}
    if not _on(section.get("enabled", "true")):
        return None
    raw = str(section.get("path", "")).strip()
    path = (Path(raw) if Path(raw).is_absolute() else repo_root / raw) if raw else DEFAULT_DIR
    found = load_indicators(path)
    for err in found.errors:
        log.error("indicator file refused: %s", err)
    return found
