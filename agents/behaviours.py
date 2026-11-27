"""Behaviour rules: generic patterns over a campaign's HTTP request sequence.

A rule file (``detections/behaviours/*.toml``) holds ``[[rules]]`` entries. Each has an
``id``, a ``kind`` from the fixed list below, the kind's thresholds, a ``label``, a
``confidence`` and a ``description``. The kinds and what they count:

- ``discovery_then_use``: at least ``min_routes`` distinct paths requested with
  ``discovered_via`` set, each within ``within_seconds`` of the discovery.
- ``adaptive_retries``: within some ``window_seconds``, at least ``min_requests`` requests,
  ``min_client_errors`` of them answered 4xx, and ``min_changes`` errors followed by a
  request on the same host that changes the path, the query or the method.
- ``object_enumeration``: at least ``min_ids`` distinct object ids asked of one item route.
- ``recovery_probing``: at least ``min_steps`` flow requests across ``min_flows`` flow kinds.
- ``marker_reuse``: at least ``min_hits`` requests that presented a per-source marker back
  (with ``other_source_only``, only markers issued to another source count).

Every count is a single pass over at most ``MAX_REQUESTS_KEPT`` requests. A match is
reported on the record (``behaviours``) and nowhere else: it never changes the record's
judgement, high-signal counts, blocklist reasons or exports.
"""

from __future__ import annotations

import logging
import tomllib
from collections import defaultdict
from pathlib import Path
from typing import Annotated, Iterable, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agents import REPO_ROOT
from agents.indicators import ID_PATTERN, Confidence

log = logging.getLogger("agents.behaviours")

DEFAULT_DIR = REPO_ROOT / "detections" / "behaviours"
MAX_RULES = 100
MAX_FILE_BYTES = 1 << 20
LIMIT = 1_000_000


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _Rule(Strict):
    id: str = Field(pattern=ID_PATTERN)
    enabled: bool = True
    label: str = Field(min_length=1, max_length=120)
    confidence: Confidence
    description: str = Field(default="", max_length=500)


class DiscoveryThenUse(_Rule):
    kind: Literal["discovery_then_use"]
    min_routes: int = Field(ge=1, le=LIMIT)
    within_seconds: int = Field(ge=1, le=30 * 86_400)


class AdaptiveRetries(_Rule):
    kind: Literal["adaptive_retries"]
    min_requests: int = Field(ge=2, le=LIMIT)
    window_seconds: int = Field(ge=1, le=86_400)
    min_client_errors: int = Field(ge=1, le=LIMIT)
    min_changes: int = Field(ge=1, le=LIMIT)


class ObjectEnumeration(_Rule):
    kind: Literal["object_enumeration"]
    min_ids: int = Field(ge=2, le=LIMIT)


class RecoveryProbing(_Rule):
    kind: Literal["recovery_probing"]
    min_steps: int = Field(ge=1, le=LIMIT)
    min_flows: int = Field(ge=1, le=4)


class MarkerReuse(_Rule):
    kind: Literal["marker_reuse"]
    min_hits: int = Field(default=1, ge=1, le=LIMIT)
    other_source_only: bool = False


Rule = Annotated[Union[DiscoveryThenUse, AdaptiveRetries, ObjectEnumeration, RecoveryProbing,
                       MarkerReuse], Field(discriminator="kind")]


class RuleFile(Strict):
    rules: list[Rule] = Field(default_factory=list, max_length=MAX_RULES)


class BehaviourMatch(Strict):
    """One rule a record matched: the count it reached and the requests it spans."""
    id: str = Field(pattern=ID_PATTERN)
    label: str = Field(max_length=120)
    confidence: Confidence
    count: int = Field(ge=1)
    first_seq: Optional[int] = None
    last_seq: Optional[int] = None


# ---- evaluation (each returns (count, matched requests) or None) ---------------------------

def _discovery_then_use(rule: DiscoveryThenUse, reqs: list):
    hits = [r for r in reqs if r.discovered_via and r.discovered_age is not None
            and r.discovered_age <= rule.within_seconds]
    paths = {r.path for r in hits}
    return (len(paths), hits) if len(paths) >= rule.min_routes else None


def _is_client_error(r) -> bool:
    return r.status is not None and 400 <= r.status < 500


def _adaptive_retries(rule: AdaptiveRetries, reqs: list):
    ordered = sorted(reqs, key=lambda r: r.ts)         # stable: log order within a second
    n = len(ordered)
    # change[i]: request i was a client error and the next request on the same host changed
    # the path, the query or the method.
    errors = [int(_is_client_error(r)) for r in ordered]
    change = [0] * n
    for i in range(n - 1):
        a, b = ordered[i], ordered[i + 1]
        if errors[i] and a.host == b.host and (a.path, a.query, a.method) != (b.path, b.query,
                                                                             b.method):
            change[i] = 1
    best = None
    start = err = chg = 0
    for end in range(n):
        err += errors[end]
        chg += change[end - 1] if end > start else 0
        while (ordered[end].ts - ordered[start].ts).total_seconds() > rule.window_seconds:
            err -= errors[start]
            if start + 1 <= end:
                chg -= change[start]
            start += 1
        size = end - start + 1
        if size >= rule.min_requests and err >= rule.min_client_errors \
                and chg >= rule.min_changes and (best is None or size > best[0]):
            best = (size, ordered[start:end + 1])
    return best


def _object_enumeration(rule: ObjectEnumeration, reqs: list):
    most: dict[str, int] = {}
    hits: dict[str, list] = defaultdict(list)
    for r in reqs:
        if r.object_id_count is None:
            continue
        key = r.route or r.path
        most[key] = max(most.get(key, 0), r.object_id_count)
        hits[key].append(r)
    if not most:
        return None
    key = max(most, key=lambda k: (most[k], k))
    return (most[key], hits[key]) if most[key] >= rule.min_ids else None


def _recovery_probing(rule: RecoveryProbing, reqs: list):
    hits = [r for r in reqs if r.flow]
    flows = {r.flow for r in hits}
    if len(hits) >= rule.min_steps and len(flows) >= rule.min_flows:
        return len(hits), hits
    return None


def _marker_reuse(rule: MarkerReuse, reqs: list):
    hits = [r for r in reqs if r.marker and (r.marker_src or not rule.other_source_only)]
    return (len(hits), hits) if len(hits) >= rule.min_hits else None


_EVAL = {"discovery_then_use": _discovery_then_use, "adaptive_retries": _adaptive_retries,
         "object_enumeration": _object_enumeration, "recovery_probing": _recovery_probing,
         "marker_reuse": _marker_reuse}


def _seq_span(hits: list) -> tuple[Optional[int], Optional[int]]:
    seqs = [r.seq for r in hits if r.seq is not None]
    return (min(seqs), max(seqs)) if seqs else (None, None)


class RuleSet:
    """The loaded rules (in file order) and the errors of files or rules left out."""

    def __init__(self, rules: Iterable = (), errors: Iterable[str] = ()):
        self.rules = list(rules)
        self.errors = list(errors)

    def evaluate(self, requests: Iterable) -> list[BehaviourMatch]:
        reqs = list(requests)
        if not reqs:
            return []
        out = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            found = _EVAL[rule.kind](rule, reqs)
            if found is None:
                continue
            count, hits = found
            first, last = _seq_span(hits)
            out.append(BehaviourMatch(id=rule.id, label=rule.label, confidence=rule.confidence,
                                      count=max(1, count), first_seq=first, last_seq=last))
        return out


def load_file(path: Path) -> list:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("file too large")
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    return RuleFile.model_validate(raw).rules


def load_rules(directory: Optional[Path] = None) -> RuleSet:
    """Every valid ``*.toml`` file under ``directory`` (sorted by name). A file that does
    not load is left out whole and named in ``errors``; a repeated id keeps the first."""
    rules: list = []
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
        for rule in loaded:
            if rule.id in seen:
                errors.append(f"{path.name}: repeated id {rule.id}")
                continue
            if len(rules) >= MAX_RULES:
                errors.append(f"{path.name}: more than {MAX_RULES} rules")
                break
            seen.add(rule.id)
            rules.append(rule)
    return RuleSet(rules, errors)


def from_config(cp, repo_root: Path = REPO_ROOT) -> Optional[RuleSet]:
    """The ``[behaviours]`` rules: None when ``enabled`` is off. ``path`` is a directory of
    TOML files or one file, relative to the repository; empty means the shipped files."""
    section = cp["behaviours"] if "behaviours" in cp else {}
    if str(section.get("enabled", "true")).strip().lower() not in ("1", "true", "yes", "on"):
        return None
    raw = str(section.get("path", "")).strip()
    path = (Path(raw) if Path(raw).is_absolute() else repo_root / raw) if raw else DEFAULT_DIR
    found = load_rules(path)
    for err in found.errors:
        log.error("behaviour file refused: %s", err)
    return found
