"""Stored triage analyses: a model answer reused for a repeated command sequence.

The same bot script arrives from many addresses. Triage asks the analyst model about the
first copy and keeps its answer here, keyed by what the model was asked; a later copy
with the same key gets the stored answer and no model call.

- The key is a SHA-256 digest of the item's kind, protocol, the system prompt and output
  schema, the campaign header facts (source address left out) and its command or request
  lines, with random-looking tokens (``agents.learned.tokens``: UUIDs, long hex, mixed
  base64-like runs) replaced by numbered placeholders, plus each token's length and class.
  A line that computes over its text (``agents.learned.computes``, for example
  ``base64 -d``) and a token that decodes to readable text stay literal, so a payload is
  always part of the key. The source address, the username and the passwords tried are
  not in the key, and an SSH session's key leaves out the honeypot's own replies.
- The value is the model's classification and narrative parts with each token value
  replaced by its placeholder; serving fills them with the new item's tokens. An answer
  is stored only when every specific string in it is a placeholder or appears literally
  in the keyed lines: text naming the source address (also defanged, or a network's
  prefix), or an address or other IOC that is neither, is not stored. Text naming the session's username is stored bound to that
  username and served only to sessions that logged in with it. Model-suggested IOCs are
  never stored; a record's IOCs come from its own commands.
- An entry expires ``days`` after it was stored and, with ``max_uses``, after that many
  serves; the next copy then asks the model again. A fresh answer that disagrees with the
  stored judgement keeps the higher one and counts the disagreement.
- The file sits in the agents' state directory, 0600, replaced atomically, at most
  ``max_entries`` entries (least recently used go first) and ``MAX_ENTRY_BYTES`` per entry.
  An unreadable or malformed file reads as empty and is replaced on the next save.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import datetime
import fcntl
import hashlib
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

from agents import learned

log = logging.getLogger(__name__)

FILE_NAME = "triage_analyses.json"
COUNTS_NAME = "triage_analyses_reused.json"
FILE_VERSION = 1
KEY_VERSION = "1"             # part of every key: a change to how keys are built misses
DEFAULT_DAYS = 30
DEFAULT_MAX_USES = 0          # 0: no limit
DEFAULT_MAX_ENTRIES = 5000
MAX_ENTRIES_LIMIT = 50_000
MAX_DAYS = 3650
MAX_ENTRY_BYTES = 16 * 1024   # an entry larger than this, as stored, is not kept
MAX_FILE_BYTES = MAX_ENTRIES_LIMIT * MAX_ENTRY_BYTES   # a larger file is not read
MAX_VALUES = 99               # placeholders per key (two digits); more and nothing is kept
MAX_SAMPLE = 200
SHORT = 16                    # characters of the key shown and accepted by --forget
TEXT_FIELDS = ("headline", "narrative")
LIST_FIELDS = ("actions", "assessment", "not_seen")
CLASS_FIELDS = ("intent", "stage", "skill", "judgement")
JUDGEMENTS = ("BENIGN", "SUSPICIOUS", "MALICIOUS")   # lowest first
_KEY = re.compile(r"^[0-9a-f]{64}$")
_SHORT = re.compile(r"^[0-9a-f]{16}$")
_WORD = r"(?<![A-Za-z0-9_]){}(?![A-Za-z0-9_])"


def short_id(key: str) -> str:
    return key[:SHORT]


def valid_short(text: str) -> bool:
    return bool(_SHORT.fullmatch(text or ""))


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


# ---- keys -------------------------------------------------------------------------------

@dataclass(frozen=True)
class Keyed:
    key: str                   # SHA-256 hex
    kind: str
    protocol: str
    values: tuple[str, ...]    # placeholder number -> this item's token value
    text: str                  # the keyed lines with placeholders, for literal checks
    sample: str                # the first keyed line, for listings

    @property
    def short(self) -> str:
        return short_id(self.key)


def _readable(value: str) -> bool:
    """True when ``value`` decodes (hex or base64) to mostly printable ASCII text."""
    raw: list[bytes] = []
    with contextlib.suppress(ValueError, binascii.Error):
        if len(value) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", value):
            raw.append(bytes.fromhex(value))
    with contextlib.suppress(ValueError, binascii.Error):
        raw.append(base64.b64decode(value + "=" * (-len(value) % 4), validate=True))
    for data in raw:
        if len(data) >= 4:
            printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
            if printable * 4 >= len(data) * 3:
                return True
    return False


def template_lines(lines: Iterable[str]) -> Optional[tuple[list[str], tuple[str, ...]]]:
    """The lines with random-looking tokens as placeholders numbered across all lines (the
    same value is the same placeholder), and the values; None when a line holds the
    placeholder marker or there are more than ``MAX_VALUES`` distinct values."""
    values: list[str] = []
    out: list[str] = []
    for line in lines:
        if learned.MARK in line:
            return None
        if learned.computes(line):
            out.append(line)
            continue
        pieces: list[str] = []
        last = 0
        for start, end in learned.tokens(line):
            value = line[start:end]
            if _readable(value):
                continue
            if value not in values:
                values.append(value)
            pieces.append(line[last:start])
            pieces.append(f"{learned.MARK}{values.index(value)}{learned.MARK}")
            last = end
        pieces.append(line[last:])
        out.append("".join(pieces))
    if len(values) > MAX_VALUES:
        return None
    return out, tuple(values)


def make_key(kind: str, protocol: str, prompt: str, head: dict,
             lines: list[str]) -> Optional[Keyed]:
    """The key for one item, or None when its lines cannot be templated."""
    templated = template_lines(lines)
    if templated is None:
        return None
    out, values = templated
    material = json.dumps({"v": KEY_VERSION, "kind": kind, "protocol": protocol,
                           "prompt": _sha(prompt), "head": head, "lines": out,
                           "shape": learned.shape(values)},
                          sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    sample = learned.escape(out[0], MAX_SAMPLE) if out else ""
    return Keyed(_sha(material), kind, protocol, values, "\n".join(out), sample)


# ---- values -----------------------------------------------------------------------------

def _texts(out: dict) -> Iterable[str]:
    for name in TEXT_FIELDS:
        if out.get(name):
            yield out[name]
    for name in LIST_FIELDS:
        yield from out.get(name) or []
    for t in out.get("techniques") or []:
        yield t["name"]


def _map_texts(out: dict, one: Callable[[str], Optional[str]]) -> Optional[dict]:
    """``out`` with every text passed through ``one``; None when ``one`` refuses any."""
    new = {k: out[k] for k in CLASS_FIELDS}
    for name in TEXT_FIELDS:
        text = one(out.get(name) or "")
        if text is None:
            return None
        new[name] = text
    for name in LIST_FIELDS:
        items = []
        for item in out.get(name) or []:
            text = one(item)
            if text is None:
                return None
            items.append(text)
        new[name] = items
    techniques = []
    for t in out.get("techniques") or []:
        name = one(t["name"])
        if name is None:
            return None
        techniques.append({"id": t["id"], "name": name})
    new["techniques"] = techniques
    return new


_DEFANG = (("[.]", "."), ("(.)", "."), ("[dot]", "."), ("(dot)", "."), ("[:]", ":"))
_IPV6_RUN = re.compile(r"[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:]*")


def _refanged(text: str) -> str:
    """``text`` with defanged dots and colons (``[.]``, ``(dot)``, ``[:]``) restored."""
    low = text.lower()
    for old, new in _DEFANG:
        low = low.replace(old, new)
    return low


def _source_forms(src_ips: Iterable[str]) -> list[str]:
    """Each source address, and for a network (``2001:db8:1:2::/64``) its prefix without
    the length and without the trailing colons, lower case."""
    forms: list[str] = []
    for value in src_ips:
        value = (value or "").strip().lower()
        if not value:
            continue
        forms.append(value)
        if "/" in value:
            base = value.split("/", 1)[0]
            forms += [base, base.rstrip(":")]
    return [f for f in forms if f]


def _ipv6_runs(text: str) -> list[str]:
    """Runs of hex digits and colons in ``text`` shaped like an IPv6 address or prefix:
    three or more colons, or a ``::``."""
    return [m.group(0).strip(":") or m.group(0) for m in _IPV6_RUN.finditer(text)
            if m.group(0).count(":") >= 3 or "::" in m.group(0)]


def storable(out: dict, keyed: Keyed, *, src_ips: Iterable[str], username: Optional[str],
             ioc_values: Callable[[str], list[str]]) -> Optional[tuple[dict, str]]:
    """The model answer ``out`` (a validated ``TriageModelOutput`` dump) as a stored value,
    and the digest of the username it is bound to ("" for none); None when it cannot be
    reused for another item.

    Every text is read with defanged dots and colons restored. Refused when any text names
    a source address in ``src_ips`` (or a network's prefix); holds an IPv6-shaped run or an
    IOC (``ioc_values``) that is neither a token of this item nor literal in the keyed
    lines; or fails ``learned.reply_template`` (a trace of a token that is not its
    verbatim value, two different tokens in one text, another random-looking token).
    Text naming ``username`` as a word binds the value to that username."""
    keyed_text = keyed.text.lower()
    tokens = {v.lower() for v in keyed.values}
    sources = _source_forms(src_ips)
    bound = ""
    for text in _texts(out):
        plain = _refanged(text)
        if any(f in plain for f in sources):
            return None
        for value in [*_ipv6_runs(plain), *ioc_values(plain)]:
            value = value.lower()
            if value not in tokens and value not in keyed_text:
                return None
        if username and re.search(_WORD.format(re.escape(username)), text, re.I):
            bound = _sha("user\x00" + username)
    stored = _map_texts(out, lambda t: learned.reply_template(t, keyed.values) if t else t)
    if stored is None:
        return None
    return stored, bound


def fill(stored: dict, values: tuple[str, ...]) -> Optional[dict]:
    """A stored value with the placeholders filled from ``values``; None when it names a
    placeholder the item does not have."""
    return _map_texts(stored, lambda t: learned.fill(t, values) if t else t)


def _valid_out(raw: object) -> bool:
    if not isinstance(raw, dict):
        return False
    if not all(isinstance(raw.get(k), str) and len(raw[k]) <= 64 for k in CLASS_FIELDS):
        return False
    if raw.get("judgement") not in JUDGEMENTS:
        return False
    if not all(isinstance(raw.get(k), str) for k in TEXT_FIELDS):
        return False
    for name in LIST_FIELDS:
        items = raw.get(name)
        if not isinstance(items, list) or len(items) > 8 or \
                not all(isinstance(i, str) for i in items):
            return False
    techniques = raw.get("techniques")
    if not isinstance(techniques, list) or len(techniques) > 12:
        return False
    for t in techniques:
        if not (isinstance(t, dict) and set(t) == {"id", "name"} and isinstance(t["id"], str)
                and isinstance(t["name"], str)):
            return False
    return set(raw) == set(CLASS_FIELDS) | set(TEXT_FIELDS) | set(LIST_FIELDS) | {"techniques"}


def _valid_entry(key: object, raw: object) -> Optional[dict]:
    if not (isinstance(key, str) and _KEY.fullmatch(key) and isinstance(raw, dict)):
        return None
    try:
        entry = {"kind": raw["kind"], "protocol": raw["protocol"], "out": raw["out"],
                 "user": raw["user"], "sample": raw["sample"],
                 "created": float(raw["created"]), "last": float(raw["last"]),
                 "uses": int(raw["uses"]), "disagreements": int(raw["disagreements"])}
    except (KeyError, TypeError, ValueError):
        return None
    if entry["kind"] not in ("session", "campaign") or not isinstance(entry["protocol"], str) \
            or len(entry["protocol"]) > 16 or not isinstance(entry["user"], str) \
            or entry["user"] not in ("",) and not _KEY.fullmatch(entry["user"]) \
            or not isinstance(entry["sample"], str) or len(entry["sample"]) > MAX_SAMPLE \
            or entry["uses"] < 0 or entry["disagreements"] < 0 \
            or not _valid_out(entry["out"]):
        return None
    if len(json.dumps(entry, ensure_ascii=False).encode("utf-8")) > MAX_ENTRY_BYTES:
        return None
    return entry


# ---- the store --------------------------------------------------------------------------

def _today(now: float) -> str:
    return datetime.datetime.fromtimestamp(now, datetime.timezone.utc).date().isoformat()


class AnalysisStore:
    """The stored analyses of one state directory. Loaded once; ``save`` merges this
    process's changes into the file as it is then (under a lock) and replaces it."""

    def __init__(self, path: Optional[os.PathLike | str], days: float = DEFAULT_DAYS,
                 max_uses: int = DEFAULT_MAX_USES, max_entries: int = DEFAULT_MAX_ENTRIES,
                 clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path) if path else None
        self.days = float(days)
        self.max_uses = int(max_uses)
        self.max_entries = max(1, min(int(max_entries), MAX_ENTRIES_LIMIT))
        self.clock = clock
        self.read_error: Optional[str] = None
        self.entries: dict[str, dict] = {}
        self._dirty: set[str] = set()
        self._removed: set[str] = set()
        self._cleared = False
        self.reused = 0              # serves by this process, not yet saved
        self.disagreements = 0       # fresh answers that disagreed, this process
        self.entries = self._read()

    # -- file --
    def _read(self) -> dict[str, dict]:
        if self.path is None:
            return {}
        try:
            if os.path.getsize(self.path) > MAX_FILE_BYTES:
                raise ValueError("file too large")
            data = json.loads(self.path.read_bytes())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, RecursionError) as exc:
            self.read_error = type(exc).__name__ if not isinstance(exc, ValueError) else \
                str(exc)[:100] or "ValueError"
            log.warning("stored analyses unreadable (%s); starting empty", self.read_error)
            return {}
        if not isinstance(data, dict) or data.get("version") != FILE_VERSION or \
                not isinstance(data.get("entries"), dict):
            self.read_error = "not a stored-analyses file of this version"
            log.warning("stored analyses unreadable (%s); starting empty", self.read_error)
            return {}
        out: dict[str, dict] = {}
        for key, raw in data["entries"].items():
            entry = _valid_entry(key, raw)
            if entry is not None:
                out[key] = entry
        return out

    def _counts_path(self) -> Optional[Path]:
        return self.path.with_name(COUNTS_NAME) if self.path else None

    def counts(self) -> dict:
        """Serves saved so far: ``{"day", "today", "total"}`` (today in UTC). Creates
        nothing; an unreadable file counts as none."""
        return read_counts(self._counts_path(), self.clock())

    def save(self) -> bool:
        """Merge this process's changes into the file and replace it. False when it cannot
        be written (the changes stay in memory)."""
        if self.path is None:
            return True
        if not (self._dirty or self._removed or self._cleared or self.reused):
            return True
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(str(self.path) + ".lock", "a+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    self._merge_and_write()
                finally:
                    fcntl.flock(lock, fcntl.LOCK_UN)
        except OSError as exc:
            log.warning("cannot save stored analyses: %s", type(exc).__name__)
            return False
        return True

    def _merge_and_write(self) -> None:
        mine = self.entries
        prior_error = self.read_error
        disk = {} if self._cleared else self._read()
        self.read_error = prior_error
        for key in self._removed:
            disk.pop(key, None)
        for key in self._dirty:
            if key in mine:
                disk[key] = mine[key]
        self._evict(disk)
        _write_json(self.path, {"version": FILE_VERSION, "entries": disk})
        if self.reused:
            now = self.clock()
            counts = read_counts(self._counts_path(), now)
            today = _today(now)
            _write_json(self._counts_path(), {
                "day": today, "today": (counts["today"] if counts["day"] == today else 0)
                + self.reused, "total": counts["total"] + self.reused})
        self.entries = disk
        self._dirty.clear()
        self._removed.clear()
        self._cleared = False
        self.reused = 0

    def _evict(self, entries: dict[str, dict]) -> None:
        if len(entries) <= self.max_entries:
            return
        for key in sorted(entries, key=lambda k: entries[k]["last"])[:len(entries)
                                                                       - self.max_entries]:
            entries.pop(key, None)

    # -- use --
    def _fresh(self, entry: dict, now: float) -> bool:
        if now - entry["created"] > self.days * 86400:
            return False
        return not (self.max_uses and entry["uses"] >= self.max_uses)

    def lookup(self, keyed: Keyed, username: Optional[str] = None) -> Optional[dict]:
        """The stored value for ``keyed`` filled with its tokens, or None (no entry, expired,
        used up, bound to another username, or it does not fill). Counts nothing: call
        ``served`` once the answer is used."""
        entry = self.entries.get(keyed.key)
        if entry is None or entry["kind"] != keyed.kind or entry["protocol"] != keyed.protocol:
            return None
        if not self._fresh(entry, self.clock()):
            return None
        if entry["user"] and entry["user"] != _sha("user\x00" + (username or "")):
            return None
        return fill(entry["out"], keyed.values)

    def served(self, keyed: Keyed) -> None:
        entry = self.entries.get(keyed.key)
        if entry is None:
            return
        entry["uses"] += 1
        entry["last"] = self.clock()
        self._dirty.add(keyed.key)
        self.reused += 1

    def put(self, keyed: Keyed, stored: dict, user: str) -> bool:
        """Keep a fresh model answer for ``keyed``. When an entry for the key exists and the
        judgements differ, the higher one is kept and the disagreement counted. False when
        the entry is too large to keep."""
        now = self.clock()
        old = self.entries.get(keyed.key)
        stored = dict(stored)
        disagreements = old["disagreements"] if old else 0
        if old is not None and old["out"]["judgement"] != stored["judgement"]:
            disagreements += 1
            self.disagreements += 1
            stored["judgement"] = max(old["out"]["judgement"], stored["judgement"],
                                      key=JUDGEMENTS.index)
            log.info("stored analysis %s: a fresh answer disagreed on judgement; kept %s",
                     keyed.short, stored["judgement"])
        entry = {"kind": keyed.kind, "protocol": keyed.protocol, "out": stored, "user": user,
                 "sample": keyed.sample, "created": now, "last": now, "uses": 0,
                 "disagreements": disagreements}
        if _valid_entry(keyed.key, entry) is None:
            return False
        self.entries[keyed.key] = entry
        self._removed.discard(keyed.key)
        self._dirty.add(keyed.key)
        return True

    def stored_judgement(self, keyed: Keyed) -> Optional[str]:
        entry = self.entries.get(keyed.key)
        return entry["out"]["judgement"] if entry else None

    # -- operator --
    def find(self, short: str) -> list[str]:
        return [k for k in self.entries if k.startswith(short)]

    def forget(self, short: str) -> Optional[int]:
        """Drop the entries whose key starts with ``short``; their count, or None when the
        file cannot be written."""
        keys = self.find(short)
        for key in keys:
            self.entries.pop(key, None)
            self._dirty.discard(key)
            self._removed.add(key)
        if keys and not self.save():
            return None
        return len(keys)

    def clear(self) -> Optional[int]:
        count = len(self.entries)
        self.entries = {}
        self._dirty.clear()
        self._removed.clear()
        self._cleared = True
        return count if self.save() else None


def _write_json(path: Path, data: dict) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".analyses-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def read_counts(path: Optional[Path], now: Optional[float] = None) -> dict:
    """``{"day", "today", "total"}`` from the counts file beside the store; zeros when it
    is missing or unreadable. Creates nothing."""
    today = _today(time.time() if now is None else now)
    out = {"day": today, "today": 0, "total": 0}
    if path is None:
        return out
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return out
    if not isinstance(data, dict):
        return out
    total, count = data.get("total"), data.get("today")
    if isinstance(total, int) and total >= 0:
        out["total"] = total
    if data.get("day") == today and isinstance(count, int) and count >= 0:
        out["today"] = count
    return out


def path_in(state_dir: os.PathLike | str) -> Path:
    return Path(state_dir) / FILE_NAME


def reused_today(state_dir: os.PathLike | str, now: Optional[float] = None) -> int:
    return read_counts(Path(state_dir) / COUNTS_NAME, now)["today"]


# ---- settings ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReuseSettings:
    enabled: bool = True
    days: float = DEFAULT_DAYS
    max_uses: int = DEFAULT_MAX_USES
    max_entries: int = DEFAULT_MAX_ENTRIES


def settings(config) -> ReuseSettings:
    """``[agents] analysis_reuse`` (default on), ``analysis_reuse_days`` (default 30, more
    than 0), ``analysis_reuse_max_uses`` (default 0, no limit) and
    ``analysis_reuse_max_entries`` (default 5000, at most 50000). ValueError on a bad
    value."""
    if "agents" not in config:
        return ReuseSettings()
    section = config["agents"]
    enabled = section.getboolean("analysis_reuse", fallback=True)
    days = section.getfloat("analysis_reuse_days", fallback=float(DEFAULT_DAYS))
    max_uses = section.getint("analysis_reuse_max_uses", fallback=DEFAULT_MAX_USES)
    max_entries = section.getint("analysis_reuse_max_entries", fallback=DEFAULT_MAX_ENTRIES)
    if not 0 < days <= MAX_DAYS:
        raise ValueError(f"[agents] analysis_reuse_days must be more than 0 and at most {MAX_DAYS}")
    if max_uses < 0:
        raise ValueError("[agents] analysis_reuse_max_uses must be 0 or more")
    if max_entries < 1:
        raise ValueError("[agents] analysis_reuse_max_entries must be 1 or more")
    return ReuseSettings(enabled, days, max_uses, min(max_entries, MAX_ENTRIES_LIMIT))


# ---- operator text ----------------------------------------------------------------------

MAX_LIST = 200


def stats_text(store: AnalysisStore) -> tuple[str, dict]:
    now = store.clock()
    entries = list(store.entries.values())
    counts = store.counts()
    summary = {"entries": len(entries),
               "fresh": sum(1 for e in entries if store._fresh(e, now)),
               "bound_to_username": sum(1 for e in entries if e["user"]),
               "disagreements": sum(e["disagreements"] for e in entries),
               "calls_saved_today": counts["today"], "calls_saved_total": counts["total"]}
    lines = [f"stored analyses: {store.path or '(memory)'}",
             f"entries: {summary['entries']}  fresh: {summary['fresh']}  "
             f"bound to a username: {summary['bound_to_username']}  "
             f"judgement disagreements: {summary['disagreements']}",
             f"model calls saved: {summary['calls_saved_today']} today (UTC), "
             f"{summary['calls_saved_total']} in total",
             f"expiry: {store.days:g} days"
             + (f", {store.max_uses} uses" if store.max_uses else "")
             + f"; at most {store.max_entries} entries"]
    return "\n".join(lines), summary


def list_text(store: AnalysisStore) -> tuple[str, dict]:
    now = store.clock()
    items = sorted(store.entries.items(), key=lambda kv: -kv[1]["last"])
    lines = [f"{len(items)} entries (most recently used first, at most {MAX_LIST} shown)"]
    for key, e in items[:MAX_LIST]:
        age = max(0.0, (now - e["created"]) / 86400)
        state = "fresh" if store._fresh(e, now) else "expired"
        lines.append(f"{short_id(key)}  {e['kind']} {learned.escape(e['protocol'], 16)}  "
                     f"{e['out']['judgement']}  used {e['uses']}  {age:.1f} days  {state}"
                     + ("  bound to a username" if e["user"] else "")
                     + (f"  disagreements {e['disagreements']}" if e["disagreements"] else ""))
        lines.append(f"    first line: {learned.escape(e['sample'], 120)}")
        headline = e["out"].get("headline") or ""
        if headline:
            lines.append(f"    headline:   {learned.escape(headline, 120)}")
    return "\n".join(lines), {"entries": len(items)}
