"""Detection drafter. Writes drafts to ``detections/pending/``; nothing is sent anywhere.

- Sigma rules for IOCs and high-signal behaviours seen across several sessions or source
  IPs. The rule body comes from a template in code; the model may only supply a title and
  description for a new draft, which are length-capped and stripped to a safe character
  set. Indicator values are attacker-chosen and are escaped (``*``, ``?``, ``\\``) so they
  match literally. Each indicator type has its own log source and field (``IOC_RULES``);
  addresses and hashes get no Sigma rule. One file per rule id, named from the id; a draft
  keeps its ``date`` and gets ``modified`` when its content changes; a rule already in
  ``approved/`` is not drafted again. Every draft is checked against the fixed shape before
  it is written. The triage record ids each draft was built from go to
  ``pending/provenance.json``, not into the rule; the response engine publishes a draft
  for a record only when that list includes it.
- ``blocklist-candidates.csv``: per source IP across all protocols. Private and reserved
  addresses are skipped, and so are UDP-only sources that never completed a nonce round
  trip (their address may be forged). Each row says whether the source address was proven,
  the highest thing the source did (``reason``, a fixed vocabulary) and when the row stops
  being valid (``expires``); rows past their expiry are left out. Every cell is built from
  validated values, never from text the attacker sent.

Every draft needs human approval (see detections/README.md).
"""

from __future__ import annotations

import csv
import datetime
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import tempfile
import uuid
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agents.addresses import is_public
from agents.llm import JsonLLM, LLMOutputError, LLMRequestError, LLMUnavailable, untrusted_block
from agents.triage import (
    JUDGEMENT_RANK,
    S3_LISTED_RE,
    IocType,
    Judgement,
    TriageRecord,
    ioc_well_formed,
    load_records,
)

log = logging.getLogger(__name__)

SIGMA_NAMESPACE = uuid.UUID("6b1d6b8e-3f0e-4c44-9a3c-6f6d0c2b9e51")
SAFE_TITLE_RE = re.compile(r"[^A-Za-z0-9 ,.:()_/-]")
MIN_SESSIONS = 2
REQUIRED_SIGMA_KEYS = ("title", "id", "status", "description", "logsource", "detection", "level")
MAX_RELATED_RECORDS = 200
MIN_SELECTOR_LEN = 8
# Values too common to be a useful selector on their own (false positives everywhere).
COMMON_TOKENS = {
    "localhost", "127.0.0.1", "0.0.0.0", "8.8.8.8", "1.1.1.1", "example.com", "google.com",
    "github.com", "githubusercontent.com", "raw.githubusercontent.com", "ubuntu.com",
    "archive.ubuntu.com", "debian.org", "deb.debian.org", "pypi.org", "amazonaws.com",
}
# Draft file names: the first eight characters of the rule id and a fixed kind, never text a
# model or an attacker chose. The same pattern is DETECTION_FILE_RE in agents/respond.py.
DRAFT_FILE_RE = re.compile(r"[0-9a-f]{8}-[a-z0-9-]{1,60}\.yml")
# Read by agents/respond.py (DETECTION_PROVENANCE_FILE, MAX_PROVENANCE_BYTES there).
PROVENANCE_FILE = "provenance.json"
MAX_PROVENANCE_BYTES = 4 * 1024 * 1024
MAX_DRAFT_BYTES = 256 * 1024


def specific_enough(value: str) -> bool:
    """A Sigma selector value must be long enough and not a common token."""
    v = value.strip().lower()
    return len(v) >= MIN_SELECTOR_LEN and v not in COMMON_TOKENS and \
        not any(v == f"http://{t}" or v == f"https://{t}" for t in COMMON_TOKENS)


# Indicator rules: where each indicator type is looked for, in the Sigma log source taxonomy
# (sigma-appendix-taxonomy). URLs and SSH keys were seen inside commands the attacker ran,
# so the rule looks for the same text in process command lines. A domain was named in such
# a command; the rule looks for a DNS question for it (category network, service dns,
# field dns.question.name). Types not listed get no Sigma rule: an address is a source or a
# destination, not a command-line string, and belongs in the STIX export
# (docs/portable-formats.md); an md5/sha1/sha256 found in command text is not known to be
# the hash of any file; file paths are too generic.
IOC_RULES = {
    IocType.URL: ("ioc-url", {"category": "process_creation", "product": "linux"},
                  "CommandLine|contains"),
    IocType.SSH_PUBKEY: ("ioc-ssh-pubkey", {"category": "process_creation", "product": "linux"},
                         "CommandLine|contains"),
    IocType.DOMAIN: ("ioc-domain", {"category": "network", "service": "dns"},
                     "dns.question.name"),
}
IOC_LABELS = {IocType.URL: "URL", IocType.SSH_PUBKEY: "SSH public key",
              IocType.DOMAIN: "domain"}

# Behaviour rules. Log sources: "category: database" is the taxonomy's SQL query log; Redis
# and Postfix have no taxonomy entry, so the product name is used as the spec's log source
# rules describe (lower case). The keywords are fixed here and match the text those
# products log; nothing from a record is added to them.
HIGH_SIGNAL_RULES = {
    "redis_takeover": {
        "logsource": {"product": "redis"},
        "keywords": ["CONFIG SET dir", "CONFIG SET dbfilename", "SLAVEOF", "REPLICAOF", "MODULE LOAD"],
        "tags": ["attack.persistence", "attack.t1505"],
        "title": "Redis takeover command chain",
    },
    "sql_exec_attempt": {
        "logsource": {"category": "database"},
        "keywords": ["COPY", "PROGRAM", "INTO OUTFILE", "LOAD_FILE", "xp_cmdshell", "sys_exec"],
        "tags": ["attack.execution", "attack.t1059"],
        "title": "Database command execution attempt",
    },
    "smtp_relay_attempt": {
        "logsource": {"product": "postfix"},
        "keywords": ["Relay access denied"],
        "tags": ["attack.resource-development"],
        "title": "SMTP open relay probing",
    },
}

# What a written draft may contain (Sigma rules specification v2.1.0), checked before every
# write. The full check with the Sigma project's library runs in the tests.
SIGMA_STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")
SIGMA_LEVELS = ("informational", "low", "medium", "high", "critical")
DRAFT_KEYS = ("title", "id", "status", "description", "author", "date", "modified", "tags",
              "logsource", "detection", "falsepositives", "level")
ATTACK_TACTICS = ("reconnaissance", "resource-development", "initial-access", "execution",
                  "persistence", "privilege-escalation", "defense-evasion", "credential-access",
                  "discovery", "lateral-movement", "collection", "command-and-control",
                  "exfiltration", "impact")
TAG_RE = re.compile(r"^attack\.(t\d{4}(\.\d{3})?|" + "|".join(ATTACK_TACTICS) + r")$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
LOGSOURCE_VALUE_RE = re.compile(r"^[a-z0-9_.-]{1,40}$")
FIELD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]{0,63}(\|contains)?$")


class SigmaText(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(max_length=100)
    description: str = Field(max_length=400)


def safe_text(value: str, cap: int) -> str:
    return re.sub(r"\s+", " ", SAFE_TITLE_RE.sub("", value)).strip()[:cap]


def is_public_ip(value: str) -> bool:
    return is_public(value)


def sigma_escape(value: str) -> str:
    """A literal string as a Sigma value: ``*`` and ``?`` are wildcards and ``\\`` is the
    escape character (rules specification, "Escape Character"), so each is escaped."""
    return value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def sigma_rule(key: str, title: str, description: str, logsource: dict, field_name: Optional[str],
               values: list[str], tags: list[str], level: str = "medium",
               day: Optional[datetime.date] = None) -> dict:
    """One draft. ``values`` are literal strings; they are escaped here."""
    escaped = [sigma_escape(v) for v in values]
    if field_name:
        detection = {"selection": {field_name: escaped}, "condition": "selection"}
    else:
        detection = {"keywords": escaped, "condition": "keywords"}
    return {
        "title": safe_text(title, 100) or "Honeypot derived indicator",
        "id": str(uuid.uuid5(SIGMA_NAMESPACE, key)),
        "status": "experimental",
        "description": safe_text(description, 400) or "Drafted from honeypot activity.",
        "author": "winnie detect agent (draft, needs human review)",
        "date": (day or datetime.date.today()).strftime("%Y-%m-%d"),
        "tags": sorted({t for t in tags if TAG_RE.fullmatch(t)}),
        "logsource": dict(logsource),
        "detection": detection,
        "falsepositives": ["Legitimate administration using the same indicator"],
        "level": level,
    }


def check_draft(rule) -> list[str]:
    """Problems that keep a draft from being written: anything outside the fixed shape
    ``sigma_rule`` builds. Empty when the draft may be written."""
    if not isinstance(rule, dict):
        return ["not a mapping"]
    problems = [f"unexpected key {k!r}" for k in rule if k not in DRAFT_KEYS]
    problems += [f"missing {k}" for k in REQUIRED_SIGMA_KEYS if k not in rule]
    if problems:
        return problems
    try:
        if str(uuid.UUID(str(rule["id"]))) != rule["id"]:
            problems.append("id is not a canonical UUID")
    except ValueError:
        problems.append("id is not a UUID")
    for name, cap in (("title", 100), ("description", 400)):
        value = rule[name]
        if not isinstance(value, str) or not value or len(value) > cap \
                or SAFE_TITLE_RE.search(value):
            problems.append(f"{name} is not plain text")
    if rule["status"] not in SIGMA_STATUSES:
        problems.append("status")
    if rule["level"] not in SIGMA_LEVELS:
        problems.append("level")
    for name in ("date", "modified"):
        if name in rule and not (isinstance(rule[name], str) and DATE_RE.fullmatch(rule[name])):
            problems.append(f"{name} is not YYYY-MM-DD")
    tags = rule.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(t, str) and TAG_RE.fullmatch(t)
                                             for t in tags):
        problems.append("tags")
    ls = rule["logsource"]
    if not isinstance(ls, dict) or not ls or any(
            k not in ("category", "product", "service") or not isinstance(v, str)
            or not LOGSOURCE_VALUE_RE.fullmatch(v) for k, v in ls.items()):
        problems.append("logsource")
    det = rule["detection"]
    if not isinstance(det, dict) or set(det) not in ({"selection", "condition"},
                                                     {"keywords", "condition"}):
        problems.append("detection")
        return problems
    name = "selection" if "selection" in det else "keywords"
    if det["condition"] != name:
        problems.append("condition")
    body = det[name]
    if name == "selection":
        if not isinstance(body, dict) or len(body) != 1 or not all(
                isinstance(f, str) and FIELD_RE.fullmatch(f) for f in body):
            problems.append("selection field")
            return problems
        (body,) = body.values()
    if not isinstance(body, list) or not body or not all(
            isinstance(v, str) and v and len(v) <= 4096 and _escaped(v) for v in body):
        problems.append("detection values")
    return problems


def _escaped(value: str) -> bool:
    """Every ``*``, ``?`` and ``\\`` in ``value`` is escaped, so it is matched literally."""
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\":
            if i + 1 >= len(value) or value[i + 1] not in "\\*?":
                return False
            i += 2
            continue
        if ch in "*?":
            return False
        i += 1
    return True


def _model_text(llm: Optional[JsonLLM], summary: str, fallback: SigmaText) -> SigmaText:
    if llm is None:
        return fallback
    system = ("Write a short Sigma rule title and description for the pattern described in "
              "the data. Return only the JSON object.")
    try:
        out = llm.complete_json(system, untrusted_block("pattern summary", summary,
                                                        secrets.token_hex(8)), SigmaText)
        out = SigmaText.model_validate(out.model_dump() if hasattr(out, "model_dump") else out)
    except (LLMOutputError, LLMRequestError, LLMUnavailable, ValidationError, ValueError,
            TypeError, AttributeError):
        return fallback
    return SigmaText(title=safe_text(out.title, 100) or fallback.title,
                     description=safe_text(out.description, 400) or fallback.description)


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=path.suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


@dataclass
class Draft:
    key: str                 # what the rule id is derived from
    kind: str                # fixed part of the file name
    rule: dict
    records: list[str]       # triage record ids the draft was built from

    @property
    def file_name(self) -> str:
        return f"{self.rule['id'][:8]}-{self.kind}.yml"


def build_drafts(records: list[TriageRecord], llm: Optional[JsonLLM] = None,
                 max_model_calls: int = 10, day: Optional[datetime.date] = None,
                 known_text: Optional[dict[str, SigmaText]] = None) -> list[Draft]:
    """The drafts these records support. ``known_text`` maps a rule id to the title and
    description of an existing draft, which are kept (and the model is not asked again)."""
    known_text = known_text or {}
    drafts: list[Draft] = []
    calls = 0
    # IOC rules: indicator seen in >= MIN_SESSIONS records or from >= 2 source IPs.
    seen: dict[tuple[str, str], dict] = defaultdict(lambda: {"records": set(), "ips": set(), "tags": set()})
    records = [r for r in records if not r.unverified_source]
    for r in records:
        for ioc in r.iocs:
            if ioc.type not in IOC_RULES:
                continue
            if not ioc_well_formed(ioc) or not specific_enough(ioc.value):
                continue
            entry = seen[(ioc.type.value, ioc.value)]
            entry["records"].add(r.id)
            entry["ips"].add(r.src_ip)
            entry["tags"].update(f"attack.{t.id.lower()}" for t in r.techniques)
    for (itype, value), entry in sorted(seen.items()):
        if len(entry["records"]) < MIN_SESSIONS and len(entry["ips"]) < 2:
            continue
        ioc_type = IocType(itype)
        kind, logsource, field_name = IOC_RULES[ioc_type]
        key = f"ioc:{itype}:{value}"
        rule_id = str(uuid.uuid5(SIGMA_NAMESPACE, key))
        label = IOC_LABELS[ioc_type]
        fallback = SigmaText(title=f"Honeypot {label} indicator",
                             description=f"A {label} that sources attacking the honeypot used in "
                                         "at least two sessions or from two addresses.")
        text = known_text.get(rule_id)
        if text is None:
            text = fallback
            if calls < max_model_calls and llm is not None:
                calls += 1
                text = _model_text(llm, f"{itype} indicator seen in {len(entry['records'])} "
                                        f"sessions from {len(entry['ips'])} IPs", fallback)
        drafts.append(Draft(key, kind, sigma_rule(
            key, text.title, text.description, logsource, field_name, [value],
            list(entry["tags"]), day=day), sorted(entry["records"])[:MAX_RELATED_RECORDS]))
    # Behaviour rules from high-signal events.
    sig: dict[str, set] = defaultdict(set)
    sig_records: dict[str, set] = defaultdict(set)
    for r in records:
        for name in r.high_signal:
            sig[name].add(r.src_ip)
            sig_records[name].add(r.id)
    for name, ips in sorted(sig.items()):
        spec = HIGH_SIGNAL_RULES.get(name)
        if spec is None:
            continue
        key = f"signal:{name}"
        text = known_text.get(str(uuid.uuid5(SIGMA_NAMESPACE, key))) or SigmaText(
            title=spec["title"], description=f"{spec['title']} seen on the honeypot.")
        drafts.append(Draft(key, "signal-" + name.replace("_", "-"), sigma_rule(
            key, text.title, text.description, spec["logsource"], None, spec["keywords"],
            spec["tags"], "high", day=day), sorted(sig_records[name])[:MAX_RELATED_RECORDS]))
    return drafts


def build_rules(records: list[TriageRecord], llm: Optional[JsonLLM] = None,
                max_model_calls: int = 10) -> dict[str, dict]:
    """{key: rule} for the drafts these records support."""
    return {d.key: d.rule for d in build_drafts(records, llm, max_model_calls)}


# Writing drafts --------------------------------------------------------------------------

def _read_draft(path: Path) -> Optional[dict]:
    """A draft file as a mapping, or None when it is not a small regular YAML mapping."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_DRAFT_BYTES:
            return None
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return None
    return doc if isinstance(doc, dict) else None


def _drafts_by_id(directory: Path) -> dict[str, list[tuple[Path, dict]]]:
    out: dict[str, list[tuple[Path, dict]]] = defaultdict(list)
    try:
        paths = sorted(directory.glob("*.yml"))
    except OSError:
        return out
    for path in paths:
        if not DRAFT_FILE_RE.fullmatch(path.name):
            continue
        doc = _read_draft(path)
        if doc is not None and isinstance(doc.get("id"), str):
            out[doc["id"]].append((path, doc))
    return out


def _same_content(a: dict, b: dict) -> bool:
    strip = ("date", "modified")
    return {k: v for k, v in a.items() if k not in strip} == \
        {k: v for k, v in b.items() if k not in strip}


def _yaml(rule: dict) -> str:
    return yaml.safe_dump({k: rule[k] for k in DRAFT_KEYS if k in rule}, sort_keys=False,
                          allow_unicode=False)


def provenance_path(detections_dir: os.PathLike | str) -> Path:
    """The pending drafts' provenance: which triage records each one was built from."""
    return Path(detections_dir) / "pending" / PROVENANCE_FILE


def write_drafts(drafts: list[Draft], detections_dir: os.PathLike | str,
                 day: datetime.date) -> dict:
    """Write the drafts to ``pending/``, one file per rule id, named from the id.

    - A rule whose id is already in ``approved/`` is not drafted again.
    - An unchanged draft is left as it is. A changed one keeps its ``date`` (first drafted)
      and gets ``modified`` (today). Title and description are those of the existing draft.
    - Other files in ``pending/`` with the same id (older names) are removed, so an id is
      in one file only.
    - A draft that fails ``check_draft`` is not written.
    - ``pending/provenance.json`` is rewritten with the record ids of every draft written or
      kept; ``publish_detection`` reads it (agents/respond.py)."""
    pending = Path(detections_dir) / "pending"
    approved = _drafts_by_id(Path(detections_dir) / "approved")
    existing = _drafts_by_id(pending)
    out = {"written": [], "unchanged": [], "skipped_approved": 0, "invalid": 0,
           "name_clash": 0, "removed_duplicates": 0}
    provenance: dict[str, list[str]] = {}
    for d in drafts:
        rule = dict(d.rule)
        rid = rule["id"]
        if rid in approved:
            out["skipped_approved"] += 1
            continue
        target = pending / d.file_name
        if target.exists() and all(p != target for p, _ in existing.get(rid, [])):
            # Another rule whose id starts with the same eight characters owns the name.
            out["name_clash"] += 1
            log.warning("detect: %s belongs to another rule; draft %s not written",
                        target.name, rid)
            continue
        previous = next((doc for p, doc in existing.get(rid, []) if p == target), None) or \
            next((doc for _, doc in existing.get(rid, [])), None)
        if previous is not None:
            if isinstance(previous.get("date"), str) and DATE_RE.fullmatch(previous["date"]):
                rule["date"] = previous["date"]
            if isinstance(previous.get("modified"), str) and \
                    DATE_RE.fullmatch(previous["modified"]):
                rule["modified"] = previous["modified"]
            if not _same_content(previous, rule):
                rule["modified"] = day.strftime("%Y-%m-%d")
        problems = check_draft(rule)
        if problems:
            out["invalid"] += 1
            log.error("detect: draft %s not written: %s", rid, "; ".join(problems[:5]))
            continue
        text = _yaml(rule)
        try:
            current = target.read_text(encoding="utf-8") if target.is_file() else None
        except (OSError, UnicodeDecodeError):
            current = None
        if current == text:
            out["unchanged"].append(target.name)
        else:
            _atomic_write(target, text)
            out["written"].append(target.name)
        for path, _ in existing.get(rid, []):
            if path != target:
                try:
                    path.unlink()
                    out["removed_duplicates"] += 1
                except OSError:
                    pass
        provenance[target.name] = d.records
    _atomic_write(provenance_path(detections_dir), provenance_document(provenance))
    return out


def provenance_document(provenance: dict[str, list[str]]) -> str:
    """The provenance file, no larger than the response engine reads: when it would be,
    each draft keeps fewer of its record ids (the first ones, in sorted order)."""
    keep = MAX_RELATED_RECORDS
    while True:
        doc = {"version": 1, "drafts": {name: ids[:keep] for name, ids in
                                        sorted(provenance.items())}}
        text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
        if len(text.encode()) <= MAX_PROVENANCE_BYTES or keep == 0:
            return text
        keep //= 2


def known_text(detections_dir: os.PathLike | str) -> dict[str, SigmaText]:
    """Title and description of each pending draft, by rule id, re-checked."""
    out = {}
    for rid, items in _drafts_by_id(Path(detections_dir) / "pending").items():
        doc = items[0][1]
        title = safe_text(str(doc.get("title", "")), 100)
        description = safe_text(str(doc.get("description", "")), 400)
        if title and description:
            out[rid] = SigmaText(title=title, description=description)
    return out


# Blocklist candidates ---------------------------------------------------------------------

BLOCKLIST_FIELDS = ["ip", "sessions", "attempts", "first_seen", "last_seen", "judgement",
                    "protocols", "source_proven", "reason", "expires"]
# What a source did, lowest first. A row carries the highest reason across its records.
BLOCKLIST_REASONS = ("probe", "login_attempt", "object_list", "register", "login",
                     "object_read", "command", "relay", "dial", "upload", "honeytoken")
REASON_RANK = {name: i for i, name in enumerate(BLOCKLIST_REASONS)}
DEFAULT_EXPIRY_DAYS = 14.0          # sources that never got past a login
DEFAULT_ACCESS_EXPIRY_DAYS = 30.0   # sources that logged in or used a planted credential
UPLOAD_SIGNALS = {"s3_upload", "ftp_upload", "quarantine_quota"}
RELAY_SIGNALS = {"smtp_relay_attempt", "http_proxy_attempt"}
COMMAND_SIGNALS = {"redis_takeover", "sql_exec_attempt", "sql_cred_dump", "download_execute",
                   "persistence", "credential_file_read", "hardware_recon"}
S3_READ_RE = re.compile(r"^GetObject /\S+ -> 20[06]$")
SAFE_PROTOCOL_RE = re.compile(r"^[a-z0-9_]{1,16}$")
CSV_UNSAFE_FIRST = tuple("=+-@\t\r\n'")


def record_reasons(r: TriageRecord) -> set[str]:
    """Every reason one record supports, derived from counts and code-set signal names."""
    signals = set(r.high_signal)
    out = {"probe"}
    if r.auth_attempts:
        out.add("login_attempt")
    if r.protocol == "s3" and any(S3_LISTED_RE.match(c) for c in r.command_sample):
        out.add("object_list")
    if r.auth_successes:
        out.add("register" if r.protocol == "sip" else "login")
    if "s3_bulk_download" in signals or any(S3_READ_RE.match(c) for c in r.command_sample):
        out.add("object_read")
    if signals & COMMAND_SIGNALS or (r.commands and (
            r.kind == "session" or (r.auth_successes and r.protocol not in ("sip", "s3")))):
        out.add("command")
    if signals & RELAY_SIGNALS:
        out.add("relay")
    if "sip_dialed_number" in signals:
        out.add("dial")
    if signals & UPLOAD_SIGNALS:
        out.add("upload")
    if r.honeytokens:
        out.add("honeytoken")
    return out


def _canonical_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(value).split("%", 1)[0]))
    except ValueError:
        return None


def _parse_ts(value: Optional[str]) -> Optional[datetime.datetime]:
    if not value or not isinstance(value, str) or not value[:1].isdigit():
        return None
    try:
        ts = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=datetime.timezone.utc)
    return ts.astimezone(datetime.timezone.utc)


def _fmt_ts(ts: Optional[datetime.datetime]) -> str:
    return ts.isoformat(timespec="seconds") if ts else ""


def _expiry_days(value, default: float) -> float:
    try:
        days = float(value)
    except (TypeError, ValueError):
        return default
    return days if days > 0 else default


def blocklist_rows(records: list[TriageRecord], now: Optional[datetime.datetime] = None,
                   expiry_days: float = DEFAULT_EXPIRY_DAYS,
                   access_expiry_days: float = DEFAULT_ACCESS_EXPIRY_DAYS,
                   expired: Optional[list[str]] = None) -> list[dict]:
    """One row per proven public source. Rows whose expiry is not after ``now`` are left
    out (their addresses are appended to ``expired`` when a list is given)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)
    expiry_days = _expiry_days(expiry_days, DEFAULT_EXPIRY_DAYS)
    access_expiry_days = _expiry_days(access_expiry_days, DEFAULT_ACCESS_EXPIRY_DAYS)
    by_ip: dict[str, dict] = {}
    for r in records:
        if r.unverified_source or not is_public_ip(r.src_ip):
            continue  # spoofable UDP-only sources never reach the blocklist
        ip = _canonical_ip(r.src_ip)
        if ip is None:
            continue
        row = by_ip.setdefault(ip, {"ip": ip, "sessions": 0, "attempts": 0, "first_seen": None,
                                    "last_seen": None, "judgement": r.judgement,
                                    "protocols": set(), "reason": "probe", "access": False})
        row["sessions"] += r.connections if r.kind == "campaign" else 1
        row["attempts"] += r.auth_attempts
        if SAFE_PROTOCOL_RE.match(r.protocol):
            row["protocols"].add(r.protocol)
        first, last = _parse_ts(r.first_seen), _parse_ts(r.last_seen)
        if first and (row["first_seen"] is None or first < row["first_seen"]):
            row["first_seen"] = first
        if last and (row["last_seen"] is None or last > row["last_seen"]):
            row["last_seen"] = last
        if JUDGEMENT_RANK[r.judgement] > JUDGEMENT_RANK[row["judgement"]]:
            row["judgement"] = r.judgement
        row["reason"] = max(record_reasons(r) | {row["reason"]}, key=REASON_RANK.__getitem__)
        row["access"] = row["access"] or bool(r.auth_successes or r.honeytokens)
    out = []
    for row in by_ip.values():
        if row["judgement"] == Judgement.BENIGN:
            continue
        base = row["last_seen"] or row["first_seen"] or now
        expires = base + datetime.timedelta(
            days=access_expiry_days if row.pop("access") else expiry_days)
        if expires <= now:
            if expired is not None:
                expired.append(row["ip"])
            continue
        row["judgement"] = row["judgement"].value
        row["protocols"] = ";".join(sorted(row["protocols"]))
        row["first_seen"] = _fmt_ts(row["first_seen"])
        row["last_seen"] = _fmt_ts(row["last_seen"])
        row["source_proven"] = "yes"   # unverified sources were skipped above
        row["expires"] = _fmt_ts(expires)
        out.append(row)
    out.sort(key=lambda x: (-JUDGEMENT_RANK[Judgement(x["judgement"])], -x["attempts"], x["ip"]))
    return out


def _csv_cell(value):
    """Integers pass; text that a spreadsheet could read as a formula, or that carries a
    control character, is written empty. Every value here is already validated, so this
    is a backstop."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return ""
    if isinstance(value, int):
        return value
    if value.startswith(CSV_UNSAFE_FIRST) or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return ""
    return value


def blocklist_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=BLOCKLIST_FIELDS, extrasaction="ignore",
                       quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    w.writeheader()
    for row in rows:
        w.writerow({k: _csv_cell(row.get(k, "")) for k in BLOCKLIST_FIELDS})
    return buf.getvalue()


def run_detect(reports_dir: os.PathLike | str, detections_dir: os.PathLike | str,
               llm: Optional[JsonLLM] = None, dry_run: bool = False,
               now: Optional[datetime.datetime] = None,
               expiry_days: float = DEFAULT_EXPIRY_DAYS,
               access_expiry_days: float = DEFAULT_ACCESS_EXPIRY_DAYS) -> dict:
    """Draft Sigma rules (see ``write_drafts``) and rewrite the blocklist candidates."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)
    day = now.astimezone(datetime.timezone.utc).date()
    records = load_records(reports_dir)
    drafts = build_drafts(records, llm, day=day,
                          known_text=None if dry_run else known_text(detections_dir))
    expired: list[str] = []
    rows = blocklist_rows(records, now=now, expiry_days=expiry_days,
                          access_expiry_days=access_expiry_days, expired=expired)
    pending = Path(detections_dir) / "pending"
    result = {"rules": len(drafts), "rule_files": [], "blocklist_rows": len(rows),
              "blocklist_expired": len(expired)}
    if not dry_run:
        out = write_drafts(drafts, detections_dir, day)
        result["rule_files"] = sorted(out["written"] + out["unchanged"])
        result.update({k: out[k] for k in ("skipped_approved", "invalid", "name_clash",
                                           "removed_duplicates")})
        result["rules_changed"] = len(out["written"])
        # Rewritten in full each run, so rows past their expiry disappear.
        _atomic_write(pending / "blocklist-candidates.csv", blocklist_csv(rows))
    return result
