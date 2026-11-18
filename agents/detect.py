"""Detection drafter. Writes drafts to ``detections/pending/``; nothing is sent anywhere.

- Sigma rules for IOCs and high-signal behaviours seen across several sessions or source
  IPs. The rule body comes from a template in code; the model may only supply a title and
  description, which are length-capped and stripped to a safe character set. Each draft
  records its provenance in ``related_records`` (the triage record ids it was built from);
  the response engine publishes a draft for a record only when that list includes it.
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
import logging
import os
import re
import secrets
import tempfile
import uuid
from collections import defaultdict
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


def specific_enough(value: str) -> bool:
    """A Sigma selector value must be long enough and not a common token."""
    v = value.strip().lower()
    return len(v) >= MIN_SELECTOR_LEN and v not in COMMON_TOKENS and \
        not any(v == f"http://{t}" or v == f"https://{t}" for t in COMMON_TOKENS)

HIGH_SIGNAL_RULES = {
    "redis_takeover": {
        "logsource": {"product": "redis", "service": "redis"},
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
        "logsource": {"product": "postfix", "service": "smtp"},
        "keywords": ["Relay access denied"],
        "tags": ["attack.resource_development"],
        "title": "SMTP open relay probing",
    },
}


class SigmaText(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(max_length=100)
    description: str = Field(max_length=400)


def safe_text(value: str, cap: int) -> str:
    return re.sub(r"\s+", " ", SAFE_TITLE_RE.sub("", value)).strip()[:cap]


def is_public_ip(value: str) -> bool:
    return is_public(value)


def sigma_rule(key: str, title: str, description: str, logsource: dict, field_name: Optional[str],
               values: list[str], tags: list[str], level: str = "medium",
               related_records: Optional[list[str]] = None) -> dict:
    if field_name:
        detection = {"selection": {f"{field_name}|contains": values}, "condition": "selection"}
    else:
        detection = {"keywords": values, "condition": "keywords"}
    return {
        "title": safe_text(title, 100) or "Honeypot derived indicator",
        "id": str(uuid.uuid5(SIGMA_NAMESPACE, key)),
        "status": "experimental",
        "description": safe_text(description, 400) or "Drafted from honeypot activity.",
        "author": "winnie detect agent (draft, needs human review)",
        "date": datetime.date.today().strftime("%Y-%m-%d"),
        "tags": sorted(set(tags)),
        "logsource": logsource,
        "detection": detection,
        "falsepositives": ["Legitimate administration using the same indicator"],
        "level": level,
        "related_records": sorted(related_records or [])[:MAX_RELATED_RECORDS],
    }


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


def build_rules(records: list[TriageRecord], llm: Optional[JsonLLM] = None,
                max_model_calls: int = 10) -> dict[str, dict]:
    rules: dict[str, dict] = {}
    calls = 0
    # IOC rules: indicator seen in >= MIN_SESSIONS records or from >= 2 source IPs.
    seen: dict[tuple[str, str], dict] = defaultdict(lambda: {"records": set(), "ips": set(), "tags": set()})
    records = [r for r in records if not r.unverified_source]
    for r in records:
        for ioc in r.iocs:
            if ioc.type == IocType.FILE_PATH:
                continue
            if ioc.type == IocType.IPV4 and not is_public_ip(ioc.value):
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
        key = f"ioc:{itype}:{value}"
        fallback = SigmaText(title=f"Honeypot {itype} indicator seen in {len(entry['records'])} sessions",
                             description=f"{itype} indicator used by {len(entry['ips'])} source IPs "
                                         "against the honeypot.")
        text = fallback
        if calls < max_model_calls and llm is not None:
            calls += 1
            text = _model_text(llm, f"{itype} indicator seen in {len(entry['records'])} sessions "
                                    f"from {len(entry['ips'])} IPs", fallback)
        rules[key] = sigma_rule(key, text.title, text.description,
                                {"category": "process_creation", "product": "linux"},
                                "CommandLine", [value], list(entry["tags"]),
                                related_records=list(entry["records"]))
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
        rules[key] = sigma_rule(key, spec["title"],
                                f"{spec['title']} observed from {len(ips)} source IPs on the honeypot.",
                                spec["logsource"], None, spec["keywords"], spec["tags"], "high",
                                related_records=list(sig_records[name]))
    return rules


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
                   "persistence", "credential_file_read"}
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
    records = load_records(reports_dir)
    rules = build_rules(records, llm)
    expired: list[str] = []
    rows = blocklist_rows(records, now=now, expiry_days=expiry_days,
                          access_expiry_days=access_expiry_days, expired=expired)
    pending = Path(detections_dir) / "pending"
    written = []
    if not dry_run:
        for rule in rules.values():
            name = re.sub(r"[^a-z0-9]+", "-", rule["title"].lower()).strip("-")[:60]
            path = pending / f"{rule['id'][:8]}-{name}.yml"
            _atomic_write(path, yaml.safe_dump(rule, sort_keys=False, allow_unicode=False))
            written.append(path.name)
        # Rewritten in full each run, so rows past their expiry disappear.
        _atomic_write(pending / "blocklist-candidates.csv", blocklist_csv(rows))
    return {"rules": len(rules), "rule_files": written, "blocklist_rows": len(rows),
            "blocklist_expired": len(expired)}
