"""Detection drafter. Writes drafts to ``detections/pending/``; nothing is sent anywhere.

- Sigma rules for IOCs and high-signal behaviours seen across several sessions or source
  IPs. The rule body comes from a template in code; the model may only supply a title and
  description, which are length-capped and stripped to a safe character set. Each draft
  records its provenance in ``related_records`` (the triage record ids it was built from);
  the response engine publishes a draft for a record only when that list includes it.
- ``blocklist-candidates.csv``: per source IP across all protocols. Private and reserved
  addresses are skipped.

Every draft needs human approval (see detections/README.md).
"""

from __future__ import annotations

import csv
import datetime
import io
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


def blocklist_rows(records: list[TriageRecord]) -> list[dict]:
    by_ip: dict[str, dict] = {}
    for r in records:
        if r.unverified_source or not is_public_ip(r.src_ip):
            continue  # spoofable UDP-only sources never reach the blocklist
        row = by_ip.setdefault(r.src_ip, {"ip": r.src_ip, "sessions": 0, "attempts": 0,
                                          "first_seen": r.first_seen, "last_seen": r.last_seen,
                                          "judgement": r.judgement, "protocols": set()})
        row["sessions"] += r.connections if r.kind == "campaign" else 1
        row["attempts"] += r.auth_attempts
        row["protocols"].add(r.protocol)
        if r.first_seen and (not row["first_seen"] or r.first_seen < row["first_seen"]):
            row["first_seen"] = r.first_seen
        if r.last_seen and (not row["last_seen"] or r.last_seen > row["last_seen"]):
            row["last_seen"] = r.last_seen
        if JUDGEMENT_RANK[r.judgement] > JUDGEMENT_RANK[row["judgement"]]:
            row["judgement"] = r.judgement
    out = []
    for row in by_ip.values():
        if row["judgement"] == Judgement.BENIGN:
            continue
        row["judgement"] = row["judgement"].value
        row["protocols"] = ";".join(sorted(row["protocols"]))
        out.append(row)
    out.sort(key=lambda x: (-JUDGEMENT_RANK[Judgement(x["judgement"])], -x["attempts"], x["ip"]))
    return out


def run_detect(reports_dir: os.PathLike | str, detections_dir: os.PathLike | str,
               llm: Optional[JsonLLM] = None, dry_run: bool = False) -> dict:
    records = load_records(reports_dir)
    rules = build_rules(records, llm)
    rows = blocklist_rows(records)
    pending = Path(detections_dir) / "pending"
    written = []
    if not dry_run:
        for rule in rules.values():
            name = re.sub(r"[^a-z0-9]+", "-", rule["title"].lower()).strip("-")[:60]
            path = pending / f"{rule['id'][:8]}-{name}.yml"
            _atomic_write(path, yaml.safe_dump(rule, sort_keys=False, allow_unicode=False))
            written.append(path.name)
        buf = io.StringIO()
        fields = ["ip", "sessions", "attempts", "first_seen", "last_seen", "judgement", "protocols"]
        w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            # Values are IPs, ints, timestamps and enums; still guard against CSV formula injection.
            w.writerow({k: (str(v).lstrip("=+-@") if isinstance(v, str) else v) for k, v in row.items()})
        _atomic_write(pending / "blocklist-candidates.csv", buf.getvalue())
    return {"rules": len(rules), "rule_files": written, "blocklist_rows": len(rows)}
