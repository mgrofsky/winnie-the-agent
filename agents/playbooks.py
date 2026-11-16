"""Response playbooks: strict schema, fixed vocabulary, deterministic matching.

A playbook (``playbooks/*.toml``) says *when* (conditions from a fixed vocabulary; no
expressions, no eval) and *what* (ordered steps, each an action from a fixed set with typed
parameters). Each action's tier is fixed here in code and cannot be set by a playbook:

- ``local``: changes only this honeypot's behaviour (per-source state). Runs automatically.
- ``notify``: sends information to a destination the operator configured. Runs automatically
  only when that connector is enabled; connectors are off by default.
- ``enforce``: changes something outside the honeypot. Never automatic: queued for
  ``python -m agents approve <id>``.

Matching reads only validated, enum- or number-typed fields of a ``TriageRecord`` plus a
few facts computed by code (``derive_facts``). Attacker strings are never compared against
anything a playbook supplies, so they cannot change which actions run.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError, field_validator

from agents import REPO_ROOT
from agents.source_state import MAX_TARPIT_MS, TAG_RE
from agents.triage import (
    JUDGEMENT_RANK,
    Intent,
    IocType,
    Judgement,
    Stage,
    TriageRecord,
)

PLAYBOOKS_DIR = REPO_ROOT / "playbooks"
PLAYBOOK_NAME_RE = r"[a-z][a-z0-9_]{1,40}"

ActionTier = Literal["local", "notify", "enforce"]

# The tier of every action, fixed in code. A playbook cannot change it.
ACTION_TIERS: dict[str, ActionTier] = {
    "tarpit": "local",
    "deepen": "local",
    "shallow": "local",
    "plant_token": "local",
    "tag_source": "local",
    "capture_more": "local",
    "notify": "notify",
    "enrich": "notify",
    "export_blocklist": "enforce",
    "publish_detection": "enforce",
    "open_ticket": "enforce",
    "block_webhook": "enforce",
}

SIGNALS = ("redis_takeover", "sql_exec_attempt", "sql_cred_dump", "smtp_relay_attempt",
           "sip_dialed_number", "quarantine_quota", "http_proxy_attempt", "ftp_upload",
           # Deterministic SSH session signals (agents.triage.session_signals).
           "download_execute", "persistence", "credential_file_read")
# Dialing prefixes treated as international or premium-rate (toll fraud targets).
PREMIUM_PREFIXES = ("1900", "1976", "0900", "0906", "0909", "09", "+1900", "+44909", "+44906")
DOMESTIC_PLUS = ("+1",)
# Words that mark patient or financial data in fake data paths, tables and API routes.
SENSITIVE_WORDS = ("patient", "patients", "observation", "observations", "encounter",
                   "encounters", "mrn", "fhir", "account", "accounts", "card", "cards",
                   "transfer", "transfers", "statement", "statements", "balance", "balances",
                   "iban", "ledger", "payment", "payments")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Conditions(Strict):
    """All given conditions must hold (AND). Lists mean any-of."""

    kinds: list[Literal["session", "campaign"]] = Field(default_factory=list)
    protocols: list[Literal["ssh", "sip", "ftp", "telnet", "postgres", "mysql", "mssql",
                            "redis", "smtp", "http", "mllp"]] = Field(default_factory=list)
    judgement_at_least: Optional[Judgement] = None
    stages: list[Stage] = Field(default_factory=list)
    intents: list[Intent] = Field(default_factory=list)
    signals: list[Literal[SIGNALS]] = Field(default_factory=list)  # type: ignore[valid-type]
    honeytoken: Optional[bool] = None
    min_attempts: Optional[int] = Field(default=None, ge=0)
    max_attempts: Optional[int] = Field(default=None, ge=0)
    min_connections: Optional[int] = Field(default=None, ge=0)
    source_verified: Optional[bool] = None
    dialed_international_or_premium: Optional[bool] = None
    sensitive_data_access: Optional[bool] = None
    malware_indicators: Optional[bool] = None
    nothing_novel: Optional[bool] = None
    scenarios: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("scenarios")
    @classmethod
    def _scen(cls, v: list[str]) -> list[str]:
        for s in v:
            if not re.fullmatch(r"[a-z][a-z0-9_]{1,40}", s):
                raise ValueError(f"bad scenario name {s!r}")
        return v


# ---- actions (typed parameters per action) -----------------------------------------------

class _Action(Strict):
    # Optional per-step guard from the same vocabulary (e.g. a higher attempt threshold).
    only_if: Optional[Conditions] = None


class TarpitAction(_Action):
    action: Literal["tarpit"]
    delay_ms: int = Field(default=1500, ge=1, le=MAX_TARPIT_MS)
    hours: int = Field(default=24, ge=1, le=720)


class DeepenAction(_Action):
    action: Literal["deepen"]
    hours: int = Field(default=24, ge=1, le=720)


class ShallowAction(_Action):
    action: Literal["shallow"]
    hours: int = Field(default=24, ge=1, le=720)


class PlantTokenAction(_Action):
    action: Literal["plant_token"]
    hours: int = Field(default=168, ge=1, le=720)


class TagAction(_Action):
    action: Literal["tag_source"]
    tag: str
    hours: int = Field(default=168, ge=1, le=720)

    @field_validator("tag")
    @classmethod
    def _tag(cls, v: str) -> str:
        if not re.fullmatch(TAG_RE, v):
            raise ValueError("bad tag")
        return v


class CaptureMoreAction(_Action):
    action: Literal["capture_more"]
    hours: int = Field(default=72, ge=1, le=720)


class NotifyAction(_Action):
    action: Literal["notify"]
    connectors: list[Literal["webhook", "siem_http", "email"]] = Field(min_length=1, max_length=3)
    include: list[Literal["dialed_numbers", "hashes", "urls", "credentials", "tags"]] = \
        Field(default_factory=list, max_length=5)


class EnrichAction(_Action):
    action: Literal["enrich"]


class ExportBlocklistAction(_Action):
    action: Literal["export_blocklist"]


class PublishDetectionAction(_Action):
    action: Literal["publish_detection"]


class OpenTicketAction(_Action):
    action: Literal["open_ticket"]
    priority: Literal["low", "medium", "high"] = "medium"


class BlockWebhookAction(_Action):
    action: Literal["block_webhook"]


Step = Annotated[Union[TarpitAction, DeepenAction, ShallowAction, PlantTokenAction, TagAction,
                       CaptureMoreAction, NotifyAction, EnrichAction, ExportBlocklistAction,
                       PublishDetectionAction, OpenTicketAction, BlockWebhookAction],
                 Field(discriminator="action")]


class Playbook(Strict):
    name: str
    description: str = Field(default="", max_length=500)
    enabled: bool = True
    # Priority playbooks may use the share of each notify connector's daily cap that is
    # reserved for them, so a flood of routine alerts cannot starve them.
    priority: StrictBool = False
    cooldown_minutes: int = Field(default=60, ge=0, le=10_080)   # per source
    max_runs_per_day: int = Field(default=100, ge=1, le=10_000)
    when: Conditions
    steps: list[Step] = Field(min_length=1, max_length=12)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not re.fullmatch(PLAYBOOK_NAME_RE, v):
            raise ValueError("bad playbook name")
        return v


def tier_of(step) -> ActionTier:
    return ACTION_TIERS[step.action]


# ---- loading -----------------------------------------------------------------------------

class PlaybookError(ValueError):
    pass


def load_playbook(path: Path) -> Playbook:
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
        pb = Playbook.model_validate(raw)
    except (OSError, tomllib.TOMLDecodeError, ValidationError) as exc:
        raise PlaybookError(f"{path.name}: {exc}") from exc
    if pb.name != path.stem:
        raise PlaybookError(f"{path.name}: name {pb.name!r} must match the file name")
    return pb


def load_playbooks(directory: Optional[Path] = None) -> tuple[list[Playbook], list[str]]:
    """All valid playbooks (sorted by name) and the errors for invalid ones."""
    out, errors = [], []
    for path in sorted(Path(directory or PLAYBOOKS_DIR).glob("*.toml")):
        try:
            out.append(load_playbook(path))
        except PlaybookError as exc:
            errors.append(str(exc)[:500])
    return out, errors


# ---- facts and matching ------------------------------------------------------------------

def _is_international_or_premium(number: str) -> bool:
    n = re.sub(r"[\s\-().]", "", number)
    if any(n.startswith(p) for p in PREMIUM_PREFIXES):
        return True
    if n.startswith("+") and not any(n.startswith(p) for p in DOMESTIC_PLUS):
        return True
    return n.startswith("00") or n.startswith("011")


def derive_facts(record: TriageRecord, scenario_name: Optional[str] = None) -> dict:
    """Booleans computed by code from validated record fields. Nothing here is copied from
    attacker text into anything that controls execution; strings are only tested."""
    words = re.compile(r"\b(" + "|".join(SENSITIVE_WORDS) + r")\b", re.I)
    sample = " ".join(record.command_sample)[:20_000]
    iocs = record.iocs
    return {
        "dialed_international_or_premium": any(
            _is_international_or_premium(num) for num, _ in record.credentials.dialed_numbers),
        "sensitive_data_access": bool(words.search(sample)) or any(
            i.type == IocType.FILE_PATH and words.search(i.value) for i in iocs),
        "malware_indicators": bool(record.high_signal.get("ftp_upload")) or any(
            i.type in (IocType.URL, IocType.MD5, IocType.SHA1, IocType.SHA256) for i in iocs),
        "nothing_novel": (record.kind == "campaign" and not record.high_signal
                          and not record.honeytokens and record.commands == 0),
        "scenario": scenario_name,
    }


def matches(cond: Conditions, record: TriageRecord, facts: dict) -> bool:
    c = cond
    if c.kinds and record.kind not in c.kinds:
        return False
    if c.protocols and record.protocol not in c.protocols:
        return False
    if c.judgement_at_least is not None and \
            JUDGEMENT_RANK[record.judgement] < JUDGEMENT_RANK[c.judgement_at_least]:
        return False
    if c.stages and record.stage not in c.stages:
        return False
    if c.intents and record.intent not in c.intents:
        return False
    if c.signals and not any(record.high_signal.get(s) for s in c.signals):
        return False
    if c.honeytoken is not None and bool(record.honeytokens) != c.honeytoken:
        return False
    if c.min_attempts is not None and record.auth_attempts < c.min_attempts:
        return False
    if c.max_attempts is not None and record.auth_attempts > c.max_attempts:
        return False
    if c.min_connections is not None and record.connections < c.min_connections:
        return False
    if c.source_verified is not None and (not record.unverified_source) != c.source_verified:
        return False
    for name in ("dialed_international_or_premium", "sensitive_data_access",
                 "malware_indicators", "nothing_novel"):
        wanted = getattr(c, name)
        if wanted is not None and bool(facts.get(name)) != wanted:
            return False
    if c.scenarios and facts.get("scenario") not in c.scenarios:
        return False
    return True
