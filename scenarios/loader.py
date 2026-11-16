"""Load a scenario pack, apply the tuner overlay, plant honeytokens, generate seed data.

Public API (used by listeners/, agents/ and SSH hooks):

    list_scenarios() -> list[str]
    load_scenario(name, seed, overlay_path=None, scenarios_dir=None) -> LoadedScenario
    LoadedScenario.scenario          validated Scenario with honeytokens substituted
    LoadedScenario.honeytokens       {name: Honeytoken(name, kind, value, planted_in)}
    LoadedScenario.table_rows(db, table) -> (columns, rows)   deterministic per seed
    LoadedScenario.accounts_for(service) -> list[(username, password)]   scenario + overlay
    LoadedScenario.policy_for(service) -> LoginPolicy                      scenario + overlay
    LoadedScenario.persona_fragment() -> str   rendered from schema-validated fields only
    write_honeytokens(loaded, path)            writes reports/honeytokens.json
    find_honeytoken(text, honeytokens) -> Optional[str]

All randomness comes from ``random.Random`` seeded with sha256(seed|scenario|purpose), so
the same sensor seed always shows the same records and the same honeytokens.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import random
import re
import string
import tempfile
import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .schema import (
    HoneytokenSpec,
    LoginPolicy,
    Overlay,
    Scenario,
    Table,
)

SCENARIOS_DIR = Path(__file__).resolve().parent

# Invented name pools. Deliberately bland; no real people are intended.
FIRST_NAMES = ["Avery", "Jordan", "Riley", "Morgan", "Casey", "Taylor", "Quinn", "Rowan",
               "Harper", "Emerson", "Finley", "Sawyer", "Reese", "Dakota", "Kendall", "Marlow",
               "Peyton", "Sutton", "Teagan", "Lennox", "Ellis", "Hollis", "Arden", "Blair"]
LAST_NAMES = ["Hartwell", "Okonkwo", "Lindqvist", "Marchetti", "Delacroix", "Brannigan",
              "Fairbanks", "Nakashima", "Oyelaran", "Pemberton", "Quillfeather", "Rasmussen",
              "Szymanski", "Thorncastle", "Vandermeer", "Whitlock", "Yarborough", "Zelenko",
              "Abernathy", "Castellanos", "Duquesne", "Ferreira", "Gallagher", "Halvorsen"]
WORDS = ["alpha", "bravo", "delta", "harbor", "summit", "ledger", "beacon", "cobalt",
         "meridian", "pioneer", "quartz", "sierra", "tundra", "vector", "willow", "zephyr"]


@dataclass(frozen=True)
class Honeytoken:
    name: str
    kind: str
    value: str
    planted_in: tuple[str, ...]


def _rng(seed: str, *purpose: str) -> random.Random:
    digest = hashlib.sha256("|".join((seed,) + purpose).encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _luhn_check_digit(number: str) -> int:
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - total % 10) % 10


def fake_card_number(rng: random.Random) -> str:
    """16 digits in the non-issued 0000 prefix range with a deliberately FAILING Luhn digit."""
    body = "0000" + "".join(rng.choice(string.digits) for _ in range(11))
    good = _luhn_check_digit(body)
    return body + str((good + 1 + rng.randrange(8)) % 10)


def fake_phone(rng: random.Random) -> str:
    """North American fictional range: +1 NXX 555-0100..0199."""
    area = rng.choice(["202", "312", "415", "512", "617", "702", "808", "919"])
    return f"+1{area}5550{rng.randrange(100, 200):03d}"


def generate_honeytoken(spec: HoneytokenSpec, seed: str, scenario: str) -> str:
    """Format-plausible, never valid. Every value carries a recognisable fake marker."""
    rng = _rng(seed, scenario, "honeytoken", spec.name)
    up = string.ascii_uppercase + string.digits
    alnum = string.ascii_letters + string.digits
    if spec.kind == "aws_access_key":
        # Real keys start AKIA/ASIA; the 'AKIAFAKE' prefix is not a real key id.
        return "AKIAFAKE" + "".join(rng.choice(up) for _ in range(12))
    if spec.kind == "api_key":
        return "sk_test_hp_" + "".join(rng.choice(alnum) for _ in range(28))
    if spec.kind == "bearer_token":
        return "hpt_" + "".join(rng.choice(alnum) for _ in range(36))
    if spec.kind == "sip_trunk_password":
        return "Trk" + "".join(rng.choice(alnum) for _ in range(13))
    if spec.kind == "ssh_private_key_id":
        return "SHA256:" + "".join(rng.choice(alnum) for _ in range(43))
    # db_password / generic_password
    return "".join(rng.choice(alnum) for _ in range(10)) + rng.choice("!#%@") + str(rng.randrange(10, 99))


class _Gen:
    def __init__(self, rng: random.Random, domain: str) -> None:
        self.rng = rng
        self.domain = domain

    def value(self, spec, index: int):
        r = self.rng
        k = spec.kind
        if k == "seq":
            return int(spec.min or 1) + index
        if k == "uuid":
            return str(uuid.UUID(int=r.getrandbits(128), version=4))
        if k == "first_name":
            return r.choice(FIRST_NAMES)
        if k == "last_name":
            return r.choice(LAST_NAMES)
        if k == "full_name":
            return f"{r.choice(FIRST_NAMES)} {r.choice(LAST_NAMES)}"
        if k == "email":
            dom = self.domain if r.random() < 0.6 else "example.com"
            return f"{r.choice(FIRST_NAMES).lower()}.{r.choice(LAST_NAMES).lower()}{index}@{dom}"
        if k == "phone":
            return fake_phone(r)
        if k == "extension":
            lo, hi = int(spec.min or 100), int(spec.max or 199)
            return str(r.randint(lo, hi))
        if k == "amount":
            lo, hi = spec.min or 1.0, spec.max or 5000.0
            return round(r.uniform(lo, hi), 2)
        if k in ("date", "datetime"):
            base = datetime.datetime(2026, 1, 1)
            days = r.randrange(int(spec.min or 0), int(spec.max or 300) + 1)
            dt = base + datetime.timedelta(days=days, seconds=r.randrange(86400))
            return dt.date().isoformat() if k == "date" else dt.strftime("%Y-%m-%d %H:%M:%S")
        if k == "account_number":
            return spec.prefix + "".join(r.choice(string.digits) for _ in range(10))
        if k == "card_number":
            return fake_card_number(r)
        if k == "iban_like":
            # 'XX' is not an ISO country code, so this can never be a valid IBAN.
            return "XX00" + "".join(r.choice(string.digits) for _ in range(18))
        if k == "mrn":
            return spec.prefix + "".join(r.choice(string.digits) for _ in range(8))
        if k == "word":
            return r.choice(WORDS)
        if k == "sentence":
            return " ".join(r.choice(WORDS) for _ in range(r.randint(3, 7))).capitalize() + "."
        if k == "bool":
            return r.random() < 0.5
        if k == "int":
            return r.randint(int(spec.min or 0), int(spec.max or 1000))
        if k == "ip_private":
            return f"10.{r.randrange(256)}.{r.randrange(256)}.{r.randrange(1, 255)}"
        if k == "choice":
            return r.choice(spec.choices) if spec.choices else None
        if k == "const":
            return spec.value
        return None


@dataclass
class LoadedScenario:
    scenario: Scenario
    seed: str
    overlay: Overlay = field(default_factory=Overlay)
    honeytokens: dict[str, Honeytoken] = field(default_factory=dict)
    path: Optional[Path] = None

    # ---- data ----------------------------------------------------------------------------

    def _find_table(self, db: str, table: str) -> Optional[Table]:
        for svc_name in ("postgres", "mysql", "mssql"):
            svc = getattr(self.scenario.services, svc_name)
            if svc is None:
                continue
            for d in svc.databases:
                if d.name == db:
                    for t in d.tables:
                        if t.name == table:
                            return t
        return None

    def table_rows(self, db: str, table: str) -> tuple[list[str], list[list]]:
        t = self._find_table(db, table)
        if t is None:
            return [], []
        columns = [c.name for c in t.columns]
        rows = [list(r) for r in t.seed_rows]
        if t.generator and t.generator.count:
            gen = _Gen(_rng(self.seed, self.scenario.name, "table", db, table),
                       self.scenario.identity.domain)
            start = len(rows)
            for i in range(t.generator.count):
                row = []
                for col in columns:
                    spec = t.generator.fields.get(col)
                    row.append(gen.value(spec, start + i) if spec else None)
                rows.append(row)
        return columns, rows

    def lookup(self, ref: str) -> tuple[list[str], list[list]]:
        """Resolve 'db.table' used by HTTP routes (list_from / item_from)."""
        db, table = ref.split(".", 1)
        return self.table_rows(db, table)

    # ---- accounts and policy --------------------------------------------------------------

    def accounts_for(self, service: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        if service == "ssh":
            out = [(a.username, a.password) for a in self.scenario.ssh.accounts]
        elif service == "sip":
            svc = self.scenario.services.sip
            if svc:
                out = [(e.extension, e.password) for e in svc.extensions]
            out += [(e.extension, e.password) for e in self.overlay.sip_extensions]
            return out
        else:
            svc = getattr(self.scenario.services, service, None)
            if svc is not None:
                out = [(a.username, a.password) for a in svc.accounts]
        out += [(a.username, a.password) for a in self.overlay.accounts.get(service, [])]
        return out

    def policy_for(self, service: str) -> LoginPolicy:
        svc = getattr(self.scenario.services, service, None)
        base = svc.policy if svc is not None else LoginPolicy()
        ov = self.overlay.policies.get(service)
        if ov is None:
            return base
        return LoginPolicy(accept=base.accept, after_n_min=ov.after_n_min,
                           after_n_max=ov.after_n_max)

    # ---- persona -------------------------------------------------------------------------

    @property
    def hostname(self) -> str:
        return self.overlay.hostname or self.scenario.identity.hostname

    def lures(self) -> list[str]:
        seen: list[str] = []
        for p in list(self.scenario.identity.lures) + list(self.overlay.lures):
            if p not in seen:
                seen.append(p)
        return seen[:25]

    def persona_fragment(self) -> str:
        """Render the SSH/Telnet persona block. Only schema-validated values are emitted."""
        ident = self.scenario.identity
        lines = [
            "Decoy host profile. Every session must see exactly this host:",
            f"- Organization: {ident.org_name}",
            f"- Hostname: {self.hostname} (FQDN {self.hostname}.{ident.domain})",
            f"- Internal IPs: {', '.join(ident.internal_ips)}",
            f"- OS: {ident.os_pretty_name}",
            f"- uname -a: {ident.kernel}",
            f"- Timezone: {ident.timezone}",
        ]
        if ident.users:
            lines.append("- Local users (name:uid:home:shell):")
            for u in ident.users:
                gecos = f" ({u.gecos})" if u.gecos else ""
                lines.append(f"  {u.name}:{u.uid}:{u.home}:{u.shell}{gecos}")
        lures = self.lures()
        if lures:
            lines.append("- These files exist and contain plausible content when read:")
            lines.extend(f"  {p}" for p in lures)
        text = "\n".join(lines)
        if self.scenario.ssh.persona_prompt:
            text += "\n\n" + self.scenario.ssh.persona_prompt.strip()
        # Returned as plain text: callers pass it as a prompt variable or message content,
        # never as template source, so braces are not escaped here.
        return text


# ---- loading -----------------------------------------------------------------------------

def list_scenarios(scenarios_dir: Optional[Path] = None) -> list[str]:
    base = Path(scenarios_dir or SCENARIOS_DIR)
    return sorted(p.parent.name for p in base.glob("*/scenario.toml"))


def _substitute(obj, tokens: dict[str, Honeytoken]):
    if isinstance(obj, str):
        return re.sub(r"\{\{ht:([a-z0-9_]+)\}\}",
                      lambda m: tokens[m.group(1)].value if m.group(1) in tokens else m.group(0),
                      obj)
    if isinstance(obj, list):
        return [_substitute(x, tokens) for x in obj]
    if isinstance(obj, dict):
        return {k: _substitute(v, tokens) for k, v in obj.items()}
    return obj


def load_overlay(path: Optional[os.PathLike | str]) -> Overlay:
    if not path or not os.path.exists(path):
        return Overlay()
    with open(path, "r", encoding="utf-8") as f:
        return Overlay.model_validate_json(f.read())


def load_scenario(name: str, seed: str, overlay_path: Optional[os.PathLike | str] = None,
                  scenarios_dir: Optional[Path] = None) -> LoadedScenario:
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,40}", name or ""):
        raise ValueError(f"invalid scenario name {name!r}")
    base = Path(scenarios_dir or SCENARIOS_DIR)
    path = base / name / "scenario.toml"
    if not path.exists():
        raise FileNotFoundError(f"scenario {name!r} not found ({path})")
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    # Validate the raw file first (placeholders allowed), then plant honeytokens.
    raw_scenario = Scenario.model_validate(raw)
    if raw_scenario.name != name:
        raise ValueError(f"scenario name mismatch: dir {name!r}, file {raw_scenario.name!r}")
    tokens = {
        spec.name: Honeytoken(spec.name, spec.kind,
                              generate_honeytoken(spec, seed, name), tuple(spec.planted_in))
        for spec in raw_scenario.honeytokens
    }
    scenario = Scenario.model_validate(_substitute(raw, tokens))
    return LoadedScenario(scenario=scenario, seed=seed, overlay=load_overlay(overlay_path),
                          honeytokens=tokens, path=path)


def write_honeytokens(loaded: LoadedScenario, path: os.PathLike | str) -> None:
    """Write the scenario's tokens, keeping any per-source planted tokens already listed."""
    planted: list = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            planted = [t for t in json.load(f).get("tokens", [])
                       if isinstance(t, dict) and t.get("planted_for")]
    except (OSError, ValueError, AttributeError):
        planted = []
    payload = {
        "scenario": loaded.scenario.name,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "note": "Fake secrets planted in decoy data. Any use of one is a top-priority signal.",
        "tokens": [
            {"name": t.name, "kind": t.kind, "value": t.value, "planted_in": list(t.planted_in)}
            for t in loaded.honeytokens.values()
        ] + planted,
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".ht-", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, path)


def load_honeytoken_values(path: os.PathLike | str) -> dict[str, str]:
    """Return {value: name} from reports/honeytokens.json; empty if missing or invalid."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {str(t["value"]): str(t["name"]) for t in data.get("tokens", [])
                if isinstance(t, dict) and len(str(t.get("value", ""))) >= 8}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def load_honeytoken_sources(path: os.PathLike | str) -> dict[str, str]:
    """Return {token name: source key} for per-source planted tokens in the registry."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {str(t["name"]): str(t["planted_for"]) for t in data.get("tokens", [])
                if isinstance(t, dict) and t.get("planted_for")}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def find_honeytoken(text: str, values: dict[str, str]) -> Optional[str]:
    if not text:
        return None
    for value, name in values.items():
        if value in text:
            return name
    return None
