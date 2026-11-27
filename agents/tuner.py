"""Decoy tuner: changes the bait on its own, inside a fence.

It writes exactly one file, the overlay (``decoy/overlay.json`` or ``$WINNIE_OVERLAY``),
which every front-end merges over its configured accounts and the active scenario. It never
writes ``config.ini`` or scenario files, and never removes a configured account.

What it may change:
- fake accounts per service (``ssh``, ``ftp``, ``mysql``, ...): add accounts attackers
  actually try; remove accounts it added itself once nobody has tried them for
  ``lookback_days``;
- SIP extensions; ``after_n`` bounds; lure file paths (built only from fixed allowlists
  of directories and bait names; attacker interest only raises a candidate's score).

Candidate selection is deterministic (frequency counts over triage records in a time
window). A model may only reorder candidates our code generated, by index. Every value is
checked against the fences again right before it is written.

Every apply first stores a numbered snapshot of the previous overlay, so any run can be
undone with ``python -m agents tune --rollback N`` (see ``--history``). A git commit of
the overlay is opt-in (``--git-commit``) for checkouts; if it fails the overlay is rolled
back to the snapshot. ``--dry-run`` prints the diff and writes nothing.

The tuner does not change the SSH banner (a banner change needs a restart, and
alternating banners is itself a tell).
"""

from __future__ import annotations

import datetime
import difflib
import json
import logging
import os
import re
import secrets
import subprocess
import tempfile
from collections import Counter
from configparser import ConfigParser, Error as ConfigParserError
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agents.llm import JsonLLM, LLMOutputError, LLMRequestError, LLMUnavailable, untrusted_block
from agents.triage import IocType, TriageRecord, load_records
from scenarios.loader import SCENARIOS_DIR
from scenarios.schema import (
    HOSTNAME_RE,
    LURE_PATH_RE,
    OVERLAY_SERVICES,
    SIP_EXTENSION_RE,
    USERNAME_RE,
    Overlay,
    OverlayAccount,
    OverlayPolicy,
    OverlaySipExtension,
    valid_password,
)

log = logging.getLogger(__name__)

MAX_ACCOUNTS = 20
MAX_LURES = 25
DEFAULT_MAX_CHANGES = 3
MIN_ATTEMPTS = 3
DEFAULT_LOOKBACK_DAYS = 14
UTC = datetime.timezone.utc


# Lure candidates are built only from these; attacker text never becomes part of a path.
LURE_DIRS = ("/root", "/opt/backup", "/var/backups", "/srv/app", "/etc/app")
LURE_NAMES = (
    ".aws/credentials", ".ssh/id_rsa", ".ssh/id_ed25519", ".env", ".git-credentials",
    ".docker/config.json", ".kube/config", ".pgpass", ".my.cnf", "backup.sql",
    "db_backup.sql.gz", "passwords.txt", "credentials.json", "secrets.yaml",
    "wallet.dat", "config.php.bak", "id_rsa.bak",
)

TUNER_SERVICES = OVERLAY_SERVICES  # includes "ssh"


class DecoyChange(BaseModel):
    """One fenced change. Validated again before it is applied."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["add_account", "remove_account", "set_hostname", "add_lure",
                  "add_sip_extension", "set_after_n"]
    service: Optional[str] = Field(default=None, pattern=r"^[a-z]{2,10}$")
    username: Optional[str] = None
    password: Optional[str] = None
    value: Optional[str] = None
    after_n_min: Optional[int] = Field(default=None, ge=1, le=20)
    after_n_max: Optional[int] = Field(default=None, ge=1, le=20)
    reason: str = Field(default="", max_length=200, pattern=r"^[A-Za-z0-9 ,.:()_/=-]*$")

    def describe(self) -> str:
        if self.kind in ("add_account", "remove_account"):
            return f"{self.kind} {self.service}:{self.username}"
        if self.kind == "add_sip_extension":
            return f"add_sip_extension {self.username}"
        if self.kind == "set_after_n":
            return f"set_after_n {self.service} {self.after_n_min}-{self.after_n_max}"
        return f"{self.kind} {self.value}"


class RankOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order: list[int] = Field(max_length=50)


class FenceError(ValueError):
    pass


def _fits(pattern: str, value: Optional[str]) -> bool:
    # fullmatch: '$' alone would accept a trailing newline.
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def lure_candidates(users: tuple[str, ...] = ()) -> set[str]:
    dirs = list(LURE_DIRS) + [f"/home/{u}" for u in users if _fits(USERNAME_RE, u)]
    return {f"{d}/{n}" for d in dirs for n in LURE_NAMES}


# ---- fences ---------------------------------------------------------------------------------

def check_change(c: DecoyChange, allowed_lures: Optional[set[str]] = None) -> None:
    """Raise FenceError unless the change is inside the fence."""
    if c.kind in ("add_account", "remove_account"):
        if c.service not in TUNER_SERVICES:
            raise FenceError("service outside fence")
        if not _fits(USERNAME_RE, c.username):
            raise FenceError("username outside fence")
        if c.kind == "add_account" and (c.password is None or not valid_password(c.password)):
            raise FenceError("password outside fence")
    elif c.kind == "add_sip_extension":
        if not _fits(SIP_EXTENSION_RE, c.username):
            raise FenceError("extension outside fence")
        if c.password is None or not valid_password(c.password):
            raise FenceError("password outside fence")
    elif c.kind == "set_hostname":
        if not _fits(HOSTNAME_RE, c.value):
            raise FenceError("hostname outside fence")
    elif c.kind == "add_lure":
        if not _fits(LURE_PATH_RE, c.value):
            raise FenceError("lure path outside fence")
        if c.value not in (allowed_lures if allowed_lures is not None else lure_candidates()):
            raise FenceError("lure path not built from the allowlists")
    elif c.kind == "set_after_n":
        if c.service not in TUNER_SERVICES + ("sip",):
            raise FenceError("service outside fence")
        if c.after_n_min is None or c.after_n_max is None or c.after_n_min > c.after_n_max:
            raise FenceError("after_n bounds outside fence")


# ---- evidence (triage records in a time window) --------------------------------------------

@dataclass
class Evidence:
    users: dict[str, Counter] = field(default_factory=dict)   # service -> username counts
    pairs: dict[str, Counter] = field(default_factory=dict)   # service -> (user, pw) counts
    sip_exts: Counter = field(default_factory=Counter)
    sip_pairs: Counter = field(default_factory=Counter)
    lure_interest: Counter = field(default_factory=Counter)  # candidate path -> records
    campaign_attempts: dict[str, list[int]] = field(default_factory=dict)


def _in_window(r: TriageRecord, since: datetime.datetime) -> bool:
    stamp = r.last_seen or r.first_seen
    if not stamp:
        return False
    try:
        ts = datetime.datetime.fromisoformat(stamp)
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts >= since


def lure_for(path: str, allowed: set[str]) -> Optional[str]:
    """Map a path an attacker went for to one allowlisted candidate (or None).

    An exact allowlisted path maps to itself; otherwise a path ending in a bait name maps
    to ``/root/<bait>``. Only the bait name is recognised; nothing from the path is copied."""
    if path in allowed:
        return path
    for name in LURE_NAMES:
        if path.endswith("/" + name):
            cand = f"/root/{name}"
            return cand if cand in allowed else None
    return None


def gather_evidence(records: list[TriageRecord], candidates: set[str],
                    since: datetime.datetime) -> Evidence:
    ev = Evidence()
    for r in records:
        if r.unverified_source or not _in_window(r, since):
            continue  # spoofable sources and old activity never drive changes
        if r.protocol == "sip":
            ev.sip_exts.update(dict(r.credentials.sip_extensions))
            ev.sip_pairs.update({(u, p): n for u, p, n in r.credentials.top_pairs})
        else:
            ev.users.setdefault(r.protocol, Counter()).update(dict(r.credentials.top_usernames))
            ev.pairs.setdefault(r.protocol, Counter()).update(
                {(u, p): n for u, p, n in r.credentials.top_pairs})
        if r.kind == "campaign":
            ev.campaign_attempts.setdefault(r.protocol, []).append(r.auth_attempts)
        wanted = {lure_for(i.value, candidates) for i in r.iocs if i.type == IocType.FILE_PATH}
        for cand in wanted - {None}:
            ev.lure_interest[cand] += 1  # once per record
    return ev


def _best_password(pairs: Counter, user: str) -> str:
    for (u, p), _ in pairs.most_common():
        if u == user and p != "<unknown>" and valid_password(p):
            return p
    return "*"


def candidates(ev: Evidence, overlay: Overlay, existing: dict[str, set[str]],
               scenario_lures: list[str], tuner_state: dict, since: datetime.datetime,
               allowed_lures: set[str]) -> list[DecoyChange]:
    out: list[DecoyChange] = []
    for svc, users in sorted(ev.users.items()):
        if svc not in TUNER_SERVICES:
            continue
        have = existing.get(svc, set()) | {a.username for a in overlay.accounts.get(svc, [])}
        for user, n in users.most_common(5):
            if n < MIN_ATTEMPTS or user in have or not _fits(USERNAME_RE, user):
                continue
            out.append(DecoyChange(kind="add_account", service=svc, username=user,
                                   password=_best_password(ev.pairs.get(svc, Counter()), user),
                                   reason=f"tried {n} times on {svc}"))
    # Remove only accounts the tuner added, after a full window with no attempts.
    for svc, added in sorted(tuner_state.get("added_accounts", {}).items()):
        for user, added_at in sorted(added.items()):
            try:
                when = datetime.datetime.fromisoformat(added_at)
            except (TypeError, ValueError):
                continue
            if when < since and ev.users.get(svc, Counter()).get(user, 0) == 0 and \
                    any(a.username == user for a in overlay.accounts.get(svc, [])):
                out.append(DecoyChange(kind="remove_account", service=svc, username=user,
                                       reason="no attempts in window"))
    have_ext = existing.get("sip", set()) | {e.extension for e in overlay.sip_extensions}
    for ext, n in ev.sip_exts.most_common(5):
        if n < MIN_ATTEMPTS or ext in have_ext or not _fits(SIP_EXTENSION_RE, ext):
            continue
        out.append(DecoyChange(kind="add_sip_extension", username=ext,
                               password=_best_password(ev.sip_pairs, ext),
                               reason=f"registered {n} times"))
    for svc, attempts in sorted(ev.campaign_attempts.items()):
        if svc not in TUNER_SERVICES + ("sip",) or len(attempts) < 5:
            continue
        median = sorted(attempts)[len(attempts) // 2]
        current = overlay.policies.get(svc)
        cur_min = current.after_n_min if current else 2
        if 1 <= median < cur_min:
            out.append(DecoyChange(kind="set_after_n", service=svc, after_n_min=max(1, median),
                                   after_n_max=max(median + 2, 2),
                                   reason=f"median attempts {median}"))
    present = set(scenario_lures) | set(overlay.lures)
    for path, n in ev.lure_interest.most_common():
        if n < 2 or path in present or path not in allowed_lures:
            continue
        out.append(DecoyChange(kind="add_lure", value=path, reason=f"wanted in {n} sessions"))
    return out


def model_rank(llm: Optional[JsonLLM], cands: list[DecoyChange]) -> list[DecoyChange]:
    """The model may only reorder our candidates by index. Anything else is ignored."""
    if llm is None or len(cands) < 2:
        return cands
    listing = "\n".join(json.dumps({"index": i, "change": c.describe()}) for i, c in enumerate(cands))
    system = ("You rank candidate honeypot bait changes by how likely they are to keep attackers "
              "engaged. Return only {\"order\": [indices]} using indices from the list.")
    try:
        out = llm.complete_json(system, untrusted_block("candidate list", listing,
                                                        secrets.token_hex(8)), RankOutput)
        order = RankOutput.model_validate(out.model_dump() if hasattr(out, "model_dump") else out).order
    except (LLMOutputError, LLMRequestError, LLMUnavailable, ValidationError, ValueError,
            TypeError, AttributeError):
        log.warning("tuner rank output unavailable or invalid; using deterministic order")
        return cands
    seen, ranked = set(), []
    for i in order:
        if isinstance(i, int) and 0 <= i < len(cands) and i not in seen:
            seen.add(i)
            ranked.append(cands[i])
    ranked += [c for i, c in enumerate(cands) if i not in seen]
    return ranked


# ---- files, snapshots, git ------------------------------------------------------------------

def _atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _read(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def _restore(path: Path, text: Optional[str]) -> None:
    if text is None:
        path.unlink(missing_ok=True)
    else:
        _atomic_write(path, text)


def _snapshot_dir(state_dir: Path) -> Path:
    return state_dir / "overlay-snapshots"


def history(state_dir: os.PathLike | str) -> list[dict]:
    """Snapshots, oldest first: [{n, timestamp, action, changes}]."""
    out = []
    for p in sorted(_snapshot_dir(Path(state_dir)).glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            out.append({"n": int(data["n"]), "timestamp": data.get("timestamp"),
                        "action": data.get("action", "tune"), "changes": data.get("changes", [])})
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            continue
    return out


def _take_snapshot(state_dir: Path, previous: Optional[str], action: str,
                   changes: list[str]) -> int:
    sdir = _snapshot_dir(state_dir)
    sdir.mkdir(parents=True, exist_ok=True)
    existing = [int(p.stem) for p in sdir.glob("*.json") if p.stem.isdigit()]
    n = max(existing, default=0) + 1
    payload = {"n": n, "timestamp": datetime.datetime.now(UTC).isoformat(timespec="seconds"),
               "action": action, "changes": changes, "previous_overlay": previous}
    _atomic_write(sdir / f"{n:06d}.json", json.dumps(payload, indent=2), mode=0o600)
    return n


def rollback(overlay_path: os.PathLike | str, state_dir: os.PathLike | str, n: int) -> dict:
    """Restore the overlay exactly as it was before snapshot ``n`` was applied.

    The current overlay is snapshotted first, so a rollback can itself be rolled back."""
    overlay_path, state_dir = Path(overlay_path), Path(state_dir)
    snap = _snapshot_dir(state_dir) / f"{int(n):06d}.json"
    if not snap.exists():
        raise FenceError(f"no snapshot {n}")
    data = json.loads(snap.read_text(encoding="utf-8"))
    previous = data.get("previous_overlay")
    if previous is not None:
        Overlay.model_validate_json(previous)  # never restore something invalid
    current = _read(overlay_path)
    taken = _take_snapshot(state_dir, current, f"rollback to before {n}", [])
    _restore(overlay_path, previous)
    return {"restored_before": int(n), "snapshot_of_current": taken}


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    # Identity via environment only; git config is never touched.
    env.setdefault("GIT_AUTHOR_NAME", "winnie-tuner")
    env.setdefault("GIT_AUTHOR_EMAIL", "tuner@winnie.invalid")
    env.setdefault("GIT_COMMITTER_NAME", "winnie-tuner")
    env.setdefault("GIT_COMMITTER_EMAIL", "tuner@winnie.invalid")
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,  # noqa: S603, S607 - fixed git argv, no shell; git from PATH in the agents image
                          env=env, timeout=60)


def _git_commit(overlay_path: Path, message: str) -> Optional[str]:
    """Commit only the overlay. Returns the commit id, or None on any failure."""
    try:
        top = _git(overlay_path.parent, "rev-parse", "--show-toplevel")
        if top.returncode != 0:
            return None
        repo = Path(top.stdout.strip())
        rel = str(overlay_path.resolve().relative_to(repo.resolve()))
        if _git(repo, "add", "--", rel).returncode != 0:
            return None
        if _git(repo, "commit", "-q", "-m", message, "--", rel).returncode != 0:
            return None
        return _git(repo, "rev-parse", "HEAD").stdout.strip() or None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


# ---- main entry -----------------------------------------------------------------------------

@dataclass
class TuneResult:
    changes: list[DecoyChange]
    rejected: list[str]
    diff: str
    snapshot: Optional[int] = None
    commit: Optional[str] = None
    errors: list[str] = field(default_factory=list)


def config_accounts(config_path: Optional[os.PathLike | str]) -> tuple[set[str], Optional[str]]:
    """Usernames in config.ini [user_accounts] (read-only). Returns (names, error)."""
    if not config_path or not os.path.exists(config_path):
        return set(), None
    try:
        cp = ConfigParser()
        cp.read(config_path)
        return (set(dict(cp.items("user_accounts"))) if "user_accounts" in cp else set()), None
    except (ConfigParserError, OSError, UnicodeDecodeError) as exc:
        return set(), f"config not readable ({type(exc).__name__}); SSH account checks skipped"


def tune(overlay_path: os.PathLike | str, reports_dir: os.PathLike | str,
         state_dir: Optional[os.PathLike | str] = None, llm: Optional[JsonLLM] = None,
         dry_run: bool = False, max_changes: int = DEFAULT_MAX_CHANGES, scenario=None,
         config_path: Optional[os.PathLike | str] = None, git_commit: bool = False,
         proposed: Optional[list] = None, now: Optional[datetime.datetime] = None,
         lookback_days: int = DEFAULT_LOOKBACK_DAYS) -> TuneResult:
    """Generate, fence and apply at most ``max_changes`` changes to the overlay.

    ``proposed`` replaces candidate generation (tests feed hostile changes through it).
    ``scenario`` (LoadedScenario) supplies existing accounts, users and lures; read-only.
    """
    overlay_path = Path(overlay_path)
    reports_dir = Path(reports_dir)
    state_dir = Path(state_dir) if state_dir else reports_dir / "state" / "tuner"
    if overlay_path.resolve().is_relative_to(SCENARIOS_DIR.resolve()) or \
            overlay_path.name in ("scenario.toml", "config.ini"):
        raise FenceError("the tuner only writes the overlay file")
    now = now or datetime.datetime.now(UTC)
    since = now - datetime.timedelta(days=lookback_days)
    errors: list[str] = []

    overlay_text = _read(overlay_path)
    try:
        overlay = Overlay.model_validate_json(overlay_text) if overlay_text else Overlay()
    except ValidationError:
        return TuneResult([], [], "", errors=["current overlay is invalid; refusing to edit it"])
    state_file = state_dir / "state.json"
    try:
        tuner_state = json.loads(state_file.read_text())
        if not isinstance(tuner_state, dict):
            tuner_state = {}
    except (OSError, ValueError):
        tuner_state = {}

    existing: dict[str, set[str]] = {}
    users: tuple[str, ...] = ()
    scen_lures: list[str] = []
    if scenario is not None:
        for svc in TUNER_SERVICES + ("sip",):
            existing[svc] = {u for u, _ in scenario.accounts_for(svc)}
        users = tuple(u.name for u in scenario.scenario.identity.users)
        scen_lures = list(scenario.scenario.identity.lures)
    names, cfg_error = config_accounts(config_path)
    if cfg_error:
        errors.append(cfg_error)
    existing["ssh"] = existing.get("ssh", set()) | names
    allowed = lure_candidates(users)

    if proposed is None:
        records = load_records(reports_dir)
        ev = gather_evidence(records, allowed, since)
        proposed = model_rank(llm, candidates(ev, overlay, existing, scen_lures, tuner_state,
                                              since, allowed))

    applied: list[DecoyChange] = []
    rejected: list[str] = []
    ov = overlay.model_copy(deep=True)
    added = {svc: dict(v) for svc, v in tuner_state.get("added_accounts", {}).items()}
    for change in proposed:
        if len(applied) >= max_changes:
            break
        try:
            change = DecoyChange.model_validate(
                change.model_dump() if isinstance(change, BaseModel) else change)
            check_change(change, allowed)
            if change.kind == "add_account":
                lst = ov.accounts.setdefault(change.service, [])
                if len(lst) >= MAX_ACCOUNTS:
                    raise FenceError("max accounts reached")
                if any(a.username == change.username for a in lst) or \
                        change.username in existing.get(change.service, set()):
                    raise FenceError("account already exists")
                lst.append(OverlayAccount(username=change.username, password=change.password))
                added.setdefault(change.service, {})[change.username] = now.isoformat()
            elif change.kind == "remove_account":
                if change.username not in added.get(change.service, {}):
                    raise FenceError("only accounts the tuner added can be removed")
                lst = ov.accounts.get(change.service, [])
                remaining = [a for a in lst if a.username != change.username]
                if not remaining and not existing.get(change.service):
                    raise FenceError("never remove the last account")
                ov.accounts[change.service] = remaining
                added[change.service].pop(change.username, None)
            elif change.kind == "set_hostname":
                ov.hostname = change.value
            elif change.kind == "add_lure":
                if len(ov.lures) >= MAX_LURES:
                    raise FenceError("max lures reached")
                if change.value not in ov.lures:
                    ov.lures.append(change.value)
            elif change.kind == "add_sip_extension":
                if len(ov.sip_extensions) >= MAX_ACCOUNTS:
                    raise FenceError("max SIP extensions reached")
                ov.sip_extensions.append(OverlaySipExtension(extension=change.username,
                                                             password=change.password))
            elif change.kind == "set_after_n":
                ov.policies[change.service] = OverlayPolicy(after_n_min=change.after_n_min,
                                                            after_n_max=change.after_n_max)
            applied.append(change)
        except (FenceError, ValidationError, ValueError, TypeError) as exc:
            rejected.append(f"{type(exc).__name__}: {str(exc)[:120]}")
            log.warning("tuner change rejected: %s", type(exc).__name__)

    # Re-validate the whole overlay before anything is written.
    ov = Overlay.model_validate(ov.model_dump())
    new_text = ov.model_dump_json(indent=2) + "\n" if ov != overlay else (overlay_text or "")
    old_text = overlay_text or ""
    diff = "".join(difflib.unified_diff(old_text.splitlines(True), new_text.splitlines(True),
                                        str(overlay_path), str(overlay_path)))
    result = TuneResult(changes=applied, rejected=rejected, diff=diff, errors=errors)
    if dry_run or not applied or not diff:
        return result

    described = [c.describe() for c in applied]
    result.snapshot = _take_snapshot(state_dir, overlay_text, "tune", described)
    _atomic_write(overlay_path, new_text)
    if git_commit:
        message = "chore(tuner): decoy changes\n\n" + "\n".join(f"- {d}" for d in described)
        result.commit = _git_commit(overlay_path, message)
        if result.commit is None:
            _restore(overlay_path, overlay_text)
            result.errors.append("git commit failed; overlay rolled back to the snapshot")
            result.changes = []
            return result

    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    record = {"timestamp": stamp, "snapshot": result.snapshot, "changes": [c.model_dump() for c in applied],
              "rejected": rejected, "commit": result.commit}
    _atomic_write(reports_dir / "tuner" / f"{stamp}-{secrets.token_hex(3)}.json",
                  json.dumps(record, indent=2))
    _atomic_write(state_file, json.dumps({"added_accounts": added}, indent=2), mode=0o600)
    return result
