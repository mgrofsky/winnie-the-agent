"""InternetDB answers delivered through the object store: the sensor never asks InternetDB.

``[connector.internetdb] mode = delivered`` splits the feature in two files that cross the
object store the sensor already writes to:

1. **The wanted list, out.** ``run-all`` writes the addresses it wants looked up (the same
   choice as a direct lookup: ``internetdb.select_addresses``, never an address inside
   ``[respond] never_act_on``, at most ``max_wanted``) to one small local file, by default
   ``internetdb_wanted.json`` next to the blocklist file (as ``tracked.json`` is)::

       {"version": 1, "generated_at": "2026-11-20T12:00:00+00:00",
        "addresses": ["198.51.100.7", "2001:db8::5"]}

   Addresses only: nothing about what a source did. ``[connector.internetdb_exchange]``
   puts it, whole, to one fixed key, when its content changed and at least once a day.

2. **The answers, in.** Something outside the sensor (``deploy/aws/internetdb_lookup.py``
   is a reference) asks InternetDB and writes one object of answers::

       {"version": 1, "generated_at": "2026-11-20T12:05:00Z",
        "answers": [
          {"ip": "198.51.100.7", "checked_at": "2026-11-20T12:04:10Z", "status": "found",
           "ports": [22, 80], "hostnames": ["a.example.net"], "tags": ["vpn"],
           "cpes": ["cpe:/a:openbsd:openssh:7.4"], "vulns": ["CVE-2017-15906"]},
          {"ip": "2001:db8::5", "checked_at": "2026-11-20T12:04:11Z", "status": "not_found"}]}

   The exchange gets it with one GetObject of one fixed key, at most once per
   ``interval_minutes`` and at most ``max_bytes``. Everything in it is untrusted. The whole
   object is refused when it is too large, not JSON, not version 1, or has more than
   ``max_entries`` answers. Each answer is then checked on its own and dropped on any
   problem: the address must be canonical, global, outside ``never_act_on``, and one the
   sensor asked for (the local wanted file) or already holds; ``checked_at`` must parse, be
   no more than five minutes ahead and no older than ``max_age_days``, and be newer than the
   answer already held; ``status`` must be ``found`` or ``not_found``; a found answer goes
   through ``internetdb.sanitize``, exactly the check a direct answer gets. Unknown keys are
   ignored. Accepted answers are merged into the local file ``InternetDbReader`` reads
   (``internetdb.json``, same format, written atomically), so triage, the console and the
   stored record work unchanged.

The two halves may run in different processes: on AWS the agents container (records, no
credentials, no egress) writes the wanted list and the exporter (the instance role, no
records) moves both files. Failures are logged, recorded in the export's event file and
returned; they never raise and never stop the other stages.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from agents.budget import ip_key
from agents.internetdb import (
    BadAnswer,
    InternetDbSettings,
    load_state,
    lookup_address,
    sanitize,
    save_state,
    select_addresses,
)
from agents.objectstore import ConfigError as StoreConfigError
from agents.objectstore import ObjectTooLarge, S3Target, error_code, get_object, put_object
from agents.ship import _record_event
from agents.triage import ShodanInfo, TriageRecord

log = logging.getLogger("agents.internetdb")
UTC = datetime.timezone.utc

SECTION = "connector.internetdb_exchange"
WANTED_FILE = "internetdb_wanted.json"
STATE_FILE = "internetdb_exchange_state.json"
VERSION = 1
MAX_WANTED = 500
MAX_WANTED_BYTES = 64 * 1024
DEFAULT_MAX_BYTES = 4 * 1024 * 1024
MAX_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_ENTRIES = 1000
MAX_MAX_ENTRIES = 5000
DEFAULT_INTERVAL_MINUTES = 15.0
REFRESH_HOURS = 24
FUTURE_SKEW = datetime.timedelta(minutes=5)
STATUSES = ("found", "not_found")
_TS_CAP = 40
# The fields of a found answer handed to ``sanitize``: InternetDB's own answer body.
ANSWER_FIELDS = ("ip", "ports", "hostnames", "tags", "cpes", "vulns")


class ConfigError(ValueError):
    """Load-time problem. Messages never include configured values."""


class InvalidDocument(ValueError):
    """A wanted list or answers object refused as a whole. Fixed text only."""


# ---- settings ------------------------------------------------------------------------------

@dataclass(frozen=True)
class ExchangeSettings:
    enabled: bool = False
    wanted: Optional[S3Target] = None
    answers: Optional[S3Target] = None
    interval_minutes: float = DEFAULT_INTERVAL_MINUTES
    max_bytes: int = DEFAULT_MAX_BYTES
    max_entries: int = DEFAULT_MAX_ENTRIES

    @classmethod
    def from_config(cls, config) -> "ExchangeSettings":
        """Read ``[connector.internetdb_exchange]``. Missing or disabled: off. Needs
        ``[connector.internetdb]`` on in delivered mode. Raises ConfigError."""
        if config is None or not config.has_section(SECTION):
            return cls()
        sec = config[SECTION]
        try:
            enabled = sec.getboolean("enabled", fallback=False)
        except ValueError:
            raise ConfigError("enabled must be true or false") from None
        if not enabled:
            return cls()
        if sec.get("kind", "s3").strip().lower() != "s3":
            raise ConfigError("kind must be s3")
        if not InternetDbSettings.from_config(config).delivered:
            raise ConfigError("needs [connector.internetdb] enabled with mode = delivered")

        def num(name: str, default, lo, hi, kind=int):
            try:
                value = kind(sec.get(name, str(default)).strip())
            except ValueError:
                raise ConfigError(f"{name} must be a number") from None
            if not lo <= value <= hi:
                raise ConfigError(f"{name} must be between {lo} and {hi}")
            return value

        common = (sec.get("bucket", ""),)
        rest = (sec.get("region", ""), sec.get("bucket_owner", ""),
                sec.get("endpoint_url", ""), sec.get("timeout", ""),
                sec.get("allow_private", ""))
        try:
            wanted = S3Target.validate(*common, sec.get("wanted_key", ""), *rest)
            answers = S3Target.validate(*common, sec.get("answers_key", ""), *rest)
        except StoreConfigError as exc:
            raise ConfigError(str(exc)) from None
        if wanted.key == answers.key:
            raise ConfigError("wanted_key and answers_key must differ")
        return cls(enabled=True, wanted=wanted, answers=answers,
                   interval_minutes=num("interval_minutes", DEFAULT_INTERVAL_MINUTES, 1.0,
                                        24 * 60.0, float),
                   max_bytes=num("max_bytes", DEFAULT_MAX_BYTES, 1024, MAX_MAX_BYTES),
                   max_entries=num("max_entries", DEFAULT_MAX_ENTRIES, 1, MAX_MAX_ENTRIES))


def wanted_path(settings: InternetDbSettings, default_dir) -> Path:
    """The local wanted list: ``wanted_file`` or ``internetdb_wanted.json`` in
    ``default_dir`` (the blocklist file's directory)."""
    return Path(settings.wanted_file) if settings.wanted_file else Path(default_dir) / WANTED_FILE


# ---- small helpers -------------------------------------------------------------------------

def _timestamp(value) -> Optional[datetime.datetime]:
    if not isinstance(value, str) or not value or len(value) > _TS_CAP:
        return None
    try:
        dt = datetime.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC)
    except (ValueError, OverflowError):
        return None


def _excluded(address: str, networks: list) -> bool:
    net = ipaddress.ip_network(ip_key(address), strict=False)
    return any(net.version == n.version and net.overlaps(n) for n in networks)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_capped(path: Path, cap: int) -> bytes:
    with open(path, "rb") as f:
        body = f.read(cap + 1)
    if len(body) > cap:
        raise InvalidDocument(f"larger than {cap} bytes")
    return body


# ---- the wanted list -----------------------------------------------------------------------

def wanted_document(addresses: list[str], now: datetime.datetime) -> bytes:
    return (json.dumps({"version": VERSION,
                        "generated_at": now.astimezone(UTC).isoformat(timespec="seconds"),
                        "addresses": addresses}, separators=(",", ":")) + "\n").encode()


def write_wanted(settings: InternetDbSettings, records: Iterable[TriageRecord], networks: list,
                 path, *, now: Optional[datetime.datetime] = None,
                 dry_run: bool = False) -> dict:
    """Write the wanted list atomically: the addresses a direct lookup would choose, most
    important first, at most ``max_wanted`` (and never more than 500)."""
    now = now or datetime.datetime.now(UTC)
    chosen = select_addresses(records, networks, now, settings.lookback_days)
    addresses = chosen[:min(settings.max_wanted, MAX_WANTED)]
    summary = {"wanted": len(addresses), "left_out": len(chosen) - len(addresses)}
    if dry_run:
        return {**summary, "status": "would write", "dry_run": True}
    try:
        _atomic_write(Path(path), wanted_document(addresses, now))
    except OSError as exc:
        summary["error"] = f"cannot write the wanted list ({type(exc).__name__})"
        log.error("InternetDB: %s", summary["error"])
        return summary
    return {**summary, "status": "written"}


def parse_wanted(body: bytes, networks: list) -> tuple[list[str], str]:
    """The addresses of a wanted list and a digest of its content without ``generated_at``.
    The file crossed a container boundary: anything but a well-formed list is refused,
    and an address inside ``networks`` is dropped before it can leave."""
    if len(body) > MAX_WANTED_BYTES:
        raise InvalidDocument(f"larger than {MAX_WANTED_BYTES} bytes")
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise InvalidDocument("not JSON") from None
    if not isinstance(doc, dict) or doc.get("version") != VERSION \
            or isinstance(doc.get("version"), bool):
        raise InvalidDocument("not a version 1 wanted list")
    if _timestamp(doc.get("generated_at")) is None:
        raise InvalidDocument("generated_at is not a timestamp")
    items = doc.get("addresses")
    if not isinstance(items, list) or len(items) > MAX_WANTED:
        raise InvalidDocument(f"addresses must be a list of at most {MAX_WANTED}")
    out: list[str] = []
    for item in items:
        if not isinstance(item, str) or lookup_address(item) != item or item in out:
            raise InvalidDocument("addresses must be distinct global addresses")
        if not _excluded(item, networks):
            out.append(item)
    digest = hashlib.sha256(json.dumps(out).encode()).hexdigest()
    return out, digest


# ---- the answers ---------------------------------------------------------------------------

def check_answers(body: bytes, allowed: set, held: dict, networks: list,
                  now: datetime.datetime, max_age_days: float,
                  max_bytes: int = DEFAULT_MAX_BYTES,
                  max_entries: int = DEFAULT_MAX_ENTRIES) -> tuple[dict, dict]:
    """``(accepted, counts)``: the answers to keep, as ``{address: {"checked_at", "info"}}``
    (the local file's entry form), and how many were dropped or not newer. Raises
    InvalidDocument when the object as a whole is refused."""
    if len(body) > max_bytes:
        raise InvalidDocument(f"larger than {max_bytes} bytes")
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise InvalidDocument("not JSON") from None
    if not isinstance(doc, dict) or doc.get("version") != VERSION \
            or isinstance(doc.get("version"), bool):
        raise InvalidDocument("not a version 1 answers object")
    items = doc.get("answers")
    if not isinstance(items, list):
        raise InvalidDocument("answers must be a list")
    if len(items) > max_entries:
        raise InvalidDocument(f"more than {max_entries} answers")
    oldest = now - datetime.timedelta(days=max_age_days)
    accepted: dict = {}
    counts = {"answers": len(items), "accepted": 0, "dropped": 0, "not_newer": 0}
    for item in items:
        entry = _one_answer(item, allowed, held, networks, now, oldest)
        if entry is None:
            counts["dropped"] += 1
            continue
        addr, value = entry
        current = accepted.get(addr) or held.get(addr)
        if current is not None and value["checked_at"] <= current["checked_at"]:
            counts["not_newer"] += 1
            continue
        accepted[addr] = value
    counts["accepted"] = len(accepted)
    return accepted, counts


def _one_answer(item, allowed: set, held: dict, networks: list, now: datetime.datetime,
                oldest: datetime.datetime) -> Optional[tuple[str, dict]]:
    """One answer checked, or None to drop it."""
    if not isinstance(item, dict):
        return None
    ip = item.get("ip")
    if not isinstance(ip, str) or lookup_address(ip) != ip:
        return None
    if ip not in allowed and ip not in held:
        return None
    if _excluded(ip, networks):
        return None
    checked = _timestamp(item.get("checked_at"))
    if checked is None or checked > now + FUTURE_SKEW or checked < oldest:
        return None
    day = checked.date().isoformat()
    status = item.get("status")
    if status == "not_found":
        return ip, {"checked_at": checked, "info": ShodanInfo(looked_up=day, found=False)}
    if status != "found":
        return None
    raw = {k: item[k] for k in ANSWER_FIELDS if k in item}
    try:
        body = json.dumps(raw).encode()
    except (TypeError, ValueError, RecursionError):
        return None
    try:
        info = sanitize(body, ip, day)
    except BadAnswer:
        return None
    return ip, {"checked_at": checked, "info": info}


# ---- the exchange --------------------------------------------------------------------------

def _state(state_dir: Path) -> dict:
    try:
        data = json.loads((state_dir / STATE_FILE).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _due(last, now: datetime.datetime, period: datetime.timedelta) -> bool:
    """True unless ``last`` is a time within ``period`` before ``now`` (a future time, a
    missing or malformed one: due)."""
    at = _timestamp(last)
    return at is None or not datetime.timedelta(0) <= now - at < period


def run_exchange(exchange: ExchangeSettings, settings: InternetDbSettings, wanted_file,
                 answers_file, state_dir, networks: list, *, dry_run: bool = False,
                 client_factory=None, now: Optional[datetime.datetime] = None) -> dict:
    """Put the local wanted list (when it changed, and at least daily) and get the answers
    (at most once per ``interval_minutes``), merging the accepted ones into the local file.
    ``client_factory`` exists for tests. Never raises for transfer failures."""
    if not exchange.enabled:
        return {"status": "disabled"}
    state_dir = Path(state_dir)
    now = now or datetime.datetime.now(UTC)
    st = _state(state_dir)
    new_state = dict(st)
    summary: dict = {}
    errors: list[str] = []

    # The wanted list, out.
    wanted: list[str] = []
    try:
        body = _read_capped(Path(wanted_file), MAX_WANTED_BYTES)
        wanted, digest = parse_wanted(body, networks)
    except FileNotFoundError:
        summary["wanted"] = "no wanted list yet"
    except OSError as exc:
        errors.append(f"cannot read the wanted list ({type(exc).__name__})")
    except InvalidDocument as exc:
        errors.append(f"the local wanted list is refused: {str(exc)[:100]}")
    else:
        summary["wanted"] = len(wanted)
        changed = st.get("wanted_sha256") != digest
        if not changed and not _due(st.get("wanted_sent_at"), now,
                                    datetime.timedelta(hours=REFRESH_HOURS)):
            summary["put"] = "unchanged"
        elif dry_run:
            summary["put"] = "would put"
        else:
            # Sent as rebuilt from the checked addresses, never the local bytes as read.
            try:
                put_object(exchange.wanted, wanted_document(wanted, now), client_factory)
            except Exception as exc:  # noqa: BLE001 - a failed put never stops a run
                errors.append(f"PutObject failed: {error_code(exc)}")
            else:
                summary["put"] = "sent"
                new_state.update(wanted_sha256=digest,
                                 wanted_sent_at=now.isoformat(timespec="seconds"))

    # The answers, in.
    if not _due(st.get("fetched_at"), now, datetime.timedelta(minutes=exchange.interval_minutes)):
        summary["get"] = "not due"
    elif dry_run:
        summary["get"] = "would get"
    else:
        new_state["fetched_at"] = now.isoformat(timespec="seconds")
        _fetch(exchange, settings, answers_file, set(wanted), networks, now, client_factory,
               summary, errors, st, new_state)

    if dry_run:
        return {**summary, "status": "dry run", "dry_run": True,
                **({"error": "; ".join(errors)} if errors else {})}
    try:
        _atomic_write(state_dir / STATE_FILE, (json.dumps(new_state) + "\n").encode())
    except OSError as exc:
        errors.append(f"cannot write the exchange state ({type(exc).__name__})")
    if errors:
        summary["error"] = "; ".join(errors)
        if summary.pop("logged", True):
            log.error("InternetDB exchange: %s", summary["error"])
            _record_event(state_dir, {"timestamp": now.isoformat(timespec="seconds"),
                                      "event": "internetdb_exchange_failed",
                                      "error": summary["error"]})
    summary.setdefault("status", "error" if errors else "done")
    return summary


def _fetch(exchange: ExchangeSettings, settings: InternetDbSettings, answers_file,
           wanted: set, networks: list, now: datetime.datetime, client_factory,
           summary: dict, errors: list, st: dict, new_state: dict) -> None:
    try:
        body = get_object(exchange.answers, exchange.max_bytes, client_factory)
    except ObjectTooLarge:
        errors.append(f"the answers object is larger than {exchange.max_bytes} bytes")
        return
    except Exception as exc:  # noqa: BLE001 - a failed fetch never stops a run
        code = error_code(exc)
        if "NoSuchKey" in code:
            summary["get"] = "no answers object yet"
        else:
            errors.append(f"GetObject failed: {code}")
        return
    path = Path(answers_file)
    state = load_state(path)
    try:
        accepted, counts = check_answers(body, wanted, state["entries"], networks, now,
                                         settings.max_age_days, exchange.max_bytes,
                                         exchange.max_entries)
    except Exception as exc:  # noqa: BLE001 - anything the check raises is a refusal
        digest = hashlib.sha256(body if isinstance(body, bytes) else b"").hexdigest()
        why = str(exc)[:120] if isinstance(exc, InvalidDocument) \
            else f"could not be checked ({type(exc).__name__})"
        errors.append(f"the answers object is refused: {why}")
        summary["kept"] = "the local answers as they were"
        if st.get("refused_sha256") == digest:
            summary["logged"] = False   # the same bad copy as before: logged once already
        new_state["refused_sha256"] = digest
        return
    new_state["refused_sha256"] = None
    summary.update(get="fetched", **counts)
    if counts["dropped"]:
        log.warning("InternetDB exchange: %d answers dropped by the checks", counts["dropped"])
    if not accepted:
        return
    state["entries"].update(accepted)
    try:
        save_state(path, state, settings.max_entries)
    except OSError as exc:
        errors.append(f"cannot write the local answers ({type(exc).__name__})")
