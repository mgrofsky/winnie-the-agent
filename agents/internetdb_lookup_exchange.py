"""Delivered InternetDB answers without anything outside the sensor: the exchange step asks
InternetDB itself.

``[connector.internetdb_exchange] kind = lookup`` is the third way to answer the delivered
hand-off (``agents/internetdb_delivered.py``). The process that holds the triage records
(``run-all``, on AWS the agents container with no egress) still only writes the wanted list
and reads ``answers_file``; nothing changes on its side. The exchange step (``ship``, on AWS
the exporter, the one process with egress) reads that list, asks InternetDB about the
addresses on it and merges the answers into ``answers_file``. No object store, no producer.

Everything that touches InternetDB or an answer is the code the other two paths already use:

- The wanted list is checked by ``internetdb_delivered.parse_wanted`` (read with a 64 KB
  cap; a version 1 object whose ``addresses`` are at most 500 distinct canonical global
  addresses, anything else refuses the whole file; other keys are ignored; an address inside
  ``[respond] never_act_on`` is dropped). The file comes from a process that reads attacker
  text, so only the checked addresses are used, and nothing but an address reaches the
  request.
- The lookups are ``internetdb.lookup_addresses``, the loop direct mode runs: the fixed host,
  TLS verification, no redirects, 5 s deadline, 64 KB cap, one request at a time at least
  ``min_interval_seconds`` apart, ``max_per_run`` and ``max_per_day``, answers (including
  "not found") fresh for ``cache_days``, back-off on 429, 5xx or a network failure, and
  ``internetdb.sanitize`` on every answer. The caps are ``[connector.internetdb]``'s.
- Its state (cache, day count, back-off) is this process's own file,
  ``<state-dir>/internetdb_lookup.json``; the agents container cannot write it on AWS.
- Answers reach ``answers_file`` through ``internetdb_delivered.check_answers``, the gate an
  object store answer passes, built in the same answers format, then merged the same way.
  So the file triage and the console read has exactly the shape the s3 path writes.

``addresses_file`` (optional) names a file of IPv4 addresses, one per line, that the host
firewall lets this process reach (``deploy/aws/host/sensor-egress.sh`` writes it). When set,
a lookup connects only to one of those: one the name resolves to now when there is one, else
the first listed. The TLS name check is still for the fixed host, so an address that does
not serve it fails the handshake and backs off like any network failure. Without the file,
or with nothing valid in it, nothing is looked up and the reason is in the result.

Failures never raise: an unreadable list, no pinned address, a refused or rate-limited
request each end up in the run result (and, for errors, the export's event file); the
other stages of the run are unaffected.
"""

from __future__ import annotations

import datetime
import json
import logging
import socket
import time
from pathlib import Path
from typing import Callable, Optional

from agents.internetdb import (
    BASE_URL,
    InternetDbSettings,
    load_state,
    lookup_address,
    lookup_addresses,
)
from agents.internetdb_delivered import (
    MAX_MAX_BYTES,
    MAX_WANTED,
    MAX_WANTED_BYTES,
    VERSION,
    ExchangeSettings,
    InvalidDocument,
    _read_capped,
    check_answers,
    merge_accepted,
    parse_wanted,
)
from agents.ship import _record_event

log = logging.getLogger("agents.internetdb")
UTC = datetime.timezone.utc

STATE_FILE = "internetdb_lookup.json"
MAX_PINNED = 8
MAX_PINNED_BYTES = 4096


# ---- the pinned addresses ------------------------------------------------------------------

def read_pinned(path) -> list[str]:
    """The addresses in ``path``: canonical global IPv4 addresses, one per line, at most
    ``MAX_PINNED``, in order, each once. Other lines are skipped. Raises OSError when the
    file cannot be read and InvalidDocument when it is larger than its cap."""
    body = _read_capped(Path(path), MAX_PINNED_BYTES)
    out: list[str] = []
    for line in body.decode("ascii", errors="replace").splitlines():
        addr = line.strip()
        if lookup_address(addr) == addr and ":" not in addr and addr not in out:
            out.append(addr)
            if len(out) >= MAX_PINNED:
                break
    return out


def pinned_resolver(pinned: list[str], base=socket.getaddrinfo):
    """A resolver for ``internetdb.pin_address`` that answers only with ``pinned``
    addresses: those the name resolves to now, in DNS order, or, when there are none (the
    name moved since the firewall was last refreshed, or DNS failed), the pinned list."""
    allowed = list(pinned)

    def resolve(host, port, proto=0, *args, **kwargs):
        try:
            found = [str(info[4][0]) for info in base(host, port, proto=proto)]
        except (OSError, IndexError, TypeError, ValueError):
            found = []
        hits = [a for a in dict.fromkeys(found) if a in allowed] or allowed
        if not hits:
            raise OSError("no pinned address")
        return [(socket.AF_INET, socket.SOCK_STREAM, proto, "", (a, port)) for a in hits]

    return resolve


# ---- the answers ---------------------------------------------------------------------------

def answers_document(state: dict, wanted: list[str], now: datetime.datetime) -> bytes:
    """The answers object (the s3 path's format) for the addresses on ``wanted`` that the
    lookup state holds a kept answer for. An answer that was not kept is left out, as a
    producer leaves it out."""
    items = []
    for ip in wanted:
        entry = state["entries"].get(ip)
        if entry is None or entry["info"] is None:
            continue
        info = entry["info"]
        item = {"ip": ip, "checked_at": entry["checked_at"].astimezone(UTC)
                .isoformat(timespec="seconds"),
                "status": "found" if info.found else "not_found"}
        if info.found:
            item.update(ports=info.ports, hostnames=info.hostnames, tags=info.tags,
                        cpes=info.cpes, vulns=info.vulns)
        items.append(item)
    return (json.dumps({"version": VERSION,
                        "generated_at": now.astimezone(UTC).isoformat(timespec="seconds"),
                        "answers": items}, separators=(",", ":")) + "\n").encode()


def deliver(settings: InternetDbSettings, state_path: Path, answers_file, wanted: list[str],
            networks: list, now: datetime.datetime) -> tuple[dict, Optional[str]]:
    """Merge the lookup state's answers for ``wanted`` into ``answers_file`` through the
    object store path's checks. Returns ``(counts, error or None)``."""
    body = answers_document(load_state(state_path), wanted, now)
    path = Path(answers_file)
    held = load_state(path)
    accepted, counts = check_answers(body, set(wanted), held["entries"], networks, now,
                                     settings.max_age_days, MAX_MAX_BYTES, MAX_WANTED)
    return counts, merge_accepted(path, held, accepted, settings.max_entries)


# ---- the exchange --------------------------------------------------------------------------

def run_lookup_exchange(exchange: ExchangeSettings, settings: InternetDbSettings, wanted_file,
                        answers_file, state_dir, networks: list, *, dry_run: bool = False,
                        transport=None, resolver=None,
                        now: Optional[datetime.datetime] = None,
                        clock: Callable[[], float] = time.monotonic,
                        sleep: Callable[[float], None] = time.sleep,
                        base_url: str = BASE_URL) -> dict:
    """Read the wanted list, look up what is due, merge the answers into ``answers_file``.
    ``transport``, ``resolver``, ``clock``, ``sleep`` and ``base_url`` exist for tests.
    Never raises for lookup or file failures."""
    if not exchange.enabled:
        return {"status": "disabled"}
    if exchange.kind != "lookup":
        return {"status": "not a lookup exchange"}
    state_dir = Path(state_dir)
    now = now or datetime.datetime.now(UTC)
    summary: dict = {"kind": "lookup"}
    errors: list[str] = []
    wanted: Optional[list[str]] = None
    try:
        wanted, _ = parse_wanted(_read_capped(Path(wanted_file), MAX_WANTED_BYTES), networks)
    except FileNotFoundError:
        summary["wanted"] = "no wanted list yet"
    except OSError as exc:
        errors.append(f"cannot read the wanted list ({type(exc).__name__})")
    except InvalidDocument as exc:
        errors.append(f"the local wanted list is refused: {str(exc)[:100]}")
    else:
        summary["wanted"] = len(wanted)

    state_path = state_dir / STATE_FILE
    if wanted:
        pinned: Optional[list[str]] = None
        if exchange.addresses_file:
            try:
                pinned = read_pinned(exchange.addresses_file)
            except (OSError, InvalidDocument) as exc:
                pinned = []
                why = "not there yet" if isinstance(exc, FileNotFoundError) \
                    else type(exc).__name__
                log.warning("InternetDB: pinned addresses unreadable (%s)", why)
            summary["pinned"] = len(pinned)
        if pinned == [] and not dry_run:
            errors.append("no pinned InternetDB address (the host firewall has none yet); "
                          "no lookups")
        else:
            if pinned:
                resolver = pinned_resolver(pinned, resolver or socket.getaddrinfo)
            result = lookup_addresses(settings, wanted, state_path, dry_run=dry_run,
                                      transport=transport, resolver=resolver, now=now,
                                      clock=clock, sleep=sleep, base_url=base_url)
            summary["lookup"] = result
            if result.get("error"):
                errors.append(result["error"])
    if wanted is not None and not dry_run:
        # Also after a run that asked nothing: answers already held still reach the file.
        try:
            counts, error = deliver(settings, state_path, answers_file, wanted, networks, now)
        except Exception as exc:  # noqa: BLE001 - a failed merge never stops a run
            counts, error = {}, f"answers not merged ({type(exc).__name__})"
        summary["delivered"] = counts.get("accepted", 0)
        if error:
            errors.append(error)

    if dry_run:
        return {**summary, "status": "dry run", "dry_run": True,
                **({"error": "; ".join(errors)} if errors else {})}
    if errors:
        summary["error"] = "; ".join(errors)
        log.error("InternetDB exchange: %s", summary["error"])
        _record_event(state_dir, {"timestamp": now.isoformat(timespec="seconds"),
                                  "event": "internetdb_exchange_failed",
                                  "error": summary["error"]})
    summary.setdefault("status", "error" if errors else "done")
    return summary
