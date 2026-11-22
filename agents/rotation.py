"""Whether the event log can be rotated without losing events a reader has not handled.

Two readers consume the log, each with its own cursor in a state directory: triage
(``triage_cursor.json``) and the event export (``ship_cursor.json``). A cursor records the
log file it read (its inode and first-line hash, shown only as an opaque ``generation``),
the byte offset up to which everything is handled, and a fingerprint (``tail``) of the bytes
just before that offset as they were when the cursor was saved.

The log may be rotated when every required reader's cursor names the log's current
generation, sits exactly at the end of the newline-complete lines, and still matches the
content there, and no unfinished line is being written. The log is sampled through one
descriptor before the cursors are read and again after; if it moved in between, the answer
is no.

A command can only read the cursors in its own state directory. On a single host both
readers share one, and the answer covers both. Where the readers keep separate state (the
AWS sensor: triage in the agents container, the export in another), a required reader whose
cursor is not here is reported as unconfirmed and ``safe`` stays false: the answer is then
``scope = "partial"`` and never an all-clear. The operator compares the attestations the two
containers print for the same log (docs/operations.md, "Rotating the event log"). Nothing
here needs a mount shared between those containers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

from agents.sessions import (Cursor, LogSample, NotRegularFile, log_generation, rewritten,
                             sample_log)

TRIAGE_CURSOR = "triage_cursor.json"
SHIP_CURSOR = "ship_cursor.json"          # agents.ship.CURSOR_FILE
CURSOR_FILES = {"triage": TRIAGE_CURSOR, "ship": SHIP_CURSOR}
SHOWN = 16                                # hex digits of a fingerprint that are printed


def required_readers(listed: Iterable[str], export_enabled: bool) -> list[str]:
    """Readers that must confirm: triage always, the export when enabled in this config,
    and every reader the config lists (``[agents] log_readers``, for one that runs in
    another container)."""
    wanted = {"triage", *[r.strip().lower() for r in listed if r.strip()]}
    if export_enabled:
        wanted.add("ship")
    known = [n for n in CURSOR_FILES if n in wanted]
    return known + sorted(wanted - set(known))


def local_readers(export_enabled: bool) -> set[str]:
    """Readers this configuration runs itself. Only these can be confirmed from a cursor
    here: a required reader that is disabled in this config is never confirmed by a cursor
    it may have left behind."""
    return {"triage"} | ({"ship"} if export_enabled else set())


def parse_reader_list(value: object) -> list[str]:
    return str(value or "").replace(",", " ").split()


def _short(value: Optional[str]) -> Optional[str]:
    return value[:SHOWN] if value else None


def _reader(name: str, cursor_dir: Path, local: bool, result: object) -> tuple[Optional[Cursor], dict, Optional[str]]:
    """What can be said about one reader without the log: its cursor, its state if that is
    already decided, and the reason it does not confirm."""
    if name not in CURSOR_FILES:
        return None, {"state": "unknown"}, f"{name}: not a known log reader (use triage or ship)"
    if isinstance(result, dict) and "error" in result:
        return None, {"state": "failed"}, f"{name}: its last run failed, so nothing is confirmed"
    cursor_file = cursor_dir / CURSOR_FILES[name]
    if not local:
        return None, {"state": "unconfirmed"}, (
            f"{name}: disabled in this configuration or run in another container; this "
            "command cannot confirm it, so compare its own attestation")
    if not cursor_file.exists():
        return None, {"state": "unconfirmed"}, (
            f"{name}: no cursor in this state directory ({cursor_dir}); it has not run here")
    return Cursor(cursor_file), {}, None


def _judge(name: str, cursor: Cursor, post: LogSample, result: object) -> tuple[dict, Optional[str]]:
    """One reader's cursor against the log's boundary."""
    generation = log_generation(cursor.inode, cursor.head)
    info = {"confirmed_offset": cursor.offset, "generation": generation}
    if generation != post.generation or cursor.offset > post.end:
        return ({"state": "other_generation", **info},
                f"{name}: its position belongs to a different log generation (the log was "
                "replaced, rotated or truncated since it last ran)")
    if cursor.tail is None:
        return ({"state": "unverified", **info},
                f"{name}: its cursor has no content fingerprint (saved by an older version, "
                "or the log changed while it ran); run it once more")
    if post.tails.get(cursor.offset) != cursor.tail or (
            cursor.size == post.size and cursor.mtime_ns != post.mtime_ns):
        # Same size as when the cursor was saved yet modified since: an in-place rewrite,
        # even one that left the bytes around the boundary alone.
        return ({"state": "other_generation", **info},
                f"{name}: the log content before its position changed since it last ran "
                "(rewritten in place)")
    info["tail"] = _short(cursor.tail)
    behind = post.end - cursor.offset
    if behind:
        extra = ""
        if isinstance(result, dict) and result.get("deferred"):
            extra = f" ({len(result['deferred'])} deferred)"
        return ({"state": "behind", "behind_bytes": behind, **info},
                f"{name}: {behind} bytes of the log are not handled yet{extra}")
    return {"state": "confirmed", "behind_bytes": 0, **info}, None


def _blocked(pending: list[str], log: Optional[dict] = None, readers: Optional[dict] = None,
             scope: str = "complete") -> dict:
    return {"safe": False, "pending": pending, "scope": scope, "log": log,
            "readers": readers or {}}


def rotation_status(results: dict, log_path, state_dir, readers: list[str],
                    local: Optional[Iterable[str]] = None,
                    config_error: Optional[str] = None) -> dict:
    """``{"safe", "pending", "scope", "log", "readers"}``.

    ``safe`` is true only when the log does not exist or is empty and no reader or the
    configuration is in error, or every reader in ``readers`` is confirmed at the log's
    current boundary. ``pending`` says why not. ``scope`` is ``"complete"`` when every
    required reader could be checked here and ``"partial"`` when one lives elsewhere: then
    ``safe`` is false whatever this reader says. ``local`` names the readers this
    configuration runs (default: all of ``readers``).
    """
    local_set = set(readers) if local is None else set(local)
    pending: list[str] = []
    if config_error:
        pending.append("the configuration could not be read, so the set of readers is "
                       f"unknown ({config_error})")
    failures = list(pending)          # errors that count even when the log is missing or empty
    cursors: dict[str, Cursor] = {}
    info: dict[str, dict] = {}
    for name in readers:
        cursor, decided, why = _reader(name, Path(state_dir), name in local_set, results.get(name))
        info[name] = decided
        if cursor is not None:
            cursors[name] = cursor
        if why is not None:
            pending.append(why)
            if decided["state"] in ("failed", "unknown"):
                failures.append(why)
    elsewhere = any(i.get("state") == "unconfirmed" for i in info.values())

    if not log_path:
        return _blocked(pending + ["no event log path is configured"], readers=info)
    try:
        before = sample_log(log_path)
    except FileNotFoundError:
        # A log that was never created holds nothing, unless something else is wrong.
        return {"safe": not failures, "pending": failures, "scope": "complete", "log": None,
                "readers": info}
    except NotRegularFile:
        return _blocked(pending + [f"the event log {log_path} is not a regular file"],
                        readers=info)
    except OSError as exc:
        return _blocked(pending + ["the event log cannot be read "
                                   f"({exc.strerror or type(exc).__name__}); no reader can "
                                   "have confirmed it"], readers=info)
    offsets = [c.offset for c in cursors.values()]
    try:
        post = sample_log(log_path, offsets)
    except OSError as exc:
        return _blocked(pending + [f"the event log changed or became unreadable while it was "
                                   f"checked ({exc.strerror or type(exc).__name__})"],
                        readers=info)
    log = {"generation": post.generation, "complete_bytes": post.end,
           "partial_bytes": post.size - post.end, "tail": _short(post.tails[post.end])}
    if (before.size, before.end, before.mtime_ns) != (post.size, post.end, post.mtime_ns) \
            or rewritten(before, post):
        return _blocked(pending + ["the log moved while it was being checked; run the check "
                                   "again with the writers stopped"], log, info,
                        "partial" if elsewhere else "complete")
    if post.size == 0:
        # An empty log holds nothing to lose, but a failed reader or a bad config still counts.
        return {"safe": not failures, "pending": failures, "scope": "complete", "log": log,
                "readers": info}
    for name, cursor in cursors.items():
        info[name], why = _judge(name, cursor, post, results.get(name))
        if why is not None:
            pending.append(why)
    if post.size - post.end:
        pending.append(f"the log ends with {post.size - post.end} bytes of an unfinished "
                       "line: a writer is active")
    return {"safe": not pending, "pending": pending,
            "scope": "partial" if elsewhere else "complete", "log": log, "readers": info}
