"""Tracked export transport: send ``tracked.json`` off the sensor, off by default::

    [connector.tracked_export]
    enabled = false
    kind = s3                 ; s3 | https
    #file = /blocklist/tracked.json
    # kind = s3: PutObject of one fixed key
    bucket = example-honeypot-events
    key = events/tracked/tracked.json
    #region = us-east-1
    #bucket_owner = 123456789012
    #endpoint_url = https://s3.example.com
    # kind = https: one PUT (or POST) of the document
    #url = https://intel.example.com/api/tracked
    #method = PUT
    #secret_env = WINNIE_TRACKED_TOKEN

The respond engine writes the document locally (``respond.write_tracked``) whenever the
list changes and on every run while ``[respond] track_before_enforce`` is on. This module
only reads that file and sends it, so it can run in a process that has the network but
not the agents' state (the AWS exporter mounts the one directory holding it, read-only).

The document is sent whole, when its content (everything but ``generated_at``) differs
from the last copy that was stored, so a removal or an expiry reaches the remote copy on
the next run, and at least once every ``REFRESH_HOURS`` anyway, so the remote
``generated_at`` shows the sensor is still exporting. A failure is
logged, recorded in the export's event file and returned; it never raises and never stops
the other stages. Nothing is retried within a run; the next run tries again.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from agents.connectors.base import DestinationError
from agents.connectors.http import ConfigError as HttpConfigError
from agents.connectors.http import EndpointConfig, HttpEndpoint, UrlTransport, load_endpoint
from agents.objectstore import ConfigError as StoreConfigError
from agents.objectstore import S3Target, error_code, put_object
from agents.ship import _record_event

log = logging.getLogger("agents.tracked")

SECTION = "connector.tracked_export"
STATE_FILE = "tracked_export_state.json"
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
KINDS = ("s3", "https")
REFRESH_HOURS = 24


class ConfigError(ValueError):
    """Load-time problem. Messages never include configured values."""


@dataclass(frozen=True)
class ExportSettings:
    enabled: bool = False
    kind: str = ""
    file: Optional[str] = None
    s3: Optional[S3Target] = None
    https: Optional[EndpointConfig] = None
    method: str = "PUT"

    @classmethod
    def from_config(cls, config) -> "ExportSettings":
        """Read ``[connector.tracked_export]``. Missing or disabled: off. Raises ConfigError."""
        if config is None or not config.has_section(SECTION):
            return cls()
        sec = config[SECTION]
        try:
            enabled = sec.getboolean("enabled", fallback=False)
        except ValueError:
            raise ConfigError("enabled must be true or false") from None
        if not enabled:
            return cls()
        kind = sec.get("kind", "").strip().lower()
        if kind not in KINDS:
            raise ConfigError("kind must be s3 or https")
        file = sec.get("file", "").strip() or None
        if file is not None and not os.path.isabs(file):
            raise ConfigError("file must be an absolute path")
        try:
            if kind == "s3":
                target = S3Target.validate(
                    sec.get("bucket", ""), sec.get("key", ""), sec.get("region", ""),
                    sec.get("bucket_owner", ""), sec.get("endpoint_url", ""),
                    sec.get("timeout", ""), sec.get("allow_private", ""))
                return cls(enabled=True, kind=kind, file=file, s3=target)
            method = sec.get("method", "PUT").strip().upper()
            if method not in ("PUT", "POST"):
                raise ConfigError("method must be PUT or POST")
            return cls(enabled=True, kind=kind, file=file,
                       https=load_endpoint(sec, "tracked_export"), method=method)
        except (StoreConfigError, HttpConfigError, DestinationError) as exc:
            raise ConfigError(str(exc)) from None


def check_document(body: bytes) -> tuple[int, str]:
    """The number of entries in a tracked export and a digest of its content without
    ``generated_at``; raises ValueError if ``body`` is not one. The file crossed a container
    boundary, so it is checked before it leaves the sensor."""
    doc = json.loads(body.decode("utf-8"))
    if not isinstance(doc, dict) or doc.get("version") != 1 \
            or not isinstance(doc.get("entries"), list):
        raise ValueError("not a tracked export")
    for entry in doc["entries"]:
        if not isinstance(entry, dict) or entry.get("status") not in ("tracked", "enforced") \
                or not isinstance(entry.get("address"), str):
            raise ValueError("not a tracked export")
    content = {k: v for k, v in doc.items() if k != "generated_at"}
    digest = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
    return len(doc["entries"]), digest


def _read_state(state_dir: Path) -> dict:
    try:
        data = json.loads((state_dir / STATE_FILE).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(state_dir: Path, digest: str, now: datetime.datetime) -> None:
    import tempfile

    state_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=state_dir, prefix=f".{STATE_FILE}.", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"sha256": digest, "sent_at": now.isoformat(timespec="seconds")}, f)
    os.replace(tmp, state_dir / STATE_FILE)


def _fail(state_dir: Path, summary: dict, error: str, now: datetime.datetime) -> dict:
    summary["error"] = error
    log.error("tracked export: %s; the next run tries again", error)
    _record_event(state_dir, {"timestamp": now.isoformat(timespec="seconds"),
                              "event": "tracked_export_failed", "error": error})
    return summary


def run_export(settings: ExportSettings, default_file, state_dir, *, dry_run: bool = False,
               client_factory=None, transport=None, resolver=None,
               now: Optional[datetime.datetime] = None) -> dict:
    """Send the local tracked export if it changed since the last stored copy. Never raises
    for transport failures."""
    if not settings.enabled:
        return {"status": "disabled"}
    state_dir = Path(state_dir)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    path = Path(settings.file) if settings.file else Path(default_file)
    summary: dict = {"kind": settings.kind}
    try:
        with open(path, "rb") as f:
            body = f.read(MAX_DOCUMENT_BYTES + 1)
    except FileNotFoundError:
        log.info("no tracked export at %s yet; nothing to send", path)
        return {**summary, "status": "no_file"}
    except OSError as exc:
        return _fail(state_dir, summary, f"cannot read the tracked export ({type(exc).__name__})",
                     now)
    if len(body) > MAX_DOCUMENT_BYTES:
        return _fail(state_dir, summary, "the tracked export is larger than "
                     f"{MAX_DOCUMENT_BYTES} bytes", now)
    try:
        summary["entries"], digest = check_document(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return _fail(state_dir, summary, "the local file is not a tracked export", now)
    summary["bytes"] = len(body)
    last = _read_state(state_dir)
    try:
        recent = now - datetime.datetime.fromisoformat(str(last.get("sent_at", ""))) < \
            datetime.timedelta(hours=REFRESH_HOURS)
    except (ValueError, TypeError):
        recent = False
    if last.get("sha256") == digest and recent:
        return {**summary, "status": "unchanged"}
    if dry_run:
        return {**summary, "status": "would send", "dry_run": True}
    if settings.kind == "s3":
        try:
            put_object(settings.s3, body, client_factory)
        except Exception as exc:  # noqa: BLE001 - a failed export never stops a run
            return _fail(state_dir, summary, f"PutObject failed: {error_code(exc)}", now)
    else:
        endpoint = HttpEndpoint(settings.https, state_dir,
                                transport if transport is not None else UrlTransport(), resolver)
        result = endpoint.perform(settings.method, settings.https.url, body)
        if not result.ok:
            return _fail(state_dir, summary, f"{settings.method} failed: {result.status[:80]}",
                         now)
    _save_state(state_dir, digest, now)
    return {**summary, "status": "sent"}
