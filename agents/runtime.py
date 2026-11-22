"""Runtime locations shared by the SSH server, the listeners and the agents CLI.

- Data directory: writable runtime state of the front-end processes (logs, quarantine,
  budget state, sensor seed). ``WINNIE_DATA_DIR`` > ``[honeypot] data_dir`` > ``<repo>/data``.
- Overlay: the tuner-owned ``Overlay`` file. ``WINNIE_OVERLAY`` > ``[scenario] overlay`` >
  ``<repo>/decoy/overlay.json``.
- Sensor seed: drives fake data and honeytokens. Random on first use, stored in the data
  directory with mode 0600, never derived from anything public. ``[scenario] seed`` may
  set it explicitly.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import stat
from configparser import ConfigParser
from pathlib import Path
from typing import Optional

from agents import REPO_ROOT

DATA_DIR_ENV = "WINNIE_DATA_DIR"
OVERLAY_ENV = "WINNIE_OVERLAY"
SEED_FILE = "sensor_seed"

log = logging.getLogger(__name__)


def _section(config: Optional[ConfigParser], name: str):
    return config[name] if config is not None and name in config else {}


def _resolve(base: Optional[Path], value: str) -> Path:
    p = Path(value)
    if p.is_absolute() or base is None:
        return p
    return base / p


def data_dir(config: Optional[ConfigParser] = None, base_dir: Optional[os.PathLike | str] = None,
             override: Optional[os.PathLike | str] = None) -> Path:
    base = Path(base_dir) if base_dir else None
    if override:
        return Path(override)
    if os.environ.get(DATA_DIR_ENV):
        return Path(os.environ[DATA_DIR_ENV])
    configured = _section(config, "honeypot").get("data_dir", "")
    if configured and configured.strip():
        return _resolve(base, configured.strip())
    return REPO_ROOT / "data"


def overlay_path(config: Optional[ConfigParser] = None, base_dir: Optional[os.PathLike | str] = None,
                 override: Optional[os.PathLike | str] = None) -> Path:
    base = Path(base_dir) if base_dir else None
    if override:
        return Path(override)
    if os.environ.get(OVERLAY_ENV):
        return Path(os.environ[OVERLAY_ENV])
    configured = _section(config, "scenario").get("overlay", "")
    if configured and configured.strip():
        return _resolve(base, configured.strip())
    return REPO_ROOT / "decoy" / "overlay.json"


def load_or_create_seed(directory: os.PathLike | str, create: bool = True) -> Optional[str]:
    """Read the sensor seed, creating a random one (mode 0600) on first use.

    Returns None when it does not exist and ``create`` is false or the directory is not
    writable; callers must then run without honeytokens rather than guess a seed.
    """
    path = Path(directory) / SEED_FILE
    for _ in range(2):
        try:
            text = path.read_text(encoding="ascii").strip()
            if re.fullmatch(r"[0-9a-f]{32,128}", text):
                return text
            log.error("sensor seed file %s is malformed; refusing to use it", path)
            return None
        except FileNotFoundError:
            pass
        except OSError as exc:
            log.error("cannot read sensor seed %s: %s", path, exc)
            return None
        if not create:
            return None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue  # another process created it first: read theirs
        except OSError as exc:
            log.error("cannot create sensor seed in %s: %s", path.parent, exc)
            return None
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(secrets.token_hex(32) + "\n")
    return None


def sensor_seed(config: Optional[ConfigParser], directory: os.PathLike | str,
                create: bool = True) -> Optional[str]:
    explicit = _section(config, "scenario").get("seed", "")
    if explicit and explicit.strip():
        return explicit.strip()
    return load_or_create_seed(directory, create=create)


def event_log_state(path: Optional[os.PathLike | str]) -> tuple[str, Optional[str]]:
    """``("ok", None)``; ``("missing", None)`` when the configured log does not exist yet,
    the normal state of a sensor that has not logged an event; or ``("error", message)``
    when no log is configured or the path cannot be read (permission denied, a directory, a
    FIFO or another file that is not a regular file)."""
    if not path:
        return "error", "no event log configured ([honeypot] log_file or --log)"
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return "missing", None
    except PermissionError:
        return "error", f"event log not readable (permission denied): {path}"
    except OSError as exc:
        return "error", f"event log not readable ({exc.strerror or type(exc).__name__}): {path}"
    if stat.S_ISDIR(st.st_mode):
        return "error", f"event log path is a directory: {path}"
    if not stat.S_ISREG(st.st_mode):      # a FIFO or device would block or never end a read
        return "error", f"event log path is not a regular file: {path}"
    if not os.access(path, os.R_OK):
        return "error", f"event log not readable (permission denied): {path}"
    return "ok", None


def respond_settings(config: Optional[ConfigParser]):
    """``RespondSettings`` from ``[respond]`` (defaults without the section). Raises
    ValueError for a bad value."""
    from agents.respond import RespondSettings

    return RespondSettings.from_config(config["respond"] if config is not None
                                       and "respond" in config else {})


def respond_connectors(config: ConfigParser, state_dir: os.PathLike | str):
    """The configured ``Connectors``, or None when the connectors package cannot be
    imported. Configuration errors are logged and leave that connector disabled."""
    try:
        from agents.connectors import Connectors
    except ImportError:
        return None
    conn = Connectors(config, Path(state_dir))
    for err in getattr(conn, "errors", []):
        # Logged under the CLI's logger so the line reads as it did before the move.
        logging.getLogger("agents").error("connector config: %s", err)
    return conn
