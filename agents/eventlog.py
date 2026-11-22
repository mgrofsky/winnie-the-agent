"""How every writer opens the shared raw event log.

The log holds attempted usernames and passwords, so a new one must be owner-only from its
first byte. Two processes write it (the SSH server and the listeners) and either may create
it, so both open it here: ``O_CREAT`` with mode 0600 in one ``open`` call, with no window in
which a file exists with a wider mode and no later ``chmod``. The mode applies only when the
file is created (a stricter umask can only remove more bits), so a file that already exists
keeps its mode: an operator who pre-creates it 0640 for a reader group keeps that choice, and
an older permissive file stays as it is until the operator tightens it (docs/operations.md,
"Event log permissions"). Writes stay ``O_APPEND``.
"""

from __future__ import annotations

import os

EVENT_LOG_MODE = 0o600


def open_event_log(path: os.PathLike | str, flags: int = os.O_WRONLY | os.O_APPEND | os.O_CREAT
                   ) -> int:
    """Open (creating, owner-only, if needed) the event log for appending; returns the fd."""
    return os.open(path, flags, EVENT_LOG_MODE)
