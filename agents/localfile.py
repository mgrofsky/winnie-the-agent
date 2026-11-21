"""Reading a small local file that another container may have written.

The exporter reads files from the ``blocklist`` volume, which the agents container writes:
the tracked export (``tracked.json``) and the InternetDB wanted list. Whoever writes that
volume could put something other than a plain file at the expected name. ``read_regular``
reads only a regular file reached without following a symlink, never blocks on a FIFO or a
device, and never reads more than ``cap + 1`` bytes, so the caller can still tell an
oversize file from one that fits.
"""

from __future__ import annotations

import os
import stat


class NotRegularFile(OSError):
    """The path is a FIFO, a directory, a device or anything else but a regular file."""


def read_regular(path, cap: int) -> bytes:
    """At most ``cap + 1`` bytes of the regular file at ``path``. Raises FileNotFoundError
    when there is nothing there, NotRegularFile for anything but a regular file, and
    another OSError for a symlink (not followed) or any other failure to read. A normal
    file's bytes are exactly what ``open(path, "rb").read(cap + 1)`` returns."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NotRegularFile("not a regular file")
        with os.fdopen(fd, "rb") as f:
            fd = -1
            return f.read(cap + 1)
    finally:
        if fd >= 0:
            os.close(fd)
