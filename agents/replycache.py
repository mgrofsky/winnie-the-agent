"""Model replies kept for sessions that replay the same conversation.

Bots run the same script against every host, so many sessions send the same lines in the
same order. A model reply is stored under a key built from everything that shaped it (see
``conversation_key``) and served again, without a model call, to a session whose whole
conversation up to that point is identical.

The cache is in memory only: bounded by ``reply_cache_entries`` (least recently used out
first) and by ``reply_cache_max_age`` seconds, and empty after a restart, so a change to
the prompt, the model or the scenario never serves a reply made under the old one.

What is never stored (``agents.hooks`` decides): replies made while a per-source effect
changes the prompt (a planted token, ``deep`` mode), replies that broke character, ended
the session or came from a fallback, replies that contain the session's own source
address, and replies to lines whose real output differs from run to run (``date``,
``/dev/urandom``, ``mktemp``, ...), where serving the same text twice would itself be a tell.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import OrderedDict
from typing import Optional

MAX_REPLY_CHARS = 16 * 1024   # longer replies are not stored

# Words whose output a real host would not repeat exactly: a cached answer to a line that
# contains one would look the same in two sessions hours apart.
VOLATILE_WORDS = frozenset((
    "date", "time", "uptime", "w", "who", "last", "lastlog", "top", "htop", "ps", "pstree",
    "free", "vmstat", "iostat", "netstat", "ss", "dmesg", "journalctl", "sleep", "watch",
    "mktemp", "uuidgen", "openssl", "shuf", "random", "urandom", "/dev/urandom",
    "/dev/random", "$random", "md5sum", "sha256sum", "stat", "timedatectl", "hwclock",
))
_WORDS = re.compile(r"[A-Za-z0-9_$/.-]+")


def volatile(line: str) -> bool:
    """True when ``line`` asks for something whose real output changes between runs."""
    for word in _WORDS.findall(line.lower()):
        if word in VOLATILE_WORDS or word.rsplit("/", 1)[-1] in VOLATILE_WORDS:
            return True
    return False


def conversation_key(previous: str, text: str) -> str:
    """The key after one more input line: a hash chained over every line so far, so two
    sessions share a key only when their whole input sequences match."""
    return hashlib.sha256(f"{previous}\x00{text}".encode("utf-8", "replace")).hexdigest()


def session_root(*parts: str) -> str:
    """The key a session starts from: scenario, sensor seed, login user, session type and
    the persona block the model sees."""
    return hashlib.sha256("\x00".join(("reply-cache",) + parts).encode("utf-8", "replace")) \
        .hexdigest()


class ReplyCache:
    """Bounded, aging map of conversation key to reply text."""

    def __init__(self, max_entries: int = 2000, max_age: float = 21600,
                 clock=time.monotonic) -> None:
        self.max_entries = max(0, int(max_entries))
        self.max_age = max(0.0, float(max_age))
        self._clock = clock
        self._items: OrderedDict[str, tuple[float, str]] = OrderedDict()
        self.hits = 0
        self.misses = 0

    @property
    def enabled(self) -> bool:
        return self.max_entries > 0 and self.max_age > 0

    def __len__(self) -> int:
        return len(self._items)

    def get(self, key: str) -> Optional[str]:
        if not self.enabled:
            return None
        item = self._items.get(key)
        if item is None or self._clock() - item[0] > self.max_age:
            if item is not None:
                del self._items[key]
            self.misses += 1
            return None
        self._items.move_to_end(key)
        self.hits += 1
        return item[1]

    def put(self, key: str, reply: str) -> bool:
        if not self.enabled or len(reply) > MAX_REPLY_CHARS:
            return False
        self._items[key] = (self._clock(), reply)
        self._items.move_to_end(key)
        while len(self._items) > self.max_entries:
            self._items.popitem(last=False)
        return True

    def clear(self) -> None:
        self._items.clear()
        self.hits = self.misses = 0
