"""Bundled common-password list used to recover passwords from challenge/response logins."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

WORDLIST_PATH = Path(__file__).resolve().parent / "data" / "common_passwords.txt"
MAX_WORDS = 5000


@lru_cache(maxsize=1)
def common_passwords() -> tuple[str, ...]:
    """Return the bundled list (deduplicated, order kept). Empty if the file is missing."""
    try:
        text = WORDLIST_PATH.read_text(encoding="utf-8")
    except OSError:
        return ()
    seen: dict[str, None] = {}
    for line in text.splitlines():
        word = line.strip()
        if word and not word.startswith("#") and len(word) <= 64:
            seen.setdefault(word, None)
        if len(seen) >= MAX_WORDS:
            break
    return tuple(seen)
