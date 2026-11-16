"""Linear glob matcher used for client-supplied patterns."""

from __future__ import annotations

import fnmatch
import random
import time

import pytest

from listeners.glob import MAX_PATTERN_BYTES, compile_glob, glob_match


@pytest.mark.parametrize("pattern,text,expected", [
    ("*", "", True), ("*", "anything", True), ("", "", True), ("", "x", False),
    ("user:*", "user:7", True), ("user:*", "users:7", False),
    ("h?llo", "hello", True), ("h?llo", "hllo", False),
    ("h[ae]llo", "hallo", True), ("h[ae]llo", "hillo", False),
    ("h[^e]llo", "hallo", True), ("h[^e]llo", "hello", False),
    ("h[a-c]llo", "hbllo", True), ("h[c-a]llo", "hbllo", True),   # reversed range, as Redis
    ("h\\*llo", "h*llo", True), ("h\\*llo", "hello", False),
    ("[\\]]x", "]x", True), ("a*b*c", "aXXbYYc", True), ("a*b*c", "aXXcYYb", False),
    ("*a*a*a*b", "a" * 50, False), ("*.conf", "redis.conf", True),
    ("db?ilename", "dbfilename", True),
])
def test_glob_semantics(pattern, text, expected):
    assert glob_match(pattern, text) is expected


def test_glob_nocase_and_bytes():
    assert glob_match("MAX*", "maxmemory", nocase=True)
    assert glob_match(b"k?", b"k\xff")
    assert glob_match("??", "é")                      # one UTF-8 character is two bytes


def test_glob_agrees_with_reference_on_random_patterns():
    rng = random.Random(7)
    alphabet = "ab"
    for _ in range(3000):
        pat = "".join(rng.choice(["a", "b", "?", "*", "[ab]", "[^a]", "[a-b]"])
                      for _ in range(rng.randint(0, 6)))
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))
        ref = fnmatch.fnmatchcase(text, pat.replace("[^", "[!"))
        assert glob_match(pat, text) is ref, (pat, text)


def test_glob_long_pattern_matches_nothing_and_is_fast():
    assert compile_glob("a" * (MAX_PATTERN_BYTES + 1)) is None
    assert not glob_match("*" * 300, "x")
    started = time.monotonic()
    g = compile_glob("a*" * 127 + "b")
    assert g is not None
    assert not g.match("a" * 200_000)
    g2 = compile_glob("*?a?" * 60 + "[^a]")
    assert not g2.match("a" * 200_000)
    assert time.monotonic() - started < 2.0
