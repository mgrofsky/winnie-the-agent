"""Linear-time glob matching for client-supplied patterns (Redis KEYS/SCAN/CONFIG GET style).

Supports ``*``, ``?``, ``[...]`` with ranges and ``^`` negation, and backslash escapes,
with Redis semantics: matching is done on UTF-8 bytes, so ``?`` matches one byte.

Never hand a client pattern to ``fnmatch`` or ``re``: ``fnmatch`` compiles (and caches)
one regex per distinct pattern, which costs about a second per 400 KB pattern and keeps
the compiled object alive. Here a pattern compiles to at most ``max_bytes`` tokens and
matching is a bit-parallel NFA simulation: one pass over the text, a handful of integer
operations per byte, no backtracking. Pure ``*``/literal patterns take a faster path
built on ``bytes.find``.
"""

from __future__ import annotations

from typing import Optional, Union

MAX_PATTERN_BYTES = 256

_STAR = object()
Text = Union[str, bytes]


def _b(value: Text) -> bytes:
    return value.encode("utf-8", errors="replace") if isinstance(value, str) else value


class Glob:
    """A compiled pattern. Build with :func:`compile_glob`."""

    def __init__(self, pattern: bytes, nocase: bool = False) -> None:
        self.nocase = nocase
        if nocase:
            pattern = pattern.lower()
        tokens = self._tokenize(pattern)
        # Collapse runs of '*': one star state is enough and keeps the closure one step.
        collapsed: list = []
        for t in tokens:
            if t is _STAR and collapsed and collapsed[-1] is _STAR:
                continue
            collapsed.append(t)
        self.tokens = collapsed
        self.simple = all(t is _STAR or isinstance(t, int) for t in collapsed)
        if self.simple:
            parts: list[bytes] = []
            cur = bytearray()
            for t in collapsed:
                if t is _STAR:
                    parts.append(bytes(cur))
                    cur = bytearray()
                else:
                    cur.append(t)
            parts.append(bytes(cur))
            self.parts = parts          # literal segments between stars
            return
        star = 0
        table = [0] * 256
        for i, t in enumerate(collapsed):
            bit = 1 << i
            if t is _STAR:
                star |= bit
            elif isinstance(t, int):
                table[t] |= bit
            elif t is None:              # '?'
                for b in range(256):
                    table[b] |= bit
            else:                        # (negate, set of bytes)
                negate, members = t
                for b in range(256):
                    if (b in members) != negate:
                        table[b] |= bit
        self.star = star
        self.table = table
        self.accept = 1 << len(collapsed)

    @staticmethod
    def _tokenize(p: bytes) -> list:
        out: list = []
        i, n = 0, len(p)
        while i < n:
            c = p[i]
            if c == 0x2A:                                    # '*'
                out.append(_STAR)
                i += 1
            elif c == 0x3F:                                  # '?'
                out.append(None)
                i += 1
            elif c == 0x5C and i + 1 < n:                    # '\x'
                out.append(p[i + 1])
                i += 2
            elif c == 0x5B:                                  # '['
                i += 1
                negate = i < n and p[i] == 0x5E
                if negate:
                    i += 1
                members: set[int] = set()
                while i < n and p[i] != 0x5D:
                    if p[i] == 0x5C and i + 1 < n:
                        members.add(p[i + 1])
                        i += 2
                    elif i + 2 < n and p[i + 1] == 0x2D and p[i + 2] != 0x5D:
                        lo, hi = p[i], p[i + 2]
                        if lo > hi:
                            lo, hi = hi, lo
                        members.update(range(lo, hi + 1))
                        i += 3
                    else:
                        members.add(p[i])
                        i += 1
                i += 1                                       # past ']' (or end of pattern)
                out.append((negate, frozenset(members)))
            else:
                out.append(c)
                i += 1
        return out

    def match(self, text: Text) -> bool:
        data = _b(text)
        if self.nocase:
            data = data.lower()
        if self.simple:
            return self._match_simple(data)
        table, star = self.table, self.star
        state = 1 | ((1 & star) << 1)
        for b in data:
            state = ((state & table[b]) << 1) | (state & star)
            if not state:
                return False
            state |= (state & star) << 1
        return bool(state & self.accept)

    def _match_simple(self, data: bytes) -> bool:
        parts = self.parts
        if len(parts) == 1:
            return data == parts[0]
        first, last = parts[0], parts[-1]
        if len(data) < len(first) + len(last) or not data.startswith(first) \
                or not data.endswith(last):
            return False
        pos, end = len(first), len(data) - len(last)
        for seg in parts[1:-1]:                 # leftmost greedy is exact for literals
            at = data.find(seg, pos, end)
            if at < 0:
                return False
            pos = at + len(seg)
        return True


def compile_glob(pattern: Text, nocase: bool = False,
                 max_bytes: int = MAX_PATTERN_BYTES) -> Optional[Glob]:
    """Compile ``pattern``; None when it is longer than ``max_bytes`` (matches nothing)."""
    raw = _b(pattern)
    if len(raw) > max_bytes:
        return None
    return Glob(raw, nocase)


def glob_match(pattern: Text, text: Text, nocase: bool = False,
               max_bytes: int = MAX_PATTERN_BYTES) -> bool:
    g = compile_glob(pattern, nocase, max_bytes)
    return g is not None and g.match(text)
