"""One model reply answers one input line, the way a shell does.

The persona model sometimes keeps going after the prompt that ends its answer: it types a
command the attacker never sent and answers that too, or prints a second prompt. Nothing a
real shell prints for one input looks like that, so ``one_reply`` cuts the reply back to
what the shell would have printed: the output, then at most one prompt (interactive), or
the output and no prompt (exec). ``agents.hooks.persona_invoke`` runs it on every model
reply before the reply is sent, kept in the history or the reply cache, logged, or used
to note the session's prompt.

The rule. A *session prompt* is a line that starts with ``user@host:dir`` then ``#`` or
``$`` (Debian, Ubuntu) or ``[user@host dir]`` then ``#`` or ``$`` (RHEL), ANSI colour codes
allowed, where the host is the scenario's hostname, the host in the prompt noted for the
session, or the host in the prompt the reply ends with (so ``su``, ``sudo -i``, ``cd``,
``hostname`` and ``ssh`` to another box all still count). The first session prompt that has
a command after it, or more output after it, ends the reply: interactive replies keep that
prompt and lose everything after it; exec replies lose the prompt too.

Before that, at the very start of the reply, up to ``MAX_LEADING`` lines are dropped when
they are the attacker's own line echoed back (with or without a prompt in front: the
terminal already echoed it), or a bare prompt with more output after it. A bare echo is
kept when only the final prompt follows it: then it may be the output itself.

Left whole, because the output itself could hold prompt-shaped lines:

- an input that could print one (it contains ``@``, a backtick, a backslash, ``%``, or a
  ``$`` expansion: ``echo 'root@x:~# id'``, ``printf``, ``$(hostname)``);
- for a command that shows file text (``cat``, ``less``, ``grep``, ``git log``, ...), any
  prompt line that is not exactly the session's current prompt, and every such line once
  the session has typed an input like the ones above (it may have written one to a file).

The work is one pass over the reply, with fixed-size pattern matches anchored at the start
of each line, so a long hostile reply costs time linear in its length.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

MAX_LEADING = 3          # leading echo or prompt lines dropped at most
MAX_SAMPLE = 120         # characters of the dropped text kept for the log, before escaping
_SGR = r"(?:\x1b\[[0-9;]{0,16}m)*"
_NAME = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}"
_HOST = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
# The prompt at the start of a line, up to and including its # or $ (and colour codes).
_PROMPT = re.compile(
    rf"{_SGR}(?:(?P<user>{_NAME}){_SGR}@{_SGR}(?P<host>{_HOST}){_SGR}:[^\s#$]{{0,256}}"
    rf"|\[{_SGR}(?P<buser>{_NAME})@(?P<bhost>{_HOST}) [^\s\]]{{1,256}}{_SGR}\]){_SGR}[#$]{_SGR}")
_SGR_ANY = re.compile(r"\x1b\[[0-9;]{0,16}m")
_FENCE = re.compile(r"[ \t]*```[\w+.-]*[ \t]*")
# Input that could itself print a prompt-shaped line.
_BUILDS_TEXT = re.compile(r"[@`\\%]|\$[({A-Za-z_]")


def builds_text(text: str) -> bool:
    """True when an input line could print arbitrary text, a prompt-shaped line among it."""
    return bool(_BUILDS_TEXT.search(text))


@dataclass(frozen=True)
class Cut:
    kept: str         # what the shell would have printed
    dropped: int      # characters removed
    sample: str       # start of the removed text, escaped, for the log only
    reason: str       # "next_command" | "extra_prompt" | "prompt_in_exec" | "echo"


@dataclass(slots=True)
class _Line:
    start: int        # offset of the line in the reply
    end: int          # offset just past the line (before its newline)
    text: str         # the line without a trailing \r


def _lines(reply: str) -> Iterable[_Line]:
    pos = 0
    n = len(reply)
    while pos <= n:
        nl = reply.find("\n", pos)
        end = n if nl < 0 else nl
        text = reply[pos:end]
        yield _Line(pos, end, text[:-1] if text.endswith("\r") else text)
        if nl < 0:
            return
        pos = nl + 1


def _filler(text: str) -> bool:
    """A line that is neither output nor prompt: blank, or a Markdown fence line."""
    return not text.strip() or bool(_FENCE.fullmatch(text))


def plain(text: str) -> str:
    """``text`` without ANSI colour codes."""
    return _SGR_ANY.sub("", text) if "\x1b" in text else text


def prompt_host(line: str) -> Optional[str]:
    """The host of a prompt at the start of ``line``, lowercased, or None."""
    m = _PROMPT.match(line)
    if m is None:
        return None
    return (m.group("host") or m.group("bhost") or "").lower() or None


class _Prompt:
    __slots__ = ("token", "user", "host", "rest")

    def __init__(self, token: str, user: str, host: str, rest: str) -> None:
        self.token = token    # the prompt text up to and including the sigil
        self.user = user
        self.host = host
        self.rest = rest      # what follows it on the line


def _prompt(line: str) -> Optional[_Prompt]:
    m = _PROMPT.match(line)
    if m is None:
        return None
    rest = line[m.end():]
    if rest and rest[0] not in " \t":
        return None           # ``root@x:~#foo`` is not a prompt with a command
    host = (m.group("host") or m.group("bhost") or "").lower()
    return _Prompt(line[:m.end()], m.group("user") or m.group("buser") or "", host, rest)


def _escape(text: str) -> str:
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in text[:MAX_SAMPLE])


def one_reply(reply: str, text: str, *, interactive: bool, hosts: Iterable[str],
              current_prompt: str, user: Optional[str] = None, viewer: bool = False,
              text_built_before: bool = False) -> Optional[Cut]:
    """What a shell would have printed for ``text``, or None when ``reply`` already is that
    (then it is used byte for byte as it came).

    ``hosts`` are the host names a session prompt may show (any host, when the prompt
    shows the session's own ``user``); ``current_prompt`` is the prompt the session is at
    (the one noted for it, else the default). ``viewer`` marks a
    command that shows file text; ``text_built_before`` an earlier input in the session
    that could have printed (or written) a prompt-shaped line.
    """
    if not reply or builds_text(text):
        return None
    if viewer and text_built_before:
        return None
    lines = list(_lines(reply))
    allowed = {h.lower() for h in hosts if h}
    # The host of the prompt the reply ends with: after ``ssh other`` or ``hostname new``
    # the session's prompts show a host nobody noted yet.
    for line in reversed(lines):
        if _filler(line.text):
            continue
        last = _prompt(line.text)
        if last is not None and not last.rest.strip():
            allowed.add(last.host)
        break
    exact = plain(current_prompt).strip()
    typed = text.strip()

    def session_prompt(line: _Line) -> Optional[_Prompt]:
        p = _prompt(line.text)
        if p is None or (p.host not in allowed and (not user or p.user != user)):
            return None
        if viewer and plain(p.token).strip() != exact:
            return None        # file text may hold old prompts; only the current one counts
        return p

    def more_after(index: int) -> bool:
        return any(not _filler(lines[j].text) for j in range(index + 1, len(lines)))

    def _only_final_prompt(index: int) -> bool:
        """True when all that follows line ``index`` is one bare session prompt."""
        k = next((j for j in range(index + 1, len(lines)) if not _filler(lines[j].text)),
                 None)
        if k is None:
            return True
        p = session_prompt(lines[k])
        return p is not None and not p.rest.strip() and not more_after(k)

    # Leading lines: the attacker's own line echoed back, with or without a prompt, and a
    # bare prompt in front of the output. Never the reply's last line of content.
    drop: list[int] = []
    i = 0
    while i < len(lines) and len(drop) < MAX_LEADING:
        line = lines[i]
        if _filler(line.text):
            i += 1
            continue
        if not more_after(i):
            break
        p = session_prompt(line)
        echo = typed and (plain(line.text).strip() == typed
                          or (p is not None and plain(p.rest).strip() == typed))
        if not echo and (p is None or p.rest.strip()):
            break
        if echo and p is None and _only_final_prompt(i):
            break      # ``ls`` in a directory holding only a file named ``ls`` prints "ls"
        drop.append(i)
        i += 1
    first_kept = i

    cut_at: Optional[int] = None
    reason = ""
    for j in range(first_kept, len(lines)):
        p = session_prompt(lines[j])
        if p is None:
            continue
        if p.rest.strip():
            cut_at, reason = j, "next_command"
        elif more_after(j):
            cut_at, reason = j, "extra_prompt"
        elif not interactive:
            cut_at, reason = j, "prompt_in_exec"
        break      # the first session prompt ends the reply either way

    if not drop and cut_at is None:
        return None
    pieces: list[str] = []
    pos = 0
    for d in drop:
        pieces.append(reply[pos:lines[d].start])
        nxt = lines[d].end + 1
        pos = min(nxt, len(reply))
    removed = "".join(reply[lines[d].start:lines[d].end + 1] for d in drop)
    if cut_at is not None:
        line = lines[cut_at]
        pieces.append(reply[pos:line.start])
        token = _prompt(line.text).token  # type: ignore[union-attr]
        if interactive:
            pieces.append(token + " ")
            removed += reply[line.start + len(token):]
        else:
            removed += reply[line.start:]
    else:
        pieces.append(reply[pos:])
        reason = "echo"
    kept = "".join(pieces)
    if kept == reply:
        return None
    return Cut(kept=kept, dropped=max(len(reply) - len(kept), 0),
               sample=_escape(removed.lstrip()), reason=reason)
