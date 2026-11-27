"""Persona replies learned from the model's own earlier answers, kept across restarts.

The reply cache (``agents.replycache``) serves a model reply again only to a session whose
whole history is identical, and only until a restart. This store keeps, per command, the
reply the model gave in many unrelated sessions, so a command the sensor has seen often
enough is answered without a model call, under any history.

What is learned. One observation per fresh model reply that was sent unchanged (``agents
.hooks`` decides; a cut, retried, replaced or fallback reply is never observed): the host
fingerprint, the login user, interactive or exec, the command template, the reply
template, the source network (/24, or /64 for IPv6), a digest of the session id and a
digest of the session's input lines before it.

Templates. A random-looking token in the command (a UUID, a run of 16 or more hex digits,
or a run of 20 or more base64 characters with upper case, lower case and digits) becomes a
numbered placeholder, one number per distinct value. Where a token's value appears
verbatim in the reply it becomes the same placeholder. A reply that holds any other trace
of a token (an 8-character piece of it in any case, its base64 or hex decoding) or a
random-looking token that is not from the command is not learned: it may be computed
from the input. Each token's length and character class (``shape``) is part of the key,
and placeholders keep each token's position and whether it repeats. A command that
computes over its text or matches patterns (``computes``) keeps its tokens literal: it is
learned only for its exact text. A reply that holds two or more different tokens, or a
token in the output of a program that sorts names (``sorts``), is not learned: the order
may follow the values. An interactive reply is stored without its final prompt, and only when
that prompt is the one the session showed before the command (the command did not move
the session); the session's current prompt is added when it is served.

When an entry is served. Once its reply template was observed in at least
``min_sessions`` sessions, from at least two source networks, under at least two
different input histories, and never with any other reply. A session's first command
(the opener is not a command) is also served when the observations made as first
commands alone meet the session and network counts: every such session starts in the
same state, so there is no other history to compare (SSH exec sessions have only that
one command). An entry observed once with a
different reply, or with a reply that could not be stored, is marked varying and is
never served: that keeps commands whose output
depends on the clock, on randomness or on session state with the model.

Same-history rule. An entry is also served to a session whose same-history key
(``script_key``: the script digest of every line and reply so far from ``script_step``,
plus how this line's tokens bind to the session's tokens and their shapes) equals one
under which it was observed with the identical reply in at least ``min_sessions``
sessions from two networks. A line that computes over its text in a session with tokens
is not looked up or observed by this rule. Such a session is in the state those
sessions were in, whatever its lines changed. The reply is stored whole (prompt
included), with session-wide placeholders, so a token read back is the session's own.
Evidence and the varying mark are kept per key (``MAX_HISTORIES`` per entry).

Storage. One JSON file beside the budget state, written under an exclusive lock on
``<file>.lock`` and replaced atomically (mode 0600), so the SSH process and the listeners
(Telnet) share it. At runtime every file read and write runs in one worker thread per
process (``background``); the reply path only queues work and looks up the in-memory
copy. Hard caps on entries, command length, reply size and
observations per entry; past ``max_entries`` the entries that are not served go first,
least recently seen first. Served counts are added in memory and written with the next
write (at most ``FLUSH_SERVES`` serves or ``FLUSH_SECONDS`` later). Every string read
back is checked again (length, printable text, well-formed placeholders); an entry that
fails is dropped. Nothing in the store is ever executed or interpreted. Any read, write
or lock failure leaves the command to the model.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import copy
import fcntl
import hashlib
import ipaddress
import json
import logging
import os
import queue
import re
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

log = logging.getLogger(__name__)

FILE_NAME = "learned_replies.json"
MARK = "\x00"                  # placeholder delimiter; a line or reply containing it is skipped
MAX_COMMAND_CHARS = 512        # longer commands are neither learned nor looked up
MAX_REPLY_BYTES = 8192         # longer replies (UTF-8, as stored) are not learned
MAX_TOKENS = 8                 # commands with more distinct tokens are not learned
MAX_OBSERVATIONS = 16          # distinct sessions kept per entry (the first ones)
MAX_NETS = 16                  # distinct source networks counted per entry
MAX_FILE_BYTES = 128 * 1024 * 1024   # above every cap below; a larger file is not read
MAX_USER_CHARS = 32
DEFAULT_MAX_ENTRIES = 2000
MAX_ENTRIES_LIMIT = 3000
DEFAULT_MIN_SESSIONS = 3
FLUSH_SERVES = 32
FLUSH_SECONDS = 60.0
FILE_VERSION = 3        # 3: token shapes and binding keys; older files read as empty
MAX_QUEUE = 256                # store jobs waiting for the worker; past it they are dropped
FRAGMENT = 8                   # a token piece this long left in a reply blocks learning
_ID = re.compile(r"^[0-9a-f]{16}$")
_DIGEST = re.compile(r"^[0-9a-f]{16}$")

_UUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
_RUN = re.compile(r"[A-Za-z0-9+=]+")
_HEX = re.compile(r"[0-9A-Fa-f]{16,}")
_B64 = re.compile(r"[A-Za-z0-9+]{20,}={0,2}")
_PLACEHOLDER = re.compile(MARK + r"([0-9]{1,2})" + MARK)


# ---- templates ----------------------------------------------------------------------------

def _random_looking(run: str) -> bool:
    if _HEX.fullmatch(run):
        return True
    return bool(_B64.fullmatch(run)) and any(c.isupper() for c in run) \
        and any(c.islower() for c in run) and any(c.isdigit() for c in run)


def tokens(text: str) -> list[tuple[int, int]]:
    """Spans of the random-looking tokens in ``text``, in order, not overlapping."""
    spans: list[tuple[int, int]] = []
    taken = [False] * len(text)
    for m in _UUID.finditer(text):
        before = text[m.start() - 1] if m.start() else ""
        after = text[m.end()] if m.end() < len(text) else ""
        if not (before.isalnum() or after.isalnum()):
            spans.append((m.start(), m.end()))
            for i in range(m.start(), m.end()):
                taken[i] = True
    for m in _RUN.finditer(text):
        if any(taken[m.start():m.end()]):
            continue
        if _random_looking(m.group(0)):
            spans.append((m.start(), m.end()))
    return sorted(spans)


@dataclass(frozen=True)
class Template:
    text: str              # the command with placeholders
    values: tuple[str, ...]  # placeholder number -> value


def command_template(command: str) -> Optional[Template]:
    """The command as a template, or None when it cannot be one (too long, holds the
    placeholder marker or a control character, has more than ``MAX_TOKENS`` distinct
    tokens)."""
    if not command or len(command) > MAX_COMMAND_CHARS or MARK in command \
            or not _clean(command):
        return None
    values: list[str] = []
    out: list[str] = []
    last = 0
    for start, end in tokens(command):
        value = command[start:end]
        if value not in values:
            values.append(value)
        out.append(command[last:start])
        out.append(f"{MARK}{values.index(value)}{MARK}")
        last = end
    out.append(command[last:])
    if len(values) > MAX_TOKENS:
        return None
    return Template("".join(out), tuple(values))


def _template(command: str) -> Optional[Template]:
    """The key template of ``command``: ``command_template``, with the session opener (an
    empty line) as its own entry, and the command kept literal (no placeholders) when it
    computes over its text (``computes``): its reply may depend on a token's value in
    ways only that exact value can show."""
    if command == "":
        return Template("", ())
    template = command_template(command)
    if template is not None and template.values and computes(command):
        return Template(command, ())
    return template


# Programs and shell forms whose output can be computed from their input text (a count, a
# length, a conversion, a slice) without holding it verbatim.
COMPUTERS = frozenset((
    "wc", "expr", "bc", "dc", "awk", "gawk", "mawk", "od", "xxd", "hexdump", "cksum", "sum",
    "md5sum", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "b2sum",
    "base64", "base32", "basenc", "cut", "head", "tail", "tr", "rev", "sort", "uniq",
    "printf", "factor", "seq", "numfmt", "let", "fold", "strings", "grep", "egrep", "fgrep",
    "sed", "perl", "python", "python2", "python3", "ruby", "php", "node", "lua", "openssl",
    "gzip", "bzip2", "xz", "zcat", "iconv", "nl", "comm", "join", "paste", "split", "dd",
    "test", "[", "[[", "case", "expr", "if",
))
# Programs whose output orders names by their values (a token sorts among other names).
SORTERS = frozenset(("ls", "dir", "vdir", "sort", "tree", "du", "find", "locate"))
_COMPUTE_FORMS = ("$((", "$[", "${", "((", "[[", "=~", "*", "?", "[")


def computes(text: str) -> bool:
    """True when ``text`` runs a program in ``COMPUTERS`` (any word, by any path), uses
    shell arithmetic or parameter expansion (``$((``, ``${#x}``, ``${x:1}``), or matches
    a pattern (``case``, ``[[``, ``=~``, a glob with ``*``, ``?`` or ``[``)."""
    if any(form in text for form in _COMPUTE_FORMS):
        return True
    return any(w.rpartition("/")[2] in COMPUTERS for w in _WORDS.split(text) if w)


_WORDS = re.compile(r"""[\s"'`;|&(){}<>=]+""")


def _token_class(value: str) -> str:
    """One letter for a token's character class: ``d`` digits, ``x`` lower-case hex,
    ``y`` upper-case hex, ``h`` mixed-case hex, ``u`` UUID, ``b`` base64-like."""
    if _UUID.fullmatch(value):
        return "u"
    if value.isdigit():
        return "d"
    if _HEX.fullmatch(value):
        return "x" if value == value.lower() else "y" if value == value.upper() else "h"
    return "b"


def shape(values: tuple[str, ...]) -> str:
    """Each token's length and class, in placeholder order (``20x,36u``): part of every
    key, so an answer seen for tokens of one length or class never stands for another."""
    return ",".join(f"{len(v)}{_token_class(v)}" for v in values)


_SHAPE = re.compile(r"(?:[0-9]{1,3}[a-z](?:,[0-9]{1,3}[a-z]){0,7})?")


@dataclass(frozen=True)
class Found:
    entry: str      # entry id
    reply: str      # the reply, placeholders filled
    rule: str       # "history" (different histories) or "script" (same history)
    whole: bool     # the reply includes its final prompt (same-history replies do)


def _decodings(value: str) -> Iterable[str]:
    """Text a token decodes to (base64 or hex), when it is mostly printable."""
    raw: list[bytes] = []
    with contextlib.suppress(ValueError, binascii.Error):
        if len(value) % 2 == 0 and _HEX.fullmatch(value):
            raw.append(bytes.fromhex(value))
    with contextlib.suppress(ValueError, binascii.Error):
        padded = value + "=" * (-len(value) % 4)
        raw.append(base64.b64decode(padded, validate=True))
    for data in raw:
        text = data.decode("utf-8", "ignore")
        text = "".join(c for c in text if c.isprintable())
        if len(text) >= 4:
            yield text


def sorts(text: str) -> bool:
    """True when ``text`` runs a program in ``SORTERS``."""
    return any(w.rpartition("/")[2] in SORTERS for w in _WORDS.split(text) if w)


def reply_template(reply: str, values: tuple[str, ...], command: str = "") -> Optional[str]:
    """The reply with each token value replaced by its placeholder, or None when the reply
    cannot be learned: it holds the marker or other control characters, is too large,
    holds a trace of a token that is not its verbatim value, holds two or more different
    tokens (their order may follow their values), or holds a token in the output of a
    ``command`` that sorts names (``ls /tmp``: where the token falls among the other names
    follows its value)."""
    if MARK in reply or not _clean(reply) or len(reply.encode("utf-8")) > MAX_REPLY_BYTES:
        return None
    if not values:
        return reply
    order = sorted(range(len(values)), key=lambda i: -len(values[i]))
    pattern = re.compile("|".join(re.escape(values[i]) for i in order))
    index = {v: i for i, v in enumerate(values)}
    templated = pattern.sub(lambda m: f"{MARK}{index[m.group(0)]}{MARK}", reply)
    rest = _PLACEHOLDER.sub(" ", templated)
    lowered = rest.lower()
    for value in values:
        low = value.lower()
        for i in range(0, max(1, len(low) - FRAGMENT + 1)):
            if low[i:i + FRAGMENT] in lowered:
                return None
        for decoded in _decodings(value):
            if decoded.lower() in lowered:
                return None
    if tokens(rest):
        return None
    if _PLACEHOLDER.search(templated) and sorts(command):
        return None
    if len(set(_PLACEHOLDER.findall(templated))) > 1:
        # The order of two tokens in output can follow their values (``ls`` sorts names),
        # which no key carries: such a reply is not learned.
        return None
    if len(templated.encode("utf-8")) > MAX_REPLY_BYTES:
        return None
    return templated


def fill(template: str, values: tuple[str, ...]) -> Optional[str]:
    """A stored reply template with the placeholders replaced, or None when it names a
    placeholder the command does not have."""
    missing = False

    def one(m: re.Match) -> str:
        nonlocal missing
        i = int(m.group(1))
        if i >= len(values):
            missing = True
            return ""
        return values[i]
    out = _PLACEHOLDER.sub(one, template)
    return None if missing or MARK in out else out


_LAYOUT = str.maketrans("", "", "\r\n\t" + MARK)


def _clean(text: str) -> bool:
    """Printable text, line endings and tabs allowed (placeholders aside)."""
    return text.translate(_LAYOUT).isprintable()


# ---- what can change state -----------------------------------------------------------------

# Programs that can change what a later command prints (files, users, the environment, the
# working directory, processes, packages) or run other code.
WRITERS = frozenset((
    "unlink", "mkfifo", "mknod",
    "cd", "pushd", "popd", "export", "unset", "set", "alias", "unalias", "source", ".",
    "eval", "exec", "touch", "mkdir", "rmdir", "rm", "mv", "cp", "ln", "install", "chmod",
    "chown", "chgrp", "chattr", "truncate", "shred", "tee", "dd", "sed", "awk", "perl",
    "python", "python2", "python3", "php", "ruby", "node", "lua", "wget", "curl", "tftp",
    "ftp", "ftpget", "scp", "sftp", "rsync", "git", "tar", "unzip", "gunzip", "gzip", "bzip2",
    "xz", "zip", "7z", "useradd", "userdel", "usermod", "adduser", "deluser", "passwd",
    "chpasswd", "groupadd", "groupdel", "crontab", "at", "systemctl", "service", "init",
    "telinit", "kill", "killall", "pkill", "nohup", "setsid", "screen", "tmux", "apt",
    "apt-get", "yum", "dnf", "apk", "rpm", "dpkg", "opkg", "pip", "pip3", "npm", "mount",
    "umount", "iptables", "ip6tables", "ufw", "nft", "sysctl", "hostname", "hostnamectl",
    "history", "su", "login", "newgrp", "ulimit", "umask", "read", "declare", "typeset",
    "local", "readonly", "shopt", "trap", "sh", "bash", "ash", "dash", "zsh", "ksh", "nc",
    "ncat", "netcat", "socat", "ssh", "vi", "vim", "nano", "ed", "reboot", "shutdown",
    "halt", "poweroff", "chroot", "modprobe", "insmod", "rmmod", "ip", "ifconfig", "route",
))
# Words in front of the program they run.
_WRAPPERS = frozenset(("sudo", "busybox", "xargs", "env", "time", "command", "nice", "ionice",
                       "timeout", "stdbuf", "builtin"))
# Programs that only read, which may be called by a path (``/bin/cat``).
_READERS = frozenset((
    "cat", "ls", "echo", "printf", "uname", "id", "whoami", "grep", "egrep", "fgrep", "head",
    "tail", "ps", "free", "df", "du", "uptime", "w", "who", "nproc", "lscpu", "lspci",
    "lsusb", "which", "true", "false", "test", "[", "wc", "sort", "uniq", "cut", "tr",
    "find", "file", "stat", "md5sum", "sha256sum", "getconf", "arch", "lsb_release",
    "dmesg", "last", "lastlog", "netstat", "ss", "top", "env", "printenv", "locale",
    "busybox", "nvidia-smi", "pwd", "date",
))
# Options that make a reading program write or run another: ``find -delete``, ``sort -o f``.
_WRITING_OPTIONS = {
    "find": ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0",
             "-fprintf", "-fls"),
    "sort": ("-o", "--output"),
    "date": ("-s", "--set"),
}
_SEGMENTS = re.compile(r"\$\(|&&|\|\||[;&|\n(){}`]")
_DEVNULL = re.compile(r"[0-9]*>>?\s*/dev/null|[0-9]*>&[0-9]|&>\s*/dev/null")
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def may_change_state(text: str) -> bool:
    """True when ``text`` could change what a later command prints: a redirect into a
    file (``/dev/null`` and descriptor copies aside), a variable assignment, a program in
    ``WRITERS`` in a command position (after any of ``sudo``, ``busybox``, ``xargs``,
    ``env``, ...), or a program run by path that is not a known reader (``./x``,
    ``/tmp/x``), or a reading program given an option that writes (``find -delete``,
    ``sort -o``). Errs on the side of True."""
    if ">" in _DEVNULL.sub(" ", text):
        return True
    for segment in _SEGMENTS.split(text):
        words = [w.strip("\"'\\") for w in segment.split()]
        if not words:
            continue
        first = words[0]
        if _ASSIGN.match(first):
            return True
        for word in words:
            options = _WRITING_OPTIONS.get(word.rpartition("/")[2])
            if options and any(w.startswith(options) for w in words):
                return True
        name = first.rpartition("/")[2]
        if name in _WRAPPERS:
            # ``sudo -u root rm x``, ``busybox wget``: any later word may be the program.
            if any(w.rpartition("/")[2] in WRITERS for w in words[1:]):
                return True
            # The program it runs: the first later word that is not an option or a number.
            run = next((w for w in words[1:] if w and not w.startswith("-")
                        and not w.replace(".", "").isdigit()), "")
            if _ASSIGN.match(run) or ("/" in run and run.rpartition("/")[2] not in _READERS):
                return True
            continue
        if name in WRITERS:
            return True
        if "/" in first and name not in _READERS:
            return True
    return False


# ---- source and history digests ------------------------------------------------------------

def network(ip: str) -> str:
    """The source network an observation counts for: the /24 for IPv4, the /64 for IPv6."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "-"
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


def digest(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode("utf-8", "replace")).hexdigest()[:16]


START = digest("turn")   # the input history of a session's first command
MAX_HISTORIES = 16       # same-history digests per entry that hold a reply's text
MAX_PENDING = 64         # same-history digests per entry in all (the rest hold digests only)
MAX_VALUE_SETS = 4       # distinct token-value sets counted per digest
WRITE_BUDGET = 64 * 1024 * 1024   # bytes written at most; lowest-priority entries go first


def script_root(fingerprint: str, user: str, interactive: bool) -> str:
    """The script digest a session starts from (``script_step`` chains its lines)."""
    return digest("script", fingerprint, user[:MAX_USER_CHARS], "i" if interactive else "x")


def session_template(text: str, values: tuple[str, ...]) -> str:
    """``text`` with every verbatim session token value as its session-wide placeholder."""
    if not values:
        return text
    order = sorted(range(len(values)), key=lambda i: -len(values[i]))
    pattern = re.compile("|".join(re.escape(values[i]) for i in order))
    index = {v: i for i, v in enumerate(values)}
    return pattern.sub(lambda m: f"{MARK}{index[m.group(0)]}{MARK}", text)


def script_step(script: str, command: str, reply: str, values: tuple[str, ...]) -> str:
    """The script digest after one more line: the command and the reply as sent, each
    with the session's token values as placeholders, so two sessions of one script that
    differ only in their random tokens keep one digest. The tokens' lengths and classes
    (``shape``) are part of it."""
    return digest("step", script, shape(values),
                  session_template(command, values), session_template(reply, values))


def script_key(script: str, command: str, values: tuple[str, ...]) -> str:
    """The same-history key of ``command`` after ``script``: the command with every token
    as its session-wide number (which earlier token it is, or a new one) and the shape of
    the session's tokens. Two lines share a key only when their tokens are bound the same
    way: ``cat /tmp/T`` after ``echo T > /tmp/T`` is not ``cat /tmp/B``."""
    return digest("bind", script, shape(values), session_template(command, values))


def value_set(values: tuple[str, ...]) -> str:
    """A digest of a session's token values (``Found`` evidence across values)."""
    return digest("values", *values)


def entry_id(fingerprint: str, user: str, interactive: bool, command: str,
             token_shape: str = "") -> str:
    return digest("learned", fingerprint, user, "i" if interactive else "x", command,
                  token_shape)


# ---- the store ---------------------------------------------------------------------------

def _valid_entry(raw) -> Optional[dict]:
    """A stored entry, checked field by field, or None."""
    if not isinstance(raw, dict):
        return None
    try:
        fp, user, command = raw["fp"], raw["user"], raw["command"]
        interactive, reply, varying = raw["interactive"], raw.get("reply"), raw["varying"]
        obs, nets = raw["obs"], raw["nets"]
        asked, served, first, last = raw["asked"], raw["served"], raw["first"], raw["last"]
    except (KeyError, TypeError):
        return None
    if not (isinstance(fp, str) and _DIGEST.fullmatch(fp) and isinstance(user, str)
            and len(user) <= MAX_USER_CHARS and user.isprintable()
            and isinstance(command, str) and len(command) <= MAX_COMMAND_CHARS + 64
            and (command or interactive)
            and _clean(command) and isinstance(interactive, bool)
            and isinstance(varying, bool)):
        return None
    if reply is not None and not (isinstance(reply, str) and _clean(reply)
                                  and len(reply.encode("utf-8")) <= MAX_REPLY_BYTES):
        return None
    cmd_ids = [int(n) for n in _PLACEHOLDER.findall(command)]
    if command.count(MARK) != 2 * len(cmd_ids) or any(i >= MAX_TOKENS for i in cmd_ids):
        return None
    if reply is not None:
        reply_ids = [int(n) for n in _PLACEHOLDER.findall(reply)]
        if reply.count(MARK) != 2 * len(reply_ids) or any(i not in cmd_ids for i in reply_ids):
            return None
    for n in (asked, served, first, last):
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            return None
    if not isinstance(obs, list) or not isinstance(nets, list):
        return None
    clean_obs = []
    for o in obs[:MAX_OBSERVATIONS]:
        if not (isinstance(o, list) and len(o) == 4 and all(isinstance(x, str) for x in o)
                and _DIGEST.fullmatch(o[0]) and _DIGEST.fullmatch(o[2])
                and _DIGEST.fullmatch(o[3]) and len(o[1]) <= 64 and o[1].isprintable()):
            return None
        clean_obs.append(list(o))
    clean_nets = [n for n in nets[:MAX_NETS] if isinstance(n, str) and len(n) <= 64
                  and n.isprintable()]
    hist = _valid_hist(raw.get("hist", {}))
    vals = raw.get("vals", [])
    if hist is None or not isinstance(vals, list) or not all(
            isinstance(v, str) and _DIGEST.fullmatch(v) for v in vals[:MAX_VALUE_SETS]):
        return None
    token_shape = raw.get("shape", "")
    if not isinstance(token_shape, str):
        return None
    if not (_SHAPE.fullmatch(token_shape)
            and len(token_shape.split(",")) == len(set(cmd_ids)) if token_shape
            else not cmd_ids):
        return None
    eid = entry_id(fp, user, interactive, command, token_shape)
    return {"id": eid, "fp": fp, "user": user, "interactive": interactive,
            "command": command, "reply": reply, "varying": varying, "obs": clean_obs,
            "nets": clean_nets, "asked": asked, "served": served, "first": first,
            "last": last, "hist": hist, "vals": list(vals[:MAX_VALUE_SETS]),
            "shape": token_shape}


def _valid_hist(raw) -> Optional[dict]:
    """Same-history evidence, checked: {script digest: {reply, varying, sessions, nets,
    last}}. Placeholders in its replies are session-wide (below ``MAX_TOKENS``)."""
    if not isinstance(raw, dict) or len(raw) > MAX_PENDING:
        return None
    out = {}
    for key, h in raw.items():
        if not (isinstance(key, str) and _DIGEST.fullmatch(key) and isinstance(h, dict)):
            return None
        reply, varying = h.get("reply"), h.get("varying")
        sessions, nets, last = h.get("sessions"), h.get("nets"), h.get("last")
        rdig, vals = h.get("rdig"), h.get("vals")
        if not (isinstance(varying, bool) and isinstance(sessions, list)
                and isinstance(nets, list) and isinstance(last, int)
                and not isinstance(last, bool) and last >= 0
                and (rdig is None or (isinstance(rdig, str) and _DIGEST.fullmatch(rdig)))
                and isinstance(vals, list)
                and all(isinstance(v, str) and _DIGEST.fullmatch(v)
                        for v in vals[:MAX_VALUE_SETS])):
            return None
        if reply is not None and (varying or rdig is None):
            return None
        if reply is not None:
            if not (isinstance(reply, str) and _clean(reply)
                    and len(reply.encode("utf-8")) <= MAX_REPLY_BYTES):
                return None
            ids = [int(n) for n in _PLACEHOLDER.findall(reply)]
            if reply.count(MARK) != 2 * len(ids) or any(i >= MAX_TOKENS for i in ids):
                return None
        if not all(isinstance(s, str) and _DIGEST.fullmatch(s) for s in sessions[:MAX_OBSERVATIONS]):
            return None
        if reply is not None and digest("reply", reply) != rdig:
            return None
        out[key] = {"reply": reply, "rdig": rdig, "varying": varying,
                    "vals": list(vals[:MAX_VALUE_SETS]),
                    "sessions": list(sessions[:MAX_OBSERVATIONS]),
                    "nets": [n for n in nets[:MAX_NETS] if isinstance(n, str)
                             and len(n) <= 64 and n.isprintable()],
                    "last": last}
    return out


def _hist_enough(h: dict, min_sessions: int) -> bool:
    return not h["varying"] and len(set(h["sessions"])) >= min_sessions \
        and len(set(h["nets"])) >= 2


def hist_served(h: dict, min_sessions: int, values: Optional[str] = None) -> bool:
    """True when same-history evidence is enough to serve its reply to a session whose
    token values have the digest ``values`` (``value_set``): values the teaching sessions
    had, or any values once the evidence spans two different sets (otherwise the reply
    may depend on the value in a way no trace check sees, such as its length or a
    count). ``values`` None asks whether it is served to anyone."""
    if h["reply"] is None or not _hist_enough(h, min_sessions):
        return False
    return values is None or values in h["vals"] or len(set(h["vals"])) >= 2


def promoted(entry: dict, min_sessions: int) -> bool:
    """True when the entry is served to some session, by either rule."""
    return servable(entry, min_sessions, START) or any(
        hist_served(h, min_sessions) for h in entry["hist"].values())


def servable(entry: dict, min_sessions: int, history: Optional[str] = None,
             values: Optional[str] = None) -> bool:
    """True when the entry's reply may be served (see the module docstring). For a
    session's first command (``history`` is ``START``) observations made as first
    commands are enough on their own: those sessions were in the same state. ``values``
    (``value_set`` of the command's tokens) must be one the observations had, unless they
    span two or more different sets; None skips that check (is it served to anyone)."""
    if entry["varying"] or entry["reply"] is None:
        return False
    obs = entry["obs"]
    if not (_enough(obs, min_sessions) and len({o[2] for o in obs}) >= 2):
        obs = [o for o in obs if o[2] == START] if history == START else []
        if not _enough(obs, min_sessions):
            return False
    sets = {o[3] for o in obs} | set(entry["vals"])
    return values is None or values in sets or len(sets) >= 2


def _enough(obs: list, min_sessions: int) -> bool:
    return len({o[0] for o in obs}) >= min_sessions and len({o[1] for o in obs}) >= 2


def _own(entries: dict[str, dict], eid: str) -> dict:
    """The entry, copied into ``entries`` before it is changed: the copy that lookups read
    and the lines cached for writing are never changed in place."""
    entry = entries[eid] = copy.deepcopy(entries[eid])
    return entry


class LearnedStore:
    """The learned replies, in one file (``path``) or in memory only (``path`` None)."""

    def __init__(self, path: Optional[str], max_entries: int = DEFAULT_MAX_ENTRIES,
                 min_sessions: int = DEFAULT_MIN_SESSIONS,
                 clock: Callable[[], float] = time.time, background: bool = False,
                 queue_size: int = MAX_QUEUE) -> None:
        """``background`` runs every file read and write (``record``, the served-count
        flush, the reload of a changed file) in one worker thread owned by the store, fed
        by a queue of at most ``queue_size`` jobs; callers never wait on the file. Without
        it (the CLI, unit tests) each call does its file work at once."""
        self.path = path
        self.max_entries = max(1, min(int(max_entries), MAX_ENTRIES_LIMIT))
        self.min_sessions = max(2, int(min_sessions))
        self.background = background
        self._clock = clock
        self._lock = threading.Lock()     # guards the copy below; never held over file I/O
        self._entries: dict[str, dict] = {}
        self._signature: Optional[tuple] = None
        # Each entry's line as last written, reused while the entry object is unchanged
        # (entries are copied before any change), so a write encodes only what changed.
        self._lines: dict[str, tuple[dict, bytes]] = {}
        self._pending: dict[str, int] = {}
        self._pending_since: Optional[float] = None
        self._reload_pending = False
        self._flush_queued = False        # one served-count flush in the queue at a time
        self._queue: "queue.Queue" = queue.Queue(maxsize=max(1, int(queue_size)))
        self._worker: Optional[threading.Thread] = None
        self._last_error = float("-inf")
        self._last_drop_log = float("-inf")
        self.dropped = 0                          # jobs dropped because the queue was full
        self.read_error: Optional[str] = None     # why the last read failed, if it did

    # -- worker ----------------------------------------------------------------------------

    def _submit(self, job: Callable[[], None]) -> bool:
        """Run ``job`` in the worker (``background``) or now. A full queue drops the job,
        counts it and logs at most once a minute; it never blocks."""
        if not self.background:
            job()
            return True
        with self._lock:
            if self._worker is None:
                self._worker = threading.Thread(target=self._run, name="learned-store",
                                                daemon=True)
                self._worker.start()
        try:
            self._queue.put_nowait(job)
        except queue.Full:
            self.dropped += 1
            now = time.monotonic()
            if now - self._last_drop_log > 60:
                self._last_drop_log = now
                log.warning("learned replies queue full: %d store jobs dropped so far",
                            self.dropped)
            return False
        return True

    def _run(self) -> None:
        while True:
            job = self._queue.get()
            try:
                if job is None:
                    return
                job()
            except Exception as exc:  # noqa: BLE001 - one bad job must not stop the worker
                self._error("learned replies job failed: %s", type(exc).__name__)
            finally:
                self._queue.task_done()

    def preload(self) -> None:
        """Ask the worker to read the file now, at start, so the first sessions after a
        restart are served from it."""
        self._reload_if_changed()

    def flush(self) -> None:
        """Wait until every queued job has run (tests; shutdown through ``close``)."""
        if self._worker is not None:
            self._queue.join()

    def close(self) -> None:
        """Drain the queue, write any pending served counts and stop the worker."""
        self.flush()
        with self._lock:
            pending = bool(self._pending)
        if pending:
            self._submit(lambda: self._transact(lambda entries: None))
        worker = self._worker
        if worker is not None:
            self._queue.join()
            self._queue.put(None)
            worker.join(timeout=30)
            self._worker = None

    # -- file ------------------------------------------------------------------------------

    def _error(self, message: str, *args) -> None:
        now = time.monotonic()
        if now - self._last_error > 60:
            self._last_error = now
            log.error(message, *args)

    def _stat(self) -> Optional[tuple]:
        try:
            st = os.stat(self.path)  # type: ignore[arg-type]
        except FileNotFoundError:
            return ()
        except OSError:
            return None
        return (st.st_ino, st.st_size, st.st_mtime_ns)

    def _parse(self, data: bytes) -> dict[str, dict]:
        """Entries from the file: a ``{"version":2}`` line, then one entry per line (so no
        single decode is long). A malformed header empties the store; a malformed or
        invalid entry line is dropped."""
        if not data.strip():
            return {}
        lines = data.split(b"\n")
        try:
            head = json.loads(lines[0].decode("utf-8", "strict"))
        except (ValueError, RecursionError):
            head = None
        if not isinstance(head, dict) or head.get("version") != FILE_VERSION:
            log.warning("learned replies file %s is malformed; starting empty", self.path)
            return {}
        out: dict[str, dict] = {}
        for raw in lines[1:MAX_ENTRIES_LIMIT + 1]:
            if not raw.strip():
                continue
            try:
                item = json.loads(raw.decode("utf-8", "strict"))
            except (ValueError, RecursionError):
                continue
            entry = _valid_entry(item)
            if entry is not None:
                out[entry["id"]] = entry
        return out

    def _read_file(self) -> bytes:
        """The file's bytes; a file over ``MAX_FILE_BYTES`` reads as empty (logged), so
        the next write replaces it."""
        with open(self.path, "rb") as f:  # type: ignore[arg-type]
            data = f.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            log.warning("learned replies file %s is over %d bytes; starting empty",
                        self.path, MAX_FILE_BYTES)
            return b""
        return data

    def _refresh(self) -> None:
        """Reload the file when it changed since the last read, then swap the new copy
        in whole. File I/O; runs in the worker, or at once without ``background``."""
        if self.path is None:
            return
        signature = self._stat()
        if signature is None:
            self.read_error = "cannot stat the file"
            return
        with self._lock:
            if signature == self._signature:
                return
        if signature == ():
            entries: dict[str, dict] = {}
        else:
            # The file is only ever replaced whole (``os.replace``): a read needs no lock.
            try:
                data = self._read_file()
            except FileNotFoundError:
                data, signature = b"", ()
            except OSError as exc:
                self.read_error = str(exc.strerror or type(exc).__name__)
                self._error("cannot read learned replies %s: %s", self.path, exc)
                return
            entries = self._parse(data)
        with self._lock:
            self._entries, self._signature = entries, signature
        self.read_error = None

    def _reload_if_changed(self) -> None:
        """Ask for a reload when the file's inode, size or mtime changed (at most one
        pending in the worker); the current copy serves until the new one is in."""
        if self.path is None:
            return
        signature = self._stat()
        with self._lock:
            if signature is None or signature == self._signature or self._reload_pending:
                return
            self._reload_pending = self.background
        if not self.background:
            self._refresh()
            return

        def job() -> None:
            with self._lock:
                self._reload_pending = False
            self._refresh()
        if not self._submit(job):
            with self._lock:
                self._reload_pending = False

    def _transact(self, change: Callable[[dict[str, dict]], None]) -> bool:
        """Apply ``change`` to the freshest entries and save them under the file lock, then
        swap the new copy in whole. File I/O; runs in the worker, or at once without
        ``background`` (and for ``forget`` and ``clear``)."""
        if self.path is None:
            with self._lock:
                self._apply_pending(self._entries)
                change(self._entries)
                self._evict(self._entries)
            return True
        with self._lock:
            pending, self._pending, self._pending_since = self._pending, {}, None
            self._flush_queued = False
        try:
            directory = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(directory, exist_ok=True)
            fd = os.open(self.path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                signature = self._stat()
                with self._lock:
                    current = dict(self._entries) if signature and \
                        signature == self._signature else None
                if current is not None:
                    entries = current     # this process wrote the file last: no re-read
                else:
                    try:
                        data = self._read_file()
                    except FileNotFoundError:
                        data = b""
                    entries = self._parse(data)
                self._add_served(entries, pending)
                change(entries)
                self._evict(entries)
                self._write(directory, entries)
                signature = self._stat()
                with self._lock:
                    self._entries, self._signature = entries, signature
        except OSError as exc:
            with self._lock:        # keep the counts for the next write
                for eid, count in pending.items():
                    self._pending[eid] = self._pending.get(eid, 0) + count
            self._error("cannot write learned replies %s: %s", self.path, exc)
            return False
        return True

    def _write(self, directory: str, entries: dict[str, dict]) -> None:
        """Replace the file with ``entries``, one per line; past ``WRITE_BUDGET`` bytes
        the entries that are not served go first, least recently seen first. Lines of
        entries unchanged since the last write are reused."""
        parts: dict[str, bytes] = {}
        lines: dict[str, tuple[dict, bytes]] = {}
        for eid, e in entries.items():
            cached = self._lines.get(eid)
            if cached is not None and cached[0] is e:
                line = cached[1]
            else:
                line = json.dumps({k: v for k, v in e.items() if k != "id"},
                                  separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            parts[eid] = line
            lines[eid] = (e, line)
        total = sum(len(p) + 1 for p in parts.values())
        if total > WRITE_BUDGET:
            for entry in sorted(entries.values(),
                                key=lambda e: (promoted(e, self.min_sessions), e["last"])):
                total -= len(parts.pop(entry["id"])) + 1
                lines.pop(entry["id"], None)
                entries.pop(entry["id"], None)
                if total <= WRITE_BUDGET:
                    break
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".learned-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(json.dumps({"version": FILE_VERSION}).encode("ascii") + b"\n")
                for line in parts.values():
                    f.write(line + b"\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)  # type: ignore[arg-type]
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        self._lines = lines

    def _apply_pending(self, entries: dict[str, dict]) -> None:
        """Served counts into ``entries`` (memory-only store; the lock is held)."""
        self._add_served(entries, self._pending)
        self._pending, self._pending_since = {}, None

    def _add_served(self, entries: dict[str, dict], pending: dict[str, int]) -> None:
        for eid, count in pending.items():
            if eid in entries:
                entry = _own(entries, eid)
                entry["served"] += count
                entry["last"] = max(entry["last"], int(self._clock()))

    def _evict(self, entries: dict[str, dict]) -> None:
        excess = len(entries) - self.max_entries
        if excess <= 0:
            return
        order = sorted(entries.values(),
                       key=lambda e: (promoted(e, self.min_sessions), e["last"]))
        for entry in order[:excess]:
            entries.pop(entry["id"], None)

    # -- runtime ---------------------------------------------------------------------------

    def lookup(self, fingerprint: str, user: str, interactive: bool, command: str,
               history: Optional[str] = None, *, clean: bool = True,
               script: Optional[str] = None,
               values: tuple[str, ...] = ()) -> Optional["Found"]:
        """The served reply for ``command``, else None. ``clean`` says the session may use
        the different-histories rule (``history`` is its input history); ``script`` (the
        line's same-history key, ``script_key``) and ``values`` (the session's token
        values) select the same-history rule, which is tried second."""
        template = _template(command)
        if template is None:
            return None
        self._reload_if_changed()
        eid = entry_id(fingerprint, user[:MAX_USER_CHARS], interactive, template.text,
                       shape(template.values))
        with self._lock:
            entry = self._entries.get(eid)
            if entry is None:
                return None
            if clean and command and servable(entry, self.min_sessions, history,
                                              value_set(template.values)):
                reply = fill(entry["reply"], template.values)
                if reply is not None:
                    return Found(eid, reply, "history", False)
            h = entry["hist"].get(script) if script is not None else None
            if h is not None and hist_served(h, self.min_sessions, value_set(values)):
                reply = fill(h["reply"], values)
                if reply is not None:
                    return Found(eid, reply, "script", True)
        return None

    def served(self, eid: str) -> None:
        """Count a serve; written with the next write, or once enough have gathered."""
        now = time.monotonic()
        with self._lock:
            self._pending[eid] = self._pending.get(eid, 0) + 1
            if self._pending_since is None:
                self._pending_since = now
            due = not self._flush_queued and (sum(self._pending.values()) >= FLUSH_SERVES
                                              or now - self._pending_since >= FLUSH_SECONDS)
            if due:
                self._flush_queued = True
        if due and not self._submit(lambda: self._transact(lambda entries: None)):
            with self._lock:
                self._flush_queued = False

    def record(self, fingerprint: str, user: str, interactive: bool, command: str,
               reply: Optional[str], *, session: str, net: str,
               history: Optional[str], script: Optional[str] = None,
               script_sent: Optional[str] = None,
               values: tuple[str, ...] = ()) -> Optional[str]:
        """``_record`` in the worker (``background``; returns the entry id once queued,
        None when the queue was full) or at once."""
        if not self.background:
            return self._record(fingerprint, user, interactive, command, reply,
                                session=session, net=net, history=history, script=script,
                                script_sent=script_sent, values=values)
        template = _template(command)
        if template is None:
            return None
        queued = self._submit(lambda: self._record(
            fingerprint, user, interactive, command, reply, session=session, net=net,
            history=history, script=script, script_sent=script_sent, values=values))
        return entry_id(fingerprint, user[:MAX_USER_CHARS], interactive, template.text,
                        shape(template.values)) if queued else None

    def _record(self, fingerprint: str, user: str, interactive: bool, command: str,
                reply: Optional[str], *, session: str, net: str,
                history: Optional[str], script: Optional[str] = None,
                script_sent: Optional[str] = None,
                values: tuple[str, ...] = ()) -> Optional[str]:
        """Record that ``command`` reached the model. With ``history`` (a clean session's
        fresh reply, sent unchanged) it is also an observation for the different-histories
        rule: of ``reply``, or, when ``reply`` is None or cannot be a template, of a reply
        that cannot be stored, which marks the entry varying. With ``script`` (the line's
        same-history key, ``script_key``) it is an observation for the same-history rule
        under that key: of ``script_sent``
        (the whole reply as sent) templated with the session's token ``values``; a reply
        that cannot be templated marks that history varying. Returns the entry id, or None
        when the command cannot be a template or the write failed."""
        template = _template(command)
        if template is None:
            return None
        user = user[:MAX_USER_CHARS]
        stored = reply_template(reply, template.values, command) if reply is not None else None
        observe = history is not None
        script_stored = reply_template(script_sent, values, command) \
            if script is not None and script_sent is not None else None
        eid = entry_id(fingerprint, user, interactive, template.text, shape(template.values))
        now = int(self._clock())
        sess = digest("session", session)

        def change(entries: dict[str, dict]) -> None:
            entry = _own(entries, eid) if eid in entries else None
            if entry is None:
                entry = {"id": eid, "fp": fingerprint, "user": user,
                         "interactive": interactive, "command": template.text,
                         "reply": None, "varying": False, "obs": [], "nets": [],
                         "asked": 0, "served": 0, "first": now, "last": now, "hist": {},
                         "vals": [], "shape": shape(template.values)}
                entries[eid] = entry
            entry["asked"] += 1
            entry["last"] = max(entry["last"], now)
            if net not in entry["nets"] and len(entry["nets"]) < MAX_NETS:
                entry["nets"].append(net)
            if script is not None:
                self._observe_script(entry, script, script_stored, sess, net, now,
                                     value_set(values))
            if not observe or entry["varying"]:
                return
            if stored is None:
                entry["varying"] = True
                entry["reply"] = None
                return
            if entry["reply"] is None and not entry["obs"]:
                entry["reply"] = stored
            if entry["reply"] != stored:
                entry["varying"] = True
                entry["reply"] = None
                return
            vals = value_set(template.values)
            if vals not in entry["vals"] and len(entry["vals"]) < MAX_VALUE_SETS:
                entry["vals"].append(vals)       # kept past the observation cap
            if all(o[0] != sess for o in entry["obs"]) and len(entry["obs"]) < MAX_OBSERVATIONS:
                entry["obs"].append([sess, net, history, vals])

        return eid if self._transact(change) else None

    def _observe_script(self, entry: dict, script: str, stored: Optional[str], sess: str,
                        net: str, now: int, vals: str) -> None:
        """One same-history observation. Evidence is counted per script digest. A digest
        keeps only a digest of its reply until it reaches the serving threshold, so up to
        ``MAX_PENDING`` digests fit per entry, and at most ``MAX_HISTORIES`` hold the
        text. Past either cap the least recently seen digest of that kind goes (a varying
        mark goes with it)."""
        hist = entry["hist"]
        h = hist.get(script)
        rdig = digest("reply", stored) if stored is not None else None
        if h is None:
            if len(hist) >= MAX_PENDING:
                del hist[min(hist, key=lambda k: (hist[k]["reply"] is not None,
                                                  hist[k]["last"]))]
            h = hist[script] = {"reply": None, "rdig": rdig, "varying": stored is None,
                                "vals": [], "sessions": [], "nets": [], "last": now}
        h["last"] = max(h["last"], now)
        if h["varying"]:
            return
        if rdig is None or rdig != h["rdig"]:
            h.update(varying=True, reply=None, rdig=None)
            return
        if sess not in h["sessions"] and len(h["sessions"]) < MAX_OBSERVATIONS:
            h["sessions"].append(sess)
        if net not in h["nets"] and len(h["nets"]) < MAX_NETS:
            h["nets"].append(net)
        if vals not in h["vals"] and len(h["vals"]) < MAX_VALUE_SETS:
            h["vals"].append(vals)
        if h["reply"] is None and _hist_enough(h, self.min_sessions):
            texts = [k for k, o in hist.items() if o["reply"] is not None]
            if len(texts) >= MAX_HISTORIES:
                oldest = min(texts, key=lambda k: hist[k]["last"])
                hist[oldest].update(reply=None)
            h["reply"] = stored

    # -- operator --------------------------------------------------------------------------

    def entries(self) -> list[dict]:
        """Every entry, read from the file now (operator command and tests)."""
        self._refresh()
        with self._lock:
            return [dict(e) for e in self._entries.values()]

    def forget(self, eid: str) -> Optional[bool]:
        """Whether the entry was there and is gone; None when the file could not be
        written."""
        found = []

        def change(entries: dict[str, dict]) -> None:
            found.append(entries.pop(eid, None) is not None)
        return bool(found and found[0]) if self._transact(change) else None

    def clear(self) -> Optional[int]:
        """How many entries were dropped; None when the file could not be written."""
        count = []

        def change(entries: dict[str, dict]) -> None:
            count.append(len(entries))
            entries.clear()
        return (count[0] if count else 0) if self._transact(change) else None


def valid_id(text: str) -> bool:
    return bool(_ID.fullmatch(text or ""))


# ---- operator text ---------------------------------------------------------------------------

def escape(text: str, limit: int = 120) -> str:
    """Attacker or model text for a terminal: printable characters kept, backslash and
    every other character written as an escape, placeholders as ``{N}``, cut to ``limit``."""
    text = _PLACEHOLDER.sub(lambda m: "{" + m.group(1) + "}", text)
    out: list[str] = []
    size = 0
    for c in text:
        if c in _ESCAPES:
            piece = _ESCAPES[c]
        elif c.isprintable():
            piece = c
        else:
            code = ord(c)
            piece = f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}" \
                if code < 0x10000 else f"\\U{code:08x}"
        out.append(piece)
        size += len(piece)
        if size > limit:
            break
    joined = "".join(out)
    return joined if len(joined) <= limit else joined[:limit - 3] + "..."


_ESCAPES = {"\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


STEPS = ("local", "cached", "learned", "capped", "model", "fallback", "budget", "offline")
MAX_LIST = 200


def step_counts(log_path: Optional[str]) -> dict[str, int]:
    """Commands per reply step from the event log: SSH ``LLM response`` lines and Telnet
    persona ``Telnet input`` lines carry the step (``reply_step``, ``data.step``); a line
    without one counts as ``unknown``; session openers are left out."""
    counts: dict[str, int] = {}
    if not log_path or not os.path.exists(log_path):
        return counts
    from agents.ui.logindex import iter_lines

    try:
        for _, _, rec in iter_lines(log_path):
            if not rec:
                continue
            step = None
            if rec.get("message") == "LLM response" and rec.get("sensor_protocol") == "ssh":
                step = rec.get("reply_step", "unknown")
            elif rec.get("message") == "Telnet input" and isinstance(rec.get("data"), dict) \
                    and rec["data"].get("persona") is True:
                step = rec["data"].get("step", "unknown")
            if step is None or step == "opener":
                continue
            step = step if isinstance(step, str) and step in STEPS else "unknown"
            counts[step] = counts.get(step, 0) + 1
    except OSError as exc:
        counts["unreadable_log"] = 1
        log.warning("cannot read %s: %s", log_path, exc)
    return counts


def stats_text(store: LearnedStore, log_path: Optional[str]) -> tuple[str, dict]:
    entries = store.entries()
    served = [e for e in entries if promoted(e, store.min_sessions)]
    summary = {"entries": len(entries), "served_entries": len(served),
               "varying": sum(1 for e in entries if e["varying"]),
               "times_served": sum(e["served"] for e in entries),
               "steps": step_counts(log_path)}
    lines = [f"learned replies: {store.path or '(memory)'}",
             f"entries: {summary['entries']}  served: {summary['served_entries']}  "
             f"varying: {summary['varying']}  times served: {summary['times_served']}"]
    total = sum(summary["steps"].values())
    if total:
        lines.append(f"commands in the log by reply step ({total}):")
        for step, n in sorted(summary["steps"].items(), key=lambda kv: -kv[1]):
            lines.append(f"  {step:<10} {n:>8}  {100.0 * n / total:5.1f}%")
    else:
        lines.append("commands in the log by reply step: none found")
    return "\n".join(lines), summary


def _command(entry: dict) -> str:
    return escape(entry["command"]) if entry["command"] else "(session opener)"


def _state(entry: dict, min_sessions: int) -> str:
    scripts = sum(1 for h in entry["hist"].values() if hist_served(h, min_sessions))
    if entry["varying"]:
        return "varying" + (f", served in {scripts} scripts" if scripts else "")
    if servable(entry, min_sessions):
        return "served" + (f", and in {scripts} scripts" if scripts else "")
    if servable(entry, min_sessions, START):
        return "served to first commands" + (f", and in {scripts} scripts" if scripts else "")
    if scripts:
        return f"served in {scripts} scripts"
    obs = entry["obs"]
    return (f"waiting {len({o[0] for o in obs})}/{min_sessions} sessions, "
            f"{len({o[1] for o in obs})}/2 networks, {len({o[2] for o in obs})}/2 histories")


def list_text(store: LearnedStore) -> tuple[str, dict]:
    entries = sorted(store.entries(), key=lambda e: -e["last"])
    lines = [f"{len(entries)} entries (newest first, at most {MAX_LIST} shown)"]
    for e in entries[:MAX_LIST]:
        mode = "tty" if e["interactive"] else "exec"
        lines.append(f"{e['id']}  {escape(e['user'], 32)} {mode}  served {e['served']}  "
                     f"asked {e['asked']}  {_state(e, store.min_sessions)}")
        lines.append(f"    command: {_command(e)}")
        if e["reply"] is not None:
            lines.append(f"    reply:   {escape(e['reply'])}")
    return "\n".join(lines), {"entries": len(entries)}


def candidates_text(store: LearnedStore, limit: int = 50) -> tuple[str, dict]:
    """Command templates that reached the model most often and are not served."""
    waiting = [e for e in store.entries() if not promoted(e, store.min_sessions)]
    waiting.sort(key=lambda e: (-e["asked"], -len(e["nets"])))
    lines = [f"commands that reach the model and are not served ({len(waiting)}; "
             f"top {min(limit, len(waiting))}):",
             f"{'asked':>7} {'networks':>8}  state / command"]
    for e in waiting[:limit]:
        nets = f"{len(e['nets'])}{'+' if len(e['nets']) >= MAX_NETS else ''}"
        lines.append(f"{e['asked']:>7} {nets:>8}  {_state(e, store.min_sessions)}")
        lines.append(f"{'':>17}  {_command(e)}")
    return "\n".join(lines), {"candidates": len(waiting)}


def path_beside(state_file: Optional[str]) -> Optional[str]:
    """The store's file in the budget state file's directory, or None (memory only)."""
    return os.path.join(os.path.dirname(os.path.abspath(state_file)), FILE_NAME) \
        if state_file else None
