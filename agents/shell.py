"""Deterministic shell answers for the commands bots use to size up a host.

One answerer for the SSH fallback (no model, model error, model cap) and the Telnet trap's
canned shell, so the two cannot disagree; with a model, known commands are answered here
first by how far a session could have changed what they report (``Answer.scope``, ``[llm]
local_shell_replies``, see ``agents.hooks``).

Every answer is computed in Python from one host profile: the scenario's identity, its
``[identity.hardware]`` table, the sensor seed and the clock. Nothing is executed, nothing
is fetched, and no pattern from the attacker is compiled as a regular expression (``grep``
patterns are fixed strings plus ``.``, ``^`` and ``$``, matched by hand). One line's
whole cost is bounded: see ``MAX_WORK``, ``MAX_STAGE_OUTPUT`` and ``MAX_FILES``.

``answer`` takes one input line: a simple command, a pipeline of our own output through
``grep``, ``head``, ``tail``, ``cut``, ``wc`` and ``awk '{print ...}'``, or a ``;`` / ``&&``
/ ``||`` list of those. Redirections (``>``, ``>>``, ``<``, ``2>&1``) and the loop IoT
loaders use to read a binary (``while read i; do echo $i; done < FILE``) are understood.
Anything it cannot evaluate exactly (substitution, globbing, other variables, an unknown
command, file or option) returns None, and the caller answers as it did before. ``reply``
goes further for the canned shell: a list is answered part by part, each part it cannot
evaluate getting what ``Shell.unhandled`` gives a whole line.

Files a session writes (``>x``, ``cp``, ``echo -ne '...' >> x``) live in a ``Session``:
in memory only, bounded by ``MAX_SCRATCH`` and ``MAX_SCRATCH_BYTES``, and never executed.
Program files read as the start of an ELF image for the host's machine (``agents.elfimage``).

Output is text, except that a byte 0x80 to 0xFF from a binary travels as the lone surrogate
``chr(0xDC00 + byte)`` (Python's ``surrogateescape``): ``wire`` turns a reply into the exact
bytes for the network, and ``printable`` into text that is safe to log or show.
"""

from __future__ import annotations

import datetime
import functools
import hashlib
import logging
import math
import posixpath
import random
import re
import shlex
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Optional

from scenarios.schema import GPU_SPECS, HARDWARE_PRESETS, Hardware

log = logging.getLogger(__name__)

MAX_LINE = 4096            # longer input is not evaluated
MAX_WORD = 1024
MAX_WORDS = 64             # per command
MAX_STAGES = 8             # commands in one pipeline
MAX_LIST = 32              # pipelines in one ; && || list (loader lines run to ~20)
MAX_PATTERN = 256          # grep pattern length
MAX_FILES = 8              # file operands one command reads
MAX_STAGE_OUTPUT = 128 * 1024  # characters one command may produce (a 64-CPU cpuinfo is 72k)
MAX_OUTPUT = 128 * 1024    # characters the whole line may produce
MAX_ECHO_OUTPUT = 4096
MAX_SCRATCH = 4 * MAX_FILES     # files and directories one session may create
MAX_SCRATCH_BYTES = MAX_OUTPUT  # characters all of a session's files may hold
# Work is counted per line, across every command in it, in rough nanoseconds: a character
# handled in C (split, find, join, slicing) costs 1, a step of a Python loop costs STEP and
# a line of input LINE. Over budget, the line falls back as an unknown line does, so the
# worst line costs a few tens of milliseconds on the event loop (see the tests).
MAX_WORK = 12_000_000
STEP = 64
LINE = 256
COMMAND = 20_000           # running one command: parsing options, building the host's tables

SHELL_BUILTINS = frozenset((
    "echo", "printf", "cd", "export", "unset", "set", "alias", "unalias", "true", ":",
    "source", ".", "umask", "ulimit", "shopt", "trap", "wait", "read", "local", "declare",
    "typeset", "readonly", "eval", "exec", "hash", "history", "builtin", "command", "enable",
))
# bash's reserved words: a line starting with one is shell syntax, never a missing command.
SHELL_KEYWORDS = frozenset(("while", "until", "for", "if", "case", "select", "function",
                            "time", "{", "[[", "!", "do", "done", "then", "fi", "esac"))
BIN_DIRS = frozenset(("/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin",
                      "/usr/local/sbin"))
# Words IoT bots send first because a device CLI knows them. bash does not, so they are
# "command not found" (``enable`` is a bash builtin and ``sh`` starts a nested shell).
NOT_COMMANDS = frozenset(("system", "shell", "linuxshell"))
DEFAULT_KERNEL = ("Linux srv01 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC "
                  "2024 x86_64 x86_64 x86_64 GNU/Linux")
MACHINES = frozenset(("x86_64", "aarch64", "i686", "armv7l"))

# How far ahead of a model an answer may be given (``Answer.scope``; a line takes the
# highest of its commands):
FIXED = 0     # facts no command can change: kernel, CPU, memory, /proc hardware files,
#               uptime, the openers. Always answered here.
SESSION = 1   # facts a session can change (hostname, users, any file or path, mounts and
#               disk use, processes, the working directory): answered here only until the
#               model has answered a command.
STATE = 2     # commands that change the session (cd, export, downloads): never answered
#               ahead of a model, which then owns the change.


# ---- literal echo / printf (also used by agents.hooks for the model path) ---------------

_NOT_LITERAL = re.compile(r"[$`*?|;&<>(){}\[\]~\\]")


def literal_output(text: str) -> Optional[str]:
    """What ``echo`` or ``printf`` of literal arguments prints, computed in code; None when
    the command is anything else or its arguments need a shell to expand."""
    try:
        words = shlex.split(text)
    except ValueError:
        return None
    if not words or words[0] not in ("echo", "printf"):
        return None
    if words[0] == "echo" and any(_NOT_LITERAL.search(w) for w in words[1:]):
        return None
    if words[0] == "printf" and (any(_NOT_LITERAL.search(w) for w in words[2:])
                                 or re.search(r"[$`]", " ".join(words[1:2]))):
        return None
    if words[0] == "echo":
        args, newline = words[1:], True
        while args and args[0] in ("-n", "-e", "-E", "-ne", "-en"):
            newline = newline and "n" not in args[0]
            args = args[1:]
        out = " ".join(args) + ("\n" if newline else "")
    else:
        if len(words) < 2:
            return None
        fmt, args = words[1], words[2:]
        fmt = fmt.replace("\\n", "\n").replace("\\t", "\t")
        if re.search(r"%[^sd%]", fmt):
            return None
        out, i = "", 0
        for part in re.split(r"(%[sd%])", fmt):
            if part == "%%":
                out += "%"
            elif part in ("%s", "%d"):
                value = args[i] if i < len(args) else ""
                i += 1
                if part == "%d":
                    try:
                        value = str(int(value or 0))
                    except ValueError:
                        return None
                out += value
            else:
                out += part
    return "".join(c for c in out if c.isprintable() or c in "\n\t")[:MAX_ECHO_OUTPUT]


def clean_word(text: str) -> str:
    """The first word of ``text``, printable characters only, as a shell error names it
    (``ping;`` is the word ``ping``: an operator ends a word)."""
    first = (text.split() or [""])[0]
    for op in ";|&<>":
        first = first.split(op, 1)[0]
    return "".join(c for c in first if c.isprintable())[:64]


# ---- bytes in replies -----------------------------------------------------------------------

def binary_text(data: bytes) -> str:
    """Raw bytes as reply text: ASCII as itself, 0x80 to 0xFF as lone surrogates."""
    return data.decode("ascii", "surrogateescape")


def byte_char(value: int) -> str:
    """One byte (``echo -e '\\xNN'``) as reply text."""
    return chr(value) if value < 0x80 else chr(0xDC00 + value)


def wire(text: str) -> bytes:
    """The exact bytes a reply puts on the network: UTF-8 text, binary bytes as they were."""
    return text.encode("utf-8", "surrogateescape")


def printable(text: str) -> str:
    """A reply as text that is safe to log, store or send to a model: line endings and tabs
    kept, every other control character and binary byte written as ``\\xNN``."""
    if text.isprintable():
        return text
    out = []
    for c in text:
        if c.isprintable() or c in "\r\n\t":
            out.append(c)
        else:
            code = ord(c) - 0xDC00 if 0xDC80 <= ord(c) <= 0xDCFF else ord(c)
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
    return "".join(out)


# ---- host profile -------------------------------------------------------------------------

@dataclass(frozen=True)
class User:
    name: str
    uid: int
    gecos: str
    home: str
    shell: str


@dataclass
class Host:
    """Everything the answers are computed from. Build with ``host_for``."""

    hostname: str = "srv01"
    domain: str = ""
    os_pretty_name: str = "Ubuntu 22.04.4 LTS"
    kernel: str = DEFAULT_KERNEL
    timezone: str = "UTC"
    internal_ips: tuple = ("10.0.0.12",)
    users: tuple = ()
    lures: tuple = ()
    hardware: Hardware = field(default_factory=Hardware)
    seed: str = "winnie"

    def __post_init__(self) -> None:
        words = self.kernel.split()
        machine_at = next((i for i, w in enumerate(words) if i >= 3 and w in MACHINES), None)
        if len(words) < 5 or words[0] != "Linux" or machine_at is None:
            words = DEFAULT_KERNEL.split()
            machine_at = words.index("x86_64")
        self.release = words[2]
        self.version = " ".join(words[3:machine_at])
        self.machine = words[machine_at]
        # "x86_64 x86_64 x86_64" in uname -a means processor and platform are known.
        self.platform_known = words[machine_at + 1:machine_at + 3] == [self.machine] * 2
        pretty = self.os_pretty_name.lower()
        self.family = ("ubuntu" if pretty.startswith("ubuntu") else
                       "debian" if pretty.startswith("debian") else
                       "rhel" if pretty.startswith(("red hat", "rocky", "alma", "centos",
                                                    "oracle")) else "other")

    @property
    def release_id(self) -> str:
        """The distribution's version number (``22.04``, ``12``, ``9.4``), or empty."""
        for word in self.os_pretty_name.split():
            if word[:1].isdigit():
                return word
        return ""

    @property
    def bash_version(self) -> tuple[int, int]:
        """The bash the distribution release ships (it decides how errors are prefixed)."""
        major = self.release_id.split(".")[0]
        table = {"ubuntu": {"18": (4, 4), "20": (5, 0), "22": (5, 1), "24": (5, 2)},
                 "debian": {"10": (5, 0), "11": (5, 1), "12": (5, 2)},
                 "rhel": {"7": (4, 2), "8": (4, 4), "9": (5, 1)}}
        return table.get(self.family, {}).get(major, (5, 1))

    @property
    def busybox(self) -> Optional[str]:
        """The distribution's busybox package version, or None where the base system does
        not ship one (RHEL and its rebuilds)."""
        major = self.release_id.split(".")[0]
        if self.family == "ubuntu":
            return {"18": "1.27.2 (Ubuntu 1:1.27.2-2ubuntu3.4)",
                    "20": "1.30.1 (Ubuntu 1:1.30.1-4ubuntu6.4)",
                    "22": "1.30.1 (Ubuntu 1:1.30.1-7ubuntu3)",
                    }.get(major, "1.36.1 (Ubuntu 1:1.36.1-6ubuntu3.1)")
        if self.family == "debian":
            return {"10": "1.30.1 (Debian 1:1.30.1-4)", "11": "1.30.1 (Debian 1:1.30.1-6+b3)",
                    }.get(major, "1.35.0 (Debian 1:1.35.0-4+b3)")
        if self.family == "rhel":
            return None
        return "1.36.1 (Ubuntu 1:1.36.1-6ubuntu3.1)"

    def rng(self, *purpose) -> random.Random:
        digest = hashlib.sha256("\x00".join(("shell", self.seed) + tuple(map(str, purpose)))
                                .encode("utf-8")).digest()
        return random.Random(int.from_bytes(digest[:8], "big"))

    # -- clock --

    def uptime_seconds(self, now: float) -> int:
        """Stable per sensor and steadily rising: between 2 and 120 days, then it
        starts again (a reboot)."""
        cycle = 118 * 86400
        phase = self.rng("boot").randrange(cycle)
        return 2 * 86400 + int((now + phase) % cycle)

    def boot_time(self, now: float) -> float:
        return now - self.uptime_seconds(now)

    def loadavg(self, now: float) -> tuple[float, float, float]:
        r = self.rng("load", int(now // 300))
        base = 0.02 * self.hardware.cpus * self.rng("load-level").uniform(0.4, 3.0)
        return (round(r.uniform(0, base * 4), 2), round(r.uniform(0, base * 2), 2),
                round(r.uniform(0, base), 2))

    def other_login(self) -> Optional[tuple[str, str]]:
        """(user, from) of the one login other than the attacker's, or None: on some
        sensors one of the scenario's login users has an idle SSH session open from the
        internal network. Stable per sensor; the persona block names it too."""
        r = self.rng("who")
        people = [u for u in self.users if u.shell.endswith(("/bash", "/sh", "/zsh"))]
        if not people or r.random() >= 0.4:
            return None
        user = r.choice(people)
        net = self.internal_ips[0].rsplit(".", 1)[0] if "." in self.internal_ips[0] \
            else "10.0.0"
        return user.name, f"{net}.{r.randrange(2, 250)}"

    def other_sessions(self, now: float) -> list[tuple[str, str, float, int]]:
        """Logins other than the attacker's (``other_login``) at ``now``: (user, from,
        login time, idle seconds); the attacker's session takes the next pts."""
        login_of = self.other_login()
        if login_of is None:
            return []
        r = self.rng("who-times")
        period = 2 * 86400            # logs in again every two days at the same time
        login = now - (now - r.randrange(period)) % period
        idle = int(min(now - login, (now - r.randrange(3600)) % 3600 + 120))
        return [(login_of[0], login_of[1], login, idle)]

    def daemons(self) -> list[tuple[str, str, str]]:
        """The optional services this sensor runs, (user, command, stat), as ``ps`` shows
        them; the persona block names them too."""
        return [d for d in _DAEMONS.get(self.family, ())
                if self.rng("daemon", d[1]).random() < 0.6]

    def local(self, ts: float) -> datetime.datetime:
        try:
            from zoneinfo import ZoneInfo

            tz = ZoneInfo(self.timezone)
        except Exception:  # noqa: BLE001 - no tz database: report UTC
            tz = datetime.timezone.utc
        return datetime.datetime.fromtimestamp(ts, tz)

    # -- memory and disk (kB), consistent between free, /proc/meminfo, df --

    def memory(self) -> dict[str, int]:
        """kB, each a whole number of 4 kB pages, as the kernel counts them."""
        r = self.rng("memory")
        total = _pages(self.hardware.memory_mb * 1024 * 0.968)
        used = _pages(total * r.uniform(0.12, 0.22))
        cache = _pages(total * r.uniform(0.18, 0.30))
        buffers = _pages(cache * 0.05)
        reclaim = _pages(cache * 0.08)
        shared = _pages(min(1024 + r.randrange(2048) * 4, total // 100))
        free = total - used - cache
        return {"total": total, "used": used, "free": free, "shared": shared,
                "buffers": buffers, "cached": cache - buffers - reclaim,
                "sreclaimable": reclaim, "cache": cache,
                "available": min(total, free + _pages(cache * 0.86))}

    def disk(self) -> tuple[int, int, int]:
        """(1K blocks, used, available) of the root file system."""
        r = self.rng("disk")
        blocks = int(self.hardware.disk_gb * 1024 * 1024 * 0.967)
        used = int(blocks * r.uniform(0.12, 0.35))
        reserved = int(blocks * 0.05) if self.family != "rhel" else 0
        return blocks, used, blocks - used - reserved

    @property
    def root_device(self) -> tuple[str, str]:
        return ("/dev/root", "ext4") if self.family == "ubuntu" else \
            ("/dev/vda1", "xfs") if self.family == "rhel" else ("/dev/vda1", "ext4")

    # -- accounts --

    def system_users(self) -> list[User]:
        table = _RHEL_PASSWD if self.family == "rhel" else _DEBIAN_PASSWD
        out = []
        for line in table.strip().splitlines():
            name, _, uid, _, gecos, home, sh = line.split(":")
            out.append(User(name, int(uid), gecos, home, sh))
        return out

    def all_users(self, login: str) -> list[User]:
        out = self.system_users() + list(self.users)
        names = {u.name for u in out}
        if login not in names:
            taken = {u.uid for u in out}
            uid = next(n for n in range(1000, 70000) if n not in taken)
            out.append(User(login, uid, "", f"/home/{login}", "/bin/bash"))
        return out

    def user(self, login: str) -> User:
        return next(u for u in self.all_users(login) if u.name == login)

    def bins(self) -> dict[str, str]:
        out = {name: f"/usr/bin/{name}" for name in _BINARIES}
        out.update({name: f"/usr/sbin/{name}" for name in _SBINARIES})
        if self.family == "rhel":
            out["lspci"] = "/usr/sbin/lspci"
        if self.hardware.gpu:
            out["nvidia-smi"] = "/usr/bin/nvidia-smi"
        if self.busybox is None:
            del out["busybox"]
        return out

    def bin_dirs(self) -> dict[str, tuple[str, ...]]:
        """What ``ls`` shows in /usr/bin and /usr/sbin (/bin and /sbin point there): the
        distribution's base system and every program ``bins`` names. Built once per kind of
        host (``_bin_dirs``)."""
        key = self.family if self.family in ("debian", "rhel") else \
            "ubuntu-24" if self.family == "ubuntu" and self.release_id >= "24" else "ubuntu-22"
        return _bin_dirs(key, tuple(sorted(self.bins().items())))[0]

    def bin_sets(self) -> dict[str, frozenset]:
        """``bin_dirs`` as sets, for lookups."""
        key = self.family if self.family in ("debian", "rhel") else \
            "ubuntu-24" if self.family == "ubuntu" and self.release_id >= "24" else "ubuntu-22"
        return _bin_dirs(key, tuple(sorted(self.bins().items())))[1]


@functools.lru_cache(maxsize=64)
def _bin_dirs(key: str, bins: tuple) -> tuple[dict, dict]:
    """(sorted names, name sets) per program directory for a base system and a host's
    ``bins``; shared by every host of that kind."""
    from agents.bin_lists import LISTS

    base_bin, base_sbin = LISTS[key]
    names = {"/usr/bin": set(base_bin), "/usr/sbin": set(base_sbin)}
    for name, path in bins:
        names[posixpath.dirname(path)].add(name)
    if "busybox" not in dict(bins):
        names["/usr/bin"].discard("busybox")
    return ({d: tuple(sorted(v)) for d, v in names.items()},
            {d: frozenset(v) for d, v in names.items()})


def _pages(kib: float) -> int:
    """Round kB down to whole 4 kB pages."""
    return int(kib) // 4 * 4


_BINARIES = ("awk", "base64", "bash", "busybox", "cat", "chattr", "chmod", "cp", "curl",
             "cut", "df", "free", "grep", "gzip", "head", "hostname", "id", "kill", "ls",
             "lscpu", "lspci", "mkdir", "mv", "nc", "nohup", "nproc", "perl", "ping", "ps",
             "python3", "rm", "scp", "sed", "sh", "ssh", "sudo", "tail", "tar", "tftp", "top",
             "uname", "uptime", "w", "wc", "wget", "which", "whoami", "crontab", "systemctl")
_SBINARIES = ("sshd", "useradd", "usermod", "iptables", "ip")

_DEBIAN_PASSWD = """
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:996:996:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:991:991:systemd Resolver:/:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
"""

_RHEL_PASSWD = """
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
systemd-coredump:x:999:997:systemd Core Dumper:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/:/usr/sbin/nologin
sssd:x:998:996:User for sssd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin
chrony:x:997:995:chrony system user:/var/lib/chrony:/sbin/nologin
"""


def host_for(scenario=None, seed: Optional[str] = None) -> Host:
    """The host profile of a loaded scenario (``scenarios.loader.LoadedScenario``), or the
    neutral default host when no scenario is active."""
    if scenario is None:
        seed = seed or "winnie"
        r = random.Random(int.from_bytes(hashlib.sha256(f"default-host|{seed}".encode())
                                         .digest()[:8], "big"))
        return Host(hardware=r.choice(HARDWARE_PRESETS), seed=seed)
    ident = scenario.scenario.identity
    hostname = scenario.hostname
    kernel_words = ident.kernel.split()
    if len(kernel_words) > 1:
        kernel_words[1] = hostname          # uname shows the current hostname
    return Host(
        hostname=hostname, domain=ident.domain, os_pretty_name=ident.os_pretty_name,
        kernel=" ".join(kernel_words), timezone=ident.timezone,
        internal_ips=tuple(ident.internal_ips),
        users=tuple(User(u.name, u.uid, u.gecos, u.home, u.shell) for u in ident.users),
        lures=tuple(scenario.lures()), hardware=scenario.hardware,
        seed=seed or scenario.seed or "winnie")


# ---- parsing ------------------------------------------------------------------------------

class _Unsupported(Exception):
    """The line needs a real shell; the caller answers as before."""


_UNQUOTED_SPECIAL = set("$`\\<>(){}*?[]~#!\"'")


def _tokenize(line: str) -> list:
    """Words, the operators ``|``, ``;``, ``&&``, ``||``, redirections (``_Redir``) and a
    bare ``$NAME`` (``_Var``, only the loop in ``_parse`` uses one). Quotes are honoured;
    anything else a shell would expand raises ``_Unsupported``."""
    if len(line) > MAX_LINE or any(not c.isprintable() and c != "\t" for c in line):
        raise _Unsupported
    tokens: list = []
    word: Optional[list] = None     # characters of the current word
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c in " \t":
            if word is not None:
                tokens.append("".join(word))
                word = None
            i += 1
            continue
        if c == "'":
            end = line.find("'", i + 1)
            if end < 0:
                raise _Unsupported
            word = word if word is not None else []
            word.append(line[i + 1:end])
            i = end + 1
            continue
        if c == '"':
            end = line.find('"', i + 1)
            if end < 0:
                raise _Unsupported
            inner = line[i + 1:end]
            if any(ch in inner for ch in "$`\\!"):
                raise _Unsupported
            word = word if word is not None else []
            word.append(inner)
            i = end + 1
            continue
        if c in "<>" or (c.isdigit() and word is None and line[i + 1:i + 2] == ">"):
            fd = int(c) if c.isdigit() else (0 if c == "<" else 1)
            i += 1 if c.isdigit() else 0
            if word is not None:
                tokens.append("".join(word))
                word = None
            op = line[i:i + 2] if line[i:i + 2] in (">>", ">&") else line[i]
            i += len(op)
            if op == ">&":
                target = _leading(line[i:], "0123456789")
                if target not in ("1", "2"):
                    raise _Unsupported
                tokens.append(_Redir(op, fd, target))
                i += len(target)
            else:
                tokens.append(_Redir(op, fd))
            continue
        if c == "$" and word is None:
            name = _leading(line[i + 1:], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                          "0123456789_")
            after = line[i + 1 + len(name):i + 2 + len(name)]
            if not name or name[0].isdigit() or (after and after not in " \t;|&<>"):
                raise _Unsupported
            tokens.append(_Var(name))
            i += 1 + len(name)
            continue
        if c in "|;&":
            if word is not None:
                tokens.append("".join(word))
                word = None
            two = line[i:i + 2]
            if two in ("&&", "||"):
                tokens.append(_Op(two))
                i += 2
            elif c == "|":
                tokens.append(_Op("|"))
                i += 1
            elif c == ";" and two != ";;":
                tokens.append(_Op(";"))
                i += 1
            else:
                raise _Unsupported           # background job or ;;
            continue
        if c in _UNQUOTED_SPECIAL:
            raise _Unsupported
        word = word if word is not None else []
        word.append(c)
        i += 1
    if word is not None:
        tokens.append("".join(word))
    return tokens


@dataclass(frozen=True)
class _Op:
    op: str


@dataclass(frozen=True)
class _Redir:
    op: str                  # < > >> >&
    fd: int
    target: Optional[str] = None   # a word follows, except for >&N


@dataclass(frozen=True)
class _Var:
    name: str


@dataclass
class _Simple:
    """One command of a pipeline: its words, its redirections in order (op, fd, target),
    and for ``while read NAME; do echo $NAME; done`` the loop's read options."""
    argv: list
    redirs: list = field(default_factory=list)
    loop: Optional[tuple] = None     # (raw: bool,) for the read loop


_LOOP = ("while", "read", None, ";", "do", "echo", "$", ";", "done")


def _loop_at(tokens: list, i: int) -> Optional[tuple[int, bool]]:
    """(index after ``done``, raw) when ``while read [-r] NAME; do echo $NAME; done`` starts
    at ``tokens[i]``, else None."""
    raw = tokens[i + 2:i + 3] == ["-r"]
    seq = tokens[i:i + 2] + tokens[i + 2 + raw:i + 9 + raw]
    if len(seq) != len(_LOOP):
        return None
    name = seq[2]
    for want, got in zip(_LOOP, seq):
        if want is None:
            ok = isinstance(got, str) and got.isidentifier()
        elif want == "$":
            ok = isinstance(got, _Var) and got.name == name
        elif want == ";":
            ok = got == _Op(";")
        else:
            ok = got == want
        if not ok:
            return None
    return i + 9 + raw, raw


def _parse(line: str) -> list[tuple[str, list[_Simple]]]:
    """[(operator before it, pipeline)], a pipeline being a list of ``_Simple``."""
    items: list[tuple[str, list[_Simple]]] = []
    joiner, pipeline, cmd = ";", [], _Simple([])
    tokens = _tokenize(line)
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if isinstance(tok, _Op):
            if not cmd.argv and not cmd.redirs and cmd.loop is None:
                raise _Unsupported
            pipeline.append(cmd)
            cmd = _Simple([])
            i += 1
            if tok.op == "|":
                continue
            items.append((joiner, pipeline))
            joiner, pipeline = tok.op, []
            continue
        if isinstance(tok, _Redir):
            if tok.op == ">&":
                cmd.redirs.append((tok.op, tok.fd, tok.target))
                i += 1
                continue
            target = tokens[i + 1] if i + 1 < len(tokens) else None
            if not isinstance(target, str) or len(target) > MAX_WORD:
                raise _Unsupported
            cmd.redirs.append((tok.op, tok.fd, target))
            i += 2
            continue
        if tok == "while" and not cmd.argv and cmd.loop is None:
            found = _loop_at(tokens, i)
            if found is None:
                raise _Unsupported
            i, raw = found
            cmd.loop = (raw,)
            continue
        if isinstance(tok, _Var) or cmd.loop is not None or len(tok) > MAX_WORD:
            raise _Unsupported
        cmd.argv.append(tok)
        i += 1
    if cmd.argv or cmd.redirs or cmd.loop is not None:
        pipeline.append(cmd)
        items.append((joiner, pipeline))
    elif pipeline or joiner != ";":
        raise _Unsupported                   # ends in | && ||
    if not items or len(items) > MAX_LIST or any(len(p) > MAX_STAGES for _, p in items) \
            or any(len(c.argv) + len(c.redirs) > MAX_WORDS for _, p in items for c in p):
        raise _Unsupported
    return items


# ---- evaluation ---------------------------------------------------------------------------

@dataclass
class Answer:
    output: str              # "\n" line endings; callers convert for the terminal
    status: int = 0
    scope: int = 0           # FIXED, SESSION or STATE: when it may be answered ahead of a model
    # False when the answer read the clock or the source address (``Shell.now``,
    # ``Shell.src_ip``): it then differs between two sessions that sent the same lines, so a
    # session that showed it can no longer share model replies (``agents.hooks``).
    shareable: bool = True

    @property
    def stateless(self) -> bool:
        """Only facts no session command can change (``FIXED``)."""
        return self.scope == FIXED


@dataclass
class _Result:
    out: str = ""
    err: str = ""
    status: int = 0
    scope: int = 0
    late: str = ""           # stderr written after the output (dd's record counts)
    exact: bool = False      # a fallback answer whose stdout is exactly what bash would print


Handler = Callable[["Shell", list[str], Optional[str]], Optional[_Result]]
_COMMANDS: dict[str, tuple[Handler, int]] = {}   # name -> (handler, scope)


def _command(*names: str, scope: int = 0):
    def register(fn: Handler) -> Handler:
        for name in names:
            _COMMANDS[name] = (fn, scope)
        return fn
    return register


class _OverBudget(_Unsupported):
    """The line needs more work or output than one line may cost."""


@dataclass
class _Scratch:
    """A file a session wrote. ``data`` is reply text (``binary_text``)."""
    data: str = ""
    mode: int = 0o644
    mtime: float = 0.0
    program: Optional[str] = None    # a copy of this program file (``cp /bin/echo x``)


@dataclass
class Session:
    """What one shell session has changed: its working directory and the files and
    directories it made or removed. Kept in memory only, at most ``MAX_SCRATCH`` entries
    and ``MAX_SCRATCH_BYTES`` characters; nothing is written to disk or executed."""
    cwd: Optional[str] = None
    files: dict = field(default_factory=dict)      # path -> _Scratch
    dirs: dict = field(default_factory=dict)       # path -> mtime, directories it made
    removed: set = field(default_factory=set)      # its own files it removed again
    version: int = 0       # bumped whenever an entry is made or removed (listing caches)

    def size(self) -> int:
        return sum(len(f.data) for f in self.files.values())


# Where a non-root login may create files.
_OPEN_DIRS = frozenset(("/tmp", "/var/tmp", "/dev/shm"))


class Shell:
    def __init__(self, host: Host, user: str, interactive: bool, cwd: Optional[str],
                 now: float, src_ip: Optional[str], session: Optional[Session] = None) -> None:
        self.host = host
        self.user = user
        self.interactive = interactive
        self.home = "/root" if user == "root" else host.user(user).home
        self.session = session if session is not None else Session()
        self.cwd = self.session.cwd or cwd or self.home
        self._now = now
        self._src_ip = src_ip
        self.private = False                # the answer read the clock or the source address
        self.argv0 = ""
        self.exe = "bash"                   # the program /proc/self/exe names
        self.busybox = False                # an applet run as ``busybox APPLET``
        self.raw = False                    # stdout goes to a file: keep every byte
        self.work = 0                       # see MAX_WORK
        self.stage_out = 0                  # characters the current command produced
        self.failed: Optional[list[str]] = None   # the command that could not be evaluated
        self.stage = 0                      # the pipeline stage being evaluated
        self.stage_fds: Optional[dict] = None     # its descriptors, once opened
        self.stage_errs: list[str] = []     # what the stages before it wrote to stderr
        self._files: dict[str, Optional[str]] = {}
        self.memo: dict = {}                # seeded values reused within the line

    @property
    def now(self) -> float:
        """The clock. Reading it makes the answer private (``Answer.shareable``)."""
        self.private = True
        return self._now

    @property
    def src_ip(self) -> Optional[str]:
        """The client's address. Reading it makes the answer private."""
        self.private = True
        return self._src_ip

    @property
    def prefix(self) -> str:
        """How bash names itself in its own errors: a login shell is ``-bash``; a command
        run over SSH exec is ``bash -c``, which adds ``line 1`` from bash 5.1 on."""
        if self.interactive:
            return "-bash"
        return "bash: line 1" if self.host.bash_version >= (5, 1) else "bash"

    def charge(self, units: int) -> None:
        self.work += units
        if self.work > MAX_WORK:
            raise _OverBudget

    def grow(self, chars: int) -> None:
        """Charge output as a command produces it, and cap one command's output."""
        self.stage_out += chars
        if self.stage_out > MAX_STAGE_OUTPUT:
            raise _OverBudget
        self.charge(chars)

    def run(self, line: str, partial: bool = False) -> Optional[Answer]:
        """The answer to a line, or None when it needs a real shell. With ``partial`` a
        list part this shell cannot evaluate gets ``_fallback`` and the rest still runs."""
        try:
            self.charge(len(line) * STEP)
            items = _parse(line)
            out, size, status, scope = [], 0, 0, FIXED
            for joiner, pipeline in items:
                if (joiner == "&&" and status != 0) or (joiner == "||" and status == 0):
                    continue
                try:
                    result = self._pipeline(pipeline)
                except _OverBudget:
                    raise
                except _Unsupported:
                    if not partial:
                        raise
                    result = self._fallback(pipeline)
                out.append(result.err + result.out + result.late)
                size += len(out[-1])
                if size > MAX_OUTPUT:
                    raise _OverBudget
                status = result.status
                scope = max(scope, result.scope)
        except _OverBudget:
            self.failed = None
            return None
        except _Unsupported:
            return None
        except Exception:  # noqa: BLE001 - a fault here must not end the attacker's session
            log.exception("canned shell failed on a line; falling back")
            self.failed = None
            return None
        finally:
            self.session.cwd = self.cwd
        return Answer("".join(out), status, scope, shareable=not self.private)

    def _fallback(self, pipeline: list[_Simple]) -> _Result:
        """What a list part this shell cannot evaluate prints, as ``unhandled`` does for a
        whole line: the tool's own error, a builtin's literal output, nothing for a known
        command, ``command not found`` for an unknown one. The stage that could not be
        evaluated and every stage after it answer so, each through its own redirections like
        any other output (bash starts every stage); what the stages before it wrote to
        stderr stays."""
        last = len(pipeline) - 1
        while True:
            failed, self.failed = self.failed, None
            k, fds, before = self.stage, self.stage_fds, "".join(self.stage_errs)
            out, errs, late, status, scope = "", [before], "", 0, STATE
            exact = False                   # stage k's stdout is known: the next stage may run
            for index in range(k, last + 1):
                cmd = pipeline[index]
                if index == k and fds is not None:
                    opened = (fds, None, FIXED)
                else:                       # not opened yet, or opening them was what failed
                    opened = self._redirect(cmd, None, lenient=True)
                if isinstance(opened, _Result):     # a redirection failed: it never ran
                    routed, exact = opened, True
                else:
                    text = self._fallback_text(cmd, failed if index == k else None)
                    routed, exact = self._route(opened[0], text, opened[2]), text.exact
                errs.append(routed.err)
                if index < last:
                    errs.append(routed.late)    # its stdout went into the next stage
                else:
                    out, late, status = routed.out, routed.late, routed.status
                scope = max(scope, routed.scope)
                if index < last and exact:
                    break
            if not (index < last and exact):
                return _Result(out, "".join(errs), status, scope, late)
            # Literal output, or none at all (``command not found``): what follows reads it.
            try:
                # after the stage that just completed, so nothing before it runs twice
                rest = self._pipeline(pipeline, index + 1, routed.out, "".join(errs))
            except _OverBudget:
                raise
            except _Unsupported:
                continue                    # a later stage: answered the same way
            rest.scope = max(rest.scope, scope)
            return rest

    def _fallback_text(self, cmd: _Simple, failed: Optional[list[str]]) -> _Result:
        """What the command that could not be evaluated prints, before its redirections."""
        argv = cmd.argv
        if not argv or cmd.loop is not None:
            return _Result(scope=STATE)
        name, words = self.resolve(argv[0]), argv
        if name == "busybox" and len(argv) > 1 and argv[1] in ("echo", "printf") \
                and self.installed("busybox"):
            name, words = argv[1], argv[1:]
        if name in ("echo", "printf"):
            text = literal_output(shlex.join([name] + words[1:]))
            return _Result(text or "", scope=STATE, exact=text is not None)
        if failed is not None:
            failed_name = self.resolve(failed[0])
            if failed_name is not None and self.installed(failed_name):
                text = _tool_error(self, failed_name, failed[1:])
                return _Result(err=text, status=1 if text else 0, scope=STATE)
        if name is None or self.installed(name) or name in SHELL_BUILTINS \
                or name in SHELL_KEYWORDS:
            return _Result(scope=STATE)
        word = clean_word(argv[0])
        return _Result(err=f"{self.prefix}: {word}: command not found\n", status=127,
                       scope=STATE, exact=True)

    def _pipeline(self, pipeline: list[_Simple], start: int = 0, stdin: Optional[str] = None,
                  errs: str = "") -> _Result:
        """Run the stages from ``start`` on, the first reading ``stdin`` (``_fallback`` resumes
        a pipeline after a stage it answered) after ``errs`` already written to stderr."""
        self.stage_errs = [errs]            # read by _fallback when a stage is unsupported
        errors, scope, result = self.stage_errs, FIXED, _Result()
        for index in range(start, len(pipeline)):
            cmd = pipeline[index]
            self.stage, self.stage_fds = index, None
            result = self._simple(cmd, stdin if index else None, index < len(pipeline) - 1)
            errors.append(result.err)
            if index < len(pipeline) - 1:
                errors.append(result.late)
            scope = max(scope, result.scope)
            stdin = result.out
        return _Result(result.out, "".join(errors), result.status, scope, result.late)

    def _simple(self, cmd: _Simple, stdin: Optional[str], piped: bool = False) -> _Result:
        """One command with its redirections, applied in order as bash applies them."""
        self.exe = "bash"                   # the shell opens the redirections
        opened = self._redirect(cmd, stdin)
        if isinstance(opened, _Result):
            return opened
        fds, stdin, scope = opened
        self.stage_fds = fds
        self.raw = fds[1][0] == "file" or (piped and fds[1][0] == "out")
        try:
            if cmd.loop is not None:
                result = _read_loop(self, cmd.loop[0], stdin)
            elif not cmd.argv:
                result = _Result()
            else:
                result = self._command(cmd.argv, stdin)
        finally:
            self.raw = False
        return self._route(fds, result, scope)

    def _redirect(self, cmd: _Simple, stdin: Optional[str], lenient: bool = False):
        """Open ``cmd``'s redirections in order: (fds, stdin, scope), or the result of one
        that fails, its message written where fd 2 points by then (``2>/dev/null </x`` is
        silent). ``lenient`` (``_fallback``) skips a redirection this shell cannot open, and
        discards output that would go there, instead of raising ``_Unsupported``."""
        fds: dict[int, tuple] = {1: ("out",), 2: ("err",)}
        scope = FIXED
        for op, fd, target in cmd.redirs:
            self.charge(COMMAND)
            try:
                if op == "<":
                    if fd != 0:
                        raise _Unsupported
                    read = self.read_file(target)
                    if read is None:
                        raise _Unsupported
                    if read.err:
                        shown = _shown(target)
                        scope = max(scope, SESSION)
                        return self._route(fds, _Result(
                            err=f"{self.prefix}: {shown}: No such file or directory\n",
                            status=1, scope=scope), scope)
                    self.charge(len(read.out))
                    stdin, scope = read.out, max(scope, read.scope)
                elif op == ">&":
                    if fd not in (1, 2):
                        raise _Unsupported
                    fds[fd] = fds[int(target)]
                else:
                    if fd not in (1, 2):
                        raise _Unsupported
                    dest = self._open_write(target, append=op == ">>")
                    if isinstance(dest, _Result):
                        # an earlier one may have made a file
                        return self._route(fds, dest, max(dest.scope, scope))
                    fds[fd] = dest
                    scope = max(scope, STATE if dest[0] == "file" else FIXED)
            except _OverBudget:
                raise
            except _Unsupported:
                if not lenient:
                    raise
                if op != "<" and fd in (1, 2):
                    fds[fd] = ("null",)
        return fds, stdin, scope

    def _route(self, fds: dict[int, tuple], result: _Result, scope: int) -> _Result:
        """``result`` sent where its descriptors point: to a session file (within the session
        limits), nowhere, or back as the reply's output or error."""
        routed = {"out": "", "err": "", "late": ""}
        for text, fd, stream in ((result.out, 1, "out"), (result.err, 2, "err"),
                                 (result.late, 2, "late")):
            dest = fds[fd]
            if dest[0] == "file":
                self._append(dest[1], text)
            elif dest[0] == "out":
                routed["out"] += text
            elif dest[0] == "err":
                routed["late" if stream == "late" else "err"] += text
        return _Result(routed["out"], routed["err"], result.status,
                       max(result.scope, scope), routed["late"])

    # -- session files --

    def path(self, word: str) -> str:
        return posixpath.normpath(posixpath.join(self.cwd, word))

    def directory(self, path: str) -> bool:
        """True for a directory this shell knows (the host's or one the session made)."""
        return path in self.session.dirs or path in _dirs(self) or path in _SYSTEM_DIRS

    def scratch_entries(self, path: str) -> list[str]:
        """Names of what the session made directly inside ``path``."""
        out = [p for p in list(self.session.files) + list(self.session.dirs)
               if posixpath.dirname(p) == path]
        return [posixpath.basename(p) for p in out]

    def writable(self, path: str) -> Optional[str]:
        """Why a new entry at ``path`` cannot be made (an error tail), or None when it can.
        Raises ``_Unsupported`` for a path whose parent this shell does not know."""
        parent = posixpath.dirname(path)
        if parent in self.session.removed and parent not in self.session.dirs:
            return "No such file or directory"
        if parent in ("/bin", "/sbin", "/usr/bin", "/usr/sbin"):
            # /bin and /sbin are /usr/bin and /usr/sbin under another name: a file made in
            # one would be missing from the other's listing. Left to the model.
            raise _Unsupported
        if (parent not in _dirs(self) and parent not in self.session.dirs) or path in _FILES \
                or self.program(path) or path in {posixpath.normpath(p) for p in self.host.lures}:
            raise _Unsupported               # a host file, or a directory we cannot list
        if _denied(self, path) or (self.user != "root" and parent not in _OPEN_DIRS
                                   and parent != self.home
                                   and not parent.startswith(self.home + "/")
                                   and not any(parent == d or parent.startswith(d + "/")
                                               for d in _OPEN_DIRS)):
            return "Permission denied"
        return None

    def _open_write(self, target: str, append: bool):
        """The destination of ``>``/``>>``: ("null",), ("file", path) or an error result."""
        path = self.path(target)
        shown = _shown(target)
        if path == "/dev/null":
            return ("null",)
        existing = self.session.files.get(path)
        if existing is None:
            if self.directory(path):
                return _Result(err=f"{self.prefix}: {shown}: Is a directory\n", status=1,
                               scope=SESSION)
            reason = self.writable(path)
            if reason is not None:
                return _Result(err=f"{self.prefix}: {shown}: {reason}\n", status=1,
                               scope=SESSION)
            self.store(path, _Scratch(mtime=self._now))
        elif not append:
            existing.data, existing.program, existing.mtime = "", None, self._now
            self.session.version += 1
        return ("file", path)

    def store(self, path: str, entry: Optional[_Scratch]) -> None:
        """Create or replace a session file (``entry``) or directory (None)."""
        s = self.session
        if path not in s.files and path not in s.dirs \
                and len(s.files) + len(s.dirs) >= MAX_SCRATCH:
            raise _OverBudget
        if entry is None:
            s.removed.discard(path)
            s.dirs[path] = self._now
            s.version += 1
            return
        if s.size() - len(s.files[path].data if path in s.files else "") \
                + len(entry.data) > MAX_SCRATCH_BYTES:
            raise _OverBudget
        self.charge(len(entry.data) + STEP)
        s.removed.discard(path)
        s.files[path] = entry
        s.version += 1

    def _append(self, path: str, text: str) -> None:
        entry = self.session.files.get(path)
        if not text or entry is None:
            return                          # removed while open: bash writes to the unlinked file
        if self.session.size() + len(text) > MAX_SCRATCH_BYTES:
            raise _OverBudget
        self.charge(len(text))
        entry.data += text
        entry.program, entry.mtime = None, self._now
        self.session.version += 1

    def remove(self, path: str) -> None:
        s = self.session
        s.files.pop(path, None)
        s.dirs.pop(path, None)
        if len(s.removed) >= MAX_SCRATCH:
            s.removed.pop()
        s.removed.add(path)
        s.version += 1

    def elf(self, program: str) -> str:
        """The start of a program file on this host (``agents.elfimage``)."""
        key = ("elf", program)
        if key not in self.memo:
            from agents import elfimage

            self.charge(elfimage.SIZE * STEP)
            self.memo[key] = binary_text(elfimage.image(self.host.machine,
                                                        self.host.rng("elf", program)))
        return self.memo[key]

    def program(self, path: str) -> Optional[str]:
        if "bin_dirs" not in self.memo:
            self.charge(COMMAND)
            self.memo["bin_dirs"] = self.host.bin_sets()
        directory, name = posixpath.split(path)
        directory = {"/bin": "/usr/bin", "/sbin": "/usr/sbin"}.get(directory, directory)
        return name if name in self.memo["bin_dirs"].get(directory, ()) else None

    def resolve(self, word: str) -> Optional[str]:
        """The command a word runs: its name, or None for a path outside the bin dirs."""
        if "/" not in word:
            return word
        directory, name = posixpath.split(posixpath.normpath(word))
        return name if directory in BIN_DIRS else None

    def bins(self) -> dict[str, str]:
        """``Host.bins``, built once per line."""
        if "bins" not in self.memo:
            self.charge(len(_BINARIES) * STEP)
            self.memo["bins"] = self.host.bins()
        return self.memo["bins"]

    def installed(self, name: str) -> bool:
        if name == "nvidia-smi":
            return bool(self.host.hardware.gpu)
        if name == "busybox":
            return self.host.busybox is not None
        return name in self.bins() or name in _COMMANDS \
            or self.program("/usr/bin/" + name) is not None \
            or self.program("/usr/sbin/" + name) is not None

    def _command(self, argv: list[str], stdin: Optional[str]) -> _Result:
        self.stage_out = 0
        self.charge(COMMAND + STEP * len(argv))
        word = argv[0]
        name = self.resolve(word)
        if name is None or ("/" in word and self.path(word) in self.session.files):
            return self._execute(word, argv[1:], stdin)
        if not self.installed(name):
            # a download can put a program there, so these hold only until the model answers
            if "/" in word:
                return _Result(err=f"{self.prefix}: {word}: No such file or directory\n",
                               status=127, scope=SESSION)
            if name in ("nvidia-smi", "busybox") or name in NOT_COMMANDS:
                return _Result(err=f"{self.prefix}: {word}: command not found\n", status=127,
                               scope=SESSION)
        entry = _COMMANDS.get(name)
        if entry is None:
            self.failed = argv
            raise _Unsupported
        handler, scope = entry
        self.argv0 = name
        self.exe = "bash" if name in SHELL_BUILTINS or name == "kill" else name
        result = handler(self, argv[1:], stdin)
        if result is None:
            self.failed = argv
            raise _Unsupported
        produced = len(result.out) + len(result.err) + len(result.late)
        if produced > MAX_STAGE_OUTPUT:
            raise _OverBudget
        self.charge(max(0, produced - self.stage_out))   # what grow() has not charged yet
        result.scope = max(result.scope, scope)
        return result

    def _execute(self, word: str, args: list[str], stdin: Optional[str] = None) -> _Result:
        """``./x``: a file the session wrote. Nothing is ever run: an empty file is an empty
        script, a copy of a program answers as that program, an ELF for another machine is
        refused as the kernel refuses it. Anything else (a script, a program for this
        machine) is unsupported."""
        path = self.path(word)
        entry = self.session.files.get(path)
        if entry is None:
            if path in self.session.removed:
                return _Result(err=f"{self.prefix}: {word}: No such file or directory\n",
                               status=127, scope=STATE)
            raise _Unsupported
        if not entry.mode & (0o111 if self.user == "root" else 0o100):   # the session owns it
            return _Result(err=f"{self.prefix}: {word}: Permission denied\n", status=126,
                           scope=STATE)
        if entry.program is not None and entry.data == self.elf(entry.program):
            result = self._command([entry.program] + args, stdin)
            result.scope = STATE
            return result
        if not entry.data:
            return _Result(scope=STATE)
        head = wire(entry.data[:64])
        if head.startswith(b"\x7fELF") and len(head) >= 20:
            order = "big" if head[5] == 2 else "little"
            from agents import elfimage

            if int.from_bytes(head[18:20], order) != elfimage.machine_field(self.host.machine):
                return _Result(err=f"{self.prefix}: {word}: cannot execute binary file: "
                                   "Exec format error\n", status=126, scope=STATE)
        elif "\x00" not in entry.data.split("\n", 1)[0]:
            raise _Unsupported               # a script: it would run its commands
        else:
            return _Result(err=f"{self.prefix}: {word}: cannot execute binary file: "
                               "Exec format error\n", status=126, scope=STATE)
        raise _Unsupported                   # a program for this machine: never run

    # -- helpers --

    def read_file(self, path: str) -> Optional[_Result]:
        """A virtual file's content, or an error result, or None when unknown."""
        path = self.path(path)
        scratch = self.session.files.get(path)
        if scratch is not None:
            return _Result(scratch.data, scope=SESSION)
        if path in self.session.removed:
            return _Result(status=1, err=f"{{cmd}}: {path}: No such file or directory\n",
                           scope=SESSION)
        program = self.exe if path == "/proc/self/exe" else self.program(path)
        if program is not None and path not in _FILES:
            # A session could replace a program file, but no model can answer its bytes.
            return _Result(self.elf(program), scope=FIXED)
        if path not in self._files:
            maker = _FILES.get(path)
            self._files[path] = maker(self) if maker is not None else None
        text = self._files[path]
        if text is not None:
            return _Result(text, scope=FIXED if path in _FIXED_FILES else SESSION)
        if path in _ABSENT.get(self.host.family, ()):
            return _Result(status=1, err=f"{{cmd}}: {path}: No such file or directory\n",
                           scope=SESSION)
        return None

    def unhandled(self, line: str) -> str:
        """The reply to a line ``run`` could not evaluate: the failing tool's own error for an
        option or file it does not know, nothing when a known command was used in a way this
        shell cannot reproduce, and ``command not found`` only for an unknown command."""
        self.work = 0                       # bounded on its own; the line's budget may be spent
        if self.failed is not None:
            name = self.resolve(self.failed[0])
            if name is not None and self.installed(name):
                return _tool_error(self, name, self.failed[1:])
        word = clean_word(line)
        if not word:
            return ""                        # ``>f ...``: bash never names an empty command
        name = self.resolve(word)
        if name is None or self.installed(name) or name in SHELL_BUILTINS \
                or name in SHELL_KEYWORDS:
            return ""
        return f"{self.prefix}: {word}: command not found\n"


def answer(host: Host, line: str, *, user: str = "root", interactive: bool = True,
           cwd: Optional[str] = None, now: Optional[float] = None,
           src_ip: Optional[str] = None) -> Optional[Answer]:
    """The deterministic answer to one input line, or None when it needs a real shell."""
    return _shell(host, user, interactive, cwd, now, src_ip).run(line.strip())


def _shell(host: Host, user: str, interactive: bool, cwd: Optional[str], now: Optional[float],
           src_ip: Optional[str], session: Optional[Session] = None) -> Shell:
    import time

    user = "".join(c for c in (user or "root") if c.isprintable() and c not in ":/ ")[:32] \
        or "root"
    return Shell(host, user, interactive, cwd, time.time() if now is None else now, src_ip,
                 session)


def persona_facts(host: Host) -> str:
    """Persona lines for what this sensor's ``w``, ``who``, ``uptime`` and ``ps`` show
    locally, so the model's own ``ps``, ``last`` and ``w`` agree with them. Stable per
    sensor (no clock)."""
    lines = []
    other = host.other_login()
    if other is not None:
        lines.append(f"- One other login is open: {other[0]} on pts/0 over SSH from "
                     f"{other[1]}, idle; w, who and last show it, and ps shows its sshd "
                     f"and -bash")
    else:
        lines.append("- No other user is logged in; last shows only earlier logins")
    daemons = [cmd.split()[0] for _, cmd, _ in host.daemons()]
    if daemons:
        lines.append("- Optional services running (ps shows these and the base system "
                     "services, nothing else long-running): " + ", ".join(daemons))
    return "\n" + "\n".join(lines)


def not_found(host: Host, interactive: bool, word: str) -> str:
    """bash's ``command not found`` line for ``word`` in this kind of session."""
    return f"{_shell(host, 'root', interactive, None, 0.0, None).prefix}: {word}: command not found"


def reply(host: Host, text: str, *, user: str = "root", interactive: bool = True,
          cwd: Optional[str] = None, now: Optional[float] = None,
          src_ip: Optional[str] = None, session: Optional[Session] = None) -> str:
    """The canned shell's full reply (no prompt, ``\\n`` endings): the deterministic answer,
    a list answered part by part, a builtin's own output (or none), a known tool's own error
    (or nothing), otherwise ``command not found``. ``session`` keeps the working directory
    and the files the session wrote from one line to the next."""
    word = clean_word(text)
    if not word and not text.strip().startswith(">"):
        return ""
    sh = _shell(host, user, interactive, cwd, now, src_ip, session)
    result = sh.run(text.strip(), partial=True)
    if result is not None:
        return result.output
    if word in SHELL_BUILTINS:
        return literal_output(text) or ""
    return sh.unhandled(text) if _stderr_shown(text) else ""


_LOOSE_REDIR = re.compile(r"(?:(?<![^ \t])([0-9]))?(&>>?|>>|>&|>|<)[ \t]*([^ \t;|&<>]*)")


def _stderr_shown(line: str) -> bool:
    """Whether the first command of a line ``run`` could not parse still writes its stderr
    to the terminal, read loosely from its redirections (``foo $X 2>/dev/null`` is silent).
    Quotes are honoured; the command ends at an unquoted ``;``, ``|`` or ``&&``."""
    masked, quote, i = [], None, 0
    while i < len(line):
        c = line[i]
        if quote is not None:
            masked.append("x" if c != quote else c)
            quote = None if c == quote else quote
        elif c in "'\"":
            quote = c
            masked.append(c)
        elif c == "\\":
            masked.append("xx")
            i += 1
        else:
            masked.append(c)
        i += 1
    text = "".join(masked)[:len(line)]
    end = re.search(r"&&|[;|]|&(?![>])(?<!>&)", text)
    fds = {1: "out", 2: "err"}
    for m in _LOOSE_REDIR.finditer(text, 0, end.start() if end else len(text)):
        op = m.group(2)
        fd = int(m.group(1)) if m.group(1) else (0 if op == "<" else 1)
        target = line[m.start(3):m.end(3)].replace("'", "").replace('"', "")
        if op.startswith("&>"):
            fds[1] = fds[2] = "away"
        elif op == ">&":
            if fd in (1, 2) and target in ("1", "2"):
                fds[fd] = fds[int(target)]
            elif fd in (1, 2) and target == "-":
                fds[fd] = "away"
        elif op != "<" and fd in (1, 2):
            fds[fd] = "away"
    return fds[2] != "away"


def prompt_path(cwd: Optional[str], home: str) -> str:
    """The directory a bash prompt shows: ``~`` for home and below it, else the path."""
    if not cwd or cwd == home:
        return "~"
    return "~" + cwd[len(home):] if cwd.startswith(home + "/") else cwd


# ---- small formatting helpers ---------------------------------------------------------------

def _lines(text: str) -> list[str]:
    return text.splitlines(keepends=True)


def _join(lines: list[str]) -> str:
    return "".join(line if line.endswith("\n") else line + "\n" for line in lines)


def _count(value: str) -> Optional[int]:
    """A count argument: digits only, absurd sizes allowed (they just select everything)."""
    if not (value.isascii() and value.isdigit()) or len(value) > 40:
        return None
    return int(value)


def _columns(names: list[str], width: int = 80, charge: Callable[[int], None] = lambda n: None
             ) -> str:
    """``ls`` output on a terminal: names in columns, filled top to bottom. Every column is
    at least 3 wide (a name and two spaces), so no more than ``(width + 2) // 3`` columns
    can fit and the search is linear in the number of names. ``charge`` is told the work."""
    if not names:
        return ""
    lengths = [len(n) for n in names]
    best = [names]
    for cols in range(min(len(names), (width + 2) // 3), 0, -1):
        charge(len(names) + cols * STEP)
        rows = math.ceil(len(names) / cols)
        if (cols - 1) * rows >= len(names):
            continue                         # the last column would be empty
        widths = [max(lengths[c * rows:(c + 1) * rows]) for c in range(cols)]
        if sum(widths) + 2 * (cols - 1) <= width:
            best = [names[c * rows:(c + 1) * rows] for c in range(cols)]
            break
    rows = len(best[0])
    widths = [max(map(len, col)) + 2 for col in best]
    charge(len(names) * STEP)
    out = []
    for r in range(rows):
        cells = [(col[r], w) for col, w in zip(best, widths) if r < len(col)]
        out.append("".join(name.ljust(w) for name, w in cells[:-1]) + cells[-1][0])
    return "\n".join(out) + "\n"


def _human(kib: float, suffix: str = "", ceil: bool = True) -> str:
    """1.5G style sizes (``df -h``) or 1.5Gi (``free -h``, with ``suffix='i'``)."""
    units = "KMGTP"
    value, unit = float(kib), 0
    while value >= 1024 and unit < len(units) - 1:
        value /= 1024
        unit += 1
    if unit == 0 and suffix:
        return f"{int(kib * 1024)}B" if kib < 1 else f"{value:.0f}Ki"
    if value < 10:
        value = math.ceil(value * 10) / 10 if ceil else round(value, 1)
        text = f"{value:.1f}"
    else:
        text = f"{math.ceil(value) if ceil else round(value):d}"
    return f"{text}{units[unit]}{suffix}"


def _url_text(value: str) -> str:
    return "".join(c for c in value if c.isalnum() or c in "-._~:/?#[]@!&'()*+,;=%")[:300]


# ---- identity and uptime ----------------------------------------------------------------------

_UNAME_FLAGS = {"s": "kernel-name", "n": "nodename", "r": "kernel-release",
                "v": "kernel-version", "m": "machine", "p": "processor",
                "i": "hardware-platform", "o": "operating-system"}
_UNAME_HELP = "Try 'uname --help' for more information.\n"


@_command("uname")
def _uname(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    h = sh.host
    wanted: set[str] = set()
    for arg in args:
        if arg.startswith("--"):
            name = arg[2:]
            if name == "all":
                wanted |= {"a"}
            elif name in _UNAME_FLAGS.values():
                wanted.add(next(k for k, v in _UNAME_FLAGS.items() if v == name))
            else:
                return _Result(err=f"uname: unrecognized option '{arg[:64]}'\n" + _UNAME_HELP,
                               status=1)
        elif arg.startswith("-") and len(arg) > 1:
            for ch in arg[1:]:
                if ch != "a" and ch not in _UNAME_FLAGS:
                    return _Result(err=f"uname: invalid option -- '{ch}'\n" + _UNAME_HELP,
                                   status=1)
                wanted.add(ch)
        else:
            return _Result(err=f"uname: extra operand '{arg[:64]}'\n" + _UNAME_HELP, status=1)
    platform = h.machine if h.platform_known else "unknown"
    values = {"s": "Linux", "n": h.hostname, "r": h.release, "v": h.version, "m": h.machine,
              "p": platform, "i": platform, "o": "GNU/Linux"}
    if "a" in wanted:
        wanted |= set("snrvmo") | (set("pi") if h.platform_known else set())
    if not wanted:
        wanted = {"s"}
    return _Result(" ".join(values[k] for k in "snrvmpio" if k in wanted) + "\n",
                   scope=SESSION if "n" in wanted else FIXED)   # the nodename can change


@_command("hostname", scope=SESSION)
def _hostname(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    h = sh.host
    if not args or args in (["-s"], ["--short"]):
        return _Result(h.hostname + "\n")
    if args in (["-f"], ["--fqdn"], ["--long"], ["-A"]):
        return _Result((f"{h.hostname}.{h.domain}" if h.domain else h.hostname)
                       + (" " if args == ["-A"] else "") + "\n")
    if args in (["-d"], ["--domain"]):
        return _Result(h.domain + "\n")
    if args in (["-i"], ["--ip-address"]):
        return _Result(h.internal_ips[0] + "\n")
    if args in (["-I"], ["--all-ip-addresses"]):
        return _Result(" ".join(h.internal_ips) + " \n")
    return None


@_command("whoami", scope=SESSION)
def _whoami(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return None if args else _Result(sh.user + "\n")


@_command("id", scope=SESSION)
def _id(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    names = [a for a in args if not a.startswith("-")]
    flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
    if len(names) > 1 or any(a.startswith("--") for a in args) or set(flags) - set("ugnG"):
        return None
    login = names[0] if names else sh.user
    known = {u.name: u for u in sh.host.all_users(sh.user)}
    if login not in known:
        return _Result(err=f"id: '{login[:64]}': no such user\n", status=1)
    u = known[login]
    gid = 0 if u.uid == 0 else u.uid
    if "u" in flags or "g" in flags or "G" in flags:
        value = (u.name if "n" in flags else str(u.uid)) if "u" in flags else \
            (u.name if "n" in flags else str(gid))
        return _Result(value + "\n")
    return _Result(f"uid={u.uid}({u.name}) gid={gid}({u.name}) groups={gid}({u.name})\n")


def _uptime_words(seconds: int) -> str:
    minutes = seconds // 60
    years, minutes = divmod(minutes, 525600)
    weeks, minutes = divmod(minutes, 10080)
    days, minutes = divmod(minutes, 1440)
    hours, minutes = divmod(minutes, 60)
    parts = [f"{n} {unit}{'s' if n != 1 else ''}" for n, unit in
             ((years, "year"), (weeks, "week"), (days, "day"), (hours, "hour"),
              (minutes, "minute")) if n]
    return "up " + (", ".join(parts) if parts else "0 minutes")


def _uptime_line(sh: Shell) -> str:
    h = sh.host
    up = h.uptime_seconds(sh.now)
    days, rest = divmod(up // 60, 1440)
    hours, minutes = divmod(rest, 60)
    span = f"{days} day{'s' if days != 1 else ''}, "
    span += f"{hours:2d}:{minutes:02d}" if hours else f"{minutes} min"
    l1, l5, l15 = h.loadavg(sh.now)
    clock = h.local(sh.now).strftime("%H:%M:%S")
    users = 1 + len(h.other_sessions(sh.now))
    return (f" {clock} up {span},  {users} user{'s' if users != 1 else ''},  load average: "
            f"{l1:.2f}, {l5:.2f}, {l15:.2f}\n")


@_command("uptime")
def _uptime(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if not args:
        return _Result(_uptime_line(sh))
    if args in (["-p"], ["--pretty"]):
        return _Result(_uptime_words(sh.host.uptime_seconds(sh.now)) + "\n")
    if args in (["-s"], ["--since"]):
        return _Result(sh.host.local(sh.host.boot_time(sh.now)).strftime("%Y-%m-%d %H:%M:%S")
                       + "\n")
    return None


def _idle(seconds: int) -> str:
    """``w``'s IDLE column, as procps prints it."""
    if seconds < 60:
        return f"{seconds}.00s"
    if seconds < 3600:
        return f"{seconds // 60}:{seconds % 60:02d}"
    if seconds < 86400:
        return f"{seconds // 3600}:{seconds % 3600 // 60:02d}m"
    return f"{seconds // 86400}days"


def _login_at(sh: Shell, ts: float) -> str:
    """``w``'s LOGIN@ column: the time today, else the weekday and hour."""
    when, today = sh.host.local(ts), sh.host.local(sh.now)
    return when.strftime("%H:%M") if when.date() == today.date() else when.strftime("%a%H")


def _sessions(sh: Shell) -> list[tuple[str, str, str, float, int, str]]:
    """(user, tty, from, login time, idle seconds, what) for every login, the attacker's
    last."""
    others = sh.host.other_sessions(sh.now)
    out = [(user, f"pts/{n}", src, login, idle, "-bash")
           for n, (user, src, login, idle) in enumerate(others)]
    out.append((sh.user, f"pts/{len(others)}", (sh.src_ip or "-")[:16], sh.now - 60, 0, ""))
    return out


@_command("w")
def _w(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if args:
        return None
    rows = []
    for user, tty, src, login, idle, what in _sessions(sh):
        cpu = ("0.02s", "0.00s") if not what else ("0.05s", "0.05s")
        rows.append(f"{user[:8]:<9}{tty:<9}{src:<17}{_login_at(sh, login):<8}"
                    f"{_idle(idle):>6}{cpu[0]:>7}{cpu[1]:>7} {what or 'w'}\n")
    return _Result(_uptime_line(sh)
                   + "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                   + "".join(rows))


@_command("who")
def _who(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if args:
        return None
    return _Result("".join(
        f"{user:<8} {tty:<12} {sh.host.local(login).strftime('%Y-%m-%d %H:%M')} ({src})\n"
        for user, tty, src, login, _, _ in _sessions(sh)))


@_command("nproc")
def _nproc(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return None if args not in ([], ["--all"]) else _Result(f"{sh.host.hardware.cpus}\n")


# ---- memory and disk ------------------------------------------------------------------------

@_command("free")
def _free(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    unit, total_line = "k", False
    for arg in args:
        if arg in ("-b", "--bytes", "-k", "--kibi", "-m", "--mebi", "-g", "--gibi", "-h",
                   "--human"):
            unit = arg.lstrip("-")[0]
        elif arg in ("-t", "--total"):
            total_line = True
        else:
            return None
    m = sh.host.memory()

    def fmt(kib: int) -> str:
        if unit == "h":
            return _human(kib, "i", ceil=False) if kib else "0B"
        return str({"b": kib * 1024, "k": kib, "m": kib // 1024, "g": kib // 1048576}[unit])

    rows = [("Mem:", [m["total"], m["used"], m["free"], m["shared"], m["cache"],
                      m["available"]]), ("Swap:", [0, 0, 0])]
    if total_line:
        rows.append(("Total:", [m["total"], m["used"], m["free"]]))
    out = ["               total        used        free      shared  buff/cache   available"]
    for label, values in rows:
        out.append(f"{label:<8}" + "".join(f"{fmt(v):>12}" for v in values))
    return _Result("\n".join(out) + "\n")


def _mounts(sh: Shell) -> list[tuple[str, str, int, int, int, str]]:
    """(device, fstype, 1K blocks, used, available, mount point) for df."""
    h = sh.host
    total = h.memory()["total"]
    blocks, used, avail = h.disk()
    device, fstype = h.root_device
    uid = h.user(sh.user).uid
    run = total // 10 // 4 * 4
    out = [("tmpfs", "tmpfs", run, 1064, run - 1064, "/run"),
           (device, fstype, blocks, used, avail, "/"),
           ("tmpfs", "tmpfs", total // 2, 0, total // 2, "/dev/shm")]
    if h.family != "rhel":
        out.append(("tmpfs", "tmpfs", 5120, 0, 5120, "/run/lock"))
    out.append(("tmpfs", "tmpfs", run, 4, run - 4, f"/run/user/{uid}"))
    return out


def _table(rows: list[list[str]], left: set[int], minimum: tuple = ()) -> str:
    widths = [max([len(r[i]) for r in rows] + [minimum[i] if i < len(minimum) else 0])
              for i in range(len(rows[0]))]
    out = []
    for r in rows:
        cells = [r[i].ljust(widths[i]) if i in left else r[i].rjust(widths[i])
                 for i in range(len(r))]
        out.append(" ".join(cells).rstrip())
    return "\n".join(out) + "\n"


@_command("df", scope=SESSION)   # a download or a mount changes it
def _df(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    human = False
    paths = []
    for arg in args:
        if arg in ("-h", "--human-readable"):
            human = True
        elif arg in ("-k",):
            human = False
        elif arg.startswith("-"):
            return None
        else:
            paths.append(posixpath.normpath(posixpath.join(sh.cwd, arg)))
    mounts = _mounts(sh)
    if paths:
        chosen = []
        for p in paths:
            best = max((m for m in mounts if p == m[5] or p.startswith(m[5].rstrip("/") + "/")),
                       key=lambda m: len(m[5]))
            chosen.append(best)
        mounts = chosen
    head = ["Filesystem", "Size" if human else "1K-blocks", "Used", "Avail" if human
            else "Available", "Use%", "Mounted on"]
    rows = [head]
    for device, _, blocks, used, avail, point in mounts:
        pct = "-" if not blocks else f"{math.ceil(used * 100 / (used + avail)) if used else 0}%"
        if human:
            rows.append([device, _human(blocks), _human(used) if used else "0",
                         _human(avail), pct, point])
        else:
            rows.append([device, str(blocks), str(used), str(avail), pct, point])
    return _Result(_table(rows, {0, 5}, (14, 5, 5, 5, 4)))


# ---- processes ------------------------------------------------------------------------------

def _processes(sh: Shell) -> list[tuple]:
    """(user, pid, ppid, %cpu, %mem, vsz, rss, tty, stat, start, time, command)."""
    h = sh.host
    r = h.rng("ps")
    boot = h.local(h.boot_time(sh.now))
    start_boot = boot.strftime("%b%d")
    ubuntu = h.family in ("ubuntu", "debian")
    names = [
        ("root", "/sbin/init" if ubuntu else
         "/usr/lib/systemd/systemd --switched-root --system --deserialize 31", "Ss"),
        ("root", "[kthreadd]", "S"), ("root", "[rcu_gp]", "I<"),
        ("root", "[kworker/0:1-events]", "I"),
        ("root", "[ksoftirqd/0]", "S"), ("root", "[kcompactd0]", "S"),
        ("root", "/lib/systemd/systemd-journald" if ubuntu else
         "/usr/lib/systemd/systemd-journald", "Ss"),
        ("root", "/lib/systemd/systemd-udevd" if ubuntu else
         "/usr/lib/systemd/systemd-udevd", "Ss"),
    ]
    if h.family == "ubuntu":
        names += [("systemd+", "/lib/systemd/systemd-networkd", "Ss"),
                  ("systemd+", "/lib/systemd/systemd-resolved", "Ss")]
    names += h.daemons()
    names += [
        ("root", "/usr/sbin/cron -f -P" if ubuntu else "/usr/sbin/crond -n", "Ss"),
        ("message+" if ubuntu else "dbus", "@dbus-daemon --system --address=systemd: --nofork "
         "--nopidfile --systemd-activation --syslog-only", "Ss"),
        ("syslog" if h.family == "ubuntu" else "root", "/usr/sbin/rsyslogd -n -iNONE", "Ssl"),
        ("root", "/sbin/agetty -o -p -- \\u --noclear - linux" if ubuntu else
         "/sbin/agetty -o -p -- \\u --noclear - linux", "Ss+"),
        ("root", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", "Ss"),
    ]
    if h.hardware.gpu:
        names.append(("root", "/usr/bin/nvidia-persistenced --user nvidia-persistenced", "Ss"))
    out, pid = [], 1
    total_kib = h.memory()["total"]
    for index, (user, cmd, stat) in enumerate(names):
        if index:
            pid = pid + 1 if cmd.startswith("[") else pid + r.randrange(40, 400)
        kernel = cmd.startswith("[")
        vsz = 0 if kernel else r.randrange(8000, 300000)
        rss = 0 if kernel else r.randrange(2000, min(40000, vsz))
        out.append((user, pid, 0 if pid == 1 else 1, 0.0, round(rss * 100 / total_kib, 1), vsz,
                    rss, "tty1" if "agetty" in cmd else "?", stat, start_boot,
                    f"0:{r.randrange(0, 40):02d}", cmd))
    listener = next(p[1] for p in out if p[11].startswith("sshd: /usr/sbin/sshd"))
    base = pid + 5000 + r.randrange(5000)
    for name, tty, _, since, _, _ in _sessions(sh):
        user = name[:8] if len(name) <= 8 else name[:7] + "+"
        start = h.local(since).strftime("%H:%M" if sh.now - since < 86400 else "%b%d")
        out += [("root", base, listener, 0.0, 0.2, 17000, 10900, "?", "Ss", start, "0:00",
                 f"sshd: {name} [priv]"),
                (user, base + 99, base, 0.0, 0.1, 9100, 5400, tty, "Ss", start, "0:00",
                 "-bash")]
        base += 200 + r.randrange(2000)
    return out


# Services some installs run and others do not; each sensor shows its own subset.
_DAEMONS = {
    "ubuntu": (("root", "/sbin/multipathd -d -s", "SLsl"),
               ("root", "/usr/sbin/irqbalance --foreground", "Ssl"),
               ("root", "/usr/libexec/polkitd --no-debug", "Ssl"),
               ("root", "/usr/lib/snapd/snapd", "Ssl"),
               ("root", "/usr/sbin/qemu-ga", "Ssl"),
               ("root", "/usr/bin/python3 /usr/share/unattended-upgrades/"
                        "unattended-upgrade-shutdown --wait-for-signal", "Ssl")),
    "debian": (("root", "/usr/sbin/qemu-ga", "Ssl"),
               ("root", "/usr/sbin/irqbalance --foreground", "Ssl"),
               ("root", "/usr/sbin/atd -f", "Ss")),
    "rhel": (("chrony", "/usr/sbin/chronyd -F 2", "S"),
             ("root", "/usr/sbin/irqbalance --foreground", "Ss"),
             ("root", "/usr/sbin/NetworkManager --no-daemon", "Ssl"),
             ("root", "/usr/bin/python3 -Es /usr/sbin/tuned -l -P", "Ssl"),
             ("root", "/usr/sbin/qemu-ga --method=virtio-serial --path=/dev/virtio-ports/"
                      "org.qemu.guest_agent.0", "Ssl")),
}


@_command("ps", scope=SESSION)
def _ps(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    procs = _processes(sh)
    mine = procs[-1]
    joined = "".join(args)
    if not args:
        return _Result(f"    PID TTY          TIME CMD\n{mine[1]:>7} {mine[7]:<8} 00:00:00 bash\n"
                       f"{mine[1] + 50:>7} {mine[7]:<8} 00:00:00 ps\n")
    rows = procs + [(mine[0], mine[1] + 50, mine[1], 0.0, 0.0, 11300, 4600, mine[7], "R+",
                     mine[9], "0:00", "ps " + " ".join(args))]
    if len(args) == 1 and joined.lstrip("-") in ("aux", "auxw", "auxww", "axu"):
        out = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
        for p in rows:
            out.append(f"{p[0]:<8} {p[1]:>7} {p[3]:>4.1f} {p[4]:>4.1f} {p[5]:>6} {p[6]:>5} "
                       f"{p[7]:<8} {p[8]:<4} {p[9]:>5} {p[10]:>6} {p[11]}")
        return _Result("\n".join(out) + "\n")
    if args in (["-ef"], ["-e", "-f"], ["-aef"]):
        out = ["UID          PID    PPID  C STIME TTY          TIME CMD"]
        for p in rows:
            minutes = int(p[10].split(":")[0]) * 60 + int(p[10].split(":")[1])
            out.append(f"{p[0]:<8} {p[1]:>7} {p[2]:>7} {0:>2} {p[9]:<5} {p[7]:<8} "
                       f"{'00:%02d:%02d' % divmod(minutes, 60):>8} {p[11]}")
        return _Result("\n".join(out) + "\n")
    return None


# ---- hardware -------------------------------------------------------------------------------

def _vendor(model: str) -> str:
    return "AuthenticAMD" if "amd" in model.lower() else "GenuineIntel"


def _mhz(model: str) -> float:
    match = re.search(r"@ ?([0-9]+(?:\.[0-9]+)?) ?GHz", model)
    return float(match.group(1)) * 1000 if match else 2400.0


_INTEL_FLAGS = ("fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 "
                "clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc "
                "rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 "
                "fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave "
                "avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase "
                "tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx avx512f avx512dq rdseed adx "
                "smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves "
                "ida arat pku ospke")
_AMD_FLAGS = ("fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush "
              "mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc "
              "rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf tsc_known_freq pni "
              "pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c "
              "rdrand hypervisor lahf_lm cmp_legacy cr8_legacy abm sse4a misalignsse "
              "3dnowprefetch topoext ssbd ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 "
              "rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 clzero xsaveerptr "
              "rdpru wbnoinvd arat npt nrip_save rdpid")


_INTEL_BUGS = "cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass swapgs mds"
_AMD_BUGS = "sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass"


def _topology(cpus: int) -> tuple[int, int]:
    """(threads per core, cores per socket); one socket."""
    threads = 2 if cpus > 1 and cpus % 2 == 0 else 1
    return threads, cpus // threads


def _cpuinfo(sh: Shell) -> str:
    hw = sh.host.hardware
    amd = _vendor(hw.cpu_model) == "AuthenticAMD"
    threads, cores = _topology(hw.cpus)
    mhz = _mhz(hw.cpu_model)
    blocks = []
    for n in range(hw.cpus):
        blocks.append(
            f"processor\t: {n}\nvendor_id\t: {_vendor(hw.cpu_model)}\n"
            f"cpu family\t: {25 if amd else 6}\nmodel\t\t: {1 if amd else 85}\n"
            f"model name\t: {hw.cpu_model}\nstepping\t: {1 if amd else 7}\n"
            f"microcode\t: {'0xa0011d1' if amd else '0x5003707'}\ncpu MHz\t\t: {mhz:.3f}\n"
            f"cache size\t: {512 if amd else 36608} KB\nphysical id\t: 0\n"
            f"siblings\t: {hw.cpus}\ncore id\t\t: {n // threads}\ncpu cores\t: {cores}\n"
            f"apicid\t\t: {n}\ninitial apicid\t: {n}\nfpu\t\t: yes\nfpu_exception\t: yes\n"
            f"cpuid level\t: {16 if amd else 13}\nwp\t\t: yes\n"
            f"flags\t\t: {_AMD_FLAGS if amd else _INTEL_FLAGS}\n"
            f"bugs\t\t: {_AMD_BUGS if amd else _INTEL_BUGS}\n"
            f"bogomips\t: {mhz * 2:.2f}\nclflush size\t: 64\ncache_alignment\t: 64\n"
            f"address sizes\t: {'48 bits physical, 48' if amd else '46 bits physical, 48'} "
            f"bits virtual\npower management:\n\n")
    return "".join(blocks)


@_command("lscpu")
def _lscpu(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if args:
        return None
    hw = sh.host.hardware
    threads, cores = _topology(hw.cpus)
    online = "0" if hw.cpus == 1 else "0,1" if hw.cpus == 2 else f"0-{hw.cpus - 1}"
    amd = _vendor(hw.cpu_model) == "AuthenticAMD"
    rows = [("Architecture", sh.host.machine), ("CPU op-mode(s)", "32-bit, 64-bit"),
            ("Address sizes", "48 bits physical, 48 bits virtual" if amd
             else "46 bits physical, 48 bits virtual"),
            ("Byte Order", "Little Endian"), ("CPU(s)", str(hw.cpus)),
            ("On-line CPU(s) list", online), ("Vendor ID", _vendor(hw.cpu_model)),
            ("Model name", hw.cpu_model), ("CPU family", "25" if amd else "6"),
            ("Model", "1" if amd else "85"), ("Thread(s) per core", str(threads)),
            ("Core(s) per socket", str(cores)), ("Socket(s)", "1"),
            ("Stepping", "1" if amd else "7"), ("BogoMIPS", f"{_mhz(hw.cpu_model) * 2:.2f}"),
            ("Hypervisor vendor", "KVM"), ("Virtualization type", "full"),
            ("L1d cache", f"{32 * cores} KiB ({cores} instance{'s' if cores > 1 else ''})"),
            ("NUMA node(s)", "1"), ("NUMA node0 CPU(s)", online)]
    return _Result("".join(f"{k + ':':<33}{v}\n" for k, v in rows))


def _pci(sh: Shell) -> list[str]:
    out = ["00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)",
           "00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]",
           "00:01.1 IDE interface: Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]",
           "00:01.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 03)",
           "00:02.0 VGA compatible controller: Cirrus Logic GD 5446",
           "00:03.0 Ethernet controller: Red Hat, Inc. Virtio network device",
           "00:04.0 SCSI storage controller: Red Hat, Inc. Virtio block device",
           "00:05.0 Unclassified device [00ff]: Red Hat, Inc. Virtio memory balloon"]
    hw = sh.host.hardware
    if hw.gpu:
        spec = GPU_SPECS[hw.gpu]
        for n in range(hw.gpu_count):
            out.append(f"00:{6 + n:02x}.0 {spec.pci_class}: {spec.pci_name}")
    return out


@_command("lspci")
def _lspci(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return None if args else _Result("\n".join(_pci(sh)) + "\n")


_DRIVER, _CUDA = "550.120", "12.4"


def _gpu_bus(n: int) -> str:
    return f"00000000:00:{6 + n:02X}.0"


def _gpu_uuid(sh: Shell, n: int) -> str:
    if ("gpu-uuid", n) in sh.memo:
        return sh.memo[("gpu-uuid", n)]
    sh.charge(STEP * 100)
    raw = sh.host.rng("gpu-uuid", n).getrandbits(128)
    h = f"{raw:032x}"
    sh.memo[("gpu-uuid", n)] = f"GPU-{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
    return sh.memo[("gpu-uuid", n)]


def _smi_table(sh: Shell) -> str:
    hw = sh.host.hardware
    spec = GPU_SPECS[hw.gpu]
    stamp = sh.host.local(sh.now).strftime("%a %b %d %H:%M:%S %Y")
    bar = "+-----------------------------------------+------------------------+----------------------+"
    lines = [
        f"{stamp}       ",
        "+-----------------------------------------------------------------------------------------+",
        f"| NVIDIA-SMI {_DRIVER:<22} Driver Version: {_DRIVER:<14} CUDA Version: {_CUDA:<9}|",
        "|-----------------------------------------+------------------------+----------------------+",
        "| GPU  Name                 Persistence-M | Bus-Id          Disp.A | Volatile Uncorr. ECC |",
        "| Fan  Temp   Perf          Pwr:Usage/Cap |           Memory-Usage | GPU-Util  Compute M. |",
        "|                                         |                        |               MIG M. |",
        "|=========================================+========================+======================|",
    ]
    r = sh.host.rng("gpu-temp", int(sh.now // 300))
    for n in range(hw.gpu_count):
        fan = "N/A" if spec.brand != "GeForce" else "0%"
        ecc = "0" if spec.brand != "GeForce" else "N/A"
        mig = "Disabled" if hw.gpu in ("a100", "h100") else "N/A"
        name = spec.product if len(spec.product) <= 26 else spec.product[:23] + "..."
        usage = f"{r.randrange(9, 30)}W / {spec.power_cap_w:>4}W"
        memory = f"1MiB / {spec.memory_mib:>6}MiB"
        persist = "On" if spec.brand != "GeForce" else "Off"
        left = f" {fan:>3}  {str(r.randrange(28, 41)) + 'C':>4}    P8"
        lines += [
            f"| {n:>3}  {name:<26}{persist:>8} | {_gpu_bus(n):>18} Off | {ecc:>20} |",
            f"|{left}{usage:>{40 - len(left)}} | {memory:>22} | {'0%':>8} {'Default':>11} |",
            f"|{'':41}|{'':24}| {mig:>20} |",
            bar,
        ]
    lines += [
        " " * 89,
        "+-----------------------------------------------------------------------------------------+",
        "| Processes:                                                                              |",
        "|  GPU   GI   CI        PID   Type   Process name                              GPU Memory |",
        "|        ID   ID                                                               Usage      |",
        "|=========================================================================================|",
        "|  No running processes found                                                             |",
        "+-----------------------------------------------------------------------------------------+",
    ]
    return "\n".join(lines) + "\n"


def _smi_query(sh: Shell) -> str:
    hw = sh.host.hardware
    spec = GPU_SPECS[hw.gpu]
    stamp = sh.host.local(sh.now).strftime("%a %b %d %H:%M:%S %Y")

    def row(key: str, value, indent: int = 4) -> str:
        return f"{' ' * indent}{key:<{42 - indent}}: {value}\n"

    out = ["\n==============NVSMI LOG==============\n\n", row("Timestamp", stamp, 0),
           row("Driver Version", _DRIVER, 0), row("CUDA Version", _CUDA, 0), "\n",
           row("Attached GPUs", hw.gpu_count, 0)]
    reserved = 310 if spec.memory_mib < 30000 else 520
    for n in range(hw.gpu_count):
        out += [f"GPU {_gpu_bus(n)}\n", row("Product Name", spec.product),
                row("Product Brand", spec.brand), row("Product Architecture", spec.architecture),
                row("Display Mode", "Disabled"), row("Display Active", "Disabled"),
                row("Persistence Mode", "Enabled" if spec.brand != "GeForce" else "Disabled"),
                row("Minor Number", n), row("GPU UUID", _gpu_uuid(sh, n)),
                row("VBIOS Version", "94.02.42.00.A9" if spec.brand == "GeForce"
                    else "92.00.36.00.01"),
                "    PCI\n", row("Bus", f"0x{6 + n:02X}", 8), row("Device", "0x00", 8),
                row("Bus Id", _gpu_bus(n), 8),
                "    FB Memory Usage\n", row("Total", f"{spec.memory_mib} MiB", 8),
                row("Reserved", f"{reserved} MiB", 8), row("Used", "1 MiB", 8),
                row("Free", f"{spec.memory_mib - reserved - 1} MiB", 8),
                row("Compute Mode", "Default"),
                "    Utilization\n", row("Gpu", "0 %", 8), row("Memory", "0 %", 8),
                "    Temperature\n", row("GPU Current Temp", "33 C", 8),
                "    GPU Power Readings\n", row("Power Draw", "19.42 W", 8),
                row("Current Power Limit", f"{spec.power_cap_w:.2f} W", 8),
                row("Processes", "None"), "\n"]
    return "".join(out)


_SMI_FIELDS = {
    "name": ("name", lambda sh, n, spec, units: spec.product),
    "memory.total": ("memory.total [MiB]",
                     lambda sh, n, spec, units: f"{spec.memory_mib}{' MiB' if units else ''}"),
    "memory.used": ("memory.used [MiB]", lambda sh, n, spec, units: f"1{' MiB' if units else ''}"),
    "memory.free": ("memory.free [MiB]", lambda sh, n, spec, units:
                    f"{spec.memory_mib - 311}{' MiB' if units else ''}"),
    "driver_version": ("driver_version", lambda sh, n, spec, units: _DRIVER),
    "count": ("count", lambda sh, n, spec, units: str(sh.host.hardware.gpu_count)),
    "index": ("index", lambda sh, n, spec, units: str(n)),
    "uuid": ("uuid", lambda sh, n, spec, units: _gpu_uuid(sh, n)),
    "pci.bus_id": ("pci.bus_id", lambda sh, n, spec, units: _gpu_bus(n)),
    "temperature.gpu": ("temperature.gpu", lambda sh, n, spec, units: "33"),
    "utilization.gpu": ("utilization.gpu [%]", lambda sh, n, spec, units:
                        f"0{' %' if units else ''}"),
    "power.limit": ("power.limit [W]", lambda sh, n, spec, units:
                    f"{spec.power_cap_w:.2f}{' W' if units else ''}"),
}


@_command("nvidia-smi")
def _nvidia_smi(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    hw = sh.host.hardware
    spec = GPU_SPECS[hw.gpu]
    if not args:
        return _Result(_smi_table(sh))
    if args in (["-q"], ["--query"]):
        return _Result(_smi_query(sh))
    if args in (["-L"], ["--list-gpus"]):
        return _Result("".join(f"GPU {n}: {spec.product} (UUID: {_gpu_uuid(sh, n)})\n"
                               for n in range(hw.gpu_count)))
    query = [a.split("=", 1)[1] for a in args if a.startswith("--query-gpu=")]
    fmt = [a.split("=", 1)[1] for a in args if a.startswith("--format=")]
    if len(query) != 1 or len(fmt) != 1 or len(args) != 2:
        return None
    fields = [f.strip() for f in query[0].split(",")]
    options = set(fmt[0].split(","))
    if "csv" not in options or options - {"csv", "noheader", "nounits"} or \
            any(f not in _SMI_FIELDS for f in fields):
        return None
    units = "nounits" not in options
    lines = [] if "noheader" in options else \
        [", ".join(_SMI_FIELDS[f][0] if units else _SMI_FIELDS[f][0].split(" [")[0]
                   for f in fields)]
    for n in range(hw.gpu_count):
        sh.charge(STEP * 4 * len(fields))
        lines.append(", ".join(_SMI_FIELDS[f][1](sh, n, spec, units) for f in fields))
    return _Result("\n".join(lines) + "\n")


# ---- files ------------------------------------------------------------------------------------

_UBUNTU_CODENAMES = {"20.04": ("focal", "Focal Fossa"), "22.04": ("jammy", "Jammy Jellyfish"),
                     "24.04": ("noble", "Noble Numbat")}


def _os_release(sh: Shell) -> str:
    h = sh.host
    pretty = h.os_pretty_name
    words = pretty.split()
    if h.family == "ubuntu" and len(words) > 1:
        version = words[1]
        vid = ".".join(version.split(".")[:2])
        code, long_name = _UBUNTU_CODENAMES.get(vid, ("", ""))
        lts = " LTS" if "LTS" in words else ""
        return (f'PRETTY_NAME="{pretty}"\nNAME="Ubuntu"\nVERSION_ID="{vid}"\n'
                f'VERSION="{version}{lts}{f" ({long_name})" if long_name else ""}"\n'
                f"VERSION_CODENAME={code}\nID=ubuntu\nID_LIKE=debian\n"
                'HOME_URL="https://www.ubuntu.com/"\nSUPPORT_URL="https://help.ubuntu.com/"\n'
                'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
                'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/'
                'privacy-policy"\n'
                f"UBUNTU_CODENAME={code}\nLOGO=ubuntu-logo\n")
    match = re.match(r"^(.*?) ([0-9][0-9.]*)(?: \((.*)\))?$", pretty)
    if h.family == "debian" and match:
        name, vid, code = match.group(1), match.group(2), match.group(3) or ""
        return (f'PRETTY_NAME="{pretty}"\nNAME="{name}"\nVERSION_ID="{vid}"\n'
                f'VERSION="{vid}{f" ({code})" if code else ""}"\nVERSION_CODENAME={code}\n'
                'ID=debian\nHOME_URL="https://www.debian.org/"\n'
                'SUPPORT_URL="https://www.debian.org/support"\n'
                'BUG_REPORT_URL="https://bugs.debian.org/"\n')
    if h.family == "rhel" and match:
        name, vid, code = match.group(1), match.group(2), match.group(3) or ""
        ident = {"red hat enterprise linux": "rhel", "rocky linux": "rocky",
                 "almalinux": "almalinux", "centos stream": "centos",
                 "oracle linux server": "ol"}.get(name.lower(), name.split()[0].lower())
        major = vid.split(".")[0]
        like = "fedora" if ident == "rhel" else "rhel centos fedora"
        return (f'NAME="{name}"\nVERSION="{vid}{f" ({code})" if code else ""}"\n'
                f'ID="{ident}"\nID_LIKE="{like}"\nVERSION_ID="{vid}"\n'
                f'PLATFORM_ID="platform:el{major}"\nPRETTY_NAME="{pretty}"\n'
                'ANSI_COLOR="0;32"\nLOGO="fedora-logo-icon"\n')
    first = words[0] if words else "Linux"
    return f'PRETTY_NAME="{pretty}"\nNAME="{first}"\nID={first.lower()}\n'


def _issue(sh: Shell) -> str:
    h = sh.host
    if h.family == "rhel":
        return "\\S\nKernel \\r on an \\m\n\n"
    if h.family == "debian":
        return re.sub(r" \(.*\)$", "", h.os_pretty_name) + " \\n \\l\n\n"
    return f"{h.os_pretty_name} \\n \\l\n\n"


def _proc_version(sh: Shell) -> str:
    h = sh.host
    if h.family == "ubuntu":
        vid = h.os_pretty_name.split()[1][:5] if len(h.os_pretty_name.split()) > 1 else ""
        tool = {"24.04": "x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0, GNU ld "
                         "(GNU Binutils for Ubuntu) 2.42",
                "20.04": "gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0, GNU ld (GNU Binutils for "
                         "Ubuntu) 2.34"}.get(
            vid, "x86_64-linux-gnu-gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0, GNU ld (GNU "
                 "Binutils for Ubuntu) 2.38")
        builder = "buildd@lcy02-amd64-086"
    elif h.family == "debian":
        tool = "gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40"
        builder = "debian-kernel@build-amd64-02"
    elif h.family == "rhel":
        tool = "gcc (GCC) 11.4.1 20231218 (Red Hat 11.4.1-3), GNU ld version 2.35.2-43.el9"
        builder = "mockbuild@x86-64-01"
    else:
        tool, builder = "gcc (GCC) 12.2.0, GNU ld 2.40", "builder@localhost"
    return f"Linux version {h.release} ({builder}) ({tool}) {h.version}\n"


def _passwd(sh: Shell) -> str:
    return "".join(f"{u.name}:x:{u.uid}:{u.uid}:{u.gecos}:{u.home}:{u.shell}\n"
                   for u in sh.host.all_users(sh.user))


def _meminfo(sh: Shell) -> str:
    m = sh.host.memory()
    rows = [("MemTotal", m["total"]), ("MemFree", m["free"]), ("MemAvailable", m["available"]),
            ("Buffers", m["buffers"]), ("Cached", m["cached"]), ("SwapCached", 0),
            ("Active", _pages(m["used"] * 0.6 + m["cache"] * 0.3)),
            ("Inactive", _pages(m["used"] * 0.3 + m["cache"] * 0.6)),
            ("SwapTotal", 0), ("SwapFree", 0), ("Dirty", 120), ("Writeback", 0),
            ("AnonPages", _pages(m["used"] * 0.7)), ("Mapped", _pages(m["cache"] * 0.2)),
            ("Shmem", m["shared"]), ("KReclaimable", m["sreclaimable"]),
            ("Slab", _pages(m["sreclaimable"] * 1.6)), ("SReclaimable", m["sreclaimable"]),
            ("SUnreclaim", _pages(m["sreclaimable"] * 0.6)),
            ("KernelStack", 16 * (160 + 8 * sh.host.hardware.cpus)),   # 16 kB stacks
            ("PageTables", 4100), ("CommitLimit", _pages(m["total"] / 2)),
            ("Committed_AS", _pages(m["used"] * 2.1)), ("VmallocTotal", 34359738367),
            ("HugePages_Total", None), ("Hugepagesize", 2048)]
    out = []
    for key, value in rows:
        if value is None:
            out.append(f"{key + ':':<16}{0:>8}\n")
        else:
            out.append(f"{key + ':':<16}{value:>8} kB\n")
    return "".join(out)


def _proc_mounts(sh: Shell) -> str:
    h = sh.host
    device, fstype = h.root_device
    total = h.memory()["total"]
    opts = "rw,relatime,discard,errors=remount-ro" if fstype == "ext4" else \
        "rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota"
    return (f"sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
            f"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
            f"udev /dev devtmpfs rw,nosuid,relatime,size={total // 2}k,mode=755,inode64 0 0\n"
            f"devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0\n"
            f"tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size={total // 10}k,mode=755,"
            f"inode64 0 0\n"
            f"{device} / {fstype} {opts} 0 0\n"
            f"tmpfs /dev/shm tmpfs rw,nosuid,nodev,inode64 0 0\n")


def _proc_uptime(sh: Shell) -> str:
    up = sh.host.uptime_seconds(sh.now)
    idle = up * sh.host.hardware.cpus * 0.97
    return f"{up}.{int(sh.now * 100) % 100:02d} {idle:.2f}\n"


def _loadavg(sh: Shell) -> str:
    l1, l5, l15 = sh.host.loadavg(sh.now)
    tasks = 180 + sh.host.hardware.cpus * 8
    last_pid = 40000 + sh.host.rng("lp").randrange(1000, 9999)
    return f"{l1:.2f} {l5:.2f} {l15:.2f} 1/{tasks} {last_pid}\n"


_FILES: dict[str, Callable[[Shell], Optional[str]]] = {
    "/proc/cpuinfo": _cpuinfo,
    "/proc/meminfo": _meminfo,
    "/proc/version": _proc_version,
    "/proc/uptime": _proc_uptime,
    "/proc/loadavg": _loadavg,
    "/proc/mounts": _proc_mounts,
    "/etc/mtab": _proc_mounts,
    "/etc/os-release": _os_release,
    "/usr/lib/os-release": _os_release,
    "/etc/issue": _issue,
    "/etc/hostname": lambda sh: sh.host.hostname + "\n",
    "/proc/sys/kernel/hostname": lambda sh: sh.host.hostname + "\n",
    "/etc/passwd": _passwd,
    "/etc/shells": lambda sh: "# /etc/shells: valid login shells\n/bin/sh\n/bin/bash\n"
                              "/usr/bin/sh\n/usr/bin/bash\n",
    "/etc/debian_version": lambda sh: None if sh.host.family not in ("debian", "ubuntu") else (
        "12.7\n" if sh.host.family == "debian" else "bookworm/sid\n"),
    "/etc/timezone": lambda sh: None if sh.host.family not in ("debian", "ubuntu") else
    sh.host.timezone + "\n",
}
# Files no command can change (kernel and hardware views). Every other file, including the
# release files under /etc and the mount table, is ``SESSION``: root can write or mount.
_FIXED_FILES = frozenset(("/proc/cpuinfo", "/proc/meminfo", "/proc/version", "/proc/uptime",
                          "/proc/loadavg"))
_ABSENT = {"ubuntu": ("/etc/redhat-release", "/etc/centos-release"),
           "debian": ("/etc/redhat-release", "/etc/centos-release", "/etc/lsb-release"),
           "rhel": ("/etc/debian_version", "/etc/lsb-release", "/etc/timezone")}


def _redhat_release(sh: Shell) -> Optional[str]:
    match = re.match(r"^(.*?) ([0-9][0-9.]*)(?: \((.*)\))?$", sh.host.os_pretty_name)
    if sh.host.family != "rhel" or not match:
        return None
    code = f" ({match.group(3)})" if match.group(3) else ""
    return f"{match.group(1)} release {match.group(2)}{code}\n"


_FILES["/etc/redhat-release"] = _redhat_release


def _lsb_release(sh: Shell) -> Optional[str]:
    if sh.host.family != "ubuntu":
        return None
    words = sh.host.os_pretty_name.split()
    vid = ".".join(words[1].split(".")[:2]) if len(words) > 1 else ""
    code = _UBUNTU_CODENAMES.get(vid, ("", ""))[0]
    return (f"DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE={vid}\nDISTRIB_CODENAME={code}\n"
            f'DISTRIB_DESCRIPTION="{sh.host.os_pretty_name}"\n')


_FILES["/etc/lsb-release"] = _lsb_release


def _files(sh: Shell, args: list[str], command: str) -> Optional[tuple]:
    """Read file operands: ([(name, text)], errors, status, scope); None if unknown."""
    if len(args) > MAX_FILES:
        return None
    out, errors, status, scope = [], "", 0, FIXED
    for name in args:
        result = sh.read_file(name)
        if result is None:
            return None
        sh.charge(len(result.out) + STEP)
        scope = max(scope, result.scope)
        if result.err:
            errors += _missing(sh, command, _shown(name))
            status = result.status
            continue
        out.append((name, result.out))
    return out, errors, status, scope


@_command("cat")
def _cat(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if any(a.startswith("-") and a != "-" for a in args):
        return None
    if not args or args == ["-"]:
        return None if stdin is None else _Result(stdin)
    read = _files(sh, args, "cat")
    if read is None:
        return None
    files, errors, status, scope = read
    for _, text in files:
        sh.grow(len(text))
    return _Result("".join(text for _, text in files), errors, status, scope)


# ---- filters ----------------------------------------------------------------------------------

def _input(sh: Shell, files: list[str], stdin: Optional[str], command: str):
    """(texts with names, errors, status, scope) from file operands or stdin."""
    if not files:
        if stdin is None:
            return None                      # would wait on the terminal
        sh.charge(len(stdin))
        return [("", stdin)], "", 0, FIXED
    return _files(sh, files, command)


class _Pattern:
    """A grep pattern: a fixed string, or (basic and extended syntax) one where ``.`` is any
    character and ``^`` / ``$`` anchor. Anything else is unsupported. Matched by hand: the
    literal runs between dots are compared with ``startswith`` at each start position, and
    every comparison is charged to the line's work budget."""

    def __init__(self, sh: Shell, text: str, fixed: bool, extended: bool, fold: bool) -> None:
        if len(text) > MAX_PATTERN:
            raise _Unsupported
        self.sh = sh
        self.fold = fold
        self.start = self.end = False
        if not fixed:
            if text.startswith("^"):
                self.start, text = True, text[1:]
            if text.endswith("$"):
                self.end, text = True, text[:-1]
            special = "[]*\\" + ("+?(){}|^$" if extended else "^$")
            if any(c in special for c in text):
                raise _Unsupported
        text = text.lower() if fold else text
        self.length = len(text)
        self.literal = text if fixed or "." not in text else None
        # (offset, run) for each literal run between dots, longest first: it fails soonest
        runs, offset = [], 0
        for run in ([text] if self.literal is not None else text.split(".")):
            if run:
                runs.append((offset, run))
            offset += len(run) + 1
        self.runs = sorted(runs, key=lambda r: -len(r[1]))

    def search(self, line: str) -> bool:
        line = line.lower() if self.fold else line
        n, m = len(line), self.length
        if self.literal is not None and not (self.start or self.end):
            return self.literal in line
        if self.start and self.end:
            starts = range(0, 1 if n == m else 0)
        elif self.start:
            starts = range(0, 1 if n >= m else 0)
        elif self.end:
            starts = range(n - m, n - m + 1) if n >= m else range(0)
        else:
            starts = range(0, max(n - m + 1, 0))
        self.sh.charge(len(starts) * STEP)
        for pos in starts:
            for offset, run in self.runs:
                self.sh.charge(STEP + len(run))
                if not line.startswith(run, pos + offset):
                    break
            else:
                return True
        return False


@_command("grep", "egrep", "fgrep")
def _grep(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    flags, patterns, operands, i = set(), [], [], 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            operands += args[i + 1:]
            break
        long = {"--count": "c", "--ignore-case": "i", "--invert-match": "v",
                "--fixed-strings": "F", "--extended-regexp": "E", "--quiet": "q",
                "--silent": "q", "--no-filename": "h", "--line-number": "n",
                "--no-messages": "s"}
        if arg in long:
            flags.add(long[arg])
        elif arg.startswith("-e") and arg != "-":
            if len(arg) > 2:
                patterns.append(arg[2:])
            elif i + 1 < len(args):
                patterns.append(args[i + 1])
                i += 1
            else:
                return None
        elif arg.startswith("-") and len(arg) > 1:
            if set(arg[1:]) - set("civFEqhns"):
                return None
            flags |= set(arg[1:])
        else:
            operands.append(arg)
        i += 1
    if not patterns:
        if not operands:
            return None
        patterns, operands = [operands[0]], operands[1:]
    if len(patterns) != 1:
        return None
    pattern = _Pattern(sh, patterns[0], "F" in flags or sh.argv0 == "fgrep",
                       "E" in flags or sh.argv0 == "egrep", "i" in flags)
    read = _input(sh, operands, stdin, "grep")
    if read is None:
        return None
    texts, errors, status, scope = read
    out, total = [], 0
    many = len(texts) > 1 and "h" not in flags
    for name, text in texts:
        count = 0
        for number, line in enumerate(_lines(text), 1):
            sh.charge(LINE + len(line))
            if pattern.search(line.rstrip("\n")) != ("v" in flags):
                count += 1
                if "c" not in flags and "q" not in flags:
                    prefix = (f"{name}:" if many else "") + (f"{number}:" if "n" in flags else "")
                    out.append(prefix + (line if line.endswith("\n") else line + "\n"))
                    sh.grow(len(out[-1]))
        total += count
        if "c" in flags and "q" not in flags:
            out.append((f"{name}:" if many else "") + f"{count}\n")
    if "s" in flags:
        errors = ""
    return _Result("".join(out), errors, 2 if status else (0 if total else 1), scope)


def _line_count(args: list[str]) -> Optional[tuple[str, list[str]]]:
    """(count spec, file operands) for head/tail; the spec keeps a leading + or -."""
    spec, files, i = "10", [], 0
    while i < len(args):
        arg = args[i]
        if arg in ("-n", "--lines") and i + 1 < len(args):
            spec, i = args[i + 1], i + 2
            continue
        if arg.startswith("--lines="):
            spec = arg.split("=", 1)[1]
        elif arg.startswith("-n"):
            spec = arg[2:]
        elif arg in ("-q", "--quiet", "--silent"):
            pass
        elif 1 < len(arg) <= 41 and arg[0] == "-" and arg[1:].isascii() and arg[1:].isdigit():
            spec = arg[1:]
        elif arg.startswith("-") and arg != "-":
            return None
        else:
            files.append(arg)
        i += 1
    digits = spec[1:] if spec[:1] in ("+", "-") else spec
    if not (0 < len(digits) <= 40 and digits.isascii() and digits.isdigit()):
        return None
    return spec, files


def _head_tail(sh: Shell, args: list[str], stdin, tail: bool) -> Optional[_Result]:
    parsed = _line_count(args)
    if parsed is None:
        return None
    spec, files = parsed
    read = _input(sh, files, stdin, "tail" if tail else "head")
    if read is None:
        return None
    texts, errors, status, scope = read
    n = int(spec.lstrip("+-"))
    out = []
    for index, (name, text) in enumerate(texts):
        lines = _lines(text)
        sh.charge(len(lines) * STEP)
        if tail:
            chosen = lines[max(n - 1, 0):] if spec.startswith("+") else \
                (lines[-n:] if n else [])
        else:
            chosen = (lines[:-n] if n else lines) if spec.startswith("-") else lines[:n]
        if len(texts) > 1:
            out.append(("\n" if index else "") + f"==> {name} <==\n")
        out.append("".join(chosen))
    return _Result("".join(out), errors, status, scope)


@_command("head")
def _head(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return _head_tail(sh, args, stdin, tail=False)


@_command("tail")
def _tail(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return _head_tail(sh, args, stdin, tail=True)


def _ranges(spec: str) -> Optional[list[tuple[int, int]]]:
    """A cut list (``5-``, ``-3``, ``1,4-6``) as sorted, merged, inclusive ranges; numbers are
    clamped, so an absurd field number just selects nothing. None when malformed; [] for a
    zero."""
    out = []
    parts = spec.split(",")
    if len(parts) > 64:
        return None
    for part in parts:
        lo_text, dash, hi_text = part.partition("-")
        for text in (lo_text, hi_text):
            if text and not (len(text) <= 40 and text.isascii() and text.isdigit()):
                return None
        if not (lo_text or hi_text):
            return None
        lo = min(int(lo_text or 1), 10**9)
        hi = (min(int(hi_text), 10**9) if hi_text else 10**9) if dash else lo
        if lo == 0 or (hi_text and int(hi_text) == 0):
            return []
        if hi < lo:
            return None
        out.append((lo, hi))
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(out):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


_CUT_HELP = "Try 'cut --help' for more information.\n"


@_command("cut")
def _cut(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    delim, mode, spec, only, files, i = None, None, None, False, [], 0
    while i < len(args):
        arg = args[i]
        if arg in ("-d", "-f", "-c", "-b") and i + 1 < len(args):
            value = args[i + 1]
            i += 2
        elif arg[:2] in ("-d", "-f", "-c", "-b") and len(arg) > 2:
            value = arg[2:]
            i += 1
        elif arg.startswith(("--delimiter=", "--fields=", "--characters=", "--bytes=")):
            key, value = arg[2:].split("=", 1)
            arg = {"delimiter": "-d", "fields": "-f", "characters": "-c", "bytes": "-b"}[key]
            i += 1
        elif arg in ("-s", "--only-delimited"):
            only = True
            i += 1
            continue
        elif arg.startswith("-") and arg != "-":
            return None
        else:
            files.append(arg)
            i += 1
            continue
        if arg[:2] == "-d":
            delim = value
        else:
            if mode is not None:
                return _Result(err="cut: only one list may be specified\n" + _CUT_HELP, status=1)
            mode, spec = ("f" if arg[:2] == "-f" else "c"), value
    if mode is None:
        return _Result(err="cut: you must specify a list of bytes, characters, or fields\n"
                       + _CUT_HELP, status=1)
    if delim is not None and len(delim) != 1:
        return _Result(err="cut: the delimiter must be a single character\n" + _CUT_HELP,
                       status=1)
    ranges = _ranges(spec)
    if ranges is None:
        return _Result(err=f"cut: invalid field range\n{_CUT_HELP}", status=1)
    if not ranges:
        return _Result(err=f"cut: {'fields' if mode == 'f' else 'byte/character positions'} "
                           f"are numbered from 1\n{_CUT_HELP}", status=1)
    read = _input(sh, files, stdin, "cut")
    if read is None:
        return None
    texts, errors, status, scope = read
    delim = "\t" if delim is None else delim

    def pick(seq):
        """The selected items of a sequence: one slice per merged range."""
        sh.charge(STEP * len(ranges))
        picked = []
        for lo, hi in ranges:
            if lo > len(seq):
                break
            picked += seq[lo - 1:hi]
        return picked

    out = []
    for _, text in texts:
        for line in _lines(text):
            sh.charge(LINE + len(line))
            body = line.rstrip("\n")
            if mode == "c":
                out.append("".join(pick(body)) + "\n")
            elif delim not in body:
                if only:
                    continue
                out.append(body + "\n")
            else:
                out.append(delim.join(pick(body.split(delim))) + "\n")
            sh.grow(len(out[-1]))
    return _Result("".join(out), errors, status, scope)


@_command("wc")
def _wc(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    wanted, files = [], []
    names = {"--lines": "l", "--words": "w", "--bytes": "c", "--chars": "m"}
    for arg in args:
        if arg in names:
            wanted.append(names[arg])
        elif arg.startswith("-") and arg != "-":
            if set(arg[1:]) - set("lwcm"):
                return None
            wanted += list(arg[1:])
        else:
            files.append(arg)
    order = [k for k in "lwmc" if k in wanted] or ["l", "w", "c"]
    read = _input(sh, files, stdin, "wc")
    if read is None:
        return None
    texts, errors, status, scope = read

    def counts(text: str) -> dict[str, int]:
        sh.charge(4 * len(text))
        return {"l": text.count("\n"), "w": len(text.split()), "m": len(text),
                "c": len(wire(text))}

    rows = [(name, counts(text)) for name, text in texts]
    if not rows:                                    # every operand was unreadable
        return _Result("", errors, status, scope)
    if len(rows) > 1:
        rows.append(("total", {k: sum(r[1][k] for r in rows) for k in "lwmc"}))
    if not files and len(order) == 1:
        return _Result(f"{rows[0][1][order[0]]}\n", errors, status, scope)
    width = 7 if not files else max(len(str(r[1][k])) for r in rows for k in order)
    out = []
    for name, c in rows:
        cells = " ".join(f"{c[k]:>{width}}" for k in order)
        out.append(cells + (f" {name}" if name else "") + "\n")
    return _Result("".join(out), errors, status, scope)


def _awk_program(program: str) -> Optional[list]:
    """The items of ``{print a, b c}``: ('field', n | 'NF'), ('text', s) or ('sep',).
    None for any other program. Parsed by hand in one pass (no regular expression: this is
    attacker text)."""
    body = program.strip(" \t\n")
    if not (body.startswith("{") and body.endswith("}")) or len(body) < 2:
        return None
    body = body[1:-1].strip(" \t\n")
    if body.endswith(";"):
        body = body[:-1].rstrip(" \t\n")
    if not body.startswith("print") or (len(body) > 5 and body[5] not in " \t\n"):
        return None
    body = body[5:]
    items: list = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c in " \t\n":
            i += 1
        elif c == ",":
            items.append(("sep",))
            i += 1
        elif c == "$":
            if body.startswith("NF", i + 1):
                items.append(("field", "NF"))
                i += 3
                continue
            j = i + 1
            while j < n and j - i <= 9 and "0" <= body[j] <= "9":
                j += 1
            if j == i + 1 or (j < n and "0" <= body[j] <= "9"):
                return None
            items.append(("field", int(body[i + 1:j])))
            i = j
        elif c == '"':
            end = body.find('"', i + 1)
            if end < 0 or "\\" in body[i + 1:end]:
                return None
            items.append(("text", body[i + 1:end]))
            i = end + 1
        else:
            return None
    if not items:
        return [("field", 0)]
    if items[0] == ("sep",) or items[-1] == ("sep",) or \
            any(a == b == ("sep",) for a, b in zip(items, items[1:])):
        return None
    return items


@_command("awk", "gawk", "mawk")
def _awk(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    sep, rest = None, list(args)
    if rest and rest[0] == "-F" and len(rest) > 1:
        sep, rest = rest[1], rest[2:]
    elif rest and rest[0].startswith("-F") and len(rest[0]) > 2:
        sep, rest = rest[0][2:], rest[1:]
    if not rest or rest[0].startswith("-"):
        return None
    if sep == "\\t":
        sep = "\t"
    if sep is not None and len(sep) != 1:
        return None
    items = _awk_program(rest[0])
    if items is None:
        return None
    read = _input(sh, rest[1:], stdin, "awk")
    if read is None:
        return None
    texts, errors, status, scope = read
    out = []
    for _, text in texts:
        for line in _lines(text):
            sh.charge(LINE + len(line) + STEP * len(items))
            record = line.rstrip("\n")
            fields = record.split() if sep in (None, " ") else record.split(sep)
            piece = []
            for item in items:
                if item[0] == "sep":
                    piece.append(" ")
                elif item[0] == "text":
                    piece.append(item[1])
                else:
                    n = len(fields) if item[1] == "NF" else item[1]
                    piece.append(record if n == 0 else (fields[n - 1] if n <= len(fields)
                                                        else ""))
            out.append("".join(piece) + "\n")
            sh.grow(len(out[-1]))
    return _Result("".join(out), errors, status, scope)


@_command("sh", "bash", scope=SESSION)
def _sh(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    """A shell fed nothing (a failed download piped into it) prints nothing; ``sh`` typed
    as a botnet opener starts a subshell that looks the same."""
    if stdin or len(args) > 1 or args[:1] and args[0].startswith("-"):
        return None
    if args:                            # a script a loader fetched: only a missing one
        path = sh.path(args[0])
        entry = sh.session.files.get(path)
        if entry is not None and not entry.data:
            return _Result(scope=STATE)
        if entry is not None or not (path in sh.session.removed or _exists(sh, path) is False):
            return None
        shown = _shown(args[0])
        if sh.busybox:                  # busybox ash, 1.30 to 1.36 alike
            return _Result(err=f"sh: can't open '{shown}': No such file or directory\n",
                           status=2, scope=STATE)
        if sh.host.family == "rhel" or sh.argv0 == "bash":
            return _Result(err=f"{sh.argv0}: {shown}: No such file or directory\n", status=127,
                           scope=STATE)
        return _Result(err=f"sh: 0: cannot open {shown}: No such file\n", status=2, scope=STATE)
    return _Result(scope=SESSION)


# ---- builtins and navigation (session state) --------------------------------------------------

def _dirs(sh: Shell) -> dict[str, list[str]]:
    """Directories ``ls`` and ``cd`` know, with their visible entries: the host's, with what
    the session made or removed."""
    if "dirs" not in sh.memo:
        sh.charge(2000 * STEP)               # the host's tables, bin lists included
        sh.memo["dirs"] = _host_dirs(sh)
    base = sh.memo["dirs"]
    s = sh.session
    if not (s.dirs or s.files or s.removed):
        return base
    key = ("dirs", s.version)
    if key in sh.memo:
        return sh.memo[key]
    out = dict(base)
    touched: dict[str, set] = {}

    def names(path: str) -> set:
        if path not in touched:
            touched[path] = set(out.get(path, ()))
            sh.charge(len(touched[path]) * STEP)
        return touched[path]

    for path in s.dirs:
        names(path)
    for path in list(s.dirs) + list(s.files):
        names(posixpath.dirname(path)).add(posixpath.basename(path))
    for path in s.removed:
        # A removed entry leaves its parent's listing only while the parent still exists: a
        # file removed with its directory must not bring the directory back.
        parent, name = posixpath.split(path)
        if parent in touched or parent in out:
            names(parent).discard(name)
    for path, entries in touched.items():
        out[path] = sorted(entries, key=lambda n: n.lower().lstrip("._"))
    sh.charge(len(s.dirs) + len(s.files) + len(s.removed) * STEP)
    sh.memo[key] = out
    return out


def _host_dirs(sh: Shell) -> dict[str, list[str]]:
    h = sh.host
    root = {"ubuntu": "bin boot dev etc home lib lib64 lost+found media mnt opt proc root run "
                      "sbin snap srv sys tmp usr var",
            "debian": "bin boot dev etc home initrd.img initrd.img.old lib lib64 lost+found "
                      "media mnt opt proc root run sbin srv sys tmp usr var vmlinuz vmlinuz.old",
            "rhel": "afs bin boot dev etc home lib lib64 media mnt opt proc root run sbin srv "
                    "sys tmp usr var"}.get(h.family, "bin boot dev etc home lib lib64 media mnt "
                                                     "opt proc root run sbin srv sys tmp usr var")
    r = h.rng("tmp")
    tags = ["systemd-logind.service", "systemd-resolved.service"] if h.family == "ubuntu" else \
        ["chronyd.service", "systemd-logind.service"]
    private = [f"systemd-private-{r.getrandbits(128):032x}-{t}-{r.getrandbits(24):06x}"
               for t in tags]
    homes = sorted({u.home.split("/")[2] for u in h.all_users(sh.user)
                    if u.home.startswith("/home/") and u.home.count("/") == 2})
    out = {"/": root.split(), "/home": homes,
           "/tmp": (["snap-private-tmp"] if h.family == "ubuntu" else []) + private,
           "/var/tmp": list(private), "/dev/shm": [], "/root": [], "/opt": [], "/srv": [],
           "/mnt": [], "/media": []}
    for u in h.all_users(sh.user):
        if u.home.startswith("/home/"):
            out.setdefault(u.home, [])
    for lure in h.lures:
        parts = lure.strip("/").split("/")
        for depth in range(len(parts)):
            parent = "/" + "/".join(parts[:depth])
            name = parts[depth]
            if parent in out and not name.startswith(".") and name not in out[parent]:
                out[parent].append(name)
            if depth < len(parts) - 1:
                out.setdefault("/" + "/".join(parts[:depth + 1]), [])
    for directory, names in h.bin_dirs().items():
        out[directory] = list(names)
        out[directory.replace("/usr", "", 1)] = list(names)     # /bin and /sbin point there
    out["/usr/local/bin"], out["/usr/local/sbin"] = [], []
    return {k: sorted(v, key=lambda s: s.lower().lstrip("._")) for k, v in out.items()}


# Directories cd accepts whose contents ls does not list.
_SYSTEM_DIRS = frozenset(("/etc", "/usr", "/var", "/proc", "/dev", "/run", "/var/run", "/sys",
                          "/boot", "/usr/lib", "/usr/share", "/var/log", "/var/lib"))


def _denied(sh: Shell, path: str) -> bool:
    return sh.user != "root" and (path == "/root" or path.startswith("/root/"))


@_command("ls", scope=SESSION)
def _ls(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    flags, operands = set(), []
    for arg in args:
        if arg.startswith("-") and len(arg) > 1 and not arg.startswith("--"):
            flags |= set(arg[1:])
        elif arg.startswith("-"):
            return None
        else:
            operands.append(arg)
    if flags - set("1al") or len(operands) > MAX_FILES:
        return None
    dirs = _dirs(sh)
    operands = operands or ["."]
    files, out, err, status = [], [], "", 0
    for word in operands:              # file operands are listed first, as typed
        path = sh.path(word)
        if path not in dirs and not _denied(sh, path):
            if path not in sh.session.files:
                return None
            files.append((word, path))
    if files:
        if "l" in flags:
            rows = [(word, _meta(sh, path)) for word, path in files]
            out.append(_long(sh, rows))
        else:
            names = [word for word, _ in files]
            out.append("\n".join(names) + "\n" if "1" in flags or not sh.interactive
                       else _columns(names, charge=sh.charge))
    listed = [w for w in operands if sh.path(w) in dirs or _denied(sh, sh.path(w))]
    for index, word in enumerate(listed):
        path = sh.path(word)
        if _denied(sh, path):
            err += f"ls: cannot open directory '{path}': Permission denied\n"
            status = 2
            continue
        listing = _listing(sh, path, dirs, flags)
        if listing is None:
            return None
        sh.grow(len(listing))
        if len(operands) > 1:
            listing = ("\n" if index or files else "") + f"{word}:\n" + listing
        out.append(listing)
    return _Result("".join(out), err, status)


def _listing(sh: Shell, path: str, dirs: dict, flags: set) -> Optional[str]:
    """One directory as ``ls`` prints it, or None where this shell cannot. Built once per
    line and session state: a line may name /usr/bin many times."""
    key = ("ls", path, sh.session.version, "".join(sorted(flags)))
    if key not in sh.memo:
        sh.memo[key] = _list_dir(sh, path, dirs, flags)
    return sh.memo[key]


def _list_dir(sh: Shell, path: str, dirs: dict, flags: set) -> Optional[str]:
    names = list(dirs[path])
    sh.charge(len(names) * STEP)
    if "a" in flags:
        if path not in _HIDDEN and path not in sh.session.dirs:
            return None                  # dot files this shell does not know
        names = [".", ".."] + sorted(names + _HIDDEN.get(path, []),
                                     key=lambda n: n.lower().lstrip("._"))
    if "l" in flags:
        rows = []
        for name in names:
            target = path if name == "." else posixpath.dirname(path) if name == ".." \
                else posixpath.join(path, name)
            meta = _meta(sh, target)
            if meta is None:
                return None
            rows.append((name, meta))
        blocks = sum(4 if m[0].startswith("d") else -(-m[3] // 4096) * 4 for _, m in rows)
        return f"total {blocks}\n" + _long(sh, rows)
    if ("1" in flags or not sh.interactive) and names:
        return "\n".join(names) + "\n"
    return _columns(names, charge=sh.charge)


_PRIVATE_DIRS = ("systemd-private-", "snap-private-tmp")
# Dot entries of the directories ``ls -a`` may list (systemd makes the X11 ones in /tmp).
_X11 = [".font-unix", ".ICE-unix", ".Test-unix", ".X11-unix", ".XIM-unix"]
_HIDDEN = {"/tmp": _X11, "/var/tmp": [], "/dev/shm": [], "/mnt": [], "/media": [],
           "/opt": [], "/srv": []}


def _meta(sh: Shell, path: str) -> Optional[tuple]:
    """(mode, links, owner, size, mtime) for ``ls -l``, or None where this shell does not
    know the entry well enough to show it: only directories and the session's own files.
    Charged, and kept for the line while the session's entries stay the same."""
    key = ("meta", path, sh.session.version)
    if key not in sh.memo:
        s = sh.session
        sh.charge(COMMAND // 4 + (len(s.files) + len(s.dirs)) * STEP
                  + len(s.files[path].data if path in s.files else ""))
        sh.memo[key] = _stat(sh, path)
    return sh.memo[key]


def _stat(sh: Shell, path: str) -> Optional[tuple]:
    entry = sh.session.files.get(path)
    boot = sh.host.boot_time(sh.now)
    if entry is not None:
        return (_mode_string(entry.mode, "-"), 1, sh.user, len(wire(entry.data)), entry.mtime)
    if path in sh.session.dirs:
        return ("drwxr-xr-x", 2, sh.user, 4096, sh.session.dirs[path])
    if posixpath.basename(path).startswith(_PRIVATE_DIRS):
        return ("drwx------", 3, "root", 4096, boot + 40)
    if posixpath.basename(path) in _X11 and posixpath.dirname(path) == "/tmp":
        return ("drwxrwxrwt", 2, "root", 4096, boot + 30)
    dirs = _dirs(sh)
    if path not in dirs and path not in _SYSTEM_DIRS:
        return None
    owner = next((u.name for u in sh.host.all_users(sh.user)
                  if u.home == path and path.startswith("/home/")), "root")
    mode = "drwxrwxrwt" if path in _OPEN_DIRS else \
        "drwx------" if path == "/root" else \
        "drwxr-x---" if path.startswith("/home/") and owner != "root" else "drwxr-xr-x"
    sh.charge(len(dirs.get(path, ())) * STEP)
    children = [n for n in list(dirs.get(path, ())) + _HIDDEN.get(path, [])
                if posixpath.join(path, n) in dirs or n.startswith(_PRIVATE_DIRS) or n in _X11]
    times = [f.mtime for p, f in sh.session.files.items() if posixpath.dirname(p) == path]
    times += [t for p, t in sh.session.dirs.items() if posixpath.dirname(p) == path]
    stamp = max([boot + (60 if path in _OPEN_DIRS else 0)] + times)
    return (mode, 2 + len(children), owner, 4096, stamp)


def _mode_string(mode: int, kind: str) -> str:
    bits = "".join(c if mode & (1 << (8 - i)) else "-" for i, c in enumerate("rwxrwxrwx"))
    return kind + bits


def _long(sh: Shell, rows: list[tuple[str, tuple]]) -> str:
    """``ls -l`` rows, each column as wide as its widest value, as GNU ls prints them."""
    if not rows:
        return ""
    now = sh.now

    def when(ts: float) -> str:
        t = sh.host.local(ts)
        return t.strftime("%b %e %H:%M") if abs(now - ts) < 15552000 else \
            t.strftime("%b %e  %Y")

    links = max(len(str(m[1])) for _, m in rows)
    owner = max(len(m[2]) for _, m in rows)
    size = max(len(str(m[3])) for _, m in rows)
    return "".join(f"{m[0]} {m[1]:>{links}} {m[2]:<{owner}} {m[2]:<{owner}} "
                   f"{m[3]:>{size}} {when(m[4])} {name}\n" for name, m in rows)


@_command("cd", scope=STATE)
def _cd(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if len(args) > 1:
        return _Result(err=f"{sh.prefix}: cd: too many arguments\n", status=1)
    target = sh.home if not args or args == ["~"] else \
        posixpath.normpath(posixpath.join(sh.cwd, args[0]))
    if _denied(sh, target):
        return _Result(err=f"{sh.prefix}: cd: {args[0]}: Permission denied\n", status=1)
    if target not in _dirs(sh) and target not in _SYSTEM_DIRS:
        if target in sh.session.removed or target in sh.session.files:
            reason = "Not a directory" if target in sh.session.files else \
                "No such file or directory"
            return _Result(err=f"{sh.prefix}: cd: {args[0]}: {reason}\n", status=1)
        return None
    sh.cwd = target
    return _Result()


@_command("pwd", scope=SESSION)
def _pwd(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return None if args else _Result(sh.cwd + "\n")


@_command("true", ":")
def _quiet(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return _Result()


_command("export", "unset", "history", scope=STATE)(_quiet)


@_command("false")
def _false(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return _Result(status=1)


def _leading(text: str, allowed: str) -> str:
    """The longest prefix of ``text`` made of ``allowed`` characters."""
    n = 0
    while n < len(text) and text[n] in allowed:
        n += 1
    return text[:n]


def _escapes(text: str) -> tuple[str, bool]:
    """``echo -e`` escapes: (text, stopped), where ``\\c`` stops all further output."""
    out, i = [], 0
    simple = {"n": "\n", "t": "\t", "\\": "\\", "a": "\a", "b": "\b", "f": "\f", "v": "\v",
              "r": "\r", "e": "\x1b"}
    while i < len(text):
        c = text[i]
        if c != "\\" or i + 1 == len(text):
            out.append(c)
            i += 1
            continue
        nxt = text[i + 1]
        if nxt in simple:
            out.append(simple[nxt])
            i += 2
        elif nxt == "c":
            return "".join(out), True
        elif nxt == "x":
            digits = _leading(text[i + 2:i + 4], "0123456789abcdefABCDEF")
            if not digits:
                out.append("\\x")
                i += 2
            else:
                out.append(byte_char(int(digits, 16)))
                i += 2 + len(digits)
        elif nxt == "0":
            digits = _leading(text[i + 2:i + 5], "01234567")
            out.append(byte_char(int(digits or "0", 8) & 0xFF))
            i += 2 + len(digits)
        else:
            out.append("\\" + nxt)
            i += 2
    return "".join(out), False


@_command("echo")
def _echo(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    newline, escapes = True, False
    while args and len(args[0]) > 1 and args[0][0] == "-" and not set(args[0][1:]) - set("neE"):
        for flag in args[0][1:]:
            newline = newline and flag != "n"
            escapes = True if flag == "e" else False if flag == "E" else escapes
        args = args[1:]
    text = " ".join(args)
    if escapes:
        text, stopped = _escapes(text)
        newline = newline and not stopped
    text += "\n" if newline else ""
    if sh.raw:          # into a file or a pipe: every byte, as written (a file's own
        return _Result(text[:MAX_ECHO_OUTPUT])  # redirection makes the line STATE)
    text = "".join(chr(ord(c) - 0xDC00) if 0xDC80 <= ord(c) <= 0xDCFF else c for c in text)
    return _Result("".join(c for c in text if c.isprintable() or c in "\n\t")[:MAX_ECHO_OUTPUT])


# ---- lookups, busybox and downloads -----------------------------------------------------------

@_command("which", scope=SESSION)
def _which(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if not args or any(a.startswith("-") for a in args):
        return None
    bins = sh.bins()
    found = [bins[a] for a in args if a in bins]
    return _Result("".join(p + "\n" for p in found), status=0 if len(found) == len(args) else 1)


@_command("command", scope=SESSION)
def _command_v(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if len(args) < 2 or args[0] != "-v":
        return None
    bins = sh.bins()
    out = [bins.get(a) or (a if a in SHELL_BUILTINS else None) for a in args[1:]]
    return _Result("".join(p + "\n" for p in out if p), status=0 if all(out) else 1)


# What bash's ``enable`` lists: every enabled builtin, in its table order.
_BASH_BUILTINS = (". : [ alias bg bind break builtin caller cd command compgen complete compopt "
                  "continue declare dirs disown echo enable eval exec exit export false fc fg "
                  "getopts hash help history jobs kill let local logout mapfile popd printf "
                  "pushd pwd read readarray readonly return set shift shopt source suspend test "
                  "times trap true type typeset ulimit umask unalias unset wait").split()


@_command("enable")
def _enable(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    """bash lists its builtins. The host presents bash on SSH and on the Telnet trap, and an
    IoT bot sending ``enable`` as its opener reads nothing from the reply, so the bash answer
    serves both."""
    if args not in ([], ["-a"]):
        return None
    return _Result("".join(f"enable {name}\n" for name in _BASH_BUILTINS))


_BUSYBOX_BANNER = ("BusyBox v{version} multi-call binary.\n"
                   "BusyBox is copyrighted by many authors between 1998-2015.\n"
                   "Licensed under GPLv2. See source distribution for detailed\n"
                   "copyright notices.\n\n"
                   "Usage: busybox [function [arguments]...]\n"
                   "   or: busybox --list[-full]\n"
                   "   or: busybox --show SCRIPT\n"
                   "   or: busybox --install [-s] [DIR]\n"
                   "   or: function [arguments]...\n\n"
                   "\tBusyBox is a multi-call binary that combines many common Unix\n"
                   "\tutilities into a single executable.  Most people will create a\n"
                   "\tlink to busybox for each function they wish to use and BusyBox\n"
                   "\twill act like whatever it was invoked as.\n")
# Applets answered here; any other applet in the package's list is unsupported, and one not
# in it is "applet not found" (``agents.busybox_text``).
_APPLETS = frozenset(("cat", "echo", "uname", "id", "whoami", "hostname", "nproc", "free",
                      "df", "ps", "ls", "wget", "tftp", "head", "tail", "cut", "wc", "grep",
                      "awk", "uptime", "sh", "true", "false", "pwd", "cp", "mv", "rm", "mkdir",
                      "touch", "chmod", "dd", "rmdir", "kill", "killall", "nc", "ftpget", "ftpput",
                      "printf"))
# Applets that print their usage when run without arguments (stderr, status 1).
_USAGE_APPLETS = frozenset(("wget", "tftp", "cp", "chmod", "rm", "mkdir", "mv", "touch",
                            "printf", "nc", "ftpget", "ftpput"))


def _applet_usage(sh: Shell, applet: str) -> _Result:
    from agents import busybox_text

    text = busybox_text.USAGE[busybox_text.generation(sh.host.busybox or "")][applet]
    return _Result(err=f"BusyBox v{sh.host.busybox} multi-call binary.\n\n{text}", status=1)


@_command("busybox")
def _busybox(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    from agents import busybox_text

    if sh.host.busybox is None:
        return None
    if not args:
        return _Result(_BUSYBOX_BANNER.format(version=sh.host.busybox))
    applets = busybox_text.APPLETS[busybox_text.generation(sh.host.busybox)]
    applet = args[0]
    if applet in ("--list", "-l") and len(args) == 1:
        return _Result("".join(name + "\n" for name in sorted(applets)))
    if applet.startswith("-"):
        return None
    if applet not in applets:
        name = "".join(c for c in applet if c.isprintable())[:64]
        return _Result(err=f"{name}: applet not found\n", status=127)
    if applet not in _APPLETS:
        return None
    if applet in _USAGE_APPLETS and len(args) == 1:
        return _applet_usage(sh, applet)
    if applet in ("kill", "killall") and len(args) == 1:
        return _Result(err=f"{applet}: you need to specify whom to kill\n", status=1)
    entry = _COMMANDS.get(applet)
    if entry is None or applet in ("killall", "ftpget", "ftpput"):
        return None
    sh.argv0, sh.exe, sh.busybox = applet, "busybox", True
    try:
        result = entry[0](sh, args[1:], stdin)
    finally:
        sh.busybox = False
    if result is not None:
        result.scope = max(result.scope, entry[1])
    return result


def _url(args: list[str], takes_value: set[str]) -> tuple[Optional[str], bool]:
    """(the first URL operand, quiet flag) for wget and curl."""
    url, quiet, skip = None, False, False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in takes_value:
            skip = True
        elif arg.startswith("--"):
            quiet = quiet or arg in ("--quiet", "--silent")
        elif arg.startswith("-") and len(arg) > 1:
            quiet = quiet or ("q" in arg[1:] or "s" in arg[1:]) and "S" not in arg[1:]
            if arg[-1] in {v[1] for v in takes_value if len(v) == 2}:
                skip = True
        elif url is None:
            url = arg
    return url, quiet


def _target(url: str) -> tuple[str, str, int]:
    """(shown URL, host, port) without any lookup."""
    shown = url if "://" in url else "http://" + url
    try:
        parts = urllib.parse.urlsplit(shown)
        host = parts.hostname or ""
    except ValueError:                              # e.g. an unclosed IPv6 bracket
        return _url_text(shown), "", 80
    try:
        port = parts.port or {"https": 443, "ftp": 21}.get(parts.scheme, 80)
    except ValueError:
        port = 80
    return _url_text(shown), _url_text(host), port


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", host)) or ":" in host


@_command("wget", scope=STATE)
def _wget(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    url, quiet = _url(args, {"-O", "-o", "-P", "-U", "-t", "-T", "-e", "--output-document",
                             "--user-agent", "--directory-prefix", "--tries", "--timeout"})
    if url is None:
        return _Result(err="wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\n"
                           "Try `wget --help' for more options.\n", status=1)
    shown, host, port = _target(url)
    if sh.busybox:
        if not host:
            return _Result(err="wget: bad address ''\n", status=1)
        if not _is_ip(host):
            return _Result(err=f"wget: bad address '{host}'\n", status=1)
        connecting = "" if quiet else f"Connecting to {host}:{port} ({host}:{port})\n"
        return _Result(err=connecting + f"wget: can't connect to remote host ({host}): "
                                        "Network is unreachable\n", status=1)
    if quiet:
        return _Result(status=4)
    stamp = sh.host.local(sh.now).strftime("%Y-%m-%d %H:%M:%S")
    if not host:
        return _Result(err=f"{shown}: Invalid host name.\n", status=1)
    if _is_ip(host):
        body = f"Connecting to {host}:{port}... failed: Network is unreachable.\n"
    else:
        body = (f"Resolving {host} ({host})... failed: Temporary failure in name resolution.\n"
                f"wget: unable to resolve host address \u2018{host}\u2019\n")
    return _Result(err=f"--{stamp}--  {shown}\n{body}", status=4)


@_command("curl", scope=STATE)
def _curl(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    url, quiet = _url(args, {"-o", "-A", "-H", "-d", "-X", "-u", "-e", "-m", "-x", "-T",
                             "--output", "--user-agent", "--header", "--data", "--request",
                             "--max-time", "--connect-timeout", "--proxy", "--retry"})
    if url is None:
        return _Result(err="curl: try 'curl --help' or 'curl --manual' for more information\n",
                       status=2)
    show_errors = "-S" in args or "--show-error" in args or any(
        a.startswith("-") and not a.startswith("--") and "S" in a for a in args)
    _, host, port = _target(url)
    if _is_ip(host):
        status = 7
        message = (f"curl: (7) Failed to connect to {host} port {port} after 0 ms: "
                   "Couldn't connect to server\n")
    else:
        status = 6
        message = f"curl: (6) Could not resolve host: {host}\n"
    return _Result(err="" if quiet and not show_errors else message, status=status)


@_command("tftp", scope=STATE)
def _tftp(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return _Result(err="Transfer timed out.\n\n", status=1) if args else None


# ---- the commands IoT loaders use: session files, dd, usage errors ----------------------------

def _try(name: str) -> str:
    return f"Try '{name} --help' for more information.\n"


def _shown(word: str) -> str:
    return "".join(c for c in word if c.isprintable())[:256]


def _split_flags(args: list[str], allowed: str) -> Optional[tuple[set, list[str]]]:
    """(short flags, operands); None for a flag outside ``allowed`` or a long option."""
    flags, operands = set(), []
    for arg in args:
        if arg.startswith("-") and len(arg) > 1 and not operands:
            if arg.startswith("--") or set(arg[1:]) - set(allowed):
                return None
            flags |= set(arg[1:])
        else:
            operands.append(arg)
    return flags, operands


def _exists(sh: Shell, path: str) -> Optional[bool]:
    """Whether ``path`` exists, or None when this shell cannot tell."""
    if path in sh.session.files or sh.directory(path) or sh.program(path) or path in _FILES:
        return True
    parent, name = posixpath.split(path)
    dirs = _dirs(sh)
    if parent in dirs and not name.startswith("."):    # listings leave out dot files
        return name in dirs[parent]
    return None


def _source(sh: Shell, word: str) -> Optional[_Scratch]:
    """What ``cp`` copies from ``word``; None when unknown, an empty-data marker when it
    does not exist (``mode`` 0)."""
    path = sh.path(word)
    entry = sh.session.files.get(path)
    if entry is not None:
        return _Scratch(entry.data, entry.mode, program=entry.program)
    program = sh.program(path)
    if program is not None:
        return _Scratch(sh.elf(program), 0o755, program=program)
    if path in _FILES and sh.read_file(path) is not None and not sh.read_file(path).err:
        return _Scratch(sh.read_file(path).out, 0o644)
    if _exists(sh, path) is False or path in sh.session.removed:
        return _Scratch(mode=0)
    return None


def _destination(sh: Shell, source: str, target: str) -> str:
    path = sh.path(target)
    return posixpath.join(path, posixpath.basename(sh.path(source))) if sh.directory(path) \
        else path


@_command("cp", scope=STATE)
def _cp(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    split = _split_flags(args, "afprRdHLPu")
    if split is None:
        return None
    flags, operands = split
    if len(operands) < 2:
        if sh.busybox:
            return _applet_usage(sh, "cp")
        if not operands:
            return _Result(err="cp: missing file operand\n" + _try("cp"), status=1)
        return _Result(err=f"cp: missing destination file operand after '{_shown(operands[0])}'"
                           "\n" + _try("cp"), status=1)
    *sources, target = operands
    if len(sources) > 1 and not sh.directory(sh.path(target)):
        return None
    err, status = "", 0
    for word in sources[:MAX_FILES]:
        src = _source(sh, word)
        if src is None:
            return None
        if src.mode == 0:
            err += (f"cp: can't stat '{_shown(word)}': No such file or directory\n"
                    if sh.busybox else
                    f"cp: cannot stat '{_shown(word)}': No such file or directory\n")
            status = 1
            continue
        dest = _destination(sh, word, target)
        reason = sh.writable(dest) if dest not in sh.session.files else None
        if reason is not None:
            err += f"cp: cannot create regular file '{_shown(target)}': {reason}\n"
            status = 1
            continue
        old = sh.session.files.get(dest)
        sh.store(dest, _Scratch(src.data, old.mode if old else src.mode, sh._now, src.program))
    return _Result(err=err, status=status)


@_command("mv", scope=STATE)
def _mv(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    split = _split_flags(args, "fin")
    if split is None:
        return None
    flags, operands = split
    if len(operands) != 2:
        if sh.busybox and len(operands) < 2:
            return _applet_usage(sh, "mv")
        if not operands:
            return _Result(err="mv: missing file operand\n" + _try("mv"), status=1)
        if len(operands) == 1:
            return _Result(err=f"mv: missing destination file operand after "
                               f"'{_shown(operands[0])}'\n" + _try("mv"), status=1)
        return None
    word, target = operands
    path = sh.path(word)
    entry = sh.session.files.get(path)
    if entry is None and path in sh.session.dirs:
        return _mv_dir(sh, word, target, path)
    if entry is None:
        if _exists(sh, path) is False or path in sh.session.removed:
            return _Result(err=f"mv: can't rename '{_shown(word)}': No such file or directory\n"
                           if sh.busybox else
                           f"mv: cannot stat '{_shown(word)}': No such file or directory\n",
                           status=1)
        return None
    dest = _destination(sh, word, target)
    if dest == path:
        return _Result()
    reason = sh.writable(dest) if dest not in sh.session.files else None
    if reason is not None:
        return _Result(err=f"mv: cannot move '{_shown(word)}' to '{_shown(target)}': {reason}\n",
                       status=1)
    sh.remove(path)
    sh.store(dest, entry)
    return _Result()


def _mv_dir(sh: Shell, word: str, target: str, path: str) -> Optional[_Result]:
    """``mv`` of a directory the session made: it and everything in it move."""
    dest = _destination(sh, word, target)
    if dest == path:
        return _Result()
    if dest.startswith(path + "/"):
        return _Result(err=f"mv: cannot move '{_shown(word)}' to a subdirectory of itself, "
                           f"'{_shown(dest)}'\n", status=1)
    if dest in sh.session.files:
        return _Result(err=f"mv: cannot overwrite non-directory '{_shown(dest)}' with "
                           f"directory '{_shown(word)}'\n", status=1)
    if sh.directory(dest):
        if dest not in sh.session.dirs or sh.scratch_entries(dest):
            return None                      # bash would merge or refuse: not followed
    reason = sh.writable(dest)
    if reason is not None:
        return _Result(err=f"mv: cannot move '{_shown(word)}' to '{_shown(target)}': {reason}\n",
                       status=1)
    s = sh.session
    inner = sorted(p for p in list(s.files) + list(s.dirs) if p.startswith(path + "/"))
    sh.charge((len(s.files) + len(s.dirs)) * STEP)
    moved = [(p, s.files.get(p)) for p in [path] + inner]
    for p, _ in reversed(moved):
        sh.remove(p)
    if dest in s.dirs:
        sh.remove(dest)
    for p, entry in moved:
        sh.store(dest + p[len(path):], entry)
    return _Result()


@_command("rmdir", scope=STATE)
def _rmdir(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    split = _split_flags(args, "")
    if split is None:
        return None
    operands = split[1]
    if not operands:
        if sh.busybox:
            return None
        return _Result(err="rmdir: missing operand\n" + _try("rmdir"), status=1)
    err, status = "", 0
    for word in operands[:MAX_FILES]:
        path = sh.path(word)
        if path in sh.session.dirs:
            reason = "Directory not empty" if sh.scratch_entries(path) else None
        elif path in sh.session.files:
            reason = "Not a directory"
        elif path in sh.session.removed or _exists(sh, path) is False:
            reason = "No such file or directory"
        else:
            return None                      # a directory of the host
        if reason is None:
            sh.remove(path)
            continue
        err += f"rmdir: '{_shown(word)}': {reason}\n" if sh.busybox else \
            f"rmdir: failed to remove '{_shown(word)}': {reason}\n"
        status = 1
    return _Result(err=err, status=status)


@_command("rm", scope=STATE)
def _rm(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    split = _split_flags(args, "frRid")
    if split is None:
        return None
    flags, operands = split
    if not operands:
        if "f" in flags:
            return _Result()
        if sh.busybox:
            return _applet_usage(sh, "rm")
        return _Result(err="rm: missing operand\n" + _try("rm"), status=1)
    err, status = "", 0
    for word in operands[:MAX_FILES]:
        path = sh.path(word)
        shown = _shown(word)
        if path in sh.session.files:
            sh.remove(path)
        elif path in sh.session.dirs:
            if not flags & set("rR"):
                err += f"rm: '{shown}' is a directory\n" if sh.busybox else \
                    f"rm: cannot remove '{shown}': Is a directory\n"
                status = 1
                continue
            for inner in [p for p in list(sh.session.files) + list(sh.session.dirs)
                          if p.startswith(path + "/")]:
                sh.remove(inner)
            sh.remove(path)
        elif path in sh.session.removed or _exists(sh, path) is False:
            if "f" not in flags:
                err += f"rm: can't remove '{shown}': No such file or directory\n" \
                    if sh.busybox else f"rm: cannot remove '{shown}': No such file or directory\n"
                status = 1
        else:
            return None                      # a file of the host: the model owns that change
    return _Result(err=err, status=status)


@_command("mkdir", scope=STATE)
def _mkdir(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    split = _split_flags(args, "p")
    if split is None:
        return None
    flags, operands = split
    if not operands:
        if sh.busybox:
            return _applet_usage(sh, "mkdir")
        return _Result(err="mkdir: missing operand\n" + _try("mkdir"), status=1)
    err, status = "", 0
    for word in operands[:MAX_FILES]:
        path = sh.path(word)
        shown = _shown(word)
        cannot = "can't" if sh.busybox else "cannot"
        if sh.directory(path) or path in sh.session.files:
            if "p" not in flags or path in sh.session.files:
                err += f"mkdir: {cannot} create directory '{shown}': File exists\n"
                status = 1
            continue
        chain = [path]
        while "p" in flags and not sh.directory(posixpath.dirname(chain[-1])) \
                and len(chain) < MAX_FILES:
            chain.append(posixpath.dirname(chain[-1]))
        if not sh.directory(posixpath.dirname(chain[-1])):
            if len(chain) >= MAX_FILES:
                return None                  # deeper than this shell follows
            if _exists(sh, posixpath.dirname(chain[-1])) is False:
                err += f"mkdir: {cannot} create directory '{shown}': No such file or directory\n"
                status = 1
                continue
            return None
        for target in reversed(chain):
            reason = sh.writable(target)
            if reason is not None:
                err += f"mkdir: {cannot} create directory '{shown}': {reason}\n"
                status = 1
                break
            sh.store(target, None)
    return _Result(err=err, status=status)


@_command("touch", scope=STATE)
def _touch(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    split = _split_flags(args, "cam")
    if split is None:
        return None
    flags, operands = split
    if not operands:
        if sh.busybox:
            return _applet_usage(sh, "touch")
        return _Result(err="touch: missing file operand\n" + _try("touch"), status=1)
    for word in operands[:MAX_FILES]:
        path = sh.path(word)
        entry = sh.session.files.get(path)
        if entry is not None:
            entry.mtime = sh._now
            sh.session.version += 1
        elif path in sh.session.dirs:
            sh.session.dirs[path] = sh._now
            sh.session.version += 1
        elif _exists(sh, path) is True:
            continue                         # a host file: only its time changes
        elif "c" not in flags:
            reason = sh.writable(path)
            if reason is not None:
                return _Result(err=f"touch: cannot touch '{_shown(word)}': {reason}\n",
                               status=1)
            sh.store(path, _Scratch(mtime=sh._now))
    return _Result()


def _parse_mode(spec: str, mode: int) -> Optional[int]:
    """A chmod MODE applied to ``mode``: octal, or ``[ugoa]*[+-=][rwxXst]*`` clauses."""
    if spec and len(spec) <= 4 and not set(spec) - set("01234567"):
        return int(spec, 8)
    for clause in spec.split(","):
        who = _leading(clause, "ugoa")
        rest = clause[len(who):]
        if not rest or rest[0] not in "+-=" or set(rest[1:]) - set("rwxXst"):
            return None
        mask = 0
        for w in who or "a":
            mask |= {"u": 0o700, "g": 0o070, "o": 0o007, "a": 0o777}[w]
        bits = 0
        for p in rest[1:]:
            bits |= {"r": 0o444, "w": 0o222, "x": 0o111, "X": 0o111, "s": 0, "t": 0}[p]
        bits &= mask
        mode = mode | bits if rest[0] == "+" else mode & ~bits if rest[0] == "-" else \
            (mode & ~mask) | bits
    return mode


@_command("chmod", scope=STATE)
def _chmod(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    flags = {a for a in args[:1] if a in ("-R", "-f", "-v", "-c")}
    operands = args[len(flags):]
    if len(operands) < 2:
        if sh.busybox:
            return _applet_usage(sh, "chmod")
        if not operands:
            return _Result(err="chmod: missing operand\n" + _try("chmod"), status=1)
        return _Result(err=f"chmod: missing operand after '{_shown(operands[0])}'\n"
                           + _try("chmod"), status=1)
    spec, files = operands[0], operands[1:]
    if _parse_mode(spec, 0) is None or "-v" in flags or "-c" in flags:
        return None
    err, status = "", 0
    for word in files[:MAX_FILES]:
        path = sh.path(word)
        entry = sh.session.files.get(path)
        if entry is not None:
            entry.mode = _parse_mode(spec, entry.mode)
            sh.session.version += 1
        elif path in sh.session.removed or _exists(sh, path) is False:
            if "-f" not in flags:
                err += f"chmod: {_shown(word)}: No such file or directory\n" if sh.busybox \
                    else f"chmod: cannot access '{_shown(word)}': No such file or directory\n"
                status = 1
        elif _exists(sh, path) is None:
            return None
    return _Result(err=err, status=status)


def _si(value: float, binary: bool = False) -> str:
    """dd's human sizes: ``3.1 MB``, ``46 MB``, ``2.0 KiB``."""
    base, units = (1024, ["B", "KiB", "MiB", "GiB"]) if binary else \
        (1000, ["B", "kB", "MB", "GB"])
    unit = 0
    while value >= base and unit < len(units) - 1:
        value /= base
        unit += 1
    if value < 10:
        return f"{math.ceil(value * 10) / 10:.1f} {units[unit]}"
    return f"{math.ceil(value):d} {units[unit]}"


@_command("dd")
def _dd(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    ops: dict[str, str] = {}
    for arg in args:
        key, sep, value = arg.partition("=")
        if not sep or key not in ("if", "bs", "ibs", "count", "skip") or key in ops:
            return None
        ops[key] = value
    sizes = {}
    for key in ("bs", "ibs", "count", "skip"):
        if key in ops:
            n = _count(ops[key])
            if n is None or (key in ("bs", "ibs") and not 0 < n <= MAX_STAGE_OUTPUT):
                return None
            sizes[key] = n
    block = sizes.get("bs", sizes.get("ibs", 512))
    if "if" in ops:
        read = sh.read_file(ops["if"])
        if read is None:
            return None
        if read.err:
            return _Result(err=f"dd: can't open '{_shown(ops['if'])}': No such file or directory\n"
                           if sh.busybox else f"dd: failed to open '{_shown(ops['if'])}': "
                           "No such file or directory\n", status=1, scope=read.scope)
        data, scope = read.out, read.scope
    elif stdin is not None:
        data, scope = stdin, FIXED
    else:
        return None                          # it would read the terminal
    raw = wire(data)                         # dd counts bytes, not characters
    start = sizes.get("skip", 0) * block
    end = len(raw) if "count" not in sizes else start + sizes["count"] * block
    piece = raw[start:end]
    chunk = piece.decode("utf-8", "surrogateescape")
    sh.grow(len(chunk))
    length = len(piece)
    full, part = length // block, 1 if length % block else 0
    stats = f"{full}+{part} records in\n{full}+{part} records out\n"
    if not sh.busybox:
        seconds = sh.host.rng("dd", length).uniform(1.5e-05, 9e-05)
        rate = _si(length / seconds) + "/s"
        if length < 1000:
            stats += f"{length} byte{'s' if length != 1 else ''} copied, {seconds:.5g} s, {rate}\n"
        else:
            stats += (f"{length} bytes ({_si(length)}, {_si(length, True)}) copied, "
                      f"{seconds:.5g} s, {rate}\n")
    return _Result(chunk, scope=scope, late=stats)


def _read_loop(sh: Shell, raw: bool, stdin: Optional[str]) -> _Result:
    """``while read [-r] i; do echo $i; done``: bash drops NUL bytes, reads to each newline
    (a last line without one is read but not echoed), takes a backslash as an escape unless
    ``-r``, and the unquoted ``$i`` is split into words that echo joins with one space."""
    if stdin is None:
        raise _Unsupported                   # it would read the terminal
    sh.exe = "bash"
    text = stdin.replace("\x00", "")
    sh.charge(len(text) * STEP)
    out, line, i = [], [], 0
    while i < len(text):
        c = text[i]
        if c == "\\" and not raw:
            if i + 1 < len(text) and text[i + 1] != "\n":
                line.append(text[i + 1])
            i += 2
            continue
        if c == "\n":
            words = [w for w in re.split("[ \t]+", "".join(line)) if w]   # IFS, not \v\f
            newline = True
            while words and len(words[0]) > 1 and words[0][0] == "-" \
                    and not set(words[0][1:]) - set("neE"):
                newline = newline and "n" not in words[0]
                words = words[1:]
            out.append(" ".join(words) + ("\n" if newline else ""))
            sh.grow(len(out[-1]))
            line = []
        else:
            line.append(c)
        i += 1
    return _Result("".join(out))


@_command("kill", scope=SESSION)
def _kill(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if args:
        return None
    return _Result(err="kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... "
                       "or kill -l [sigspec]\n", status=2)


@_command("printf")
def _printf(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if args:
        return None                          # the literal_output path answers these
    return _Result(err="printf: usage: printf [-v var] format [arguments]\n", status=2)


@_command("ping")
def _ping(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if args:
        return None
    return _Result(err="ping: usage error: Destination address required\n", status=1)


_NC_USAGE = ("usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n"
             "\t  [-m minttl] [-O length] [-P proxy_username] [-p source_port]\n"
             "\t  [-q seconds] [-s sourceaddr] [-T keyword] [-V rtable] [-W recvlimit]\n"
             "\t  [-w timeout] [-X proxy_protocol] [-x proxy_address[:port]]\n"
             "\t  [destination] [port]\n")


@_command("nc")
def _nc(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if args or sh.busybox:
        return None
    if sh.host.family == "rhel":         # nmap's ncat
        return _Result(err="Ncat: You must specify a host to connect to. QUITTING.\n", status=2)
    return _Result(err=_NC_USAGE, status=1)


# ---- a known tool used in a way this shell does not reproduce ---------------------------------

# Short options the GNU tools accept; another letter gets the tool's own "invalid option".
_GNU_OPTIONS = {
    "cat": "AbeEnstTuv", "head": "cnqvz", "tail": "cfFnqsvz", "cut": "bcdfnsz", "wc": "clmwL",
    "ls": "1ABCDFGHILNQRSTUXZabcdfghiklmnopqrstuvwx", "id": "agGnruzZ", "whoami": "",
    "nproc": "", "df": "aBhHiklPtTvx", "uname": "asnrvmpio",
    "grep": "0123456789ABCDEFGHILPRTUVZabcdefhilmnoqrsuvwxyz",
}
# Short options that take a value (the next word is not a file operand).
_VALUE_OPTIONS = {"head": "cn", "tail": "cn", "cut": "bcdf", "grep": "ABCefm", "awk": "Ffv",
                  "gawk": "Ffv", "mawk": "Ffv", "df": "BtTx", "ls": "ITw", "wc": ""}
# Commands whose operands are files (the first operand of grep and awk is the program).
_FILE_TOOLS = {"cat": 0, "head": 0, "tail": 0, "cut": 0, "wc": 0, "grep": 1, "egrep": 1,
               "fgrep": 1, "awk": 1, "gawk": 1, "mawk": 1, "ls": 0, "df": 0}


def _missing(sh: Shell, name: str, path: str) -> str:
    """What the tool says about a path that is not on this host."""
    if name == "ls":
        return f"ls: cannot access '{path}': No such file or directory\n"
    if name in ("head", "tail"):
        return f"{name}: cannot open '{path}' for reading: No such file or directory\n"
    if name in ("awk", "gawk", "mawk"):
        if sh.host.family == "rhel" or name == "gawk":
            return f"{name}: fatal: cannot open file `{path}' for reading: No such file or directory\n"
        return f"{name}: cannot open {path} (No such file or directory)\n"
    return f"{name}: {path}: No such file or directory\n"


def _tool_error(sh: Shell, name: str, args: list[str]) -> str:
    """The real tool's complaint about an option or file it does not know, or nothing when
    it would have printed output this shell cannot reproduce. Never ``command not found``
    for a command that exists."""
    shown = "".join(c for c in name if c.isprintable())[:64]
    gnu = _GNU_OPTIONS.get(name)
    takes = _VALUE_OPTIONS.get(name, "")
    operands, i = [], 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            operands += args[i + 1:]
            break
        if arg.startswith("-") and len(arg) > 1 and not arg.startswith("--"):
            for k, ch in enumerate(arg[1:], 1):
                if gnu is not None and ch not in gnu:
                    if name == "grep":
                        return (f"grep: invalid option -- '{ch}'\n"
                                "Usage: grep [OPTION]... PATTERNS [FILE]...\n"
                                "Try 'grep --help' for more information.\n")
                    return (f"{shown}: invalid option -- '{ch}'\n"
                            f"Try '{shown} --help' for more information.\n")
                if ch in takes:
                    i += 1 if k == len(arg) - 1 else 0     # value in the next word
                    break
        elif not arg.startswith("-") or arg == "-":
            operands.append(arg)
        i += 1
    if name in _FILE_TOOLS:
        skip = _FILE_TOOLS[name]
        if name in ("grep", "egrep", "fgrep") and any(a.startswith("-e") for a in args):
            skip = 0
        known = set(_dirs(sh)) | _SYSTEM_DIRS | {"-"}
        lures = {posixpath.normpath(p) for p in sh.host.lures}
        out = []
        for path in operands[skip:skip + MAX_FILES]:
            full = posixpath.normpath(posixpath.join(sh.cwd, path))
            shown_path = "".join(c for c in path if c.isprintable())[:256]
            if full in known and name not in ("ls", "df"):
                out.append(f"{shown}: {shown_path}: Is a directory\n")
            elif full not in known and full not in lures and full not in _FILES \
                    and full not in sh.session.files and sh.program(full) is None:
                out.append(_missing(sh, shown, shown_path))
        return "".join(out)
    return ""
