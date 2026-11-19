"""Deterministic shell answers for the commands bots use to size up a host.

One answerer for the SSH fallback (no model, model error) and the Telnet trap's canned
shell, so the two cannot disagree; with a model, host facts are answered here first until
the model has handled a command in the session (``[llm] local_shell_replies``, see
``agents.hooks``).

Every answer is computed in Python from one host profile: the scenario's identity, its
``[identity.hardware]`` table, the sensor seed and the clock. Nothing is executed, nothing
is fetched, and no pattern from the attacker is compiled as a regular expression (``grep``
patterns are fixed strings plus ``.``, ``^`` and ``$``, matched by hand). One line's
whole cost is bounded: see ``MAX_WORK``, ``MAX_STAGE_OUTPUT`` and ``MAX_FILES``.

``answer`` takes one input line: a simple command, a pipeline of our own output through
``grep``, ``head``, ``tail``, ``cut``, ``wc`` and ``awk '{print ...}'``, or a ``;`` / ``&&``
/ ``||`` list of those. Anything it cannot evaluate exactly (redirection, substitution,
globbing, variables, an unknown command, file or option) returns None, and the caller
answers as it did before.
"""

from __future__ import annotations

import datetime
import hashlib
import math
import posixpath
import random
import re
import shlex
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Optional

from scenarios.schema import GPU_SPECS, Hardware

MAX_LINE = 4096            # longer input is not evaluated
MAX_WORD = 1024
MAX_WORDS = 64             # per command
MAX_STAGES = 8             # commands in one pipeline
MAX_LIST = 8               # pipelines in one ; && || list
MAX_PATTERN = 256          # grep pattern length
MAX_FILES = 8              # file operands one command reads
MAX_STAGE_OUTPUT = 128 * 1024  # characters one command may produce (a 64-CPU cpuinfo is 72k)
MAX_OUTPUT = 128 * 1024    # characters the whole line may produce
MAX_ECHO_OUTPUT = 4096
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
BIN_DIRS = frozenset(("/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin",
                      "/usr/local/sbin"))
# IoT botnet openers: a device CLI accepts these silently before the bot tries busybox.
OPENERS = frozenset(("enable", "system", "shell", "linuxshell", "sh", "bash"))
DEFAULT_KERNEL = ("Linux srv01 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC "
                  "2024 x86_64 x86_64 x86_64 GNU/Linux")
MACHINES = frozenset(("x86_64", "aarch64", "i686", "armv7l"))


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
    """The first word of ``text``, printable characters only, as a shell error names it."""
    return "".join(c for c in (text.split() or [""])[0] if c.isprintable())[:64]


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
        base = 0.02 * self.hardware.cpus
        return (round(r.uniform(0, base * 4), 2), round(r.uniform(0, base * 2), 2),
                round(r.uniform(0, base), 2))

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


def _pages(kib: float) -> int:
    """Round kB down to whole 4 kB pages."""
    return int(kib) // 4 * 4


_BINARIES = ("awk", "base64", "bash", "busybox", "cat", "chattr", "chmod", "cp", "curl",
             "cut", "df", "free", "grep", "gzip", "head", "hostname", "id", "kill", "ls",
             "lscpu", "lspci", "mkdir", "mv", "nc", "nohup", "nproc", "perl", "ps",
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
        return Host(seed=seed or "winnie")
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
        lures=tuple(scenario.lures()), hardware=ident.hardware,
        seed=seed or scenario.seed or "winnie")


# ---- parsing ------------------------------------------------------------------------------

class _Unsupported(Exception):
    """The line needs a real shell; the caller answers as before."""


_UNQUOTED_SPECIAL = set("$`\\<>(){}*?[]~#!\"'")


def _tokenize(line: str) -> list:
    """Words and the operators ``|``, ``;``, ``&&``, ``||``. Quotes are honoured; anything
    a shell would expand or redirect raises ``_Unsupported``."""
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


def _parse(line: str) -> list[tuple[str, list[list[str]]]]:
    """[(operator before it, pipeline)], a pipeline being a list of argv lists."""
    items: list[tuple[str, list[list[str]]]] = []
    joiner, pipeline, argv = ";", [], []
    for tok in _tokenize(line):
        if isinstance(tok, _Op):
            if not argv:
                raise _Unsupported
            pipeline.append(argv)
            argv = []
            if tok.op == "|":
                continue
            items.append((joiner, pipeline))
            joiner, pipeline = tok.op, []
            continue
        if len(tok) > MAX_WORD:
            raise _Unsupported
        argv.append(tok)
    if argv:
        pipeline.append(argv)
        items.append((joiner, pipeline))
    elif pipeline or joiner != ";":
        raise _Unsupported                   # ends in | && ||
    if not items or len(items) > MAX_LIST or any(len(p) > MAX_STAGES for _, p in items) \
            or any(len(a) > MAX_WORDS for _, p in items for a in p):
        raise _Unsupported
    return items


# ---- evaluation ---------------------------------------------------------------------------

@dataclass
class Answer:
    output: str              # "\n" line endings; callers convert for the terminal
    status: int = 0
    stateless: bool = True   # only host facts: safe to answer ahead of a model


@dataclass
class _Result:
    out: str = ""
    err: str = ""
    status: int = 0
    stateless: bool = True


Handler = Callable[["Shell", list[str], Optional[str]], Optional[_Result]]
_COMMANDS: dict[str, tuple[Handler, bool]] = {}   # name -> (handler, stateless)


def _command(*names: str, stateless: bool = True):
    def register(fn: Handler) -> Handler:
        for name in names:
            _COMMANDS[name] = (fn, stateless)
        return fn
    return register


class _OverBudget(_Unsupported):
    """The line needs more work or output than one line may cost."""


class Shell:
    def __init__(self, host: Host, user: str, interactive: bool, cwd: Optional[str],
                 now: float, src_ip: Optional[str]) -> None:
        self.host = host
        self.user = user
        self.interactive = interactive
        self.home = "/root" if user == "root" else host.user(user).home
        self.cwd = cwd or self.home
        self.now = now
        self.src_ip = src_ip
        self.argv0 = ""
        self.work = 0                       # see MAX_WORK
        self.stage_out = 0                  # characters the current command produced
        self.failed: Optional[list[str]] = None   # the command that could not be evaluated
        self._files: dict[str, Optional[str]] = {}
        self.memo: dict = {}                # seeded values reused within the line

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

    def run(self, line: str) -> Optional[Answer]:
        try:
            self.charge(len(line) * STEP)
            items = _parse(line)
            out, size, status, stateless = [], 0, 0, True
            for joiner, pipeline in items:
                if (joiner == "&&" and status != 0) or (joiner == "||" and status == 0):
                    continue
                result = self._pipeline(pipeline)
                out.append(result.err + result.out)
                size += len(out[-1])
                if size > MAX_OUTPUT:
                    raise _OverBudget
                status = result.status
                stateless = stateless and result.stateless
        except _OverBudget:
            self.failed = None
            return None
        except _Unsupported:
            return None
        return Answer("".join(out), status, stateless)

    def _pipeline(self, pipeline: list[list[str]]) -> _Result:
        stdin: Optional[str] = None
        errors, stateless, result = [], True, _Result()
        for index, argv in enumerate(pipeline):
            result = self._command(argv, stdin if index else None)
            errors.append(result.err)
            stateless = stateless and result.stateless
            stdin = result.out
        return _Result(result.out, "".join(errors), result.status, stateless)

    def resolve(self, word: str) -> Optional[str]:
        """The command a word runs: its name, or None for a path outside the bin dirs."""
        if "/" not in word:
            return word
        directory, name = posixpath.split(posixpath.normpath(word))
        return name if directory in BIN_DIRS else None

    def installed(self, name: str) -> bool:
        if name == "nvidia-smi":
            return bool(self.host.hardware.gpu)
        if name == "busybox":
            return self.host.busybox is not None
        return name in self.host.bins() or name in _COMMANDS

    def _command(self, argv: list[str], stdin: Optional[str]) -> _Result:
        self.stage_out = 0
        self.charge(COMMAND + STEP * len(argv))
        word = argv[0]
        name = self.resolve(word)
        if name is None:
            raise _Unsupported
        if not self.installed(name):
            if "/" in word:
                return _Result(err=f"{self.prefix}: {word}: No such file or directory\n",
                               status=127)
            if name in ("nvidia-smi", "busybox"):
                return _Result(err=f"{self.prefix}: {word}: command not found\n", status=127)
        entry = _COMMANDS.get(name)
        if entry is None:
            self.failed = argv
            raise _Unsupported
        handler, stateless = entry
        self.argv0 = name
        result = handler(self, argv[1:], stdin)
        if result is None:
            self.failed = argv
            raise _Unsupported
        produced = len(result.out) + len(result.err)
        if produced > MAX_STAGE_OUTPUT:
            raise _OverBudget
        self.charge(max(0, produced - self.stage_out))   # what grow() has not charged yet
        result.stateless = result.stateless and stateless
        return result

    # -- helpers --

    def read_file(self, path: str) -> Optional[_Result]:
        """A virtual file's content, or an error result, or None when unknown."""
        path = posixpath.normpath(posixpath.join(self.cwd, path))
        if path not in self._files:
            maker = _FILES.get(path)
            self._files[path] = maker(self) if maker is not None else None
        text = self._files[path]
        if text is not None:
            return _Result(text, stateless=path != "/etc/passwd")
        if path in _ABSENT.get(self.host.family, ()):
            return _Result(status=1, err=f"{{cmd}}: {path}: No such file or directory\n")
        return None

    def unhandled(self, line: str) -> str:
        """The reply to a line ``run`` could not evaluate: the failing tool's own error for an
        option or file it does not know, nothing when a known command was used in a way this
        shell cannot reproduce, and ``command not found`` only for an unknown command."""
        if self.failed is not None:
            name = self.resolve(self.failed[0])
            if name is not None and self.installed(name):
                return _tool_error(self, name, self.failed[1:])
        word = clean_word(line)
        name = self.resolve(word)
        if name is None or self.installed(name) or name in SHELL_BUILTINS:
            return ""
        return f"{self.prefix}: {word}: command not found\n"


def answer(host: Host, line: str, *, user: str = "root", interactive: bool = True,
           cwd: Optional[str] = None, now: Optional[float] = None,
           src_ip: Optional[str] = None) -> Optional[Answer]:
    """The deterministic answer to one input line, or None when it needs a real shell."""
    return _shell(host, user, interactive, cwd, now, src_ip).run(line.strip())


def _shell(host: Host, user: str, interactive: bool, cwd: Optional[str], now: Optional[float],
           src_ip: Optional[str]) -> Shell:
    import time

    user = "".join(c for c in (user or "root") if c.isprintable() and c not in ":/ ")[:32] \
        or "root"
    return Shell(host, user, interactive, cwd, time.time() if now is None else now, src_ip)


def reply(host: Host, text: str, *, user: str = "root", interactive: bool = True,
          cwd: Optional[str] = None, now: Optional[float] = None,
          src_ip: Optional[str] = None) -> str:
    """The canned shell's full reply (no prompt, ``\\n`` endings): the deterministic answer,
    a builtin's own output (or none), a known tool's own error (or nothing), otherwise
    ``command not found``."""
    word = clean_word(text)
    if not word:
        return ""
    sh = _shell(host, user, interactive, cwd, now, src_ip)
    result = sh.run(text.strip())
    if result is not None:
        return result.output
    if word in SHELL_BUILTINS:
        return literal_output(text) or ""
    return sh.unhandled(text)


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


def _columns(names: list[str], width: int = 80) -> str:
    """``ls`` output on a terminal: names in columns, filled top to bottom."""
    if not names:
        return ""
    best = [names]
    for cols in range(len(names), 0, -1):
        rows = math.ceil(len(names) / cols)
        grid = [names[c * rows:(c + 1) * rows] for c in range(cols)]
        if not grid[-1]:
            continue
        widths = [max(map(len, col)) for col in grid]
        if sum(widths) + 2 * (len(grid) - 1) <= width:
            best = grid
            break
    rows = len(best[0])
    widths = [max(map(len, col)) + 2 for col in best]
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
    return _Result(" ".join(values[k] for k in "snrvmpio" if k in wanted) + "\n")


@_command("hostname")
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


@_command("whoami")
def _whoami(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return None if args else _Result(sh.user + "\n")


@_command("id")
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
    return f" {clock} up {span},  1 user,  load average: {l1:.2f}, {l5:.2f}, {l15:.2f}\n"


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


@_command("w")
def _w(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if args:
        return None
    login = sh.host.local(sh.now - 60).strftime("%H:%M")
    src = (sh.src_ip or "-")[:16]
    return _Result(_uptime_line(sh)
                   + "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                   + f"{sh.user[:8]:<9}{'pts/0':<9}{src:<17}{login:<8}{'0.00s':>6}"
                     f"{'0.02s':>7}{'0.00s':>7} w\n")


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


@_command("df")
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
    login = h.local(sh.now - 60).strftime("%H:%M")
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
    base = pid + 5000 + r.randrange(5000)
    tty = "pts/0"
    user = sh.user[:8] if len(sh.user) <= 8 else sh.user[:7] + "+"
    out += [("root", base, out[-1][1], 0.0, 0.2, 17000, 10900, "?", "Ss", login, "0:00",
             f"sshd: {sh.user} [priv]"),
            (user, base + 99, base, 0.0, 0.1, 9100, 5400, tty, "Ss", login, "0:00", "-bash")]
    return out


@_command("ps")
def _ps(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    procs = _processes(sh)
    mine = procs[-1]
    joined = "".join(args)
    if not args:
        return _Result(f"    PID TTY          TIME CMD\n{mine[1]:>7} {mine[7]:<8} 00:00:00 bash\n"
                       f"{mine[1] + 50:>7} {mine[7]:<8} 00:00:00 ps\n", stateless=False)
    rows = procs + [(mine[0], mine[1] + 50, mine[1], 0.0, 0.0, 11300, 4600, mine[7], "R+",
                     mine[9], "0:00", "ps " + " ".join(args))]
    if len(args) == 1 and joined.lstrip("-") in ("aux", "auxw", "auxww", "axu"):
        out = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
        for p in rows:
            out.append(f"{p[0]:<8} {p[1]:>7} {p[3]:>4.1f} {p[4]:>4.1f} {p[5]:>6} {p[6]:>5} "
                       f"{p[7]:<8} {p[8]:<4} {p[9]:>5} {p[10]:>6} {p[11]}")
        return _Result("\n".join(out) + "\n", stateless=False)
    if args in (["-ef"], ["-e", "-f"], ["-aef"]):
        out = ["UID          PID    PPID  C STIME TTY          TIME CMD"]
        for p in rows:
            minutes = int(p[10].split(":")[0]) * 60 + int(p[10].split(":")[1])
            out.append(f"{p[0]:<8} {p[1]:>7} {p[2]:>7} {0:>2} {p[9]:<5} {p[7]:<8} "
                       f"{'00:%02d:%02d' % divmod(minutes, 60):>8} {p[11]}")
        return _Result("\n".join(out) + "\n", stateless=False)
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
    """Read file operands: ([(name, text)], errors, status, stateless); None if unknown."""
    if len(args) > MAX_FILES:
        return None
    out, errors, status, stateless = [], "", 0, True
    for name in args:
        result = sh.read_file(name)
        if result is None:
            return None
        sh.charge(len(result.out) + STEP)
        if result.err:
            errors += result.err.replace("{cmd}", command).replace(
                posixpath.normpath(posixpath.join(sh.cwd, name)), name)
            status = result.status
            continue
        stateless = stateless and result.stateless
        out.append((name, result.out))
    return out, errors, status, stateless


@_command("cat")
def _cat(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if any(a.startswith("-") and a != "-" for a in args):
        return None
    if not args or args == ["-"]:
        return None if stdin is None else _Result(stdin)
    read = _files(sh, args, "cat")
    if read is None:
        return None
    files, errors, status, stateless = read
    for _, text in files:
        sh.grow(len(text))
    return _Result("".join(text for _, text in files), errors, status, stateless)


# ---- filters ----------------------------------------------------------------------------------

def _input(sh: Shell, files: list[str], stdin: Optional[str], command: str):
    """(texts with names, errors, status, stateless) from file operands or stdin."""
    if not files:
        if stdin is None:
            return None                      # would wait on the terminal
        sh.charge(len(stdin))
        return [("", stdin)], "", 0, True
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
    texts, errors, status, stateless = read
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
    return _Result("".join(out), errors, 2 if status else (0 if total else 1), stateless)


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
    texts, errors, status, stateless = read
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
    return _Result("".join(out), errors, status, stateless)


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
    texts, errors, status, stateless = read
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
    return _Result("".join(out), errors, status, stateless)


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
    texts, errors, status, stateless = read

    def counts(text: str) -> dict[str, int]:
        sh.charge(4 * len(text))
        return {"l": text.count("\n"), "w": len(text.split()), "m": len(text),
                "c": len(text.encode("utf-8"))}

    rows = [(name, counts(text)) for name, text in texts]
    if len(rows) > 1:
        rows.append(("total", {k: sum(r[1][k] for r in rows) for k in "lwmc"}))
    if not files and len(order) == 1:
        return _Result(f"{rows[0][1][order[0]]}\n", errors, status, stateless)
    width = 7 if not files else max(len(str(r[1][k])) for r in rows for k in order)
    out = []
    for name, c in rows:
        cells = " ".join(f"{c[k]:>{width}}" for k in order)
        out.append(cells + (f" {name}" if name else "") + "\n")
    return _Result("".join(out), errors, status, stateless)


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
    texts, errors, status, stateless = read
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
    return _Result("".join(out), errors, status, stateless)


@_command("sh", "bash")
def _sh(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    """A shell fed nothing (a failed download piped into it) prints nothing; ``sh`` typed
    as a botnet opener starts a subshell that looks the same."""
    if args or stdin:
        return None
    return _Result(stateless=False)


# ---- builtins and navigation (session state: never answered ahead of a model) ---------------

def _dirs(sh: Shell) -> dict[str, list[str]]:
    """Directories ``ls`` and ``cd`` know, with their visible entries."""
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
    return {k: sorted(v, key=lambda s: s.lower().lstrip("._")) for k, v in out.items()}


def _denied(sh: Shell, path: str) -> bool:
    return sh.user != "root" and (path == "/root" or path.startswith("/root/"))


@_command("ls", stateless=False)
def _ls(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    one = False
    paths = []
    for arg in args:
        if arg == "-1":
            one = True
        elif arg.startswith("-"):
            return None
        else:
            paths.append(posixpath.normpath(posixpath.join(sh.cwd, arg)))
    dirs = _dirs(sh)
    paths = paths or [sh.cwd]
    out, err, status = [], "", 0
    for index, path in enumerate(paths):
        if _denied(sh, path):
            err += f"ls: cannot open directory '{path}': Permission denied\n"
            status = 2
            continue
        if path not in dirs:
            return None
        names = dirs[path]
        listing = "\n".join(names) + "\n" if (one or not sh.interactive) and names else \
            _columns(names)
        if len(paths) > 1:
            listing = ("\n" if index else "") + f"{path}:\n" + listing
        out.append(listing)
    return _Result("".join(out), err, status)


@_command("cd", stateless=False)
def _cd(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if len(args) > 1:
        return _Result(err=f"{sh.prefix}: cd: too many arguments\n", status=1)
    target = sh.home if not args or args == ["~"] else \
        posixpath.normpath(posixpath.join(sh.cwd, args[0]))
    if _denied(sh, target):
        return _Result(err=f"{sh.prefix}: cd: {args[0]}: Permission denied\n", status=1)
    if target not in _dirs(sh) and target not in ("/etc", "/usr", "/var", "/proc", "/dev",
                                                   "/run", "/sys", "/boot"):
        return None
    sh.cwd = target
    return _Result()


@_command("pwd", stateless=False)
def _pwd(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return None if args else _Result(sh.cwd + "\n")


@_command("true", ":", "export", "unset", "history", stateless=False)
def _quiet(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return _Result()


@_command("false", stateless=False)
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
                out.append(chr(int(digits, 16)))
                i += 2 + len(digits)
        elif nxt == "0":
            digits = _leading(text[i + 2:i + 5], "01234567")
            out.append(chr(int(digits or "0", 8)))
            i += 2 + len(digits)
        else:
            out.append("\\" + nxt)
            i += 2
    return "".join(out), False


@_command("echo", stateless=False)
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
    return _Result("".join(c for c in text if c.isprintable() or c in "\n\t")[:MAX_ECHO_OUTPUT])


# ---- lookups, busybox and downloads -----------------------------------------------------------

@_command("which")
def _which(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if not args or any(a.startswith("-") for a in args):
        return None
    bins = sh.host.bins()
    found = [bins[a] for a in args if a in bins]
    return _Result("".join(p + "\n" for p in found), status=0 if len(found) == len(args) else 1)


@_command("command")
def _command_v(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if len(args) < 2 or args[0] != "-v":
        return None
    bins = sh.host.bins()
    out = [bins.get(a) or (a if a in SHELL_BUILTINS else None) for a in args[1:]]
    return _Result("".join(p + "\n" for p in out if p), status=0 if all(out) else 1)


@_command(*OPENERS - {"sh", "bash", "enable"})
def _opener(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return None if args else _Result()


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
_APPLETS = frozenset(("cat", "echo", "uname", "id", "whoami", "hostname", "nproc", "free",
                      "df", "ps", "ls", "wget", "tftp", "head", "tail", "cut", "wc", "grep",
                      "awk", "uptime", "sh", "true", "false", "pwd", "cd"))


@_command("busybox")
def _busybox(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    if sh.host.busybox is None:
        return None
    if not args:
        return _Result(_BUSYBOX_BANNER.format(version=sh.host.busybox))
    applet = args[0]
    if applet in _APPLETS:
        entry = _COMMANDS.get(applet)
        if entry is None:
            return None
        sh.argv0 = applet
        result = entry[0](sh, args[1:], stdin)
        if result is not None:
            result.stateless = result.stateless and entry[1]
        return result
    if applet.startswith("-"):
        return None
    name = "".join(c for c in applet if c.isprintable())[:64]
    return _Result(err=f"{name}: applet not found\n", status=127)


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
    parts = urllib.parse.urlsplit(shown)
    try:
        port = parts.port or {"https": 443, "ftp": 21}.get(parts.scheme, 80)
    except ValueError:
        port = 80
    return _url_text(shown), _url_text(parts.hostname or ""), port


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", host)) or ":" in host


@_command("wget", stateless=False)
def _wget(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    url, quiet = _url(args, {"-O", "-o", "-P", "-U", "-t", "-T", "-e", "--output-document",
                             "--user-agent", "--directory-prefix", "--tries", "--timeout"})
    if url is None:
        return _Result(err="wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\n"
                           "Try `wget --help' for more options.\n", status=1)
    shown, host, port = _target(url)
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


@_command("curl", stateless=False)
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


@_command("tftp", stateless=False)
def _tftp(sh: Shell, args: list[str], stdin) -> Optional[_Result]:
    return _Result(err="Transfer timed out.\n\n", status=1) if args else None


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
        known = set(_dirs(sh)) | {"/etc", "/usr", "/var", "/proc", "/dev", "/run", "/sys",
                                  "/boot", "-"}
        lures = {posixpath.normpath(p) for p in sh.host.lures}
        out = []
        for path in operands[skip:skip + MAX_FILES]:
            full = posixpath.normpath(posixpath.join(sh.cwd, path))
            shown_path = "".join(c for c in path if c.isprintable())[:256]
            if full in known and name not in ("ls", "df"):
                out.append(f"{shown}: {shown_path}: Is a directory\n")
            elif full not in known and full not in lures and full not in _FILES:
                out.append(_missing(sh, shown, shown_path))
        return "".join(out)
    return ""
