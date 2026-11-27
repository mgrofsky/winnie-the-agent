"""FTP trap: vsftpd-like server with a fake in-memory tree after login.

Passive mode only. PASV/EPSV open a listener on ``ctx.bind_host`` (first free port of
``ctx.ftp_pasv_ports``, or an ephemeral port) that accepts exactly one connection, only
from the control connection's source IP, with a timeout. The 227 reply advertises
``ctx.ftp_pasv_address`` or else the control connection's local address, never the bind
address. PORT/EPRT are refused with vsftpd's own replies (what a client behind NAT gets
from it), so the honeypot never connects out.

Replies follow the banner's server family: vsftpd by default, ProFTPD when the banner names
it (HELP, STAT, ALLO, SITE and RMD answers).

STOR streams to the capped quarantine (``ctx.quarantine``) while reading. Upload bytes are
bounded by the quarantine caps, not the control connection's byte cap: an upload over the
per-file cap is cut at the cap, stored and logged as truncated (size and SHA-256 of the part
kept); over a per-source or total quota reading stops and nothing is kept. With no
quarantine configured, upload bytes count toward the connection byte cap. Nothing else
writes attacker bytes.

An unused passive listener closes after ``ftp_pasv_accept_timeout`` seconds, and a source
may hold at most ``ftp_pasv_per_ip`` open passive listeners.
"""

from __future__ import annotations

import asyncio
import hashlib
import struct
import gzip
import ipaddress
import posixpath
import re
from dataclasses import dataclass
from typing import Optional

from agents.budget import ip_key
from listeners.base import (ConnClosed, Conn, ListenerContext, QuarantineResult,
                            ServiceSettings, start_tcp)

DEFAULT_BANNER = "(vsFTPd 3.0.5)"
DEFAULT_MTIME = "2026-03-02 09:14"
MAX_SESSION_ENTRIES = 500         # files and directories per session, parents included
MAX_PATH_DEPTH = 32               # path components per file or directory
KEEP_UPLOAD_BYTES = 65536          # uploads kept in memory (per session) to echo on RETR
DATA_CHUNK = 65536
DEFAULT_TREE = {
    "/pub/README.txt": "Public file area. Contact the administrator for access to other areas.\n",
    "/backup/.keep": "",
    "/upload/.keep": "",
}
FEATURES = ["EPSV", "MDTM", "PASV", "REST STREAM", "SIZE", "TVFS", "UTF8",
            "MLST type*;size*;modify*;perm*;"]
VSFTPD_HELP = ("214-The following commands are recognized.\r\n"
               " ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n"
               " MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n"
               " RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n"
               " XPWD XRMD\r\n"
               "214 Help OK.\r\n")
PROFTPD_COMMANDS = ("CWD XCWD CDUP XCUP SMNT* QUIT PORT PASV EPRT EPSV ALLO* RNFR RNTO DELE "
                    "MDTM RMD XRMD MKD XMKD PWD XPWD SIZE SYST HELP NOOP FEAT OPTS HOST CLNT "
                    "AUTH* CCC* CONF* ENC* MIC* PBSZ* PROT* TYPE STRU MODE RETR STOR STOU APPE "
                    "REST ABOR RANG USER PASS ACCT* REIN* LIST NLST STAT SITE MLSD MLST").split()
VSFTPD_VERSION_RE = re.compile(r"vsftpd\s+(\d{1,2}\.\d{1,2}\.\d{1,2})", re.IGNORECASE)
PROFTPD_NAME_RE = re.compile(r"proftpd[^()]*\(([\x20-\x27\x2a-\x7e]{1,64})\)", re.IGNORECASE)


@dataclass
class Entry:
    content: Optional[bytes]
    size: int
    mtime: str
    uploaded: bool = False      # RETR returns the full stored size, not the scenario cap


class Tree:
    """Per-session fake filesystem. Directories are implied by file paths plus ``dirs``."""

    def __init__(self, files: dict[str, Entry]) -> None:
        self.files = files
        self.dirs: set[str] = {"/"}
        for path in files:
            self._add_parents(path)

    def _missing_parents(self, path: str) -> list[str]:
        out = []
        parent = posixpath.dirname(path)
        while parent and parent not in self.dirs:
            out.append(parent)
            parent = posixpath.dirname(parent)
        return out

    def _add_parents(self, path: str) -> None:
        self.dirs.update(self._missing_parents(path))
        self.dirs.add("/")

    def _fits(self, path: str, new_entries: list[str]) -> bool:
        """Within the depth limit, and the session cap still holds with the new entries."""
        if path.count("/") > MAX_PATH_DEPTH:
            return False
        return len(self.files) + len(self.dirs) + len(new_entries) <= MAX_SESSION_ENTRIES

    def add_file(self, path: str, entry: Entry) -> bool:
        if path not in self.files:
            missing = self._missing_parents(path)
            if not self._fits(path, missing + [path]):
                return False
        self.files[path] = entry
        self._add_parents(path)
        return True

    def add_dir(self, path: str) -> bool:
        """Create a directory and its missing parents, or nothing at all (cap or depth)."""
        missing = [path] + self._missing_parents(path)
        if not self._fits(path, missing):
            return False
        self.dirs.update(missing)
        return True

    def listing(self, d: str) -> list[tuple[str, bool, Optional[Entry]]]:
        out: list[tuple[str, bool, Optional[Entry]]] = []
        for sub in sorted(self.dirs):
            if sub != "/" and posixpath.dirname(sub) == d:
                out.append((posixpath.basename(sub), True, None))
        for path, entry in sorted(self.files.items()):
            name = posixpath.basename(path)
            if posixpath.dirname(path) == d and name != ".keep":
                out.append((name, False, entry))
        return out


def _gen_size(path: str) -> int:
    return 512 + int.from_bytes(hashlib.sha256(path.encode()).digest()[:2], "big") % 30000


AWS_CREDENTIALS_PATH = "/.aws/credentials"


def aws_profile(name: str, key_id: str, secret: str) -> str:
    return (f"[{name}]\naws_access_key_id = {key_id}\naws_secret_access_key = {secret}\n"
            "region = us-east-1\n")


def plant_source_token(ctx: ListenerContext, files: dict[str, "Entry"], ip: str) -> None:
    """Sources marked ``plant_token`` see an AWS credentials file holding their own token."""
    entry = ctx.source(ip)
    if entry is None or not entry.plant_token:
        return
    key_id, secret = ctx.source_token(ip)
    existing = files.get(AWS_CREDENTIALS_PATH)
    if existing is not None and existing.content:
        base = existing.content.rstrip(b"\n") + b"\n\n"
        content = base + aws_profile("backup", key_id, secret).encode()
    else:
        content = aws_profile("default", key_id, secret).encode()
    files[AWS_CREDENTIALS_PATH] = Entry(content, len(content), DEFAULT_MTIME)


def build_tree(ctx: ListenerContext, ip: Optional[str] = None) -> Tree:
    files: dict[str, Entry] = {}
    sc = ctx.scenario
    svc = sc.scenario.services.ftp if sc is not None else None
    if svc is not None:
        for f in svc.files:
            content = f.content.encode("utf-8") if f.content is not None else None
            size = f.size if f.size is not None else (len(content) if content is not None
                                                       else _gen_size(f.path))
            files[f.path] = Entry(content, size, f.mtime or DEFAULT_MTIME)
    if sc is not None:
        for p in sc.lures():
            files.setdefault(p, Entry(None, _gen_size(p), DEFAULT_MTIME))
    if not files:
        for p, text in DEFAULT_TREE.items():
            files[p] = Entry(text.encode(), len(text), DEFAULT_MTIME)
    if ip is not None:
        plant_source_token(ctx, files, ip)
    return Tree(files)


def _pseudo_random(seed: str, n: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}|{i}".encode()).digest()
        i += 1
    return bytes(out[:n])


def _binary_content(seed: str, name: str, size: int) -> Optional[bytes]:
    """Files whose extension promises a binary format get that format's real structure, so
    `file`, `gzip -t` or an audio player do not immediately show them to be fake."""
    lower = name.lower()
    if lower.endswith((".gz", ".tgz")):
        # Stored (level 0) gzip of pseudo-random bytes: valid stream, size close to `size`.
        overhead = 18 + 5 * (size // 65535 + 1)
        return gzip.compress(_pseudo_random(seed, max(0, size - overhead)), compresslevel=0,
                             mtime=0)[:size]
    if lower.endswith(".wav"):
        pcm = _pseudo_random(seed, max(0, size - 44))
        header = (b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVEfmt "
                  + struct.pack("<IHHIIHH", 16, 1, 1, 8000, 16000, 2, 16)
                  + b"data" + struct.pack("<I", len(pcm)))
        return (header + pcm)[:size]
    return None


def generate_content(ctx: ListenerContext, path: str, size: int) -> bytes:
    """Deterministic, plausible content for files that have no scenario content."""
    name = posixpath.basename(path)
    binary = _binary_content(hashlib.sha256(f"{ctx.seed}|ftpbin|{path}".encode()).hexdigest(),
                             name, size)
    if binary is not None:
        return binary
    host = ctx.scenario.hostname if ctx.scenario is not None else "srv01"
    seed = hashlib.sha256(f"{ctx.seed}|ftp|{path}".encode()).hexdigest()
    lines = [f"# {name}", f"# generated on {host} {DEFAULT_MTIME}", ""]
    total = sum(len(x) + 1 for x in lines)
    i = 0
    while total < size:
        h = hashlib.sha256(f"{seed}|{i}".encode()).hexdigest()
        line = f"{h[:8]} {h[8:12]} entry_{i:05d} status=ok ref={h[12:28]}"
        lines.append(line)
        total += len(line) + 1
        i += 1
    return ("\n".join(lines) + "\n").encode()[:size]


def _mtime_parts(mtime: str) -> tuple[str, str]:
    """('Mar 02 09:14', '20260302091400') from 'YYYY-MM-DD[ HH:MM]'."""
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    date, _, clock = mtime.partition(" ")
    y, mo, d = date.split("-")
    clock = clock or "00:00"
    return (f"{months[int(mo) - 1]} {d} {clock}", f"{y}{mo}{d}{clock.replace(':', '')}00")


def _mlst_facts(is_dir: bool, size: int, mtime: str) -> str:
    """RFC 3659 facts for MLSD/MLST, as advertised in FEAT."""
    kind, perm = ("dir", "flcdmpe") if is_dir else ("file", "adfrw")
    return f"type={kind};size={size};modify={_mtime_parts(mtime)[1]};perm={perm};"


def _plain_ip(value: str) -> str:
    """Normalise an address for comparison (IPv4-mapped IPv6 -> IPv4, scope dropped)."""
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return value
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ip)


def same_source(peer_ip: str, control_ip: str) -> bool:
    """A data connection is accepted only from the control connection's source address."""
    return _plain_ip(str(peer_ip)) == _plain_ip(str(control_ip))


def eprt_refusal(arg: str, local_ipv6: bool) -> str:
    """vsftpd's reply to an EPRT it does not follow: the parse error for a malformed
    argument, otherwise the bounce-protection refusal."""
    parts = arg.split("|", 4)
    if len(parts) < 2 or parts[0]:
        return "500 Bad EPRT command."
    proto = parts[1].split("|")[0]
    if proto not in ("1", "2") or (proto == "2" and not local_ipv6):
        return "500 Bad EPRT protocol."
    if len(parts) != 5 or parts[4]:
        return "500 Bad EPRT command."
    try:
        ip = ipaddress.ip_address(parts[2].split("%", 1)[0])
    except ValueError:
        return "500 Bad EPRT command."
    if ip.version != (4 if proto == "1" else 6):
        return "500 Bad EPRT command."
    if not parts[3].isdigit() or len(parts[3]) > 5 or int(parts[3]) > 65535:
        return "500 Bad EPRT command."
    return "500 Illegal EPRT command."


def pasv_host(conn: Conn) -> Optional[str]:
    """The IPv4 address for a 227 reply: configured, else the control connection's local
    address (what the client actually reached, e.g. the published host address)."""
    for candidate in (conn.ctx.ftp_pasv_address, conn.dst_ip):
        if not candidate:
            continue
        plain = _plain_ip(candidate)
        try:
            if ipaddress.ip_address(plain).version == 4 and plain != "0.0.0.0":  # noqa: S104 - compares an address, binds nothing
                return plain
        except ValueError:
            continue
    return None


class Passive:
    """One-shot passive data listener, same source IP only.

    The listener counts toward the source's ``ftp_pasv_per_ip`` slots until it accepts its
    connection or closes; unused, it closes after ``ftp_pasv_accept_timeout`` seconds."""

    def __init__(self, conn: Conn) -> None:
        self.conn = conn
        self.server: Optional[asyncio.base_events.Server] = None
        self.ready: asyncio.Future = asyncio.get_running_loop().create_future()
        self.port = 0
        self.key = ip_key(conn.src_ip)
        self.timer: Optional[asyncio.TimerHandle] = None

    @staticmethod
    def slots_full(conn: Conn) -> bool:
        return conn.ctx.ftp_pasv_open.get(ip_key(conn.src_ip), 0) >= conn.ctx.limits.ftp_pasv_per_ip

    async def open(self) -> Optional[int]:
        """Bind the first free port of the configured range (ephemeral when none is set).
        None when every port of the range is busy."""
        host = self.conn.ctx.bind_host
        ports = self.conn.ctx.ftp_pasv_ports
        candidates = range(ports[0], ports[1] + 1) if ports else (0,)
        for port in candidates:
            try:
                self.server = await asyncio.start_server(self._accept, host=host, port=port)
            except OSError:
                continue
            self.port = self.server.sockets[0].getsockname()[1]
            pending = self.conn.ctx.ftp_pasv_open
            pending[self.key] = pending.get(self.key, 0) + 1
            self.timer = asyncio.get_running_loop().call_later(
                self.conn.ctx.limits.ftp_pasv_accept_timeout, self._expire)
            return self.port
        return None

    def _expire(self) -> None:
        if not self.ready.done():
            self.ready.set_result(None)     # a later transfer command gets 425 at once
        self.close_listener()

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("-",)
        if not same_source(str(peer[0]), self.conn.src_ip) or self.ready.done():
            suppressed = self.conn.ctx.gate.check(f"{peer[0]}|ftp|pasv_foreign_peer")
            if suppressed is not None:
                self.conn.emit("limit", "Passive connection refused",
                               data={"reason": "pasv_foreign_peer", "peer": str(peer[0]),
                                     "suppressed": suppressed})
            writer.close()
            return
        self.ready.set_result((reader, writer))
        self.close_listener()

    async def wait(self) -> Optional[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        try:
            return await asyncio.wait_for(asyncio.shield(self.ready),
                                          timeout=min(self.conn.timeout, 30.0))
        except asyncio.TimeoutError:
            return None
        finally:
            self.close_listener()

    def close_listener(self) -> None:
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None
        if self.server is not None:
            self.server.close()
            self.server = None
            pending = self.conn.ctx.ftp_pasv_open
            left = pending.get(self.key, 0) - 1
            if left > 0:
                pending[self.key] = left
            else:
                pending.pop(self.key, None)

    def close(self) -> None:
        self.close_listener()
        if self.ready.done() and not self.ready.cancelled():
            try:
                pair = self.ready.result()
                if pair is not None:
                    pair[1].close()
            except Exception:  # noqa: BLE001, S110 - best-effort cleanup
                pass
        elif not self.ready.done():
            self.ready.cancel()


class FtpSession:
    def __init__(self, conn: Conn, settings: ServiceSettings) -> None:
        self.conn = conn
        self.ctx = conn.ctx
        self.settings = settings
        self.user: Optional[str] = None
        self.logged_in = False
        self.cwd = "/"
        self.tree: Optional[Tree] = None
        self.passive: Optional[Passive] = None
        self.rnfr: Optional[str] = None
        self.ascii = True             # TYPE as STAT reports it
        svc = self.ctx.scenario.scenario.services.ftp if self.ctx.scenario is not None else None
        self.retr_max = svc.retr_max_bytes if svc is not None else 65536
        banner = settings.banner or DEFAULT_BANNER
        self.family = "proftpd" if "proftpd" in banner.lower() else "vsftpd"
        m = VSFTPD_VERSION_RE.search(banner)
        self.vsftpd_version = m.group(1) if m else "3.0.5"
        m = PROFTPD_NAME_RE.search(banner)
        self.server_name = m.group(1).strip() if m else "ProFTPD Default Installation"
        host = self.ctx.scenario.hostname if self.ctx.scenario is not None else "localhost"
        self.admin = f"root@{host}"

    async def reply(self, text: str) -> None:
        await self.conn.write(text + "\r\n")

    def path(self, arg: str) -> str:
        p = posixpath.normpath(posixpath.join(self.cwd, arg or "."))
        return "/" + p.lstrip("/") if p != "/" else "/"

    async def run(self) -> None:
        banner = self.settings.banner or DEFAULT_BANNER
        await self.reply(banner if banner.startswith("220") else f"220 {banner}")
        try:
            while True:
                raw = await self.conn.readline()
                if not self.conn.command():
                    await self.reply("421 Too many commands, closing control connection.")
                    return
                line = raw.decode("utf-8", errors="replace")
                cmd, _, arg = line.strip().partition(" ")
                cmd = cmd.upper()
                self.conn.emit("command", "FTP command",
                               username=self.user, data={"input": line, "cmd": cmd[:16]})
                self.conn.capture("ftp_command", raw)
                if not await self.dispatch(cmd, arg.strip()):
                    return
        finally:
            if self.passive is not None:
                self.passive.close()

    async def dispatch(self, cmd: str, arg: str) -> bool:
        if cmd == "QUIT":
            await self.reply("221 Goodbye.")
            return False
        if cmd == "USER":
            if self.logged_in:
                await self.reply("530 Can't change to another user.")
            else:
                self.user = arg
                await self.reply("331 Please specify the password.")
            return True
        if cmd == "PASS":
            if self.logged_in:
                await self.reply("230 Already logged in.")
            elif self.user is None:
                await self.reply("503 Login with USER first.")
            elif self.conn.login(self.user, arg):
                self.logged_in = True
                self.tree = build_tree(self.ctx, self.conn.src_ip)
                await self.reply("230 Login successful.")
            else:
                await self.reply("530 Login incorrect.")
            return True
        simple = {"SYST": "215 UNIX Type: L8", "NOOP": "200 NOOP ok.",
                  "OPTS": "200 Always in UTF8 mode.", "ABOR": "225 No transfer to ABOR."}
        if cmd in simple:
            await self.reply(simple[cmd])
            return True
        if cmd == "FEAT":
            await self.conn.write("211-Features:\r\n" + "".join(f" {f}\r\n" for f in FEATURES)
                                  + "211 End\r\n")
            return True
        if not self.logged_in:
            await self.reply("530 Please login with USER and PASS.")
            return True
        await self.post_login(cmd, arg)
        return True

    async def post_login(self, cmd: str, arg: str) -> None:
        tree = self.tree
        assert tree is not None
        if cmd in ("PWD", "XPWD"):
            await self.reply(f'257 "{self.cwd}" is the current directory')
        elif cmd in ("CWD", "XCWD"):
            target = self.path(arg)
            if target in tree.dirs:
                self.cwd = target
                await self.reply("250 Directory successfully changed.")
            else:
                await self.reply("550 Failed to change directory.")
        elif cmd in ("CDUP", "XCUP"):
            self.cwd = posixpath.dirname(self.cwd) or "/"
            await self.reply("250 Directory successfully changed.")
        elif cmd == "TYPE":
            self.ascii = arg.upper().startswith("A")
            mode = "ASCII" if self.ascii else "Binary"
            await self.reply(f"200 Switching to {mode} mode.")
        elif cmd in ("MODE", "STRU"):
            await self.reply("200 Mode set to S." if cmd == "MODE" else "200 Structure set to F.")
        elif cmd == "REST":
            await self.reply(f"350 Restart position accepted ({arg[:20] or '0'}).")
        elif cmd in ("PORT", "EPRT"):
            self.conn.emit("command", "FTP active mode refused",
                           data={"cmd": cmd, "arg": arg, "signal": "ftp_active_mode"})
            await self.port(cmd, arg)
        elif cmd in ("PASV", "EPSV"):
            await self.open_passive(cmd)
        elif cmd in ("LIST", "NLST", "MLSD"):
            await self.send_listing(cmd, arg)
        elif cmd == "SIZE":
            entry = tree.files.get(self.path(arg))
            await self.reply(f"213 {entry.size}" if entry else "550 Could not get file size.")
        elif cmd == "MDTM":
            entry = tree.files.get(self.path(arg))
            await self.reply(f"213 {_mtime_parts(entry.mtime)[1]}" if entry
                             else "550 Could not get file modification time.")
        elif cmd == "RETR":
            await self.retr(arg)
        elif cmd in ("STOR", "APPE", "STOU"):
            await self.stor(cmd, arg)
        elif cmd == "DELE":
            p = self.path(arg)
            if tree.files.pop(p, None) is not None:
                await self.reply("250 Delete operation successful.")
            else:
                await self.reply("550 Delete operation failed.")
        elif cmd in ("MKD", "XMKD"):
            p = self.path(arg)
            if p in tree.dirs or not tree.add_dir(p):
                await self.reply("550 Create directory operation failed.")
            else:
                await self.reply(f'257 "{p}" created')
        elif cmd in ("RMD", "XRMD"):
            await self.rmd(arg)
        elif cmd == "RNFR":
            p = self.path(arg)
            if p in tree.files or p in tree.dirs:
                self.rnfr = p
                await self.reply("350 Ready for RNTO.")
            else:
                await self.reply("550 RNFR command failed.")
        elif cmd == "RNTO":
            if self.rnfr is None:
                await self.reply("503 RNFR required first.")
                return
            src, dst = self.rnfr, self.path(arg)
            self.rnfr = None
            if src in tree.files:
                entry = tree.files.pop(src)
                if not tree.add_file(dst, entry):
                    tree.files[src] = entry
                    await self.reply("550 Rename failed.")
                    return
            else:
                tree.dirs.discard(src)
                tree.dirs.add(dst)
            await self.reply("250 Rename successful.")
        elif cmd == "MLST":
            p = self.path(arg)
            if p in tree.files:
                facts = _mlst_facts(False, tree.files[p].size, tree.files[p].mtime)
            elif p in tree.dirs:
                facts = _mlst_facts(True, 4096, DEFAULT_MTIME)
            else:
                await self.reply("550 Permission denied.")
                return
            await self.conn.write(f"250-Listing {p}\r\n {facts} {p}\r\n250 End\r\n")
        elif cmd == "SITE":
            await self.site(arg)
        elif cmd == "STAT" and not arg:
            await self.stat()
        elif cmd == "STAT":
            await self.reply("211 FTP server status: connected, logged in as " + (self.user or ""))
        elif cmd == "HELP":
            await self.help()
        elif cmd == "ALLO":
            await self.reply("202 No storage allocation necessary" if self.family == "proftpd"
                             else "202 ALLO command ignored.")
        elif cmd in ("AUTH", "PBSZ", "PROT"):
            await self.reply("530 Please login with USER and PASS.")
        else:
            await self.reply("500 Unknown command.")

    # ---- data connection -------------------------------------------------------------------

    async def open_passive(self, cmd: str) -> None:
        if self.passive is not None:
            self.passive.close()
            self.passive = None
        host = pasv_host(self.conn) if cmd == "PASV" else None
        if cmd == "PASV" and host is None:
            await self.reply("425 Use EPSV with IPv6.")
            return
        if Passive.slots_full(self.conn):
            suppressed = self.ctx.gate.check(f"{self.conn.src_ip}|ftp|ftp_pasv_per_ip")
            if suppressed is not None:
                self.conn.emit("limit", "Too many passive listeners for source",
                               data={"reason": "ftp_pasv_per_ip", "suppressed": suppressed})
            await self.reply("425 Could not listen for passive connection.")
            return
        passive = Passive(self.conn)
        port = await passive.open()
        if port is None:
            suppressed = self.ctx.gate.check(f"{self.conn.src_ip}|ftp|pasv_ports_busy")
            if suppressed is not None:
                self.conn.emit("limit", "No free passive port",
                               data={"reason": "pasv_ports_busy", "suppressed": suppressed})
            await self.reply("425 Could not listen for passive connection.")
            return
        self.passive = passive
        if cmd == "EPSV":
            await self.reply(f"229 Entering Extended Passive Mode (|||{port}|)")
            return
        assert host is not None
        h = host.replace(".", ",")
        await self.reply(f"227 Entering Passive Mode ({h},{port // 256},{port % 256}).")

    async def port(self, cmd: str, arg: str) -> None:
        """PORT/EPRT refused with vsftpd's replies. Like vsftpd, either one first drops a
        pending passive listener."""
        if self.passive is not None:
            self.passive.close()
            self.passive = None
        if cmd == "PORT":
            await self.reply("500 Illegal PORT command.")
            return
        local_ipv6 = ":" in _plain_ip(str(self.conn.dst_ip))
        await self.reply(eprt_refusal(arg, local_ipv6))

    async def rmd(self, arg: str) -> None:
        tree = self.tree
        assert tree is not None
        p = self.path(arg)
        name = arg[:200] or p
        pro = self.family == "proftpd"
        if p not in tree.dirs or p == "/":
            await self.reply(f"550 {name}: No such file or directory" if pro
                             else "550 Remove directory operation failed.")
            return
        prefix = p + "/"
        keep = [f for f in tree.files if f.startswith(prefix)
                and posixpath.basename(f) == ".keep" and posixpath.dirname(f) == p]
        if any(f.startswith(prefix) for f in tree.files if f not in keep) or \
                any(d.startswith(prefix) for d in tree.dirs):
            await self.reply(f"550 {name}: Directory not empty" if pro
                             else "550 Remove directory operation failed.")
            return
        for f in keep:
            tree.files.pop(f, None)
        tree.dirs.discard(p)
        await self.reply("250 RMD command successful" if pro
                         else "250 Remove directory operation successful.")

    async def help(self) -> None:
        if self.family == "vsftpd":
            await self.conn.write(VSFTPD_HELP)
            return
        rows = [PROFTPD_COMMANDS[i:i + 8] for i in range(0, len(PROFTPD_COMMANDS), 8)]
        body = "".join(" " + "".join(f"{c:<8}" for c in row) + "\r\n" for row in rows)
        await self.conn.write("214-The following commands are recognized (* =>'s "
                              f"unimplemented):\r\n{body}214 Direct comments to {self.admin}\r\n")

    async def stat(self) -> None:
        mode = "ASCII" if self.ascii else "BINARY"
        ip = self.conn.src_ip
        if self.family == "proftpd":
            await self.conn.write(f"211-Status of '{self.server_name}'\r\n"
                                  f" Connected from {ip} ({ip})\r\n"
                                  f" Logged in as {self.user or ''}\r\n"
                                  f" TYPE: {mode}, STRUcture: File, Mode: Stream\r\n"
                                  " No data connection\r\n211 End of status\r\n")
            return
        await self.conn.write("211-FTP server status:\r\n"
                              f"     Connected to {ip}\r\n"
                              f"     Logged in as {self.user or ''}\r\n"
                              f"     TYPE: {mode}\r\n"
                              "     No session bandwidth limit\r\n"
                              "     Session timeout in seconds is 300\r\n"
                              "     Control connection is plain text\r\n"
                              "     Data connections will be plain text\r\n"
                              "     At session startup, client count was 1\r\n"
                              f"     vsFTPd {self.vsftpd_version} - secure, fast, stable\r\n"
                              "211 End of status\r\n")

    async def data_conn(self) -> Optional[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        if self.passive is None:
            await self.reply("425 Use PORT or PASV first.")
            return None
        passive, self.passive = self.passive, None
        pair = await passive.wait()
        if pair is None:
            passive.close()
            await self.reply("425 Failed to establish connection.")
        return pair

    async def send_data(self, pair, payload: bytes) -> None:
        writer = pair[1]
        try:
            writer.write(payload)
            await asyncio.wait_for(writer.drain(), timeout=self.conn.timeout)
        except (asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            writer.close()

    async def site(self, arg: str) -> None:
        """vsftpd's SITE subcommands: CHMOD (nothing changes), UMASK and HELP."""
        sub, _, rest = arg.partition(" ")
        sub, rest = sub.upper(), rest.strip()
        if self.family == "proftpd":
            await self.proftpd_site(sub[:32], rest)
        elif sub == "HELP":
            await self.reply("214 CHMOD UMASK HELP")
        elif sub == "CHMOD":
            target = rest.partition(" ")[2].strip()
            tree = self.tree
            assert tree is not None
            if not target:
                await self.reply("501 SITE CHMOD needs 2 arguments.")
            elif self.path(target) in tree.files or self.path(target) in tree.dirs:
                await self.reply("200 SITE CHMOD command ok.")
            else:
                await self.reply("550 SITE CHMOD command failed.")
        elif sub == "UMASK":
            if not rest:
                await self.reply("200 Your current UMASK is 0077")
            else:
                digits = rest[:len(rest) - len(rest.lstrip("01234567"))][-4:] or "0"
                await self.reply(f"200 UMASK set to {int(digits, 8):04o}")
        else:
            await self.reply("500 Unknown SITE command.")

    async def proftpd_site(self, sub: str, rest: str) -> None:
        """ProFTPD's core SITE subcommands: CHMOD (nothing changes), CHGRP and HELP."""
        tree = self.tree
        assert tree is not None
        if sub == "HELP":
            await self.conn.write("214-The following SITE commands are recognized (* =>'s "
                                  "unimplemented)\r\n CHGRP   CHMOD   HELP    \r\n"
                                  f"214 Direct comments to {self.admin}\r\n")
        elif sub in ("CHMOD", "CHGRP"):
            target = rest.partition(" ")[2].strip()
            if not target:
                await self.reply(f"500 'SITE {sub}' not understood")
            elif self.path(target) in tree.files or self.path(target) in tree.dirs:
                await self.reply(f"200 SITE {sub} command successful")
            else:
                await self.reply(f"550 {target[:200]}: No such file or directory")
        else:
            await self.reply(f"500 'SITE {sub}' not understood")

    async def send_listing(self, cmd: str, arg: str) -> None:
        args = [a for a in arg.split() if not a.startswith("-")]
        target = self.path(args[0]) if args else self.cwd
        tree = self.tree
        assert tree is not None
        if target in tree.files:
            entries = [(posixpath.basename(target), False, tree.files[target])]
        elif target in tree.dirs:
            entries = tree.listing(target)
        elif cmd == "MLSD":
            await self.reply("550 Permission denied.")
            return
        else:
            entries = []
        pair = await self.data_conn()
        if pair is None:
            return
        await self.reply("150 Here comes the directory listing.")
        rows = []
        for name, is_dir, entry in entries:
            size = 4096 if is_dir else entry.size  # type: ignore[union-attr]
            mtime = DEFAULT_MTIME if is_dir else entry.mtime  # type: ignore[union-attr]
            ls_time = _mtime_parts(mtime)[0]
            if cmd == "NLST":
                rows.append(name)
            elif cmd == "MLSD":
                rows.append(f"{_mlst_facts(is_dir, size, mtime)} {name}")
            else:
                mode = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                links = 2 if is_dir else 1
                rows.append(f"{mode}    {links} 1000     1000     {size:>8} {ls_time} {name}")
        await self.send_data(pair, "".join(r + "\r\n" for r in rows).encode("utf-8"))
        await self.reply("226 Directory send OK.")

    async def retr(self, arg: str) -> None:
        p = self.path(arg)
        tree = self.tree
        assert tree is not None
        entry = tree.files.get(p)
        if entry is None:
            await self.reply("550 Failed to open file.")
            return
        if entry.uploaded:
            # The client's own upload: same bytes when kept, else the same size.
            payload = entry.content if entry.content is not None else generate_content(
                self.ctx, p, min(entry.size, self.ctx.limits.quarantine_max_file_bytes))
        elif entry.content is not None:
            payload = entry.content[: self.retr_max]
        else:
            payload = generate_content(self.ctx, p, min(entry.size, self.retr_max))
        pair = await self.data_conn()
        if pair is None:
            return
        await self.reply(f"150 Opening BINARY mode data connection for {posixpath.basename(p)} "
                         f"({len(payload)} bytes).")
        await self.send_data(pair, payload)
        self.conn.emit("command", "FTP download", username=self.user,
                       data={"cmd": "RETR", "path": p, "size": len(payload)})
        await self.reply("226 Transfer complete.")

    async def stor(self, cmd: str, arg: str) -> None:
        p = self.path(arg or "upload.bin")
        pair = await self.data_conn()
        if pair is None:
            return
        await self.reply("150 Ok to send data.")
        reader, writer = pair
        store = self.ctx.quarantine
        qw = store.open(self.conn.src_ip) if store is not None else None
        early: Optional[QuarantineResult] = qw if isinstance(qw, QuarantineResult) else None
        sink = None if early is not None else qw
        cap = self.ctx.limits.quarantine_max_file_bytes
        hasher = hashlib.sha256()
        keep: Optional[bytearray] = bytearray()
        size = 0
        truncated = False
        try:
            # Upload bytes are bounded by the quarantine caps: reading stops at the per-file
            # cap or a quota. With no quarantine they count toward the connection byte cap.
            while early is None:
                try:
                    chunk = await asyncio.wait_for(reader.read(DATA_CHUNK),
                                                   timeout=self.conn.timeout)
                except (asyncio.TimeoutError, ConnectionError):
                    break
                if not chunk:
                    break
                if store is None:
                    self.conn.count_bytes(len(chunk))      # raises ConnClosed over the cap
                if len(chunk) > cap - size:
                    chunk, truncated = chunk[:cap - size], True
                stored_ok = sink.write(chunk) if sink is not None else True
                if sink is not None and sink.failed:
                    break                                  # over a quota: nothing is kept
                size += len(chunk)
                hasher.update(chunk)
                if keep is not None:
                    if size <= KEEP_UPLOAD_BYTES:
                        keep += chunk
                    else:
                        keep = None
                if truncated or not stored_ok:
                    break
        except ConnClosed:
            if sink is not None:
                sink.abort()
            self.conn.emit("command", "FTP upload aborted (connection byte limit)",
                           username=self.user,
                           data={"cmd": cmd, "path": p, "filename": posixpath.basename(p),
                                 "size": size, "stored": False, "reason": "max_conn_bytes",
                                 "high_signal": True, "signal": "ftp_upload"})
            raise
        except BaseException:
            if sink is not None:
                sink.abort()
            raise
        finally:
            writer.close()
        result = early if early is not None else (
            sink.finish() if sink is not None else QuarantineResult("disabled"))
        fields = {"cmd": cmd, "path": p, "filename": posixpath.basename(p), "size": size,
                  "sha256": hasher.hexdigest(), "high_signal": True, "signal": "ftp_upload"}
        status = result.status
        if status == "stored":
            fields.update(stored=True, quarantine_name=result.name)
        elif status == "duplicate":
            fields.update(stored=False, duplicate=True, quarantine_name=result.name)
        else:
            reasons = {"ip_quota": "quarantine_per_ip_bytes",
                       "total_quota": "quarantine_total_bytes", "disabled": "quarantine_disabled",
                       "error": "quarantine_error"}
            fields.update(stored=False, reason=reasons.get(status, status))
        if truncated and status not in ("ip_quota", "total_quota", "error"):
            fields.update(truncated=True, reason="quarantine_max_file_bytes")
        if result.quota_hit:
            self.quota_event(status, size)
        if status in ("ip_quota", "total_quota"):
            fields.pop("sha256")                     # only part of the upload was read
            self.conn.emit("command", "FTP upload refused", username=self.user, data=fields)
            await self.reply("552 Requested file action aborted. Exceeded storage allocation.")
            return
        if status == "error":
            self.conn.emit("command", "FTP upload failed", username=self.user, data=fields)
            await self.reply("451 Failure writing to local file.")
            return
        if truncated:
            self.conn.emit("command", "FTP upload truncated", username=self.user, data=fields)
            await self.reply("552 Requested file action aborted. Exceeded storage allocation.")
            return
        self.conn.emit("command", "FTP upload", username=self.user, data=fields)
        assert self.tree is not None
        self.tree.add_file(p, Entry(bytes(keep) if keep is not None else None, size,
                                    DEFAULT_MTIME, uploaded=True))
        await self.reply("226 Transfer complete.")

    def quota_event(self, status: str, size: int) -> None:
        """High-signal: a quota stopped capture (one line, then periodic counts)."""
        suppressed = self.ctx.gate.check(f"{self.conn.src_ip}|ftp|quarantine_{status}")
        if suppressed is None:
            return
        self.conn.emit("limit", "Quarantine quota reached; upload not captured",
                       level="WARNING", username=self.user,
                       data={"reason": status, "size": size, "suppressed": suppressed,
                             "high_signal": True, "signal": "quarantine_quota"})


async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    async def handle(conn: Conn) -> None:
        await FtpSession(conn, settings).run()

    return [await start_tcp(ctx, "ftp", settings.port, handle)]
