"""SMTP trap: Postfix-like submission server that captures AUTH and never relays.

Messages accepted after DATA are logged (headers, recipients, size, sha256, first 2 KB of
body) and discarded. No outbound socket is ever opened. Recipients outside the scenario
domain are logged as relay attempts (``high_signal``); before auth they get 554.

Postfix (3.6 replies) without TLS: STARTTLS is not advertised and answers 502; HELP and
EXPN are not commands (502); ETRN is refused by ``smtpd_etrn_restrictions`` (554). The advertised SIZE is the limit
DATA enforces, kept under the connection byte cap so a message within it is not cut off
by that cap.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
from typing import Optional

from listeners.base import ConnClosed, Conn, ListenerContext, ServiceSettings, start_tcp

MAX_MESSAGE_BYTES = 10_240_000
SIZE_HEADROOM = 65_536            # connection bytes left for commands around one message
HEADER_LOG_CAP = 4096
BODY_LOG_CAP = 2048
MAX_RCPTS = 100
SMTP_VERBS = frozenset({"HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "NOOP", "QUIT", "VRFY",
                        "EXPN", "HELP", "AUTH", "STARTTLS", "BDAT", "ETRN"})
# Lines a client sends after the AUTH command for each mechanism (LOGIN: user, password).
AUTH_CONTINUATIONS = {"PLAIN": 1, "LOGIN": 2}
ADDR_RE = re.compile(r"<\s*([^<>\s]{0,320})\s*>|(\S{1,320})")
SIZE_PARAM_RE = re.compile(r"(?:^|\s)SIZE=(\d{1,20})(?=\s|$)", re.IGNORECASE)
DOMAIN_RE = re.compile(r"[A-Za-z0-9.-]{1,253}")


def _identity(ctx: ListenerContext) -> tuple[str, str]:
    if ctx.scenario is not None:
        return ctx.scenario.hostname, ctx.scenario.scenario.identity.domain
    return "mail", "example.com"


def b64decode(text: str) -> Optional[str]:
    try:
        return base64.b64decode(text.strip().encode("ascii"), validate=True).decode(
            "utf-8", errors="replace")
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None


def size_limit(ctx: ListenerContext) -> int:
    """The message size DATA accepts and EHLO advertises: Postfix's default, or less so the
    whole message fits in the connection byte cap (rounded down to whole KiB)."""
    room = max(1024, ctx.limits.max_conn_bytes - SIZE_HEADROOM)
    return min(MAX_MESSAGE_BYTES, room // 1024 * 1024)


def parse_addr(arg: str, prefix: str) -> Optional[str]:
    """'FROM:<a@b> SIZE=1' -> 'a@b'; None if the verb prefix is missing."""
    if not arg.upper().startswith(prefix):
        return None
    m = ADDR_RE.search(arg[len(prefix):].strip())
    if not m:
        return ""
    return m.group(1) if m.group(1) is not None else m.group(2)


class SmtpSession:
    def __init__(self, conn: Conn, settings: ServiceSettings) -> None:
        self.conn = conn
        self.ctx = conn.ctx
        self.settings = settings
        self.host, self.domain = _identity(self.ctx)
        self.fqdn = f"{self.host}.{self.domain}"
        self.size_limit = size_limit(self.ctx)
        self.helo: Optional[str] = None
        self.user: Optional[str] = None
        self.authed = False
        self.auth_lines_pending = 0
        self.reset()

    def reset(self) -> None:
        self.mail_from: Optional[str] = None
        self.rcpts: list[str] = []

    async def reply(self, text: str) -> None:
        await self.conn.write(text + "\r\n")

    def is_local(self, addr: str) -> bool:
        domain = addr.rpartition("@")[2].lower().strip(".")
        if not domain or "@" not in addr:
            return True      # bare local part ("postmaster") is local
        return domain == self.domain or domain.endswith("." + self.domain) or domain == self.fqdn

    async def run(self) -> None:
        banner = self.settings.banner or f"{self.fqdn} ESMTP Postfix"
        await self.reply(banner if banner.startswith("220") else f"220 {banner}")
        while True:
            raw = await self.conn.readline()
            if not self.conn.command():
                await self.reply("421 4.7.0 Error: too many commands")
                return
            line = raw.decode("utf-8", errors="replace")
            verb, _, arg = line.strip().partition(" ")
            verb = verb.upper()
            if self.auth_lines_pending and verb not in SMTP_VERBS:
                # Credentials a client pipelined after an AUTH that was refused before its
                # exchange started: logged as a secret, never as a command line.
                self.auth_lines_pending -= 1
                self.conn.emit("command", "SMTP AUTH data after refused AUTH",
                               username=self.user, password=line.strip()[:512],
                               data={"cmd": "AUTH_DATA"})
                await self.reply("502 5.5.2 Error: command not recognized")
                continue
            self.auth_lines_pending = 0
            if verb != "AUTH":    # AUTH material is logged by the auth_attempt event
                self.conn.emit("command", "SMTP command", username=self.user,
                               data={"input": line, "cmd": verb[:16]})
            if not await self.dispatch(verb, arg.strip()):
                return

    async def dispatch(self, verb: str, arg: str) -> bool:
        if verb == "QUIT":
            await self.reply("221 2.0.0 Bye")
            return False
        if verb == "EHLO":
            if not arg:
                await self.reply("501 Syntax: EHLO hostname")
                return True
            self.helo = arg[:255]
            self.reset()
            caps = ["PIPELINING", f"SIZE {self.size_limit}", "VRFY", "ETRN", "AUTH PLAIN LOGIN",
                    "ENHANCEDSTATUSCODES", "8BITMIME", "DSN", "SMTPUTF8"]
            await self.conn.write(f"250-{self.fqdn}\r\n" + "".join(f"250-{c}\r\n" for c in caps[:-1])
                                  + f"250 {caps[-1]}\r\n")
            return True
        if verb == "HELO":
            if not arg:
                await self.reply("501 Syntax: HELO hostname")
                return True
            self.helo = arg[:255]
            self.reset()
            await self.reply(f"250 {self.fqdn}")
            return True
        if verb == "STARTTLS":
            # Postfix with TLS off: the command exists but is not implemented.
            if arg:
                await self.reply("501 5.5.4 Syntax: STARTTLS")
            else:
                await self.reply("502 5.5.1 Error: command not implemented")
            return True
        if verb == "ETRN":
            await self.etrn(arg)
            return True
        if verb in ("NOOP", "RSET"):
            if verb == "RSET":
                self.reset()
            await self.reply("250 2.0.0 Ok")
            return True
        if verb == "VRFY":
            await self.reply("252 2.0.0 Send some mail, I'll try my best")
            return True
        if verb == "AUTH":
            await self.auth(arg)
            return True
        if verb == "MAIL":
            await self.mail(arg)
            return True
        if verb == "RCPT":
            await self.rcpt(arg)
            return True
        if verb == "DATA":
            await self.data()
            return True
        await self.reply("502 5.5.2 Error: command not recognized")
        return True

    # ---- AUTH ------------------------------------------------------------------------------

    async def challenge(self, prompt: str) -> Optional[str]:
        await self.reply(f"334 {prompt}")
        raw = await self.conn.readline()
        if not self.conn.command():
            raise ConnClosed("max_commands")
        text = raw.decode("utf-8", errors="replace").strip()
        if text == "*":
            await self.reply("501 5.7.0 Authentication aborted")
            return None
        return text

    async def auth(self, arg: str) -> None:
        mech, _, initial = arg.partition(" ")
        mech = mech.upper()
        initial = initial.strip()
        if self.helo is None or self.authed:
            # Refused before the exchange: lines the client pipelined for it are secrets.
            self.auth_lines_pending = max(0, AUTH_CONTINUATIONS.get(mech, 0) - (1 if initial else 0))
            await self.reply("503 5.5.1 Error: send HELO/EHLO first" if self.helo is None
                             else "503 5.5.1 Error: already authenticated")
            return
        if mech == "PLAIN":
            text = initial if initial and initial != "=" else await self.challenge("")
            if text is None:
                return
            decoded = b64decode(text)
            if decoded is None:
                await self.reply("501 5.5.2 Cannot decode response")
                return
            parts = decoded.split("\x00")
            if len(parts) != 3:
                await self.reply("535 5.7.8 Error: authentication failed: Invalid authentication data")
                return
            username, password = parts[1] or parts[0], parts[2]
        elif mech == "LOGIN":
            text = initial or await self.challenge("VXNlcm5hbWU6")
            if text is None:
                return
            username = b64decode(text)
            if username is None:
                await self.reply("501 5.5.2 Cannot decode response")
                return
            text = await self.challenge("UGFzc3dvcmQ6")
            if text is None:
                return
            password = b64decode(text)
            if password is None:
                await self.reply("501 5.5.2 Cannot decode response")
                return
        else:
            self.conn.emit("command", "SMTP AUTH unsupported mechanism",
                           data={"cmd": "AUTH", "mechanism": mech[:32]})
            await self.reply("535 5.7.8 Error: authentication failed: Invalid authentication mechanism")
            return
        if self.conn.login(username, password, client=self.helo,
                           data={"mechanism": mech}):
            self.authed = True
            self.user = username
            await self.reply("235 2.7.0 Authentication successful")
        else:
            await self.reply("535 5.7.8 Error: authentication failed: authentication failure")

    async def etrn(self, arg: str) -> None:
        """ETRN as Postfix's etrn_cmd answers it with ``smtpd_helo_required = yes`` and
        ``smtpd_etrn_restrictions = reject``."""
        if self.helo is None:
            await self.reply("503 Error: send HELO/EHLO first")
            return
        if self.mail_from is not None:
            await self.reply("503 Error: MAIL transaction in progress")
            return
        parts = arg.split()
        if len(parts) != 1:
            await self.reply("500 Syntax: ETRN domain")
            return
        domain = parts[0][1:] if parts[0][:1] in ("@", "#") else parts[0]
        if not DOMAIN_RE.fullmatch(domain) or ".." in domain or domain.startswith((".", "-")):
            await self.reply("501 Error: invalid parameter syntax")
            return
        await self.reply(f"554 5.7.1 <{domain}>: Etrn command rejected: Access denied")

    # ---- transaction ---------------------------------------------------------------------

    async def mail(self, arg: str) -> None:
        if self.helo is None:
            await self.reply("503 5.5.1 Error: send HELO/EHLO first")
            return
        if self.mail_from is not None:
            await self.reply("503 5.5.1 Error: nested MAIL command")
            return
        addr = parse_addr(arg, "FROM:")
        if addr is None:
            await self.reply("501 5.5.4 Syntax: MAIL FROM:<address>")
            return
        m = SIZE_PARAM_RE.search(arg)
        if m and int(m.group(1)) > self.size_limit:
            await self.reply("552 5.3.4 Message size exceeds fixed limit")
            return
        self.mail_from = addr
        await self.reply("250 2.1.0 Ok")

    async def rcpt(self, arg: str) -> None:
        if self.mail_from is None:
            await self.reply("503 5.5.1 Error: need MAIL command")
            return
        addr = parse_addr(arg, "TO:")
        if not addr:
            await self.reply("501 5.5.4 Syntax: RCPT TO:<address>")
            return
        if len(self.rcpts) >= MAX_RCPTS:
            await self.reply("452 4.5.3 Error: too many recipients")
            return
        local = self.is_local(addr)
        if not local:
            self.conn.emit("command", "SMTP relay attempt", username=self.user,
                           data={"cmd": "RCPT", "rcpt": addr, "mail_from": self.mail_from,
                                 "authenticated": self.authed, "high_signal": True,
                                 "signal": "smtp_relay_attempt",
                                 "rcpt_domain": addr.rpartition("@")[2]})
            if not self.authed:
                await self.reply(f"554 5.7.1 <{addr}>: Relay access denied")
                return
        self.rcpts.append(addr)
        await self.reply("250 2.1.5 Ok")

    async def data(self) -> None:
        if not self.rcpts:
            await self.reply("503 5.5.1 Error: need RCPT command")
            return
        await self.reply("354 End data with <CR><LF>.<CR><LF>")
        cap = self.size_limit
        lines: list[bytes] = []
        size = 0
        over = False
        while True:
            raw = await self.conn.readline(strip=False)
            line = raw.rstrip(b"\r\n")
            if line == b".":
                break
            if line.startswith(b".."):
                line = line[1:]
            size += len(line) + 2
            if size > cap:
                over = True
                continue
            lines.append(line)
        if over:
            self.conn.emit("limit", "SMTP message too large", data={"reason": "message_size",
                                                                    "size": size})
            self.reset()
            await self.reply("552 5.3.4 Error: message file too big")
            return
        message = b"\r\n".join(lines) + b"\r\n"
        try:
            split = lines.index(b"")
        except ValueError:
            split = len(lines)
        headers = b"\r\n".join(lines[:split])
        body = b"\r\n".join(lines[split + 1:])
        subject = ""
        for h in lines[:split]:
            if h.lower().startswith(b"subject:"):
                subject = h[8:].strip().decode("utf-8", errors="replace")
                break
        queue_id = os.urandom(5).hex().upper()
        self.conn.emit("command", "SMTP message accepted", username=self.user,
                       data={"cmd": "DATA", "mail_from": self.mail_from or "",
                             "recipients": ",".join(self.rcpts), "rcpt_count": len(self.rcpts),
                             "size": len(message), "sha256": hashlib.sha256(message).hexdigest(),
                             "subject": subject,
                             "headers": headers[:HEADER_LOG_CAP].decode("utf-8", errors="replace"),
                             "body_head": body[:BODY_LOG_CAP].decode("utf-8", errors="replace"),
                             "authenticated": self.authed, "queue_id": queue_id,
                             **({"high_signal": True, "signal": "smtp_relay_attempt"}
                                if any(not self.is_local(r) for r in self.rcpts) else {})})
        self.conn.capture("smtp_body", body[:16_384])
        self.reset()
        await self.reply(f"250 2.0.0 Ok: queued as {queue_id}")


async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    async def handle(conn: Conn) -> None:
        await SmtpSession(conn, settings).run()

    return [await start_tcp(ctx, "smtp", settings.port, handle)]
