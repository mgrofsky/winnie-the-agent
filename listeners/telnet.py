"""Telnet trap: login/password prompts, then the persona shell (or a tiny canned shell).

After login every line goes through ``agents.hooks.persona_invoke`` when
``ctx.persona_history`` is set (budgets enforced there); otherwise a deterministic minimal
shell answers. Nothing is ever executed.
"""

from __future__ import annotations

from typing import Optional

from listeners.base import ConnClosed, Conn, ListenerContext, ServiceSettings, start_tcp

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ECHO, SGA = 1, 3
END_OF_SESSION = "YYY-END-OF-SESSION-YYY"
MAX_LOGIN_TRIES = 3
RESPONSE_LOG_CAP = 2048


class TelnetReader:
    """Line reader that strips IAC negotiation (state survives chunk boundaries)."""

    def __init__(self, conn: Conn) -> None:
        self.conn = conn
        self.buf = bytearray()
        self.lines: list[bytes] = []
        self.state = "data"     # data | iac | opt | sb | sb_iac
        self.last_cr = False

    def feed(self, chunk: bytes) -> None:
        for b in chunk:
            st = self.state
            if st == "iac":
                if b == IAC:
                    self.buf.append(IAC)
                    self.state = "data"
                elif b in (DO, DONT, WILL, WONT):
                    self.state = "opt"
                elif b == SB:
                    self.state = "sb"
                else:
                    self.state = "data"
                continue
            if st == "opt":
                self.state = "data"
                continue
            if st == "sb":
                if b == IAC:
                    self.state = "sb_iac"
                continue
            if st == "sb_iac":
                self.state = "data" if b == SE else "sb"
                continue
            if b == IAC:
                self.state = "iac"
                continue
            if b in (0x0A, 0x00) and self.last_cr:
                self.last_cr = False
                continue
            self.last_cr = b == 0x0D
            if b in (0x0D, 0x0A):
                self.lines.append(bytes(self.buf))
                self.buf.clear()
            elif b in (0x08, 0x7F):
                if self.buf:
                    self.buf.pop()
            else:
                self.buf.append(b)
            if len(self.buf) > self.conn.ctx.limits.max_line_bytes:
                self.conn.emit("limit", "Line too long", data={"reason": "max_line_bytes"})
                raise ConnClosed("max_line_bytes")

    async def readline(self) -> str:
        while not self.lines:
            self.feed(await self.conn.read_some(4096))
        return self.lines.pop(0).decode("utf-8", errors="replace")


def _identity(ctx: ListenerContext) -> tuple[str, str, str]:
    """(hostname, os_pretty_name, kernel) from the scenario or neutral defaults."""
    if ctx.scenario is not None:
        ident = ctx.scenario.scenario.identity
        return ctx.scenario.hostname, ident.os_pretty_name, ident.kernel
    return ("srv01", "Ubuntu 22.04.4 LTS",
            "Linux srv01 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux")


def canned_shell(ctx: ListenerContext, user: str, line: str, cwd: str) -> tuple[str, bool]:
    """Deterministic minimal shell. Returns (output, close)."""
    host, os_name, kernel = _identity(ctx)
    parts = line.split()
    if not parts:
        return "", False
    cmd, args = parts[0], parts[1:]
    uid = 0 if user == "root" else 1000
    if cmd in ("exit", "logout", "quit"):
        return "logout\r\n", True
    if cmd == "whoami":
        return f"{user}\r\n", False
    if cmd == "id":
        return f"uid={uid}({user}) gid={uid}({user}) groups={uid}({user})\r\n", False
    if cmd == "uname":
        return (f"{kernel}\r\n" if "-a" in args else "Linux\r\n"), False
    if cmd == "hostname":
        return f"{host}\r\n", False
    if cmd == "pwd":
        return f"{cwd}\r\n", False
    if cmd == "echo":
        return " ".join(args)[:512] + "\r\n", False
    if cmd in ("cd", "true", ":", "export", "unset", "history"):
        return "", False
    if cmd == "ls":
        return "\r\n", False
    if cmd == "cat" and args and args[0] in ("/etc/os-release", "/etc/issue"):
        return f'PRETTY_NAME="{os_name}"\r\n', False
    return f"-bash: {cmd[:64]}: command not found\r\n", False


async def _login(conn: Conn, reader: TelnetReader, host: str) -> Optional[str]:
    for _ in range(MAX_LOGIN_TRIES):
        await conn.write(f"{host} login: ")
        user = (await reader.readline()).strip()
        if not conn.command():
            return None
        if not user:
            continue
        await conn.write(bytes([IAC, WILL, ECHO]) + b"Password: ")
        password = await reader.readline()
        await conn.write(bytes([IAC, WONT, ECHO]) + b"\r\n")
        if conn.login(user, password):
            return user
        await conn.write("\r\nLogin incorrect\r\n")
    return None


def _crlf(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\n", "\r\n")


async def _persona_session(conn: Conn, reader: TelnetReader, user: str) -> None:
    from agents import hooks

    ctx = conn.ctx
    refusal = hooks.session_open(conn.task_name, conn.src_ip)
    if refusal is not None:
        conn.emit("limit", "Persona session refused", data={"reason": "budget_session"})
        await conn.write(_crlf(refusal))
        return
    llm_config = {"configurable": {"session_id": conn.task_name}}
    try:
        async def ask(text: str, counts: bool = True):
            return await hooks.persona_invoke(
                ctx.persona_history, session_id=conn.task_name, src_ip=conn.src_ip,
                username=user, text=text, interactive=True, llm_config=llm_config,
                counts_as_command=counts)

        first = await ask("", counts=False)
        content = str(getattr(first, "content", ""))
        await conn.write(_crlf(content))
        if getattr(first, "budget_exceeded", False):
            conn.emit("limit", "Persona budget exceeded", data={"reason": "budget"})
            return
        while True:
            line = hooks.clip_input(await reader.readline())
            if not conn.command():
                return
            resp = await ask(line)
            content = str(getattr(resp, "content", ""))
            exceeded = bool(getattr(resp, "budget_exceeded", False))
            conn.emit("command", "Telnet input", username=user,
                      data={"input": line, "response": content[:RESPONSE_LOG_CAP],
                            "persona": True, "budget_exceeded": exceeded})
            conn.capture("telnet_input", line)
            if content == END_OF_SESSION:
                return
            await conn.write(_crlf(content))
            if exceeded:
                return
    finally:
        hooks.session_close(conn.task_name, ctx.persona_sessions)


async def _canned_session(conn: Conn, reader: TelnetReader, user: str) -> None:
    host, os_name, _ = _identity(conn.ctx)
    cwd = "/root" if user == "root" else f"/home/{user}"
    sigil = "#" if user == "root" else "$"
    await conn.write(f"Welcome to {os_name}\r\n\r\n")
    while True:
        await conn.write(f"{user}@{host}:~{sigil} ")
        line = await reader.readline()
        if not conn.command():
            return
        out, close = canned_shell(conn.ctx, user, line.strip(), cwd)
        conn.emit("command", "Telnet input", username=user,
                  data={"input": line, "response": out[:RESPONSE_LOG_CAP], "persona": False})
        conn.capture("telnet_input", line)
        await conn.write(out)
        if close:
            return


async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    async def handle(conn: Conn) -> None:
        reader = TelnetReader(conn)
        host, os_name, _ = _identity(ctx)
        await conn.write(bytes([IAC, WILL, SGA, IAC, DO, 24]))   # SGA, ask terminal type
        banner = settings.banner or f"{os_name}"
        await conn.write(f"{banner}\r\n\r\n")
        user = await _login(conn, reader, host)
        if user is None:
            return
        if ctx.persona_history is not None:
            await _persona_session(conn, reader, user)
        else:
            await _canned_session(conn, reader, user)

    return [await start_tcp(ctx, "telnet", settings.port, handle)]
