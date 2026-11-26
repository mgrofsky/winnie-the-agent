"""Fake PostgreSQL server (protocol 3.0).

SSL/GSS requests get 'N'. The startup message is parsed (user, database,
application_name), then a password is requested with the configured method
(``ServiceSettings.auth_method``): ``md5`` (default; AuthenticationMD5Password with a
random salt, the password recovered by testing md5(md5(password + user) + salt) against
the configured accounts and the bundled common-password list) or ``cleartext``.
``conn.login`` decides. ``password_encryption`` in SHOW/pg_settings follows the method.
After a fake login the simple query protocol is answered by ``listeners.sqlfake``;
the extended protocol (Parse/Bind/Describe/Execute/Sync) gets best-effort support so
drivers do not hang: Bind substitutes the parameters into the statement as literals, and a
Describe of a statement answers only a read statement through the engine, so a write or
DDL statement runs once, at Execute. Nothing is executed.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
from typing import Optional

from listeners.base import Conn, ConnClosed, ListenerContext, ServiceSettings, start_tcp
from listeners.wordlist import common_passwords
from listeners.sqlfake import (DEFAULT_VERSIONS, READ_VERBS, FakeSql, Result, SqlError,
                               cell_text, column_kind, strip_comments, wire_text)

SSL_REQUEST = 80877103
GSS_REQUEST = 80877104
CANCEL_REQUEST = 80877102
MAX_STARTUP = 10000
MAX_MESSAGE = 1 << 20
MAX_PREPARED = 64

TYPE_OIDS = {"int": (20, 8), "float": (701, 8), "bool": (16, 1), "text": (25, -1)}
AUTH_METHODS = ("md5", "cleartext")
# What SHOW password_encryption reports for each method. An md5 challenge only happens
# when the stored verifier is md5, so that server must report md5. Cleartext ("password"
# in pg_hba.conf) works with any verifier, and a stock PostgreSQL 15 reports its default.
PASSWORD_ENCRYPTION = {"md5": "md5", "cleartext": "scram-sha-256"}
MD5_RESPONSE_RE = re.compile(r"md5[0-9a-f]{32}")
MAX_MD5_CANDIDATES = 6000


# ---- encoders -----------------------------------------------------------------------------

def msg(kind: bytes, body: bytes = b"") -> bytes:
    return kind + struct.pack("!I", len(body) + 4) + body


def cstr(s: str) -> bytes:
    return s.replace("\x00", "").encode("utf-8", "replace") + b"\x00"


def error_response(code: str, message: str, severity: str = "ERROR") -> bytes:
    body = (b"S" + cstr(severity) + b"V" + cstr(severity) + b"C" + cstr(code) +
            b"M" + cstr(wire_text(message, 1000)) + b"\x00")
    return msg(b"E", body)


def ready(status: bytes = b"I") -> bytes:
    return msg(b"Z", status)


def row_description(columns: list[str], rows: list[list]) -> bytes:
    body = struct.pack("!H", len(columns))
    for i, name in enumerate(columns):
        oid, size = TYPE_OIDS[column_kind(rows, i)]
        body += cstr(wire_text(name, 63)) + struct.pack("!IhIhih", 0, 0, oid, size, -1, 0)
    return msg(b"T", body)


def data_row(values: list) -> bytes:
    body = struct.pack("!H", len(values))
    for v in values:
        text = cell_text(v, "postgres")
        if text is None:
            body += struct.pack("!i", -1)
        else:
            raw = text.encode("utf-8", "replace")
            body += struct.pack("!i", len(raw)) + raw
    return msg(b"D", body)


def command_tag(ans: Result) -> str:
    if ans.is_query:
        return ans.tag or f"SELECT {len(ans.rows)}"
    return ans.tag


def render_simple(ans) -> bytes:
    if isinstance(ans, SqlError):
        return error_response(ans.code, ans.message, ans.severity)
    if ans.tag == "EMPTY":
        return msg(b"I")
    if ans.is_query:
        out = row_description(ans.columns, ans.rows)
        out += b"".join(data_row(r) for r in ans.rows)
        return out + msg(b"C", cstr(command_tag(ans)))
    return msg(b"C", cstr(ans.tag))


# ---- decoding helpers ---------------------------------------------------------------------

def parse_startup(body: bytes) -> dict[str, str]:
    params: dict[str, str] = {}
    parts = body.split(b"\x00")
    for i in range(0, len(parts) - 1, 2):
        key = parts[i].decode("utf-8", "replace")[:64]
        if not key:
            break
        params[key] = parts[i + 1].decode("utf-8", "replace")[:256]
        if len(params) >= 32:
            break
    return params


def _cstring(buf: bytes, pos: int) -> tuple[str, int]:
    end = buf.find(b"\x00", pos)
    if end < 0:
        raise ValueError("unterminated string")
    return buf[pos:end].decode("utf-8", "replace"), end + 1


def _sql_literal(raw: Optional[bytes], fmt: int) -> str:
    if raw is None:
        return "NULL"
    if fmt == 1:
        if len(raw) in (2, 4, 8):
            return str(int.from_bytes(raw, "big", signed=True))
        return "'" + raw.hex() + "'"
    text = raw.decode("utf-8", "replace")
    if re.fullmatch(r"-?\d{1,18}(\.\d+)?", text):
        return text
    return "'" + text.replace("'", "''") + "'"


class ShortMessage(Exception):
    """A length or count field points past the end of the message."""


def _take(buf: bytes, pos: int, n: int) -> tuple[bytes, int]:
    if n < 0 or pos + n > len(buf):
        raise ShortMessage()
    return buf[pos:pos + n], pos + n


def md5_password_hash(password: str, user: str, salt: bytes) -> str:
    inner = hashlib.md5((password + user).encode("utf-8")).hexdigest()
    return "md5" + hashlib.md5(inner.encode("ascii") + salt).hexdigest()


def recover_md5_password(response: str, user: str, salt: bytes,
                         accounts: list[tuple[str, str]]) -> Optional[str]:
    """Find the password behind an md5 response by trying likely candidates."""
    if not MD5_RESPONSE_RE.fullmatch(response):
        return None
    candidates = [pw for _u, pw in accounts if pw and pw != "*"]
    candidates += [user, user + "123", user + "1", ""] if user else [""]
    candidates += list(common_passwords())
    seen: set[str] = set()
    for pw in candidates[:MAX_MD5_CANDIDATES]:
        if pw in seen:
            continue
        seen.add(pw)
        if md5_password_hash(pw, user, salt) == response:
            return pw
    return None


def substitute_params(query: str, params: list[str]) -> str:
    def repl(m: re.Match) -> str:
        i = int(m.group(1)) - 1
        return params[i] if 0 <= i < len(params) else "NULL"
    return re.sub(r"\$(\d{1,3})", repl, query)


# ---- connection ---------------------------------------------------------------------------

async def read_message(conn: Conn) -> tuple[bytes, bytes]:
    head = await conn.readexactly(5)
    kind = head[:1]
    (length,) = struct.unpack("!I", head[1:])
    if length < 4 or length > MAX_MESSAGE:
        conn.emit("limit", "Message too large", data={"reason": "packet_size", "size": length})
        raise ConnClosed("packet_size")
    body = await conn.readexactly(length - 4)
    return kind, body


async def handle(conn: Conn) -> None:
    settings = conn.ctx.service("postgres")
    params: Optional[dict[str, str]] = None
    for _ in range(4):
        head = await conn.readexactly(4)
        (length,) = struct.unpack("!I", head)
        if length < 8 or length > MAX_STARTUP:
            conn.emit("error", "Bad startup length", data={"reason": "startup_length", "size": length})
            return
        body = await conn.readexactly(length - 4)
        (code,) = struct.unpack("!I", body[:4])
        if code in (SSL_REQUEST, GSS_REQUEST):
            conn.emit("command", "Encryption request refused",
                      data={"request": "ssl" if code == SSL_REQUEST else "gssenc"})
            await conn.write(b"N")
            continue
        if code == CANCEL_REQUEST:
            conn.emit("command", "Cancel request", data={"request": "cancel"})
            return
        if code >> 16 != 3:
            conn.emit("error", "Unsupported protocol", data={"reason": "protocol", "version": code})
            await conn.write(error_response(
                "0A000", f"unsupported frontend protocol {code >> 16}.{code & 0xFFFF}: server "
                "supports 3.0 to 3.0", "FATAL"))
            return
        params = parse_startup(body[4:])
        break
    if params is None:
        return
    user = params.get("user", "")
    database = params.get("database", "") or user
    app = params.get("application_name", "")
    if not user:
        await conn.write(error_response("28000", "no PostgreSQL user name specified in startup "
                                        "packet", "FATAL"))
        return
    method = (settings.auth_method or "md5").lower()
    if method not in AUTH_METHODS:
        method = "md5"
    salt = os.urandom(4)
    if method == "md5":
        await conn.write(msg(b"R", struct.pack("!I", 5) + salt))  # AuthenticationMD5Password
    else:
        await conn.write(msg(b"R", struct.pack("!I", 3)))  # AuthenticationCleartextPassword
    try:
        kind, body = await read_message(conn)
    except ConnClosed:
        conn.emit("auth_attempt", "Client disconnected before sending a password", username=user,
                  client=app or None, success=False, data={"database": database, "reason": "no_password"})
        raise
    if kind != b"p":
        conn.emit("error", "Expected password message", data={"reason": "bad_auth_message"})
        return
    password = body.split(b"\x00", 1)[0].decode("utf-8", "replace")
    extra = {k: v for k, v in params.items() if k not in ("user", "database", "application_name")}
    data: dict = {"database": database, "auth": method}
    if method == "md5":
        response = password[:64]
        recovered = recover_md5_password(response, user, salt, settings.accounts)
        data.update({"salt": salt.hex(), "md5_response": response,
                     "password_recovered": recovered is not None})
        password = recovered if recovered is not None else "<unrecovered>"
    for k, v in list(extra.items())[:8]:
        data[f"param_{k}"[:64]] = v
    ok = conn.login(user, password, client=app or None, data=data)
    if not ok:
        await conn.write(error_response(
            "28P01", f'password authentication failed for user "{wire_text(user, 63)}"', "FATAL"))
        return
    version = settings.version or DEFAULT_VERSIONS["postgres"]
    fake = FakeSql(conn, "postgres", user, database, version=version, port=conn.dst_port
                   if isinstance(conn.dst_port, int) else 5432)
    fake.password_encryption = PASSWORD_ENCRYPTION[method]
    if not fake.db_exists(database):
        await conn.write(error_response("3D000", f'database "{wire_text(database, 63)}" does not '
                                        "exist", "FATAL"))
        return
    out = msg(b"R", struct.pack("!I", 0))
    status = {"server_version": version, "server_encoding": "UTF8",
              "client_encoding": params.get("client_encoding", "UTF8")[:32] or "UTF8",
              "DateStyle": "ISO, MDY", "integer_datetimes": "on",
              "standard_conforming_strings": "on", "TimeZone": "Etc/UTC",
              "IntervalStyle": "postgres", "is_superuser": "off",
              "session_authorization": user[:63], "application_name": app[:63]}
    for k, v in status.items():
        out += msg(b"S", cstr(k) + cstr(wire_text(v, 63)))
    out += msg(b"K", struct.pack("!II", fake.pid, int.from_bytes(os.urandom(4), "big")))
    out += ready()
    await conn.write(out)
    await query_loop(conn, fake)


async def query_loop(conn: Conn, fake: FakeSql) -> None:
    statements: dict[str, str] = {}
    portals: dict[str, dict] = {}
    skipping = False  # after an extended-protocol error, discard until Sync
    while True:
        kind, body = await read_message(conn)
        if kind == b"X":
            conn.emit("command", "Terminate", data={"message": "terminate"})
            return
        if kind == b"S":
            skipping = False
            await conn.write(ready())
            continue
        if kind == b"H":
            continue
        if skipping:
            continue
        if kind == b"Q":
            if not conn.command():
                return
            sql = body.rstrip(b"\x00").decode("utf-8", "replace")
            answers = await fake.run(sql)
            await conn.write(b"".join(render_simple(a) for a in answers) + ready())
            continue
        try:
            if kind == b"P":
                name, pos = _cstring(body, 0)
                query, pos = _cstring(body, pos)
                if len(statements) >= MAX_PREPARED and name not in statements:
                    statements.pop(next(iter(statements)))
                statements[name] = query
                await conn.write(msg(b"1"))
            elif kind == b"B":
                portal, pos = _cstring(body, 0)
                stmt, pos = _cstring(body, pos)
                chunk, pos = _take(body, pos, 2)
                (nfmt,) = struct.unpack("!H", chunk)
                chunk, pos = _take(body, pos, 2 * nfmt)
                fmts = list(struct.unpack(f"!{nfmt}H", chunk))
                chunk, pos = _take(body, pos, 2)
                (nparams,) = struct.unpack("!H", chunk)
                values = []
                for i in range(nparams):
                    chunk, pos = _take(body, pos, 4)
                    (ln,) = struct.unpack("!i", chunk)
                    raw = None
                    if ln != -1:
                        raw, pos = _take(body, pos, ln)
                    if i < 256:
                        fmt = fmts[i] if len(fmts) > 1 else (fmts[0] if fmts else 0)
                        values.append(_sql_literal(raw, fmt))
                if stmt not in statements:
                    raise KeyError(stmt)
                if len(portals) >= MAX_PREPARED and portal not in portals:
                    portals.pop(next(iter(portals)))
                portals[portal] = {"query": substitute_params(statements[stmt], values),
                                   "answer": None}
                await conn.write(msg(b"2"))
            elif kind == b"D":
                target = body[:1]
                name, _ = _cstring(body, 1)
                if target == b"S":
                    if name not in statements:
                        raise KeyError(name)
                    query = statements[name]
                    nparams = len(set(re.findall(r"\$(\d{1,3})", query)))
                    out = msg(b"t", struct.pack("!H", nparams) + struct.pack("!I", 25) * nparams)
                    if not _is_read(query):
                        await conn.write(out + msg(b"n"))
                        continue
                    ans = await _describe_answer(conn, fake, substitute_params(query, []))
                    if isinstance(ans, SqlError):
                        await conn.write(error_response(ans.code, ans.message, ans.severity))
                        skipping = True
                    else:
                        await conn.write(out + _describe_rows(ans))
                else:
                    p = portals.get(name)
                    if p is None:
                        raise KeyError(name)
                    if p["answer"] is None:
                        if not conn.command():
                            return
                        p["answer"] = await _run_one(fake, p["query"])
                    if isinstance(p["answer"], SqlError):
                        await conn.write(error_response(p["answer"].code, p["answer"].message,
                                                        p["answer"].severity))
                        skipping = True
                    else:
                        await conn.write(_describe_rows(p["answer"]))
            elif kind == b"E":
                name, _ = _cstring(body, 0)
                p = portals.get(name)
                if p is None:
                    raise KeyError(name)
                if p["answer"] is None:
                    if not conn.command():
                        return
                    p["answer"] = await _run_one(fake, p["query"])
                ans = p["answer"]
                if isinstance(ans, SqlError):
                    await conn.write(error_response(ans.code, ans.message, ans.severity))
                    skipping = True
                elif ans.tag == "EMPTY":
                    await conn.write(msg(b"I"))
                elif ans.is_query:
                    await conn.write(b"".join(data_row(r) for r in ans.rows) +
                                     msg(b"C", cstr(command_tag(ans))))
                else:
                    await conn.write(msg(b"C", cstr(ans.tag)))
                p["answer"] = None
            elif kind == b"C":
                target = body[:1]
                name, _ = _cstring(body, 1)
                (statements if target == b"S" else portals).pop(name, None)
                await conn.write(msg(b"3"))
            elif kind in (b"d", b"c", b"f"):
                await conn.write(error_response("08P01", "unexpected COPY message"))
                skipping = True
            else:
                conn.emit("error", "Unknown message type", data={"reason": "unknown_message",
                                                               "type": kind.hex()})
                await conn.write(error_response("08P01", f"invalid frontend message type "
                                                f"{kind[0]}", "FATAL"))
                return
        except ShortMessage:
            conn.emit("error", "Malformed extended-protocol message",
                      data={"reason": "short_message", "type": kind.hex()})
            await conn.write(error_response("08P01", "insufficient data left in message"))
            skipping = True
        except (KeyError, ValueError, struct.error, IndexError):
            conn.emit("error", "Malformed extended-protocol message",
                      data={"reason": "malformed", "type": kind.hex()})
            await conn.write(error_response("26000", "prepared statement does not exist"
                                            if kind in (b"B", b"D", b"E") else "invalid message format"))
            skipping = True


def _is_read(query: str) -> bool:
    """True when the statement's first word is a read verb (it can return rows)."""
    m = re.match(r"[\s(]*([A-Za-z]+)", strip_comments(query[:4096], "postgres"))
    return bool(m) and m.group(1).lower() in READ_VERBS["postgres"]


async def _run_one(fake: FakeSql, query: str):
    answers = await fake.run(query)
    return answers[-1] if answers else Result([], [], tag="EMPTY", is_query=False)


async def _describe_answer(conn: Conn, fake: FakeSql, query: str):
    if not conn.command():
        raise ConnClosed("command_limit")
    return await _run_one(fake, query)


def _describe_rows(ans) -> bytes:
    if isinstance(ans, Result) and ans.is_query and ans.tag != "EMPTY":
        return row_description(ans.columns, ans.rows)
    return msg(b"n")


async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    server = await start_tcp(ctx, "postgres", settings.port, handle)
    return [server]
