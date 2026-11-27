"""Fake MySQL server (protocol 10, text and binary protocol).

HandshakeV10 with a random salt and mysql_native_password (no CLIENT_SSL). The
HandshakeResponse41 is parsed (user, auth response, database, plugin, connect attrs);
the password is recovered by testing the scramble against the configured accounts and a
common-password list for both mysql_native_password (SHA1) and caching_sha2_password
(SHA256). ``conn.login`` decides, for the first login and for COM_CHANGE_USER. After
login, COM_QUERY is answered by ``listeners.sqlfake``. Prepared statements
(COM_STMT_PREPARE / EXECUTE / SEND_LONG_DATA / RESET / CLOSE) bind each parameter into the
statement text as a quoted literal and answer the bound text through the same engine, with
binary-protocol result rows. Nothing is executed.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
from array import array
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

from listeners.base import Conn, ConnClosed, ListenerContext, ServiceSettings, start_tcp
from listeners.sqlfake import (DEFAULT_VERSIONS, MAX_STATEMENT_CHARS, FakeSql, SqlError,
                               cell_text, column_kind, split_statements, strip_comments,
                               wire_text)

CLIENT_LONG_PASSWORD = 0x1
CLIENT_FOUND_ROWS = 0x2
CLIENT_LONG_FLAG = 0x4
CLIENT_CONNECT_WITH_DB = 0x8
CLIENT_NO_SCHEMA = 0x10
CLIENT_ODBC = 0x40
CLIENT_IGNORE_SPACE = 0x100
CLIENT_PROTOCOL_41 = 0x200
CLIENT_INTERACTIVE = 0x400
CLIENT_SSL = 0x800
CLIENT_IGNORE_SIGPIPE = 0x1000
CLIENT_TRANSACTIONS = 0x2000
CLIENT_RESERVED = 0x4000
CLIENT_SECURE_CONNECTION = 0x8000
CLIENT_MULTI_RESULTS = 0x20000
CLIENT_PS_MULTI_RESULTS = 0x40000
CLIENT_PLUGIN_AUTH = 0x80000
CLIENT_CONNECT_ATTRS = 0x100000
CLIENT_PLUGIN_AUTH_LENENC = 0x200000
CLIENT_CAN_HANDLE_EXPIRED = 0x400000
CLIENT_DEPRECATE_EOF = 0x1000000

SERVER_CAPS = (CLIENT_LONG_PASSWORD | CLIENT_FOUND_ROWS | CLIENT_LONG_FLAG | CLIENT_CONNECT_WITH_DB
               | CLIENT_NO_SCHEMA | CLIENT_ODBC | CLIENT_IGNORE_SPACE | CLIENT_PROTOCOL_41
               | CLIENT_INTERACTIVE | CLIENT_IGNORE_SIGPIPE | CLIENT_TRANSACTIONS | CLIENT_RESERVED
               | CLIENT_SECURE_CONNECTION | CLIENT_MULTI_RESULTS | CLIENT_PS_MULTI_RESULTS
               | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_ATTRS | CLIENT_PLUGIN_AUTH_LENENC
               | CLIENT_CAN_HANDLE_EXPIRED | CLIENT_DEPRECATE_EOF)

STATUS_AUTOCOMMIT = 0x0002
STATUS_MORE_RESULTS = 0x0008
NATIVE = "mysql_native_password"
SHA2 = "caching_sha2_password"
MAX_PACKET = 1 << 20
MAX_AUTH_PACKET = 8192
MAX_CANDIDATES = 2000

TYPE_DECIMAL = 0x00
TYPE_TINY = 0x01
TYPE_SHORT = 0x02
TYPE_LONG = 0x03
TYPE_FLOAT = 0x04
TYPE_DOUBLE = 0x05
TYPE_NULL = 0x06
TYPE_TIMESTAMP = 0x07
TYPE_LONGLONG = 0x08
TYPE_INT24 = 0x09
TYPE_DATE = 0x0A
TYPE_TIME = 0x0B
TYPE_DATETIME = 0x0C
TYPE_YEAR = 0x0D
TYPE_NEWDECIMAL = 0xF6
TYPE_VAR_STRING = 0xFD

# Prepared statements: per-connection caps. MAX_PARAMS is the server's own placeholder limit.
MAX_PREPARED = 32
MAX_PARAMS = 65535
MAX_LONG_DATA = 32768          # COM_STMT_SEND_LONG_DATA bytes kept per statement
MAX_LONG_DATA_TOTAL = 262144   # and per connection

INLINE_PASSWORDS = ["", "root", "password", "123456", "admin", "mysql", "toor", "12345678",
                    "qwerty", "123", "1234", "12345", "test", "pass", "changeme", "letmein",
                    "welcome", "P@ssw0rd", "Password1", "secret", "admin123", "root123",
                    "default", "oracle", "postgres", "sa"]


@lru_cache(maxsize=1)
def common_passwords() -> tuple[str, ...]:
    path = Path(__file__).resolve().parent / "data" / "common_passwords.txt"
    words: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                w = line.rstrip("\r\n")
                if w and not w.startswith("#") and len(w) <= 64:
                    words.append(w)
                if len(words) >= MAX_CANDIDATES:
                    break
    except OSError:
        pass
    return tuple(words) if words else tuple(INLINE_PASSWORDS)


# ---- scrambles ----------------------------------------------------------------------------

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=False))


def native_scramble(password: str, salt: bytes) -> bytes:
    if not password:
        return b""
    h1 = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).digest()
    h2 = hashlib.sha1(h1, usedforsecurity=False).digest()
    return _xor(h1, hashlib.sha1(salt + h2, usedforsecurity=False).digest())


def sha2_scramble(password: str, salt: bytes) -> bytes:
    if not password:
        return b""
    h1 = hashlib.sha256(password.encode("utf-8")).digest()
    h2 = hashlib.sha256(h1).digest()
    return _xor(h1, hashlib.sha256(h2 + salt).digest())


def recover_password(response: bytes, salt: bytes, plugin: str, username: str,
                     accounts: list[tuple[str, str]]) -> Optional[str]:
    if not response:
        return ""
    fn = sha2_scramble if plugin == SHA2 else native_scramble
    want = 32 if plugin == SHA2 else 20
    if len(response) != want:
        return None
    seen: set[str] = set()
    candidates = [pw for _u, pw in accounts if pw and pw != "*"]
    candidates += [username, username + "123", username + "1"] if username else []
    candidates += list(common_passwords()) + INLINE_PASSWORDS
    for pw in candidates[:MAX_CANDIDATES + 100]:
        if pw in seen:
            continue
        seen.add(pw)
        if fn(pw, salt) == response:
            return pw
    return None


# ---- packet encoding ------------------------------------------------------------------------

def lenenc_int(n: int) -> bytes:
    if n < 251:
        return bytes([n])
    if n < 1 << 16:
        return b"\xfc" + n.to_bytes(2, "little")
    if n < 1 << 24:
        return b"\xfd" + n.to_bytes(3, "little")
    return b"\xfe" + n.to_bytes(8, "little")


def lenenc_str(s: str | bytes) -> bytes:
    raw = s.encode("utf-8", "replace") if isinstance(s, str) else s
    return lenenc_int(len(raw)) + raw


def read_lenenc_int(buf: bytes, pos: int) -> tuple[int, int]:
    first = buf[pos]
    if first < 251:
        return first, pos + 1
    width = {0xFC: 2, 0xFD: 3, 0xFE: 8}.get(first)
    if width is None or pos + 1 + width > len(buf):
        raise ValueError("bad lenenc int")
    return int.from_bytes(buf[pos + 1:pos + 1 + width], "little"), pos + 1 + width


def _span(buf: bytes, pos: int, n: int) -> tuple[bytes, int]:
    """``n`` bytes at ``pos``; a length that runs past the packet is malformed."""
    if pos + n > len(buf):
        raise ValueError("length past end of packet")
    return buf[pos:pos + n], pos + n


def _cstring(buf: bytes, pos: int) -> tuple[bytes, int]:
    end = buf.find(b"\x00", pos)
    if end < 0:
        return buf[pos:], len(buf)
    return buf[pos:end], end + 1


def handshake_v10(version: str, conn_id: int, salt: bytes) -> bytes:
    return (b"\x0a" + version.encode() + b"\x00" + conn_id.to_bytes(4, "little") + salt[:8]
            + b"\x00" + (SERVER_CAPS & 0xFFFF).to_bytes(2, "little") + bytes([255])
            + STATUS_AUTOCOMMIT.to_bytes(2, "little") + (SERVER_CAPS >> 16).to_bytes(2, "little")
            + bytes([21]) + b"\x00" * 10 + salt[8:20] + b"\x00" + NATIVE.encode() + b"\x00")


def ok_packet(affected: int = 0, header: int = 0x00, status: int = STATUS_AUTOCOMMIT) -> bytes:
    return (bytes([header]) + lenenc_int(affected) + lenenc_int(0)
            + status.to_bytes(2, "little") + b"\x00\x00")


def err_packet(errno: int, sqlstate: str, message: str) -> bytes:
    state = (sqlstate + "HY000")[:5].encode("ascii", "replace")
    return (b"\xff" + errno.to_bytes(2, "little") + b"#" + state
            + wire_text(message, 512).encode("utf-8", "replace"))


def bad_handshake(seq: int) -> bytes:
    """ER_HANDSHAKE_ERROR, what the server sends for an unparseable handshake response."""
    pk = Packets(seq + 1)
    pk.add(b"\xff" + (1043).to_bytes(2, "little") + b"#08S01Bad handshake")
    return bytes(pk.buf)


def eof_packet(status: int = STATUS_AUTOCOMMIT) -> bytes:
    return b"\xfe\x00\x00" + status.to_bytes(2, "little")


def column_def(name: str, db: str, kind: str) -> bytes:
    if kind == "int":
        ctype, charset, length, flags = TYPE_LONGLONG, 63, 21, 0x0080
    elif kind == "float":
        ctype, charset, length, flags = TYPE_DOUBLE, 63, 22, 0x0080
    elif kind == "bool":
        ctype, charset, length, flags = TYPE_TINY, 63, 1, 0x0080
    else:
        ctype, charset, length, flags = TYPE_VAR_STRING, 255, 1020, 0
    return (lenenc_str("def") + lenenc_str(wire_text(db, 64)) + lenenc_str("") + lenenc_str("")
            + lenenc_str(wire_text(name, 256)) + lenenc_str("") + b"\x0c"
            + charset.to_bytes(2, "little") + length.to_bytes(4, "little") + bytes([ctype])
            + flags.to_bytes(2, "little") + (b"\x1f" if kind in ("text", "float") else b"\x00")
            + b"\x00\x00")


def text_row(values: list) -> bytes:
    out = b""
    for v in values:
        t = cell_text(v, "mysql")
        out += b"\xfb" if t is None else lenenc_str(t)
    return out


class Packets:
    """Sequence-numbered packet writer for one command/response exchange."""

    def __init__(self, seq: int) -> None:
        self.seq = seq
        self.buf = bytearray()

    def add(self, payload: bytes) -> None:
        self.buf += len(payload).to_bytes(3, "little") + bytes([self.seq & 0xFF]) + payload
        self.seq = (self.seq + 1) & 0xFF


async def read_packet(conn: Conn, cap: int = MAX_PACKET) -> tuple[int, bytes]:
    head = await conn.readexactly(4)
    length = int.from_bytes(head[:3], "little")
    if length >= 0xFFFFFF or length > cap:
        conn.emit("limit", "Packet too large", data={"reason": "packet_size", "size": length})
        raise ConnClosed("packet_size")
    payload = await conn.readexactly(length)
    return head[3], payload


# ---- handshake response -------------------------------------------------------------------

def parse_response41(payload: bytes) -> dict:
    flags = int.from_bytes(payload[0:4], "little")
    info: dict = {"flags": flags, "charset": payload[8] if len(payload) > 8 else 0}
    pos = 32
    user, pos = _cstring(payload, pos)
    info["username"] = user.decode("utf-8", "replace")[:128]
    if flags & CLIENT_PLUGIN_AUTH_LENENC:
        n, pos = read_lenenc_int(payload, pos)
        auth, pos = _span(payload, pos, n)
    elif flags & CLIENT_SECURE_CONNECTION:
        n = payload[pos]
        auth, pos = _span(payload, pos + 1, n)
    else:
        auth, pos = _cstring(payload, pos)
    info["auth"] = bytes(auth[:256])
    info["database"] = ""
    if flags & CLIENT_CONNECT_WITH_DB and pos < len(payload):
        db, pos = _cstring(payload, pos)
        info["database"] = db.decode("utf-8", "replace")[:128]
    info["plugin"] = ""
    if flags & CLIENT_PLUGIN_AUTH and pos < len(payload):
        plugin, pos = _cstring(payload, pos)
        info["plugin"] = plugin.decode("utf-8", "replace")[:64]
    info["attrs"] = {}
    if flags & CLIENT_CONNECT_ATTRS and pos < len(payload):
        info["attrs"] = parse_attrs(payload, pos)
    return info


def parse_attrs(payload: bytes, pos: int) -> dict[str, str]:
    """Connection attributes (a lenenc total, then lenenc key/value pairs), at most 32."""
    attrs: dict[str, str] = {}
    total, pos = read_lenenc_int(payload, pos)
    if pos + total > len(payload):
        raise ValueError("connect attrs past end of packet")
    end = pos + total
    while pos < end and len(attrs) < 32:
        kl, pos = read_lenenc_int(payload, pos)
        k, pos = _span(payload, pos, kl)
        vl, pos = read_lenenc_int(payload, pos)
        v, pos = _span(payload, pos, vl)
        attrs[k.decode("utf-8", "replace")[:64]] = v.decode("utf-8", "replace")[:256]
    return attrs


def client_string(attrs: dict[str, str]) -> Optional[str]:
    if not attrs:
        return None
    parts = [attrs.get("program_name", ""), attrs.get("_client_name", ""),
             attrs.get("_client_version", "")]
    plat = "/".join(x for x in (attrs.get("_os", ""), attrs.get("_platform", "")) if x)
    text = " ".join(p for p in parts if p)
    if plat:
        text += f" ({plat})"
    return text or None


# ---- connection ---------------------------------------------------------------------------

async def handle(conn: Conn) -> None:
    settings = conn.ctx.service("mysql")
    version = settings.version or DEFAULT_VERSIONS["mysql"]
    salt = bytes((b % 94) + 33 for b in os.urandom(20))
    conn_id = 8 + int.from_bytes(os.urandom(2), "big")
    pk = Packets(0)
    pk.add(handshake_v10(version, conn_id, salt))
    await conn.write(pk.buf)

    seq, payload = await read_packet(conn, MAX_AUTH_PACKET)
    if len(payload) < 32:
        flags = int.from_bytes(payload[0:4], "little") if len(payload) >= 4 else 0
        if flags & CLIENT_SSL:
            conn.emit("command", "Client requested TLS (not offered)", data={"request": "ssl"})
        else:
            conn.emit("error", "Short handshake response", data={"reason": "malformed"})
            await conn.write(bad_handshake(seq))
        return
    flags = int.from_bytes(payload[0:4], "little")
    if not flags & CLIENT_PROTOCOL_41:
        conn.emit("error", "Pre-4.1 client", data={"reason": "old_protocol"})
        out = Packets(seq + 1)
        out.add(err_packet(1251, "08004", "Client does not support authentication protocol "
                           "requested by server; consider upgrading MySQL client"))
        await conn.write(out.buf)
        return
    try:
        info = parse_response41(payload)
    except (ValueError, IndexError):
        conn.emit("error", "Malformed handshake response", data={"reason": "malformed"})
        await conn.write(bad_handshake(seq))
        return
    caps = SERVER_CAPS & info["flags"]
    username = info["username"]
    plugin = info["plugin"] or NATIVE
    auth = info["auth"]
    next_seq = seq + 1
    switched = False
    if plugin not in (NATIVE, SHA2) and caps & CLIENT_PLUGIN_AUTH:
        # Ask the client to redo the scramble with mysql_native_password.
        sw = Packets(next_seq)
        sw.add(b"\xfe" + NATIVE.encode() + b"\x00" + salt + b"\x00")
        await conn.write(sw.buf)
        seq, auth = await read_packet(conn, MAX_AUTH_PACKET)
        auth = auth[:256]
        next_seq = seq + 1
        switched = True
        conn.emit("command", "Auth plugin switch", data={"from_plugin": info["plugin"],
                                                         "to_plugin": NATIVE})
        plugin = NATIVE
    elif plugin not in (NATIVE, SHA2):
        plugin = NATIVE
    recovered = recover_password(auth, salt, plugin, username, settings.accounts)
    attrs = info["attrs"]
    data = {"database": info["database"], "salt": salt.hex(), "auth_response": auth.hex(),
            "auth_plugin": plugin, "client_plugin": info["plugin"], "password_recovered":
            recovered is not None, "client_flags": f"{info['flags']:08x}", "auth_switched": switched}
    for k, v in list(attrs.items())[:10]:
        data[f"attr_{k}"[:64]] = v
    password = recovered if recovered is not None else "<unrecovered>"
    ok = conn.login(username, password, client=client_string(attrs), data=data)
    out = Packets(next_seq)
    if not ok:
        out.add(err_packet(1045, "28000", f"Access denied for user '{wire_text(username, 64)}'@"
                           f"'{conn.src_ip}' (using password: {'YES' if auth else 'NO'})"))
        await conn.write(out.buf)
        return
    fake = FakeSql(conn, "mysql", username, info["database"], version=version,
                   port=conn.dst_port if isinstance(conn.dst_port, int) else 3306)
    if info["database"] and not fake.db_exists(info["database"]):
        out.add(err_packet(1049, "42000", f"Unknown database '{wire_text(info['database'], 64)}'"))
        await conn.write(out.buf)
        return
    if info["database"]:
        fake.database = fake.catalog[info["database"].lower()].name
    if plugin == SHA2:
        out.add(b"\x01\x03")  # fast_auth_success
    out.add(ok_packet())
    await conn.write(out.buf)
    await command_loop(conn, Session(fake, caps, salt, settings))


# ---- result sets ---------------------------------------------------------------------------

def binary_kinds(rows: list[list], ncols: int) -> list[str]:
    """Column kinds for binary-protocol rows: an int column whose values do not fit a signed
    64-bit integer, or a float column with a value too large for a double, is sent as text."""
    kinds = []
    for i in range(ncols):
        kind = column_kind(rows, i)
        values = [r[i] for r in rows if i < len(r) and r[i] is not None]
        if kind == "int" and any(not -(1 << 63) <= v < (1 << 63) for v in values):
            kind = "text"
        elif kind == "float":
            try:
                for v in values:
                    float(v)
            except OverflowError:
                kind = "text"
        kinds.append(kind)
    return kinds


def binary_row(values: list, kinds: list[str]) -> bytes:
    """ProtocolBinary::ResultsetRow: 0x00, a NULL bitmap offset by two bits, then the values."""
    bitmap = bytearray((len(kinds) + 9) // 8)
    body = b""
    for i, kind in enumerate(kinds):
        v = values[i] if i < len(values) else None
        if v is None:
            bitmap[(i + 2) // 8] |= 1 << ((i + 2) % 8)
        elif kind == "int":
            body += int(v).to_bytes(8, "little", signed=True)
        elif kind == "float":
            body += struct.pack("<d", float(v))
        elif kind == "bool":
            body += b"\x01" if v else b"\x00"
        else:
            body += lenenc_str(cell_text(v, "mysql") or "")
    return b"\x00" + bytes(bitmap) + body


def add_answer(pk: Packets, answer, caps: int, db: str, binary: bool = False,
               more: bool = False) -> None:
    """One answer as an OK, ERR or result set; ``more`` sets SERVER_MORE_RESULTS_EXISTS."""
    status = STATUS_AUTOCOMMIT | (STATUS_MORE_RESULTS if more else 0)
    if isinstance(answer, SqlError):
        pk.add(err_packet(answer.errno or 1064, answer.code, answer.message))
        return
    if not answer.is_query or answer.tag == "EMPTY":
        if answer.tag == "EMPTY":
            pk.add(err_packet(1065, "42000", "Query was empty"))
        else:
            pk.add(ok_packet(answer.affected, status=status))
        return
    ncols = len(answer.columns)
    kinds = (binary_kinds(answer.rows, ncols) if binary
             else [column_kind(answer.rows, i) for i in range(ncols)])
    pk.add(lenenc_int(ncols))
    for name, kind in zip(answer.columns, kinds, strict=True):
        pk.add(column_def(name, db, kind))
    if not caps & CLIENT_DEPRECATE_EOF:
        pk.add(eof_packet(status))
    for row in answer.rows:
        pk.add(binary_row(row, kinds) if binary else text_row(row))
    pk.add(ok_packet(0, header=0xFE, status=status) if caps & CLIENT_DEPRECATE_EOF
           else eof_packet(status))


def render(answer, caps: int, db: str, seq: int, binary: bool = False) -> bytes:
    pk = Packets(seq)
    add_answer(pk, answer, caps, db, binary)
    return bytes(pk.buf)


def render_all(answers: list, caps: int, db: str, seq: int) -> bytes:
    """Every answer of a (multi-statement) query; all but the last carry MORE_RESULTS."""
    pk = Packets(seq)
    for i, ans in enumerate(answers):
        add_answer(pk, ans, caps, db, more=i < len(answers) - 1)
    return bytes(pk.buf)


# ---- prepared statements ------------------------------------------------------------------

# Quoted text from just after the opening quote through the closing one; a doubled quote or
# a backslash escape stays inside. Possessive quantifiers keep the match linear.
_QUOTE_END = {
    "'": re.compile(r"[^'\\]*+(?:(?:\\.|'')[^'\\]*+)*+'", re.S),
    '"': re.compile(r'[^"\\]*+(?:(?:\\.|"")[^"\\]*+)*+"', re.S),
    "`": re.compile(r"[^`]*+(?:``[^`]*+)*+`"),
}
_PS_SPECIAL = re.compile(r"['\"`#?/-]")


def placeholders(sql: str, cap: int = MAX_PARAMS + 1) -> list[int]:
    """Offsets of ``?`` markers outside quotes and comments, by the server's lexical rules:
    backslash escapes and doubled quotes inside quotes, ``--`` followed by a blank, ``#``
    and ``/* */`` comments, and the body of an executable ``/*! */`` comment read as code.
    Scanning stops after ``cap`` markers or at an unterminated quote or comment."""
    marks: list[int] = []
    n = len(sql)
    i = 0
    while len(marks) < cap:
        m = _PS_SPECIAL.search(sql, i)
        if m is None:
            break
        i = m.start()
        ch = sql[i]
        if ch == "?":
            marks.append(i)
            i += 1
        elif ch in "'\"`":
            q = _QUOTE_END[ch].match(sql, i + 1)
            if q is None:
                break
            i = q.end()
        elif ch == "#" or (sql.startswith("--", i) and (i + 2 >= n or sql[i + 2] in " \t\r\n\f\v")):
            end = sql.find("\n", i)
            if end < 0:
                break
            i = end + 1
        elif sql.startswith("/*!", i):
            i += 3
        elif sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            if end < 0:
                break
            i = end + 2
        else:
            i += 1
    return marks


def quote_text(text: str) -> str:
    """A string literal that the engine reads back as ``text``: quotes are doubled and
    backslashes stay as they are, since the engine reads them literally."""
    return "'" + text.replace("'", "''") + "'"


def bind_params(sql: str, marks, literals: list[str]) -> str:
    """``sql`` with the marker at each offset replaced by its literal, in one pass."""
    parts: list[str] = []
    prev = 0
    for pos, lit in zip(marks, literals, strict=True):
        parts.append(sql[prev:pos])
        parts.append(lit)
        prev = pos + 1
    parts.append(sql[prev:])
    return "".join(parts)


def _float_literal(v: float) -> str:
    if v != v or v in (float("inf"), float("-inf")):
        return "NULL"
    text = repr(v)
    mantissa, _, exp = text.partition("e")
    if exp and "." not in mantissa:
        text = f"{mantissa}.0e{exp}"
    return text


_INT_WIDTH = {TYPE_TINY: 1, TYPE_SHORT: 2, TYPE_YEAR: 2, TYPE_LONG: 4, TYPE_INT24: 4,
              TYPE_LONGLONG: 8}
_NUMERIC_TEXT = re.compile(r"-?\d{1,65}(\.\d{1,30})?")


def param_literal(buf: bytes, pos: int, ptype: int, unsigned: bool) -> tuple[str, int]:
    """One binary-protocol parameter value as a SQL literal. Types the server does not
    know as numeric or temporal are read as length-encoded strings, as the server does."""
    if ptype in _INT_WIDTH:
        raw, pos = _span(buf, pos, _INT_WIDTH[ptype])
        return str(int.from_bytes(raw, "little", signed=not unsigned)), pos
    if ptype == TYPE_FLOAT:
        raw, pos = _span(buf, pos, 4)
        return _float_literal(struct.unpack("<f", raw)[0]), pos
    if ptype == TYPE_DOUBLE:
        raw, pos = _span(buf, pos, 8)
        return _float_literal(struct.unpack("<d", raw)[0]), pos
    if ptype == TYPE_NULL:
        return "NULL", pos
    if ptype in (TYPE_DATE, TYPE_DATETIME, TYPE_TIMESTAMP):
        n, pos = _span(buf, pos, 1)
        if n[0] not in (0, 4, 7, 11):
            raise ValueError("bad temporal length")
        raw, pos = _span(buf, pos, n[0])
        raw = raw.ljust(11, b"\x00")
        year = int.from_bytes(raw[0:2], "little")
        text = f"{year:04d}-{raw[2]:02d}-{raw[3]:02d}"
        if ptype != TYPE_DATE:
            text += f" {raw[4]:02d}:{raw[5]:02d}:{raw[6]:02d}"
            if n[0] == 11:
                text += f".{int.from_bytes(raw[7:11], 'little') % 1000000:06d}"
        return quote_text(text), pos
    if ptype == TYPE_TIME:
        n, pos = _span(buf, pos, 1)
        if n[0] not in (0, 8, 12):
            raise ValueError("bad time length")
        raw, pos = _span(buf, pos, n[0])
        raw = raw.ljust(12, b"\x00")
        hours = int.from_bytes(raw[1:5], "little") * 24 + raw[5]
        text = f"{'-' if raw[0] else ''}{hours:02d}:{raw[6]:02d}:{raw[7]:02d}"
        if n[0] == 12:
            text += f".{int.from_bytes(raw[8:12], 'little') % 1000000:06d}"
        return quote_text(text), pos
    ln, pos = read_lenenc_int(buf, pos)
    raw, pos = _span(buf, pos, ln)
    text = raw.decode("utf-8", "replace")
    if ptype in (TYPE_DECIMAL, TYPE_NEWDECIMAL) and _NUMERIC_TEXT.fullmatch(text):
        return text, pos
    return quote_text(text), pos


@dataclass
class Prepared:
    """A prepared statement: marker offsets (compact), and the parameter types as sent
    (two bytes each: type, flags) once a COM_STMT_EXECUTE has bound them."""
    sql: str
    marks: array
    types: Optional[bytes] = None
    long_data: dict[int, bytearray] = field(default_factory=dict)
    long_bytes: int = 0
    error: Optional[tuple[int, str]] = None   # reported by the next execute


class Session:
    """Per-connection state after login."""

    def __init__(self, fake: FakeSql, caps: int, salt: bytes, settings: ServiceSettings) -> None:
        self.fake = fake
        self.caps = caps
        self.salt = salt
        self.settings = settings
        self.stmts: dict[int, Prepared] = {}
        self.next_id = 1
        self.long_total = 0
        self.multi = False

    def drop(self, stmt_id: int) -> None:
        stmt = self.stmts.pop(stmt_id, None)
        if stmt is not None:
            self.long_total -= stmt.long_bytes

    def clear_long_data(self, stmt: Prepared) -> None:
        self.long_total -= stmt.long_bytes
        stmt.long_bytes = 0
        stmt.long_data.clear()

    def drop_all(self) -> None:
        self.stmts.clear()
        self.long_total = 0


def malformed_packet() -> bytes:
    return err_packet(1835, "HY000", "Malformed communication packet.")


def unknown_stmt(stmt_id: int, where: str) -> bytes:
    return err_packet(1243, "HY000", f"Unknown prepared statement handler ({stmt_id}) given to {where}")


def param_def() -> bytes:
    return (lenenc_str("def") + lenenc_str("") * 3 + lenenc_str("?") + lenenc_str("") + b"\x0c"
            + (63).to_bytes(2, "little") + (0).to_bytes(4, "little") + bytes([TYPE_VAR_STRING])
            + (0x0080).to_bytes(2, "little") + b"\x00\x00\x00")


async def stmt_prepare(conn: Conn, sess: Session, sql: str, seq: int) -> None:
    fake = sess.fake
    if len(sess.stmts) >= MAX_PREPARED:
        conn.emit("limit", "Prepared statement limit", data={"reason": "max_prepared"})
        pk = Packets(seq)
        pk.add(err_packet(1461, "42000", "Can't create more than max_prepared_stmt_count "
                          "statements (current value: 16382)"))
        await conn.write(pk.buf)
        return
    if len(sql) > MAX_STATEMENT_CHARS or len(split_statements(strip_comments(sql))) != 1:
        # Empty, oversized or several statements: the engine's own error (logged there).
        answers = await fake.run(sql, multi=False)
        await conn.write(render(answers[-1], sess.caps, fake.database, seq))
        return
    marks = placeholders(sql)
    data = {"command": "stmt_prepare", "statement": sql[:2000], "params": len(marks)}
    token = conn.ctx.honeytoken_in(sql)
    if token:
        data.update(honeytoken=token, high_signal=True)
    pk = Packets(seq)
    if len(marks) > MAX_PARAMS:
        conn.emit("command", "COM_STMT_PREPARE", username=fake.user, data=data)
        pk.add(err_packet(1390, "HY000", "Prepared statement contains too many placeholders"))
        await conn.write(pk.buf)
        return
    stmt_id = sess.next_id
    sess.next_id = (sess.next_id + 1) & 0xFFFFFFFF or 1
    sess.stmts[stmt_id] = Prepared(sql, array("I", marks))
    data["statement_id"] = stmt_id
    conn.emit("command", "COM_STMT_PREPARE", username=fake.user, data=data)
    pk.add(b"\x00" + stmt_id.to_bytes(4, "little") + (0).to_bytes(2, "little")
           + len(marks).to_bytes(2, "little") + b"\x00" + (0).to_bytes(2, "little"))
    if marks:
        for _ in marks:
            pk.add(param_def())
        if not sess.caps & CLIENT_DEPRECATE_EOF:
            pk.add(eof_packet())
    await conn.write(pk.buf)


def parse_execute(payload: bytes, stmt: Prepared) -> Optional[list[str]]:
    """The bound literals of a COM_STMT_EXECUTE, or None when no parameter types were ever
    sent. Raises ValueError or IndexError for a malformed packet."""
    n = len(stmt.marks)
    if len(payload) < 10:
        raise ValueError("short execute")
    if not n:
        return []
    pos = 10
    nulls, pos = _span(payload, pos, (n + 7) // 8)
    bound, pos = _span(payload, pos, 1)
    if bound[0] == 1:
        stmt.types, pos = _span(payload, pos, 2 * n)
    if stmt.types is None:
        return None
    literals = []
    types = stmt.types
    for i in range(n):
        ptype, unsigned = types[2 * i], bool(types[2 * i + 1] & 0x80)
        if nulls[i // 8] & (1 << (i % 8)):
            literals.append("NULL")
        elif i in stmt.long_data:
            literals.append(quote_text(stmt.long_data[i].decode("utf-8", "replace")))
        else:
            lit, pos = param_literal(payload, pos, ptype, unsigned)
            literals.append(lit)
    return literals


async def stmt_execute(conn: Conn, sess: Session, payload: bytes, seq: int) -> None:
    pk = Packets(seq)
    stmt_id = int.from_bytes(payload[1:5], "little") if len(payload) >= 5 else -1
    stmt = sess.stmts.get(stmt_id)
    if stmt is None:
        conn.emit("command", "COM_STMT_EXECUTE", data={"command": "stmt_execute",
                                                       "statement_id": stmt_id, "known": False})
        pk.add(malformed_packet() if stmt_id < 0 else unknown_stmt(stmt_id, "mysqld_stmt_execute"))
        await conn.write(pk.buf)
        return
    if stmt.error is not None:
        errno, message = stmt.error
        stmt.error = None
        sess.clear_long_data(stmt)
        pk.add(err_packet(errno, "HY000", message))
        await conn.write(pk.buf)
        return
    try:
        literals = parse_execute(payload, stmt)
    except (ValueError, IndexError):
        conn.emit("error", "Malformed COM_STMT_EXECUTE", data={"reason": "malformed",
                                                              "statement_id": stmt_id})
        pk.add(malformed_packet())
        await conn.write(pk.buf)
        return
    sess.clear_long_data(stmt)
    if literals is None:
        pk.add(err_packet(1210, "HY000", "Incorrect arguments to mysqld_stmt_execute"))
        await conn.write(pk.buf)
        return
    fake = sess.fake
    answers = await fake.run(bind_params(stmt.sql, stmt.marks, literals), multi=False)
    await conn.write(render(answers[-1], sess.caps, fake.database, seq, binary=True))


def stmt_long_data(conn: Conn, sess: Session, payload: bytes) -> None:
    """COM_STMT_SEND_LONG_DATA: no reply. Bytes past the caps are dropped."""
    if len(payload) < 7:
        conn.emit("error", "Malformed COM_STMT_SEND_LONG_DATA", data={"reason": "malformed"})
        return
    stmt = sess.stmts.get(int.from_bytes(payload[1:5], "little"))
    if stmt is None:
        return
    param = int.from_bytes(payload[5:7], "little")
    if param >= len(stmt.marks):
        stmt.error = (1210, "Incorrect arguments to mysqld_stmt_send_long_data")
        return
    chunk = payload[7:]
    room = min(MAX_LONG_DATA - stmt.long_bytes, MAX_LONG_DATA_TOTAL - sess.long_total)
    if len(chunk) > room:
        conn.emit("limit", "Long data truncated", data={"reason": "long_data", "dropped":
                                                        len(chunk) - max(room, 0)})
        chunk = chunk[:max(room, 0)]
    stmt.long_data.setdefault(param, bytearray()).extend(chunk)
    stmt.long_bytes += len(chunk)
    sess.long_total += len(chunk)


# ---- COM_CHANGE_USER ----------------------------------------------------------------------

def parse_change_user(payload: bytes, caps: int) -> dict:
    end = payload.find(b"\x00", 1)
    if end < 0 or end + 1 >= len(payload):
        raise ValueError("short COM_CHANGE_USER")
    info: dict = {"username": payload[1:end].decode("utf-8", "replace")[:128]}
    pos = end + 1
    if caps & CLIENT_SECURE_CONNECTION:
        auth, pos = _span(payload, pos + 1, payload[pos])
    else:
        auth, pos = _cstring(payload, pos)
    info["auth"] = bytes(auth[:256])
    db, pos = _cstring(payload, pos)
    info["database"] = db.decode("utf-8", "replace")[:128]
    info["plugin"] = ""
    info["attrs"] = {}
    if pos + 2 <= len(payload):
        pos += 2  # character set
        if caps & CLIENT_PLUGIN_AUTH and pos < len(payload):
            plugin, pos = _cstring(payload, pos)
            info["plugin"] = plugin.decode("utf-8", "replace")[:64]
        if caps & CLIENT_CONNECT_ATTRS and pos < len(payload):
            info["attrs"] = parse_attrs(payload, pos)
    return info


async def change_user(conn: Conn, sess: Session, payload: bytes, seq: int) -> bool:
    """Re-authenticate against the scramble from the greeting; False closes the connection."""
    pk = Packets(seq)
    try:
        info = parse_change_user(payload, sess.caps)
    except (ValueError, IndexError):
        conn.emit("error", "Malformed COM_CHANGE_USER", data={"reason": "malformed"})
        pk.add(err_packet(1047, "08S01", "Unknown command"))
        await conn.write(pk.buf)
        return False
    username = info["username"]
    plugin = info["plugin"] if info["plugin"] in (NATIVE, SHA2) else NATIVE
    auth = info["auth"]
    recovered = recover_password(auth, sess.salt, plugin, username, sess.settings.accounts)
    data = {"command": "change_user", "database": info["database"], "salt": sess.salt.hex(),
            "auth_response": auth.hex(), "auth_plugin": plugin, "client_plugin": info["plugin"],
            "password_recovered": recovered is not None}
    for k, v in list(info["attrs"].items())[:10]:
        data[f"attr_{k}"[:64]] = v
    ok = conn.login(username, recovered if recovered is not None else "<unrecovered>",
                    client=client_string(info["attrs"]), data=data)
    if not ok:
        pk.add(err_packet(1045, "28000", f"Access denied for user '{wire_text(username, 64)}'@"
                          f"'{conn.src_ip}' (using password: {'YES' if auth else 'NO'})"))
        await conn.write(pk.buf)
        return False
    fake = sess.fake
    db = info["database"]
    if db and not fake.db_exists(db):
        pk.add(err_packet(1049, "42000", f"Unknown database '{wire_text(db, 64)}'"))
        await conn.write(pk.buf)
        return False
    sess.drop_all()
    fake.user = username
    fake.database = fake.catalog[db.lower()].name if db else ""
    if plugin == SHA2:
        pk.add(b"\x01\x03")  # fast_auth_success
    pk.add(ok_packet())
    await conn.write(pk.buf)
    return True


# ---- command loop -------------------------------------------------------------------------

async def command_loop(conn: Conn, sess: Session) -> None:
    fake = sess.fake
    caps = sess.caps
    while True:
        seq, payload = await read_packet(conn)
        if not payload:
            continue
        cmd = payload[0]
        if cmd == 0x01:
            conn.emit("command", "COM_QUIT", data={"command": "quit"})
            return
        if not conn.command():
            return
        pk = Packets(seq + 1)
        if cmd == 0x03:
            sql = payload[1:].decode("utf-8", "replace")
            answers = await fake.run(sql, multi=sess.multi)
            await conn.write(render_all(answers, caps, fake.database, seq + 1))
        elif cmd == 0x02:
            name = payload[1:].decode("utf-8", "replace")[:64]
            answers = await fake.run(f"USE `{name.replace('`', '')}`")
            await conn.write(render(answers[-1], caps, fake.database, seq + 1))
        elif cmd == 0x16:
            await stmt_prepare(conn, sess, payload[1:].decode("utf-8", "replace"), seq + 1)
        elif cmd == 0x17:
            await stmt_execute(conn, sess, payload, seq + 1)
        elif cmd == 0x18:
            stmt_long_data(conn, sess, payload)
        elif cmd == 0x19:
            if len(payload) >= 5:
                stmt_id = int.from_bytes(payload[1:5], "little")
                conn.emit("command", "COM_STMT_CLOSE", data={"command": "stmt_close",
                                                             "statement_id": stmt_id})
                sess.drop(stmt_id)
        elif cmd == 0x1A:
            stmt_id = int.from_bytes(payload[1:5], "little") if len(payload) >= 5 else -1
            stmt = sess.stmts.get(stmt_id)
            if stmt_id < 0:
                pk.add(malformed_packet())
            elif stmt is None:
                pk.add(unknown_stmt(stmt_id, "mysqld_stmt_reset"))
            else:
                sess.clear_long_data(stmt)
                stmt.error = None
                pk.add(ok_packet())
            await conn.write(pk.buf)
        elif cmd == 0x1B:
            option = int.from_bytes(payload[1:3], "little") if len(payload) >= 3 else -1
            conn.emit("command", "COM_SET_OPTION", data={"command": "set_option", "option": option})
            if option < 0:
                pk.add(malformed_packet())
            elif option > 1:
                pk.add(err_packet(1047, "08S01", "Unknown command"))
            else:
                sess.multi = option == 0
                pk.add(ok_packet(0, header=0xFE) if caps & CLIENT_DEPRECATE_EOF else eof_packet())
            await conn.write(pk.buf)
        elif cmd == 0x1F:
            conn.emit("command", "COM_RESET_CONNECTION", data={"command": "reset_connection"})
            sess.drop_all()
            pk.add(ok_packet())
            await conn.write(pk.buf)
        elif cmd == 0x11:
            if not await change_user(conn, sess, payload, seq + 1):
                return
        elif cmd == 0x0E:
            conn.emit("command", "COM_PING", data={"command": "ping"})
            pk.add(ok_packet())
            await conn.write(pk.buf)
        elif cmd == 0x09:
            conn.emit("command", "COM_STATISTICS", data={"command": "statistics"})
            pk.add(b"Uptime: 2764812  Threads: 3  Questions: 1840221  Slow queries: 12  "
                   b"Opens: 1622  Flush tables: 3  Open tables: 812  Queries per second avg: 0.665")
            await conn.write(pk.buf)
        elif cmd == 0x04:
            table = payload[1:].split(b"\x00", 1)[0].decode("utf-8", "replace")[:64]
            conn.emit("command", "COM_FIELD_LIST", data={"command": "field_list", "table": table})
            pk.add(ok_packet(0, header=0xFE) if caps & CLIENT_DEPRECATE_EOF else eof_packet())
            await conn.write(pk.buf)
        else:
            conn.emit("command", "Unsupported command", data={"command": f"0x{cmd:02x}",
                                                              "payload": payload[1:200].hex()})
            pk.add(err_packet(1047, "08S01", "Unknown command"))
            await conn.write(pk.buf)


async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    server = await start_tcp(ctx, "mysql", settings.port, handle)
    return [server]
