"""Fake MySQL server (protocol 10, text protocol).

HandshakeV10 with a random salt and mysql_native_password (no CLIENT_SSL). The
HandshakeResponse41 is parsed (user, auth response, database, plugin, connect attrs);
the password is recovered by testing the scramble against the configured accounts and a
common-password list for both mysql_native_password (SHA1) and caching_sha2_password
(SHA256). ``conn.login`` decides. After login, COM_QUERY is answered by
``listeners.sqlfake``. Nothing is executed.
"""

from __future__ import annotations

import hashlib
import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from listeners.base import Conn, ConnClosed, ListenerContext, ServiceSettings, start_tcp
from listeners.sqlfake import (DEFAULT_VERSIONS, FakeSql, SqlError, cell_text, column_kind,
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
NATIVE = "mysql_native_password"
SHA2 = "caching_sha2_password"
MAX_PACKET = 1 << 20
MAX_AUTH_PACKET = 8192
MAX_CANDIDATES = 2000

TYPE_LONGLONG = 0x08
TYPE_DOUBLE = 0x05
TYPE_TINY = 0x01
TYPE_VAR_STRING = 0xFD

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
    h1 = hashlib.sha1(password.encode("utf-8")).digest()
    h2 = hashlib.sha1(h1).digest()
    return _xor(h1, hashlib.sha1(salt + h2).digest())


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


def ok_packet(affected: int = 0, header: int = 0x00) -> bytes:
    return (bytes([header]) + lenenc_int(affected) + lenenc_int(0)
            + STATUS_AUTOCOMMIT.to_bytes(2, "little") + b"\x00\x00")


def err_packet(errno: int, sqlstate: str, message: str) -> bytes:
    state = (sqlstate + "HY000")[:5].encode("ascii", "replace")
    return (b"\xff" + errno.to_bytes(2, "little") + b"#" + state
            + wire_text(message, 512).encode("utf-8", "replace"))


def bad_handshake(seq: int) -> bytes:
    """ER_HANDSHAKE_ERROR, what the server sends for an unparseable handshake response."""
    pk = Packets(seq + 1)
    pk.add(b"\xff" + (1043).to_bytes(2, "little") + b"#08S01Bad handshake")
    return pk.buf


def eof_packet() -> bytes:
    return b"\xfe\x00\x00" + STATUS_AUTOCOMMIT.to_bytes(2, "little")


def column_def(name: str, db: str, kind: str) -> bytes:
    if kind == "int":
        ctype, charset, length, flags = TYPE_LONGLONG, 63, 21, 0x0080 | 0x0020
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
        self.buf = b""

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
    attrs: dict[str, str] = {}
    if flags & CLIENT_CONNECT_ATTRS and pos < len(payload):
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
    info["attrs"] = attrs
    return info


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
    await command_loop(conn, fake, caps)


def render(answer, caps: int, db: str, seq: int) -> bytes:
    pk = Packets(seq)
    if isinstance(answer, SqlError):
        pk.add(err_packet(answer.errno or 1064, answer.code, answer.message))
        return pk.buf
    if not answer.is_query or answer.tag == "EMPTY":
        if answer.tag == "EMPTY":
            pk.add(err_packet(1065, "42000", "Query was empty"))
        else:
            pk.add(ok_packet(answer.affected))
        return pk.buf
    pk.add(lenenc_int(len(answer.columns)))
    for i, name in enumerate(answer.columns):
        pk.add(column_def(name, db, column_kind(answer.rows, i)))
    if not caps & CLIENT_DEPRECATE_EOF:
        pk.add(eof_packet())
    for row in answer.rows:
        pk.add(text_row(row))
    pk.add(ok_packet(0, header=0xFE) if caps & CLIENT_DEPRECATE_EOF else eof_packet())
    return pk.buf


async def command_loop(conn: Conn, fake: FakeSql, caps: int) -> None:
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
        if cmd == 0x03:
            sql = payload[1:].decode("utf-8", "replace")
            answers = await fake.run(sql, multi=False)
            await conn.write(render(answers[-1], caps, fake.database, seq + 1))
        elif cmd == 0x02:
            name = payload[1:].decode("utf-8", "replace")[:64]
            answers = await fake.run(f"USE `{name.replace('`', '')}`")
            await conn.write(render(answers[-1], caps, fake.database, seq + 1))
        elif cmd == 0x0E:
            conn.emit("command", "COM_PING", data={"command": "ping"})
            pk = Packets(seq + 1)
            pk.add(ok_packet())
            await conn.write(pk.buf)
        elif cmd == 0x09:
            conn.emit("command", "COM_STATISTICS", data={"command": "statistics"})
            pk = Packets(seq + 1)
            pk.add(b"Uptime: 2764812  Threads: 3  Questions: 1840221  Slow queries: 12  "
                   b"Opens: 1622  Flush tables: 3  Open tables: 812  Queries per second avg: 0.665")
            await conn.write(pk.buf)
        elif cmd == 0x04:
            table = payload[1:].split(b"\x00", 1)[0].decode("utf-8", "replace")[:64]
            conn.emit("command", "COM_FIELD_LIST", data={"command": "field_list", "table": table})
            pk = Packets(seq + 1)
            pk.add(ok_packet(0, header=0xFE) if caps & CLIENT_DEPRECATE_EOF else eof_packet())
            await conn.write(pk.buf)
        else:
            conn.emit("command", "Unsupported command", data={"command": f"0x{cmd:02x}",
                                                              "payload": payload[1:200].hex()})
            pk = Packets(seq + 1)
            pk.add(err_packet(1047, "08S01", "Unknown command"))
            await conn.write(pk.buf)


async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    server = await start_tcp(ctx, "mysql", settings.port, handle)
    return [server]
