"""Fake Microsoft SQL Server (TDS 7.x, no TLS).

PRELOGIN is answered with ENCRYPT_NOT_SUP. A client that insists on encryption
(ENCRYPT_ON / ENCRYPT_REQ) cannot continue without TLS: that is logged and the
connection is closed after the PRELOGIN reply. LOGIN7 is parsed (offset/length table,
UCS-2LE strings, password de-obfuscated: XOR 0xA5 then swap nibbles) and decided by
``conn.login``. After a fake login, SQL batches are answered by ``listeners.sqlfake``
with every column rendered as NVARCHAR. RPC requests for sp_executesql, sp_prepare,
sp_execute, sp_prepexec and sp_unprepare bind their parameters (by position, then by name)
into the statement text as literals and answer it through the same engine, with a return
status and DONEPROC; other procedures get the server's permission error. A request that
batches several calls gets each answered in order. Nothing is executed. Enabled per
scenario (contact_center turns it on).
"""

from __future__ import annotations

import datetime
import re
import struct
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Optional, Union

from listeners.base import Conn, ConnClosed, ListenerContext, ServiceSettings, start_tcp
from listeners.sqlfake import (DEFAULT_VERSIONS, FakeSql, SqlError, cell_text, classify_dangerous,
                               safe_name, wire_text)

PKT_SQL_BATCH = 0x01
PKT_RPC = 0x03
PKT_REPLY = 0x04
PKT_ATTENTION = 0x06
PKT_LOGIN7 = 0x10
PKT_PRELOGIN = 0x12

ENCRYPT_OFF, ENCRYPT_ON, ENCRYPT_NOT_SUP, ENCRYPT_REQ = 0, 1, 2, 3
MAX_TDS_PACKET = 32768
MAX_LOGIN = 16384
MAX_BATCH = 1 << 20
OUT_PACKET = 4096
COLLATION = bytes([0x09, 0x04, 0xD0, 0x00, 0x34])  # SQL_Latin1_General_CP1_CI_AS
TDS74 = 0x74000004
KNOWN_TDS = {0x71000000, 0x71000001, 0x72090002, 0x730A0003, 0x730B0003, 0x74000004}


# ---- encoders -----------------------------------------------------------------------------

def ucs2(s: str) -> bytes:
    return s.encode("utf-16-le", "replace")


def ucs2_units(s: str, max_units: int) -> bytes:
    """UTF-16LE text cut to at most ``max_units`` code units without splitting a
    surrogate pair. TDS length prefixes count code units, not characters."""
    raw = ucs2(s[:max_units])
    if len(raw) > 2 * max_units:
        raw = raw[:2 * max_units]
        if 0xD800 <= int.from_bytes(raw[-2:], "little") <= 0xDBFF:
            raw = raw[:-2]
    return raw


def b_varchar(s: str) -> bytes:
    raw = ucs2_units(s, 255)
    return bytes([len(raw) // 2]) + raw


def us_varchar(s: str) -> bytes:
    raw = ucs2_units(s, 4000)
    return (len(raw) // 2).to_bytes(2, "little") + raw


def packets(ptype: int, payload: bytes) -> bytes:
    out = b""
    chunks = [payload[i:i + OUT_PACKET - 8] for i in range(0, len(payload), OUT_PACKET - 8)] or [b""]
    for i, chunk in enumerate(chunks):
        status = 0x01 if i == len(chunks) - 1 else 0x00
        out += (bytes([ptype, status]) + (len(chunk) + 8).to_bytes(2, "big") + b"\x00\x00"
                + bytes([(i + 1) & 0xFF, 0]) + chunk)
    return out


def message_token(token: int, number: int, state: int, klass: int, message: str, server: str,
                  wide_line: bool = True) -> bytes:
    body = (number.to_bytes(4, "little") + bytes([state, klass]) + us_varchar(wire_text(message, 2000))
            + b_varchar(server) + b_varchar("")
            + (1).to_bytes(4 if wide_line else 2, "little"))
    return bytes([token]) + len(body).to_bytes(2, "little") + body


def done(status: int = 0, curcmd: int = 0, rowcount: int = 0, wide: bool = True) -> bytes:
    return (b"\xFD" + status.to_bytes(2, "little") + curcmd.to_bytes(2, "little")
            + rowcount.to_bytes(8 if wide else 4, "little"))


def envchange(kind: int, new: str, old: str) -> bytes:
    body = bytes([kind]) + b_varchar(new) + b_varchar(old)
    return b"\xE3" + len(body).to_bytes(2, "little") + body


def envchange_collation() -> bytes:
    body = bytes([7, len(COLLATION)]) + COLLATION + b"\x00"
    return b"\xE3" + len(body).to_bytes(2, "little") + body


def version_parts(version: str) -> tuple[int, int, int]:
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return 15, 0, 4322
    return int(m.group(1)) & 0xFF, int(m.group(2)) & 0xFF, int(m.group(3)) & 0xFFFF


def prelogin_reply(version: str) -> bytes:
    major, minor, build = version_parts(version)
    # VERSION, ENCRYPTION, INSTOPT, THREADID only, in this order. MARS is optional in a
    # reply, and common clients (impacket) parse the reply positionally and misread the
    # encryption flag when a fifth option is present.
    opts = [
        (0x00, bytes([major, minor]) + build.to_bytes(2, "big") + b"\x00\x00"),
        (0x01, bytes([ENCRYPT_NOT_SUP])),
        (0x02, b"\x00"),
        (0x03, b""),
    ]
    header_len = len(opts) * 5 + 1
    head, data = b"", b""
    for tok, val in opts:
        head += bytes([tok]) + (header_len + len(data)).to_bytes(2, "big") + len(val).to_bytes(2, "big")
        data += val
    return head + b"\xFF" + data


def colmetadata(columns: list[str], wide: bool = True) -> bytes:
    out = b"\x81" + len(columns).to_bytes(2, "little")
    for name in columns:
        out += ((0).to_bytes(4 if wide else 2, "little") + (0x0001).to_bytes(2, "little")
                + b"\xE7" + (8000).to_bytes(2, "little") + COLLATION + b_varchar(wire_text(name, 128)))
    return out


def row_token(values: list) -> bytes:
    out = b"\xD1"
    for v in values:
        text = cell_text(v, "mssql")
        if text is None:
            out += b"\xFF\xFF"
        else:
            raw = ucs2_units(text, 4000)  # NVARCHAR(4000): at most 8000 bytes
            out += len(raw).to_bytes(2, "little") + raw
    return out


# ---- decoders -----------------------------------------------------------------------------

def parse_prelogin(p: bytes) -> dict[int, bytes]:
    opts: dict[int, bytes] = {}
    pos = 0
    while pos + 5 <= len(p) and p[pos] != 0xFF and len(opts) < 16:
        tok = p[pos]
        off = int.from_bytes(p[pos + 1:pos + 3], "big")
        ln = int.from_bytes(p[pos + 3:pos + 5], "big")
        pos += 5
        if off + ln <= len(p):
            opts[tok] = p[off:off + ln]
    return opts


def deobfuscate(raw: bytes) -> bytes:
    out = bytearray()
    for b in raw:
        b ^= 0xA5
        out.append(((b & 0x0F) << 4) | (b >> 4))
    return bytes(out)


def obfuscate(raw: bytes) -> bytes:
    """Client-side transform (used by tests): swap nibbles then XOR 0xA5."""
    return bytes((((b & 0x0F) << 4) | (b >> 4)) ^ 0xA5 for b in raw)


def parse_login7(p: bytes) -> dict:
    if len(p) < 86:
        raise ValueError("short LOGIN7")
    info: dict = {
        "length": int.from_bytes(p[0:4], "little"),
        "tds_version": int.from_bytes(p[4:8], "little"),
        "packet_size": int.from_bytes(p[8:12], "little"),
        "client_prog_ver": int.from_bytes(p[12:16], "little"),
        "client_pid": int.from_bytes(p[16:20], "little"),
        "option_flags2": p[25],
    }

    def field(pos: int, password: bool = False) -> str:
        off = int.from_bytes(p[pos:pos + 2], "little")
        n = int.from_bytes(p[pos + 2:pos + 4], "little")
        if n == 0:
            return ""
        if n > 256 or off + 2 * n > len(p):
            raise ValueError("LOGIN7 field out of bounds")
        raw = p[off:off + 2 * n]
        if password:
            raw = deobfuscate(raw)
        return raw.decode("utf-16-le", "replace")

    info["hostname"] = field(36)
    info["username"] = field(40)
    info["password"] = field(44, password=True)
    info["app_name"] = field(48)
    info["server_name"] = field(52)
    info["client_interface"] = field(60)
    info["language"] = field(64)
    info["database"] = field(68)
    info["client_id"] = p[72:78].hex() if len(p) >= 78 else ""
    sspi_len = int.from_bytes(p[80:82], "little") if len(p) >= 82 else 0
    info["sspi"] = sspi_len > 0 or bool(info["option_flags2"] & 0x80)
    return info


async def read_message(conn: Conn, cap: int) -> tuple[int, bytes]:
    payload = b""
    ptype = -1
    for _ in range(256):
        head = await conn.readexactly(8)
        if ptype < 0 and head[0] == 0x16 and head[1] == 0x03:
            conn.emit("command", "TLS handshake without negotiation", data={"request": "tls"})
            raise ConnClosed("tls")
        ptype = head[0] if ptype < 0 else ptype
        status = head[1]
        length = int.from_bytes(head[2:4], "big")
        if length < 8 or length > MAX_TDS_PACKET:
            conn.emit("error", "Bad TDS packet length", data={"reason": "packet_size", "size": length})
            raise ConnClosed("packet_size")
        payload += await conn.readexactly(length - 8)
        if len(payload) > cap:
            conn.emit("limit", "TDS message too large", data={"reason": "packet_size",
                                                             "size": len(payload)})
            raise ConnClosed("packet_size")
        if status & 0x01:
            return ptype, payload
    raise ConnClosed("too_many_packets")


# ---- connection ---------------------------------------------------------------------------

async def handle(conn: Conn) -> None:
    settings = conn.ctx.service("mssql")
    version = settings.version or DEFAULT_VERSIONS["mssql"]
    scen = conn.ctx.scenario
    server = (scen.scenario.identity.hostname if scen is not None else "SQL01").upper()[:64]

    ptype, payload = await read_message(conn, MAX_LOGIN)
    if ptype == PKT_PRELOGIN:
        opts = parse_prelogin(payload)
        enc = opts.get(0x01, b"\x00")[:1]
        enc_val = enc[0] if enc else ENCRYPT_OFF
        ver = opts.get(0x00, b"")
        conn.emit("command", "PRELOGIN", data={
            "client_version": ver.hex(), "encryption": enc_val,
            "instance": opts.get(0x02, b"").split(b"\x00")[0].decode("latin-1")[:64]})
        await conn.write(packets(PKT_REPLY, prelogin_reply(version)))
        if enc_val in (ENCRYPT_ON, ENCRYPT_REQ):
            conn.emit("command", "Client requires encryption; TLS not offered, closing",
                      data={"request": "tls_required", "encryption": enc_val})
            return
        ptype, payload = await read_message(conn, MAX_LOGIN)
    if ptype != PKT_LOGIN7:
        conn.emit("error", "Expected LOGIN7", data={"reason": "unexpected_packet", "type": ptype})
        return
    try:
        info = parse_login7(payload)
    except (ValueError, IndexError):
        conn.emit("error", "Malformed LOGIN7", data={"reason": "malformed"})
        return
    tds = info["tds_version"] if info["tds_version"] in KNOWN_TDS else TDS74
    wide = tds >= 0x72090002
    client = " ".join(x for x in (info["app_name"], f"[{info['client_interface']}]"
                                  if info["client_interface"] else "") if x) or None
    data = {"hostname": info["hostname"], "app_name": info["app_name"],
            "server_name": info["server_name"], "client_interface": info["client_interface"],
            "database": info["database"], "language": info["language"],
            "tds_version": f"{info['tds_version']:08x}", "client_pid": info["client_pid"],
            "client_id": info["client_id"], "sspi": info["sspi"]}
    if info["sspi"] and not info["username"]:
        conn.emit("auth_attempt", "Integrated (SSPI) login attempt", success=False,
                  client=client, data=data)
        out = message_token(0xAA, 18452, 1, 14, "Login failed. The login is from an untrusted "
                            "domain and cannot be used with Integrated authentication.", server, wide)
        await conn.write(packets(PKT_REPLY, out + done(0x0002, 0, 0, wide)))
        return
    username = info["username"]
    ok = conn.login(username, info["password"], client=client, data=data)
    if not ok:
        out = message_token(0xAA, 18456, 1, 14, f"Login failed for user '{wire_text(username, 128)}'.",
                            server, wide)
        await conn.write(packets(PKT_REPLY, out + done(0x0002, 0, 0, wide)))
        return
    fake = FakeSql(conn, "mssql", username, info["database"] or "master", version=version,
                   port=conn.dst_port if isinstance(conn.dst_port, int) else 1433)
    if info["database"] and not fake.db_exists(info["database"]):
        out = message_token(0xAA, 4060, 1, 11, f'Cannot open database "{wire_text(info["database"], 128)}"'
                            " requested by the login. The login failed.", server, wide)
        out += message_token(0xAA, 18456, 1, 14, f"Login failed for user '{wire_text(username, 128)}'.",
                             server, wide)
        await conn.write(packets(PKT_REPLY, out + done(0x0002, 0, 0, wide)))
        return
    fake.database = fake.catalog[fake.database.lower()].name
    major, minor, build = version_parts(version)
    out = envchange(1, fake.database, "master")
    out += message_token(0xAB, 5701, 2, 0, f"Changed database context to '{fake.database}'.",
                         server, wide)
    out += envchange_collation()
    out += envchange(2, "us_english", "")
    out += message_token(0xAB, 5703, 1, 0, "Changed language setting to us_english.", server, wide)
    ack = (bytes([1]) + tds.to_bytes(4, "big") + b_varchar("Microsoft SQL Server")
           + bytes([major, minor]) + build.to_bytes(2, "big"))
    out += b"\xAD" + len(ack).to_bytes(2, "little") + ack
    out += envchange(4, "4096", "4096")
    out += done(0, 0, 0, wide)
    await conn.write(packets(PKT_REPLY, out))
    await batch_loop(conn, fake, server, wide)


def strip_all_headers(payload: bytes, wide: bool) -> bytes:
    if len(payload) >= 4:
        total = int.from_bytes(payload[0:4], "little")
        if 4 <= total <= len(payload) and total <= 1024:
            if wide or (total >= 22 and len(payload) >= 8
                        and int.from_bytes(payload[4:8], "little") <= total):
                return payload[total:]
    return payload


def render(answers: list, server: str, wide: bool, fake: FakeSql, inproc: bool = False) -> bytes:
    """Tokens for the answers of a batch; ``inproc`` ends each with DONEINPROC (a DONEPROC
    follows) instead of DONE."""
    out = b""
    for i, ans in enumerate(answers):
        more = 0x0001 if i < len(answers) - 1 or inproc else 0

        def end(status: int, curcmd: int = 0, rows: int = 0) -> bytes:
            tok = done(status, curcmd, rows, wide)
            return b"\xFF" + tok[1:] if inproc else tok

        if isinstance(ans, SqlError):
            out += message_token(0xAA, ans.errno or 50000, 1, ans.klass, ans.message, server, wide)
            out += end(0x0002 | more)
        elif ans.is_query and ans.columns:
            out += colmetadata(ans.columns, wide)
            out += b"".join(row_token(r) for r in ans.rows)
            out += end(0x0010 | more, 0xC1, len(ans.rows))
        elif ans.tag == "USE":
            out += envchange(1, fake.database, "master")
            out += message_token(0xAB, 5701, 2, 0, f"Changed database context to "
                                 f"'{fake.database}'.", server, wide)
            out += end(more)
        elif ans.tag in ("SET", "BEGIN", "COMMIT", "ROLLBACK", "EMPTY") or not ans.tag:
            out += end(more)
        else:
            out += end(0x0010 | more, 0, ans.affected)
    return out if out or inproc else done(0, 0, 0, wide)


# ---- RPC requests -------------------------------------------------------------------------

# ProcIDs a client may send instead of a procedure name (MS-TDS, RPC request).
PROC_IDS = {1: "sp_cursor", 2: "sp_cursoropen", 3: "sp_cursorprepare", 4: "sp_cursorexecute",
            5: "sp_cursorprepexec", 6: "sp_cursorunprepare", 7: "sp_cursorfetch",
            8: "sp_cursoroption", 9: "sp_cursorclose", 10: "sp_executesql", 11: "sp_prepare",
            12: "sp_execute", 13: "sp_prepexec", 14: "sp_prepexecrpc", 15: "sp_unprepare"}
MAX_RPC_PARAMS = 2100          # the server's own parameter limit
MAX_HANDLES = 64               # prepared handles one connection keeps (oldest dropped first)
MAX_PROC_NAME = 128
MAX_RPC_CALLS = 20             # calls one RPC request may batch (as many as statements a batch runs)

# TDS data types by how the value length is carried.
FIXED_TYPES = {0x1F: 0, 0x30: 1, 0x32: 1, 0x34: 2, 0x38: 4, 0x3A: 4, 0x3B: 4, 0x3C: 8,
               0x3D: 8, 0x3E: 8, 0x7A: 4, 0x7F: 8}
BYTELEN_TYPES = {0x24, 0x26, 0x37, 0x3F, 0x68, 0x6A, 0x6C, 0x6D, 0x6E, 0x6F, 0x2F, 0x27,
                 0x2D, 0x25}
DECIMAL_TYPES = {0x37, 0x3F, 0x6A, 0x6C}
SCALED_TIME_TYPES = {0x29, 0x2A, 0x2B}   # TIMEN, DATETIME2N, DATETIMEOFFSETN
DATEN = 0x28
USHORTLEN_TYPES = {0xA5, 0xA7, 0xAD, 0xAF, 0xE7, 0xEF}
LONGLEN_TYPES = {0x22, 0x23, 0x63}
XMLTYPE = 0xF1
COLLATED_TYPES = {0xA7, 0xAF, 0xE7, 0xEF, 0x23, 0x63}
UNICODE_TYPES = {0xE7, 0xEF, 0x63, XMLTYPE}
ANSI_TYPES = {0xA7, 0xAF, 0x2F, 0x27, 0x23}
BINARY_TYPES = {0xA5, 0xAD, 0x2D, 0x25, 0x22}
INT_TYPES = {0x30: False, 0x34: True, 0x38: True, 0x7F: True}   # type -> signed
UNLIMITED = 0xFFFF


class RpcMalformed(Exception):
    """The RPC stream cannot be parsed."""


class TooManyParams(Exception):
    """More parameters than the server accepts."""


@dataclass
class RpcParam:
    name: str
    status: int
    tds_type: int
    value: Any          # None, int, float, Decimal, str or bytes
    literal: str        # the value as a T-SQL literal


def _take(buf: bytes, pos: int, n: int) -> tuple[bytes, int]:
    if n < 0 or pos + n > len(buf):
        raise RpcMalformed("length past end of message")
    return buf[pos:pos + n], pos + n


def _uint(buf: bytes, pos: int, n: int) -> tuple[int, int]:
    raw, pos = _take(buf, pos, n)
    return int.from_bytes(raw, "little"), pos


def _read_plp(buf: bytes, pos: int) -> tuple[Optional[bytes], int]:
    total, pos = _uint(buf, pos, 8)
    if total == 0xFFFFFFFFFFFFFFFF:
        return None, pos
    chunks = []
    while True:
        n, pos = _uint(buf, pos, 4)
        if n == 0:
            return b"".join(chunks), pos
        raw, pos = _take(buf, pos, n)
        chunks.append(raw)


def _float_text(v: float) -> str:
    if v != v or v in (float("inf"), float("-inf")):
        return "NULL"
    mantissa, _, exp = repr(v).partition("e")
    return f"{mantissa}.0e{exp}" if exp and "." not in mantissa else repr(v)


def _time_text(units: int, scale: int) -> str:
    seconds, frac = divmod(units, 10 ** scale)
    if seconds >= 86400:
        raise RpcMalformed("time out of range")
    text = f"{seconds // 3600:02d}:{seconds // 60 % 60:02d}:{seconds % 60:02d}"
    return text + (f".{frac:0{scale}d}" if scale else "")


def _scaled(n: int, scale: int) -> str:
    """``n`` / 10**scale as exact decimal text (no rounding to a context precision)."""
    digits = str(abs(n)).rjust(scale + 1, "0")
    text = digits[:len(digits) - scale] + ("." + digits[len(digits) - scale:] if scale else "")
    return ("-" if n < 0 else "") + text


def _date(raw: bytes) -> datetime.date:
    return datetime.date(1, 1, 1) + datetime.timedelta(days=int.from_bytes(raw, "little"))


def _decode(t: int, raw: bytes, scale: int) -> tuple[Any, str]:
    """A non-NULL parameter value and its literal."""
    if t in INT_TYPES or t == 0x26:
        if len(raw) not in (1, 2, 4, 8):
            raise RpcMalformed("bad integer length")
        v = int.from_bytes(raw, "little", signed=INT_TYPES.get(t, len(raw) > 1))
        return v, str(v)
    if t in (0x32, 0x68):
        v = 1 if raw[:1] != b"\x00" else 0
        return v, str(v)
    if t in (0x3B, 0x3E, 0x6D):
        if len(raw) not in (4, 8):
            raise RpcMalformed("bad float length")
        v = struct.unpack("<f" if len(raw) == 4 else "<d", raw)[0]
        return v, _float_text(v)
    if t in (0x3C, 0x7A, 0x6E):
        if len(raw) == 8:
            cents = (int.from_bytes(raw[0:4], "little", signed=True) << 32) | int.from_bytes(raw[4:8], "little")
        elif len(raw) == 4:
            cents = int.from_bytes(raw, "little", signed=True)
        else:
            raise RpcMalformed("bad money length")
        text = _scaled(cents, 4)
        return Decimal(text), text
    if t in (0x3D, 0x3A, 0x6F):
        if len(raw) == 8:
            days = int.from_bytes(raw[0:4], "little", signed=True)
            ticks = int.from_bytes(raw[4:8], "little")
            when = (datetime.datetime(1900, 1, 1) + datetime.timedelta(days=days)
                    + datetime.timedelta(milliseconds=round(ticks * 10 / 3)))
            text = when.strftime("%Y-%m-%d %H:%M:%S.") + f"{when.microsecond // 1000:03d}"
        elif len(raw) == 4:
            when = (datetime.datetime(1900, 1, 1)
                    + datetime.timedelta(days=int.from_bytes(raw[0:2], "little"),
                                         minutes=int.from_bytes(raw[2:4], "little")))
            text = when.strftime("%Y-%m-%d %H:%M:00")
        else:
            raise RpcMalformed("bad datetime length")
        return text, f"'{text}'"
    if t in DECIMAL_TYPES:
        if len(raw) < 2:
            raise RpcMalformed("bad decimal length")
        text = _scaled(int.from_bytes(raw[1:], "little") * (1 if raw[0] == 1 else -1), scale)
        return Decimal(text), text
    if t == 0x24:
        if len(raw) != 16:
            raise RpcMalformed("bad uniqueidentifier length")
        text = str(uuid.UUID(bytes_le=raw)).upper()
        return text, f"'{text}'"
    if t == DATEN:
        if len(raw) != 3:
            raise RpcMalformed("bad date length")
        text = _date(raw).isoformat()
        return text, f"'{text}'"
    if t in SCALED_TIME_TYPES:
        date_len = {0x29: 0, 0x2A: 3, 0x2B: 5}[t]
        tlen = len(raw) - date_len
        if tlen not in (3, 4, 5):
            raise RpcMalformed("bad time length")
        text = _time_text(int.from_bytes(raw[:tlen], "little"), scale)
        if t != 0x29:
            day = _date(raw[tlen:tlen + 3])
            if t == 0x2B:
                offset = int.from_bytes(raw[tlen + 3:], "little", signed=True)
                when = (datetime.datetime.combine(day, datetime.time())
                        + datetime.timedelta(seconds=int(text[:2]) * 3600 + int(text[3:5]) * 60
                                             + int(text[6:8]), minutes=offset))
                sign = "-" if offset < 0 else "+"
                text = (when.strftime("%Y-%m-%d %H:%M:%S") + text[8:]
                        + f" {sign}{abs(offset) // 60:02d}:{abs(offset) % 60:02d}")
            else:
                text = f"{day.isoformat()} {text}"
        return text, f"'{text}'"
    if t in UNICODE_TYPES:
        text = raw.decode("utf-16-le", "replace")
        return text, "N'" + text.replace("'", "''") + "'"
    if t in ANSI_TYPES:
        text = raw.decode("cp1252", "replace")
        return text, "'" + text.replace("'", "''") + "'"
    if t in BINARY_TYPES:
        return raw, "0x" + raw.hex().upper()
    raise RpcMalformed(f"unsupported type 0x{t:02x}")


def read_param_value(buf: bytes, pos: int) -> tuple[int, Any, str, int]:
    """TYPE_INFO then the value: (type, value, literal, next position). A NULL value is
    (type, None, "NULL")."""
    t, pos = _uint(buf, pos, 1)
    scale = 0
    if t in FIXED_TYPES:
        raw, pos = _take(buf, pos, FIXED_TYPES[t])
        if t == 0x1F:
            return t, None, "NULL", pos
    elif t in BYTELEN_TYPES or t == DATEN or t in SCALED_TIME_TYPES:
        if t in BYTELEN_TYPES:
            _, pos = _uint(buf, pos, 1)                     # max length
        if t in DECIMAL_TYPES:
            _, pos = _uint(buf, pos, 1)                     # precision
        if t in DECIMAL_TYPES or t in SCALED_TIME_TYPES:
            scale, pos = _uint(buf, pos, 1)
            if scale > 7 and t in SCALED_TIME_TYPES or scale > 38:
                raise RpcMalformed("bad scale")
        n, pos = _uint(buf, pos, 1)
        if n == 0:
            return t, None, "NULL", pos
        raw, pos = _take(buf, pos, n)
    elif t in USHORTLEN_TYPES:
        maxlen, pos = _uint(buf, pos, 2)
        if t in COLLATED_TYPES:
            _, pos = _take(buf, pos, 5)
        if maxlen == UNLIMITED:
            raw, pos = _read_plp(buf, pos)
            if raw is None:
                return t, None, "NULL", pos
        else:
            n, pos = _uint(buf, pos, 2)
            if n == 0xFFFF:
                return t, None, "NULL", pos
            raw, pos = _take(buf, pos, n)
    elif t in LONGLEN_TYPES:
        _, pos = _uint(buf, pos, 4)
        if t in COLLATED_TYPES:
            _, pos = _take(buf, pos, 5)
        n, pos = _uint(buf, pos, 4)
        if n == 0xFFFFFFFF:
            return t, None, "NULL", pos
        raw, pos = _take(buf, pos, n)
    elif t == XMLTYPE:
        schema, pos = _uint(buf, pos, 1)
        if schema:
            for width in (1, 1, 2):
                n, pos = _uint(buf, pos, width)
                _, pos = _take(buf, pos, 2 * n)
        raw, pos = _read_plp(buf, pos)
        if raw is None:
            return t, None, "NULL", pos
    else:
        raise RpcMalformed(f"unknown type 0x{t:02x}")
    value, literal = _decode(t, raw, scale)
    return t, value, literal, pos


@dataclass
class RpcCall:
    name: str
    params: list[RpcParam]
    raw: bytes              # the call's own bytes, without the separator
    no_exec: bool = False   # a NoExecFlag follows: the server answers it without running it


def separators(wide: bool) -> bytes:
    """Bytes that end one RPC of a batched request: BatchFlag 0x80 before TDS 7.2; BatchFlag
    0xFF and NoExecFlag 0xFE from 7.2 (0x80 is then a valid 128-character name length)."""
    return b"\xFF\xFE" if wide else b"\x80"


def parse_rpc(body: bytes, wide: bool = True) -> tuple[str, list[RpcParam]]:
    """The first RPC of a request: procedure name and parameters."""
    name, params, _ = _parse_call(body, 0, separators(wide))
    return name, params


def parse_rpc_batch(body: bytes, wide: bool) -> tuple[list[RpcCall], Optional[str]]:
    """The RPCs of a request in order, and the problem that ends the request early, if any:
    "too_many_params", "too_many_calls" (more than ``MAX_RPC_CALLS``) or "malformed". The
    calls parsed before the problem are returned with it. A separator after the last call
    is accepted."""
    seps = separators(wide)
    calls: list[RpcCall] = []
    pos = 0
    while True:
        if len(calls) >= MAX_RPC_CALLS:
            return calls, "too_many_calls"
        start = pos
        try:
            name, params, pos = _parse_call(body, pos, seps)
        except TooManyParams:
            return calls, "too_many_params"
        except (RpcMalformed, ValueError, OverflowError, struct.error):
            return calls, "malformed"
        call = RpcCall(name, params, body[start:pos])
        calls.append(call)
        if pos >= len(body):
            return calls, None
        call.no_exec = body[pos] == 0xFE and wide
        pos += 1
        if pos >= len(body):
            return calls, None


def _parse_call(body: bytes, pos: int, seps: bytes) -> tuple[str, list[RpcParam], int]:
    """One RPC starting at ``pos``: name, parameters and the position after its last
    parameter (the end of the body or a separator)."""
    n, pos = _uint(body, pos, 2)
    if n == 0xFFFF:
        proc_id, pos = _uint(body, pos, 2)
        name = PROC_IDS.get(proc_id, f"#{proc_id}")
    else:
        if n > MAX_PROC_NAME * 2:
            raise RpcMalformed("procedure name too long")
        raw, pos = _take(body, pos, 2 * n)
        name = raw.decode("utf-16-le", "replace")
    _, pos = _take(body, pos, 2)                            # option flags
    params: list[RpcParam] = []
    while pos < len(body) and body[pos] not in seps:
        if len(params) >= MAX_RPC_PARAMS:
            raise TooManyParams()
        nlen, pos = _uint(body, pos, 1)
        raw, pos = _take(body, pos, 2 * nlen)
        status, pos = _uint(body, pos, 1)
        if status & 0x08:
            raise RpcMalformed("encrypted parameter")
        t, value, literal, pos = read_param_value(body, pos)
        params.append(RpcParam(raw.decode("utf-16-le", "replace"), status, t, value, literal))
    return name, params, pos


def proc_key(name: str) -> str:
    """The bare, lower-case procedure name: ``[sys].[sp_executesql]`` -> ``sp_executesql``."""
    return name.split(".")[-1].strip().strip("[]\"").lower()


def declared_names(decl: str) -> Optional[list[str]]:
    """Parameter names (lower case, with ``@``) from an ``@params`` declaration, or None
    when a piece does not start with ``@name type``."""
    names: list[str] = []
    depth, start = 0, 0
    pieces = []
    for i, ch in enumerate(decl):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            pieces.append(decl[start:i])
            start = i + 1
    pieces.append(decl[start:])
    for piece in pieces:
        piece = piece.strip()
        if not piece and len(pieces) == 1:
            break
        m = re.match(r"(@[\w@#$]+)\s+\S", piece)
        if not m or len(names) >= MAX_RPC_PARAMS:
            return None
        names.append(m.group(1).lower())
    return names


# T-SQL tokens that can hide an @name: quoted text, quoted identifiers, comments; then
# system functions (@@...) and parameter names. Unterminated quotes run to the end.
_TSQL_TOKEN = re.compile(r"'[^']*+(?:''[^']*+)*+'?|\"[^\"]*+\"?|\[[^\]]*+(?:\]\][^\]]*+)*+\]?"
                         r"|--[^\n]*+|/\*(?:[^*]|\*(?!/))*+(?:\*/)?|@@[\w@#$]*+|@[\w@#$]++", re.S)


def bind_names(stmt: str, literals: dict[str, str]) -> str:
    """``stmt`` with each declared ``@name`` outside quotes and comments replaced by its
    literal (names match case-insensitively), in one pass."""
    def repl(m: re.Match) -> str:
        tok = m.group(0)
        if tok.startswith("@") and not tok.startswith("@@"):
            return literals.get(tok.lower(), tok)
        return tok
    return _TSQL_TOKEN.sub(repl, stmt)


@dataclass
class Handles:
    """sp_prepare handles of one connection: handle -> (declaration, statement)."""
    stmts: dict[int, tuple[str, str]] = field(default_factory=dict)
    next_id: int = 1

    def add(self, decl: str, stmt: str) -> int:
        if len(self.stmts) >= MAX_HANDLES:
            self.stmts.pop(next(iter(self.stmts)))
        handle = self.next_id
        self.next_id = self.next_id + 1 if self.next_id < 0x7FFFFFFF else 1
        self.stmts[handle] = (decl, stmt)
        return handle


def return_status(value: int = 0) -> bytes:
    return b"\x79" + value.to_bytes(4, "little", signed=True)


def return_value(ordinal: int, name: str, value: int, wide: bool) -> bytes:
    """RETURNVALUE for an INT output parameter."""
    return (b"\xAC" + ordinal.to_bytes(2, "little") + b_varchar(name) + b"\x01"
            + (0).to_bytes(4 if wide else 2, "little") + (0x0001).to_bytes(2, "little")
            + b"\x26\x04\x04" + value.to_bytes(4, "little", signed=True))


def proc_error(number: int, message: str, server: str, wide: bool, klass: int = 16) -> bytes:
    return message_token(0xAA, number, 1, klass, message, server, wide)


def done_proc(status: int, wide: bool) -> bytes:
    return b"\xFE" + done(status, 0, 0, wide)[1:]


def not_supplied(proc: str, param: str, server: str, wide: bool) -> bytes:
    return proc_error(201, f"Procedure or function '{proc}' expects parameter '{param}', which "
                      "was not supplied.", server, wide)


def wrong_text_type(param: str, server: str, wide: bool) -> bytes:
    return proc_error(214, f"Procedure expects parameter '{param}' of type "
                      "'ntext/nchar/nvarchar'.", server, wide)


def bind_values(proc: str, names: list[str], decl: str, stmt: str, values: list[RpcParam],
                first: int) -> Union[dict[str, str], SqlError]:
    """Literals for the declared ``names`` from ``values`` (the call's parameters from
    ordinal ``first``, 1-based): unnamed values fill names in declaration order, named
    values match case-insensitively. A positional value after a named one, an undeclared
    name, a name given twice or a missing value gets the server's error."""
    bound: dict[str, str] = {}
    named = False
    for i, p in enumerate(values):
        if not p.name:
            if named:
                return SqlError("119", f"Must pass parameter number {first + i} and subsequent "
                                "parameters as '@name = value'. After the form '@name = value' "
                                "has been used, all subsequent parameters must be passed in the "
                                "form '@name = value'.", errno=119, klass=15)
            if i >= len(names):
                return SqlError("8144", f"Procedure or function {proc} has too many arguments "
                                "specified.", errno=8144)
            bound[names[i]] = p.literal
            continue
        named = True
        key = p.name.lower()
        if key not in names:
            return SqlError("8145", f"{wire_text(p.name, 128)} is not a parameter for procedure "
                            f"{proc}.", errno=8145)
        if key in bound:
            return SqlError("8143", f"Parameter '{wire_text(p.name, 128)}' was supplied "
                            "multiple times.", errno=8143)
        bound[key] = p.literal
    missing = next((n for n in names if n not in bound), None)
    if missing is not None:
        return SqlError("8178", f"The parameterized query '({wire_text(decl, 200)})"
                        f"{wire_text(stmt, 200)}' expects the parameter '{missing}', which "
                        "was not supplied.", errno=8178)
    return bound


async def _run_bound(fake: FakeSql, proc: str, decl: str, stmt: str, params: list[RpcParam],
                     first: int) -> list:
    """Bind ``params[first:]`` to the names declared in ``decl`` and answer through the
    engine; a declaration or argument mismatch gets the server's error instead."""
    names = declared_names(decl)
    if names is None:
        return [fake.syntax_error(decl)]
    bound = bind_values(proc, names, decl, stmt, params[first:], first + 1)
    if isinstance(bound, SqlError):
        return [bound]
    return await fake.run(bind_names(stmt, bound))


def proc_reply(answers: list, server: str, wide: bool, fake: FakeSql,
               out_params: bytes = b"") -> tuple[bytes, int]:
    failed = any(isinstance(a, SqlError) for a in answers)
    return (render(answers, server, wide, fake, inproc=True) + return_status(0) + out_params,
            0x0002 if failed else 0)


def call_text(name: str, params: list[RpcParam]) -> str:
    """The call as an EXEC statement: sanitized name, then up to 64 arguments."""
    safe = re.sub(r"[^\w.\[\]#@$]", "", name)[:MAX_PROC_NAME] or "sp_unknown"
    args = ", ".join(f"{p.name}={p.literal}" if p.name else p.literal for p in params[:64])
    return f"EXEC {safe} {args}".strip()


def _text_param(params: list[RpcParam], i: int) -> Optional[RpcParam]:
    return params[i] if i < len(params) else None


def protocol_error(server: str, wide: bool) -> bytes:
    return message_token(0xAA, 4002, 1, 16, "The incoming tabular data stream (TDS) protocol "
                         "stream is incorrect.", server, wide) + done(0x0002, 0, 0, wide)


async def rpc(conn: Conn, fake: FakeSql, handles: Handles, body: bytes, server: str,
              wide: bool) -> tuple[bytes, bool]:
    """The reply to one RPC request, and whether to close the connection after it. Each
    batched call is answered in order and ends with a DONEPROC; every DONEPROC but the last
    carries DONE_MORE, and a call that fails does not stop the ones after it. The calls
    before a malformed one, or before the call cap, are answered before the protocol error
    and the close."""
    calls, problem = parse_rpc_batch(body, wide)
    out = b""
    for i, call in enumerate(calls):
        data = {"procedure": wire_text(call.name, MAX_PROC_NAME), "params": len(call.params),
                "text": call_text(call.name, call.params)[:800], "payload": call.raw[:400].hex()}
        if len(calls) > 1 or problem:
            data.update(call=i + 1, calls=len(calls))
        if call.no_exec:
            data["no_exec"] = True
        conn.emit("command", "RPC request", data=data)
        if call.no_exec:
            tokens, status = skipped_call(fake, call, server, wide), 0x0002
        else:
            tokens, status = await rpc_call(conn, fake, handles, call, server, wide)
        # A protocol error after the last call ends the reply with DONE, so DONEPROC is final
        # only when nothing follows it.
        last = i == len(calls) - 1 and problem is None
        out += tokens + done_proc(status | (0 if last else 0x0001), wide)
    if problem == "too_many_params":
        conn.emit("command", "RPC request", data={"reason": "too_many_params"})
        out += proc_error(8003, "The incoming request has too many parameters. The server "
                          f"supports a maximum of {MAX_RPC_PARAMS} parameters. Reduce the number "
                          "of parameters and resend the request.", server, wide) \
            + done_proc(0x0002, wide)
    elif problem:
        conn.emit("error", "Malformed RPC request", data={"reason": problem,
                                                          "payload": body[:200].hex()})
        return out + protocol_error(server, wide), True
    return out, False


def skipped_call(fake: FakeSql, call: RpcCall, server: str, wide: bool) -> bytes:
    """The answer to a call marked with NoExecFlag: the server does not run it and answers
    as for a procedure that does not exist. An exec primitive is still logged as one."""
    err = SqlError("2812", f"Could not find stored procedure '{safe_name(proc_key(call.name))}'.",
                   errno=2812)
    text = call_text(call.name, call.params)
    danger = classify_dangerous(" ".join(text.split()).lower())
    if danger:
        fake._log(text, err, {"kind": "refused", "high_signal": True, "signal": "sql_exec_attempt",
                              "match": danger[0], "rpc": True, "no_exec": True})
    return proc_error(err.errno, err.message, server, wide)


async def rpc_call(conn: Conn, fake: FakeSql, handles: Handles, call: RpcCall, server: str,
                   wide: bool) -> tuple[bytes, int]:
    """The tokens for one call, before its DONEPROC, and the DONEPROC status."""
    name, params = call.name, call.params
    key = proc_key(name)
    if key in ("sp_executesql", "sp_prepare", "sp_prepexec"):
        # sp_executesql: @statement, @params, values; the others: @handle, @params, @stmt, ...
        si, di = (0, 1) if key == "sp_executesql" else (2, 1)
        stmt_name = "@statement" if key == "sp_executesql" else "@stmt"
        if key != "sp_executesql" and not params:
            return not_supplied(key, "@handle", server, wide), 0x0002
        stmt_p, decl_p = _text_param(params, si), _text_param(params, di)
        if decl_p is not None and decl_p.tds_type not in UNICODE_TYPES - {XMLTYPE} \
                and decl_p.value is not None:
            return wrong_text_type("@params", server, wide), 0x0002
        if stmt_p is None:
            missing = "@params" if key != "sp_executesql" and decl_p is None else stmt_name
            return not_supplied(key, missing, server, wide), 0x0002
        if stmt_p.tds_type not in UNICODE_TYPES - {XMLTYPE}:
            return wrong_text_type(stmt_name, server, wide), 0x0002
        stmt = stmt_p.value or ""
        decl = (decl_p.value or "") if decl_p is not None else ""
        out = b""
        if key != "sp_executesql":
            handle = handles.add(decl, stmt)
            conn.emit("command", "RPC prepare", data={"procedure": key, "handle": handle,
                                                      "statement": stmt[:2000]})
            out = return_value(0, params[0].name, handle, wide)
            if key == "sp_prepare":
                return return_status(0) + out, 0
        if stmt_p.value is None:
            return proc_reply([], server, wide, fake, out)
        answers = await _run_bound(fake, key, decl, stmt, params,
                                   3 if key == "sp_prepexec" else 2)
        return proc_reply(answers, server, wide, fake, out)
    if key in ("sp_execute", "sp_unprepare"):
        handle_p = _text_param(params, 0)
        if handle_p is None:
            return not_supplied(key, "@handle", server, wide), 0x0002
        handle = handle_p.value if isinstance(handle_p.value, int) else None
        if handle is None or handle not in handles.stmts:
            return proc_error(8179, f"Could not find prepared statement with handle "
                              f"{handle_p.literal}.", server, wide), 0x0002
        if key == "sp_unprepare":
            del handles.stmts[handle]
            return return_status(0), 0
        decl, stmt = handles.stmts[handle]
        return proc_reply(await _run_bound(fake, key, decl, stmt, params, 1), server, wide, fake)
    # Any other procedure: the engine's high-signal refusal for exec primitives, otherwise
    # the server's EXECUTE permission error. Logged as the equivalent EXEC statement.
    text = call_text(name, params)
    low = " ".join(text.split()).lower()
    danger = classify_dangerous(low)
    if danger:
        err = fake.dangerous_error(danger[0], danger[1], text)
        meta = {"kind": "refused", "high_signal": True, "signal": "sql_exec_attempt",
                "match": danger[0], "rpc": True}
    else:
        if key.startswith(("sp_", "xp_")):
            err = SqlError("229", f"The EXECUTE permission was denied on the object "
                           f"'{safe_name(key)}', database 'mssqlsystemresource', schema 'sys'.",
                           errno=229, klass=14)
        else:
            err = fake.permission_error("exec", text)
        meta = {"kind": "refused", "rpc": True}
    fake._log(text, err, meta)
    return message_token(0xAA, err.errno or 50000, 1, err.klass, err.message, server, wide), 0x0002


async def batch_loop(conn: Conn, fake: FakeSql, server: str, wide: bool) -> None:
    handles = Handles()
    while True:
        ptype, payload = await read_message(conn, MAX_BATCH)
        if ptype == PKT_ATTENTION:
            await conn.write(packets(PKT_REPLY, done(0x0020, 0, 0, wide)))
            continue
        if not conn.command():
            return
        if ptype == PKT_SQL_BATCH:
            text = strip_all_headers(payload, wide).decode("utf-16-le", "replace")
            answers = await fake.run(text)
            await conn.write(packets(PKT_REPLY, render(answers, server, wide, fake)))
        elif ptype == PKT_RPC:
            out, close = await rpc(conn, fake, handles, strip_all_headers(payload, wide), server, wide)
            await conn.write(packets(PKT_REPLY, out))
            if close:
                return
        else:
            conn.emit("command", "Unsupported TDS packet", data={"type": ptype,
                                                                 "payload": payload[:200].hex()})
            await conn.write(packets(PKT_REPLY, protocol_error(server, wide)))
            return


async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    server = await start_tcp(ctx, "mssql", settings.port, handle)
    return [server]
