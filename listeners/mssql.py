"""Fake Microsoft SQL Server (TDS 7.x, no TLS).

PRELOGIN is answered with ENCRYPT_NOT_SUP. A client that insists on encryption
(ENCRYPT_ON / ENCRYPT_REQ) cannot continue without TLS: that is logged and the
connection is closed after the PRELOGIN reply. LOGIN7 is parsed (offset/length table,
UCS-2LE strings, password de-obfuscated: XOR 0xA5 then swap nibbles) and decided by
``conn.login``. After a fake login, SQL batches are answered by ``listeners.sqlfake``
with every column rendered as NVARCHAR. RPC requests get a generic error. Nothing is
executed. Enabled per scenario (contact_center turns it on).
"""

from __future__ import annotations

import re

from listeners.base import Conn, ConnClosed, ListenerContext, ServiceSettings, start_tcp
from listeners.sqlfake import DEFAULT_VERSIONS, FakeSql, SqlError, cell_text, wire_text

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


def render(answers: list, server: str, wide: bool, fake: FakeSql) -> bytes:
    out = b""
    for i, ans in enumerate(answers):
        more = 0x0001 if i < len(answers) - 1 else 0
        if isinstance(ans, SqlError):
            out += message_token(0xAA, ans.errno or 50000, 1, ans.klass, ans.message, server, wide)
            out += done(0x0002 | more, 0, 0, wide)
        elif ans.is_query and ans.columns:
            out += colmetadata(ans.columns, wide)
            out += b"".join(row_token(r) for r in ans.rows)
            out += done(0x0010 | more, 0xC1, len(ans.rows), wide)
        elif ans.tag == "USE":
            out += envchange(1, fake.database, "master")
            out += message_token(0xAB, 5701, 2, 0, f"Changed database context to "
                                 f"'{fake.database}'.", server, wide)
            out += done(more, 0, 0, wide)
        elif ans.tag in ("SET", "BEGIN", "COMMIT", "ROLLBACK", "EMPTY") or not ans.tag:
            out += done(more, 0, 0, wide)
        else:
            out += done(0x0010 | more, 0, ans.affected, wide)
    return out or done(0, 0, 0, wide)


async def batch_loop(conn: Conn, fake: FakeSql, server: str, wide: bool) -> None:
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
            body = strip_all_headers(payload, wide)
            conn.emit("command", "RPC request", data={"payload": body[:400].hex(),
                                                      "text": body[:800].decode("utf-16-le", "replace")})
            out = message_token(0xAA, 8180, 1, 16, "Statement(s) could not be prepared.", server, wide)
            await conn.write(packets(PKT_REPLY, out + done(0x0002, 0, 0, wide)))
        else:
            conn.emit("command", "Unsupported TDS packet", data={"type": ptype,
                                                                 "payload": payload[:200].hex()})
            out = message_token(0xAA, 4002, 1, 16, "The incoming tabular data stream (TDS) protocol "
                                "stream is incorrect.", server, wide)
            await conn.write(packets(PKT_REPLY, out + done(0x0002, 0, 0, wide)))
            return


async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    server = await start_tcp(ctx, "mssql", settings.port, handle)
    return [server]
