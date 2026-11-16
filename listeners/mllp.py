"""HL7 v2 over MLLP trap: log inbound messages and answer a well-formed ACK (MSA|AA).

Frames are 0x0b <message> 0x1c 0x0d. Bytes outside a frame are discarded. Nothing from
the message is executed or forwarded; copied MSH fields are sanitised before echoing.
"""

from __future__ import annotations

import datetime
import os
import re
from typing import Optional

from listeners.base import ConnClosed, Conn, ListenerContext, ServiceSettings, start_tcp

SB, EB, CR = b"\x0b", b"\x1c", b"\x0d"
MAX_FRAME = 1_048_576
LOG_COPY_CAP = 2048
SAFE_FIELD_RE = re.compile(r"[^A-Za-z0-9 ._\-]")


def _safe(value: str, cap: int = 40) -> str:
    return SAFE_FIELD_RE.sub("", value)[:cap]


def parse_msh(message: str) -> Optional[dict[str, str]]:
    segments = [s for s in re.split(r"\r\n|\r|\n", message) if s]
    msh = next((s for s in segments if s.startswith("MSH") and len(s) >= 8), None)
    if msh is None:
        return None
    fs = msh[3]
    fields = msh.split(fs)
    comp = msh[4] if len(msh) > 4 else "^"

    def f(i: int) -> str:
        return fields[i] if i < len(fields) else ""

    msg_type = f(8)
    parts = msg_type.split(comp)
    return {"sending_app": f(2), "sending_facility": f(3), "receiving_app": f(4),
            "receiving_facility": f(5), "timestamp": f(6), "message_type": msg_type,
            "message_code": parts[0] if parts else "",
            "trigger": parts[1] if len(parts) > 1 else "", "control_id": f(9),
            "processing_id": f(10), "version": f(11), "segments": str(len(segments)),
            "segment_ids": ",".join(s[:3] for s in segments[:30])}


def build_ack(msh: Optional[dict[str, str]], facility: str, app: str = "HIS") -> bytes:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    ctrl = _safe((msh or {}).get("control_id", ""), 20)
    trigger = _safe((msh or {}).get("trigger", ""), 3)
    version = _safe((msh or {}).get("version", ""), 8) or "2.5"
    proc = _safe((msh or {}).get("processing_id", ""), 3) or "P"
    their_app = _safe((msh or {}).get("sending_app", ""))
    their_fac = _safe((msh or {}).get("sending_facility", ""))
    code = "AA" if msh is not None else "AR"
    ack_id = "ACK" + os.urandom(6).hex().upper()
    segments = [
        f"MSH|^~\\&|{app}|{facility}|{their_app}|{their_fac}|{now}||ACK^{trigger}^ACK|"
        f"{ack_id}|{proc}|{version}",
        f"MSA|{code}|{ctrl}",
    ]
    if msh is None:
        segments.append("ERR|||100^Segment sequence error^HL70357|E")
    return SB + ("\r".join(segments) + "\r").encode("ascii") + EB + CR


async def start(ctx: ListenerContext, settings: ServiceSettings) -> list:
    svc = ctx.scenario.scenario.services.mllp if ctx.scenario is not None else None
    facility = _safe(svc.sending_facility if svc is not None else "EHR") or "EHR"
    app = _safe(settings.banner or "HIS") or "HIS"
    cap = min(MAX_FRAME, ctx.limits.max_conn_bytes)

    async def handle(conn: Conn) -> None:
        buf = bytearray()
        scanned = 0          # bytes of buf already searched for the end marker
        while True:
            end = buf.find(EB + CR, scanned)
            if end < 0:
                # The marker is two bytes, so the last byte may still begin one.
                scanned = max(0, len(buf) - 1)
                if len(buf) > cap:
                    conn.emit("limit", "MLLP frame too large", data={"reason": "frame_size",
                                                                     "size": len(buf)})
                    raise ConnClosed("frame_size")
                buf += await conn.read_some(65536)
                continue
            frame = bytes(buf[:end])
            del buf[:end + 2]
            scanned = 0
            start_at = frame.rfind(SB)
            junk = start_at if start_at >= 0 else len(frame)
            if start_at < 0:
                conn.emit("error", "MLLP frame without start block",
                          level="WARNING", data={"reason": "no_start_block", "size": len(frame)})
                continue
            if not conn.command():
                return
            text = frame[start_at + 1:].decode("utf-8", errors="replace")
            msh = parse_msh(text)
            data: dict = {"size": len(text), "copy": text[:LOG_COPY_CAP], "discarded": junk,
                          "parsed": msh is not None}
            if msh:
                data.update(msh)
            conn.emit("command", "HL7 message", data=data)
            await conn.write(build_ack(msh, facility, app))

    return [await start_tcp(ctx, "mllp", settings.port, handle)]
