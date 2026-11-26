"""HL7 v2 over MLLP trap: log inbound messages and answer a well-formed ACK (MSA|AA).

A query gets its own response type with a "no data found" status instead of an ACK:
QRY^A19 gets ADR^A19 (MSA, QAK with status NF, the QRD echoed) and QBP^Q22 gets RSP^K22
(MSA, QAK with status NF and the query name, the QPD echoed).

Frames are 0x0b <message> 0x1c 0x0d. Bytes outside a frame are discarded. Nothing from
the message is executed or forwarded; copied fields are sanitised before echoing and
re-encoded with the standard separators, component by component and bounded in size.
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
ECHO_SAFE_RE = re.compile(r"[^A-Za-z0-9 ._\-@]")   # also keeps QPD-3 "@PID.5.1" names
MAX_SEGMENTS = 200          # segments scanned for a query's QRD/QPD
MAX_ECHO_FIELDS = 12        # fields of a QRD/QPD echoed
MAX_ECHO_REPS = 5           # repetitions per echoed field
MAX_ECHO_COMPONENTS = 10    # components per echoed repetition
# Query message -> (response message code, trigger, structure, query segment).
QUERIES = {("QRY", "A19"): ("ADR", "A19", "ADR_A19", "QRD"),
           ("QBP", "Q22"): ("RSP", "K22", "RSP_K21", "QPD")}


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
            "trigger": parts[1] if len(parts) > 1 else "",
            "structure": parts[2] if len(parts) > 2 else "", "control_id": f(9),
            "processing_id": f(10), "version": f(11), "segments": str(len(segments)),
            "segment_ids": ",".join(s[:3] for s in segments[:30])}


def _header(msh: Optional[dict[str, str]], facility: str, app: str, msg_type: str,
            prefix: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    version = _safe((msh or {}).get("version", ""), 8) or "2.5"
    proc = _safe((msh or {}).get("processing_id", ""), 3) or "P"
    their_app = _safe((msh or {}).get("sending_app", ""))
    their_fac = _safe((msh or {}).get("sending_facility", ""))
    msg_id = prefix + os.urandom(6).hex().upper()
    return (f"MSH|^~\\&|{app}|{facility}|{their_app}|{their_fac}|{now}||{msg_type}|"
            f"{msg_id}|{proc}|{version}")


def _frame(segments: list[str]) -> bytes:
    return SB + ("\r".join(segments) + "\r").encode("ascii") + EB + CR


def build_ack(msh: Optional[dict[str, str]], facility: str, app: str = "HIS") -> bytes:
    ctrl = _safe((msh or {}).get("control_id", ""), 20)
    trigger = _safe((msh or {}).get("trigger", ""), 3)
    code = "AA" if msh is not None else "AR"
    segments = [_header(msh, facility, app, f"ACK^{trigger}^ACK", "ACK"),
                f"MSA|{code}|{ctrl}"]
    if msh is None:
        segments.append("ERR|||100^Segment sequence error^HL70357|E")
    return _frame(segments)


def query_segment(message: str, name: str) -> Optional[list[list[list[str]]]]:
    """The first ``name`` segment's fields as repetitions of components, read with the
    message's own separators (MSH-1 and MSH-2), sanitised and bounded; None when absent."""
    segments = [s for s in re.split(r"\r\n|\r|\n", message) if s][:MAX_SEGMENTS]
    msh = next((s for s in segments if s.startswith("MSH") and len(s) >= 8), None)
    if msh is None:
        return None
    fs, comp, rep = msh[3], msh[4], msh[5]
    seg = next((s for s in segments if s.split(fs, 1)[0] == name), None)
    if seg is None:
        return None
    out: list[list[list[str]]] = []
    for value in seg.split(fs)[1:MAX_ECHO_FIELDS + 1]:
        reps = []
        for r in value.split(rep)[:MAX_ECHO_REPS]:
            reps.append([ECHO_SAFE_RE.sub("", c)[:40] for c in r.split(comp)[:MAX_ECHO_COMPONENTS]])
        out.append(reps)
    return out


def _encode(fields: list[list[list[str]]]) -> str:
    """Fields back to text with the standard separators (| ~ ^), trailing empties dropped."""
    def join(parts: list[str], sep: str) -> str:
        while parts and not parts[-1]:
            parts = parts[:-1]
        return sep.join(parts)
    return join([join([join(list(c), "^") for c in reps], "~") for reps in fields], "|")


def build_query_response(msh: dict[str, str], message: str, facility: str,
                         app: str = "HIS") -> Optional[tuple[bytes, str]]:
    """A "no data found" response to a supported query, with its message type; None for
    any other message."""
    spec = QUERIES.get((msh.get("message_code", "").upper(), msh.get("trigger", "").upper()))
    if spec is None:
        return None
    resp_code, resp_trigger, structure, seg_name = spec
    echoed = query_segment(message, seg_name) or []
    msg_type = f"{resp_code}^{resp_trigger}" + (f"^{structure}" if msh.get("structure") else "")
    ctrl = _safe(msh.get("control_id", ""), 20)
    first = lambda i: _encode([echoed[i]]) if len(echoed) > i else ""  # noqa: E731
    if seg_name == "QRD":
        qak = f"QAK|{first(3)}|NF"                      # QRD-4 query id is the query tag
    else:
        qak = f"QAK|{first(1)}|NF|{first(0)}"           # QPD-2 query tag, QPD-1 query name
    segments = [_header(msh, facility, app, msg_type, resp_code), f"MSA|AA|{ctrl}", qak,
                f"{seg_name}|{_encode(echoed)}".rstrip("|")]
    return _frame(segments), f"{resp_code}^{resp_trigger}"


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
            answer = build_query_response(msh, text, facility, app) if msh else None
            if answer is not None:
                data.update(response=answer[1], query_status="NF")
            conn.emit("command", "HL7 message", data=data)
            await conn.write(answer[0] if answer is not None else build_ack(msh, facility, app))

    return [await start_tcp(ctx, "mllp", settings.port, handle)]
