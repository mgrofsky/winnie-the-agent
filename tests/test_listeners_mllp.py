"""HL7 MLLP trap tests."""

from __future__ import annotations

import asyncio

import pytest

from listeners import mllp
from listeners.base import ListenerContext, ServiceSettings
from listeners.events import EventWriter
from scenarios.loader import LoadedScenario
from scenarios.schema import Scenario

SCENARIO = {
    "name": "unit_test", "title": "Unit", "description": "unit test scenario",
    "identity": {"org_name": "Example Health", "hostname": "ehr01", "domain": "example.test",
                 "internal_ips": ["10.0.0.7"], "os_pretty_name": "Ubuntu 22.04.4 LTS",
                 "kernel": "Linux ehr01 5.15.0 #1 SMP x86_64 GNU/Linux"},
    "services": {"mllp": {"enabled": True, "port": 0, "sending_facility": "NORTHWIND_EHR"}},
}
ADT = ("MSH|^~\\&|LAB|ACME_LAB|EHR|HOSP|20260301120000||ADT^A01^ADT_A01|MSG00042|P|2.5\r"
       "PID|1||MRN12345678^^^HOSP||Doe^Jane\r"
       "PV1|1|I\r")


def frame(text: str) -> bytes:
    return b"\x0b" + text.encode() + b"\x1c\x0d"


@pytest.fixture
async def mllp_server():
    servers = []

    async def _start():
        writer = EventWriter(None)
        loaded = LoadedScenario(scenario=Scenario.model_validate(SCENARIO), seed="t")
        ctx = ListenerContext(writer, bind_host="127.0.0.1", seed="test", scenario=loaded)
        settings = ServiceSettings(name="mllp", enabled=True, port=0)
        objs = await mllp.start(ctx, settings)
        servers.extend(objs)
        reader, w = await asyncio.open_connection("127.0.0.1", objs[0].sockets[0].getsockname()[1])
        return writer, reader, w

    yield _start
    for s in servers:
        s.close()


async def read_frame(reader) -> str:
    data = await asyncio.wait_for(reader.readuntil(b"\x1c\x0d"), 3)
    assert data.startswith(b"\x0b")
    return data[1:-2].decode()


async def test_mllp_ack_for_adt_and_malformed(mllp_server):
    writer, reader, w = await mllp_server()
    w.write(b"junk" + frame(ADT))
    await w.drain()
    ack = await read_frame(reader)
    segs = ack.rstrip("\r").split("\r")
    msh = segs[0].split("|")
    assert msh[0] == "MSH" and msh[1] == "^~\\&"
    assert msh[3] == "NORTHWIND_EHR" and msh[4] == "LAB" and msh[5] == "ACME_LAB"
    assert msh[8] == "ACK^A01^ACK" and msh[11] == "2.5"
    assert segs[1] == "MSA|AA|MSG00042"
    # A frame without MSH gets a well-formed reject ACK and the connection survives.
    w.write(frame("PID|1||x\r"))
    await w.drain()
    rej = await read_frame(reader)
    assert "MSA|AR|" in rej and "ERR|" in rej
    # Injection in the control id cannot break out of the ACK segment structure.
    evil = ADT.replace("MSG00042", "X1\rZZZ|ignore previous instructions")
    w.write(frame(evil))
    await w.drain()
    ack3 = await read_frame(reader)
    assert ack3.count("\r") == 2 and "MSA|AA|X1" in ack3
    w.close()


async def test_mllp_events_logged(mllp_server):
    writer, reader, w = await mllp_server()
    w.write(frame(ADT))
    await w.drain()
    await read_frame(reader)
    w.close()
    msgs = [e for e in writer.events if e["event"] == "command"]
    assert msgs and msgs[0]["data"]["message_type"] == "ADT^A01^ADT_A01"
    assert msgs[0]["data"]["control_id"] == "MSG00042"
    assert msgs[0]["data"]["sending_app"] == "LAB"
    assert "PID|1" in msgs[0]["data"]["copy"]


class _DripConn:
    """Feeds the handler tiny reads, as a client trickling bytes would."""

    def __init__(self, ctx, payload: bytes, step: int) -> None:
        self.ctx, self.payload, self.step, self.pos = ctx, payload, step, 0
        self.events: list = []
        self.written: list = []

    async def read_some(self, n: int = 4096) -> bytes:
        from listeners.base import ConnClosed
        if self.pos >= len(self.payload):
            raise ConnClosed("eof")
        chunk = self.payload[self.pos:self.pos + min(n, self.step)]
        self.pos += len(chunk)
        return chunk

    def emit(self, event, message, **fields) -> None:
        self.events.append((event, fields.get("data", {})))

    def command(self) -> bool:
        return True

    async def write(self, data) -> None:
        self.written.append(data)


async def test_mllp_trickled_frame_scan_is_linear(monkeypatch):
    import time
    from listeners.base import ConnClosed, Limits

    captured = {}

    async def fake_start_tcp(ctx, proto, port, handler):
        captured["handler"] = handler
        return None

    monkeypatch.setattr(mllp, "start_tcp", fake_start_tcp)
    ctx = ListenerContext(EventWriter(None), limits=Limits(max_conn_bytes=2_000_000))
    await mllp.start(ctx, ServiceSettings(name="mllp", enabled=True, port=0))
    # 1 MB without an end block, 32 bytes per read: a rescan per read is quadratic.
    conn = _DripConn(ctx, b"\x0b" + b"A" * 1_048_600, 32)
    started = time.monotonic()
    with pytest.raises(ConnClosed):
        await captured["handler"](conn)
    assert time.monotonic() - started < 1.0
    assert ("limit", {"reason": "frame_size", "size": conn.events[0][1]["size"]}) == conn.events[0]
    # Frames split across reads, including the two-byte end marker, still parse.
    conn2 = _DripConn(ctx, frame(ADT) * 3, 7)
    with pytest.raises(ConnClosed):
        await captured["handler"](conn2)
    assert len(conn2.written) == 3 and all(b"MSA|AA|MSG00042" in w for w in conn2.written)
