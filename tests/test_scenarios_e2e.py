"""End-to-end: a scenario brings its services up with its own banners, accounts and data."""

import asyncio
import ftplib
import json
import struct
from configparser import ConfigParser


from listeners.__main__ import build_context
from listeners.base import SERVICES
import importlib


def _config(tmp_path, scenario: str) -> ConfigParser:
    cp = ConfigParser()
    cp["honeypot"] = {"log_file": str(tmp_path / "events.jsonl"), "sensor_name": "e2e"}
    cp["scenario"] = {"active": scenario, "seed": "e2e-seed",
                      "overlay": str(tmp_path / "overlay.json")}
    cp["listeners"] = {"bind_host": "127.0.0.1", "reports_dir": str(tmp_path / "reports"),
                       "quarantine_dir": str(tmp_path / "q")}
    for svc in SERVICES:
        cp["listeners"][f"{svc}_port"] = "0"
    return cp


async def _up(tmp_path, scenario):
    cp = _config(tmp_path, scenario)
    ctx = build_context(cp, tmp_path, None, data_dir=str(tmp_path / "data"))
    handles, ports = [], {}
    for name in SERVICES:
        s = ctx.settings[name]
        if not s.enabled:
            continue
        module = importlib.import_module(f"listeners.{name}")
        hs = await module.start(ctx, s)
        handles += hs
        for h in hs:
            if hasattr(h, "sockets") and h.sockets:
                ports.setdefault(name, h.sockets[0].getsockname()[1])
            elif hasattr(h, "get_extra_info"):
                ports.setdefault(f"{name}_udp", h.get_extra_info("sockname")[1])
    return ctx, handles, ports


def _close(handles):
    for h in handles:
        h.close()


def _events(tmp_path):
    path = tmp_path / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


async def _udp(port: int, payload: bytes) -> bytes:
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    class P(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            if not fut.done():
                fut.set_result(data)

    transport, _ = await loop.create_datagram_endpoint(P, remote_addr=("127.0.0.1", port))
    transport.sendto(payload)
    try:
        return await asyncio.wait_for(fut, timeout=3)
    finally:
        transport.close()


async def test_sip_provider_end_to_end(tmp_path):
    ctx, handles, ports = await _up(tmp_path, "sip_provider")
    try:
        sc = ctx.scenario.scenario
        # Honeytokens are planted in the fake data; the registry is the agents' job, never
        # written by a front-end.
        assert set(ctx.scenario.honeytokens) == {h.name for h in sc.honeytokens}
        assert not (tmp_path / "reports" / "honeytokens.json").exists()

        # SIP: OPTIONS answered with the scenario's server header.
        opts = (b"OPTIONS sip:100@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5999;branch=z9hG4bK1\r\n"
                b"From: <sip:scanner@127.0.0.1>;tag=1\r\nTo: <sip:100@127.0.0.1>\r\nCall-ID: e2e-1\r\n"
                b"CSeq: 1 OPTIONS\r\nUser-Agent: friendly-scanner\r\nContent-Length: 0\r\n\r\n")
        resp = (await _udp(ports["sip_udp"], opts)).decode()
        assert resp.startswith("SIP/2.0 200") and sc.services.sip.server_header in resp

        # FTP: scenario banner, a listed account logs in, scenario files are listed.
        user, pw = ctx.scenario.accounts_for("ftp")[0]

        def ftp_session():
            f = ftplib.FTP()
            welcome = f.connect("127.0.0.1", ports["ftp"], timeout=5)
            f.login(user, pw)
            names = f.nlst("/")
            f.quit()
            return welcome, names

        welcome, names = await asyncio.to_thread(ftp_session)
        if sc.services.ftp.banner:
            assert sc.services.ftp.banner.split(" ", 1)[1] in welcome
        top = {p.path.strip("/").split("/")[0] for p in sc.services.ftp.files}
        assert top & {n.strip("/").split("/")[-1] for n in names}

        # MySQL: handshake carries the scenario version string.
        r, w = await asyncio.open_connection("127.0.0.1", ports["mysql"])
        header = await asyncio.wait_for(r.readexactly(4), 3)
        body = await r.readexactly(int.from_bytes(header[:3], "little"))
        w.close()
        assert body[0] == 10
        assert body[1:].split(b"\x00", 1)[0].decode() == ctx.settings["mysql"].version
    finally:
        _close(handles)
    await asyncio.sleep(0.05)
    events = _events(tmp_path)
    assert any(e["sensor_protocol"] == "ftp" and e["event"] == "auth_attempt" and e.get("success")
               and e["username"] == user for e in events)
    assert any(e["sensor_protocol"] == "sip" and e["event"] == "options" for e in events)


async def test_healthcare_end_to_end(tmp_path):
    ctx, handles, ports = await _up(tmp_path, "healthcare")
    try:
        sc = ctx.scenario.scenario
        assert ctx.settings["mllp"].enabled and not ctx.settings["sip"].enabled

        # MLLP: ACK from the scenario's sending facility.
        r, w = await asyncio.open_connection("127.0.0.1", ports["mllp"])
        msg = ("MSH|^~\\&|LAB|LABFAC|EHR|MRH|20261114083015||ORU^R01|E2E1|P|2.5\r"
               "PID|1||00000001^^^MRH^MR||Doe^Test\r")
        w.write(b"\x0b" + msg.encode() + b"\x1c\x0d")
        await w.drain()
        ack = (await asyncio.wait_for(r.readuntil(b"\x1c\x0d"), 3)).decode()
        w.close()
        assert "MSA|AA|E2E1" in ack and sc.services.mllp.sending_facility in ack

        # PostgreSQL: SSL refused with N, then cleartext password requested.
        r, w = await asyncio.open_connection("127.0.0.1", ports["postgres"])
        w.write(struct.pack("!ii", 8, 80877103))
        await w.drain()
        assert await asyncio.wait_for(r.readexactly(1), 3) == b"N"
        user = ctx.scenario.accounts_for("postgres")[0][0]
        params = b"user\x00" + user.encode() + b"\x00database\x00ehr_clinical\x00\x00"
        w.write(struct.pack("!ii", 8 + len(params), 196608) + params)
        await w.drain()
        auth = await asyncio.wait_for(r.readexactly(9), 3)
        w.close()
        # md5 (5) by default, cleartext (3) when configured; either is a password request.
        assert auth[:1] == b"R" and struct.unpack("!i", auth[5:9])[0] in (3, 5)

        # HTTP: the FHIR API answers under the scenario's routes once authenticated.
        if "http" in ports:
            http = sc.services.http
            r, w = await asyncio.open_connection("127.0.0.1", ports["http"])
            w.write(f"GET {http.login_path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
            await w.drain()
            page = (await asyncio.wait_for(r.read(65536), 3)).decode(errors="replace")
            w.close()
            assert page.startswith("HTTP/1.1 200") and http.login_title in page
    finally:
        _close(handles)


def test_listeners_cli_list_and_describe(capsys):
    from listeners.__main__ import main

    assert main(["--list-scenarios"]) == 0
    listed = capsys.readouterr().out
    for name in ("sip_provider", "contact_center", "bank", "saas", "api_platform", "healthcare"):
        assert name in listed
    assert main(["--describe", "sip_provider"]) == 0
    out = capsys.readouterr().out
    assert "Service sip: enabled" in out
    from scenarios.loader import load_scenario

    shown = load_scenario("sip_provider", seed="preview")
    assert not [t for t in shown.recognised_tokens() if t in out]
