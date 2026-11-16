"""Source verification (SIP nonce round trip), per-source keying, and telnet timeouts."""

import asyncio
import hashlib
import re

from listeners import telnet
from listeners.base import ConnectionLimiter, Limits, ListenerContext, ServiceSettings, SlidingRate
from listeners.events import EventWriter
from listeners.sip import SipCore
from scenarios.schema import LoginPolicy


def _register(nonce: str = "", user: str = "100", password: str = "1234") -> bytes:
    head = ("REGISTER sip:pbx.example SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1\r\n"
            f"From: <sip:{user}@pbx.example>;tag=1\r\nTo: <sip:{user}@pbx.example>\r\n"
            "Call-ID: nonce-test\r\nCSeq: 1 REGISTER\r\n")
    if nonce:
        realm, uri = "asterisk", "sip:pbx.example"
        ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"REGISTER:{uri}".encode()).hexdigest()
        resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        head += (f'Authorization: Digest username="{user}",realm="{realm}",nonce="{nonce}",'
                 f'uri="{uri}",response="{resp}",algorithm=MD5\r\n')
    return (head + "Content-Length: 0\r\n\r\n").encode()


def _core():
    ctx = ListenerContext(EventWriter(None))
    settings = ServiceSettings("sip", True, 0, policy=LoginPolicy(accept="all"))
    return ctx, SipCore(ctx, settings)


def test_udp_source_verified_only_by_our_nonce():
    ctx, core = _core()
    real, spoofed = ("192.0.2.10", 5060), ("192.0.2.66", 5060)
    challenge = core.handle(_register(), real, ("0.0.0.0", 5060), "udp")[0][1].decode()
    nonce = re.search(r'nonce="([^"]+)"', challenge).group(1)
    core.handle(_register(nonce), real, ("0.0.0.0", 5060), "udp")
    # A spoofed source cannot see the challenge: it answers with a nonce it made up, or
    # replays one issued to someone else.
    core.handle(_register("1700000000/deadbeef"), spoofed, ("0.0.0.0", 5060), "udp")
    core.handle(_register(nonce), spoofed, ("0.0.0.0", 5060), "udp")
    attempts = [e for e in ctx.writer.events if e["event"] == "auth_attempt"]
    by_ip = [(e["src_ip"], e["data"]["nonce_verified"]) for e in attempts]
    # The spoofed source's repeat attempt is aggregated (unverified sources are gated).
    assert by_ip == [("192.0.2.10", True), ("192.0.2.66", False)]
    assert list(core.verified_sources) == ["192.0.2.10"]


def test_listener_limits_key_ipv6_on_slash_64():
    limiter = ConnectionLimiter(Limits(max_connections_per_ip=1))
    assert limiter.acquire("2001:db8:5:6::1") is None
    assert limiter.acquire("2001:db8:5:6::abcd") == "max_connections_per_ip"
    assert limiter.acquire("2001:db8:5:7::1") is None
    limiter.release("2001:db8:5:6::1")
    assert limiter.acquire("2001:db8:5:6::2") is None
    rate = SlidingRate(per_minute=1)
    assert rate.allow("2001:db8:9:9::1") and not rate.allow("2001:db8:9:9::2")


async def test_telnet_idle_connection_is_closed():
    ctx = ListenerContext(EventWriter(None), limits=Limits(pre_login_timeout=0.3, read_timeout=0.3,
                                                      session_timeout=5),
                          bind_host="127.0.0.1")
    servers = await telnet.start(ctx, ServiceSettings("telnet", True, 0))
    port = servers[0].sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.wait_for(reader.read(4096), 2)          # banner / login prompt
        await asyncio.wait_for(reader.read(), 3)  # we send nothing; returns only at EOF
        assert reader.at_eof()                     # the server closed the idle connection
        writer.close()
    finally:
        for s in servers:
            s.close()
    assert any(e["event"] == "close" for e in ctx.writer.events)
