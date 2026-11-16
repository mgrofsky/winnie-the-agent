"""Test helper: feed a listener pathological inputs under a time bound.

All listeners share one event loop, so any input that makes a handler spin blocks every
protocol. ``hammer`` sends each payload on its own connection while a probe connection
measures how quickly a fresh client still gets served.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class HammerResult:
    worst_payload_seconds: float
    worst_probe_seconds: float
    payloads: int


async def _drain(reader: asyncio.StreamReader, idle: float) -> None:
    while True:
        try:
            chunk = await asyncio.wait_for(reader.read(65536), idle)
        except asyncio.TimeoutError:
            return
        if not chunk:
            return


async def _send(port: int, preamble: list[bytes], payload: bytes, idle: float) -> float:
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
    except OSError:
        return 0.0
    try:
        await _drain(reader, 0.2)
        for line in preamble:
            writer.write(line)
            await writer.drain()
            await _drain(reader, 0.2)
        writer.write(payload)
        await writer.drain()
        await _drain(reader, idle)
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()
    return time.perf_counter() - start


async def _probe(port: int, request: bytes = b"") -> float:
    start = time.perf_counter()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        if request:
            writer.write(request)
            await writer.drain()
        await asyncio.wait_for(reader.read(1), 5)
    except asyncio.TimeoutError:
        pass
    finally:
        writer.close()
    return time.perf_counter() - start


async def hammer(port: int, payloads: list[bytes], preamble: list[bytes] = (),
                 idle: float = 0.3, probe: bool = True, probe_request: bytes = b"") -> HammerResult:
    """Send each payload (after ``preamble`` lines) and time it; probe the listener while
    the payloads are in flight. Services that do not speak first need ``probe_request``."""
    worst_probe = 0.0
    worst = 0.0
    for payload in payloads:
        attack = asyncio.create_task(_send(port, list(preamble), payload, idle))
        if probe:
            await asyncio.sleep(0.02)
            worst_probe = max(worst_probe, await _probe(port, probe_request))
        worst = max(worst, await attack)
    return HammerResult(worst, worst_probe, len(payloads))


def repeats(specials: str, size: int = 60_000) -> list[bytes]:
    """Long runs of each special character, and of all of them interleaved."""
    out = [(c * size).encode() for c in specials]
    out.append((specials * (size // max(1, len(specials)))).encode())
    return out
