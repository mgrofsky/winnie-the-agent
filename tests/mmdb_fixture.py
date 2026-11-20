"""A tiny MaxMind DB (.mmdb) writer for tests: real files the ``maxminddb`` reader opens.

Follows the MaxMind DB format spec (version 2.0): an IPv6 search tree with 24-bit records,
16 zero bytes, the data section, then the metadata marker and map. It writes maps, strings,
unsigned integers, booleans, doubles and arrays: enough for GeoLite2 / DB-IP shaped records.
No pointers and no deduplication; fixtures are a handful of networks.
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


def _control(type_num: int, size: int) -> bytes:
    if size < 29:
        size_bits, extra = size, b""
    elif size < 29 + 256:
        size_bits, extra = 29, bytes([size - 29])
    elif size < 285 + 65536:
        size_bits, extra = 30, struct.pack(">H", size - 285)
    else:
        size_bits, extra = 31, struct.pack(">I", size - 65821)[1:]
    if type_num <= 7:
        return bytes([(type_num << 5) | size_bits]) + extra
    return bytes([size_bits, type_num - 7]) + extra


def _uint(value: int, type_num: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    return _control(type_num, len(raw)) + raw


def encode(value) -> bytes:
    if isinstance(value, bool):
        return _control(14, int(value))
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _control(2, len(raw)) + raw
    if isinstance(value, float):
        return _control(3, 8) + struct.pack(">d", value)
    if isinstance(value, int):
        if value < 0:
            raise ValueError("signed integers are not needed by the fixtures")
        return _uint(value, 6 if value < 2 ** 32 else 9)
    if isinstance(value, dict):
        out = _control(7, len(value))
        for k, v in value.items():
            out += encode(str(k)) + encode(v)
        return out
    if isinstance(value, (list, tuple)):
        return _control(11, len(value)) + b"".join(encode(v) for v in value)
    raise TypeError(type(value).__name__)


def _bits(network: str) -> list[int]:
    net = ipaddress.ip_network(network, strict=False)
    if net.version == 4:   # IPv4 lives at ::a.b.c.d in an IPv6 tree
        value, prefix = int(net.network_address), 96 + net.prefixlen
    else:
        value, prefix = int(net.network_address), net.prefixlen
    return [(value >> (127 - i)) & 1 for i in range(prefix)]


def write_mmdb(path: Path, records: dict[str, object], *, database_type: str = "Test",
               build_epoch: int = 1_790_000_000, description: str = "test fixture") -> Path:
    """Write ``{network: record}`` to ``path``. Networks must not overlap."""
    data = b""
    offsets = []
    for record in records.values():
        offsets.append(len(data))
        data += encode(record)
    nodes: list[list] = [[None, None]]   # child: None (empty), ("node", i) or ("data", off)
    for (network, _), offset in zip(records.items(), offsets):
        bits, node = _bits(network), 0
        for depth, bit in enumerate(bits):
            if depth == len(bits) - 1:
                nodes[node][bit] = ("data", offset)
                break
            child = nodes[node][bit]
            if child is None:
                nodes.append([None, None])
                child = nodes[node][bit] = ("node", len(nodes) - 1)
            if child[0] != "node":
                raise ValueError("overlapping networks")
            node = child[1]
    count = len(nodes)

    def value(child) -> int:
        if child is None:
            return count
        return child[1] if child[0] == "node" else count + 16 + child[1]

    tree = b"".join(value(left).to_bytes(3, "big") + value(right).to_bytes(3, "big")
                    for left, right in nodes)
    metadata = {"node_count": count, "record_size": 24, "ip_version": 6,
                "database_type": database_type, "languages": ["en"],
                "binary_format_major_version": 2, "binary_format_minor_version": 0,
                "build_epoch": build_epoch, "description": {"en": description}}
    meta = _control(7, len(metadata))
    for k, v in metadata.items():
        meta += encode(k)
        if k in ("record_size", "ip_version", "binary_format_major_version",
                 "binary_format_minor_version"):
            meta += _uint(v, 5)      # uint16, as the spec says
        elif k == "build_epoch":
            meta += _uint(v, 9)      # uint64
        else:
            meta += encode(v)
    path.write_bytes(tree + b"\x00" * 16 + data + METADATA_MARKER + meta)
    return path
