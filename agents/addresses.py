"""Which addresses count as public (routable on the internet).

One definition for every place that must refuse private, loopback, link-local, CGNAT,
multicast, reserved and documentation addresses: per-source actions, blocklists, Sigma
selectors and outbound connector destinations.

Tests that need a public-looking source use ``public_for_tests`` to treat one
documentation range as public, so the repository holds no real addresses.
"""

from __future__ import annotations

import contextlib
import ipaddress
from typing import Iterator

_TEST_PUBLIC: tuple = ()


def is_public(value: str) -> bool:
    """True for a global unicast address. Invalid input is not public."""
    try:
        ip = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if any(ip in net for net in _TEST_PUBLIC):
        return True
    return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified)


@contextlib.contextmanager
def public_for_tests(*cidrs: str) -> Iterator[None]:
    """Treat the given (documentation) ranges as public inside the block. Tests only."""
    global _TEST_PUBLIC
    before = _TEST_PUBLIC
    _TEST_PUBLIC = before + tuple(ipaddress.ip_network(c) for c in cidrs)
    try:
        yield
    finally:
        _TEST_PUBLIC = before
