"""Connector contract for outbound notify / enrich / enforce actions.

Rules every connector follows:
- Runs only in the agents process (never in a front-end), only to destinations the operator
  configured, all disabled by default.
- Destinations are validated when loaded: ``https`` only, and no private, loopback,
  link-local or otherwise non-public address (literal, or any address the host name
  resolves to at send time) unless ``allow_private = true`` for that connector.
- The host name is resolved once per call and the connection goes to that validated
  address (see ``pin_address``); nothing resolves the name a second time.
- Secrets are read from environment variables named in config (``secret_env``); values
  never appear in config, the repo, logs or reports.
- A socket timeout on every operation plus one overall deadline per call, retries off,
  no redirects, and a per-day call cap.
- Network I/O goes through an injected ``Transport`` so tests never touch the network.

Config (``config.ini``)::

    [connector.webhook]
    enabled = false
    url = https://hooks.example.com/services/...
    secret_env = WINNIE_WEBHOOK_TOKEN      ; optional, sent as a bearer token
    max_per_day = 200
    timeout = 10
    allow_private = false
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Optional, Protocol, Union
from urllib.parse import urlsplit

from agents.addresses import is_public
from pydantic import BaseModel, ConfigDict, Field

JsonValue = Union[str, int, bool, list[str]]


class Notification(BaseModel):
    """Everything a notify connector may send. Built by the engine from validated triage
    fields; every string is already sanitised and length-capped."""

    model_config = ConfigDict(extra="forbid")

    playbook: str = Field(max_length=64)
    title: str = Field(max_length=160)
    summary: str = Field(max_length=300)
    record_id: str = Field(max_length=200)
    source: str = Field(max_length=64)
    protocol: str = Field(max_length=16)
    judgement: str = Field(max_length=16)
    stage: str = Field(max_length=32)
    details: dict[str, JsonValue] = Field(default_factory=dict)
    # True when the source completed a TCP handshake or a nonce round trip; None for
    # notices that name no source (for example the suppressed-notifications notice).
    source_verified: Optional[bool] = None


# ---- defanging for human-facing outputs ----------------------------------------------------
#
# Chat, email and ticket outputs show attacker-derived URLs, domains and addresses in a
# form that clients do not turn into links or mentions: ``hxxp://``, ``[.]`` between
# labels and ``[at]`` for ``@``. The SIEM output keeps raw values.

_SCHEME_RE = re.compile(r"\b(h)tt(ps?)(?=://)|\b(f)t(p)(?=://)", re.I)
_DOT_RE = re.compile(r"(?<=[A-Za-z0-9])\.(?=[A-Za-z0-9])")


def _scheme(m: re.Match) -> str:
    if m.group(1):
        return f"{m.group(1)}xx{m.group(2)}"
    return f"{m.group(3)}x{m.group(4)}"


def defang(text: str) -> str:
    text = _SCHEME_RE.sub(_scheme, str(text))
    text = _DOT_RE.sub("[.]", text)
    return text.replace("@", "[at]")


def defang_value(value):
    """``defang`` applied to every string in a JSON-like value."""
    if isinstance(value, str):
        return defang(value)
    if isinstance(value, list):
        return [defang_value(v) for v in value]
    if isinstance(value, dict):
        return {k: defang_value(v) for k, v in value.items()}
    return value


# Fields computed by code from fixed vocabularies; never defanged.
PLAIN_FIELDS = ("playbook", "record_id", "protocol", "judgement", "stage", "source_verified")


def defanged_dump(n: "Notification") -> dict:
    """The notification as a dict with every attacker-derived string defanged."""
    data = n.model_dump()
    return {k: (v if k in PLAIN_FIELDS else defang_value(v)) for k, v in data.items()}


@dataclass
class ConnectorResult:
    ok: bool
    status: str                      # "sent", "disabled", "cap_reached", "error: ...", ...
    data: dict = field(default_factory=dict)   # enrich results (sanitised, capped)


class Transport(Protocol):
    """Minimal HTTP transport. Implementations must not follow redirects.

    ``address`` is the IP address already resolved and validated by ``pin_address``. The
    transport connects to that address and must not resolve the URL's host name itself;
    the host name from ``url`` is used only for TLS (SNI and certificate verification)
    and the ``Host`` header.
    """

    def request(self, method: str, url: str, headers: dict[str, str], body: Optional[bytes],
                timeout: float, address: str) -> tuple[int, bytes]:
        ...


class DestinationError(ValueError):
    pass


def _non_public(addr: str) -> bool:
    return not is_public(addr)


def validate_destination(url: str, allow_private: bool = False) -> str:
    """Validate a configured URL at load time. Returns the URL or raises DestinationError."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise DestinationError("only https destinations are allowed")
    if not parts.hostname:
        raise DestinationError("destination has no host")
    if parts.username or parts.password:
        raise DestinationError("credentials in URLs are not allowed; use secret_env")
    host = parts.hostname
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if literal and _non_public(host) and not allow_private:
        raise DestinationError("private, loopback or reserved address not allowed")
    if not literal and host in ("localhost",) and not allow_private:
        raise DestinationError("localhost not allowed")
    return url


def pin_address(host: str, port: int, allow_private: bool = False,
                resolver=socket.getaddrinfo) -> str:
    """Resolve ``host`` once, validate every address, and return the one to connect to.

    Why pinning exists: checking the addresses and then letting the client library resolve
    the name again at connect time leaves a window (DNS rebinding) in which a host whose
    answer changes between the two lookups reaches a private address. Callers therefore
    connect to the address returned here and use ``host`` only for TLS and ``Host``.

    Every returned address must be public unless ``allow_private`` is set; the name is
    resolved and pinned either way.
    """
    try:
        infos = resolver(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise DestinationError(f"cannot resolve destination: {type(exc).__name__}") from exc
    addresses = []
    for info in infos:
        try:
            addr = str(ipaddress.ip_address(info[4][0]))
        except (ValueError, IndexError, TypeError):
            raise DestinationError("destination resolves to an invalid address") from None
        if not allow_private and _non_public(addr):
            raise DestinationError("destination resolves to a non-public address")
        addresses.append(addr)
    if not addresses:
        raise DestinationError("destination resolves to no address")
    return addresses[0]
