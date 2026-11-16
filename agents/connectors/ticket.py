"""Enforce-tier POSTs: open a ticket and push an approved IP or IPv6 /64 to a block
endpoint. Both only run after approval; this module just performs the call. Ticket text
is defanged (``hxxp``, ``[.]``, ``[at]``) so the ticket system does not link it."""

from __future__ import annotations

import ipaddress
import json

from .base import ConnectorResult, defang
from .http import HttpEndpoint

_TICKET_FIELDS = {"title": 160, "summary": 300, "priority": 16, "source": 64, "record_id": 200}
_REASON_MAX = 300


def _text(value, limit: int) -> str:
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    s = "".join(c if c.isprintable() else " " for c in s)
    return s[:limit]


def build_ticket(payload: dict) -> dict:
    payload = payload if isinstance(payload, dict) else {}
    out = {k: _text(payload.get(k), limit) for k, limit in _TICKET_FIELDS.items()}
    for k in ("title", "summary", "source"):
        out[k] = defang(out[k])[:_TICKET_FIELDS[k]]
    return out


class TicketConnector:
    def __init__(self, endpoint: HttpEndpoint) -> None:
        self.endpoint = endpoint

    def open_ticket(self, payload: dict) -> ConnectorResult:
        body = json.dumps(build_ticket(payload), ensure_ascii=True).encode()
        return self.endpoint.perform("POST", self.endpoint.cfg.url, body)


class BlockConnector:
    def __init__(self, endpoint: HttpEndpoint) -> None:
        self.endpoint = endpoint

    def block(self, ip: str, reason: str) -> ConnectorResult:
        """``ip`` is a single address or an IPv6 /64 source key."""
        value = str(ip).strip()
        try:
            if "/" in value:
                net = ipaddress.ip_network(value, strict=True)
                if net.version != 6 or net.prefixlen != 64:
                    raise ValueError("only IPv6 /64 networks")
                field = {"network": str(net)}
            else:
                field = {"ip": str(ipaddress.ip_address(value))}
        except ValueError:
            return ConnectorResult(False, "error: invalid_ip")
        body = json.dumps({**field, "reason": _text(reason, _REASON_MAX)},
                          ensure_ascii=True).encode()
        return self.endpoint.perform("POST", self.endpoint.cfg.url, body)
