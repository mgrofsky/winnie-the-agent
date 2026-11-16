"""IP enrichment through a generic HTTP JSON reputation or threat-intel service.

Privacy note: enabling this connector discloses attacker source IPs to the configured
third party (and to anyone that service shares its query logs with). Only enable it for
a service you are allowed to send that data to. Unverified UDP sources are never passed
here by the engine.

Config: ``url`` is a template containing ``{ip}``; the address is inserted URL-encoded.
The placeholder must not be part of the host name, so the destination never depends on
attacker input. ``secret_env`` names the variable holding the API key and ``header``
names the header it is sent in (default ``Authorization``, sent as a bearer token;
any other header carries the raw value).

The response is untrusted. It is parsed as JSON and flattened into at most 32 keys of
str/int/float/bool, keys and string values cut to 128 characters, control characters
removed. Anything else is dropped.
"""

from __future__ import annotations

import ipaddress
import json
import math
from urllib.parse import quote, urlsplit

from .base import ConnectorResult, DestinationError
from .http import ConfigError, HttpEndpoint

PLACEHOLDER = "{ip}"
SAMPLE_IPS = ("192.0.2.1", "2001:db8::1")
MAX_KEYS = 32
MAX_STR = 128
MAX_DEPTH = 8
_INT_LIMIT = 2 ** 63


def render(template: str, ip: str) -> str:
    return template.replace(PLACEHOLDER, quote(ip, safe=""))


def check_template(template: str) -> list[str]:
    """Rendered sample URLs, for load-time validation. Raises ConfigError."""
    if template.count(PLACEHOLDER) < 1:
        raise ConfigError("url must contain {ip}")
    if PLACEHOLDER in urlsplit(template).netloc:
        raise ConfigError("{ip} must not be part of the host name")
    rendered = [render(template, s) for s in SAMPLE_IPS]
    if len({urlsplit(u).netloc for u in rendered}) != 1:
        raise ConfigError("{ip} must not be part of the host name")
    return rendered


def _clean(s: str) -> str:
    return "".join(c for c in s if c.isprintable())[:MAX_STR]


def _scalar(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if -_INT_LIMIT < value < _INT_LIMIT else None
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return _clean(value)
    return None


def sanitise(doc) -> dict:
    """Flatten an untrusted JSON document into a small dict of scalars."""
    out: dict = {}
    stack = [("", doc, 0)]
    while stack and len(out) < MAX_KEYS:
        prefix, value, depth = stack.pop()
        if isinstance(value, dict):
            if depth >= MAX_DEPTH:
                continue
            items = list(value.items())[:MAX_KEYS * 4]
            for k, v in reversed(items):
                key = _clean(str(k))
                stack.append((f"{prefix}.{key}" if prefix else key, v, depth + 1))
        elif isinstance(value, list):
            if depth >= MAX_DEPTH:
                continue
            for i, v in reversed(list(enumerate(value[:MAX_KEYS * 4]))):
                stack.append((f"{prefix}.{i}" if prefix else str(i), v, depth + 1))
        else:
            scalar = _scalar(value)
            key = _clean(prefix) or "value"
            if scalar is not None and key not in out:
                out[key] = scalar
    return out



class EnrichConnector:
    def __init__(self, endpoint: HttpEndpoint) -> None:
        self.endpoint = endpoint

    def enrich(self, ip: str) -> ConnectorResult:
        try:
            addr = str(ipaddress.ip_address(str(ip).strip()))
        except ValueError:
            return ConnectorResult(False, "error: invalid_ip")
        url = render(self.endpoint.cfg.url, addr)
        if urlsplit(url).scheme != "https":
            return ConnectorResult(False, f"error: {DestinationError.__name__}")
        return self.endpoint.perform("GET", url, None, on_body=self._parse)

    @staticmethod
    def _parse(data: bytes) -> ConnectorResult:
        try:
            doc = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return ConnectorResult(False, "error: invalid_json")
        return ConnectorResult(True, "ok", data=sanitise(doc))
