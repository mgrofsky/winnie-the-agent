"""Outbound connectors used by response playbooks.

``Connectors`` loads every ``[connector.<name>]`` section once. A section that is missing
or has ``enabled = false`` leaves that connector off; a section that fails validation
leaves it off and records a message in ``errors`` (load never raises). Every call returns
a ``ConnectorResult`` and never raises.
"""

from __future__ import annotations

import configparser
from pathlib import Path
from typing import Callable, Optional

from .base import ConnectorResult, DestinationError, Notification, Transport
from .email import EmailConnector, load_email
from .enrich import EnrichConnector, check_template
from .http import ConfigError, HttpEndpoint, UrlTransport, load_endpoint
from .siem_http import SiemHttpConnector
from .ticket import BlockConnector, TicketConnector
from .webhook import WebhookConnector

NOTIFY_NAMES = ("webhook", "siem_http", "email")
NAMES = ("webhook", "siem_http", "email", "enrich", "ticket", "block_webhook")
# Sections read by other parts of the agents (the event export in agents/ship.py).
OTHER_SECTIONS = ("s3_events",)

__all__ = ["Connectors", "ConnectorResult", "Notification", "Transport", "NAMES"]

_HTTP_CLASSES = {
    "webhook": WebhookConnector,
    "siem_http": SiemHttpConnector,
    "ticket": TicketConnector,
    "block_webhook": BlockConnector,
    "enrich": EnrichConnector,
}

_DISABLED = "disabled"


class Connectors:
    def __init__(self, config: configparser.ConfigParser, state_dir: Path,
                 transport: Optional[Transport] = None, smtp_factory: Optional[Callable] = None,
                 resolver=None) -> None:
        self.errors: list[str] = []
        self._items: dict[str, object] = {}
        state_dir = Path(state_dir)
        transport = transport if transport is not None else UrlTransport()
        for section in config.sections():
            if section.startswith("connector.") and section[len("connector."):] not in NAMES + OTHER_SECTIONS:
                self.errors.append(f"[{section}]: unknown connector")
        for name in NAMES:
            key = f"connector.{name}"
            if not config.has_section(key):
                continue
            section = config[key]
            try:
                if not section.getboolean("enabled", fallback=False):
                    continue
                self._items[name] = self._build(name, section, state_dir, transport,
                                                smtp_factory, resolver)
            except ValueError as exc:
                # ConfigError and DestinationError messages never contain configured values.
                msg = str(exc) if isinstance(exc, (ConfigError, DestinationError)) \
                    else "invalid value"
                self.errors.append(f"[{key}]: {msg}; connector disabled")
            except Exception as exc:
                self.errors.append(f"[{key}]: {type(exc).__name__}; connector disabled")

    @staticmethod
    def _build(name, section, state_dir, transport, smtp_factory, resolver):
        if name == "email":
            return EmailConnector(load_email(section), state_dir, smtp_factory, resolver)
        if name == "enrich":
            template = (section.get("url", "") or "").strip()
            sample = check_template(template)[0]
            cfg = load_endpoint(section, name, url=sample)
        else:
            cfg = load_endpoint(section, name)
        return _HTTP_CLASSES[name](HttpEndpoint(cfg, state_dir, transport, resolver))

    def enabled(self, name: str) -> bool:
        return name in self._items

    def daily_cap(self, name: str) -> Optional[int]:
        """The configured ``max_per_day`` of an enabled connector, else None."""
        item = self._items.get(name)
        if item is None:
            return None
        cfg = getattr(getattr(item, "endpoint", None), "cfg", None) or getattr(item, "cfg", None)
        return getattr(cfg, "max_per_day", None)

    def notify(self, name: str, n: Notification) -> ConnectorResult:
        if name not in NOTIFY_NAMES:
            return ConnectorResult(False, "error: unknown_connector")
        item = self._items.get(name)
        if item is None:
            return ConnectorResult(False, _DISABLED)
        return _guard(lambda: item.notify(n))

    def enrich(self, ip: str) -> ConnectorResult:
        item = self._items.get("enrich")
        if item is None:
            return ConnectorResult(False, _DISABLED)
        return _guard(lambda: item.enrich(ip))

    def open_ticket(self, payload: dict) -> ConnectorResult:
        item = self._items.get("ticket")
        if item is None:
            return ConnectorResult(False, _DISABLED)
        return _guard(lambda: item.open_ticket(payload))

    def block(self, ip: str, reason: str) -> ConnectorResult:
        item = self._items.get("block_webhook")
        if item is None:
            return ConnectorResult(False, _DISABLED)
        return _guard(lambda: item.block(ip, reason))


def _guard(fn) -> ConnectorResult:
    try:
        return fn()
    except Exception as exc:
        return ConnectorResult(False, f"error: {type(exc).__name__}")
