"""JSON events to an HTTP collector. One event per notification; the notification
fields sit under ``event`` so its own ``source`` field does not clash with the
top-level ``source`` that identifies this sensor."""

from __future__ import annotations

import datetime
import json

from .base import ConnectorResult, Notification
from .http import HttpEndpoint

EVENT_SOURCE = "winnie"


def build_event(n: Notification, now: datetime.datetime | None = None) -> dict:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return {
        "@timestamp": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "source": EVENT_SOURCE,
        "event": n.model_dump(),
    }


class SiemHttpConnector:
    def __init__(self, endpoint: HttpEndpoint) -> None:
        self.endpoint = endpoint

    def notify(self, n: Notification) -> ConnectorResult:
        body = json.dumps(build_event(n), ensure_ascii=True).encode()
        return self.endpoint.perform("POST", self.endpoint.cfg.url, body)
