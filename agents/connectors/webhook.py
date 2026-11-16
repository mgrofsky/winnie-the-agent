"""Generic JSON webhook notifier. The payload carries a ``text`` line so chat webhooks
(Slack, Teams, Mattermost and similar) render it without extra configuration. Attacker-derived
URLs, domains, addresses and ``@`` are defanged so the chat client neither links nor
mentions them."""

from __future__ import annotations

import json

from .base import ConnectorResult, Notification, defang, defanged_dump
from .http import HttpEndpoint


def build_payload(n: Notification) -> dict:
    return {"text": defang(f"{n.title}: {n.summary}"), "event": defanged_dump(n)}


class WebhookConnector:
    def __init__(self, endpoint: HttpEndpoint) -> None:
        self.endpoint = endpoint

    def notify(self, n: Notification) -> ConnectorResult:
        body = json.dumps(build_payload(n), ensure_ascii=True).encode()
        return self.endpoint.perform("POST", self.endpoint.cfg.url, body)
