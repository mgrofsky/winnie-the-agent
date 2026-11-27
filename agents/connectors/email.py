"""Plain-text email notifications through a configured SMTP relay.

Config::

    [connector.email]
    enabled = false
    host = smtp.example.com
    port = 587
    from = winnie@example.com
    to = soc@example.com, oncall@example.com
    starttls = true
    username_env = WINNIE_SMTP_USER     ; optional, both or neither
    password_env = WINNIE_SMTP_PASSWORD
    max_per_day = 200
    timeout = 10
    allow_private = false

Each send has one overall deadline (``timeout`` seconds for the whole SMTP exchange) in
addition to the socket timeout on every operation.

Credentials are only ever sent after STARTTLS succeeds; a config with credentials and
``starttls = false`` is refused at load.

The relay's host name is resolved once and validated by ``pin_address``; the TCP connection
goes to that address (``PinnedSMTP``) while STARTTLS verifies the certificate against the
configured host name, so a DNS answer that changes after the check cannot redirect the
connection to a private address.
"""

from __future__ import annotations

import ipaddress
import re
import smtplib
import socket
import ssl
import time
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Callable, Optional

from agents.llm import DailyCallCounter

from .base import ConnectorResult, Notification, defang_value, defanged_dump, pin_address, \
    validate_destination
from .http import (
    ConfigError,
    DeadlineExceeded,
    error_result,
    parse_env_name,
    parse_limits,
    read_secret,
)

_clock = time.monotonic

_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_ADDR = re.compile(r"^[^@\s<>,;\"]{1,64}@[A-Za-z0-9.-]{1,253}$")
MAX_RECIPIENTS = 20


class PinnedSMTP(smtplib.SMTP):
    """``smtplib.SMTP`` that connects to a fixed, already validated IP address.

    ``host`` stays the configured name: ``smtplib`` keeps it as ``_host`` and STARTTLS
    passes it as ``server_hostname``, so SNI and certificate hostname checks use the name
    while the socket goes to ``address``. No DNS lookup of ``host`` happens here.
    """

    def __init__(self, host: str, port: int, timeout: float, address: str,
                 create_connection=socket.create_connection) -> None:
        self.pinned_address = address
        self._create_connection = create_connection
        super().__init__(host, port, timeout=timeout)

    def _get_socket(self, host, port, timeout):
        if timeout is not None and not timeout:
            raise ValueError("Non-blocking socket (timeout=0) is not supported")
        return self._create_connection((self.pinned_address, port), timeout,
                                       self.source_address)


def default_smtp_factory(host: str, port: int, timeout: float, address: str):
    """Called as ``factory(host, port, timeout, address=...)``; ``address`` is the pinned
    IP to connect to and ``host`` the name used for STARTTLS verification."""
    return PinnedSMTP(host, port, timeout, address)


@dataclass
class EmailConfig:
    host: str
    port: int
    sender: str
    recipients: list[str]
    starttls: bool
    username_env: Optional[str]
    password_env: Optional[str]
    max_per_day: int
    timeout: float
    allow_private: bool


def _check_host(host: str, allow_private: bool) -> None:
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if not literal and not _HOST.match(host):
        raise ConfigError("host must be a host name or IP address")
    shown = f"[{host}]" if literal and ":" in host else host
    validate_destination(f"https://{shown}/", allow_private)


def load_email(section) -> EmailConfig:
    max_per_day, timeout, allow_private = parse_limits(section, "email")
    host = (section.get("host", "") or "").strip()
    if not host:
        raise ConfigError("host is required")
    _check_host(host, allow_private)
    try:
        port = int(section.get("port", "587"))
    except ValueError:
        raise ConfigError("port must be an integer") from None
    if not 0 < port < 65536:
        raise ConfigError("port out of range")
    sender = (section.get("from", "") or "").strip()
    if not _ADDR.match(sender):
        raise ConfigError("from must be a single email address")
    recipients = [r.strip() for r in (section.get("to", "") or "").split(",") if r.strip()]
    if not recipients or len(recipients) > MAX_RECIPIENTS or \
            not all(_ADDR.match(r) for r in recipients):
        raise ConfigError(f"to must list 1-{MAX_RECIPIENTS} email addresses")
    try:
        starttls = section.getboolean("starttls", fallback=True)
    except ValueError:
        raise ConfigError("starttls must be true or false") from None
    username_env = parse_env_name(section, "username_env")
    password_env = parse_env_name(section, "password_env")
    if (username_env is None) != (password_env is None):
        raise ConfigError("username_env and password_env must be set together")
    if username_env is not None and not starttls:
        raise ConfigError("credentials require starttls = true")
    return EmailConfig(host=host, port=port, sender=sender, recipients=recipients,
                       starttls=starttls, username_env=username_env, password_env=password_env,
                       max_per_day=max_per_day, timeout=timeout, allow_private=allow_private)


def _line(value: str) -> str:
    return "".join(c if c.isprintable() else " " for c in str(value))


def build_body(n: Notification) -> str:
    """Plain-text body. Attacker-derived URLs, domains, addresses and ``@`` are defanged."""
    d = defanged_dump(n)
    lines = [
        f"Title: {_line(d['title'])}",
        f"Summary: {_line(d['summary'])}",
        "",
        f"Playbook: {_line(n.playbook)}",
        f"Record: {_line(n.record_id)}",
        f"Source: {_line(d['source'])}",
        f"Source verified: {_line(n.source_verified)}",
        f"Protocol: {_line(n.protocol)}",
        f"Judgement: {_line(n.judgement)}",
        f"Stage: {_line(n.stage)}",
    ]
    if n.details:
        lines += ["", "Details:"]
        for key, value in d["details"].items():
            shown = ", ".join(value) if isinstance(value, list) else value
            lines.append(f"  {_line(key)}: {_line(shown)}")
    return "\n".join(lines) + "\n"


def build_message(cfg: EmailConfig, n: Notification) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = _line(defang_value(n.title))
    msg["From"] = cfg.sender
    msg["To"] = ", ".join(cfg.recipients)
    msg.set_content(build_body(n))
    return msg


class CredentialsWithoutTls(Exception):
    pass


class EmailConnector:
    def __init__(self, cfg: EmailConfig, state_dir: Path,
                 smtp_factory: Optional[Callable] = None, resolver=None) -> None:
        self.cfg = cfg
        self.smtp_factory = smtp_factory or default_smtp_factory
        self.resolver = resolver
        self.counter = DailyCallCounter(Path(state_dir) / "connector_email.json",
                                        cfg.max_per_day)

    def notify(self, n: Notification) -> ConnectorResult:
        try:
            user = read_secret(self.cfg.username_env)
            password = read_secret(self.cfg.password_env)
            if user is not None and not self.cfg.starttls:
                raise CredentialsWithoutTls()
            msg = build_message(self.cfg, n)
        except Exception as exc:
            return error_result(exc)
        if not self.counter.take():
            return ConnectorResult(False, "cap_reached")
        try:
            if self.resolver is None:
                address = pin_address(self.cfg.host, self.cfg.port, self.cfg.allow_private)
            else:
                address = pin_address(self.cfg.host, self.cfg.port, self.cfg.allow_private,
                                      self.resolver)
            deadline = _clock() + self.cfg.timeout
            smtp = self.smtp_factory(self.cfg.host, self.cfg.port, self.cfg.timeout,
                                     address=address)

            def step() -> None:
                left = deadline - _clock()
                if left <= 0:
                    raise DeadlineExceeded()
                settimeout = getattr(getattr(smtp, "sock", None), "settimeout", None)
                if callable(settimeout):
                    settimeout(left)

            try:
                step()
                smtp.ehlo()
                if self.cfg.starttls:
                    step()
                    smtp.starttls(context=ssl.create_default_context())
                    step()
                    smtp.ehlo()
                if user is not None:
                    step()
                    smtp.login(user, password)
                step()
                smtp.send_message(msg, from_addr=self.cfg.sender, to_addrs=self.cfg.recipients)
            finally:
                try:
                    smtp.quit()
                except Exception:
                    try:
                        smtp.close()
                    except Exception:  # noqa: S110 - best-effort cleanup
                        pass
        except Exception as exc:
            return error_result(exc)
        return ConnectorResult(True, "sent")
