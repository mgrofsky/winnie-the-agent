"""HTTP plumbing shared by the HTTP connectors.

``UrlTransport`` is the default ``Transport``: ``http.client`` over TLS, https only, no
redirects, no proxies, a socket timeout on every operation plus one overall deadline per
call (``timeout`` seconds from start to the last body byte, so a server that drips bytes
cannot hold a call open), a 64 KB response cap and no retries. It
connects to the address pinned by ``pin_address`` and never resolves the host name itself;
the host name is used for SNI, certificate verification (default SSL context) and the
``Host`` header.

``HttpEndpoint`` holds one connector's validated settings and performs a single call with
the shared rules applied in order: secret lookup, daily cap, resolve and pin a validated
address, request to that address. Every failure becomes a ``ConnectorResult``; nothing
raises out of ``perform``.
"""

from __future__ import annotations

import http.client
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

from agents.llm import DailyCallCounter

from .base import ConnectorResult, Transport, pin_address, validate_destination

MAX_RESPONSE_BYTES = 64 * 1024
DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 30.0
DEFAULT_MAX_PER_DAY = 200
USER_AGENT = "winnie-connector/1"

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")


class ResponseTooLarge(Exception):
    pass


class DeadlineExceeded(TimeoutError):
    """The whole call took longer than its timeout."""


class SecretMissing(Exception):
    pass


class InvalidSecret(Exception):
    pass


class ConfigError(ValueError):
    """Load-time problem. Messages never include configured values."""


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection to a fixed, already validated IP address.

    ``host`` stays the configured host name, so ``http.client`` sends it in the ``Host``
    header and the TLS handshake uses it for SNI and certificate hostname checks. Only the
    TCP connect goes to ``address``; no DNS lookup of ``host`` happens here, which closes
    the window between the address check and the connect (DNS rebinding).
    """

    def __init__(self, host: str, port: int, address: str, *, timeout: float,
                 context: ssl.SSLContext, create_connection=socket.create_connection) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self.pinned_address = address
        self._create_connection = create_connection
        self._tls_context = context

    def connect(self) -> None:
        sock = self._create_connection((self.pinned_address, self.port), self.timeout)
        try:
            self.sock = self._tls_context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def default_connection_factory(host: str, port: int, address: str, timeout: float,
                               context: ssl.SSLContext):
    return PinnedHTTPSConnection(host, port, address, timeout=timeout, context=context)


class UrlTransport:
    """Default transport. ``connection_factory`` exists so tests can swap the network
    layer; it is called as ``factory(host, port, address, timeout, context)`` and returns
    an object with ``request``, ``getresponse`` and ``close`` like ``HTTPSConnection``.

    ``http.client`` neither follows redirects nor reads proxy settings, so a 3xx comes
    back as a plain status code and proxy environment variables have no effect."""

    READ_CHUNK = 8192

    def __init__(self, connection_factory=None, context_factory=ssl.create_default_context,
                 clock=time.monotonic) -> None:
        self._factory = connection_factory or default_connection_factory
        self._context_factory = context_factory
        self._clock = clock

    def request(self, method: str, url: str, headers: dict[str, str], body: Optional[bytes],
                timeout: float, address: str) -> tuple[int, bytes]:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise ValueError("https only")
        host = parts.hostname
        if not host:
            raise ValueError("no host")
        port = parts.port or 443
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        deadline = self._clock() + timeout

        def remaining() -> float:
            left = deadline - self._clock()
            if left <= 0:
                raise DeadlineExceeded()
            settimeout = getattr(getattr(conn, "sock", None), "settimeout", None)
            if callable(settimeout):
                settimeout(left)
            return left

        context = self._context_factory()
        conn = self._factory(host, port, address, timeout, context)
        try:
            conn.request(method, target, body=body, headers=headers)
            remaining()
            resp = conn.getresponse()
            status = int(resp.status)
            chunks: list[bytes] = []
            size = 0
            while size <= MAX_RESPONSE_BYTES:
                remaining()
                chunk = resp.read(min(self.READ_CHUNK, MAX_RESPONSE_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            remaining()
            data = b"".join(chunks)
        finally:
            conn.close()
        if status >= 300:
            return status, data[:MAX_RESPONSE_BYTES]
        if len(data) > MAX_RESPONSE_BYTES:
            raise ResponseTooLarge()
        return status, data


@dataclass
class EndpointConfig:
    name: str
    url: str
    secret_env: Optional[str]
    header: str
    max_per_day: int
    timeout: float
    allow_private: bool


def parse_limits(section, name: str) -> tuple[int, float, bool]:
    """Shared ``max_per_day``, ``timeout`` and ``allow_private`` parsing."""
    try:
        max_per_day = int(section.get("max_per_day", str(DEFAULT_MAX_PER_DAY)))
    except ValueError:
        raise ConfigError("max_per_day must be an integer") from None
    if max_per_day < 0:
        raise ConfigError("max_per_day must be >= 0")
    try:
        timeout = float(section.get("timeout", str(DEFAULT_TIMEOUT)))
    except ValueError:
        raise ConfigError("timeout must be a number") from None
    if not 0 < timeout <= MAX_TIMEOUT:
        raise ConfigError(f"timeout must be > 0 and <= {int(MAX_TIMEOUT)} seconds")
    try:
        allow_private = section.getboolean("allow_private", fallback=False)
    except ValueError:
        raise ConfigError("allow_private must be true or false") from None
    return max_per_day, timeout, allow_private


def parse_env_name(section, key: str) -> Optional[str]:
    value = (section.get(key, "") or "").strip()
    if not value:
        return None
    if not _ENV_NAME.match(value):
        # Do not echo the value: a secret pasted here by mistake must not reach logs.
        raise ConfigError(f"{key} must be an environment variable name")
    return value


def load_endpoint(section, name: str, url: Optional[str] = None) -> EndpointConfig:
    """Parse and validate an HTTP connector section. ``url`` overrides the configured
    one for validation (used for templated URLs)."""
    raw_url = (section.get("url", "") or "").strip()
    if not raw_url:
        raise ConfigError("url is required")
    max_per_day, timeout, allow_private = parse_limits(section, name)
    validate_destination(url if url is not None else raw_url, allow_private)
    header = (section.get("header", "Authorization") or "Authorization").strip()
    if not _HEADER_NAME.match(header):
        raise ConfigError("header must be a plain header name")
    return EndpointConfig(name=name, url=raw_url, secret_env=parse_env_name(section, "secret_env"),
                          header=header, max_per_day=max_per_day, timeout=timeout,
                          allow_private=allow_private)


def read_secret(env_name: Optional[str]) -> Optional[str]:
    if env_name is None:
        return None
    value = os.environ.get(env_name, "")
    if not value:
        raise SecretMissing()
    if any(c in value for c in "\r\n\x00"):
        raise InvalidSecret()
    return value


_ERROR_NAMES = {SecretMissing: "secret_missing", InvalidSecret: "invalid_secret"}


def error_result(exc: BaseException) -> ConnectorResult:
    """Only the exception type is reported; messages can carry header values."""
    name = _ERROR_NAMES.get(type(exc), type(exc).__name__)
    return ConnectorResult(False, f"error: {name}")


class HttpEndpoint:
    def __init__(self, cfg: EndpointConfig, state_dir: Path, transport: Transport,
                 resolver=None) -> None:
        self.cfg = cfg
        self.transport = transport
        self.resolver = resolver
        self.counter = DailyCallCounter(Path(state_dir) / f"connector_{cfg.name}.json",
                                        cfg.max_per_day)

    def _auth_headers(self) -> dict[str, str]:
        secret = read_secret(self.cfg.secret_env)
        if secret is None:
            return {}
        if self.cfg.header.lower() == "authorization":
            return {"Authorization": f"Bearer {secret}"}
        return {self.cfg.header: secret}

    def perform(self, method: str, url: str, body: Optional[bytes] = None,
                on_body: Optional[Callable[[bytes], ConnectorResult]] = None) -> ConnectorResult:
        try:
            headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
            headers.update(self._auth_headers())
            if body is not None:
                headers["Content-Type"] = "application/json"
        except Exception as exc:
            return error_result(exc)
        if not self.counter.take():
            return ConnectorResult(False, "cap_reached")
        try:
            parts = urlsplit(url)
            host = parts.hostname or ""
            port = parts.port or 443
            if self.resolver is None:
                address = pin_address(host, port, self.cfg.allow_private)
            else:
                address = pin_address(host, port, self.cfg.allow_private, self.resolver)
            status, data = self.transport.request(method, url, headers, body, self.cfg.timeout,
                                                  address)
            status = int(status)
        except Exception as exc:
            return error_result(exc)
        if 300 <= status < 400:
            return ConnectorResult(False, f"error: redirect_{status}")
        if not 200 <= status < 300:
            return ConnectorResult(False, f"error: http_{status}")
        if data is not None and len(data) > MAX_RESPONSE_BYTES:
            return ConnectorResult(False, "error: response_too_large")
        if on_body is not None:
            try:
                return on_body(data or b"")
            except Exception as exc:
                return error_result(exc)
        return ConnectorResult(True, "sent")
