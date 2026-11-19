"""One fixed object in an S3 or S3-compatible store: put it, or get it, and nothing else.

Used by the tracked export (PutObject of one key) and the sightings fetch (GetObject of one
key). Each use builds its own client with ``ship.s3_client`` and a guard that refuses, before
any request is sent, every operation but the one it was built for and any bucket or key but
the configured ones. That includes the ``HeadBucket`` the S3 region redirect can issue on
its own.

``endpoint_url`` points the client at another store that speaks the S3 API (other clouds'
interoperability endpoints, self-hosted stores). It must be ``https``; a private or loopback
address literal needs ``allow_private``. Unlike the HTTP connectors, the S3 client
resolves the name itself: only a literal address (and ``localhost``) is checked, when the
configuration is loaded; a host name is not resolved or pinned, so point it only at a
name you control. Credentials come from the default chain (instance role, environment or the shared
credentials file), never from config.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from agents.connectors.base import DestinationError, validate_destination
from agents.ship import _BUCKET_RE, _OWNER_RE, _REGION_RE, OperationRefused, s3_client

_KEY_RE = re.compile(r"^[A-Za-z0-9!_.*'()/=-]{1,1024}$")
# With endpoint_url, region names are the store's own ("auto", "garage", ...).
_ANY_REGION_RE = re.compile(r"^[A-Za-z0-9-]{1,32}$")
MAX_TIMEOUT = 30.0
DEFAULT_TIMEOUT = 10.0


class ConfigError(ValueError):
    """Load-time problem. Messages never include configured values."""


@dataclass(frozen=True)
class S3Target:
    bucket: str
    key: str
    region: Optional[str] = None
    bucket_owner: Optional[str] = None
    endpoint_url: Optional[str] = None
    timeout: float = DEFAULT_TIMEOUT

    @classmethod
    def validate(cls, bucket: str, key: str, region: str = "", bucket_owner: str = "",
                 endpoint_url: str = "", timeout: str = "", allow_private: str = "") -> "S3Target":
        """Build from raw config strings. Raises ConfigError."""
        bucket, key = (bucket or "").strip(), (key or "").strip()
        if not _BUCKET_RE.fullmatch(bucket) or ".." in bucket:
            raise ConfigError("bucket is missing or not a valid bucket name")
        if not _KEY_RE.fullmatch(key) or key.startswith("/") or key.endswith("/") \
                or ".." in key or "//" in key:
            raise ConfigError("key is missing or contains characters outside the allowed set")
        endpoint = (endpoint_url or "").strip() or None
        private = (allow_private or "").strip().lower() in ("1", "true", "yes", "on")
        if endpoint is not None:
            try:
                validate_destination(endpoint, private)
            except DestinationError as exc:
                raise ConfigError(f"endpoint_url: {exc}") from None
            if "?" in endpoint or "#" in endpoint:
                raise ConfigError("endpoint_url may not carry a query or fragment")
        region = (region or "").strip() or None
        pattern = _ANY_REGION_RE if endpoint else _REGION_RE
        if region is not None and not pattern.fullmatch(region):
            raise ConfigError("region is not a valid region name")
        owner = (bucket_owner or "").strip() or None
        if owner is not None and not _OWNER_RE.fullmatch(owner):
            raise ConfigError("bucket_owner must be a 12-digit account id")
        try:
            seconds = float((timeout or "").strip() or DEFAULT_TIMEOUT)
        except ValueError:
            raise ConfigError("timeout must be a number") from None
        if not 0 < seconds <= MAX_TIMEOUT:
            raise ConfigError(f"timeout must be above 0 and at most {MAX_TIMEOUT:g}")
        return cls(bucket=bucket, key=key, region=region, bucket_owner=owner,
                   endpoint_url=endpoint, timeout=seconds)


class OneObjectGuard:
    """Client hooks: only ``operation``, only on ``bucket`` / ``key``. Raises
    ``OperationRefused`` before a request is built or sent."""

    def __init__(self, operation: str, bucket: str, key: str) -> None:
        self.operation, self.bucket, self.key = operation, bucket, key

    def before_call(self, model=None, **_kwargs) -> None:
        name = getattr(model, "name", None)
        if name != self.operation:
            raise OperationRefused(f"S3 operation {str(name)[:40]} is not allowed")

    def before_parameters(self, params=None, model=None, **_kwargs) -> None:
        self.before_call(model=model)
        params = params if isinstance(params, dict) else {}
        if params.get("Bucket") != self.bucket or params.get("Key") != self.key:
            raise OperationRefused("S3 bucket or key outside the configured object")

    def hooks(self) -> tuple:
        return (("before-parameter-build.s3", self.before_parameters),
                ("before-call.s3", self.before_call))


def guarded_client_factory(operation: str) -> Callable[[S3Target], object]:
    """A factory for clients that can only run ``operation`` on the target's one object."""

    def factory(target: S3Target, session=None):
        guard = OneObjectGuard(operation, target.bucket, target.key)
        return s3_client(target.region, target.timeout, guard.hooks(),
                         endpoint_url=target.endpoint_url, session=session)

    return factory


def error_code(exc: Exception) -> str:
    """The exception type and, for service errors, the error code; never the message."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if code:
            return f"{type(exc).__name__}: {str(code)[:64]}"
    return type(exc).__name__


def put_object(target: S3Target, body: bytes, factory=None) -> None:
    """PutObject of ``body`` to the target. Raises on failure."""
    client = (factory or guarded_client_factory("PutObject"))(target)
    params = {"Bucket": target.bucket, "Key": target.key, "Body": body,
              "ContentType": "application/json"}
    if target.bucket_owner:
        params["ExpectedBucketOwner"] = target.bucket_owner
    client.put_object(**params)


class ObjectTooLarge(Exception):
    pass


def get_object(target: S3Target, max_bytes: int, factory=None) -> bytes:
    """GetObject of the target, at most ``max_bytes``. Raises on failure or when larger."""
    client = (factory or guarded_client_factory("GetObject"))(target)
    params = {"Bucket": target.bucket, "Key": target.key}
    if target.bucket_owner:
        params["ExpectedBucketOwner"] = target.bucket_owner
    resp = client.get_object(**params)
    length = resp.get("ContentLength")
    body = resp.get("Body")
    try:
        if isinstance(length, int) and length > max_bytes:
            raise ObjectTooLarge()
        data = body.read(max_bytes + 1)
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    if len(data) > max_bytes:
        raise ObjectTooLarge()
    return data
