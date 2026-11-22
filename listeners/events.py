"""Shared event model and writer for the low-interaction login traps.

Every listener event is one JSON line in the honeypot log, in the same shape as
``JSONFormatter`` in ``SSH/ssh_server.py`` plus an ``event`` field. All attacker-supplied
values are length-capped and have control characters escaped before they are written.

This module is the contract between ``listeners/`` and ``agents/sessions.py``.
"""

from __future__ import annotations

import datetime
import json
import os
import threading
import uuid
from typing import Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agents.eventlog import open_event_log

MAX_VALUE_CHARS = 512
MAX_DATA_KEYS = 32

Protocol = Literal["sip", "ftp", "telnet", "postgres", "mysql", "redis", "smtp", "http", "mssql",
                   "mllp", "s3"]
EventType = Literal[
    "connection",     # TCP connection accepted or first UDP datagram from a source
    "auth_attempt",   # credentials (or challenge/response material) submitted
    "command",        # any other protocol command or request
    "register",       # SIP REGISTER (with or without Authorization)
    "invite",         # SIP INVITE (dialed number in data.dialed)
    "options",        # SIP OPTIONS
    "limit",          # a hard limit was hit (data.reason)
    "error",          # malformed input; handler recovered (data.reason)
    "close",          # connection closed
    "notice",         # about the decoy itself, not the client (a cut persona reply)
]

DataValue = Union[str, int, bool]


def clean(value: object, cap: int = MAX_VALUE_CHARS) -> str:
    """Escape control characters and cap length. Never raises."""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="backslashreplace")
    else:
        text = str(value)
    out = []
    for ch in text:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif code < 0x20 or code == 0x7F or 0x80 <= code < 0xA0:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
        if len(out) >= cap:
            break
    result = "".join(out)
    return result[:cap]


def new_task_name(protocol: str) -> str:
    return f"{protocol}-{uuid.uuid4()}"


class ListenerEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(
        datetime.timezone.utc).isoformat(sep="T", timespec="milliseconds"))
    level: Literal["INFO", "WARNING"] = "INFO"
    task_name: str
    src_ip: str
    src_port: Union[int, str]
    dst_ip: str = "-"
    dst_port: Union[int, str]
    message: str
    sensor_name: str
    sensor_protocol: Protocol
    event: EventType
    transport: Literal["tcp", "udp"] = "tcp"
    username: Optional[str] = None
    password: Optional[str] = None
    client: Optional[str] = None       # client software string (User-Agent, client attrs)
    success: Optional[bool] = None     # True only for an accepted fake login/registration
    data: dict[str, DataValue] = Field(default_factory=dict)

    @field_validator("task_name", "src_ip", "dst_ip", "message", "sensor_name",
                     "username", "password", "client", mode="before")
    @classmethod
    def _clean_str(cls, v):
        return None if v is None else clean(v)

    @field_validator("data", mode="before")
    @classmethod
    def _clean_data(cls, v):
        if not isinstance(v, dict):
            return {}
        cleaned: dict[str, DataValue] = {}
        for i, (k, val) in enumerate(v.items()):
            if i >= MAX_DATA_KEYS:
                break
            key = clean(k, 64)
            if isinstance(val, bool) or isinstance(val, int):
                cleaned[key] = val
            elif val is None:
                continue
            else:
                cleaned[key] = clean(val)
        return cleaned


class EventWriter:
    """Append ListenerEvents as JSON lines. Thread- and task-safe, never raises."""

    def __init__(self, path: Optional[str], sensor_name: str = "winnie") -> None:
        self.path = path
        self.sensor_name = sensor_name
        self._lock = threading.Lock()
        self.events: list[dict] = []  # in-memory copy for tests when path is None

    def emit(self, **fields) -> Optional[ListenerEvent]:
        fields.setdefault("sensor_name", self.sensor_name)
        try:
            event = ListenerEvent(**fields)
        except Exception:  # noqa: BLE001 - logging must never take a handler down
            return None
        line = event.model_dump_json(exclude_none=True)
        with self._lock:
            if self.path is None:
                self.events.append(json.loads(line))
                return event
            try:
                # O_APPEND keeps whole-line writes from interleaving with the SSH process;
                # a log created here is owner-only, like one the SSH server creates.
                fd = open_event_log(self.path)
                try:
                    os.write(fd, (line + "\n").encode("utf-8"))
                finally:
                    os.close(fd)
            except OSError:
                return None
        return event
