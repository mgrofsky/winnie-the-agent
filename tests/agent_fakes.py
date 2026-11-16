"""Shared fakes for tests/test_agents_*.py. No network, no real model."""

from __future__ import annotations

import base64
import datetime
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agents.llm import LLMOutputError

T0 = datetime.datetime(2026, 11, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)


class FakeJsonLLM:
    """Returns scripted outputs. Mirrors AnthropicJsonLLM: invalid output -> LLMOutputError."""

    def __init__(self, *outputs: Any) -> None:
        self.outputs = list(outputs)
        self.calls: list[tuple[str, str, type]] = []

    def complete_json(self, system, user, schema):
        self.calls.append((system, user, schema))
        out = self.outputs.pop(0) if len(self.outputs) > 1 else (self.outputs[0] if self.outputs else {})
        if isinstance(out, Exception):
            raise out
        try:
            return schema.model_validate(out)
        except ValidationError as exc:
            raise LLMOutputError("invalid") from exc


def ts(minutes: float = 0) -> str:
    return (T0 + datetime.timedelta(minutes=minutes)).isoformat(timespec="milliseconds")


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def ssh_session(sid: str, ip: str, commands: list[str], start: float = 0, user: str = "root",
                password: str = "toor", closed: bool = True) -> list[dict]:
    base = {"level": "INFO", "task_name": sid, "src_ip": ip, "src_port": 50000, "dst_ip": "10.0.0.5",
            "dst_port": 22, "sensor_name": "t", "sensor_protocol": "ssh"}
    recs = [dict(base, timestamp=ts(start), message="SSH connection received"),
            dict(base, timestamp=ts(start + 0.1), message="Authentication success",
                 username=user, password=password)]
    m = start + 0.2
    for c in commands:
        recs.append(dict(base, timestamp=ts(m), message="User input", details=b64(c), interactive=True))
        recs.append(dict(base, timestamp=ts(m + 0.05), message="LLM response",
                         details=b64(f"output of {c}\n$ "), interactive=True))
        m += 0.1
    if closed:
        recs.append(dict(base, timestamp=ts(m + 0.1), message="SSH connection closed"))
    return recs


def trap_event(protocol: str, event: str, ip: str, task: str, minutes: float = 0, **fields) -> dict:
    rec = {"timestamp": ts(minutes), "level": "INFO", "task_name": task, "src_ip": ip,
           "src_port": 40000, "dst_ip": "10.0.0.5", "dst_port": 5060, "message": event,
           "sensor_name": "t", "sensor_protocol": protocol, "event": event, "transport": "tcp"}
    rec.update(fields)
    return rec


def write_log(path: Path, records: list, extra_lines: list[str] = ()) -> Path:
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
        for line in extra_lines:
            f.write(line + "\n")
    return path


GOOD_TRIAGE = {
    "intent": "CRYPTOMINING", "stage": "EXECUTION", "skill": "LOW", "judgement": "MALICIOUS",
    "techniques": [{"id": "T1105", "name": "Ingress Tool Transfer"},
                   {"id": "T1496", "name": "Resource Hijacking"}],
    "extra_iocs": [], "narrative": "Downloaded and ran a miner.",
}
