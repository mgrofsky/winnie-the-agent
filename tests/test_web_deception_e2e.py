"""End to end: a visitor on the dev_portal HTTP trap, its real events, and the triage record.

The visitor reads the app shell, the bundle, /env.js and the OpenAPI document, calls two
hidden routes it found, walks object ids on a lured item route, runs the recovery flows and
sends a marker back. Its events go through ``sessions.parse_log`` and triage with the
shipped indicator and behaviour files. The only change made to the logged lines is the
source address: loopback becomes a documentation address that the test treats as public,
so the blocklist check means something.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import re
from pathlib import Path

import pytest

from listeners import http
from listeners.base import Limits, ListenerContext, ServiceSettings
from listeners.events import EventWriter
from scenarios.loader import load_scenario

SOURCE = "198.51.100.77"
UA = "norma/0.4"
EVIDENCE = ("seq", "req", "lure_id", "discovered_via", "discovered_age", "marker", "flow",
            "flow_step", "object_id_count")
RULES = {"discovered-routes-used", "object-enumeration", "recovery-probing", "marker-reuse"}


async def _request(port: int, method: str, path: str, headers=None, body: bytes = b""):
    lines = [f"{method} {path} HTTP/1.1", "Host: web01", f"User-Agent: {UA}",
             "Connection: close"]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
    await w.drain()
    out = await asyncio.wait_for(r.read(), 5)
    w.close()
    head, _, payload = out.partition(b"\r\n\r\n")
    return int(head.split(b" ", 2)[1]), payload


async def visit(log_path: Path) -> list[dict]:
    """Play the visitor against a real listener writing ``log_path``; the logged lines,
    with the source address replaced by ``SOURCE``."""
    raw = log_path.with_suffix(".raw")
    scen = load_scenario("dev_portal", seed="e2e")
    ctx = ListenerContext(EventWriter(str(raw), sensor_name="e2e"), scenario=scen, seed="e2e",
                          bind_host="127.0.0.1", honeytokens=scen.recognised_tokens(),
                          limits=Limits(rate_per_ip_per_minute=10_000))
    svc = scen.scenario.services.http
    settings = ServiceSettings(name="http", enabled=True, port=0, policy=svc.policy,
                               accounts=scen.accounts_for("http"))
    ctx.settings["http"] = settings
    servers = await http.start(ctx, settings)
    port = servers[0].sockets[0].getsockname()[1]
    js = {"Content-Type": "application/json"}
    domain = scen.scenario.identity.domain
    try:
        _, shell = await _request(port, "GET", "/")
        bundle = re.search(rb'src="(/static/js/[^"]+\.js)"', shell).group(1).decode()
        await _request(port, "GET", bundle)
        _, env = await _request(port, "GET", "/env.js")
        text = env.decode()
        key = json.loads(text[text.index("{"):text.rindex("}") + 1])["publicApiKey"]
        await _request(port, "GET", "/api/openapi.json")
        await _request(port, "GET", "/api/internal/admin/settings")     # hidden, needs bearer
        await _request(port, "GET", "/api/internal/export/users")       # hidden
        for user_id in range(1, 13):                                    # lured item route
            await _request(port, "GET", f"/api/v1/users/{user_id}")
        await _request(port, "POST", "/api/v1/auth/username", js,
                       json.dumps({"username": f"ops@{domain}"}).encode())
        await _request(port, "POST", "/api/v1/auth/forgot-password", js,
                       json.dumps({"email": f"ops@{domain}"}).encode())
        await _request(port, "POST", "/api/v1/auth/reset-password", js,
                       json.dumps({"token": "stale-link", "password": "pw"}).encode())
        await _request(port, "GET", "/api/v1/auth/activate/stale-link")
        await _request(port, "GET", "/api/v1/projects", {"X-Api-Key": key})
        await asyncio.sleep(0.05)
    finally:
        for s in servers:
            s.close()
            await s.wait_closed()
    lines = [json.loads(line) for line in raw.read_text().splitlines()]
    for line in lines:
        if line.get("src_ip") == "127.0.0.1":
            line["src_ip"] = SOURCE
    log_path.write_text("".join(json.dumps(line) + "\n" for line in lines))
    return lines


def triage(tmp_path: Path, log_path: Path, with_sets: bool):
    from agents.behaviours import load_rules
    from agents.indicators import load_indicators
    from agents.triage import load_records, run_triage

    reports = tmp_path / ("found" if with_sets else "plain")
    now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    sets = {"indicators": load_indicators(), "rules": load_rules()} if with_sets else {}
    run_triage(log_path, reports, None, now=now, **sets)
    records = [r for r in load_records(reports) if r.src_ip == SOURCE]
    assert len(records) == 1, [r.src_ip for r in load_records(reports)]
    return records[0], now


@pytest.mark.usefixtures("public_test_net")
def test_visitor_sequence_indicators_and_behaviours(tmp_path):
    from agents import sessions
    from agents.detect import blocklist_rows, record_reasons
    from agents.triage import Judgement

    log_path = tmp_path / "log.jsonl"
    lines = asyncio.run(visit(log_path))
    commands = [line for line in lines if line["event"] == "command"]
    assert len(commands) == 23 and all(line["client"] == UA for line in commands)

    # The parsed campaign keeps every request, in order, with the evidence fields.
    parsed = sessions.parse_log(log_path)
    camp = next(c for c in parsed.campaigns.values() if c.src_ip == SOURCE)
    reqs = camp.requests
    assert [r.seq for r in reqs] == list(range(1, 24))
    assert [r.path for r in reqs[:4]] == ["/", commands[1]["data"]["path"], "/env.js",
                                         "/api/openapi.json"]
    for line, r in zip(commands, reqs):
        data = line["data"]
        assert (r.path, r.status, r.route) == (data["path"], data["status"], data["route"])
        assert (r.lure, r.discovered_via, r.flow, r.marker) == (
            data.get("lure_id", ""), data.get("discovered_via", ""), data.get("flow", ""),
            data.get("marker", ""))
        assert r.object_id_count == data.get("object_id_count")
    assert reqs[1].lure == "main-bundle" and reqs[2].lure == "env-js"
    admin, export = reqs[4], reqs[5]
    assert admin.status == 401 and admin.discovered_via == "main-bundle"
    assert export.status == 200 and export.discovered_via == "main-bundle"
    walk = [r for r in reqs if r.route == "/api/v1/users/{id}"]
    assert [r.object_id_count for r in walk] == list(range(1, 13))
    assert {r.flow for r in reqs if r.flow} == {"username_check", "recovery_request",
                                               "recovery_reset", "activation"}
    assert reqs[-1].marker == "public_api_key" and not reqs[-1].marker_src

    plain, _ = triage(tmp_path, log_path, with_sets=False)
    found, now = triage(tmp_path, log_path, with_sets=True)
    seq = found.request_sequence
    assert [e.seq for e in seq] == list(range(1, 24))
    assert [e.path for e in seq] == [r.path for r in reqs]
    assert seq[5].discovered_via == "main-bundle"

    norma = next(m for m in found.indicator_matches if m.id == "artex-ua-norma")
    assert (norma.framework, norma.confidence) == ("ARTEX", "medium") and norma.count >= 23
    got = {b.id: b for b in found.behaviours}
    assert RULES <= set(got), sorted(got)
    assert got["object-enumeration"].count == 12
    assert got["recovery-probing"].count == 4
    assert got["marker-reuse"].first_seq == got["marker-reuse"].last_seq == 23

    # The matches change nothing else about the record and never reach the blocklist.
    strip = {"indicator_matches", "behaviours", "narrative", "llm_used"}
    assert found.model_dump(exclude=strip) == plain.model_dump(exclude=strip)
    assert found.judgement == plain.judgement and found.high_signal == plain.high_signal
    assert record_reasons(found) == record_reasons(plain)
    assert [row for row in blocklist_rows([found], now=now) if row["ip"] == SOURCE] == []
    # Control: the same record judged suspicious is a blocklist row, so the check bites.
    suspicious = found.model_copy(update={"judgement": Judgement.SUSPICIOUS})
    assert [row["ip"] for row in blocklist_rows([suspicious], now=now)] == [SOURCE]
