"""The Sigma drafts converted to queries: detections/pipelines/winnie-events.yml with two
published pySigma backends (Elasticsearch Lucene, OpenSearch Lucene). Conversion only: no
search engine runs here. The versions are pinned in pyproject.toml and checked below, so the
table in docs/portable-formats.md stays true."""

from __future__ import annotations

import datetime
from importlib import metadata
from pathlib import Path

import pytest
import yaml

pytest.importorskip("sigma", reason="pySigma (dev dependency) not installed")
elasticsearch = pytest.importorskip("sigma.backends.elasticsearch",
                                    reason="pysigma-backend-elasticsearch not installed")
opensearch = pytest.importorskip("sigma.backends.opensearch",
                                 reason="pysigma-backend-opensearch not installed")

from sigma.collection import SigmaCollection  # noqa: E402
from sigma.exceptions import SigmaTransformationError  # noqa: E402
from sigma.processing.pipeline import ProcessingPipeline  # noqa: E402

from agents.detect import HIGH_SIGNAL_RULES, IOC_RULES, build_drafts  # noqa: E402
from agents.triage import Ioc, TriageRecord  # noqa: E402

PIPELINE = Path(__file__).resolve().parents[1] / "detections" / "pipelines" / "winnie-events.yml"
BACKENDS = {"elasticsearch-lucene": elasticsearch.LuceneBackend,
            "opensearch-lucene": opensearch.OpensearchLuceneBackend}
TESTED_VERSIONS = {"pysigma": "1.5.1", "pysigma-backend-elasticsearch": "2.1.1",
                   "pysigma-backend-opensearch": "2.0.3"}
URL = "http://198.51.100.9/bins/x*y?.sh"


def _record(rid, ip, iocs=(), signals=None, protocol="telnet"):
    return TriageRecord(kind="session", id=rid, protocol=protocol, src_ip=ip,
                        first_seen="2026-11-01T00:00:00+00:00",
                        last_seen="2026-11-01T01:00:00+00:00", commands=2, intent="UNKNOWN",
                        stage="NONE", skill="AUTOMATED", judgement="MALICIOUS", narrative="x",
                        high_signal=signals or {}, iocs=[Ioc(type=t, value=v) for t, v in iocs])


def every_draft() -> dict[str, str]:
    """{kind: YAML} for every kind of draft the detect agent writes."""
    iocs = [("url", URL), ("domain", "update-cdn.example"),
            ("ssh_pubkey", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey0123 op*?\\x")]
    signals = {name: 1 for name in HIGH_SIGNAL_RULES}
    records = [_record(f"r{i}", f"198.51.100.{20 + i}", iocs, signals) for i in range(2)]
    drafts = build_drafts(records, day=datetime.date(2026, 11, 2))
    out = {d.kind: yaml.safe_dump(d.rule, sort_keys=False) for d in drafts}
    expected = {kind for kind, _, _ in IOC_RULES.values()} | \
        {"signal-" + n.replace("_", "-") for n in HIGH_SIGNAL_RULES}
    assert set(out) == expected
    return out


def convert(backend: str, text: str, pipeline: bool = True) -> list[str]:
    # A fresh pipeline and collection each time: conversion changes the parsed rule.
    pipe = ProcessingPipeline.from_yaml(PIPELINE.read_text()) if pipeline else ProcessingPipeline()
    return BACKENDS[backend](pipe).convert(SigmaCollection.from_yaml(text))


def test_tested_versions_are_the_installed_ones():
    for name, version in TESTED_VERSIONS.items():
        assert metadata.version(name) == version, name


@pytest.mark.parametrize("backend", sorted(BACKENDS))
def test_every_rule_kind_converts_or_is_refused_with_a_reason(backend):
    for kind, text in every_draft().items():
        if kind == "ioc-domain":
            with pytest.raises(SigmaTransformationError, match="records no DNS queries"):
                convert(backend, text)
            # Without the Winnie pipeline the backend converts it for a DNS log.
            assert convert(backend, text, pipeline=False) == [
                "dns.question.name:update\\-cdn.example"]
            continue
        (query,) = convert(backend, text)
        assert query and "CommandLine" not in query and "Relay" not in query, (kind, query)


@pytest.mark.parametrize("backend", sorted(BACKENDS))
def test_golden_queries(backend):
    drafts = every_draft()
    assert convert(backend, drafts["ioc-url"]) == [
        "(sensor_protocol:telnet AND event:command) AND "
        "data.input:*http\\:\\/\\/198.51.100.9\\/bins\\/x\\*y\\?.sh*"]
    assert convert(backend, drafts["signal-redis-takeover"]) == [
        "(sensor_protocol:redis AND event:command) AND (*CONFIG\\ SET\\ dir* OR "
        "*CONFIG\\ SET\\ dbfilename* OR *SLAVEOF* OR *REPLICAOF* OR *MODULE\\ LOAD*)"]
    assert convert(backend, drafts["signal-smtp-relay-attempt"]) == [
        "(sensor_protocol:smtp AND event:command) AND *SMTP\\ relay\\ attempt*"]
    assert convert(backend, drafts["signal-sql-exec-attempt"]) == [
        "((sensor_protocol:(postgres OR mysql OR mssql)) AND event:command) AND "
        "(*COPY* OR *PROGRAM* OR *INTO\\ OUTFILE* OR *LOAD_FILE* OR *xp_cmdshell* OR "
        "*sys_exec*)"]


def test_attacker_wildcards_stay_literal_in_the_query():
    # The URL's * and ? arrive escaped in the Lucene query: only the two wildcards that
    # |contains adds are left unescaped.
    (query,) = convert("opensearch-lucene", every_draft()["ioc-url"])
    value = query.split("data.input:", 1)[1]
    assert value.startswith("*") and value.endswith("*")
    inner = value[1:-1]
    assert "\\*" in inner and "\\?" in inner
    assert inner.replace("\\*", "").replace("\\?", "").count("*") == 0


def test_the_pipeline_names_only_fields_winnie_writes():
    from listeners.events import ListenerEvent

    doc = yaml.safe_load(PIPELINE.read_text())
    fields = set()
    for t in doc["transformations"]:
        fields.update(t.get("mapping", {}).values() if t["type"] == "field_name_mapping" else ())
        fields.update(t.get("conditions", {}) if t["type"] == "add_condition" else ())
    top = {f for f in fields if "." not in f}
    assert top <= set(ListenerEvent.model_fields)
    assert fields - top == {"data.input"}
    # The values the pipeline relies on are the ones the front-ends write.
    root = Path(__file__).resolve().parents[1] / "listeners"
    assert 'data={"input": line' in (root / "telnet.py").read_text()
    assert '"SMTP relay attempt"' in (root / "smtp.py").read_text()
    assert '"input": " ".join(args)' in (root / "redis.py").read_text()
