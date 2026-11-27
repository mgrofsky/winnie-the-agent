"""Scenario packs: validation, synthetic-data rules, describe output, determinism."""

from __future__ import annotations

import re

import pytest

from scenarios.check import check_scenario, check_text, luhn_valid
from scenarios.describe import describe, list_text
from scenarios.loader import list_scenarios, load_scenario
from scenarios.schema import Scenario

SHIPPED = ["api_platform", "bank", "contact_center", "healthcare", "saas", "sip_provider", "dev_portal"]


def test_all_expected_scenarios_ship():
    assert set(SHIPPED) <= set(list_scenarios())


@pytest.mark.parametrize("name", SHIPPED)
def test_scenario_validates_and_loads(name):
    loaded = load_scenario(name, seed="sensor-a")
    sc = loaded.scenario
    assert sc.name == name
    assert 3 <= len(loaded.honeytokens) <= 5
    # every template was expanded, and the expanded pack validates on its own
    assert "{{" not in sc.model_dump_json()
    Scenario.model_validate(sc.model_dump())
    # every honeytoken value actually appears somewhere in the fake data
    blob = sc.model_dump_json()
    for db_svc in ("postgres", "mysql"):
        svc = getattr(sc.services, db_svc)
        if svc:
            for db in svc.databases:
                for t in db.tables:
                    blob += repr(loaded.table_rows(db.name, t.name)[1])
    for tok in loaded.honeytokens.values():
        assert tok.value in blob, f"{name}: honeytoken {tok.name} not planted"
    # realistic high-port defaults; MSSQL only where the target plausibly runs it
    ports = {"sip": 5060, "ftp": 2121, "telnet": 2323, "postgres": 5432, "mysql": 3306,
             "redis": 6379, "smtp": 2525, "http": 8080, "mllp": 2575}
    for svc_name, port in ports.items():
        svc = getattr(sc.services, svc_name)
        if svc is not None and svc.enabled:
            assert svc.port == port
            if svc_name != "mllp":
                p = svc.policy
                assert p.accept == "after_n" and 2 <= p.after_n_min <= p.after_n_max <= 6
    mssql_on = sc.services.mssql is not None and sc.services.mssql.enabled
    assert mssql_on == (name == "contact_center")
    if mssql_on:
        assert sc.services.mssql.port == 1433


@pytest.mark.parametrize("name", SHIPPED)
@pytest.mark.parametrize("seed", ["sensor-a", "sensor-b", "check", "x9"])
def test_checker_reports_no_problems(name, seed):
    assert check_scenario(load_scenario(name, seed=seed)) == []


def test_luhn_helper():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


@pytest.mark.parametrize("text,needle", [
    ("card 4111111111111111 on file", "Luhn"),
    ("card 4111 1111 " + "1111 1111 on file", "Luhn"),
    ("iban GB82WEST12345698765432", "IBAN"),
    ("mail ops@" + "bigcorp" + ".com", "email"),
    ("call +1 312 867 5309", "phone"),
    ("call (312) 867-5309", "phone"),
    ("ssn 123-45-6789", "SSN"),
    ("key " + "AKIA" + "IOSFODNN7EXAMPLE", "AWS"),
    ("customer of Wells Fargo", "organisation"),
    ("peer at " + ".".join(["8"] * 4), "public IP"),
])
def test_checker_flags_bad_values(text, needle):
    problems = check_text(text, "acme.example")
    assert any(needle in p for p in problems), problems


@pytest.mark.parametrize("text", [
    "card 0000123456789012",            # failing Luhn
    "call +1 312 555 0142 or (617) 555-0199",
    "uk drama 01632 960123 / 07700 900456",
    "a@example.com b@x.example c@host.acme.example d@foo.test",
    "ssn 900-12-3456 666-12-3456",
    "10.1.2.3 192.168.0.1 203.0.113.9 127.0.0.1",
    "XX001234567890123456789012",
    "MSH|20261114083015|",
])
def test_checker_accepts_synthetic_values(text):
    assert check_text(text, "acme.example") == []


def test_checker_flags_hand_made_bad_scenario():
    loaded = load_scenario("bank", seed="bad")
    sc = loaded.scenario
    # Bad values are assembled at runtime so the source itself holds none of them.
    domain = "realbank" + ".com"
    sc.identity.domain = domain
    sc.services.ftp.files[0].content = (
        f"card {'4111' + '1' * 12} for treasury@{domain} via {'.'.join(['8', '8', '4', '4'])} "
        "(Bank of America)")
    problems = "\n".join(check_scenario(loaded))
    for needle in ("identity.domain", "Luhn", "email", "public IP", "organisation"):
        assert needle in problems, needle


@pytest.mark.parametrize("name", SHIPPED)
def test_describe_lists_services_but_no_honeytoken_values(name):
    text = describe(name, seed="sensor-a")
    loaded = load_scenario(name, seed="sensor-a")
    sc = loaded.scenario
    for svc_name in ("sip", "ftp", "telnet", "postgres", "mysql", "redis", "smtp", "http",
                     "mllp"):
        svc = getattr(sc.services, svc_name)
        if svc is not None and svc.enabled:
            assert f"Service {svc_name}: enabled, port {svc.port}" in text
    assert sc.identity.org_name in text
    for tok in loaded.honeytokens.values():
        assert tok.name in text
        assert tok.value not in text


def test_describe_specifics():
    sip = describe("sip_provider")
    assert "extension 1001 (Reception)" in sip
    assert "table cdr:" in sip and "database asteriskcdrdb" in sip
    assert "/backups/etc-asterisk/pjsip.conf" in sip
    api = describe("api_platform")
    header = load_scenario("api_platform", seed="describe").scenario.services.http.api_key_header
    assert "OpenAPI document: /openapi.json" in api and f"API key header {header}" in api
    assert re.fullmatch(r"X-[A-Za-z0-9]+-Key", header)
    hc = describe("healthcare")
    assert "Service mllp: enabled, port 2575" in hc and "/fhir/Patient/{id}" in hc


def test_list_text_names_every_scenario():
    text = list_text()
    for name in SHIPPED:
        assert name in text
    assert "INVALID" not in text


@pytest.mark.parametrize("name", SHIPPED)
def test_honeytokens_deterministic_per_seed(name):
    a1 = load_scenario(name, seed="sensor-a").honeytokens
    a2 = load_scenario(name, seed="sensor-a").honeytokens
    b = load_scenario(name, seed="sensor-b").honeytokens
    assert {k: v.value for k, v in a1.items()} == {k: v.value for k, v in a2.items()}
    for k in a1:
        assert a1[k].value != b[k].value


@pytest.mark.parametrize("name", SHIPPED)
def test_tables_generate_deterministically(name):
    a = load_scenario(name, seed="sensor-a")
    a2 = load_scenario(name, seed="sensor-a")
    b = load_scenario(name, seed="sensor-b")
    sc = a.scenario
    generated = 0
    differs = False
    for svc_name in ("postgres", "mysql"):
        svc = getattr(sc.services, svc_name)
        if svc is None:
            continue
        for db in svc.databases:
            for t in db.tables:
                cols, rows = a.table_rows(db.name, t.name)
                assert cols == [c.name for c in t.columns]
                assert (cols, rows) == a2.table_rows(db.name, t.name)
                if t.generator and t.generator.count:
                    generated += 1
                    assert len(rows) == len(t.seed_rows) + t.generator.count
                    if rows != b.table_rows(db.name, t.name)[1]:
                        differs = True
    assert generated >= 1
    assert differs


# ---- HTTP web-deception keys ----------------------------------------------------------------

def _http(**over):
    from scenarios.schema import HttpService

    base = {"enabled": True, "port": 8080, "api_prefix": "/api", "openapi_path": "/api/openapi.json",
            "routes": [{"path": "/api/v1/items/{id}", "item_from": "db.items", "item_key": "id"},
                       {"method": "POST", "path": "/api/v1/forgot", "auth": "none",
                        "flow": "recovery_request"}]}
    base.update(over)
    return HttpService.model_validate(base)


def test_http_deception_keys_validate():
    svc = _http(assets=[{"path": "/static/app.js", "kind": "bundle", "lure": "app-js",
                         "advertises": ["/api/v1/items/{id}"]},
                        {"path": "/env.js", "kind": "runtime_config", "lure": "env",
                         "body": 'window.__ENV__ = {"k": "{marker:client_id}"};'}],
                openapi_aliases=["/swagger.json"], openapi_advertises=["/api/v1/forgot"])
    assert svc.marker_names() == {"client_id"}


@pytest.mark.parametrize("over,needle", [
    ({"assets": [{"path": "/api/openapi.json", "kind": "bundle", "lure": "x"}]}, "already"),
    ({"assets": [{"path": "/a.js", "kind": "bundle", "lure": "x", "advertises": ["/nope"]}]},
     "not a route"),
    ({"assets": [{"path": "/a/{id}.js", "kind": "bundle", "lure": "x"}]}, "pattern"),
    ({"assets": [{"path": "/a.css", "kind": "static", "lure": "x"}]}, "needs a body"),
    ({"assets": [{"path": "/a.js", "kind": "bundle", "lure": "Bad Lure"}]}, "pattern"),
    ({"openapi_advertises": ["/api/v1/other"]}, "not a route"),
    ({"openapi_aliases": ["/api/v1/forgot"]}, "already"),
    ({"openapi_path": None, "openapi_aliases": ["/swagger.json"]}, "need openapi_path"),
    ({"routes": [{"path": "/r", "flow": "activation", "json_body": {"a": 1}}]}, "flow route"),
    ({"routes": [{"path": "/r", "flow": "login"}]}, "flow"),
    ({"assets": [{"path": "/e.js", "kind": "runtime_config", "lure": "e",
                  "body": " ".join(f"{{marker:m{i}}}" for i in range(17))}]}, "marker names"),
])
def test_http_deception_keys_refused(over, needle):
    with pytest.raises(ValueError, match=needle):
        _http(**over)


def test_dev_portal_assets_are_checked_and_clean():
    from scenarios.web_assets import scenario_asset_texts

    loaded = load_scenario("dev_portal", seed="sensor-a")
    texts = dict(scenario_asset_texts(loaded))
    assert len(texts) == 4 and all(texts.values())
    assert check_scenario(loaded) == []
