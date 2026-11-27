import datetime
from configparser import ConfigParser

import pytest
from pydantic import ValidationError

from agents.behaviours import RuleFile, RuleSet, from_config, load_rules
from agents.sessions import HttpRequest

T0 = datetime.datetime(2026, 11, 1, 12, 0, tzinfo=datetime.timezone.utc)


def req(i, path="/x", seconds=None, **kw):
    kw.setdefault("method", "GET")
    return HttpRequest(ts=T0 + datetime.timedelta(seconds=i if seconds is None else seconds),
                       conn="c1", path=path, seq=i, **kw)


def rules(*items):
    return RuleSet(RuleFile.model_validate({"rules": list(items)}).rules)


def rule(kind, **kw):
    return {"id": f"r-{kind.replace('_', '-')}", "kind": kind, "label": "agentic reconnaissance",
            "confidence": "medium", **kw}


def ids(found):
    return [b.id for b in found]


@pytest.mark.parametrize("bad", [
    {"kind": "rate"},
    {"kind": "object_enumeration", "min_ids": 1},
    {"kind": "object_enumeration"},
    {"kind": "object_enumeration", "min_ids": 3, "extra": 1},
    {"kind": "recovery_probing", "min_steps": 1, "min_flows": 5},
    {"kind": "adaptive_retries", "min_requests": 5, "window_seconds": 0, "min_client_errors": 1,
     "min_changes": 1},
    {"kind": "marker_reuse", "id": "Bad Id"},
    {"kind": "marker_reuse", "confidence": "sure"},
])
def test_schema_refuses(bad):
    with pytest.raises(ValidationError):
        RuleFile.model_validate({"rules": [{**rule("marker_reuse"), **bad}]})


def test_discovery_then_use_at_and_below_threshold():
    rs = rules(rule("discovery_then_use", min_routes=2, within_seconds=600))
    used = [req(1, "/api/a", discovered_via="bundle", discovered_age=30),
            req(2, "/api/a", discovered_via="bundle", discovered_age=40),
            req(3, "/api/b", discovered_via="openapi", discovered_age=600)]
    found = rs.evaluate(used)
    assert ids(found) == ["r-discovery-then-use"]
    assert (found[0].count, found[0].first_seq, found[0].last_seq) == (2, 1, 3)
    late = used[:2] + [req(3, "/api/b", discovered_via="openapi", discovered_age=601)]
    assert rs.evaluate(late) == []
    no_stamp = [req(1, "/api/a"), req(2, "/api/b")]
    assert rs.evaluate(no_stamp) == []


def _retry_run(n_err, n_change, total, spread):
    out = []
    for i in range(total):
        status = 404 if i < n_err else 200
        # The first n_change errors are followed by a different path; the rest repeat it.
        path = f"/p{i}" if i <= n_change else f"/p{n_change}"
        out.append(req(i, path, seconds=i * spread / max(1, total - 1), status=status,
                       host="h.example"))
    return out


def test_adaptive_retries_at_and_below_threshold():
    rs = rules(rule("adaptive_retries", min_requests=10, window_seconds=60,
                    min_client_errors=5, min_changes=3))
    assert ids(rs.evaluate(_retry_run(5, 3, 10, 50))) == ["r-adaptive-retries"]
    assert rs.evaluate(_retry_run(4, 3, 10, 50)) == []            # too few errors
    assert rs.evaluate(_retry_run(5, 2, 10, 50)) == []            # too few changes
    assert rs.evaluate(_retry_run(5, 3, 9, 50)) == []             # too few requests
    assert rs.evaluate(_retry_run(5, 3, 10, 120)) == []           # spread past the window


def test_adaptive_retries_counts_only_changes_on_the_same_host():
    rs = rules(rule("adaptive_retries", min_requests=2, window_seconds=60,
                    min_client_errors=1, min_changes=1))
    same = [req(0, "/a", status=404, host="h"), req(1, "/b", status=200, host="h")]
    other = [req(0, "/a", status=404, host="h"), req(1, "/b", status=200, host="g")]
    method = [req(0, "/a", status=405, host="h"),
              req(1, "/a", status=200, host="h", method="POST")]
    assert ids(rs.evaluate(same)) == ids(rs.evaluate(method)) == ["r-adaptive-retries"]
    assert rs.evaluate(other) == []


def test_adaptive_retries_is_linear_on_a_full_sequence():
    rs = rules(rule("adaptive_retries", min_requests=300, window_seconds=86_400,
                    min_client_errors=150, min_changes=100))
    run = [req(i, f"/p{i}", status=404 if i % 2 else 200, host="h") for i in range(300)]
    assert ids(rs.evaluate(run)) == ["r-adaptive-retries"]


def test_object_enumeration_at_and_below_threshold():
    rs = rules(rule("object_enumeration", min_ids=10))
    walk = [req(i, f"/api/items/{i}", route="/api/items/{id}", object_id_count=i + 1)
            for i in range(10)]
    found = rs.evaluate(walk)
    assert ids(found) == ["r-object-enumeration"] and found[0].count == 10
    assert rs.evaluate(walk[:9]) == []


def test_recovery_probing_at_and_below_threshold():
    rs = rules(rule("recovery_probing", min_steps=3, min_flows=2))
    probe = [req(1, "/u", flow="username_check"), req(2, "/r", flow="recovery_request"),
             req(3, "/r", flow="recovery_request")]
    assert ids(rs.evaluate(probe)) == ["r-recovery-probing"]
    assert rs.evaluate(probe[:2]) == []
    one_kind = [req(i, "/r", flow="recovery_request") for i in range(5)]
    assert rs.evaluate(one_kind) == []


def test_marker_reuse_and_other_source_only():
    own = [req(1, "/a", marker="build")]
    other = [req(1, "/a", marker="build", marker_src=True)]
    assert ids(rules(rule("marker_reuse")).evaluate(own)) == ["r-marker-reuse"]
    strict = rules(rule("marker_reuse", other_source_only=True))
    assert strict.evaluate(own) == [] and ids(strict.evaluate(other)) == ["r-marker-reuse"]
    assert rules(rule("marker_reuse")).evaluate([req(1, "/a")]) == []


def test_disabled_rules_and_missing_seq():
    rs = rules({**rule("marker_reuse"), "enabled": False})
    assert rs.evaluate([req(1, "/a", marker="m")]) == []
    found = rules(rule("marker_reuse")).evaluate(
        [HttpRequest(ts=T0, conn="c", path="/a", marker="m")])
    assert (found[0].first_seq, found[0].last_seq) == (None, None)


def test_shipped_rules_load_and_name_agentic_reconnaissance():
    rs = load_rules()
    assert rs.errors == []
    assert {r.kind for r in rs.rules} == {"discovery_then_use", "adaptive_retries",
                                         "object_enumeration", "recovery_probing",
                                         "marker_reuse"}
    for r in rs.rules:
        assert r.label.startswith("agentic reconnaissance")
        assert "artex" not in r.label.lower()


def test_thresholds_come_from_the_configured_file(tmp_path):
    (tmp_path / "mine.toml").write_text(
        '[[rules]]\nid = "walk"\nkind = "object_enumeration"\nlabel = "walk"\n'
        'confidence = "low"\nmin_ids = 3\n')
    cp = ConfigParser()
    cp.read_string(f"[behaviours]\npath = {tmp_path / 'mine.toml'}\n")
    rs = from_config(cp)
    walk = [req(i, f"/i/{i}", route="item", object_id_count=i + 1) for i in range(3)]
    assert ids(rs.evaluate(walk)) == ["walk"]
    assert ids(load_rules().evaluate(walk)) == []     # the shipped rule wants ten
    off = ConfigParser()
    off.read_string("[behaviours]\nenabled = no\n")
    assert from_config(off) is None
