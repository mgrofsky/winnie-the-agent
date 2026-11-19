"""The AWS example templates: parsed offline, checked for their security properties, and
kept in step with the scenarios and listener ports. No AWS calls."""

import configparser
import copy
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AWS = ROOT / "deploy" / "aws"

_spec = importlib.util.spec_from_file_location("aws_check", AWS / "check.py")
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)


@pytest.fixture(scope="module")
def sensor():
    return check.load(check.SENSOR)


@pytest.fixture(scope="module")
def bucket():
    return check.load(check.BUCKET)


def _role_statements(doc):
    return doc["Resources"]["InstanceRole"]["Properties"]["Policies"][0]["PolicyDocument"][
        "Statement"]


def _lt(doc):
    return doc["Resources"]["LaunchTemplate"]["Properties"]["LaunchTemplateData"]


def _bucket_statements(doc):
    return doc["Resources"]["EventsBucketPolicy"]["Properties"]["PolicyDocument"]["Statement"]


def test_shipped_templates_pass_every_check():
    assert check.run() == []


# ---- each sensor rule fires ----------------------------------------------------------------

def _set_inbound_default(d):
    d["Parameters"]["InboundCidr"]["Default"] = "0.0.0.0/0"


def _drop_inbound_condition(d):
    del d["Resources"]["InSsh"]["Condition"]


def _service_condition_only(d):
    d["Resources"]["InS3"]["Condition"] = "S3On"


def _open_ingress(d):
    d["Resources"]["InHttp"]["Properties"]["CidrIp"] = "0.0.0.0/0"


def _open_egress(d):
    d["Resources"]["InstanceSecurityGroup"]["Properties"]["SecurityGroupEgress"].append(
        {"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"})


def _no_egress(d):
    del d["Resources"]["EndpointSecurityGroup"]["Properties"]["SecurityGroupEgress"]


def _imds_optional(d):
    _lt(d)["MetadataOptions"]["HttpTokens"] = "optional"


def _hop_limit_two(d):
    _lt(d)["MetadataOptions"]["HttpPutResponseHopLimit"] = 2


def _key_pair(d):
    _lt(d)["KeyName"] = "example-key"


def _role_get_object(d):
    _role_statements(d)[-1]["Action"] = ["s3:PutObject", "s3:GetObject"]


def _role_wildcard_action(d):
    _role_statements(d).append({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})


def _role_wildcard_resource(d):
    _role_statements(d)[2]["Resource"] = "*"


def _role_admin_policy(d):
    d["Resources"]["InstanceRole"]["Properties"]["ManagedPolicyArns"].append(
        "arn:aws:iam::aws:policy/AdministratorAccess")


def _userland_proxy_on(d):
    ud = _lt(d)["UserData"]["Fn::Base64"]["Fn::Sub"]
    ud[0] = ud[0].replace('"userland-proxy": false', '"userland-proxy": true')


def _no_metadata_block(d):
    ud = _lt(d)["UserData"]["Fn::Base64"]["Fn::Sub"]
    ud[0] = ud[0].replace("add -i br-+ -d 169.254.169.254/32 -j DROP\n", "")


def _lifecycle_expires_tagged(d):
    props = d["Resources"]["Repository"]["Properties"]["LifecyclePolicy"]
    props["LifecyclePolicyText"] = props["LifecyclePolicyText"].replace('"untagged"', '"any"')


def _service_edit(d, service, old, new):
    """Replace the first ``old`` after the embedded compose file's ``service`` header."""
    ud = _lt(d)["UserData"]["Fn::Base64"]["Fn::Sub"]
    head, sep, tail = ud[0].partition(f"\n  {service}:\n")
    assert sep and old in tail, old
    ud[0] = head + sep + tail.replace(old, new, 1)


def _ui_edit(d, old, new):
    """Replace ``old`` inside the embedded compose file's ui service only."""
    _service_edit(d, "ui", old, new)


def _user_data_edit(d, old, new):
    ud = _lt(d)["UserData"]["Fn::Base64"]["Fn::Sub"]
    assert old in ud[0], old
    ud[0] = ud[0].replace(old, new)


def _ui_published_everywhere(d):
    _ui_edit(d, '"127.0.0.1:8480:8480"', '"8480:8480"')


def _ui_writes_agent_data(d):
    _ui_edit(d, "agentdata:/agents:ro", "agentdata:/agents")


def _ui_on_frontend(d):
    _ui_edit(d, "networks: [backend]", "networks: [backend, frontend]")


def _ui_actions(d):
    _ui_edit(d, '"--port", "8480"]', '"--port", "8480", "--actions"]')


def _ui_always_on(d):
    _ui_edit(d, "profiles: [ui]", "profiles: []")


def _ui_logs_to_cloudwatch(d):
    _ui_edit(d, "driver: local", "driver: awslogs")


def _ui_default_on(d):
    d["Parameters"]["UiEnabled"]["Default"] = "true"


def _ui_ingress(d):
    d["Resources"]["InUi"] = {
        "Type": "AWS::EC2::SecurityGroupIngress", "Condition": "InboundOn",
        "Properties": {"GroupId": {"Ref": "InstanceSecurityGroup"}, "IpProtocol": "tcp",
                       "FromPort": 8480, "ToPort": 8480, "CidrIp": {"Ref": "InboundCidr"}}}


def _ui_inline_ingress_all_ports(d):
    d["Resources"]["EndpointSecurityGroup"]["Properties"]["SecurityGroupIngress"].append(
        {"IpProtocol": "-1", "SourceSecurityGroupId": {"Ref": "InstanceSecurityGroup"}})


def _exporter_mounts_agentdata(d):
    _service_edit(d, "exporter", "blocklist:/blocklist:ro", "agentdata:/blocklist:ro")


def _exporter_writes_blocklist(d):
    _service_edit(d, "exporter", "blocklist:/blocklist:ro", "blocklist:/blocklist")


def _ui_writes_blocklist(d):
    _ui_edit(d, "blocklist:/agents/reports/blocklist:ro", "blocklist:/agents/reports/blocklist")


def _agents_blocklist_read_only(d):
    _service_edit(d, "agents", "blocklist:/agents/reports/blocklist\n",
                  "blocklist:/agents/reports/blocklist:ro\n")


def _blocklist_undeclared(d):
    _user_data_edit(d, "\n  blocklist: {}\n", "\n")


def _tracked_default_on(d):
    d["Parameters"]["TrackedExport"]["Default"] = "true"


def _tracked_key_loose(d):
    d["Parameters"]["TrackedKey"]["AllowedPattern"] = r"^[a-z0-9./_-]+\.json$"


def _tracked_key_outside_prefix(d):
    _user_data_edit(d, "${EventsPrefix}/${TrackedKey}", "${TrackedKey}")


def _tracked_file_elsewhere(d):
    _user_data_edit(d, '"file": "/blocklist/tracked.json"', '"file": "/agents/tracked.json"')


def _tracked_export_without_shipping(d):
    _user_data_edit(d, '"enabled": "true" if ship == "true" and tracked == "true" else "false"',
                    '"enabled": tracked')


def _tracked_export_always_on(d):
    _user_data_edit(d, '"enabled": "true" if ship == "true" and tracked == "true" else "false"',
                    '"enabled": "true"')


def _agents_config_ships(d):
    _user_data_edit(d, 'config.ini.TEMPLATE config.ini $ARGS "${NeverActOn}" false',
                    'config.ini.TEMPLATE config.ini $ARGS "${NeverActOn}" true')


def _tracked_arg_swapped(d):
    _user_data_edit(d, "${EventsBucketOwner} ${TrackedExport} ${EventsPrefix}/${TrackedKey}",
                    "${EventsBucketOwner} true ${EventsPrefix}/${TrackedKey}")


def _render_script_broken(d):
    _user_data_edit(d, "lines = open(src", "lines = opn(src")


def _agents_mount_ship_config(d):
    _service_edit(d, "agents", "./config.ini:/config/config.ini:ro",
                  "./config-ship.ini:/config/config.ini:ro")


def _exporter_without_blocklist(d):
    _service_edit(d, "exporter", "\n      - blocklist:/blocklist:ro\n", "\n")


def _exporter_blocklist_twice(d):
    _service_edit(d, "exporter", "- blocklist:/blocklist:ro\n",
                  "- blocklist:/blocklist:ro\n      - blocklist:/more:ro\n")


def _exporter_mounts_agent_state(d):
    _service_edit(d, "exporter", "- blocklist:/blocklist:ro\n",
                  "- blocklist:/blocklist:ro\n      - agentdata:/agents/state:ro\n")


def _tracked_key_numeric(d):
    d["Parameters"]["TrackedKey"]["AllowedPattern"] = \
        r"^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*){0,3}\.json$"


def _tracked_key_numeric_default(d):
    d["Parameters"]["TrackedKey"]["Default"] = "2026/tracked.json"


SENSOR_BREAKS = {
    "tracked_export] enabled is not false": _tracked_export_without_shipping,
    "with shipping false and TrackedExport false the rendered [connector.tracked_export]":
        _tracked_export_always_on,
    "config.ini without shipping and config-ship.ini with it": _agents_config_ships,
    "does not get TrackedExport as its tracked switch": _tracked_arg_swapped,
    "render_config.py fails": _render_script_broken,
    "the agents service mounts the exporter's config-ship.ini": _agents_mount_ship_config,
    "the exporter does not mount blocklist exactly once": _exporter_without_blocklist,
    "the exporter mounts blocklist at /more": _exporter_blocklist_twice,
    "the exporter mounts agentdata": _exporter_mounts_agent_state,
    "TrackedKey allows a key among the exported events": _tracked_key_numeric,
    "TrackedKey default does not start with a letter": _tracked_key_numeric_default,
    "InboundCidr has a default": _set_inbound_default,
    "InSsh does not depend on InboundOn": _drop_inbound_condition,
    "InS3 does not depend on InboundOn": _service_condition_only,
    "InHttp uses a literal open range": _open_ingress,
    "egress to an open range": _open_egress,
    "EndpointSecurityGroup declares no egress": _no_egress,
    "does not require IMDSv2": _imds_optional,
    "hop limit is not 1": _hop_limit_two,
    "sets a key pair": _key_pair,
    "allows s3:GetObject outside the events prefix": _role_get_object,
    "wildcard action s3:*": _role_wildcard_action,
    "uses Resource * for logs:CreateLogStream": _role_wildcard_resource,
    "not exactly AmazonSSMManagedInstanceCore": _role_admin_policy,
    "userland proxy is not off": _userland_proxy_on,
    "containers can reach the metadata service": _no_metadata_block,
    "can expire tagged images": _lifecycle_expires_tagged,
    "ui service publishes 8480:8480 beyond loopback": _ui_published_everywhere,
    "ui service mounts agentdata read-write": _ui_writes_agent_data,
    "ui service is on the front-end network": _ui_on_frontend,
    "ui service runs with --actions": _ui_actions,
    "ui service is not behind the ui profile": _ui_always_on,
    "sign-in link) leaves the host": _ui_logs_to_cloudwatch,
    "UiEnabled is not off by default": _ui_default_on,
    "ingress rule InUi reaches the console port 8480": _ui_ingress,
    "EndpointSecurityGroup ingress reaches the console port 8480": _ui_inline_ingress_all_ports,
    "the exporter mounts agentdata": _exporter_mounts_agentdata,
    "the exporter mounts blocklist read-write": _exporter_writes_blocklist,
    "blocklist volume is writable by the ui service": _ui_writes_blocklist,
    "agents service does not write the blocklist volume": _agents_blocklist_read_only,
    "the blocklist volume is not declared": _blocklist_undeclared,
    "TrackedExport is not off by default": _tracked_default_on,
    "TrackedKey allows a key outside the events prefix": _tracked_key_loose,
    "tracked key is not under the events prefix": _tracked_key_outside_prefix,
    "tracked export is not read from the blocklist mount": _tracked_file_elsewhere,
}


@pytest.mark.parametrize("expected", sorted(SENSOR_BREAKS))
def test_each_sensor_rule_fires(sensor, expected):
    doc = copy.deepcopy(sensor)
    SENSOR_BREAKS[expected](doc)
    errors = check.check_sensor(doc)
    assert any(expected in e for e in errors), errors


# ---- each bucket rule fires ----------------------------------------------------------------

def _no_tls_deny(d):
    sts = _bucket_statements(d)
    sts[:] = [s for s in sts if not (isinstance(s, dict) and s.get("Sid") == "DenyNonTls")]


def _grant_get(d):
    _bucket_statements(d)[0]["Action"] = ["s3:PutObject", "s3:GetObject"]


def _grant_whole_bucket(d):
    _bucket_statements(d)[0]["Resource"] = {"Fn::Sub": "${EventsBucket.Arn}/*"}


def _grant_whole_account(d):
    del _bucket_statements(d)[0]["Condition"]


def _public_policy(d):
    d["Resources"]["EventsBucket"]["Properties"]["PublicAccessBlockConfiguration"][
        "BlockPublicPolicy"] = False


def _no_versioning(d):
    del d["Resources"]["EventsBucket"]["Properties"]["VersioningConfiguration"]


def _anyone_reads(d):
    _bucket_statements(d).append({"Sid": "Open", "Effect": "Allow", "Principal": "*",
                                  "Action": "s3:GetObject", "Resource": "x"})


BUCKET_BREAKS = {
    "denies requests without TLS": _no_tls_deny,
    "grants the sensor account more than PutObject": _grant_get,
    "grants outside the events prefix": _grant_whole_bucket,
    "is not limited to the sensor role": _grant_whole_account,
    "BlockPublicPolicy is not on": _public_policy,
    "versioning is not enabled": _no_versioning,
    "Open allows any principal": _anyone_reads,
}


@pytest.mark.parametrize("expected", sorted(BUCKET_BREAKS))
def test_each_bucket_rule_fires(bucket, expected):
    doc = copy.deepcopy(bucket)
    BUCKET_BREAKS[expected](doc)
    errors = check.check_bucket(doc)
    assert any(expected in e for e in errors), errors


def test_names_and_account_ids_are_parameters_only(sensor, bucket):
    raw = check.SENSOR.read_text()
    assert check.check_names(sensor, raw, "s") == []
    doc = copy.deepcopy(bucket)
    doc["Parameters"]["SensorAccountId"]["Default"] = "123456789012"
    assert any("SensorAccountId has a default" in e for e in check.check_names(doc, "", "b"))
    doc = copy.deepcopy(sensor)
    doc["Parameters"]["NamePrefix"]["Default"] = "initech-honeypot"
    assert any("not generic" in e for e in check.check_names(doc, "", "s"))
    account = "4" * 6 + "5" * 6          # assembled: the tree must not hold one whole
    leaked = f"arn:aws:iam::{account}:root"
    assert check.check_names(sensor, leaked, "s") == [f"s: literal account id {account}"]


# ---- consistency with the rest of the repository ------------------------------------------

def test_scenario_mapping_matches_the_scenarios(sensor):
    from listeners.base import SERVICES
    from scenarios.loader import list_scenarios, load_scenario

    mapping = sensor["Mappings"]["ScenarioServices"]
    assert sorted(mapping) == sorted(n.replace("_", "-") for n in list_scenarios())
    assert sorted(sensor["Parameters"]["Scenario"]["AllowedValues"]) == sorted(mapping)
    for name in list_scenarios():
        services = load_scenario(name, "seed").scenario.services
        flags = mapping[name.replace("_", "-")]
        for svc in SERVICES:
            enabled = bool(getattr(services, svc) and getattr(services, svc).enabled)
            assert flags[svc.capitalize()] == ("true" if enabled else "false"), (name, svc)


def test_published_ports_reach_the_listener_ports(sensor):
    from listeners.base import DEFAULT_PORTS, SERVICES

    user_data = _lt(sensor)["UserData"]["Fn::Base64"]["Fn::Sub"][0]
    cases = dict(re.findall(r"^\s+([a-z0-9]+)\) PORTS=\"\$PORTS ([^\"]+)\"", user_data, re.M))
    assert set(cases) == set(SERVICES)
    for svc, ports in cases.items():
        container = {p.split(":")[1].split("/")[0] for p in ports.split()}
        assert str(DEFAULT_PORTS[svc]) in container, svc
    assert sensor["Parameters"]["S3Port"]["Default"] == 9000 == DEFAULT_PORTS["s3"]
    # Every service has an inbound rule gated on its own condition.
    rules = {r.get("Condition") for r in check.resources(sensor, "AWS::EC2::SecurityGroupIngress")
             .values()}
    assert {f"{s.capitalize()}In" for s in SERVICES} <= rules


def test_console_is_switched_by_a_profile_and_matches_the_compose_service(sensor):
    import yaml

    ud, variables = _lt(sensor)["UserData"]["Fn::Base64"]["Fn::Sub"]
    assert 'echo "COMPOSE_PROFILES=${UiProfiles}" > .env' in ud
    assert variables["UiProfiles"] == {"Fn::If": ["UiOn", "ui", ""]}
    assert sensor["Conditions"]["UiOn"] == {"Fn::Equals": [{"Ref": "UiEnabled"}, "true"]}
    embedded = check.embedded_compose(ud)["services"]["ui"]
    local = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]["ui"]
    assert embedded["command"] == local["command"]
    assert embedded["ports"] == local["ports"] == ["127.0.0.1:8480:8480"]


def test_blocklist_volume_is_written_by_the_agents_and_read_by_the_rest(sensor):
    ud = _lt(sensor)["UserData"]["Fn::Base64"]["Fn::Sub"][0]
    compose = check.embedded_compose(ud)
    services = compose["services"]
    assert "blocklist" in compose["volumes"]
    assert "blocklist:/agents/reports/blocklist" in services["agents"]["volumes"]
    assert "agentdata:/agents" in services["agents"]["volumes"]
    assert "blocklist:/agents/reports/blocklist:ro" in services["ui"]["volumes"]
    assert sorted(services["exporter"]["volumes"]) == sorted([
        "./config-ship.ini:/config/config.ini:ro", "frontend:/data:ro",
        "exportstate:/agents", "blocklist:/blocklist:ro"])
    for name in ("ssh", "listeners"):
        assert not any(str(v).startswith("blocklist:") for v in services[name]["volumes"])
    assert check.check_exporter(compose) == check.check_blocklist(compose) == []


def test_tracked_key_stays_under_the_events_prefix(sensor):
    param = sensor["Parameters"]["TrackedKey"]
    pattern = param["AllowedPattern"]
    assert re.fullmatch(pattern, param["Default"])
    for key in ("tracked/tracked.json", "a/b-c/d_e/f.g.json"):
        assert re.fullmatch(pattern, key), key
    for key in check.TRACKED_KEY_ESCAPES + check.TRACKED_KEY_COLLISIONS + (
            "tracked", "Tracked.json", "a/b/c/d/e.json"):
        assert not re.fullmatch(pattern, key), key
    # Events are written under <prefix>YYYY/MM/DD/; a key starting with a letter never is.
    assert re.fullmatch(pattern, "t2026/11/tracked.json")
    assert check.GENERIC_DEFAULT.match(param["Default"])
    assert not check.GENERIC_DEFAULT.match("tracked/initech.json")


def _render(sensor, tmp_path, dst, ship, tracked):
    """Run the bootstrap's render_config.py on the repository's config template."""
    ud = _lt(sensor)["UserData"]["Fn::Base64"]["Fn::Sub"][0]
    script = re.search(r"^cat > render_config\.py <<'PY'\n(.*?)\nPY$", ud, re.S | re.M).group(1)
    (tmp_path / "render_config.py").write_text(script)
    out = tmp_path / dst
    subprocess.run([sys.executable, str(tmp_path / "render_config.py"),
                    str(ROOT / "SSH" / "config.ini.TEMPLATE"), str(out), "winnie-sensor",
                    "sip-provider", "192.0.2.10", "false", "example-honeypot-events", "events",
                    "us-east-1", "123456789012", tracked, "events/tracked/tracked.json", "", ship],
                   check=True, capture_output=True)
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    cp.read(out, encoding="utf-8")
    return cp


@pytest.mark.parametrize("tracked", ["true", "false"])
def test_rendered_configs_turn_the_tracked_export_on_for_the_exporter_only(sensor, tmp_path,
                                                                           tracked):
    agents = _render(sensor, tmp_path, "config.ini", "false", tracked)
    ship = _render(sensor, tmp_path, "config-ship.ini", "true", tracked)
    for cp in (agents, ship):
        assert cp.get("respond", "track_before_enforce") == tracked
        assert cp.get("connector.tracked_export", "key") == "events/tracked/tracked.json"
        assert cp.get("connector.tracked_export", "file") == "/blocklist/tracked.json"
        assert cp.get("connector.tracked_export", "kind") == "s3"
    assert agents.get("connector.tracked_export", "enabled") == "false"
    assert agents.get("connector.s3_events", "enabled") == "false"
    assert ship.get("connector.tracked_export", "enabled") == tracked
    assert ship.get("connector.s3_events", "enabled") == "true"


def test_smtp_needs_its_own_switch(sensor):
    expr = sensor["Conditions"]["SmtpOn"]["Fn::And"]
    assert {"Fn::Equals": [{"Ref": "SmtpEnabled"}, "true"]} in expr
    assert sensor["Parameters"]["SmtpEnabled"]["Default"] == "false"


def test_the_example_is_linked_from_the_docs():
    assert "deploy/aws/README.md" in (ROOT / "README.md").read_text()
    assert "../deploy/aws/README.md" in (ROOT / "docs" / "operations.md").read_text()
    readme = (AWS / "README.md").read_text()
    for needed in ("--no-execute-changeset", "linux/amd64", "compose-bin", "userland",
                   "169.254.169.254", "AccessDenied", "InboundEnabled=false", "TLS"):
        assert needed in readme, needed
