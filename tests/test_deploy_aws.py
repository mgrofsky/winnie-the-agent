"""The AWS example templates: parsed offline, checked for their security properties, and
kept in step with the scenarios and listener ports. No AWS calls."""

import copy
import importlib.util
import re
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


SENSOR_BREAKS = {
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
