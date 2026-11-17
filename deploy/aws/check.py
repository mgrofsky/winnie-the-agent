"""Offline checks for the AWS example templates (no AWS calls).

    uv run python deploy/aws/check.py            # prints "ok" or one problem per line

``check_sensor`` and ``check_bucket`` take a parsed template and return a list of problems,
so tests can feed them altered copies and see each rule fire.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Optional

import yaml

HERE = Path(__file__).resolve().parent
SENSOR = HERE / "sensor.yaml"
BUCKET = HERE / "events-bucket.yaml"

SSM_MANAGED = "arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
# Everything the instance role may do beyond the SSM managed policy.
ROLE_ACTIONS = {"ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability",
                "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "logs:CreateLogStream",
                "logs:PutLogEvents", "s3:PutObject"}
UNSCOPABLE = {"ecr:GetAuthorizationToken"}     # AWS offers no resource-level permission
DOCUMENTATION_ACCOUNT_IDS = {"000000000000", "123456789012"}
UI_PORT = 8480                                 # operator console, host loopback only
# Literal parameter defaults: project or example names, scenario names, instance types,
# public SSM parameter paths, addresses, numbers and switches. Nothing that could name an
# organisation.
GENERIC_DEFAULT = re.compile(r"^(winnie[a-z0-9-]*|example[a-z0-9.-]*|events|compose-bin|"
                             r"[a-z][0-9][a-z]*\.[a-z0-9]+|/aws/service/[a-z0-9/_.-]+|"
                             r"[0-9./]+|true|false|)$")


def scenario_names() -> set[str]:
    root = HERE.parents[1] / "scenarios"
    return {p.parent.name.replace("_", "-") for p in root.glob("*/scenario.toml")}


class CfnLoader(yaml.SafeLoader):
    """Reads CloudFormation short tags (!Ref, !Sub, ...) as {"Fn::X": value} mappings."""


def _tag(loader: CfnLoader, suffix: str, node: yaml.Node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    if suffix == "Ref":
        return {"Ref": value}
    if suffix == "GetAtt" and isinstance(value, str):
        value = value.split(".", 1)
    if suffix == "Condition":
        return {"Condition": value}
    return {f"Fn::{suffix}": value}


CfnLoader.add_multi_constructor("!", _tag)


def load(path: Path) -> dict:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=CfnLoader)


# ---- helpers ------------------------------------------------------------------------------

def resources(doc: dict, rtype: str) -> dict:
    return {k: v for k, v in (doc.get("Resources") or {}).items() if v.get("Type") == rtype}


def as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def text(value) -> str:
    """A string or the template string of !Sub; JSON for anything else."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and "Fn::Sub" in value:
        sub = value["Fn::Sub"]
        return sub if isinstance(sub, str) else sub[0]
    return json.dumps(value)


def is_open(cidr) -> bool:
    if not isinstance(cidr, str):
        return False
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen == 0
    except ValueError:
        return False


def opens_port(rule: dict, port: int) -> bool:
    """Whether an ingress rule admits ``port`` (all protocols, or a literal range holding it)."""
    if str(rule.get("IpProtocol")) == "-1":
        return True
    lo, hi = rule.get("FromPort"), rule.get("ToPort")
    return isinstance(lo, int) and isinstance(hi, int) and lo <= port <= hi


def condition_uses(doc: dict, name, target: str, seen=None) -> bool:
    """Whether condition ``name`` requires condition ``target`` (directly or through Fn::And)."""
    if name == target:
        return True
    seen = seen or set()
    if not isinstance(name, str) or name in seen:
        return False
    seen.add(name)
    expr = (doc.get("Conditions") or {}).get(name)
    if isinstance(expr, dict) and "Fn::And" in expr:
        return any(isinstance(e, dict) and "Condition" in e
                   and condition_uses(doc, e["Condition"], target, seen) for e in expr["Fn::And"])
    return False


def account_ids(raw: str) -> list[str]:
    return [m for m in re.findall(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])", raw)
            if m not in DOCUMENTATION_ACCOUNT_IDS]


def check_names(doc: dict, raw: str, label: str) -> list[str]:
    errors = [f"{label}: literal account id {a}" for a in account_ids(raw)]
    for name, param in (doc.get("Parameters") or {}).items():
        if "AccountId" in name or name.endswith("Owner"):
            if "Default" in param:
                errors.append(f"{label}: parameter {name} has a default")
        default = param.get("Default")
        if isinstance(default, str) and not GENERIC_DEFAULT.match(default) \
                and default not in scenario_names():
            errors.append(f"{label}: parameter {name} default {default!r} is not generic")
    return errors


# ---- sensor -------------------------------------------------------------------------------

def check_sensor(doc: dict, raw: str = "") -> list[str]:
    errors: list[str] = []
    params = doc.get("Parameters") or {}

    inbound = params.get("InboundCidr")
    if inbound is None:
        errors.append("parameter InboundCidr is missing")
    elif "Default" in inbound:
        errors.append("parameter InboundCidr has a default")
    for name, param in params.items():
        if is_open(param.get("Default")):
            errors.append(f"parameter {name} defaults to an open range")

    for name, sg in resources(doc, "AWS::EC2::SecurityGroup").items():
        props = sg.get("Properties") or {}
        if not props.get("SecurityGroupEgress"):
            errors.append(f"security group {name} declares no egress (CloudFormation adds allow-all)")
        for rule in as_list(props.get("SecurityGroupEgress") or []):
            if is_open(rule.get("CidrIp")) or is_open(rule.get("CidrIpv6")):
                errors.append(f"security group {name} has egress to an open range")
        for rule in as_list(props.get("SecurityGroupIngress") or []):
            if "SourceSecurityGroupId" not in rule:
                errors.append(f"security group {name} has inline ingress from an address range")
            if opens_port(rule, UI_PORT):
                errors.append(f"security group {name} ingress reaches the console port {UI_PORT}")
    for name, rule in resources(doc, "AWS::EC2::SecurityGroupEgress").items():
        props = rule.get("Properties") or {}
        if "CidrIp" in props or "CidrIpv6" in props:
            errors.append(f"egress rule {name} goes to an address range")
    for name, rule in resources(doc, "AWS::EC2::SecurityGroupIngress").items():
        props = rule.get("Properties") or {}
        if not condition_uses(doc, rule.get("Condition"), "InboundOn"):
            errors.append(f"ingress rule {name} does not depend on InboundOn")
        if is_open(props.get("CidrIp")) or is_open(props.get("CidrIpv6")):
            errors.append(f"ingress rule {name} uses a literal open range")
        if props.get("CidrIp") != {"Ref": "InboundCidr"}:
            errors.append(f"ingress rule {name} is not limited to InboundCidr")
        if opens_port(props, UI_PORT):
            errors.append(f"ingress rule {name} reaches the console port {UI_PORT}")
    if (params.get("UiEnabled") or {}).get("Default") != "false":
        errors.append("parameter UiEnabled is not off by default")

    templates = resources(doc, "AWS::EC2::LaunchTemplate")
    if not templates:
        errors.append("no launch template")
    for name, lt in templates.items():
        data = (lt.get("Properties") or {}).get("LaunchTemplateData") or {}
        md = data.get("MetadataOptions") or {}
        if str(md.get("HttpTokens")) != "required":
            errors.append(f"launch template {name} does not require IMDSv2")
        if str(md.get("HttpPutResponseHopLimit")) != "1":
            errors.append(f"launch template {name} hop limit is not 1")
        if "KeyName" in data:
            errors.append(f"launch template {name} sets a key pair")
        user_data = text((data.get("UserData") or {}).get("Fn::Base64"))
        errors += [f"launch template {name}: {e}" for e in check_user_data(user_data)]
    for name, inst in resources(doc, "AWS::EC2::Instance").items():
        props = inst.get("Properties") or {}
        if "KeyName" in props:
            errors.append(f"instance {name} sets a key pair")
        if "LaunchTemplate" not in props:
            errors.append(f"instance {name} does not use the launch template")

    errors += check_role(doc)
    errors += check_repository(doc)
    return ["sensor: " + e for e in errors]


USER_DATA_FACTS = {
    "sshd is not masked": "systemctl mask sshd.service",
    "the Docker userland proxy is not off": '"userland-proxy": false',
    "containers can reach the metadata service":
        "add -i br-+ -d 169.254.169.254/32 -j DROP",
    "the front-end network can open connections":
        "add -s 172.30.0.0/24 -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP",
    "the agents network can open connections":
        "add -s 172.30.1.0/24 -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP",
    "the Compose plugin is not taken from the repository": "docker cp \"$cid:/docker-compose\"",
    "the exporter does not get its own config": "./config-ship.ini:/config/config.ini:ro",
    "passwords are not hashed in the export": '"passwords": "hash"',
}


def check_user_data(user_data: str) -> list[str]:
    errors = [msg for msg, needle in USER_DATA_FACTS.items() if needle not in user_data]
    ships = re.findall(r"python -m agents ship[^\"\]]*", user_data)
    if not ships:
        errors.append("nothing runs python -m agents ship")
    for cmd in ships:
        for opt in ("--config", "--log", "--data-dir /data", "--state-dir"):
            if opt not in cmd:
                errors.append(f"the ship command lacks {opt}")
    errors += check_ui(embedded_compose(user_data))
    return errors


def embedded_compose(user_data: str) -> Optional[dict]:
    """The docker-compose.yml the bootstrap writes, parsed; None if it cannot be found."""
    m = re.search(r"^cat > docker-compose\.yml <<'EOF'\n(.*?)\nEOF$", user_data, re.S | re.M)
    if not m:
        return None
    try:
        doc = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        return None
    return doc if isinstance(doc, dict) else None


def check_ui(compose: Optional[dict]) -> list[str]:
    """The operator console in the embedded compose file: off unless its profile is on,
    read-only, published on the host's loopback only, never on the front-end network."""
    if compose is None:
        return ["the embedded docker-compose.yml cannot be read"]
    ui = (compose.get("services") or {}).get("ui")
    if not isinstance(ui, dict):
        return ["the embedded compose file has no ui service"]
    errors: list[str] = []
    if ui.get("profiles") != ["ui"]:
        errors.append("the ui service is not behind the ui profile")
    for port in as_list(ui.get("ports") or []):
        if not str(port).startswith("127.0.0.1:"):
            errors.append(f"the ui service publishes {port} beyond loopback")
    if "network_mode" in ui:
        errors.append(f"the ui service uses network_mode {ui['network_mode']}")
    networks = ui.get("networks") or []
    if "frontend" in networks:
        errors.append("the ui service is on the front-end network")
    if networks != ["backend"]:
        errors.append("the ui service is not only on the backend network")
    for volume in as_list(ui.get("volumes") or []):
        parts = str(volume).split(":")
        if len(parts) < 3 or parts[2] != "ro":
            errors.append(f"the ui service mounts {parts[0]} read-write")
    command = ui.get("command") or []
    if "--actions" in command or "--actions" in str(command):
        errors.append("the ui service runs with --actions")
    for key in ui.get("environment") or {}:
        if key.startswith(("AWS_", "ANTHROPIC", "WINNIE_WEBHOOK")) or key.endswith("_API_KEY"):
            errors.append(f"the ui service gets {key}")
    if (ui.get("logging") or {}).get("driver") != "local":
        errors.append("the ui service log (with its sign-in link) leaves the host")
    return errors


def check_role(doc: dict) -> list[str]:
    errors: list[str] = []
    roles = {n: r for n, r in resources(doc, "AWS::IAM::Role").items()
             if "ec2.amazonaws.com" in json.dumps((r.get("Properties") or {})
                                                  .get("AssumeRolePolicyDocument"))}
    if len(roles) != 1:
        return [f"expected exactly one EC2 instance role, found {len(roles)}"]
    name, role = next(iter(roles.items()))
    props = role.get("Properties") or {}
    managed = [text(m) for m in as_list(props.get("ManagedPolicyArns") or [])]
    if managed != [SSM_MANAGED]:
        errors.append(f"instance role {name} managed policies are not exactly "
                      "AmazonSSMManagedInstanceCore")
    for policy in as_list(props.get("Policies") or []):
        for st in as_list(policy["PolicyDocument"]["Statement"]):
            if st.get("Effect") != "Allow" or "NotAction" in st or "NotResource" in st:
                errors.append(f"instance role {name} has a statement that is not a plain Allow")
                continue
            actions = as_list(st.get("Action"))
            res = [text(r) for r in as_list(st.get("Resource"))]
            for action in actions:
                if "*" in action:
                    errors.append(f"instance role {name} has a wildcard action {action}")
                elif action not in ROLE_ACTIONS:
                    errors.append(f"instance role {name} allows {action}")
                if action.startswith("s3:") and (action != "s3:PutObject" or any(
                        not r.endswith("/${EventsPrefix}/*") for r in res)):
                    errors.append(f"instance role {name} allows {action} outside the events prefix")
            if "*" in res and not set(actions) <= UNSCOPABLE:
                errors.append(f"instance role {name} uses Resource * for {', '.join(actions)}")
            if any(r != "*" and r.endswith(":*:*") for r in res):
                errors.append(f"instance role {name} has a wildcard resource")
    return errors


def check_repository(doc: dict) -> list[str]:
    errors: list[str] = []
    for name, repo in resources(doc, "AWS::ECR::Repository").items():
        text_ = ((repo.get("Properties") or {}).get("LifecyclePolicy") or {}) \
            .get("LifecyclePolicyText")
        if not text_:
            continue
        for rule in json.loads(text_).get("rules", []):
            if rule.get("selection", {}).get("tagStatus") != "untagged":
                errors.append(f"repository {name} lifecycle can expire tagged images "
                              "(the Compose binary copy among them)")
    return errors


# ---- bucket -------------------------------------------------------------------------------

def _statements(doc: dict) -> list[dict]:
    out = []
    for policy in resources(doc, "AWS::S3::BucketPolicy").values():
        for st in as_list(policy["Properties"]["PolicyDocument"]["Statement"]):
            if isinstance(st, dict) and "Fn::If" in st:
                st = st["Fn::If"][1]
            if isinstance(st, dict) and "Effect" in st:
                out.append(st)
    return out


def _sensor_principal(st: dict) -> bool:
    return "SensorAccountId" in json.dumps(st.get("Principal"))


def check_bucket(doc: dict, raw: str = "") -> list[str]:
    errors: list[str] = []
    buckets = resources(doc, "AWS::S3::Bucket")
    if len(buckets) != 1:
        return [f"bucket: expected one bucket, found {len(buckets)}"]
    props = next(iter(buckets.values())).get("Properties") or {}
    block = props.get("PublicAccessBlockConfiguration") or {}
    for key in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls",
                "RestrictPublicBuckets"):
        if block.get(key) is not True:
            errors.append(f"public access block {key} is not on")
    if (props.get("VersioningConfiguration") or {}).get("Status") != "Enabled":
        errors.append("versioning is not enabled")
    if not ((props.get("LifecycleConfiguration") or {}).get("Rules")):
        errors.append("no lifecycle rules")

    sts = _statements(doc)
    tls = [s for s in sts if s["Effect"] == "Deny" and s.get("Principal") == "*"
           and "aws:SecureTransport" in json.dumps(s.get("Condition"))
           and len(as_list(s.get("Resource"))) == 2]
    if not tls:
        errors.append("no statement denies requests without TLS on the bucket and its objects")
    grants = [s for s in sts if s["Effect"] == "Allow" and _sensor_principal(s)]
    if not grants:
        errors.append("the sensor role is granted nothing")
    for s in grants:
        if as_list(s.get("Action")) != ["s3:PutObject"]:
            errors.append(f"statement {s.get('Sid')} grants the sensor account more than PutObject")
        if not all(text(r).endswith("/${EventsPrefix}/*") for r in as_list(s.get("Resource"))):
            errors.append(f"statement {s.get('Sid')} grants outside the events prefix")
        if "aws:PrincipalArn" not in json.dumps(s.get("Condition")):
            errors.append(f"statement {s.get('Sid')} is not limited to the sensor role")
    denies = [s for s in sts if s["Effect"] == "Deny" and _sensor_principal(s)]
    if not any(s.get("NotAction") == "s3:PutObject" for s in denies):
        errors.append("the sensor account is not denied everything but PutObject")
    if not any(s.get("Action") == "s3:PutObject" and "NotResource" in s for s in denies):
        errors.append("the sensor account is not denied PutObject outside the events prefix")
    for s in sts:
        if s["Effect"] == "Allow" and s.get("Principal") == "*":
            errors.append(f"statement {s.get('Sid')} allows any principal")
    return ["bucket: " + e for e in errors]


def run() -> list[str]:
    errors = []
    for path, fn in ((SENSOR, check_sensor), (BUCKET, check_bucket)):
        raw = path.read_text(encoding="utf-8")
        doc = load(path)
        errors += fn(doc, raw) + check_names(doc, raw, path.name)
    return errors


def main() -> int:
    errors = run()
    for e in errors:
        print(e)
    if not errors:
        print("ok")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
