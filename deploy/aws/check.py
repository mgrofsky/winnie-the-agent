"""Offline checks for the AWS example templates (no AWS calls).

    uv run python deploy/aws/check.py            # prints "ok" or one problem per line

``check_sensor``, ``check_bucket`` and ``check_models`` take a parsed template and return a
list of problems, so tests can feed them altered copies and see each rule fire.
"""

from __future__ import annotations

import configparser
import functools
import importlib.util
import ipaddress
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

import yaml

HERE = Path(__file__).resolve().parent
SENSOR = HERE / "sensor.yaml"
BUCKET = HERE / "events-bucket.yaml"
MODELS = HERE / "models.yaml"

_spec = importlib.util.spec_from_file_location("strip_comments", HERE / "strip_comments.py")
strip_comments = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(strip_comments)

SSM_MANAGED = "arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
# Everything the instance role may do beyond the SSM managed policy.
ROLE_ACTIONS = {"ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability",
                "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "logs:CreateLogStream",
                "logs:PutLogEvents", "s3:PutObject"}
UNSCOPABLE = {"ecr:GetAuthorizationToken"}     # AWS offers no resource-level permission
# TailscaleEnabled only: what the role may do with Parameter Store, and on which names. The
# node state is the only parameter it may write.
SSM_PARAMETER = "arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter/${NamePrefix}/"
TAILSCALE_STATE = SSM_PARAMETER + "tailscale-state"
TAILSCALE_READS = {TAILSCALE_STATE, SSM_PARAMETER + "tailscale-authkey",
                   SSM_PARAMETER + "ui-token"}
TAILSCALE_SWITCHES = ("TailscaleEnabled", "UiTailnetSignIn", "UiActions")
# The only egress rule to an address range: tcp 443 for tailscaled and the exporter's
# InternetDB lookups, under HostEgressOn (TailscaleEnabled or InternetDbLookup).
TAILSCALE_EGRESS = "InstanceEgressTailscale"
HOST_EGRESS = "HostEgressOn"
TAILSCALE_POLICY = "InstanceTailscaleParameters"
# EC2 refuses user data over 16 KiB (raw, before base64), and CloudFormation an inline
# template body over 51,200 bytes (strip_comments.py writes the deploy copy).
USER_DATA_LIMIT = 16_384
TEMPLATE_BODY_LIMIT = strip_comments.TEMPLATE_BODY_LIMIT
# Longest values of what the user data substitutes besides parameters: a region name (14
# characters today, so 16 leaves room), the URL suffix (amazonaws.com.cn), the partition
# (aws-us-gov), an IPv4 address, and the space-joined service list.
LONGEST = {"AWS::AccountId": 12, "AWS::Region": 16, "AWS::URLSuffix": 16, "AWS::Partition": 10,
           "ElasticIp": 15, "Services": 64}
# The ui service's mounts with UiActions on (docker-compose.actions.yml): exactly these two
# become read-write, nothing else changes.
UI_ACTIONS_MOUNTS = ["agentdata:/agents", "blocklist:/agents/reports/blocklist"]
DOCUMENTATION_ACCOUNT_IDS = {"000000000000", "123456789012"}
UI_PORT = 8480                                 # operator console, host loopback only
# Keys TrackedKey's pattern must refuse: each would leave EventsPrefix/ or be ambiguous.
TRACKED_KEY_ESCAPES = ("../tracked.json", "tracked/../../tracked.json", "/tracked.json",
                       "tracked//tracked.json", "tracked/..json", "tracked/./tracked.json")
# Keys that could land among the exported events, which are written under
# EventsPrefix/YYYY/MM/DD/: TrackedKey's first segment must start with a letter.
TRACKED_KEY_COLLISIONS = ("2026/11/18/tracked.json", "2026.json", "0/tracked.json",
                          "2026-11/tracked.json", "9tracked/tracked.json")
CONFIG_TEMPLATE = HERE.parents[1] / "SSH" / "config.ini.TEMPLATE"
# Each config file the bootstrap renders, and the shipping switch its render call must
# pass: only the exporter's copy may turn a transport on.
RENDER_CALLS = {"config.ini": "false", "config-ship.ini": "true"}
# Position of TrackedExport among render_config.py's arguments after src and dst.
TRACKED_ARG = 8
# The exporter's mounts: source -> (target, read-only). Nothing else of the agents' data.
EXPORTER_MOUNTS = {"./config-ship.ini": ("/config/config.ini", True),
                   "frontend": ("/data", True),
                   "exportstate": ("/agents", False),
                   "blocklist": ("/blocklist", True)}
# InternetDbDelivered: the one object the role and the S3 endpoint may read, and the user
# data variables that carry the feature. Each renders to "" when the switch is off, so the
# bootstrap is then exactly what it was without the feature.
IDB_ANSWERS = "arn:${AWS::Partition}:s3:::${EventsBucketName}/${InternetDbAnswersKey}"
IDB_ROLE_STATEMENT = {"Sid": "GetInternetDbAnswers", "Effect": "Allow",
                      "Action": "s3:GetObject", "Resource": {"Fn::Sub": IDB_ANSWERS}}
IDB_ENDPOINT_STATEMENT = {"Sid": "InternetDbAnswers", "Effect": "Allow", "Principal": "*",
                          "Action": "s3:GetObject", "Resource": {"Fn::Sub": IDB_ANSWERS}}
IDB_WANTED_KEY = "${EventsPrefix}/internetdb/wanted.json"
IDB_VARIABLES = {"IdbArgs": " true " + IDB_WANTED_KEY + " ${InternetDbAnswersKey}",
                 "IdbRead": "\n      - internetdb:/internetdb:ro",
                 "IdbWrite": "\n      - internetdb:/internetdb",
                 "IdbVolume": "\n  internetdb: {}"}
# InternetDbLookup: the same volume, the exporter's lookup kind, and the directory where the
# host firewall saves the addresses it pinned, read-only for the exporter alone.
IDB_EGRESS_DIR = "/var/lib/sensor-egress/exporter"
IDB_LOOKUP_VARIABLES = {**IDB_VARIABLES, "IdbArgs": " lookup",
                        "IdbWrite": IDB_VARIABLES["IdbWrite"] + "\n      - " + IDB_EGRESS_DIR
                        + ":/egress:ro"}
# InternetDbLookup's switch for the host firewall, written before the egress step runs, in a
# file of its own so the egress step itself is the same with the switch off.
IDB_EGRESS_SWITCH = "echo INTERNETDB_LOOKUP=true > /etc/sensor-egress-idb.env\n"
# Variables the same with either switch take IdbAnyOn; the others InternetDbOn, then
# IdbLookupOn.
IDB_SHARED = ("IdbRead", "IdbVolume")
IDB_CONDITIONS = {
    "InternetDbOn": {"Fn::Equals": [{"Ref": "InternetDbDelivered"}, "true"]},
    "IdbLookupOn": {"Fn::Equals": [{"Ref": "InternetDbLookup"}, "true"]},
    "IdbAnyOn": {"Fn::Or": [{"Condition": "InternetDbOn"},
                                   {"Condition": "IdbLookupOn"}]},
    HOST_EGRESS: {"Fn::Or": [{"Condition": "TailscaleOn"},
                             {"Condition": "IdbLookupOn"}, {"Condition": "OtxOn"}]},
    "OtxOn": {"Fn::Not": [{"Fn::Equals": [{"Ref": "OtxSubmit"}, "false"]}]},
}
IDB_RULE = {"RuleCondition": {"Fn::Equals": [{"Ref": "InternetDbLookup"}, "true"]},
            "Assertions": [{"Assert": {"Fn::Not": [{"Fn::Equals": [
                {"Ref": "InternetDbDelivered"}, "true"]}]},
                "AssertDescription": "Not both InternetDbLookup and InternetDbDelivered."}]}
# Who mounts the internetdb volume, where, and read-only or not; no other service may.
IDB_MOUNTS = {"exporter": ("/internetdb", False), "agents": ("/internetdb", True),
              "ui": ("/internetdb", True)}
# OtxSubmit: the render argument (otx-dry-run or otx-send), the key file for the exporter
# alone and, unless InternetDbLookup already mounts it, the host firewall's pinned
# addresses; each "" when the switch is off. OtxStep writes the host firewall's switch and
# the key file before the egress step.
OTX_VALUES = ("dry-run", "send")
OTX_KEY_FILE = "./otx-key"
OTX_KEY_MOUNT = "\n      - " + OTX_KEY_FILE + ":/run/otx-key:ro"
OTX_EGRESS_MOUNT = "\n      - " + IDB_EGRESS_DIR + ":/egress:ro"
OTX_VARIABLES = {
    "OtxArgs": {"Fn::If": ["OtxOn", {"Fn::Sub": " otx-${OtxSubmit}"}, ""]},
    "OtxMount": {"Fn::If": ["OtxOn", {"Fn::If": ["IdbLookupOn", OTX_KEY_MOUNT,
                                                 OTX_KEY_MOUNT + OTX_EGRESS_MOUNT]}, ""]},
}
OTX_STEP_LINES = [
    "echo OTX_SUBMIT=true > /etc/sensor-egress-otx.env",
    "(umask 077; aws ssm get-parameter --region $REGION --name /${NamePrefix}/otx-api-key "
    "--with-decryption --query Parameter.Value --output text > otx-key) || "
    'echo "otx key: FAILED ($?)"',
    "chown 10001:10001 otx-key",
]
# Literal parameter defaults: project or example names, scenario names, instance types,
# public SSM parameter paths, addresses, numbers and switches. Nothing that could name an
# organisation.
GENERIC_DEFAULT = re.compile(r"^(winnie[a-z0-9-]*|example[a-z0-9.-]*|events|compose-bin|console|"
                             r"tracked/tracked\.json|internetdb/answers\.json|"
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
        if name == TAILSCALE_EGRESS:
            errors += check_tailscale_egress(rule)
        elif "CidrIp" in props or "CidrIpv6" in props:
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
        if mentions_tailscale(rule):
            errors.append(f"ingress rule {name} depends on a Tailscale switch (the tailnet "
                          "needs no inbound rule)")
    for switch in ("UiEnabled",) + TAILSCALE_SWITCHES:
        if (params.get(switch) or {}).get("Default") != "false":
            errors.append(f"parameter {switch} is not off by default")
    errors += check_tailscale_switches(doc)
    errors += check_model_switches(doc)
    if (params.get("TrackedExport") or {}).get("Default") != "false":
        errors.append("parameter TrackedExport is not off by default")
    tracked_key = params.get("TrackedKey") or {}
    pattern = tracked_key.get("AllowedPattern")
    if not isinstance(pattern, str) or any(re.search(pattern, k) for k in TRACKED_KEY_ESCAPES):
        errors.append("parameter TrackedKey allows a key outside the events prefix")
    if not isinstance(pattern, str) or any(re.search(pattern, k)
                                           for k in TRACKED_KEY_COLLISIONS):
        errors.append("parameter TrackedKey allows a key among the exported events")
    default = tracked_key.get("Default")
    if not isinstance(default, str) or not re.match(r"[a-z]", default):
        errors.append("parameter TrackedKey default does not start with a letter")

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
        base64_value = (data.get("UserData") or {}).get("Fn::Base64")
        user_data = text(base64_value)
        sub = base64_value.get("Fn::Sub") if isinstance(base64_value, dict) else None
        variables = sub[1] if isinstance(sub, list) and len(sub) == 2 else {}
        found: list[str] = []
        for on in (False, True, "lookup"):
            for otx in (False,) + OTX_VALUES:
                expanded, problems = internetdb_user_data(user_data, variables, on)
                expanded, more = otx_user_data(expanded, variables, otx, on)
                found += problems + more + check_user_data(expanded, internetdb=on, otx=otx)
        errors += [f"launch template {name}: {e}" for e in dict.fromkeys(found)]
        errors += [f"launch template {name}: {e}"
                   for e in check_user_data_steps(doc, (data.get("UserData") or {})
                                                  .get("Fn::Base64"))]
    for name, inst in resources(doc, "AWS::EC2::Instance").items():
        props = inst.get("Properties") or {}
        if "KeyName" in props:
            errors.append(f"instance {name} sets a key pair")
        if "LaunchTemplate" not in props:
            errors.append(f"instance {name} does not use the launch template")

    errors += check_role(doc)
    errors += check_endpoint_policy(doc)
    errors += check_internetdb_switch(doc)
    errors += check_repository(doc)
    if raw:
        errors += deploy_copy_problems(raw)
    return ["sensor: " + e for e in errors]


# ---- size limits --------------------------------------------------------------------------

def deploy_copy_problems(raw: str) -> list[str]:
    """The comment-stripped deploy copy parses to the same document and fits the inline
    template limit."""
    stripped = strip_comments.strip(raw)
    errors: list[str] = []
    try:
        same = yaml.load(stripped, Loader=CfnLoader) == yaml.load(raw, Loader=CfnLoader)
    except yaml.YAMLError as exc:
        return [f"the comment-stripped copy does not parse ({str(exc)[:80]})"]
    if not same:
        errors.append("the comment-stripped copy is not the same document")
    size = len(stripped.encode())
    if size > TEMPLATE_BODY_LIMIT:
        errors.append(f"the comment-stripped copy is {size} bytes, over the "
                      f"{TEMPLATE_BODY_LIMIT}-byte template body limit")
    return errors


def _pattern_width(pattern: str) -> Optional[int]:
    """The longest string ``pattern`` can match, or None if it has no limit."""
    import re._parser as sre_parse              # the stdlib's regex parser (Python 3.11+)
    width = sre_parse.parse(pattern).getwidth()[1]
    return None if width >= sre_parse.MAXREPEAT else width


def longest_value(param: dict) -> Optional[int]:
    """The longest value CloudFormation accepts for ``param``, or None if unbounded."""
    if "MaxLength" in param:
        return int(param["MaxLength"])
    if "AllowedValues" in param:
        return max(len(str(v)) for v in param["AllowedValues"])
    if param.get("Type") == "Number" and "MaxValue" in param:
        return max(len(str(param["MaxValue"])), len(str(param.get("MinValue", ""))))
    if isinstance(param.get("AllowedPattern"), str):
        return _pattern_width(param["AllowedPattern"])
    return None


def _longest(value, doc: dict, errors: list[str]) -> str:
    """The longest rendering of a user data value: every Fn::If takes its longer branch
    and every ${Name} its longest allowed value."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and "Fn::If" in value:
        options = [_longest(v, doc, errors) for v in value["Fn::If"][1:]]
        return max(options, key=lambda s: len(s.encode()))
    if isinstance(value, dict) and "Fn::Join" in value:
        sep, parts = value["Fn::Join"]
        return sep.join(_longest(p, doc, errors) for p in parts)
    if isinstance(value, dict) and "Fn::Sub" in value:
        sub = value["Fn::Sub"]
        template, variables = (sub, {}) if isinstance(sub, str) else (sub[0], sub[1])
        local = {k: _longest(v, doc, errors) for k, v in variables.items()}
        return re.sub(r"\$\{([^}]*)\}",
                      lambda m: _placeholder(m.group(1), local, doc, errors), template)
    errors.append(f"user data value {json.dumps(value)[:60]} cannot be measured")
    return ""


def _placeholder(name: str, local: dict, doc: dict, errors: list[str]) -> str:
    if name.startswith("!"):
        return "${" + name[1:] + "}"
    if name in local:
        return local[name]
    if name in LONGEST:
        return "x" * LONGEST[name]
    params = doc.get("Parameters") or {}
    prefix = "x" * (longest_value(params.get("NamePrefix") or {}) or 0)
    if name == "HostLogGroup":
        return f"/{prefix}/host"
    if name == "Repository.RepositoryUri":
        return "x" * LONGEST["AWS::AccountId"] + ".dkr.ecr." + "x" * LONGEST["AWS::Region"] \
            + "." + "x" * LONGEST["AWS::URLSuffix"] + "/" + prefix
    if name not in params:
        errors.append(f"user data substitutes {name}, which has no known longest value")
        return ""
    width = longest_value(params[name])
    if width is None:
        errors.append(f"parameter {name} is in the user data but has no length limit")
        return ""
    return "x" * width


def user_data_size(doc: dict, base64_value) -> tuple[int, list[str]]:
    """Bytes of the user data at the longest allowed values, every switch on."""
    errors: list[str] = []
    rendered = _longest(base64_value, doc, errors)
    return len(rendered.encode()), errors


# ---- Tailscale ----------------------------------------------------------------------------

def mentions_tailscale(node) -> bool:
    """Whether a resource or expression refers to a Tailscale switch or its condition."""
    blob = json.dumps(node)
    return any(n in blob for n in ("TailscaleOn", "ConsoleStepOn") + TAILSCALE_SWITCHES[:2])


def check_tailscale_egress(rule: dict) -> list[str]:
    """tailscaled's and the exporter's way out: tcp 443 only, and only with TailscaleEnabled
    or InternetDbLookup (whose host firewall limits the exporter)."""
    props = rule.get("Properties") or {}
    errors: list[str] = []
    if rule.get("Condition") != HOST_EGRESS:
        errors.append(f"egress rule {TAILSCALE_EGRESS} does not depend on {HOST_EGRESS}")
    if str(props.get("IpProtocol")) != "tcp" or props.get("FromPort") != 443 \
            or props.get("ToPort") != 443:
        errors.append(f"egress rule {TAILSCALE_EGRESS} allows more than tcp 443")
    if "CidrIpv6" in props:
        errors.append(f"egress rule {TAILSCALE_EGRESS} also allows IPv6")
    return errors


def _requires(switch: str, *assertions: dict) -> dict:
    return {"RuleCondition": {"Fn::Equals": [{"Ref": switch}, "true"]},
            "Assertions": list(assertions)}


def _must_be_true(param: str, why: str) -> dict:
    return {"Assert": {"Fn::Equals": [{"Ref": param}, "true"]}, "AssertDescription": why}


def _must_be_set(param: str) -> dict:
    return {"Assert": {"Fn::Not": [{"Fn::Equals": [{"Ref": param}, ""]}]},
            "AssertDescription": f"{param} is required when TailscaleEnabled is true."}


# The rules that refuse half a setup, exactly as they must read.
TAILSCALE_RULES = {
    "TailscaleNeedsItsSettings": _requires(
        "TailscaleEnabled",
        _must_be_true("UiEnabled", "TailscaleEnabled=true needs UiEnabled=true (it serves the "
                                   "console)."),
        _must_be_set("TailscaleImageTag"), _must_be_set("TailscaleHostname"),
        _must_be_set("TailnetSuffix")),
    "UiSignInNeedsTailscale": _requires(
        "UiTailnetSignIn",
        _must_be_true("TailscaleEnabled", "UiTailnetSignIn=true needs TailscaleEnabled=true (it "
                                          "is a tailnet page).")),
    "UiActionsNeedUi": _requires(
        "UiActions", _must_be_true("UiEnabled", "UiActions=true needs UiEnabled=true.")),
}
# The one resource of its kind allowed to exist only with a switch: the EC2 API endpoint the
# host firewall uses to read the S3 prefix list.
EC2_ENDPOINT = "Ec2Endpoint"
PREFIX_LIST_ARN = "arn:${AWS::Partition}:ec2:${AWS::Region}:aws:prefix-list/${S3PrefixListId}"
# The host firewall's one read, in the role's own policy under HostEgressOn.
PREFIX_ROLE_STATEMENT = {"Effect": "Allow",
                         "Action": "ec2:GetManagedPrefixListEntries",
                         "Resource": {"Fn::Sub": PREFIX_LIST_ARN}}
EC2_ENDPOINT_POLICY = {"Version": "2012-10-17", "Statement": [
    {"Sid": "S3PrefixListOnly", "Effect": "Allow", "Principal": "*",
     "Action": "ec2:GetManagedPrefixListEntries", "Resource": {"Fn::Sub": PREFIX_LIST_ARN}}]}


def check_ec2_endpoint(res: dict) -> list[str]:
    props = res.get("Properties") or {}
    errors: list[str] = []
    if res.get("Condition") != HOST_EGRESS:
        errors.append(f"endpoint {EC2_ENDPOINT} exists without {HOST_EGRESS}")
    if props.get("ServiceName") != {"Fn::Sub": "com.amazonaws.${AWS::Region}.ec2"}:
        errors.append(f"endpoint {EC2_ENDPOINT} is not the EC2 API endpoint")
    if props.get("PolicyDocument") != EC2_ENDPOINT_POLICY:
        errors.append(f"endpoint {EC2_ENDPOINT} policy allows more than reading the S3 "
                      "prefix list")
    if props.get("SecurityGroupIds") != [{"Ref": "EndpointSecurityGroup"}]:
        errors.append(f"endpoint {EC2_ENDPOINT} is not behind the endpoint security group")
    return errors


def check_tailscale_switches(doc: dict) -> list[str]:
    """Each Tailscale switch has its condition and the rules that refuse half a setup."""
    errors: list[str] = []
    conditions = doc.get("Conditions") or {}
    for cond, param in (("TailscaleOn", "TailscaleEnabled"), ("UiActionsOn", "UiActions")):
        if conditions.get(cond) != {"Fn::Equals": [{"Ref": param}, "true"]}:
            errors.append(f"condition {cond} is not {param} = true")
    if conditions.get("ConsoleStepOn") != {"Fn::Or": [{"Condition": "TailscaleOn"},
                                                      {"Condition": "UiActionsOn"}]}:
        errors.append("condition ConsoleStepOn is not TailscaleOn or UiActionsOn")
    rules = doc.get("Rules") or {}
    for name, want in TAILSCALE_RULES.items():
        if rules.get(name) != want:
            errors.append(f"rule {name} is missing or not exactly as required")
    for name, res in (doc.get("Resources") or {}).items():
        if name == EC2_ENDPOINT:
            errors += check_ec2_endpoint(res)
            continue
        if res.get("Type") in ("AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroup",
                               "AWS::EC2::EIP", "AWS::EC2::VPCEndpoint"):
            if res.get("Condition") in ("TailscaleOn", "ConsoleStepOn", "UiActionsOn"):
                errors.append(f"{res['Type']} {name} exists only with a console or tailnet switch")
    if EC2_ENDPOINT not in (doc.get("Resources") or {}):
        errors.append(f"no {EC2_ENDPOINT}: the host cannot read the S3 prefix list")
    return errors


# The node step's join: one up() with these flags exactly. Later flags win, so its callers
# may add only a timeout and the join key file, and nothing else in the step may run
# "tailscale up" or "tailscale set".
UP_LINE = ('up() { timeout 200 $T up --reset --hostname=${TailscaleHostname} --ssh=false '
           '--accept-routes=false --accept-dns=false --netfilter-mode=off --advertise-routes= '
           '--advertise-exit-node=false --exit-node= "$@"; }')
UP_EXTRA = re.compile(r"^(--timeout=\d+s|--auth-key=file:\$K)$")
NODE_LINES = {
    "the join flags are not exactly the required ones": UP_LINE,
    "tailscale serve does not proxy to the loopback console":
        "timeout 120 $T serve --bg --https=443 http://127.0.0.1:8480",
    "a rerun does not replace tailscale by rename": "mv -f $T.new $T",
    "a rerun does not replace tailscaled by rename": "mv -f $D.new $D",
    "a rerun does not restart tailscaled": "systemctl restart tailscaled.service",
    "the node's name is not compared with the expected one":
        '[ "$n" = ${TailscaleHostname}.${TailnetSuffix}. ] || { echo "tailscale: joined as $n, '
        'not ${TailscaleHostname}.${TailnetSuffix} (remove the old device); the console would '
        'refuse that name" >&2; exit 1; }',
}
NAME_LOOKUP = ("n=$($T status --json | python3 -c 'import json,sys; "
               "print(json.load(sys.stdin)[\"Self\"][\"DNSName\"])')")


def check_node_step(node: str) -> list[str]:
    lines = node.splitlines()
    errors = [msg for msg, line in NODE_LINES.items() if lines.count(line) != 1]
    serve = NODE_LINES["tailscale serve does not proxy to the loopback console"]
    if NAME_LOOKUP not in lines:
        errors.append("the node's name is not read from tailscale status")
    elif UP_LINE in lines and serve in lines and not (
            lines.index(UP_LINE) < lines.index(NAME_LOOKUP) < lines.index(serve)):
        errors.append("the node's name is not checked between the join and serve")
    if node.count("$T up") != 1 or node.count("tailscale up") or re.search(
            r"(\$T|tailscale) set\b", node):
        errors.append("the node step runs tailscale up or set outside up()")
    for line in lines:
        if line == UP_LINE:
            continue
        for m in re.finditer(r"(?:^|\|\||&&|;|then|do)\s*up\b([^|;&]*)", line):
            extra = [a for a in m.group(1).split() if not UP_EXTRA.match(a)]
            if extra:
                errors.append(f"up() is called with {' '.join(extra)[:60]}")
    for pattern, what in ((r"--advertise-routes=\S", "advertises routes"),
                          (r"--exit-node=\S", "uses an exit node"),
                          (r"funnel", "uses funnel"), (r"--auth-key=(?!file:\$K)", "passes a "
                          "join key other than the file")):
        if re.search(pattern, node, re.I):
            errors.append(f"the node step {what}")
    return errors


# The host files the image carries for the tailnet option (deploy/aws/host), copied out by
# the bootstrap. The Dockerfile must put them at /app/deploy/aws/host.
HOST_DIR = HERE / "host"
HOST_IN_IMAGE = "COPY deploy/aws/host ./deploy/aws/host"
# The exporter's limits once tcp 443 is open to anywhere (host/sensor-egress.sh): these
# lines, in this order, and no other iptables line.
EGRESS_RULES = [
    'w="iptables -w"',
    'u="-m owner --uid-owner 10001"',
    "$w -C OUTPUT $u -j REJECT 2>/dev/null || $w -I OUTPUT 1 $u -j REJECT",
    "ip6tables -w -C OUTPUT $u -j REJECT 2>/dev/null || ip6tables -w -I OUTPUT 1 $u -j REJECT",
    '[ "${1:-}" != deny ] || exit 0',
    "$w -N SENSOR-UID 2>/dev/null || $w -F SENSOR-UID",
    "$w -C OUTPUT $u -j SENSOR-UID 2>/dev/null || $w -I OUTPUT 1 $u -j SENSOR-UID",
    "$w -A SENSOR-UID -o tailscale0 -j REJECT",
    "$w -A SENSOR-UID -o lo -d 127.0.0.53 -p udp --dport 53 -j ACCEPT",
    "$w -A SENSOR-UID -o lo -d 127.0.0.53 -p tcp --dport 53 -j ACCEPT",
    "$w -A SENSOR-UID -d 169.254.169.254 -p tcp --dport 80 -j ACCEPT",
    "$w -A SENSOR-UID -d 169.254.169.253 -p udp --dport 53 -j ACCEPT",
    '$w -A SENSOR-UID -d "$VPC_CIDR" -p udp --dport 53 -j ACCEPT',
    '$w -A SENSOR-UID -d "$VPC_CIDR" -p tcp --dport 443 -j ACCEPT',
    'for c in $(cat "$C" 2>/dev/null || :); do if good "$c"; then $w -A SENSOR-UID '
    '-d "$c" -p tcp --dport 443 -j ACCEPT; fi; done',
    # INTERNETDB_LOOKUP=true only: one /32 per pinned InternetDB address, after the rest.
    '[ "$IDB" != true ] || for a in $(head -n 8 "$I" 2>/dev/null || :); do if pub "$a"; then '
    '$w -A SENSOR-UID -d "$a/32" -p tcp --dport 443 -j ACCEPT; fi; done',
    # OTX_SUBMIT=true only: the same for the pinned OTX addresses, last.
    '[ "$OTX" != true ] || for a in $(head -n 8 "$O" 2>/dev/null || :); do if pub "$a"; then '
    '$w -A SENSOR-UID -d "$a/32" -p tcp --dport 443 -j ACCEPT; fi; done',
]
# The deny comes before the settings are read, so a bad or missing settings file leaves
# uid 10001 with no egress at all.
EGRESS_SETTINGS = '. "${SENSOR_EGRESS_ENV:-/etc/sensor-egress.env}"'
EGRESS_IP4 = 'ip4="^[0-9]{1,3}(\\.[0-9]{1,3}){3}/[0-9]{1,2}$"'
EGRESS_GOOD = 'good() { [[ $1 =~ $ip4 ]] && [ "${1#*/}" -ge 8 ] && [ "${1#*/}" -le 32 ]; }'
# The step that installs it: its settings, the hooks into the boot-time firewall (including
# the DOCKER-USER drop of tailnet traffic) and the first run, none of them allowed to fail.
EGRESS_STEP_LINES = [
    "printf 'REGION=%s\\nPREFIX_LIST=%s\\nVPC_CIDR=%s\\n' ${AWS::Region} ${S3PrefixListId} "
    "${VpcCidr} > /etc/sensor-egress.env",
    "H=/app/deploy/aws/host",
    'docker run --rm --network none --entrypoint cat "$IMAGE" $H/sensor-egress.sh | install '
    "-m 0700 /dev/stdin /usr/local/sbin/sensor-egress.sh",
    "for u in sensor-egress.service sensor-egress.timer sensor-egress-boot.service; do docker run --rm --network none "
    '--entrypoint cat "$IMAGE" $H/$u > /etc/systemd/system/$u; done',
    "F=/usr/local/sbin/sensor-firewall.sh",
    "grep -q tailscale0 $F || echo 'add -i tailscale0 -j DROP' >> $F",
    "grep -q sensor-egress $F || echo /usr/local/sbin/sensor-egress.sh >> $F",
    "/usr/local/sbin/sensor-egress.sh refresh",
    "$F",
    "systemctl daemon-reload",
    "systemctl enable --now sensor-egress-boot.service sensor-egress.timer",
]
EGRESS_UNITS = {
    "sensor-egress.service": ["Type=oneshot", "ExecStart=/usr/local/sbin/sensor-egress.sh refresh"],
    "sensor-egress.timer": ["OnBootSec=2min", "OnUnitActiveSec=15min", "WantedBy=timers.target"],
}
# The rules at every boot, before Docker restarts the containers: Docker requires the unit,
# whose first step (the deny) may not fail and whose second (the full rules) may. Exactly
# these ExecStart lines, in this order, and nothing that loosens the hold on Docker.
EGRESS_BOOT_UNIT = "sensor-egress-boot.service"
EGRESS_BOOT_LINES = ["Before=docker.service", "Type=oneshot", "RemainAfterExit=yes",
                     "ExecStart=/usr/local/sbin/sensor-egress.sh deny",
                     "ExecStart=-/usr/local/sbin/sensor-egress.sh", "RequiredBy=docker.service"]
EGRESS_BOOT_EXEC = ["ExecStart=/usr/local/sbin/sensor-egress.sh deny", "ExecStart=-/usr/local/sbin/sensor-egress.sh"]
EGRESS_BOOT_FORBIDDEN = ("After=docker", "Wants=docker", "WantedBy=", "DefaultDependencies=no", "ExecStartPre=",
                         "ExecStartPost=", "SuccessExitStatus=", "Condition", "Assert")
# The node's unit (host/tailscaled.service) and what the node step writes for it.
TAILSCALED_LINES = [
    "EnvironmentFile=/etc/sensor-tailscale.env",
    "ExecStart=/usr/local/sbin/tailscaled --statedir=/var/lib/tailscale --state=${TS_STATE}",
    "NoNewPrivileges=yes", "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE",
    "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "ProtectKernelModules=yes",
    "RestrictSUIDSGID=yes", "MemoryDenyWriteExecute=yes", "DevicePolicy=closed",
    "DeviceAllow=/dev/net/tun rw", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
]
NODE_STEP_LINES = [
    "printf 'TS_STATE=arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter/"
    "${NamePrefix}/tailscale-state\\n' > /etc/sensor-tailscale.env",
    'docker run --rm --network none --entrypoint cat "$IMAGE" /app/deploy/aws/host/'
    "tailscaled.service > /etc/systemd/system/tailscaled.service && "
    '/usr/local/sbin/sensor-tailscale.sh || echo "tailscale: FAILED ($?)"',
]


def check_boot_unit(unit: str) -> list[str]:
    """sensor-egress-boot.service: the uid 10001 rules before Docker, and Docker held without them."""
    lines = [line.strip() for line in unit.splitlines()]
    errors = [f"{EGRESS_BOOT_UNIT} lacks {n}" for n in EGRESS_BOOT_LINES if n not in lines]
    if [line for line in lines if line.startswith("ExecStart")] != EGRESS_BOOT_EXEC:
        errors.append(f"{EGRESS_BOOT_UNIT} does not run exactly the deny (may not fail) and then the "
                      "full rules")
    for line in lines:
        if not line.startswith("#") and line.startswith(EGRESS_BOOT_FORBIDDEN):
            errors.append(f"{EGRESS_BOOT_UNIT} weakens its hold on Docker: {line[:60]}")
    return errors


def check_host_files(egress: Optional[str] = None, units: Optional[dict] = None,
                     tailscaled: Optional[str] = None, dockerfile: Optional[str] = None,
                     boot: Optional[str] = None) -> list[str]:
    """The files under deploy/aws/host that the image carries for the tailnet option."""
    egress = (HOST_DIR / "sensor-egress.sh").read_text(encoding="utf-8") if egress is None \
        else egress
    units = units if units is not None else {
        n: (HOST_DIR / n).read_text(encoding="utf-8") for n in EGRESS_UNITS}
    tailscaled = (HOST_DIR / "tailscaled.service").read_text(encoding="utf-8") \
        if tailscaled is None else tailscaled
    boot = (HOST_DIR / EGRESS_BOOT_UNIT).read_text(encoding="utf-8") if boot is None else boot
    dockerfile = DOCKERFILE.read_text(encoding="utf-8") if dockerfile is None else dockerfile
    errors: list[str] = []
    if HOST_IN_IMAGE not in dockerfile.splitlines():
        errors.append("the Dockerfile does not put deploy/aws/host at /app/deploy/aws/host")
    script = egress.splitlines()
    positions = [script.index(r) if r in script else -1 for r in EGRESS_RULES]
    if -1 in positions:
        errors.append(f"the exporter's egress rules lack: {EGRESS_RULES[positions.index(-1)][:70]}")
    elif positions != sorted(positions):
        errors.append("the exporter's egress rules are out of order")
    for line in script:
        if not line.lstrip().startswith("#") and re.search(r"iptables|SENSOR-UID|OUTPUT", line) \
                and line not in EGRESS_RULES:
            errors.append(f"the egress script has an extra rule: {line[:70]}")
    if EGRESS_IP4 not in script or EGRESS_GOOD not in script:
        errors.append("the egress script does not validate CIDRs")
    if "set -euo pipefail" not in script:
        errors.append("the egress script does not stop on errors")
    deny = [script.index(r) if r in script else -1 for r in EGRESS_RULES[2:5]]
    if EGRESS_SETTINGS not in script or -1 in deny or max(deny) > script.index(EGRESS_SETTINGS):
        errors.append("the egress script does not install the deny before it reads its settings")
    errors += check_boot_unit(boot)
    for name, needed in EGRESS_UNITS.items():
        lines = units.get(name, "").splitlines()
        if any(n not in lines for n in needed):
            errors.append(f"{name} does not refresh the prefix list as required")
    errors += check_model_host()
    lines = tailscaled.splitlines()
    for needed in TAILSCALED_LINES:
        if needed not in lines:
            errors.append(f"tailscaled.service lacks {needed}")
    if sum(1 for line in lines if line.startswith("ExecStart=")) != 1:
        errors.append("tailscaled.service has more than one ExecStart")
    return errors


def check_egress_step(step: str) -> list[str]:
    lines = step.splitlines()
    errors = [f"the egress step lacks the line: {line[:70]}" for line in EGRESS_STEP_LINES
              if lines.count(line) != 1]
    if [line for line in lines if line.strip()] != EGRESS_STEP_LINES:
        errors.append("the egress step runs something other than its required lines")
    return errors


def _overlay(script: str, name: str):
    m = re.search(r"printf '(services:.*?)' > " + re.escape(name), script)
    if not m:
        return None
    try:
        return yaml.safe_load(m.group(1).encode().decode("unicode_escape"))
    except yaml.YAMLError:
        return None


# The console step's compose overlays, exactly: the token file for the ui service, and with
# UiActions its two read-write mounts.
TAILNET_OVERLAY = {"services": {"ui": {"env_file": ["./ui-token.env"]}}}
ACTIONS_OVERLAY = {"services": {"ui": {"volumes": UI_ACTIONS_MOUNTS}}}


def check_console_step(console: str) -> list[str]:
    errors: list[str] = []
    if _overlay(console, "docker-compose.tailnet.yml") != TAILNET_OVERLAY:
        errors.append("the tailnet overlay is not exactly the token file for the ui service")
    if _overlay(console, "docker-compose.actions.yml") != ACTIONS_OVERLAY:
        errors.append("the actions overlay changes more than the agent data and blocklist "
                      "mounts")
    added = re.findall(r"^f=\$f:(\S+)$", console, re.M)
    if added != ["docker-compose.tailnet.yml", "docker-compose.actions.yml"] or \
            "f=docker-compose.yml:docker-compose.override.yml" not in console.splitlines():
        errors.append("COMPOSE_FILE lists files other than the base, override and the two "
                      "overlays")
    lines = console.splitlines()
    rewrite = ["sed -i '/^COMPOSE_FILE=/d' .env", 'echo "COMPOSE_FILE=$f" >> .env']
    if not all(r in lines for r in rewrite) or lines.index(rewrite[0]) + 1 != lines.index(
            rewrite[1]):
        errors.append("a rerun appends another COMPOSE_FILE line instead of rewriting it")
    return errors


def _step_body(variables: dict, step: str) -> str:
    return text((variables.get(step) or {}).get("Fn::If", [None, ""])[1])


def check_user_data_steps(doc: dict, base64_value) -> list[str]:
    """The optional bootstrap steps: off they render to nothing, on they keep the lines
    above, and the whole script fits EC2's limit with every switch on."""
    errors: list[str] = []
    sub = (base64_value or {}).get("Fn::Sub") if isinstance(base64_value, dict) else None
    if not isinstance(sub, list) or len(sub) != 2:
        return ["the user data is not a !Sub with variables"]
    variables = sub[1]
    steps = {"EgressStep": HOST_EGRESS, "ConsoleStep": "ConsoleStepOn",
             "TailscaleNodeStep": "TailscaleOn", "ModelStep": "ModelOn"}
    for step, cond in steps.items():
        value = variables.get(step)
        if not (isinstance(value, dict) and "Fn::If" in value
                and value["Fn::If"][0] == cond and value["Fn::If"][2] == ""):
            errors.append(f"step {step} is not empty unless {cond}")
    lines = sub[0].splitlines()
    if "${IdbEgress}${OtxStep}${EgressStep}${ConsoleStep}${ModelStep}cat > "\
            "/etc/systemd/system/sensor.service <<'EOF'" not in lines:
        errors.append("the egress, console and model steps do not run, in that order, right "
                      "before the stack is started")
    otx_step = variables.get("OtxStep")
    if not (isinstance(otx_step, dict) and _branch(otx_step, "OtxOn")
            and otx_step["Fn::If"][2] == ""
            and [line for line in _step_body(variables, "OtxStep").splitlines()
                 if line.strip()] == OTX_STEP_LINES):
        errors.append("step OtxStep is not exactly the host firewall switch and the key file, "
                      "and empty unless OtxOn")
    if variables.get("IdbEgress") != {"Fn::If": ["IdbLookupOn", IDB_EGRESS_SWITCH, ""]}:
        errors.append("step IdbEgress is not exactly the InternetDB switch for the host "
                      "firewall, and empty unless IdbLookupOn")
    if '${TailscaleNodeStep}echo "bootstrap complete"' not in lines:
        errors.append("the node step does not run after the stack is up")
    errors += check_egress_step(_step_body(variables, "EgressStep"))
    node = _step_body(variables, "TailscaleNodeStep")
    errors += check_node_step(node)
    tail = node.split("\nEOF\n", 1)[-1].splitlines()
    if [line for line in tail if line.strip()] != NODE_STEP_LINES:
        errors.append("the node step does not write the state ARN and the unit exactly as "
                      "required")
    errors += check_console_step(_step_body(variables, "ConsoleStep"))
    if [line for line in _step_body(variables, "ModelStep").splitlines() if line.strip()] \
            != MODEL_STEP_LINES:
        errors.append("the model step is not exactly its settings, the script from the image "
                      "and the setup run")
    size, problems = user_data_size(doc, base64_value)
    errors += problems
    if size > USER_DATA_LIMIT:
        errors.append(f"the user data is {size} bytes at the longest allowed values, over "
                      f"EC2's {USER_DATA_LIMIT}")
    return errors


USER_DATA_FACTS = {
    "sshd is not masked": "systemctl mask sshd.service",
    "the Docker userland proxy is not off": '"userland-proxy": false',
    "containers can reach the metadata service":
        "add -i br-+ -d 169.254.169.254/32 -j DROP",
    "the front-end network can open connections":
        "add -s 172.30.0.0/24 -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP",
    "the agents network can open connections":
        "add -s 172.30.1.0/24 -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP",
    "the firewall script is not what the boot-time unit runs":
        "ExecStart=/usr/local/sbin/sensor-firewall.sh",
    "the Compose plugin is not taken from the repository": "docker cp \"$cid:/docker-compose\"",
    "the exporter does not get its own config": "./config-ship.ini:/config/config.ini:ro",
    "the tracked key is not under the events prefix": "${EventsPrefix}/${TrackedKey}",
}
# The bootstrap copies render_config.py out of the image built from this repository; the
# Dockerfile must put it there, and the host runs it with Amazon Linux 2023's Python 3.9.
RENDER_SCRIPT = HERE / "render_config.py"
DOCKERFILE = HERE.parents[1] / "Dockerfile"
RENDER_COPY = ('docker run --rm --network none --entrypoint cat "$IMAGE" '
               '/app/deploy/aws/render_config.py > render_config.py')
RENDER_IN_IMAGE = "COPY deploy/aws/render_config.py ./deploy/aws/render_config.py"
HOST_PYTHON = (3, 9)
RENDER_FACTS = {
    "passwords are not hashed in the export": '"passwords": "hash"',
    "the tracked export is not read from the blocklist mount": '"file": "/blocklist/tracked.json"',
}


def _branch(got, condition: str):
    branch = got.get("Fn::If") if isinstance(got, dict) else None
    if isinstance(branch, list) and len(branch) == 3 and branch[0] == condition:
        return branch
    return None


def internetdb_user_data(user_data: str, variables: dict, on) -> tuple[str, list[str]]:
    """The user data with the InternetDB variables rendered for ``on`` (False: both
    switches off; True: InternetDbDelivered; "lookup": InternetDbLookup), and any variable
    that is not exactly its expected value for each switch and "" with both off."""
    errors: list[str] = []
    for name, value in IDB_VARIABLES.items():
        got = variables.get(name)
        lookup = IDB_LOOKUP_VARIABLES[name]
        if name in IDB_SHARED:
            branch = _branch(got, "IdbAnyOn")
            ok = branch is not None and value == lookup and text(branch[1]) == value \
                and branch[2] == ""
        else:
            branch = _branch(got, "InternetDbOn")
            inner = _branch(branch[2], "IdbLookupOn") if branch else None
            ok = inner is not None and text(branch[1]) == value and text(inner[1]) == lookup \
                and inner[2] == ""
        if not ok:
            errors.append(f"user data variable {name} is not exactly its InternetDbDelivered "
                          "or InternetDbLookup value, and empty when off")
        user_data = user_data.replace("${" + name + "}", lookup if on == "lookup"
                                      else value if on else "")
    return user_data, errors


def otx_user_data(user_data: str, variables: dict, otx, internetdb=False) -> tuple[str, list[str]]:
    """The user data with the OTX variables rendered for ``otx`` (False: OtxSubmit off, or
    its value), and a problem for any variable that is not exactly as required."""
    errors = [f"user data variable {name} is not exactly its OtxSubmit value, and empty "
              "when off" for name, want in OTX_VARIABLES.items() if variables.get(name) != want]
    mount = OTX_KEY_MOUNT + ("" if internetdb == "lookup" else OTX_EGRESS_MOUNT)
    user_data = user_data.replace("${OtxArgs}", f" otx-{otx}" if otx else "")
    return user_data.replace("${OtxMount}", mount if otx else ""), errors


def check_internetdb_switch(doc: dict) -> list[str]:
    errors: list[str] = []
    params = doc.get("Parameters") or {}
    for switch in ("InternetDbDelivered", "InternetDbLookup", "OtxSubmit"):
        if (params.get(switch) or {}).get("Default") != "false":
            errors.append(f"parameter {switch} is not off by default")
    if (params.get("OtxSubmit") or {}).get("AllowedValues") != ["false", *OTX_VALUES]:
        errors.append("parameter OtxSubmit allows other values than false, dry-run and send")
    conditions = doc.get("Conditions") or {}
    for name, want in IDB_CONDITIONS.items():
        if conditions.get(name) != want:
            errors.append(f"condition {name} is not exactly as required")
    if (doc.get("Rules") or {}).get("InternetDbOneWay") != IDB_RULE:
        errors.append("rule InternetDbOneWay does not refuse InternetDbLookup with "
                      "InternetDbDelivered")
    key = params.get("InternetDbAnswersKey") or {}
    pattern = key.get("AllowedPattern")
    if not isinstance(pattern, str) or any(re.search(pattern, k) for k in TRACKED_KEY_ESCAPES) \
            or not re.fullmatch(pattern, str(key.get("Default"))):
        errors.append("parameter InternetDbAnswersKey allows a key that is not one plain key")
    return errors


def _conditional(item, condition: str, statement: dict) -> Optional[bool]:
    """None for a plain statement; True when ``item`` is exactly ``statement`` under
    ``condition`` and nothing otherwise; False for any other conditional."""
    if not (isinstance(item, dict) and "Fn::If" in item):
        return None
    branch = item["Fn::If"]
    return isinstance(branch, list) and len(branch) == 3 and branch[0] == condition \
        and branch[1] == statement and branch[2] == {"Ref": "AWS::NoValue"}


def check_endpoint_policy(doc: dict) -> list[str]:
    """The S3 gateway endpoint: the only conditional statement is the answers read."""
    errors: list[str] = []
    for name, ep in resources(doc, "AWS::EC2::VPCEndpoint").items():
        policy = (ep.get("Properties") or {}).get("PolicyDocument") or {}
        for item in as_list(policy.get("Statement") or []):
            if _conditional(item, "InternetDbOn", IDB_ENDPOINT_STATEMENT) is False:
                errors.append(f"endpoint {name} has a conditional statement other than the "
                              "InternetDB answers read")
    return errors


def check_user_data(user_data: str, render_script: Optional[str] = None,
                    dockerfile: Optional[str] = None, internetdb=False, otx=False) -> list[str]:
    errors = [msg for msg, needle in USER_DATA_FACTS.items() if needle not in user_data]
    ships = re.findall(r"python -m agents ship[^\"\]]*", user_data)
    if not ships:
        errors.append("nothing runs python -m agents ship")
    for cmd in ships:
        for opt in ("--config", "--log", "--data-dir /data", "--state-dir"):
            if opt not in cmd:
                errors.append(f"the ship command lacks {opt}")
    compose = embedded_compose(user_data)
    errors += check_ui(compose)
    if compose is not None:
        errors += check_exporter(compose, internetdb, otx) + check_blocklist(compose) \
            + check_configs(compose) + check_internetdb_volume(compose, internetdb, otx)
    errors += check_render(user_data, render_script, dockerfile, internetdb, otx)
    errors += check_host_files(dockerfile=dockerfile)
    return errors


def check_render(user_data: str, script: Optional[str] = None,
                 dockerfile: Optional[str] = None, internetdb=False, otx=False) -> list[str]:
    """render_config.py as the image carries it, run on the repository's config template:
    the tracked export is on only when shipping and TrackedExport both are, and the agents'
    config.ini keeps every transport off (only config-ship.ini, the exporter's, ships)."""
    script = RENDER_SCRIPT.read_text(encoding="utf-8") if script is None else script
    dockerfile = DOCKERFILE.read_text(encoding="utf-8") if dockerfile is None else dockerfile
    errors: list[str] = []
    if RENDER_COPY not in user_data.splitlines():
        errors.append("the bootstrap does not copy render_config.py out of the image")
    docker_lines = dockerfile.splitlines()
    if RENDER_IN_IMAGE not in docker_lines or "WORKDIR /app" not in docker_lines:
        errors.append("the Dockerfile does not put render_config.py at "
                      "/app/deploy/aws/render_config.py")
    try:
        import ast
        ast.parse(script, feature_version=HOST_PYTHON)
    except SyntaxError:
        errors.append("render_config.py does not parse as Python 3.9 (the host's python3)")
    errors += [msg for msg, needle in RENDER_FACTS.items() if needle not in script]
    tail = re.escape(IDB_LOOKUP_VARIABLES["IdbArgs"]) if internetdb == "lookup" else \
        re.escape(IDB_VARIABLES["IdbArgs"]) if internetdb else ""
    tail += re.escape(f" otx-{otx}") if otx else ""
    calls = dict(re.findall(r'^python3 render_config\.py config\.ini\.TEMPLATE (\S+) \$ARGS '
                            r'"\$NEVER" (\S+)' + tail + '$', user_data, re.M))
    if not re.search(r'^NEVER="\$\{NeverActOn\}"$', user_data, re.M):
        errors.append("render_config.py does not get NeverActOn")
    if calls != RENDER_CALLS:
        errors.append("the configs are not rendered as config.ini without shipping and "
                      "config-ship.ini with it")
    args = re.search(r'^ARGS="([^"]*)"$', user_data, re.M)
    words = args.group(1).split() if args else []
    if len(words) <= TRACKED_ARG or words[TRACKED_ARG] != "${TrackedExport}":
        errors.append("render_config.py does not get TrackedExport as its tracked switch")
    for ship in ("true", "false"):
        for tracked in ("true", "false"):
            got = _render(script, ship, tracked)
            if got is None:
                errors.append(f"render_config.py fails with shipping {ship} and "
                              f"TrackedExport {tracked}")
                continue
            want = {("connector.tracked_export", "enabled"):
                    "true" if ship == tracked == "true" else "false",
                    ("connector.s3_events", "enabled"): ship,
                    ("respond", "track_before_enforce"): tracked}
            for (section, key), value in want.items():
                if got.get((section, key)) != value:
                    errors.append(f"with shipping {ship} and TrackedExport {tracked} the "
                                  f"rendered [{section}] {key} is not {value}")
    if internetdb == "lookup":
        for ship in ("true", "false"):
            got = _render_internetdb(script, ship, "lookup")
            want = {("connector.internetdb", "mode"): "delivered",
                    ("connector.internetdb", "answers_file"): "/internetdb/internetdb.json",
                    ("connector.internetdb", "wanted_file"):
                        "/blocklist/internetdb_wanted.json" if ship == "true" else None,
                    ("connector.internetdb_exchange", "enabled"): ship,
                    ("connector.internetdb_exchange", "kind"): "lookup",
                    ("connector.internetdb_exchange", "addresses_file"):
                        "/egress/internetdb-addresses",
                    ("connector.internetdb_exchange", "wanted_key"): None,
                    ("connector.internetdb_exchange", "answers_key"): None}
            if got is None or any(got.get(k) != v for k, v in want.items()):
                errors.append(f"with shipping {ship} and InternetDbLookup the rendered "
                              "InternetDB settings are not delivered mode with the lookup "
                              "exchange on for the exporter only")
    elif internetdb:
        for ship in ("true", "false"):
            got = _render_internetdb(script, ship)
            want = {("connector.internetdb", "mode"): "delivered",
                    ("connector.internetdb", "answers_file"): "/internetdb/internetdb.json",
                    ("connector.internetdb", "wanted_file"):
                        "/blocklist/internetdb_wanted.json" if ship == "true" else None,
                    ("connector.internetdb_exchange", "enabled"): ship,
                    ("connector.internetdb_exchange", "wanted_key"): "events/internetdb/wanted.json",
                    ("connector.internetdb_exchange", "answers_key"): "internetdb/answers.json"}
            if got is None or any(got.get(k) != v for k, v in want.items()):
                errors.append(f"with shipping {ship} and InternetDbDelivered the rendered "
                              "InternetDB settings are not delivered mode with the exchange "
                              "on for the exporter only")
    if otx:
        kind = "lookup" if internetdb == "lookup" else "s3" if internetdb else None
        for ship in ("true", "false"):
            got = _render_otx(script, ship, otx, kind)
            on_ship = ship == "true"
            want = {"enabled": "true", "submit": ship,
                    "dry_run": "false" if otx == "send" else "true",
                    "secret_file": "/run/otx-key" if on_ship else None,
                    "candidates_file": "/blocklist/otx_candidates.json" if on_ship else None,
                    "addresses_file": "/egress/otx-addresses" if on_ship else None,
                    "secret_env": None}
            if got is None or any(got.get(k) != v for k, v in want.items()):
                errors.append(f"with shipping {ship} and OtxSubmit {otx} the rendered OTX "
                              "settings do not submit from the exporter only, with its key "
                              "file and pinned addresses")
    return errors


@functools.lru_cache(maxsize=24)
def _render_otx(script: str, ship: str, otx: str, kind: Optional[str]) -> Optional[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "render_config.py"
        path.write_text(script, encoding="utf-8")
        out = Path(tmp) / "config.ini"
        idb = [] if kind is None else ["lookup"] if kind == "lookup" else \
            ["true", "events/internetdb/wanted.json", "internetdb/answers.json"]
        try:
            subprocess.run([sys.executable, "-I", str(path), str(CONFIG_TEMPLATE), str(out),
                            "winnie-sensor", "example", "192.0.2.10", "false",
                            "example-events", "events", "us-east-1", "123456789012", "false",
                            "events/tracked/tracked.json", "", ship, *idb, f"otx-{otx}"],
                           check=True, capture_output=True, timeout=60, cwd=tmp)
        except (OSError, subprocess.SubprocessError):
            return None
        cp = configparser.ConfigParser(interpolation=None, strict=False)
        cp.read(out, encoding="utf-8")
        return {k: cp.get("connector.otx", k, fallback=None)
                for k in ("enabled", "submit", "dry_run", "secret_file", "secret_env",
                          "candidates_file", "addresses_file")}


@functools.lru_cache(maxsize=8)
def _render_internetdb(script: str, ship: str, kind: str = "s3") -> Optional[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "render_config.py"
        path.write_text(script, encoding="utf-8")
        out = Path(tmp) / "config.ini"
        try:
            subprocess.run([sys.executable, "-I", str(path), str(CONFIG_TEMPLATE), str(out),
                            "winnie-sensor", "example", "192.0.2.10", "false",
                            "example-events", "events", "us-east-1", "123456789012", "false",
                            "events/tracked/tracked.json", "", ship]
                           + (["lookup"] if kind == "lookup" else
                              ["true", "events/internetdb/wanted.json",
                               "internetdb/answers.json"]),
                           check=True, capture_output=True, timeout=60, cwd=tmp)
        except (OSError, subprocess.SubprocessError):
            return None
        cp = configparser.ConfigParser(interpolation=None, strict=False)
        cp.read(out, encoding="utf-8")
        return {(s, k): cp.get(s, k, fallback=None)
                for s, k in (("connector.internetdb", "mode"),
                             ("connector.internetdb", "answers_file"),
                             ("connector.internetdb", "wanted_file"),
                             ("connector.internetdb_exchange", "enabled"),
                             ("connector.internetdb_exchange", "kind"),
                             ("connector.internetdb_exchange", "addresses_file"),
                             ("connector.internetdb_exchange", "wanted_key"),
                             ("connector.internetdb_exchange", "answers_key"))}


@functools.lru_cache(maxsize=16)
def _render(script: str, ship: str, tracked: str) -> Optional[dict]:
    """Run render_config.py on the config template; the switches it writes, or None."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "render_config.py"
        path.write_text(script, encoding="utf-8")
        out = Path(tmp) / "config.ini"
        try:
            subprocess.run([sys.executable, "-I", str(path), str(CONFIG_TEMPLATE), str(out),
                            "winnie-sensor", "example", "192.0.2.10", "false",
                            "example-events", "events", "us-east-1", "123456789012", tracked,
                            "events/tracked/tracked.json", "", ship],
                           check=True, capture_output=True, timeout=60, cwd=tmp)
        except (OSError, subprocess.SubprocessError):
            return None
        cp = configparser.ConfigParser(interpolation=None, strict=False)
        cp.read(out, encoding="utf-8")
        return {(s, k): cp.get(s, k, fallback=None)
                for s, k in (("connector.tracked_export", "enabled"),
                             ("connector.s3_events", "enabled"),
                             ("respond", "track_before_enforce"))}


def check_configs(compose: dict) -> list[str]:
    """Only the exporter mounts config-ship.ini; every other service mounts config.ini."""
    errors: list[str] = []
    for name, service in (compose.get("services") or {}).items():
        for source, _, _ in _mounts(service or {}):
            if source == "./config-ship.ini" and name != "exporter":
                errors.append(f"the {name} service mounts the exporter's config-ship.ini")
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


def _mounts(service: dict) -> list[tuple[str, str, bool]]:
    """(source, target, read-only) for each short-syntax volume of a compose service."""
    out = []
    for volume in as_list(service.get("volumes") or []):
        parts = str(volume).split(":")
        out.append((parts[0], parts[1] if len(parts) > 1 else "",
                    len(parts) > 2 and parts[2] == "ro"))
    return out


def check_exporter(compose: dict, internetdb=False, otx=False) -> list[str]:
    """The exporter holds the instance role, so it mounts its own config and state, the
    front-end log (read-only) and the blocklist directory (read-only), with
    InternetDbDelivered or InternetDbLookup the internetdb volume it writes, and with
    InternetDbLookup the host firewall's pinned addresses (read-only); nothing else."""
    allowed = dict(EXPORTER_MOUNTS)
    if internetdb:
        allowed["internetdb"] = IDB_MOUNTS["exporter"]
    if internetdb == "lookup" or otx:
        allowed[IDB_EGRESS_DIR] = ("/egress", True)
    if otx:
        allowed[OTX_KEY_FILE] = ("/run/otx-key", True)
    exporter = (compose.get("services") or {}).get("exporter")
    if not isinstance(exporter, dict):
        return ["the embedded compose file has no exporter service"]
    errors: list[str] = []
    if any(not isinstance(v, str) for v in as_list(exporter.get("volumes") or [])):
        errors.append("the exporter has a volume that is not in short syntax")
    sources = [source for source, _, _ in _mounts(exporter)]
    for source in allowed:
        if sources.count(source) != 1:
            errors.append(f"the exporter does not mount {source} exactly once")
    for source, target, read_only in _mounts(exporter):
        if source not in allowed:
            errors.append(f"the exporter mounts {source}")
            continue
        want_target, want_ro = allowed[source]
        if target != want_target:
            errors.append(f"the exporter mounts {source} at {target}")
        if want_ro and not read_only:
            errors.append(f"the exporter mounts {source} read-write")
    return errors


def check_internetdb_volume(compose: dict, internetdb, otx=False) -> list[str]:
    """Off: no internetdb volume anywhere. On: the exporter writes it, the agents and the
    console read it, each at /internetdb, and no other service mounts it."""
    errors: list[str] = []
    for name, service in (compose.get("services") or {}).items():
        egress = [s for s, _, _ in _mounts(service or {}) if s.startswith("/var/lib/sensor-egress")]
        if egress and (name != "exporter" or not (internetdb == "lookup" or otx)):
            errors.append(f"the {name} service mounts the host firewall's files")
        if any(s == OTX_KEY_FILE for s, _, _ in _mounts(service or {})) \
                and (name != "exporter" or not otx):
            errors.append(f"the {name} service mounts the OTX key file")
        got = [(t, ro) for s, t, ro in _mounts(service or {}) if s == "internetdb"]
        want = [IDB_MOUNTS[name]] if internetdb and name in IDB_MOUNTS else []
        if got != want:
            errors.append(f"the {name} service mounts the internetdb volume other than as "
                          "InternetDbDelivered requires")
    if ("internetdb" in (compose.get("volumes") or {})) != bool(internetdb):
        errors.append("the internetdb volume is declared without InternetDbDelivered, or "
                      "missing with it")
    return errors


def check_blocklist(compose: dict) -> list[str]:
    """Only the agents write the blocklist volume, at the blocklist file's directory."""
    errors: list[str] = []
    agents_write = False
    for name, service in (compose.get("services") or {}).items():
        for source, target, read_only in _mounts(service or {}):
            if source != "blocklist":
                continue
            if name == "agents":
                agents_write |= target == "/agents/reports/blocklist" and not read_only
            elif not read_only:
                errors.append(f"the blocklist volume is writable by the {name} service")
    if not agents_write:
        errors.append("the agents service does not write the blocklist volume at "
                      "/agents/reports/blocklist")
    if "blocklist" not in (compose.get("volumes") or {}):
        errors.append("the blocklist volume is not declared")
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
        statements = []
        for item in as_list(policy["PolicyDocument"]["Statement"]):
            kind = _conditional(item, "InternetDbOn", IDB_ROLE_STATEMENT)
            if kind is False:
                kind = _conditional(item, HOST_EGRESS, PREFIX_ROLE_STATEMENT)
            if kind is None:
                statements.append(item)
            elif kind is False:
                errors.append(f"instance role {name} has a conditional statement other than "
                              "the InternetDB answers read and the S3 prefix list read")
        errors += _check_statements(name, statements)
    # A role can be named in many forms (Ref, a Sub of its name, a literal), so every
    # separate policy resource is suspect: only the one tailnet policy may exist.
    for kind in ("AWS::IAM::ManagedPolicy", "AWS::IAM::Policy"):
        for pname in resources(doc, kind):
            errors.append(f"{kind} {pname} exists; the instance role's permissions must be "
                          "its own inline policy and InstanceTailscaleParameters only")
    for pname, policy in resources(doc, "AWS::IAM::RolePolicy").items():
        pprops = policy.get("Properties") or {}
        if pname != TAILSCALE_POLICY or pprops.get("RoleName") != {"Ref": name}:
            errors.append(f"role policy {pname} is not {TAILSCALE_POLICY} on the instance role")
            continue
        if policy.get("Condition") != "TailscaleOn":
            errors.append(f"role policy {pname} applies without TailscaleOn")
        errors += _check_statements(name, as_list(pprops["PolicyDocument"]["Statement"]),
                                    tailscale=True)
    return errors


def _check_statements(name: str, statements: list, tailscale: bool = False) -> list[str]:
    errors: list[str] = []
    allowed = ROLE_ACTIONS | ({"ssm:GetParameter", "ssm:PutParameter"} if tailscale else set())
    for st in statements:
        if st.get("Effect") != "Allow" or "NotAction" in st or "NotResource" in st:
            errors.append(f"instance role {name} has a statement that is not a plain Allow")
            continue
        actions = as_list(st.get("Action"))
        res = [text(r) for r in as_list(st.get("Resource"))]
        for action in actions:
            if "*" in action:
                errors.append(f"instance role {name} has a wildcard action {action}")
            elif action not in allowed:
                errors.append(f"instance role {name} allows {action}")
            if action == "ssm:PutParameter" and res != [TAILSCALE_STATE]:
                errors.append(f"instance role {name} may write a parameter other than "
                              "the Tailscale node state")
            if action == "ec2:GetManagedPrefixListEntries" and res != [PREFIX_LIST_ARN]:
                errors.append(f"instance role {name} reads a prefix list other than S3's")
            if action == "ssm:GetParameter" and not set(res) <= TAILSCALE_READS:
                errors.append(f"instance role {name} reads a parameter other than the "
                              "Tailscale state, join key and console token")
            if action.startswith("s3:") and (action != "s3:PutObject" or any(
                    not r.endswith("/${EventsPrefix}/*") for r in res)):
                errors.append(f"instance role {name} allows {action} outside the events prefix")
        if "*" in res and not set(actions) <= UNSCOPABLE:
            errors.append(f"instance role {name} uses Resource * for {', '.join(actions)}")
        if any(r != "*" and r.endswith(":*:*") for r in res):
            errors.append(f"instance role {name} has a wildcard resource")
        if any(r.startswith("arn:${AWS::Partition}:ssm:") and "*" in r for r in res):
            errors.append(f"instance role {name} has a wildcard parameter")
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


# ---- models on Bedrock --------------------------------------------------------------------

# The two model switches, the same in sensor.yaml and models.yaml. A model id is
# provider.name[:version] with an optional geographic inference profile prefix; names hold
# no dots, so a profile's foundation model is its second and third parts.
MODEL_PARAMS = ("PersonaModelId", "AnalystModelId")
PROFILE_PREFIXES = ("us", "us-gov", "eu", "apac", "jp", "au", "global")
MODEL_ID = r"^(((us|us-gov|eu|apac|jp|au|global)\.)?[a-z0-9-]+\.[a-z0-9-]+(:[a-z0-9]+){0,2})?$"
MODEL_IDS_GOOD = ("", "anthropic.claude-haiku-5-5", "amazon.nova-pro-v1:0",
                  "anthropic.claude-3-5-sonnet-20240620-v1:0") + tuple(
    f"{p}.anthropic.claude-haiku-5-5" for p in PROFILE_PREFIXES)
# Ids the pattern must refuse: wildcards, ARNs, paths, another name hidden behind a dot (the
# grant would name a different model), spaces and newlines (they reach config.ini and a
# shell variable).
MODEL_IDS_BAD = ("*", "anthropic.*", "anthropic.claude*", "us.*", "us.anthropic.claude.x",
                 "anthropic.claude.x", "arn:aws:bedrock:us-east-1::foundation-model/a.b",
                 "anthropic/claude", "a.b/../c", "a.b c", "a.b\nc", "a.b;c", "A.B", ".a.b",
                 "us.", "xx.anthropic.claude-x", "usgov.anthropic.claude-x",
                 "us-east-1.anthropic.claude-x", "ca.anthropic.claude-x", "eu.*",
                 "us-gov.anthropic.claude.x", "anthropic")
MODEL_CONDITIONS = {
    "PersonaOn": {"Fn::Not": [{"Fn::Equals": [{"Ref": "PersonaModelId"}, ""]}]},
    "AnalystOn": {"Fn::Not": [{"Fn::Equals": [{"Ref": "AnalystModelId"}, ""]}]},
    "ModelOn": {"Fn::Or": [{"Condition": "PersonaOn"}, {"Condition": "AnalystOn"}]},
}
# The base of the callers' role names; sensor-model.sh appends -persona or -analyst.
MODEL_ROLE = "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/${NamePrefix}-model"
# The sensor's model step: settings, the script out of the image, the setup run. Nothing
# else; everything it does is in deploy/aws/host/sensor-model.sh.
MODEL_STEP_LINES = [
    "printf 'REGION=%s\\nSUFFIX=%s\\nVPC_CIDR=%s\\nROLE_ARN=%s\\nPERSONA_MODEL=%s\\n"
    "ANALYST_MODEL=%s\\n' ${AWS::Region} ${AWS::URLSuffix} ${VpcCidr} " + MODEL_ROLE
    + ' "${PersonaModelId}" "${AnalystModelId}" > /etc/sensor-model.env',
    'docker run --rm --network none --entrypoint cat "$IMAGE" '
    "/app/deploy/aws/host/sensor-model.sh | install -m 0700 /dev/stdin "
    "/usr/local/sbin/sensor-model.sh",
    '/usr/local/sbin/sensor-model.sh setup "$IMAGE" || echo "model: FAILED ($?)"',
]


def check_model_param(name: str, param: dict) -> list[str]:
    errors: list[str] = []
    if param.get("Default") != "":
        errors.append(f"parameter {name} is not empty (off) by default")
    if param.get("AllowedPattern") != MODEL_ID:
        errors.append(f"parameter {name} does not use the model id pattern")
    pattern = param.get("AllowedPattern") if isinstance(param.get("AllowedPattern"), str) else ""
    loose = [b for b in MODEL_IDS_BAD if not pattern or re.fullmatch(pattern, b)]
    if loose:
        errors.append(f"parameter {name} accepts {loose[0]!r}")
    if pattern and any(not re.fullmatch(pattern, g) for g in MODEL_IDS_GOOD):
        errors.append(f"parameter {name} refuses a valid model id")
    if "MaxLength" not in param:
        errors.append(f"parameter {name} has no MaxLength")
    return errors


def check_model_switches(doc: dict) -> list[str]:
    """sensor.yaml: the model switches are off by default and add no resource here; the
    endpoints and the role are models.yaml's."""
    errors: list[str] = []
    params = doc.get("Parameters") or {}
    for name in MODEL_PARAMS:
        errors += check_model_param(name, params.get(name) or {})
    conditions = doc.get("Conditions") or {}
    for name, want in MODEL_CONDITIONS.items():
        if conditions.get(name) != want:
            errors.append(f"condition {name} is not as required")
    switches = set(MODEL_PARAMS) | set(MODEL_CONDITIONS)
    for name, res in (doc.get("Resources") or {}).items():
        if name == "LaunchTemplate":
            continue
        blob = json.dumps(res)
        if any(f'"{s}"' in blob or "${" + s + "}" in blob for s in switches) \
                or "bedrock" in blob.lower():
            errors.append(f"resource {name} depends on a model switch (sensor.yaml adds no "
                          "resource for models)")
    return errors


# The host script's rules: one accept per caller, from its fixed address to the endpoint's
# one address on tcp 443; the removal of caller accepts to any other address; nothing else.
MODEL_SCRIPT = HOST_DIR / "sensor-model.sh"
MODEL_CALLERS = ['[ -z "$PERSONA_MODEL" ] || callers+=(persona:172.30.0.10)',
                 '[ -z "$ANALYST_MODEL" ] || callers+=(analyst:172.30.1.10)']
MODEL_RULES = [
    '  iptables -w -C DOCKER-USER -s "${c#*:}" -d "$EP" -p tcp --dport 443 -j ACCEPT 2>/dev/null \\',
    '    || iptables -w -I DOCKER-USER 1 -s "${c#*:}" -d "$EP" -p tcp --dport 443 -j ACCEPT',
    "rules=$(iptables -w -S DOCKER-USER)",
    '  iptables -w -D DOCKER-USER -s "${BASH_REMATCH[1]}" -d "${BASH_REMATCH[2]}" -p tcp '
    '--dport 443 -j ACCEPT',
]
# Each caller's overlay names its own credentials directory, which holds its own role's
# credentials only: ssh (the persona) persona, agents (the analyst) analyst.
MODEL_SERVICES = ['    [ -z "$PERSONA_MODEL" ] || svc ssh frontend 172.30.0.10 persona',
                  '    [ -z "$ANALYST_MODEL" ] || svc agents backend 172.30.1.10 analyst']
MODEL_SCRIPT_FACTS = {
    "does not stop on errors": "set -euo pipefail",
    "does not use the model id pattern": "id='" + MODEL_ID + "'",
    "does not check the VPC range":
        "&& python3 -c 'import ipaddress as i,sys; n=i.ip_network(sys.argv[1]); "
        "sys.exit(not (n.is_private and 8 <= n.prefixlen <= 28))' \"$VPC_CIDR\" 2>/dev/null \\",
    "does not test addresses against the VPC":
        "inside() { python3 -c 'import ipaddress as i,sys; sys.exit(i.ip_address(sys.argv[1]) "
        "not in i.ip_network(sys.argv[2]))' \"$1\" \"$VPC_CIDR\" 2>/dev/null; }",
    "does not check the looked-up address is inside the VPC":
        'if [[ $a =~ ^[0-9]{1,3}(\\.[0-9]{1,3}){3}$ ]] && inside "$a"; then echo "$a" > '
        '"$S/endpoint"; break; fi',
    "does not check the endpoint address is inside the VPC":
        '[[ $EP =~ ^[0-9]{1,3}(\\.[0-9]{1,3}){3}$ ]] && inside "$EP" \\',
    "does not start its timer": "systemctl enable --now sensor-model.timer",
    "does not remove accepts to an old address":
        "stale='^-A DOCKER-USER -s (172\\.30\\.[01]\\.10)/32 -d ([0-9.]+)/32 -p tcp -m tcp "
        "--dport 443 -j ACCEPT$'",
    "removes more than caller accepts to an old address":
        '[[ $line =~ $stale ]] && [ "${BASH_REMATCH[2]}" != "$EP" ] || continue',
    "does not recreate only the callers when the address changed":
        '[ -z "$(docker compose ps -q --status running "$s" 2>/dev/null || :)" ] \\',
    "does not ask for one-hour credentials of the caller's own role":
        '--role-arn "$ROLE_ARN-$1" --role-session-name "sensor-$1" --duration-seconds 3600 \\',
    "does not write a caller's credentials into its own directory": '> "$D/$1/creds.new"; then',
    "does not make the credentials readable by uid 10001 only":
        'chmod 0400 "$D/$1/creds.new" "$D/$1/config.new"',
    "does not replace the credentials in one rename": 'mv -f "$D/$1/creds.new" "$D/$1/creds.json"',
    "does not keep each credentials directory for uid 10001 only":
        'install -d -m 0500 -o 10001 -g 10001 "$D/$1"',
    "does not keep the credentials root for root only": 'install -d -m 0700 "$D"',
    "does not check the overlay before it uses it":
        "COMPOSE_FILE=$f:docker-compose.model.new.yml docker compose config --quiet",
}
# The only modes the script sets: config.ini and the credentials, both 0400.
MODEL_CHMODS = ["chmod 0400 config.ini", 'chmod 0400 "$D/$1/creds.new" "$D/$1/config.new"']
MODEL_UNITS = {
    "sensor-model.service": ["Type=oneshot", "ExecStart=/usr/local/sbin/sensor-model.sh"],
    "sensor-model.timer": ["OnUnitActiveSec=15min", "WantedBy=timers.target"],
}
# Each caller's overlay: its fixed address, the endpoint's name, its own credentials
# directory read-only and two variables. Exactly this; nothing else of the service changes.
MODEL_OVERLAY = ("svc() { printf '  %s:\\n    networks: {%s: {ipv4_address: %s}}\\n    "
                 "extra_hosts: [\"%s:%s\"]\\n    environment: {AWS_CONFIG_FILE: /model/config, "
                 "AWS_EC2_METADATA_DISABLED: \"true\"}\\n    volumes: [\"%s/%s:/model:ro\"]\\n' "
                 "\"$1\" \"$2\" \"$3\" \"$NAME\" \"$EP\" \"$D\" \"$4\"; }")


def check_model_host(script: Optional[str] = None, units: Optional[dict] = None) -> list[str]:
    script = MODEL_SCRIPT.read_text(encoding="utf-8") if script is None else script
    units = units if units is not None else {
        n: (HOST_DIR / n).read_text(encoding="utf-8") for n in MODEL_UNITS}
    lines = script.splitlines()
    code = [x for x in lines if not x.lstrip().startswith("#")]
    errors = [f"sensor-model.sh {msg}" for msg, line in MODEL_SCRIPT_FACTS.items()
              if line.strip() not in [x.strip() for x in lines]]
    for line in code:
        if "iptables" in line and line not in MODEL_RULES:
            errors.append(f"sensor-model.sh has an extra rule: {line.strip()[:70]}")
        if re.search(r"\bchmod\b", line) and line.strip() not in MODEL_CHMODS:
            errors.append(f"sensor-model.sh sets another mode: {line.strip()[:70]}")
    if any(rule not in lines for rule in MODEL_RULES):
        errors.append("sensor-model.sh lacks its accept rule or its stale-accept removal")
    # One definition of each function the checks rely on (a later one would replace it).
    for fn in ("inside", "svc", "renew", "overlay"):
        if len([x for x in code if re.search(rf"(^|[;\s]|function\s+){fn}\s*\(\)", x)]) != 1:
            errors.append(f"sensor-model.sh defines {fn}() more than once")
    if [x for x in lines if "callers+=" in x] != MODEL_CALLERS:
        errors.append("sensor-model.sh opens the endpoint to callers other than the ssh and "
                      "agents containers' fixed addresses")
    if [x for x in lines if re.search(r"\bsvc \w", x)] != MODEL_SERVICES \
            or MODEL_OVERLAY not in [x.strip() for x in lines]:
        errors.append("sensor-model.sh's overlay changes more than the ssh and agents "
                      "containers' address, endpoint name, own credentials mount and variables")
    for name, needed in MODEL_UNITS.items():
        if any(n not in units.get(name, "").splitlines() for n in needed):
            errors.append(f"{name} does not renew the credentials as required")
    return errors


# ---- models.yaml: the grant, evaluated for sample ids ----

SAMPLE_ACCOUNT, SAMPLE_REGION = "123456789012", "us-east-1"
MODEL_RESOURCES = {"BedrockEndpoint": "AWS::EC2::VPCEndpoint",
                   "StsEndpoint": "AWS::EC2::VPCEndpoint", "PersonaRole": "AWS::IAM::Role",
                   "AnalystRole": "AWS::IAM::Role",
                   "InstanceAssumeModelRole": "AWS::IAM::RolePolicy"}
# Each caller's role: its condition, its name (sensor-model.sh assumes MODEL_ROLE-<who>
# into the directory only that caller mounts) and the parameter it may invoke.
MODEL_CALLER_ROLES = {"PersonaRole": ("PersonaOn", "persona", "PersonaModelId"),
                      "AnalystRole": ("AnalystOn", "analyst", "AnalystModelId")}
MODEL_SAMPLES = [("us.anthropic.claude-haiku-5-5", ""), ("", "eu.anthropic.claude-haiku-5-5"),
                 ("global.anthropic.claude-sonnet-5-5", "amazon.nova-pro-v1:0"),
                 ("us.anthropic.claude-haiku-5-5", "us.anthropic.claude-sonnet-5-5"),
                 ("apac.anthropic.claude-haiku-5-5", "us-gov.anthropic.claude-haiku-5-5"),
                 ("jp.anthropic.claude-haiku-5-5", "au.anthropic.claude-haiku-5-5")]
_IF = lambda cond, role: {"Fn::If": [cond, {"Fn::GetAtt": [role, "Arn"]}, {"Ref": "AWS::NoValue"}]}
MODEL_ROLE_ARNS = [_IF("PersonaOn", "PersonaRole"), _IF("AnalystOn", "AnalystRole")]
_NO_VALUE = object()


def expected_grant(model: str) -> set[str]:
    """What one model id may be invoked as: a plain id, its foundation model in this region;
    a profile id, the profile here and its foundation model in any region."""
    if not model:
        return set()
    parts = model.split(".")
    if parts[0] in PROFILE_PREFIXES and len(parts) == 3:
        return {f"arn:aws:bedrock:{SAMPLE_REGION}:{SAMPLE_ACCOUNT}:inference-profile/{model}",
                f"arn:aws:bedrock:*::foundation-model/{'.'.join(parts[1:])}"}
    return {f"arn:aws:bedrock:{SAMPLE_REGION}::foundation-model/{model}"}


def evaluate(node, doc: dict, values: dict):
    """CloudFormation's intrinsic functions, as far as models.yaml uses them."""
    if isinstance(node, list):
        out = [evaluate(n, doc, values) for n in node]
        return [o for o in out if o is not _NO_VALUE]
    if not isinstance(node, dict):
        return node
    if len(node) == 1:
        (key, arg), = node.items()
        if key == "Ref":
            return _NO_VALUE if arg == "AWS::NoValue" else values[arg]
        if key == "Condition":
            return evaluate(doc["Conditions"][arg], doc, values)
        if key == "Fn::If":
            cond = evaluate(doc["Conditions"][arg[0]], doc, values)
            return evaluate(arg[1] if cond else arg[2], doc, values)
        if key == "Fn::Equals":
            a, b = (evaluate(x, doc, values) for x in arg)
            return a == b
        if key == "Fn::Not":
            return not evaluate(arg[0], doc, values)
        if key == "Fn::Or":
            return any(evaluate(x, doc, values) for x in arg)
        if key == "Fn::And":
            return all(evaluate(x, doc, values) for x in arg)
        if key == "Fn::Split":
            return evaluate(arg[1], doc, values).split(arg[0])
        if key == "Fn::Select":
            return evaluate(arg[1], doc, values)[int(arg[0])]
        if key == "Fn::Join":
            return arg[0].join(evaluate(arg[1], doc, values))
        if key == "Fn::GetAtt":
            return values[".".join(arg)]
        if key == "Fn::Sub":
            template, local = (arg, {}) if isinstance(arg, str) else arg
            local = {k: evaluate(v, doc, values) for k, v in local.items()}
            return re.sub(r"\$\{([^}]*)\}",
                          lambda m: str(local.get(m.group(1), values.get(m.group(1)))), template)
    return {k: evaluate(v, doc, values) for k, v in node.items()}


def model_values(persona: str, analyst: str) -> dict:
    return {"AWS::Partition": "aws", "AWS::Region": SAMPLE_REGION,
            "AWS::AccountId": SAMPLE_ACCOUNT, "NamePrefix": "winnie-sensor",
            "PersonaModelId": persona, "AnalystModelId": analyst,
            "VpcId": "vpc-0example", "SubnetId": "subnet-0example",
            "EndpointSecurityGroupId": "sg-0example", "BedrockEndpoint": "vpce-0bedrock",
            "PersonaRole.Arn": f"arn:aws:iam::{SAMPLE_ACCOUNT}:role/winnie-sensor-model-persona",
            "AnalystRole.Arn": f"arn:aws:iam::{SAMPLE_ACCOUNT}:role/winnie-sensor-model-analyst"}


def _grant_problems(label: str, statements: list, want: set, role: bool) -> list[str]:
    errors: list[str] = []
    got: set[str] = set()
    for st in statements:
        if not isinstance(st, dict) or st.get("Effect") != "Allow" or "NotAction" in st \
                or "NotResource" in st or "NotPrincipal" in st:
            errors.append(f"{label} has a statement that is not a plain Allow")
            continue
        if as_list(st.get("Action")) != ["bedrock:InvokeModel"]:
            errors.append(f"{label} allows {', '.join(map(str, as_list(st.get('Action'))))}")
        if role and st.get("Condition") != {"StringEquals": {"aws:SourceVpce": "vpce-0bedrock"}}:
            errors.append(f"{label} is not limited to the bedrock-runtime endpoint")
        if not role and "Condition" in st:
            errors.append(f"{label} has a condition")
        got |= set(as_list(st.get("Resource")))
    if got - want:
        errors.append(f"{label} grants {', '.join(sorted(got - want))} beyond the configured "
                      "models")
    if want - got:
        errors.append(f"{label} lacks {', '.join(sorted(want - got))}")
    return errors


def check_models(doc: dict, raw: str = "") -> list[str]:
    """models.yaml: two endpoints and a role per caller, each passing bedrock:InvokeModel on
    exactly the configured models (each role: its own caller's model only), or assuming
    those roles, and nothing else."""
    errors: list[str] = []
    params = doc.get("Parameters") or {}
    for name in MODEL_PARAMS:
        errors += check_model_param(name, params.get(name) or {})
    res = doc.get("Resources") or {}
    for name, kind in MODEL_RESOURCES.items():
        if (res.get(name) or {}).get("Type") != kind:
            errors.append(f"no {kind} {name}")
    for name in res:
        if name not in MODEL_RESOURCES:
            errors.append(f"resource {name} is not one of the five the option needs")
        want_cond = MODEL_CALLER_ROLES.get(name, (None,))[0]
        if (res.get(name) or {}).get("Condition") != want_cond:
            errors.append(f"resource {name} has a condition other than "
                          f"{want_cond or 'none (the stack is the switch)'}")
    if errors:
        return ["models: " + e for e in errors]
    bedrock, sts = res["BedrockEndpoint"]["Properties"], res["StsEndpoint"]["Properties"]
    assume = res["InstanceAssumeModelRole"]["Properties"]
    for name, props, service in (("BedrockEndpoint", bedrock, "bedrock-runtime"),
                                 ("StsEndpoint", sts, "sts")):
        if props.get("ServiceName") != {"Fn::Sub": "com.amazonaws.${AWS::Region}." + service}:
            errors.append(f"endpoint {name} is not the {service} endpoint")
        if props.get("SecurityGroupIds") != [{"Ref": "EndpointSecurityGroupId"}]:
            errors.append(f"endpoint {name} is not behind the sensor's endpoint security group")
    # GetCallerIdentity needs no permission and only names the caller; the endpoint's private
    # name covers the whole VPC, so it is allowed for operators' sessions on the host.
    if sts.get("PolicyDocument") != {"Version": "2012-10-17", "Statement": [
            {"Sid": "AssumeModelRoles", "Effect": "Allow", "Principal": "*",
             "Action": "sts:AssumeRole", "Resource": MODEL_ROLE_ARNS},
            {"Sid": "WhoAmI", "Effect": "Allow", "Principal": "*",
             "Action": "sts:GetCallerIdentity", "Resource": "*"}]}:
        errors.append("endpoint StsEndpoint policy allows more than assuming the callers' "
                      "roles and GetCallerIdentity")
    host = {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/${NamePrefix}-host"}
    for name, (_, who, _) in MODEL_CALLER_ROLES.items():
        role = res[name]["Properties"]
        if role.get("RoleName") != {"Fn::Sub": "${NamePrefix}-model-" + who}:
            errors.append(f"{name} is not named {MODEL_ROLE.rsplit('/', 1)[1]}-{who}, the "
                          f"role whose credentials only the {who} caller mounts")
        if role.get("AssumeRolePolicyDocument") != {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": host}, "Action": "sts:AssumeRole"}]}:
            errors.append(f"{name} can be assumed by more than the sensor's instance role")
        if "ManagedPolicyArns" in role or "PermissionsBoundary" in role \
                or len(role.get("Policies") or []) != 1:
            errors.append(f"{name} has policies other than its one inline policy")
        if int(role.get("MaxSessionDuration", 3600)) > 3600:
            errors.append(f"{name} sessions may last more than an hour")
    if assume.get("RoleName") != {"Fn::Sub": "${NamePrefix}-host"} or \
            assume.get("PolicyDocument") != {"Version": "2012-10-17", "Statement": [
                {"Sid": "AssumeModelRoles", "Effect": "Allow", "Action": "sts:AssumeRole",
                 "Resource": MODEL_ROLE_ARNS}]}:
        errors.append("InstanceAssumeModelRole gives the instance role more than assuming "
                      "the callers' roles")
    for persona, analyst in MODEL_SAMPLES:
        values = model_values(persona, analyst)
        label = f"with {persona or '-'} / {analyst or '-'}"
        try:
            ep = evaluate(bedrock.get("PolicyDocument"), doc, values)["Statement"]
            errors += _grant_problems(f"{label} the endpoint policy", ep,
                                      expected_grant(persona) | expected_grant(analyst),
                                      role=False)
            for name, (cond, _, param) in MODEL_CALLER_ROLES.items():
                if not evaluate(doc["Conditions"][cond], doc, values):
                    continue
                rp = evaluate(res[name]["Properties"]["Policies"][0]["PolicyDocument"], doc,
                              values)["Statement"]
                errors += _grant_problems(f"{label} the {name} policy", as_list(rp),
                                          expected_grant(values[param]), role=True)
        except (KeyError, IndexError, TypeError, AttributeError, ValueError) as exc:
            errors.append(f"{label} the policies cannot be evaluated ({type(exc).__name__})")
    rules = doc.get("Rules") or {}
    if "NeedsAModel" not in rules:
        errors.append("no rule refuses a deploy with neither model set")
    return ["models: " + e for e in errors]


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
    for path, fn in ((SENSOR, check_sensor), (BUCKET, check_bucket), (MODELS, check_models)):
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
