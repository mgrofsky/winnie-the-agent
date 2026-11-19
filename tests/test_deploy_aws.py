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


def _agents_config_ships(d):
    _user_data_edit(d, 'config.ini.TEMPLATE config.ini $ARGS "$NEVER" false',
                    'config.ini.TEMPLATE config.ini $ARGS "$NEVER" true')


def _never_act_on_dropped(d):
    _user_data_edit(d, 'NEVER="${NeverActOn}"', 'NEVER=""')


def _tracked_arg_swapped(d):
    _user_data_edit(d, "${EventsBucketOwner} ${TrackedExport} ${EventsPrefix}/${TrackedKey}",
                    "${EventsBucketOwner} true ${EventsPrefix}/${TrackedKey}")


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


# ---- the tailnet option breaks --------------------------------------------------------------

def _steps(d):
    return _lt(d)["UserData"]["Fn::Base64"]["Fn::Sub"][1]


def _step_edit(d, step, old, new):
    body = _steps(d)[step]["Fn::If"][1]
    assert old in body["Fn::Sub"], old
    body["Fn::Sub"] = body["Fn::Sub"].replace(old, new)


def _tailscale_policy(d):
    return d["Resources"]["InstanceTailscaleParameters"]


def _tailscale_statements(d):
    return _tailscale_policy(d)["Properties"]["PolicyDocument"]["Statement"]


def _tailscale_default_on(d):
    d["Parameters"]["TailscaleEnabled"]["Default"] = "true"


def _sign_in_default_on(d):
    d["Parameters"]["UiTailnetSignIn"]["Default"] = "true"


def _actions_default_on(d):
    d["Parameters"]["UiActions"]["Default"] = "true"


def _tailscale_egress_always(d):
    del d["Resources"]["InstanceEgressTailscale"]["Condition"]


def _tailscale_egress_all_ports(d):
    d["Resources"]["InstanceEgressTailscale"]["Properties"]["ToPort"] = 65535


def _tailscale_egress_udp(d):
    d["Resources"]["InstanceEgressTailscale"]["Properties"]["IpProtocol"] = "-1"


def _other_egress_to_anywhere(d):
    d["Resources"]["InstanceEgressAnywhere"] = copy.deepcopy(
        d["Resources"]["InstanceEgressTailscale"])


def _tailnet_ingress(d):
    d["Resources"]["InTailnet"] = {
        "Type": "AWS::EC2::SecurityGroupIngress", "Condition": "TailscaleOn",
        "Properties": {"GroupId": {"Ref": "InstanceSecurityGroup"}, "IpProtocol": "udp",
                       "FromPort": 41641, "ToPort": 41641, "CidrIp": {"Ref": "InboundCidr"}}}


def _tailnet_security_group(d):
    d["Resources"]["TailnetGroup"] = copy.deepcopy(d["Resources"]["EndpointSecurityGroup"])
    d["Resources"]["TailnetGroup"]["Condition"] = "TailscaleOn"


def _policy_always(d):
    del _tailscale_policy(d)["Condition"]


def _put_any_parameter(d):
    _tailscale_statements(d)[0]["Resource"] = {
        "Fn::Sub": "arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter/*"}


def _put_join_key(d):
    _tailscale_statements(d)[1]["Action"] = ["ssm:GetParameter", "ssm:PutParameter"]


def _read_prefix(d):
    _tailscale_statements(d)[1]["Resource"].append({"Fn::Sub": check.SSM_PARAMETER + "*"})


def _read_other(d):
    _tailscale_statements(d)[1]["Resource"].append({"Fn::Sub": check.SSM_PARAMETER + "db-password"})


def _delete_parameter(d):
    _tailscale_statements(d)[0]["Action"].append("ssm:DeleteParameter")


def _ssm_wildcard_action(d):
    _tailscale_statements(d)[0]["Action"] = "ssm:*"


def _no_suffix_rule(d):
    d["Rules"]["TailscaleNeedsItsSettings"]["Assertions"].pop()


def _no_ui_rule(d):
    d["Rules"]["TailscaleNeedsItsSettings"]["Assertions"].pop(0)


def _no_sign_in_rule(d):
    del d["Rules"]["UiSignInNeedsTailscale"]


def _console_step_condition(d):
    d["Conditions"]["ConsoleStepOn"] = {"Condition": "TailscaleOn"}


def _netfilter_on(d):
    _step_edit(d, "TailscaleNodeStep", "--netfilter-mode=off", "--netfilter-mode=on")


def _tailscale_ssh(d):
    _step_edit(d, "TailscaleNodeStep", "--ssh=false", "--ssh=true")


def _accept_routes(d):
    _step_edit(d, "TailscaleNodeStep", "--accept-routes=false", "--accept-routes=true")


def _no_tailnet_drop(d):
    _step_edit(d, "EgressStep", "grep -q tailscale0 $F || echo 'add -i tailscale0 -j DROP' >> $F",
               "echo 'add -i tailscale0 -j DROP'")


def _state_on_disk(d):
    _step_edit(d, "TailscaleNodeStep", "TS_STATE=arn:", "TS_STATE=/var/lib/tailscale/x#arn:")


def _key_on_command_line(d):
    _step_edit(d, "TailscaleNodeStep", "--auth-key=file:$K", '--auth-key="$(cat $K)"')


def _funnel(d):
    _step_edit(d, "TailscaleNodeStep", "$T serve status", "$T funnel --bg 443")


def _serve_elsewhere(d):
    _step_edit(d, "TailscaleNodeStep", "http://127.0.0.1:8480", "http://172.30.0.2:8080")


def _node_step_always(d):
    _steps(d)["TailscaleNodeStep"]["Fn::If"][2] = "echo on\n"


def _actions_overlay_frontend(d):
    _step_edit(d, "ConsoleStep", "      - blocklist:/agents/reports/blocklist\\n",
               "      - blocklist:/agents/reports/blocklist\\n      - frontend:/data\\n")


def _user_data_too_big(d):
    _step_edit(d, "TailscaleNodeStep", "$T serve status", "$T serve status\n" + "#" * 4000)


# The review's cases: each passed the checker before it was tightened.

def _join_flags_appended(d):
    _step_edit(d, "TailscaleNodeStep", "up --timeout=60s", "up --timeout=60s --netfilter-mode=on --ssh")


def _join_key_call_with_more(d):
    _step_edit(d, "TailscaleNodeStep", "up --auth-key=file:$K --timeout=180s",
               "up --auth-key=file:$K --timeout=180s --accept-routes")


def _advertise_routes(d):
    _step_edit(d, "TailscaleNodeStep", "--advertise-routes= ", "--advertise-routes=0.0.0.0/0 ")


def _exit_node(d):
    _step_edit(d, "TailscaleNodeStep", "--exit-node= ", "--exit-node=peer ")


def _tailscale_set(d):
    _step_edit(d, "TailscaleNodeStep", "$T ip -4", "$T set --ssh\n$T ip -4")


def _drop_not_in_rule(d):
    d["Rules"]["TailscaleNeedsItsSettings"]["Assertions"][1]["Assert"] = {
        "Fn::Equals": [{"Ref": "TailscaleImageTag"}, ""]}


def _overlay_publishes_console(d):
    _step_edit(d, "ConsoleStep", "env_file: [./ui-token.env]\\n",
               "env_file: [./ui-token.env]\\n    ports: [\"0.0.0.0:8480:8480\"]\\n")


def _overlay_host_network(d):
    _step_edit(d, "ConsoleStep", "env_file: [./ui-token.env]\\n",
               "env_file: [./ui-token.env]\\n    network_mode: host\\n")


def _overlay_other_service(d):
    _step_edit(d, "ConsoleStep", "f=$f:docker-compose.tailnet.yml",
               "f=$f:docker-compose.tailnet.yml:docker-compose.extra.yml")


def _managed_policy(d):
    d["Resources"]["ExtraPolicy"] = {
        "Type": "AWS::IAM::ManagedPolicy",
        "Properties": {"Roles": [{"Ref": "InstanceRole"}], "PolicyDocument": {
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "ssm:PutParameter", "Resource": "*"}]}}}


def _plain_policy(d):
    d["Resources"]["ExtraPolicy"] = copy.deepcopy(d["Resources"]["InstanceTailscaleParameters"])
    d["Resources"]["ExtraPolicy"]["Type"] = "AWS::IAM::Policy"


def _role_policy_by_name(d):
    d["Resources"]["ExtraRolePolicy"] = copy.deepcopy(d["Resources"]["InstanceTailscaleParameters"])
    d["Resources"]["ExtraRolePolicy"]["Properties"]["RoleName"] = {"Fn::Sub": "${NamePrefix}-host"}


def _tailnet_policy_by_name(d):
    _tailscale_policy(d)["Properties"]["RoleName"] = {"Fn::Sub": "${NamePrefix}-host"}


def _prefix_list_any(d):
    _tailscale_statements(d)[2]["Resource"] = {
        "Fn::Sub": "arn:${AWS::Partition}:ec2:${AWS::Region}:aws:prefix-list/*"}


def _ec2_endpoint_open(d):
    d["Resources"]["Ec2Endpoint"]["Properties"]["PolicyDocument"]["Statement"][0]["Action"] = "ec2:*"


def _ec2_endpoint_always(d):
    del d["Resources"]["Ec2Endpoint"]["Condition"]


def _egress_step_tolerated(d):
    _step_edit(d, "EgressStep", "/usr/local/sbin/sensor-egress.sh refresh\n",
               "/usr/local/sbin/sensor-egress.sh refresh || echo \"egress: FAILED\"\n")


def _boot_unit_not_enabled(d):
    _step_edit(d, "EgressStep", "systemctl enable --now sensor-egress-boot.service sensor-egress.timer\n",
               "systemctl enable --now sensor-egress.timer\n")


def _boot_unit_not_copied(d):
    _step_edit(d, "EgressStep", "sensor-egress.timer sensor-egress-boot.service; do",
               "sensor-egress.timer; do")


def _egress_step_skipped(d):
    _steps(d)["EgressStep"]["Fn::If"][0] = "UiActionsOn"


def _egress_after_stack(d):
    _user_data_edit(d, "${EgressStep}${ConsoleStep}${ModelStep}cat > /etc/systemd/system/sensor.service",
                    "${ConsoleStep}${ModelStep}cat > /etc/systemd/system/sensor.service")
    _user_data_edit(d, '${TailscaleNodeStep}echo "bootstrap complete"',
                    '${TailscaleNodeStep}${EgressStep}echo "bootstrap complete"')


def _no_name_check(d):
    _step_edit(d, "TailscaleNodeStep", '[ "$n" = ${TailscaleHostname}.${TailnetSuffix}. ] || ',
               ": || ")


def _compose_file_appended(d):
    _step_edit(d, "ConsoleStep", "sed -i '/^COMPOSE_FILE=/d' .env\n", "")


def _no_restart(d):
    _step_edit(d, "TailscaleNodeStep", "systemctl restart tailscaled.service",
               "systemctl start tailscaled.service")


def _host_name_unbounded(d):
    d["Parameters"]["TailscaleHostname"]["AllowedPattern"] = "^[a-z0-9-]*$"


TAILNET_BREAKS = {
    "TailscaleEnabled is not off by default": _tailscale_default_on,
    "UiTailnetSignIn is not off by default": _sign_in_default_on,
    "UiActions is not off by default": _actions_default_on,
    "InstanceEgressTailscale does not depend on TailscaleOn": _tailscale_egress_always,
    "InstanceEgressTailscale allows more than tcp 443": _tailscale_egress_all_ports,
    "InstanceEgressTailscale allows more than tcp 443 ": _tailscale_egress_udp,
    "egress rule InstanceEgressAnywhere goes to an address range": _other_egress_to_anywhere,
    "ingress rule InTailnet depends on a Tailscale switch": _tailnet_ingress,
    "SecurityGroup TailnetGroup exists only with a console or tailnet switch":
        _tailnet_security_group,
    "role policy InstanceTailscaleParameters applies without TailscaleOn": _policy_always,
    "may write a parameter other than the Tailscale node state": _put_any_parameter,
    "may write a parameter other than the Tailscale node state ": _put_join_key,
    "has a wildcard parameter": _read_prefix,
    "reads a parameter other than the Tailscale state": _read_other,
    "allows ssm:DeleteParameter": _delete_parameter,
    "wildcard action ssm:*": _ssm_wildcard_action,
    "rule TailscaleNeedsItsSettings is missing or not exactly as required": _no_suffix_rule,
    "rule TailscaleNeedsItsSettings is missing or not exactly as required ": _no_ui_rule,
    "rule UiSignInNeedsTailscale is missing or not exactly as required": _no_sign_in_rule,
    "condition ConsoleStepOn is not TailscaleOn or UiActionsOn": _console_step_condition,
    "the join flags are not exactly the required ones": _netfilter_on,
    "the join flags are not exactly the required ones ": _tailscale_ssh,
    "the join flags are not exactly the required ones  ": _accept_routes,
    "the egress step lacks the line: grep -q tailscale0": _no_tailnet_drop,
    "does not write the state ARN and the unit exactly": _state_on_disk,
    "passes a join key other than the file": _key_on_command_line,
    "the node step uses funnel": _funnel,
    "tailscale serve does not proxy to the loopback console": _serve_elsewhere,
    "step TailscaleNodeStep is not empty unless TailscaleOn": _node_step_always,
    "the actions overlay changes more than": _actions_overlay_frontend,
    "over EC2's 16384": _user_data_too_big,
    "parameter TailscaleHostname is in the user data but has no length limit":
        _host_name_unbounded,
    "up() is called with --netfilter-mode=on --ssh": _join_flags_appended,
    "up() is called with --accept-routes": _join_key_call_with_more,
    "the node step advertises routes": _advertise_routes,
    "the node step uses an exit node": _exit_node,
    "the node step runs tailscale up or set outside up()": _tailscale_set,
    "rule TailscaleNeedsItsSettings is missing or not exactly as required  ": _drop_not_in_rule,
    "the tailnet overlay is not exactly the token file for the ui service":
        _overlay_publishes_console,
    "the tailnet overlay is not exactly the token file for the ui service ": _overlay_host_network,
    "COMPOSE_FILE lists files other than": _overlay_other_service,
    "AWS::IAM::ManagedPolicy ExtraPolicy exists": _managed_policy,
    "AWS::IAM::Policy ExtraPolicy exists": _plain_policy,
    "role policy ExtraRolePolicy is not InstanceTailscaleParameters on the instance role":
        _role_policy_by_name,
    "role policy InstanceTailscaleParameters is not InstanceTailscaleParameters":
        _tailnet_policy_by_name,
    "reads a prefix list other than S3's": _prefix_list_any,
    "endpoint Ec2Endpoint policy allows more than reading the S3 prefix list": _ec2_endpoint_open,
    "endpoint Ec2Endpoint exists without TailscaleOn": _ec2_endpoint_always,
    "the egress step lacks the line: /usr/local/sbin/sensor-egress.sh refresh":
        _egress_step_tolerated,
    "step EgressStep is not empty unless TailscaleOn": _egress_step_skipped,
    "the egress step lacks the line: systemctl enable --now sensor-egress-boot.service":
        _boot_unit_not_enabled,
    "the egress step lacks the line: for u in sensor-egress.service sensor-egress.timer sensor-egress-b":
        _boot_unit_not_copied,
    "the egress, console and model steps do not run, in that order, right before the stack":
        _egress_after_stack,
    "the node's name is not compared with the expected one": _no_name_check,
    "a rerun appends another COMPOSE_FILE line instead of rewriting it": _compose_file_appended,
    "a rerun does not restart tailscaled": _no_restart,
}


@pytest.mark.parametrize("expected", sorted(TAILNET_BREAKS))
def test_each_tailnet_rule_fires(sensor, expected):
    doc = copy.deepcopy(sensor)
    TAILNET_BREAKS[expected](doc)
    errors = check.check_sensor(doc)
    assert any(expected.strip() in e for e in errors), errors


SENSOR_BREAKS = {
    "config.ini without shipping and config-ship.ini with it": _agents_config_ships,
    "render_config.py does not get NeverActOn": _never_act_on_dropped,
    "does not get TrackedExport as its tracked switch": _tracked_arg_swapped,
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
    """Run render_config.py (as the image carries it) on the repository's config template."""
    out = tmp_path / dst
    subprocess.run([sys.executable, str(AWS / "render_config.py"),
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
                   "169.254.169.254", "AccessDenied", "InboundEnabled=false", "TLS",
                   "strip_comments.py", "build/sensor.deploy.yaml", "TailscaleEnabled=false",
                   "tailscale-state", "five certificates", "tailscale down",
                   "sensor-egress", "--uid-owner 10001", "Rebuild and push the image",
                   "aws ssm delete-parameter --name /winnie-sensor/tailscale-authkey"):
        assert needed in readme, needed
    ops = (ROOT / "docs" / "operations.md").read_text()
    assert "../deploy/aws/README.md#console-over-a-tailnet-optional" in ops
    assert "#console-over-a-tailnet-optional" in readme


# ---- size limits and the deploy copy -------------------------------------------------------

def test_both_size_limits_hold_with_every_switch_on(sensor):
    size, problems = check.user_data_size(sensor, _lt(sensor)["UserData"]["Fn::Base64"])
    assert problems == []
    assert size <= check.USER_DATA_LIMIT
    raw = check.SENSOR.read_text()
    assert check.deploy_copy_problems(raw) == []
    assert len(check.strip_comments.strip(raw).encode()) <= check.TEMPLATE_BODY_LIMIT


def test_the_deploy_copy_guard_fires():
    raw = check.SENSOR.read_text()
    padded = raw.replace("Outputs:\n", "Outputs:\n  Padding:\n    Value: " + "x" * 6000 + "\n")
    assert any("over the 51200-byte" in e for e in check.deploy_copy_problems(padded))
    # A stripper that also eats a script's "#" line changes the document.
    broken = raw.replace("#!/bin/bash\n              set -euo pipefail\n              exec",
                         "#!/bin/bash\n              # kept\n              set -euo pipefail\n"
                         "              exec", 1)
    assert "# kept" in check.strip_comments.strip(broken)
    assert check.deploy_copy_problems(broken) == []


def test_strip_keeps_block_scalars_and_drops_comment_lines():
    text = ("# top\nA: 1\n  # indented comment\nB: |\n  #!/bin/bash\n  # in the script\n\n"
            "  echo hi\nC: >-\n  # folded text\n# after\nD: [1, 2]\n")
    assert check.strip_comments.strip(text) == (
        "A: 1\nB: |\n  #!/bin/bash\n  # in the script\n\n  echo hi\nC: >-\n  # folded text\n"
        "D: [1, 2]\n")


@pytest.mark.parametrize("template", [check.SENSOR, check.BUCKET])
def test_strip_comments_writes_the_same_document(template, tmp_path):
    out = tmp_path / "deploy.yaml"
    result = subprocess.run([sys.executable, str(AWS / "strip_comments.py"), str(template),
                             str(out)], capture_output=True, text=True, check=True)
    assert "same document" in result.stdout
    assert check.load(out) == check.load(template)
    assert len(out.read_bytes()) <= check.TEMPLATE_BODY_LIMIT
    assert not any(line.lstrip().startswith("# ") for line in out.read_text().splitlines()
                   if not line.startswith(" " * 18))


def test_strip_comments_refuses_a_copy_over_the_limit(tmp_path):
    big = tmp_path / "big.yaml"
    big.write_text("Description: " + "x" * 52000 + "\n")
    result = subprocess.run([sys.executable, str(AWS / "strip_comments.py"), str(big),
                             str(tmp_path / "out.yaml")], capture_output=True, text=True)
    assert result.returncode == 1 and "over the 51200-byte" in result.stderr
    assert not (tmp_path / "out.yaml").exists()


# ---- the tailnet option, rendered ----------------------------------------------------------

SAMPLE = {"AWS::Region": "us-east-1", "AWS::AccountId": "123456789012",
          "AWS::URLSuffix": "amazonaws.com", "AWS::Partition": "aws",
          "ElasticIp": "192.0.2.10", "HostLogGroup": "/winnie-sensor/host",
          "Repository.RepositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/winnie-sensor",
          "NamePrefix": "winnie-sensor", "Scenario": "sip-provider", "SmtpEnabled": "false",
          "EventsBucketName": "example-events", "EventsPrefix": "events",
          "EventsBucketOwner": "123456789012", "TrackedExport": "false",
          "TrackedKey": "tracked/tracked.json", "NeverActOn": "198.51.100.0/24",
          "ImageTag": "abc123", "ComposeImageTag": "compose-bin", "S3Port": "9000",
          "AgentsIntervalSeconds": "3600", "TailscaleImageTag": "tailscale-v1.0.0",
          "TailscaleHostname": "sensor-1", "TailnetSuffix": "example-tailnet.ts.net",
          "UiOperator": "console", "S3PrefixListId": "pl-0123456789abcdef0",
          "VpcCidr": "10.64.0.0/16"}


def _rendered(sensor, tailscale, actions, sign_in, persona="", analyst=""):
    """The user data CloudFormation would produce for these switches and SAMPLE values."""
    values = dict(SAMPLE, TailscaleEnabled=tailscale, UiActions=actions, UiTailnetSignIn=sign_in,
                  PersonaModelId=persona, AnalystModelId=analyst)
    on = {"TailscaleOn": tailscale == "true", "UiActionsOn": actions == "true",
          "ConsoleStepOn": "true" in (tailscale, actions), "ModelOn": bool(persona or analyst)}

    def render(v):
        if isinstance(v, str):
            return v
        if "Fn::If" in v:
            cond, yes, no = v["Fn::If"]
            return render(yes) if on.get(cond, True) else render(no)
        if "Fn::Join" in v:
            return v["Fn::Join"][0].join(render(p) for p in v["Fn::Join"][1])
        sub = v["Fn::Sub"]
        template, local = (sub, {}) if isinstance(sub, str) else sub
        local = {k: render(x) for k, x in local.items()}

        def one(m):
            name = m.group(1)
            if name.startswith("!"):
                return "${" + name[1:] + "}"
            return local[name] if name in local else values[name]
        return re.sub(r"\$\{([^}]*)\}", one, template)
    return render(_lt(sensor)["UserData"]["Fn::Base64"])


def _scripts(user_data):
    return dict(re.findall(r"install -m 0700 /dev/stdin /usr/local/sbin/(\S+) <<'EOF'\n"
                           r"(.*?)\nEOF\n", user_data, re.S))


SWITCHES = [("false", "false", "false"), ("false", "true", "false"), ("true", "false", "false"),
            ("true", "true", "true")]


@pytest.mark.parametrize("switches", SWITCHES)
def test_rendered_bootstrap_is_valid_shell(sensor, tmp_path, switches):
    user_data = _rendered(sensor, *switches)
    scripts = {"user-data": user_data, **_scripts(user_data)}
    assert ("sensor-tailscale.sh" in scripts) == (switches[0] == "true")
    assert ("sensor-console.sh" in scripts) == ("true" in switches[:2])
    for name, body in scripts.items():
        path = tmp_path / name
        path.write_text(body)
        result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
        assert result.returncode == 0, (name, result.stderr)


def test_with_every_switch_off_no_tailnet_or_actions_step_runs(sensor):
    user_data = _rendered(sensor, "false", "false", "false")
    for needle in ("tailscale", "COMPOSE_FILE", "ui-token", "actions = true", "external_host",
                   "/go"):
        assert needle not in user_data, needle
    compose = check.embedded_compose(user_data)
    env = {"WINNIE_DATA_DIR": "/data", "WINNIE_OVERLAY": "/overlay/overlay.json",
           "WINNIE_SOURCE_STATE": "/overlay/source_state.json"}
    for name in ("ssh", "listeners", "agents", "ui"):
        assert compose["services"][name]["environment"] == env, name
    assert "sleep 3600; done" in compose["services"]["agents"]["command"][2]


def test_console_step_edits_hit_one_line_each_of_the_config_template(sensor):
    """The step's sed expressions, applied (as Python regexes) to the repository's config
    template, set exactly the [ui] keys they name."""
    script = _scripts(_rendered(sensor, "true", "true", "true"))["sensor-console.sh"]
    exprs = re.findall(r"-e [\"']s/(.*?)/(.*?)/[\"']", script)
    assert len(exprs) == 3
    text = (ROOT / "SSH" / "config.ini.TEMPLATE").read_text()
    for pattern, replacement in exprs:
        assert len(re.findall(pattern, text, re.M)) == 1, pattern
        text = re.sub(pattern, replacement, text, flags=re.M)
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    cp.read_string(text)
    assert cp.get("ui", "external_host") == "sensor-1.example-tailnet.ts.net"
    assert cp.get("ui", "actions") == "true"
    assert cp.get("ui", "operator") == "console"


def test_console_step_changes_only_the_ui_service(sensor):
    script = _scripts(_rendered(sensor, "true", "true", "true"))["sensor-console.sh"]
    import yaml

    overlays = re.findall(r"printf '(services:.*?)' > (docker-compose\.\w+\.yml)", script)
    assert [name for _, name in overlays] == ["docker-compose.tailnet.yml",
                                              "docker-compose.actions.yml"]
    for body, _ in overlays:
        doc = yaml.safe_load(body.encode().decode("unicode_escape"))
        assert list(doc["services"]) == ["ui"]
    # COMPOSE_FILE is written only after compose accepts the files, config.ini after that.
    order = [script.index(s) for s in ("docker compose config --quiet", 'echo "COMPOSE_FILE=',
                                       'sed -i -E "${e[@]}" config.ini')]
    assert order == sorted(order)
    assert "chown 10001:10001 config.ini" in script and "chmod 0400 config.ini" in script


def test_join_key_and_token_never_reach_a_command_line_or_the_log(sensor):
    scripts = _scripts(_rendered(sensor, "true", "true", "true"))
    node, console = scripts["sensor-tailscale.sh"], scripts["sensor-console.sh"]
    assert "--auth-key=file:$K" in node and "trap 'rm -f $K' EXIT" in node
    assert "tskey" not in node
    for body in (node, console):
        assert "set -x" not in body
        assert not re.search(r"echo [^|>]*\$t\b", body)
    assert "umask 077" in console.split("ui-token.env")[0]
    assert "umask 077" in node.split("go.html")[0]


def test_tailnet_role_policy_is_one_write_three_reads_and_the_prefix_list(sensor):
    policy = sensor["Resources"]["InstanceTailscaleParameters"]
    assert policy["Condition"] == "TailscaleOn"
    assert policy["Properties"]["RoleName"] == {"Ref": "InstanceRole"}
    by_action = {}
    for st in policy["Properties"]["PolicyDocument"]["Statement"]:
        for action in check.as_list(st["Action"]):
            by_action.setdefault(action, set()).update(
                check.text(r) for r in check.as_list(st["Resource"]))
    assert by_action == {"ssm:PutParameter": {check.TAILSCALE_STATE},
                         "ssm:GetParameter": check.TAILSCALE_READS,
                         "ec2:GetManagedPrefixListEntries": {check.PREFIX_LIST_ARN}}


def test_tailnet_option_opens_nothing_inbound(sensor):
    for name, res in sensor["Resources"].items():
        if res.get("Condition") in ("TailscaleOn", "ConsoleStepOn", "UiActionsOn"):
            assert res["Type"] in ("AWS::EC2::SecurityGroupEgress", "AWS::IAM::RolePolicy") \
                or name == check.EC2_ENDPOINT, name
    egress = sensor["Resources"]["InstanceEgressTailscale"]["Properties"]
    assert (egress["IpProtocol"], egress["FromPort"], egress["ToPort"]) == ("tcp", 443, 443)


# ---- the exporter's egress rules, run against fake iptables and aws -------------------------

FAKE_IPTABLES = """#!/bin/bash
echo "$(basename "$0") $*" >> "$LOG"
case " $* " in *" -C "*) exit 1 ;; esac
exit 0
"""


def _run_egress(tmp_path, answer, *, saved=None, vpc="10.64.0.0/16", aws_fails=False,
                refresh=True, args=None, env_file_present=True):
    """Run host/sensor-egress.sh with fake iptables, ip6tables and aws on PATH. Returns
    (exit code, stderr, the OUTPUT order, the SENSOR-UID rules, the saved list or None)."""
    bin_ = tmp_path / "bin"
    bin_.mkdir(exist_ok=True)
    for name in ("iptables", "ip6tables"):
        (bin_ / name).write_text(FAKE_IPTABLES)
        (bin_ / name).chmod(0o755)
    (tmp_path / "answer").write_text(answer + "\n")
    (bin_ / "aws").write_text("#!/bin/bash\n" + ("exit 255\n" if aws_fails
                                                  else f"cat {tmp_path / 'answer'}\n"))
    (bin_ / "aws").chmod(0o755)
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    if saved is not None:
        (state / "s3-cidrs").write_text(saved)
    env_file = tmp_path / "egress.env"
    if env_file_present:
        env_file.write_text(f"REGION=us-east-1\nPREFIX_LIST=pl-0123456789abcdef0\nVPC_CIDR={vpc}\n")
    log = tmp_path / "log"
    log.write_text("")
    import os
    env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}", LOG=str(log),
               SENSOR_EGRESS_ENV=str(env_file), SENSOR_EGRESS_DIR=str(state),
               SENSOR_EGRESS_RETRY_SECONDS="0")
    args = ["bash", str(AWS / "host" / "sensor-egress.sh")] + (
        args if args is not None else ["refresh"] if refresh else [])
    result = subprocess.run(args, env=env, capture_output=True, text=True)
    tables, chain = {"iptables": [], "ip6tables": []}, []
    for line in log.read_text().splitlines():
        tool, *rest = line.split()
        if rest[:3] == ["-w", "-I", "OUTPUT"]:
            tables[tool].insert(int(rest[3]) - 1, f"{tool} {' '.join(rest[4:])}")
        elif rest[:3] == ["-w", "-A", "SENSOR-UID"]:
            chain.append(" ".join(rest[3:]))
    output = tables["iptables"] + tables["ip6tables"]
    cache = state / "s3-cidrs"
    return (result.returncode, result.stderr, output, chain,
            cache.read_text() if cache.exists() else None)


def _s3_accepts(chain):
    return [r.split()[1] for r in chain if r.endswith("--dport 443 -j ACCEPT")
            and not r.startswith("-d 10.64.0.0/16")]


UID = "-m owner --uid-owner 10001"


def test_egress_rules_limit_the_exporter_and_end_in_a_reject(tmp_path):
    code, err, output, chain, cache = _run_egress(tmp_path, "198.51.100.0/24\t203.0.113.0/24")
    assert code == 0, err
    # The jump comes first and the REJECT right after it, so a packet that falls out of a
    # half-built SENSOR-UID is refused.
    assert output == [f"iptables {UID} -j SENSOR-UID", f"iptables {UID} -j REJECT",
                      f"ip6tables {UID} -j REJECT"]
    assert chain[0] == "-o tailscale0 -j REJECT"
    assert _s3_accepts(chain) == ["198.51.100.0/24", "203.0.113.0/24"]
    assert cache == "198.51.100.0/24\n203.0.113.0/24\n"
    assert not any("0.0.0.0/0" in r or r.endswith("-j ACCEPT") and "-d" not in r for r in chain)


@pytest.mark.parametrize("answer", ["", "not-a-cidr", "198.51.100.0/24 0.0.0.0/0",
                                    "198.51.100.0/24 192.0.2.0/4", "198.51.100.0/24;reboot"])
def test_a_bad_or_failed_lookup_keeps_the_last_list(tmp_path, answer):
    code, err, _, chain, cache = _run_egress(tmp_path, answer, saved="198.51.100.0/24\n")
    assert code == 0 and "lookup failed, keeping the last list" in err
    assert cache == "198.51.100.0/24\n"
    assert _s3_accepts(chain) == ["198.51.100.0/24"]


def test_with_no_list_the_exporter_reaches_no_s3_address(tmp_path):
    code, err, output, chain, cache = _run_egress(tmp_path, "", aws_fails=True)
    assert code == 0 and cache is None
    assert _s3_accepts(chain) == []
    assert f"iptables {UID} -j REJECT" in output


def test_a_wide_or_bad_saved_entry_is_skipped(tmp_path):
    _, _, _, chain, _ = _run_egress(tmp_path, "", refresh=False,
                                    saved="198.51.100.0/24\n0.0.0.0/0\nx\n10.0.0.0/7\n")
    assert _s3_accepts(chain) == ["198.51.100.0/24"]


@pytest.mark.parametrize("vpc", ["0.0.0.0/0", "10.64.0.0", "10.64.0.0/16 -j ACCEPT"])
def test_bad_settings_leave_only_the_deny(tmp_path, vpc):
    code, err, output, chain, _ = _run_egress(tmp_path, "198.51.100.0/24", vpc=vpc)
    assert code != 0
    assert output == [f"iptables {UID} -j REJECT", f"ip6tables {UID} -j REJECT"]
    assert chain == []


def test_missing_settings_leave_only_the_deny(tmp_path):
    code, _, output, chain, _ = _run_egress(tmp_path, "", refresh=False, env_file_present=False)
    assert code != 0
    assert output == [f"iptables {UID} -j REJECT", f"ip6tables {UID} -j REJECT"]
    assert chain == []


def test_deny_needs_no_settings_and_stops_there(tmp_path):
    # sensor-egress-boot.service's first step, before Docker starts
    code, err, output, chain, cache = _run_egress(tmp_path, "198.51.100.0/24", args=["deny"],
                                                  env_file_present=False)
    assert code == 0, err
    assert output == [f"iptables {UID} -j REJECT", f"ip6tables {UID} -j REJECT"]
    assert chain == [] and cache is None


def test_boot_order_deny_then_saved_list(tmp_path):
    # the boot unit's two steps in order, from a saved list, with no lookup
    _run_egress(tmp_path, "", args=["deny"], saved="198.51.100.0/24\n")
    code, err, output, chain, _ = _run_egress(tmp_path, "", args=[], saved="198.51.100.0/24\n",
                                              aws_fails=True)
    assert code == 0, err
    assert output[:2] == [f"iptables {UID} -j SENSOR-UID", f"iptables {UID} -j REJECT"]
    assert _s3_accepts(chain) == ["198.51.100.0/24"]


def test_host_files_are_valid_and_reach_the_image():
    assert subprocess.run(["bash", "-n", str(AWS / "host" / "sensor-egress.sh")]).returncode == 0
    assert check.check_host_files() == []
    dockerignore = (ROOT / ".dockerignore").read_text().splitlines()
    assert not any(p.startswith("deploy") for p in dockerignore)


def _host_edit(name, old, new):
    text_ = (AWS / "host" / name).read_text()
    assert old in text_, old
    return text_.replace(old, new, 1)


HOST_BREAKS = {
    "the exporter's egress rules lack: $w -A SENSOR-UID -o tailscale0 -j REJECT":
        dict(egress=("sensor-egress.sh", "$w -A SENSOR-UID -o tailscale0 -j REJECT\n", "")),
    "the egress script has an extra rule: $w -A SENSOR-UID -j ACCEPT":
        dict(egress=("sensor-egress.sh", "ip6tables -w -C", "$w -A SENSOR-UID -j ACCEPT\nip6tables -w -C")),
    "the egress script has an extra rule: $w -A SENSOR-UID -d 0.0.0.0/0":
        dict(egress=("sensor-egress.sh", '-d "$VPC_CIDR" -p tcp', "-d 0.0.0.0/0 -p tcp")),
    "the exporter's egress rules lack: ip6tables":
        dict(egress=("sensor-egress.sh", "ip6tables -w -C OUTPUT $u -j REJECT 2>/dev/null || "
                     "ip6tables -w -I OUTPUT 1 $u -j REJECT\n", "")),
    "the egress script does not validate CIDRs":
        dict(egress=("sensor-egress.sh", '[ "${1#*/}" -ge 8 ]', "true")),
    "the egress script does not stop on errors":
        dict(egress=("sensor-egress.sh", "set -euo pipefail\n", "")),
    "tailscaled.service lacks ProtectSystem=strict":
        dict(tailscaled=("tailscaled.service", "ProtectSystem=strict\n", "")),
    "tailscaled.service has more than one ExecStart":
        dict(tailscaled=("tailscaled.service", "ExecStopPost=", "ExecStart=\nExecStopPost=")),
    "the egress script does not install the deny before it reads its settings":
        dict(egress=("sensor-egress.sh", '[ "${1:-}" != deny ] || exit 0\n. "${SENSOR_EGRESS_ENV:-/etc/sensor-egress.env}"\n',
                     '. "${SENSOR_EGRESS_ENV:-/etc/sensor-egress.env}"\n[ "${1:-}" != deny ] || exit 0\n')),
    "sensor-egress-boot.service lacks Before=docker.service":
        dict(boot=("sensor-egress-boot.service", "Before=docker.service\n", "")),
    "sensor-egress-boot.service lacks RequiredBy=docker.service":
        dict(boot=("sensor-egress-boot.service", "RequiredBy=docker.service", "WantedBy=multi-user.target")),
    "sensor-egress-boot.service weakens its hold on Docker: WantedBy=multi-user.target":
        dict(boot=("sensor-egress-boot.service", "RequiredBy=docker.service", "WantedBy=multi-user.target")),
    "sensor-egress-boot.service weakens its hold on Docker: After=docker.service":
        dict(boot=("sensor-egress-boot.service", "Before=docker.service", "Before=docker.service\nAfter=docker.service")),
    "sensor-egress-boot.service does not run exactly the deny (may not fail)":
        dict(boot=("sensor-egress-boot.service", "ExecStart=/usr/local/sbin/sensor-egress.sh deny",
                   "ExecStart=-/usr/local/sbin/sensor-egress.sh deny")),
    "sensor-egress-boot.service lacks ExecStart=/usr/local/sbin/sensor-egress.sh deny":
        dict(boot=("sensor-egress-boot.service", "ExecStart=/usr/local/sbin/sensor-egress.sh deny\n", "")),
    "sensor-egress-boot.service weakens its hold on Docker: ConditionPathExists":
        dict(boot=("sensor-egress-boot.service", "[Service]", "ConditionPathExists=/etc/sensor-egress.env\n[Service]")),
    "sensor-egress-boot.service lacks RemainAfterExit=yes":
        dict(boot=("sensor-egress-boot.service", "RemainAfterExit=yes\n", "")),
    "tailscaled.service lacks ExecStart=/usr/local/sbin/tailscaled --statedir":
        dict(tailscaled=("tailscaled.service", "--state=${TS_STATE}", "")),
}


@pytest.mark.parametrize("expected", sorted(HOST_BREAKS))
def test_each_host_file_rule_fires(expected):
    (kind, (name, old, new)), = HOST_BREAKS[expected].items()
    errors = check.check_host_files(**{kind: _host_edit(name, old, new)})
    assert any(expected in e for e in errors), errors


def test_egress_rules_out_of_order_fire():
    text_ = (AWS / "host" / "sensor-egress.sh").read_text()
    lines = text_.splitlines()
    i = lines.index("$w -C OUTPUT $u -j REJECT 2>/dev/null || $w -I OUTPUT 1 $u -j REJECT")
    j = lines.index("$w -C OUTPUT $u -j SENSOR-UID 2>/dev/null || $w -I OUTPUT 1 $u -j SENSOR-UID")
    lines[i], lines[j] = lines[j], lines[i]
    assert "the exporter's egress rules are out of order" in check.check_host_files(
        egress="\n".join(lines))


def test_host_files_must_be_in_the_image():
    dockerfile = (ROOT / "Dockerfile").read_text().replace(check.HOST_IN_IMAGE + "\n", "")
    assert any("does not put deploy/aws/host" in e
               for e in check.check_host_files(dockerfile=dockerfile))


def test_egress_units_refresh_the_list():
    units = {n: (AWS / "host" / n).read_text() for n in check.EGRESS_UNITS}
    units["sensor-egress.timer"] = units["sensor-egress.timer"].replace("15min", "30d")
    assert any("sensor-egress.timer does not refresh" in e
               for e in check.check_host_files(units=units))


# ---- render_config.py: in the image, run on the host ---------------------------------------

def _render_edit(old, new):
    script = (AWS / "render_config.py").read_text()
    assert old in script, old
    return script.replace(old, new)


RENDER_BREAKS = {
    "tracked_export] enabled is not false":
        ('"enabled": "true" if ship == "true" and tracked == "true" else "false"',
         '"enabled": tracked'),
    "with shipping false and TrackedExport false the rendered [connector.tracked_export]":
        ('"enabled": "true" if ship == "true" and tracked == "true" else "false"',
         '"enabled": "true"'),
    "render_config.py fails": ("lines = open(src", "lines = opn(src"),
    "tracked export is not read from the blocklist mount":
        ('"file": "/blocklist/tracked.json"', '"file": "/agents/tracked.json"'),
    "passwords are not hashed in the export": ('"passwords": "hash"', '"passwords": "clear"'),
    "does not parse as Python 3.9": ("import configparser, re, sys\n",
                                     "import configparser, re, sys\nmatch 1:\n    case 1: pass\n"),
}


@pytest.mark.parametrize("expected", sorted(RENDER_BREAKS))
def test_each_render_rule_fires(sensor, expected):
    ud = _lt(sensor)["UserData"]["Fn::Base64"]["Fn::Sub"][0]
    errors = check.check_render(ud, script=_render_edit(*RENDER_BREAKS[expected]))
    assert any(expected in e for e in errors), errors


def test_render_config_must_come_from_the_image(sensor):
    ud = _lt(sensor)["UserData"]["Fn::Base64"]["Fn::Sub"][0]
    assert check.check_render(ud) == []
    assert any("does not copy render_config.py out of the image" in e
               for e in check.check_render(ud.replace(check.RENDER_COPY, "true")))
    dockerfile = (ROOT / "Dockerfile").read_text().replace(check.RENDER_IN_IMAGE, "")
    assert any("Dockerfile does not put render_config.py" in e
               for e in check.check_render(ud, dockerfile=dockerfile))


def test_with_every_switch_off_no_egress_step_runs(sensor):
    user_data = _rendered(sensor, "false", "false", "false")
    for needle in ("sensor-egress", "SENSOR-UID", "uid-owner", "/app/deploy/aws/host",
                   "sensor-tailscale.env", "ec2 get-managed-prefix-list-entries"):
        assert needle not in user_data, needle
    assert check.RENDER_COPY in user_data.splitlines()


# ---- models on Bedrock (models.yaml, the model step, host/sensor-model.sh) -----------------

@pytest.fixture(scope="module")
def models():
    return check.load(check.MODELS)


def test_models_template_passes_and_fits(models):
    raw = check.MODELS.read_text()
    assert check.check_models(models, raw) == []
    assert check.check_names(models, raw, "m") == []
    assert check.deploy_copy_problems(raw) == []


@pytest.mark.parametrize("persona, analyst", check.MODEL_SAMPLES + [("anthropic.claude-x", "")])
def test_the_grant_is_exactly_the_configured_models(models, persona, analyst):
    values = check.model_values(persona, analyst)
    res = models["Resources"]
    endpoint = check.evaluate(res["BedrockEndpoint"]["Properties"]["PolicyDocument"], models,
                              values)["Statement"]
    assert {r for st in endpoint for r in check.as_list(st["Resource"])} == (
        check.expected_grant(persona) | check.expected_grant(analyst))
    assert all(st["Action"] == "bedrock:InvokeModel" for st in endpoint)
    assert len(endpoint) == (persona != "") + (analyst != "")
    # Each caller's role: its own model, nothing of the other caller's.
    for name, model in (("PersonaRole", persona), ("AnalystRole", analyst)):
        if not model:
            continue
        role = check.evaluate(res[name]["Properties"]["Policies"][0]["PolicyDocument"],
                              models, values)["Statement"]
        assert {r for st in role for r in check.as_list(st["Resource"])} == \
            check.expected_grant(model)
        assert all(st["Action"] == "bedrock:InvokeModel" for st in role)


@pytest.mark.parametrize("prefix", check.PROFILE_PREFIXES)
def test_every_geographic_prefix_is_a_profile(prefix):
    model = f"{prefix}.anthropic.claude-haiku-5-5"
    assert re.fullmatch(check.MODEL_ID, model)
    assert check.expected_grant(model) == {
        f"arn:aws:bedrock:us-east-1:123456789012:inference-profile/{model}",
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-5-5"}


def test_callers_roles_never_cover_each_other(models):
    # Different models for the two callers: neither role's grant names the other's model.
    persona, analyst = "us.anthropic.claude-haiku-5-5", "eu.anthropic.claude-sonnet-5-5"
    values = check.model_values(persona, analyst)
    res = models["Resources"]
    got = {}
    for name in ("PersonaRole", "AnalystRole"):
        st = check.evaluate(res[name]["Properties"]["Policies"][0]["PolicyDocument"], models,
                            values)["Statement"]
        got[name] = {r for s in st for r in check.as_list(s["Resource"])}
    assert not got["PersonaRole"] & check.expected_grant(analyst)
    assert not got["AnalystRole"] & check.expected_grant(persona)
    assert res["PersonaRole"]["Condition"] == "PersonaOn"
    assert res["AnalystRole"]["Condition"] == "AnalystOn"


def test_a_profile_grants_its_own_model_and_nothing_else():
    assert check.expected_grant("us.anthropic.claude-haiku-5-5") == {
        "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-haiku-5-5",
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-5-5"}
    assert check.expected_grant("anthropic.claude-haiku-5-5") == {
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-haiku-5-5"}


def test_model_id_pattern_is_the_same_in_both_templates(sensor, models):
    for name in check.MODEL_PARAMS:
        assert sensor["Parameters"][name] == models["Parameters"][name]
    pattern = check.MODEL_ID
    for good in check.MODEL_IDS_GOOD:
        assert re.fullmatch(pattern, good)
    for bad in check.MODEL_IDS_BAD:
        assert not re.fullmatch(pattern, bad)


def _model_statement(d, where, who):
    res = d["Resources"]
    if where == "endpoint":
        doc = res["BedrockEndpoint"]["Properties"]["PolicyDocument"]
        return doc["Statement"][0 if who == "Persona" else 1]["Fn::If"][1]
    return res[f"{who}Role"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0]


def _endpoint_any_bedrock(d):
    _model_statement(d, "endpoint", "Persona")["Action"] = "bedrock:*"


def _endpoint_streams(d):
    _model_statement(d, "endpoint", "Persona")["Action"] = [
        "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]


def _endpoint_any_model(d):
    _model_statement(d, "endpoint", "Analyst")["Resource"] = "*"


def _endpoint_any_foundation_model(d):
    st = _model_statement(d, "endpoint", "Persona")
    st["Resource"]["Fn::If"][1][1] = {"Fn::Sub": "arn:${AWS::Partition}:bedrock:*::foundation-model/*"}


def _endpoint_profile_any_region(d):
    st = _model_statement(d, "endpoint", "Persona")
    st["Resource"]["Fn::If"][1][0] = {"Fn::Sub": "arn:${AWS::Partition}:bedrock:*:${AWS::AccountId}:"
                                                 "inference-profile/${PersonaModelId}"}


def _endpoint_persona_always(d):
    sts = d["Resources"]["BedrockEndpoint"]["Properties"]["PolicyDocument"]["Statement"]
    sts[0] = sts[0]["Fn::If"][1]


def json_swap(node, old, new):
    import json
    return json.loads(json.dumps(node).replace(old, new))


def _persona_role_grants_analyst_model(d):
    st = _model_statement(d, "role", "Persona")
    st["Resource"] = json_swap(st["Resource"], "PersonaModelId", "AnalystModelId")


def _analyst_role_grants_persona_model(d):
    st = _model_statement(d, "role", "Analyst")
    st["Resource"] = json_swap(st["Resource"], "AnalystModelId", "PersonaModelId")


def _persona_role_grants_both(d):
    statements = d["Resources"]["PersonaRole"]["Properties"]["Policies"][0]["PolicyDocument"][
        "Statement"]
    statements.append(json_swap(statements[0], "PersonaModelId", "AnalystModelId"))


def _persona_role_named_analyst(d):
    d["Resources"]["PersonaRole"]["Properties"]["RoleName"] = {
        "Fn::Sub": "${NamePrefix}-model-analyst"}


def _one_shared_role(d):
    del d["Resources"]["AnalystRole"]


def _persona_role_always(d):
    del d["Resources"]["PersonaRole"]["Condition"]


def _role_without_endpoint_condition(d):
    del _model_statement(d, "role", "Persona")["Condition"]


def _role_lists_models(d):
    _model_statement(d, "role", "Analyst")["Action"] = ["bedrock:InvokeModel",
                                                        "bedrock:ListFoundationModels"]


def _role_not_action(d):
    st = _model_statement(d, "role", "Persona")
    st["NotAction"] = st.pop("Action")


def _sts_any_call(d):
    d["Resources"]["StsEndpoint"]["Properties"]["PolicyDocument"]["Statement"][1]["Action"] = "sts:*"


def _sts_assume_anything(d):
    d["Resources"]["StsEndpoint"]["Properties"]["PolicyDocument"]["Statement"][0]["Resource"] = "*"


def _trust_whole_account(d):
    d["Resources"]["AnalystRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"][0][
        "Principal"]["AWS"] = {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}


def _role_managed_policy(d):
    d["Resources"]["PersonaRole"]["Properties"]["ManagedPolicyArns"] = [
        "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"]


def _role_long_sessions(d):
    d["Resources"]["PersonaRole"]["Properties"]["MaxSessionDuration"] = 43200


def _instance_assumes_anything(d):
    d["Resources"]["InstanceAssumeModelRole"]["Properties"]["PolicyDocument"]["Statement"][0][
        "Resource"] = "*"


def _extra_model_resource(d):
    d["Resources"]["OpenEgress"] = {"Type": "AWS::EC2::SecurityGroupEgress", "Properties": {}}


def _conditional_endpoint(d):
    d["Resources"]["StsEndpoint"]["Condition"] = "PersonaOn"


def _endpoint_own_group(d):
    d["Resources"]["BedrockEndpoint"]["Properties"]["SecurityGroupIds"] = ["sg-0other"]


def _control_plane_endpoint(d):
    d["Resources"]["BedrockEndpoint"]["Properties"]["ServiceName"] = {
        "Fn::Sub": "com.amazonaws.${AWS::Region}.bedrock"}


def _model_pattern_open(d):
    d["Parameters"]["AnalystModelId"]["AllowedPattern"] = "^.*$"


def _model_pattern_dots(d):
    d["Parameters"]["PersonaModelId"]["AllowedPattern"] = r"^[a-z0-9.:-]*$"


def _model_pattern_any_prefix(d):
    d["Parameters"]["PersonaModelId"]["AllowedPattern"] = check.MODEL_ID.replace(
        "|global)", "|global|xx)")


def _model_pattern_no_global(d):
    d["Parameters"]["PersonaModelId"]["AllowedPattern"] = check.MODEL_ID.replace("|global", "")


def _model_pattern_no_eu(d):
    d["Parameters"]["AnalystModelId"]["AllowedPattern"] = check.MODEL_ID.replace("|eu", "")


def _profile_condition_misses_jp(d):
    d["Conditions"]["PersonaProfile"]["Fn::Or"] = [
        c for c in d["Conditions"]["PersonaProfile"]["Fn::Or"] if "jp" not in str(c)]


def _model_default_on(d):
    d["Parameters"]["PersonaModelId"]["Default"] = "us.anthropic.claude-haiku-5-5"


def _no_model_rule(d):
    del d["Rules"]["NeedsAModel"]


MODEL_BREAKS = {
    "the endpoint policy allows bedrock:*": _endpoint_any_bedrock,
    "the endpoint policy allows bedrock:InvokeModel, bedrock:InvokeModelWithResponseStream":
        _endpoint_streams,
    "the endpoint policy grants * beyond the configured models": _endpoint_any_model,
    "foundation-model/* beyond the configured models": _endpoint_any_foundation_model,
    "arn:aws:bedrock:*:123456789012:inference-profile/us.anthropic.claude-haiku-5-5 beyond":
        _endpoint_profile_any_region,
    "with - / eu.anthropic.claude-haiku-5-5 the endpoint policy grants": _endpoint_persona_always,
    # Each caller's role never covers the other caller's model.
    "with jp.anthropic.claude-haiku-5-5 / au.anthropic.claude-haiku-5-5 the PersonaRole policy "
    "grants arn:aws:bedrock:us-east-1:123456789012:inference-profile/au.anthropic.claude-haiku-5-5":
        _persona_role_grants_analyst_model,
    "with us.anthropic.claude-haiku-5-5 / us.anthropic.claude-sonnet-5-5 the AnalystRole "
    "policy grants arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-5-5":
        _analyst_role_grants_persona_model,
    "with us.anthropic.claude-haiku-5-5 / us.anthropic.claude-sonnet-5-5 the PersonaRole "
    "policy grants arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-5-5":
        _persona_role_grants_both,
    "PersonaRole is not named ${NamePrefix}-model-persona": _persona_role_named_analyst,
    "no AWS::IAM::Role AnalystRole": _one_shared_role,
    "resource PersonaRole has a condition other than PersonaOn": _persona_role_always,
    "the PersonaRole policy is not limited to the bedrock-runtime endpoint":
        _role_without_endpoint_condition,
    "the AnalystRole policy allows bedrock:InvokeModel, bedrock:ListFoundationModels":
        _role_lists_models,
    "the PersonaRole policy has a statement that is not a plain Allow": _role_not_action,
    "StsEndpoint policy allows more than assuming the callers' roles and GetCallerIdentity":
        _sts_any_call,
    "StsEndpoint policy allows more than assuming": _sts_assume_anything,
    "AnalystRole can be assumed by more than the sensor's instance role": _trust_whole_account,
    "PersonaRole has policies other than its one inline policy": _role_managed_policy,
    "PersonaRole sessions may last more than an hour": _role_long_sessions,
    "InstanceAssumeModelRole gives the instance role more than assuming": _instance_assumes_anything,
    "resource OpenEgress is not one of the five": _extra_model_resource,
    "resource StsEndpoint has a condition other than none": _conditional_endpoint,
    "endpoint BedrockEndpoint is not behind the sensor's endpoint security group":
        _endpoint_own_group,
    "endpoint BedrockEndpoint is not the bedrock-runtime endpoint": _control_plane_endpoint,
    "parameter AnalystModelId accepts '*'": _model_pattern_open,
    "parameter PersonaModelId accepts 'us.anthropic.claude.x'": _model_pattern_dots,
    "parameter PersonaModelId accepts 'xx.anthropic.claude-x'": _model_pattern_any_prefix,
    "parameter PersonaModelId refuses a valid model id": _model_pattern_no_global,
    "parameter AnalystModelId refuses a valid model id": _model_pattern_no_eu,
    "with jp.anthropic.claude-haiku-5-5 / au.anthropic.claude-haiku-5-5 the endpoint policy grants arn:aws:bedrock:us-east-1::foundation-model/jp.anthropic.claude-haiku-5-5":
        _profile_condition_misses_jp,
    "parameter PersonaModelId is not empty (off) by default": _model_default_on,
    "no rule refuses a deploy with neither model set": _no_model_rule,
}


@pytest.mark.parametrize("expected", sorted(MODEL_BREAKS))
def test_each_models_rule_fires(models, expected):
    doc = copy.deepcopy(models)
    MODEL_BREAKS[expected](doc)
    errors = check.check_models(doc)
    assert any(expected in e for e in errors), errors


# sensor.yaml: the option adds no resource, and its step is exactly the three lines.

def _sensor_model_default_on(d):
    d["Parameters"]["AnalystModelId"]["Default"] = "anthropic.claude-haiku-5-5"


def _sensor_bedrock_endpoint(d):
    d["Resources"]["BedrockEndpoint"] = copy.deepcopy(d["Resources"]["Ec2Endpoint"])
    d["Resources"]["BedrockEndpoint"]["Condition"] = "ModelOn"


def _sensor_role_invokes(d):
    _role_statements(d).append({"Effect": "Allow", "Action": "bedrock:InvokeModel",
                                "Resource": "*"})


def _model_on_always(d):
    d["Conditions"]["ModelOn"] = {"Fn::Equals": ["a", "a"]}


def _model_step_always(d):
    variables = _lt(d)["UserData"]["Fn::Base64"]["Fn::Sub"][1]
    variables["ModelStep"] = variables["ModelStep"]["Fn::If"][1]


def _model_step_opens_metadata(d):
    variables = _lt(d)["UserData"]["Fn::Base64"]["Fn::Sub"][1]
    step = variables["ModelStep"]["Fn::If"][1]
    step["Fn::Sub"] = step["Fn::Sub"] + "iptables -D DOCKER-USER -i br-+ -d 169.254.169.254/32 -j DROP\n"


def _model_step_before_console(d):
    _user_data_edit(d, "${EgressStep}${ConsoleStep}${ModelStep}cat",
                    "${EgressStep}${ModelStep}${ConsoleStep}cat")


SENSOR_MODEL_BREAKS = {
    "parameter AnalystModelId is not empty (off) by default": _sensor_model_default_on,
    "resource BedrockEndpoint depends on a model switch": _sensor_bedrock_endpoint,
    "instance role InstanceRole allows bedrock:InvokeModel": _sensor_role_invokes,
    "condition ModelOn is not as required": _model_on_always,
    "step ModelStep is not empty unless ModelOn": _model_step_always,
    "the model step is not exactly its settings": _model_step_opens_metadata,
    "the egress, console and model steps do not run, in that order": _model_step_before_console,
}


@pytest.mark.parametrize("expected", sorted(SENSOR_MODEL_BREAKS))
def test_each_sensor_model_rule_fires(sensor, expected):
    doc = copy.deepcopy(sensor)
    SENSOR_MODEL_BREAKS[expected](doc)
    errors = check.check_sensor(doc)
    assert any(expected in e for e in errors), errors


def test_with_both_models_off_the_bootstrap_has_no_model_step(sensor):
    for switches in SWITCHES:
        user_data = _rendered(sensor, *switches)
        for needle in ("sensor-model", "bedrock", "PERSONA_MODEL", "AWS_CONFIG_FILE"):
            assert needle not in user_data, needle


@pytest.mark.parametrize("persona, analyst", [("us.anthropic.claude-haiku-5-5", ""),
                                              ("", "anthropic.claude-haiku-5-5"),
                                              ("global.anthropic.claude-sonnet-5-5",
                                               "us.anthropic.claude-haiku-5-5")])
def test_model_step_renders_valid_shell_and_names_the_model_role(sensor, tmp_path, persona,
                                                                 analyst):
    user_data = _rendered(sensor, "true", "true", "true", persona, analyst)
    path = tmp_path / "user-data"
    path.write_text(user_data)
    assert subprocess.run(["bash", "-n", str(path)]).returncode == 0
    settings = re.search(r"^printf 'REGION=.*> /etc/sensor-model\.env$", user_data, re.M).group(0)
    assert "arn:aws:iam::123456789012:role/winnie-sensor-model" in settings
    assert f'"{persona}" "{analyst}"' in settings
    # After the console step, which writes COMPOSE_FILE first; before the stack starts.
    lines = user_data.splitlines()
    setup = lines.index('/usr/local/sbin/sensor-model.sh setup "$IMAGE" || echo "model: FAILED ($?)"')
    assert lines.index('/usr/local/sbin/sensor-console.sh || echo "console: FAILED ($?)"') < setup
    assert setup < lines.index("cat > /etc/systemd/system/sensor.service <<'EOF'")


def test_fixed_caller_addresses_are_on_their_networks(sensor):
    compose = check.embedded_compose(_rendered(sensor, "false", "false", "false"))
    import ipaddress
    nets = {n: ipaddress.ip_network(c["ipam"]["config"][0]["subnet"])
            for n, c in compose["networks"].items()}
    assert ipaddress.ip_address("172.30.0.10") in nets["frontend"]
    assert ipaddress.ip_address("172.30.1.10") in nets["backend"]
    assert compose["services"]["ssh"]["networks"] == ["frontend"]
    assert compose["services"]["agents"]["networks"] == ["backend"]


def _model_host_edit(old, new, name="sensor-model.sh"):
    script = check.MODEL_SCRIPT.read_text()
    units = {n: (check.HOST_DIR / n).read_text() for n in check.MODEL_UNITS}
    if name == "sensor-model.sh":
        assert old in script, old
        script = script.replace(old, new)
    else:
        assert old in units[name], old
        units[name] = units[name].replace(old, new)
    return check.check_model_host(script, units)


MODEL_HOST_BREAKS = {
    "sensor-model.sh has an extra rule": ("for c in", "iptables -w -I DOCKER-USER 1 -s 172.30.0.0/24 -j ACCEPT\nfor c in"),
    "callers other than the ssh and agents containers' fixed addresses":
        ("callers+=(persona:172.30.0.10)", "callers+=(persona:172.30.0.0/24)"),
    "overlay changes more than": ('extra_hosts: ["%s:%s"]', 'network_mode: host\\n    extra_hosts: ["%s:%s"]'),
    # ssh's mount must be the persona's directory, and only it.
    "overlay changes more than the ssh and agents containers' address, endpoint name, own":
        ("svc ssh frontend 172.30.0.10 persona", "svc ssh frontend 172.30.0.10 analyst"),
    "own credentials mount": ('volumes: ["%s/%s:/model:ro"]', 'volumes: ["%s:/model:ro"]'),
    "does not ask for one-hour credentials of the caller's own role":
        ('--role-arn "$ROLE_ARN-$1"', '--role-arn "$ROLE_ARN-analyst"'),
    "does not write a caller's credentials into its own directory":
        ('> "$D/$1/creds.new"; then', '> "$D/analyst/creds.new"; then'),
    "does not check the endpoint address is inside the VPC": ('&& inside "$EP" \\', '\\'),
    "does not check the looked-up address is inside the VPC": ('&& inside "$a"; then', '; then'),
    "does not test addresses against the VPC":
        ("inside() { python3 -c 'import ipaddress as i,sys; sys.exit(i.ip_address(sys.argv[1]) "
         "not in i.ip_network(sys.argv[2]))' \"$1\" \"$VPC_CIDR\" 2>/dev/null; }",
         "inside() { true; }"),
    "defines inside() more than once": ("\n# One run at a time", "\ninside() { true; }\n# One run at a time"),
    "does not use the model id pattern": ("(us|us-gov|eu|apac|jp|au|global)", "[a-z-]+"),
    "does not check the VPC range": ("8 <= n.prefixlen <= 28", "0 <= n.prefixlen <= 32"),
    "does not start its timer": ("systemctl enable --now sensor-model.timer",
                                 "systemctl enable sensor-model.timer"),
    "does not remove accepts to an old address": ("-j ACCEPT$'\nrules=", "-j NOTHING$'\nrules="),
    "removes more than caller accepts to an old address":
        ('[ "${BASH_REMATCH[2]}" != "$EP" ] || continue', 'true || continue'),
    "does not recreate only the callers when the address changed":
        ('[ -z "$(docker compose ps -q --status running "$s" 2>/dev/null || :)" ] \\', 'false \\'),
    "does not ask for one-hour credentials": ("--duration-seconds 3600", "--duration-seconds 43200"),
    "does not make the credentials readable by uid 10001 only":
        ('chmod 0400 "$D/$1/creds.new"', 'chmod 0444 "$D/$1/creds.new"'),
    "sets another mode": ("      mv -f \"$D/$1/creds.new\"",
                          "      chmod a+r \"$D/$1/creds.new\"\n      mv -f \"$D/$1/creds.new\""),
    "does not keep each credentials directory for uid 10001 only": ("-m 0500 -o 10001", "-m 0755 -o 10001"),
    "does not keep the credentials root for root only": ('install -d -m 0700 "$D"', 'install -d -m 0755 "$D"'),
    "does not check the overlay before it uses it":
        ("  COMPOSE_FILE=$f:docker-compose.model.new.yml docker compose config --quiet\n", ""),
}


@pytest.mark.parametrize("expected", sorted(MODEL_HOST_BREAKS))
def test_each_model_host_rule_fires(expected):
    old, new = MODEL_HOST_BREAKS[expected]
    assert any(expected in e for e in _model_host_edit(old, new)), expected


def test_model_timer_must_renew():
    errors = _model_host_edit("OnUnitActiveSec=15min", "OnUnitActiveSec=2h", "sensor-model.timer")
    assert any("sensor-model.timer does not renew" in e for e in errors)


# ---- sensor-model.sh, run against fake aws, getent, iptables and docker ----

CREDS = ('{"AccessKeyId": "ASIA%s", "SecretAccessKey": "example-secret", '
         '"SessionToken": "example-token", "Expiration": "2026-11-19T13:00:00+00:00"}')

# DOCKER-USER as a list in $RULES: -C, -I, -D and -S behave as iptables does for these
# rules (-S prints the /32 and -m tcp forms), and every call is logged.
FAKE_IPTABLES_STATEFUL = r'''#!/usr/bin/env python3
import os, sys
args = [a for a in sys.argv[1:] if a != "-w"]
open(os.environ["LOG"], "a").write("iptables -w " + " ".join(args) + "\n")
path = os.environ["RULES"]
rules = open(path).read().splitlines() if os.path.exists(path) else []
op, chain = args[0], args[1]
assert chain == "DOCKER-USER", args
def rule(spec):
    return ("-s %s/32 -d %s/32 -p tcp -m tcp --dport 443 -j ACCEPT"
            % (spec[spec.index("-s") + 1], spec[spec.index("-d") + 1]))
if op == "-S":
    print("-N DOCKER-USER")
    for r in rules:
        print("-A DOCKER-USER " + r)
    print("-A DOCKER-USER -s 172.30.0.0/16 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN")
    print("-A DOCKER-USER -s 172.30.0.0/16 -j DROP")
    sys.exit(0)
if op == "-C":
    sys.exit(0 if rule(args[2:]) in rules else 1)
if op == "-I":
    rules.insert(0, rule(args[3:]))
elif op == "-D":
    if rule(args[2:]) not in rules:
        sys.exit(1)
    rules.remove(rule(args[2:]))
open(path, "w").write("".join(r + "\n" for r in rules))
'''


def _run_model(tmp_path, *, persona="us.anthropic.claude-haiku-5-5", analyst="",
               answer="10.64.0.37", saved=None, aws_fails=False, compose_fails=False,
               setup=True, env_text=None, running=False, script=None):
    """Run host/sensor-model.sh with fakes on PATH. Returns (exit code, stderr, accept
    rules added as (source, destination), the home directory, the credentials directory,
    the log). The fake DOCKER-USER chain persists in tmp_path across runs."""
    import os
    bin_ = tmp_path / "bin"
    bin_.mkdir(exist_ok=True)
    log = tmp_path / "log"
    log.write_text("")
    fakes = {
        "iptables": FAKE_IPTABLES_STATEFUL,
        "getent": f"#!/bin/bash\n[ -n '{answer}' ] && echo '{answer}       STREAM $2'\n",
        # The access key id names the role assumed, so each caller's file shows whose it is.
        "aws": "#!/bin/bash\necho \"aws $*\" >> \"$LOG\"\n" + (
            "exit 255\n" if aws_fails else
            "a=\"$*\"; r=\"${a##*--role-arn }\"; r=\"${r%% *}\"; r=\"${r##*/}\"\n"
            f"printf '%s\\n' '{CREDS}' | sed \"s/ASIA%s/ASIA-$r/\"\n"),
        "docker": "#!/bin/bash\necho \"docker $*\" >> \"$LOG\"\n" + (
            "case \"$*\" in *'compose config'*) exit 1 ;; esac\n" if compose_fails else "")
            + "case \"$*\" in *' run '*|run*) echo '[Unit]' ;; esac\n"
            + ("case \"$*\" in *'compose ps'*) echo 0123abcd ;; esac\n" if running else ""),
        "systemctl": "#!/bin/bash\necho \"systemctl $*\" >> \"$LOG\"\n",
        "chown": "#!/bin/bash\n",
        "flock": "#!/bin/bash\necho \"flock $*\" >> \"$LOG\"\n",
        # Records the requested mode and owner; a test cannot write into a 0500 directory
        # it does not own as root does.
        "install": "#!/bin/bash\necho \"install $*\" >> \"$LOG\"\nmkdir -p \"${@: -1}\"\n",
    }
    for name, body in fakes.items():
        (bin_ / name).write_text(body)
        (bin_ / name).chmod(0o755)
    home, creds, state, units = (tmp_path / d for d in ("home", "creds", "state", "units"))
    for d in (home, state, units):
        d.mkdir(exist_ok=True)
    if saved is not None:
        (state / "endpoint").write_text(saved + "\n")
    firewall = tmp_path / "sensor-firewall.sh"
    if not (home / "config.ini").exists():       # a second run on the same host keeps its files
        _render(None, tmp_path, home / "config.ini", "false", "false")
        (home / "render_config.py").write_text((AWS / "render_config.py").read_text())
        (home / ".env").write_text("COMPOSE_PROFILES=ui\nCOMPOSE_FILE=docker-compose.yml:"
                                   "docker-compose.override.yml:docker-compose.tailnet.yml\n")
        firewall.write_text("#!/bin/bash\n")
    env_file = tmp_path / "model.env"
    env_file.write_text(env_text if env_text is not None else
                        "REGION=us-east-1\nSUFFIX=amazonaws.com\nVPC_CIDR=10.64.0.0/16\n"
                        "ROLE_ARN=arn:aws:iam::123456789012:role/winnie-sensor-model\n"
                        f"PERSONA_MODEL={persona}\nANALYST_MODEL={analyst}\n")
    env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}", LOG=str(log),
               RULES=str(tmp_path / "rules"),
               SENSOR_MODEL_ENV=str(env_file), SENSOR_MODEL_DIR=str(creds),
               SENSOR_MODEL_STATE=str(state), SENSOR_HOME=str(home),
               SENSOR_FIREWALL=str(firewall), SENSOR_UNIT_DIR=str(units),
               SENSOR_MODEL_RETRY_SECONDS="0")
    path = check.MODEL_SCRIPT
    if script is not None:
        path = tmp_path / "sensor-model.sh"
        path.write_text(script)
    args = ["bash", str(path)] + (
        ["setup", "123456789012.dkr.ecr.us-east-1.amazonaws.com/winnie-sensor:abc123"]
        if setup else [])
    result = subprocess.run(args, env=env, capture_output=True, text=True)
    accepts = []
    for line in log.read_text().splitlines():
        words = line.split()
        if words[:4] == ["iptables", "-w", "-I", "DOCKER-USER"]:
            assert words[5:] == ["-s", words[6], "-d", words[8], "-p", "tcp", "--dport", "443",
                                 "-j", "ACCEPT"], line
            accepts.append((words[6], words[8]))
        if words[:4] == ["iptables", "-w", "-D", "DOCKER-USER"]:
            assert words[4:] == ["-s", words[5], "-d", words[7], "-p", "tcp", "--dport", "443",
                                 "-j", "ACCEPT"], line
        assert not (words[0] == "iptables" and "DOCKER-USER" not in words), line
        assert not (words[0] == "iptables" and words[2] not in ("-C", "-I", "-D", "-S")), line
    return result.returncode, result.stderr, accepts, home, creds, log.read_text()


def _chain(tmp_path):
    """The fake DOCKER-USER chain's caller accepts, as (source, destination)."""
    path = tmp_path / "rules"
    return sorted((r.split()[1].split("/")[0], r.split()[3].split("/")[0])
                  for r in (path.read_text().splitlines() if path.exists() else []))


def _cred_modes(creds, who):
    return {n: (creds / who / n).stat().st_mode & 0o777 for n in ("creds.json", "config")}


def _cfg(home):
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    cp.read(home / "config.ini")
    return cp


def test_setup_gives_only_the_persona_a_path_and_credentials(tmp_path):
    import json
    import yaml
    code, err, accepts, home, creds, log = _run_model(tmp_path)
    assert code == 0, err
    assert accepts == [("172.30.0.10", "10.64.0.37")]
    assert _chain(tmp_path) == [("172.30.0.10", "10.64.0.37")]
    overlay = yaml.safe_load((home / "docker-compose.model.yml").read_text())
    assert overlay == {"services": {"ssh": {
        "networks": {"frontend": {"ipv4_address": "172.30.0.10"}},
        "extra_hosts": ["bedrock-runtime.us-east-1.amazonaws.com:10.64.0.37"],
        "environment": {"AWS_CONFIG_FILE": "/model/config", "AWS_EC2_METADATA_DISABLED": "true"},
        "volumes": [f"{creds}/persona:/model:ro"]}}}
    assert not (home / "docker-compose.model.new.yml").exists()
    cp = _cfg(home)
    assert (cp.get("llm", "llm_provider"), cp.get("llm", "model_name"),
            cp.get("llm", "aws_region")) == ("AWS", "us.anthropic.claude-haiku-5-5", "us-east-1")
    assert cp.get("agents", "provider") == "anthropic"          # analyst left without a model
    assert (home / ".env").read_text().splitlines() == [
        "COMPOSE_PROFILES=ui",
        "COMPOSE_FILE=docker-compose.yml:docker-compose.override.yml:"
        "docker-compose.tailnet.yml:docker-compose.model.yml"]
    got = json.loads((creds / "persona" / "creds.json").read_text())
    assert got == {"Version": 1, **json.loads(CREDS % "-winnie-sensor-model-persona")}
    assert (creds / "persona" / "config").read_text() == (
        "[default]\ncredential_process = cat /model/creds.json\n")
    assert _cred_modes(creds, "persona") == {"creds.json": 0o400, "config": 0o400}
    assert sorted(p.name for p in creds.iterdir()) == ["persona"]   # no analyst directory
    assert not list(creds.rglob("*.new"))
    assert f"install -d -m 0500 -o 10001 -g 10001 {creds}/persona" in log
    assert f"install -d -m 0700 {creds}" in log
    assert "--role-arn arn:aws:iam::123456789012:role/winnie-sensor-model-persona " in log
    assert "--duration-seconds 3600" in log and "--endpoint-url https://sts.us-east-1.amazonaws.com" in log
    assert "sensor-model.sh" in (tmp_path / "sensor-firewall.sh").read_text()
    # Started now, not at the next boot: set-up runs after timers.target.
    assert "systemctl enable --now sensor-model.timer" in log
    assert "flock -w 600 9" in log
    # A second setup run adds nothing twice.
    _run_model(tmp_path)
    assert (home / ".env").read_text().count("docker-compose.model.yml") == 1
    assert (tmp_path / "sensor-firewall.sh").read_text().count("sensor-model") == 1
    assert _chain(tmp_path) == [("172.30.0.10", "10.64.0.37")]


def test_setup_with_both_models_gives_each_caller_its_own_role_and_mount(tmp_path):
    import json
    import yaml
    code, err, accepts, home, creds, log = _run_model(
        tmp_path, persona="us.anthropic.claude-haiku-5-5", analyst="global.anthropic.claude-x")
    assert code == 0, err
    assert sorted(accepts) == [("172.30.0.10", "10.64.0.37"), ("172.30.1.10", "10.64.0.37")]
    overlay = yaml.safe_load((home / "docker-compose.model.yml").read_text())
    assert set(overlay["services"]) == {"ssh", "agents"}
    assert overlay["services"]["agents"]["networks"] == {"backend": {"ipv4_address": "172.30.1.10"}}
    # Each container mounts its own directory and nothing else of the credentials root.
    assert overlay["services"]["ssh"]["volumes"] == [f"{creds}/persona:/model:ro"]
    assert overlay["services"]["agents"]["volumes"] == [f"{creds}/analyst:/model:ro"]
    # Each directory holds its own role's credentials.
    for who in ("persona", "analyst"):
        got = json.loads((creds / who / "creds.json").read_text())
        assert got["AccessKeyId"] == f"ASIA-winnie-sensor-model-{who}"
        assert _cred_modes(creds, who) == {"creds.json": 0o400, "config": 0o400}
        assert f"--role-session-name sensor-{who} " in log
    cp = _cfg(home)
    assert (cp.get("agents", "provider"), cp.get("agents", "model")) == (
        "bedrock", "global.anthropic.claude-x")


def test_readable_credentials_are_caught(tmp_path):
    # The mode test above would catch a script that leaves the files world-readable.
    script = check.MODEL_SCRIPT.read_text().replace('chmod 0400 "$D/$1/creds.new"',
                                                    'chmod 0444 "$D/$1/creds.new"')
    code, err, _, _, creds, _ = _run_model(tmp_path, script=script)
    assert code == 0, err
    assert _cred_modes(creds, "persona") != {"creds.json": 0o400, "config": 0o400}


@pytest.mark.parametrize("answer", ["192.0.2.10", "", "10.64.0.999", "10.65.0.1"])
def test_an_address_outside_the_vpc_changes_nothing(tmp_path, answer):
    code, err, accepts, home, creds, _ = _run_model(tmp_path, answer=answer)
    assert code == 1 and "no address inside the VPC" in err
    assert accepts == []
    assert not (home / "docker-compose.model.yml").exists()
    assert _cfg(home).get("llm", "llm_provider") == "openai"
    assert not creds.exists()


def test_a_failed_lookup_keeps_the_saved_address(tmp_path):
    code, err, accepts, _, _, _ = _run_model(tmp_path, answer="", saved="10.64.0.37",
                                             setup=False)
    assert code == 0, err
    assert accepts == [("172.30.0.10", "10.64.0.37")]


def test_the_same_address_again_changes_nothing(tmp_path):
    _run_model(tmp_path, persona="us.anthropic.claude-haiku-5-5", analyst="eu.anthropic.claude-x")
    code, err, accepts, _, _, log = _run_model(
        tmp_path, persona="us.anthropic.claude-haiku-5-5", analyst="eu.anthropic.claude-x",
        setup=False, running=True)
    assert code == 0, err
    assert accepts == [] and " -D " not in log and "compose" not in log


def test_a_new_address_moves_the_accepts_and_the_pin(tmp_path):
    import yaml
    _run_model(tmp_path, persona="us.anthropic.claude-haiku-5-5", analyst="eu.anthropic.claude-x")
    # Some other accept already in the chain, not a caller's: left alone.
    (tmp_path / "rules").write_text((tmp_path / "rules").read_text()
                                    + "-s 172.30.2.10/32 -d 10.64.0.37/32 -p tcp -m tcp "
                                      "--dport 443 -j ACCEPT\n")
    code, err, accepts, home, _, log = _run_model(
        tmp_path, persona="us.anthropic.claude-haiku-5-5", analyst="eu.anthropic.claude-x",
        answer="10.64.0.52", setup=False, running=True)
    assert code == 0, err
    assert sorted(accepts) == [("172.30.0.10", "10.64.0.52"), ("172.30.1.10", "10.64.0.52")]
    assert _chain(tmp_path) == [("172.30.0.10", "10.64.0.52"), ("172.30.1.10", "10.64.0.52"),
                                ("172.30.2.10", "10.64.0.37")]
    overlay = yaml.safe_load((home / "docker-compose.model.yml").read_text())
    for s in ("ssh", "agents"):
        assert overlay["services"][s]["extra_hosts"] == [
            "bedrock-runtime.us-east-1.amazonaws.com:10.64.0.52"]
    ups = [l for l in log.splitlines() if " up " in l]
    assert ups == ["docker compose up -d --no-deps ssh", "docker compose up -d --no-deps agents"]
    # The new accept goes in before the old ones go, and the pin after both.
    lines = log.splitlines()
    first_delete = next(i for i, l in enumerate(lines) if " -D " in l)
    assert max(i for i, l in enumerate(lines) if " -I " in l) < first_delete
    assert first_delete < next(i for i, l in enumerate(lines) if "compose config" in l)


def test_a_new_address_recreates_only_the_configured_running_callers(tmp_path):
    _run_model(tmp_path)                                          # persona only
    code, err, _, _, _, log = _run_model(tmp_path, answer="10.64.0.52", setup=False,
                                         running=True)
    assert code == 0, err
    assert [l for l in log.splitlines() if " up " in l] == ["docker compose up -d --no-deps ssh"]
    # Not running (a boot before the stack starts): the overlay alone, sensor.service does the rest.
    code, err, _, home, _, log = _run_model(tmp_path, answer="10.64.0.61", setup=False)
    assert code == 0, err
    assert " up " not in log and "10.64.0.61" in (home / "docker-compose.model.yml").read_text()


def test_a_refused_new_pin_still_removes_the_old_accepts(tmp_path):
    _run_model(tmp_path)
    before = (tmp_path / "home" / "docker-compose.model.yml").read_text()
    code, _, _, home, _, log = _run_model(tmp_path, answer="10.64.0.52", setup=False,
                                          compose_fails=True, running=True)
    assert code != 0
    # Fails closed: the containers keep the old name pin, which no rule lets them reach.
    assert _chain(tmp_path) == [("172.30.0.10", "10.64.0.52")]
    assert (home / "docker-compose.model.yml").read_text() == before
    assert " up " not in log
    # The next run tries the pin again.
    code, err, _, home, _, _ = _run_model(tmp_path, answer="10.64.0.52", setup=False)
    assert code == 0, err
    assert "10.64.0.52" in (home / "docker-compose.model.yml").read_text()


def test_a_refused_overlay_leaves_the_config_alone(tmp_path):
    code, _, accepts, home, _, _ = _run_model(tmp_path, compose_fails=True)
    assert code != 0 and accepts == []
    assert _cfg(home).get("llm", "llm_provider") == "openai"
    assert "docker-compose.model.yml" not in (home / ".env").read_text()
    assert not (home / "docker-compose.model.yml").exists()


def test_failed_credentials_leave_no_partial_file(tmp_path):
    code, err, accepts, _, creds, _ = _run_model(tmp_path, aws_fails=True)
    assert code == 1 and "could not assume the persona model role" in err
    assert accepts == [("172.30.0.10", "10.64.0.37")]       # the path is useless without them
    assert [p.relative_to(creds).as_posix() for p in creds.rglob("*")] == ["persona"]


@pytest.mark.parametrize("bad", ["PERSONA_MODEL=*", "PERSONA_MODEL='a.b;id'",
                                 "ANALYST_MODEL=anthropic.claude.x",
                                 "PERSONA_MODEL=ca.anthropic.claude-x",
                                 "ANALYST_MODEL=usgov.anthropic.claude-x",
                                 "ROLE_ARN=arn:aws:iam::123456789012:role/*",
                                 "VPC_CIDR=0.0.0.0/0", "VPC_CIDR=100.64.0.0/10",
                                 "REGION='us-east-1 x'", "SUFFIX=amazonaws.com/x"])
def test_bad_settings_stop_before_anything(tmp_path, bad):
    good = ("REGION=us-east-1\nSUFFIX=amazonaws.com\nVPC_CIDR=10.64.0.0/16\n"
            "ROLE_ARN=arn:aws:iam::123456789012:role/winnie-sensor-model\n"
            "PERSONA_MODEL=us.anthropic.claude-x\nANALYST_MODEL=\n")
    key = bad.split("=")[0]
    text = re.sub(rf"^{key}=.*$", lambda m: bad, good, flags=re.M)
    code, err, accepts, home, _, log = _run_model(tmp_path, env_text=text)
    assert code == 1 and "bad settings" in err
    assert accepts == [] and "docker" not in log and "aws" not in log


@pytest.mark.parametrize("prefix", check.PROFILE_PREFIXES)
def test_every_geographic_prefix_passes_the_host_script(tmp_path, prefix):
    code, err, _, home, _, _ = _run_model(tmp_path, persona=f"{prefix}.anthropic.claude-x")
    assert code == 0, err
    assert _cfg(home).get("llm", "model_name") == f"{prefix}.anthropic.claude-x"
