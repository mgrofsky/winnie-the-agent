"""Render a sensor config file from the image's config template (AWS bootstrap).

    python3 render_config.py SRC DST NAME SCENARIO PUBLIC_IP SMTP BUCKET PREFIX REGION OWNER \\
        TRACKED TRACKED_KEY NEVER_ACT_ON SHIP
    python3 render_config.py models DST PERSONA_MODEL ANALYST_MODEL REGION

deploy/aws/sensor.yaml copies this file out of the image (/app/deploy/aws/render_config.py)
and runs it with the host's python3 (Amazon Linux 2023 ships 3.9, so nothing newer than
3.9 here) twice: config.ini for the front-ends and agents with SHIP=false, config-ship.ini
for the exporter with SHIP=true. Sections the template has only commented out
("#[connector.s3_events]") get a real header at the end. Every value written is read back
with configparser; any mismatch exits non-zero and the bootstrap stops.

The models form edits DST in place (the model step, PersonaModelId / AnalystModelId): a
non-empty persona model id sets [llm] to Bedrock with that model, a non-empty analyst model
id sets [agents] the same way, both in REGION and with the default profile, whose
credentials the step provides. An empty id leaves its section as it was.
"""
import configparser, re, sys
if sys.argv[1:2] == ["models"]:
    dst, persona, analyst, region = sys.argv[2:6]
    src = dst
    want = {}
    if persona:
        want["llm"] = {"llm_provider": "AWS", "model_name": persona, "aws_region": region,
                       "aws_credentials_profile": "default"}
    if analyst:
        want["agents"] = {"provider": "bedrock", "model": analyst, "aws_region": region}
else:
    (src, dst, name, scenario, public_ip, smtp, bucket, prefix, region, owner, tracked,
     tracked_key, never, ship) = sys.argv[1:15]
    want = None
lines = open(src, encoding="utf-8").read().splitlines()
if want is None:
    want = {
        "honeypot": {"sensor_name": name},
        "scenario": {"active": scenario.replace("-", "_")},
        "listeners": {"ftp_pasv_ports": "30000-30019", "ftp_pasv_address": public_ip,
                      "llm": "false"},
        "respond": {"queue_enforce": "true", "track_before_enforce": tracked},
        "connector.s3_events": {"enabled": ship, "bucket": bucket, "prefix": prefix + "/",
                                "region": region, "bucket_owner": owner,
                                "layout": "wrapped", "passwords": "hash"},
        "connector.tracked_export": {
            "enabled": "true" if ship == "true" and tracked == "true" else "false",
            "kind": "s3", "file": "/blocklist/tracked.json", "bucket": bucket,
            "key": tracked_key, "region": region, "bucket_owner": owner},
    }
    if smtp != "true":
        want["listeners"]["smtp_enabled"] = "false"
    if never.strip():
        want["respond"]["never_act_on"] = never.strip()
for section in want:
    if "[%s]" % section not in [l.strip() for l in lines]:
        lines += ["", "[%s]" % section]
def section_range(section):
    start = None
    for i, line in enumerate(lines):
        m = re.match(r"^\[([^\]]+)\]\s*$", line)
        if m and start is not None:
            return start, i
        if m and m.group(1) == section:
            start = i
    if start is None:
        sys.exit("config template has no [%s] section" % section)
    return start, len(lines)
for section, keys in want.items():
    for key, value in keys.items():
        start, end = section_range(section)
        hit = None
        for pattern in (r"^%s\s*=", r"^#\s*%s\s*="):
            for i in range(start + 1, end):
                if re.match(pattern % re.escape(key), lines[i]):
                    hit = i
                    break
            if hit is not None:
                break
        if hit is None:
            while end > start + 1 and not lines[end - 1].strip():
                end -= 1
            lines.insert(end, "%s = %s" % (key, value))
        else:
            lines[hit] = "%s = %s" % (key, value)
open(dst, "w", encoding="utf-8").write("\n".join(lines) + "\n")
cp = configparser.ConfigParser(interpolation=None, strict=False)
cp.read(dst, encoding="utf-8")
for section, keys in want.items():
    for key, value in keys.items():
        if cp.get(section, key, fallback=None) != value:
            sys.exit("config.ini check failed: [%s] %s" % (section, key))
print("%s written" % dst)
