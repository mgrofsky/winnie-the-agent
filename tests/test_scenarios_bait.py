"""Per-sensor bait: templates in scenario packs expand from the sensor seed."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path

import pytest

from scenarios.bait import (
    FIRST_NAMES,
    LAST_NAMES,
    PASSWORD_WORDS,
    WEAK_PASSWORDS,
    TEMPLATE_RE,
    Bait,
    BaitError,
    Pins,
    is_template_only,
)
from scenarios.check import _DENY_RE, check_scenario
from scenarios.describe import describe
from scenarios.loader import SCENARIOS_DIR, list_scenarios, load_scenario
from scenarios.schema import (
    DOMAIN_RE,
    HOSTNAME_RE,
    USERNAME_RE,
    iter_credentials,
    valid_password,
)

SHIPPED = ["sip_provider", "contact_center", "bank", "healthcare", "saas", "api_platform"]


def _bait(seed="sensor-a", scenario="t_pack", **pins) -> Bait:
    return Bait(seed, scenario, Pins(**pins), {"tok": "VALUE-OF-TOKEN"})


def _x(text, seed="sensor-a", **pins) -> str:
    b = _bait(seed, **pins)
    b.scan(text)
    return b.expand_text(text)


# ---- generators ---------------------------------------------------------------------------

def test_same_template_same_value_and_labels_differ():
    b = _bait()
    doc = {"a": "{{password:ops}}", "b": ["x {{password:ops}} y"], "c": "{{password:other}}"}
    b.scan(doc)
    out = b.expand(doc)
    assert out["a"] == out["b"][0][2:-2]
    assert out["a"] != out["c"]
    assert "{{" not in json.dumps(out)


@pytest.mark.parametrize("style", ["human", "weak", "user", "service", "random"])
def test_password_styles_are_valid_and_vary_by_seed(style):
    values = {_x("{{password:voiceops:%s}}" % style, seed=f"s{i}") for i in range(200)}
    assert all(valid_password(v) and v for v in values)
    assert len(values) > (20 if style in ("weak", "user") else 150)


def test_human_passwords_take_human_shapes():
    values = [_x("{{password:p}}", seed=f"s{i}") for i in range(600)]
    shapes = {
        "season+year": r"(Spring|Summer|Autumn|Fall|Winter)\d{2,4}\W?",
        "keyboard": r"(?i).*(qwer|asdf|zxcv|1qaz|zaq1|qazwsx|1q2w|qweasd|123qwe|qwe123|poiuy).*",
        "name+digits": "(?i)(" + "|".join(FIRST_NAMES) + r")\d{2,4}\W?",
        "word+year+symbol": "(?i)(" + "|".join(PASSWORD_WORDS) + r")(\d{2}|\d{4})[!*.?_-]",
    }
    for label, pattern in shapes.items():
        assert any(re.fullmatch(pattern, v) for v in values), label
    # Not one template value: hundreds of different ones.
    assert len(set(values)) > 500


def test_word_lists_are_large_enough_to_say_nothing():
    assert len(set(FIRST_NAMES)) >= 250 and len(set(LAST_NAMES)) >= 250
    assert len(set(PASSWORD_WORDS)) >= 250 and len(set(WEAK_PASSWORDS)) >= 60


def test_user_style_builds_on_the_label():
    for i in range(50):
        assert _x("{{password:voiceops:user}}", seed=f"s{i}").lower().startswith("voiceops")


def test_sha1_is_the_hash_of_the_labelled_password():
    b = _bait()
    doc = {"pw": "{{password:admin:weak}}", "hash": "{{sha1:admin}}"}
    b.scan(doc)
    out = b.expand(doc)
    assert out["hash"] == hashlib.sha1(out["pw"].encode()).hexdigest()
    # Without a password template the hash still has one stable source.
    alone = _x("{{sha1:nobody}}")
    assert re.fullmatch(r"[0-9a-f]{40}", alone) and alone == _x("{{sha1:nobody}}")


@pytest.mark.parametrize("fmt, pattern", [
    ("token", r"[A-Za-z0-9]{40}"),
    ("api_key", r"[A-Za-z0-9]{32}"),
    ("client_secret", r"[A-Za-z0-9_-]{40}"),
    ("session", r"[0-9a-v]{26}"),
    ("uuid", r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"),
    ("aws_secret", r"[A-Za-z0-9/+]{40}"),
])
def test_secret_formats(fmt, pattern):
    v = _x("{{secret:%s:x}}" % fmt)
    assert re.fullmatch(pattern, v), v
    assert v != _x("{{secret:%s:x}}" % fmt, seed="sensor-b")


def test_secrets_never_look_like_live_provider_keys():
    live = re.compile(r"AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|sk_live_|rk_live_|xox[abpr]-|"
                      r"ghp_|gho_|github_pat_|glpat-|AIza[0-9A-Za-z_-]{35}|SG\.[\w-]{22}\.")
    for i in range(300):
        for fmt in ("token", "api_key", "client_secret", "aws_secret"):
            assert not live.search(_x("{{secret:%s:k}}" % fmt, seed=f"s{i}"))


@pytest.mark.parametrize("kind, pattern", [
    ("digits", r"[0-9]{6}"), ("hex", r"[0-9a-f]{6}"), ("alnum", r"[A-Za-z0-9]{6}")])
def test_sized_generators(kind, pattern):
    assert re.fullmatch(pattern, _x("{{%s:6:x}}" % kind))


def test_hosts_nets_and_people():
    b = _bait()
    doc = {
        "h": ["{{host:pbx}}", "{{host:db}}", "{{host:pbx}}"],
        "n": ["{{net:lan}}.21", "{{net:dmz}}.5"],
        "p": ["{{person:1.full_name}}", "{{person:1.first}}", "{{person:1.last}}",
              "{{person:1.username}}", "{{person:1.email}}", "{{person:2.full_name}}"],
        "d": "{{org.domain}}",
    }
    b.scan(doc)
    out = b.expand(doc)
    assert out["h"][0] == out["h"][2] != out["h"][1]
    for h in out["h"]:
        assert re.fullmatch(HOSTNAME_RE, h) and "pbx" in out["h"][0]
    import ipaddress
    for ip in out["n"]:
        assert ipaddress.ip_address(ip).is_private
    full, first, last, user, email, other = out["p"]
    assert full == f"{first} {last}" and full != other
    assert re.fullmatch(USERNAME_RE, user)
    assert email.endswith("@" + out["d"])


def test_people_do_not_depend_on_expansion_order():
    a, b = _bait(), _bait()
    a.scan("{{person:7.full_name}} {{person:1.full_name}}")
    b.scan("{{person:1.full_name}} {{person:7.full_name}}")
    assert a.expand_text("{{person:7.full_name}}") == b.expand_text("{{person:7.full_name}}")


def test_org_identity_is_invented_and_reserved():
    names, domains = set(), set()
    for i in range(400):
        b = _bait(seed=f"s{i}", org_suffixes=["Voice Networks", "Telecom"],
                  domain_words=["voice", "tel"])
        org = b.org()
        names.add(org["name"])
        domains.add(org["domain"])
        assert not _DENY_RE.search(org["name"]), org["name"]
        assert re.fullmatch(DOMAIN_RE, org["domain"])
        assert org["domain"].endswith((".example", ".test"))
        assert org["name"].endswith(("Voice Networks", "Telecom"))
        assert org["abbr"].isalnum() and org["ABBR"] == org["abbr"].upper()
    assert len(names) > 350 and len(domains) > 300
    old = ("bellweather", "larkspur", "quillmere", "marrowfield", "plinthwork", "corvidae")
    assert not [n for n in names if n.split()[0].lower().startswith(old)]


def test_pins_fix_identity():
    pinned = _x("{{org.name}}|{{org.domain}}|{{org.abbr}}|{{host:pbx}}",
                org_name="Example Voice Networks", domain="ex-voice.example",
                hosts={"pbx": "pbx01"})
    assert pinned == "Example Voice Networks|ex-voice.example|evn|pbx01"
    # Pinning the name leaves credentials per sensor.
    assert _x("{{password:x}}", org_name="A Corp") != _x("{{password:x}}", seed="b",
                                                          org_name="A Corp")


def test_literal_braces():
    assert _x("{{open}} .Values.x {{close}}") == "{{ .Values.x }}"


@pytest.mark.parametrize("bad, needle", [
    ("{{nosuch:x}}", "unknown template"),
    ("{{org.ceo}}", "unknown organisation field"),
    ("{{password:x:strong}}", "unknown password style"),
    ("{{password:}}", "password template"),
    ("{{secret:stripe:x}}", "unknown secret format"),
    ("{{digits:0:x}}", "digits template"),
    ("{{digits:500:x}}", "digits template"),
    ("{{person:0.first}}", "person template"),
    ("{{person:1.ssn}}", "person template"),
    ("{{host:PBX}}", "host template"),
    ("{{ht:missing}}", "unknown honeytoken"),
    ("{{password:x}} {{password:x:weak}}", "conflicts with"),
])
def test_bad_templates_are_load_errors(bad, needle):
    with pytest.raises(BaitError, match=needle):
        _bait().scan({"field": bad})


def test_empty_seed_is_an_error():
    with pytest.raises(BaitError, match="no sensor seed"):
        Bait("", "t_pack")
    with pytest.raises(BaitError, match="no sensor seed"):
        load_scenario("sip_provider", seed="")


def test_template_only_helper():
    assert is_template_only("{{password:x}}") and is_template_only("") and \
        is_template_only("********") and is_template_only("{{ht:a}}")
    assert not is_template_only("admin") and not is_template_only("pw-{{digits:2:x}}x")


# ---- loading a pack -----------------------------------------------------------------------

PACK = """
name = "t_pack"
title = "{{org.name}} test"
description = "x"

[bait]
org_suffixes = ["Labs"]
domain_words = ["lab"]

[identity]
org_name = "{{org.name}}"
hostname = "{{host:app}}"
domain = "{{org.domain}}"
internal_ips = ["{{net:lan}}.10"]
os_pretty_name = "Debian GNU/Linux 12 (bookworm)"
kernel = "Linux {{host:app}} 6.1.0-26-amd64 x86_64 GNU/Linux"

[[identity.users]]
name = "{{person:1.username}}"
uid = 1001
gecos = "{{person:1.full_name}}"
home = "/home/{{person:1.username}}"

[[ssh.accounts]]
username = "{{person:1.username}}"
password = "{{password:person1}}"

[services.ftp]
enabled = true
port = 2121

[[services.ftp.accounts]]
username = "{{person:1.username}}"
password = "{{password:person1}}"

[[services.ftp.files]]
path = "/notes.txt"
content = "login {{person:1.username}} / {{password:person1}} on {{host:app}}.{{org.domain}}"
"""


def _pack(tmp_path: Path, text: str = PACK, name: str = "t_pack") -> Path:
    (tmp_path / name).mkdir(parents=True, exist_ok=True)
    (tmp_path / name / "scenario.toml").write_text(text)
    return tmp_path


def test_pack_expands_consistently_across_services(tmp_path):
    loaded = load_scenario("t_pack", seed="sensor-a", scenarios_dir=_pack(tmp_path))
    sc = loaded.scenario
    user, pw = loaded.accounts_for("ssh")[0]
    assert loaded.accounts_for("ftp") == [(user, pw)]
    assert sc.services.ftp.files[0].content == \
        f"login {user} / {pw} on {sc.identity.hostname}.{sc.identity.domain}"
    assert sc.identity.users[0].home == f"/home/{user}"
    assert sc.title == f"{sc.identity.org_name} test" and sc.identity.org_name.endswith(" Labs")
    assert loaded.bait["{{password:person1}}"] == pw
    assert f"Linux {sc.identity.hostname} " in sc.identity.kernel


def test_pack_stable_per_seed_and_different_across_seeds(tmp_path):
    d = _pack(tmp_path)
    a1 = load_scenario("t_pack", seed="sensor-a", scenarios_dir=d)
    a2 = load_scenario("t_pack", seed="sensor-a", scenarios_dir=d)
    b = load_scenario("t_pack", seed="sensor-b", scenarios_dir=d)
    assert a1.scenario == a2.scenario and a1.bait == a2.bait
    assert a1.accounts_for("ssh") != b.accounts_for("ssh")
    assert a1.scenario.identity.org_name != b.scenario.identity.org_name


def test_literal_identity_pins_templates(tmp_path):
    text = PACK.replace('org_name = "{{org.name}}"', 'org_name = "Pinned Labs"') \
               .replace('domain = "{{org.domain}}"', 'domain = "pinned.example"')
    loaded = load_scenario("t_pack", seed="sensor-a", scenarios_dir=_pack(tmp_path, text))
    assert loaded.scenario.title == "Pinned Labs test"
    assert loaded.scenario.services.ftp.files[0].content.endswith(".pinned.example")


def test_bait_section_pins_and_hosts(tmp_path):
    text = PACK.replace('org_suffixes = ["Labs"]',
                        'org_name = "Kestrel Labs"\ndomain = "kestrel.test"\n'
                        'hosts = { app = "app07" }')
    loaded = load_scenario("t_pack", seed="sensor-a", scenarios_dir=_pack(tmp_path, text))
    ident = loaded.scenario.identity
    assert (ident.org_name, ident.domain, ident.hostname) == \
        ("Kestrel Labs", "kestrel.test", "app07")


def test_custom_pack_with_literals_keeps_working(tmp_path):
    text = """
name = "t_pack"
title = "Literal pack"
description = "x"
[identity]
org_name = "Literal Org"
hostname = "host1"
domain = "literal.example"
internal_ips = ["10.0.0.5"]
os_pretty_name = "Debian GNU/Linux 12"
kernel = "Linux host1 6.1.0 x86_64"
[[ssh.accounts]]
username = "root"
password = "hunter2"
[services.redis]
enabled = true
port = 6379
[[services.redis.accounts]]
username = "default"
password = "{{ht:redis_pw}}"
[[honeytokens]]
name = "redis_pw"
kind = "db_password"
planted_in = ["redis account"]
"""
    loaded = load_scenario("t_pack", seed="sensor-a", scenarios_dir=_pack(tmp_path, text))
    assert loaded.accounts_for("ssh") == [("root", "hunter2")]
    assert loaded.accounts_for("redis")[0][1] == loaded.honeytokens["redis_pw"].value
    assert loaded.bait == {}


def test_unknown_template_in_pack_names_the_field(tmp_path):
    text = PACK.replace('content = "login', 'content = "{{passwd:x}} login')
    with pytest.raises(BaitError, match=r"services\.ftp\.files\[0\]\.content.*unknown template"):
        load_scenario("t_pack", seed="sensor-a", scenarios_dir=_pack(tmp_path, text))


# ---- the bundled packs --------------------------------------------------------------------

def _raw(name: str) -> dict:
    with open(SCENARIOS_DIR / name / "scenario.toml", "rb") as f:
        return tomllib.load(f)


@pytest.mark.parametrize("name", SHIPPED)
def test_bundled_pack_has_no_literal_credentials(name):
    """Every field the schema marks as a credential (account passwords, SIP secrets and
    seed-row cells of ``secret = true`` columns) is a template, empty or masked."""
    found = list(iter_credentials(_raw(name)))
    assert found, "the walk found no credential fields at all"
    literal = [(p, v) for p, v in found if not is_template_only(v)]
    assert literal == []


# Assignments of a secret-looking name to a value inside free text (file contents, HTTP
# bodies, Redis values, JSON bodies): KEY=value, key: value, "key": "value", URL userinfo.
_SECRET_NAME = r"[A-Za-z_.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|sess(?:ion)?id)"
_ASSIGN_RE = re.compile(r"(?i)(?<![A-Za-z])(" + _SECRET_NAME + r")[A-Za-z_]*['\"]?\s*(?:=>|=|:)\s*"
                        r"['\"]?([^\s'\",;<>)]+)")
_URL_CRED_RE = re.compile(r"://[^/\s:@]+:([^@\s/]+)@")
_SECRET_KEY_RE = re.compile(r"(?i)^(?:.*_)?(password|passwd|pwd|secret|client_secret|token|"
                            r"api_key|apikey|access_key|secret_key|session_id|sid)$")
_HARMLESS = re.compile(r"^(\{\{.*|\*+.*|[0-9]{1,5}|true|false|yes|no|none|null|required|"
                       r"hidden|optional|bearer|basic|header|query|string|apiKey|http)$", re.I)


def _free_text_secrets(raw) -> list[tuple[str, str]]:
    from scenarios.bait import iter_strings

    hits = []

    def walk(obj, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                sub = f"{path}.{k}" if path else k
                if isinstance(v, str) and _SECRET_KEY_RE.match(str(k)) and \
                        not is_template_only(v) and not _HARMLESS.match(v):
                    hits.append((sub, v))
                walk(v, sub)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{path}[{i}]")

    walk(raw)
    for path, text in iter_strings(raw):
        text = TEMPLATE_RE.sub("{{}}", text)
        for m in _ASSIGN_RE.finditer(text):
            if not _HARMLESS.match(m.group(2)):
                hits.append((path, m.group(0)))
        for m in _URL_CRED_RE.finditer(text):
            if not is_template_only(m.group(1)):
                hits.append((path, m.group(0)))
    return hits


@pytest.mark.parametrize("name", SHIPPED)
def test_bundled_pack_has_no_literal_secrets_in_free_text(name):
    assert _free_text_secrets(_raw(name)) == []


def test_free_text_scan_catches_the_usual_shapes():
    raw = {"a": "AMPDBPASS = 'hunter2'", "b": "postgres://u:hunter2@db/x",
           "c": {"client_secret": "abc123def"}, "d": "export DB_PASSWORD=hunter2",
           "ok": "password={{password:x}} token=******** <input type=\"password\">"}
    assert [p for p, _ in _free_text_secrets(raw)] == ["c.client_secret", "a", "b", "d"]


@pytest.mark.parametrize("name", SHIPPED)
def test_bundled_pack_identity_and_credentials_are_per_sensor(name):
    a1 = load_scenario(name, seed="sensor-a")
    a2 = load_scenario(name, seed="sensor-a")
    b = load_scenario(name, seed="sensor-b")
    assert a1.scenario == a2.scenario and a1.bait == a2.bait
    ia, ib = a1.scenario.identity, b.scenario.identity
    assert ia.org_name != ib.org_name and ia.domain != ib.domain and ia.hostname != ib.hostname
    for svc in ("ssh", "sip", "ftp", "telnet", "postgres", "mysql", "mssql", "redis", "smtp",
                "http", "s3"):
        pa = [p for _, p in a1.accounts_for(svc)]
        pb = [p for _, p in b.accounts_for(svc)]
        if pa:
            assert pa != pb, svc
    assert any(k.startswith("{{password:") for k in a1.bait)


@pytest.mark.parametrize("name", SHIPPED)
@pytest.mark.parametrize("seed", ["sensor-a", "sensor-b", "s3", "s4", "s5", "s6"])
def test_bundled_pack_passes_the_checker_for_many_seeds(name, seed):
    assert check_scenario(load_scenario(name, seed=seed)) == []


@pytest.mark.parametrize("name", SHIPPED)
def test_bundled_pack_text_names_no_fixed_organisation(name):
    """The old fixed identities must not survive in the pack text."""
    text = (SCENARIOS_DIR / name / "scenario.toml").read_text().lower()
    for old in ("bellweather", "larkspur", "quillmere", "marrowfield", "plinthwork",
                "corvidae", "bwv-", "qst-", "pbx01", "gw-edge-02", "ehr-int01", "cc-app02",
                "qst-obk01", "hpt_revoked", "copperleaf", "northgate", "tidewater",
                "lanternfly", "brookhollow", "pebblestack", "riverside"):
        assert old not in text, old


def test_every_shipped_pack_listed():
    assert set(SHIPPED) <= set(list_scenarios())


def test_describe_shows_this_sensors_bait_but_no_honeytokens():
    loaded = load_scenario("sip_provider", seed="sensor-a")
    out = describe("sip_provider", seed="sensor-a")
    assert "specific to this sensor" in out
    for template, value in loaded.bait.items():
        if template.startswith("{{password:"):
            assert f"{template} = {value}" in out
    for t in loaded.honeytokens.values():
        assert t.value not in out
    assert loaded.scenario.identity.org_name in out
    assert describe("sip_provider", seed="sensor-b") != out


# ---- one story across services ------------------------------------------------------------

def test_sip_provider_story_is_consistent_on_one_sensor():
    loaded = load_scenario("sip_provider", seed="sensor-a")
    sc = loaded.scenario
    ht = {t.name: t.value for t in loaded.honeytokens.values()}
    files = {f.path: f.content or "" for f in sc.services.ftp.files}
    # The database password in the FreePBX config backup is the one MySQL accepts.
    mysql = dict(loaded.accounts_for("mysql"))
    assert f"AMPDBPASS'] = '{mysql['freepbxuser']}'" in files["/backups/etc/freepbx.conf"]
    assert mysql["freepbxuser"] == ht["freepbx_db_password"]
    # The engineer's user name is the same in /etc/passwd, the web UI and the SSH profile,
    # and their web password is the one root uses over SSH.
    engineer = sc.identity.users[1].name
    http = dict(loaded.accounts_for("http"))
    assert http[engineer] == dict(loaded.accounts_for("ssh"))["root"]
    assert f"Owner: {engineer}" in files["/backups/scripts/offsite-backup.sh"]
    # The FreePBX admin hashes crack to the web passwords.
    _, rows = loaded.table_rows("asterisk", "ampusers")
    hashes = {r[0]: r[1] for r in rows}
    assert hashes["admin"] == hashlib.sha1(http["admin"].encode()).hexdigest()
    assert hashes[engineer] == hashlib.sha1(http[engineer].encode()).hexdigest()
    # Shared accounts reuse one password across SSH, FTP and telnet.
    assert len({dict(loaded.accounts_for(s))["voiceops"] for s in ("ssh", "ftp", "telnet")}) == 1
    # Host, domain and network agree everywhere they appear.
    host, domain = sc.identity.hostname, sc.identity.domain
    assert sc.services.smtp.banner == f"220 {host}.{domain} ESMTP Postfix (Debian/GNU)"
    assert sc.services.sip.realm == domain
    lan = sc.identity.internal_ips[0].rsplit(".", 1)[0]
    assert f"local_net={lan}.0/24" in files["/backups/etc-asterisk/pjsip.conf"]
    assert f"Linux {host} " in sc.identity.kernel
    assert host in loaded.persona_fragment() and sc.identity.org_name in loaded.persona_fragment()
    # SIP extensions and the FreePBX users table name the same people.
    _, users = loaded.table_rows("asterisk", "users")
    names = {r[0]: r[2] for r in users}
    for ext in sc.services.sip.extensions:
        assert names[ext.extension] == ext.display_name


def test_tuner_overlay_adds_accounts_on_top_of_a_templated_pack(tmp_path):
    import datetime

    from agents.triage import CredentialStats, TriageRecord
    from agents.tuner import tune

    now = datetime.datetime.now(datetime.timezone.utc)
    rec = TriageRecord(
        kind="campaign", id="c1", protocol="ssh", src_ip="198.51.100.7",
        first_seen=now.isoformat(), last_seen=now.isoformat(), auth_attempts=5,
        intent="CREDENTIAL_BRUTE_FORCE", stage="CREDENTIAL_ACCESS", skill="AUTOMATED",
        judgement="SUSPICIOUS", narrative="x",
        credentials=CredentialStats(top_usernames=[("oracle", 4)],
                                    top_pairs=[("oracle", "oracle%123", 4)]))
    reports = tmp_path / "reports" / "campaigns"
    reports.mkdir(parents=True)
    (reports / "c1.json").write_text(rec.model_dump_json())
    overlay = tmp_path / "overlay.json"
    loaded = load_scenario("sip_provider", seed="sensor-a")
    res = tune(overlay, tmp_path / "reports", state_dir=tmp_path / "state", scenario=loaded,
               now=now)
    assert "add_account ssh:oracle" in [c.describe() for c in res.changes]
    again = load_scenario("sip_provider", seed="sensor-a", overlay_path=overlay)
    ssh = again.accounts_for("ssh")
    assert ("oracle", "oracle%123") in ssh
    # The pack's own per-sensor accounts are untouched by the overlay.
    assert ssh[:len(loaded.accounts_for("ssh"))] == loaded.accounts_for("ssh")


def test_ship_hashes_per_sensor_passwords():
    from agent_fakes import trap_event

    from agents import ship

    loaded = load_scenario("sip_provider", seed="sensor-a")
    user, pw = loaded.accounts_for("ftp")[0]
    rec = trap_event("ftp", "auth", "198.51.100.7", "t", username=user, password=pw)
    key = ship.password_key("sensor-a")
    out = ship.protect(rec, "hash", key)
    assert out["password"] == ship.hash_secret(key, pw)
    assert pw not in json.dumps(out) and out["username"] == user


def test_org_names_avoid_common_real_place_names():
    real = {"oakland", "millbrook", "glenwood", "oakwood", "elmwood", "ashford", "holland",
            "flintstone", "rushmore", "birchwood", "heathrow", "claymore", "brookfield",
            "fairfield", "springfield", "ashland", "reedley", "hazelwood", "mossley"}
    for i in range(3000):
        short = _bait(seed=f"s{i}").org()["short"].lower()
        assert short not in real, short


def test_companies_and_places_are_invented_distinct_and_per_sensor():
    seen_names = set()
    for i in range(300):
        b = _bait(seed=f"s{i}", org_suffixes=["Labs"])
        doc = {"c": [f"{{{{company:{n}.name}}}}" for n in range(1, 11)],
               "s": [f"{{{{company:{n}.short}}}}" for n in range(1, 11)],
               "d": [f"{{{{company:{n}.domain}}}}" for n in range(1, 11)],
               "p": [f"{{{{place:{n}}}}}" for n in range(1, 6)], "o": "{{org.short}}"}
        b.scan(doc)
        out = b.expand(doc)
        words = out["s"] + out["p"] + [out["o"]]
        assert len(set(w.lower() for w in words)) == len(words)
        for name, short, dom in zip(out["c"], out["s"], out["d"], strict=True):
            assert name.startswith(short + " ") and not _DENY_RE.search(name)
            assert dom == short.lower() + ".example" and re.fullmatch(DOMAIN_RE, dom)
        seen_names.add(out["c"][0])
    assert len(seen_names) > 250


@pytest.mark.parametrize("bad", ["{{company:0.name}}", "{{company:1.ceo}}", "{{place:x}}",
                                 "{{url:}}", "{{url:url:password:x}}", "{{url:open}}"])
def test_bad_company_place_and_url_templates(bad):
    with pytest.raises(BaitError):
        _bait().scan({"f": bad})


def test_bundled_customer_companies_differ_per_sensor():
    a = load_scenario("saas", seed="sensor-a").table_rows
    b = load_scenario("saas", seed="sensor-b").table_rows
    db = load_scenario("saas", seed="sensor-a").scenario.services.postgres.databases[0].name
    assert [r[2] for r in a(db, "tenants")[1][1:4]] != [r[2] for r in b(db, "tenants")[1][1:4]]
