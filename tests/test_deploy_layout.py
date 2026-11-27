"""Docker trust boundaries: who may write what (compose is parsed, never run)."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _compose():
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text())


def _mounts(service):
    out = []
    for v in service.get("volumes", []):
        parts = v.split(":")
        out.append((parts[0], parts[1], parts[2] if len(parts) > 2 else "rw"))
    return out


def test_agents_container_does_not_mount_the_repository():
    agents = _compose()["services"]["agents"]
    for src, _dst, mode in _mounts(agents):
        assert src not in (".", "./", str(ROOT)), "repo must not be mounted"
        if src.startswith("."):
            assert mode == "ro" and src == "./SSH/config.ini"


def test_volume_write_boundaries():
    services = _compose()["services"]
    agents = {src: mode for src, _d, mode in _mounts(services["agents"])}
    assert agents["frontend"] == "ro" and agents["agentdata"] == "rw" and agents["overlay"] == "rw"
    for name, svc in services.items():
        if name in ("agents", "ui"):     # ui: see test_ui_console_is_read_only_and_loopback
            continue
        mounts = {src: mode for src, _d, mode in _mounts(svc)}
        assert "agentdata" not in mounts, f"{name} must not see agent data"
        assert mounts.get("overlay") == "ro", f"{name} must not write the overlay"
        assert all(mode == "ro" for src, mode in mounts.items() if src.startswith("."))


def test_frontends_use_the_data_volume_for_state():
    services = _compose()["services"]
    for name in ("ssh", "listeners"):
        env = services[name]["environment"]
        assert env["WINNIE_DATA_DIR"] == "/data"
        assert env["WINNIE_OVERLAY"] == "/overlay/overlay.json"
        assert env["WINNIE_SOURCE_STATE"] == "/overlay/source_state.json"
        assert services[name]["read_only"] is True and services[name]["user"] == "10001:10001"
    assert "ANTHROPIC_API_KEY" in services["agents"]["environment"]
    text = (ROOT / "docker-compose.yml").read_text()
    assert "sk-ant" not in text  # never a key value, only the variable name


def test_only_agents_make_outbound_connector_calls():
    services = _compose()["services"]
    assert services["agents"]["environment"]["WINNIE_SOURCE_STATE"] == "/overlay/source_state.json"
    for name in ("ssh", "listeners"):
        assert not any(k.startswith("WINNIE_WEBHOOK") for k in services[name]["environment"])


def test_only_the_agents_get_aws_settings_and_only_the_region():
    services = _compose()["services"]
    aws = {k for k in services["agents"]["environment"] if k.startswith("AWS_")}
    assert aws == {"AWS_REGION"}
    for name, svc in services.items():
        if name != "agents":
            assert not any(k.startswith("AWS_") for k in svc.get("environment") or {}), name
        assert not any(".aws" in str(v) for v in svc.get("volumes") or []), name


# Directories the code writes at runtime (they live on volumes or under env-configured
# paths in the image), as opposed to directories it reads and must find in the image.
RUNTIME_WRITTEN = {"data", "reports", "quarantine", "detections", "decoy"}


SSH_RUNTIME_FILES = {"SSH/ssh_server.py", "SSH/prompt.txt", "SSH/config.ini.TEMPLATE"}


def _copy_sources():
    """Sources of the Dockerfile's COPY lines (copies from another stage excluded)."""
    import re

    out = []
    for m in re.finditer(r"^COPY (?!--from)(.+)$", (ROOT / "Dockerfile").read_text(), re.M):
        *sources, _dest = m.group(1).split()
        out.extend(src.rstrip("/") for src in sources)
    return out


def test_image_contains_everything_loaded_at_runtime():
    import re

    sources = _copy_sources()
    # A whole directory is copied by name; SSH is copied file by file (checked below).
    copied = {src for src in sources if "/" not in src}
    copied |= {src.split("/")[0] for src in sources if src.startswith("SSH/")}
    # Every top-level directory the code reaches through REPO_ROOT.
    referenced = set()
    for pkg in ("agents", "listeners", "scenarios", "SSH"):
        for path in (ROOT / pkg).rglob("*.py"):
            referenced |= set(re.findall(r'REPO_ROOT / "([A-Za-z_.-]+)"', path.read_text()))
    missing = referenced - RUNTIME_WRITTEN - copied
    assert not missing, f"loaded at runtime but not copied into the image: {missing}"
    # Every first-party package imported anywhere at runtime.
    imported = set()
    for pkg in ("agents", "listeners", "scenarios", "SSH"):
        for path in (ROOT / pkg).rglob("*.py"):
            imported |= set(re.findall(r"^\s*(?:from|import) (agents|listeners|scenarios)\b",
                                       path.read_text(), re.M))
    assert imported <= copied, f"imported but not in the image: {imported - copied}"
    assert {"SSH", "playbooks"} <= copied


def test_image_copies_only_the_named_ssh_files_and_the_license():
    text = (ROOT / "Dockerfile").read_text()
    sources = _copy_sources()
    # No directory-wide copy of SSH/: it would sweep in keys, local config and deploy notes.
    assert "SSH" not in sources
    assert {s for s in sources if s.startswith("SSH")} == SSH_RUNTIME_FILES
    for src in SSH_RUNTIME_FILES:
        assert (ROOT / src).is_file(), src
    assert "COPY LICENSE /app/LICENSE" in text
    license_text = (ROOT / "LICENSE").read_text()
    assert "Splunk GitHub" in license_text and "Matt Grofsky" in license_text
    # The build context also leaves out local deployment material and generated secrets.
    ignored = (ROOT / ".dockerignore").read_text().split()
    for pattern in ("SSH/DEPLOY/", "SSH/config.ini", "SSH/*host_key*", "SSH/*.pub"):
        assert pattern in ignored, pattern
    # The AWS bootstrap files stay in the image.
    assert "COPY deploy/aws/render_config.py" in text and "COPY deploy/aws/host" in text


def _aws_compose():
    """The docker-compose.yml that deploy/aws/sensor.yaml writes on the host."""
    import re
    import textwrap

    text = (ROOT / "deploy" / "aws" / "sensor.yaml").read_text()
    body = re.search(r"cat > docker-compose.yml <<'EOF'\n(.*?)\n\s*EOF\n", text, re.S).group(1)
    # CloudFormation substitutions: a trailing one splices in optional lines (dropped here),
    # one inside a value becomes a placeholder, and the image reference is not needed.
    lines = [line for line in textwrap.dedent(body).splitlines()
             if not line.strip().startswith("image:")]
    cleaned = [re.sub(r"\$\{[^}]*\}", "x", re.sub(r"\$\{[^}]*\}$", "", line)) for line in lines]
    return yaml.safe_load("\n".join(cleaned))


def test_every_event_log_reader_and_writer_runs_as_the_same_uid():
    """The raw event log is created 0600 by whichever writer logs first, so the readers (agents,
    exporter, console) can open it only because they share the writers' UID, in both the
    bundled compose file and the AWS host's."""
    for name, services in (("docker-compose.yml", _compose()["services"]),
                           ("deploy/aws/sensor.yaml", _aws_compose()["services"])):
        for service, spec in services.items():
            assert spec.get("user") == "10001:10001", f"{name}: {service} runs as {spec.get('user')}"
    aws = _aws_compose()["services"]
    assert {"ssh", "listeners", "agents", "exporter"} <= set(aws)
    assert "USER 10001" in (ROOT / "Dockerfile").read_text()


def test_nothing_else_in_the_shipped_deployment_creates_the_event_log():
    """Only the SSH handler and the listeners' writer create ssh_log.log; no image step, compose
    file or bootstrap script pre-creates or touches it."""
    import re

    for path in (ROOT / "Dockerfile", ROOT / "docker-compose.yml", ROOT / "deploy" / "aws" / "sensor.yaml"):
        for line in path.read_text().splitlines():
            if "ssh_log" in line:
                assert not re.search(r"\b(touch|install|chmod|chown|mkdir|cp|tee|>)\b[^\"']*ssh_log",
                                     line.replace("--log", "").replace("--log-file", "")), \
                    f"{path.name}: {line.strip()}"
    creators = [p.relative_to(ROOT).as_posix() for pkg in ("agents", "listeners", "SSH")
                for p in (ROOT / pkg).rglob("*.py")
                if "open_event_log" in p.read_text() and p.name != "eventlog.py"]
    assert sorted(creators) == ["SSH/ssh_server.py", "listeners/events.py"]


class _OverrideLoader(yaml.SafeLoader):
    """Reads compose override files: ``!override`` keeps the value it tags."""


_OverrideLoader.add_constructor(
    "!override", lambda loader, node: loader.construct_sequence(node)
    if isinstance(node, yaml.SequenceNode) else loader.construct_scalar(node))


def _override(name):
    return yaml.load((ROOT / name).read_text(), Loader=_OverrideLoader)


# Three kinds of service: agents, the operator console (ui) and the front-ends (the rest).
FRONTENDS = [name for name in _compose()["services"] if name not in ("agents", "ui")]


def test_every_frontend_is_only_on_the_frontend_network():
    services = _compose()["services"]
    assert {"listeners-bank", "listeners-healthcare", "listeners-contact-center",
            "listeners-saas", "listeners-api-platform"} <= set(FRONTENDS)
    for name in FRONTENDS:
        assert services[name].get("networks") == ["frontend"], f"{name} not on frontend"
    assert "networks" not in services["agents"]       # agents stay on the default network


def test_isolated_and_lab_overrides_cover_every_frontend():
    isolated = _override("docker-compose.isolated.yml")["services"]
    lab = _override("docker-compose.lab.yml")["services"]
    published = []
    for name in FRONTENDS:
        assert isolated[name]["networks"] == ["frontend"] and isolated[name]["ports"] == [], name
        assert lab[name]["ports"], name
        for port in lab[name]["ports"]:
            assert port.startswith("127.0.0.1:"), f"{name} publishes {port} beyond loopback"
            published.append(port.rsplit(":", 1)[0] + ("/udp" if port.endswith("/udp") else ""))
    assert len(published) == len(set(published)), "lab host ports collide"


# ---- operator console ----------------------------------------------------------------------

def test_ui_console_is_read_only_and_loopback():
    compose = _compose()
    ui = compose["services"]["ui"]
    assert ui.get("profiles") == ["ui"], "the console must be off unless asked for"
    mounts = {src: mode for src, _d, mode in _mounts(ui)}
    assert {"agentdata", "frontend", "overlay", "./SSH/config.ini"} <= set(mounts)
    assert all(mode == "ro" for mode in mounts.values()), mounts
    assert not any(src in (".", "./", str(ROOT)) for src in mounts), "repo must not be mounted"
    # Its own network: front-ends must not reach it, and it does not join the default
    # network the agents service is on.
    networks = ui.get("networks")
    assert networks and "frontend" not in networks and "default" not in networks, networks
    for net in networks:
        assert not (compose["networks"].get(net) or {}).get("internal"), "published port"
    assert ui.get("ports"), "the console is published on loopback"
    for port in ui["ports"]:
        assert str(port).startswith("127.0.0.1:"), f"ui publishes {port} beyond loopback"
    env = ui.get("environment") or {}
    for key in env:
        assert not key.startswith(("ANTHROPIC", "AWS_", "WINNIE_WEBHOOK")), key
        assert not key.endswith("_API_KEY"), key
    assert env["WINNIE_UI_TOKEN"] == "${WINNIE_UI_TOKEN:-}"
    assert ui["read_only"] is True and ui["user"] == "10001:10001"
    assert ui["cap_drop"] == ["ALL"] and "no-new-privileges:true" in ui["security_opt"]
    assert "--actions" not in ui["command"]
    assert ui["command"][:4] == ["python", "-m", "agents", "ui"]


def test_ui_uses_the_same_directories_as_the_agents():
    services = _compose()["services"]
    run_all = services["agents"]["command"][-1]
    ui = services["ui"]["command"]
    for flag in ("--config", "--log", "--data-dir", "--reports-dir", "--state-dir",
                 "--detections-dir"):
        value = ui[ui.index(flag) + 1]
        assert f"{flag} {value}" in run_all, flag
    for key in ("WINNIE_DATA_DIR", "WINNIE_OVERLAY", "WINNIE_SOURCE_STATE"):
        assert services["ui"]["environment"][key] == services["agents"]["environment"][key]


def test_ui_actions_override_changes_only_the_agent_data_mode_and_the_command():
    base = _compose()["services"]["ui"]
    override = _override("docker-compose.ui-actions.yml")
    assert set(override) == {"services"} and set(override["services"]) == {"ui"}
    ui = override["services"]["ui"]
    assert set(ui) == {"command", "volumes"}
    assert ui["command"] == base["command"] + ["--actions"]
    # Compose merges volumes by target, so this replaces only the /agents mount.
    assert ui["volumes"] == ["agentdata:/agents"]
    assert {dst for _s, dst, _m in _mounts(ui)} <= {dst for _s, dst, _m in _mounts(base)}


def test_ui_overrides_keep_it_on_loopback():
    lab = _override("docker-compose.lab.yml")["services"]
    assert all(p.startswith("127.0.0.1:") for p in lab["ui"]["ports"])
    lab_ports = {p.rsplit(":", 1)[0] for name in FRONTENDS for p in lab[name]["ports"]}
    assert not {p.rsplit(":", 1)[0] for p in lab["ui"]["ports"]} & lab_ports
    isolated = _override("docker-compose.isolated.yml")
    assert "ui" not in isolated["services"]
    assert set(isolated["networks"]) == {"frontend"}


def test_image_ships_the_indicator_and_behaviour_files():
    # Their default path is under the repository's detections/, which the image does not
    # otherwise copy (the runtime detections directory is a volume elsewhere).
    sources = _copy_sources()
    assert {"detections/indicators", "detections/behaviours"} <= set(sources)
