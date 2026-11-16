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
        if name == "agents":
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


def test_image_contains_everything_loaded_at_runtime():
    import re

    copied = {m.group(1).rstrip("/") for m in re.finditer(
        r"^COPY (?!--from)(\S+) \./", (ROOT / "Dockerfile").read_text(), re.M)}
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


class _OverrideLoader(yaml.SafeLoader):
    """Reads compose override files: ``!override`` keeps the value it tags."""


_OverrideLoader.add_constructor(
    "!override", lambda loader, node: loader.construct_sequence(node)
    if isinstance(node, yaml.SequenceNode) else loader.construct_scalar(node))


def _override(name):
    return yaml.load((ROOT / name).read_text(), Loader=_OverrideLoader)


FRONTENDS = [name for name in _compose()["services"] if name != "agents"]


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
