from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SSH_DIR = REPO_ROOT / "SSH"
if str(SSH_DIR) not in sys.path:
    sys.path.insert(0, str(SSH_DIR))

import ssh_server  # noqa: E402

# The browser tests need the optional "browser" dependency group (pytest-playwright);
# without it their folder is not collected at all.
try:
    import playwright  # noqa: F401
except ImportError:
    collect_ignore = ["browser"]


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path_factory, monkeypatch):
    # Runtime state (budget counters, sensor seed) must never land in the repository.
    monkeypatch.setenv("WINNIE_DATA_DIR", str(tmp_path_factory.mktemp("data")))
    monkeypatch.setenv("WINNIE_SOURCE_STATE", str(tmp_path_factory.mktemp("state") / "source_state.json"))


@pytest.fixture(autouse=True)
def default_budget():
    # Production entry points initialise the budget; tests that drive handle_client
    # directly get an explicit in-memory one (the hooks fail closed without it).
    from agents import hooks
    from agents.budget import Budget, BudgetConfig

    from agents.replycache import ReplyCache

    hooks.set_budget(Budget(BudgetConfig()))
    # The reply cache is off unless a test turns it on: most tests replay the same lines
    # in several sessions and expect the model to be asked each time.
    hooks.set_reply_cache(ReplyCache(max_entries=0))
    yield
    hooks.reset()


@pytest.fixture
def ssh_module():
    return ssh_server


@pytest.fixture(autouse=True)
def reset_ssh_server_state():
    original_config = ssh_server.config
    original_config_base_dir = ssh_server.config_base_dir
    original_accounts = ssh_server.accounts
    original_llm_sessions = ssh_server.llm_sessions
    original_with_message_history = ssh_server.with_message_history
    original_logger_level = ssh_server.logger.level
    original_logger_propagate = ssh_server.logger.propagate

    yield

    for handler in list(ssh_server.logger.handlers):
        handler.flush()
        handler.close()
    ssh_server.logger.handlers.clear()
    ssh_server.logger.filters.clear()
    ssh_server.logger.setLevel(original_logger_level)
    ssh_server.logger.propagate = original_logger_propagate

    ssh_server.config = original_config
    ssh_server.config_base_dir = original_config_base_dir
    ssh_server.accounts = original_accounts
    ssh_server.llm_sessions = original_llm_sessions
    ssh_server.with_message_history = original_with_message_history


@pytest.fixture
def public_test_net():
    """Treat the TEST-NET-2 documentation range as public, for tests that need a source
    address that per-source actions, blocklists and connectors accept."""
    from agents.addresses import public_for_tests

    with public_for_tests("198.51.100.0/24"):
        yield


# Folders the CLI writes to when no directory is passed. A test that runs a command without
# its own --reports-dir / --detections-dir writes into the checkout; the run fails if any of
# them changed.
_RUNTIME_DIRS = ("detections/pending", "detections/approved", "reports", "quarantine")


def _runtime_snapshot() -> dict:
    out = {}
    for rel in _RUNTIME_DIRS:
        base = REPO_ROOT / rel
        if base.exists():
            for p in base.rglob("*"):
                try:
                    out[str(p.relative_to(REPO_ROOT))] = p.stat().st_mtime_ns
                except OSError:
                    continue
    return out


def pytest_sessionstart(session):
    session.config._winnie_runtime_before = _runtime_snapshot()


def pytest_sessionfinish(session, exitstatus):
    before = getattr(session.config, "_winnie_runtime_before", None)
    if before is None:
        return
    after = _runtime_snapshot()
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    if changed:
        session.config.get_terminal_writer().line(
            "tests wrote into the checkout (pass a temporary directory): "
            + ", ".join(changed[:10]), red=True)
        session.exitstatus = 1
