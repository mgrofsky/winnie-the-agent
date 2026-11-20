from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SSH_DIR = REPO_ROOT / "SSH"
if str(SSH_DIR) not in sys.path:
    sys.path.insert(0, str(SSH_DIR))

import ssh_server  # noqa: E402


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
