import asyncio
from configparser import ConfigParser
import json
import logging
from types import SimpleNamespace

import pytest


def _write_config(path, log_file="ssh_log.log"):
    path.write_text(
        f"""
[honeypot]
log_file = {log_file}
sensor_name = template-sensor

[ssh]
port = 8022
host_priv_key = ssh_host_key
server_version_string = OpenSSH_Template

[llm]
llm_provider = openai
model_name = gpt-4o
trimmer_max_tokens = 64000
temperature = 0.2
system_prompt = template system

[user_accounts]
old = oldpw
""".lstrip()
    )


def _configure_minimal_logging(ssh_server, log_file):
    ssh_server.config = ConfigParser()
    ssh_server.config["honeypot"] = {
        "log_file": str(log_file),
        "sensor_name": "unit-test",
    }
    ssh_server.configure_logging()


def test_configure_runtime_loads_config_and_applies_cli_overrides(tmp_path, ssh_module):
    config_file = tmp_path / "config.ini"
    log_file = tmp_path / "override.log"
    _write_config(config_file)

    fake_history = object()
    args = ssh_module.parse_args(
        [
            "--config",
            str(config_file),
            "--llm-provider",
            "ollama",
            "--model-name",
            "llama3.3",
            "--trimmer-max-tokens",
            "123",
            "--system-prompt",
            "system override",
            "--temperature",
            "0.4",
            "--port",
            "2222",
            "--host-priv-key",
            "custom_host_key",
            "--server-version-string",
            "OpenSSH_Test",
            "--log-file",
            str(log_file),
            "--sensor-name",
            "sensor-override",
            "--user-account",
            "guest=",
            "--user-account",
            "root=*",
            "--user-account",
            "analyst",
        ]
    )

    ssh_module.configure_runtime(args, message_history=fake_history)

    assert ssh_module.config_base_dir == str(tmp_path)
    assert ssh_module.with_message_history is fake_history
    assert ssh_module.config["llm"]["llm_provider"] == "ollama"
    assert ssh_module.config["llm"]["model_name"] == "llama3.3"
    assert ssh_module.config["llm"]["trimmer_max_tokens"] == "123"
    assert ssh_module.config["llm"]["system_prompt"] == "system override"
    assert ssh_module.config["llm"]["temperature"] == "0.4"
    assert ssh_module.config["ssh"]["port"] == "2222"
    assert ssh_module.config["ssh"]["host_priv_key"] == "custom_host_key"
    assert ssh_module.config["ssh"]["server_version_string"] == "OpenSSH_Test"
    assert ssh_module.config["honeypot"]["log_file"] == str(log_file)
    assert ssh_module.config["honeypot"]["sensor_name"] == "sensor-override"
    assert ssh_module.accounts["old"] == "oldpw"
    assert ssh_module.accounts["guest"] == ""
    assert ssh_module.accounts["root"] == "*"
    assert ssh_module.accounts["analyst"] == ""


def test_load_config_exits_when_explicit_config_is_missing(tmp_path, capsys, ssh_module):
    missing_config = tmp_path / "missing.ini"
    args = ssh_module.parse_args(["--config", str(missing_config)])

    with pytest.raises(SystemExit) as exc_info:
        ssh_module.load_config(args)

    assert exc_info.value.code == 1
    assert f"specified config file '{missing_config}' does not exist" in capsys.readouterr().err


def test_resolve_runtime_path_prefers_config_directory_then_script_directory(
    tmp_path, monkeypatch, ssh_module
):
    config_dir = tmp_path / "configured"
    script_dir = tmp_path / "script"
    config_dir.mkdir()
    script_dir.mkdir()
    config_file = config_dir / "asset.txt"
    script_file = script_dir / "script-only.txt"
    absolute_file = tmp_path / "absolute.txt"
    config_file.write_text("from config")
    script_file.write_text("from script")
    absolute_file.write_text("absolute")

    monkeypatch.setattr(ssh_module, "config_base_dir", str(config_dir))
    monkeypatch.setattr(ssh_module, "SCRIPT_DIR", str(script_dir))

    assert ssh_module.resolve_runtime_path("asset.txt") == str(config_file)
    assert ssh_module.resolve_runtime_path("script-only.txt") == str(script_file)
    assert ssh_module.resolve_runtime_path(str(absolute_file)) == str(absolute_file)
    assert ssh_module.resolve_runtime_path("missing.txt") == "missing.txt"


def test_get_prompts_honors_inline_prompt_and_config_relative_prompt_file(
    tmp_path, monkeypatch, capsys, ssh_module
):
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("file prompt")
    ssh_module.config = ConfigParser()
    ssh_module.config["llm"] = {"system_prompt": "system prompt"}
    monkeypatch.setattr(ssh_module, "config_base_dir", str(tmp_path))

    assert ssh_module.get_prompts("inline prompt", "prompt.txt") == {
        "system_prompt": "system prompt",
        "user_prompt": "inline prompt",
    }
    assert ssh_module.get_prompts(None, "prompt.txt") == {
        "system_prompt": "system prompt",
        "user_prompt": "file prompt",
    }

    with pytest.raises(SystemExit) as blank_exit:
        ssh_module.get_prompts("   ", None)
    assert blank_exit.value.code == 1
    assert "prompt text cannot be empty" in capsys.readouterr().err

    with pytest.raises(SystemExit) as missing_exit:
        ssh_module.get_prompts(None, "does-not-exist.txt")
    assert missing_exit.value.code == 1
    assert "specified prompt file" in capsys.readouterr().err


def test_get_user_accounts_requires_at_least_one_configured_account(ssh_module):
    ssh_module.config = ConfigParser()
    with pytest.raises(ValueError, match="No user accounts"):
        ssh_module.get_user_accounts()

    ssh_module.config["user_accounts"] = {}
    with pytest.raises(ValueError, match="No user accounts"):
        ssh_module.get_user_accounts()


def test_authentication_contracts_for_honeypot_login_modes(ssh_module):
    ssh_module.accounts = {
        "guest": "",
        "user1": "secretpw",
        "root": "*",
    }
    server = ssh_module.MySSHServer()

    assert server.password_auth_supported() is True
    assert server.host_based_auth_supported() is False
    assert server.public_key_auth_supported() is False
    assert server.kbdinit_auth_supported() is False

    assert server.begin_auth("guest") is False
    assert server.begin_auth("user1") is True
    assert server.begin_auth("root") is True
    assert server.begin_auth("intruder") is True

    assert server.validate_password("user1", "secretpw") is True
    assert server.validate_password("user1", "wrong") is False
    assert server.validate_password("root", "") is True
    assert server.validate_password("root", "anything") is True
    assert server.validate_password("intruder", "") is True
    assert server.validate_password("intruder", "anything") is True


def test_json_formatter_emits_documented_log_shape(ssh_module):
    formatter = ssh_module.JSONFormatter("sensor-a")
    record = logging.LogRecord(
        name="ssh_server",
        level=logging.INFO,
        pathname="ssh_server.py",
        lineno=123,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    record.task_name = "session-1"
    record.src_ip = "192.0.2.10"
    record.src_port = 5555
    record.dst_ip = "198.51.100.20"
    record.dst_port = 22
    record.interactive = False
    record.details = "cHdk"

    data = json.loads(formatter.format(record))

    assert data["timestamp"].endswith("+00:00")
    assert data["level"] == "INFO"
    assert data["task_name"] == "session-1"
    assert data["src_ip"] == "192.0.2.10"
    assert data["src_port"] == 5555
    assert data["dst_ip"] == "198.51.100.20"
    assert data["dst_port"] == 22
    assert data["message"] == "hello world"
    assert data["sensor_name"] == "sensor-a"
    assert data["sensor_protocol"] == "ssh"
    assert data["interactive"] is False
    assert data["details"] == "cHdk"


class FakeExtraInfoSource:
    def __init__(self, peername=None, sockname=None, winnie_session_id=None):
        self._extra_info = {
            "peername": peername,
            "sockname": sockname,
            "winnie_session_id": winnie_session_id,
        }

    def get_extra_info(self, name, default=None):
        return self._extra_info.get(name, default)


def test_new_session_id_uses_session_prefix(ssh_module):
    first = ssh_module.new_session_id()
    second = ssh_module.new_session_id()

    assert first.startswith("session-")
    assert second.startswith("session-")
    assert first != second


def test_get_session_id_reads_winnie_session_extra(ssh_module):
    source = FakeExtraInfoSource(winnie_session_id="session-test")

    assert ssh_module.get_session_id(source) == "session-test"
    assert ssh_module.get_session_id(None, fallback="session-fallback") == "session-fallback"


def test_get_connection_log_extra_maps_peer_and_socket_names(ssh_module):
    source = FakeExtraInfoSource(
        peername=("192.0.2.10", 4444),
        sockname=("198.51.100.20", 22),
    )

    assert ssh_module.get_connection_log_extra(source) == {
        "src_ip": "192.0.2.10",
        "src_port": 4444,
        "dst_ip": "198.51.100.20",
        "dst_port": 22,
    }


def test_get_connection_log_extra_defaults_missing_peername(ssh_module):
    source = FakeExtraInfoSource(sockname=("198.51.100.20", 22))

    assert ssh_module.get_connection_log_extra(source) == {
        "src_ip": "-",
        "src_port": "-",
        "dst_ip": "198.51.100.20",
        "dst_port": 22,
    }


def test_get_connection_log_extra_defaults_missing_sockname(ssh_module):
    source = FakeExtraInfoSource(peername=("192.0.2.10", 4444))

    assert ssh_module.get_connection_log_extra(source) == {
        "src_ip": "192.0.2.10",
        "src_port": 4444,
        "dst_ip": "-",
        "dst_port": "-",
    }


def test_get_session_log_extra_combines_connection_metadata_and_task_name(ssh_module):
    source = FakeExtraInfoSource(
        peername=("192.0.2.10", 4444),
        sockname=("198.51.100.20", 22),
        winnie_session_id="session-test",
    )

    assert ssh_module.get_session_log_extra(source) == {
        "src_ip": "192.0.2.10",
        "src_port": 4444,
        "dst_ip": "198.51.100.20",
        "dst_port": 22,
        "task_name": "session-test",
    }


@pytest.mark.asyncio
async def test_context_filter_adds_async_task_name_only(ssh_module):
    asyncio.current_task().set_name("session-test")
    record = logging.LogRecord("ssh_server", logging.INFO, "ssh_server.py", 1, "msg", (), None)

    assert ssh_module.ContextFilter().filter(record) is True
    assert record.task_name == "session-test"
    assert not hasattr(record, "src_ip")
    assert not hasattr(record, "src_port")
    assert not hasattr(record, "dst_ip")
    assert not hasattr(record, "dst_port")


@pytest.mark.asyncio
async def test_context_filter_preserves_explicit_task_name(ssh_module):
    asyncio.current_task().set_name("asyncio-task")
    record = logging.LogRecord("ssh_server", logging.INFO, "ssh_server.py", 1, "msg", (), None)
    record.task_name = "session-explicit"

    assert ssh_module.ContextFilter().filter(record) is True
    assert record.task_name == "session-explicit"


def test_llm_session_history_is_created_once_per_session_id(ssh_module):
    first = ssh_module.llm_get_session_history("session-a")
    second = ssh_module.llm_get_session_history("session-a")
    other = ssh_module.llm_get_session_history("session-b")

    assert first is second
    assert other is not first


def test_choose_llm_instantiates_supported_providers_with_configured_options(
    monkeypatch, ssh_module
):
    def fake_model(provider_name):
        class FakeModel:
            def __init__(self, **kwargs):
                self.provider_name = provider_name
                self.kwargs = kwargs

        return FakeModel

    monkeypatch.setattr(ssh_module, "ChatOpenAI", fake_model("openai"))
    monkeypatch.setattr(ssh_module, "AzureChatOpenAI", fake_model("azure"))
    monkeypatch.setattr(ssh_module, "ChatOllama", fake_model("ollama"))
    monkeypatch.setattr(ssh_module, "ChatBedrockConverse", fake_model("aws"))
    monkeypatch.setattr(ssh_module, "ChatGoogleGenerativeAI", fake_model("gemini"))

    ssh_module.config = ConfigParser()
    ssh_module.config["llm"] = {
        "llm_provider": "openai",
        "model_name": "configured-model",
        "temperature": "0.3",
        "azure_deployment": "deployment-name",
        "azure_endpoint": "https://azure.example",
        "azure_api_version": "2025-01-01-preview",
        "aws_region": "us-west-2",
        "aws_credentials_profile": "winnie-profile",
    }

    openai = ssh_module.choose_llm("OpenAI", "model-x")
    assert openai.provider_name == "openai"
    assert openai.kwargs == {"model": "model-x", "temperature": 0.3}

    ollama = ssh_module.choose_llm("ollama", "model-x")
    assert ollama.provider_name == "ollama"
    assert ollama.kwargs == {"model": "model-x", "temperature": 0.3}

    aws = ssh_module.choose_llm("AWS", "model-x")
    assert aws.provider_name == "aws"
    assert aws.kwargs == {
        "model": "model-x",
        "region_name": "us-west-2",
        "credentials_profile_name": "winnie-profile",
        "temperature": 0.3,
    }

    gemini = ssh_module.choose_llm("gemini", "model-x")
    assert gemini.provider_name == "gemini"
    assert gemini.kwargs == {"model": "model-x", "temperature": 0.3}

    azure = ssh_module.choose_llm("azure")
    assert azure.provider_name == "azure"
    assert azure.kwargs == {
        "azure_deployment": "deployment-name",
        "azure_endpoint": "https://azure.example",
        "api_version": "2025-01-01-preview",
        "model": "configured-model",
        "temperature": 0.3,
    }


def test_choose_llm_rejects_unknown_provider(ssh_module):
    ssh_module.config = ConfigParser()
    ssh_module.config["llm"] = {
        "llm_provider": "openai",
        "model_name": "configured-model",
        "temperature": "0.2",
    }

    with pytest.raises(ValueError, match="Invalid LLM provider"):
        ssh_module.choose_llm("bogus")


@pytest.mark.asyncio
async def test_session_summary_logs_judgement_once(tmp_path, ssh_module):
    log_file = tmp_path / "ssh_log.log"
    _configure_minimal_logging(ssh_module, log_file)

    class FakeSession:
        def __init__(self):
            self.calls = []

        async def ainvoke(self, payload, config=None):
            self.calls.append((payload, config))
            return SimpleNamespace(
                content="The user attempted post-foothold reconnaissance.\n\nJudgement: MALICIOUS"
            )

    class FakeProcess:
        def get_extra_info(self, name):
            assert name == "username"
            return "guest"

    session = FakeSession()
    server = ssh_module.MySSHServer()
    llm_config = {"configurable": {"session_id": "session-a"}}
    log_extra = {
        "src_ip": "192.0.2.10",
        "src_port": 4444,
        "dst_ip": "198.51.100.20",
        "dst_port": 22,
        "task_name": "session-a",
    }

    await ssh_module.session_summary(FakeProcess(), llm_config, session, server, log_extra)
    await ssh_module.session_summary(FakeProcess(), llm_config, session, server, log_extra)

    assert len(session.calls) == 1
    payload, config = session.calls[0]
    assert payload["username"] == "guest"
    assert payload["interactive"] is True
    assert "Examine the list of all the SSH commands" in payload["messages"][0].content
    assert config == llm_config
    assert server.summary_generated is True

    for handler in ssh_module.logger.handlers:
        handler.flush()
    records = [json.loads(line) for line in log_file.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["message"] == "Session summary"
    assert records[0]["src_ip"] == "192.0.2.10"
    assert records[0]["src_port"] == 4444
    assert records[0]["dst_ip"] == "198.51.100.20"
    assert records[0]["dst_port"] == 22
    assert records[0]["task_name"] == "session-a"
    assert records[0]["details"].endswith("Judgement: MALICIOUS")
    assert records[0]["judgement"] == "MALICIOUS"


@pytest.mark.parametrize("provider", ["openai", "azure", "ollama", "aws", "gemini", "anthropic"])
def test_history_trimming_counts_tokens_locally_for_every_provider(ssh_module, monkeypatch,
                                                                   provider):
    """Trimming works offline: no tokenizer files and no provider token-count call."""
    from langchain_core.language_models import base as lm_base
    from langchain_core.language_models.fake_chat_models import FakeListChatModel
    from langchain_core.messages import AIMessage, HumanMessage

    def no_tokenizer(*_args, **_kwargs):
        raise OSError("tokenizer files are not available")

    monkeypatch.setattr(lm_base, "get_tokenizer", no_tokenizer)
    seen = []

    class Recorder(FakeListChatModel):
        def _call(self, messages, stop=None, run_manager=None, **kwargs):
            seen.append(list(messages))
            return super()._call(messages, stop=stop, run_manager=run_manager, **kwargs)

        def get_num_tokens_from_messages(self, messages, tools=None):
            raise AssertionError("token counting must not go through the provider")

    monkeypatch.setattr(ssh_module, "choose_llm", lambda *_a, **_k: Recorder(responses=["ok"]))
    cfg = ConfigParser()
    cfg["llm"] = {"llm_provider": provider, "model_name": "m", "trimmer_max_tokens": "200"}
    monkeypatch.setattr(ssh_module, "config", cfg)
    monkeypatch.setattr(ssh_module, "llm_sessions", {})
    history = ssh_module.llm_get_session_history("s1")
    for i in range(40):
        history.add_message(HumanMessage(content=f"command {i} " + "x" * 200))
        history.add_message(AIMessage(content=f"output {i} " + "y" * 200))

    chain = ssh_module.build_message_history("system prompt", "")
    chain.invoke({"messages": [HumanMessage(content="whoami")]},
                 config={"configurable": {"session_id": "s1"}})

    (sent,) = seen
    assert len(sent) < 20                      # older turns were trimmed away
    assert sent[-1].content == "whoami"


@pytest.mark.parametrize("provider,key_env", [("openai", "OPENAI_API_KEY"),
                                              ("anthropic", "ANTHROPIC_API_KEY"),
                                              ("gemini", "GOOGLE_API_KEY"),
                                              ("azure", "AZURE_OPENAI_API_KEY")])
async def test_server_starts_offline_when_the_provider_key_is_not_set(
        tmp_path, monkeypatch, ssh_module, provider, key_env):
    """The template config with no API key in the environment must start and answer with
    canned shell replies instead of failing while the model client is built."""
    from agents import hooks

    monkeypatch.delenv(key_env, raising=False)
    config_file = tmp_path / "config.ini"
    _write_config(config_file, log_file=str(tmp_path / "ssh_log.log"))
    config_file.write_text(config_file.read_text().replace("llm_provider = openai",
                                                           f"llm_provider = {provider}"))
    args = ssh_module.parse_args(["--config", str(config_file), "--prompt", "a mail server"])

    ssh_module.configure_runtime(args)

    assert ssh_module.with_message_history is not None
    reply = await hooks.persona_invoke(
        ssh_module.with_message_history, session_id="s1", src_ip="198.51.100.7",
        username="guest", text="uname -a", interactive=True,
        llm_config={"configurable": {"session_id": "s1"}})
    assert reply.content.startswith("Linux ") and "GNU/Linux\r\n" in reply.content


def test_history_trim_counter_weights_non_ascii_text(ssh_module):
    from langchain_core.messages import HumanMessage

    counted = ssh_module.trim_token_counter([HumanMessage(content="文" * 1000)])
    assert counted >= 1000


def test_temperature_is_not_sent_unless_configured(ssh_module, monkeypatch):
    captured = {}

    class Fake:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(ssh_module, "ChatBedrockConverse", Fake)
    ssh_module.config = ConfigParser()
    ssh_module.config["llm"] = {"llm_provider": "AWS", "model_name": "model-x"}
    ssh_module.choose_llm()
    assert "temperature" not in captured
    captured.clear()
    ssh_module.config["llm"]["temperature"] = "0.4"
    ssh_module.choose_llm()
    assert captured["temperature"] == 0.4


# ---- event log permissions -------------------------------------------------------------------

def _log_event(ssh_module, log_file, message):
    _configure_minimal_logging(ssh_module, log_file)
    ssh_module.logger.info(message)
    for handler in ssh_module.logger.handlers:
        handler.flush()
        handler.close()


def _mode(path):
    return path.stat().st_mode & 0o777


def _listener_event(path, message="from listener"):
    from listeners.events import EventWriter

    event = EventWriter(str(path), "unit").emit(
        task_name="t1", src_ip="203.0.113.1", src_port=4000, dst_port=21, message=message,
        sensor_protocol="ftp", event="connection")
    assert event is not None


def _write_as(writer, ssh_module, path, message):
    if writer == "ssh":
        _log_event(ssh_module, path, message)
    else:
        _listener_event(path, message)


def _messages(path):
    return [json.loads(line)["message"] for line in path.read_text().splitlines()]


@pytest.fixture
def umask():
    """Set the process umask for a test and restore it."""
    import os

    original = os.umask(0o022)
    os.umask(original)

    def apply(value):
        os.umask(value)

    yield apply
    os.umask(original)


@pytest.mark.parametrize("writer", ["ssh", "listener"])
@pytest.mark.parametrize("mask", [0o000, 0o022, 0o077])
def test_new_event_log_is_owner_only_whichever_writer_creates_it(
        tmp_path, ssh_module, umask, writer, mask):
    log_file = tmp_path / "ssh_log.log"
    umask(mask)
    _write_as(writer, ssh_module, log_file, "first")
    assert _mode(log_file) == 0o600                  # a permissive umask can not widen it
    assert _messages(log_file) == ["first"]


@pytest.mark.parametrize("first, second", [("ssh", "listener"), ("listener", "ssh")])
@pytest.mark.parametrize("mask", [0o000, 0o022, 0o077])
def test_either_writer_may_create_the_log_first_and_the_other_appends(
        tmp_path, ssh_module, umask, first, second, mask):
    log_file = tmp_path / "ssh_log.log"
    umask(mask)
    _write_as(first, ssh_module, log_file, "one")
    _write_as(second, ssh_module, log_file, "two")
    _write_as(first, ssh_module, log_file, "three")
    assert _messages(log_file) == ["one", "two", "three"]       # appended, never rewritten
    assert _mode(log_file) == 0o600


@pytest.mark.parametrize("writer", ["ssh", "listener"])
def test_creating_the_log_never_widens_or_chmods_it(tmp_path, ssh_module, umask, monkeypatch,
                                                    writer):
    """The mode is set by the creating open itself: no later chmod, so no window in which a
    file with a wider mode exists."""
    import os

    def forbidden(*args, **kwargs):
        raise AssertionError("the writer must not chmod the event log")

    monkeypatch.setattr(os, "chmod", forbidden)
    monkeypatch.setattr(os, "fchmod", forbidden, raising=False)
    umask(0o000)
    log_file = tmp_path / "ssh_log.log"
    _write_as(writer, ssh_module, log_file, "first")
    assert _mode(log_file) == 0o600


@pytest.mark.parametrize("writer", ["ssh", "listener"])
@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644])
def test_an_existing_log_keeps_its_mode_and_is_appended_to(tmp_path, ssh_module, umask,
                                                           writer, mode):
    """A log the operator pre-created 0640 for a reader group stays 0640; an older permissive
    log is left as it is (the operator tightens it, see docs/operations.md)."""
    log_file = tmp_path / "ssh_log.log"
    log_file.write_text(json.dumps({"message": "old"}) + "\n")
    log_file.chmod(mode)
    umask(0o000)
    _write_as(writer, ssh_module, log_file, "new")
    assert _messages(log_file) == ["old", "new"]
    assert _mode(log_file) == mode


def test_reopening_the_event_log_appends_and_keeps_an_operators_mode(tmp_path, ssh_module):
    import os

    log_file = tmp_path / "ssh_log.log"
    previous = os.umask(0o022)
    try:
        _log_event(ssh_module, log_file, "before restart")
        assert _mode(log_file) == 0o600
        log_file.chmod(0o640)                       # the operator opted in to a reader group
        _log_event(ssh_module, log_file, "after restart")
    finally:
        os.umask(previous)
    assert _messages(log_file) == ["before restart", "after restart"]
    assert _mode(log_file) == 0o640


def test_preexisting_private_log_stays_private(tmp_path, ssh_module):
    import os

    log_file = tmp_path / "ssh_log.log"
    log_file.write_text("")
    log_file.chmod(0o600)
    previous = os.umask(0o000)
    try:
        _log_event(ssh_module, log_file, "kept private")
    finally:
        os.umask(previous)
    assert _mode(log_file) == 0o600


def test_open_event_log_survives_rotation_by_rename(tmp_path, ssh_module):
    log_file = tmp_path / "ssh_log.log"
    _configure_minimal_logging(ssh_module, log_file)
    ssh_module.logger.info("one")
    log_file.rename(tmp_path / "ssh_log.log.1")     # rotation while the handler holds it open
    ssh_module.logger.info("two")
    for handler in ssh_module.logger.handlers:
        handler.flush()
        handler.close()
    rotated = (tmp_path / "ssh_log.log.1").read_text()
    assert "one" in rotated and "two" in rotated
