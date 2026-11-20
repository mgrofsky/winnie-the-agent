"""Runtime hooks called from ``SSH/ssh_server.py`` (and the telnet listener).

Keeps the upstream server file close to upstream: it calls these few functions at clearly
marked points. Entry points must initialise the budget (``init_runtime`` or ``set_budget``);
without it every model path fails closed with a canned reply.
"""

from __future__ import annotations

import base64
import logging
import os
import re
from configparser import ConfigParser
from types import SimpleNamespace
from typing import Any, MutableMapping, Optional

from langchain_core.messages import AIMessage, HumanMessage

from agents.budget import (
    CANNED_CONNECTION_REFUSED,
    CANNED_INTERACTIVE,
    CANNED_NON_INTERACTIVE,
    SUMMARY_SKIPPED,
    Budget,
    BudgetConfig,
)
from agents import runtime, shell
from agents.budget import ip_key
from agents.source_state import MAX_TARPIT_MS, SourceStateView, source_state_path, source_token

_budget: Optional[Budget] = None
_config_path: Optional[str] = None
_cli_accounts: dict[str, str] = {}
_overlay_path: Optional[str] = None
_accounts_mtimes: tuple = ()
_scenario = None                       # scenarios.loader.LoadedScenario
_scenario_args: Optional[tuple] = None  # (name, seed, overlay_path) for reload
_overlay_mtime: Optional[float] = None
_session_fragments: dict[str, str] = {}
_session_prompts: dict[str, str] = {}   # the last prompt the model showed, per session
MAX_LOCAL_HISTORY = 4096   # characters of a local answer kept in the chat history
_source_view: Optional[SourceStateView] = None
_seed: Optional[str] = None
_offline_reason: Optional[str] = None   # set when the persona model cannot be used at all
_local_replies = True   # answer host facts from the profile before asking the model

# Providers whose client needs an API key from the environment; without it every call
# would fail after network round trips, so the persona runs offline instead.
_PROVIDER_KEYS = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
                  "gemini": "GOOGLE_API_KEY", "azure": "AZURE_OPENAI_API_KEY"}

log = logging.getLogger(__name__)


def _mtime(path: Optional[str]) -> Optional[float]:
    try:
        return os.path.getmtime(path) if path else None
    except OSError:
        return None


def init_runtime(config: ConfigParser, config_path: Optional[str], base_dir: str,
                 cli_accounts: Optional[dict[str, str]] = None,
                 data_dir: Optional[str] = None) -> None:
    """Called once from ssh_server.configure_runtime (and the listeners entry point)."""
    global _budget, _config_path, _cli_accounts, _scenario, _scenario_args
    global _overlay_mtime, _overlay_path, _accounts_mtimes, _source_view, _seed
    ddir = runtime.data_dir(config, base_dir, data_dir)
    _budget = Budget(BudgetConfig.from_config(config, base_dir, str(ddir)))
    _source_view = SourceStateView(source_state_path())
    _budget.mode_provider = source_mode
    _seed = runtime.sensor_seed(config, ddir)
    set_offline(provider_unavailable(config))
    set_local_replies(local_replies_enabled(config))
    _config_path = os.path.abspath(config_path) if config_path else None
    _cli_accounts = dict(cli_accounts or {})
    _overlay_path = str(runtime.overlay_path(config, base_dir))
    _accounts_mtimes = (_mtime(_config_path), _mtime(_overlay_path))
    _session_fragments.clear()
    _scenario = None
    _scenario_args = None
    name = config["scenario"].get("active", "").strip() if "scenario" in config else ""
    if name:
        from scenarios.loader import load_scenario

        seed = _seed
        if seed is None:
            raise RuntimeError(f"no sensor seed available in {ddir}; cannot load scenario")
        _scenario_args = (name, seed, _overlay_path)
        _scenario = load_scenario(*_scenario_args)
        _overlay_mtime = _mtime(_overlay_path)


def provider_unavailable(config: ConfigParser) -> Optional[str]:
    """Why the configured persona provider cannot be used (its API key is not set), or None.
    Providers without a key in the environment (ollama, aws) are assumed usable."""
    provider = (config["llm"].get("llm_provider", "") if "llm" in config else "").lower()
    key_env = _PROVIDER_KEYS.get(provider)
    return f"{key_env} not set" if key_env and not os.environ.get(key_env) else None


def local_replies_enabled(config: ConfigParser) -> bool:
    """``[llm] local_shell_replies`` (default on)."""
    return config["llm"].getboolean("local_shell_replies", fallback=True) \
        if "llm" in config else True


def set_local_replies(enabled: bool) -> None:
    """With a model, answer host facts (``uname``, ``nproc``, ``free``, ``/proc``, ``lspci``,
    ``nvidia-smi``, ...) from the host profile instead, until the model has handled a
    command in the session."""
    global _local_replies
    _local_replies = bool(enabled)


def shell_host(scenario=None) -> shell.Host:
    """The host profile the deterministic shell answers from: the given scenario (the
    listeners pass their own), else the active one, else the neutral default host."""
    return shell.host_for(scenario if scenario is not None else get_scenario(), _seed)


def offline_reason() -> Optional[str]:
    """Why the persona runs without a model, or None when a model is configured."""
    return _offline_reason


def set_offline(reason: Optional[str]) -> None:
    """Run the persona without a model (canned shell replies), e.g. when no API key is set."""
    global _offline_reason
    _offline_reason = reason
    if reason:
        log.warning("persona model unavailable (%s): sessions get canned shell replies", reason)


def _hostname() -> str:
    scenario = get_scenario()
    return scenario.hostname if scenario is not None else "srv01"


def shell_prompt(username: Optional[str], hostname: Optional[str] = None) -> str:
    user = (username or "user")[:32]
    return f"{user}@{hostname or _hostname()}:~{'#' if user == 'root' else '$'} "


SHELL_BUILTINS = shell.SHELL_BUILTINS
MAX_ECHO_OUTPUT = shell.MAX_ECHO_OUTPUT
_literal_output = shell.literal_output


def fallback_reply(text: str, interactive: bool, username: Optional[str],
                   host: Optional[shell.Host] = None, src_ip: Optional[str] = None,
                   prompt: Optional[str] = None) -> str:
    """A plausible shell reply when the model cannot answer: a prompt for the session
    opener, otherwise the deterministic shell's reply (``agents.shell.reply``: host facts
    from the profile, a builtin's own output, a known tool's own error, else 'command not
    found'), then the prompt. ``prompt`` is the one the model showed last, so a directory
    the model moved to stays in the prompt (and is the working directory here)."""
    host = host or shell_host()
    cwd = None
    if interactive and prompt:
        cwd = _prompt_directory(prompt, username)
    else:
        prompt = shell_prompt(username, host.hostname) if interactive else ""
    word = shell.clean_word(text)
    if not word:
        return prompt
    if word in ("exit", "logout") and interactive:
        return "YYY-END-OF-SESSION-YYY"   # same marker the model uses to end the session
    out = shell.reply(host, text, user=username or "user",
                      interactive=interactive, cwd=cwd, src_ip=src_ip)
    return (out.replace("\n", "\r\n") if interactive else out) + prompt


def _prompt_directory(prompt: str, username: Optional[str]) -> Optional[str]:
    """The working directory a ``user@host:DIR# `` prompt shows, or None."""
    _, sep, rest = prompt.strip().partition(":")
    path = rest[:-1] if sep and rest[-1:] in ("#", "$") else ""
    user = (username or "user")[:32]
    home = "/root" if user == "root" else f"/home/{user}"
    if path == "~" or path.startswith("~/"):
        path = home + path[1:]
    return path if path.startswith("/") and len(path) <= 256 else None


def in_character_reply(text: str, interactive: bool, username: Optional[str],
                       prompt: Optional[str] = None) -> str:
    """Replacement for a model reply that stepped out of the role: the real output for
    ``echo``/``printf`` of literal arguments, otherwise empty output, then the prompt (the
    one the model showed last, when known)."""
    word = (text.split() or [""])[0]
    if word in ("exit", "logout") and interactive:
        return "YYY-END-OF-SESSION-YYY"
    output = _literal_output(text) or ""
    if interactive:
        return output.replace("\n", "\r\n") + (prompt or shell_prompt(username))
    return output


def set_source_state(view: Optional[SourceStateView], seed: Optional[str] = None) -> None:
    """Install the per-source state view (and sensor seed for planted tokens)."""
    global _source_view, _seed
    _source_view = view
    if seed is not None:
        _seed = seed
    if _budget is not None:
        _budget.mode_provider = source_mode


def source_entry(ip: str):
    return _source_view.get(ip) if _source_view is not None else None


def source_mode(key: str) -> str:
    entry = source_entry(key)
    return entry.budget_mode if entry is not None else "normal"


def reset() -> None:
    """Back to the uninitialised state (tests)."""
    global _budget, _config_path, _scenario, _scenario_args, _overlay_mtime, _overlay_path
    global _accounts_mtimes, _source_view, _seed, _offline_reason, _local_replies
    _offline_reason = None
    _local_replies = True
    _source_view = None
    _seed = None
    _budget = None
    _config_path = _overlay_path = None
    _accounts_mtimes = ()
    _scenario = _scenario_args = _overlay_mtime = None
    _cli_accounts.clear()
    _session_fragments.clear()
    _session_prompts.clear()


def set_budget(budget: Budget) -> None:
    global _budget
    _budget = budget
    if _source_view is not None and budget.mode_provider is None:
        budget.mode_provider = source_mode


class BudgetNotInitialised(RuntimeError):
    """No budget was configured for this process; model calls fail closed."""


def get_budget() -> Budget:
    """The process budget. There is no silent in-memory default: entry points must call
    ``init_runtime`` or ``set_budget``; until then every model path fails closed."""
    if _budget is None:
        raise BudgetNotInitialised("budget not initialised")
    return _budget


def _budget_or_none() -> Optional[Budget]:
    if _budget is None:
        log.error("budget not initialised: refusing model calls (canned replies)")
    return _budget


def get_scenario():
    """Return the active LoadedScenario, reloading the tuner overlay if it changed."""
    global _scenario, _overlay_mtime
    if _scenario is None or _scenario_args is None:
        return _scenario
    current = _mtime(_scenario_args[2])
    if current != _overlay_mtime:
        try:
            from scenarios.loader import load_scenario

            _scenario = load_scenario(*_scenario_args)
        except Exception as exc:  # noqa: BLE001 - keep serving the last good scenario
            log.warning("overlay reload failed, keeping previous: %s", type(exc).__name__)
        _overlay_mtime = current
    return _scenario


# ---- input / sessions -------------------------------------------------------------------

def clip_input(text: str) -> str:
    budget = _budget
    return (budget or Budget(BudgetConfig())).clip(text)  # clipping never needs state


def _log(logger, message: str, log_extra: Optional[dict], **extra) -> None:
    if logger is None:
        return
    merged = dict(log_extra or {})
    merged.update(extra)
    logger.info(message, extra=merged)


def session_open(session_id: str, src_ip: str, logger=None, log_extra=None) -> Optional[str]:
    """Admit a session. Returns canned text to send before closing when refused."""
    budget = _budget_or_none()
    reason = "budget_not_initialised" if budget is None else budget.session_open(session_id, src_ip)
    if reason is None:
        return None
    _log(logger, "Budget exceeded", log_extra, reason=reason)
    return CANNED_CONNECTION_REFUSED


def session_close(session_id: str, history_store: Optional[MutableMapping] = None) -> None:
    """Release the concurrency slot and free the session's chat history."""
    if _budget is not None:
        _budget.session_close(session_id)
    _session_fragments.pop(session_id, None)
    _session_prompts.pop(session_id, None)
    if history_store is not None:
        history_store.pop(session_id, None)


def persona_fragment(session_id: str, src_ip: Optional[str] = None) -> str:
    """Persona block pinned per session so one session always sees one host. A source
    marked for a planted token also sees its own unique credentials in it."""
    if session_id in _session_fragments:
        return _session_fragments[session_id]
    scenario = get_scenario()
    fragment = scenario.persona_fragment() if scenario is not None else ""
    entry = source_entry(src_ip) if src_ip else None
    if entry is not None and entry.plant_token and _seed:
        access, secret = source_token(_seed, ip_key(src_ip))  # generated by us, never attacker text
        fragment += ("\n- /root/.aws/credentials exists and contains a [default] profile with "
                     f"aws_access_key_id = {access} and aws_secret_access_key = {secret}")
    if len(_session_fragments) > 10_000:
        _session_fragments.clear()
    _session_fragments[session_id] = fragment
    return fragment


def _clip_error(exc: BaseException) -> str:
    """The provider's error text for the log, printable characters only and clipped."""
    return "".join(c for c in str(exc) if c.isprintable())[:300]


def _usage_tokens(response: Any) -> Optional[int]:
    usage = getattr(response, "usage_metadata", None)
    if isinstance(usage, dict):
        total = usage.get("total_tokens")
        if isinstance(total, int) and total > 0:
            return total
    return None


def _content(response: Any) -> str:
    """The reply as plain text. Providers may return a list of content blocks (text plus
    reasoning or other block types); only the text blocks are kept."""
    content = getattr(response, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
        return "".join(parts)
    return ""


def _as_text_reply(response: Any) -> Any:
    """The response unchanged when its content is already a string, otherwise a plain
    object carrying the text, so callers can always write ``content`` to the client."""
    if isinstance(getattr(response, "content", ""), str):
        return response
    return SimpleNamespace(content=_content(response),
                           usage_metadata=getattr(response, "usage_metadata", None))


# Phrases a shell never prints but a model does when it steps out of the role. A reply that
# matches is replaced (see ``breaks_character`` for where in the reply a match counts),
# unless the attacker's own input contains the phrase (so ``echo`` of it still works).
# Apostrophes are normalised first, so curly ones match too.
_BREAK_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"\bas an ai\b",
    r"\b(?:large )?language model\b",
    r"\bi(?:'m| am) (?:an? |the )?(?:ai|artificial intelligence|assistant|chatbot|virtual assistant)\b",
    r"\bi(?:'m| am) sorry,? but\b",
    r"\bi apologi[sz]e,? but\b",
    r"\bi (?:cannot|can't|can not|won't|will not|am unable to|am not able to) "
    r"(?:help|assist|comply|provide|continue|fulfil|fulfill|pretend|role-?play|do that)\b",
    r"\bmy (?:system )?(?:prompt|instructions)\b",
    r"\bsystem prompt\b",
))
MAX_BREAK_LOGGED = 2000   # characters of an out-of-character reply kept in the log
_APOSTROPHES = str.maketrans({"\u2019": "'", "\u2018": "'", "\u02bc": "'"})
_PROMPT_LINE = re.compile(r"\S+@\S+:\S*[$#]\s*$")
# Commands whose output is file or document text, where a phrase deep in the output is
# content, not the model talking.
CONTENT_VIEWERS = frozenset({"cat", "less", "more", "head", "tail", "man", "grep", "strings"})


def _is_content_viewer(text: str) -> bool:
    words = text.split()
    if not words:
        return False
    if words[0] == "sudo" and len(words) > 1:
        words = words[1:]
    return words[0] in CONTENT_VIEWERS or words[:2] == ["git", "log"]


def breaks_character(reply: str, text: str) -> bool:
    """True when a model reply reads as the model talking, not as shell output.

    A phrase counts only in the first two non-empty lines of the reply, or anywhere when
    the reply has no shell prompt line at all; for a content viewer (``cat``, ``man``,
    ``git log``, ...) only in the first line.
    """
    lowered_input = text.lower().translate(_APOSTROPHES)
    lines = [line for line in reply.translate(_APOSTROPHES).splitlines() if line.strip()]
    has_prompt = any(_PROMPT_LINE.search(line) for line in lines)
    viewer = _is_content_viewer(text)
    for index, line in enumerate(lines):
        for pattern in _BREAK_PATTERNS:
            match = pattern.search(line)
            if not match or match.group(0).lower() in lowered_input:
                continue
            if viewer and index > 0:
                continue
            if index < 2 or not has_prompt:
                return True
    return False


def _replace_in_history(history, session_id: str, sent: str) -> None:
    """Swap the out-of-character reply the chain stored for the text actually sent, so
    the model never sees its own break again."""
    getter = getattr(history, "get_session_history", None)
    if not callable(getter):
        return
    try:
        messages = getter(session_id).messages
    except Exception:  # noqa: BLE001 - a history store without this shape is left alone
        return
    if messages and isinstance(messages[-1], AIMessage):
        messages[-1] = AIMessage(content=sent)


def _remember(history, session_id: str, text: str, sent: str) -> Optional[str]:
    """Add a turn answered without the model to the session history, so the model's later
    replies stay consistent with it. Returns what was stored (None when nothing was)."""
    getter = getattr(history, "get_session_history", None)
    if not callable(getter):
        return None
    try:
        getter(session_id).add_messages([HumanMessage(content=text), AIMessage(content=sent)])
    except Exception:  # noqa: BLE001 - a history store without this shape is left alone
        return None
    return sent


def _clip_local(output: str) -> str:
    """A local answer as kept in the chat history: at most ``MAX_LOCAL_HISTORY``
    characters, cut at a line end."""
    if len(output) <= MAX_LOCAL_HISTORY:
        return output
    head = output[:MAX_LOCAL_HISTORY]
    cut = head.rfind("\n")
    return head[:cut + 1] if cut > 0 else head + "\n"


def _note_prompt(session_id: str, content: str) -> None:
    """Remember the prompt a model reply ends with, for replies made without the model."""
    last = content.rstrip(" \r\n").rpartition("\n")[2].strip()
    if len(last) <= 300 and _FINAL_PROMPT.match(last):
        if len(_session_prompts) > 10_000:
            _session_prompts.clear()
        _session_prompts[session_id] = last + " "


_FINAL_PROMPT = re.compile(r"^\S*@\S*[$#]$")


def _tidy_prompt(content: str) -> str:
    """Make a reply that ends in a shell prompt end the way a shell does: no blank lines
    between the output and the prompt, and one space after it."""
    stripped = content.rstrip(" \r\n")
    head, sep, last = stripped.rpartition("\n")
    if not _FINAL_PROMPT.match(last.strip()):
        return content
    if not sep:
        return last.strip() + " "
    eol = "\r\n" if head.endswith("\r") or "\r\n" in head else "\n"
    return head.rstrip(" \r\n") + eol + last.strip() + " "


async def _tarpit(src_ip: str) -> None:
    entry = source_entry(src_ip)
    if entry is not None and entry.tarpit_ms > 0:
        import asyncio

        await asyncio.sleep(min(entry.tarpit_ms, MAX_TARPIT_MS) / 1000)


async def persona_invoke(history, *, session_id: str, src_ip: str, username: Optional[str],
                         text: str, interactive: bool, llm_config: dict, logger=None,
                         log_extra: Optional[dict] = None, counts_as_command: bool = True,
                         scenario=None):
    """The one path every persona model call takes (SSH and telnet).

    Reserves the estimated cost first. When a limit would be exceeded the model is not
    called: a canned, plausible response is returned with ``budget_exceeded=True`` and
    the caller closes. A failed call keeps its reserved charge. Offline (no model), replies
    are canned and charge no tokens; the per-session command cap still applies. With a
    model and ``local_shell_replies`` on, a host fact is answered from the profile the same
    way (no tokens, counted as a command, added to the history and to the token estimate)
    until the model has handled a command in the session; then the model answers all.
    ``scenario`` overrides the active scenario for those answers (the telnet listener).
    """
    budget = _budget_or_none()
    host = shell_host(scenario)
    local = None
    # Local answers only until the model has handled a command in this session: after
    # that the model owns the host's state (it has the local answers in its history).
    if budget is not None and not _offline_reason and _local_replies and counts_as_command \
            and not budget.model_answered(session_id):
        local = shell.answer(host, text, user=username or "user", interactive=interactive,
                             src_ip=src_ip)
        local = local if local is not None and local.stateless else None
    if budget is None:
        reason, reservation = "budget_not_initialised", None
    elif _offline_reason or local is not None:
        reason = budget.count_command(session_id, src_ip) if counts_as_command else None
        reservation = None
    else:
        reason, reservation = budget.reserve(session_id, src_ip, text, counts_as_command)
    if reason is not None:
        _log(logger, "Budget exceeded", log_extra, reason=reason)
        canned = CANNED_INTERACTIVE if interactive else CANNED_NON_INTERACTIVE
        return SimpleNamespace(content=canned, budget_exceeded=True)
    if _offline_reason:
        await _tarpit(src_ip)
        return SimpleNamespace(content=fallback_reply(text, interactive, username, host, src_ip))
    if local is not None:
        await _tarpit(src_ip)
        prompt = shell_prompt(username, host.hostname) if interactive else ""

        def shown(output: str) -> str:
            return (output.replace("\n", "\r\n") if interactive else output) + prompt

        stored = _remember(history, session_id, text, shown(_clip_local(local.output)))
        if stored is not None:
            budget.add_history(session_id, src_ip, text, stored)
        return SimpleNamespace(content=shown(local.output), local_reply=True)
    try:
        response = await history.ainvoke(
            {
                "messages": [HumanMessage(content=text)],
                "username": username,
                "interactive": interactive,
                "decoy_profile": persona_fragment(session_id, src_ip),
            },
            config=llm_config,
        )
    except Exception as exc:  # noqa: BLE001 - a provider failure must not end the session
        _log(logger, "Model error", log_extra, error=type(exc).__name__,
             error_detail=_clip_error(exc))
        await _tarpit(src_ip)
        return SimpleNamespace(content=fallback_reply(text, interactive, username, host, src_ip,
                                                      _session_prompts.get(session_id)))
    budget.commit(reservation, text, _content(response), usage_tokens=_usage_tokens(response))
    await _tarpit(src_ip)
    if breaks_character(_content(response), text):
        sent = in_character_reply(text, interactive, username, _session_prompts.get(session_id))
        _replace_in_history(history, session_id, sent)
        original = _content(response)[:MAX_BREAK_LOGGED]
        _log(logger, "Persona break", log_extra,
             details=base64.b64encode(original.encode("utf-8", "replace")).decode("ascii"))
        return SimpleNamespace(content=sent, persona_break=True)
    reply = _as_text_reply(response)
    if interactive:
        expected = (_literal_output(text) or "").strip()
        if expected and expected not in reply.content:
            # echo/printf of literal text has one right answer; use it when the model's differs
            sent = in_character_reply(text, interactive, username,
                                      _session_prompts.get(session_id))
            _replace_in_history(history, session_id, sent)
            return SimpleNamespace(content=sent,
                                   usage_metadata=getattr(reply, "usage_metadata", None))
        tidy = _tidy_prompt(reply.content)
        _note_prompt(session_id, tidy)
        if tidy != reply.content:
            return SimpleNamespace(content=tidy,
                                   usage_metadata=getattr(reply, "usage_metadata", None))
    return reply


async def summary_invoke(history, *, session_id: str, src_ip: str, username: Optional[str],
                         prompt: str, llm_config: dict, logger=None, log_extra=None):
    """Session summary call, under the same session, per-source and daily caps.

    Skipped (no model call) when the session made no model-backed command, so a source
    reconnecting in a loop cannot spend the day on summaries of nothing.
    """
    budget = _budget_or_none()
    if budget is None:
        _log(logger, "Budget exceeded", log_extra, reason="budget_not_initialised",
             stage="session_summary")
        return SimpleNamespace(content=SUMMARY_SKIPPED, budget_exceeded=True)
    if _offline_reason:
        return SimpleNamespace(content=SUMMARY_SKIPPED, budget_exceeded=True)
    if budget.model_commands(session_id) == 0:
        _log(logger, "Summary skipped", log_extra, reason="no_model_commands")
        return SimpleNamespace(content=SUMMARY_SKIPPED, budget_exceeded=True)
    reason, reservation = budget.reserve(session_id, src_ip, prompt, counts_as_command=False)
    if reason is not None:
        _log(logger, "Budget exceeded", log_extra, reason=reason, stage="session_summary")
        return SimpleNamespace(content=SUMMARY_SKIPPED, budget_exceeded=True)
    try:
        response = await history.ainvoke(
            {
                "messages": [HumanMessage(content=prompt)],
                "username": username,
                "interactive": True,
                "decoy_profile": persona_fragment(session_id, src_ip),
            },
            config=llm_config,
        )
    except Exception as exc:  # noqa: BLE001 - no summary is better than a crashed handler
        _log(logger, "Model error", log_extra, error=type(exc).__name__,
             error_detail=_clip_error(exc), stage="session_summary")
        return SimpleNamespace(content=SUMMARY_SKIPPED, budget_exceeded=True)
    budget.commit(reservation, prompt, _content(response), usage_tokens=_usage_tokens(response))
    return _as_text_reply(response)


# ---- account reload ---------------------------------------------------------------------

def _overlay_ssh_accounts() -> dict[str, str]:
    if not _overlay_path or not os.path.exists(_overlay_path):
        return {}
    from scenarios.loader import load_overlay

    overlay = load_overlay(_overlay_path)
    return {a.username: a.password for a in overlay.accounts.get("ssh", [])}


def merged_accounts(config_accounts: dict[str, str]) -> dict[str, str]:
    """Config accounts win; tuner overlay accounts only add new usernames; CLI wins over all."""
    merged = dict(_overlay_ssh_accounts())
    merged.update(config_accounts)
    merged.update(_cli_accounts)
    return merged


def reload_accounts_if_changed(current: dict) -> dict:
    """Re-read SSH accounts when config.ini or the overlay changes (mtime check)."""
    global _accounts_mtimes
    if not _config_path and not _overlay_path:
        return current
    mtimes = (_mtime(_config_path), _mtime(_overlay_path))
    if mtimes == _accounts_mtimes:
        return current
    _accounts_mtimes = mtimes
    try:
        config_accounts: dict[str, str] = {}
        if _config_path:
            parser = ConfigParser()
            parser.read(_config_path)
            if "user_accounts" in parser:
                config_accounts = {k: v for k, v in parser.items("user_accounts")}
        fresh = merged_accounts(config_accounts)
    except Exception as exc:  # noqa: BLE001 - a bad edit must not lock everyone out
        log.warning("account reload failed, keeping previous: %s", type(exc).__name__)
        return current
    return fresh or current
