"""Runtime hooks called from ``SSH/ssh_server.py`` (and the telnet listener).

Keeps the upstream server file close to upstream: it calls these few functions at clearly
marked points. Entry points must initialise the budget (``init_runtime`` or ``set_budget``);
without it every model path fails closed with a canned reply.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import re
from configparser import ConfigParser
from dataclasses import dataclass
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
from agents import learned, onereply, runtime, shell
from agents.budget import ip_key
from agents.learned import LearnedStore
from agents.replycache import ReplyCache, conversation_key, session_root, volatile
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
# The last prompt the model showed, per session: (prompt, working directory). The directory
# is None when the prompt's shape does not give it; local answers then stop for the session.
_session_prompts: dict[str, tuple[str, Optional[str]]] = {}
# Reply-cache state per session: a hash over everything in its history so far, or ``_LEFT``
# once the session has left the cache (see ``persona_invoke``).
_session_keys: dict[str, str] = {}
_LEFT = ""
# Sessions that typed a line able to print a prompt-shaped line (``onereply.builds_text``),
# and how many model replies were cut per session (``agents.onereply``).
_session_built: dict[str, bool] = {}
_session_cuts: dict[str, int] = {}
_cuts_total = 0
MAX_TRACKED_SESSIONS = 10_000   # per-session tables evict their oldest entry past this
# What the canned shell keeps per session when it answers instead of the model (files the
# session wrote, its directory): each holds up to ``shell.MAX_SCRATCH_BYTES``, so far fewer.
_shell_sessions: dict[str, shell.Session] = {}
_shell_stale: set[str] = set()    # sessions the model answered since their fallback ran
MAX_SHELL_SESSIONS = 256
_cache: Optional[ReplyCache] = None
MAX_LOCAL_HISTORY = 4096   # characters of a local answer kept in the chat history
MAX_LOCAL_DELAY_MS = 2000
_local_delay_ms = 0        # [llm] local_reply_delay_ms
_source_view: Optional[SourceStateView] = None
_seed: Optional[str] = None
_offline_reason: Optional[str] = None   # set when the persona model cannot be used at all
_local_replies = True   # answer host facts from the profile before asking the model
MAX_PERSONA_RETRIES = 2
_persona_retries = 1    # [llm] persona_retries
_learned: Optional[LearnedStore] = None   # [llm] learned_replies
_learn_model = ""       # digest of the [llm] provider, model and system prompt
# Learned-reply state per session.
_learn_sessions: dict[str, "_LearnState"] = {}   # ``_LearnState``, ``_learn_turn``

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
    set_reply_cache(None)
    _source_view = SourceStateView(source_state_path())
    _budget.mode_provider = source_mode
    _seed = runtime.sensor_seed(config, ddir)
    set_offline(provider_unavailable(config))
    set_local_replies(local_replies_enabled(config))
    set_local_delay(local_delay_ms(config))
    set_persona_retries(persona_retries(config))
    set_learned(learned_store(config, _budget.config.state_file),
                model_fingerprint(config, base_dir))
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
    """With a model, answer known commands from the host profile first (see
    ``persona_invoke`` for which, and when)."""
    global _local_replies
    _local_replies = bool(enabled)


def local_delay_ms(config: ConfigParser) -> int:
    """``[llm] local_reply_delay_ms`` (default 0, at most ``MAX_LOCAL_DELAY_MS``)."""
    value = config["llm"].getint("local_reply_delay_ms", fallback=0) if "llm" in config else 0
    if value < 0:
        raise ValueError("[llm] local_reply_delay_ms must be 0 or more")
    return min(value, MAX_LOCAL_DELAY_MS)


def set_local_delay(ms: int) -> None:
    """With a model, wait between half and all of ``ms`` before a reply made without a model
    call (local, cached or past the model cap), so those are not instant next to model
    replies. 0 (the default) answers at once."""
    global _local_delay_ms
    _local_delay_ms = max(0, min(int(ms), MAX_LOCAL_DELAY_MS))


def persona_retries(config: ConfigParser) -> int:
    """``[llm] persona_retries`` (default 1, at most ``MAX_PERSONA_RETRIES``)."""
    value = config["llm"].getint("persona_retries", fallback=1) if "llm" in config else 1
    if value < 0:
        raise ValueError("[llm] persona_retries must be 0 or more")
    return min(value, MAX_PERSONA_RETRIES)


def set_persona_retries(count: int) -> None:
    """How many times a rejected persona reply is asked again (``persona_invoke``)."""
    global _persona_retries
    _persona_retries = max(0, min(int(count), MAX_PERSONA_RETRIES))


def learned_settings(config: ConfigParser) -> tuple[bool, int, int]:
    """``[llm] learned_replies`` (default on), ``learned_min_sessions`` (default 3, at
    least 2) and ``learned_max_entries`` (default 2000, at most 20000)."""
    if "llm" not in config:
        return True, learned.DEFAULT_MIN_SESSIONS, learned.DEFAULT_MAX_ENTRIES
    enabled = config["llm"].getboolean("learned_replies", fallback=True)
    min_sessions = config["llm"].getint("learned_min_sessions",
                                        fallback=learned.DEFAULT_MIN_SESSIONS)
    max_entries = config["llm"].getint("learned_max_entries",
                                       fallback=learned.DEFAULT_MAX_ENTRIES)
    if min_sessions < 2:
        raise ValueError("[llm] learned_min_sessions must be 2 or more")
    if max_entries < 1:
        raise ValueError("[llm] learned_max_entries must be 1 or more")
    return enabled, min_sessions, min(max_entries, learned.MAX_ENTRIES_LIMIT)


def learned_store(config: ConfigParser, state_file: Optional[str]) -> Optional[LearnedStore]:
    """The learned-reply store, in ``learned_replies.json`` beside the budget state file
    (in memory when the budget has no state file), or None when ``learned_replies`` is
    off."""
    enabled, min_sessions, max_entries = learned_settings(config)
    if not enabled:
        return None
    store = LearnedStore(learned.path_beside(state_file), max_entries, min_sessions,
                         background=True)
    store.preload()
    return store


def model_fingerprint(config: ConfigParser, base_dir: str) -> str:
    """A digest of the ``[llm]`` provider and model, part of every learned entry's key
    (``note_persona_prompts`` adds the prompts the persona chain was built with)."""
    if "llm" not in config:
        return learned.digest("model")
    provider = config["llm"].get("llm_provider", "")
    model = config["llm"].get("model_name", "")
    return learned.digest("model", provider, model)


def note_persona_prompts(system_prompt: str, user_prompt: str) -> None:
    """Add the system and user prompt the persona chain uses to the learned-entry key, so
    a changed prompt never serves a reply made under the old one. Called by each entry
    point once its chain is built (after ``set_learned``)."""
    global _learn_model
    _learn_model = learned.digest("prompts", _learn_model, system_prompt or "",
                                  user_prompt or "")


def set_learned(store: Optional[LearnedStore], model: str = "") -> None:
    """Install the learned-reply store (None turns learned replies off) and the model
    fingerprint its entries are keyed under."""
    global _learned, _learn_model
    if _learned is not None and _learned is not store:
        close_learned()
    _learned = store
    _learn_model = model
    _learn_sessions.clear()


def close_learned() -> None:
    """Write what the learned store still has queued and stop its worker (shutdown)."""
    if _learned is not None:
        try:
            _learned.close()
        except Exception as exc:  # noqa: BLE001 - shutdown goes on
            log.warning("learned replies close failed: %s", type(exc).__name__)


def learned_replies() -> Optional[LearnedStore]:
    return _learned


def _track(table: dict, session_id: str, value) -> None:
    """Set a per-session value as the newest entry; past ``MAX_TRACKED_SESSIONS`` the oldest
    session's entry goes (one at a time, never the whole table)."""
    table.pop(session_id, None)
    table[session_id] = value
    while len(table) > MAX_TRACKED_SESSIONS:
        table.pop(next(iter(table)))


def set_reply_cache(cache: Optional[ReplyCache]) -> None:
    """Install a reply cache; None builds one from the budget's settings when first used."""
    global _cache
    _cache = cache
    _session_keys.clear()


def reply_cache() -> Optional[ReplyCache]:
    """The process's model reply cache (built from ``[budget] reply_cache_*``)."""
    global _cache
    if _cache is None and _budget is not None:
        _cache = ReplyCache(_budget.config.reply_cache_entries,
                            _budget.config.reply_cache_max_age)
    return _cache


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
                   prompt: Optional[str] = None, session_id: Optional[str] = None) -> str:
    """A plausible shell reply when the model cannot answer: a prompt for the session
    opener, otherwise the deterministic shell's reply (``agents.shell.reply``: host facts
    from the profile, a builtin's own output, a known tool's own error, else 'command not
    found'), then the prompt. ``prompt`` is the one the model showed last, so a directory
    the model moved to stays in the prompt (and is the working directory here).
    ``session_id`` keeps the files the session wrote, and its directory, from one fallback
    line to the next, as the Telnet canned shell does (``shell.Session``)."""
    host = host or shell_host()
    cwd = None
    session = None
    entered = False
    if session_id is not None:
        session = _shell_sessions.get(session_id)
        # A model reply since the last fallback line may have moved the session: its
        # prompt seeds the directory again.
        entered = session is not None and session_id not in _shell_stale
        _shell_stale.discard(session_id)
        session = session or shell.Session()
        _track_shell(session_id, session)
    if interactive and prompt and entered:
        # The model's last prompt seeded the directory on the first fallback line; from
        # then on the session says where it is, and the prompt follows it.
        cwd, prompt = session.cwd or None, None
    elif interactive and prompt:
        cwd = prompt_directory(prompt, username)
        if session is not None and cwd is not None:
            session.cwd = cwd                # the model's prompt says where the session is
    elif interactive:
        prompt = None                        # where the session is once the line has run
    else:
        prompt = ""
    word = shell.clean_word(text)
    if not word and not text.lstrip().startswith(">"):     # ``>f`` is a command too
        return prompt if prompt is not None else _prompt_at(username, host, session)
    if word in ("exit", "logout") and interactive:
        return "YYY-END-OF-SESSION-YYY"   # same marker the model uses to end the session
    out = shell.reply(host, text, user=username or "user",
                      interactive=interactive, cwd=cwd, src_ip=src_ip, session=session)
    if prompt is None:
        prompt = _prompt_at(username, host, session)
    return (out.replace("\n", "\r\n") if interactive else out) + prompt


def _prompt_at(username: Optional[str], host: shell.Host,
               session: Optional[shell.Session]) -> str:
    """The prompt for the directory the canned shell's session is in."""
    user = (username or "user")[:32]
    if session is None or not session.cwd:
        return shell_prompt(user, host.hostname)
    home = "/root" if user == "root" else f"/home/{user}"
    path = shell.prompt_path(session.cwd, home)
    return f"{user}@{host.hostname}:{path}{'#' if user == 'root' else '$'} "


def _track_shell(session_id: str, session: shell.Session) -> None:
    _shell_sessions.pop(session_id, None)
    _shell_sessions[session_id] = session
    while len(_shell_sessions) > MAX_SHELL_SESSIONS:
        _shell_stale.discard(next(iter(_shell_sessions)))
        _shell_sessions.pop(next(iter(_shell_sessions)))


def prompt_directory(prompt: str, username: Optional[str]) -> Optional[str]:
    """The working directory a prompt shows, or None when its shape does not give one:
    ``user@host:DIR# `` (Debian, Ubuntu), or ``[user@host DIR]# `` (RHEL) when DIR is ``~``
    or ``/`` (otherwise it is only the last path component). One pass, at most 300
    characters."""
    line = prompt.strip()
    if not line or len(line) > 300 or line[-1] not in "#$" or any(c.isspace() for c in line
                                                                 if c != " "):
        return None
    user = (username or "user")[:32]
    home = "/root" if user == "root" else f"/home/{user}"
    body = line[:-1]
    if body.startswith("[") and body.endswith("]"):
        who, sep, path = body[1:-1].partition(" ")
        if "@" not in who or not sep:
            return None
        return home if path == "~" else "/" if path == "/" else None
    who, sep, path = body.partition(":")
    if not sep or "@" not in who or " " in body:
        return None
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
    global _accounts_mtimes, _source_view, _seed, _offline_reason, _local_replies, _cache
    global _cuts_total
    _cache = None
    set_learned(None)
    _session_keys.clear()
    _session_built.clear()
    _session_cuts.clear()
    _cuts_total = 0
    _offline_reason = None
    _local_replies = True
    set_local_delay(0)
    set_persona_retries(1)
    _source_view = None
    _seed = None
    _budget = None
    _config_path = _overlay_path = None
    _accounts_mtimes = ()
    _scenario = _scenario_args = _overlay_mtime = None
    _cli_accounts.clear()
    _session_fragments.clear()
    _session_prompts.clear()
    _shell_sessions.clear()
    _shell_stale.clear()


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
    """An input line within the line cap, any undecodable byte (a surrogate escape) replaced."""
    budget = _budget
    text = text.encode("utf-8", "replace").decode("utf-8") if not text.isascii() else text
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
    _session_keys.pop(session_id, None)
    _learn_sessions.pop(session_id, None)
    _session_built.pop(session_id, None)
    _session_cuts.pop(session_id, None)
    _shell_sessions.pop(session_id, None)
    _shell_stale.discard(session_id)
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
    _track(_session_fragments, session_id, fragment)
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


_FENCE_LINE = re.compile(r"^[ \t]*```[\w+.-]*[ \t]*$")


def _strip_fences(reply: str, text: str) -> str:
    """The reply without the Markdown code fence a model sometimes wraps shell output in:
    a fence line on its own at the very start or the very end, and the line closing a
    fence opened at the start. Left alone when the input
    itself contains a fence (``echo`` of one). For a content viewer (``cat``, ``less``,
    ...) a fence may be the file's own text, so only one after the final prompt goes."""
    if "```" not in reply or "```" in text:
        return reply
    lines = reply.split("\n")
    if _is_content_viewer(text):
        solid = [i for i, line in enumerate(lines) if line.strip()]
        if (len(solid) >= 2 and _FENCE_LINE.match(lines[solid[-1]].rstrip("\r"))
                and _FINAL_PROMPT.match(lines[solid[-2]].strip())):
            del lines[solid[-1]:]
        return "\n".join(lines)
    def fence(i: int) -> bool:
        return bool(_FENCE_LINE.match(lines[i].rstrip("\r")))

    first = next((i for i, line in enumerate(lines) if line.strip()), None)
    opened = first is not None and fence(first)
    if opened:
        del lines[:first + 1]
    last = next((i for i in range(len(lines) - 1, -1, -1) if lines[i].strip()), None)
    if last is not None and fence(last):
        del lines[last:]
    elif opened:
        # the fence closed before the prompt line: drop that closing line too
        closing = next((i for i in range(len(lines) - 1, -1, -1) if fence(i)), None)
        if closing is not None:
            del lines[closing]
    return "\n".join(lines)


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


# Commands that can print text a session stored earlier. Wider than CONTENT_VIEWERS on
# purpose: this only decides when a reply is left whole.
_SHOWS_TEXT = CONTENT_VIEWERS | frozenset({
    "sed", "awk", "nl", "tac", "cut", "sort", "uniq", "tee", "paste", "od", "xxd",
    "hexdump", "base64", "vi", "vim", "nano", "ed", "source", ".", "sh", "bash", "ash",
    "dash", "read", "diff", "cmp", "wc", "rev", "tr", "fold", "column", "egrep", "fgrep",
    "zcat", "dd", "cp", "mv", "history",
})
_WORD_SPLIT = re.compile(r"""[\s"'`;|&(){}<>]+""")


def _may_show_text(text: str) -> bool:
    """True when any word of the input names such a command, by any path or wrapper
    (``/bin/cat n``, ``sudo -u root cat n``, ``busybox cat n``, ``xargs cat``)."""
    for word in _WORD_SPLIT.split(text):
        if word.rpartition("/")[2] in _SHOWS_TEXT or word.startswith("./"):
            return True
    return False


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


def _replace_in_history(history, session_id: str, sent: str,
                        was: Optional[str] = None) -> None:
    """Swap the reply the chain stored for the text actually sent (an out-of-character
    reply, so the model never sees its own break again). With ``was``, only when the last
    message is that reply."""
    getter = getattr(history, "get_session_history", None)
    if not callable(getter):
        return
    try:
        messages = getter(session_id).messages
    except Exception:  # noqa: BLE001 - a history store without this shape is left alone
        return
    if messages and isinstance(messages[-1], AIMessage) and (
            was is None or messages[-1].content == was):
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


def _note_prompt(session_id: str, content: str, username: Optional[str]) -> None:
    """Remember the prompt a model reply ends with (its last line, whatever its shape), for
    replies made without the model. When the shape does not give the working directory,
    the session gets no more local answers (``persona_invoke``), even if a later prompt
    does."""
    last = content.rstrip(" \r\n").rpartition("\n")[2].strip()
    if not last or len(last) > 300:
        last = ""
    before = _session_prompts.get(session_id)
    cwd = prompt_directory(last, username) if last else None
    if before is not None and before[1] is None:
        cwd = None
    prompt = last + " " if last else (before[0] if before else "")
    _track(_session_prompts, session_id, (prompt, cwd))
    if session_id in _shell_sessions:
        _shell_stale.add(session_id)


_FINAL_PROMPT = re.compile(r"^(?:\S*@\S*|\[\S+@\S+ \S+\])[$#]$")


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


def _not_found_hint(host: shell.Host, interactive: bool) -> str:
    """Persona line: a program the host does not have gets the shell's own error, in the
    form bash prints it for this kind of session, instead of invented output."""
    line = shell.not_found(host, interactive, "NAME")
    after = " followed by the prompt" if interactive else ""
    return (f"\n- A command that is not installed on a host like this prints only `{line}` "
            f"(NAME as typed){after}; do not invent output for it.")


def _cacheable_source(src_ip: str) -> bool:
    """False while a per-source effect changes what the model is shown or allowed (a
    planted token in the persona block, ``deep`` or ``shallow`` mode): such replies are
    neither served from nor stored in the reply cache."""
    entry = source_entry(src_ip)
    return entry is None or (not entry.plant_token and entry.budget_mode == "normal")


def _turn_key(session_id: str, src_ip: str, username: Optional[str], interactive: bool,
              host: shell.Host, text: str) -> Optional[str]:
    """The reply-cache key for this input line, or None when the session is out of the
    cache. The key is a hash chained over the session root (host, seed, user, session type,
    persona block) and every turn so far, input and the reply as kept in the history
    (``_advance``), so two sessions share a key only when their histories are identical.

    A session leaves the cache for good, neither reading nor writing it, once its history
    holds anything that is not a function of its key (``_leave``), when a per-source effect
    applies (``_cacheable_source``), and when it has had turns but its state was evicted:
    restarting from the root would key a history that is not there."""
    previous = _session_keys.get(session_id)
    if previous == _LEFT:
        return None
    if previous is None:
        if _budget is not None and _budget.session_started(session_id):
            _leave(session_id)
            return None
        previous = session_root(host.hostname, host.kernel, _seed or "", username or "",
                                "interactive" if interactive else "exec",
                                persona_fragment(session_id, src_ip), shell.persona_facts(host))
    if not _cacheable_source(src_ip):
        _leave(session_id)
        return None
    return conversation_key(previous, text)


def _advance(session_id: str, key: Optional[str], kept: str) -> None:
    """Chain a turn into the session's key: ``kept`` is the reply as the history holds it,
    and it is a function of ``key`` (a shareable local answer, a cached reply, or a model
    reply just stored under ``key``)."""
    if key is not None and _session_keys.get(session_id) != _LEFT:
        _track(_session_keys, session_id, conversation_key(key, "\x01" + kept))


def _leave(session_id: str) -> None:
    """Take the session out of the reply cache for the rest of its life."""
    _track(_session_keys, session_id, _LEFT)


def _store(key: Optional[str], text: str, reply: str, src_ip: str) -> bool:
    """Keep a model reply for identical replays. False when it was not stored, because it
    must not be shared (a second line behind the key: it names the session's address, or
    answers a line whose real output changes between runs) or the cache cannot take it."""
    cache = reply_cache()
    if key is None or cache is None or not reply or volatile(text) \
            or not _cacheable_source(src_ip) or reply == "YYY-END-OF-SESSION-YYY" \
            or (src_ip and (src_ip in reply or src_ip[:16] in reply)):
        return False
    return cache.put(key, reply)


@dataclass
class _LearnState:
    history: str               # digest of the session's command lines so far
    clean: bool                # no line so far could change state
    script: Optional[str]      # script digest (``learned.script_step``), None once unusable
    tokens: tuple[str, ...]    # the session's token values, numbered session-wide


@dataclass(frozen=True)
class _LearnTurn:
    fingerprint: str     # host, persona block, seed and model the reply was made under
    history: str         # digest of the session's command lines before this one
    command: bool        # a counted, non-empty command: its model use is recorded
    opener: bool         # the session opener: same-history rule only
    eligible: bool       # may be observed and served by the different-histories rule
    script: Optional[str]          # script digest before this line, for the same-history rule
    values: tuple[str, ...]        # the session's token values including this line's
    volatile: bool       # real output changes between runs: never observed or served
    key: Optional[str] = None      # same-history key: the script and this line's bindings


def _learn_turn(session_id: str, src_ip: str, username: Optional[str], interactive: bool,
                host: shell.Host, text: str, counts_as_command: bool) -> Optional[_LearnTurn]:
    """This line's place in the learned store, and the session's state advanced past it
    (the script digest advances in ``_learn_advance``, once the reply is known).

    Different-histories rule: a session may observe and be served while none of its
    earlier lines could change what a later command prints (``learned.may_change_state``):
    such a learned reply was made on a host in its starting state.

    Same-history rule: a session may observe and be served while its script digest is
    known: the chain over every line so far (command and reply as sent, the session's
    random tokens as session-wide placeholders) from a root of host fingerprint, user and
    interactive or exec. Two sessions with one digest sent the same lines and saw the same
    replies, so they are in the same state whatever those lines changed. A session leaves
    this rule when a line cannot be templated (over ``learned.MAX_TOKENS`` token values in
    the session, a control character, over 512 characters) or a reply ends it. A line is
    looked up and observed under ``learned.script_key``: the script digest plus how its
    tokens bind to the session's (which earlier token each one is, or a new one) and
    their lengths and classes. A line that computes over its text (``learned.computes``)
    while the session has tokens is chained but not served or observed by this rule.

    A session whose state was evicted after it had turns is out of both for good. Lines
    whose real output changes between runs (``replycache.volatile``) are never observed or
    served, and a source with a planted token or a ``deep`` or ``shallow`` mode never uses
    the store. None when the store is off or the source is excluded."""
    if _learned is None:
        return None
    fingerprint = learned.digest("host", _learn_model, host.hostname, host.kernel, _seed or "",
                                 persona_fragment(session_id, src_ip), shell.persona_facts(host))
    state = _learn_sessions.get(session_id)
    if state is None:
        fresh = _budget is None or not _budget.session_started(session_id)
        state = _LearnState(learned.START, fresh,
                            learned.script_root(fingerprint, username or "user", interactive)
                            if fresh else None, ())
        _track(_learn_sessions, session_id, state)
    before = (state.history, state.clean, state.script)
    values = state.tokens
    if counts_as_command:
        state.history = learned.digest("turn", state.history, text)
        state.clean = state.clean and not learned.may_change_state(text)
        template = learned.command_template(text) if text.strip() else learned.Template("", ())
        if template is None:
            state.script = None
        else:
            values = values + tuple(v for v in template.values if v not in values)
            if len(values) > learned.MAX_TOKENS:
                state.script, values = None, state.tokens
            state.tokens = values
    if not _cacheable_source(src_ip):
        return None
    command = counts_as_command and bool(text.strip())
    opener = not counts_as_command and text == ""
    vol = volatile(text)
    script = before[2] if (command or opener) and state.script is not None else None
    # A line that computes over its text (a count, a slice, a conversion) in a session
    # that has tokens may depend on a token in ways no key can carry: not by this rule.
    key = learned.script_key(script, text, values) \
        if script is not None and not (values and learned.computes(text)) else None
    return _LearnTurn(fingerprint, before[0], command, opener,
                      command and before[1] and not vol, script, values, vol, key)


def _learn_advance(session_id: str, learn: Optional[_LearnTurn], text: str,
                   result) -> None:
    """Chain this line and its reply as sent into the session's script digest. For the
    opener, and for output that reads the clock or the source address, only the prompt
    the session was left at is chained, not the output; a budget refusal or the end of
    the session takes the session out of the same-history rule."""
    state = _learn_sessions.get(session_id)
    if state is None or state.script is None:
        return
    if learn is None or (learn.command and learn.script is None):
        state.script = None      # an excluded source, or a line that cannot be templated
        return
    if not (learn.opener or learn.command):
        return
    sent = str(getattr(result, "content", ""))
    if getattr(result, "budget_exceeded", False) or sent == "YYY-END-OF-SESSION-YYY":
        state.script = None
        return
    noted = _session_prompts.get(session_id)
    prompt = noted[0] if noted else ""
    if learn.opener:
        # The banner may differ from session to session and is not chained; the prompt
        # it left the session at is.
        state.script = learned.digest("opener", state.script, prompt)
        return
    if (learn.volatile or getattr(result, "private_reply", False)) \
            and learned.may_change_state(text):
        state.script = None      # clock or address output kept in a file or a variable
        return
    if learn.volatile or getattr(result, "private_reply", False):
        # Output that reads the clock or the source address differs in every session and
        # carries no state: the line and the prompt it left are chained, its output is not.
        sent = "\x01" + str(getattr(result, "reply_step", "")) + "\x01" + prompt
    state.script = learned.script_step(learn.script, text, sent, learn.values)


def _learned_lookup(learn: Optional[_LearnTurn], username: Optional[str], interactive: bool,
                    text: str):
    if learn is None or _learned is None or learn.volatile \
            or not (learn.eligible or learn.key is not None):
        return None
    try:
        return _learned.lookup(learn.fingerprint, username or "user", interactive, text,
                               history=learn.history, clean=learn.eligible,
                               script=learn.key, values=learn.values)
    except Exception as exc:  # noqa: BLE001 - a store failure leaves the line to the model
        log.warning("learned reply lookup failed: %s", type(exc).__name__)
        return None


def _learn(learn: Optional[_LearnTurn], *, session_id: str, src_ip: str,
           username: Optional[str], interactive: bool, host: shell.Host, text: str,
           sent: Optional[str], shown_prompt: Optional[str]) -> None:
    """Record that ``text`` reached the model and, when ``sent`` is the model's fresh reply
    sent unchanged, observe it.

    Different-histories rule (a clean session): an interactive reply is kept without its
    final prompt, and only when that prompt is the one shown before the line (the line did
    not move the session). Same-history rule: the reply is kept whole, prompt included,
    since every session with that digest shows the same prompt. For both, a reply that
    ends the session or contains the session's address cannot be stored, and an observed
    reply that cannot be stored (or holds a trace of a token) counts as a different
    reply: the entry, or that history, becomes varying."""
    if learn is None or not (learn.command or learn.opener) or _learned is None:
        return
    shareable = sent is not None and sent != "YYY-END-OF-SESSION-YYY" \
        and not (src_ip and (src_ip in sent or src_ip[:16] in sent))
    observed = sent is not None and learn.eligible
    body = None
    if observed and shareable:
        if interactive:
            prompt = shown_prompt or shell_prompt(username, host.hostname)
            body = sent[:-len(prompt)] if sent.endswith(prompt) else None
        else:
            body = sent
    script = learn.key if sent is not None and not learn.volatile else None
    try:
        _learned.record(learn.fingerprint, username or "user", interactive, text, body,
                        session=session_id, net=learned.network(src_ip),
                        history=learn.history if observed else None, script=script,
                        script_sent=sent if shareable else None, values=learn.values)
    except Exception as exc:  # noqa: BLE001 - a store failure never reaches the session
        log.warning("learned reply record failed: %s", type(exc).__name__)


def step_fields(response) -> dict:
    """``reply_step`` for the event logged with a persona reply, when it has one."""
    step = getattr(response, "reply_step", None)
    return {"reply_step": step} if isinstance(step, str) else {}


async def _pause() -> None:
    """``local_reply_delay_ms`` before a reply made without a model call."""
    if _local_delay_ms > 0:
        import asyncio
        import random

        await asyncio.sleep(random.uniform(0.5, 1.0) * _local_delay_ms / 1000)


def replies_cut() -> int:
    """How many model replies were cut back to one round since start (``agents.onereply``)."""
    return _cuts_total


def _cut_reply(history, response, *, session_id: str, text: str, interactive: bool,
               username: Optional[str], host: shell.Host, shown_prompt: Optional[str],
               logger, log_extra: Optional[dict]) -> Optional[dict]:
    """Cut a model reply back to what a shell prints for ``text`` (``onereply.one_reply``).
    When it was cut: the history holds the kept text instead, one "Reply cut" event is
    logged (counts and a short escaped sample, never the whole dropped text), and the
    returned dict carries the kept text and the event fields."""
    global _cuts_total
    reply = _content(response)
    current = shown_prompt or shell_prompt(username, host.hostname)
    noted = onereply.prompt_host(shown_prompt) if shown_prompt else None
    cut = onereply.one_reply(
        reply, text, interactive=interactive, hosts=(host.hostname, noted),
        current_prompt=current, user=(username or "user")[:32],
        viewer=_may_show_text(text),
        text_built_before=session_id in _session_built)
    if cut is None:
        return None
    _replace_in_history(history, session_id, cut.kept)
    _cuts_total += 1
    count = _session_cuts.get(session_id, 0) + 1
    _track(_session_cuts, session_id, count)
    fields = {"cut_reason": cut.reason, "dropped_chars": cut.dropped,
              "dropped_sample": cut.sample, "cuts_in_session": count}
    _log(logger, "Reply cut", log_extra, **fields)
    return {"kept": cut.kept, **fields}


async def persona_invoke(history, *, session_id: str, src_ip: str, username: Optional[str],
                         text: str, interactive: bool, llm_config: dict, logger=None,
                         log_extra: Optional[dict] = None, counts_as_command: bool = True,
                         scenario=None):
    """The one path every persona model call takes (SSH and telnet); see
    ``_persona_invoke``. The result carries ``reply_step``: the step that answered
    (``local``, ``cached``, ``learned``, ``capped``, ``model``, ``fallback`` after a model
    error, ``budget``, ``offline``), or ``opener`` for the session opener."""
    learn = _learn_turn(session_id, src_ip, username, interactive, shell_host(scenario), text,
                        counts_as_command) \
        if _budget is not None and not _offline_reason else None
    result = await _persona_invoke(
        history, session_id=session_id, src_ip=src_ip, username=username, text=text,
        interactive=interactive, llm_config=llm_config, logger=logger, log_extra=log_extra,
        counts_as_command=counts_as_command, scenario=scenario, learn=learn)
    _learn_advance(session_id, learn, text, result)
    if not counts_as_command:
        result.reply_step = "opener"
    return result


async def _persona_invoke(history, *, session_id: str, src_ip: str, username: Optional[str],
                          text: str, interactive: bool, llm_config: dict, logger=None,
                          log_extra: Optional[dict] = None, counts_as_command: bool = True,
                          scenario=None, learn: Optional[_LearnTurn] = None):
    """The one path every persona model call takes (SSH and telnet).

    Reserves the estimated cost first. When a limit would be exceeded the model is not
    called: a canned, plausible response is returned with ``budget_exceeded=True`` and
    the caller closes. A failed call keeps its reserved charge. Offline (no model), replies
    are canned and charge no tokens; the per-session command cap still applies.

    With a model, in this order (none of the first three is a model call or charges
    tokens; each counts as a command and is added to the history and to the token
    estimate):

    - ``local_shell_replies``: a line the deterministic shell can answer is answered from
      the host profile when it reads only facts no command can change (``shell.FIXED``),
      or facts a session can change (``shell.SESSION``) while no model reply has answered
      a command yet. It ends with the prompt the model showed last; once that prompt's
      shape does not give the working directory, the session gets no more local answers.
      ``scenario`` overrides the active scenario (the telnet listener).
    - the reply cache: a model reply stored for a session whose history so far was the
      same (``agents.replycache``, ``_turn_key``). Consulted before the model cap.
    - learned replies: a reply the model gave to the same command template in enough
      unrelated sessions, with the session's current prompt, or in enough sessions whose
      whole script so far matched this one, whole (``agents.learned``, ``_learn_turn``).
      The session opener is looked up by the second rule only. Consulted before the model cap; logged as a "Learned reply" event (the
      result carries ``learned_reply`` for a caller without a logger). It is added to the
      history, counts as a model reply for the local-answer rule, and keeps the session
      in or out of the reply cache as a cached reply does.
    - ``max_model_commands_per_session``: once the model has been asked that many
      commands (failed calls included), the deterministic shell answers the rest
      (``model_capped=True``; logged once).

    A session stays in the reply cache only while every turn in its history is a function
    of its key: a local answer that read neither the clock nor the source address
    (``shell.Answer.shareable``), a cached reply, or a model reply it has just stored. Any
    other turn (such a local answer, a model error, a fallback, a replaced or unstored
    reply) takes it out for good.

    A fresh model reply is cut back to one round (``_cut_reply``, ``agents.onereply``)
    before anything else reads it; the result then carries ``reply_cut`` (the logged
    fields) so a caller without a logger (telnet) can record the event.

    A reply that breaks character, is empty (interactive) or empty once code fences are
    stripped, or misprints a literal ``echo`` is asked again up to ``persona_retries``
    times (``_retry_reason``, ``_persona_retry``): the same input with a short note and
    examples added to the persona block. Each retry is charged to the budget but does not
    count as another command, and the history keeps only the reply that is sent. One
    "Persona retry" event per retry; the result carries ``persona_retry`` (the reasons).
    When the last reply is still rejected, ``_model_reply`` replaces it, and an empty
    reply after a retry becomes ``in_character_reply`` (never stored in the reply cache).

    Every command that reaches the model is recorded in the learned store, and a fresh
    reply sent unchanged (not cut, retried or replaced; prompt tidying aside) is observed
    there (``_learn``).
    """
    budget = _budget_or_none()
    host = shell_host(scenario)
    if onereply.builds_text(text):
        _track(_session_built, session_id, True)
    prompt_state = _session_prompts.get(session_id) if interactive else None
    shown_prompt = prompt_state[0] if prompt_state else None
    with_model = budget is not None and not _offline_reason
    key = _turn_key(session_id, src_ip, username, interactive, host, text) \
        if with_model else None
    local = cached = found = None
    capped = False
    owned = None
    if with_model:
        local_ok = prompt_state is None or prompt_state[1] is not None
        if _local_replies and counts_as_command and local_ok:
            cwd = prompt_state[1] if prompt_state else None
            answered = budget.model_answered(session_id)
            # While no model call has been made for a command (``model_answered``; a
            # failed call counts), the only state is what ``fallback_reply`` keeps in
            # ``_shell_sessions`` (as under a model cap of 0). Local
            # answers read that state, on a copy kept only if the answer is used, so a
            # line left to the fallback is not applied twice. Once a model call has been
            # made (which never reverts), only FIXED answers are used, and no session
            # state can change those: the state then lives in the model's history, or in
            # the fallback session that the model path (cap, error) itself runs.
            fallback = _shell_sessions.get(session_id) if not answered else None
            scratch = fallback.copy() if fallback is not None else None
            answer = shell.answer(host, text, user=username or "user",
                                  interactive=interactive, cwd=cwd, src_ip=src_ip,
                                  session=scratch)
            if answer is not None and (answer.scope == shell.FIXED or (
                    answer.scope == shell.SESSION and not answered)):
                local = answer
                if scratch is not None:
                    _track_shell(session_id, scratch)
                    owned = scratch
        cache = reply_cache()
        if local is None and key is not None and cache is not None:
            cached = cache.get(key)
        if local is None and cached is None:
            found = _learned_lookup(learn, username, interactive, text)
        capped = local is None and cached is None and found is None and counts_as_command \
            and budget.model_cap_reached(session_id, src_ip)
    if budget is None:
        reason, reservation = "budget_not_initialised", None
    elif _offline_reason or local is not None or cached is not None or found is not None \
            or capped:
        reason = budget.count_command(session_id, src_ip, cached=cached is not None,
                                      learned=found is not None) \
            if counts_as_command else None
        reservation = None
    else:
        reason, reservation = budget.reserve(session_id, src_ip, text, counts_as_command)
    if reason is not None:
        _log(logger, "Budget exceeded", log_extra, reason=reason)
        canned = CANNED_INTERACTIVE if interactive else CANNED_NON_INTERACTIVE
        return SimpleNamespace(content=canned, budget_exceeded=True, reply_step="budget")
    if _offline_reason:
        await _tarpit(src_ip)
        return SimpleNamespace(content=fallback_reply(text, interactive, username, host, src_ip,
                                                      session_id=session_id),
                               reply_step="offline")
    if local is not None:
        await _tarpit(src_ip)
        await _pause()
        prompt = "" if not interactive else _prompt_at(username, host, owned) \
            if owned is not None else (shown_prompt or shell_prompt(username, host.hostname))

        def shown(output: str) -> str:
            return (output.replace("\n", "\r\n") if interactive else output) + prompt

        kept = shown(_clip_local(shell.printable(local.output)))   # binary bytes as \xNN
        stored = _remember(history, session_id, text, kept)
        if stored is not None:
            budget.add_history(session_id, src_ip, text, stored)
        if local.shareable:
            _advance(session_id, key, kept)
        else:
            _leave(session_id)
        return SimpleNamespace(content=shown(local.output), local_reply=True, reply_step="local",
                               private_reply=not local.shareable)
    if cached is not None:
        await _tarpit(src_ip)
        await _pause()
        if _remember(history, session_id, text, cached) is not None:
            budget.add_history(session_id, src_ip, text, cached)
        if interactive:
            _note_prompt(session_id, cached, username)
        _advance(session_id, key, cached)
        return SimpleNamespace(content=cached, cached_reply=True, reply_step="cached")
    if found is not None:
        await _tarpit(src_ip)
        await _pause()
        sent = found.reply if found.whole or not interactive else \
            found.reply + (shown_prompt or shell_prompt(username, host.hostname))
        if _remember(history, session_id, text, sent) is not None:
            budget.add_history(session_id, src_ip, text, sent)
        if interactive:
            _note_prompt(session_id, sent, username)
        _advance(session_id, key, sent)
        with contextlib.suppress(Exception):
            _learned.served(found.entry)   # type: ignore[union-attr]
        _log(logger, "Learned reply", log_extra, learned_id=found.entry,
             learned_rule=found.rule)
        return SimpleNamespace(content=sent, reply_step="learned",
                               learned_reply={"learned_id": found.entry,
                                              "learned_rule": found.rule})
    if capped:
        if budget.note_model_cap(session_id):
            _log(logger, "Model cap reached", log_extra,
                 limit=budget.model_cap(session_id, src_ip))
        await _tarpit(src_ip)
        await _pause()
        _leave(session_id)
        sent = fallback_reply(text, interactive, username, host, src_ip, shown_prompt,
                              session_id)
        if sent != "YYY-END-OF-SESSION-YYY":
            stored = _remember(history, session_id, text, _clip_local(shell.printable(sent)))
            if stored is not None:
                budget.add_history(session_id, src_ip, text, stored)
        return SimpleNamespace(content=sent, model_capped=True, reply_step="capped")
    try:
        response = await history.ainvoke(
            {
                "messages": [HumanMessage(content=text)],
                "username": username,
                "interactive": interactive,
                "decoy_profile": persona_fragment(session_id, src_ip)
                + shell.persona_facts(host) + _not_found_hint(host, interactive),
            },
            config=llm_config,
        )
    except Exception as exc:  # noqa: BLE001 - a provider failure must not end the session
        _log(logger, "Model error", log_extra, error=type(exc).__name__,
             error_detail=_clip_error(exc))
        _leave(session_id)
        await _tarpit(src_ip)
        return SimpleNamespace(content=fallback_reply(text, interactive, username, host, src_ip,
                                                      shown_prompt, session_id),
                               reply_step="fallback")
    budget.commit(reservation, text, _content(response), usage_tokens=_usage_tokens(response))
    await _tarpit(src_ip)
    # First, before the reply is sent, kept, cached, logged or read for the prompt: cut it
    # back to the one round the input asked for.
    cut = _cut_reply(history, response, session_id=session_id, text=text,
                     interactive=interactive, username=username, host=host,
                     shown_prompt=shown_prompt, logger=logger, log_extra=log_extra)
    if cut is not None:
        response = SimpleNamespace(content=cut["kept"],
                                   usage_metadata=getattr(response, "usage_metadata", None))
    retries: list[str] = []
    reason = _retry_reason(response, text, interactive) if _persona_retries else None
    while reason is not None and len(retries) < _persona_retries:
        retried = await _persona_retry(
            history, response, reason, len(retries) + 1, budget=budget,
            session_id=session_id, src_ip=src_ip,
            username=username, text=text, interactive=interactive, llm_config=llm_config,
            host=host, shown_prompt=shown_prompt, logger=logger, log_extra=log_extra)
        if retried is None:
            break
        retries.append(reason)
        response, retry_cut = retried
        cut = retry_cut or cut
        reason = _retry_reason(response, text, interactive)
    reply_key = key
    if retries and not _content(response).strip():
        # A replacement, not a model reply: never stored in the reply cache.
        _leave(session_id)
        reply_key = None
        response = SimpleNamespace(content=in_character_reply(text, interactive, username,
                                                              shown_prompt),
                                   usage_metadata=getattr(response, "usage_metadata", None))
        _replace_in_history(history, session_id, response.content)
    fresh = _content(response)
    result = _model_reply(history, response, session_id=session_id, key=reply_key, text=text,
                          interactive=interactive, username=username,
                          shown_prompt=shown_prompt, src_ip=src_ip, logger=logger,
                          log_extra=log_extra)
    if not isinstance(result, SimpleNamespace):
        result = SimpleNamespace(content=result.content,
                                 usage_metadata=getattr(result, "usage_metadata", None))
    unchanged = cut is None and not retries and not getattr(result, "persona_break", False) \
        and result.content == (_tidy_prompt(fresh) if interactive else fresh)
    _learn(learn, session_id=session_id, src_ip=src_ip, username=username,
           interactive=interactive, host=host, text=text,
           sent=result.content if unchanged else None, shown_prompt=shown_prompt)
    result.reply_step = "model"
    if cut is not None:
        result.reply_cut = {k: v for k, v in cut.items() if k != "kept"}
    if retries:
        result.persona_retry = retries
    return result


_RETRY_PROBLEMS = {
    "persona_break": "it talked about itself instead of printing terminal output",
    "empty": "it was empty",
    "literal_mismatch": "it did not print the literal text the command echoes",
}


def _retry_reason(response, text: str, interactive: bool) -> Optional[str]:
    """Why a fresh model reply would be replaced (``_model_reply``), or None when it is
    sent: ``persona_break``, ``empty`` (interactive, or empty once fences are stripped),
    ``literal_mismatch`` (interactive ``echo``/``printf`` of literal text)."""
    content = _content(response)
    if breaks_character(content, text):
        return "persona_break"
    unfenced = _strip_fences(content, text)
    if not unfenced.strip() and (interactive or unfenced != content):
        return "empty"
    if interactive:
        expected = (_literal_output(text) or "").strip()
        if expected and expected not in unfenced:
            return "literal_mismatch"
    return None


def _retry_note(reason: str, interactive: bool, prompt: str) -> str:
    """The note added to the persona block for a retry: what was wrong and two examples
    of a correct terminal reply."""
    end = prompt if interactive else ""
    nl = "\r\n" if interactive else "\n"
    return ("\n\nNote: your previous reply to this input was rejected because "
            f"{_RETRY_PROBLEMS[reason]}. Reply with exactly what the terminal prints for it"
            f"{', ending with the prompt' if interactive else ''}, and nothing else. Examples "
            f"of correct replies:\ninput: echo ok\nreply: {json.dumps('ok' + nl + end)}\n"
            "input: nosuchtool --help\nreply: "
            f"{json.dumps('-bash: nosuchtool: command not found' + nl + end)}")


def _drop_last_turn(history, session_id: str, text: str) -> bool:
    """Remove the input line and reply the chain just stored, when they are the last two
    messages of the session's history. True when they were removed."""
    getter = getattr(history, "get_session_history", None)
    if not callable(getter):
        return False
    try:
        messages = getter(session_id).messages
    except Exception:  # noqa: BLE001 - a history store without this shape is left alone
        return False
    if len(messages) >= 2 and isinstance(messages[-1], AIMessage) and \
            isinstance(messages[-2], HumanMessage) and messages[-2].content == text:
        del messages[-2:]
        return True
    return False


async def _persona_retry(history, response, reason: str, attempt: int, *, budget: Budget,
                         session_id: str, src_ip: str, username: Optional[str], text: str,
                         interactive: bool, llm_config: dict, host: shell.Host,
                         shown_prompt: Optional[str], logger, log_extra: Optional[dict]):
    """Ask the model once more for ``text``. Returns (response, cut fields or None), or
    None when the budget refuses the call or the call fails; the history then holds the
    rejected reply, for ``_model_reply`` to replace."""
    refused, reservation = budget.reserve(session_id, src_ip, text, counts_as_command=False)
    if refused is not None:
        return None
    _log(logger, "Persona retry", log_extra, reason=reason, attempt=attempt)
    rejected = _content(response)
    dropped = _drop_last_turn(history, session_id, text)
    prompt = shown_prompt or shell_prompt(username, host.hostname)
    try:
        response = await history.ainvoke(
            {
                "messages": [HumanMessage(content=text)],
                "username": username,
                "interactive": interactive,
                "decoy_profile": persona_fragment(session_id, src_ip)
                + shell.persona_facts(host) + _not_found_hint(host, interactive)
                + _retry_note(reason, interactive, prompt),
            },
            config=llm_config,
        )
    except Exception as exc:  # noqa: BLE001 - a provider failure keeps the first reply's path
        _log(logger, "Model error", log_extra, error=type(exc).__name__,
             error_detail=_clip_error(exc))
        if dropped:
            _remember(history, session_id, text, rejected)
        return None
    budget.commit(reservation, text, _content(response), usage_tokens=_usage_tokens(response))
    cut = _cut_reply(history, response, session_id=session_id, text=text,
                     interactive=interactive, username=username, host=host,
                     shown_prompt=shown_prompt, logger=logger, log_extra=log_extra)
    if cut is not None:
        response = SimpleNamespace(content=cut["kept"],
                                   usage_metadata=getattr(response, "usage_metadata", None))
    return response, ({k: v for k, v in cut.items() if k != "kept"} if cut else None)


def _model_reply(history, response, *, session_id: str, key: Optional[str], text: str,
                 interactive: bool, username: Optional[str], shown_prompt: Optional[str],
                 src_ip: str, logger, log_extra: Optional[dict]):
    """A fresh model reply (already cut to one round) checked, tidied, kept and returned."""
    if breaks_character(_content(response), text):
        _leave(session_id)
        sent = in_character_reply(text, interactive, username, shown_prompt)
        _replace_in_history(history, session_id, sent)
        original = _content(response)[:MAX_BREAK_LOGGED]
        _log(logger, "Persona break", log_extra,
             details=base64.b64encode(original.encode("utf-8", "replace")).decode("ascii"))
        return SimpleNamespace(content=sent, persona_break=True)
    reply = _as_text_reply(response)
    unfenced = _strip_fences(reply.content, text)
    if unfenced != reply.content:
        if not unfenced.strip():
            unfenced = in_character_reply(text, interactive, username, shown_prompt)
        _replace_in_history(history, session_id, unfenced)
        reply = SimpleNamespace(content=unfenced,
                                usage_metadata=getattr(reply, "usage_metadata", None))
    if interactive:
        expected = (_literal_output(text) or "").strip()
        if expected and expected not in reply.content:
            # echo/printf of literal text has one right answer; use it when the model's differs
            _leave(session_id)
            sent = in_character_reply(text, interactive, username, shown_prompt)
            _replace_in_history(history, session_id, sent)
            return SimpleNamespace(content=sent,
                                   usage_metadata=getattr(reply, "usage_metadata", None))
        tidy = _tidy_prompt(reply.content)
        _note_prompt(session_id, tidy, username)
        if tidy != reply.content:
            _replace_in_history(history, session_id, tidy, was=reply.content)
        _keep(session_id, key, text, tidy, src_ip)
        if tidy != reply.content:
            return SimpleNamespace(content=tidy,
                                   usage_metadata=getattr(reply, "usage_metadata", None))
        return reply
    _keep(session_id, key, text, reply.content, src_ip)
    return reply


def _keep(session_id: str, key: Optional[str], text: str, reply: str, src_ip: str) -> None:
    """Store a fresh model reply and chain it into the key, or, when it cannot be stored,
    take the session out of the cache: another session sending the same lines would get a
    different reply here, so nothing this one stores later would fit its history."""
    if _store(key, text, reply, src_ip):
        _advance(session_id, key, reply)
    else:
        _leave(session_id)


SUMMARY_KEY = "\x00session summary"


async def summary_invoke(history, *, session_id: str, src_ip: str, username: Optional[str],
                         prompt: str, llm_config: dict, logger=None, log_extra=None):
    """Session summary call, under the same session, per-source and daily caps.

    Skipped (no model call) when no model reply answered a command in the session (fresh,
    cached or learned), so a source reconnecting in a loop cannot spend the day on summaries of
    nothing. A session that replayed a cached conversation gets the cached summary.
    """
    budget = _budget_or_none()
    if budget is None:
        _log(logger, "Budget exceeded", log_extra, reason="budget_not_initialised",
             stage="session_summary")
        return SimpleNamespace(content=SUMMARY_SKIPPED, budget_exceeded=True)
    if _offline_reason:
        return SimpleNamespace(content=SUMMARY_SKIPPED, budget_exceeded=True)
    if budget.model_commands(session_id) == 0 and budget.cached_commands(session_id) == 0 \
            and budget.learned_commands(session_id) == 0:
        _log(logger, "Summary skipped", log_extra, reason="no_model_commands")
        return SimpleNamespace(content=SUMMARY_SKIPPED, budget_exceeded=True)
    state = _session_keys.get(session_id)
    key = conversation_key(state, SUMMARY_KEY) if state else None   # None or _LEFT: no cache
    cache = reply_cache()
    if key and cache is not None and _cacheable_source(src_ip):
        cached = cache.get(key)
        if cached is not None:
            return SimpleNamespace(content=cached, cached_reply=True)
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
    reply = _as_text_reply(response)
    if key:
        _store(key, "", reply.content, src_ip)
    return reply


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
