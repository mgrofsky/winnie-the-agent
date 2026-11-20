"""python -m listeners --config SSH/config.ini [--scenario NAME] [--list-scenarios] [--describe NAME]

Starts every enabled low-interaction listener in one process. Which services run, their
ports, banners, accounts and fake data come from the active scenario; per-service keys in
the ``[listeners]`` config section override it.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import logging
import os
import sys
from configparser import ConfigParser
from pathlib import Path
from typing import Optional

from agents import REPO_ROOT
from listeners.base import (
    SERVICES,
    Limits,
    ListenerContext,
    default_seed,
    parse_port_range,
    resolve_settings,
)
from listeners.events import EventWriter

log = logging.getLogger("listeners")


def _resolve(base: Path, value: str) -> str:
    p = Path(value)
    return str(p if p.is_absolute() else base / p)


def _telnet_persona(config: ConfigParser, base: Path):
    """Build the SSH persona chain for telnet (same code path as SSH). Best effort.
    Returns (chain, the dict holding its per-session chat histories)."""
    ssh_dir = REPO_ROOT / "SSH"
    if str(ssh_dir) not in sys.path:
        sys.path.insert(0, str(ssh_dir))
    import ssh_server  # noqa: E402

    ssh_server.config = config
    ssh_server.config_base_dir = str(base)
    prompt_file = config["llm"].get("prompt_file", "prompt.txt") if "llm" in config else "prompt.txt"
    if not os.path.exists(ssh_server.resolve_runtime_path(prompt_file)):
        # get_prompts would exit the whole process; the caller falls back to the static shell.
        raise FileNotFoundError("[llm] prompt_file not found")
    prompts = ssh_server.get_prompts(None, prompt_file)
    chain = ssh_server.build_message_history(prompts["system_prompt"], prompts["user_prompt"])
    return chain, ssh_server.llm_sessions


def build_context(config: ConfigParser, base: Path, scenario_name: Optional[str],
                  log_file: Optional[str] = None, data_dir: Optional[str] = None) -> ListenerContext:
    if "listeners" not in config:
        config["listeners"] = {}
    section = config["listeners"]
    if data_dir:  # container layout: everything writable lives under one volume
        section["quarantine_dir"] = str(Path(data_dir) / "quarantine")
    limits = Limits.from_section(section)
    honeypot = config["honeypot"] if "honeypot" in config else {}
    log_file = log_file or section.get("log_file") or honeypot.get("log_file", "ssh_log.log")
    writer = EventWriter(_resolve(base, log_file), honeypot.get("sensor_name", "winnie"))
    from agents import runtime

    ddir = runtime.data_dir(config, base, data_dir)
    seed = default_seed(config, ddir)

    scenario = None
    name = scenario_name or (config["scenario"].get("active", "").strip() if "scenario" in config else "")
    # Read-only for the front-ends; only the agents write it. The honeytoken registry is
    # written by the agents too (from the same seed), never by a front-end.
    overlay = str(runtime.overlay_path(config, base))
    if name:
        from scenarios.loader import load_scenario

        scenario = load_scenario(name, seed, overlay)

    from agents import hooks
    from agents.budget import Budget, BudgetConfig
    from agents.source_state import source_state_path

    # Same [budget] limits and the same locked daily state file as the SSH process, so the
    # daily caps are shared. Telnet's persona calls go through this same Budget.
    budget = Budget(BudgetConfig.from_config(config, str(base), str(ddir)))
    hooks.set_budget(budget)
    json_llm = None
    if str(section.get("llm", "false")).lower() in ("1", "true", "yes", "on"):
        from agents.llm import build_json_llm

        # Same provider as the analyst agents. One logical call is one request: no SDK
        # retries, no validation retry.
        json_llm = build_json_llm(config, section.get("model"), timeout=limits.llm_timeout,
                                  sdk_max_retries=0, validation_retries=0)

    ctx = ListenerContext(
        writer=writer, limits=limits, seed=seed, scenario=scenario,
        settings=resolve_settings(config, scenario),
        quarantine_dir=_resolve(base, section.get("quarantine_dir", str(REPO_ROOT / "quarantine"))),
        budget=budget, json_llm=json_llm,
        honeytokens=scenario.recognised_tokens() if scenario else {},
        bind_host=section.get("bind_host", "0.0.0.0"),
        source_state_path=str(source_state_path()),
    )
    # One per-source view for this process: the budget (deep / shallow) and the telnet
    # persona path in agents.hooks (planted tokens, tarpit) read the same state as the
    # listeners themselves.
    hooks.set_source_state(ctx.source_state, seed)
    hooks.set_local_replies(hooks.local_replies_enabled(config))
    ctx.overlay_path = overlay  # type: ignore[attr-defined]
    ctx.ftp_pasv_ports = parse_port_range(section.get("ftp_pasv_ports", ""))
    ctx.ftp_pasv_address = (section.get("ftp_pasv_address", "") or "").strip() or None
    # The telnet persona uses the [llm] provider (same as SSH), only when model use is enabled
    # for the listeners and that provider's key is available; otherwise a canned shell.
    model_use = str(section.get("llm", "false")).lower() in ("1", "true", "yes", "on")
    if ctx.settings["telnet"].enabled and model_use and hooks.provider_unavailable(config) is None \
            and str(section.get("telnet_persona", "true")).lower() in ("1", "true", "yes", "on"):
        try:
            ctx.persona_history, ctx.persona_sessions = _telnet_persona(config, base)
        except Exception as exc:  # noqa: BLE001 - telnet falls back to the static shell
            log.warning("telnet persona unavailable: %s", type(exc).__name__)
    return ctx


async def _reload_overlay(ctx: ListenerContext, config: ConfigParser, interval: float = 30.0) -> None:
    """Pick up tuner overlay changes (accounts, SIP extensions, after_n) without a restart."""
    path = getattr(ctx, "overlay_path", None)
    if not path or ctx.scenario is None:
        return
    from scenarios.loader import load_scenario

    last = os.path.getmtime(path) if os.path.exists(path) else None
    while True:
        await asyncio.sleep(interval)
        current = os.path.getmtime(path) if os.path.exists(path) else None
        if current == last:
            continue
        last = current
        try:
            ctx.scenario = load_scenario(ctx.scenario.scenario.name, ctx.seed, path)
        except Exception as exc:  # noqa: BLE001 - keep the last good overlay
            log.warning("overlay reload failed: %s", type(exc).__name__)
            continue
        fresh = resolve_settings(config, ctx.scenario)
        for name, s in ctx.settings.items():
            s.accounts = fresh[name].accounts
            s.policy = fresh[name].policy


async def _report_suppressed(ctx: ListenerContext, interval: Optional[float] = None) -> None:
    """Every gate window, write summary lines for suppressed log lines not yet reported."""
    while True:
        await asyncio.sleep(interval if interval is not None else ctx.gate.window)
        try:
            ctx.report_suppressed()
        except Exception as exc:  # noqa: BLE001 - reporting must never stop the listeners
            log.warning("suppression summary failed: %s", type(exc).__name__)


async def serve(ctx: ListenerContext, config: ConfigParser) -> None:
    handles = []
    for name in SERVICES:
        settings = ctx.settings[name]
        if not settings.enabled:
            continue
        try:
            module = importlib.import_module(f"listeners.{name}")
        except ImportError:
            log.error("listener %s enabled but listeners/%s.py is missing; skipped", name, name)
            continue
        handles += await module.start(ctx, settings)
        log.info("listener %s on %s:%s", name, ctx.bind_host, settings.port)
    if not handles:
        log.error("no listeners enabled")
        return
    reloader = asyncio.create_task(_reload_overlay(ctx, config))
    reporter = asyncio.create_task(_report_suppressed(ctx))
    try:
        await asyncio.Event().wait()
    finally:
        reloader.cancel()
        reporter.cancel()


def _describe_seed(config: ConfigParser, base: Path, args) -> tuple[str, str]:
    """The seed --describe expands bait with, and a line saying where it came from. Reads
    the sensor seed without creating one."""
    if args.seed_preview:
        return args.seed_preview, "Seed: the --seed-preview value, not this sensor's own."
    from agents import runtime

    try:
        ddir = runtime.data_dir(config, base, args.data_dir)
        seed = runtime.sensor_seed(config, ddir, create=False)
    except OSError:
        seed = None
    if seed:
        return seed, "Seed: this sensor's own seed."
    return "preview", ("Seed: none found for this sensor yet (it is created on first start); "
                       "showing a preview. The running sensor will show different values.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m listeners", description=__doc__)
    parser.add_argument("--config", help="path to config.ini (default SSH/config.ini)")
    parser.add_argument("--scenario", help="override [scenario] active")
    parser.add_argument("--list-scenarios", action="store_true")
    parser.add_argument("--describe", metavar="NAME",
                        help="show what a scenario exposes on this sensor (its seed's bait)")
    parser.add_argument("--seed-preview", metavar="TEXT",
                        help="with --describe: show the bait for this seed instead of the "
                             "sensor's own")
    parser.add_argument("--log-file", help="override the event log path")
    parser.add_argument("--data-dir", help="writable dir for quarantine, budget state, reports")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    config_path = Path(args.config) if args.config else REPO_ROOT / "SSH" / "config.ini"
    config = ConfigParser()
    if config_path.exists():
        config.read(config_path)
    elif args.config:
        print(f"config not found: {config_path}", file=sys.stderr)
        return 1

    if args.list_scenarios or args.describe:
        from scenarios import describe as d

        if args.list_scenarios:
            print(d.list_text())
            return 0
        seed, note = _describe_seed(config, config_path.resolve().parent, args)
        print(d.describe(args.describe, seed=seed, seed_note=note))
        return 0
    ctx = build_context(config, config_path.resolve().parent, args.scenario,
                        log_file=args.log_file, data_dir=args.data_dir)
    try:
        asyncio.run(serve(ctx, config))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
