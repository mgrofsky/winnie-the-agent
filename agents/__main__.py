"""CLI: python -m agents {triage,respond,digest,tune,detect,ship,run-all,queue,approve,reject,unblock,
enforce,playbooks,ui,stix,learned}.

Directories:
- ``--data-dir``: the front-ends' data directory (log, sensor seed). Only read here, except
  by ``learned --forget`` and ``learned --clear``, which change the learned-reply store.
- ``--reports-dir``: triage records, digests, tuner records, honeytoken registry.
- ``--state-dir``: cursor, tuner snapshots and state, analyst call counter
  (default ``<reports-dir>/state``).
- ``--overlay``: the tuner-owned overlay file.

``ship`` sends the event log to S3 when ``[connector.s3_events]`` is enabled, the tracked
export when ``[connector.tracked_export]`` is, fetches sightings when
``[connector.sightings]`` is, and looks up interesting sources in Shodan InternetDB when
``[connector.internetdb]`` is; ``run-all`` runs it as its last step. With
``[connector.internetdb] mode = delivered`` ``run-all`` writes the wanted list, and
``[connector.internetdb_exchange]`` moves it and the answers through the object store
(``kind = s3``) or, with ``kind = lookup``, asks InternetDB itself in the process that runs
it (on AWS the exporter, never the agents container).
With ``[connector.otx]`` enabled ``run-all`` writes the OTX candidates file and the
process with ``submit = true`` (on AWS the exporter) adds them to the day's OTX pulse.

``enforce <address>`` moves one tracked blocklist entry to enforced (``[respond]
track_before_enforce``).

``ui`` serves the operator console on loopback (``[ui]``; ``--bind``, ``--port``,
``--actions``, ``--by``, ``--external-host``). It reads the same directories, takes no run
lock and never calls a model. The sign-in token comes from ``WINNIE_UI_TOKEN`` or is
generated at start.

``learned`` shows and edits the persona's learned replies (``agents.learned``, the file
beside the budget state file): ``--stats`` (entries, and commands per reply step from the
event log), ``--list``, ``--candidates`` (commands that reach the model most often and are
not served), ``--forget <id>`` and ``--clear``. It prints plain text with attacker text
escaped, takes no run lock and never calls a model.

``stix`` writes the STIX 2.1 bundle (``[stix]``, off by default) to a local file;
``run-all`` does too when it is enabled. Nothing is sent anywhere (agents/stix.py).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from configparser import ConfigParser, Error as ConfigParserError
from pathlib import Path
from typing import Optional

from agents import REPO_ROOT, runtime
from agents.llm import DEFAULT_ANALYST_MODEL, BudgetedJsonLLM, DailyCallCounter, build_json_llm

log = logging.getLogger("agents")


def _load_config(path: Optional[str]) -> tuple[ConfigParser, Path, Optional[str]]:
    """Returns (config, base dir, error). A config that cannot be parsed is reported."""
    cp = ConfigParser()
    target = Path(path) if path else REPO_ROOT / "SSH" / "config.ini"
    if path and not target.exists():
        return cp, target.resolve().parent, f"config not found: {path}"
    if target.exists():
        try:
            # read_file, not read(): read() silently skips a file it cannot open (a directory,
            # no permission), which would look like an empty config.
            with open(target) as handle:
                cp.read_file(handle, source=str(target))
        except (ConfigParserError, UnicodeDecodeError, OSError) as exc:
            return ConfigParser(), target.resolve().parent, \
                f"config not readable: {type(exc).__name__}"
    return cp, target.resolve().parent, None


def _resolve(base: Path, value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else base / p


def _llm(args, cp: ConfigParser, state_dir: Path, max_calls: int):
    if args.no_llm:
        return None
    agents_cfg = cp["agents"] if "agents" in cp else {}
    inner = build_json_llm(cp, args.model)
    if inner is None:
        log.warning("running without a model (SSH sessions and campaigns get deterministic "
                    "records)")
        return None
    daily = DailyCallCounter(state_dir / "analyst_calls.json",
                             int(agents_cfg.get("max_analyst_calls_per_day", 500)))
    return BudgetedJsonLLM(inner, max_calls, daily)


def _scenario(cp: ConfigParser, data_dir: Path, overlay: Path):
    if "scenario" not in cp or not cp["scenario"].get("active", "").strip():
        return None
    from scenarios.loader import load_scenario

    seed = runtime.sensor_seed(cp, data_dir, create=False)
    if seed is None:
        log.warning("no sensor seed in %s yet (the front-ends create it); honeytokens and "
                    "scenario data are unavailable this run", data_dir)
        return None
    return load_scenario(cp["scenario"]["active"].strip(), seed, overlay)


UI_TOKEN_ENV = "WINNIE_UI_TOKEN"  # noqa: S105 - the variable's name, not a value


def _ui(args, cp: ConfigParser, base: Path, *, data_dir: Path, reports: Path, state: Path,
        detections: Path, overlay: Path, source_state: Path, log_path: Optional[str]) -> dict:
    """Serve the operator console until interrupted. The token is never read from the
    config file: ``WINNIE_UI_TOKEN`` or a fresh one (``serve`` logs the sign-in link)."""
    from agents.budget import BudgetConfig
    from agents.respond import RespondSettings
    from agents.ui.activity import DEFAULT_MAX_ENTRIES, MAX_ENTRIES, MIN_ENTRIES
    from agents.indicators import from_config as indicators_from_config
    from agents.ui.api import Api, ApiLimits, ApiPaths
    from agents.ui.server import UiSettings, serve

    ui_cfg = cp["ui"] if "ui" in cp else {}
    agents_cfg = cp["agents"] if "agents" in cp else {}
    operator = (args.by or str(ui_cfg.get("operator", ""))).strip()[:64]
    try:
        settings = UiSettings(
            bind=args.bind or str(ui_cfg.get("bind", "127.0.0.1")).strip() or "127.0.0.1",
            port=args.port if args.port is not None else int(ui_cfg.get("port", 8480)),
            actions=args.actions or str(ui_cfg.get("actions", "false")).strip().lower()
            in ("1", "true", "yes", "on"),
            operator=operator,
            allow_non_loopback=args.allow_non_loopback,
            token=os.environ.get(UI_TOKEN_ENV, ""),
            # Validated by build_server; an empty --external-host turns the config value off.
            external_host=args.external_host if args.external_host is not None
            else str(ui_cfg.get("external_host", "")).strip())
        analyst_cap = int(agents_cfg.get("max_analyst_calls_per_day", 500))
        activity_entries = min(MAX_ENTRIES, max(MIN_ENTRIES, int(ui_cfg.get(
            "activity_entries", DEFAULT_MAX_ENTRIES))))
    except ValueError:
        return {"error": "[ui] port or activity_entries, or [agents] "
                         "max_analyst_calls_per_day, is not a number"}
    try:
        respond_settings = runtime.respond_settings(cp)
    except ValueError as exc:
        log.warning("%s; the console uses the [respond] defaults", str(exc)[:200])
        respond_settings = RespondSettings()
    budget_state, token_cap = data_dir / "budget_state.json", None
    try:
        budget = BudgetConfig.from_config(cp, str(base), str(data_dir))
        budget_state = Path(budget.state_file) if budget.state_file else budget_state
        token_cap = budget.max_tokens_per_day
    except ValueError:
        pass
    from agents.ship import sensor_label
    from agents.sightings import ConfigError as SightingsConfigError
    from agents.sightings import SightingsSettings

    from agents.enrich import from_config as geo_from_config
    from agents.internetdb import reader_from_config as internetdb_reader

    geo = geo_from_config(cp)
    if geo.attribution:
        import dataclasses

        settings = dataclasses.replace(settings, attribution=geo.attribution)
    try:
        sightings = SightingsSettings.from_config(cp)
    except SightingsConfigError as exc:
        log.warning("%s; the console uses the [sightings] defaults", str(exc)[:200])
        sightings = SightingsSettings()
    api = Api(ApiPaths(reports=reports, state=state, data=data_dir, detections=detections,
                       overlay=overlay, source_state=source_state,
                       log=Path(log_path) if log_path else None, budget_state=budget_state),
              settings=respond_settings,
              limits=ApiLimits(analyst_calls_per_day=analyst_cap,
                               frontend_tokens_per_day=token_cap,
                               activity_entries=activity_entries),
              # Decisions use what approve / reject / unblock use, re-read per decision so
              # a bad [respond] refuses them rather than acting on the defaults above.
              operator=operator,
              respond_settings=lambda: runtime.respond_settings(cp),
              connectors=lambda: runtime.respond_connectors(cp, state),
              sensor=sensor_label(cp), sightings=sightings, geo=geo,
              shodan=internetdb_reader(cp, state), indicators=indicators_from_config(cp))
    try:
        serve(settings, api)
    except (ValueError, OSError) as exc:
        # build_server refuses a non-loopback bind, a bad port, a bad external name or a
        # short token; the message names only settings, never the token.
        reason = getattr(exc, "strerror", None) or type(exc).__name__
        msg = str(exc)[:300] if isinstance(exc, ValueError) else \
            f"cannot listen on {settings.bind}:{settings.port} ({reason})"
        log.error("%s", msg)
        return {"error": msg}
    return {"status": "stopped"}


def _learned(args, cp: ConfigParser, base: Path, data_dir: Path, log_path: Optional[str]) -> dict:
    """``learned``: one action on the learned-reply store. Returns a summary with the plain
    text to print under ``text``."""
    from agents import learned
    from agents.budget import BudgetConfig
    from agents.hooks import learned_settings

    try:
        enabled, min_sessions, max_entries = learned_settings(cp)
        state_file = BudgetConfig.from_config(cp, str(base), str(data_dir)).state_file
    except ValueError as exc:
        return {"error": str(exc)[:200]}
    path = learned.path_beside(state_file)
    if path is None:
        return {"error": "[budget] state_file is empty: learned replies are kept in memory"}
    store = learned.LearnedStore(path, max_entries, min_sessions)
    if args.forget is not None:
        if not learned.valid_id(args.forget):
            return {"error": "an entry id is 16 lowercase hex characters"}
        removed = store.forget(args.forget)
        if removed is None:
            return {"error": f"cannot write {path}"}
        return {"text": f"{args.forget}: {'forgotten' if removed else 'not found'}",
                "forgotten": removed}
    if args.clear:
        count = store.clear()
        if count is None:
            return {"error": f"cannot write {path}"}
        return {"text": f"cleared {count} entries", "cleared": count}
    if args.list:
        text, summary = learned.list_text(store)
    elif args.candidates:
        text, summary = learned.candidates_text(store)
    else:
        text, summary = learned.stats_text(store, log_path)
    if store.read_error is not None:
        return {"error": f"cannot read {path}: {store.read_error[:100]}"}
    if not enabled:
        text = "[llm] learned_replies is off: the store is not used.\n" + text
    return {"text": text, **summary}


def _run(argv=None, rotation: Optional[dict] = None) -> dict:
    """Parse args and run the requested agents. Returns a summary dict (also used by tests).
    ``rotation``, when given, is filled with what ``log_rotation_status`` needs."""
    parser = argparse.ArgumentParser(prog="python -m agents", description=__doc__)
    parser.add_argument("command", choices=["triage", "respond", "digest", "tune", "detect",
                                            "ship", "run-all", "queue", "approve", "reject", "unblock",
                                            "enforce", "playbooks", "ui", "stix", "learned"])
    parser.add_argument("target", nargs="?", help="approval id for approve / reject; address "
                                                  "or network for unblock; address for enforce")
    parser.add_argument("--log", help="honeypot JSON-lines log (default: [honeypot] log_file)")
    parser.add_argument("--config", help="path to SSH/config.ini (read only)")
    parser.add_argument("--dry-run", action="store_true", help="print what would change, write nothing")
    parser.add_argument("--data-dir", default=None, help="front-end data dir (read only)")
    parser.add_argument("--reports-dir", default=None, help="default: <repo>/reports")
    parser.add_argument("--state-dir", default=None, help="default: <reports-dir>/state")
    parser.add_argument("--detections-dir", default=None, help="default: <repo>/detections")
    parser.add_argument("--overlay", default=None, help="default: [scenario] overlay or "
                                                        "<repo>/decoy/overlay.json")
    parser.add_argument("--model", default=None, help=f"analyst model (default {DEFAULT_ANALYST_MODEL})")
    parser.add_argument("--no-llm", action="store_true", help="never call a model")
    parser.add_argument("--git-commit", action="store_true",
                        help="tune: also commit the overlay (only when run from a checkout)")
    parser.add_argument("--history", action="store_true", help="tune: list overlay snapshots")
    parser.add_argument("--rollback", type=int, metavar="N",
                        help="tune: restore the overlay as it was before snapshot N")
    parser.add_argument("--max-llm-calls", type=int, default=None)
    parser.add_argument("--max-changes", type=int, default=None)
    parser.add_argument("--day", default=None, help="digest day YYYY-MM-DD (default today, UTC)")
    parser.add_argument("--by", default=None,
                        help="approve/reject/unblock/enforce: who decided (default: OS user); ui: the "
                             "operator label (default [ui] operator)")
    parser.add_argument("--bind", default=None, help="ui: address (default [ui] bind, 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="ui: port (default [ui] port, 8480)")
    parser.add_argument("--actions", action="store_true",
                        help="ui: allow approve/reject/unblock even when [ui] actions is off")
    parser.add_argument("--allow-non-loopback", action="store_true",
                        help="ui: allow a non-loopback bind (only inside a container whose port "
                             "is published on loopback)")
    parser.add_argument("--external-host", default=None, metavar="NAME",
                        help="ui: also accept this HTTPS name, served by a reverse proxy on the "
                             "same host (default [ui] external_host, none)")
    parser.add_argument("--list", action="store_true",
                        help="playbooks: list them; learned: list the entries")
    parser.add_argument("--stats", action="store_true",
                        help="learned: entry counts and commands per reply step")
    parser.add_argument("--candidates", action="store_true",
                        help="learned: commands that reach the model most and are not served")
    parser.add_argument("--forget", default=None, metavar="ID", help="learned: drop one entry")
    parser.add_argument("--clear", action="store_true", help="learned: drop every entry")
    parser.add_argument("--validate", action="store_true", help="playbooks: validate all files")
    parser.add_argument("--all", action="store_true", help="queue: include decided/expired items")
    parser.add_argument("--source-state", default=None, help="per-source state file "
                        "(default $WINNIE_SOURCE_STATE or <repo>/decoy/source_state.json)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    cp, base, cfg_error = _load_config(args.config)
    results: dict = {}
    if cfg_error:
        results["config_error"] = cfg_error
        log.error("%s; continuing with defaults", cfg_error)
    agents_cfg = cp["agents"] if "agents" in cp else {}
    data_dir = runtime.data_dir(cp, base, args.data_dir)
    reports = Path(args.reports_dir) if args.reports_dir else REPO_ROOT / "reports"
    state = Path(args.state_dir) if args.state_dir else reports / "state"
    detections = Path(args.detections_dir) if args.detections_dir else REPO_ROOT / "detections"
    overlay = runtime.overlay_path(cp, base, args.overlay)
    config_path = Path(args.config) if args.config else REPO_ROOT / "SSH" / "config.ini"
    log_path = args.log or (str(_resolve(base, cp["honeypot"].get("log_file", "ssh_log.log")))
                            if "honeypot" in cp else None)
    max_calls = args.max_llm_calls if args.max_llm_calls is not None else \
        int(agents_cfg.get("max_llm_calls_per_run", 20))
    max_changes = args.max_changes if args.max_changes is not None else \
        int(agents_cfg.get("max_tuner_changes_per_run", 3))

    respond_cfg = cp["respond"] if "respond" in cp else {}
    if rotation is not None:
        from agents.rotation import local_readers, parse_reader_list, required_readers

        try:       # an unreadable setting counts as enabled: the export then has to confirm
            export_on = cp.getboolean("connector.s3_events", "enabled", fallback=False)
        except ValueError:
            export_on = True
        rotation.update(log_path=log_path, state=state, readers=required_readers(
            parse_reader_list(agents_cfg.get("log_readers", "")), export_on),
            local=local_readers(export_on), config_error=cfg_error)

    def _settings():
        return runtime.respond_settings(cp)

    def _connectors():
        return runtime.respond_connectors(cp, state)

    if args.command == "ui":
        # Before anything that takes the run lock or builds a model: the console reads, and
        # its decisions take only the queue lock, as the approve / reject / unblock CLI does.
        from agents.source_state import source_state_path

        results["ui"] = _ui(args, cp, base, data_dir=data_dir, reports=reports, state=state,
                            detections=detections, overlay=overlay,
                            source_state=source_state_path(args.source_state),
                            log_path=log_path)
        return results
    if args.command == "learned":
        results["learned"] = _learned(args, cp, base, data_dir, log_path)
        return results
    if args.command == "playbooks":
        from agents.playbooks import load_playbooks, tier_of

        pbs, errors = load_playbooks()
        results["playbooks"] = [{"name": pb.name, "enabled": pb.enabled,
                                 "steps": [f"{st.action} ({tier_of(st)})" for st in pb.steps]}
                                for pb in pbs]
        results["errors"] = errors
        if args.validate and errors:
            results["playbooks_error"] = {"error": f"{len(errors)} invalid playbook(s)"}
        return results
    def _sensor() -> str:
        from agents.ship import sensor_label

        return sensor_label(cp)

    if args.command in ("queue", "approve", "reject", "unblock", "enforce"):
        try:
            settings = _settings()
        except ValueError as exc:
            results[args.command] = {"error": str(exc)[:200]}
            return results
    if args.command == "queue":
        from agents.respond import list_queue

        results["queue"] = list_queue(state, include_closed=args.all,
                                      expired_suppress_hours=settings.expired_suppress_hours)
        return results
    if args.command in ("approve", "reject"):
        from agents.respond import ApprovalError, approve, reject

        try:
            if args.command == "approve":
                results["approval"] = approve(
                    args.target or "", state, reports, detections, connectors=_connectors(),
                    by=args.by, blocklist_file=settings.blocklist_file,
                    blocklist_format=settings.blocklist_format,
                    blocklist_ttl_days=settings.blocklist_ttl_days,
                    expired_suppress_hours=settings.expired_suppress_hours,
                    never_act_on=settings.never_act_on,
                    track_before_enforce=settings.track_before_enforce, sensor=_sensor())
            else:
                results["approval"] = reject(args.target or "", state, by=args.by,
                                             suppress_hours=settings.reject_suppress_hours,
                                             reports_dir=reports)
        except ApprovalError as exc:
            results["approval"] = {"error": str(exc)}
        return results
    if args.command == "unblock":
        from agents.respond import unblock

        try:
            results["unblock"] = unblock(args.target or "", state, reports,
                                         blocklist_file=settings.blocklist_file,
                                         blocklist_format=settings.blocklist_format,
                                         ttl_days=settings.blocklist_ttl_days, by=args.by,
                                         track_before_enforce=settings.track_before_enforce,
                                         sensor=_sensor())
        except ValueError as exc:
            results["unblock"] = {"error": f"not an address or network: {str(exc)[:100]}"}
        return results
    if args.command == "enforce":
        from agents.respond import EnforceError, enforce

        try:
            results["enforce"] = enforce(
                args.target or "", state, reports, connectors=_connectors(), by=args.by,
                blocklist_file=settings.blocklist_file,
                blocklist_format=settings.blocklist_format,
                ttl_days=settings.blocklist_ttl_days, never_act_on=settings.never_act_on,
                track_before_enforce=settings.track_before_enforce, sensor=_sensor())
        except EnforceError as exc:
            results["enforce"] = {"error": str(exc)[:200]}
        return results

    def _ship_stage(always: bool) -> None:
        """Event export. ``always``: report a disabled export instead of skipping it."""
        from agents import ship

        try:
            settings = ship.ShipSettings.from_config(cp)
        except ship.ConfigError as exc:
            results["ship"] = {"error": f"[{ship.SECTION}]: {exc}"}
            log.error("%s", results["ship"]["error"])
            return
        if not settings.enabled:
            if always:
                results["ship"] = {"status": "disabled"}
            return
        try:
            res = ship.run_ship(settings, log_path, state,
                                seed=runtime.sensor_seed(cp, data_dir, create=False),
                                sensor=ship.sensor_label(cp), dry_run=args.dry_run)
        except Exception as exc:  # noqa: BLE001 - the export never stops the other stages
            res = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
            log.error("ship failed: %s", res["error"])
        if args.dry_run:
            print(json.dumps(res, indent=2, default=str))
        results["ship"] = res

    def _exchange_stage() -> None:
        """Tracked export out, sightings in. Each is off unless its connector is enabled; a
        failure is recorded and never stops the other stages."""
        from agents import sightings, tracked
        from agents.respond import tracked_target

        try:
            exp = tracked.ExportSettings.from_config(cp)
            if exp.enabled:
                try:
                    blocklist_file = _settings().blocklist_file
                except ValueError:
                    blocklist_file = None
                results["tracked_export"] = tracked.run_export(
                    exp, tracked_target(reports, blocklist_file), state, dry_run=args.dry_run)
        except tracked.ConfigError as exc:
            results["tracked_export"] = {"error": f"[{tracked.SECTION}]: {exc}"}
            log.error("%s", results["tracked_export"]["error"])
        except Exception as exc:  # noqa: BLE001 - the export never stops the other stages
            results["tracked_export"] = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
            log.error("tracked export failed: %s", results["tracked_export"]["error"])
        try:
            fetch = sightings.FetchSettings.from_config(cp)
            if fetch.enabled:
                results["sightings_fetch"] = sightings.run_fetch(
                    fetch, sightings.SightingsSettings.from_config(cp), state,
                    dry_run=args.dry_run)
        except sightings.ConfigError as exc:
            results["sightings_fetch"] = {"error": f"[{sightings.SECTION}]: {exc}"}
            log.error("%s", results["sightings_fetch"]["error"])
        except Exception as exc:  # noqa: BLE001 - the fetch never stops the other stages
            results["sightings_fetch"] = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
            log.error("sightings fetch failed: %s", results["sightings_fetch"]["error"])
        _internetdb_stage()
        _otx_stage()

    def _otx_stage() -> None:
        """Indicators to AlienVault OTX. Off unless ``[connector.otx]`` is enabled. run-all
        writes the candidates (it has the records); the submission runs where ``submit`` is
        on (on AWS the exporter only). A failure never stops a run."""
        from agents import otx
        from agents.respond import tracked_target
        from agents.triage import load_records

        try:
            settings = otx.OtxSettings.from_config(cp)
            if not settings.enabled:
                return
            out: dict = {}
            results["otx"] = out
            try:
                networks = _settings().networks() + otx.own_networks(cp)
                blocklist_file = _settings().blocklist_file
            except ValueError as exc:
                # Without a valid never_act_on list no address is safe to send.
                out["error"] = f"[respond]: {str(exc)[:160]}; nothing submitted"
                log.error("otx: %s", out["error"])
                return
            path = otx.candidates_path(settings, tracked_target(reports, blocklist_file).parent)
            if args.command == "run-all":
                out["candidates"] = otx.write_candidates(
                    settings, load_records(reports), networks, path,
                    uploads_dir=otx.quarantine_dir(cp, base, args.data_dir),
                    cap=otx.max_file_bytes(cp), dry_run=args.dry_run)
                if "error" in out["candidates"]:
                    out["error"] = out["candidates"]["error"]
            if settings.submit:
                out["submit"] = otx.run_submit(settings, path, state, networks,
                                               cli_dry_run=args.dry_run)
                if "error" in out["submit"] and "error" not in out:
                    out["error"] = out["submit"]["error"]
        except otx.ConfigError as exc:
            results["otx"] = {"error": f"[{otx.SECTION}]: {exc}"}
            log.error("%s", results["otx"]["error"])
        except Exception as exc:  # noqa: BLE001 - the submission never stops the other stages
            results["otx"] = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
            log.error("otx failed: %s", results["otx"]["error"])

    def _internetdb_stage() -> None:
        """What Shodan InternetDB knows about interesting sources, into a local file. Off
        unless ``[connector.internetdb]`` is enabled; a failure never stops a run."""
        from agents import internetdb
        from agents.triage import load_records

        try:
            settings = internetdb.InternetDbSettings.from_config(cp)
            if not settings.enabled:
                return
            try:
                networks = _settings().networks()
            except ValueError as exc:
                # Without a valid never_act_on list no address is safe to send.
                results["internetdb"] = {"error": f"[respond]: {str(exc)[:160]}; no lookups"}
                log.error("internetdb: %s", results["internetdb"]["error"])
                return
            if settings.delivered:
                results["internetdb"] = _internetdb_delivered(settings, networks)
                return
            results["internetdb"] = internetdb.run_lookup(
                settings, load_records(reports), networks, state, dry_run=args.dry_run)
        except internetdb.ConfigError as exc:
            results["internetdb"] = {"error": f"[{internetdb.SECTION}]: {exc}"}
            log.error("%s", results["internetdb"]["error"])
        except Exception as exc:  # noqa: BLE001 - the lookup never stops the other stages
            results["internetdb"] = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
            log.error("internetdb lookup failed: %s", results["internetdb"]["error"])

    def _internetdb_delivered(settings, networks) -> dict:
        """Delivered mode: run-all writes the wanted list (it has the records); the exchange,
        where enabled, puts it and gets the answers. Nothing here asks InternetDB."""
        from agents import internetdb_delivered as dl
        from agents.respond import tracked_target
        from agents.triage import load_records

        out: dict = {"mode": "delivered"}
        wanted = dl.wanted_path(settings, tracked_target(reports, _settings().blocklist_file)
                                .parent)
        if args.command == "run-all":
            out["wanted"] = dl.write_wanted(settings, load_records(reports), networks, wanted,
                                            dry_run=args.dry_run)
        try:
            exchange = dl.ExchangeSettings.from_config(cp)
        except dl.ConfigError as exc:
            out["exchange"] = {"error": f"[{dl.SECTION}]: {exc}"}
            log.error("%s", out["exchange"]["error"])
            return out
        if exchange.enabled and exchange.kind == "lookup":
            # This process asks InternetDB itself: on AWS the exporter, never the agents.
            from agents.internetdb_lookup_exchange import run_lookup_exchange

            out["exchange"] = run_lookup_exchange(exchange, settings, wanted,
                                                  settings.answers_path(state), state,
                                                  networks, dry_run=args.dry_run)
        elif exchange.enabled:
            out["exchange"] = dl.run_exchange(exchange, settings, wanted,
                                              settings.answers_path(state), state, networks,
                                              dry_run=args.dry_run)
        return out

    def _stix_stage(always: bool) -> None:
        """STIX 2.1 bundle into a local file. Off unless ``[stix]`` is enabled; nothing is
        sent. ``always``: report a disabled export instead of skipping it. A failure never
        stops the other stages."""
        from agents import otx, stix
        from agents.triage import load_records

        try:
            settings = stix.StixSettings.from_config(cp)
            if not settings.enabled:
                if always:
                    results["stix"] = {"status": "disabled"}
                return
            try:
                respond_settings = _settings()
                networks = respond_settings.networks() + otx.own_networks(cp)
            except ValueError as exc:
                # Without a valid never_act_on list no address is safe to write.
                failed = {"error": f"[respond]: {str(exc)[:160]}; nothing written"}
                results["stix"] = failed
                log.error("stix: %s", failed["error"])
                return
            results["stix"] = stix.run_export(
                settings, load_records(reports), reports, state, networks,
                uploads_dir=otx.quarantine_dir(cp, base, args.data_dir),
                upload_cap=otx.max_file_bytes(cp),
                ttl_days=respond_settings.blocklist_ttl_days, dry_run=args.dry_run)
        except stix.ConfigError as exc:
            failed = {"error": f"[{stix.SECTION}]: {exc}"}
            results["stix"] = failed
            log.error("%s", failed["error"])
        except Exception as exc:  # noqa: BLE001 - the export never stops the other stages
            failed = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
            results["stix"] = failed
            log.error("stix export failed: %s", failed["error"])

    def locked(fn) -> dict:
        """One writing run at a time: a second one exits with an error instead of
        interleaving read-modify-write updates of records, cursors and state."""
        import contextlib

        from agents.respond import RunLocked, run_lock

        with contextlib.ExitStack() as stack:
            try:
                stack.enter_context(run_lock(state))
            except RunLocked as exc:
                log.error("%s", exc)
                results["run_lock"] = {"error": str(exc)}
                return results
            except OSError as exc:
                # e.g. the default state directory on a read-only root filesystem
                msg = (f"cannot create or write the state directory {state} "
                       f"({exc.strerror or type(exc).__name__}); pass --state-dir with a "
                       "writable directory")
                log.error("%s", msg)
                results["run_lock"] = {"error": msg}
                return results
            return fn()

    if args.command == "stix":
        def _stix() -> dict:
            _stix_stage(always=True)
            return results

        return _stix() if args.dry_run else locked(_stix)

    if args.command == "tune" and (args.history or args.rollback is not None):
        from agents.tuner import history, rollback

        if args.history:
            results["history"] = history(state / "tuner")
            return results

        def _rollback() -> dict:
            results["rollback"] = rollback(overlay, state / "tuner", args.rollback)
            return results

        return locked(_rollback)

    def _stages() -> dict:
        llm = _llm(args, cp, state, max_calls)  # one cap shared by every stage of this run
        scenario = None
        try:
            scenario = _scenario(cp, data_dir, overlay)
            if scenario is not None and not args.dry_run:
                from scenarios.loader import write_honeytokens

                write_honeytokens(scenario, reports / "honeytokens.json")
        except Exception as exc:  # noqa: BLE001 - the other stages still run
            results["scenario_error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
            log.error("scenario load failed: %s", results["scenario_error"])

        def stage(name: str, fn) -> None:
            try:
                results[name] = fn()
            except Exception as exc:  # noqa: BLE001 - one failing agent must not stop the others
                results[name] = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
                log.error("%s failed: %s", name, results[name]["error"])

        geo_cache: list = []

        def _geo():
            # The [geoip] lookup, opened once for triage and the digest; off when unset.
            if not geo_cache:
                from agents.enrich import from_config as geo_from_config

                geo_cache.append(geo_from_config(cp))
            return geo_cache[0]

        def _shodan():
            # The exporter's local InternetDB file, read only; None when the feature is off.
            from agents.internetdb import reader_from_config

            return reader_from_config(cp, state)

        if args.command in ("triage", "run-all"):
            log_state, log_error = runtime.event_log_state(log_path)
            if log_state == "missing":
                # A new sensor: nothing has been logged yet.
                results["triage"] = {"status": "no_log",
                                     "note": f"no event log yet at {log_path}"}
                log.info("no event log yet at %s; nothing to triage", log_path)
            elif log_error:
                results["triage"] = {"error": log_error}
                log.error("%s", log_error)
            else:
                from agents.behaviours import from_config as rules_from_config
                from agents.indicators import from_config as indicators_from_config
                from agents.triage import run_triage

                from agents.triage import MAX_RECORDS_PER_RUN, RECORD_RETENTION_DAYS

                def _triage():
                    return run_triage(
                        log_path, reports, llm, max_llm_calls=max_calls, dry_run=args.dry_run,
                        state_dir=state,
                        max_records_per_run=int(agents_cfg.get("max_records_per_run",
                                                               MAX_RECORDS_PER_RUN)),
                        retention_days=float(agents_cfg.get("record_retention_days",
                                                            RECORD_RETENTION_DAYS)),
                        geo=_geo(), shodan=_shodan(),
                        indicators=indicators_from_config(cp), rules=rules_from_config(cp))

                stage("triage", _triage)
        if args.command in ("respond", "run-all") and \
                str(respond_cfg.get("enabled", "true")).lower() in ("1", "true", "yes", "on"):
            from agents.respond import run_respond
            from agents.source_state import source_state_path

            def _respond():
                seed = runtime.sensor_seed(cp, data_dir, create=False)
                res = run_respond(
                    reports, state, detections, source_state_path(args.source_state),
                    connectors=None if args.dry_run else _connectors(),
                    scenario_name=scenario.scenario.name if scenario is not None else None,
                    seed=seed, dry_run=args.dry_run, settings=_settings(), sensor=_sensor())
                if args.dry_run:
                    print(json.dumps(res, indent=2, default=str))
                return {"runs": len(res["runs"]), "skipped": len(res["skipped"]),
                        "playbook_errors": res["playbook_errors"],
                        "source_state_snapshot": res["source_state_snapshot"],
                        "proxy_suspected": res["proxy_suspected"],
                        "suppressed_notices": res["suppressed_notices"],
                        "suppressed_pending": res["suppressed_pending"],
                        "retention": res["retention"], "size_alarm": res["size_alarm"]}

            stage("respond", _respond)
        if args.command in ("digest", "run-all"):
            from agents.triage import digest

            def _digest():
                text = digest(reports, day=args.day, dry_run=args.dry_run, geo=_geo())
                if args.dry_run or args.command == "digest":
                    print(text)
                return "printed" if args.dry_run else "written"

            stage("digest", _digest)
        if args.command in ("tune", "run-all"):
            from agents.tuner import tune

            def _tune():
                res = tune(overlay, reports, state_dir=state / "tuner", llm=llm, dry_run=args.dry_run,
                           max_changes=max_changes, scenario=scenario, config_path=config_path,
                           git_commit=args.git_commit)
                if args.dry_run:
                    print(res.diff or "(no changes)")
                return {"changes": [c.describe() for c in res.changes], "rejected": res.rejected,
                        "snapshot": res.snapshot, "commit": res.commit, "errors": res.errors}

            stage("tune", _tune)
        if args.command == "run-all":
            _stix_stage(always=False)
        if args.command in ("detect", "run-all"):
            from agents.detect import run_detect

            stage("detect", lambda: run_detect(
                reports, detections, llm, dry_run=args.dry_run,
                expiry_days=agents_cfg.get("blocklist_expiry_days", 14),
                access_expiry_days=agents_cfg.get("blocklist_access_expiry_days", 30)))
        if args.command == "run-all":
            _ship_stage(always=False)
            _exchange_stage()

        return results

    if args.command == "ship":
        def _ship() -> dict:
            _ship_stage(always=True)
            _exchange_stage()
            return results

        return _ship() if args.dry_run else locked(_ship)
    if not args.dry_run:
        return locked(_stages)
    return _stages()


def run(argv=None) -> dict:
    """Run one command; triage, ship and run-all also say whether the event log may be
    rotated now (``log_rotation``) and log a warning line when it may not."""
    args_list = list(sys.argv[1:] if argv is None else argv)
    context: dict = {}
    results = _run(args_list, context)
    # triage, ship and run-all are the commands whose results carry these keys.
    if ("triage" in results or "ship" in results) and "--dry-run" not in args_list \
            and "run_lock" not in results and context:
        status = log_rotation_status(results, **context)
        results["log_rotation"] = status
        if not status["safe"]:
            log.warning("event log not safe to rotate yet: %s", "; ".join(status["pending"]))
    return results


def log_rotation_status(results: dict, *, log_path, state, readers, local=None,
                        config_error=None) -> dict:
    """Whether rotating the event log now loses nothing: every required reader (triage, the
    export when enabled, and any reader listed in ``[agents] log_readers``) has confirmed
    the log's current generation up to its current end. The keys ``safe`` and ``pending``
    are the contract; ``scope``, ``log`` and ``readers`` carry the evidence (see
    ``agents.rotation``). A configuration error never yields ``safe``."""
    from agents.rotation import rotation_status

    return rotation_status(results, log_path, state, readers, local, config_error)


def main(argv=None) -> int:
    results = run(argv)
    learned = results.get("learned")
    if isinstance(learned, dict) and "text" in learned:
        print(learned.pop("text"))
    print(json.dumps(results, indent=2, default=str), file=sys.stderr)
    failed = any(isinstance(v, dict) and "error" in v for v in results.values())
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
