"""CLI: python -m agents {triage,respond,digest,tune,detect,ship,run-all,queue,approve,reject,unblock,
enforce,playbooks,ui}.

Directories:
- ``--data-dir``: the front-ends' data directory (log, sensor seed). Only read here.
- ``--reports-dir``: triage records, digests, tuner records, honeytoken registry.
- ``--state-dir``: cursor, tuner snapshots and state, analyst call counter
  (default ``<reports-dir>/state``).
- ``--overlay``: the tuner-owned overlay file.

``ship`` sends the event log to S3 when ``[connector.s3_events]`` is enabled, the tracked
export when ``[connector.tracked_export]`` is, and fetches sightings when
``[connector.sightings]`` is; ``run-all`` runs it as its last step.

``enforce <address>`` moves one tracked blocklist entry to enforced (``[respond]
track_before_enforce``).

``ui`` serves the operator console on loopback (``[ui]``; ``--bind``, ``--port``,
``--actions``, ``--by``, ``--external-host``). It reads the same directories, takes no run
lock and never calls a model. The sign-in token comes from ``WINNIE_UI_TOKEN`` or is
generated at start.
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
            cp.read(target)
        except (ConfigParserError, UnicodeDecodeError) as exc:
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


UI_TOKEN_ENV = "WINNIE_UI_TOKEN"


def _ui(args, cp: ConfigParser, base: Path, *, data_dir: Path, reports: Path, state: Path,
        detections: Path, overlay: Path, source_state: Path, log_path: Optional[str]) -> dict:
    """Serve the operator console until interrupted. The token is never read from the
    config file: ``WINNIE_UI_TOKEN`` or a fresh one (``serve`` logs the sign-in link)."""
    from agents.budget import BudgetConfig
    from agents.respond import RespondSettings
    from agents.ui.activity import DEFAULT_MAX_ENTRIES, MAX_ENTRIES, MIN_ENTRIES
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
              sensor=sensor_label(cp), sightings=sightings)
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


def _run(argv=None) -> dict:
    """Parse args and run the requested agents. Returns a summary dict (also used by tests)."""
    parser = argparse.ArgumentParser(prog="python -m agents", description=__doc__)
    parser.add_argument("command", choices=["triage", "respond", "digest", "tune", "detect",
                                            "ship", "run-all", "queue", "approve", "reject", "unblock",
                                            "enforce", "playbooks", "ui"])
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
    parser.add_argument("--list", action="store_true", help="playbooks: list them")
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
                from agents.triage import run_triage

                from agents.triage import MAX_RECORDS_PER_RUN, RECORD_RETENTION_DAYS

                def _triage():
                    return run_triage(
                        log_path, reports, llm, max_llm_calls=max_calls, dry_run=args.dry_run,
                        state_dir=state,
                        max_records_per_run=int(agents_cfg.get("max_records_per_run",
                                                               MAX_RECORDS_PER_RUN)),
                        retention_days=float(agents_cfg.get("record_retention_days",
                                                            RECORD_RETENTION_DAYS)))

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
                text = digest(reports, day=args.day, dry_run=args.dry_run)
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
    results = _run(args_list)
    # triage, ship and run-all are the commands whose results carry these keys.
    if ("triage" in results or "ship" in results) and "--dry-run" not in args_list \
            and "run_lock" not in results:
        status = log_rotation_status(results)
        results["log_rotation"] = status
        if not status["safe"]:
            log.warning("event log not safe to rotate yet: %s", "; ".join(status["pending"]))
    return results


def log_rotation_status(results: dict) -> dict:
    """Whether rotating the event log now loses nothing: triage has no unfinished or
    deferred items left in it and the export has shipped everything."""
    pending = []
    triage = results.get("triage")
    if isinstance(triage, dict) and "error" not in triage:
        if triage.get("pending_bytes", 0) > 0 or triage.get("deferred"):
            pending.append(f"triage: {triage.get('pending_bytes', 0)} bytes of the log hold "
                           f"unfinished or deferred items ({len(triage.get('deferred') or [])} "
                           "deferred)")
    elif isinstance(triage, dict):
        pending.append("triage: failed, nothing was processed")
    ship = results.get("ship")
    if isinstance(ship, dict) and (ship.get("more_pending") or "error" in ship):
        pending.append("ship: events not exported yet")
    return {"safe": not pending, "pending": pending}


def main(argv=None) -> int:
    results = run(argv)
    print(json.dumps(results, indent=2, default=str), file=sys.stderr)
    failed = any(isinstance(v, dict) and "error" in v for v in results.values())
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
