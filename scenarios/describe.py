"""Human-readable summaries of scenario packs.

Backs ``python -m listeners --list-scenarios`` and ``--describe <name>``:

    list_text() -> str                         one line per shipped scenario
    describe(name, seed="describe") -> str     what the scenario exposes for that seed

Identity, hosts, people and credentials come from ``{{...}}`` templates expanded from the
seed, so the output is specific to one sensor; ``describe`` lists every expanded template.
Honeytoken *values* are never printed, only their names, kinds and where they are planted.
FTP file contents, S3 object bodies and HTTP bodies are not printed either (they may embed
honeytokens).
"""

from __future__ import annotations

from typing import Optional

from .loader import list_scenarios, load_scenario

SERVICE_ORDER = ("sip", "ftp", "telnet", "postgres", "mysql", "mssql", "redis", "smtp",
                 "http", "mllp", "s3")


def _policy(p) -> str:
    if p.accept == "after_n":
        return f"after_n {p.after_n_min}-{p.after_n_max}"
    return p.accept


def list_text(scenarios_dir: Optional[str] = None) -> str:
    lines = []
    for name in list_scenarios(scenarios_dir):
        try:
            loaded = load_scenario(name, seed="describe", scenarios_dir=scenarios_dir)
        except Exception as exc:  # show broken packs rather than hiding them
            lines.append(f"{name:<16} INVALID: {exc.__class__.__name__}")
            continue
        sc = loaded.scenario
        enabled = [s for s in SERVICE_ORDER
                   if getattr(sc.services, s) is not None and getattr(sc.services, s).enabled]
        lines.append(f"{name:<16} {sc.title}  [ssh, {', '.join(enabled)}]")
    return "\n".join(lines)


def describe(name: str, seed: str = "describe", scenarios_dir: Optional[str] = None,
             seed_note: Optional[str] = None) -> str:
    loaded = load_scenario(name, seed=seed, scenarios_dir=scenarios_dir)
    sc = loaded.scenario
    ident = sc.identity
    out: list[str] = []
    w = out.append

    w(f"Scenario: {sc.name} - {sc.title}")
    w(" ".join(sc.description.split()))
    w("")
    if loaded.bait:
        w("Values below are specific to this sensor: they are derived from its seed, and a "
          "sensor with another seed shows a different organisation, hosts, people and "
          "credentials.")
        if seed_note:
            w(seed_note)
        w("")
    w("Identity")
    w(f"  organisation: {ident.org_name}")
    w(f"  host:         {ident.hostname}.{ident.domain}")
    w(f"  internal IPs: {', '.join(ident.internal_ips)}")
    w(f"  OS:           {ident.os_pretty_name} ({ident.timezone})")
    if ident.users:
        w(f"  local users:  {', '.join(u.name for u in ident.users)}")
    if ident.lures:
        w(f"  lure files:   {len(ident.lures)} ({', '.join(ident.lures[:4])}"
          f"{', ...' if len(ident.lures) > 4 else ''})")
    w("")
    w("SSH / Telnet persona")
    w(f"  accounts: {', '.join(a.username for a in sc.ssh.accounts) or '(none)'}")
    w(f"  persona prompt: {len(sc.ssh.persona_prompt)} chars")

    for svc_name in SERVICE_ORDER:
        svc = getattr(sc.services, svc_name)
        if svc is None:
            continue
        w("")
        state = "enabled" if svc.enabled else "disabled"
        w(f"Service {svc_name}: {state}, port {svc.port}")
        if svc.banner:
            w(f"  banner:  {svc.banner}")
        if svc.version:
            w(f"  version: {svc.version}")
        w(f"  login policy: {_policy(loaded.policy_for(svc_name))}")
        if svc_name == "sip":
            w(f"  realm: {svc.realm}; Server: {svc.server_header}; "
              f"transports: {'udp ' if svc.udp else ''}{'tcp' if svc.tcp else ''}".rstrip())
            if svc.extension_ranges:
                w(f"  extension ranges: {', '.join(svc.extension_ranges)}")
            for e in svc.extensions:
                w(f"  extension {e.extension}" + (f" ({e.display_name})" if e.display_name else ""))
            for h in svc.dial_plan_hints:
                w(f"  dial plan: {h}")
        else:
            users = [a.username for a in svc.accounts]
            if users:
                w(f"  accounts: {', '.join(users)}")
        if svc_name in ("postgres", "mysql", "mssql"):
            for db in svc.databases:
                w(f"  database {db.name} (schema {db.schema_name})")
                for t in db.tables:
                    _, rows = loaded.table_rows(db.name, t.name)
                    cols = ", ".join(c.name for c in t.columns)
                    w(f"    table {t.name}: {len(rows)} rows [{cols}]")
        if svc_name == "ftp":
            for f in svc.files:
                size = f.size if f.size is not None else len((f.content or "").encode())
                w(f"  file {f.path} ({size} bytes)")
        if svc_name == "redis":
            for k in svc.keys:
                w(f"  key {k.key} ({k.type})")
        if svc_name == "mllp":
            w(f"  sending facility: {svc.sending_facility}")
        if svc_name == "s3":
            w(f"  region: {svc.region}; downloads capped at {svc.get_max_bytes} bytes")
            for b in svc.buckets:
                flags = [f for f in ("public_list", "public_read") if getattr(b, f)]
                keys = sum(o.count for o in b.objects)
                w(f"  bucket {b.name} ({keys} keys{', ' + ', '.join(flags) if flags else ''})")
        if svc_name == "http":
            w(f"  Server: {svc.server_header}")
            w(f"  login: {svc.login_path} \"{svc.login_title}\"")
            if svc.branding:
                w(f"  branding: {svc.branding}")
            for p in svc.pages:
                w(f"  page {p.path} \"{p.title}\"" + ("" if p.requires_login else " (public)"))
            if svc.api_prefix:
                w(f"  API prefix: {svc.api_prefix} (API key header {svc.api_key_header}; "
                  f"LLM for unknown routes: {'yes' if svc.llm_unknown_api_routes else 'no'})")
            w(f"  LLM for unknown paths: {'yes' if svc.llm_unknown_paths else 'no'}")
            for r in svc.routes:
                if r.list_from:
                    src = f"list of {r.list_from}"
                elif r.item_from:
                    src = f"item of {r.item_from} by {r.item_key}"
                elif r.json_body is not None:
                    src = "canned JSON"
                else:
                    src = "empty"
                w(f"  route {r.method:<6} {r.path}  auth={r.auth} status={r.status} ({src})")
            if svc.openapi_path:
                n_paths = len((svc.openapi or {}).get("paths", {}))
                w(f"  OpenAPI document: {svc.openapi_path} ({n_paths} paths)")

    if loaded.bait:
        w("")
        w("Per-sensor bait (template = value for this seed)")
        for template, value in loaded.bait.items():
            w(f"  {template} = {value}")

    w("")
    w("Honeytokens (values are written to reports/honeytokens.json, never printed here)")
    for t in loaded.honeytokens.values():
        w(f"  {t.name} [{t.kind}]")
        for loc in t.planted_in:
            w(f"    planted in: {loc}")
    return "\n".join(out)
