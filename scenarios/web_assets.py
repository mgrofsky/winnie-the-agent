"""Generated content for HTTP decoy assets (``services.http.assets`` without a ``body``).

    asset_text(asset, service, app) -> str     what the listener serves for one asset
    scenario_asset_texts(loaded) -> [(path, text)]   every asset's text, for the checker

A bundle is a minified webpack chunk holding an API client table, a source map carries the
TypeScript of that client in ``sourcesContent``, and a runtime config is a JSON object (or a
``window.__ENV__`` assignment when the path ends in ``.js``) with ``apiBase``, feature flags
and the endpoint table. Every advertised route appears in each. The text depends only on the
scenario, so the listener builds it once per scenario; ``{marker:NAME}`` in a scenario's own
body is filled in per source by the listener.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Optional

PARAM_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]{0,63})\}")
JS_ARGS = "etnrioasuc"
VERBS = {"POST": "create", "PUT": "update", "PATCH": "patch", "DELETE": "delete"}


def _hash(*parts: str) -> bytes:
    return hashlib.sha256("|".join(parts).encode()).digest()


def _words(path: str) -> list[str]:
    out = []
    for seg in path.split("/"):
        if not seg or PARAM_RE.fullmatch(seg) or re.fullmatch(r"v\d+|api", seg):
            continue
        out += [w for w in re.split(r"[^A-Za-z0-9]+", seg) if w]
    return out or ["root"]


def endpoint_name(method: str, path: str) -> str:
    """A client method name such as ``listUsers``, ``getUser`` or ``createNote``."""
    words = _words(path)
    ends_in_param = bool(PARAM_RE.fullmatch(path.rstrip("/").rsplit("/", 1)[-1]))
    if method == "GET":
        verb = "get" if ends_in_param else "list"
    else:
        verb = VERBS.get(method, method.lower())
    if ends_in_param and words[-1].endswith("s") and len(words[-1]) > 3:
        words[-1] = words[-1][:-1]
    return verb + "".join(w[:1].upper() + w[1:] for w in words)


def endpoints(asset, service) -> list[tuple[str, str, str]]:
    """(name, method, path) for every route at each advertised path, names made unique."""
    out, seen = [], set()
    for path in asset.advertises:
        for route in service.routes:
            if route.path != path:
                continue
            name = base = endpoint_name(route.method, path)
            n = 2
            while name in seen:
                name, n = f"{base}{n}", n + 1
            seen.add(name)
            out.append((name, route.method, path))
    return out


def _js_url(path: str) -> tuple[str, list[str]]:
    """A JavaScript expression for the path, with one argument per path parameter."""
    parts, args, pos = [], [], 0
    for m in PARAM_RE.finditer(path):
        arg = JS_ARGS[len(args) % len(JS_ARGS)]
        args.append(arg)
        parts.append(json.dumps(path[pos:m.start()]))
        parts.append(f"encodeURIComponent({arg})")
        pos = m.end()
    if pos < len(path) or not parts:
        parts.append(json.dumps(path[pos:]))
    return "+".join(parts), args


def _ts_url(path: str) -> tuple[str, list[str]]:
    params = PARAM_RE.findall(path)
    return "`" + PARAM_RE.sub(lambda m: "${encodeURIComponent(" + m.group(1) + ")}", path) + "`", \
        params


def _map_for(asset, service) -> Optional[str]:
    for other in service.assets:
        if other.kind == "source_map" and other.path == asset.path + ".map":
            return other.path.rsplit("/", 1)[-1]
    return None


def bundle(asset, service, app: str) -> str:
    h = _hash(asset.path, app)
    chunk, module, dep = 100 + h[0] * 3, 1000 + int.from_bytes(h[1:3], "big") % 8999, \
        1000 + int.from_bytes(h[3:5], "big") % 8999
    table = []
    for name, method, path in endpoints(asset, service):
        url, args = _js_url(path)
        if method in ("POST", "PUT", "PATCH"):
            body_arg = JS_ARGS[len(args) % len(JS_ARGS)]
            table.append(f'{name}:function({",".join(args + [body_arg])}){{return s("{method}",'
                         f"{url},{body_arg})}}")
        else:
            table.append(f'{name}:function({",".join(args)}){{return s("{method}",{url})}}')
    text = (f'"use strict";(self.webpackChunk{app}=self.webpackChunk{app}||[]).push([[{chunk}],'
            f"{{{module}:function(e,t,n){{n.d(t,{{Z:function(){{return l}}}});var r=n({dep}),"
            "a=(window.__ENV__||{}).apiOrigin||window.location.origin,"
            "s=function(e,t,n){return r.Z.request({baseURL:a,method:e,url:t,data:n,"
            "withCredentials:!0})},"
            f"l={{{','.join(table)}}}}}}}]);\n")
    map_name = _map_for(asset, service)
    if map_name:
        text += f"//# sourceMappingURL={map_name}\n"
    return text


def source_map(asset, service, app: str) -> str:
    entries = []
    for name, method, path in endpoints(asset, service):
        url, params = _ts_url(path)
        args = [f"{p}: string" for p in params]
        call = f"http.request({{ method: \"{method}\", url: {url}"
        if method in ("POST", "PUT", "PATCH"):
            args.append("body: unknown")
            call += ", data: body"
        entries.append(f"  {name}: ({', '.join(args)}) => {call} }}),")
    client = ('import axios from "axios";\n\n'
              "const env = (window as any).__ENV__ ?? {};\n\n"
              "export const http = axios.create({\n"
              "  baseURL: env.apiOrigin ?? window.location.origin,\n  withCredentials: true,\n"
              "  timeout: 15000,\n});\n")
    api = ('import { http } from "./client";\n\nexport const api = {\n' + "\n".join(entries)
           + "\n};\n\nexport default api;\n")
    bundle_file = asset.path.rsplit("/", 1)[-1]
    bundle_file = bundle_file[:-4] if bundle_file.endswith(".map") else "main.js"
    lines = max(1, len(entries))
    mappings = ";".join(["AAAA,SAASA,EAAE,CAAC"] + ["AACA,MAAMC,EAAE"] * lines)
    doc = {"version": 3, "file": bundle_file, "mappings": mappings,
           "sources": [f"webpack://{app}/./src/api/client.ts",
                       f"webpack://{app}/./src/api/index.ts"],
           "sourcesContent": [client, api], "names": ["http", "api", "request"],
           "sourceRoot": ""}
    return json.dumps(doc, separators=(",", ":"))


def runtime_config(asset, service, app: str) -> str:
    h = _hash(asset.path, app, "config")
    table = {name: path for name, _method, path in endpoints(asset, service)}
    doc = {"apiBase": service.api_prefix or "", "environment": "production",
           "release": h[:5].hex(), "features": {"newDashboard": True, "bulkExport": h[5] % 2 == 0,
                                               "sso": True, "betaReports": False},
           "endpoints": table}
    if asset.path.endswith(".js"):
        return "window.__ENV__ = " + json.dumps(doc, indent=2) + ";\n"
    return json.dumps(doc, indent=2) + "\n"


def asset_text(asset, service, app: str = "app") -> str:
    """The scenario's own body, or generated content for the asset's kind."""
    if asset.body is not None:
        return asset.body
    if asset.kind == "bundle":
        return bundle(asset, service, app)
    if asset.kind == "source_map":
        return source_map(asset, service, app)
    return runtime_config(asset, service, app)


def app_name(domain: str) -> str:
    """The webpack app name: the first label of the scenario's domain, letters only."""
    label = re.sub(r"[^a-z]", "", (domain or "").split(".", 1)[0].lower())
    return label[:32] or "app"


def scenario_asset_texts(loaded) -> list[tuple[str, str]]:
    sc = loaded.scenario
    svc = sc.services.http
    if svc is None:
        return []
    app = app_name(sc.identity.domain)
    return [(a.path, asset_text(a, svc, app)) for a in svc.assets]
