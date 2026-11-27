# Web deception

The HTTP trap can hold an automated visitor's attention the way a real web app does, and
record what it does in order. A scenario adds decoy front-end assets that show the API's
routes, lures on the routes worth finding, per-source values that show when something
served to one visitor comes back, and safe account flows. Each request event carries
evidence of where the visitor learned the route it called. Triage keeps the campaign's
request sequence, matches it against indicator lists and behaviour rules, and shows the
result on the record and in the console.

The parts:

- **Decoy assets**: a JavaScript bundle, its source map, runtime config (`/env.js`,
  `/assets/config.json`) and static files, served with their own content type and cache
  headers. Their text is generated from the routes they advertise, or written in the
  scenario.
- **Lures and discovery**: every asset and the OpenAPI document has a lure ID. A source
  that fetches one is recorded as shown its routes, and its later requests to those
  routes carry `discovered_via` (the lure ID) and `discovered_age` (seconds since).
  A route marked `hidden` is left out of the generated OpenAPI document, so a visitor
  learns of it only from an asset or a document the scenario writes.
- **Per-source markers**: `{marker:NAME}` in an asset or route body becomes a value
  derived for that source. When the value comes back in a later request, from the same
  source or another one, the event names the marker.
- **Safe flows**: username checks, password recovery, password reset and account
  activation, answered with fixed local replies.
- **Per-request evidence**: `seq` (the source's request number), the lure, discovery,
  marker, flow and object-ID count on each HTTP `command` event.
- **Request sequence in triage**: the first 100 requests of each HTTP campaign, in order,
  with the `seq` and time to find each raw line.
- **Indicator lists**: user agents, paths, queries and addresses, each with its sources and
  a confidence, in data files.
- **Behaviour rules**: five generic patterns over the request sequence, with thresholds in
  data files.

All of it is general purpose: any scenario can use the assets, lures, markers and flows,
and the indicator and behaviour files are the operator's to change. The shipped indicator
file carries the user agents and requests that public reports on the ARTEX agentic
framework describe, as one named use of the indicator list.

## Scenario keys

The keys are optional and belong in `[services.http]`; the full list is in
[scenarios.md](scenarios.md#services).

| Key | Where | What it does |
|---|---|---|
| `[[...assets]]` | service | Up to 30 assets: `path`, `kind` (`bundle`, `source_map`, `runtime_config`, `static`), `lure`, `advertises` (route paths) and an optional `body`. Without a `body` the content is generated from `advertises`; a `static` asset needs a `body`. |
| `openapi_advertises` | service | Routes the OpenAPI document counts as showing. With it set, fetching the document records discovery under `openapi_lure` (default `openapi`). |
| `openapi_aliases` | service | Extra paths that serve the OpenAPI document, such as `/swagger.json` and `/v3/api-docs`. |
| `lure` | route | The route's lure ID, logged as `lure_id`. An item route with a lure also logs `object_id_count`. |
| `hidden` | route | Left out of the generated OpenAPI document and the model's prompt; the route still answers. A scenario that writes its own `openapi` table is served as written. |
| `flow` | route | `username_check`, `recovery_request`, `recovery_reset` or `activation`. |
| `{marker:NAME}` | asset `body`, route `json_body` | A per-source value; up to 16 names per scenario. |

`dev_portal` uses all of them. Trimmed from `scenarios/dev_portal/scenario.toml`:

```toml
[services.http]
api_key_header = "X-Api-Key"
openapi_path = "/api/openapi.json"
openapi_aliases = ["/swagger.json", "/v3/api-docs"]
openapi_lure = "openapi"
openapi_advertises = [
    "/api/v1/projects",
    "/api/v1/projects/{id}",
    "/api/v1/auth/username",
    "/api/v1/auth/forgot-password",
    "/api/internal/admin/settings",
    "/api/internal/export/{dataset}",
]

[[services.http.routes]]
method = "GET"
path = "/api/v1/users/{id}"
auth = "none"
item_from = "workspace.users"
item_key = "id"
lure = "user-item"
hidden = true

[[services.http.routes]]
method = "POST"
path = "/api/v1/auth/forgot-password"
auth = "none"
status = 202
flow = "recovery_request"
lure = "recovery"

[[services.http.routes]]
method = "GET"
path = "/api/internal/export/{dataset}"
auth = "none"
lure = "export"
hidden = true
[services.http.routes.json_body]
dataset = "{dataset}"
job_id = "{marker:export_job_id}"
status = "queued"
# ...

[[services.http.assets]]
path = "/static/js/main.{{hex:8:bundle}}.js"
kind = "bundle"
lure = "main-bundle"
advertises = [
    "/api/v1/projects",
    "/api/v1/projects/{id}",
    "/api/v1/users/{id}",
    "/api/v1/auth/username",
    "/api/v1/auth/forgot-password",
    "/api/v1/auth/reset-password",
    "/api/internal/admin/settings",
    "/api/internal/export/{dataset}",
]

[[services.http.assets]]
path = "/env.js"
kind = "runtime_config"
lure = "env-js"
advertises = ["/api/v1/projects", "/api/internal/export/{dataset}"]
body = '''
window.__ENV__ = {
  "apiBase": "/api",
  "environment": "production",
  "release": "{marker:build}",
  "oauthClientId": "{marker:client_id}",
  "publicApiKey": "{marker:public_api_key}",
  "exportsPath": "/internal/export",
  "features": { "bulkExport": true, "sso": false, "betaReports": false }
};
'''
```

`/api/v1/users/{id}` appears only in the bundle and the source map, so a request to it
shows the visitor read one of them. A marker's shape follows its name: a short hex hash
for a build, commit or release name, a UUID for an `*_id` name, a 32-character key for a
key or token name, otherwise 20 lowercase letters and digits.

Select the scenario with `[scenario] active = dev_portal` in `config.ini` (see
[scenarios.md](scenarios.md#selecting-a-scenario)) and check a pack of your own with
`uv run python -m scenarios.check <name>`.

## A visitor, request by request

These lines are listener output for one visitor to `dev_portal` with the user agent
`norma/0.4`. The visitor loads the page, reads the bundle, `/env.js` and the OpenAPI
document, calls two internal routes, walks twelve user IDs, tries the account flows, and
then sends the API key `/env.js` gave it. One full line:

```json
{"timestamp": "2026-11-27T18:45:06.042+00:00", "level": "INFO", "task_name": "http-077db2c2-9ee2-4783-9e61-57593c610999", "src_ip": "198.51.100.77", "src_port": 52055, "dst_ip": "198.51.100.10", "dst_port": 52053, "message": "GET /static/js/main.366146e5.js", "sensor_name": "e2e", "sensor_protocol": "http", "event": "command", "transport": "tcp", "client": "norma/0.4", "data": {"method": "GET", "path": "/static/js/main.366146e5.js", "query": "", "status": 200, "host": "web01", "route": "asset", "seq": 2, "req": 1, "lure_id": "main-bundle", "resp_type": "application/javascript", "resp_bytes": 1002}}
```

Then a selection, trimmed: connection and close lines and the requests with `seq` 1, 3, 6,
8 to 17 and 20 are left out, and so are the keys `level`, `task_name`, ports,
`dst_ip`, `message`, `sensor_name`, `sensor_protocol`, `transport`, `host`, `req`,
`query`, `resp_type`, `resp_bytes`, `content_type` and `body_bytes`:

```json
{"timestamp": "2026-11-27T18:45:06.043+00:00", "src_ip": "198.51.100.77", "event": "command", "client": "norma/0.4", "data": {"method": "GET", "path": "/api/openapi.json", "status": 200, "route": "openapi", "seq": 4, "lure_id": "openapi"}}
{"timestamp": "2026-11-27T18:45:06.043+00:00", "src_ip": "198.51.100.77", "event": "command", "client": "norma/0.4", "data": {"method": "GET", "path": "/api/internal/admin/settings", "status": 401, "route": "/api/internal/admin/settings", "seq": 5, "lure_id": "admin-settings", "discovered_via": "main-bundle", "discovered_age": 0}}
{"timestamp": "2026-11-27T18:45:06.045+00:00", "src_ip": "198.51.100.77", "event": "command", "client": "norma/0.4", "data": {"method": "GET", "path": "/api/v1/users/1", "status": 200, "route": "/api/v1/users/{id}", "seq": 7, "lure_id": "user-item", "discovered_via": "main-bundle", "discovered_age": 0, "object_id_count": 1}}
{"timestamp": "2026-11-27T18:45:06.053+00:00", "src_ip": "198.51.100.77", "event": "command", "client": "norma/0.4", "data": {"method": "GET", "path": "/api/v1/users/12", "status": 200, "route": "/api/v1/users/{id}", "seq": 18, "lure_id": "user-item", "discovered_via": "main-bundle", "discovered_age": 0, "object_id_count": 12}}
{"timestamp": "2026-11-27T18:45:06.053+00:00", "src_ip": "198.51.100.77", "event": "command", "client": "norma/0.4", "data": {"method": "POST", "path": "/api/v1/auth/username", "status": 200, "route": "/api/v1/auth/username", "seq": 19, "lure_id": "username-check", "discovered_via": "main-bundle", "discovered_age": 0, "flow": "username_check", "flow_step": "exists", "body": "{\"username\": \"ops@dornbank-app.example\"}"}}
{"timestamp": "2026-11-27T18:45:06.054+00:00", "src_ip": "198.51.100.77", "event": "command", "client": "norma/0.4", "data": {"method": "POST", "path": "/api/v1/auth/reset-password", "status": 400, "route": "/api/v1/auth/reset-password", "seq": 21, "lure_id": "recovery-reset", "discovered_via": "main-bundle", "discovered_age": 0, "flow": "recovery_reset", "flow_step": "token_rejected", "body": "{\"token\": \"stale-link\", \"password\": \"pw\"}"}}
{"timestamp": "2026-11-27T18:45:06.055+00:00", "src_ip": "198.51.100.77", "event": "command", "client": "norma/0.4", "data": {"method": "GET", "path": "/api/v1/auth/activate/stale-link", "status": 400, "route": "/api/v1/auth/activate/{token}", "seq": 22, "lure_id": "activation", "flow": "activation", "flow_step": "token_rejected"}}
{"timestamp": "2026-11-27T18:45:06.055+00:00", "src_ip": "198.51.100.77", "event": "auth_attempt", "username": "<api_key>", "password": "MJjdqR3s225DkWsivDDzz8Lse61MqBBY", "client": "norma/0.4", "success": false, "data": {"method": "api_key", "path": "/api/v1/projects"}}
{"timestamp": "2026-11-27T18:45:06.055+00:00", "src_ip": "198.51.100.77", "event": "command", "client": "norma/0.4", "data": {"method": "GET", "path": "/api/v1/projects", "status": 401, "route": "/api/v1/projects", "seq": 23, "discovered_via": "main-bundle", "discovered_age": 0, "marker": "public_api_key", "api_key_header": "X-Api-Key"}}
```

What the lines show:

- `seq` counts this source's requests on the listener across connections; each request
  here came on its own connection.
- Routes the bundle advertised carry `discovered_via: main-bundle`, the first asset that
  showed them, even when the OpenAPI document listed them later. The admin route answered
  401 and is still recorded as a discovered route.
- `object_id_count` climbs with each distinct ID asked of the lured item route.
- Each flow request names its `flow` and `flow_step`. The username check answers `exists`
  for the scenario's own accounts only; the reset and activation tokens are rejected.
- The activation route has no `discovered_via`: only the source map advertises it, and
  this visitor did not fetch the source map.
- The last request sent the `publicApiKey` value from `/env.js` in `X-Api-Key`. The
  listener logs the key as a login attempt, as for any API key, and the request event names
  the marker `public_api_key`. `marker_src` would be `true` if a different source had been
  given that value.

## The finding

Triage turns those lines into one campaign record. Trimmed to the fields that matter here,
with four of its 23 `request_sequence` entries:

```json
{
  "id": "campaign-http-198_51_100_77-20261127T1800",
  "kind": "campaign",
  "protocol": "http",
  "src_ip": "198.51.100.77",
  "judgement": "BENIGN",
  "high_signal": {},
  "llm_used": false,
  "clients": ["norma/0.4"],
  "request_sequence": [
    {"seq": 2, "at": "2026-11-27T18:45:06+00:00", "offset": 0, "conn": "http-077db2c2-9ee2-4783-9e61-57593c610999", "method": "GET", "path": "/static/js/main.366146e5.js", "query": "", "status": 200, "route": "asset", "client": "norma/0.4", "lure": "main-bundle", "discovered_via": "", "flow": "", "flow_step": "", "marker": "", "marker_src": false},
    {"seq": 5, "at": "2026-11-27T18:45:06+00:00", "offset": 0, "conn": "http-1a4630f9-855d-4c6c-b9ea-8964c6e238f7", "method": "GET", "path": "/api/internal/admin/settings", "query": "", "status": 401, "route": "/api/internal/admin/settings", "client": "norma/0.4", "lure": "admin-settings", "discovered_via": "main-bundle", "flow": "", "flow_step": "", "marker": "", "marker_src": false},
    {"seq": 19, "at": "2026-11-27T18:45:06+00:00", "offset": 0, "conn": "http-e8e9ebb4-0e57-4204-96db-930c1299033c", "method": "POST", "path": "/api/v1/auth/username", "query": "", "status": 200, "route": "/api/v1/auth/username", "client": "norma/0.4", "lure": "username-check", "discovered_via": "main-bundle", "flow": "username_check", "flow_step": "exists", "marker": "", "marker_src": false},
    {"seq": 23, "at": "2026-11-27T18:45:06+00:00", "offset": 0, "conn": "http-7dd43453-b246-4bb4-a7be-018c62382656", "method": "GET", "path": "/api/v1/projects", "query": "", "status": 401, "route": "/api/v1/projects", "client": "norma/0.4", "lure": "", "discovered_via": "main-bundle", "flow": "", "flow_step": "", "marker": "public_api_key", "marker_src": false}
  ],
  "indicator_matches": [
    {"id": "artex-ua-norma", "framework": "ARTEX", "label": "ARTEX default user agent (agent web fetch)", "confidence": "medium", "count": 24},
    {"id": "recon-env-js", "framework": "", "label": "Runtime configuration fetch (reconnaissance path)", "confidence": "low", "count": 1}
  ],
  "behaviours": [
    {"id": "discovered-routes-used", "label": "agentic reconnaissance: called routes it found in a bundle, map or API document", "confidence": "medium", "count": 18, "first_seq": 5, "last_seq": 23},
    {"id": "object-enumeration", "label": "agentic reconnaissance: walked object ids on one route", "confidence": "medium", "count": 12, "first_seq": 7, "last_seq": 18},
    {"id": "recovery-probing", "label": "agentic reconnaissance: probed account recovery flows", "confidence": "medium", "count": 4, "first_seq": 19, "last_seq": 22},
    {"id": "marker-reuse", "label": "agentic reconnaissance: presented a value it was served", "confidence": "high", "count": 1, "first_seq": 23, "last_seq": 23}
  ]
}
```

- `request_sequence` keeps each request's `seq` and `at`, so the raw line can be found in
  the event log; `offset` is seconds since the first request (all of these came within
  one second).
- `indicator_matches` names the entry, its framework and confidence, and how many times it
  matched. The user-agent count includes the login attempt line. Where each fact comes
  from (`sources`, `reported`, `notes`) stays in the indicator file, and the console shows
  it beside the match.
- `behaviours` names each rule that matched, its count and the requests it spans. Four of
  the five shipped rules matched; `adaptive-retries` needs more errors in a minute than this
  visitor produced.
- `judgement` is `BENIGN` and `high_signal` is empty: the matches sit beside the rule-based
  judgement and never change it. This record was written without a model (`llm_used` is
  false), so its headline and narrative are the rule-based ones; with a model configured, a
  matched behaviour asks it for a narrative within the call caps.

The record does not appear in `blocklist-candidates.csv` for these matches. The digest
lists each match as a `Finding:` line, for example
`agentic reconnaissance: walked object ids on one route (ARTEX-like): medium confidence, count 12`.

The console's campaign record page shows the same in two sections:

- **Behaviours and indicators**, headed "Pattern and list matches: shown for context, never
  used for the judgement or the blocklist." Each behaviour shows its label, "(ARTEX-like)"
  when an indicator naming that framework also matched, its confidence, count and request
  span ("requests #7 to #18"). Each indicator shows its label, confidence and hits, then
  "Reported 2026-11-25 by" the source URLs (as text) and the entry's notes.
- **Request sequence**, a table with the columns `#`, `+s`, Request, Status, Route,
  Found in, Flow, Marker and Client, and a link to the raw Activity for the same source and
  time span. Planted values in paths, queries and user agents are masked, as in the
  Activity view.

## Indicator lists

Indicator entries live in `detections/indicators/*.toml`. Each `[[indicators]]` entry:

```toml
[[indicators]]
id = "artex-ua-norma"
type = "user_agent"          # user_agent, path, query, ipv4, ipv6
match = "prefix"             # exact, prefix, contains (addresses: exact only)
value = "norma/"
framework = "ARTEX"          # optional
label = "ARTEX default user agent (agent web fetch)"
confidence = "medium"        # low, medium, high
sources = ["https://..."]    # one to five https URLs that state the fact
reported = "2026-11-25"
notes = "Each source's own qualification."
```

Matching is plain string comparison: user agents without case, a `query` entry against the
path and query joined by `?`, addresses exactly. The key-by-key reference is in
[detections/README.md](../detections/README.md#indicator-lists).

The shipped file, `agentic-frameworks.toml`:

| id | type, match | value | confidence | source |
|---|---|---|---|---|
| `artex-ua-enrich` | user agent, prefix | `artex-enrich/` | medium | Microsoft, 2026-11-25 |
| `artex-ua-norma` | user agent, prefix | `norma/` | medium | Microsoft, 2026-11-25; Wiz |
| `artex-ua-reconprobe` | user agent, exact | `ReconProbe/1.0` | low | Wiz, 2026-10-22 |
| `recon-env-js` | path, exact | `/env.js` | low | Wiz, 2026-10-22 |
| `recon-assets-config-json` | path, exact | `/assets/config.json` | low | Wiz, 2026-10-22 |
| `recon-packs-js` | path, prefix | `/packs/js/` | low | Wiz, 2026-10-22 |
| `recon-swagger-openapi` | query, exact | `/swagger/?format=openapi` | low | Wiz, 2026-10-22 |
| `recon-sso-jwt` | query, prefix | `/sso?jwt=` | low | Wiz, 2026-10-22 |
| `recon-validate-username` | path, exact | `/Account/ValidateUserName` | low | Wiz, 2026-10-22 |
| `recon-password-reset-token` | path, contains | `/GeneratePasswordResetToken` | low | Wiz, 2026-10-22 |
| `recon-forgot-password` | path, exact | `/forgot_password` | low | Wiz, 2026-10-22 |

The three user agents carry the framework ARTEX. User agents are trivially changed, and
the reports say so: Microsoft says threat actors using ARTEX can and do vary them, and Wiz
says many in its list are not unique to this actor. The paths and queries carry no
framework, since any scanner may request them. No port, request rate or address ships as
an indicator.

To add your own entries, including addresses, put another `.toml` file beside the shipped
one in `detections/indicators/`. `[indicators] path` in `config.ini` points at one directory
or one file instead of the shipped directory, and `enabled = false` turns matching off. Ids
must be unique across files; a file that does not validate is left out whole and logged.

A match is shown on the record, in the digest and in the console, and a playbook can use
it as a condition. It never changes a judgement and never puts a source on the blocklist.

## Behaviour rules

Behaviour rules live in `detections/behaviours/*.toml`. Each `[[rules]]` entry has `id`,
`kind`, `label`, `confidence`, `description`, an optional `enabled`, and the kind's
thresholds. The shipped `recon.toml` has one rule of each kind:

| id | kind | matches when | shipped thresholds | confidence |
|---|---|---|---|---|
| `discovered-routes-used` | `discovery_then_use` | distinct paths requested within a time of the asset or document that showed them | `min_routes = 2`, `within_seconds = 3600` | medium |
| `adaptive-retries` | `adaptive_retries` | within a window: enough requests, enough 4xx answers, and enough errors followed by a changed path, query or method on the same host | `min_requests = 20`, `window_seconds = 60`, `min_client_errors = 10`, `min_changes = 5` | low |
| `object-enumeration` | `object_enumeration` | distinct object IDs asked of one item route | `min_ids = 10` | medium |
| `recovery-probing` | `recovery_probing` | flow requests across flow kinds | `min_steps = 3`, `min_flows = 2` | medium |
| `marker-reuse` | `marker_reuse` | requests that presented a per-source marker back (`other_source_only = true` counts only markers issued to another source) | `min_hits = 1` | high |

To change a threshold, edit the rule, or copy the file into a directory of your own and
point `[behaviours] path` at it. `enabled = false` on a rule turns that rule off;
`[behaviours] enabled = false` turns them all off. Rules see the first 300 requests of a
campaign, and the listener counts at most 200 IDs per route, so thresholds above those never
match.

The shipped labels say "agentic reconnaissance". On a record that also matched an
indicator naming a framework, a behaviour is described as like it ("ARTEX-like"), never as
attributed to it. The model sees the request sequence, not the labels.

## Playbook

Two playbook conditions read these matches (see
[playbooks.md](playbooks.md#conditions)):

- `behaviours_any`: the record matched any of the listed rule ids.
- `indicator_confidence_at_least`: the record matched an indicator entry of at least this
  confidence.

A playbook whose enforce step has only these two as conditions is refused; add a
condition such as `judgement_at_least` or `honeytoken` to such a step. The shipped
`playbooks/agentic_recon.toml` runs on HTTP campaigns that matched any shipped rule, at
most once an hour per source and 200 times a day:

```toml
[when]
kinds = ["campaign"]
protocols = ["http"]
behaviours_any = ["discovered-routes-used", "object-enumeration", "recovery-probing", "marker-reuse", "adaptive-retries"]

[[steps]]
action = "tag_source"
tag = "agentic_recon"

[[steps]]
action = "capture_more"

[[steps]]
action = "notify"
connectors = ["webhook", "siem_http", "email"]
include = ["tags"]
```

Tagging and capturing more change only this honeypot and run automatically. The
notification goes through whichever of those connectors are enabled.

## Safety

- The flows send nothing: a recovery request gets the same "if an account exists" reply for
  every address, and no mail is sent. Every reset and activation token is "invalid or
  expired", so no credential becomes valid and no session is issued. Logins still go
  through the trap's normal login handling.
- Everything served is synthetic. Asset text, the OpenAPI document and route bodies come
  from the scenario and its seed, and generated asset text is checked with the rest of the
  scenario by `scenarios.check`.
- Markers have no fixed prefix or fragment. A value is derived from the sensor seed, the scenario, the
  source and the marker name, in the plain format its name suggests, and is recognised by
  lookup of what was issued, so the source code gives a reader nothing to search for.
- Discovery, markers and ID counts are held in memory per source, for a day after the
  source's last request: request counters for up to 65,536 sources, the rest for up to
  8,192 sources that fetched an asset, were issued a marker or asked an ID (200 IDs per
  route, 400,000 in all). Marker recognition looks at a bounded prefix of each request
  field in linear time, and indicator and behaviour files never become regular expressions.

## Limits

- Discovery state and issued markers are lost when the listener restarts. Requests after a
  restart carry no `discovered_via` for routes shown before it, and a marker issued before
  it is recognised again only once it has been served again.
- A triage record written by this version has fields an older version does not know; an
  older version skips such records, which matters when rolling back.
- `dev_portal` is selected through `config.ini`. The AWS sensor template's scenario
  parameter does not list it.
