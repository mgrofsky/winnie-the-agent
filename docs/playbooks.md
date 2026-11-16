# Response playbooks

Playbooks decide what happens after triage. `python -m agents respond` (also part of
`run-all`, right after triage) matches each new triage record against the playbooks in
`playbooks/*.toml` and runs the matching steps. Matching and execution are deterministic
code (`agents/playbooks.py`, `agents/respond.py`); the model never chooses an action, and
attacker strings are never compared against anything a playbook supplies.

## Playbook format

```toml
name = "toll_fraud"                      # must match the file name
description = "SIP source dialing international or premium-rate numbers."
enabled = true
priority = false                         # may use the reserved notification share
cooldown_minutes = 120                   # per source, 0 to 10080
max_runs_per_day = 200

[when]
protocols = ["sip"]
dialed_international_or_premium = true

[[steps]]
action = "tag_source"
tag = "toll_fraud"

[[steps]]
action = "tarpit"
delay_ms = 2000
hours = 48

[[steps]]
action = "export_blocklist"

[steps.only_if]                          # optional guard on one step
min_attempts = 100
```

Unknown keys are rejected. A playbook has 1 to 12 steps, run in order. A step may carry an
`only_if` guard written in the same condition vocabulary. Validate all playbooks with
`python -m agents playbooks --validate`; an invalid file is reported and skipped, the others
still run.

## Conditions

All conditions given in `[when]` must hold. List values mean "any of".

| Condition | Type | Matches when |
|---|---|---|
| `kinds` | `session`, `campaign` | the record is an SSH session or a trap campaign |
| `protocols` | `ssh`, `sip`, `ftp`, `telnet`, `postgres`, `mysql`, `mssql`, `redis`, `smtp`, `http`, `mllp` | the record's protocol is listed |
| `judgement_at_least` | `BENIGN`, `SUSPICIOUS`, `MALICIOUS` | the judgement is at least this |
| `stages` | kill-chain stages | the record's stage is listed |
| `intents` | intents | the record's intent is listed |
| `signals` | see below | any listed high-signal event occurred |
| `honeytoken` | bool | a honeytoken was (or was not) used |
| `min_attempts`, `max_attempts` | int | login attempt count is within bounds |
| `min_connections` | int | connection count is at least this |
| `source_verified` | bool | the source completed a TCP handshake or a SIP nonce round trip |
| `dialed_international_or_premium` | bool | a dialed number starts with an international (`00`, `011`, `+` other than `+1`) or premium-rate prefix |
| `sensitive_data_access` | bool | commands or file paths touched patient or financial data (words such as `patient`, `mrn`, `fhir`, `account`, `card`, `iban`, `ledger`, `payment`) |
| `malware_indicators` | bool | an FTP upload, or a URL or file hash among the IOCs |
| `nothing_novel` | bool | a campaign with no high-signal event, no honeytoken and no commands |
| `scenarios` | scenario names | the sensor's active scenario is listed |

Signals: `redis_takeover`, `sql_exec_attempt`, `sql_cred_dump`, `smtp_relay_attempt`,
`sip_dialed_number`, `quarantine_quota`, `http_proxy_attempt`, `ftp_upload`, and the SSH
session signals `download_execute`, `persistence`, `credential_file_read`.

There are no expressions and no free-text matching. Conditions read only enum and numeric
fields of a validated triage record, plus the facts above, which code computes from it.

## Actions and tiers

Every action's tier is fixed in code (`ACTION_TIERS` in `agents/playbooks.py`). A playbook
cannot change it.

| Tier | Action | Parameters | Effect |
|---|---|---|---|
| local | `tarpit` | `delay_ms` (1 to 5000), `hours` | delay every reply to the source |
| local | `deepen` | `hours` | double the source's per-session and per-source model budget |
| local | `shallow` | `hours` | canned replies only, no model calls, for the source |
| local | `plant_token` | `hours` (default 168) | show the source its own honeytoken (see [scenarios.md](scenarios.md#honeytokens)) |
| local | `tag_source` | `tag`, `hours` | label the source (up to 8 tags) |
| local | `capture_more` | `hours` (default 72) | log fuller request bodies for the source, within caps |
| notify | `notify` | `connectors` (`webhook`, `siem_http`, `email`), `include` | send a notification |
| notify | `enrich` | | look up the source address at the configured reputation service |
| enforce | `export_blocklist` | | add the source to the approved blocklist file |
| enforce | `publish_detection` | | move matching Sigma drafts from `detections/pending/` to `detections/approved/` |
| enforce | `open_ticket` | `priority` (`low`, `medium`, `high`) | open a ticket through the ticket connector |
| enforce | `block_webhook` | | send the source to the block webhook |

How each tier runs:

- **local** steps run automatically and change only this honeypot, through the per-source
  state file. Each effect has its own expiry (`hours`, at most 720). When several steps
  set a budget mode, the one from the most recent activity wins.
- **notify** steps run automatically, but only through connectors enabled in config. All
  connectors are off by default; a step whose connector is off is recorded as inert.
- **enforce** steps never run automatically. With `[respond] queue_enforce = true` they are
  written to an approval queue; with it off (the default) they are recorded as inert.
  `publish_detection` is queued only when a draft exists whose provenance includes the
  triggering record.

### Source gates

Before any step runs, the source is checked. These apply to every tier, local and notify
included:

- A source seen only over UDP that never answered a SIP nonce may be spoofed. It gets no
  action and no notification naming it; the run is only recorded.
- Non-global addresses (private, loopback, link-local, CGNAT, multicast, reserved,
  unspecified; IPv6 is judged by its /64) get no action.
- Addresses inside `[respond] never_act_on` get no action. List your own ranges,
  monitoring, CDN and resolver addresses there.

**Proxy guard.** When more than `proxy_threshold` (default 0.5) of at least
`proxy_min_records` (default 20) records in the lookback window come from one non-global
address, a proxy or Docker's userland proxy is probably hiding the real clients. For that
run, per-source local and enforce actions and enrichment are refused and a warning is
logged. Notifications still go out.

## Notifications

Notifications are built from structured, code-computed fields: playbook, protocol, source,
judgement, stage, signals, counts and IOC type counts. `include` adds optional details:
`dialed_numbers`, `hashes`, `urls`, `credentials` (top usernames; passwords are never
sent) and `tags`.

The analyst's free-text narrative is left out unless `[respond] include_narrative = true`.
Then it is appended with the label `untrusted model narrative` and stripped of mention and
markup characters. Chat, email and ticket outputs defang URLs, domains and addresses
(`hxxp`, `[.]`, `[at]`) so clients neither link nor mention them; the SIEM output keeps raw
values for searching.

Caps:

- Each connector has a daily cap (`max_per_day`, default 200).
- Each playbook may send at most `notify_max_per_playbook` (default 50) notifications per
  connector per day.
- `notify_reserved_share` (default 0.25) of each connector's daily cap is reserved for
  playbooks marked `priority = true`, so routine alerts cannot starve them.
- A notification dropped by a cap is recorded in the run. At most once every
  `suppressed_notice_minutes` (default 60), one "N notifications suppressed" notice is sent
  per connector when capacity allows.

## Connectors

Connectors (`agents/connectors/`) run only in the agents process, never in a front-end.
Configure them in `config.ini`:

```ini
[connector.webhook]
enabled = true
url = https://hooks.example.com/services/T000/B000/XXXX
secret_env = WINNIE_WEBHOOK_TOKEN   ; optional, sent as a bearer token
max_per_day = 200
timeout = 10
allow_private = false
```

| Connector | Tier | Sends |
|---|---|---|
| `webhook` | notify | JSON with a `text` line that chat webhooks render directly |
| `siem_http` | notify | one JSON event per notification, raw values |
| `email` | notify | plain-text email through an SMTP relay (`host`, `port`, `from`, `to`, `starttls`, `username_env`, `password_env`) |
| `enrich` | notify | a GET to `url` with `{ip}` replaced (`header` names the API key header); the response is flattened to at most 32 short scalar fields |
| `ticket` | enforce | a POST describing the approved action |
| `block_webhook` | enforce | a POST with the approved address or IPv6 /64 |

Rules every connector follows:

- `https` only (email: STARTTLS, and credentials are refused without it).
- No private, loopback, link-local or otherwise non-public destination unless
  `allow_private = true`. The host name is resolved once per call, every address is
  checked, and the connection goes to that validated address, so a DNS answer that changes
  after the check (DNS rebinding) cannot redirect it.
- No redirects, no proxies, no retries. A socket timeout on every operation plus one
  overall deadline per call, so a slow server cannot hold a call open. Responses are capped
  at 64 KB.
- A daily call cap per connector.
- Secrets come from environment variables named in config. URLs with embedded credentials
  are rejected.

Enabling `enrich` discloses attacker addresses to a third party. Only enable it for a
service you are allowed to send that data to.

## Approval workflow

```bash
python -m agents queue                 # pending approvals
python -m agents queue --all           # include decided and expired ones
python -m agents approve a-0123456789ab [--by alice]
python -m agents reject  a-0123456789ab [--by alice]
python -m agents unblock 203.0.113.7   # or a network, e.g. 2001:db8:1:2::/64
```

- A queued item records the action, playbook, triggering record, subject (IPv4 address or
  IPv6 /64), parameters, a structured summary and an expiry (`approval_ttl_hours`,
  default 72).
- An identical pending request is not queued twice. A rejected request is not queued again
  for the same playbook, source and action for `reject_suppress_hours` (default 168); one
  that expired undecided is held back for `expired_suppress_hours` (default 24).
- `approve` takes a lock and moves the item to `executing` before running it, so two
  concurrent approvals cannot both execute. It re-checks the source gates
  (verified, global, not in `never_act_on`) at approval time.
- Approved blocklist entries expire after `blocklist_ttl_days` (default 30); `unblock`
  removes one sooner. The blocklist file is rewritten in full each time.

The blocklist is written to `[respond] blocklist_file` (default
`reports/blocklist/approved.txt`); nothing is pushed anywhere. Formats
(`blocklist_format`):

- `plain`: one address or network per line;
- `csv`: `ip,approved_at,expires_at`;
- `nftables`: a complete `nft -f` file defining `table inet winnie` with two interval sets,
  `winnie_block_v4` and `winnie_block_v6`, flushed and refilled on every write so removed
  and expired entries disappear on reload. Check it with `nft -c -f <file>` and reference
  the sets from your own rules, for example
  `ip saddr @winnie_block_v4 drop` in a chain of that table.

## Records and retention

Every playbook run is recorded as JSON in `reports/response/` (trigger, playbook, each step
with its tier and result; for enforce steps, who approved it and when). Per-source state
changes are snapshotted under `<state dir>/source-state-snapshots/`.

`[respond]` retention settings:

| Key | Default | Meaning |
|---|---|---|
| `retention_days` | 30 | decided approvals and run records older than this are removed |
| `snapshot_keep` | 200 | source-state snapshots always kept |
| `snapshot_keep_days` | 7 | snapshots younger than this are also kept |
| `size_alarm_mb` | 500 | warn when approvals, run records and snapshots together exceed this |
| `lookback_hours` | 48 | records older than this are never acted on |

## Shipped playbooks

| Playbook | Trigger | Steps |
|---|---|---|
| `honeytoken_reuse` (priority) | a honeytoken was used | tag, capture more, notify, export blocklist, block webhook |
| `database_takeover` (priority) | Redis takeover chain, SQL command execution or credential dump | tag, deepen, plant token, notify |
| `sensitive_data_access` (priority) | patient or financial data touched on the `healthcare` or `bank` scenario | tag, plant token, deepen, notify |
| `malware_drop` | FTP upload or download-and-execute in SSH | tag, capture more, notify, publish detection |
| `toll_fraud` | SIP dialing to international or premium-rate numbers | tag, tarpit 2 s, notify, export blocklist |
| `noisy_brute_force` | campaign with 50+ attempts and nothing novel | shallow for 48 h; export blocklist only above 5,000 attempts |

Out of the box, only local steps have an effect: notify steps are inert until a connector is
enabled, and enforce steps are inert until `queue_enforce = true`.

## CLI reference

```
python -m agents {triage,respond,digest,tune,detect,ship,run-all,queue,approve,reject,unblock,playbooks}
```

| Option | Meaning |
|---|---|
| `--config` | path to `config.ini` (read only) |
| `--log` | event log (default: `[honeypot] log_file`) |
| `--data-dir` | front-end data directory (read only; sensor seed) |
| `--reports-dir` | default `<repo>/reports` |
| `--state-dir` | default `<reports-dir>/state` |
| `--detections-dir` | default `<repo>/detections` |
| `--overlay` | tuner overlay file |
| `--source-state` | per-source state file (default `$WINNIE_SOURCE_STATE` or `decoy/source_state.json`) |
| `--dry-run` | show what would happen; write and send nothing |
| `--no-llm` | never call a model |
| `--model`, `--max-llm-calls`, `--max-changes` | override `[agents]` settings |
| `--day` | digest day, `YYYY-MM-DD` |
| `--history`, `--rollback N`, `--git-commit` | tuner snapshots and opt-in commit |
| `--by` | approve / reject: who decided (default: the OS user) |
| `--all` | queue: include decided and expired items |
| `--list`, `--validate` | playbooks: list or validate |

`run-all` runs triage, respond, digest, tune and detect in that order, then the event
export (`ship`) when `[connector.s3_events]` is enabled. Each stage runs even if another
fails; failures are reported in the JSON summary on stderr and in the exit code (2).
`[respond] enabled = false` turns respond off, alone and in `run-all`. Every command that
writes (`triage`, `respond`, `digest`, `tune` including `--rollback`, `detect`, `ship` and
`run-all`) holds an exclusive lock (`agents.lock` in the state directory)
for the whole run; a second run started while one is in progress exits at once with a
`run_lock` error and status 2. Dry runs write nothing and take no lock. The `approve`,
`reject`, `queue` and `unblock` commands must use the same `--state-dir` and
`--reports-dir` as the runs that queued the items.
