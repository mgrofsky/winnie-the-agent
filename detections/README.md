# Detection drafts: human approval required

Everything under `detections/pending/` is a **draft** written by `python -m agents detect`.
Nothing here is deployed, sent, or enforced automatically.

- `*.yml`: Sigma rules built from a fixed template in `agents/detect.py`, one file per rule
  id (`<first 8 characters of the id>-<kind>.yml`). The model can only supply the title and
  description of a new draft, and those are length-capped and limited to a safe character
  set. Indicator values come from regex extraction over attacker commands, so they are
  attacker-controlled strings; Sigma wildcards and backslashes in them are escaped, so they
  match literally. Read each one before use. `date` is when a rule was first drafted and
  `modified` when it last changed; a rule already in `approved/` is not drafted again.
  Log sources, the pipeline in `pipelines/winnie-events.yml` and what was tested are in
  [docs/portable-formats.md](../docs/portable-formats.md).
- `provenance.json`: the triage record ids each pending draft was built from. The
  `publish_detection` action uses it to pick the drafts for a record.
- `blocklist-candidates.csv`: `ip, sessions, attempts, first_seen, last_seen, judgement,
  protocols, source_proven, reason, expires`, covering every protocol. The first seven
  columns are unchanged from earlier versions; new columns are only ever appended. Private
  and reserved addresses (including the documentation ranges) are skipped. BENIGN-only
  sources are left out, and so are UDP-only sources that never completed a nonce round
  trip, since their address may be forged.
  - `source_proven`: `yes` when the address completed a TCP exchange or a SIP nonce round
    trip, so it cannot be a forged UDP source. Every row written today is `yes`; check it
    anyway, so a consumer keeps working if unproven rows are ever included.
  - `reason`: the highest thing the source did, from this list, lowest first: `probe`
    (connected, nothing more), `login_attempt`, `object_list` (listed storage buckets or
    objects), `register` (a SIP registration was accepted), `login` (a fake login was
    accepted), `object_read` (downloaded a stored object), `command` (ran commands after a
    login, or a takeover or command execution attempt on a service without one), `relay`
    (tried to relay mail or proxy a request), `dial` (placed a SIP call), `upload` (sent a
    file), `honeytoken` (used a planted credential). Code picks it from counts and signal
    names; nothing the attacker sent is copied into it.
  - `expires`: `last_seen` plus `[agents] blocklist_access_expiry_days` (default 30) for
    sources that got past a login or used a planted credential, otherwise plus
    `[agents] blocklist_expiry_days` (default 14). The file is rewritten in full on each
    run and rows past their expiry are left out.
  - Every cell comes from a parsed address, a count, a re-formatted timestamp or a fixed
    word. A cell that would still start with `=`, `+`, `-`, `@` or a control character is
    written empty, so the file cannot carry a spreadsheet formula.

  Read [Using the intelligence outside the sensor](../docs/operations.md#using-the-intelligence-outside-the-sensor)
  before feeding this file to anything that blocks or pages.

## Indicator lists

`detections/indicators/*.toml` hold indicator entries that triage matches against each
campaign; `[indicators] enabled` and `path` in `config.ini` turn them off or point at other
files. Each `[[indicators]]` entry has:

| Key | Values |
|---|---|
| `id` | lower-case letters, digits, `.`, `_`, `-`; unique across files |
| `type` | `user_agent`, `path`, `query` (path and query joined by `?`), `ipv4`, `ipv6` |
| `match` | `exact`, `prefix` or `contains` (addresses: `exact` only); user agents compare without case |
| `value` | up to 200 characters |
| `framework`, `label` | what the entry stands for |
| `confidence` | `low`, `medium` or `high` |
| `sources`, `reported`, `notes` | the https pages that state the fact, the report date, and each source's own qualification |

Matching is plain string comparison; no regular expression is built from these files. A
file that does not validate is left out whole and logged. `agentic-frameworks.toml` ships
the ARTEX user agents `artex-enrich/` and `norma/` (medium) and `ReconProbe/1.0` (low), and
low-confidence paths and queries one report listed from the same activity. Those carry no
framework, since any scanner may request them. User agents are trivially changed. Add your
own entries, including addresses, in another file.

## Behaviour rules

`detections/behaviours/*.toml` hold rules over a campaign's HTTP request sequence;
`[behaviours] enabled` and `path` turn them off or point at other files. Each `[[rules]]`
entry has `id`, `kind`, `label`, `confidence`, `description`, optional `enabled`, and the
kind's thresholds:

| Kind | Thresholds | Matches when |
|---|---|---|
| `discovery_then_use` | `min_routes`, `within_seconds` | that many distinct paths were requested within that long of the asset or document that showed them to the source |
| `adaptive_retries` | `min_requests`, `window_seconds`, `min_client_errors`, `min_changes` | within the window: that many requests, that many 4xx answers, and that many errors followed by a changed path, query or method on the same host |
| `object_enumeration` | `min_ids` | that many distinct object ids were asked of one item route |
| `recovery_probing` | `min_steps`, `min_flows` | that many username, recovery, reset or activation flow requests across that many flow kinds |
| `marker_reuse` | `min_hits`, `other_source_only` | a per-source marker served to a source came back in a request (with `other_source_only`, from a different source) |

`recon.toml` ships one rule of each kind, labelled "agentic reconnaissance". Indicator and
behaviour matches appear on the triage record, in the digest and in the console, and
playbooks can use them (`behaviours_any`, `indicator_confidence_at_least`; see
[docs/playbooks.md](../docs/playbooks.md#conditions)). They never change a record's
judgement and never put a source in `blocklist-candidates.csv`.

## Promoting a draft

Before promoting a draft:
1. Check the indicator is not shared infrastructure (CDN, cloud NAT, a scanner you rely on).
2. Test the Sigma rule against a day of normal logs for false positives.
3. Move it out of `pending/` yourself, or approve the `publish_detection` action a playbook
   queued for it (`python -m agents approve <id>`), which moves the draft to
   `detections/approved/`. Nothing moves a draft without one of those two steps.

See [docs/architecture.md](../docs/architecture.md#detect) and
[docs/playbooks.md](../docs/playbooks.md#approval-workflow).
