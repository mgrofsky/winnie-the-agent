# Architecture

This page describes the components, how data moves between them, the log format they share,
and the budgets that bound model use. Related pages:
[scenarios](scenarios.md), [playbooks](playbooks.md), [operations](operations.md),
[security model](security-model.md).

## Components

The system has two halves. **Front-ends** face attackers and write events. **Agents** read
those events afterwards and produce records, reports, tuning changes and responses. The two
halves share files, never a network connection.

| Component | Location | Role |
|---|---|---|
| SSH honeypot | `SSH/ssh_server.py`, `agents/hooks.py`, `agents/shell.py` | The upstream DECEIVE server: a model plays a Linux shell. `ssh_server.py` stays close to upstream; each addition is a small call into `agents/hooks.py`, marked with an `agent layer` comment. |
| Listeners | `listeners/` | Low-interaction traps for SIP (UDP and TCP), FTP, Telnet, PostgreSQL, MySQL, MSSQL, Redis, SMTP, HTTP, HL7 MLLP and S3-compatible storage, all in one asyncio process (`python -m listeners`). |
| Scenarios | `scenarios/` | One strict schema describing the fake target; loader, synthetic-data checker and describer. See [scenarios.md](scenarios.md). |
| Budgets | `agents/budget.py` | Spend and concurrency limits for every model call, shared by the SSH and listener processes. |
| Triage | `agents/triage.py`, `agents/sessions.py` | Turns the log into one validated record per SSH session or trap campaign; writes the daily digest. |
| Response | `agents/respond.py`, `agents/playbooks.py`, `agents/source_state.py`, `agents/connectors/` | Runs playbooks on new records. See [playbooks.md](playbooks.md). |
| Tuner | `agents/tuner.py` | Adjusts fake accounts, SIP extensions, lures and login thresholds in the overlay. |
| Detect | `agents/detect.py` | Writes Sigma rule drafts and blocklist candidates to `detections/pending/`. |
| Event export | `agents/ship.py` | Copies new event log lines to S3 as JSON lines for a SIEM (`[connector.s3_events]`, off by default). See [operations.md](operations.md#event-export-to-s3). |
| Operator console | `agents/ui/` | `python -m agents ui`: a local web console over the records, queue, digests, tuner state, playbooks and detections. Read-only unless actions are on; loopback only. See [operations.md](operations.md#operator-console) and [security-model.md](security-model.md#operator-console). |
| CLI | `agents/__main__.py` | `python -m agents <command>`; `run-all` runs triage, respond, digest, tune and detect in that order, then the event export when it is enabled. |

### SSH persona

Every persona model call goes through `agents.hooks.persona_invoke`, which:

1. reserves the estimated cost in the budget, and returns a canned
   `fork: Resource temporarily unavailable` reply (and the session closes) when a limit
   would be exceeded;
2. adds the active scenario's host profile to the prompt, pinned for the whole session so
   a returning attacker sees the same host;
3. applies the source's tarpit delay, if a playbook set one.

If the model call fails (provider error, timeout), the session continues with a plausible
canned reply instead, from the deterministic shell in `agents/shell.py` (below), followed
by a prompt; `exit` or `logout` end the session. If the configured provider needs an API
key from the environment (`anthropic`, `openai`, `gemini`, `azure`) and the variable is not
set, the persona runs offline from the start: no network attempt is made and every command
gets a canned reply. A warning is logged once at startup. Offline replies charge no tokens
to any budget; the per-session command cap and the concurrency limits still apply.

#### Deterministic shell

`agents/shell.py` is the one answerer for the SSH fallback and the Telnet trap's canned
shell, so the two cannot disagree. It answers, from the scenario's host profile
(`[identity]` and `[identity.hardware]`), the sensor seed and the clock, with no model and
no subprocess:

- identity and uptime: `uname` (all flags, real field order), `hostname`, `uptime` (also
  `-p`, `-s`), `whoami`, `id`, `w`, `nproc`, `free` (`-b`, `-k`, `-m`, `-g`, `-h`, `-t`),
  `df` (`-h`, paths), `ps` (plain, `aux`, `-ef`);
- files: `/proc/cpuinfo`, `/proc/meminfo`, `/proc/version`, `/proc/uptime`,
  `/proc/loadavg`, `/proc/mounts`, `/etc/os-release`, `/etc/issue`, `/etc/hostname`,
  `/etc/passwd` (the scenario's users plus the login account), `/etc/shells`, and the
  distribution's own release files (another distribution's are "No such file");
- hardware: `lscpu`, `lspci`, `nvidia-smi` (plain, `-q`, `-L`, `--query-gpu` with CSV
  output), or `command not found` when the profile has no GPU;
- `which`, `command -v`, `ls` (and `cd`, `pwd`) of `/`, `/home`, `/tmp`, `/var/tmp`,
  `/dev/shm`, `/root`, `/opt`, `/srv`, `/mnt`, `/media` and home directories, showing the
  scenario's lures where they live;
- the IoT botnet openers: `sh` (a nested shell, no output), `enable` (bash's list of
  builtins: both front ends present bash, and a bot sending it reads nothing from the
  reply), `system`, `shell` and `linuxshell` (`command not found`, as bash says), and
  `busybox NAME` (`NAME: applet not found`), with the BusyBox version the distribution
  release ships; RHEL and its rebuilds ship none, so there `busybox` is
  `command not found`;
- `wget`, `curl` and `tftp`, which exist but fail (no route, or no name resolution) without
  any lookup or connection;
- `echo` (including `-e` escapes) and the quiet builtins.

A command given by path (`/bin/uname`, `/bin/./uname`, `/usr/bin/id`) answers the same.
Pipelines of that output through `grep` (`-c`, `-i`, `-v`, `-n`, `-q`, `-F`, `-e`),
`head`/`tail -n`, `cut -d -f/-c`, `wc` and `awk '{print $N, ...}'` (with `-F`) are
evaluated in Python, as are `;`, `&&` and `||` lists of them. `grep` patterns are fixed
strings plus `.`, `^` and `$`, matched by hand; no attacker text is ever compiled as a
regular expression, and the module's own parsing of attacker text (words, `awk` programs,
`cut` lists, counts, `echo -e` escapes) is a single linear pass.

This code runs on the event loop, so one line's cost is bounded as a whole: every command
and filter charges one work counter per character and per loop step, every command's output
is capped at 128 KiB (the line's at 128 KiB too), and a command reads at most 8 files. A
line over any of these limits falls back like an unknown line. The worst line we could
construct on the largest valid profile (64 CPUs, 8 GPUs) costs about 12 ms. Input over
4096 characters, more than 8 commands in a pipeline or 32 in a list, control characters,
substitution, variables, globbing, and any command, option or file it does not
know fall back too: to the model; without one, to a builtin's own output, the known tool's
own error for an option or file it does not handle (`invalid option`, `No such file or
directory`) or no output, and `command not found` only for a command the host does not
have. Errors from the shell itself are worded as bash words them: `-bash: ...` in an
interactive session, and over SSH exec `bash: line 1: ...` (bash 5.1 and later, by the
scenario's distribution release) or `bash: ...` (older bash). `/proc/meminfo` and `free`
report whole 4 kB pages.

The canned shell also answers what IoT loaders send (Mirai, Gafgyt-style droppers): a list
runs part by part, `ping`, `nc` and bare `busybox APPLET` print their real usage (recorded
from the distribution's busybox package), and `/bin/echo`, `/bin/busybox` and
`/proc/self/exe` read as the start of an ELF image for the host's machine
(`agents/elfimage.py`), the same bytes through `cat`, `dd` and a `while read` loop. Files a
Telnet session writes (`>x`, `cp`, `chmod`, `echo -ne ... >> x`) are kept in memory for
that session (32 entries, 128 KiB) and never run. Binary bytes leave as the exact bytes;
the event log and the model's history keep `\xNN` text instead.

With a model and `[llm] local_shell_replies = true` (the default), a line the shell can
answer is answered from the profile, by how far its commands could disagree with what the
session has done (`agents.shell.FIXED`, `SESSION`, `STATE`; a line takes the highest):

- Facts no command can change are answered locally for the whole session: the kernel
  (`uname` without the nodename), `uptime`, `w`, `who`, `nproc`, `free`, `lscpu`, `lspci`,
  `nvidia-smi` on a GPU host, the `/proc` CPU, memory, version, uptime and load files,
  `echo`, the IoT openers and `busybox` applet probes.
- Facts a session can change (`hostname`, `uname -n` and `-a`, `whoami`, `id`, `which`,
  `command -v`, `ls`, `pwd`, `ps`, `df`, `sh`, every file outside those `/proc` files,
  including `/etc/os-release` and the other release files, a file that does not exist, and
  a program path that does not exist, such as `/usr/bin/xmr`) are answered locally only
  until a model reply (fresh or cached) has answered a command in the session; after that
  the model answers them, because it may have run `hostname x`, `useradd`, written a file
  or downloaded a program. The model's own session opener does not count.
- Commands that change the session (`cd`, `export`, `unset`, `history`, `wget`, `curl`,
  `tftp`) always go to the model, which then owns the change.

A local answer given after the model has answered ends with exactly the prompt the model
last showed (the last line of its reply), and paths resolve from the directory that prompt
shows: `user@host:DIR# `, or `[user@host ~]# ` and `[user@host /]# ` on RHEL. When the
prompt has any other shape (`export PS1='$ '`, or RHEL's `[root@host tmp]# `, which shows
only the last path component), the session gets no more local answers; the model answers
everything from then on. Local answers cost no model call, count
against the per-session command cap but not the model cap, follow the source's `shallow`
mode, and are added to the session's chat history (each clipped to 4 KB) so the model's
later replies agree with them; those characters count in the token estimate made before
each model call. A session whose commands were all answered this way gets no model
summary. When the model fails after it has moved the session to another directory, the
fallback reply keeps the prompt (and working directory) the model last showed.

The persona block tells the model the exact line bash prints for a program the host does
not have (`-bash: NAME: command not found` in a login shell, `bash: line 1: NAME: command
not found` over SSH exec on bash 5.1 and later), so it answers an unknown program the way
the shell would instead of inventing output.

A model reply that reads as the model talking and not as shell output (for example "As an
AI", "I'm sorry, but", "I apologize, but", or a mention of its instructions or system
prompt; straight and curly apostrophes alike) is not sent. A phrase counts only in the
first two non-empty lines of the reply, or anywhere when the reply has no shell prompt
line; for content viewers (`cat`, `less`, `more`, `head`, `tail`, `man`, `grep`,
`strings`, `git log`) only in the first line, so file text that mentions a language model
passes. The attacker instead gets what a shell would print: for `echo` or `printf` of
literal arguments the real output computed in code, for anything else empty output, then
the prompt (`#` for root, `$` otherwise). The sent text also replaces the model's reply in
the session history, so the model never sees its own break again. A `Persona break` event
records the original reply (base64 in `details`, clipped to 2,000 characters). A phrase
the attacker typed themselves is allowed through. The check is a short list of patterns in
`agents/hooks.py`; it catches the common ways a model steps out of the role, not every
one.

Sessions have a login timeout (60 s), an idle timeout (300 s) and an absolute lifetime
(1800 s); each frees a concurrency slot. Chat history is dropped when a session closes. The
session summary at the end uses the same budget and is skipped when the session ran no
model-backed command.

Telnet uses the same persona path, with the `[llm]` provider, when `[listeners] llm = true`
and that provider's API key is present (providers without a key, such as Ollama or Bedrock,
count as available); otherwise it answers with a small deterministic shell.

### Listeners

All listeners share one event loop, so anything that blocks it takes every protocol down.
And with the default `after_n` login policy any client gets in within a few tries, so all
post-login code is treated as reachable without authentication. The shared framework in
`listeners/base.py` therefore enforces:

- connection slots globally, per source (IPv6 per /64), per service and per source per
  service, plus a per-source connection rate;
- shorter read timeouts before login than after; connections that send almost nothing
  within `progress_window` seconds are closed;
- per-line, per-connection byte and per-connection command caps;
- no regular expression or `fnmatch` on attacker-supplied patterns: SQL `LIKE` uses a
  linear matcher and Redis glob patterns use `listeners/glob.py` (linear time, 256-byte
  cap);
- repetitive low-value events (refused connections, malformed datagrams) are logged once,
  then as periodic counters, under a global events-per-second ceiling;
- exceptions never escape a handler: they are logged as an `error` event and the
  connection is closed.

Login policy per service: `all` (any credentials), `listed` (only configured accounts),
`after_n` (accept after a random number of attempts between `after_n_min` and
`after_n_max`, per source) or `none`.

Protocol notes:

- **SIP** (`listeners/sip.py`): `REGISTER` gets a Digest challenge; the password is
  recovered when it is a configured extension password, a common password or the username.
  `INVITE` is logged with the dialed number and always ends in 486 or 480; from a source
  with no live registration it is first challenged with 407. Over UDP there is at most one
  response per request, responses are never larger than the request (compact header names,
  optional headers dropped, otherwise no answer), more than 5 Via hops and SIP responses are
  never answered, and per-source and global response rates are capped.
  `[listeners] sip_udp_slack_bytes` (0 to 512, default 0) lets a response exceed its
  request by that many bytes, so that minimal REGISTERs from clients such as `sipsak` get
  their 401 challenge, at the cost of a small, rate-capped amplification factor. A UDP source
  counts as verified only after it echoes a nonce the trap issued, and every UDP event
  says which it is (`data.source_verified`). Each datagram passes the per-source request
  limit first, then a global inbound limit (`udp_requests_per_second`, default 200), both
  before any parsing, so one busy source cannot use up the shared budget; datagrams over
  the global limit are dropped and reported in one aggregated `limit` event per
  minute. Events from unverified UDP sources go through the low-value gate in a pool of
  their own (first event of each kind per source, then periodic lines with a `suppressed`
  count), so log growth does not depend on how many source addresses a flood forges, and a
  forged flood cannot crowd out log lines about real sources.
- **Low-value gate**: refused connections, malformed input and unverified-source events
  are logged once per source and reason, then at most once per minute with a `suppressed`
  count, under per-second ceilings (`low_value_events_per_second` and
  `unverified_events_per_second`). Counts that never got a line of their own (sources that
  never returned, keys evicted from memory, lines over a ceiling) are written every minute
  as one `Suppressed N low-value log lines` event per protocol and pool (`src_ip` `-`,
  `data.reason` `suppressed_summary`). Triage keeps these sensor-level lines, and the
  inbound drop lines, per day, and the digest lists them under "Sensor limits".
- **FTP**: passive mode only, on `ftp_pasv_ports`, advertising `ftp_pasv_address` (default:
  the control connection's local address). Data connections are accepted only from the
  control connection's source. `PORT`/`EPRT` are refused. An unused passive listener
  closes after `ftp_pasv_accept_timeout` seconds (default 30), and one source may hold at
  most `ftp_pasv_per_ip` open passive listeners (default 2). Uploads stream into the
  quarantine with caps enforced while reading; upload bytes are bounded by the quarantine
  caps, not by `max_conn_bytes`. An upload over `quarantine_max_file_bytes` is cut at the
  cap, stored, and logged as truncated with the size and SHA-256 of the part kept; over a
  per-source or total quota reading stops and nothing is stored. Identical files are stored
  once; hitting a quota is a high-signal event. A session's fake tree holds at most 500
  files and directories (parents included) and paths at most 32 components deep.
- **PostgreSQL**: SSL requests are declined; md5 password exchange by default (the password
  is recovered from the bundled common-password list when possible), `postgres_auth =
  cleartext` for the cleartext exchange. Simple query protocol, with best-effort extended
  protocol support so drivers do not hang.
- **MySQL**: `mysql_native_password` handshake without TLS; the password is recovered from
  the scramble for native and `caching_sha2_password` clients.
- **MSSQL**: TDS 7.x without TLS. `PRELOGIN` is answered with "encryption not supported";
  a client that requires encryption is logged and disconnected. Works with impacket
  `mssqlclient` and `sqlcmd` using ODBC Driver 13; ODBC Driver 18 requires encryption by
  default and is refused. Enabled in the `contact_center` scenario.
- **SQL** (all three): statements go to `listeners/sqlfake.py`, an in-memory fake engine.
  File, program and command-execution primitives get a believable permission error and a
  `sql_exec_attempt` signal; catalog queries and scenario tables get canned or generated
  answers; anything else may go to the budgeted model (when `[listeners] llm = true`)
  through a strict schema, and otherwise gets a syntax error.
- **Redis**: RESP and inline protocol, fake per-connection keyspace. The takeover chain
  (`CONFIG SET dir/dbfilename`, `SAVE`, `SLAVEOF`/`REPLICAOF`, `MODULE LOAD`, `EVAL`,
  `FLUSHALL`) answers plausibly and is logged as high-signal; nothing touches disk or
  connects out.
- **SMTP**: Postfix-like; captures `AUTH`; messages after `DATA` are logged (headers,
  recipients, size, SHA-256, first 2 KB) and discarded. Recipients outside the scenario
  domain are relay attempts.
- **HTTP**: login form and Basic, Bearer and API-key capture; after login a small site and
  JSON API built from the scenario. Unknown routes under the API prefix may be answered by
  the budgeted model when the scenario enables `llm_unknown_api_routes`; otherwise 404.
- **HL7 MLLP**: frames are logged and answered with an `AA` acknowledgement; nothing is
  forwarded.
- **S3**: enough of the S3 REST API (plain HTTP, path-style and virtual-hosted) for the AWS
  CLI, boto3, s3cmd and curl: ListBuckets, HeadBucket, GetBucketLocation, GetBucketAcl and
  GetBucketPolicy (canned), ListObjects V1 and V2 (prefix, delimiter, `max-keys` up to
  1,000, continuation, `encoding-type=url`), HeadObject, GetObject with `Range`, PutObject,
  DeleteObject(s) and a minimal multipart upload; everything else is a correct S3 XML
  error. Buckets and objects come from the scenario; object bodies are text, a scenario
  table as CSV, or deterministic filler generated per byte range, never the size on paper.
  SigV4 (header and presigned) and SigV2 are parsed for the access key id, region and
  signed headers; access follows the login policy keyed on the access key id, a SigV4
  signature is verified only for a scenario account with a secret, and `public_list` /
  `public_read` buckets answer anonymous requests. A planted access key id is accepted
  unless the policy is `none`, and is always logged as `s3_planted_key` with the token
  name. Upload bodies stream to the quarantine (FTP caps and truncation; `Expect:
  100-continue` and `aws-chunked` handled; each multipart part is its own quarantine entry)
  and the object is then listed for that source only, for an hour. Signals: `s3_list`,
  `s3_download`, `s3_bulk_download` (25 downloads or 64 MB from one source within 10
  minutes, high-signal), `s3_upload` (high-signal), `s3_planted_key` (high-signal).
  Deterministic triage maps successful listings to Discovery (T1619), a bulk download to
  data theft at Collection (T1530) and an upload to T1105; the `malware_drop` playbook
  fires on `s3_upload` and `honeytoken_reuse` on a planted key.

### Triage

`python -m agents triage` reads the log from a high-water mark (byte offset plus the file's
inode), groups events, and writes one `TriageRecord` (JSON) per item to `reports/`:

- **Sessions**: SSH connections where the attacker ran at least one command.
- **Campaigns**: everything else, aggregated per source, per protocol, per time window
  (60 minutes). A brute forcer making thousands of connections becomes one record. IPv6
  sources are grouped by /64, like every other per-source control: the record's `src_ip`
  is the /64, `src_addresses` keeps up to 20 of the addresses seen and
  `src_address_count` counts them all.
  Unverified UDP sources (seen only over UDP, no nonce round trip; the address may be
  forged) are folded into one aggregate record per protocol and window, with source
  `unverified`; while parsing, at most 1,000 such sources per window get their own
  campaign and counters per campaign are bounded.

At most `[agents] max_records_per_run` records (default 1,000) are written per run; the rest
stay pending for the next run. Session and campaign records older than
`[agents] record_retention_days` (default 90; 0 keeps them) are removed at the end of each
triage run.

Each record carries intent, kill-chain stage, skill, judgement, MITRE technique IDs, IOCs,
a short narrative, high-signal counts, honeytoken use and credential statistics. Values
come from the analyst model when one is used and validate against a strict schema;
otherwise they are computed by code.

The narrative is laid out in parts so every record reads the same way:

| Field | What it holds | Cap |
|---|---|---|
| `headline` | a few words naming the activity | 100 characters |
| `actions` | what the source did, one short sentence each | 5 items, 160 characters each |
| `assessment` | what it most likely means | 4 items, 160 characters each |
| `not_seen` | what was looked for and not found | 5 items, 60 characters each |
| `narrative` | one plain paragraph, always filled | 600 characters |
| `clients` | campaigns: the most frequent client names the source announced | 3 items, 80 characters each |

The model writes `headline`, `actions`, `assessment` and `not_seen`; without a model the
rule-based triage fills them from the same facts it uses for judgement (signals, counts,
dialed numbers, honeytokens). The parts are forgiving where the rest of the schema is
strict: a part that is missing or of the wrong type is empty, an over-long one is clipped,
control characters become spaces, and the record is still written. The model is asked to
leave `narrative` empty and it is composed from the parts; a paragraph the model does give
is kept. `narrative` stays for everything that already reads it (connectors, the
`include_narrative` summary, search).

Who, volume and target are never written by the model. They are derived from the record
at display time (`triage.record_facts`): who from the source address, address count,
username and `clients`; volume from connections, login attempts, commands or requests and
high-signal counts; target from dialed numbers, SIP extensions, usernames tried and
honeytokens. Records written before the parts existed have them empty and are shown as
their paragraph.

Example (a rule-based SIP record, as the digest shows it):

```text
1. MALICIOUS / IMPACT / sip from `198.51.100.7` (`campaign-sip-198_51_100_7-20261101T1200`)
   - **`Toll-fraud probing over SIP`** (MALICIOUS)
   - Who: `198.51.100.7`, `client "examplesip"`
   - Volume: 6 connections, no login attempts, 6 requests, 6 x sip_dialed_number
   - Target: `number 0015550100`, `number 01115550100`, `number 915550100`, `1 more number`
   - What they did
     - `Dialed 6 outside numbers`
   - What it means
     - `Hostile: the activity goes beyond scanning or guessing`
     - `Looking for a route that places outbound calls at someone else's cost`
   - Not seen: `login attempts`, `honeytoken use`
```

Deterministic rules set floors the model cannot lower:

- In SSH sessions, code detects download-and-execute, persistence (cron, systemd, shell rc
  files, `authorized_keys`), and reads of credential files (`/etc/shadow`, SSH private
  keys, cloud and tool credential files). Each one, and any honeytoken use, makes the
  judgement `MALICIOUS` and raises the stage.
- Campaigns get a model look only when there was a fake login followed by activity, a
  high-signal event or honeytoken use, and the source is verified. Failed-only brute force
  is always handled by code.

Model-suggested IOCs are kept only if they appear verbatim in the transcript and match their
type's format.

Without any model configured (no Anthropic credentials, or `--no-llm`), every SSH session
and campaign gets a deterministic record. When a model is configured but temporarily
unavailable (rate limit, outage, timeout) or the call cap is reached, model work stops for
that run and the affected items are deferred to the next run; nothing is lost because the
cursor is saved after every item.

The digest (`reports/daily/YYYY-MM-DD.md`) lists counts, the top three items (honeytoken
use first, then judgement, stage, high-signal events and novelty), high-signal events,
credential statistics per protocol, and SIP extensions and dialed numbers. Each of the top
three is laid out as above (headline, who, volume, target, what they did, what it means,
not seen), or as its paragraph when the record has no parts. Attacker and model strings
are rendered inside escaped code spans.

### Tuner

`python -m agents tune` looks at the last 14 days of triage records and:

- adds fake accounts (for SSH and every listener service) and SIP extensions that
  attackers actually try;
- removes accounts it added itself once nobody has tried them for a full window (never a
  configured account, never the last account of a service);
- adds lure files built only from fixed allowlists of directories and bait names;
- adjusts `after_n` bounds.

It writes only the overlay (`$WINNIE_OVERLAY`, else `[scenario] overlay`, else
`decoy/overlay.json`). Every change
first stores a numbered snapshot, so any run can be undone (`tune --history`,
`tune --rollback N`). `--dry-run` prints the diff. `--git-commit` additionally commits the
overlay when running from a checkout; if the commit fails the overlay is rolled back.
Candidate selection is deterministic; the model may only reorder candidates by index. The
fences are listed in [security-model.md](security-model.md#tuner-fences).

The SSH server re-reads accounts from `config.ini` and the overlay when either file changes
(checked at the next login attempt) and reloads the host profile for new sessions;
listeners poll the overlay every 30 seconds. Configured accounts always win over overlay
accounts.

### Detect

`python -m agents detect` writes drafts only, to `detections/pending/`:

- Sigma rules for IOCs and high-signal behaviour seen across several sessions or sources.
  The rule body comes from a template in code; the model may only supply a title and
  description, which are length-capped and limited to a safe character set. Each draft
  lists the triage records it was built from.
- `blocklist-candidates.csv`, one row per source across all protocols. Private, reserved
  and documentation addresses and unverified sources (see [Source proof](#source-proof))
  are skipped. Each row carries `source_proven`, a `reason` from a fixed vocabulary and an
  `expires` time; rows past their expiry are left out of the next run's file. See
  [Using the intelligence outside the sensor](operations.md#using-the-intelligence-outside-the-sensor)
  before acting on it.

See [detections/README.md](../detections/README.md).

## Data flow and trust boundaries

```
attacker --> SSH server ----+                       +--> reports/ (records, digests,
attacker --> listeners -----+--> event log --> agents     response runs, honeytokens)
                            |    quarantine       |  +--> detections/pending/
                            |    budget state     |  +--> connectors (opt-in)
                            |    sensor seed      |  +--> S3 event export (opt-in)
                            +<-- overlay <--------+
                            +<-- source state <---+
```

| Store | Written by | Read by | Docker volume |
|---|---|---|---|
| Event log, quarantine, budget state, sensor seed | SSH server, listeners | agents, operator console (read-only) | `frontend` |
| Overlay, per-source state | agents | SSH server, listeners, operator console (read-only) | `overlay` |
| Triage records, digests, response runs, approval queue, tuner snapshots, honeytoken registry, detection drafts, event export cursor | agents; operator console only with actions on (approval queue, blocklist, audit records) | operator, operator console | `agentdata` |
| `config.ini`, host key, `prompt.txt` | operator | all (read-only) | bind mount |

The sensor seed (`<data dir>/sensor_seed`, mode 0600, random on first start) drives every
generated record and honeytoken value, so a sensor keeps showing the same fake data across
restarts and rebuilds. `[scenario] seed` can set it explicitly. It is never derived from the
sensor name or anything else public.

Per-source state (`agents/source_state.py`) holds what playbooks decided about one source:
tags, tarpit delay (at most 5 s), budget mode (`deep` or `shallow`), fuller capture, and a
planted honeytoken. Each effect has its own expiry. The file is bounded to 10,000 entries;
over the bound, entries are evicted by priority (plain tags and tarpits first, planted
tokens last). Front-ends reload it when its modification time changes.

## Logging contract

All components append to one JSON-lines file. The SSH server uses upstream DECEIVE's
`JSONFormatter`; listener events (`listeners/events.py`) use the same top-level fields plus
an event type. This file is the only interface between front-ends and agents
(`agents/sessions.py` parses it).

Common fields:

| Field | Meaning |
|---|---|
| `timestamp` | UTC, ISO 8601 with milliseconds. |
| `level` | `INFO`, `WARNING` or `ERROR`. |
| `task_name` | Unique per connection (SSH: `session-<uuid>`; listeners: `<protocol>-<uuid>`). |
| `src_ip`, `src_port`, `dst_ip`, `dst_port` | Connection endpoints as seen by the process. |
| `message` | Human-readable event name. |
| `sensor_name` | `[honeypot] sensor_name`. |

SSH `message` values include `SSH connection received`, `User attempting to authenticate`,
`Authentication success` / `Authentication failed` (with `username` and `password`),
`User input` (base64 text in `details`, plus `interactive`), `LLM response` (base64 text in
`details`), `Session summary` (summary in `details`, `judgement` field: `BENIGN`,
`SUSPICIOUS`, `MALICIOUS`, or `UNKNOWN` when no summary was made, for example without a
model), `Budget exceeded`
(with `reason`), `Model error`, `Persona break`, `Session timeout` and
`SSH connection closed`.

Listener events add:

| Field | Meaning |
|---|---|
| `sensor_protocol` | `sip`, `ftp`, `telnet`, `postgres`, `mysql`, `mssql`, `redis`, `smtp`, `http`, `mllp`, `s3` (SSH lines carry `ssh`). |
| `event` | `connection`, `auth_attempt`, `command`, `register`, `invite`, `options`, `limit`, `error`, `close`. |
| `transport` | `tcp` or `udp`. |
| `username`, `password` | Submitted credentials, when the protocol reveals them. |
| `client` | Client software string (User-Agent, connect attributes). |
| `success` | `true` only for an accepted fake login or registration. |
| `data` | Up to 32 protocol-specific keys (for example `dialed`, `high_signal`, `signal`, `reason`, `sha256`). |

Every attacker-supplied value is length-capped (512 characters) and has control characters
escaped before it is written. Listener writes use `O_APPEND`, so lines from the SSH and
listener processes never interleave.

### Source proof

A UDP datagram's source address is whatever the sender wrote, so a SIP event over UDP may
name an address that never sent anything. Two flags say when the address is proven:

| Field | On | Meaning |
|---|---|---|
| `data.source_verified` | every SIP request event over UDP (not `error` or `limit` lines); SIP `invite` over either transport | `true` when the address has completed a nonce round trip with this listener: it was sent a challenge nonce and came back with it, so it can receive packets at that address. `false` otherwise. |
| `data.nonce_verified` | SIP `auth_attempt` (a REGISTER with credentials) and an answered `invite` | `true` when this request carries a nonce the trap issued to this same address. This is the round trip itself; it is what turns `source_verified` on for the address's later events. |

When they are set:

- An address becomes verified the first time a request from it carries a nonce issued to
  it. From then on its UDP events carry `source_verified: true`, including the event that
  proved it.
- The listener remembers the 10,000 most recently verified addresses, in memory only. An
  address that falls out of that list, or any address after a listener restart, is
  unverified again until it completes another round trip.
- Events from unverified UDP sources go through the low-value gate: the first of each kind
  per source, then periodic lines with a `suppressed` count. A missing line does not mean
  nothing arrived.
- TCP events (every other listener, SIP over TCP, and SSH) do not need the flag. A completed
  TCP handshake proves the address, so `transport: tcp` (or an SSH line) is proof on its
  own, and `source_verified` may be absent there.

A consumer that decides anything per address (blocking, alerting, reputation, counting
distinct attackers) should keep only events where `transport` is `tcp`, or
`data.source_verified` is `true`, or `data.nonce_verified` is `true`, and treat the rest
as unattributed volume. Without that filter a forged-source flood can put any address,
including a victim's or your own, into the result. Triage applies the same rule: campaigns
seen only over UDP without a round trip are marked `unverified_source`, never raise
severity, and never reach the blocklist candidates or Sigma drafts.

## Budgets

`agents/budget.py` enforces limits before any model call. When a limit would be exceeded the
model is not called: the attacker gets a canned error and the session closes, and a
`Budget exceeded` event with the reason is logged.

| Limit (`[budget]`) | Default |
|---|---|
| `max_line_bytes` (input is truncated) | 2048 |
| `max_commands_per_session` | 200 |
| `max_model_commands_per_session` (see below) | 50 |
| `max_tokens_per_session` | 400,000 |
| `max_tokens_per_ip_per_day` (IPv6 per /64) | 1,000,000 |
| `max_tokens_per_day` (global) | 3,000,000 |
| `max_concurrent_sessions` | 20 |
| `max_concurrent_sessions_per_ip` | 3 |
| `reply_cache_entries` (0 turns the reply cache off) | 2000 |
| `reply_cache_max_age` (seconds) | 21600 |

- The estimated cost (history length / 4 plus 512 output tokens) is reserved before the
  call and corrected from the provider's usage data afterwards, so concurrent sessions can
  overshoot a cap by at most one estimate's error. Failed calls keep their charge.
- Daily counters live in a JSON file in the data directory (`state_file`), updated under
  an exclusive file lock, so the SSH server and the listeners on one host share the caps
  and a restart does not reset the day. A malformed file restarts the day from zero with a
  warning.
- A source in `shallow` mode (set by a playbook) gets canned replies only; `deep` doubles
  its per-session and per-source limits (the model cap too). The global cap never changes.
- `max_model_commands_per_session` counts the commands the model was asked, failed calls
  included (a failed call still reserved its cost). Cached replies are looked up first and
  still served past it. When a
  session reaches it, the session is not closed: every later command is answered by the
  deterministic shell, so an unknown command gets `command not found` and `exit` still
  ends the session. One `Model cap reached` event (with `limit`) is logged per session; the
  shell's answers are added to the history for the summary. Listener model calls (SQL,
  HTTP) stop at the same cap and get their protocol's error. There is no per-source
  counterpart: a source opening session after session to reset the cap is already bounded
  by `max_tokens_per_ip_per_day` and `max_concurrent_sessions_per_ip`.
- The reply cache (`agents/replycache.py`) keeps model replies in memory and serves one
  again, with no model call and no tokens, to a session whose history so far is identical.
  The key is a hash chained over the host (scenario and sensor seed), the login user,
  interactive or exec, the persona block, and every turn so far: each input line and the
  reply as the history holds it. Bots replay one script, so their sessions mostly hit. A
  hit is added to the history, counts toward `max_commands_per_session` but not the model
  cap, and counts as a model reply for the local-answer rule above. The session summary is
  cached the same way.
- A session uses the cache only while everything in its history is a function of its key:
  a local answer that read neither the clock nor the source address
  (`agents.shell.Answer.shareable`), a cached reply, or a model reply it has just stored.
  It leaves the cache for good, neither reading nor writing it, as soon as its history gets
  anything else: a local answer from `w`, `who`, `uptime`, `ps`, `/proc/uptime` or
  `/proc/loadavg` (clock or address), a model error or fallback, a reply past the model
  cap, a reply replaced because it broke character or misprinted an `echo`, or a model
  reply that was not stored. A source with a planted token or a `deep` or `shallow` mode
  never uses it, and neither does a session whose cache state was evicted (it never
  restarts from the root key). Not stored, as a second line: replies that end the
  session, replies that contain the session's address (whole, or cut to 16 characters as
  `w` cuts IPv6), replies to lines whose real output changes between runs (`date`,
  `uptime`, `ps`, `/dev/urandom`, `mktemp`, `openssl`, ...) and replies over 16 KB. The
  cache is bounded by `reply_cache_entries` (least recently used out first) and
  `reply_cache_max_age`, and is not kept across a restart, so a changed prompt, model or
  scenario never serves an old reply.
- Timing: a local or cached reply is as fast as a real shell, while a model reply takes
  the model's latency, so a script can tell which commands reach the model. The
  per-source tarpit does not cover this (it applies to flagged sources only, to every
  reply). `[llm] local_reply_delay_ms` (default 0, at most 2000) waits a random half to all
  of that time before a local, cached or capped reply in a model-backed session. It only
  narrows the gap, since model latency varies far more, and it slows every scripted bot,
  so it is off by default.
- `[llm] prompt_caching` marks the persona request for the provider's prompt cache. It is
  on by default for the Anthropic provider. For `aws` it is off by default and is used
  only when set to `true`, and then only for model ids containing `anthropic.` or
  `amazon.nova` (the families langchain-aws marks cache points for; other Bedrock models
  reject them). Not every model in those families accepts cache points, so if the first
  request with one is refused as invalid (Bedrock `ValidationException`, Anthropic 400),
  it is retried without the cache point and caching stays off until restart, with one
  `Prompt caching disabled` log line. It places one breakpoint on the last message, so the
  system prompt, persona block and the session so far are read from the provider's cache
  on the next command. Other providers are unchanged. The budget still charges the full
  token count the provider reports.
- Listener model calls (SQL, HTTP and Telnet fallbacks) use the same budget, take a session
  slot, run at most `llm_max_inflight` at a time, make one request with no retries, and
  fail closed when no budget is initialised.
- Analyst calls are capped per run (`[agents] max_llm_calls_per_run`, shared by all stages)
  and per UTC day (`max_analyst_calls_per_day`).

SSH reads a whole line before the line cap applies (the SSH library buffers it), so a very
long line without a newline still costs memory before it is truncated.
