# Security model

A honeypot invites hostile input on purpose. This page states what the system assumes, what
it defends against, how, and where the limits are.

## Assets and adversaries

What must be protected:

- the host and network the sensor runs on, and anything reachable from it;
- third parties: the sensor must not become a reflector, relay, scanner or source of
  attacks;
- the operator's model spend;
- the operator's other systems reached by outbound connectors (chat, SIEM, ticketing,
  firewall managers);
- the captured data itself (credentials, commands, uploads).

Adversaries:

- **Attackers on the network** connect to the front-ends and control every byte they send:
  commands, usernames, passwords, SIP headers, SQL, HTTP requests, uploaded files. They may
  spoof UDP source addresses.
- **Prompt injection.** Everything an attacker sends may be crafted to steer a model: the
  persona model sees it directly, and analyst models see it in transcripts.
- **Resource exhaustion.** Attackers may try to burn model budget, exhaust connections or
  memory, or stall the shared event loop.

Out of scope: an attacker with code execution on the sensor host, a compromised model
provider, and a malicious operator.

## Fences

### Nothing real behind the traps

- The SSH and Telnet shells are model output or canned text. Nothing an attacker types is
  executed.
- SQL goes to an in-memory fake engine; Redis `SAVE` writes nothing and `SLAVEOF` never
  dials; SMTP accepts and discards; SIP never sends media or places a call; HL7 messages
  are acknowledged and logged only. The S3 trap serves scenario text, scenario tables and
  generated filler; object keys are only looked up in memory and never become file paths.
- Uploaded files (FTP `STOR`, S3 `PutObject` and `UploadPart`) go to a capped quarantine (stored once per SHA-256, mode 0600) and are
  never read back, parsed or executed.

### Front-ends do not connect out

No listener opens an outbound connection: FTP active mode is refused, and passive data
connections are accepted only from the control connection's source. The S3 trap refuses
`CopyObject` and never resolves a URL, endpoint or bucket name it is given. The only outbound
traffic a front-end originates is a model API call, when a model is configured. Enforce
this with a host firewall as well (see [operations.md](operations.md#egress-control-in-production)).

### Not a reflector

Over UDP, SIP sends at most one response per request, never larger than the request by
default (`sip_udp_slack_bytes` can allow up to 512 extra bytes), ignores SIP responses and
requests with more than 5 Via hops, and caps responses per source and globally. Datagrams
over the size limit are dropped.

Spoofed-source floods are bounded too: a per-source limit and then a global inbound limit
(`udp_requests_per_second`) drop excess datagrams before any parsing, events from sources
that never completed a nonce round trip are aggregated by the low-value gate in a pool of
their own (so they cannot crowd out log lines about real sources), and triage folds those
sources into one record per protocol and window instead of one file per forged address.
Suppressed log lines are never lost silently: every count is written in a periodic summary
line and appears in the daily digest.

### Bounded resources

- Model spend: per session, per source per day (IPv6 per /64) and global daily token caps,
  command caps and concurrency limits, reserved before every call
  ([architecture.md](architecture.md#budgets)).
- Listeners: connection slots globally, per source, per service and per source per service;
  rate limits; read timeouts; minimum-progress checks; byte and command caps per connection;
  rate-limited logging of low-value events.
- S3: request heads are capped like HTTP (8 KB line, 50 headers, 16 KB in all); bodies of
  non-upload requests at 64 KB; uploads stream to the quarantine and stop at its per-file
  cap or a quota, with `aws-chunked` framing overhead capped; a download sends at most the
  scenario's `get_max_bytes` and a connection at most 64 MB; listings return at most 1,000
  keys per page; per-source upload and delete state is bounded and expires after an hour.
- No regular expression or `fnmatch` runs on attacker-supplied patterns; Redis globs and SQL
  `LIKE` use linear-time matchers. A test feeds every listener long runs of its protocol's
  special characters under a time bound.
- Analyst calls: capped per run and per day.

### Logged data is inert

Attacker-supplied values in the log are length-capped and have control characters escaped.
SSH input and model output are base64-encoded. The digest renders attacker strings inside
escaped code spans.

## What the model can and cannot influence

Models get no tools, shell, files or network. They return text (the persona) or one JSON
object (analysts).

| Model | Can influence | Cannot influence |
|---|---|---|
| Persona (SSH, Telnet) | the text the attacker sees in that session | anything else: its output is sent to the attacker and logged, nothing more |
| SQL / HTTP fallback | column names and capped cell values, or a JSON body, validated against a strict schema | protocol state, other connections, files |
| Triage analyst | intent, stage, skill, judgement, techniques, a narrative and extra IOCs, all schema-validated | severity below the deterministic floor; IOCs that do not appear verbatim in the transcript; which playbooks run beyond what those enum fields select |
| Tuner ranking | the order of candidates the code generated, by index | any value written to the overlay |
| Detect | a length-capped, character-restricted title and description | the rule body and selectors |

Every analyst output must validate against a strict pydantic schema (unknown keys
forbidden, enums, patterns, length caps). Output that fails is dropped and logged, never
applied. Attacker text is passed to analysts inside a block delimited by a random per-call
nonce, so it cannot forge the end marker; this is a convenience, not the control. The
control is schema validation plus the fact that no free-form model text flows into the
persona prompt, the config, the overlay or a playbook decision.

Playbooks match only on enum and numeric fields of a validated record plus facts computed by
code. The model-written narrative leaves the honeypot only if
`[respond] include_narrative = true`, labelled untrusted, stripped of markup, and cut to
fit the 300-character summary.

### Tuner fences

All fences use full-string matching, so a trailing newline never passes.

- Account username `[a-z_][a-z0-9_-]{0,31}`; password printable ASCII, at most 64
  characters, no leading or trailing space. At most 20 accounts per service. The tuner
  removes only accounts it added, never the last account of a service, and never a
  configured account.
- SIP extension `[0-9]{2,6}`, at most 20.
- Lures are built only from fixed allowlists of directories and bait file names; attacker
  activity only raises a candidate's score. At most 25.
- Hostname `[a-z][a-z0-9-]{0,62}` (manual changes only).
- `after_n` bounds 1 to 20, min not above max.
- It never writes `config.ini` or a scenario file, never switches scenarios and never
  changes the SSH banner.

Usernames, extensions and passwords taken from attacker activity are used for
authentication only and are never rendered into a prompt.

## Response and outbound rules

- **Tiers fixed in code.** Local actions change only this honeypot. Notify actions go only
  to connectors the operator enabled. Enforce actions (blocklist, detection publishing,
  tickets, block webhook) never run without `python -m agents approve <id>`, and only if
  `[respond] queue_enforce = true`. Approvals expire.
- **Source gates.** UDP sources that never completed a nonce round trip, non-global
  addresses and `never_act_on` ranges get no per-source action of any tier. This prevents
  an attacker from spoofing a victim's address into a blocklist or a tarpit. Gates are
  checked again at approval time.
- **Proxy guard.** If one non-global address accounts for most records, per-source actions
  are refused for the run, since every client would otherwise share one identity.
- **Connectors.** `https` only (SMTP requires STARTTLS before credentials); no private or
  loopback destinations unless explicitly allowed; the destination address is resolved
  once, validated and pinned, defeating DNS rebinding; no redirects, proxies or retries;
  one overall deadline per call; a 64 KB response cap; a daily cap per connector. Secrets
  come from environment variables named in config and never appear in config, logs or
  reports.
- **Event export.** With `[connector.s3_events]` enabled, the agents process (never a
  front-end) sends the event log to the configured S3 bucket: attacker addresses, ports,
  user names, commands and request content. Unless `passwords = clear`, these are replaced
  by keyed hashes (`drop` removes them instead):
  - every `password` field, and the protocol fields listed in `SECRET_FIELDS` in
    `agents/ship.py` (SIP digest responses and recovered passwords, MySQL and PostgreSQL
    password responses, HTTP bodies and unparsed `Authorization` values, FTP `PASS` lines,
    Redis `AUTH`/`HELLO`/`MIGRATE`/`CONFIG SET requirepass` command lines, S3
    `X-Amz-Security-Token` values), plus any data key whose name looks like a secret;
    S3 request signatures (`X-Amz-Signature`, `Signature`) are never logged at all;
  - inside every other string field: values of URL query or form parameters whose name
    contains `pass`, `pwd`, `secret`, `token`, `key`, `auth`, `cred`, `sig` or `session`;
    the password in URL userinfo (`scheme://user:secret@host`) and SIP URIs
    (`sip:user:secret@host`); Redis `ACL SETUSER` `>password`/`<password` rules and the
    password after `AUTH`.

  At the source, an HTTP Basic token without a colon is logged as the password (user
  `<basic>`), and SMTP lines a client pipelined after a refused `AUTH` are logged as the
  password of an `AUTH_DATA` event, so both are covered above. Not covered: secrets in
  other free-text shapes, for example a password typed as a plain argument of an SSH or
  Telnet command (`mysql -pSecret`), a credential inside an FTP file name, or SSH
  `User input` text, which is shipped as captured. The client
  uses the default AWS credential chain, `https`, connect and read timeouts, at most two
  attempts, and refuses every operation but `PutObject`, so the bucket can be write-only
  for the sensor. AWS endpoints are not pinned the way connector destinations are; the
  TLS certificate check against the AWS host name is the protection. Delivery is at least
  once.
- **Notification content.** Built from structured fields; attacker-derived URLs, domains,
  addresses and `@` are defanged in chat, email and ticket outputs; the enrichment
  response is treated as untrusted and flattened to a few short scalar fields.
- **Caps.** Per-playbook and per-connector daily notification caps, with a share reserved for
  priority playbooks, so a flood of routine events cannot spam the operator or crowd out
  important alerts.

## Container boundaries

Non-root, read-only root filesystem, no capabilities, `no-new-privileges`. Front-ends can
write only their own data volume; they read the overlay and per-source state but cannot
change them. The agents read the front-end volume read-only and do not mount the
repository. A compromised listener therefore cannot alter what the agents produce, and a
compromised agents process cannot change the front-ends' code or configuration.

## Operator console

`python -m agents ui` (see [operations.md](operations.md#operator-console)) is a web
console for the operator. It is a security component even though only the operator uses
it: almost everything it displays was typed by attackers.

**What it can read and write.**

| Mode | Reads | Writes |
|---|---|---|
| Read-only (default) | event log, agent data (records, digests, queue, tuner and decoy state, detections), overlay, playbooks | nothing (in Docker every mount is read-only) |
| Actions on (`--actions` or `[ui] actions = true`, plus agent data mounted read-write) | the same | approval queue, blocklist store and file, `response/` audit records, approved detections: what `approve`, `reject` and `unblock` write |

With actions on it calls the same `approve`, `reject` and `unblock` functions as the CLI,
so the same gates apply: the source is re-checked at approval time, the queue lock stops a
double execution, expired items cannot be approved. Decisions are recorded as
`ui:<operator>`. The overlay and the event log stay read-only in both modes. With actions
on, the console is in the same trust zone as the agents container.

**Loopback only, behind a tunnel.** The server binds a loopback address and refuses
anything else unless told otherwise; the Docker service binds 0.0.0.0 inside its container
and the host publishes it on 127.0.0.1 only. There is no public URL and no inbound port:
the operator reaches it through `ssh -L` or SSM port forwarding. The console is on a
network of its own, so the honeypot containers cannot connect to it. That network cannot
be internal (Docker does not publish ports from internal networks), so what limits the
container's egress is what it holds: no model key, no AWS settings, no connector secrets,
read-only data.

**Sign-in and request checks** (`agents/ui/server.py`):

- At start the server logs one sign-in link with a random token (or uses
  `WINNIE_UI_TOKEN`, at least 24 characters). `GET /?token=...` sets an HttpOnly,
  SameSite=Strict session cookie. The cookie holds its issue time and an HMAC-SHA256 of
  it under a random key made fresh at every start, never derived from the token: a
  session ends when the server restarts (even with a fixed `WINNIE_UI_TOKEN`) and after 12
  hours, both enforced by the server, with nothing stored server-side. An altered,
  expired or future-dated cookie gets the same 401 as no cookie. The CSRF value is an
  HMAC of the cookie value, so one session's value is refused with another's cookie. The
  token itself is never stored in a cookie, returned by an endpoint or logged again.
- The sign-in token is not used up: after a restart or expiry the operator opens the same
  logged link again (with a fixed `WINNIE_UI_TOKEN`, the same link across restarts). The
  token is compared first, so the correct one always signs in; failed attempts are
  counted and answered 429 once over 10 a minute, which slows guessing but cannot lock the
  operator out.
- Every request's `Host` must name localhost, 127.0.0.1 or [::1], which defeats DNS
  rebinding. Every POST also needs an `Origin` exactly equal to `http://` plus that
  `Host` (so a page on another local port or under another loopback name cannot post),
  the session cookie, the `X-Winnie-CSRF` header, actions turned on, and a JSON object
  body of at most 16 KiB.
- A POST refused by any of those checks is answered before its body is read and the
  connection closed, so an unauthenticated client cannot hold a worker with a slow body.
  An accepted body must arrive within 10 seconds in total. At most 32 connections are
  served at once; the rest get a fixed 503. HTTP/0.9 requests are closed unanswered.
- Static files come from a fixed table; no file is looked up from the request path.
  Errors become a bare 500.
- The console's unblock removes exactly one listed entry: the target must parse to a key
  already on the blocklist. A network covering several entries (or everything, such as
  `0.0.0.0/0`) is refused; ranges are unblocked with `python -m agents unblock`.

**Displayed text is attacker-controlled.** Commands, usernames, passwords, HTTP requests
and transcripts are all hostile input. The console renders them as text only, never as
HTML: no inline script, a strict Content-Security-Policy (`default-src 'none'`, scripts
and styles from the console itself only, `frame-ancestors 'none'`), `nosniff`, no
referrer, no caching, and JSON with `<`, `>`, `&`, U+2028 and U+2029 escaped.

**What it deliberately cannot do.** It never calls a model, so nothing it shows can steer
one. It never displays configuration or secrets. It cannot roll back the tuner (use
`python -m agents tune --rollback N`) or change playbooks, scenarios or the overlay.

**Host access is the control.** Anyone who can reach the loopback port and read the
container log (or knows `WINNIE_UI_TOKEN`) can use the console, and with actions on can
approve a block. Restrict shell, Docker and SSM access on the host accordingly.

## Fingerprinting

The source is public, so assume the attacker has read it. What they can and cannot use:

**Not recognisable from the source.** The bait in the bundled scenarios is expanded per
sensor from the private sensor seed: the organisation name and domain, host names, internal
networks, people and user names, every account password, password hash, token, key and
session id (see [per-sensor bait](scenarios.md#per-sensor-bait)). None of these values is
in the repository, so searching for one finds nothing, and two sensors with different seeds
do not share them. Passwords are drawn from shapes and word lists that real people use, and
keys and tokens from plain formats with no project-specific prefix. Without the seed the
values cannot be predicted.

**Still recognisable.** Templates hide values, not structure. Someone who has read the
scenarios can still match:

- protocol behaviour: how each trap answers, its error texts, timing, which commands and
  queries it understands, the login policy (`after_n` accepts any password after a few
  tries), and the S3 and SQL emulation's gaps;
- software versions in banners and headers (FreePBX 16.0.40, MariaDB 10.11.6, a given
  Postfix, nginx or Apache version), which are the same on every sensor running a scenario;
- the shape of the fake data: table and column names, file paths and their layout, Redis
  key names, HTTP routes and page text, bucket name suffixes, the order and number of seed
  rows, the generator ranges, and the fictional phone ranges and documentation addresses;
- the story itself: one organisation of a recognisable kind with these services and these
  files;
- tokens issued by earlier versions, which carried fixed markers (an `AKIAFAKE` key id
  prefix, `sk_test_hp_`, `hpt_`, `Trk`). Current versions never issue them; they are only
  recognised when they come back;
- the naming conventions the generators use (host name shapes, the invented halves of
  organisation names, the person and password word lists), which narrow a guess without
  giving a value.

Planted tokens (honeytokens and per-source pairs) carry no fixed marker. Each has the length
and alphabet of the real format and is derived from the seed; the sensor recognises one by
looking it up in an index of every value it can have issued, not by its shape, so a reader
of the source has nothing to search for.

**AWS-style access key ids.** A planted key id is `AKIA` and 16 characters of `A-Z2-7`,
which is the shape real key ids have. There is no shape-based guarantee that such an id was
never issued to a real account. AWS documents no reserved range, and any rule that would
give one (a fixed fragment, a character real ids never contain, a checksum) is a constant
anyone who reads this source could search for, which is the fingerprint this design
removes. The guarantee settled on is about the pair, not the id:

- the secret paired with a planted key id is derived from the sensor seed (40 base64
  characters), so it is not the secret of any real key, and AWS refuses any request signed
  with it whatever the key id; a planted pair can never authenticate anywhere but on this
  sensor;
- a planted key id alone could equal a real one: there are 2^80 possible ids, so even with
  a hundred billion keys issued the chance is below one in 10^12 per token. The only thing
  a key id alone reveals to its holder is the owning account's id (via
  `sts:GetAccessKeyInfo`, which needs valid credentials of the caller's own);
- the synthetic-data checker refuses AWS-shaped key ids in a scenario unless they are the
  sensor's own planted tokens, so a real key id cannot be pasted into a pack by mistake.

The least harmful option was the real shape: it costs a vanishing collision risk with no
access attached, against a marker that would identify every sensor.

An operator who needs a sensor that survives a careful look should write their own
scenario, or at least pin the identity and change the story, banners and data layout of a
bundled one. The bundled scenarios are examples.

## Known limits

- Docker's userland proxy hides client addresses; per-source controls are meaningless until
  it is disabled.
- The SSH library buffers a whole input line before the line cap applies.
- Token reservations are estimates; a cap can be exceeded by at most one call's estimation
  error.
- The daily budget is shared per host, not across hosts.
- The S3 trap speaks plain HTTP. Access key ids are logged; signatures are verified only for
  scenario accounts that carry a secret, so any other key is accepted or refused by policy,
  not by cryptography.
- The captured data contains real-looking and sometimes real credentials. Protecting it is
  the operator's job.
- The operator console trusts anyone who can reach its loopback port and read its log.
  Host access is the only control in front of it.
