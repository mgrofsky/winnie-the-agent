# Operations

How to deploy, run, upgrade and troubleshoot a sensor. Read
[security-model.md](security-model.md) first; this page assumes you have decided where the
sensor may run and what it may reach.

## Before you deploy

- **Isolation.** Run the sensor on a dedicated host or VM, in a network segment with no
  route to production systems, management networks or other sensors. Treat the host as
  hostile: assume anything on it can be read by an attacker who finds a bug in a
  listener.
- **Legal and policy.** A honeypot records traffic, credentials and content sent by third
  parties. Whether you may operate one, where, and what you may keep depends on your
  jurisdiction, your hosting provider's acceptable use policy and your organisation's
  policies. The operator is responsible for this, not the software.
- **SIP.** The SIP trap advertises a PBX on 5060. It never places, bridges or forwards a
  call and never sends media, but it attracts toll-fraud scanners and some hosting
  providers prohibit VoIP services. Over UDP, a spoofed request makes the trap send its
  (smaller) response to the spoofed address, within per-source and global rate caps. Keep
  `sip_udp_slack_bytes = 0` on internet-facing sensors unless you need to answer minimal
  REGISTERs.
- **HL7.** The MLLP trap acknowledges any HL7 v2 message. If a real clinical system is
  misconfigured to send to it, the log will contain real patient data and the sender will
  believe delivery succeeded. Only expose it where no real HL7 sender can reach it by
  mistake, and treat its log as potentially regulated health data.
- **S3.** The S3 trap speaks plain HTTP only. It cannot be published as 443: clients
  that expect `https://` fail the TLS handshake before a request is logged. Publish it on
  9000 (the MinIO default, which scanners probe) or on 80 of a second address of the
  sensor (80 is already the HTTP trap's port on the first). A client must be pointed at
  it with `--endpoint-url http://...`; scanners that only try `https://<bucket>.s3...`
  never reach it. PutObject bodies go to the quarantine like FTP uploads.
- **Captured data.** The event log, `reports/`, the quarantine and the approval queue hold
  plain-text passwords (often real credentials reused elsewhere), attacker commands and
  uploaded files. Restrict access to the host and volumes, keep the data no longer than you
  need, and never commit it (it is gitignored).

## Docker files

| File | Purpose |
|---|---|
| `Dockerfile` | One image (`python:3.13-slim`, dependencies from `uv.lock`) for all services. Runs as UID 10001. |
| `docker-compose.yml` | `ssh`, `listeners` and `agents` services, plus one example sensor per scenario and the operator console (`ui`), each behind a profile. Host ports default to the real service ports. |
| `docker-compose.lab.yml` | Override: every port bound to 127.0.0.1 on a high port, for a workstation lab. |
| `docker-compose.isolated.yml` | Override: front-ends on an internal network with no route out and no DNS, for verifying that nothing connects outward. |
| `docker-compose.ui-actions.yml` | Override: lets the operator console approve, reject and unblock (agent data read-write, `--actions`). See [Operator console](#operator-console). |

All services run as a non-root user with a read-only root filesystem, a small `/tmp`
tmpfs, all capabilities dropped and `no-new-privileges`.

Volumes:

| Volume | Written by | Mounted read-only by | Contents |
|---|---|---|---|
| `frontend` | `ssh`, `listeners` | `agents`, `ui` | event log, quarantine, budget state, sensor seed |
| `overlay` | `agents` | `ssh`, `listeners`, `ui` | tuner overlay, per-source state |
| `agentdata` | `agents` (and `ui` with actions on) | `ui` | triage records, digests, response runs, approvals, tuner snapshots, honeytoken registry, detection drafts, blocklist |

`./SSH` (config, host key, prompt) is bind-mounted read-only into the front-ends, and
`./SSH/config.ini` alone into `agents`. The agents container does not mount the
repository. On Linux hosts the containers read these files as UID 10001, so
`SSH/config.ini`, `SSH/prompt.txt` and `SSH/ssh_host_key` must be readable by that UID.

The `agents` service runs `python -m agents run-all` every `RUN_ALL_INTERVAL_SECONDS`
(3600). Model API keys are passed into the containers by name: the front-ends get
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY` and `AZURE_OPENAI_API_KEY` from the
shell that runs `docker compose`, and the agents get `ANTHROPIC_API_KEY`. With
`[agents] provider = bedrock` no key is needed: the agents use the AWS credential chain
(on EC2, the instance role, which needs `bedrock:InvokeModel` on the chosen model).

### Ports

| Service | Container port | Default host port (`docker-compose.yml`) | Lab host port (`docker-compose.lab.yml`, 127.0.0.1) |
|---|---|---|---|
| SSH | 8022 | 22 (`SSH_HOST_PORT`) | 12222 |
| FTP | 2121 | 21 | 12121 |
| FTP passive | 30000-30019 | 30000-30019 | 30000-30019 |
| Telnet | 2323 | 23 | 12323 |
| SMTP | 2525 | 25 | 12525 |
| HTTP | 8080 | 80 (`HTTP_HOST_PORT`) | 18080 |
| MSSQL | 1433 | 1433 | 11433 |
| MySQL | 3306 | 3306 | 13306 |
| SIP | 5060 UDP and TCP | 5060 | 15060 |
| PostgreSQL | 5432 | 5432 | 15432 |
| Redis | 6379 | 6379 | 16379 |
| HL7 MLLP | 2575 | 2575 | 12575 |
| S3 | 9000 | 9000 (`S3_HOST_PORT`) | 19000 |

Only services enabled by the active scenario listen. The FTP passive range must match
`[listeners] ftp_pasv_ports`, and `ftp_pasv_address` must be the address clients use to
reach the sensor (its public address in production, `127.0.0.1` in the lab); otherwise
clients are told to connect to the container's internal address.

The per-scenario example services (`docker compose --profile bank up`, and likewise
`healthcare`, `contact_center`, `saas`, `api_platform`) each run a listeners process for
one scenario on its own host ports, on the `frontend` network like `listeners`. The lab and
isolated overrides cover them too (lab ports: bank 21xxx, healthcare 22xxx,
contact_center 23xxx, saas 24xxx, api_platform 25xxx, HTTP on 8443-8447). A real
multi-scenario deployment gives each sensor its own data volume and agents service.

### Client addresses

Per-source limits, logs, triage and blocklists need the real client address. Docker's
userland proxy replaces it with the bridge gateway address for both TCP and UDP. Either
disable it in `/etc/docker/daemon.json`:

```json
{ "userland-proxy": false }
```

and restart the Docker daemon (published ports are then handled with NAT rules that keep
the source address), or run the front-ends with `network_mode: host`. Check that the first
log lines after a test connection show the client's address, not a 172.x gateway address,
before relying on any per-source control. The response engine's proxy guard refuses
per-source actions when most records come from one non-global address, but it is a safety
net, not a substitute.

## Lab deployment

```bash
cp SSH/config.ini.TEMPLATE SSH/config.ini
ssh-keygen -t rsa -b 4096 -N "" -f SSH/ssh_host_key
# in SSH/config.ini: [listeners] ftp_pasv_address = 127.0.0.1
docker compose -p winnie-lab -f docker-compose.yml -f docker-compose.lab.yml up -d
docker compose -p winnie-lab -f docker-compose.yml -f docker-compose.lab.yml logs -f
```

Test with real clients against 127.0.0.1 and the lab ports. With the default
`sip_provider` scenario, for example: `ssh -p 12222 root@127.0.0.1`,
`mysql -h 127.0.0.1 -P 13306 -u root -p`, `curl -i http://127.0.0.1:18080/` and
`sipsak -U -s sip:1001@127.0.0.1 -r 15060 -u 1001 -a <password>` (give `sipsak` the port
with `-r`: it misreads a five-digit port inside the URI). The traps accept a login after a
few attempts from the same source, or at once for an account listed in the scenario
(`scenarios/<name>/scenario.toml` lists them).

To check that the front-ends make no outbound connections, use the isolated override and
run clients as containers on the same internal network:

```bash
docker compose -p winnie-lab -f docker-compose.yml -f docker-compose.isolated.yml up -d
docker run --rm --network winnie-lab_frontend winnie-agents:local python -c "import urllib.request; print(urllib.request.urlopen('http://listeners:8080/').status)"
```

Docker publishes no ports for containers attached only to an internal network, so this
layout serves no external traffic and is for testing only.

## Egress control in production

[deploy/aws/README.md](../deploy/aws/README.md) applies everything in this section on AWS:
a host with no internet route, the `DOCKER-USER` rules below, IMDSv2 with a hop limit of
1, and the export run by its own container on the host network.

The front-ends need no outbound access except the persona model API, if you use one.
Enforce that at the host firewall. Docker evaluates the `DOCKER-USER` chain for forwarded
container traffic before its own rules, so a rule there that drops new outbound connections
from the front-end containers' subnet blocks egress while replies to inbound connections
(which belong to established flows) still pass:

```bash
# 172.30.0.0/24: the subnet of the front-end network, from
#   docker network inspect <project>_frontend --format '{{(index .IPAM.Config 0).Subnet}}'
# Allow the model API first if the persona uses one (repeat per address or use an ipset):
iptables -I DOCKER-USER -s 172.30.0.0/24 -d 198.51.100.20 -p tcp --dport 443 \
  -m conntrack --ctstate NEW -j ACCEPT
iptables -A DOCKER-USER -s 172.30.0.0/24 -m conntrack --ctstate NEW -j DROP
```

Notes:

- `docker-compose.yml` puts `ssh` and `listeners` on their own `frontend` network and the
  `agents` service on the default one, so filtering the front-end subnet does not affect
  the agents' egress (analyst model API and enabled connectors).
- Provider API endpoints change address; an allow rule by IP needs maintenance. Without a
  persona model, drop all new outbound connections from the front-ends.
- Apply the same with `ip6tables` if Docker IPv6 is enabled.
- Rules in `DOCKER-USER` are not persistent across reboots by default; save them with your
  distribution's firewall tooling.

## Image size and token counting

The image is about 650 MB on disk (about 135 MB as a gzipped `docker save`): the Python
base image plus the client libraries for the supported model providers. No machine
learning framework is installed.

SSH history trimming and the token budget count tokens locally: four ASCII characters per
token, and each other character weighted by its UTF-8 size (a CJK character counts as 1.5
tokens), so estimates for non-English text are not below what providers charge. No tokenizer files are downloaded and no
token-count API call is made, so trimming works the same on hosts with no outbound
access. `[llm] trimmer_max_tokens` is therefore an estimate, not the provider's exact
count; leave some headroom below the model's context window.

## Running without a model

Everything runs without any model configured:

- The SSH and Telnet shells answer from the deterministic shell: `uname`, `uptime`, `id`,
  `nproc`, `free`, `df`, `ps`, `/proc` and `/etc` files, `lscpu`, `lspci`, `nvidia-smi`,
  `which`, `ls` of standard directories, the IoT botnet openers and `busybox` probes, with
  `wget` and `curl` failing, all consistent with the scenario's host profile. A known
  command used with an option or file the shell does not handle gets that tool's own error
  (`invalid option`, `No such file or directory`) or no output; only an unknown command
  gets `command not found`. Then a prompt (see
  [architecture.md](architecture.md#deterministic-shell)). `exit` and `logout` end the
  session. If the persona's provider needs an API key and it is not set, no network attempt
  is made.
- Unknown SQL and API requests get protocol errors instead of model answers.
- Triage writes deterministic records for every SSH session and campaign. Download-and-
  execute, persistence, credential-file reads, hardware sizing for mining and honeytoken
  use still mark a session `MALICIOUS`.
- The tuner ranks candidates by frequency; detect uses its default titles.

## Data and retention

| Data | Location (Docker volume) | Pruned by the software |
|---|---|---|
| Event log | `frontend`: `/data/ssh_log.log` | no |
| Quarantine | `frontend` | no, but capped per file, per source and in total |
| Triage session and campaign records | `agentdata`: `/agents/reports/sessions/`, `/agents/reports/campaigns/` | yes, after `[agents] record_retention_days` (90) |
| Digests | `agentdata`: `/agents/reports/daily/` | no |
| Response run records, decided approvals | `agentdata` | yes, after `[respond] retention_days` (30) |
| Source-state snapshots | `agentdata`: `/agents/state/source-state-snapshots/` | yes: last `snapshot_keep` (200) plus anything younger than `snapshot_keep_days` (7) |
| Per-source state | `overlay` | entries expire; at most 10,000 |
| Approved blocklist | `agentdata`: `/agents/reports/blocklist/` | entries expire after `blocklist_ttl_days` (30) |
| Detection drafts | `agentdata`: `/agents/detections/pending/` | no |
| Blocklist candidates | `agentdata`: `/agents/detections/pending/blocklist-candidates.csv` | rewritten each detect run; rows past `expires` (`[agents] blocklist_expiry_days`, 14, or `blocklist_access_expiry_days`, 30) are left out |
| Event export cursor and failure events | `agentdata`: `/agents/state/ship_cursor.json`, `ship_events.jsonl` | the failure file is kept under 1 MB |
| Tracked list | `agentdata`: `/agents/reports/blocklist/tracked.json` | rewritten whole on every respond run while `track_before_enforce` is on; entries expire with the blocklist |
| Sightings and transfer state | `agentdata`: `/agents/state/sightings.json`, `tracked_export_state.json`, `sightings_fetch_state.json` | no; the sightings file is replaced by each good fetch |

Rotate the event log yourself, and only when nothing is pending. The summary of every
`triage`, `ship` and `run-all` run carries `log_rotation`: `{"safe": true}` when triage has
no unfinished or deferred items left in the log and the export has shipped everything;
otherwise `safe` is false, `pending` says what is waiting (bytes of the log still needed by
triage, events not yet exported), and the run logs `event log not safe to rotate yet`.
Rotating then would lose those sessions, campaigns or events. On a busy sensor some
campaign is usually still open (its window plus 10 minutes), so rotate after a run that
reports `safe`, for example in a quiet period or with the front-ends briefly stopped. The
triage cursor notices a new file (different inode) or a truncated one and starts from the
beginning. Prefer copy-and-truncate, because the SSH server keeps its log file open. Triage removes its own
session and campaign records after `record_retention_days`; delete digests on whatever
schedule your data policy sets.

Keep `sensor_seed` (on the `frontend` volume) across rebuilds: it determines all fake data
and honeytoken values. A new seed changes every honeytoken, so earlier tokens are no longer
recognised.

## Event export to S3

`python -m agents ship` copies the JSON-lines event log to an S3 bucket in a layout a SIEM
S3 reader can consume. `run-all` runs it as its last step when it is enabled. It runs only
in the agents process; the front-ends never connect out. It is off by default.

### Configuration

```ini
[connector.s3_events]
enabled = true
bucket = example-honeypot-events
prefix = events/                 ; default events/
region = us-east-1               ; optional; set it to the bucket's region
#bucket_owner = 123456789012     ; optional; sent as ExpectedBucketOwner
source = aws.honeypot            ; default aws.honeypot
layout = wrapped                 ; wrapped (default) or flat
passwords = hash                 ; hash (default), clear or drop
max_events_per_object = 5000
max_objects_per_run = 50
max_bytes_per_object = 5242880   ; 5 MiB
timeout = 10                     ; seconds, per connect and per read
```

Credentials come from the default AWS credential chain: the instance role or the
environment of the agents process. Nothing in the repository or in `config.ini` holds them.
In Docker the `agents` service is given `AWS_REGION` and nothing else. With an instance
role, containers reach the instance metadata service only if the IMDSv2 hop limit is at
least 2.

`python -m agents ship --dry-run` prints the object keys and counts it would write and
makes no call.

### Object layout

Keys are `<prefix>YYYY/MM/DD/HH-<epoch>-<sensor>-<n>-<random>.jsonl`. The date, hour and epoch
seconds are the time of the run in UTC, `<sensor>` is `[honeypot] sensor_name` (letters,
digits, `.`, `_` and `-`; anything else becomes `-`), `n` counts the objects written in
that run from 0 and `<random>` is 8 random hex digits, so two runs in the same second
never write the same key. Each object holds one JSON object per line, newline terminated:

- `wrapped`: `{"source": "<source>", "detail": {<event>}}`
- `flat`: the event itself.

An object closes at `max_events_per_object` events or `max_bytes_per_object` bytes. A run
writes at most `max_objects_per_run` objects; the rest waits for the next run.

### Delivery

Delivery is at least once. The export keeps its own cursor in the state directory
(`ship_cursor.json`), with the same rotation checks as the triage cursor (inode, a hash of
the first line, and the newline just before the offset). The cursor moves only after a
successful `PutObject`, so lines in an object that failed or was interrupted are sent again
in the next run, and a reader may see an event twice. Only complete lines are shipped; a
line still being written waits. Malformed lines, and a single line larger than
`max_bytes_per_object`, are skipped and counted. A rotated or
truncated log is shipped from its start.

A failed put is recorded in `ship_events.jsonl` in the state directory (error code only)
and reported in the run summary. It never stops triage or respond. The run holds the same
run lock as every other agents command that writes.

### Bucket policy

The client calls `PutObject` and nothing else: a hook on the client refuses every other
operation, including the `HeadBucket` the S3 region redirect can send when `region` is
wrong. That lets the bucket grant the sensor write access only. A generic example; replace
the account id, role and bucket names:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SensorWritesEventsOnly",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:role/example-honeypot-agents"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::example-honeypot-events/events/*"
    },
    {
      "Sid": "SensorReadsNothing",
      "Effect": "Deny",
      "Principal": {"AWS": "arn:aws:iam::123456789012:role/example-honeypot-agents"},
      "Action": ["s3:GetObject", "s3:ListBucket", "s3:DeleteObject", "s3:PutObjectAcl"],
      "Resource": ["arn:aws:s3:::example-honeypot-events",
                   "arn:aws:s3:::example-honeypot-events/*"]
    },
    {
      "Sid": "TlsOnly",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::example-honeypot-events",
                   "arn:aws:s3:::example-honeypot-events/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }
  ]
}
```

With `bucket_owner` set, a put to a bucket owned by any other account fails. Write access
still lets a compromised sensor overwrite objects whose keys it knows; turn on bucket
versioning or Object Lock if the archive must be tamper-evident.

### Passwords

`passwords` controls every field that can carry a submitted password or secret: the
`password` field of auth attempts on every protocol (SSH, Telnet, FTP, SMTP AUTH, Redis
AUTH, HTTP basic, bearer, API key and form logins, SIP, MySQL, PostgreSQL, MSSQL), SIP
digest responses and recovered INVITE passwords, MySQL and PostgreSQL challenge responses,
HTTP request bodies and unparsed `Authorization` values, the FTP `PASS` line, Redis
`AUTH`, `HELLO ... AUTH`, `MIGRATE` and `CONFIG SET requirepass` input, captured HTTP
bodies and FTP `PASS` lines, and any client-named field whose name looks like a password
(for example a PostgreSQL startup parameter called `password`). The list is in
`agents/ship.py` (`SECRET_FIELDS`); a test fails when an event gains a password-like
field that is not classified. SSH command input (base64 `details`) and SQL statements are
not treated as password fields.

- `hash` (default): each value becomes `sha256:<hex>`, an HMAC-SHA256 keyed with a value
  derived from the sensor seed. Equal passwords on one sensor give equal hashes, so reuse
  and spraying still show up, but a table of plain SHA-256 hashes of common passwords
  does not reverse them, and hashes from different sensors do not match. Without a sensor
  seed nothing is shipped.
- `drop`: the fields are removed.
- `clear`: values are shipped as captured.

Hashing is the default because the bucket and the SIEM behind it are read by more people
and systems than the sensor. Submitted passwords are often real: reused credentials from
breaches, or a person who reached the trap by mistake and typed their own password. The
hash keeps the correlation value without copying those secrets into another system. Anyone
holding the sensor seed can still test guesses against the hashes, so the seed stays on the
front-end volume.

## Tracked list and sightings

With `[respond] track_before_enforce = true`, approving a blocklist entry only tracks it,
and blocking it is a second decision. The stages, the `enforce` command and what happens
to existing entries are in [playbooks.md](playbooks.md#track-before-enforce). This section
covers the two files that connect the tracked list to the rest of your environment:

- **Out:** `tracked.json`, written by respond next to the blocklist file. Your cloud can
  watch it. `[connector.tracked_export]` sends it.
- **In:** `sightings.json`, written by your environment: where else it saw a listed
  address. The console shows it next to each entry. `[connector.sightings]` can fetch it.

Both transfers are off by default. They run in the agents process only, in
`python -m agents ship` and at the end of `run-all`.

### Turning it on

1. Set `[respond] track_before_enforce = true` (and `queue_enforce = true`, without which
   nothing is queued) and restart the services. Entries already on the blocklist stay
   enforced.
2. Approve an `export_blocklist` item. It appears in `tracked.json`
   (`reports/blocklist/tracked.json` by default) and as Tracked on the console's blocklist
   screen. Nothing is blocked.
3. Optional: enable `[connector.tracked_export]` so your cloud can read the list. Check it
   with `python -m agents ship --dry-run`.
4. Optional: have your environment produce the sightings document, and either write it to
   `[sightings] path` or enable `[connector.sightings]` to fetch it.
5. When you decide to block an entry: `python -m agents enforce 198.51.100.7`, or Enforce
   on the console with [actions on](#turning-actions-on).

### Tracked export

```ini
[connector.tracked_export]
enabled = true
kind = s3                          ; s3 or https
#file = /blocklist/tracked.json    ; default: tracked.json next to the blocklist file
# kind = s3: PutObject of one key
bucket = example-honeypot-events
key = tracked/tracked.json
region = us-east-1
#bucket_owner = 123456789012
#endpoint_url = https://s3.example.com
# kind = https: one PUT or POST
#url = https://intel.example.com/api/tracked
#method = PUT
#secret_file = /run/secrets/tracked-token
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | false | |
| `kind` | none | `s3` or `https`; required |
| `file` | `tracked.json` next to `[respond] blocklist_file` | absolute path to read the document from, for a process that does not see the agents' reports directory |
| `bucket`, `key` | none | `s3`: the one object written; required |
| `region` | none | `s3`: the bucket's region; with `endpoint_url`, the store's own region name |
| `bucket_owner` | none | `s3`: 12-digit account id, sent as `ExpectedBucketOwner` |
| `endpoint_url` | none | `s3`: another store that speaks the S3 API; `https` only |
| `url` | none | `https`: the destination; required |
| `method` | `PUT` | `https`: `PUT` or `POST` |
| `secret_env`, `secret_file` | none | `https`: bearer token from an environment variable, or from a file (absolute path, read at each call); one or the other |
| `header` | `Authorization` | `https`: the header that carries the token |
| `max_per_day` | 200 | `https`: sends per day |
| `timeout` | 10 | seconds, at most 30 |
| `allow_private` | false | allow a private or loopback `endpoint_url` or `url` |

- The document is sent whole when its content (everything but `generated_at`) differs from
  the last copy stored (a hash in `<state-dir>/tracked_export_state.json`), so a removal or
  an expiry reaches the remote copy on the next run, and at least once every 24 hours
  otherwise, so the remote `generated_at` shows the sensor is still exporting.
- Before sending, the file is checked to be a tracked export of at most 8 MiB.
- `kind = s3` writes exactly one object with `PutObject`. As with the event export, a hook
  on the client refuses every other operation, bucket and key before a request is sent, so
  the sensor needs `s3:PutObject` on that one key and nothing else. Credentials come from
  the default AWS credential chain, never from `config.ini`. `endpoint_url` must be
  `https`, and a private address or `localhost` in it is refused at load unless
  `allow_private` is set. The S3 client resolves the name itself on each call, so unlike
  the HTTP connectors the address is not pinned.
- `kind = https` follows the [connector rules](playbooks.md#connectors): `https` only,
  public destinations unless `allow_private`, the address resolved and pinned per call, no
  redirects, timeouts, a response cap and the daily cap.
- A failure is logged, recorded in `ship_events.jsonl` (shown in the Event export row of
  the console's overview) and tried again on the next run. It never stops the event
  export or the rest of the run.

On AWS, see [deploy/aws/README.md](../deploy/aws/README.md) for running the tracked export
from the exporter container.

### Sightings

Your environment writes one JSON document, by any means it likes:

```json
{
  "version": 1,
  "generated_at": "2026-11-18T09:00:00Z",
  "sightings": [
    {
      "address": "198.51.100.7",
      "where": "prod",
      "service": "tcp/443",
      "first_seen": "2026-11-17T22:10:00Z",
      "last_seen": "2026-11-18T08:55:00Z",
      "count": 14,
      "source": "flow logs"
    },
    {
      "address": "2001:db8:4:5::1f",
      "where": "staging",
      "service": "tcp/22",
      "first_seen": "2026-11-16T03:00:00Z",
      "last_seen": "2026-11-16T03:40:00Z",
      "count": 3,
      "source": "threat-list finding"
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `version` | 1 |
| `generated_at` | when the producer wrote it; ISO 8601, UTC if no zone is given |
| `sightings[].address` | an IPv4 address, or an IPv6 address or /64; IPv6 is matched by its /64 |
| `where` | where it was seen, a short label of your choosing |
| `service` | what it reached, for example `tcp/443` |
| `first_seen`, `last_seen` | ISO 8601; `first_seen` not after `last_seen` |
| `count` | a non-negative integer |
| `source` | what reported it, for example `flow logs` |

The file is untrusted and checked strictly. The whole file is refused on the first
problem: over the size or entry cap, a wrong type, an invalid address or timestamp, a
negative or non-integer count, a string over 256 characters. Strings are cut to 64
characters with control and other
invisible characters removed. Unknown keys are ignored. Sightings of addresses that are
not on the list are ignored.

```ini
[sightings]
#path = /agents/state/sightings.json   ; default: sightings.json in the state directory
max_bytes = 1048576
max_entries = 5000
stale_hours = 48

[connector.sightings]
enabled = true
kind = s3                              ; s3 or https
interval_minutes = 15
bucket = example-honeypot-events
key = sightings/sightings.json
region = us-east-1
#url = https://intel.example.com/api/sightings
#secret_env = WINNIE_SIGHTINGS_TOKEN
```

| Key | Default | Meaning |
|---|---|---|
| `[sightings] path` | `<state-dir>/sightings.json` | absolute path of the local file the console reads |
| `max_bytes` | 1048576 (1 MiB) | larger files are refused; at most 16 MiB |
| `max_entries` | 5000 | more sightings than this and the file is refused; at most 100,000 |
| `stale_hours` | 48 | the console marks the file stale when `generated_at` is older than this |
| `[connector.sightings] enabled` | false | |
| `kind` | none | `s3` (`GetObject` of one key) or `https` (`GET`); required |
| `interval_minutes` | 15 | fetch at most this often, 1 to 1440 |

The other `[connector.sightings]` keys are those of the tracked export: `bucket`, `key`,
`region`, `bucket_owner`, `endpoint_url` for `s3`; `url`, `secret_env` or `secret_file`,
`header`, `max_per_day` for `https`; `timeout` and `allow_private` for both. The `s3`
client is its own, guarded to `GetObject` of that one key. An `https` response may be as
large as `max_bytes`.

How it is used:

- **Display only.** Nothing acts on a sighting. It never triggers enforcement.
- **Fetch.** The local file is replaced atomically, and only by a copy that passed the
  checks. A failed or refused fetch keeps the local file, is logged (the same refused copy
  only once), is recorded in `ship_events.jsonl` and is tried again when next due.
- **A refused local file.** The console keeps showing the last good copy it read, marks the
  file refused and logs the problem once. The good copy is held in memory, so after a
  console restart a refused file shows no sightings until a good one arrives.
- **Stale.** A file older than `stale_hours` is still shown, marked stale.

On the console's blocklist screen, when the switch is on or any entry is tracked, each
entry shows its status (Tracked or Enforced), since when, its expiry and its sightings:
total count, number of places, last seen, and a small table of where, service, count, last
seen and source ("No sightings yet" when there are none). A line above the list gives the
sightings file's age and the stale and refused markers. With actions on, a tracked entry
has Enforce next to Unblock. Its confirmation says which files change and whether the
block connector will be called, and the request carries a hash of the entry as shown, so an
entry that changed or expired since the page loaded is refused. With the switch off and no
tracked entries the screen is as before.

### Using this with your cloud

The contract is the two JSON documents above: the tracked export going out and the
sightings document coming in. Anything that can read one object and write another can take
part. This repository has no adapter for any cloud, so every row below is a likely shape,
not something that has been tested.

| Platform | Out: the tracked export feeds | In: sightings come from | Status |
|---|---|---|---|
| AWS | `kind = s3` to a bucket; a scheduled job you own turns it into a managed threat list, for example a GuardDuty threat list, or a watch rule in your SIEM | GuardDuty findings, VPC flow logs or load balancer logs, summarised by a scheduled job into `sightings.json` in a bucket; `[connector.sightings] kind = s3` | not tested |
| Azure | `kind = https` to an endpoint you run, which loads it into a Microsoft Sentinel watchlist or threat-intelligence import | Sentinel or Defender alerts, or network flow logs, summarised by a scheduled job and served over `https` | not tested |
| Google Cloud | `kind = https` to an endpoint you run, or `kind = s3` with `endpoint_url` if your bucket offers an S3-compatible endpoint; loaded into a Security Command Center or Chronicle reference list | Security Command Center findings or VPC flow logs, summarised by a scheduled job | not tested |
| Self-hosted or S3-compatible store | `kind = s3` with `endpoint_url` (and `allow_private` for an internal one) | any job that writes `sightings.json` to the same store | not tested |

Things to hold on both sides:

- **The producer decides what the sensor learns.** The sensor is a machine attackers are
  invited to probe. Assume whoever takes it over reads the sightings file. Write the
  minimum: only addresses that are on the tracked list, a coarse `where` (an environment
  label such as `prod`, never a host name, an internal address or an account id), the
  service as protocol and port, counts and times. Leave out anything you would not hand to
  the attacker.
- **The consumer owns the conversion.** A list built from the tracked export is evidence
  from an exposed host. Apply the rules in [Using the intelligence outside the
  sensor](#using-the-intelligence-outside-the-sensor): validate every entry, check an
  allow-list, cap the size and honour `expires_at`. A watch list or threat list that alerts
  fits the tracked stage; blocking belongs to enforced entries only, if at all.
- **One object each way.** Give the sensor write access to the one export object and read
  access to the one sightings object, nothing else, and no credentials for the systems the
  lists feed.

## Where addresses are

The console and the digest can show where a source address is: country, region, city and
the network that owns it (AS number and name), for example
`198.51.100.7 · Frankfurt, Germany · AS64500 Example Cloud`. The answer comes from database
files you put on disk. Nothing is looked up over the network: the containers have no
internet access, and this feature does not change that. Reverse DNS names are not shown;
they need a live query.

It is off until you set a path. With the files or the `maxminddb` package missing, it
stays off and everything else works as before; the agents and the console each log one
line at start saying whether it is on, with each file's build date, or why it is off.

### Getting a database

Two free sources work, in MaxMind's `.mmdb` format. Use either, or one of each:

- **DB-IP Lite** (no account): "IP to City Lite" and "IP to ASN Lite" in MMDB format from
  db-ip.com, updated monthly. Licensed CC BY 4.0: wherever the results are shown you must
  credit DB-IP with "IP Geolocation by DB-IP" and a link to db-ip.com. Set `attribution`
  (below) and the console shows it in its footer.
- **MaxMind GeoLite2** (free account and licence key): "GeoLite2 City" and "GeoLite2 ASN".
  The GeoLite2 licence applies, including its attribution requirement and keeping the files
  up to date; read it before you use them.

Download on a machine with internet access, never from inside the sensor's containers,
then copy the files to the sensor host.

### Turning it on

Put the files in a `geoip` directory next to `docker-compose.yml`, uncomment the
`./geoip:/geoip:ro` lines under the `agents` and `ui` services, and add to `SSH/config.ini`:

```ini
[geoip]
city_db = /geoip/dbip-city-lite.mmdb
asn_db = /geoip/dbip-asn-lite.mmdb
attribution = IP Geolocation by DB-IP (db-ip.com)
```

Paths are as the containers see them and must be absolute. Either key alone works. The image
installs `maxminddb` (the `geoip` extra in `pyproject.toml`); without Docker,
`uv sync --extra geoip`. `*.mmdb` and `geoip/` are in `.gitignore`: never commit them.

### What it changes

- Each new triage record stores what the lookup said when it was written (`src_geo`:
  country code and name, region, city, AS number and owner, and the build date of each
  file), so the record keeps what was true at the time. Older records get a lookup when
  shown, and the record page says which ("when recorded" or "looked up now").
- The console shows it after the address on the overview's top sources and honeytoken
  hits, the records list (with a country filter), the record page (the Who line and the
  campaign's source addresses), approval cards, the blocklist and tracked list, the decoy
  screen's per-source state and the activity screen.
- The digest's Who line carries the same short form.
- Exports and notifications do not change.

Private, loopback, link-local, shared (CGNAT), documentation, multicast and reserved
addresses are labelled ("private address") without a lookup. A network wider than /24
(IPv4) or /48 (IPv6) is not looked up.

### Refreshing

Download the new release, copy it next to the old file and rename it into place
(`mv dbip-city-lite.mmdb.new dbip-city-lite.mmdb`). Both processes check the files about
once a minute and switch to the new copy without a restart. Overwriting the file in place
works too but can give odd answers for up to a minute, so prefer the rename. On AWS the
host has no path to fetch these files; see the deployment README.

## What Shodan already knows about a source

The console can show what Shodan's public InternetDB already holds about an interesting
source address: open ports, host names, tags (for example `vpn`, `scanner`, `cloud`), CPEs
and known vulnerability ids. On the record page and the overview's top sources (and the
decoy screen's per-source list) it is one line under the address, for example
`Shodan: ports 22, 80, 8080 · tags vpn · 3 known CVEs · host a.example.net`, which opens to
the full lists, the lookup date and a "Data from Shodan InternetDB" credit. Shodan collects
this on its own schedule (refreshed weekly), so the source never sees the lookup.

It is off by default. Off, unreachable or rate limited, everything else works as before.

### Terms of use

InternetDB needs no account or key. Shodan's terms: free for non-commercial use; a company
may use it internally, but not to build a product it charges for (that needs a Shodan
enterprise licence). Check that your use fits before you turn it on.

### What is sent, and from where

- One HTTPS GET per address to `https://internetdb.shodan.io/<address>`, with the address
  in the path and nothing else: no cookies, no key, a generic user agent
  (`internetdb-client/1`), nothing about what the source did. The host is fixed in the code;
  the configuration cannot point it anywhere else. The certificate is verified, redirects
  are not followed, each call has a 5 second deadline and the answer is capped at 64 KB.
- It runs in the `agents` container as part of `run-all` (and `python -m agents ship`),
  next to the sightings fetch. The honeypot containers never make it and gain no network
  access. The results go to `<state-dir>/internetdb.json`, which triage and the console
  read; no new connection between containers.
- Which addresses: the single source address of triage records seen in the last 7 days
  that were judged SUSPICIOUS or MALICIOUS or used a honeytoken, most important first.
  Never an unverified UDP source, a private or other non-global address, a campaign's
  network, or an address inside `[respond] never_act_on` (list your own and allow-listed
  addresses there). With a `never_act_on` that does not parse, nothing is looked up.
- Pacing: one request at a time, at least a second apart, at most 100 per run and 2000 per
  UTC day. An answer, including "no information", is kept 7 days. A 429, a server error, a
  redirect or a network failure stops the run and backs off for 15 minutes, doubling up to
  a day. The file keeps at most 5000 addresses, oldest dropped first.

### The answer is data

Host names come from reverse DNS and certificates, so an attacker can choose them. Each
value is checked before it is kept: ports are integers from 1 to 65535 (at most 50),
host names use only letters, digits, hyphens and dots, at most 253 characters (at most
10), tags and CPEs a short, conservative character set (at most 20 each), and
vulnerability ids must look like `CVE-2024-12345` (at most 50). Anything else is dropped,
and an answer that is not a JSON object for the address asked about is not kept. The
file is checked the same way again when read. It is display only: nothing acts on it, it
is never put into a model prompt, and the console shows it as plain text.

### Turning it on

```ini
[connector.internetdb]
enabled = true
```

The other keys (`max_per_run`, `max_per_day`, `min_interval_seconds`, `cache_days`,
`lookback_days`, `max_entries`) are in `SSH/config.ini.TEMPLATE` with their defaults. In
`docker-compose.yml` the `agents` service already has outbound access; if you filter its
egress, allow tcp 443 to `internetdb.shodan.io` (it is served from Cloudflare, so its
addresses are shared and can change). `python -m agents ship --dry-run` says how many
addresses would be looked up without sending anything.

### What it changes

- Each new triage record stores what the file held for its source when it was written
  (`src_shodan`, with the lookup date). The lookup runs at the end of a run, after triage,
  so a source's first record usually has none stored; the console then shows the file's
  current answer, marked "latest lookup" rather than "when recorded".
- Records written with the feature off are byte-for-byte as before. The digest, exports,
  notifications, approval cards and their `view_hash` do not change.
- On the AWS deployment the agents container never asks InternetDB; use delivered answers
  or the exporter's own lookups (below); see its README.

### Delivered answers

Some sensors must not reach InternetDB at all: on AWS the agents container has no egress,
and InternetDB sits behind a shared CDN, so no firewall rule can let the sensor reach it
without also reaching every other site there. Delivered mode moves the lookup off the
sensor. The sensor never makes a request to InternetDB; only two small files move, through
the object store the sensor already writes to.

```ini
[connector.internetdb]
enabled = true
mode = delivered            ; direct (the default) | delivered

[connector.internetdb_exchange]   ; in the process that has the store credentials
enabled = true
kind = s3
bucket = example-honeypot-events
wanted_key = events/internetdb/wanted.json
answers_key = internetdb/answers.json
#region, bucket_owner, endpoint_url, interval_minutes = 15, max_bytes, max_entries
```

1. `run-all` writes the wanted list: the addresses a direct lookup would choose (same
   selection, same `never_act_on` rule), most important first, at most `max_wanted`
   (default and limit 500), to `internetdb_wanted.json` next to the blocklist file (or
   `wanted_file`). Written atomically, owner only, on every run.
2. The exchange (`ship`, or the end of `run-all`) puts that list to `wanted_key` when its
   addresses changed and at least once a day. It is checked first and rebuilt from the
   checked addresses, so nothing else in the local file can leave, and `never_act_on` is
   applied again.
3. Something outside the sensor reads the list, asks InternetDB and writes the answers to
   `answers_key`. [`deploy/aws/internetdb_lookup.py`](../deploy/aws/internetdb_lookup.py) is
   a reference: one file, standard library plus boto3, runnable as a Lambda function or by
   hand.
4. The exchange gets the answers object (one GetObject of one key, at most once per
   `interval_minutes`, at most `max_bytes`), checks it (below) and merges what passes into
   `answers_file` (default `<state-dir>/internetdb.json`), the file triage and the console
   already read. Everything after that works as in direct mode.

On one host, one config does all of it. On AWS the agents container writes the list and the
exporter moves both files; the deployment README has the wiring.

**The wanted list** (sensor to store):

```json
{"version": 1, "generated_at": "2026-11-20T12:00:00+00:00",
 "addresses": ["198.51.100.7", "2001:db8::5"]}
```

Addresses only, in canonical form, no duplicates, at most 500. Nothing about what a source
did.

**The answers object** (store to sensor):

```json
{"version": 1, "generated_at": "2026-11-20T12:05:00Z",
 "answers": [
   {"ip": "198.51.100.7", "checked_at": "2026-11-20T12:04:10Z", "status": "found",
    "ports": [22, 80], "hostnames": ["a.example.net"], "tags": ["vpn"],
    "cpes": ["cpe:/a:openbsd:openssh:7.4"], "vulns": ["CVE-2017-15906"]},
   {"ip": "2001:db8::5", "checked_at": "2026-11-20T12:04:11Z", "status": "not_found"}]}
```

A found answer is InternetDB's own answer body plus `checked_at` and `status`; `not_found`
is what a 404 means. Rules, in the order the sensor applies them:

- The whole object is refused (the local answers stay as they were, logged once per bad
  copy) when it is larger than `max_bytes` (default 4 MB), not UTF-8 JSON, not an object
  with `"version": 1`, has no `answers` list, or has more than `max_entries` answers
  (default 1000).
- Each answer is then checked on its own and dropped on any problem:
  - `ip` is a string in canonical form (`2001:db8::5`, not `2001:DB8::5`), a single global
    address, outside `[respond] never_act_on`, and either on the current local wanted list
    or already held in `answers_file`. Answers for addresses the sensor never asked about
    are dropped.
  - `checked_at` is an ISO 8601 time (no zone means UTC), at most five minutes in the
    future, no older than `max_age_days` (default 30), and newer than the answer already
    held for that address (an older or equal one is skipped, not counted as bad).
  - `status` is `found` or `not_found`.
  - For `found`, `ip`, `ports`, `hostnames`, `tags`, `cpes` and `vulns` go through exactly
    the check a direct answer gets (see "The answer is data" above), with the lookup date
    taken from `checked_at`.
- Unknown keys are ignored (the reference producer keeps its own state under `producer`).
- The local file keeps at most `max_entries` addresses of `[connector.internetdb]`, oldest
  dropped first.

With `kind = s3` the direct-mode keys (`max_per_run`, `max_per_day`, `min_interval_seconds`,
`cache_days`) do nothing; pacing is the producer's job. The reference producer uses the
same defaults: at most 100 lookups a run and 2000 a day, a second apart, answers fresh for
7 days, back-off on 429, 5xx or network failure. With `kind = lookup` (next) they apply to
the exporter's own lookups.

### The exporter asks InternetDB

The third way needs nothing outside the sensor and no object store. The agents side does
not change at all: it stays `mode = delivered`, writes the wanted list and reads
`answers_file`. The exchange step (`ship`, in the process that has egress) reads the wanted
list, asks InternetDB itself and writes the checked answers to `answers_file`.

```ini
[connector.internetdb]
enabled = true
mode = delivered

[connector.internetdb_exchange]   ; in the exporter's config only
enabled = true
kind = lookup
#addresses_file = /egress/internetdb-addresses   ; connect only to these (AWS sets it)
```

- The wanted list is treated as untrusted input: the same check as the `s3` kind (read up
  to 64 KB, version 1, at most 500 distinct canonical global addresses or the whole file is
  refused, other keys ignored, `never_act_on` applied again). Only an address from it goes
  into a request, in the path of the fixed URL; nothing in the file can change the host,
  the headers or anything else sent.
- The lookups are the same code as direct mode: the fixed host, certificate checked, no
  redirects, 5 s deadline, 64 KB cap, one at a time at least `min_interval_seconds` apart,
  `max_per_run` and `max_per_day`, answers (including "not found") fresh for `cache_days`,
  back-off on 429, 5xx or a network failure, and the same check of every answer.
- The exporter keeps its cache, day count and back-off in its own state directory
  (`<state-dir>/internetdb_lookup.json`). On AWS the agents container cannot write it.
- Answers reach `answers_file` through the same check as an answers object from the store,
  so the file has exactly the shape the `s3` kind writes.
- Unreachable, refused by a firewall or rate limited: the event export, the tracked export
  and sightings carry on; the reason is in the run result (`internetdb.exchange`).
- `addresses_file` (optional): a file of IPv4 addresses, one per line, at most 8. When set,
  a lookup connects only to one of them (the first the name resolves to, else the first
  listed), still checking the certificate for `internetdb.shodan.io`. On AWS the host
  firewall writes it (see the deployment README). With the file set but empty or missing,
  nothing is looked up.
- `python -m agents ship --dry-run` reports how many addresses would be looked up.

**Which of the three.** Direct when the process that triages may reach the internet (a
single host you run yourself). The exporter's lookups when that process must stay without
egress but the exporter may reach InternetDB (the AWS deployment with `InternetDbLookup`).
Delivered through the object store when nothing on the sensor may reach InternetDB, or you
want the lookups to come from another network (`InternetDbDelivered` and a producer such as
the reference Lambda function).

## Indicators to OTX

The sensor can give confirmed indicators back to the community as an AlienVault OTX pulse:
the addresses of sources that did real harm, and the SHA-256 of files they uploaded. It is
off by default, and even when turned on it only writes what it would send to a file until
you turn sending on.

**A public pulse is public.** Anyone can read it, so it shows that whoever owns the OTX
account runs a honeypot, and roughly when each listed source hit it (the pulse is one per
UTC day). Sources that check OTX can learn that the sensor's own traffic is being
reported. The pulse is private (`public = false`) unless you change that.

### What is sent, and what is not

Only indicators from a source whose address is proven **and** that did something past
probing. Proven: not `unverified_source`, so the address completed a TCP exchange or a SIP
nonce round trip. Past probing, from facts the code counted (never from model output):

| Class | Meaning |
|---|---|
| `logged_in` | an accepted login, or an accepted SIP REGISTER |
| `honeytoken` | used a planted credential |
| `download_execute`, `persistence`, `credential_file_read`, `hardware_recon` | ran commands that do these |
| `redis_takeover`, `sql_exec_attempt`, `sql_cred_dump` | took over a service or ran commands through it |
| `smtp_relay_attempt`, `sip_dialed_number` | tried to relay mail or place outside calls |
| `s3_bulk_download`, `s3_upload`, `s3_planted_key`, `ftp_upload`, `quarantine_quota` | took or uploaded files, or used a planted storage key |

Failed logins alone, `ftp_active_mode` and `http_proxy_attempt` (probes scanners send) do
not count. A record the model judged BENIGN is not sent: the model can hold a source back
but never put one forward.

Two indicator types, nothing else:

- `IPv4`: the source address, global unicast only.
- `FileHash-SHA256`: the hash of a file such a source uploaded, as the front-end computed it
  while storing the file in the quarantine (read from the quarantine's own metadata, never
  from attacker text). A file that reached the quarantine's per-file cap may have been cut,
  so its hash is left out. `hashes = false` turns these off.

No URLs, domains, commands, passwords, user names, user agents or anything else the
attacker wrote: an attacker could name an innocent host to get it listed. Each indicator's
title and description are fixed text plus the protocol and class names, for example
"Source address seen on a honeypot over SSH. Logged in or registered; Tried to fetch a file
and run it."

Never sent: an address inside `[respond] never_act_on` (list your own and allow-listed
addresses there), a private or other non-global address, the sensor's own address
(`[listeners] ftp_pasv_address`, which the AWS deployment sets to the Elastic IP), an
unverified UDP source, and IPv6 addresses (not in this version). The check runs when the
candidates are written and again when they are read. With a `never_act_on` that does not
parse, nothing is sent.

### How it runs

1. `run-all` (it has the triage records) writes the candidates to `otx_candidates.json` next
   to the blocklist file: addresses, hashes, protocol and class names, timestamps. Records
   seen in the last 7 days, at most 1000 indicators and 256 KB (when they do not
   fit, hashes go before addresses, the oldest first).
2. `ship` (or `run-all` when `submit = true`) reads that file with the same care as the
   InternetDB wanted list: a regular file only (no FIFO, no symlink), at most 256 KB, every
   field checked, the whole file refused on any problem. It adds what it has not sent
   before to the day's pulse: `POST /api/v1/pulses/create` the first time in a UTC day,
   `PATCH /api/v1/pulses/<id>` with the new indicators after that.

The request goes to `https://otx.alienvault.com` only (fixed in the code), with the
certificate and name checked, no redirects, no proxy, a 15 second deadline and a 1 MB
answer cap. At most 200 indicators per run (one request) and 1000 per UTC day. A 429, a
server error, a redirect, a refused key, any other unexpected status or a network failure
stops the run and backs off for 15 minutes, doubling up to a day. If the day's pulse was
deleted on OTX, the next run creates a new one. Only the new pulse's id is read from an
answer, and only when it is 24 letters or digits.

Every indicator sent is remembered in `<state-dir>/otx_state.json` (at most 20000, and never
more than the 8 MB the state reader accepts; oldest dropped first), so nothing is sent
twice. Each run adds one `otx_submit` event with the counts (sent, failed, skipped as
already sent, excluded, hashes off or over the cap) to `<state-dir>/ship_events.jsonl`. A failure never stops the event export or the other
stages.

### Turning it on

Make an OTX account, copy its API key from the settings page, and keep it out of
`config.ini`:

```ini
[connector.otx]
enabled = true
secret_env = WINNIE_OTX_KEY       ; or secret_file = /run/otx-key (one line)
#tags = honeypot
#tlp = green                      ; white | green | amber | red
#public = false
#expiration_days = 30
```

With only that, it runs **dry**: each run writes the request it would make, with the
indicators, to `<state-dir>/otx_dry_run.json`, and sends nothing (no key is read). Read
that file. When it is what you want to share, set `dry_run = false`. The indicators held
back during the dry run are sent then, within the caps. `python -m agents ship --dry-run`
reports how many would be sent and writes nothing.

The key is read only when a request is about to be sent. It is never logged and never
written to the state, the dry-run file, the events or an error message.

A process that must not send (the agents container on AWS) gets `submit = false`: it
writes the candidates and does nothing else. The process that sends needs tcp 443 to
`otx.alienvault.com`. `addresses_file` limits it to the addresses listed there, as for the
exporter's InternetDB lookups; on AWS the host firewall writes it.

## Using the intelligence outside the sensor

The sensor produces addresses and indicators: `detections/pending/blocklist-candidates.csv`,
Sigma drafts, the approved blocklist file (`[respond] blocklist_file`), the tracked list
(`tracked.json`) and, with export on, the raw events. Feeding any of them into a firewall,
a WAF, a session border controller, a SIEM or a paging system happens outside the sensor's fences, and a mistake there blocks or
wakes up the wrong people. The guidance below applies to all of them, including the
approved blocklist: a person approving an entry does not make the entry's source more
trustworthy.

- **Act only on proven sources.** Use candidate rows with `source_proven` set to `yes`, and
  events that pass the [source proof](architecture.md#source-proof) filter (`transport`
  is `tcp`, or `data.source_verified` or `data.nonce_verified` is `true`). A UDP source
  address is whatever the sender wrote, so an unproven address may belong to a bystander
  the attacker picked. Acting on it lets anyone choose whom you block.
- **Expire entries.** Honour `expires` in the candidate file, and give anything you derive
  from raw events an expiry of its own. Attack traffic comes mostly from rented servers,
  residential proxies and compromised devices whose addresses change hands. A permanent
  entry ends up blocking whoever holds the address next, and nobody remembers why it is
  there.
- **Keep an allow-list and check it before listing.** List your carriers and SIP trunks,
  offices and VPN egress, monitoring and uptime checks, the scanners you pay for, and your
  customers' known addresses. Check it before an address goes onto any list, not after a
  complaint. The sensor is on the internet and sees some of your own traffic, and an
  attacker can provoke it into listing an address you depend on. A block on a carrier or a
  monitor is an outage you caused.
- **Check whether the address was already a successful caller.** Before acting, look the
  address up in the logs of your real services: authenticated logins, completed calls,
  normal API use, from before it first appeared on the sensor. If it was, never page or
  block on it automatically; send it to a person. It may be a customer behind shared NAT,
  a customer's compromised device, or a forged source aimed at you. Each of those needs a
  different response, and none of them is an automatic block.
- **Cap list size.** Give every list a maximum number of entries, and when it is full,
  stop adding and alert instead of evicting older entries. An attacker with many proven
  addresses (a botnet is enough) can generate entries faster than you review them. If new
  entries push out old ones, a flood evicts the real entries you meant to keep; if nothing
  is capped, the list can exhaust a firewall's rule table or slow every lookup.
- **Start any block in count or review mode.** A new rule or list should first log or count
  what it would have dropped, for long enough to see real traffic against it, before it
  drops anything. A wrong entry in count mode costs a log line; in block mode it costs a
  customer, often silently.
- **Prefer detection to blocking for services you do not expose.** If the sensor emulates a
  service you do not run on the internet (Redis, S3, a database port), blocking listed
  addresses on that service protects nothing. Alert instead when a listed address appears
  in your real logs on any service. That match is rare and worth a look, and it costs
  nothing when the entry is wrong.
- **Treat the sensor as possibly compromised.** The sensor exchanges data with attackers
  all day, so plan for the day its output is wrong or written by someone else. A list
  derived from its events is evidence for a person or a correlating system to weigh, not
  an authority your enforcement trusts directly. In practice: have the receiving side pull
  from the sensor rather than letting the sensor push into enforcement; give the sensor no
  credentials for your firewalls, WAF or SIEM rules; validate every entry on the receiving
  side (address syntax, not on the allow-list, within the size cap, has an expiry); and
  keep a way to remove everything that came from the sensor in one step.

## Running agent commands in Docker

The agents CLI defaults to paths inside the repository, which do not exist in the
container. Pass the same directories the scheduled loop uses:

```bash
dc="docker compose -p winnie-lab -f docker-compose.yml -f docker-compose.lab.yml"
args="--config /config/config.ini --data-dir /data --reports-dir /agents/reports \
  --state-dir /agents/state --detections-dir /agents/detections"

$dc exec agents python -m agents queue $args
$dc exec agents python -m agents approve a-0123456789ab --by alice $args
$dc exec agents python -m agents tune --history $args
$dc exec agents python -m agents tune --rollback 3 $args
$dc exec agents python -m agents run-all --dry-run --log /data/ssh_log.log $args
$dc exec agents python -m agents ship --dry-run --log /data/ssh_log.log $args
```

## Operator console

`python -m agents ui` is a local web console over the same files the CLI reads. It shows:

- an overview and pipeline health;
- the response approval queue;
- triage records, with SSH transcript replay and the decoy's reply under each command; a
  record's narrative is laid out in parts (headline, who, volume, target, what they did,
  what it means, not seen) on the record page, the overview and the queue, and the records
  table shows the headline; records written before the parts existed show their paragraph;
- raw activity: every event in the log, any service, with filters and search;
- daily digests;
- how the decoy is being adjusted (Decoy);
- playbooks and detections.

It is read-only by default. It never calls a model and never shows configuration or
secrets. The CLI commands keep working alongside it: the console only reads the files the
pipeline writes, and its decisions (with actions on) go through the same functions as the
CLI's, so you can use either at any time.

The console shows what the agents have produced; it does not triage anything itself. On a
fresh host, or after the agent volumes are lost, Overview, Queue, Records and Digests stay
empty until the first `run-all` pass finishes. The `agents` service runs one when it
starts and then every `RUN_ALL_INTERVAL_SECONDS` (an hour by default). To run one now, use
`run-all` without `--dry-run` as in [Running agent commands in
Docker](#running-agent-commands-in-docker):

```bash
$dc exec agents python -m agents run-all --log /data/ssh_log.log $args
```

### Starting it

Without Docker, from the repository root (same default paths as the other commands; pass
`--config`, `--log`, `--data-dir`, `--reports-dir`, `--state-dir` and `--detections-dir` to
point it elsewhere):

```bash
python -m agents ui
```

With Docker, from the same directory as the rest of the stack:

```bash
docker compose --profile ui up -d ui
```

The `ui` service is off unless the profile is named. It uses the agents' image and
directories, mounts every volume read-only, gets no model key, AWS setting or connector
secret, and is on a network of its own, so the honeypot containers cannot reach it.

Options: `--bind` (default 127.0.0.1), `--port` (default 8480), `--actions`, `--by NAME`,
`--external-host NAME` (see [below](#reaching-it-over-a-private-network)). The same settings
can go in `config.ini`:

```ini
[ui]
port = 8480
bind = 127.0.0.1
actions = false
operator = alice
```

The console refuses to bind anything but a loopback address unless given
`--allow-non-loopback`. The Docker service uses it because the container binds 0.0.0.0
while the host publishes the port on 127.0.0.1 only.

### Signing in

At start the console logs a sign-in link with a random token, new on every start:

```bash
docker compose logs ui          # or the terminal that runs python -m agents ui
```

Open that link; it sets a session cookie. The session ends after 12 hours and whenever
the console restarts; the page then shows "not signed in". The link itself stays valid
for as long as that console process runs, so open it again to get a new session. To keep
the same token (and link) across restarts, set `WINNIE_UI_TOKEN` (24 characters or more)
in the shell that starts it; sessions still end at each restart. Anyone with the link and
access to the port can use the console, so treat the log and the token like a password.

Wrong tokens are slowed down (429 after ten a minute) but never block the right one.

### Reaching it

The console listens on loopback only. There is no public URL and no inbound port to open.
To reach it from another machine without a tunnel, see the next section.

- **On the same machine:** `http://127.0.0.1:8480`.
- **On a remote host:** forward the port over SSH, then open `http://127.0.0.1:8480` on
  your workstation:

  ```bash
  ssh -L 8480:127.0.0.1:8480 <host>
  ```

- **On the AWS sensor:** SSM port forwarding, see
  [deploy/aws/README.md](../deploy/aws/README.md#operator-console-optional).

Use `127.0.0.1` or `localhost` in the address bar: the console rejects requests that name
any other host. Actions must come from the page under the same name and port they are
sent to, so stay on one address (do not sign in on `localhost` and act from a tab opened
on `127.0.0.1`).

### Reaching it over a private network

To open the console from another machine without logging in to the host, put an HTTPS
reverse proxy on the same host, in front of the loopback port, and reach it over a private
mesh VPN. The console keeps listening on 127.0.0.1; it only accepts one more name. On AWS,
the example template sets all of this up with `TailscaleEnabled=true`, following the rules
in [Joining the sensor to the VPN](#joining-the-sensor-to-the-vpn); see
[Console over a tailnet](../deploy/aws/README.md#console-over-a-tailnet-optional). By
hand, with Tailscale for example:

```bash
tailscale serve --bg --https=443 http://127.0.0.1:8480
```

That serves the node's own HTTPS name, for example `sensor.example-tailnet.ts.net`, to
devices on the tailnet only. Then tell the console that name:

```ini
[ui]
external_host = sensor.example-tailnet.ts.net
```

or start it with `--external-host sensor.example-tailnet.ts.net` (the flag wins; with
Docker, use `config.ini`, and set `WINNIE_UI_TOKEN` in the shell that runs compose). Use the
exact name the browser will show, with `:port` only if the proxy is not on 443. It must be
a plain DNS name: no `https://`, no path, no IP address. The console refuses to start on
anything else.

Under that name the console is HTTPS only: the session cookie is `Secure`, responses
carry `Strict-Transport-Security`, and actions must come from an `https://` page on that
name. A session started on `127.0.0.1` does not work under the external name, and the
reverse; sign in on the one you use. The console ignores `X-Forwarded-*` and identity
headers the proxy adds; it trusts only the token.

- Set a fixed `WINNIE_UI_TOKEN` (24 characters or more, kept in your password manager), so
  signing in does not need the container log. At start the console logs both links and a
  warning that it is reachable through a proxy. Those links carry the token, so keep the
  console's log on the host (a `local` or `json-file` log driver; the AWS template sets
  `driver: local`), never a driver that ships it elsewhere, and treat the log as a secret.
- Start read-only. Add the actions override only when you mean to act from the console,
  and take it off again after.
- Limit the VPN's access rules to your own devices and this one port. See
  [security-model.md](security-model.md#operator-console).

#### Joining the sensor to the VPN

The sensor is a host attackers are invited to probe. Join it so that, if it is ever taken
over, it reaches nothing on the private network. With Tailscale (the AWS template's
`TailscaleEnabled` option does each of these for you, except the tag check and the access
rules, which live in the tailnet's admin console):

- **Join with a tagged auth key, and check the tag after joining.** An auth key without a
  tag joins the host as the person who made the key, with that person's access to
  everything else on the tailnet. This is the line that matters most: confirm in the admin
  console that the node shows the tag and no user before going further.
- **Access rules: people in, nothing out.** Allow named people or a group to the tag on
  tcp 443 only, and write no rule with the tag as a source. Check from the host:
  `tailscale status` should list no peers beyond the devices you let in, and a connection
  from the host to any of them should fail.
- **Turn off Tailscale's firewall management on a Docker host:**
  `tailscale up --netfilter-mode=off`. In the default mode it inserts its own chain at the
  top of `FORWARD`, ahead of Docker's `DOCKER-USER` jump, and that chain accepts forwarded
  traffic into and out of `tailscale0`. A bridged container could then reach the tailnet,
  and the tailnet the containers, past the [egress rules](#egress-control-in-production)
  this project relies on. With `off` it writes no rules; the next line is the only one
  you need.
- **Drop forwarded traffic from the tunnel:**
  `iptables -I DOCKER-USER -i tailscale0 -j DROP` (and persist it with the other
  `DOCKER-USER` rules). Without it, a device on the tailnet can reach the honeypot's
  published ports and show up as an attacker in the event log. The proxy on 443 is a host
  process, so this does not affect the console.
- **Nothing else on the sensor:** no Tailscale SSH, no accepted routes, no Tailscale-managed
  DNS, no exit node (`--ssh=false --accept-routes=false --accept-dns=false`, and no
  `--exit-node`).
- **Kernel (TUN) mode, not userspace networking.** In userspace mode tailscaled terminates
  connections itself and there is no `tailscale0` interface, so the rule above has nothing
  to match.
- **Outbound tcp 443, for tailscaled only.** The node needs it to reach the coordination
  server and relays. A cloud firewall rule for tcp 443 to anywhere opens it to every
  process on the host network, not only tailscaled: on the AWS template that includes the
  exporter, which holds the instance role and parses data attackers wrote, and could then
  send the role's credentials anywhere. So limit the unprivileged host-network processes on
  the host itself, by owner: the AWS template sends every packet of the exporter's user
  (uid 10001) through an `OUTPUT` chain that accepts only what it needed before (its
  endpoints, the S3 prefix list's CIDRs, the metadata service, DNS) and nothing out
  `tailscale0`, and rejects the rest, and applies those rules before Docker starts at every
  boot, since host firewall rules do not survive a reboot and Docker restarts the
  containers on its own; see
  [Console over a tailnet](../deploy/aws/README.md#console-over-a-tailnet-optional).
  Bridged containers are not affected by the 443 rule: the `DOCKER-USER` rules stop every
  new connection from them. No inbound rule is needed: the node reaches out, and relays
  carry the traffic back.
- **Delete the join key once the node has joined.** Wherever the key is kept for the
  host to read, anything that takes over the host can read it too, and a valid tagged
  key joins a new machine as the sensor. Revoke it in the admin console as well.
- **A rebuilt host is a new node, unless its state is kept elsewhere.** The node's identity
  lives in tailscaled's state. Kept on the instance, a replaced instance needs a new tagged
  key (and the old node removed). The AWS template keeps it in one Parameter Store
  SecureString instead (tailscaled's `--state=arn:...` store), so a rebuilt host comes back
  as the same node. That parameter is then a credential: whoever can read it can run a
  copy of the node. Its TLS certificate is not in the state and is issued again after
  each rebuild, within Let's Encrypt's limit of five for the same name a week.
- **A sign-in page makes the access rules the only gate.** The AWS template's optional
  `/go` page (`UiTailnetSignIn`) signs in whoever the tailnet lets reach the node, so the
  token stops being a second check. Use it only when the access rules name exactly the
  people who should sign in.

### Activity

The Activity screen (key `7`) lists every line of the event log, newest first: time,
source, service, event, username, outcome and a one-line summary. Open a row to see what
was sent and what the honeypot answered, in plain monospace text, with long values
collapsed behind "Show more". Click a source to filter to it; click a session to see all
of its events in order, for any service, with a link to its triage record when there is
one. A record's page links back to its raw activity: a session to its own events, a
campaign to its source and service over its time span.

Filters live in the address, so a view can be bookmarked and the back button works:

| Filter | Matches |
|---|---|
| Time | the last hour, 24 hours (default) or 7 days, everything indexed, or a custom range in UTC |
| Service | the protocol (`ssh`, `telnet`, `http`, `s3`, `ftp`, `smtp`, `sip`, `redis`, `postgres`, `mysql`, `mssql`, `mllp`); the list shows the 50 busiest services in the window with counts |
| Event | connection, login attempt, input, reply, request, transfer, register, call attempt, error, close, other |
| Outcome | success or failure (login attempts and SIP registrations carry one) |
| Source | one exact address, or a network such as `198.51.100.0/24` |
| User | one exact username |
| Search | text in what was sent or answered, the log message, username, password, source or session (case-insensitive) |

What "answered" means depends on what each service logs:

| Service | Sent | Answered or result |
|---|---|---|
| SSH | the typed input (decoded from the log's base64) | the decoy's reply, a separate "reply" event |
| Telnet | the input line | the reply text |
| HTTP | method, path, query and body | the status code only |
| S3 | method, path and query | the operation and status code |
| PostgreSQL, MySQL, SQL Server | the statement | the result the log records (rows returned, rows affected or an error code) |
| FTP, SMTP, Redis, MLLP | the command or message | none for commands (the log does not record the reply); a transfer's file and size, an accepted message's size and recipients |
| SIP | the request and dialed number | the stage (challenge, rejected, registered) |

Where the log has only a status or result, that is shown and nothing more; an input with
no recorded reply says so.

**The indexed window.** The console keeps one small entry per log line in memory (offset,
time, source, service, event, session, username, outcome); nothing is written to disk. It
starts at the last 64 MiB of the log and grows from there, up to `[ui] activity_entries`
lines (default 200,000, at most 500,000), dropping the oldest. The strings in an entry are
cut (source at 46 characters, session id and username at 64) and shared between entries.
Measured worst case, with every line carrying its own source, session id and username at
those lengths: about 0.55 KiB an entry, so about 115 MiB of console memory at the default
and 275 MiB at the maximum. Real logs repeat sources and sessions and use much less. When
older lines exist outside the window, the screen says so and how far back it reaches; read
those on the host. Each refresh reads at most 64 MiB of new log, and log rotation or
truncation starts the index again.

**Reads per request.** Every request reads lines back from disk under one budget of
16 MiB: a page of events, a search, a session view and a record's replies. A page or a
search that runs out returns what it read and says so, and "Load older" (or "Search
further back") continues from there; a session view or replies list says it stopped at
the read limit. Only lines with very long content (large HTTP bodies, long pasted
scripts) get near it.

**When the log changes underneath the page.** "Load older" and the new-events check carry
the identity of the log they were loaded from. After the log is rotated or truncated, or
the console restarts, the server refuses the old position, and the screen reloads the list
from the newest events with a notice, instead of mixing rows from two files.

The screen checks for new events every 30 seconds and offers them ("3 new events, Show")
instead of inserting rows under what you are reading. Honeytoken values the sensor planted
are masked everywhere in the console (event text, usernames, passwords, sources, session
ids, the transcript and replies) as on the honeytokens screen, whose "reveal" is the only
place a value is shown. Text is masked whole before it is cut, so a value across a cut is
not shown in part. Other passwords attackers typed are shown. A search still finds lines
by a planted value; it is masked in what is shown.

A session view lists every event of one session in order. For SSH, the logins and
commands are replayed from the transcript (as on the record page) and the connection,
close and error lines come from the indexed window, merged by time; a line without a
usable time keeps its place in the file. When the window no longer holds those lines, the
heading says "Logins and commands" instead of "Everything".

On a record's page, an SSH session's commands are listed with the decoy's reply under
each, collapsed to its first lines. Replies are paired with commands by their place in the
session (the third command gets the reply that followed the third input), never by text,
so repeated identical commands keep their own replies. As a check, the paired input must
start with the record's command; when it does not, the command says "reply could not be
matched" rather than showing a reply that may belong to another command. A command with
no reply logged says "no reply recorded". Campaign records keep their command sample as
before: it gathers commands from many connections and has no single sequence to pair
(Telnet sessions are campaigns, so their replies are read on the session view instead).

### Decoy

The Decoy screen shows how the fake system is being adjusted to stay convincing. Nothing on
it needs a decision. It has three parts:

- **Current adjustments to the fake system**: what the tuner has layered over the
  configured scenario (`decoy/overlay.json`), in words: fake logins per service, bait
  files, the host name, SIP extensions and how many tries a login takes. The raw file is
  behind "Show the raw adjustments file". Empty means the fake system is the scenario as
  configured.
- **What the tuner changed and when**: one row per tuner run with its time, how many
  changes it made and how many its fence refused. Open a row for each change in words
  with its reason, each refusal with its reason, and the raw run record. "Undo points"
  lists the snapshots `python -m agents tune --rollback N` restores. Empty means the tuner
  has found no reason to change anything yet; it runs with every `run-all` pass and works
  without a model (a model only reorders its suggestions).
- **What returning attackers are shown**: each source a playbook's local step singled
  out, when a stored record last saw it, and what is kept for it on every visit (its own
  planted secret, slowed replies, longer or canned replies, fuller logging, labels), with
  the playbooks that set it and when it expires.

Times are relative, with the exact UTC time on hover, as on the other screens.

### Turning actions on

With actions on, the console can approve, reject and unblock, and enforce a tracked entry.
It calls the same functions as `python -m agents approve`, `reject`, `unblock` and
`enforce`, so every gate those commands have
still applies (source re-checks at approval time, the queue lock, expiry). Decisions are
recorded as `ui:<operator>`, from `--by` or `[ui] operator`.

```bash
# Without Docker
python -m agents ui --actions --by alice ...      # or [ui] actions = true

# With Docker: agent data read-write and --actions, nothing else changes
docker compose -f docker-compose.yml -f docker-compose.ui-actions.yml --profile ui up -d ui
```

Actions need write access to the agent data (the approval queue, the blocklist and the
`response/` audit records under `reports/`). The overlay and the event log stay
read-only. In Docker the console holds no connector secrets, so approve `open_ticket` and
`block_webhook` items with the CLI in the `agents` container, which has them. With track
before enforce on, approving `block_webhook` only tracks the source and calls nothing, so
the console can approve it. Likewise, with the block connector enabled, run `enforce` there
if the connector should be called.

The console's unblock takes one blocklist entry exactly as listed. To remove a range
(every entry inside a network), use `python -m agents unblock <network>`.

With actions on, the console can change what the sensor blocks. Anyone who can reach its
port and read its log can approve a block, so keep host access as tight as for the agents
container itself.

## Upgrading and rolling back

Code: pull, rebuild and restart. Volumes persist across rebuilds.

```bash
git pull
docker compose build
docker compose up -d
```

Configuration: `config.ini` is read at start; restart the services after changing it. SSH
accounts in `config.ini` and the overlay are picked up without a restart.

Overlay (tuner changes): every change is a numbered snapshot of the previous overlay.

```bash
python -m agents tune --history             # list snapshots
python -m agents tune --rollback N          # restore the overlay as it was before snapshot N
python -m agents tune --dry-run             # see what the next run would change
```

A rollback snapshots the current overlay first, so it can itself be undone. The SSH server
and listeners pick up the restored overlay without a restart (listeners within 30
seconds). To stop the tuner, run individual stages instead of `run-all`, or keep it at
`[agents] max_tuner_changes_per_run = 0`.

Per-source state: there is no rollback command. Each snapshot in
`source-state-snapshots/` stores the previous file content in its `previous` field;
restore it by writing that content back to the state file, or delete the state file to
clear every per-source effect at once.

### When the bait changes

The bait a sensor shows (organisation, hosts, people, account passwords, hashes, keys and
honeytokens) is derived from the sensor seed and the scenario. It stays the same across
restarts and rebuilds, and it changes when any of these change:

- the scenario file, including an upgrade that changes a bundled scenario or the way a
  template is expanded (the upgrade that introduced per-sensor bait replaced every fixed
  value in the bundled scenarios, and the upgrade that removed the fixed markers from
  honeytokens replaced every honeytoken value and per-source key id);
- the seed (`[scenario] seed`, or the seed file in the data directory);
- the active scenario.

After such a change, credentials attackers collected earlier stop working: a returning
attacker's old password for a trap account is refused (or accepted only by the `after_n`
policy like any guess), and the files they read now hold different values. Honeytokens are
the exception: the values earlier versions handed out are still recognised when they come
back (they are written to `reports/honeytokens.json` with `"legacy": true` and checked by
the listeners and triage), but they are never handed out again. Per-source pairs keep their
secret; only the key id changed, and the old key id is recognised too.

Pinning the identity (`[bait] org_name`, `domain`, `hosts`) keeps the organisation and
host names but not the credentials. To keep a password across an upgrade or a seed change,
pin it by label in the scenario:

```toml
[bait]
passwords = { root_admin = "the value attackers already have", voiceops = "..." }
```

`--describe` lists every template and its current value, so take that list before the
upgrade if you want to pin what attackers have seen. A pinned value is used for that
label whatever its style, and `{{sha1:LABEL}}` hashes the pinned value.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Every source in the log is a 172.x or similar gateway address; a "proxy may be hiding client addresses" warning | Docker userland proxy is on. See [Client addresses](#client-addresses). |
| SSH shell answers host facts (`uname`, `free`, `lspci`) but `command not found` to everything else | No persona model: the provider's API key is not set in the container's environment, or the model call failed (look for `Model error` events and the startup warning). |
| SSH sessions close with `fork: Resource temporarily unavailable` | A budget limit was reached; the `Budget exceeded` event names which one. |
| A long session starts answering `command not found` for things the model used to answer | It reached `[budget] max_model_commands_per_session`; look for its `Model cap reached` event. The session stays open on the deterministic shell. |
| `Prompt caching disabled` in the SSH log | The provider refused the first request that carried a cache point (the model does not take them). Requests are retried without one and caching stays off until restart. Remove `[llm] prompt_caching = true` for that model. |
| FTP `LIST` or `RETR` hangs or connects to a private address | `ftp_pasv_address` not set to the address clients reach, or the passive port range is not published. |
| A MySQL, PostgreSQL or MSSQL client fails right after connecting | The client requires TLS, which the traps do not offer (for `sqlcmd` with ODBC 18, encryption is required by default). The attempt is logged. |
| `sipsak` REGISTER gets no reply over UDP | Its request is smaller than the 401 challenge. Set `[listeners] sip_udp_slack_bytes` (for example 128) if you need to answer it. |
| Agents log "no sensor seed yet" | The front-ends have not started yet or the `frontend` volume is not mounted; the seed is created on first start. |
| Playbooks run but nothing is sent or queued | Notify steps need an enabled connector; enforce steps need `[respond] queue_enforce = true`. Run `python -m agents respond --dry-run` to see each step's status. |
| The blocklist screen marks sightings `refused` | The newest sightings file failed the checks; the console log names the first problem. Fix the producer. The last good copy stays on show. |
| Steps show `refused: non-global source` or `refused: never_act_on` | The source is private, loopback or similar (expected in a lab), or inside a `[respond] never_act_on` range. |
| `run-all` exits with status 2 | One stage failed; the JSON summary on stderr names it. The other stages still ran. A `run_lock` error means another `respond` or `run-all` run was still in progress, so nothing ran. |
