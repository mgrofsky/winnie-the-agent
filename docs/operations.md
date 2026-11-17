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
| `Dockerfile` | One image (`python:3.11-slim`, dependencies from `uv.lock`) for all services. Runs as UID 10001. |
| `docker-compose.yml` | `ssh`, `listeners` and `agents` services, plus one example sensor per scenario behind a profile. Host ports default to the real service ports. |
| `docker-compose.lab.yml` | Override: every port bound to 127.0.0.1 on a high port, for a workstation lab. |
| `docker-compose.isolated.yml` | Override: front-ends on an internal network with no route out and no DNS, for verifying that nothing connects outward. |

All services run as a non-root user with a read-only root filesystem, a small `/tmp`
tmpfs, all capabilities dropped and `no-new-privileges`.

Volumes:

| Volume | Written by | Mounted read-only by | Contents |
|---|---|---|---|
| `frontend` | `ssh`, `listeners` | `agents` | event log, quarantine, budget state, sensor seed |
| `overlay` | `agents` | `ssh`, `listeners` | tuner overlay, per-source state |
| `agentdata` | `agents` | (none) | triage records, digests, response runs, approvals, tuner snapshots, honeytoken registry, detection drafts, blocklist |

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

- The SSH and Telnet shells answer with plausible canned replies (`command not found` and a
  prompt; `exit` and `logout` end the session). If the persona's provider needs an API key
  and it is not set, no network attempt is made.
- Unknown SQL and API requests get protocol errors instead of model answers.
- Triage writes deterministic records for every SSH session and campaign. Download-and-
  execute, persistence, credential-file reads and honeytoken use still mark a session
  `MALICIOUS`.
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
| Event export cursor and failure events | `agentdata`: `/agents/state/ship_cursor.json`, `ship_events.jsonl` | the failure file is kept under 1 MB |

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
| SSH shell answers only `command not found` | No persona model: the provider's API key is not set in the container's environment, or the model call failed (look for `Model error` events and the startup warning). |
| SSH sessions close with `fork: Resource temporarily unavailable` | A budget limit was reached; the `Budget exceeded` event names which one. |
| FTP `LIST` or `RETR` hangs or connects to a private address | `ftp_pasv_address` not set to the address clients reach, or the passive port range is not published. |
| A MySQL, PostgreSQL or MSSQL client fails right after connecting | The client requires TLS, which the traps do not offer (for `sqlcmd` with ODBC 18, encryption is required by default). The attempt is logged. |
| `sipsak` REGISTER gets no reply over UDP | Its request is smaller than the 401 challenge. Set `[listeners] sip_udp_slack_bytes` (for example 128) if you need to answer it. |
| Agents log "no sensor seed yet" | The front-ends have not started yet or the `frontend` volume is not mounted; the seed is created on first start. |
| Playbooks run but nothing is sent or queued | Notify steps need an enabled connector; enforce steps need `[respond] queue_enforce = true`. Run `python -m agents respond --dry-run` to see each step's status. |
| Steps show `refused: non-global source` or `refused: never_act_on` | The source is private, loopback or similar (expected in a lab), or inside a `[respond] never_act_on` range. |
| `run-all` exits with status 2 | One stage failed; the JSON summary on stderr names it. The other stages still ran. A `run_lock` error means another `respond` or `run-all` run was still in progress, so nothing ran. |
