# Scenarios

A scenario is one TOML file, `scenarios/<name>/scenario.toml`, that describes the whole fake
target: the organisation and host, which services run and how they behave, fake accounts,
fake data, the HTTP surface, the SSH persona's host profile, and honeytokens. Every protocol
on a sensor reads the same scenario, so an attacker who finds a database password on the
FTP share can use it on the database listener, and the SSH shell describes the same host.

Scenario files are written by people. Code never edits them; the tuner's changes live in a
separate [overlay](#overlay) merged on top at load time.

## Selecting a scenario

```ini
[scenario]
active = healthcare
```

or `--scenario healthcare` on `ssh_server.py` or `python -m listeners`. Changing the active
scenario needs a restart. List and inspect the shipped scenarios with:

```bash
uv run python -m listeners --list-scenarios
uv run python -m listeners --describe healthcare
```

`--describe` prints what a scenario exposes on this sensor: the organisation, hosts,
people and credentials expanded from the sensor's seed (see [per-sensor bait](#per-sensor-bait)),
with every template and its value. It reads the seed from `[scenario] seed` or the seed file
in the data directory (`--config`, `--data-dir`) and never creates one; before the sensor
has started once it shows a labelled preview, and `--seed-preview TEXT` shows the bait for
any other seed. It prints honeytoken names, kinds and locations, never their values, and
leaves out FTP file contents and HTTP bodies, which may embed honeytokens.

## Shipped scenarios

| Name | Services | Fake target |
|---|---|---|
| `sip_provider` | SIP, MySQL, FTP, S3, HTTP, SMTP, Telnet | Hosted PBX reseller on FreePBX 16 / Asterisk 18: SIP registration with extension ranges, FreePBX admin UI, CDR and configuration databases, config backups and voicemail copies on FTP, call recordings, CDR exports and config backups in S3 buckets, a legacy telnet console. |
| `contact_center` | SIP, PostgreSQL, MSSQL, FTP, HTTP | Outsourced contact center: Asterisk trunks and agent extensions, agent desktop and supervisor console with a REST API, CRM database, call recordings and CRM exports on FTP. |
| `bank` | PostgreSQL, Redis, FTP, S3, HTTP | Community bank: online banking and back-office portal, REST API for accounts, cards, transfers and statements, core-banking database, Redis session cache, FTP drop for payment batch files, S3 statement archive, batch staging and database backups. |
| `healthcare` | HL7 MLLP, PostgreSQL, FTP, HTTP | Regional health system integration host: patient portal and EHR admin console, FHIR R4-style API (Patient, Observation, Encounter), inbound ADT/ORU feeds over MLLP, clinical database, lab and imaging FTP share. |
| `saas` | PostgreSQL, Redis, SMTP, S3, HTTP | Multi-tenant work-tracking SaaS: customer web app, admin console, bearer-token API, tenants and tokens in PostgreSQL, sessions and job queues in Redis, a notification mail relay, S3 uploads and database exports plus a public assets bucket that also holds a deploy `.env`. |
| `api_platform` | PostgreSQL, Redis, HTTP | B2B data API gateway: versioned REST endpoints with API-key auth, an OpenAPI document, consumer and key records in PostgreSQL, rate-limit counters in Redis. Unknown API routes may be answered by the budgeted model. |
| `dev_portal` | PostgreSQL, HTTP | Project-workspace web app: a single-page frontend with a JavaScript bundle, its source map and a runtime `/env.js`, a JSON API with an OpenAPI document that lists internal admin and export routes, item routes over generated projects and users, username checks, password recovery and activation flows. |

The SSH honeypot runs alongside any scenario and takes the scenario's host profile.

The shipped scenarios are examples. Their organisation, hosts, people and credentials are
templates, so every sensor shows its own (see below), but the story, the services and the
shape of the data are the same on every sensor that runs them. For a target that has to
convince a careful attacker, write your own scenario or pin the identity in `[bait]`.

## Per-sensor bait

The repository is public. A literal password, key or company name in a scenario would let
anyone who sees it on a sensor search for it and learn that the host is this honeypot, and
every sensor running the same scenario would look the same. So any string in a scenario
(and any table key) may hold `{{...}}` templates, expanded once at load time from the
sensor seed and the scenario name:

```toml
[identity]
org_name = "{{org.name}}"
hostname = "{{host:pbx}}"
domain = "{{org.domain}}"
internal_ips = ["{{net:voice}}.21"]

[[ssh.accounts]]
username = "root"
password = "{{password:dba}}"

[[services.ftp.files]]
path = "/backups/etc/my.cnf"
content = '''
[client]
user = root
password = {{password:dba}}
host = {{host:pbx}}.{{org.domain}}
'''
```

The same template with the same label is the same value everywhere in the scenario, so the
password in the FTP file is the one SSH accepts. The values stay the same across restarts
of one sensor and differ between sensors with different seeds.

| Template | Expands to |
|---|---|
| `{{org.name}}` | Organisation name: an invented word plus one of `[bait] org_suffixes` (`Hallowmere Voice Networks`). |
| `{{org.short}}`, `{{org.slug}}` | The invented word (`Hallowmere`), and the same in lower case for names and paths (`hallowmere`). |
| `{{org.abbr}}`, `{{org.ABBR}}` | Initials of the name in lower and upper case (`hvn`, `HVN`), for bucket prefixes, account codes and client ids. |
| `{{org.domain}}` | The name plus one of `[bait] domain_words` under `.example` or `.test` (`hallowmere-voice.example`). |
| `{{host:LABEL}}` | A host name for the role `LABEL` in one of several naming conventions (`pbx02`, `pbx-07`, `chi-pbx01`, `hvn-pbx03`). Different labels never collide. |
| `{{net:LABEL}}` | The first three octets of a private /24 (`10.41.8`); write `{{net:lan}}.21` for an address. |
| `{{person:N.FIELD}}` | Person `N` (1 to 99) from large pools of common names. `FIELD` is `first`, `last`, `full_name`, `username` (one naming convention per sensor, valid as a Unix user name) or `email` (at `{{org.domain}}`). |
| `{{password:LABEL}}` | A password a person would choose: word, year and symbol, season and year, keyboard walks, a first name and digits, the company name and year, and other shapes common in breach corpora. |
| `{{password:LABEL:STYLE}}` | `weak`: a default or top-of-wordlist password (`admin123`, `Welcome1`). `user`: built from the label as an account name (`voiceops`, `voiceops2023`). `service`: an application account password set once and never rotated (`crm_app_2022`). `random`: 14 to 20 generated characters. `human` is the default. |
| `{{sha1:LABEL}}` | SHA-1 hex of `{{password:LABEL}}`, for password-hash columns that crack to a working login. |
| `{{company:N.FIELD}}` | Another company `N` (1 to 99) for customers, tenants and partners: `name` (an invented word and a business type, `Willetwell Clinic`), `short`, `slug`, `domain` (`willetwell.example`). Never the organisation's own name. |
| `{{place:N}}` | An invented place name `N` (1 to 99) for branches and sites. |
| `{{secret:FORMAT:LABEL}}` | `token` (40 alphanumerics), `bearer` (43 of `A-Za-z0-9-_`, the usual opaque OAuth token), `api_key` (32 alphanumerics), `client_secret` (40 of `A-Za-z0-9-_`), `session` (26 of `0-9a-v`, the PHP session id format), `uuid` (version 4), `aws_secret` (40 base64 characters). No format carries a real provider's prefix. |
| `{{digits:N:LABEL}}`, `{{hex:N:LABEL}}`, `{{alnum:N:LABEL}}` | `N` (1 to 128) digits, lower-case hex or alphanumerics, for session ids, account numbers and the like. |
| `{{ht:NAME}}` | The honeytoken `NAME` (see [honeytokens](#honeytokens)). |
| `{{url:TEMPLATE}}` | Any value template above, percent-encoded for a URL: `postgres://app:{{url:password:db}}@{{host:db}}:5432/app`. Unreserved characters stay as they are, so a value without symbols (every honeytoken password) is unchanged and still recognised. Use it wherever a password sits in a URL or a connection string. |
| `{{open}}`, `{{close}}` | Literal `{{` and `}}`. |

A `LABEL` is 1 to 64 of `A-Za-z0-9_.-` (`host` labels: lower case, starting with a letter).
One label must always be used with the same arguments: `{{password:x}}` and
`{{password:x:weak}}` in one scenario is an error, as are an unknown template, a bad
argument, an undeclared honeytoken and an empty seed. Each error names the field and the
template. Templates are expanded before validation, so the expanded values must satisfy the
schema (a `{{person:1.username}}` in `[[identity.users]] name` is a valid user name, a
`{{net:lan}}.5` in `internal_ips` a private address).

### `[bait]`: pinning the identity

```toml
[bait]
org_suffixes = ["Voice Networks", "Telecom", "Communications"]  # endings for {{org.name}}
domain_words = ["voice", "tel"]                                 # words for {{org.domain}}
org_name = "Example Voice Networks"     # optional pin for {{org.*}}
domain = "example-voice.example"        # optional pin for {{org.domain}}
hosts = { pbx = "pbx01" }               # optional pins for {{host:LABEL}}
passwords = { root = "Summer2024!" }    # optional pins for {{password:LABEL}}
```

Values in `[bait]` are literal. Without pins the organisation is derived from the seed. A
literal `identity.org_name` or `identity.domain` counts as a pin too, so a scenario written
before templates existed, with literal values throughout, loads exactly as before. Pinning
the identity leaves the credentials per sensor; pin a password by label in `passwords` to
keep it across a seed change or an upgrade (see
[operations](operations.md#when-the-bait-changes)).

## Schema

The schema is `scenarios/schema.py`. Every model forbids unknown keys, and strings are
checked against patterns and length limits, so a typo fails at load time rather than
producing an odd-looking service. Top level:

```toml
name = "example_corp"            # [a-z][a-z0-9_]{1,40}, must match the directory name
title = "..."                    # one line, max 120 characters
description = """..."""          # max 2000 characters

[identity]                       # the host and organisation
[ssh]                            # persona prompt fragment and SSH accounts
[services.<service>]             # one table per enabled service
[[honeytokens]]                  # planted fake secrets
```

### `[identity]`

| Key | Notes |
|---|---|
| `org_name` | 2 to 80 characters, plain text. |
| `hostname` | `[a-z][a-z0-9-]{0,62}`. |
| `domain` | Must be a reserved domain (see [synthetic data rules](#synthetic-data-rules)). |
| `internal_ips` | 1 to 8 addresses, each must be private. |
| `os_pretty_name`, `kernel`, `timezone` | Shown by the persona (`uname`, `/etc/os-release`). |
| `lures` | Up to 25 absolute paths of bait files the persona should show. |
| `[[identity.users]]` | Up to 16 users: `name`, `uid`, `gecos`, `home`, `shell`. |
| `[identity.hardware]` | Optional. What the shell reports about CPU, memory, disk and GPU; see below. |

### `[identity.hardware]`

The deterministic shell (`agents/shell.py`) answers the commands bots use to size a host
from this table plus the rest of `[identity]`, so `nproc`, `free`, `df`, `/proc/cpuinfo`,
`/proc/meminfo`, `lscpu`, `lspci` and `nvidia-smi` agree with each other. Leave it out for
a small cloud VM with no GPU (`lspci` shows a plain VGA device and `nvidia-smi` is not
installed), which is what most real targets look like. Which VM is chosen by the sensor
seed from six shapes (2 to 8 vCPUs, 4 to 32 GB, Xeon 8259CL or 8275CL, or EPYC 7R13;
`HARDWARE_PRESETS` in `scenarios/schema.py`), so two sensors running the same scenario do
not report the same machine. The persona block shows the model the same shape. Set the
table to pin it; a key left out of a table you do set takes the default below.

| Key | Default | Notes |
|---|---|---|
| `cpu_model` | `Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz` | Up to 64 characters. A model containing `AMD` reports an AMD vendor and flags. |
| `cpus` | `2` | 1 to 64. |
| `memory_mb` | `4096` | 512 to 1048576. The kernel reports about 97% of it, as on a VM. |
| `disk_gb` | `40` | 8 to 65536, the root file system. |
| `gpu` | none | One of `rtx3060`, `rtx3090`, `rtx4090`, `t4`, `a10g`, `a100`, `l4`, `h100`. Consumer cards show as `VGA compatible controller` in `lspci`, data-center cards as `3D controller`. |
| `gpu_count` | `1` | 1 to 8, used when `gpu` is set. |

```toml
[identity.hardware]
cpus = 16
memory_mb = 65536
disk_gb = 500
gpu = "rtx4090"
gpu_count = 2
```

Uptime, load and memory use are derived from the sensor seed and the clock: stable for one
sensor (the boot time does not move between commands), different between sensors. So are
how busy the host is (its load level), which optional services show in `ps` (multipathd,
snapd, irqbalance, qemu-ga and the like for the distribution) and whether one of the
scenario's login users has an idle SSH session open from the internal network (`w`, `who`,
`uptime` and `ps` all show it). The persona block names that login and those services, so
the model's own `ps`, `w` and `last` agree with the local answers. The kernel string is the
scenario's `kernel`, as written; with no scenario it is one Ubuntu 22.04 build
(`5.15.0-105-generic`).

### `[ssh]`

`persona_prompt` (up to 6000 characters) is added to the SSH and Telnet persona's prompt
together with a host profile rendered from `[identity]`. `[[ssh.accounts]]` adds SSH
accounts (`username`, `password`).

### Services

Each service table shares these keys:

| Key | Notes |
|---|---|
| `enabled` | Default `false`. |
| `port` | Listening port inside the process (defaults: SIP 5060, FTP 2121, Telnet 2323, PostgreSQL 5432, MySQL 3306, MSSQL 1433, Redis 6379, SMTP 2525, HTTP 8080, MLLP 2575, S3 9000). |
| `banner`, `version` | Printable ASCII. |
| `[services.<s>.policy]` | `accept = "all" | "listed" | "after_n" | "none"`, `after_n_min`, `after_n_max` (1 to 20). |
| `[[services.<s>.accounts]]` | Up to 50 `username` / `password` pairs. |

`[listeners] <service>_enabled`, `<service>_port` and `<service>_accept` in `config.ini`
override the scenario per service.

Service-specific keys:

- **`sip`**: `udp`, `tcp`, `realm`, `server_header`, `[[services.sip.extensions]]`
  (`extension`, `password`, `display_name`), `extension_ranges` (`"200-299"`),
  `dial_plan_hints`, `register_expires`.
- **`ftp`**: `[[services.ftp.files]]` (`path`, `content` up to 16 KB, displayed `size`,
  `mtime`), `retr_max_bytes`.
- **`postgres`, `mysql`, `mssql`**: `[[services.<s>.databases]]` with `name`, `schema_name`
  and `[[...tables]]`. A table has `name`, `columns` (`name`, `type`: `int`, `bigint`,
  `text`, `varchar`, `numeric`, `bool`, `date`, `timestamp`, `uuid`, `json`), literal
  `seed_rows`, and an optional `generator` (`count` up to 500, `fields` mapping columns to
  generator kinds). A column with `secret = true` holds credentials (passwords, hashes,
  tokens); its seed-row values in shipped scenarios are templates.
- **`redis`**: `[[services.redis.keys]]` with `key`, `type` (`string`, `hash`, `list`,
  `set`) and `value`.
- **`http`**: `server_header`, `login_path`, `login_title`, `branding`, `[[...pages]]`
  (`path`, `title`, `body_html`, `requires_login`), `api_prefix`, `api_key_header`,
  `[[...routes]]`, `openapi_path`, `openapi`, `llm_unknown_api_routes`,
  `llm_unknown_paths`. A route has
  `method`, `path` (may contain `{param}`), `auth` (`none`, `session`, `basic`, `bearer`,
  `api_key`, `any`), `status`, and exactly one source of content: `json_body`, `list_from`
  (`"db.table"`, with `list_limit`) or `item_from` (with `item_key`).
  `llm_unknown_paths` (default true) lets the model answer a GET for an unknown path
  outside `api_prefix` when `[listeners] llm` is on; the answer is cached per path, so
  every client sees the same page. The most-probed paths have fixed answers: `/robots.txt`
  disallows everything; `/.env`, `/.git/config` (with `/.git/HEAD`) and `/.aws/credentials`
  are served only when they can hold the scenario's honeytokens or the source's planted
  pair; everything else is the server's own 404 (or 403 for `/server-status` and
  `/cgi-bin/` behind an Apache `server_header`).
- **`http` web deception** (all optional): `[[...assets]]`, `openapi_aliases`,
  `openapi_advertises`, `openapi_lure`, and on a route `lure`, `hidden` and `flow`.
  - An asset has `path`, `kind` (`bundle`, `source_map`, `runtime_config`, `static`),
    `lure` (its lure ID), `advertises` (route paths) and an optional `body`. Without a
    `body` the content is generated from the advertised routes: a minified webpack chunk
    with an API client table, a source map whose `sourcesContent` holds that client, or a
    config object with `apiBase`, feature flags and an endpoint table relative to
    `apiBase` (a `window.__ENV__` assignment when the path ends in `.js`). A `static`
    asset needs a `body`. Assets answer GET and HEAD with their own content type, `ETag`,
    `Last-Modified` and cache headers.
  - A source that fetches an asset, or the OpenAPI document (at `openapi_path` or an
    `openapi_aliases` path) when `openapi_advertises` is set, is recorded as shown those
    routes. Its later requests to them carry `discovered_via` and `discovered_age`.
  - `{marker:NAME}` in an asset `body` or a route `json_body` is replaced per source by a
    value derived from the sensor seed, the source and the name (a short hex hash for a
    build or commit name, a UUID for an `*_id` name, a 32-character key for a key or
    token name). A marker presented back in the target, body, `Authorization`, the
    API-key header or `Cookie` is logged as `marker`, with `marker_src` when it was
    issued to another source. Up to 16 marker names per scenario.
  - `hidden = true` leaves a route out of the generated OpenAPI document and the model's
    prompt; it still answers.
  - `flow` answers a route with a fixed local reply: `username_check` (`exists` true only
    for the service's accounts), `recovery_request` (the same message for every address),
    `recovery_reset` and `activation` (every token is invalid or expired). A flow route
    has no other content source.
  - Item routes with a `lure` log `object_id_count`, the distinct IDs this source asked.
  - [web-deception.md](web-deception.md) walks through a visitor to `dev_portal` and the
    triage record it produces.
- **`mllp`**: `sending_facility`.
- **`s3`**: `server_header`, `region`, `owner_name`, `get_max_bytes` (bytes one download
  sends, at most 16 MB) and `[[services.s3.buckets]]` with `name`, `region`, `created`,
  `public_list`, `public_read` and `[[...objects]]`. An object has `key`, `content_type`,
  `mtime` and one source of content: literal `text` (may hold `{{ht:<name>}}`), `table`
  (`"db.table"` rendered as CSV, with `table_limit`) or neither, for deterministic filler
  of `size` bytes generated per request (`.wav`, `.gz`, `.zip` and `.pdf` keys start with
  that format's header). `count` turns one spec into a series whose `key` holds `{n}` or
  `{n:05d}`; up to 100,000 keys per bucket and 200,000 per scenario. Accounts use the
  access key id as `username`; a `password` other than `*` is the secret, and SigV4
  requests with that key are then verified.
- **`smtp`**, **`telnet`**: common keys only.

Generator kinds: `seq`, `uuid`, `first_name`, `last_name`, `full_name`, `email`, `phone`,
`extension`, `amount`, `date`, `datetime`, `account_number`, `card_number`, `iban_like`,
`mrn`, `word`, `sentence`, `bool`, `int`, `ip_private`, `choice`, `const`. Options: `min`,
`max`, `choices`, `value`, `prefix`.

## Honeytokens

A honeytoken is a fake secret planted in the scenario's data. Declare it once:

```toml
[[honeytokens]]
name = "backup_s3_key"
kind = "aws_access_key"
planted_in = ["FTP /backups/offsite-sync.sh", "Redis config:storage"]
```

and reference it anywhere in the scenario's strings with `{{ht:backup_s3_key}}`. At load
time each placeholder is replaced with a value derived from the sensor seed, the scenario
name and the token name, so the same sensor always shows the same value and different
sensors show different ones. A placeholder that names an undeclared token fails
validation. `planted_in` is a human description used by `--describe` and the digest.

Kinds: `aws_access_key`, `api_key`, `bearer_token`, `db_password`, `sip_trunk_password`,
`generic_password`, `ssh_private_key_id`. Each value has the length and alphabet of the
real thing and no fixed marker: AWS-style key ids are `AKIA` and 16 characters of `A-Z2-7`,
API keys `sk_test_` and 24 alphanumerics (never a live-key prefix), bearer tokens 43
characters of unpadded base64url, SIP trunk passwords 16 alphanumerics, SSH key ids
`SHA256:` and 43 base64 characters, and database and generic passwords 10 alphanumerics, one
of `-._` and two digits (no character that needs escaping in a URL or connection string).
None of them is valid anywhere: they are derived from the sensor seed, so no real service
issued them, and an AWS-style pair is useless because its secret is the secret of no real
key (see [security model](security-model.md#fingerprinting)).

A token is recognised by lookup, not by its shape. Every value this sensor can have issued
(scenario honeytokens and per-source pairs) is held in an index, and each input is searched
with one lookup per position over its first 16 KiB, whatever the number of tokens. Values
issued by earlier versions (which did carry markers) are indexed too, so a token handed out
before an upgrade is still recognised when it comes back; they are never issued again.

The agents write every token to `reports/honeytokens.json`. When a token value appears in
any later input (a password, a username, a command, an HTTP request) the event and the
triage record are marked, and honeytoken use ranks first in the digest and triggers the
`honeytoken_reuse` playbook.

**Per-source tokens.** The `plant_token` playbook action gives one source its own AWS-style
key pair, derived from the sensor seed and the source address. That source, and only that
source, then sees it in its fake data: FTP `/.aws/credentials`, Redis keys, an HTTP config
route and the SSH persona's `/root/.aws/credentials`. The registry records which source it
was planted for, so later use is attributed to exactly that source (`honeytoken_sources` on
the triage record), even when it comes from a different address.

## Synthetic data rules

Nothing in a scenario may be, or be mistaken for, real data. `scenarios/check.py` enforces
this over every string in a loaded scenario (after template expansion) and every
generated row:

- card-like 13 to 19 digit numbers must fail the Luhn check (the generator uses the
  non-issued `0000` prefix with a failing check digit);
- IBAN-shaped strings with a real country code must fail mod-97 (the generator uses the
  non-country code `XX`);
- phone numbers must be in a fictional range: NANP 555-0100 to 555-0199, or the UK drama
  ranges 01632 960xxx and 07700 900xxx;
- email domains must be `example.com`, `example.org`, `example.net`, under `.example`,
  `.test` or `.invalid`, or the scenario's own `identity.domain`, which must itself be
  reserved;
- SSN-shaped values only with area 000, 666 or 9xx;
- AWS access key IDs only when they are one of the sensor's own honeytokens (a literal key
  id in a scenario could be someone's real key);
- no well-known real bank, hospital, carrier or vendor names;
- IPv4 addresses must be private, loopback, link-local, reserved or in the documentation
  ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

```bash
uv run python -m scenarios.check              # all scenarios; exits 1 on any problem
uv run python -m scenarios.check healthcare   # one scenario
```

The test suite runs the checker over every shipped scenario.

## Overlay

`decoy/overlay.json` (or `$WINNIE_OVERLAY`, or `[scenario] overlay`) holds the tuner's
changes, validated by the `Overlay` model in `scenarios/schema.py`:

- `accounts`: extra fake accounts per service (`ssh`, `ftp`, `telnet`, `postgres`,
  `mysql`, `mssql`, `redis`, `smtp`, `http`), at most 20 per service;
- `sip_extensions`: at most 20;
- `lures`: at most 25 paths;
- `policies`: `after_n_min` / `after_n_max` per service;
- `hostname`: optional override (manual use; the tuner does not propose it).

Overlay accounts are merged with the scenario's and `[user_accounts]`; configured accounts
always win. See [architecture.md](architecture.md#tuner) for how the overlay is versioned and
rolled back.

## Adding a scenario

1. Create `scenarios/<name>/scenario.toml`. Start from the shipped scenario closest to
   what you want; `name` must match the directory.
2. Invent everything: organisation, people, domains (`.example`), phone numbers, account
   formats. Use templates for credentials, and for the identity unless you pin it, and
   generators for bulk rows instead of hand-written data.
3. Declare honeytokens and reference them with `{{ht:<name>}}` in places an attacker would
   look: config files on FTP, credential tables, Redis config hashes, API examples.
4. Validate:

   ```bash
   uv run python -m scenarios.check <name>
   uv run python -m listeners --describe <name>
   uv run pytest tests/test_scenarios.py tests/test_scenarios_e2e.py tests/test_scenarios_bait.py
   ```

5. Run it locally (`--scenario <name>`) and connect with real clients for each enabled
   service.

To have playbooks treat the new scenario like `bank` or `healthcare`, add its name to the
`scenarios` condition of the relevant playbook (for example `sensitive_data_access`).
