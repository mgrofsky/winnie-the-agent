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

`--describe` prints what a scenario exposes. It prints honeytoken names, kinds and
locations, never their values, and leaves out FTP file contents and HTTP bodies, which may
embed honeytokens.

## Shipped scenarios

| Name | Services | Fake target |
|---|---|---|
| `sip_provider` | SIP, MySQL, FTP, HTTP, SMTP, Telnet | Hosted PBX reseller on FreePBX 16 / Asterisk 18: SIP registration with extension ranges, FreePBX admin UI, CDR and configuration databases, config backups and voicemail copies on FTP, a legacy telnet console. |
| `contact_center` | SIP, PostgreSQL, MSSQL, FTP, HTTP | Outsourced contact center: Asterisk trunks and agent extensions, agent desktop and supervisor console with a REST API, CRM database, call recordings and CRM exports on FTP. |
| `bank` | PostgreSQL, Redis, FTP, HTTP | Community bank: online banking and back-office portal, REST API for accounts, cards, transfers and statements, core-banking database, Redis session cache, FTP drop for payment batch files. |
| `healthcare` | HL7 MLLP, PostgreSQL, FTP, HTTP | Regional health system integration host: patient portal and EHR admin console, FHIR R4-style API (Patient, Observation, Encounter), inbound ADT/ORU feeds over MLLP, clinical database, lab and imaging FTP share. |
| `saas` | PostgreSQL, Redis, SMTP, HTTP | Multi-tenant work-tracking SaaS: customer web app, admin console, bearer-token API, tenants and tokens in PostgreSQL, sessions and job queues in Redis, a notification mail relay. |
| `api_platform` | PostgreSQL, Redis, HTTP | B2B data API gateway: versioned REST endpoints with API-key auth, an OpenAPI document, consumer and key records in PostgreSQL, rate-limit counters in Redis. Unknown API routes may be answered by the budgeted model. |

The SSH honeypot runs alongside any scenario and takes the scenario's host profile.

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

### `[ssh]`

`persona_prompt` (up to 6000 characters) is added to the SSH and Telnet persona's prompt
together with a host profile rendered from `[identity]`. `[[ssh.accounts]]` adds SSH
accounts (`username`, `password`).

### Services

Each service table shares these keys:

| Key | Notes |
|---|---|
| `enabled` | Default `false`. |
| `port` | Listening port inside the process (defaults: SIP 5060, FTP 2121, Telnet 2323, PostgreSQL 5432, MySQL 3306, MSSQL 1433, Redis 6379, SMTP 2525, HTTP 8080, MLLP 2575). |
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
  generator kinds).
- **`redis`**: `[[services.redis.keys]]` with `key`, `type` (`string`, `hash`, `list`,
  `set`) and `value`.
- **`http`**: `server_header`, `login_path`, `login_title`, `branding`, `[[...pages]]`
  (`path`, `title`, `body_html`, `requires_login`), `api_prefix`, `api_key_header`,
  `[[...routes]]`, `openapi_path`, `openapi`, `llm_unknown_api_routes`. A route has
  `method`, `path` (may contain `{param}`), `auth` (`none`, `session`, `basic`, `bearer`,
  `api_key`, `any`), `status`, and exactly one source of content: `json_body`, `list_from`
  (`"db.table"`, with `list_limit`) or `item_from` (with `item_key`).
- **`mllp`**: `sending_facility`.
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
`generic_password`, `ssh_private_key_id`. Values are format-plausible but can never be
valid credentials anywhere: AWS-style keys use the `AKIAFAKE` prefix, API keys
`sk_test_hp_`, bearer tokens `hpt_`.

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
this over every string in a loaded scenario (after honeytoken substitution) and every
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
- AWS access key IDs only with the `AKIAFAKE` prefix;
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
   formats. Use generators for bulk rows instead of hand-written data.
3. Declare honeytokens and reference them with `{{ht:<name>}}` in places an attacker would
   look: config files on FTP, credential tables, Redis config hashes, API examples.
4. Validate:

   ```bash
   uv run python -m scenarios.check <name>
   uv run python -m listeners --describe <name>
   uv run pytest tests/test_scenarios.py tests/test_scenarios_e2e.py
   ```

5. Run it locally (`--scenario <name>`) and connect with real clients for each enabled
   service.

To have playbooks treat the new scenario like `bank` or `healthcare`, add its name to the
`scenarios` condition of the relevant playbook (for example `sensitive_data_access`).
