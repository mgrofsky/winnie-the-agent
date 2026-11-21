# Portable formats: Sigma rules and STIX 2.1

The sensor writes two kinds of file meant for other tools:

- **Sigma rule drafts** in `detections/pending/`, written by `python -m agents detect`
  (and `run-all`). Drafts only: a person approves each one.
- **A STIX 2.1 bundle**, written by `python -m agents stix` (and `run-all`) when `[stix]`
  is enabled. Off by default. A local file; nothing is sent anywhere.

This page says what is in them, how to check them yourself, and exactly what has been
tested. Three different claims are kept apart below:

1. **Valid**: the file passes the standard's own validator.
2. **Converts**: a Sigma rule converts to a query through a named, tested pySigma backend
   and pipeline. That says nothing about whether the query matches anything in a running
   product.
3. **Ingested**: a product was seen loading the file. Nothing has been tested at this
   level.

## Sigma rule drafts

Each draft is one rule built from a fixed template in `agents/detect.py`
(Sigma rules specification v2.1.0). The model may only write the title and description of
a new draft; those are length-capped and limited to plain characters.

| Draft | Log source | Matches |
| --- | --- | --- |
| URL seen in attacker commands (`*-ioc-url.yml`) | `category: process_creation`, `product: linux` | `CommandLine|contains` the URL |
| SSH public key seen in attacker commands (`*-ioc-ssh-pubkey.yml`) | `category: process_creation`, `product: linux` | `CommandLine|contains` the key |
| Domain named in attacker commands (`*-ioc-domain.yml`) | `category: network`, `service: dns` | `dns.question.name` equals the domain |
| Redis takeover (`*-signal-redis-takeover.yml`) | `product: redis` | fixed keywords |
| Database command execution (`*-signal-sql-exec-attempt.yml`) | `category: database` | fixed keywords |
| SMTP relay probing (`*-signal-smtp-relay-attempt.yml`) | `product: postfix` | the keyword `Relay access denied` |

Log sources and fields follow the Sigma taxonomy appendix where it has one
(`process_creation`, `database`, `network`/`dns` with `dns.question.name`). Redis and
Postfix have no taxonomy entry; their product names are used as the specification's log
source rules describe.

No Sigma rule is written for an IP address or for an MD5, SHA-1 or SHA-256 found in
command text. An address is a source or a destination, not a command-line string; the STIX
export carries addresses. A hash in command text is not known to be the hash of any file.

Indicator values come from attacker commands, so they are attacker-chosen. The Sigma
wildcards `*` and `?` and the escape character `\` in them are escaped, so a rule matches
the value literally and never as a pattern the attacker wrote.

Other properties of the drafts:

- `status: experimental`, and the author line says it is a draft for review.
- Tags: ATT&CK tactics with hyphens (`attack.resource-development`) and technique ids
  (`attack.t1059.004`); anything else is left out.
- One file per rule id, named `<first 8 characters of the id>-<kind>.yml`. `date` is when
  the rule was first drafted; `modified` is set when its content changes. A rule already in
  `detections/approved/` is not drafted again.
- The triage records a draft was built from are listed in `detections/pending/provenance.json`,
  not inside the rule. The `publish_detection` playbook action reads that file.

### The pipeline onto Winnie's own events

`detections/pipelines/winnie-events.yml` is a pySigma processing pipeline that maps the
drafts onto the front-ends' JSON events (`listeners/events.py`), as they would be indexed
in a search engine:

- Command-line drafts match `data.input` of telnet `command` events.
- The Redis, database and Postfix drafts are limited to `command` events from the matching
  front-end (`sensor_protocol`). Winnie logs a refused relay as "SMTP relay attempt", so the
  Postfix keyword is mapped to that.
- DNS drafts are refused with a message: Winnie records no DNS queries. Run them against
  your own DNS logs.
- SSH is not covered. The SSH front-end logs each command base64-encoded in `details`, so
  no part of a command can be matched there.
- Event values have backslashes doubled and control characters written as `\xNN`, so an
  indicator containing those does not match.

Converting a draft with Python (the same calls the tests make):

```python
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline
from sigma.backends.opensearch import OpensearchLuceneBackend

pipeline = ProcessingPipeline.from_yaml(Path("detections/pipelines/winnie-events.yml").read_text())
rules = SigmaCollection.from_yaml(Path("detections/pending/<file>.yml").read_text())
print(OpensearchLuceneBackend(pipeline).convert(rules))
```

## STIX 2.1 bundle

`python -m agents stix` writes `reports/stix/bundle.json` (`[stix] output_file` to change
it). Nothing is sent anywhere and no credential is used. Configure it in `[stix]` in
`SSH/config.ini`; every setting is described in `SSH/config.ini.TEMPLATE`.

What is in it:

- One `identity` for the sensor (`identity_class: system`, name from `identity_name`) and
  the standard TLP `marking-definition` chosen in `tlp` (default amber), embedded in the
  bundle. Every other object refers to both.
- `observed-data` with an `ipv4-addr`, `ipv6-addr` or `file` object, for what was merely
  seen: proven source addresses from the last `lookback_days`, and whole files the
  quarantine stored (by SHA-256). An unproven UDP source is never included. Addresses in
  `[respond] never_act_on`, the sensor's own address and non-global addresses are left out.
- `indicator` only for what passed a promotion rule that already exists:
  - the OTX connector's selection: a proven source that logged in, used a planted
    credential or did one of the counted active things (the same code, not a copy). The
    model's verdict can only hold a source back, never promote it;
  - an entry the operator approved onto the blocklist (tracked or enforced).
- A `sighting` linking each live indicator to the observed-data it came from.

Indicators:

- `pattern_type: stix`; the address or hash is checked first and then escaped for the
  pattern grammar. IPv4 addresses use `=`, an IPv6 /64 from the blocklist uses `ISSUBSET`,
  hashes use `file:hashes.'SHA-256'`.
- `valid_from` is when the indicator first became valid. `valid_until` is always later: the
  blocklist entry's own `expires_at`, or the last sighting plus `address_lifetime_days`
  (30) for an address or `hash_lifetime_days` (365) for a file hash. A file's hash does not
  pass to an innocent owner the way a rented address does, so it is kept longer. An approved
  entry without a usable window gets no indicator; the address stays observed-data.
- Review state: `labels` is one or more of `rule-promoted`, `operator-tracked` and
  `operator-enforced`, with a fixed `confidence` (50, 70, 85; the highest applies).
  `indicator_types` is `malicious-activity`.
- Names and descriptions are fixed text plus code-set names. No attacker text is written.

Identifiers and versions:

- Cyber-observable objects use the specification's deterministic ids (section 2.9): UUIDv5
  in its namespace over the ID contributing properties. Every other object has a UUIDv5 id
  in this project's namespace over the identity name, the type and the value. The same
  input gives the same file, byte for byte.
- `created` stays fixed and `modified` moves only when an object's content changes. The
  state for this is kept in `<state-dir>/stix_state-<hash of identity_name>.json`.

Withdrawal and expiry:

- When the operator removes an address from the blocklist (`python -m agents unblock` or the
  console), its indicator is set to `revoked: true` on the next export, even if the
  automatic rule would still promote the address. The removal is read from the audit
  record in `reports/response`, which `unblock` writes before it changes the blocklist (if
  the record cannot be written, the unblock fails and nothing is removed). Run the export
  (or `run-all`) more often than `[respond] retention_days`, so the record is still there.
- Revocation is permanent: STIX 2.1 section 3.6 says that once an object is revoked, "later
  versions of that object MUST NOT be created". So the revoked id is never written live
  again. While the withdrawal stands (`keep_days`, 30, from the removal) the automatic rule
  cannot promote the address. If the operator approves it again, the new indicator has a
  new id. After `keep_days`, the rule can promote it again, also under a new id.
- Natural expiry is not a revocation: `valid_until` says it and the object stays as it was.
- Expired and revoked objects leave the bundle `keep_days` after they ended.

Caps and safety:

- `max_objects` (5000) and `max_bytes` (8 MiB) cap the bundle. The size is the exact size
  of the file. Objects go in as whole groups (an indicator with its sighting, observed-data
  and address objects; or an observation with its address object), operator-approved
  indicators first. A group that does not fit is left out whole.
- Before writing, every reference in the bundle (`*_ref`, `*_refs`, at any depth) must
  resolve to an object in it.
- Files are written atomically and readable by the owner only.

### When the state is lost

The export stops with an error, writes nothing, and leaves the previous bundle as it was
when:

- the state file exists but cannot be read or holds anything inconsistent;
- the state file is missing while a bundle from the same identity exists;
- the state would grow past what the next run may read (lower `lookback_days` or
  `keep_days`);
- an unblock record in `reports/response` cannot be read, is not in the expected form or is
  dated later than the export's clock, or there are more than 20,000 of them (the export
  reads every one, so that no withdrawal is missed; `[respond] retention_days` removes old
  ones);
- a reference would not resolve.

This prevents an id that was revoked from being written live again. To recover, restore
the state file from a backup. If there is none, choose a new `identity_name`. That makes a
new producer whose objects all have new ids, so nothing contradicts what consumers already
have. Do not just delete the state and the bundle: the same identity would then write ids
it had revoked before. Back up the state file together with the bundle.

## Checking the files yourself

The tools the tests use are dev dependencies (`uv sync` installs them):

```bash
# STIX: the OASIS validator in strict mode. Check 103 asks for UUIDv4 ids on SDOs; the
# spec allows other UUID versions (section 2.9) and these are UUIDv5 so that a re-export
# is identical, so that one check is disabled.
uv run stix2_validator --strict --disable 103 reports/stix/bundle.json

# Sigma: parse a draft with the Sigma project's library.
uv run python -c "import sys; from sigma.rule import SigmaRule; SigmaRule.from_yaml(open(sys.argv[1]).read()); print('ok')" detections/pending/<file>.yml
```

## Tested consumers

| Target | What was tested | Result |
| --- | --- | --- |
| Sigma specification | every draft kind parsed by pySigma 1.5.1 (`SigmaRule.from_yaml`) and checked with its validators, except the two that download MITRE ATT&CK and D3FEND data; ATT&CK tags are checked against a fixed pattern instead | valid |
| Elasticsearch (Lucene query) | conversion of every draft kind with the Winnie pipeline through pysigma-backend-elasticsearch 2.1.1 (`LuceneBackend`); fixed queries compared | converts; DNS drafts refused by the pipeline on purpose |
| OpenSearch (Lucene query) | conversion through pysigma-backend-opensearch 2.0.3 (`OpensearchLuceneBackend`); fixed queries compared | converts; DNS drafts refused by the pipeline on purpose |
| Splunk | not tested: pysigma-backend-splunk 3.0.1 needs pySigma 2, which the Elasticsearch and OpenSearch backends do not support, so it cannot be installed alongside them | not tested |
| A running Elasticsearch or OpenSearch | not tested: no query has been run against indexed events | not tested |
| STIX 2.1 specification | every bundle the tests produce checked with stix2-validator 3.3.2 in strict mode (check 103 disabled, see above), plus a check that every reference resolves | valid |
| stix2 3.0.2 (OASIS Python library) | the deterministic ids of `ipv4-addr`, `ipv6-addr` and `file` objects, and the four TLP marking definitions, compared with the library's | identical |
| Any TIP, SIEM or firewall (MISP, OpenCTI, Sentinel, GuardDuty, others) | nothing | not tested |
