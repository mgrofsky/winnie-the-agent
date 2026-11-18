# Detection drafts: human approval required

Everything under `detections/pending/` is a **draft** written by `python -m agents detect`.
Nothing here is deployed, sent, or enforced automatically.

- `*.yml`: Sigma rules built from a fixed template in `agents/detect.py`. The model can only
  supply the title and description, and those are length-capped and limited to a safe
  character set. Indicator values come from regex extraction over attacker commands, so they
  are attacker-controlled strings. Read each one before use.
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

Before promoting a draft:
1. Check the indicator is not shared infrastructure (CDN, cloud NAT, a scanner you rely on).
2. Test the Sigma rule against a day of normal logs for false positives.
3. Move it out of `pending/` yourself, or approve the `publish_detection` action a playbook
   queued for it (`python -m agents approve <id>`), which moves the draft to
   `detections/approved/`. Nothing moves a draft without one of those two steps.

See [docs/architecture.md](../docs/architecture.md#detect) and
[docs/playbooks.md](../docs/playbooks.md#approval-workflow).
