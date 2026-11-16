# Detection drafts: human approval required

Everything under `detections/pending/` is a **draft** written by `python -m agents detect`.
Nothing here is deployed, sent, or enforced automatically.

- `*.yml`: Sigma rules built from a fixed template in `agents/detect.py`. The model can only
  supply the title and description, and those are length-capped and limited to a safe
  character set. Indicator values come from regex extraction over attacker commands, so they
  are attacker-controlled strings. Read each one before use.
- `blocklist-candidates.csv`: `ip, sessions, attempts, first_seen, last_seen, judgement,
  protocols`, covering every protocol. Private and reserved addresses (including the
  documentation ranges) are skipped. BENIGN-only sources are left out.

Before promoting a draft:
1. Check the indicator is not shared infrastructure (CDN, cloud NAT, a scanner you rely on).
2. Test the Sigma rule against a day of normal logs for false positives.
3. Move it out of `pending/` yourself, or approve the `publish_detection` action a playbook
   queued for it (`python -m agents approve <id>`), which moves the draft to
   `detections/approved/`. Nothing moves a draft without one of those two steps.

See [docs/architecture.md](../docs/architecture.md#detect) and
[docs/playbooks.md](../docs/playbooks.md#approval-workflow).
