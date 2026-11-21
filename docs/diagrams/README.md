# Data-flow diagram

![Winnie the Agent: data flow and trust boundaries](winnie-dataflow.png)

The diagram is drawn in Excalidraw; the `.excalidraw` source is kept outside this repository. It is drawn in Excalidraw's hand-drawn style: the code font (Comic Shanns) for all text and sloppiness 2 on every element. `winnie-dataflow.svg` and `winnie-dataflow.png` are the dark-theme export, the primary one; `winnie-dataflow-light.svg` and `winnie-dataflow-light.png` are the light-theme export of the same scene. Both PNGs are 3200 pixels wide, and both SVGs embed the font they use.

## Reading the diagram

The columns run left to right in the order data moves: attackers on the internet, the front-ends that face them, the captured data they write, the agents pipeline, the files the agents write, operator approval (with the operator console), and the model providers. Each pipeline step is a row. The file a step writes sits on that step's row, and the analyst model API spans the rows of the three steps that call it (triage, tune and detect). The persona model API lines up with the SSH honeypot, the only front-end that calls a model. The tracked list and the sightings copy sit on ship's row, the step that moves them, and the operator's cloud sits under them in the bottom band. The InternetDB files (the wanted list and the checked answers) sit under them, also beside ship, and Shodan InternetDB sits at the left of the bottom band. The IP lookup files sit in their own small zone under the front-ends, beside the agents container that reads them. Third-party services run along the bottom, and the legend and the numbered flows fill the right-hand column.

### Colors and lines

| Mark | Meaning |
|---|---|
| Blue box | Application code: the front-ends and the agents |
| Green box | Safeguards: the approval queue, the operator, the operator console, and enforcement after approval |
| Amber box | Untrusted input from attackers, or a third-party service |
| Purple box | A model provider |
| Gray box | Bundled read-only data, or server-only output |
| Small dark tab with a number | The start of a numbered flow |
| Red arrow | A flow that carries a credential |
| Double-headed red arrow | A request with the credential to a provider, and its answer back |
| Dashed rectangle | A trust boundary |
| Dashed gray arrow | A read-only read: bundled configuration, agent output the front-ends read back, or what the console displays |

In the dark export Excalidraw's own dark theme shifts every color, so the same roles read as lighter strokes on dark fills.

### Trust boundaries

- **Internet (untrusted).** Scanners, bots and people. Everything they send is attacker-supplied.
- **Front-ends.** The SSH honeypot and the protocol traps (SIP, FTP, Telnet, SMTP, HTTP, S3, Redis, PostgreSQL, MySQL, MSSQL, HL7). They only write events. What they pretend to be comes from `config.ini` and `scenario.toml`, with bait generated per sensor.
- **Captured data.** The event log (JSON lines) and the quarantine, where FTP and S3 uploads are stored by SHA-256 and never run. Its content is attacker-supplied, so the agents treat it as untrusted.
- **Agents container.** `python -m agents run-all`, once an hour, in a separate container: triage, respond, digest, tune, detect, and ship, which runs whichever exports and lookups are enabled (event export, tracked export, sightings fetch, InternetDB). Agents never talk to attackers.
- **Agent outputs.** Local files: `reports/`, per-source state, `decoy/overlay.json`, `detections/pending`, the tracked list (`tracked.json`) with the local copy of `sightings.json`, and the InternetDB files: the checked answers (`internetdb.json`) and, in delivered mode, the wanted list (`internetdb_wanted.json`).
- **Operator approval.** Enforce actions wait in the approval queue until the operator approves or rejects them. Nothing outside the honeypot changes without that approval. With `[respond] track_before_enforce`, an approved block only goes on the tracked list, and blocking it is a second decision. The operator console (`python -m agents ui`) is here too: it binds loopback only and is reached through a tunnel. Read-only by default; with actions on it is in the same trust zone as the agents container.
- **Local files, no network.** The IP lookup databases (`[geoip]`): MaxMind-format `.mmdb` files for location and network owner (DB-IP Lite or MaxMind GeoLite2) that the operator puts on disk. They are read with no network call of any kind, and everything read from them is cleaned and checked like other data. Off unless a path is set.
- **Model providers (internet).** The persona model API (optional; without a key the shell gives canned replies) and the analyst model API, whose output must pass a schema check. Models get no tools.
- **Third-party services (internet).** Notify connectors (webhook, SIEM, email; off by default), an S3 bucket for a SIEM, the ticket system and block webhook that enforcement calls, and the operator's own cloud (an object store or HTTPS endpoint) that receives `tracked.json` and supplies `sightings.json` and, with the InternetDB hand-off, receives the wanted list and supplies the answers. Shodan InternetDB (keyless; only source addresses are sent) answers with open ports, host names, tags, CPEs and known CVE ids. Whatever comes back from any of them is untrusted.

### Numbered flows

1. **Attackers.** Logins and commands reach the SSH honeypot; logins, registers and queries reach the protocol traps.
2. **Persona.** The SSH honeypot sends prompts with the persona key to the persona model API and gets the replies back. Its use is budgeted.
3. **Events.** Both front-ends write events to the event log. The FTP and S3 traps put uploads in quarantine.
4. **Read.** Triage reads the new lines of the event log.
5. **Analyst calls.** Triage (transcripts), tune (candidates) and detect (patterns) call the analyst model API with the analyst key. Each answer is JSON that must pass a schema check.
6. **Agent outputs.** Triage writes records and digest writes the daily digest and run log to `reports/`; respond writes tarpit and depth to per-source state; tune writes bait changes to `decoy/overlay.json`; detect writes Sigma drafts and blocklist candidates to `detections/pending`.
7. **Respond.** Playbooks matched by code send notifications through the notify connectors, with their credentials, and file enforce requests in the approval queue.
8. **Approval.** The operator reviews the queue and approves or rejects. Only approved actions reach enforcement: the blocklist file, publishing a detection from `detections/pending`, and calls to the ticket system and block webhook.
9. **Read-only feedback.** The front-ends read `decoy/overlay.json` and per-source state. They never write anything the agents produce.
10. **Export.** When `[connector.s3_events]` is enabled, ship sends new event log lines to the S3 bucket, with passwords hashed by default.
11. **Track before enforce.** With `[respond] track_before_enforce = true`, approving `export_blocklist` or `block_webhook` puts the address on the tracked list (`tracked.json`) instead of blocking it. Blocking takes a second, separate decision (`python -m agents enforce <address>` or the console's Enforce), which runs the approval checks again.
12. **Tracked export.** When `[connector.tracked_export]` is enabled, ship reads `tracked.json` and sends it, as one object, to the operator's object store or HTTPS endpoint, with that connector's credential, so the operator's cloud can watch the list (for example as a threat list).
13. **Sightings.** When `[connector.sightings]` is enabled, ship fetches `sightings.json` from the operator's environment and keeps a local copy, which the console shows next to each tracked entry. It is untrusted input, parsed strictly, and display only: nothing acts on a sighting.
14. **Operator console.** The operator reaches the console, which binds loopback only, through `ssh -L` or SSM port forwarding; on the AWS template, optionally over a mesh VPN (tailnet), with nothing new open to the internet. It reads the event log, the agent outputs and the sightings copy. With actions on, it writes what `approve`, `reject`, `unblock` and `enforce` write (approval queue, blocklist, `tracked.json`) through the same checks as the CLI. The tailnet option is shown only as a label on this flow; its details, including how the AWS exporter's egress is pinned by host rules, are in [deploy/aws/README.md](../../deploy/aws/README.md) and [security-model.md](../security-model.md#operator-console).

15. **IP lookup.** Triage, the digest and the console read the local IP lookup files for each source address's country, region, city and network owner (AS number). No network call. Triage stores the answer on each record. The arrow ends at the agents container; the console's read of the same files is not drawn separately.
16. **InternetDB lookup.** When `[connector.internetdb]` is enabled, ship sends the source addresses of records judged suspicious or malicious, or that used a honeytoken (only the address, no key, at a fixed host) to Shodan InternetDB and gets open ports, host names, tags, CPEs and known CVE ids back. Every answer must pass the answer checks before it is written to `internetdb.json`, which triage (onto the record) and the console read. Nothing acts on it, and none of it goes to a model. Which process asks depends on the config:
    - `mode = direct` (the default): ship asks InternetDB itself. This is the gray arrow from ship to Shodan InternetDB, and only the "checked answers" arrow of the pair beside ship is used.
    - `mode = delivered` with `[connector.internetdb_exchange] kind = lookup`: `run-all` writes the wanted list, and ship in the process that has the egress (on AWS, the exporter, never the agents container) reads it, asks InternetDB itself, and writes the checked answers. This uses the same gray arrow and both arrows of the pair (wanted list, checked answers).
17. **InternetDB hand-off.** `mode = delivered` with `kind = s3`: ship puts the wanted list (addresses only) in the operator's object store and fetches the answers from it, with the exporter's credential, like flows 12 and 13. Something outside the sensor asks InternetDB and writes the answers; that producer is not drawn. The answers file is refused whole when too large, and each answer is checked on its own as in flow 16 before it reaches `internetdb.json`. This is the double-headed red arrow from ship to the operator's cloud, and both arrows of the pair beside ship.

## Editing and re-exporting

1. Open [excalidraw.com](https://excalidraw.com) and load the `.excalidraw` source (menu, Open). Labels are bound to their boxes and arrows to their ends, so a box can be dragged and its arrows follow. Each zone is a group; double-click into a group to move one box.
2. Arrows with corners are Excalidraw elbow arrows whose middle segments are pinned, so the app keeps their lanes when a box moves. Straight arrows are plain arrows. A straight arrow's label sits on its middle segment, so some straight arrows carry two extra points on the line to place the label in a gap.
3. Keep the conventions: the code font, sloppiness 2, the three text sizes (40, 18, and 14), and the colors in the table above.
4. Save the scene (menu, Save to, Disk). Then export PNG and SVG twice, in dark and light theme (menu, Export image; turn off "Embed scene"), and replace the four image files here.

The images here were exported offline through Excalidraw's own restore and export code (`@excalidraw/excalidraw` 0.18.1) in headless Chromium, then rasterized at 3200 pixels wide. Long coordinates in the SVGs are rounded to four decimals.
