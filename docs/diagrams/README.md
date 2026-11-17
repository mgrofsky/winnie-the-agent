# Data-flow diagram

![Winnie the Agent: data flow and trust boundaries](winnie-dataflow.png)

The diagram is drawn in Excalidraw; the `.excalidraw` source is kept outside this repository. It is drawn in Excalidraw's hand-drawn style: the code font (Comic Shanns) for all text and sloppiness 2 on every element. `winnie-dataflow.svg` and `winnie-dataflow.png` are the dark-theme export, the primary one; `winnie-dataflow-light.svg` and `winnie-dataflow-light.png` are the light-theme export of the same scene. Both PNGs are 3200 pixels wide, and both SVGs embed the font they use.

## Reading the diagram

The columns run left to right in the order data moves: attackers on the internet, the front-ends that face them, the captured data they write, the agents pipeline, the files the agents write, operator approval, and the model providers. Each pipeline step is a row. The file a step writes sits on that step's row, and the analyst model API spans the rows of the three steps that call it (triage, tune and detect). The persona model API lines up with the SSH honeypot, the only front-end that calls a model. Third-party services run along the bottom, and the legend and the numbered flows fill the right-hand column.

### Colors and lines

| Mark | Meaning |
|---|---|
| Blue box | Application code: the front-ends and the agents |
| Green box | Safeguards: the approval queue, the operator, and enforcement after approval |
| Amber box | Untrusted input from attackers, or a third-party service |
| Purple box | A model provider |
| Gray box | Bundled read-only data, or server-only output |
| Small dark tab with a number | The start of a numbered flow |
| Red arrow | A flow that carries a credential |
| Double-headed red arrow | A request with the credential to a provider, and its answer back |
| Dashed rectangle | A trust boundary |
| Dashed gray arrow | A read-only read: bundled configuration, or agent output the front-ends read back |

In the dark export Excalidraw's own dark theme shifts every color, so the same roles read as lighter strokes on dark fills.

### Trust boundaries

- **Internet (untrusted).** Scanners, bots and people. Everything they send is attacker-supplied.
- **Front-ends.** The SSH honeypot and the protocol traps (SIP, FTP, Telnet, SMTP, HTTP, S3, Redis, PostgreSQL, MySQL, MSSQL, HL7). They only write events. What they pretend to be comes from `config.ini` and `scenario.toml`, with bait generated per sensor.
- **Captured data.** The event log (JSON lines) and the quarantine, where FTP and S3 uploads are stored by SHA-256 and never run. Its content is attacker-supplied, so the agents treat it as untrusted.
- **Agents container.** `python -m agents run-all`, once an hour, in a separate container: triage, respond, digest, tune, detect, and ship when the event export is enabled. Agents never talk to attackers.
- **Agent outputs.** Local files: `reports/`, per-source state, `decoy/overlay.json`, and `detections/pending`.
- **Operator approval.** Enforce actions wait in the approval queue until the operator approves or rejects them. Nothing outside the honeypot changes without that approval.
- **Model providers (internet).** The persona model API (optional; without a key the shell gives canned replies) and the analyst model API, whose output must pass a schema check. Models get no tools.
- **Third-party services (internet).** Notify connectors (webhook, SIEM, email; off by default), an S3 bucket for a SIEM, and the ticket system and block webhook that enforcement calls.

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

## Editing and re-exporting

1. Open [excalidraw.com](https://excalidraw.com) and load the `.excalidraw` source (menu, Open). Labels are bound to their boxes and arrows to their ends, so a box can be dragged and its arrows follow. Each zone is a group; double-click into a group to move one box.
2. Arrows with corners are Excalidraw elbow arrows whose middle segments are pinned, so the app keeps their lanes when a box moves. Straight arrows are plain arrows. A straight arrow's label sits on its middle segment, so some straight arrows carry two extra points on the line to place the label in a gap.
3. Keep the conventions: the code font, sloppiness 2, the three text sizes (40, 18, and 14), and the colors in the table above.
4. Save the scene (menu, Save to, Disk). Then export PNG and SVG twice, in dark and light theme (menu, Export image; turn off "Embed scene"), and replace the four image files here.

The images here were exported offline through Excalidraw's own restore and export code (`@excalidraw/excalidraw` 0.18.1) in headless Chromium, then rasterized at 3200 pixels wide.
