"""Canary payloads and a page watcher shared by the browser tests."""

from __future__ import annotations

import datetime
import uuid
from dataclasses import dataclass, field

from console_lab import Lab
from ui_fixture import _append, ssh_lines

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
