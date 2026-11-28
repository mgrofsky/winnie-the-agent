"""Static checks over the operator console front-end (agents/ui/static).

There is no JavaScript test runner in this repository, so these tests hold the front-end
to its security rules by reading the files: every file is served from the fixed table,
no script uses an HTML-parsing or code-evaluating sink or browser storage, the HTML has
no inline code or styles, nothing points at another host, and the script requests only
API routes the server has.
"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from agents.ui.server import STATIC_DIR, STATIC_FILES

FILES = sorted(p for p in STATIC_DIR.iterdir() if p.is_file())
JS_FILES = [p for p in FILES if p.suffix == ".js"]
HTML_FILES = [p for p in FILES if p.suffix == ".html"]

# The one URL-shaped string a standalone SVG file must carry. It names a namespace and is
# never fetched.
SVG_NAMESPACE = 'xmlns="http://www.w3.org/2000/svg"'

FORBIDDEN_JS = [
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "DOMParser",
    "createContextualFragment", "eval(", "new Function", 'setAttribute("style"',
    "setAttribute('style'", "javascript:", "localStorage", "sessionStorage", "indexedDB",
    "document.cookie", "srcdoc",
]

# Every API path literal the script may contain: the routes in the console's API contract.
# Dynamic parts (ids, days, file names) are appended in code after these prefixes.
API_LITERALS = {
    "/api/session",
    "/api/overview",
    "/api/records",
    "/api/records/",
    "/api/queue",
    "/api/queue/",
    "/api/blocklist",
    "/api/blocklist/unblock",
    "/api/blocklist/enforce",
    "/api/digests",
    "/api/digests/",
    "/api/decoy",
    "/api/playbooks",
    "/api/detections",
    "/api/detections/",
    "/api/honeytokens",
    "/api/activity",
    "/api/activity/session/",
    "/api/map",
}
# Suffixes appended after an id: GET /api/records/{id}/transcript|replies and
# POST /api/queue/{id}/approve|reject.
API_SUFFIXES = {"/transcript", "/replies", "/approve", "/reject"}


def test_static_dir_has_files():
    names = {p.name for p in FILES}
    assert {"index.html", "app.js", "app.css"} <= names


def test_every_static_file_is_served_and_every_entry_exists():
    served = {name for name, _ in STATIC_FILES.values()}
    on_disk = {p.name for p in FILES}
    assert on_disk == served
    for path, (name, ctype) in STATIC_FILES.items():
        assert (STATIC_DIR / name).is_file(), path
        assert path in ("/", "/index.html") or path == "/static/" + name
        assert ctype


def test_content_types_match_extensions():
    expected = {
        ".html": "text/html; charset=utf-8",
        ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".svg": "image/svg+xml",
    }
    for name, ctype in STATIC_FILES.values():
        suffix = "." + name.rsplit(".", 1)[-1]
        assert ctype == expected[suffix], name


@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_js_has_no_forbidden_sink(path):
    text = path.read_text(encoding="utf-8")
    for needle in FORBIDDEN_JS:
        assert needle not in text, f"{path.name} contains {needle!r}"
    assert not re.search(r"\bdocument\.writeln\b", text)
    assert not re.search(r"\bsetTimeout\(\s*['\"`]", text), "string passed to setTimeout"
    assert not re.search(r"\bsetInterval\(\s*['\"`]", text), "string passed to setInterval"
    assert not re.search(r"\.on[a-z]+\s*=(?!=)", text), "event handler property; use addEventListener"
    assert not re.search(r"\bimport\s*\(", text), "dynamic import"


@pytest.mark.parametrize("path", HTML_FILES, ids=lambda p: p.name)
def test_html_has_no_inline_code_or_styles(path):
    text = path.read_text(encoding="utf-8")
    for tag in re.findall(r"<script\b[^>]*>", text, flags=re.I):
        assert re.search(r'\bsrc="/static/[a-z0-9_-]+\.js"', tag), tag
    bodies = re.findall(r"<script\b[^>]*>(.*?)</script>", text, flags=re.I | re.S)
    assert len(bodies) == len(re.findall(r"<script\b", text, flags=re.I))
    assert all(not body.strip() for body in bodies)
    assert not re.search(r"<style\b", text, flags=re.I)
    assert not re.search(r"\sstyle\s*=", text, flags=re.I)
    assert not re.search(r"\son[a-z]+\s*=", text, flags=re.I)
    assert not re.search(r"<(?:iframe|object|embed|base|form)\b", text, flags=re.I)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_file_references_another_host(path):
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".svg":
        assert text.count(SVG_NAMESPACE) == 1
        text = text.replace(SVG_NAMESPACE, "")
    assert not re.search(r"(?i)https?:", text), path.name
    assert not re.search(r"(?i)(?<![:/\w])//[a-z0-9.-]+\.[a-z]{2,}", text), path.name
    assert not re.search(r"(?i)\bdata:", text), path.name
    assert "@import" not in text and "url(" not in text, path.name


def test_svg_has_no_script_or_links():
    for path in FILES:
        if path.suffix != ".svg":
            continue
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"(?i)<script|<foreignObject|\shref=|\son[a-z]+=", text), path.name


@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_js_requests_only_known_api_routes(path):
    text = path.read_text(encoding="utf-8")
    literals = re.findall(r"""["'`](/api[^"'`]*)["'`]""", text)
    assert literals, "no API paths found"
    unknown = sorted(set(literals) - API_LITERALS)
    assert unknown == [], unknown
    # Every literal appended to an API prefix is a known route suffix.
    for suffix in re.findall(r"""\+\s*["'`](/[a-z]+)["'`]""", text):
        assert suffix in API_SUFFIXES, suffix
    # Network access goes through the one request helper.
    assert len(re.findall(r"\bfetch\(", text)) == 1
    assert "XMLHttpRequest" not in text and "WebSocket" not in text and "EventSource" not in text
    assert "sendBeacon" not in text


def test_index_loads_only_the_static_table():
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    refs = re.findall(r'(?:src|href)="([^"]+)"', html)
    assert refs
    for ref in refs:
        assert ref in STATIC_FILES, ref


def _function(text: str, name: str) -> str:
    """The source of one top-level ``function name(...)`` in app.js, up to the next one."""
    start = re.search(rf"\n  (?:async )?function {name}\(", text).start() + 1
    nxt = re.search(r"\n  (?:async )?function \w+\(", text[start + 1:])
    return text[start:start + 1 + nxt.start()] if nxt else text[start:]


def test_approval_card_acts_on_the_file_id_and_only_on_decidable_items():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    card = _function(text, "approvalCard")
    # Decisions go to the approval file's own name, checked against the id pattern, and only
    # for items the server marked decidable whose served id is that same name.
    assert "APPROVAL_ID_RE.test(item.id) ? item.id : null" in card
    assert "item.can_decide_here === true && a.id === id" in card
    assert 'decide("approve", id, viewHash, ctx)' in card
    assert 'decide("reject", id, viewHash, ctx)' in card
    assert "item.undecidable_reason" in card


def test_publish_detection_names_its_files_as_the_target():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    card = _function(text, "approvalCard")
    assert 'a.action === "publish_detection"' in card
    # The card title, the card's rows and the confirmation rows name the files; the source
    # is shown as context.
    assert '[" of ", fileNames(files)' in card
    assert '["Files", fileNames(files)], ["Source", mono(target)]' in card
    assert '"Approve and publish "' in card and "names.join" in card
    # File names come from the server's list and are re-checked against its pattern, and
    # are rendered as text nodes (mono / el with text), never as attributes.
    files = _function(text, "detectionFiles")
    assert "DETECTION_RE.test(f.name)" in files
    names = _function(text, "fileNames")
    assert "mono(f.name)" in names and "attrs" not in names


def test_confirmation_panel_label_is_fixed_text():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    panel = _function(text, "openConfirm")
    assert '"aria-label": "Confirmation"' in panel
    assert not re.search(r"attrs:\s*\{[^}]*opts\.", panel), "data in an attribute"


def test_withheld_transcript_is_said_up_front():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    record = _function(text, "drawRecord")
    assert 'typeof data.transcript_withheld === "string"' in record
    assert record.index("transcript_withheld") < record.index("transcriptView(id)")
    assert 'text: data.transcript_withheld' in record


def test_capped_answers_are_flagged_on_screen():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert "d.truncated === true" in _function(text, "fill")


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_js_parses(path):
    result = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True,
                            timeout=60)
    assert result.returncode == 0, result.stderr


def test_activity_links_only_checked_values():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    # A source from the log becomes a link only when it is plainly an address, and a
    # session only when it matches the server's session id pattern.
    assert "ADDRESS_RE.test(src) ? link(" in _function(text, "sourceLink")
    assert "SESSION_ID_RE.test(id)" in _function(text, "sessionHref")
    rows = _function(text, "addActivityRows")
    assert "attrs" not in rows.split("const toggle")[0]
    assert '"aria-label": "Show details"' in rows and "it." not in rows.split("const flip")[0]


def test_background_refresh_never_inserts_activity_rows():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    view = _function(text, "viewActivity")
    assert 'kind === "poll" ? checkNewActivity(ctx)' in view
    check = _function(text, "checkNewActivity")
    assert "after: ctx.newest" in check and "addActivityRows" not in check


def test_replies_say_when_none_was_recorded():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    replies = _function(text, "commandReplies")
    assert 'it.recorded === true' in replies and "replyNote(it.status)" in replies
    assert "API.replies(id)" in replies and "read_cut === true" in replies
    note = _function(text, "replyNote")
    assert '"no reply recorded"' in note
    assert 'status === "unmatched"' in note and "could not be matched" in note
    assert 'status === "not_read"' in note


def test_activity_cursors_carry_the_log_id_and_reload_when_it_changes():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    check = _function(text, "checkNewActivity")
    assert "after: ctx.newest, log_id: ctx.logId" in check
    assert "err.status === 409" in check and "logChanged(ctx)" in check
    foot = _function(text, "activityFoot")
    assert "before: cursor, log_id: ctx.logId" in foot
    assert "err.status === 409" in foot and "logChanged(ctx)" in foot
    changed = _function(text, "logChanged")
    assert "ctx.logNotice = " in changed and "manualRefresh()" in changed
    draw = _function(text, "drawActivity")
    assert "ctx.logId = " in draw and "ctx.logNotice" in draw


def test_activity_says_when_a_read_stopped_at_the_limit():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    assert "readCut === true" in _function(text, "activityFoot")
    session = _function(text, "drawActivitySession")
    assert "data.read_cut === true" in session and "data.events_cut === true" in session


def test_ssh_session_heading_is_accurate():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    session = _function(text, "drawActivitySession")
    assert 'data.connection_lines !== true' in session
    assert '"Logins and commands in this session, in order"' in session
    assert '"Everything in this session, in order"' in session


def test_every_section_has_a_number_key():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    sections = re.findall(r'\{ key: "([a-z]+)", label: "[A-Za-z ]+", hash: "#/', text)
    n = len(sections)
    assert "activity" in sections and "map" in sections and n == 8
    assert f"/^[1-{n}]$/.test(ev.key)" in text and f"Keys: 1-{n} switch sections" in text


def test_every_screen_says_what_it_is():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    views = re.findall(r"\n  function (view[A-Z]\w*)\(", text)
    for name in views:
        body = _function(text, name)
        if "pageHead(" in body and name != "viewNotFound":
            assert "intro(" in body or "lead" in body, name


def test_decoy_screen_speaks_in_words_with_raw_detail_behind_an_expander():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    draw = _function(text, "drawDecoy")
    for heading in ("Current adjustments to the fake system", "What the tuner changed and when",
                    "What returning attackers are shown"):
        assert f'"{heading}"' in draw, heading
    view = _function(text, "viewDecoy")
    assert "Nothing here needs a decision." in view
    # Internal field names are not used as labels; the raw data is text in an expander.
    for key in ("tarpit_ms", "budget_mode", "capture_more", "plant_token", "after_n"):
        assert f'label: "{key}' not in draw and f'"{key}"' not in draw, key
    assert "textBlock(JSON.stringify(value, null, 2))" in _function(text, "rawDetails")
    # Empty states say why and what would fill them.
    assert draw.count("empty(") >= 4
    assert "The tuner has not changed anything yet" in draw
    assert "No attacker has been singled out yet" in draw


def test_request_sequence_and_findings_are_text_with_the_raw_activity_link():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    record = _function(text, "drawRecord")
    assert "findingsSection(data.findings)" in record
    assert "requestSequence(r, id, sequence)" in record
    seq = _function(text, "requestSequence")
    assert "rawActivityLink(r, id)" in seq and "link(" not in seq.replace("rawActivityLink(", "")
    findings = _function(text, "findingsSection")
    # Source URLs are shown as text, never as links.
    assert "link(" not in findings and "href" not in findings
    assert '"-like"' in findings and "never used for the judgement or the blocklist" in findings


def test_map_keeps_attacker_text_out_of_attributes_and_reloads_on_a_new_log():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    start = text.index("  // ---- screen: map")
    end = text.index("  // ---- screen: not found")
    view = text[start:end]
    # Event and source values reach the page as text nodes or canvas text only.
    for attrs in re.findall(r"attrs:\s*\{[^}]*\}", view):
        assert not re.search(r"\b(it|s|o|src|d)\.", attrs), attrs
    for label in re.findall(r'setAttribute\("aria-label", ([^;]*)\);', view):
        assert not re.search(r"\b(it|o|src|d)\.|\.src\b|\.place\b|\.label\b", label), label
    # The delta poll carries the log id and starts over when the server says the log changed.
    poll = _function(text, "pollMap")
    assert "after: m.cursor, log_id: m.logId" in poll and "err.status === 409" in poll
    assert "loadMap(m)" in poll
    # Timers stop when the screen changes.
    assert "state.view.stop()" in _function(text, "render")
    assert "m.gen === state.gen" in _function(text, "alive")


def test_map_drops_answers_to_superseded_requests_and_rebuilds_sources():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    load = _function(text, "loadMap")
    assert "const req = ++m.req" in load and "req !== m.req" in load
    poll = _function(text, "pollMap")
    assert "const req = ++m.req" in poll and poll.count("req !== m.req") == 2
    assert "m.loading" in poll
    ingest = _function(text, "ingest")
    assert "m.sources = new Map()" in ingest and "busy.has(key)" in ingest


def test_map_motion_is_time_based_bounded_and_stable():
    text = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    start = text.index("  // ---- screen: map")
    end = text.index("  // ---- screen: not found")
    view = text[start:end]
    # A loop's phase comes from the event, so a redraw never reshuffles the dots.
    assert "Math.random" not in view
    motion = _function(text, "drawMotion")
    assert "stableHash(loop.key)" in motion and "dt / trip" in motion
    assert "const cap = flyingCap(m)" in motion and "flying >= cap" in motion
    assert "MAP_FLYING_PREVIEW : MAP_FLYING" in _function(text, "flyingCap")
    assert "slice(-flyingCap(m))" in _function(text, "ingest")
    # Elapsed time drives motion, capped so a hidden tab does not jump the dots.
    frame = _function(text, "frame")
    assert "Math.min(100" in frame and "document.hidden" in frame
    assert "m.paused || m.still ? 0 : drawMotion" in frame
