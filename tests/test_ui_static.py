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
    "/api/digests",
    "/api/digests/",
    "/api/decoy",
    "/api/playbooks",
    "/api/detections",
    "/api/detections/",
    "/api/honeytokens",
}
# Suffixes appended after an id: GET /api/records/{id}/transcript and
# POST /api/queue/{id}/approve|reject.
API_SUFFIXES = {"/transcript", "/approve", "/reject"}


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


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.parametrize("path", JS_FILES, ids=lambda p: p.name)
def test_js_parses(path):
    result = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True,
                            timeout=60)
    assert result.returncode == 0, result.stderr
