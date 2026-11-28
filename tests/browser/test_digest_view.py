"""The Digests screen in Chromium: a digest's Markdown shown as formatted text built from
text nodes, links only to the console's own routes, a plain-text view past the reader's
limits, the raw Markdown on request, and a download that is the file as written."""

from __future__ import annotations

import pytest

pytest.importorskip("playwright")

from playwright.sync_api import expect  # noqa: E402

from browser_support import (  # noqa: E402
    DIGEST_DAY, DIGEST_IMG, DIGEST_LONG, DIGEST_RECORD, DIGEST_SCRIPT, digest_fixture, watch)
from test_browser_console import assert_nothing_injected  # noqa: E402

pytestmark = pytest.mark.browser


def plant_digest(lab, text: str, day: str = DIGEST_DAY):
    path = lab.tree.reports / "daily" / f"{day}.md"
    path.write_text(text, encoding="utf-8")
    return path


def open_digest(page, lab, day: str = DIGEST_DAY):
    page.goto(f"{lab.base_url}/#/digests/{day}")
    page.wait_for_load_state("networkidle")
    expect(page.get_by_role("heading", level=2, name=f"Digest for {day}")).to_be_visible()


def tags(locator) -> list[str]:
    return locator.evaluate_all("(nodes) => nodes.map((n) => n.tagName.toLowerCase())")


def test_a_digest_renders_as_formatted_text_and_executes_nothing(browser, lab):
    plant_digest(lab, digest_fixture())
    # bypass_csp: an injected handler or script would run, so only the console's own
    # escaping stands between the payloads and the page.
    context = browser.new_context(bypass_csp=True)
    page = context.new_page()
    seen = watch(page)
    try:
        page.goto(lab.sign_in_url)
        page.get_by_role("navigation", name="Sections").wait_for()
        open_digest(page, lab)
        md = page.locator("main .md")
        expect(md).to_have_count(1)

        # Headings sit under the section's h2: # is h3, ## is h4, ### is h5.
        expect(md.locator("h3")).to_have_text([f"Honeypot digest {DIGEST_DAY}"])
        expect(md.locator("h4")).to_have_text(["Top three needing attention", "Notes", "Sources"])
        expect(md.locator("h5")).to_have_text(["ftp"])

        # Lists: the numbered top three with bulleted parts nested two deep, and five levels.
        expect(md.locator("ol > li")).to_have_count(2)
        expect(md.locator("ol > li > ul > li > ul > li")).to_have_count(2)
        expect(md.locator("ul ul ul ul ul > li")).to_have_text(["level 5"])
        expect(md.locator("ol > li").first.locator(":scope > ul > li").first.locator("strong > code")) \
            .to_have_text("Downloader fetched and ran a **payload** <b>bold</b>")

        # Tables: header cells, every body row, alignment from the delimiter row.
        tables = md.locator("table")
        expect(tables).to_have_count(2)
        expect(tables.first.locator("th[scope=col]")).to_have_text(["Judgement", "Count"])
        expect(tables.first.locator("tbody tr")).to_have_count(3)
        expect(tables.nth(1).locator("tbody tr")).to_have_count(200)
        expect(tables.nth(1).locator("tbody td")).to_have_count(1200)
        assert tables.nth(1).locator("th").evaluate_all("(n) => n.map((c) => c.className)") == \
            ["md-left", "md-center", "md-right", "", "md-right", ""]

        # Inline: bold, italic, code (an escaped pipe is a pipe), the fence, quote, rule.
        expect(md.locator("p em")).to_have_text(["italic", "also italic"])
        expect(md.locator("p strong").first).to_have_text("bold")
        expect(md.get_by_text("uname -a; cat /proc/cpuinfo | grep name", exact=True)).to_have_count(1)
        expect(md.locator("pre.md-pre > code")).to_contain_text("<script>window.__winnie_xss = 'fence'</script>")
        expect(md.locator("blockquote > p > code")).to_have_text(["code"])
        expect(md.locator("blockquote blockquote")).to_have_text("A nested quote.")
        expect(md.locator("hr")).to_have_count(1)
        expect(md.locator("code").filter(has_text=DIGEST_LONG)).to_have_count(1)

        # Links: only the console's own routes; every other target is the text as written.
        hrefs = md.locator("a").evaluate_all("(n) => n.map((a) => a.getAttribute('href'))")
        assert hrefs == [f"#/records/{DIGEST_RECORD}", "#/digests/2026-01-14", "#/queue"]
        for written in ("[guide](https://example.com/guide)",
                        "[run](javascript:window.__winnie_xss='link')",
                        "[bad route](#/records/<script>)",
                        "![tracker](https://example.com/t.png)",
                        "<a href=\"#/\" onclick=\"window.__winnie_xss='a'\">a tag</a>",
                        "&lt;b&gt; &amp; &#60;script&#62;"):
            expect(md).to_contain_text(written)

        # Hostile text is visible as text, and nothing it holds became markup or ran.
        expect(md.get_by_text(DIGEST_SCRIPT, exact=True)).to_have_count(1)
        expect(md).to_contain_text(DIGEST_IMG)
        assert set(tags(md.locator("*"))) <= {
            "h3", "h4", "h5", "p", "ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td",
            "div", "code", "pre", "strong", "em", "a", "blockquote", "hr"}
        page.get_by_role("link", name="the first record").hover()
        assert_nothing_injected(page)
        assert seen.problems() == []
    finally:
        context.close()


def test_raw_markdown_and_download_give_the_file_as_written(signed_in, lab):
    page, seen = signed_in
    path = plant_digest(lab, digest_fixture())
    open_digest(page, lab)
    toggle = page.get_by_role("button", name="Raw Markdown")
    expect(toggle).to_have_attribute("aria-pressed", "false")
    toggle.click()
    expect(toggle).to_have_attribute("aria-pressed", "true")
    expect(page.locator("main .md")).to_have_count(0)
    raw = page.locator("main pre.text-block")
    assert raw.text_content() == path.read_text(encoding="utf-8")
    toggle.click()
    expect(page.locator("main .md h3")).to_have_text(f"Honeypot digest {DIGEST_DAY}")

    with page.expect_download() as info:
        page.get_by_role("button", name="Download Markdown").click()
    download = info.value
    assert download.suggested_filename == f"digest-{DIGEST_DAY}.md"
    assert download.failure() is None
    assert open(download.path(), "rb").read() == path.read_bytes()
    assert seen.problems() == []


def test_the_writers_own_digest_downloads_byte_for_byte(signed_in, lab):
    page, seen = signed_in
    path = sorted((lab.tree.reports / "daily").glob("????-??-??.md"))[-1]
    day = path.stem
    open_digest(page, lab, day)
    expect(page.locator("main .md h3")).to_have_text(f"Honeypot digest {day}")
    expect(page.locator("main .md ol > li")).to_have_count(3)
    with page.expect_download() as info:
        page.get_by_role("button", name="Download Markdown").click()
    assert open(info.value.path(), "rb").read() == path.read_bytes()
    assert seen.problems() == []


DEEP_LIST = "\n".join("  " * depth + f"- level {depth}" for depth in range(12))
PAST_LIMITS = {
    "line": "# Long\n\n" + "x" * 20_001 + "\n",
    "depth": DEEP_LIST + "\n",
    "quotes": ">" * 5000 + " deep\n",
    "rows": "| a | b |\n|---|---|\n" + "| 1 | 2 |\n" * 501,
    "columns": "|" + " a |" * 21 + "\n|" + "---|" * 21 + "\n",
    "nodes": "- `a` b\n" * 12_000,
}


@pytest.mark.parametrize("bound", sorted(PAST_LIMITS))
def test_a_digest_past_a_limit_is_shown_as_plain_text(signed_in, lab, bound):
    page, seen = signed_in
    text = PAST_LIMITS[bound]
    plant_digest(lab, text)
    open_digest(page, lab)
    main = page.locator("main")
    expect(main.get_by_text("Shown as plain text")).to_be_visible()
    expect(main.locator(".md")).to_have_count(0)
    expect(main.get_by_role("button", name="Raw Markdown")).to_have_count(0)
    assert main.locator("pre.text-block").text_content() == text
    expect(main.get_by_role("button", name="Download Markdown")).to_be_visible()
    assert seen.problems() == []


def test_a_cut_digest_offers_no_download(signed_in, lab):
    page, seen = signed_in
    plant_digest(lab, "# Big\n\n" + ("- `x` y\n" * 30_000))
    open_digest(page, lab)
    main = page.locator("main")
    expect(main).to_contain_text("Cut at 200,000 characters; the full file is on the host")
    expect(main.get_by_role("button", name="Download Markdown")).to_have_count(0)
    assert seen.problems() == []
