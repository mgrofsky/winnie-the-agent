"""The operator console in Chromium: sign-in, every section, Activity, one approval end to
end, and attacker-controlled strings shown as text with nothing executed."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright")

from playwright.sync_api import expect  # noqa: E402

from browser_support import (  # noqa: E402
    CANARIES, CANARY_ATTR, CANARY_SCRIPT, CANARY_SESSION, CANARY_SOURCE, CANARY_USER, watch)
from ui_fixture import IMG, SCRIPT  # noqa: E402

pytestmark = pytest.mark.browser

SECTIONS = {
    "#/": "Overview",
    "#/queue": "Approval queue",
    "#/records": "Records",
    "#/digests": "Daily digests",
    "#/decoy": "Decoy",
    "#/playbooks": "Playbooks",
    "#/activity": "Activity",
}

# True if any element carries an inline event handler attribute or a javascript: URL.
HANDLER_ATTRIBUTES = """() => [...document.querySelectorAll('*')].some((el) =>
    [...el.attributes].some((a) => a.name.startsWith('on')
        || /^\\s*javascript:/i.test(a.value)))"""


def open_section(page, base_url: str, hash_: str) -> None:
    page.goto(f"{base_url}/{hash_}")
    page.wait_for_load_state("networkidle")
    expect(page.get_by_role("heading", level=1).first).to_have_text(SECTIONS[hash_])


def assert_nothing_injected(page) -> None:
    assert page.evaluate("() => window.__winnie_xss") is None
    # The console loads exactly one script, its own, from the fixed static table.
    scripts = page.evaluate("() => [...document.scripts].map((s) => s.src)")
    assert scripts == [page.url.split("/#")[0].rstrip("/") + "/static/app.js"]
    assert page.locator("img, svg[onload], iframe, object, embed").count() == 0
    assert page.evaluate(HANDLER_ATTRIBUTES) is False


# ---- sign-in -------------------------------------------------------------------------------

def test_without_a_session_the_console_shows_only_the_signed_out_page(lab, page):
    seen = watch(page)
    response = page.goto(lab.base_url + "/")
    assert response.status == 401
    expect(page.locator("body")).to_contain_text("Not signed in")
    # The signed-out page has no script, form or link: the only way in is the logged link.
    assert page.locator("script, form, a").count() == 0
    assert page.context.cookies() == []
    assert seen.failed == [f"401 GET {lab.base_url}/"]


def test_a_wrong_token_is_refused_and_sets_no_cookie(lab, page):
    response = page.goto(lab.base_url + "/?token=" + "x" * 43)
    assert response.status == 403
    assert page.context.cookies() == []


def test_the_sign_in_link_sets_an_httponly_strict_cookie_and_drops_the_token(lab, page):
    seen = watch(page)
    page.goto(lab.sign_in_url)
    page.get_by_role("navigation", name="Sections").wait_for()
    assert page.url == lab.base_url + "/"
    [cookie] = page.context.cookies()
    assert cookie["name"] == "winnie_ui" and cookie["httpOnly"] is True
    assert cookie["sameSite"] == "Strict" and cookie["secure"] is False
    assert lab.token not in cookie["value"]
    # HttpOnly: the page's own script cannot read the session.
    assert page.evaluate("() => document.cookie") == ""
    # COOP same-origin with COEP require-corp: the page runs cross-origin isolated.
    assert page.evaluate("() => window.crossOriginIsolated") is True
    assert seen.problems() == []


def test_losing_the_session_shows_signed_out_and_stops(signed_in, lab):
    page, _ = signed_in
    page.context.clear_cookies()
    page.goto(lab.base_url + "/#/records")
    expect(page.get_by_role("heading", name="Signed out")).to_be_visible()
    expect(page).to_have_title("Signed out - Winnie console")


# ---- every section -------------------------------------------------------------------------

@pytest.mark.parametrize("hash_", list(SECTIONS))
def test_each_section_loads_without_console_errors_or_failed_requests(signed_in, lab, hash_):
    page, seen = signed_in
    open_section(page, lab.base_url, hash_)
    expect(page.locator("main")).not_to_contain_text("could not be loaded")
    assert seen.problems() == []
    assert_nothing_injected(page)


def test_keyboard_shortcuts_reach_every_section(signed_in, lab):
    page, seen = signed_in
    for number, title in enumerate(SECTIONS.values(), start=1):
        page.keyboard.press(str(number))
        expect(page.get_by_role("heading", level=1).first).to_have_text(title)
    assert seen.problems() == []


# ---- activity ------------------------------------------------------------------------------

def test_activity_lists_the_fixture_events(signed_in, lab):
    page, seen = signed_in
    open_section(page, lab.base_url, "#/activity")
    main = page.locator("main")
    for service in ("ftp", "redis", "ssh"):
        expect(main.get_by_role("option", name=re.compile(rf"^{service} \(\d+\)$"))).to_be_attached()
    rows = main.locator("tbody tr")
    expect(rows.first).to_be_visible()
    for text in ("198.51.100.7", "198.51.100.8", "198.51.100.20", "198.51.100.21",
                 "CONFIG SET dir /root/.ssh", "cat /etc/shadow", "login admin"):
        expect(main).to_contain_text(text)
    assert seen.problems() == []


def test_activity_session_page_shows_the_transcript(signed_in, lab):
    page, seen = signed_in
    session = lab.tree.ids["session_b"]
    page.goto(f"{lab.base_url}/#/activity/session/{session}")
    page.wait_for_load_state("networkidle")
    expect(page.get_by_role("heading", level=1)).to_have_text(session)
    expect(page.locator("main")).to_contain_text("cat /etc/shadow")
    expect(page.locator("main")).to_contain_text(IMG)
    assert seen.problems() == []
    assert_nothing_injected(page)


# ---- one approval end to end ---------------------------------------------------------------

def test_approving_a_pending_item_runs_it_and_closes_it(signed_in, lab):
    page, seen = signed_in
    aid = lab.tree.ids["pending"]
    blocklist = lab.tree.reports / "blocklist" / "approved.txt"
    assert "198.51.100.21" not in blocklist.read_text().split()
    open_section(page, lab.base_url, "#/queue")
    card = page.locator("main").locator(".card", has_text=aid)
    card.get_by_role("button", name="Approve", exact=True).click()
    confirm = page.get_by_role("group", name="Confirmation")
    expect(confirm).to_contain_text("Approve and run export_blocklist on 198.51.100.21?")
    # Focus starts on Cancel, so a stray Enter decides nothing.
    expect(confirm.get_by_role("button", name="Cancel")).to_be_focused()
    with page.expect_response(lambda r: r.url.endswith(f"/api/queue/{aid}/approve")) as answer:
        confirm.get_by_role("button", name="Approve and run").click()
    response = answer.value
    assert response.status == 200
    request = response.request
    assert request.method == "POST"
    assert request.header_value("x-winnie-csrf")
    assert request.header_value("origin") == lab.base_url
    expect(page.get_by_role("status").filter(has_text=f"Approve {aid}: done.")).to_be_visible()
    assert "198.51.100.21" in blocklist.read_text().split()
    expect(page.locator("main")).to_contain_text("Nothing is waiting for a decision.")
    assert seen.problems() == []


# ---- attacker-controlled strings -----------------------------------------------------------

def test_attacker_strings_render_as_text_and_execute_nothing(browser, lab):
    # bypass_csp: an injected handler or script would run, so only the console's own
    # escaping stands between the payloads and the page.
    context = browser.new_context(bypass_csp=True)
    page = context.new_page()
    seen = watch(page)
    page.goto(lab.sign_in_url)
    page.get_by_role("navigation", name="Sections").wait_for()
    try:
        page.goto(f"{lab.base_url}/#/activity/session/{CANARY_SESSION}")
        page.wait_for_load_state("networkidle")
        main = page.locator("main")
        for payload in CANARIES:
            expect(main).to_contain_text(payload)
        expect(main).to_contain_text(CANARY_USER)
        main.get_by_text(CANARY_USER).first.hover()
        assert_nothing_injected(page)

        page.goto(f"{lab.base_url}/#/activity?src={CANARY_SOURCE}")
        page.wait_for_load_state("networkidle")
        expect(page.locator("main")).to_contain_text(CANARY_SCRIPT)
        for row in page.locator("main tbody tr").all()[:6]:
            row.click()
        assert_nothing_injected(page)

        for hash_ in ("#/", "#/queue", "#/records", "#/playbooks"):
            open_section(page, lab.base_url, hash_)
            expect(page.locator("main")).to_contain_text(SCRIPT)
            assert_nothing_injected(page)
        assert seen.problems() == []
    finally:
        context.close()


def test_hostile_hash_routes_render_as_text(signed_in, lab):
    page, seen = signed_in
    for route in (f"#/records/{CANARY_SCRIPT}", f"#/activity/session/{CANARY_ATTR}",
                  "#/activity?src=%3Cimg%20src%3Dx%20onerror%3D1%3E"):
        page.goto(f"{lab.base_url}/{route}")
        page.wait_for_load_state("networkidle")
        assert_nothing_injected(page)
    assert all(not m.startswith("dialog") for m in seen.problems())
