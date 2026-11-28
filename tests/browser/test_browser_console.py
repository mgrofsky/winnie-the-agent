"""The operator console in Chromium: sign-in, every section, Activity, one approval end to
end, and attacker-controlled strings shown as text with nothing executed."""

from __future__ import annotations

import datetime
import json
import re

import pytest

pytest.importorskip("playwright")

from playwright.sync_api import expect  # noqa: E402

from browser_support import (  # noqa: E402
    CANARIES, CANARY_ATTR, CANARY_SCRIPT, CANARY_SESSION, CANARY_SOURCE, CANARY_USER, watch)
from ui_fixture import IMG, SCRIPT, _append, map_lines  # noqa: E402

pytestmark = pytest.mark.browser

SECTIONS = {
    "#/": "Overview",
    "#/queue": "Approval queue",
    "#/records": "Records",
    "#/digests": "Daily digests",
    "#/decoy": "Decoy",
    "#/playbooks": "Playbooks",
    "#/activity": "Activity",
    "#/map": "Map",
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


# ---- map -----------------------------------------------------------------------------------

# Distinct colours in the canvas, read once (the land, sea and dots differ from a blank one).
CANVAS_COLOURS = """() => {
    const c = document.querySelector('canvas.map-canvas');
    const d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
    const seen = new Set();
    for (let i = 0; i < d.length; i += 4 * 97) seen.add(d[i] + ',' + d[i + 1] + ',' + d[i + 2] + ',' + d[i + 3]);
    return seen.size;
}"""


def flying(page) -> int:
    return int(page.locator(".map-counters .tile", has_text="In flight")
               .locator(".tile-value").inner_text())


IN_FLIGHT = """(least) => [...document.querySelectorAll('.map-counters .tile')]
    .some((t) => t.textContent.startsWith('In flight')
        && Number(t.querySelector('.tile-value').textContent) >= least)"""


def wait_until_flying(page, least: int = 1, timeout: int = 15000) -> None:
    page.wait_for_function(IN_FLIGHT, arg=least, timeout=timeout)


def canvas_moves(page, gap_ms: int = 400) -> bool:
    """True if the map canvas looks different ``gap_ms`` apart."""
    canvas = page.locator("canvas.map-canvas")
    first = canvas.screenshot()
    page.wait_for_timeout(gap_ms)
    return canvas.screenshot() != first


def test_map_draws_the_world_lists_events_and_flies_them(signed_in, lab):
    page, seen = signed_in
    open_section(page, lab.base_url, "#/map")
    feed = page.get_by_role("list", name="Events, newest first")
    expect(feed.locator("li").first).to_be_visible()
    expect(feed).to_contain_text("Amsterdam, Netherlands")
    expect(feed).to_contain_text(re.compile(r"(ssh 22|http 8080|telnet 23|ftp 21|redis 6379)"))
    page.wait_for_function("() => document.querySelector('canvas.map-canvas').width > 0")
    assert page.evaluate(CANVAS_COLOURS) > 8
    # The newest events replay on open, and events written after it arrive by the next poll.
    _append(lab.tree.log, map_lines(lab.tree.now.now(lab.tree.now.tzinfo), 5, step=0.3, seed=21))
    wait_until_flying(page)
    expect(page.get_by_role("group", name="Services shown").get_by_role("button")).not_to_have_count(0)
    assert seen.problems() == []
    assert_nothing_injected(page)


def test_map_pause_stops_movement(signed_in, lab):
    page, seen = signed_in
    open_section(page, lab.base_url, "#/map")
    wait_until_flying(page)
    page.get_by_role("button", name="Pause").click()
    expect(page.get_by_role("button", name="Resume")).to_have_attribute("aria-pressed", "true")
    canvas = page.locator("canvas.map-canvas")
    page.wait_for_timeout(300)
    first = canvas.screenshot()
    page.wait_for_timeout(700)
    assert canvas.screenshot() == first
    assert flying(page) == 0
    page.get_by_role("button", name="Resume").click()
    wait_until_flying(page)
    assert seen.problems() == []


def test_map_keeps_moving_between_events(signed_in, lab):
    page, seen = signed_in
    open_section(page, lab.base_url, "#/map")
    wait_until_flying(page)
    # Nothing new arrives: the opening trips are over, and the window's events still loop.
    page.wait_for_timeout(6000)
    assert flying(page) > 0
    assert canvas_moves(page)
    assert seen.problems() == []


def test_map_with_reduced_motion_shows_dots_and_no_flights(browser, lab):
    context = browser.new_context(reduced_motion="reduce")
    page = context.new_page()
    seen = watch(page)
    try:
        page.goto(lab.sign_in_url)
        page.get_by_role("navigation", name="Sections").wait_for()
        open_section(page, lab.base_url, "#/map")
        _append(lab.tree.log, map_lines(lab.tree.now.now(lab.tree.now.tzinfo), 5, seed=22))
        feed = page.get_by_role("list", name="Events, newest first")
        before = feed.locator("li").count()
        expect(feed.locator("li")).not_to_have_count(before, timeout=15000)
        assert flying(page) == 0
        page.wait_for_timeout(3000)
        assert flying(page) == 0
        assert not canvas_moves(page)
        assert seen.problems() == []
    finally:
        context.close()


def test_map_shows_attacker_text_as_text(browser, lab):
    context = browser.new_context(bypass_csp=True)
    page = context.new_page()
    seen = watch(page)
    try:
        page.goto(lab.sign_in_url)
        page.get_by_role("navigation", name="Sections").wait_for()
        open_section(page, lab.base_url, "#/map")
        feed = page.get_by_role("list", name="Events, newest first")
        # The canary source's place is a script tag, and its login and command are payloads.
        expect(feed).to_contain_text(SCRIPT + ", Singapore")
        expect(feed).to_contain_text(CANARY_SOURCE)
        feed.get_by_text(SCRIPT + ", Singapore").first.hover()
        page.get_by_text("Hide addresses").click()
        expect(feed).not_to_contain_text(CANARY_SOURCE)
        assert_nothing_injected(page)
        assert seen.problems() == []
    finally:
        context.close()


def test_a_feed_row_opens_activity_for_its_source(signed_in, lab):
    page, seen = signed_in
    open_section(page, lab.base_url, "#/map")
    row = page.get_by_role("list", name="Events, newest first").locator("li",
                                                                      has_text="Amsterdam").first
    row.focus()
    page.keyboard.press("Enter")
    expect(page.get_by_role("heading", level=1).first).to_have_text("Activity")
    assert "src=198.51.100.21" in page.url
    assert seen.problems() == []


def map_answer(total: int, sources: list[str], newest: int = 100, items=()) -> dict:
    """A /api/map answer of the server's shape: ``sources`` each with one event."""
    return {"items": list(items), "skipped": 0, "newest": newest, "log_id": "fake.0",
            "window": "15m", "located": True,
            "sources": [{"src": s, "events": 1, "point": [10.0, 10.0 + i], "place": "Somewhere",
                         "country": "NL", "service": "ssh", "last": None}
                        for i, s in enumerate(sources)],
            "totals": {"events": total, "services": {"ssh": total}, "countries": {"NL": total},
                       "per_minute": []},
            "sensor": {"name": "fixture", "label": "Lab sensor", "point": [40.7, -74.0],
                       "placed": True}}


def test_a_service_filter_removes_its_looping_dots(signed_in, lab):
    page, seen = signed_in
    now = datetime.datetime.now(datetime.timezone.utc)
    sources = ["198.51.100.7", "198.51.100.8"]
    data = map_answer(2, sources, items=[
        {"src": sources[0], "service": "ssh", "offset": 10,
         "time": (now - datetime.timedelta(seconds=40)).isoformat()},
        {"src": sources[1], "service": "ftp", "offset": 11,
         "time": (now - datetime.timedelta(seconds=20)).isoformat()}])
    data["totals"]["services"] = {"ftp": 1, "ssh": 1}
    page.route("**/api/map?*", lambda route: route.fulfill(json=data))
    open_section(page, lab.base_url, "#/map")
    page.wait_for_timeout(3000)
    assert flying(page) == 2
    page.get_by_role("group", name="Services shown").get_by_role("button", name="ftp").click()
    page.wait_for_timeout(300)
    assert flying(page) == 1
    page.get_by_role("group", name="Services shown").get_by_role("button", name="ssh").click()
    page.wait_for_timeout(300)
    assert flying(page) == 0
    assert not canvas_moves(page)
    assert seen.problems() == []


def test_display_mode_and_overview_map_keep_moving(signed_in, lab):
    page, seen = signed_in
    page.locator(".map-preview canvas.map-canvas").wait_for()
    page.wait_for_timeout(6000)
    assert canvas_moves(page)
    page.goto(f"{lab.base_url}/#/map?window=15m&display=1")
    expect(page.get_by_role("heading", level=1)).to_have_text("Live activity")
    page.wait_for_timeout(6000)
    assert canvas_moves(page)
    assert seen.problems() == []


def map_sources_label(page) -> str:
    return page.locator("canvas.map-canvas").get_attribute("aria-label")


def test_map_drops_sources_whose_events_left_the_window(signed_in, lab):
    page, seen = signed_in
    answers = [map_answer(2, ["198.51.100.7", "198.51.100.8"]),
               map_answer(1, ["198.51.100.7"], newest=101)]

    def answer(route):
        body = answers.pop(0) if len(answers) > 1 else answers[0]
        route.fulfill(status=200, content_type="application/json", body=json.dumps(body))

    page.route("**/api/map?*", answer)
    page.goto(f"{lab.base_url}/#/map")
    canvas = page.locator("canvas.map-canvas")
    expect(canvas).to_have_attribute("aria-label", re.compile(r"^World map: 2 sources"))
    # The next poll's window no longer holds 198.51.100.8: its dot and count go.
    expect(canvas).to_have_attribute("aria-label", re.compile(r"^World map: 1 source,"),
                                     timeout=12000)
    tile = page.locator(".map-counters .tile").first
    expect(tile).to_contain_text("1")
    assert seen.problems() == []


def test_a_source_past_the_top_list_stays_while_its_events_loop(signed_in, lab):
    page, seen = signed_in
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    first = map_answer(2, ["198.51.100.7"], items=[
        {"src": "198.51.100.7", "service": "ssh", "offset": 10, "time": now},
        {"src": "198.51.100.8", "service": "ftp", "offset": 11, "time": now,
         "point": [20.0, 30.0], "place": "Elsewhere"}])
    answers = [first, map_answer(2, ["198.51.100.7"], newest=101)]
    deltas = []

    def answer(route):
        if "after=" in route.request.url:
            deltas.append(route.request.url)
        body = answers.pop(0) if len(answers) > 1 else answers[0]
        route.fulfill(status=200, content_type="application/json", body=json.dumps(body))

    page.route("**/api/map?*", answer)
    page.goto(f"{lab.base_url}/#/map")
    canvas = page.locator("canvas.map-canvas")
    expect(canvas).to_have_attribute("aria-label", re.compile(r"^World map: 2 sources"))
    # The delta lists only the top source; the other one's event is still in the window.
    page.wait_for_timeout(6500)
    assert deltas, "no delta poll was answered"
    page.wait_for_timeout(300)
    expect(canvas).to_have_attribute("aria-label", re.compile(r"^World map: 2 sources"))
    assert flying(page) == 2
    assert seen.problems() == []


def test_a_slow_answer_for_an_earlier_window_is_dropped(signed_in, lab):
    page, seen = signed_in
    held = []

    def answer(route):
        url = route.request.url
        if "window=15m" in url and "after=" not in url and not held:
            held.append(route)          # the first load answers only after the switch
            return
        total = 111 if "window=1h" in url else 222
        route.fulfill(status=200, content_type="application/json",
                      body=json.dumps(map_answer(total, ["198.51.100.7"])))

    page.route("**/api/map?*", answer)
    page.goto(f"{lab.base_url}/#/map")
    expect(page.get_by_role("heading", level=1).first).to_have_text("Map")
    page.wait_for_function("() => true")
    assert held, "the first window load was not intercepted"
    page.get_by_role("button", name="1 hour").click()
    tile = page.locator(".map-counters .tile").first
    expect(tile).to_contain_text("Events in the last hour")
    expect(tile).to_contain_text("111")
    held[0].fulfill(status=200, content_type="application/json",
                    body=json.dumps(map_answer(999, ["198.51.100.8", "198.51.100.9"])))
    page.wait_for_timeout(500)
    expect(tile).to_contain_text("111")
    expect(page.locator("canvas.map-canvas")).to_have_attribute(
        "aria-label", re.compile(r"^World map: 1 source,"))
    assert seen.problems() == []


def test_collapsed_navigation_keeps_section_names_and_queue_count(signed_in):
    page, seen = signed_in
    toggle = page.get_by_role("button", name="Collapse navigation")
    nav = page.get_by_role("navigation", name="Sections")
    wide = nav.bounding_box()["width"]
    toggle.click()
    expect(page.get_by_role("button", name="Expand navigation")).to_have_attribute(
        "aria-expanded", "false")
    expect(nav.get_by_role("link", name=re.compile("1 pending approval"))).to_be_visible()
    records = nav.get_by_role("link", name="Records")
    records.focus()
    page.keyboard.press("Enter")
    expect(page.get_by_role("heading", level=1)).to_have_text("Records")
    assert nav.bounding_box()["width"] < wide
    page.get_by_role("button", name="Expand navigation").click()
    expect(toggle).to_have_attribute("aria-expanded", "true")
    assert seen.problems() == []


def test_overview_map_link_opens_investigation_and_private_wall_display(signed_in, lab):
    page, seen = signed_in
    preview = page.get_by_role("link", name=re.compile("open full map", re.I))
    preview.focus()
    page.keyboard.press("Enter")
    expect(page.get_by_role("heading", level=1)).to_have_text("Map")
    display = page.get_by_role("button", name="Display mode").or_(
        page.get_by_role("link", name="Display mode"))
    display.click()
    feed = page.get_by_role("list", name="Events, newest first")
    expect(feed.locator("li").first).to_be_visible()
    expect(page.get_by_role("navigation", name="Sections")).not_to_be_visible()
    page.keyboard.press("7")
    expect(page.get_by_role("heading", level=1)).to_have_text("Live activity")
    body = page.locator("body").inner_text()
    assert all(address not in body for address in (CANARY_SOURCE, "198.51.100.21"))
    assert CANARY_USER not in body and CANARY_SCRIPT not in body
    leave = page.get_by_role("button", name=re.compile("Exit display", re.I)).or_(
        page.get_by_role("link", name=re.compile("Exit display", re.I)))
    leave.focus()
    page.keyboard.press("Enter")
    expect(page.get_by_role("navigation", name="Sections")).to_be_visible()
    expect(page.get_by_role("heading", level=1)).to_have_text("Map")
    assert seen.problems() == []


def test_overview_receives_new_record_without_moving_keyboard_focus(signed_in, lab):
    page, seen = signed_in
    preview = page.get_by_role("link", name=re.compile("open full map", re.I))
    preview.focus()
    sessions = lab.tree.reports / "sessions"
    original = json.loads((sessions / (lab.tree.ids["session_a"] + ".json")).read_text())
    record = {**original, "id": "session-" + "a" * 32,
              "last_seen": lab.tree.now.isoformat(), "headline": "New fixture incident"}
    (sessions / (record["id"] + ".json")).write_text(json.dumps(record))
    expect(page.locator("main")).to_contain_text("New fixture incident", timeout=10000)
    expect(preview).to_be_focused()
    assert seen.problems() == []


def test_selected_source_has_its_own_judgement_and_activity_link(signed_in, lab):
    page, seen = signed_in
    sources = ["198.51.100.7", "198.51.100.8"]
    data = map_answer(2, sources)
    data["sources"][0].update(judgement="MALICIOUS", last=lab.tree.now.isoformat(), service="ftp")
    data["totals"]["services"] = {"ftp": 1, "ssh": 1}
    data["items"] = [{"src": sources[0], "service": "ssh", "offset": 10,
                      "time": lab.tree.now.isoformat()}]
    page.route("**/api/map?*", lambda route: route.fulfill(json=data))
    open_section(page, lab.base_url, "#/map")
    canvas = page.get_by_role("img", name=re.compile("World map: 2 sources"))
    # This source also used SSH. Hiding its latest service preserves the source marker.
    page.get_by_role("group", name="Services shown").get_by_role("button", name="ftp").click()
    expect(page.get_by_role("list", name="Events, newest first")).to_contain_text(sources[0])
    canvas.focus()
    page.keyboard.press("ArrowRight")
    details = page.locator(".map-detail")
    expect(details).to_contain_text(sources[0])
    expect(details).to_contain_text("MALICIOUS", ignore_case=True)
    page.keyboard.press("ArrowRight")
    expect(details).to_contain_text(sources[1])
    expect(details).to_contain_text("Untriaged", ignore_case=True)
    expect(details).to_contain_text("Age unknown", ignore_case=True)
    hide = page.get_by_role("checkbox", name="Hide addresses")
    hide.check()
    expect(details).not_to_contain_text(sources[1])
    expect(details.get_by_role("link")).to_have_count(0)
    hide.uncheck()
    expect(details).to_contain_text(sources[1])
    details.get_by_role("link", name=re.compile("View activity", re.I)).click()
    expect(page.get_by_role("heading", level=1)).to_have_text("Activity")
    assert "src=" + sources[1] in page.url
    assert seen.problems() == []
