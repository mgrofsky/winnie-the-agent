"""Overview keeps its incident links and last good data during a slow or failed poll."""

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import expect  # noqa: E402

pytestmark = pytest.mark.browser


def test_overview_staleness_and_focus_are_independent_of_map(lab, page):
    page.clock.install()
    # A failing map should not block a successful Overview or affect its freshness.
    page.route("**/api/map?*", lambda route: route.fulfill(status=503, json={"error": "busy"}))
    page.goto(lab.sign_in_url)
    status = page.locator(".header-right .updated[aria-live]")
    expect(status).to_have_text("Live")
    incidents = page.locator("section").filter(has=page.get_by_role("heading", name="Recent incidents"))
    first = incidents.locator("tbody a").first
    first.focus()
    href = first.get_attribute("href")
    selected = page.locator(f'main a[href="{href}"]').first
    held = []
    page.route("**/api/overview?*", lambda route: held.append(route))
    with page.expect_request(lambda req: "/api/overview?" in req.url):
        page.clock.fast_forward(5000)
    page.clock.fast_forward(11000)
    expect(status).to_have_text("Delayed")
    expect(selected).to_be_focused()
    assert len(held) == 1  # slow reads never overlap
    # An interrupted body can arrive with HTTP 200. Keep the last good snapshot.
    held[0].fulfill(status=200, content_type="application/json", body='{"totals":')
    expect(status).to_have_text("Reconnecting")
    expect(selected).to_be_focused()

    # A different record arrives before the focused one in the next successful response.
    data = page.request.get(lab.base_url + "/api/overview?window=24h").json()
    extra = {**data["recent_incidents"][0], "id": "new-fixture", "summary": "New fixture arrival"}
    data["recent_incidents"] = [extra]
    page.unroute("**/api/overview?*")
    page.route("**/api/overview?*", lambda route: route.fulfill(json=data))
    page.clock.fast_forward(5000)
    expect(status).to_have_text("Live")
    expect(page.get_by_text("New fixture arrival")).to_be_visible()
    expect(selected).to_be_focused()
    page.get_by_role("link", name="Open queue").focus()
    page.clock.fast_forward(5000)
    expect(incidents.locator(f'a[href="{href}"]')).to_have_count(0)
