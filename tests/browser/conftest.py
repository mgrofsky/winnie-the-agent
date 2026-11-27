"""Fixtures for the Playwright tests: the console on loopback with the synthetic tree, and a
signed-in page with a watcher for console errors, failed requests and dialogs."""

from __future__ import annotations

import pytest

from browser_support import plant_canaries, watch
from console_lab import start


@pytest.fixture
def lab(tmp_path):
    """A console of its own for each test, so a decision in one test changes no other."""
    console = start(tmp_path / "tree")
    plant_canaries(console)
    yield console
    console.stop()


@pytest.fixture
def signed_in(lab, page):
    """A page signed in through the sign-in link, and what it has done so far."""
    seen = watch(page)
    page.goto(lab.sign_in_url)
    page.get_by_role("navigation", name="Sections").wait_for()
    return page, seen
