"""The HTTP trap's per-source web-deception state: discovery, markers, IDs, bounds."""

from types import SimpleNamespace

from listeners import http_state as hs
from listeners.base import ListenerContext
from listeners.events import EventWriter
from scenarios.tokens import marker_value


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make(scenario_name="pack"):
    ctx = ListenerContext(EventWriter(None), seed="s",
                          scenario=SimpleNamespace(scenario=SimpleNamespace(name=scenario_name)))
    clock = Clock()
    return ctx, hs.HttpState(ctx, clock=clock), clock


def test_seq_counts_per_source():
    _, st, _ = make()
    assert [st.next_seq("a"), st.next_seq("a"), st.next_seq("b"), st.next_seq("a")] == [1, 2, 1, 3]


def test_first_showing_is_kept_and_age_grows():
    _, st, clock = make()
    assert st.discovery("a", "/x") is None
    st.show("a", ["/x", "/y"], "bundle")
    clock.now += 30
    st.show("a", ["/x"], "openapi")
    clock.now += 12
    assert st.discovery("a", "/x") == ("bundle", 42)
    assert st.discovery("b", "/x") is None


def test_markers_are_derived_per_source_and_found_across_sources():
    ctx, st, _ = make()
    va, vb = st.marker("a", "client_id"), st.marker("b", "client_id")
    assert va != vb and va == marker_value("s", "pack", "a", "client_id")
    assert st.marker("a", "client_id") == va
    assert st.find_marker([None, f"Bearer {vb}"]) == ("client_id", "b")
    assert st.find_marker([va]) == ("client_id", "a")
    assert st.find_marker(["x" * 50_000 + va]) is None        # beyond the scanned prefix
    assert st.find_marker(["nothing here"]) is None


def test_marker_values_have_realistic_shapes():
    names = ("build", "client_id", "api_key", "tenant")
    values = {n: marker_value("s", "p", "k", n) for n in names}
    assert len(values["build"]) == 12 and int(values["build"], 16) >= 0
    assert len(values["client_id"]) == 36 and values["client_id"][14] == "4"
    assert len(values["api_key"]) == 32 and values["api_key"].isalnum()
    assert len(values["tenant"]) == 20
    assert all(len(v) >= 8 for v in values.values())       # long enough to be looked up


def test_ids_are_counted_distinct_and_capped(monkeypatch):
    _, st, _ = make()
    monkeypatch.setattr(hs, "MAX_IDS", 3)
    counts = [st.count_id("a", "/r/{id}", v) for v in ("1", "2", "2", "3", "4", "5")]
    assert counts == [1, 2, 2, 3, 3, 3]
    assert st.count_id("b", "/r/{id}", "1") == 1


def test_idle_sources_are_dropped_with_their_markers():
    _, st, clock = make()
    va = st.marker("a", "api_key")
    st.show("a", ["/x"], "bundle")
    clock.now += hs.SOURCE_TTL + 1
    st.show("b", ["/x"], "bundle")
    assert "a" not in st.sources and st.find_marker([va]) is None
    assert st.discovery("a", "/x") is None and not st._probe


def test_source_count_is_bounded(monkeypatch):
    _, st, _ = make()
    monkeypatch.setattr(hs, "MAX_SOURCES", 3)
    first = st.marker("s0", "api_key")
    for i in range(1, 6):
        st.show(f"s{i}", ["/x"], "bundle")
    assert len(st.sources) == 3 and st.find_marker([first]) is None


def test_shown_routes_and_id_routes_are_bounded(monkeypatch):
    _, st, _ = make()
    monkeypatch.setattr(hs, "MAX_SHOWN", 2)
    monkeypatch.setattr(hs, "MAX_ID_ROUTES", 2)
    st.show("a", ["/1", "/2", "/3"], "bundle")
    assert list(st.sources["a"].shown) == ["/2", "/3"]
    for r in ("/a", "/b", "/c"):
        st.count_id("a", r, "1")
    assert list(st.sources["a"].ids) == ["/b", "/c"]


def test_state_starts_over_when_the_scenario_changes():
    ctx = ListenerContext(EventWriter(None), seed="s",
                          scenario=SimpleNamespace(scenario=SimpleNamespace(name="one")))
    st = hs.http_state(ctx)
    value = st.marker("a", "api_key")
    assert hs.http_state(ctx) is st and st.find_marker([value])
    ctx.scenario = SimpleNamespace(scenario=SimpleNamespace(name="two"))
    assert hs.http_state(ctx).find_marker([value]) is None


def test_a_request_alone_keeps_only_a_counter(monkeypatch):
    _, st, clock = make()
    monkeypatch.setattr(hs, "MAX_COUNTERS", 3)
    for i in range(5):
        st.next_seq(f"scan{i}")
    assert not st.sources and list(st.counters) == ["scan2", "scan3", "scan4"]
    clock.now += hs.SOURCE_TTL + 1
    assert st.next_seq("scan4") == 1 and list(st.counters) == ["scan4"]


def test_ids_held_for_all_sources_are_bounded(monkeypatch):
    _, st, _ = make()
    monkeypatch.setattr(hs, "MAX_TOTAL_IDS", 5)
    for v in range(3):
        st.count_id("old", "/r/{id}", str(v))
    for v in range(4):
        st.count_id("new", "/r/{id}", str(v))
    assert "old" not in st.sources and st.id_total == 4
    assert st.count_id("new", "/r/{id}", "x" * 100_000) == 5
