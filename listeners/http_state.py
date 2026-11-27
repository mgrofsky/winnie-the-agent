"""Per-source web-deception state for the HTTP trap, in memory and bounded.

For each source (``ip_key``) on one listener context it holds:

- a request counter (the ``seq`` evidence key);
- the routes the source has been shown by a decoy asset or the OpenAPI document
  (route path -> lure ID and time of the first showing);
- the per-source markers issued to it, also indexed value -> (name, source) so a marker
  presented back is recognised, from the same source or from another one;
- the distinct object IDs it asked of each lured item route.

Sources idle for ``SOURCE_TTL`` seconds, or beyond ``MAX_SOURCES``, are dropped with
their markers. Everything is forgotten when the listener restarts or its scenario changes;
a marker value can be derived again for the same source (``scenarios.tokens.marker_value``).
"""

from __future__ import annotations

import time
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from listeners.base import ListenerContext
from scenarios.tokens import PROBE, SCAN_LIMIT, marker_value

MAX_SOURCES = 4096
SOURCE_TTL = 86400.0        # seconds a source's state outlives its last request
MAX_SHOWN = 200             # routes remembered as shown, per source
MAX_ID_ROUTES = 50          # item routes counted, per source
MAX_IDS = 1000              # distinct IDs remembered per route; the count stops there
MAX_ID_CHARS = 200


@dataclass
class SourceView:
    last: float = 0.0
    seq: int = 0
    shown: OrderedDict = field(default_factory=OrderedDict)    # route path -> (lure, time)
    markers: dict = field(default_factory=dict)                # marker name -> value
    ids: OrderedDict = field(default_factory=OrderedDict)      # route path -> set of IDs


class HttpState:
    def __init__(self, ctx: ListenerContext, clock: Callable[[], float] = time.monotonic) -> None:
        self.ctx = ctx
        self.clock = clock
        self.scenario = ctx.scenario
        self.sources: OrderedDict[str, SourceView] = OrderedDict()
        self._issued: dict[str, tuple[str, str]] = {}          # value -> (name, source key)
        self._probe: dict[str, set[str]] = {}                  # value[:PROBE] -> values

    def refresh(self) -> None:
        """Start over when the listener's scenario changes."""
        if self.ctx.scenario is not self.scenario:
            self.scenario = self.ctx.scenario
            self.sources.clear()
            self._issued.clear()
            self._probe.clear()

    # ---- sources ------------------------------------------------------------------------

    def source(self, key: str) -> SourceView:
        now = self.clock()
        view = self.sources.get(key)
        if view is None:
            view = self.sources[key] = SourceView()
        else:
            self.sources.move_to_end(key)
        view.last = now
        while self.sources:
            old = next(iter(self.sources.values()))
            if len(self.sources) <= MAX_SOURCES and old.last >= now - SOURCE_TTL:
                break
            self.sources.popitem(last=False)
            self._forget(old)
        return view

    def _forget(self, view: SourceView) -> None:
        for value in view.markers.values():
            self._issued.pop(value, None)
            bucket = self._probe.get(value[:PROBE])
            if bucket is not None:
                bucket.discard(value)
                if not bucket:
                    del self._probe[value[:PROBE]]

    def next_seq(self, key: str) -> int:
        view = self.source(key)
        view.seq += 1
        return view.seq

    # ---- discovery ----------------------------------------------------------------------

    def show(self, key: str, paths: Iterable[str], lure: str) -> None:
        """Record that ``key`` was shown ``paths`` by ``lure``. The first showing stays."""
        view = self.source(key)
        now = self.clock()
        for path in paths:
            if path in view.shown:
                continue
            view.shown[path] = (lure, now)
            while len(view.shown) > MAX_SHOWN:
                view.shown.popitem(last=False)

    def discovery(self, key: str, path: str) -> Optional[tuple[str, int]]:
        """(lure ID, whole seconds since) when ``key`` was shown the route ``path``."""
        view = self.sources.get(key)
        if view is None or path not in view.shown:
            return None
        lure, at = view.shown[path]
        return lure, max(0, int(self.clock() - at))

    # ---- markers ------------------------------------------------------------------------

    def marker(self, key: str, name: str) -> str:
        """The value of marker ``name`` for ``key``, recorded as issued to it."""
        view = self.source(key)
        value = view.markers.get(name)
        if value is None:
            scen = self.ctx.scenario
            scen_name = scen.scenario.name if scen is not None else ""
            value = marker_value(self.ctx.seed, scen_name, key, name)
            view.markers[name] = value
            self._issued[value] = (name, key)
            self._probe.setdefault(value[:PROBE], set()).add(value)
        return value

    def find_marker(self, texts: Iterable[Optional[str]]) -> Optional[tuple[str, str]]:
        """(marker name, source key it was issued to) for the first issued marker found in
        ``texts``. One dictionary probe per position of a bounded prefix of each text."""
        if not self._issued:
            return None
        for text in texts:
            if not text:
                continue
            hit = self._issued.get(text)
            if hit is not None:
                return hit
            text = text[:SCAN_LIMIT]
            for i in range(len(text) - PROBE + 1):
                bucket = self._probe.get(text[i:i + PROBE])
                if bucket:
                    for value in bucket:
                        if text.startswith(value, i):
                            return self._issued[value]
        return None

    # ---- object IDs ---------------------------------------------------------------------

    def count_id(self, key: str, route: str, value: str) -> int:
        """Record an ID asked of an item route; the number of distinct IDs asked so far
        (at most ``MAX_IDS``)."""
        view = self.source(key)
        ids = view.ids.get(route)
        if ids is None:
            ids = view.ids[route] = set()
            while len(view.ids) > MAX_ID_ROUTES:
                view.ids.popitem(last=False)
        else:
            view.ids.move_to_end(route)
        if len(ids) < MAX_IDS:
            ids.add(value[:MAX_ID_CHARS])
        return len(ids)


_STATES: "weakref.WeakKeyDictionary[ListenerContext, HttpState]" = weakref.WeakKeyDictionary()


def http_state(ctx: ListenerContext) -> HttpState:
    state = _STATES.get(ctx)
    if state is None:
        state = _STATES[ctx] = HttpState(ctx)
    state.refresh()
    return state
