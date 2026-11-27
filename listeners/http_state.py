"""Per-source web-deception state for the HTTP trap, in memory and bounded.

For each source (``ip_key``) on one listener context it holds:

- a request counter (the ``seq`` evidence key), kept for up to ``MAX_COUNTERS`` sources;
- the routes the source has been shown by a decoy asset or the OpenAPI document
  (route path -> lure ID and time of the first showing);
- the per-source markers issued to it, also indexed value -> (name, source) so a marker
  presented back is recognised, from the same source or from another one;
- the distinct object IDs it asked of each lured item route, as 64-bit digests.

The last three exist only for a source that was shown something, issued a marker or asked
an ID, so a one-request scanner takes no room there. Sources idle for ``SOURCE_TTL``
seconds, beyond ``MAX_SOURCES``, or the oldest ones while more than ``MAX_TOTAL_IDS`` IDs
are held, are dropped with their markers. Everything is forgotten when the listener
restarts or its scenario changes; a marker value can be derived again for the same source
(``scenarios.tokens.marker_value``).
"""

from __future__ import annotations

import hashlib
import time
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from listeners.base import ListenerContext
from scenarios.tokens import PROBE, SCAN_LIMIT, marker_value

MAX_COUNTERS = 65536        # sources whose request counter is kept
MAX_SOURCES = 8192          # sources with discovery, marker or ID state
SOURCE_TTL = 86400.0        # seconds a source's state outlives its last request
MAX_SHOWN = 200             # routes remembered as shown, per source
MAX_ID_ROUTES = 8           # item routes counted, per source
MAX_IDS = 200               # distinct IDs remembered per route; the count stops there
MAX_TOTAL_IDS = 400_000     # IDs held for all sources together


@dataclass
class SourceView:
    last: float = 0.0
    shown: OrderedDict = field(default_factory=OrderedDict)    # route path -> (lure, time)
    markers: dict = field(default_factory=dict)                # marker name -> value
    ids: OrderedDict = field(default_factory=OrderedDict)      # route path -> set of digests
    id_total: int = 0


class HttpState:
    def __init__(self, ctx: ListenerContext, clock: Callable[[], float] = time.monotonic) -> None:
        self.ctx = ctx
        self.clock = clock
        self.scenario = ctx.scenario
        self.counters: OrderedDict[str, list] = OrderedDict()   # key -> [seq, last]
        self.sources: OrderedDict[str, SourceView] = OrderedDict()
        self.id_total = 0
        self._issued: dict[str, tuple[str, str]] = {}          # value -> (name, source key)
        self._probe: dict[str, set[str]] = {}                  # value[:PROBE] -> values

    def refresh(self) -> None:
        """Start over when the listener's scenario changes."""
        if self.ctx.scenario is not self.scenario:
            self.scenario = self.ctx.scenario
            self.counters.clear()
            self.sources.clear()
            self.id_total = 0
            self._issued.clear()
            self._probe.clear()

    # ---- sources ------------------------------------------------------------------------

    def next_seq(self, key: str) -> int:
        """This source's request number on this listener."""
        now = self.clock()
        entry = self.counters.get(key)
        if entry is None or entry[1] < now - SOURCE_TTL:
            entry = self.counters[key] = [0, now]
        self.counters.move_to_end(key)
        entry[0] += 1
        entry[1] = now
        while len(self.counters) > MAX_COUNTERS or \
                next(iter(self.counters.values()))[1] < now - SOURCE_TTL:
            self.counters.popitem(last=False)
        # Every request keeps an existing view alive (it never creates one) and drops views
        # idle for a day, with their markers.
        self._view(key, create=False)
        self._trim(now, keep=None)
        return entry[0]

    def _view(self, key: str, create: bool) -> Optional[SourceView]:
        now = self.clock()
        view = self.sources.get(key)
        if view is not None and view.last < now - SOURCE_TTL:
            self._drop(key)
            view = None
        if view is None:
            if not create:
                return None
            view = self.sources[key] = SourceView()
        else:
            self.sources.move_to_end(key)
        view.last = now
        self._trim(now, keep=key)
        return view

    def _trim(self, now: float, keep: Optional[str]) -> None:
        while self.sources:
            old_key, old = next(iter(self.sources.items()))
            if old_key == keep or (len(self.sources) <= MAX_SOURCES
                                   and old.last >= now - SOURCE_TTL
                                   and self.id_total <= MAX_TOTAL_IDS):
                break
            self._drop(old_key)

    def _drop(self, key: str) -> None:
        view = self.sources.pop(key, None)
        if view is None:
            return
        self.id_total -= view.id_total
        for value in view.markers.values():
            self._issued.pop(value, None)
            bucket = self._probe.get(value[:PROBE])
            if bucket is not None:
                bucket.discard(value)
                if not bucket:
                    del self._probe[value[:PROBE]]

    # ---- discovery ----------------------------------------------------------------------

    def show(self, key: str, paths: Iterable[str], lure: str) -> None:
        """Record that ``key`` was shown ``paths`` by ``lure``. The first showing stays."""
        view = self._view(key, create=True)
        now = self.clock()
        for path in paths:
            if path in view.shown:
                continue
            view.shown[path] = (lure, now)
            while len(view.shown) > MAX_SHOWN:
                view.shown.popitem(last=False)

    def discovery(self, key: str, path: str) -> Optional[tuple[str, int]]:
        """(lure ID, whole seconds since) when ``key`` was shown the route ``path``."""
        view = self._view(key, create=False)
        if view is None or path not in view.shown:
            return None
        lure, at = view.shown[path]
        return lure, max(0, int(self.clock() - at))

    # ---- markers ------------------------------------------------------------------------

    def marker(self, key: str, name: str) -> str:
        """The value of marker ``name`` for ``key``, recorded as issued to it."""
        view = self._view(key, create=True)
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
        self._trim(self.clock(), keep=None)      # an expired source's markers are forgotten
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
        view = self._view(key, create=True)
        ids = view.ids.get(route)
        if ids is None:
            ids = view.ids[route] = set()
            while len(view.ids) > MAX_ID_ROUTES:
                _, dropped = view.ids.popitem(last=False)
                view.id_total -= len(dropped)
                self.id_total -= len(dropped)
        else:
            view.ids.move_to_end(route)
        if len(ids) < MAX_IDS:
            digest = int.from_bytes(hashlib.blake2b(value.encode("utf-8", "replace"),
                                                    digest_size=8).digest(), "big")
            if digest not in ids:
                ids.add(digest)
                view.id_total += 1
                self.id_total += 1
                self._trim(self.clock(), keep=key)
        return len(ids)


_STATES: "weakref.WeakKeyDictionary[ListenerContext, HttpState]" = weakref.WeakKeyDictionary()


def http_state(ctx: ListenerContext) -> HttpState:
    state = _STATES.get(ctx)
    if state is None:
        state = _STATES[ctx] = HttpState(ctx)
    state.refresh()
    return state
