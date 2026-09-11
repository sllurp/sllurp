"""Tag report deduplication helpers.

LLRP readers can aggregate repeated observations inside a TagReportData, but
applications can still receive the same EPC in multiple reports. This module
provides a client-side timed suppression fallback with Zebra-style semantics:
report immediately, suppress for the configured interval, then allow another
report. Suppressed sightings do not extend the interval.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from threading import RLock
from typing import Any


TagKey = Callable[[Mapping[str, Any]], Any]
TagCallback = Callable[[Any, list[Mapping[str, Any]]], None]


def _freeze(value: Any) -> Any:
    """Convert common decoded LLRP values into a stable hashable value."""
    if isinstance(value, Mapping):
        return tuple(sorted((key, _freeze(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    try:
        hash(value)
    except TypeError:
        return repr(value)
    return value


def default_tag_key(tag: Mapping[str, Any], *, include_antenna: bool = False) -> Any:
    """Return a stable identity key for an LLRP TagReportData dictionary."""
    if "EPC-96" in tag:
        key = ("EPC-96", _freeze(tag["EPC-96"]))
    elif "EPC" in tag:
        key = ("EPC", _freeze(tag["EPC"]))
    elif "EPCData" in tag:
        key = ("EPCData", _freeze(tag["EPCData"]))
    else:
        key = ("TagReportData", _freeze(tag))

    if include_antenna:
        key = (key, "AntennaID", _freeze(tag.get("AntennaID")))
    return key


class TagReportDeduplicator:
    """Suppress duplicate tag reports for a fixed cooldown interval.

    The first sighting is emitted immediately. Additional sightings inside
    ``window_seconds`` are dropped without refreshing the expiry time. Once
    the interval from the last emitted sighting expires, the tag is eligible
    to be emitted again.

    Expiry is tracked with a deque plus a dictionary so normal lookup and
    cleanup are amortized O(1), including large active populations.
    """

    def __init__(
        self,
        callback: TagCallback | None = None,
        *,
        window_seconds: float = 1.0,
        include_antenna: bool = False,
        key: TagKey | None = None,
        max_entries: int = 1_000_000,
        emit_empty: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if window_seconds < 0:
            raise ValueError("window_seconds cannot be negative")
        if max_entries <= 0:
            raise ValueError("max_entries must be greater than zero")

        self.callback = callback
        self.window_seconds = float(window_seconds)
        self.include_antenna = bool(include_antenna)
        self.key = key
        self.max_entries = int(max_entries)
        self.emit_empty = bool(emit_empty)
        self.clock = clock
        self._seen: dict[Any, float] = {}
        self._expiry_queue: deque[tuple[float, Any]] = deque()
        self._evictions = 0
        self._lock = RLock()

    @property
    def entry_count(self) -> int:
        return len(self._seen)

    @property
    def evictions(self) -> int:
        return self._evictions

    def reset(self) -> None:
        """Forget all previously seen tags and reset eviction statistics."""
        with self._lock:
            self._seen.clear()
            self._expiry_queue.clear()
            self._evictions = 0

    def _tag_key(self, tag: Mapping[str, Any]) -> Any:
        if self.key is not None:
            return _freeze(self.key(tag))
        return default_tag_key(tag, include_antenna=self.include_antenna)

    def _purge_expired(self, now: float) -> None:
        while self._expiry_queue and self._expiry_queue[0][0] <= now:
            expiry, key = self._expiry_queue.popleft()
            if self._seen.get(key) == expiry:
                self._seen.pop(key, None)

    def _trim(self) -> None:
        while len(self._seen) > self.max_entries and self._expiry_queue:
            expiry, key = self._expiry_queue.popleft()
            if self._seen.get(key) == expiry:
                self._seen.pop(key, None)
                self._evictions += 1

    def filter(self, tag_reports: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        """Return only reports whose fixed cooldown has expired."""
        reports = list(tag_reports)
        if self.window_seconds == 0:
            return reports

        now = self.clock()
        unique: list[Mapping[str, Any]] = []
        with self._lock:
            self._purge_expired(now)
            for tag in reports:
                key = self._tag_key(tag)
                expiry = self._seen.get(key)
                if expiry is not None and now < expiry:
                    continue

                expiry = now + self.window_seconds
                self._seen[key] = expiry
                self._expiry_queue.append((expiry, key))
                unique.append(tag)
            self._trim()
        return unique

    def __call__(self, reader: Any, tag_reports: Iterable[Mapping[str, Any]]) -> None:
        """Filter reports and invoke the wrapped callback, if configured."""
        unique = self.filter(tag_reports)
        if self.callback is not None and (unique or self.emit_empty):
            self.callback(reader, unique)
