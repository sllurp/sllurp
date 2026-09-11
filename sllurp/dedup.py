"""Tag report deduplication helpers.

LLRP readers can accumulate repeated observations inside a TagReportData and
expose TagSeenCount, but applications can still receive the same EPC in
multiple reports.  This module provides an optional client-side suppression
window without changing the reader's RF behavior.
"""

from __future__ import annotations

import time
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
    """Return a useful identity key for an LLRP TagReportData dictionary.

    EPC-96 is the common compact LLRP representation.  Variable-length EPCs
    are normally decoded under EPCData.  If neither is present, the complete
    report is used so the deduplicator still behaves deterministically.
    """
    if "EPC-96" in tag:
        key = ("EPC-96", _freeze(tag["EPC-96"]))
    elif "EPCData" in tag:
        key = ("EPCData", _freeze(tag["EPCData"]))
    else:
        key = ("TagReportData", _freeze(tag))

    if include_antenna:
        key = (key, "AntennaID", _freeze(tag.get("AntennaID")))
    return key


class TagReportDeduplicator:
    """Suppress duplicate tag reports for a configurable time window.

    The deduplicator is designed to be used directly as an sllurp tag callback
    wrapper::

        dedup = TagReportDeduplicator(my_callback, window_seconds=1.0)
        reader.add_tag_report_callback(dedup)

    By default, the EPC is the identity and duplicate sightings refresh the
    suppression window.  Set ``include_antenna=True`` if the same EPC seen on
    different antennas should be delivered separately.
    """

    def __init__(
        self,
        callback: TagCallback | None = None,
        *,
        window_seconds: float = 1.0,
        include_antenna: bool = False,
        key: TagKey | None = None,
        max_entries: int = 100_000,
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
        self._lock = RLock()

    def reset(self) -> None:
        """Forget all previously seen tags."""
        with self._lock:
            self._seen.clear()

    def _tag_key(self, tag: Mapping[str, Any]) -> Any:
        if self.key is not None:
            return _freeze(self.key(tag))
        return default_tag_key(tag, include_antenna=self.include_antenna)

    def _purge_expired(self, now: float) -> None:
        if not self._seen:
            return
        if self.window_seconds == 0:
            self._seen.clear()
            return
        cutoff = now - self.window_seconds
        expired = [key for key, last_seen in self._seen.items() if last_seen <= cutoff]
        for key in expired:
            self._seen.pop(key, None)

    def _trim(self) -> None:
        overflow = len(self._seen) - self.max_entries
        if overflow <= 0:
            return
        for key, _ in sorted(self._seen.items(), key=lambda item: item[1])[:overflow]:
            self._seen.pop(key, None)

    def filter(self, tag_reports: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        """Return only reports not seen inside the configured window."""
        reports = list(tag_reports)
        if self.window_seconds == 0:
            return reports

        now = self.clock()
        unique: list[Mapping[str, Any]] = []
        with self._lock:
            self._purge_expired(now)
            for tag in reports:
                key = self._tag_key(tag)
                last_seen = self._seen.get(key)
                self._seen[key] = now
                if last_seen is None or now - last_seen >= self.window_seconds:
                    unique.append(tag)
            self._trim()
        return unique

    def __call__(self, reader: Any, tag_reports: Iterable[Mapping[str, Any]]) -> None:
        """Filter reports and invoke the wrapped callback, if configured."""
        unique = self.filter(tag_reports)
        if self.callback is not None and (unique or self.emit_empty):
            self.callback(reader, unique)
