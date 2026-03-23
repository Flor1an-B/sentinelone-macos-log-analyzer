from __future__ import annotations
from datetime import datetime
from macloganalyzer.models.event import Event


class Timeline:
    def __init__(self, events: list[Event]):
        self._events = sorted(events, key=lambda e: e.timestamp)

    @property
    def events(self) -> list[Event]:
        return self._events

    @property
    def start(self) -> datetime | None:
        return self._events[0].timestamp if self._events else None

    @property
    def end(self) -> datetime | None:
        return self._events[-1].timestamp if self._events else None

    def in_window(self, start: datetime, end: datetime) -> list[Event]:
        return [e for e in self._events if start <= e.timestamp <= end]

    def for_process(self, process_name: str) -> list[Event]:
        pn = process_name.lower()
        return [
            e for e in self._events
            if pn in e.process_name.lower() or pn in e.process_path.lower()
        ]

    def for_group(self, group_id: str) -> list[Event]:
        return [e for e in self._events if e.group_id == group_id]

    def by_source_type(self, source_type: str) -> list[Event]:
        return [e for e in self._events if e.source_type == source_type]
