from __future__ import annotations
from collections import defaultdict
from macloganalyzer.models.event import Event


class ProcessIndex:
    def __init__(self, events: list[Event]):
        self._by_name: dict[str, list[Event]] = defaultdict(list)
        self._by_path: dict[str, list[Event]] = defaultdict(list)

        for event in events:
            if event.process_name:
                self._by_name[event.process_name.lower()].append(event)
            if event.process_path:
                self._by_path[event.process_path].append(event)

    def by_name(self, name: str) -> list[Event]:
        return self._by_name.get(name.lower(), [])

    def by_path(self, path: str) -> list[Event]:
        return self._by_path.get(path, [])

    def all_process_names(self) -> set[str]:
        return set(self._by_name.keys())

    def processes_with_category(self, category: str) -> set[str]:
        result = set()
        for name, events in self._by_name.items():
            if any(e.behavior_category == category for e in events):
                result.add(name)
        return result
