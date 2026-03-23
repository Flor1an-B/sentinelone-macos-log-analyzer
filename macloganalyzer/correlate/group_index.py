from __future__ import annotations
from collections import defaultdict
from macloganalyzer.models.event import Event


class GroupIndex:
    def __init__(self, events: list[Event]):
        self._by_group: dict[str, list[Event]] = defaultdict(list)

        for event in events:
            if event.group_id:
                self._by_group[event.group_id].append(event)

    def events_for_group(self, group_id: str) -> list[Event]:
        return self._by_group.get(group_id, [])

    def categories_for_group(self, group_id: str) -> set[str]:
        return {
            e.behavior_category
            for e in self._by_group.get(group_id, [])
            if e.behavior_category
        }

    def all_groups(self) -> set[str]:
        return set(self._by_group.keys())

    def primary_for_group(self, group_id: str) -> str:
        events = self._by_group.get(group_id, [])
        if events:
            return events[0].extra.get("primary", "") or events[0].process_path
        return ""
