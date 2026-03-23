from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from macloganalyzer.models.event import Event
    from macloganalyzer.models.finding import Finding
    from macloganalyzer.models.context import SystemContext
    from macloganalyzer.correlate.timeline import Timeline
    from macloganalyzer.correlate.process_index import ProcessIndex
    from macloganalyzer.correlate.group_index import GroupIndex


@dataclass
class AnalysisContext:
    system: SystemContext
    timeline: Timeline
    process_index: ProcessIndex
    group_index: GroupIndex
    crash_events: list[Event] = field(default_factory=list)


class BaseRule(ABC):
    id: str = ""
    name: str = ""
    severity: str = "INFO"
    mitre_id: str | None = None
    mitre_name: str | None = None
    description: str = ""

    @abstractmethod
    def evaluate(self, ctx: AnalysisContext) -> list[Finding]: ...

    def _make_finding(
        self,
        ctx: AnalysisContext,
        description: str = "",
        recommendation: str = "",
        process: str = "",
        evidence: list | None = None,
    ) -> Finding:
        from macloganalyzer.models.finding import Finding
        evs = evidence or []
        return Finding(
            rule_id=self.id,
            rule_name=self.name,
            severity=self.severity,
            mitre_id=self.mitre_id,
            mitre_name=self.mitre_name,
            description=description or self.description,
            recommendation=recommendation,
            process=process,
            evidence=evs,
            first_seen=min((e.timestamp for e in evs), default=None),
            last_seen=max((e.timestamp for e in evs), default=None),
        )
