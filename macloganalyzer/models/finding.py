from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from macloganalyzer.models.event import Event


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str             # CRITICAL | HIGH | MEDIUM | LOW | INFO
    description: str
    recommendation: str
    process: str = ""
    mitre_id: str | None = None
    mitre_name: str | None = None
    evidence: list[Event] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def severity_order(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(self.severity, 5)
