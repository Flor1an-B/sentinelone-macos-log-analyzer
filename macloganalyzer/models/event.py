from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Event:
    source_file: str
    source_type: str          # "match_report" | "ui_log" | "crash_diag"
    timestamp: datetime       # UTC
    process_path: str
    process_name: str
    event_type: str
    behavior_category: str | None = None
    target_path: str | None = None
    group_id: str | None = None
    extra: dict = field(default_factory=dict)
