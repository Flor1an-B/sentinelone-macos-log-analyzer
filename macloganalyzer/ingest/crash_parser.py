from __future__ import annotations
import re
import logging
from datetime import datetime, timezone
from pathlib import Path

from macloganalyzer.models.event import Event

logger = logging.getLogger(__name__)

DATE_PATTERN = re.compile(r'Date/Time:\s+(.+)')
COMMAND_PATTERN = re.compile(r'Command:\s+(.+)')
PATH_PATTERN = re.compile(r'^Path:\s+(/\S+)', re.MULTILINE)
PID_PATTERN = re.compile(r'PID:\s+(\d+)')
EVENT_PATTERN = re.compile(r'^Event:\s+(.+)', re.MULTILINE)
ACTION_PATTERN = re.compile(r'Action taken:\s+(.+)')


def parse_crashes(dump_path: Path) -> list[Event]:
    crashes_dir = dump_path / "crashes"
    if not crashes_dir.exists():
        return []

    events: list[Event] = []
    for diag_file in crashes_dir.rglob("*.diag"):
        try:
            event = _parse_diag(diag_file)
            if event:
                events.append(event)
        except Exception as e:
            logger.warning(f"Failed to parse crash {diag_file.name}: {e}")

    return events


def _parse_diag(path: Path) -> Event | None:
    content = path.read_text(errors="replace")

    date_m = DATE_PATTERN.search(content)
    command_m = COMMAND_PATTERN.search(content)
    path_m = PATH_PATTERN.search(content)
    pid_m = PID_PATTERN.search(content)
    event_m = EVENT_PATTERN.search(content)
    action_m = ACTION_PATTERN.search(content)

    if not date_m or not command_m:
        return None

    timestamp = _parse_crash_timestamp(date_m.group(1).strip())
    process_path = path_m.group(1) if path_m else ""
    process_name = command_m.group(1).strip()
    event_type = event_m.group(1).strip() if event_m else "crash"
    action = action_m.group(1).strip() if action_m else ""
    pid = int(pid_m.group(1)) if pid_m else 0

    return Event(
        source_file=str(path),
        source_type="crash_diag",
        timestamp=timestamp or datetime.now(timezone.utc),
        process_path=process_path or f"/{process_name}",
        process_name=process_name,
        event_type=event_type,
        behavior_category="crash",
        target_path=None,
        group_id=None,
        extra={"pid": pid, "action": action, "diag_file": path.name},
    )


def _parse_crash_timestamp(ts_str: str) -> datetime | None:
    """Parse '2026-03-14 17:10:50.996 +0100' and similar."""
    ts_str = ts_str.strip()
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    return None
