from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from macloganalyzer.models.event import Event

logger = logging.getLogger(__name__)


def parse_match_reports(dump_path: Path) -> list[Event]:
    """Parse all JSONL files in match_reports/."""
    match_dir = dump_path / "match_reports"
    if not match_dir.exists():
        return []

    events: list[Event] = []
    files = sorted(match_dir.glob("match-report-*"))

    for f in files:
        try:
            events.extend(_parse_file(f))
        except Exception as e:
            logger.warning(f"Failed to parse {f.name}: {e}")

    return events


def _parse_file(path: Path) -> list[Event]:
    events: list[Event] = []
    content = path.read_text(errors="replace")

    for line_num, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            events.extend(_extract_events(obj, str(path)))
        except json.JSONDecodeError as e:
            logger.debug(f"{path.name}:{line_num}: JSON parse error: {e}")

    return events


def _extract_events(obj: dict, source_file: str) -> list[Event]:
    events: list[Event] = []

    primary = obj.get("primary", "") or ""
    group_id = obj.get("group", "") or ""
    matches = obj.get("context", {}).get("matches", [])

    primary_name = Path(primary).name if primary else ""

    for match in matches:
        behavior_category = match.get("name", "") or ""
        final = match.get("final", False)

        matched_items = match.get("matched-items", [])
        if not matched_items:
            continue

        for item in matched_items:
            process = item.get("process", "") or primary
            ts_str = item.get("timestamp", "") or ""
            event_type = item.get("name", "") or ""
            item_ctx = item.get("context", {}) or {}
            target_path = item_ctx.get("path", "") or ""

            timestamp = _parse_timestamp(ts_str)
            if timestamp is None:
                continue

            pname = Path(process).name if process else primary_name

            events.append(Event(
                source_file=source_file,
                source_type="match_report",
                timestamp=timestamp,
                process_path=process or primary,
                process_name=pname or primary_name,
                event_type=event_type,
                behavior_category=behavior_category or None,
                target_path=target_path or None,
                group_id=group_id or None,
                extra={
                    "primary": primary,
                    "final": final,
                    "flags": item_ctx.get("flags"),
                },
            ))

    return events


def _parse_timestamp(ts_str: str) -> datetime | None:
    """Parse '2026-03-18 13:46:41+0000' and similar formats."""
    if not ts_str:
        return None
    for fmt in (
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    return None
