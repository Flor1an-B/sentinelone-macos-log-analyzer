from __future__ import annotations
import re
import logging
from datetime import datetime, timezone
from pathlib import Path

from macloganalyzer.models.event import Event
from macloganalyzer.models.context import SystemContext

logger = logging.getLogger(__name__)

# [2026-01-09 21:37:05.227] [agent_ui] [info] message
LOG_PATTERN = re.compile(
    r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\] \[(\w[\w-]*)\] \[(\w+)\] (.+)'
)
UUID_PATTERN = re.compile(
    r'[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    re.IGNORECASE,
)
URL_PATTERN = re.compile(r'https?://[^\s]+sentinelone\.net[^\s,]*')
VERSION_PATTERN = re.compile(r'\b\d+\.\d+\.\d+\.\d+\b')

FUNCTIONAL_STATES = frozenset({
    "agentDisabled", "antiTamperOff", "missingPermissions",
})


def parse_ui_logs(dump_path: Path, ctx: SystemContext) -> list[Event]:
    ui_logs_dir = dump_path / "logs" / "ui-logs"
    if not ui_logs_dir.exists():
        return []

    events: list[Event] = []
    functional_states_seen: set[str] = set()

    for log_file in sorted(ui_logs_dir.glob("ui-log-*")):
        try:
            file_events, states = _parse_ui_log_file(log_file, ctx)
            events.extend(file_events)
            functional_states_seen.update(states)
        except Exception as e:
            logger.warning(f"Failed to parse UI log {log_file.name}: {e}")

    ctx.ui_agent_states = list(functional_states_seen)
    return events


def _parse_ui_log_file(path: Path, ctx: SystemContext) -> tuple[list[Event], set[str]]:
    events: list[Event] = []
    states: set[str] = set()

    content = path.read_text(errors="replace")

    for line in content.splitlines():
        m = LOG_PATTERN.match(line.strip())
        if not m:
            continue

        ts_str, component, level, message = m.groups()
        timestamp = _parse_ui_timestamp(ts_str)
        if timestamp is None:
            continue

        # Extract agent metadata
        if not ctx.agent_uuid:
            uuid_m = UUID_PATTERN.search(message)
            if uuid_m and ("uuid" in message.lower() or "UUID" in message):
                ctx.agent_uuid = uuid_m.group()

        if not ctx.console_url:
            url_m = URL_PATTERN.search(message)
            if url_m:
                ctx.console_url = url_m.group().rstrip(".,;)")

        if ctx.agent_version in ("Unknown", ""):
            ver_m = VERSION_PATTERN.search(message)
            if ver_m and ("version" in message.lower() or "Version" in message):
                ctx.agent_version = ver_m.group()

        # Track functional states
        for state in FUNCTIONAL_STATES:
            if state in message:
                if any(w in message for w in ("Clearing", "cleared", "resolved")):
                    states.discard(state)
                else:
                    states.add(state)

        # Emit event for warnings, errors, and state changes
        if level in ("warning", "error") or any(s in message for s in FUNCTIONAL_STATES):
            events.append(Event(
                source_file=str(path),
                source_type="ui_log",
                timestamp=timestamp,
                process_path="/Library/Sentinel/sentinel-agent.bundle/Contents/MacOS/agent-ui",
                process_name="agent-ui",
                event_type=f"ui_{level}",
                behavior_category=None,
                target_path=None,
                group_id=None,
                extra={"message": message[:200], "component": component, "level": level},
            ))

    return events, states


def _parse_ui_timestamp(ts_str: str) -> datetime | None:
    try:
        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
