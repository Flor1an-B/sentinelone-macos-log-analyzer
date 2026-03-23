from __future__ import annotations
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from macloganalyzer.models.context import SystemContext
from macloganalyzer.models.event import Event
from macloganalyzer.models.finding import Finding
from macloganalyzer.ingest.text_parser import parse_text_files
from macloganalyzer.ingest.jsonl_parser import parse_match_reports
from macloganalyzer.ingest.ui_log_parser import parse_ui_logs
from macloganalyzer.ingest.crash_parser import parse_crashes
from macloganalyzer.ingest.plist_parser import parse_plist_sources
from macloganalyzer.ingest.install_log_parser import parse_install_logs
from macloganalyzer.ingest.extended_text_parser import parse_extended_text
from macloganalyzer.analyze.alerts import generate_operational_alerts
from macloganalyzer.correlate.timeline import Timeline
from macloganalyzer.correlate.process_index import ProcessIndex
from macloganalyzer.correlate.group_index import GroupIndex
from macloganalyzer.rules.base import AnalysisContext
from macloganalyzer.rules.registry import discover_rules
from macloganalyzer.config import SEVERITY_ORDER

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[int, int, str], None]


def run_pipeline(
    dump_path: Path,
    severity_filter: str = "LOW",
    since: datetime | None = None,
    until: datetime | None = None,
    process_filter: str | None = None,
    progress_callback: ProgressCallback | None = None,
) -> tuple[SystemContext, list[Finding], list[Event]]:
    """
    Main analysis pipeline.
    Returns: (system_context, findings, all_events)
    """
    def progress(step: int, message: str) -> None:
        if progress_callback:
            progress_callback(step, 6, message)

    # ── Step 1: Parse system files ────────────────────────────────────────────
    progress(1, "Ingesting system files...")
    ctx = SystemContext(dump_path=str(dump_path))
    _infer_from_dirname(dump_path, ctx)
    parse_text_files(dump_path, ctx)
    parse_plist_sources(dump_path, ctx)
    parse_install_logs(dump_path, ctx)
    parse_extended_text(dump_path, ctx)
    ctx.operational_alerts = generate_operational_alerts(ctx)

    # ── Step 2: Parse match_reports ───────────────────────────────────────────
    progress(2, "Parsing match_reports...")
    mr_events = parse_match_reports(dump_path)
    mr_dir = dump_path / "match_reports"
    if mr_dir.exists():
        import re as _re
        _MR_DATE_RE = _re.compile(r"(\d{4})\.(\d{2})\.(\d{2})")
        daily: dict[str, int] = {}
        total_files = 0
        for f in mr_dir.iterdir():
            total_files += 1
            m = _MR_DATE_RE.search(f.name)
            if m:
                date_str = f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
                daily[date_str] = daily.get(date_str, 0) + 1
        ctx.mr_daily_counts = daily
        ctx.parse_stats["match_reports_files"] = total_files
    else:
        ctx.parse_stats["match_reports_files"] = 0
    ctx.parse_stats["match_reports_events"] = len(mr_events)

    # ── Step 3: Parse UI logs ─────────────────────────────────────────────────
    progress(3, "Parsing UI logs...")
    ui_events = parse_ui_logs(dump_path, ctx)
    ctx.parse_stats["ui_log_events"] = len(ui_events)

    # ── Step 4: Parse crash reports ───────────────────────────────────────────
    progress(4, "Parsing crash reports...")
    crash_events = parse_crashes(dump_path)
    ctx.parse_stats["crash_events"] = len(crash_events)

    # ── Combine and filter ────────────────────────────────────────────────────
    all_events = mr_events + ui_events + crash_events

    if since:
        all_events = [e for e in all_events if e.timestamp >= since]
    if until:
        all_events = [e for e in all_events if e.timestamp <= until]
    if process_filter:
        pf = process_filter.lower()
        all_events = [
            e for e in all_events
            if pf in e.process_name.lower() or pf in e.process_path.lower()
        ]

    # ── Step 5: Correlation indexes + rules ───────────────────────────────────
    progress(5, "Correlating events and applying rules...")
    timeline = Timeline(all_events)
    process_index = ProcessIndex(all_events)
    group_index = GroupIndex(mr_events)  # Only match_reports have group IDs

    analysis_ctx = AnalysisContext(
        system=ctx,
        timeline=timeline,
        process_index=process_index,
        group_index=group_index,
        crash_events=crash_events,
    )

    rules = discover_rules()
    ctx.parse_stats["rules_count"] = len(rules)

    all_findings: list[Finding] = []
    for rule in rules:
        try:
            found = rule.evaluate(analysis_ctx)
            all_findings.extend(found)
        except Exception as e:
            logger.warning(f"Rule {rule.id} failed: {e}")

    ctx.parse_stats["total_findings"] = len(all_findings)

    # ── Filter and sort findings ──────────────────────────────────────────────
    min_order = SEVERITY_ORDER.get(severity_filter, 3)
    filtered = [
        f for f in all_findings
        if SEVERITY_ORDER.get(f.severity, 5) <= min_order
    ]
    filtered.sort(key=lambda f: (
        SEVERITY_ORDER.get(f.severity, 5),
        -(f.first_seen.timestamp() if f.first_seen else 0),
    ))
    ctx.parse_stats["filtered_findings"] = len(filtered)

    # ── Step 6: Ready to report ───────────────────────────────────────────────
    progress(6, "Generating reports...")

    return ctx, filtered, all_events


def _infer_from_dirname(dump_path: Path, ctx: SystemContext) -> None:
    """Extract dump date from directory name like SentinelLog_2026.03.19_14.11.00_root."""
    for part in dump_path.name.split("_"):
        if "." in part and len(part) == 10:
            try:
                datetime.strptime(part, "%Y.%m.%d")
                ctx.parse_stats["dump_date"] = part.replace(".", "-")
                return
            except ValueError:
                continue
