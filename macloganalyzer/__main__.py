from __future__ import annotations
import argparse
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from macloganalyzer.pipeline import run_pipeline
from macloganalyzer.report.markdown import generate_markdown
from macloganalyzer.report.json_report import generate_json
from macloganalyzer.report.html_report import generate_html
from macloganalyzer.report.console import (
    print_summary, print_banner, make_progress,
    APP_VERSION, APP_AUTHOR,
)
from macloganalyzer.update import run_update

console = Console()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="macloganalyzer",
        description="Analyze a SentinelOne log dump and generate a security report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  macloganalyzer ./SentinelLog_2026.03.19_14.11.00_root\n"
            "  macloganalyzer ./dump --severity HIGH --format md\n"
            "  macloganalyzer ./dump --since 2026-03-15 --process GhostWatch\n"
        ),
    )
    parser.add_argument(
        "dump_path",
        nargs="?",
        help="Path to the SentinelOne dump directory",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Check for updates and download changed files from GitHub",
    )
    parser.add_argument(
        "--output-dir", "-o",
        help="Output directory (default: <dump_name>_report/ next to the dump)",
    )
    parser.add_argument(
        "--format",
        choices=["md", "json", "html", "all"],
        default="all",
        help="Output format(s) (default: all)",
    )
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Minimum severity to include in the report (default: LOW)",
    )
    parser.add_argument(
        "--since",
        metavar="YYYY-MM-DD",
        help="Filter events after this date",
    )
    parser.add_argument(
        "--until",
        metavar="YYYY-MM-DD",
        help="Filter events before this date",
    )
    parser.add_argument(
        "--process",
        help="Filter on a specific process (partial match)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed parsing logs",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"SentinelOne macOS Log Analyzer {APP_VERSION}  by {APP_AUTHOR}",
    )

    args = parser.parse_args()

    # ── Update mode ───────────────────────────────────────────────────────────
    if args.update:
        run_update(APP_VERSION)
        sys.exit(0)

    if not args.dump_path:
        parser.error("dump_path is required (or use --update to check for updates)")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # Validate dump path
    dump_path = Path(args.dump_path).resolve()
    if not dump_path.exists() or not dump_path.is_dir():
        console.print(f"[red]Error:[/red] Directory not found: {dump_path}")
        sys.exit(1)

    # Auto-discover nested SentinelLog dump if the given path is a wrapper directory
    dump_path = _resolve_dump_root(dump_path, console)

    # Output directory — dedicated subfolder by default
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = dump_path.parent / f"{dump_path.name}_report"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Parse date filters
    since: datetime | None = None
    until: datetime | None = None
    if args.since:
        try:
            since = datetime.strptime(args.since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            console.print(f"[red]Invalid format for --since:[/red] {args.since} (expected: YYYY-MM-DD)")
            sys.exit(1)
    if args.until:
        try:
            until = datetime.strptime(args.until, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            console.print(f"[red]Invalid format for --until:[/red] {args.until} (expected: YYYY-MM-DD)")
            sys.exit(1)

    # Run pipeline with progress bar
    print_banner()
    _t0 = time.monotonic()
    with make_progress() as progress:
        task = progress.add_task("Initializing...", total=6)

        def on_progress(step: int, total: int, message: str) -> None:
            progress.update(task, completed=step, description=f"[{step}/{total}] {message}")

        ctx, findings, events = run_pipeline(
            dump_path=dump_path,
            severity_filter=args.severity,
            since=since,
            until=until,
            process_filter=args.process,
            progress_callback=on_progress,
        )

    # Generate reports
    stem = dump_path.name
    report_md = output_dir / f"{stem}_report.md"
    report_json = output_dir / f"{stem}_findings.json"
    report_html = output_dir / f"{stem}_report.html"

    if args.format in ("md", "all"):
        generate_markdown(ctx, findings, events, report_md)

    if args.format in ("json", "all"):
        generate_json(ctx, findings, events, report_json)

    if args.format in ("html", "all"):
        generate_html(ctx, findings, events, report_html)

    # Print summary to console
    _elapsed = time.monotonic() - _t0
    html_path = str(report_html) if args.format in ("html", "all") else None
    print_summary(ctx, findings, str(report_md), str(report_json), html_path, elapsed=_elapsed)


def _resolve_dump_root(path: Path, console: Console) -> Path:
    """
    A SentinelOne dump root is identified by the presence of match_reports/ or
    sentinelctl-status.txt. If the given path is a wrapper directory containing
    a single SentinelLog_* subdirectory, descend automatically.
    """
    _DUMP_MARKERS = ("match_reports", "sentinelctl-status.txt", "csrutil_status.txt")

    # Already looks like a dump root
    if any((path / m).exists() for m in _DUMP_MARKERS):
        return path

    # Look for a single subdirectory that looks like a dump root
    candidates = [
        child for child in path.iterdir()
        if child.is_dir() and any((child / m).exists() for m in _DUMP_MARKERS)
    ]

    if len(candidates) == 1:
        console.print(
            f"[dim]Auto-detected dump in subfolder "
            f"[cyan]{candidates[0].name}[/cyan][/dim]"
        )
        return candidates[0]

    if len(candidates) > 1:
        console.print(
            f"[yellow]Warning:[/yellow] {len(candidates)} dumps found in "
            f"{path.name}. Specify the desired subfolder:"
        )
        for c in candidates:
            console.print(f"  • {c}")
        sys.exit(1)

    console.print(
        f"[yellow]Warning:[/yellow] No SentinelOne dump indicators found in "
        f"{path}. Analysis will continue but results may be empty."
    )
    return path


if __name__ == "__main__":
    main()
