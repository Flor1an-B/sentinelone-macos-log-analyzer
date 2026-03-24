from __future__ import annotations
import io
import sys
import time
from datetime import datetime, timezone
from macloganalyzer._version import __version__ as _APP_VERSION

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

from macloganalyzer.models.context import SystemContext
from macloganalyzer.models.finding import Finding

# Force UTF-8 output on Windows so Rich can render box-drawing / unicode chars
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except AttributeError:
        pass  # already wrapped or non-standard stream

# ── Application identity ───────────────────────────────────────────────────────
APP_NAME    = "SentinelOne macOS Log Analyzer"
APP_VERSION = _APP_VERSION
APP_AUTHOR  = "Florian Bertaux"

console = Console(highlight=False)

SEVERITY_STYLE = {
    "CRITICAL": "bright_red bold",
    "HIGH":     "red bold",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "white dim",
}
SEVERITY_COLOR = {
    "CRITICAL": "bright_red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "white",
    "MINIMAL":  "green",
}
SEVERITY_ICON = {
    "CRITICAL": "●",
    "HIGH":     "●",
    "MEDIUM":   "●",
    "LOW":      "●",
    "INFO":     "○",
}


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=32, style="dim cyan", complete_style="cyan"),
        TaskProgressColumn(style="dim"),
        console=console,
        transient=False,
    )


def print_banner() -> None:
    """Print the application startup banner."""
    console.print()
    console.print(Rule(style="dim blue"))
    console.print(
        f"  [bold cyan]{APP_NAME}[/bold cyan]"
        f"  [dim]v{APP_VERSION}[/dim]"
        f"  [dim]·[/dim]"
        f"  [dim]by {APP_AUTHOR}[/dim]"
        f"  [dim]·[/dim]"
        f"  [dim]SentinelOne Log Analysis Tool[/dim]"
    )
    console.print(Rule(style="dim blue"))
    console.print()


def _risk_label(findings: list[Finding]) -> tuple[int, str]:
    weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    score = min(100, sum(weights.get(f.severity, 0) for f in findings))
    if score >= 75:   label = "CRITICAL"
    elif score >= 50: label = "HIGH"
    elif score >= 25: label = "MEDIUM"
    elif score > 0:   label = "LOW"
    else:             label = "MINIMAL"
    return score, label


def _bar(value: int, max_value: int, width: int = 20, color: str = "cyan") -> str:
    """Render a proportional block bar."""
    if max_value == 0:
        filled = 0
    else:
        filled = round(value / max_value * width)
    filled = max(0, min(width, filled))
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * (width - filled)}[/dim]"


def print_summary(
    ctx: SystemContext,
    findings: list[Finding],
    report_md: str,
    report_json: str,
    report_html: str | None = None,
    elapsed: float | None = None,
) -> None:
    hostname  = ctx.hostname or ctx.model or "Unknown"
    dump_date = ctx.parse_stats.get("dump_date", "Unknown")
    now_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    # ── Banner ────────────────────────────────────────────────────────────────
    console.print()
    console.print(Rule(
        f"[bold cyan]{APP_NAME}[/bold cyan]  [dim]v{APP_VERSION}[/dim]"
        f"  [dim]·  {APP_AUTHOR}[/dim]"
        f"  [dim]·  {hostname}[/dim]",
        style="cyan",
    ))
    console.print()

    # ── Critical alerts ───────────────────────────────────────────────────────
    alerts: list[str] = []
    if ctx.sip_enabled is False:
        alerts.append("[bold red]⚠  SIP DISABLED[/bold red]  —  System Integrity Protection is OFF.")
    agent_state = ctx.sentinel_status.get("agent", {}).get("Agent Operational State", "")
    if agent_state and agent_state.lower() not in ("enabled", "active", "running"):
        alerts.append(f"[bold red]⚠  AGENT NOT OPERATIONAL[/bold red]  —  State: {agent_state}")
    if ctx.sentinel_status.get("missing_authorizations"):
        alerts.append("[bold yellow]⚠  MISSING AUTHORIZATIONS[/bold yellow]  —  Agent lacks critical permissions.")
    if ctx.sentinel_status.get("degraded_services"):
        ds = ctx.sentinel_status["degraded_services"]
        alerts.append(f"[bold yellow]⚠  DEGRADED SERVICES ({len(ds)})[/bold yellow]  —  {', '.join(ds)}")
    # Operational alerts from alert engine
    for a in (ctx.operational_alerts or [])[:3]:
        lvl = a.get("level", "")
        if lvl == "CRITICAL":
            alerts.append(f"[bold red]⚠  {a.get('title','')}[/bold red]")
        elif lvl == "HIGH" and len(alerts) < 5:
            alerts.append(f"[bold yellow]!  {a.get('title','')}[/bold yellow]")

    if alerts:
        alert_lines = "\n".join(f"  {a}" for a in alerts)
        console.print(Panel(
            alert_lines,
            title="[bold red] Operational Alerts [/bold red]",
            border_style="red",
            padding=(0, 1),
            expand=False,
        ))
        console.print()

    # ── System Overview ───────────────────────────────────────────────────────
    sip_str = (
        "[green]Enabled[/green]" if ctx.sip_enabled is True
        else "[red]DISABLED[/red]" if ctx.sip_enabled is False
        else "[dim]Unknown[/dim]"
    )
    elapsed_str = f"  [dim]{elapsed:.1f}s[/dim]" if elapsed is not None else ""
    sys_table = Table(box=None, show_header=False, padding=(0, 1), expand=False)
    sys_table.add_column(style="dim", no_wrap=True, min_width=14)
    sys_table.add_column()
    for k, v in [
        ("Host",       f"[bold]{hostname}[/bold]"),
        ("Model",      ctx.model or "—"),
        ("OS",         f"{ctx.os_version or '—'}  [dim]({ctx.arch or '—'})[/dim]"),
        ("User",       f"[cyan]{ctx.primary_user or '—'}[/cyan]"),
        ("S1 Agent",   f"[cyan]{ctx.agent_version or '—'}[/cyan]"),
        ("Dump Date",  f"[blue]{dump_date}[/blue]"),
        ("SIP",        sip_str),
        ("Analyzed",   f"[dim]{now_str}[/dim]{elapsed_str}"),
    ]:
        sys_table.add_row(k, v)

    console.print(Panel(sys_table, title="[dim] System Overview [/dim]", border_style="dim blue", padding=(0, 1)))
    console.print()

    # ── Parse statistics ──────────────────────────────────────────────────────
    stats = ctx.parse_stats
    stat_pairs = [
        ("Events parsed",    f"{stats.get('match_reports_events', 0):,}"),
        ("Match reports",    f"{stats.get('match_reports_count', stats.get('match_reports_events', 0)):,}"),
        ("Rules applied",    f"{stats.get('rules_count', 0):,}"),
        ("Raw findings",     f"{stats.get('total_findings', 0):,}"),
        ("After filter",     f"{stats.get('filtered_findings', 0):,}"),
        ("Parse warnings",   f"[{'yellow' if ctx.parse_warnings else 'green'}]{len(ctx.parse_warnings)}[/{'yellow' if ctx.parse_warnings else 'green'}]"),
    ]
    stat_table = Table(box=None, show_header=False, padding=(0, 3), expand=False)
    stat_table.add_column(style="dim", no_wrap=True, min_width=18)
    stat_table.add_column(justify="right", style="cyan", no_wrap=True, min_width=8)
    stat_table.add_column(style="dim", no_wrap=True, min_width=18)
    stat_table.add_column(justify="right", style="cyan", no_wrap=True, min_width=8)
    for i in range(0, len(stat_pairs), 2):
        l1, v1 = stat_pairs[i]
        l2, v2 = stat_pairs[i + 1] if i + 1 < len(stat_pairs) else ("", "")
        stat_table.add_row(l1, v1, l2, v2)

    console.print(Rule("[dim] Statistics [/dim]", style="dim"))
    console.print(stat_table)
    console.print()

    # ── Output files ──────────────────────────────────────────────────────────
    console.print(Rule("[dim] Output [/dim]", style="dim"))
    out_table = Table(box=None, show_header=False, padding=(0, 1), expand=False)
    out_table.add_column(style="dim", no_wrap=True, min_width=12)
    out_table.add_column()
    if report_html:
        out_table.add_row("[bold]HTML[/bold]",     f"[bold cyan]{report_html}[/bold cyan]")
    out_table.add_row("Markdown",  report_md)
    out_table.add_row("JSON",      report_json)
    console.print(out_table)
    if report_html:
        console.print(f"\n  [dim]Open in browser →[/dim]  [cyan]{report_html}[/cyan]")
    console.print()
    console.print(Rule(style="dim blue"))
    console.print()
