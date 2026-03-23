"""update.py — Self-update module for SentinelOne macOS Log Analyzer.

Compares local package files against the latest GitHub release using git blob
SHA1 checksums, then downloads only the files that have changed.

Usage (CLI):
    macloganalyzer --update
"""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import NamedTuple

# ── Configuration ─────────────────────────────────────────────────────────────
_REPO     = "Flor1an-B/sentinelone-macos-log-analyzer"
_RAW_BASE = f"https://raw.githubusercontent.com/{_REPO}/main"
_API_BASE = f"https://api.github.com/repos/{_REPO}"
_GITHUB   = f"github.com/{_REPO}"
_TIMEOUT  = 20  # seconds per HTTP request

# Only manage Python source files within the macloganalyzer package
_PKG_PREFIX   = "macloganalyzer/"
_ALLOWED_EXTS = {".py"}


# ── Data types ────────────────────────────────────────────────────────────────

class _FileChange(NamedTuple):
    path:       str   # repo-relative, e.g. "macloganalyzer/update.py"
    kind:       str   # "added" | "modified" | "removed"
    remote_sha: str   # git blob SHA1 from GitHub tree API (empty for "removed")


# ── Public entry point ────────────────────────────────────────────────────────

def run_update(current_version: str) -> None:
    """Interactive self-updater.  Called by ``macloganalyzer --update``."""
    from rich.align import Align
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
    )
    from rich.prompt import Confirm
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
    from rich import box

    console = Console()

    # ── Banner ────────────────────────────────────────────────────────────────
    _print_banner(console, current_version)

    # ── Fetch latest release tag ──────────────────────────────────────────────
    with console.status("[bold cyan]Connecting to GitHub…[/bold cyan]", spinner="dots"):
        try:
            latest = _fetch_latest_version()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                console.print(
                    "\n[yellow]⚠[/yellow]  No releases published yet on GitHub. "
                    "Check back later or visit:\n"
                    f"  [dim cyan]{_GITHUB}/releases[/dim cyan]\n"
                )
            else:
                console.print(f"\n[red]✗[/red]  GitHub API error {exc.code}: {exc.reason}\n")
            sys.exit(1)
        except urllib.error.URLError as exc:
            console.print(f"\n[red]✗[/red]  Could not reach GitHub: {exc.reason}\n")
            sys.exit(1)
        except Exception as exc:
            console.print(f"\n[red]✗[/red]  Unexpected error: {exc}\n")
            sys.exit(1)

    if _version_tuple(latest) <= _version_tuple(current_version):
        console.print(
            f"  [green]✓[/green]  Already up to date — "
            f"[bold green]v{current_version}[/bold green]\n"
        )
        return

    # ── Show version delta ────────────────────────────────────────────────────
    console.print(
        f"  [dim]Current[/dim]  [bold white]v{current_version}[/bold white]\n"
        f"  [dim]Latest [/dim]  [bold green]v{latest}[/bold green]  "
        f"[green]●  Update available[/green]\n"
    )

    # ── Build diff ────────────────────────────────────────────────────────────
    with console.status("[bold cyan]Fetching change list…[/bold cyan]", spinner="dots"):
        try:
            import macloganalyzer as _pkg
            pkg_dir     = Path(_pkg.__file__).parent
            remote_tree = _fetch_remote_tree(latest)
            local_tree  = _build_local_tree(pkg_dir)
            changes     = _diff_trees(local_tree, remote_tree)
        except Exception as exc:
            console.print(f"\n[red]✗[/red]  Could not compute diff: {exc}\n")
            sys.exit(1)

    if not changes:
        console.print("[green]✓[/green]  No file changes detected — already in sync.\n")
        return

    # ── Change table ──────────────────────────────────────────────────────────
    _print_change_table(console, changes)

    # ── Confirm ───────────────────────────────────────────────────────────────
    try:
        confirmed = Confirm.ask(
            f"\n  Apply update  [bold white]v{current_version}[/bold white]"
            f"  →  [bold green]v{latest}[/bold green]?",
            default=True,
        )
    except (KeyboardInterrupt, EOFError):
        console.print("\n\n[dim]Update cancelled.[/dim]\n")
        return

    if not confirmed:
        console.print("\n[dim]Update cancelled.[/dim]\n")
        return

    # ── Download & apply ──────────────────────────────────────────────────────
    console.print()
    errors: list[str] = []
    to_download = [c for c in changes if c.kind != "removed"]
    to_remove   = [c for c in changes if c.kind == "removed"]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description:<55}"),
        BarColumn(bar_width=24),
        MofNCompleteColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(
            "[cyan]Downloading files…[/cyan]",
            total=len(to_download),
        )

        for change in to_download:
            short = change.path[len(_PKG_PREFIX):]          # strip "macloganalyzer/"
            progress.update(task, description=f"[cyan]{change.path}[/cyan]")
            try:
                content = _download_file(change.path, latest)

                # Verify integrity: downloaded content must match GitHub tree SHA
                if _git_blob_sha(content) != change.remote_sha:
                    raise ValueError("SHA mismatch — file integrity check failed")

                dest = pkg_dir / short
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)

                kind_badge = (
                    "[green]+ added[/green]"
                    if change.kind == "added"
                    else "[yellow]~ updated[/yellow]"
                )
                progress.console.print(f"  {kind_badge}  [dim]{change.path}[/dim]")

            except Exception as exc:
                errors.append(f"{change.path}: {exc}")
                progress.console.print(
                    f"  [red]✗ error[/red]   [dim]{change.path}[/dim]  "
                    f"[red dim]{exc}[/red dim]"
                )
            finally:
                progress.advance(task)

        # Handle removals (rare: file deleted in new version)
        for change in to_remove:
            short = change.path[len(_PKG_PREFIX):]
            dest  = pkg_dir / short
            try:
                dest.unlink(missing_ok=True)
                progress.console.print(f"  [red]- removed[/red]  [dim]{change.path}[/dim]")
            except Exception as exc:
                errors.append(f"{change.path}: {exc}")

    # ── Result ────────────────────────────────────────────────────────────────
    console.print()
    if errors:
        err_lines = "\n".join(f"  [red]•[/red] {e}" for e in errors)
        console.print(
            Panel(
                f"{err_lines}\n\n[dim]Some files were not updated. "
                "Re-run [bold]macloganalyzer --update[/bold] or reinstall manually.[/dim]",
                title="[red bold]  Update completed with errors  [/red bold]",
                border_style="red",
                padding=(1, 2),
            )
        )
    else:
        ok_count = len(to_download) + len(to_remove)
        console.print(
            Panel(
                f"  [bold white]v{current_version}[/bold white]"
                f"  [dim]→[/dim]  "
                f"[bold green]v{latest}[/bold green]"
                f"  [dim]·[/dim]  {ok_count} file(s) updated\n\n"
                "  [dim]Restart [bold]macloganalyzer[/bold] to use the new version.[/dim]",
                title="[green bold]  ✓  Update complete  [/green bold]",
                border_style="green",
                padding=(1, 2),
                width=68,
            )
        )
    console.print()


# ── Visual helpers ────────────────────────────────────────────────────────────

def _print_banner(console, current_version: str) -> None:  # type: ignore[no-untyped-def]
    from rich.align import Align
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.text import Text

    # Top decorative rule
    console.print()
    console.print(Rule(style="dim cyan"))

    # Title line
    title = Text()
    title.append("🛡  ", style="bold")
    title.append("SentinelOne macOS Log Analyzer", style="bold cyan")
    title.append("  ·  ", style="dim white")
    title.append("Updater", style="bold white")

    # Body
    body = Text(justify="left")
    body.append("\n")
    body.append("  by ", style="dim")
    body.append("Florian Bertaux", style="bold white")
    body.append("\n")
    body.append(f"  {_GITHUB}", style="dim cyan underline")
    body.append("\n\n")
    body.append("  Current version  ", style="dim")
    body.append(f"v{current_version}", style="bold yellow")
    body.append("\n")

    console.print(
        Align.center(
            Panel(
                body,
                title=title,
                border_style="cyan",
                padding=(0, 3),
                width=70,
            )
        )
    )
    console.print(Rule(style="dim cyan"))
    console.print()


def _print_change_table(console, changes: list[_FileChange]) -> None:  # type: ignore[no-untyped-def]
    from rich.table import Table
    from rich import box

    _KIND_LABEL = {
        "added":    "[bold green]+ added[/bold green]",
        "modified": "[bold yellow]~ modified[/bold yellow]",
        "removed":  "[bold red]- removed[/bold red]",
    }
    _KIND_ORDER = {"added": 0, "modified": 1, "removed": 2}

    table = Table(
        box=box.ROUNDED,
        border_style="dim cyan",
        show_header=True,
        header_style="bold dim",
        padding=(0, 1),
        expand=False,
    )
    table.add_column("Status",   width=14, no_wrap=True)
    table.add_column("File",     style="dim cyan")

    for change in sorted(changes, key=lambda c: (_KIND_ORDER.get(c.kind, 9), c.path)):
        table.add_row(_KIND_LABEL.get(change.kind, "?"), change.path)

    console.print(f"  [bold white]{len(changes)}[/bold white] file(s) to update:\n")
    console.print(table)


# ── GitHub helpers ────────────────────────────────────────────────────────────

def _fetch_latest_version() -> str:
    """Return the latest release version string (without leading 'v')."""
    url = f"{_API_BASE}/releases/latest"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        data = json.loads(resp.read())
    tag = data.get("tag_name", "").lstrip("v")
    if not tag:
        raise ValueError("Could not parse latest release tag from GitHub API response.")
    return tag


def _fetch_remote_tree(tag: str) -> dict[str, str]:
    """Return {repo_path: git_blob_sha1} for all updatable remote files at *tag*."""
    url = f"{_API_BASE}/git/trees/v{tag}?recursive=1"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        data = json.loads(resp.read())
    result: dict[str, str] = {}
    for item in data.get("tree", []):
        if item.get("type") != "blob":
            continue
        path = item["path"]
        if not path.startswith(_PKG_PREFIX):
            continue
        if Path(path).suffix not in _ALLOWED_EXTS:
            continue
        result[path] = item["sha"]
    return result


def _build_local_tree(pkg_dir: Path) -> dict[str, str]:
    """Return {repo_path: git_blob_sha1} for all local package Python files."""
    result: dict[str, str] = {}
    for f in pkg_dir.rglob("*.py"):
        try:
            content = f.read_bytes()
        except OSError:
            continue
        # Convert absolute path to repo-relative: "macloganalyzer/..."
        rel = f.relative_to(pkg_dir.parent).as_posix()
        result[rel] = _git_blob_sha(content)
    return result


def _diff_trees(
    local: dict[str, str],
    remote: dict[str, str],
) -> list[_FileChange]:
    """Compare local vs remote trees and return the list of changes."""
    changes: list[_FileChange] = []
    for path, sha in remote.items():
        if path not in local:
            changes.append(_FileChange(path, "added", sha))
        elif local[path] != sha:
            changes.append(_FileChange(path, "modified", sha))
    for path in local:
        if path not in remote:
            changes.append(_FileChange(path, "removed", ""))
    return changes


def _download_file(repo_path: str, tag: str) -> bytes:
    """Download a single file from the tagged release commit on GitHub."""
    url = f"https://raw.githubusercontent.com/{_REPO}/v{tag}/{repo_path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return resp.read()


# ── Cryptographic helpers ─────────────────────────────────────────────────────

def _git_blob_sha(content: bytes) -> str:
    """Compute the git blob SHA1 of raw file content.

    Git stores objects as: SHA1("blob {size}\\0{content}")
    This matches the SHA returned by the GitHub tree API.
    """
    header = f"blob {len(content)}\0".encode()
    return hashlib.sha1(header + content).hexdigest()


def _version_tuple(v: str) -> tuple[int, ...]:
    """Convert a version string to a comparable tuple."""
    try:
        return tuple(int(x) for x in v.strip().split("."))
    except ValueError:
        return (0,)
