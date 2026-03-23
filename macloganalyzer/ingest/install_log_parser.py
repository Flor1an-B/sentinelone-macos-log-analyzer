"""install_log_parser.py — Parses logs/install.log and logs/asl.log.

Extracts:
  - Package installation events (installer/installd)
  - System boot/shutdown/login/logout events (asl.log UTMPX records)
  - Software update check frequency
  - XProtect security update dates
  - Aggregate operational statistics
"""
from __future__ import annotations
import gzip
import re
from datetime import datetime
from pathlib import Path

from macloganalyzer.models.context import SystemContext


# ─── Regexes ─────────────────────────────────────────────────────────────────

# install.log timestamp: "2026-01-31 12:10:13+01"
_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[+-]\d{2}")

# Product archive line: installer/Installer/installd/system_installd
_PRODUCT_ARCHIVE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[+-]\d{2} \S+ "
    r"(?:[Ii]nstal(?:ler|ld|l_installd))\[(\d+)\]: "
    r"Product archive (.+?)(?:\s+trustLevel=(\d+))?$"
)
# "Opened from: /path/to/file.pkg"
_OPENED_FROM_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[+-]\d{2} \S+ "
    r"[Ii]nstal(?:ler|ld)\[(\d+)\]: Opened from: (.+\.pkg)"
)
# PKLeopardPackage continuation (tab-indented after Product archive)
_PKG_DETAIL_RE = re.compile(
    r'PKLeopardPackage <id=([^,]+), version=([^,]+), url=([^>]+)>'
)
# Extracting uid from Extracting line: "uid=501"
_UID_RE = re.compile(r"\buid=(\d+)")

# Power events from softwareupdated
_POWER_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[+-]\d{2} \S+ softwareupdated\[\d+\]: "
    r"SUOSUPowerEventObserver: (System has powered on|System will sleep|System will restart)"
)
# Periodic update check
_UPDATE_CHECK_RE = re.compile(r"SUOSUServiceDaemon: Periodic autoupdate action called")

# XProtect destination path (embedded in installd output)
_XPROTECT_RE = re.compile(
    r"^\s+destination path:.*XProtect(?:PlistConfigData|Payloads).*\.pkg"
)

# asl.log: BOOT_TIME / SHUTDOWN_TIME / USER_PROCESS / DEAD_PROCESS
# Format: "Feb 12 15:31:30 hostname bootlog[0] <Notice>: BOOT_TIME 1770906690 709930"
_ASL_EVENT_RE = re.compile(
    r"^(\w{3} +\d{1,2} \d{2}:\d{2}:\d{2}) \S+ \S+\[\d+\] <\w+>: "
    r"(BOOT_TIME|SHUTDOWN_TIME|USER_PROCESS|DEAD_PROCESS)[: ]+(.*)$"
)

# ─── Source classification ────────────────────────────────────────────────────

_SOURCE_LABELS = {
    "app_store":     "App Store",
    "auto_update":   "Auto-update",
    "system_update": "System Update",
    "manual":        "⚠️ Manual",
    "sentinel":      "SentinelOne",
    "unknown":       "Unknown",
}


def _classify_source(path: str) -> str:
    p = path.lower()
    if "sentinelone" in p or "sentinel-agent" in p or "sentinel_agent" in p:
        return "sentinel"
    if "com.apple.appstoreagent" in p or "/com.apple.appstore/" in p:
        return "app_store"
    if ("swcdn.apple.com" in p or "com.apple.softwareupdate" in p
            or "xprotect" in p.lower()):
        return "system_update"
    if any(kw in p for kw in [
        "onedrivedaemonupdate", "com.microsoft.autoupdate",
        "zoom.us/updater", "application support/zoom.us",
        "application%20support/zoom.us",
    ]):
        return "auto_update"
    if "/downloads/" in p:
        return "manual"
    if p.startswith("/tmp") or p.startswith("/private/tmp"):
        return "manual"
    return "unknown"


# ─── Bundle ID → friendly name ───────────────────────────────────────────────

_BUNDLE_NAMES: dict[str, str] = {
    "com.microsoft.OneDrive":              "Microsoft OneDrive",
    "us.zoom.pkg.videomeeting":            "Zoom",
    "com.sentinelone.pkg.sentinel-agent":  "SentinelOne Agent",
    "com.apple.pkg.Numbers14":             "Numbers",
    "com.apple.pkg.iMovie_AppStore":       "iMovie",
    "com.apple.pkg.Pages14":              "Pages",
    "com.apple.pkg.Keynote14":            "Keynote",
    "com.apple.pkg.GarageBand":           "GarageBand",
    "com.microsoft.onenote.standalone":   "Microsoft OneNote",
    "com.microsoft.word.standalone":      "Microsoft Word",
    "com.microsoft.excel.standalone":     "Microsoft Excel",
    "com.microsoft.powerpoint.standalone":"Microsoft PowerPoint",
    "com.microsoft.autoupdate2":          "Microsoft AutoUpdate",
}

_PKG_NAME_CLEAN_RE = re.compile(
    r"_\d{2}\.\d+.*$|_BinaryDelta$|_AppStore$|_Updater$|\.pkg$"
)


def _friendly_name(bundle_id: str, pkg_path: str) -> str:
    if bundle_id and bundle_id in _BUNDLE_NAMES:
        return _BUNDLE_NAMES[bundle_id]
    if bundle_id:
        # Use last component of bundle ID as fallback
        parts = bundle_id.split(".")
        last = parts[-1].replace("-", " ").replace("_", " ")
        # Capitalize words, strip "pkg" prefix
        if last.lower().startswith("pkg "):
            last = last[4:]
        return last.title()
    # Fall back to pkg filename
    filename = pkg_path.rsplit("/", 1)[-1]
    filename = _PKG_NAME_CLEAN_RE.sub("", filename)
    return filename.replace("_", " ").replace("-", " ").strip() or pkg_path


# ─── install.log parser ───────────────────────────────────────────────────────

def _parse_install_log(path: Path) -> tuple[list[dict], list[dict], dict]:
    """
    Returns (install_history, boot_events, stats).
    boot_events here = power-on/sleep events from softwareupdated.
    """
    install_history: list[dict] = []
    boot_events: list[dict] = []
    stats = {
        "update_checks": 0,
        "xprotect_updates": 0,
        "boot_count": 0,
        "sleep_count": 0,
        "sentinel_install_date": None,
        "log_period_start": None,
        "log_period_end": None,
    }

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return install_history, boot_events, stats

    pending: dict | None = None  # current install entry being built

    for line in lines:
        # Track date range
        m_ts = _TS_RE.match(line)
        if m_ts:
            ts_str = m_ts.group(1)
            if stats["log_period_start"] is None or ts_str < stats["log_period_start"]:
                stats["log_period_start"] = ts_str[:10]
            if stats["log_period_end"] is None or ts_str > stats["log_period_end"]:
                stats["log_period_end"] = ts_str[:10]

        # Flush pending if this is a new timestamp line (not a continuation)
        if pending is not None and m_ts and not line.startswith("\t"):
            if pending.get("bundle_id") or pending.get("source_path"):
                install_history.append(pending)
            pending = None

        # Power events
        m_power = _POWER_RE.match(line)
        if m_power:
            ts, event = m_power.group(1), m_power.group(2)
            ev_type = "boot" if "powered on" in event else (
                "restart" if "restart" in event else "sleep"
            )
            boot_events.append({"event_type": ev_type, "timestamp": ts})
            if ev_type == "boot":
                stats["boot_count"] += 1
            elif ev_type == "sleep":
                stats["sleep_count"] += 1
            continue

        # Update check
        if _UPDATE_CHECK_RE.search(line):
            stats["update_checks"] += 1
            continue

        # XProtect update
        if _XPROTECT_RE.match(line):
            stats["xprotect_updates"] += 1
            continue

        # Opened from (GUI installer — captures path before Product archive)
        m_open = _OPENED_FROM_RE.match(line)
        if m_open:
            ts, _pid, pkg_path = m_open.group(1), m_open.group(2), m_open.group(3)
            source = _classify_source(pkg_path)
            pending = {
                "timestamp": ts,
                "date": ts[:10],
                "package_name": _friendly_name("", pkg_path),
                "bundle_id": "",
                "version": "",
                "source_type": source,
                "source_path": pkg_path,
                "trust_level": None,
                "uid": None,
            }
            continue

        # Product archive
        m_arch = _PRODUCT_ARCHIVE_RE.match(line)
        if m_arch:
            ts, _pid, pkg_path, trust = (
                m_arch.group(1), m_arch.group(2),
                m_arch.group(3), m_arch.group(4),
            )
            source = _classify_source(pkg_path)
            # Don't create a new pending if we already have one (Opened from already set it)
            if pending is None or pending.get("timestamp") != ts:
                pending = {
                    "timestamp": ts,
                    "date": ts[:10],
                    "package_name": _friendly_name("", pkg_path),
                    "bundle_id": "",
                    "version": "",
                    "source_type": source,
                    "source_path": pkg_path,
                    "trust_level": int(trust) if trust else None,
                    "uid": None,
                }
            continue

        # PKLeopardPackage detail (tab-indented continuation)
        if pending is not None and "\t" in line:
            m_pkg = _PKG_DETAIL_RE.search(line)
            if m_pkg:
                bundle_id, version = m_pkg.group(1), m_pkg.group(2)
                pending["bundle_id"] = bundle_id
                pending["version"] = version
                pending["package_name"] = _friendly_name(bundle_id, pending.get("source_path", ""))
                # Re-classify now that we have the bundle ID
                pending["source_type"] = _classify_source(
                    pending.get("source_path", "") + " " + bundle_id
                )
            # Extract uid if present
            m_uid = _UID_RE.search(line)
            if m_uid and pending.get("uid") is None:
                pending["uid"] = int(m_uid.group(1))

    # Flush last pending
    if pending and (pending.get("bundle_id") or pending.get("source_path")):
        install_history.append(pending)

    # Post-process: find SentinelOne install date
    for entry in install_history:
        if entry.get("source_type") == "sentinel":
            stats["sentinel_install_date"] = entry["date"]
            break

    # Deduplicate by (date, bundle_id) keeping the first occurrence
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for entry in install_history:
        key = (entry["date"], entry["bundle_id"] or entry["source_path"])
        if key not in seen:
            seen.add(key)
            deduped.append(entry)

    stats["total_installs"] = len(deduped)
    return deduped, boot_events, stats


# ─── asl.log parser ──────────────────────────────────────────────────────────

_ASL_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


def _parse_asl_log(path: Path) -> list[dict]:
    """Return list of {event_type, timestamp, unix_time, pid} from asl.log."""
    sessions: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return sessions

    # Infer year from filename context (use current year as best guess)
    year = datetime.now().year

    for line in lines:
        m = _ASL_EVENT_RE.match(line)
        if not m:
            continue
        ts_raw, event_type, payload = m.group(1), m.group(2), m.group(3).strip()

        # Parse "Mon DD HH:MM:SS" → approximate datetime string
        parts = ts_raw.split()
        if len(parts) == 3:
            mon_num = _ASL_MONTHS.get(parts[0], "01")
            day = parts[1].strip().zfill(2)
            ts_str = f"{year}-{mon_num}-{day} {parts[2]}"
        else:
            ts_str = ts_raw

        ev_map = {
            "BOOT_TIME":      "boot",
            "SHUTDOWN_TIME":  "shutdown",
            "USER_PROCESS":   "login",
            "DEAD_PROCESS":   "logout",
        }
        ev = ev_map.get(event_type, event_type.lower())

        # Extract unix timestamp if present (BOOT_TIME / SHUTDOWN_TIME)
        unix_time: int | None = None
        parts_payload = payload.split()
        if parts_payload and parts_payload[0].isdigit():
            unix_time = int(parts_payload[0])

        sessions.append({
            "event_type": ev,
            "timestamp": ts_str,
            "unix_time": unix_time,
        })

    return sessions


# ─── Entry point ─────────────────────────────────────────────────────────────

def parse_install_logs(dump_path: Path, ctx: SystemContext) -> None:
    """Parse logs/install.log and logs/asl.log into ctx."""
    logs_dir = dump_path / "logs"
    if not logs_dir.is_dir():
        return

    install_log = logs_dir / "install.log"
    if install_log.exists() and install_log.stat().st_size > 0:
        history, boot_evs, stats = _parse_install_log(install_log)
        ctx.install_history = history
        ctx.install_stats = stats
        # Merge power events into install_stats
        ctx.install_stats["power_events"] = boot_evs

    asl_log = logs_dir / "asl.log"
    if asl_log.exists() and asl_log.stat().st_size > 0:
        ctx.system_sessions = _parse_asl_log(asl_log)
