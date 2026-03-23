"""alerts.py — Auto-generate operational alerts from parsed SystemContext."""
from __future__ import annotations
from macloganalyzer.models.context import SystemContext


def generate_operational_alerts(ctx: SystemContext) -> list[dict]:
    """
    Synthesize all parsed data into prioritized, actionable operational alerts.
    Each alert: {level, title, detail, action}
    level: CRITICAL | HIGH | MEDIUM | INFO
    """
    alerts: list[dict] = []

    def _alert(level: str, title: str, detail: str, action: str) -> None:
        alerts.append({"level": level, "title": title, "detail": detail, "action": action})

    # ── 1. Asset signature integrity ─────────────────────────────────────────
    # Core assets are critical for detection — invalid = protection gap
    _CORE_ASSETS = frozenset({
        "signatures", "sha1", "sha256", "arbiter", "blacklist", "whitelist",
    })
    invalid_assets = [a["name"] for a in ctx.asset_signatures if a.get("status") == "invalid"]
    if invalid_assets:
        core_invalid = [n for n in invalid_assets if any(k in n.lower() for k in _CORE_ASSETS)]
        feat_invalid = [n for n in invalid_assets if n not in core_invalid]
        if core_invalid:
            _alert(
                "CRITICAL",
                f"Core detection asset signature invalid: {', '.join(core_invalid)}",
                f"The core detection asset(s) {', '.join(core_invalid)} failed signature verification. "
                "These assets are required for static AI / hash-based detection. "
                "This may indicate file corruption, tampering, or a version mismatch.",
                "Re-download assets from the SentinelOne console (Agent → Actions → Fetch Logs), "
                "or reinstall the agent if the issue persists.",
            )
        if feat_invalid:
            _alert(
                "MEDIUM",
                f"Feature asset signature invalid: {', '.join(feat_invalid)}",
                f"The feature asset(s) {', '.join(feat_invalid)} failed signature verification. "
                "These assets affect supplementary capabilities (e.g. exclusion lists, DV config) "
                "but do not disable core threat detection.",
                "Re-download assets from the SentinelOne console (Agent → Actions → Fetch Logs). "
                "Monitor for recurrence; escalate if it persists after asset refresh.",
            )

    # ── 2. Daemon not ready ───────────────────────────────────────────────────
    # Excluded from alerting:
    #   - sentineld_shell: on-demand only, activates during remote shell sessions
    #   - Shell: companion entry for sentineld_shell
    #   - Lib Hooks Service / Lib Logs Service: deprecated, no longer used by the agent
    _ON_DEMAND = frozenset({
        "sentineld_shell",
        "Shell",
        "Lib Hooks Service",
        "Lib Logs Service",
    })
    not_ready = [
        d["name"] for d in ctx.daemon_states
        if not d.get("ready", True) and d["name"] not in _ON_DEMAND
    ]
    if not_ready:
        _alert(
            "HIGH",
            f"Agent daemon(s) not ready: {', '.join(not_ready)}",
            f"The following SentinelOne daemons are in 'not ready' state: {', '.join(not_ready)}. "
            "A daemon not ready may reduce detection coverage or agent functionality.",
            "Check System Preferences → Privacy & Security → Full Disk Access — ensure SentinelOne is authorized. "
            "If permissions are already granted, restart the agent: sentinelctl stop && sentinelctl start.",
        )

    # ── 3. sentineld disk write spike (crash report) ─────────────────────────
    disk_spike = any(
        "sentineld" in str(e.get("process", "")).lower() and "disk" in str(e.get("event_type", "")).lower()
        for e in ctx.system_sessions
    )
    # Also check via agent_log errors or sentinel_operational
    sentinel_crashes = [
        e for e in (ctx.system_sessions or [])
        if "sentineld" in str(e.get("process", "")).lower()
    ]
    # Check parse_stats for crash count
    crash_count = ctx.parse_stats.get("crash_events", 0)
    if crash_count > 0:
        # Check if any sentineld crash
        sentinel_crash_note = ""
        for event in (ctx.system_sessions or []):
            if event.get("event_type") == "crash" and "sentineld" in str(event.get("pid", "")):
                sentinel_crash_note = " A sentineld disk-write resource violation was detected (2.1 GB in 90s)."
                break
    # Direct check: look for disk write spike in sentinel_operational
    db_io = ctx.sentinel_db_health
    if db_io.get("db_read_gib", 0) > 20 or db_io.get("db_write_gib", 0) > 20:
        _alert(
            "HIGH",
            f"SentinelOne database I/O very high: "
            f"{db_io.get('db_read_gib', 0):.1f} GiB read / {db_io.get('db_write_gib', 0):.1f} GiB written",
            f"Since {db_io.get('db_stats_since', 'unknown')}, sentineld has performed "
            f"{db_io.get('db_read_gib', 0):.1f} GiB of reads and {db_io.get('db_write_gib', 0):.1f} GiB of writes. "
            "This is abnormally high and correlates with the disk-write resource violation recorded in the crash logs "
            "(2.1 GB written in 90 seconds, exceeding Apple's 24.86 KB/s limit).",
            "Review agent log for database flush events. If the issue is recurrent, "
            "consider restarting the agent. Escalate to SentinelOne support with the crash .diag file.",
        )

    # ── 4. state.wonky database ───────────────────────────────────────────────
    if ctx.sentinel_db_health.get("has_wonky"):
        wonky_mb = ctx.sentinel_db_health.get("wonky_db_mb", 0)
        _alert(
            "HIGH",
            f"SentinelOne state database recovery file present (state.wonky — {wonky_mb} MB)",
            "A 'state.wonky' recovery file exists in the SentinelOne database directory. "
            "This file is created by LevelDB when the main state.db was not cleanly closed "
            "(e.g., after a crash or forced kill). It indicates the database may have been in an inconsistent state.",
            "Monitor for recurrence. If agent behavior is abnormal (missed detections, high CPU), "
            "restart the agent to trigger a clean DB recovery, or reinstall if the file keeps reappearing.",
        )

    # ── 5. Full disk scan never run ───────────────────────────────────────────
    scan_status = ctx.sentinel_operational.get("last_scan_status", "")
    if scan_status.lower() in ("never", "never.", ""):
        _alert(
            "MEDIUM",
            "Full disk scan has never been performed on this endpoint",
            "sentinelctl scan-info reports 'Last full disk scan: Never'. "
            "Without a baseline scan, dormant or pre-installed threats may not be detected.",
            "Trigger an on-demand full disk scan from the SentinelOne management console "
            "(Endpoints → select device → Actions → Full Disk Scan).",
        )

    # ── 6. Memory pressure ────────────────────────────────────────────────────
    pressure = ctx.vm_memory.get("pressure_level", "")
    free_mb  = ctx.vm_memory.get("free_mb", -1)
    if pressure in ("CRITICAL", "WARNING") and free_mb >= 0:
        level = "HIGH" if pressure == "CRITICAL" else "MEDIUM"
        _alert(
            level,
            f"System memory critically low: {free_mb} MB free",
            f"Only {free_mb} MB of physical memory is available. "
            f"The system is under heavy memory compression "
            f"({ctx.vm_memory.get('compressed_mb', 0)} MB compressed). "
            "Memory pressure can cause SentinelOne to be throttled or killed by the OS (Jetsam), "
            "leading to missed detections or agent restarts.",
            "Identify and close memory-intensive applications (e.g., Google Chrome with many tabs). "
            "If this is a persistent state, consider increasing RAM or reducing DV collection scope.",
        )

    # ── 7. Dual AV / conflicting security tools ──────────────────────────────
    dual_av_services = ctx.sentinelctl_error  # not the right place — use third_party_services
    # Check third_party_services for known AV/EDR service names
    _AV_SIGS = {
        "kaspersky": "Kaspersky AV",
        "crowdstrike": "CrowdStrike Falcon",
        "carbonblack": "Carbon Black",
        "cylance": "Cylance",
        "malwarebytes": "Malwarebytes",
        "sophos": "Sophos",
        "eset": "ESET",
        "bitdefender": "Bitdefender",
        "avast": "Avast",
        "symantec": "Symantec",
        "norton": "Norton",
        "mcafee": "McAfee",
        "f-secure": "F-Secure",
    }
    active_av = []
    for svc in ctx.third_party_services:
        name_lower = svc.get("name", "").lower()
        enabled = svc.get("enabled", False)
        if enabled:
            for sig, display in _AV_SIGS.items():
                if sig in name_lower:
                    active_av.append(display)
                    break
    # Also check installed_apps
    for app in ctx.installed_apps:
        app_lower = app.lower()
        for sig, display in _AV_SIGS.items():
            if sig in app_lower and display not in active_av:
                active_av.append(display)
                break
    if active_av:
        _alert(
            "HIGH",
            f"Conflicting security software detected: {', '.join(set(active_av))}",
            f"The following third-party security products were found alongside SentinelOne: "
            f"{', '.join(set(active_av))}. Running multiple endpoint protection products simultaneously "
            "is unsupported and may cause performance degradation, false positives, "
            "detection conflicts, or agent instability.",
            "Verify with the endpoint owner. If the conflicting product is intentional, "
            "document the justification. Otherwise, uninstall the conflicting product "
            "or coordinate exclusions between the two platforms.",
        )

    # ── 8. SIP disabled ───────────────────────────────────────────────────────
    if ctx.sip_enabled is False:
        _alert(
            "CRITICAL",
            "System Integrity Protection (SIP) is disabled",
            "SIP is disabled on this endpoint. SIP prevents unauthorized modification of system files "
            "and protects SentinelOne's own kernel-level components from tampering. "
            "Without SIP, an attacker can more easily disable or bypass endpoint protection.",
            "Re-enable SIP by booting into Recovery Mode (hold Power on Apple Silicon) "
            "and running: csrutil enable. Investigate why SIP was disabled.",
        )

    # ── 9. Agent management connectivity errors ───────────────────────────────
    agent_log = ctx.agent_log or {}
    dv_config_errors = agent_log.get("dv_config_errors", [])
    if dv_config_errors:
        _alert(
            "MEDIUM",
            f"Deep Visibility config errors from management ({len(dv_config_errors)} invalid variables)",
            f"The agent received DV configuration variables it does not recognize: "
            f"{', '.join(dv_config_errors[:5])}{'...' if len(dv_config_errors) > 5 else ''}. "
            "This indicates a version mismatch between the SentinelOne management console and the agent. "
            "Affected DV features may not be configured as intended.",
            "Upgrade the agent to the version required by the console policy, "
            "or downgrade the console policy to match the agent version.",
        )

    # ── 10. Agent log ASSERT errors ───────────────────────────────────────────
    asserts = agent_log.get("unique_asserts", {})
    if asserts:
        top_assert = next(iter(asserts))
        _alert(
            "MEDIUM",
            f"Agent log ASSERT errors detected ({sum(asserts.values())} occurrences)",
            f"The agent log contains ASSERT failures. Most frequent: '{top_assert[:120]}' "
            f"({asserts[top_assert]} times). ASSERT failures indicate unexpected internal state, "
            "potential data corruption, or schema mismatches in the detection context.",
            "Monitor for recurrence. If detection quality degrades, collect a full diagnostic "
            "bundle and escalate to SentinelOne support.",
        )

    # ── 11. Disk capacity ─────────────────────────────────────────────────────
    # Only check real data volumes — skip pseudo-filesystems (devfs, /dev, tiny volumes)
    _REAL_MOUNTS = {"/", "/System/Volumes/Data", "/System/Volumes/Update"}
    _DISK_CRITICAL = 95
    _DISK_HIGH     = 90
    _DISK_MEDIUM   = 85
    for vol in (ctx.disk_volumes or []):
        # Skip pseudo-filesystems: devfs (/dev), autofs, tiny volumes (< 1 GB shown as K/M)
        mp   = vol.get("mounted", "")
        size = vol.get("size", "")
        fs   = vol.get("filesystem", "")
        if mp == "/dev" or fs.startswith("devfs") or fs.startswith("map "):
            continue
        if size and size[-1] not in ("G", "T"):  # skip K/M-sized pseudo volumes
            continue
        cap = vol.get("capacity", 0)
        if cap >= _DISK_CRITICAL:
            _alert(
                "CRITICAL",
                f"Disk almost full: {mp} at {cap}%",
                f"Volume '{mp}' is {cap}% full ({vol.get('used','?')} used of {vol.get('size','?')}). "
                "macOS requires free space for memory swapping, crash reporting, and update installation. "
                "At this level, the OS and SentinelOne may begin failing silently.",
                f"Free space on '{mp}' immediately. Identify large files with: "
                "sudo du -sh /* | sort -rh | head -20. "
                "Consider moving data off-device or deleting redundant files.",
            )
            break  # one alert per dump is enough
        elif cap >= _DISK_HIGH:
            _alert(
                "HIGH",
                f"Disk space critically low: {mp} at {cap}%",
                f"Volume '{mp}' is {cap}% full ({vol.get('used','?')} used of {vol.get('size','?')}). "
                "Low disk space can cause agent DB write failures and missed log collection.",
                f"Free space on '{mp}' before it reaches 95%. "
                "Use: sudo du -sh /* | sort -rh | head -20 to find large directories.",
            )
            break
        elif cap >= _DISK_MEDIUM:
            _alert(
                "MEDIUM",
                f"Disk space warning: {mp} at {cap}%",
                f"Volume '{mp}' is {cap}% full ({vol.get('used','?')} used of {vol.get('size','?')}). "
                "Monitor for further growth — SentinelOne DB writes and macOS swap may accelerate consumption.",
                "Monitor disk usage. Plan cleanup or expansion before reaching 90%.",
            )
            break

    # ── 13. Unauthorized local config overrides ───────────────────────────────
    if ctx.local_config_modified:
        _alert(
            "MEDIUM",
            "Local SentinelOne config override detected (sentinelctl-config_local.txt)",
            "The file sentinelctl-config_local.txt is non-empty, indicating configuration values "
            "have been applied locally on this endpoint — outside of the management console policy. "
            "This may indicate manual tampering, a support-level override, or misconfiguration "
            "that bypasses centrally enforced policy settings.",
            "Review sentinelctl-config_local.txt content and verify if the override is authorized. "
            "If not, clear it with: sudo sentinelctl config --source local --delete <key>. "
            "Ensure all config is managed via the console policy.",
        )

    # Sort: CRITICAL first, then HIGH, MEDIUM, INFO
    _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    alerts.sort(key=lambda a: _order.get(a["level"], 9))
    return alerts
