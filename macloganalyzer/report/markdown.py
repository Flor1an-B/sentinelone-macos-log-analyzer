from __future__ import annotations
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from macloganalyzer.models.context import SystemContext
from macloganalyzer.models.finding import Finding
from macloganalyzer.models.event import Event
from macloganalyzer.report.console import APP_VERSION

_DUAL_AV_NAMES = frozenset({
    "kaspersky", "malwarebytes", "avast", "bitdefender", "norton",
    "crowdstrike", "sophos", "eset", "f-secure", "symantec",
})

SEVERITY_ICON = {
    "CRITICAL": "[CRIT]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MED]",
    "LOW": "[LOW]",
    "INFO": "[INFO]",
}


def generate_markdown(
    ctx: SystemContext,
    findings: list[Finding],
    events: list[Event],
    output_path: Path,
) -> None:
    lines: list[str] = []
    now = datetime.now(timezone.utc)

    mr_events = [e for e in events if e.source_type == "match_report"]

    _header(lines, ctx, now)
    _executive_summary(lines, ctx, findings)
    _operational_alerts(lines, ctx)
    _quick_brief(lines, ctx, findings, mr_events)

    # ── System ────────────────────────────────────────────────────────────────
    lines += ["---", "", "## System", ""]
    _system_context(lines, ctx)
    _system_performance(lines, ctx)
    _network_context(lines, ctx)
    _third_party_services(lines, ctx)
    _system_activity(lines, ctx)

    # ── SentinelOne Agent ─────────────────────────────────────────────────────
    lines += ["---", "", "## SentinelOne Agent", ""]
    _agent_health(lines, ctx)
    _console_comms(lines, ctx)

    # ── Security Analysis ─────────────────────────────────────────────────────
    lines += ["---", "", "## Security Analysis", ""]
    _process_profiles(lines, findings, events)
    _findings_section(lines, findings)
    _ioc_summary(lines, findings, events)
    _timeline_section(lines, events)
    _statistics(lines, ctx, findings, events)
    _threat_intel(lines, ctx)
    _blind_spots(lines, ctx)

    output_path.write_text("\n".join(lines), encoding="utf-8")


# ─── Section builders ────────────────────────────────────────────────────────

def _header(lines: list, ctx: SystemContext, now: datetime) -> None:
    dump_date = ctx.parse_stats.get("dump_date", "Unknown")
    lines += [
        "# SentinelOne macOS Log Analyzer — Analysis Report",
        "",
        "| Property | Value |",
        "|----------|-------|",
        f"| Machine | {ctx.hostname} ({ctx.model}) |",
        f"| OS | {ctx.os_version} — {ctx.arch} |",
        f"| User | `{ctx.primary_user}` |",
        f"| SentinelOne Agent | {ctx.agent_version} |",
        f"| Dump Date | {dump_date} |",
        f"| Analysis Date | {now.strftime('%Y-%m-%d %H:%M:%S UTC')} |",
        f"| Tool Version | SentinelOne macOS Log Analyzer {APP_VERSION} |",
        "",
        "---",
        "",
        "## How to Read This Report",
        "",
        "This report is generated from a SentinelOne log dump collected by `sentinelctl`. "
        "It is intended for L1/L2/L3 technical support engineers diagnosing agent health and macOS system state.",
        "",
        "**Two independent indicators**",
        "",
        "| Indicator | What it measures | Audience |",
        "|-----------|-----------------|----------|",
        "| 🟢🟡🔴 **Agent Health** | Operational state of the agent (daemons, asset signatures, DB, connectivity) | L1/L2 Support |",
        "| **Security Risk 0–100** | Weighted severity of security findings (MITRE-mapped detection rules) | L3/SOC |",
        "",
        "An agent can be 🔴 CRITICAL with Security Risk = 0 (broken agent, no threats detected) — "
        "for a support engineer, the Agent Health indicator is the primary signal.",
        "",
        "**Security Risk Score ranges**",
        "",
        "| Range | Level | Meaning |",
        "|-------|-------|---------|",
        "| 0 | MINIMAL | No significant findings |",
        "| 1–24 | LOW | Informational signals only |",
        "| 25–49 | MEDIUM | Suspicious activity, review recommended |",
        "| 50–74 | HIGH | Significant threat, investigate within 24h |",
        "| ≥ 75 | CRITICAL | Immediate response required |",
        "",
        "Score uses category confidence weights (attack chains count more than recon), "
        "diminishing returns for repeated findings, and context multipliers (SIP disabled, disconnected agent).",
        "",
        "**Severity Levels**",
        "",
        "| Level | Action |",
        "|-------|--------|",
        "| CRITICAL | Escalate immediately — active compromise or imminent risk |",
        "| HIGH | Investigate within 24h |",
        "| MEDIUM | Review in next maintenance window — may be early-stage attack |",
        "| LOW | Low-confidence signal, monitor |",
        "| INFO | Telemetry annotation, no threat impact |",
        "",
        "**L1/L2/L3 Guidance**",
        "",
        "- **L1:** Read Operational Alerts + Quick Brief. Escalate if CRITICAL/HIGH.",
        "- **L2:** Validate agent health, check Console Analysis and Processes. "
        "Correlate findings with Timeline.",
        "- **L3:** Deep-dive Findings, IOC, Threat Intel, and Blind Spots. "
        "Use Statistics for trend analysis. Cross-reference MITRE ATT&CK technique IDs.",
        "",
        "---",
        "",
    ]


_SEV_BASE = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}
_CAT_CONF = {
    "CHAIN": 1.00, "CRED": 0.90, "EVADE": 0.85, "EXFIL": 0.85,
    "PRIV": 0.75, "PERSIST": 0.70, "CONF": 0.55, "RECON": 0.45,
}
_CAT_CAP = {
    "CHAIN": 30, "CRED": 25, "EVADE": 20, "EXFIL": 20,
    "PRIV": 15, "PERSIST": 15, "CONF": 10, "RECON": 10,
}


def _risk_score(findings: list[Finding], ctx: SystemContext | None = None) -> tuple[int, str]:
    """Multi-criteria risk score: category confidence + diminishing returns + context."""
    cat_findings: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        cat = f.rule_id.split("-")[0].upper() if "-" in f.rule_id else "OTHER"
        cat_findings[cat].append(f)

    raw_total = 0.0
    for cat, cat_flist in cat_findings.items():
        conf = _CAT_CONF.get(cat, 0.60)
        cap  = _CAT_CAP.get(cat, 12)
        cat_flist_sorted = sorted(
            cat_flist, key=lambda f: _SEV_BASE.get(f.severity, 0), reverse=True
        )
        cat_score = 0.0
        for i, f in enumerate(cat_flist_sorted):
            decay = max(0.2, 1.0 - i * 0.25)
            cat_score += _SEV_BASE.get(f.severity, 0) * conf * decay
        raw_total += min(cat_score, cap)

    multiplier = 1.0
    bonus = 0.0
    if ctx is not None:
        if ctx.sip_enabled is False:
            multiplier += 0.15
        for section_data in (ctx.policy_config or {}).values():
            if isinstance(section_data, dict):
                if section_data.get("RemoteShell", "").strip() in ("1", "true", "yes", "enabled"):
                    bonus += 8.0
                    break
        mgmt = (ctx.sentinel_status or {}).get("Management", "")
        if isinstance(mgmt, str) and "disconnected" in mgmt.lower():
            bonus += 5.0

    score = min(100, round(raw_total * multiplier + bonus))
    if score >= 75:
        label = "CRITICAL"
    elif score >= 50:
        label = "HIGH"
    elif score >= 25:
        label = "MEDIUM"
    elif score > 0:
        label = "LOW"
    else:
        label = "MINIMAL"
    return score, label


def _agent_health_score_md(ctx: SystemContext) -> tuple[str, str, list[str]]:
    """
    Compute agent health level for Markdown report. Returns (level, color_unused, reasons).

    Mirrors _agent_health_score() in html_report.py — keep in sync.

    CRITICAL — core protection genuinely broken:
      sentineld not running, protection disabled in policy,
      core detection assets invalid, management explicitly disconnected.

    DEGRADED — running but coverage reduced:
      Lib Hooks / Lib Logs / Framework not ready, feature assets invalid,
      missing authorizations, state.wonky, SIP disabled, memory pressure,
      abnormal DB write volume.

    NOT flagged: sentineld_shell (on-demand), empty assets (normal).
    """
    critical: list[str] = []
    degraded: list[str] = []

    st = ctx.sentinel_status or {}
    daemons = st.get("daemons", {}) if st else {}
    integrity = daemons.get("integrity", {})
    services = daemons.get("services", {})

    # ── CRITICAL: sentineld not running ──────────────────────────────────────
    sentineld_running = any(
        "sentineld" == p.get("binary", "").lower().split("/")[-1]
        for p in (ctx.running_processes or [])
    )
    sentineld_integrity = integrity.get("sentineld", "").lower()
    if not sentineld_running and sentineld_integrity not in ("ok", "running", ""):
        critical.append(
            f"sentineld not running (integrity: {integrity.get('sentineld', 'absent')})"
        )
    elif sentineld_integrity and sentineld_integrity not in ("ok", "running", "not running"):
        critical.append(f"sentineld integrity check failed: {sentineld_integrity}")

    # ── CRITICAL: Protection subsystem explicitly disabled in policy ──────────
    pc = ctx.policy_config or {}
    if pc.get("General", {}).get("Protection", "") == "0":
        critical.append("Protection subsystem explicitly DISABLED in management policy")

    # ── CRITICAL: Core detection assets invalid ───────────────────────────────
    _CORE_ASSETS = frozenset({
        "signatures", "sha1", "sha256", "arbiter",
        "blacklist", "blacklistbase", "blacklistadd",
        "whitelist", "whitelistbase", "whitelistadd", "whitelistextended",
        "globaldata",
    })
    invalid_core = [
        a["name"] for a in (ctx.asset_signatures or [])
        if a.get("status", "").lower() == "invalid"
        and a["name"].lower() in _CORE_ASSETS
    ]
    invalid_feature = [
        a["name"] for a in (ctx.asset_signatures or [])
        if a.get("status", "").lower() == "invalid"
        and a["name"].lower() not in _CORE_ASSETS
    ]
    if invalid_core:
        critical.append(
            f"Core detection asset(s) invalid: {', '.join(invalid_core[:3])}"
            + (f" (+{len(invalid_core)-3} more)" if len(invalid_core) > 3 else "")
        )

    # ── CRITICAL: Management explicitly disconnected ──────────────────────────
    mgmt = st.get("management", {}) if st else {}
    mgmt_connected = str(mgmt.get("Connected", "")).strip().lower()
    if mgmt_connected in ("disconnected", "no", "false"):
        critical.append(
            "Agent disconnected from management console — "
            "local Static/Behavioral AI continues protecting the endpoint, "
            "but policy updates, STAR rules, threat intel sync, Remote Shell, "
            "and console visibility are unavailable"
        )

    # ── DEGRADED: sentineld_guard (watchdog) not running ─────────────────────
    sentineld_guard_running = any(
        "sentineld_guard" == p.get("binary", "").lower().split("/")[-1]
        for p in (ctx.running_processes or [])
    )
    guard_integrity = integrity.get("sentineld_guard", "").lower()
    if not sentineld_guard_running and guard_integrity not in ("ok", "running", ""):
        degraded.append(
            "sentineld_guard (watchdog) not running — "
            "agent not self-healing; killing sentineld would leave endpoint unprotected until reboot"
        )

    # ── DEGRADED: Coverage-reducing service states ────────────────────────────
    # NOTE: Lib Hooks Service and Lib Logs Service are no longer used by the
    # agent and will be removed in a future release — intentionally excluded.
    _COVERAGE_SERVICES = {
        "Framework":
            "ES Framework (Apple Endpoint Security) not ready — kernel-level visibility reduced",
        "Network Extension":
            "Deep Visibility network events blind, Firewall Control and Network Quarantine unavailable",
    }
    _ON_DEMAND_SERVICES = frozenset({
        "sentineld_shell",      # activates only during remote shell sessions
        "Lib Hooks Service",    # deprecated — no longer used by the agent
        "Lib Logs Service",     # deprecated — no longer used by the agent
    })

    for svc_name, svc_desc in _COVERAGE_SERVICES.items():
        svc_state = services.get(svc_name, "").lower()
        if svc_state in ("not ready", "not running"):
            degraded.append(f"{svc_name} not ready — {svc_desc}")
        int_state = integrity.get(svc_name, "").lower()
        if int_state and int_state not in ("ok", "running", "not running") and svc_name not in services:
            degraded.append(f"{svc_name} integrity: {int_state}")

    # ── DEGRADED: Feature asset signatures invalid ────────────────────────────
    if invalid_feature:
        degraded.append(
            f"Feature asset(s) with invalid signature: {', '.join(invalid_feature[:3])}"
            + (f" (+{len(invalid_feature)-3} more)" if len(invalid_feature) > 3 else "")
            + " (affects specific features, not core protection)"
        )

    # ── DEGRADED: Missing authorizations ─────────────────────────────────────
    if st.get("missing_authorizations"):
        degraded.append(
            "Missing system authorizations — grant Full Disk Access in System Settings"
        )

    # ── DEGRADED: DB integrity ────────────────────────────────────────────────
    if (ctx.sentinel_db_health or {}).get("has_wonky"):
        degraded.append("state.wonky DB recovery file present — agent DB was not cleanly closed")

    # ── DEGRADED: System conditions affecting agent stability ─────────────────
    if ctx.sip_enabled is False:
        degraded.append("SIP disabled — reduces OS-level tamper protection for the agent")

    pressure = (ctx.vm_memory or {}).get("pressure_level", "")
    if pressure in ("CRITICAL", "WARNING"):
        degraded.append(f"Memory pressure: {pressure} — may cause agent instability")

    db_write = (ctx.sentinel_db_health or {}).get("db_write_gib", 0)
    if db_write > 10:
        degraded.append(
            f"Abnormal DB write volume: {db_write:.1f} GiB — "
            "may indicate scan runaway or log flooding"
        )

    if critical:
        return "CRITICAL", "#dc2626", critical + degraded
    if degraded:
        return "DEGRADED", "#d97706", degraded
    return "HEALTHY", "#16a34a", ["sentineld running · all core services ready · assets valid · console connected"]


def _executive_summary(lines: list, ctx: SystemContext, findings: list[Finding]) -> None:
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    score, label = _risk_score(findings, ctx)
    health_level, health_col, health_reasons = _agent_health_score_md(ctx)

    lines += [
        "## Executive Summary",
        "",
        "*Source: All detection rules applied to match_reports, process data, configuration files, and system state. "
        "Each finding maps to a MITRE ATT&CK technique and includes evidence events. "
        "CRITICAL: active compromise or immediate risk — response required. "
        "HIGH: investigate within 24h. MEDIUM: suspicious activity to review. "
        "LOW/INFO: weak signals or contextual observations. "
        "A large MEDIUM count with zero HIGH/CRITICAL may indicate normal operational noise.*",
        "",
    ]

    _HEALTH_ICON_MD = {"CRITICAL": "🔴", "DEGRADED": "🟡", "HEALTHY": "🟢"}
    health_icon = _HEALTH_ICON_MD.get(health_level, "⚪")

    lines += [
        "| Indicator | Value |",
        "|-----------|-------|",
        f"| Agent Health | {health_icon} **{health_level}** |",
        f"| Security Risk | **{score}/100 — {label}** |",
        "",
    ]
    if health_reasons and health_level != "HEALTHY":
        lines += [f"> **Agent Health issues:** {' · '.join(health_reasons[:4])}", ""]

    if not findings:
        lines += ["> No findings detected with the current filter settings.", ""]
    else:
        lines += [
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = by_sev.get(sev, 0)
            if count:
                lines.append(f"| {SEVERITY_ICON.get(sev, '')} **{sev}** | {count} |")

        lines.append("")
        top = [f for f in findings if f.severity in ("CRITICAL", "HIGH")][:5]
        if top:
            lines += ["**Immediate action items:**", ""]
            for f in top:
                first = f.first_seen.strftime("%Y-%m-%d %H:%M") if f.first_seen else "-"
                lines.append(f"- `[{f.rule_id}]` **{f.rule_name}** — `{f.process}` ({first})")

    lines += ["", "---", ""]


def _quick_brief(
    lines: list,
    ctx: SystemContext,
    findings: list[Finding],
    mr_events: list[Event],
) -> None:
    """Analyst Quick Brief: risk factors, action items, correlations."""
    agent    = ctx.sentinel_status.get("agent", {})
    degraded = ctx.sentinel_status.get("degraded_services", [])
    by_sev: dict[str, int] = defaultdict(int)
    for f in findings:
        by_sev[f.severity] += 1

    lines += [
        "## Analyst Quick Brief",
        "",
        "*Auto-generated summary computed from all dump sources. "
        "Risk factors ranked by priority (P0 = immediate critical), "
        "recommended actions listed by urgency, cross-source correlations identified automatically.*",
        "",
    ]

    # ── Risk factors ────────────────────────────────────────────────────────
    lines += ["### Key Risk Factors", ""]
    risks: list[str] = []

    if ctx.sip_enabled is False:
        risks.append("**[P0 CRITICAL] SIP Disabled** — System Integrity Protection is OFF. "
                     "macOS cannot protect core system files from modification.")

    agent_state = agent.get("Agent Operational State", "")
    if agent_state and agent_state.lower() not in ("enabled", "active", "running"):
        risks.append(f"**[P0 CRITICAL] Agent Not Operational** — "
                     f"SentinelOne agent state: `{agent_state}`. "
                     "Real-time threat detection may be inactive.")

    if ctx.sentinel_status.get("missing_authorizations"):
        risks.append("**[P0 HIGH] Missing System Authorizations** — "
                     "The agent lacks critical macOS permissions (Full Disk Access or Accessibility). "
                     "Some detection categories are blind.")

    n_crit = by_sev.get("CRITICAL", 0)
    if n_crit:
        procs = list(dict.fromkeys(
            f.process for f in findings if f.severity == "CRITICAL" and f.process
        ))[:3]
        risks.append(f"**[P0 CRITICAL] {n_crit} Critical Finding(s)** — "
                     f"Critical detections for: {', '.join(f'`{p}`' for p in procs)}.")

    if degraded:
        risks.append(f"**[P1 HIGH] {len(degraded)} Degraded S1 Service(s)** — "
                     f"{', '.join(f'`{s}`' for s in degraded[:4])} not running.")

    n_high = by_sev.get("HIGH", 0)
    if n_high:
        procs = list(dict.fromkeys(
            f.process for f in findings if f.severity == "HIGH" and f.process
        ))[:3]
        risks.append(f"**[P1 HIGH] {n_high} High Severity Finding(s)** — "
                     f"High-severity detections involving: {', '.join(f'`{p}`' for p in procs)}.")

    if ctx.sentinelctl_error:
        risks.append(f"**[P2 MEDIUM] macOS Log Archive Unavailable** — "
                     f"`{ctx.sentinelctl_error[:120]}` — "
                     "The macOS unified log archive could not be opened during dump collection. "
                     "SentinelOne detection events (match_reports) are unaffected.")

    dual_av = [a for a in ctx.installed_apps
               if any(kw in a.lower() for kw in _DUAL_AV_NAMES)]
    if dual_av:
        risks.append(f"**[P2 MEDIUM] Multiple Security Products Detected** — "
                     f"Third-party AV found alongside SentinelOne: "
                     f"{', '.join(f'`{a}`' for a in dual_av[:3])}. "
                     "Dual-AV configurations can cause Endpoint Security Framework conflicts.")

    dv_flags = ctx.agent_config.get("dv_collect_flags", {})
    if dv_flags and not any(dv_flags.values()):
        risks.append("**[P2 MEDIUM] Deep Visibility Collection Fully Disabled** — "
                     "All Deep Visibility collection flags are OFF. "
                     "Behavioral telemetry is not being forwarded to the management console.")

    kexts_3p = [k for k in ctx.kernel_extensions
                if not any(k.startswith(p) for p in ("com.apple", "com.sentinelone"))]
    if kexts_3p:
        risks.append(f"**[P3 LOW] {len(kexts_3p)} Third-Party Kernel Extension(s)** — "
                     f"Loaded: {', '.join(f'`{k}`' for k in kexts_3p[:3])}. "
                     "Kernel extensions run in ring 0 and represent elevated attack surface.")

    if ctx.path_exclusions:
        risks.append(f"**[P3 LOW] {len(ctx.path_exclusions)} Monitoring Exclusion(s) Active** — "
                     "These locations are NOT monitored for threats and could be used as safe harbors.")

    if risks:
        for r in risks:
            lines.append(f"- {r}")
    else:
        lines.append("*No risk factors identified.*")
    lines.append("")

    # ── Action items ────────────────────────────────────────────────────────
    lines += ["### Recommended Actions", ""]
    actions: list[str] = []

    if ctx.sip_enabled is False:
        actions.append("Re-enable SIP: boot into macOS Recovery and run `csrutil enable`. "
                       "If SIP must remain disabled, document and escalate the justification.")

    if agent_state and agent_state.lower() not in ("enabled", "active", "running"):
        actions.append(f"Investigate why the agent is in state **{agent_state}**. "
                       "Check the management console for endpoint alerts and restart the agent.")

    if ctx.sentinel_status.get("missing_authorizations"):
        actions.append("Grant SentinelOne Full Disk Access: **System Settings → Privacy & Security "
                       "→ Full Disk Access**. A reboot may be required.")

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    top_findings = sorted(
        [f for f in findings if f.severity in sev_order],
        key=lambda f: (sev_order[f.severity], -(f.first_seen.timestamp() if f.first_seen else 0)),
    )
    seen_procs: set[str] = set()
    for f in top_findings:
        if len(actions) >= 8:
            break
        proc_key = f.process or f.rule_name
        if proc_key in seen_procs:
            continue
        seen_procs.add(proc_key)
        rec = f.recommendation or f.description[:100]
        actions.append(f"Investigate `{proc_key}`: **{f.rule_name}** — {rec}")

    if degraded:
        actions.append(f"Restart degraded services from the management console or endpoint: "
                       f"{', '.join(f'`{s}`' for s in degraded[:3])}.")
    if dual_av:
        actions.append(f"Review whether `{dual_av[0]}` is compatible with SentinelOne. "
                       "Consult the compatibility matrix and consider removing conflicting AV.")
    if ctx.path_exclusions:
        actions.append(f"Audit {len(ctx.path_exclusions)} path exclusion(s) — verify each is still "
                       "required and that no suspicious process paths fall within excluded locations.")
    if ctx.sentinelctl_error:
        actions.append("The macOS unified log archive was unavailable during dump collection — "
                       "this is expected and does not affect SentinelOne detection data. "
                       "To collect system logs, use `log collect` on the live endpoint.")

    if actions:
        for i, a in enumerate(actions, 1):
            lines.append(f"{i}. {a}")
    else:
        lines.append("*No immediate actions required.*")
    lines.append("")

    # ── Correlations ────────────────────────────────────────────────────────
    correlations: list[str] = []

    # 1. Crash + behavioral finding same day
    crash_day: dict[tuple, int] = defaultdict(int)
    for e in mr_events:
        if e.source_type == "crash" and e.process_name and e.timestamp:
            crash_day[(e.process_name.lower(), e.timestamp.date())] += 1
    for f in findings:
        if not f.first_seen or not f.process:
            continue
        proc_base = f.process.lower().split("/")[-1]
        for (crash_proc, crash_date), _ in crash_day.items():
            crash_base = crash_proc.split("/")[-1]
            if (proc_base in crash_base or crash_base in proc_base) and crash_date == f.first_seen.date():
                correlations.append(
                    f"**{f.process.split('/')[-1]}** crashed on `{crash_date}` and triggered "
                    f"a behavioral detection (**{f.rule_name}**) the same day — "
                    "may indicate instability caused by malicious activity."
                )
                break

    # 2. Single process spanning 3+ rule categories (multi-stage pattern)
    proc_cats: dict[str, set[str]] = defaultdict(set)
    proc_fmap: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.process:
            cat = f.rule_id.split("-")[0].upper() if "-" in f.rule_id else f.rule_id[:6].upper()
            proc_cats[f.process].add(cat)
            proc_fmap[f.process].append(f)
    for proc, cats in proc_cats.items():
        if len(cats) >= 3:
            worst = min(
                proc_fmap[proc],
                key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f.severity, 5),
            ).severity
            correlations.append(
                f"**{proc.split('/')[-1]}** triggered detections across "
                f"**{len(cats)} rule categories** ({', '.join(sorted(cats))}) — "
                f"multi-stage attack pattern. Max severity: {worst}."
            )

    # 3. Single-day burst: 5+ findings from same process on one day
    proc_day_count: dict[tuple, int] = defaultdict(int)
    for f in findings:
        if f.first_seen and f.process:
            proc_day_count[(f.process, f.first_seen.date())] += 1
    for (proc, day), count in proc_day_count.items():
        if count >= 5:
            correlations.append(
                f"**{proc.split('/')[-1]}** generated **{count} detections on {day}** — "
                "high-density single-day activity may indicate automated execution or a rapid attack sequence."
            )

    # Deduplicate
    seen_corr: set[str] = set()
    unique_corr: list[str] = []
    for c in correlations:
        key = re.sub(r'\*\*|`', '', c)[:60]
        if key not in seen_corr:
            seen_corr.add(key)
            unique_corr.append(c)

    if unique_corr:
        lines += ["### Detected Correlations", ""]
        for c in unique_corr[:8]:
            lines.append(f"- {c}")
        lines.append("")

    # ── Data reliability warnings ────────────────────────────────────────────
    reliability: list[str] = []
    if ctx.sentinelctl_error:
        reliability.append(f"macOS log archive unavailable: `{ctx.sentinelctl_error[:100]}`. "
                           "SentinelOne detection events (match_reports) are unaffected — "
                           "only macOS system log context is missing.")
    if not mr_events:
        reliability.append("No match_reports events parsed — behavioral detection data unavailable.")
    if not ctx.sentinel_status:
        reliability.append("sentinelctl-status.txt could not be parsed — agent health unknown.")
    if reliability:
        lines += ["### Data Reliability Warnings", ""]
        for r in reliability:
            lines.append(f"> ⚠️ {r}")
        lines.append("")

    lines += ["---", ""]


def _system_context(lines: list, ctx: SystemContext) -> None:
    sip_status = (
        "Enabled" if ctx.sip_enabled
        else ("**DISABLED**" if ctx.sip_enabled is False else "Unknown")
    )
    lines += [
        "## System Context",
        "",
        "*System profile extracted from the dump: OS, hardware, primary user, installed applications, "
        "kernel extensions and mounted volumes. "
        "Baseline context to assess the attack surface and correlate detections with the actual environment.*",
        "",
        "| Property | Value |",
        "|----------|-------|",
        f"| Hostname | `{ctx.hostname}` |",
        f"| Serial Number | `{ctx.serial_number}` |" if ctx.serial_number else "| Serial Number | Not found |",
        f"| Model | {ctx.model} |",
        f"| OS | {ctx.os_version} |",
        f"| Architecture | {ctx.arch} |",
        f"| CPU | {ctx.cpu_count} core(s) |",
        f"| SIP | {sip_status} |",
        f"| Boot Args | `{ctx.boot_args or '(none)'}` |",
        f"| Sleep Blocked By | {', '.join(f'`{s}`' for s in (ctx.power_state or {}).get('sleep_preventing', [])) or 'None'} |",
        f"| Agent UUID | `{ctx.agent_uuid or 'Not found'}` |",
        f"| Console | {ctx.console_url or 'Not found'} |",
        f"| Agent Version | {ctx.agent_version} |",
        "",
    ]

    if ctx.installed_apps:
        lines += [
            f"**Installed Applications ({len(ctx.installed_apps)}):**",
            "",
            ", ".join(f"`{a}`" for a in sorted(ctx.installed_apps)),
            "",
        ]

    if ctx.launch_daemons:
        lines += [f"**Active LaunchDaemons ({len(ctx.launch_daemons)}):**", ""]
        for d in ctx.launch_daemons[:15]:
            lines.append(f"- `{d}`")
        if len(ctx.launch_daemons) > 15:
            lines.append(f"- *(+ {len(ctx.launch_daemons) - 15} more)*")
        lines.append("")

    if ctx.ui_agent_states:
        lines += ["**Agent Functional States:**", ""]
        for state in ctx.ui_agent_states:
            lines.append(f"- `{state}`")
        lines.append("")

    # Third-party kexts (runtime state from kextstat.txt)
    if ctx.third_party_kexts:
        lines += [
            f"### Third-Party Kernel Extensions — Runtime ({len(ctx.third_party_kexts)})",
            "",
            "| Bundle ID | Version | UUID |",
            "|-----------|---------|------|",
        ]
        for k in ctx.third_party_kexts:
            lines.append(f"| `{k['name']}` | `{k['version']}` | `{k['uuid']}` |")
        lines.append("")

    # Mounted volumes
    if ctx.mounted_volumes:
        lines += [
            f"### Mounted Volumes ({len(ctx.mounted_volumes)})",
            "",
            "| Device | Mount Point | Type | Options |",
            "|--------|-------------|------|---------|",
        ]
        for v in ctx.mounted_volumes:
            opts = ", ".join(v.get("options", []))
            lines.append(
                f"| `{v['device']}` | `{v['mountpoint']}` | {v['fstype']} | {opts} |"
            )
        lines.append("")

    # Security package versions
    if ctx.security_packages:
        lines += ["### Security Package Versions", ""]
        for kw, label in [("XProtect", "XProtect"), ("Gatekeeper", "Gatekeeper"), ("MRT", "MRT")]:
            matched = sorted({p for p in ctx.security_packages if kw in p}, reverse=True)[:2]
            if matched:
                versions = [p.rsplit(".", 1)[-1] for p in matched]
                lines.append(f"- **{label}:** {', '.join(f'`{v}`' for v in versions)}")
        lines.append("")

    # Running processes snapshot
    if ctx.running_processes:
        procs = ctx.running_processes
        lines += [
            f"### Running Processes at Dump Time — {len(procs)} total",
            "",
            "**Top 15 by CPU:**",
            "",
            "| PID | Process | User | CPU% | MEM% |",
            "|-----|---------|------|------|------|",
        ]
        for p in procs[:15]:
            lines.append(
                f"| {p['pid']} | `{p['binary'][:40]}` | {p['user']} | {p['cpu']}% | {p['mem']}% |"
            )
        s1 = [p for p in procs if "sentinel" in p["binary"].lower()
              or "sentinel" in p["command"].lower()[:40]]
        if s1:
            lines += ["", "**SentinelOne Processes:**", ""]
            for p in s1:
                lines.append(f"- `{p['binary']}` (PID {p['pid']}) — CPU {p['cpu']}% MEM {p['mem']}%")
        lines.append("")

    lines += ["---", ""]


def _agent_health(lines: list, ctx: SystemContext) -> None:
    """Detailed SentinelOne agent health section from sentinelctl-status.txt."""
    st = ctx.sentinel_status
    has_any = bool(st or ctx.daemon_states or ctx.asset_signatures)
    if not has_any:
        return

    lines += [
        "## SentinelOne Agent Health",
        "",
        "*Source: sentinelctl-status.txt, sentinelctl-policies.txt, sentinelctl-config_policy.txt, "
        "sentinelctl-scan-info.txt, sentinelctl-stats.txt. "
        "Key checks: (1) Agent Operational State must be 'enabled'. "
        "(2) Daemon States — not-ready daemons reduce coverage. "
        "'Lib Hooks Service' and 'Lib Logs Service' not-ready = missing Full Disk Access. "
        "(3) Asset Signatures — INVALID = corrupted/tampered asset files. "
        "(4) Detection Policies — DISABLED policies with active findings = critical gap. "
        "(5) DB write GiB > 10 = abnormal scan activity.*",
        "",
    ]

    if st:
        agent = st.get("agent", {})
        mgmt = st.get("management", {})
        degraded = st.get("degraded_services", [])
        missing_auth = st.get("missing_authorizations", False)

        lines += [
            "| Property | Value |",
            "|----------|-------|",
        ]
        for key in ("Version", "ID", "Install Date", "Agent Operational State",
                    "Protection", "Ready", "Infected", "Network Quarantine",
                    "Compatible OS", "ES Framework", "Agent Network Monitoring",
                    "Network Extension"):
            val = agent.get(key, "")
            if val:
                lines.append(f"| {key} | `{val}` |")
        if mgmt.get("Server"):
            lines.append(f"| Management Server | `{mgmt['Server']}` |")
        if mgmt.get("Connected"):
            lines.append(f"| Connected | `{mgmt['Connected']}` |")
        if mgmt.get("Last Seen"):
            lines.append(f"| Last Seen | `{mgmt['Last Seen']}` |")
        lines.append("")

        if missing_auth:
            lines += [
                "> **ALERT: Missing Authorizations** — The agent is missing critical system permissions. "
                "Some detections may be blind.",
                "",
            ]

        daemons = st.get("daemons", {})
        services = daemons.get("services", {})
        integrity = daemons.get("integrity", {})

        if services or integrity:
            lines += ["### Internal Services", ""]
            if services:
                lines += [
                    "| Service | State |",
                    "|---------|-------|",
                ]
                for svc, state in sorted(services.items()):
                    flag = " ⚠️" if state.lower() in ("not ready", "not running") else ""
                    lines.append(f"| {svc} | `{state}`{flag} |")
                lines.append("")
            if integrity:
                lines += [
                    "| Process | Integrity |",
                    "|---------|-----------|",
                ]
                for proc, state in sorted(integrity.items()):
                    flag = " ⚠️" if state.lower() != "ok" else ""
                    lines.append(f"| `{proc}` | `{state}`{flag} |")
                lines.append("")

        if degraded:
            lines += [
                f"> **{len(degraded)} degraded service(s):** "
                + ", ".join(f"`{s}`" for s in degraded),
                "",
            ]

    # Detection policies
    if ctx.detection_policies:
        from collections import Counter
        action_counts = Counter(p["action"] for p in ctx.detection_policies)
        lines += [
            f"### Detection Policy Coverage ({len(ctx.detection_policies)} rules)",
            "",
            "| Action | Count |",
            "|--------|-------|",
        ]
        for action, count in sorted(action_counts.items()):
            flag = " ⚠️" if action == "disabled" else ""
            lines.append(f"| {action.upper()}{flag} | {count} |")
        lines.append("")

    # Operational stats
    ops = ctx.sentinel_operational
    if ops:
        lines += ["### Operational Statistics", ""]
        if ops.get("scan_info_raw"):
            lines.append(f"**Last Disk Scan:** {ops['scan_info_raw'][:120]}")
            lines.append("")
        if ops.get("db_stats_start") or ops.get("db_bytes_read"):
            lines += [
                "| Metric | Value |",
                "|--------|-------|",
            ]
            if ops.get("db_stats_start"):
                lines.append(f"| DB Stats Since | {ops['db_stats_start']} |")
            if ops.get("db_bytes_read"):
                lines.append(f"| DB Bytes Read | `{ops['db_bytes_read']}` |")
            if ops.get("db_bytes_written"):
                lines.append(f"| DB Bytes Written | `{ops['db_bytes_written']}` |")
            lines.append("")

    # Management policy configuration
    pc = ctx.policy_config
    if pc:
        lines += ["### Management Policy", ""]
        prot = pc.get("General", {}).get("Protection", "?")
        lines.append(f"**Protection subsystem:** {'Active' if prot == '1' else 'INACTIVE'}")
        lines.append("")

        _FEATURES = [
            ("DeepVisibility", "Deep Visibility"),
            ("Firewall", "Firewall"),
            ("Ranger", "Ranger Discovery"),
            ("DeviceControl", "Device Control"),
            ("LogCollection", "Log Collection"),
            ("Location", "Location Tracking"),
            ("RemoteShell", "Remote Shell"),
            ("RemoteScriptOrchestration", "Remote Script Exec"),
        ]
        lines += ["| Feature | Status |", "|---------|--------|"]
        for key, label in _FEATURES:
            enabled = pc.get(key, {}).get("Enabled", "?")
            status = "Enabled" if enabled == "1" else ("Disabled" if enabled == "0" else "?")
            flag = " ⚠️" if key == "RemoteShell" and enabled == "1" else ""
            lines.append(f"| {label} | {status}{flag} |")
        lines.append("")

        auto_resp = pc.get("Remediation", {}).get("AutomaticResponses", [])
        if auto_resp:
            lines.append(f"**Auto-remediation:** {', '.join(f'`{a}`' for a in auto_resp)}")
            lines.append("")

        dv = pc.get("DeepVisibility", {})
        dv_events = {k: v for k, v in dv.items() if k.startswith("Collect")}
        if dv_events:
            on_count = sum(1 for v in dv_events.values() if v != "0")
            off_events = [k[7:] for k, v in dv_events.items() if v == "0"]
            lines.append(
                f"**Deep Visibility collection:** {on_count}/{len(dv_events)} event types active"
            )
            if off_events:
                lines.append(f"Not collected: {', '.join(off_events[:10])}"
                             + (f" (+{len(off_events)-10} more)" if len(off_events) > 10 else ""))
            lines.append("")

        ext_url = pc.get("ExternalServices", {}).get("LogCollectionServiceURL", "")
        if ext_url:
            lines.append(f"**Log Ingestion URL:** `{ext_url}`")
            lines.append("")

    # Daemon states
    if ctx.daemon_states:
        not_ready = [d for d in ctx.daemon_states if not d.get("ready", True)]
        lines += [f"### Daemon States ({len(ctx.daemon_states)} daemons)", ""]
        if not_ready:
            names = ", ".join(f"`{d['name']}`" for d in not_ready[:4])
            extra = f" (+{len(not_ready)-4} more)" if len(not_ready) > 4 else ""
            lines += [
                f"> ⚠️ **{len(not_ready)} daemon(s) not ready:** {names}{extra} "
                "— may indicate missing Full Disk Access.",
                "",
            ]
        lines += ["| Daemon | Status |", "|--------|--------|"]
        for d in sorted(ctx.daemon_states, key=lambda x: (x.get("ready", True), x["name"])):
            flag = "✓ Ready" if d.get("ready") else "✗ Not Ready"
            mark = " ⚠️" if not d.get("ready") else ""
            lines.append(f"| `{d['name']}` | {flag}{mark} |")
        lines.append("")

    # Asset signatures
    if ctx.asset_signatures:
        invalids = [a for a in ctx.asset_signatures if a.get("status", "").lower() in ("invalid", "empty")]
        lines += [f"### Asset Signatures ({len(ctx.asset_signatures)} assets)", ""]
        if invalids:
            names = ", ".join(f"`{a['name']}`" for a in invalids[:3])
            extra = f" (+{len(invalids)-3} more)" if len(invalids) > 3 else ""
            lines += [
                f"> 🚨 **{len(invalids)} invalid/empty asset signature(s):** {names}{extra} "
                "— corrupted or tampered asset files.",
                "",
            ]
        lines += ["| Asset | Signature |", "|-------|-----------|"]
        for a in sorted(ctx.asset_signatures, key=lambda x: (
            0 if x.get("status", "").lower() == "invalid" else
            1 if x.get("status", "").lower() == "empty" else 2, x["name"]
        )):
            flag = " ⚠️" if a.get("status", "").lower() in ("invalid", "empty") else ""
            lines.append(f"| `{a['name']}` | `{a.get('status','').upper()}`{flag} |")
        lines.append("")

    lines += ["---", ""]


def _console_comms(lines: list, ctx: SystemContext) -> None:
    """Console communication analysis: connectivity, intervals, telemetry timeline, ATS."""
    mgmt = ctx.sentinel_status.get("management", {})
    has_data = bool(mgmt or ctx.comm_intervals or ctx.mr_daily_counts or ctx.agent_log)
    if not has_data:
        return

    lines += [
        "## Console Communication Analysis",
        "",
        "*Analysis of the agent ↔ console link: connection status, telemetry send frequencies, "
        "and match_reports timeline (reports per day). "
        "A telemetry gap (≥ 3 consecutive days with no reports) may indicate a connectivity issue "
        "or a bypass attempt.*",
        "",
    ]

    # ── Connectivity ──────────────────────────────────────────────────────────
    if mgmt:
        lines += ["### Connectivity", "", "| Property | Value |", "|----------|-------|"]
        if mgmt.get("Server"):
            lines.append(f"| Management Server | `{mgmt['Server']}` |")
        connected = mgmt.get("Connected", "")
        if connected:
            flag = "" if connected.lower() == "yes" else " ⚠️"
            lines.append(f"| Connected | `{connected}`{flag} |")
        if mgmt.get("Last Seen"):
            lines.append(f"| Last Heartbeat | `{mgmt['Last Seen']}` |")
        site_key = mgmt.get("Site Key") or ctx.sentinel_status.get("agent", {}).get("Site Key", "")
        if site_key and len(site_key) > 8:
            masked = site_key[:4] + "****" + site_key[-4:]
            lines.append(f"| Site Key | `{masked}` |")
        dv_server = ctx.agent_config.get("dvServer") or ctx.agent_config.get("dv_server", "")
        if dv_server:
            lines.append(f"| Deep Visibility Server | `{dv_server}` |")
        lines.append("")

    # ── Agent log summary ─────────────────────────────────────────────────────
    al = ctx.agent_log
    if al:
        total  = al.get("total_lines", 0)
        errors = al.get("error_count", 0)
        err_pct = f"{100*errors//total}%" if total else "—"
        period_s = al.get("log_period_start", "")[:19]
        period_e = al.get("log_period_end",   "")[:19]
        lvl = al.get("level_counts", {})
        lines += [
            "### Agent Log — sentinelctl-log.txt",
            "",
            f"| Property | Value |",
            f"|----------|-------|",
            f"| Period | `{period_s}` → `{period_e}` |",
            f"| Total lines | {total:,} |",
            f"| Info (I) | {lvl.get('I', 0):,} |",
            f"| Debug (Df) | {lvl.get('Df', 0):,} |",
            f"| Errors (E) | {errors:,} ({err_pct}) |",
        ]
        # Proxy
        proxy = ctx.proxy_config
        if proxy:
            if proxy.get("has_proxy"):
                lines.append(f"| Proxy | `{proxy['proxy_server']}` |")
            else:
                excl = ", ".join(proxy.get("exceptions", []))
                lines.append(f"| Proxy | Direct internet (exceptions: {excl or 'none'}) |")
        lines.append("")

        # RCP requests
        rcp_counts = al.get("rcp_type_counts", {})
        if rcp_counts:
            rcp_reqs = al.get("rcp_requests", [])
            lines += ["**Console → Agent RCP Requests** *(Remote Control Protocol)*", "", "| Request Type | Count | Last Seen |", "|---|---|---|"]
            for rtype, cnt in sorted(rcp_counts.items(), key=lambda x: -x[1]):
                last = next((r["timestamp"][:19] for r in reversed(rcp_reqs) if r["req_type"] == rtype), "—")
                lines.append(f"| `{rtype}` | {cnt:,} | `{last}` |")
            lines.append("")

        # Keep-alive
        ka_count = al.get("keep_alive_count", 0)
        ka_recent = al.get("keep_alive_recent", [])
        if ka_count:
            last_ka = ka_recent[-1][:19] if ka_recent else "—"
            lines += [f"**Keep-alive events:** {ka_count:,} total — last at `{last_ka}`", ""]

        # Error breakdown
        err_comps = al.get("error_by_component", {})
        if err_comps:
            lines += ["**Agent Errors by Component:**", "", "| Component | Errors |", "|-----------|--------|"]
            for comp, cnt in list(err_comps.items())[:6]:
                lines.append(f"| `{comp}` | {cnt:,} |")
            lines.append("")
            # Unique asserts
            asserts = al.get("unique_asserts", {})
            if asserts:
                lines += ["*Recurring ASSERT messages:*", ""]
                for msg, cnt in list(asserts.items())[:3]:
                    lines.append(f"- × {cnt:,} — `{msg[:100]}`")
                lines.append("")

        # Asset updates
        assets = al.get("asset_updates", [])
        if assets:
            lines += ["**Detection Asset Updates:**", "", "| Asset | Version | Loaded At |", "|-------|---------|-----------|"]
            for a in assets:
                lines.append(f"| `{a['name']}` | `{a['version'][:40]}` | {a['timestamp'][:19]} |")
            lines.append("")

        # Dynamic detection matches
        tech_counts = al.get("technique_counts", {})
        det_total = al.get("detection_total", 0)
        if det_total:
            lines += [
                f"**Dynamic Detection Matches — {det_total:,} events** "
                f"*(behavioral MITRE-mapped detections fired by the agent)*",
                "",
                "| Technique | Count |",
                "|-----------|-------|",
            ]
            for tech, cnt in list(tech_counts.items())[:20]:
                lines.append(f"| `{tech}` | {cnt:,} |")
            lines.append("")
            det_sample = al.get("detection_matches", [])[:20]
            if det_sample:
                lines += ["*Recent detection samples:*", "", "| Timestamp | Technique | Primary Path |", "|-----------|-----------|--------------|"]
                for dm in det_sample:
                    path_val = dm["primary_path"] or dm["origin_path"]
                    lines.append(f"| `{dm['timestamp'][:19]}` | `{dm['technique']}` | `{path_val[:80]}` |")
                lines.append("")

        # Integrity protection blocks
        inv_counts = al.get("invoker_counts", {})
        int_total  = al.get("integrity_total", 0)
        if int_total:
            lines += [
                f"**Integrity Protection Blocks — {int_total:,} events** "
                f"*(processes denied access to SentinelOne agent)*",
                "",
                "| Invoking Process | Blocks |",
                "|-----------------|--------|",
            ]
            for inv, cnt in list(inv_counts.items())[:15]:
                lines.append(f"| `{inv[:80]}` | {cnt:,} |")
            lines.append("")

        # Device control
        dc_events = al.get("device_control_events", [])
        if dc_events:
            latest_dc = dc_events[-1]
            lines += [
                "**Device Control Policy** *(latest observed state)*",
                "",
                "| Interface | State |",
                "|-----------|-------|",
                f"| USB | {latest_dc['usb']} |",
                f"| Thunderbolt | {latest_dc['thunderbolt']} |",
                f"| Bluetooth | {latest_dc['bluetooth']} |",
                f"| Bluetooth Low Energy | {latest_dc['ble']} |",
                f"",
                f"*Last status at `{latest_dc['timestamp'][:19]}` "
                f"({len(dc_events)} status events in log period).*",
                "",
            ]

        # Mount events
        m_events = al.get("mount_events", [])
        if m_events:
            allowed_m = sum(1 for e in m_events if e["allowed"])
            denied_m  = len(m_events) - allowed_m
            lines += [
                f"**Mount Requests — {len(m_events)} events** "
                f"({allowed_m} allowed, {denied_m} denied)",
                "",
                "| Timestamp | Device | Decision |",
                "|-----------|--------|----------|",
            ]
            for me in m_events[:20]:
                dec = "Allow" if me["allowed"] else "Deny"
                lines.append(f"| `{me['timestamp'][:19]}` | `{me['device']}` | {dec} |")
            if len(m_events) > 20:
                lines.append(f"*…and {len(m_events)-20} more events.*")
            lines.append("")

        # CPU high-water marks
        c_events = al.get("cpu_events", [])
        if c_events:
            exceeds_c = sum(1 for e in c_events if e["exceeds"])
            lines += [
                f"**CPU High-Water Mark Events — {len(c_events)} events** "
                f"({exceeds_c} threshold exceeded)",
                "",
                "| Timestamp | Process | CPU% | Threshold | Direction |",
                "|-----------|---------|------|-----------|-----------|",
            ]
            for ce in c_events[:20]:
                direction = "▲ Exceeded" if ce["exceeds"] else "▼ Recovered"
                lines.append(f"| `{ce['timestamp'][:19]}` | `{ce['process'][:60]}` | {ce['value']} | {ce['threshold']} | {direction} |")
            if len(c_events) > 20:
                lines.append(f"*…and {len(c_events)-20} more events.*")
            lines.append("")

    # ── Communication intervals ───────────────────────────────────────────────
    if ctx.comm_intervals:
        def _fmt_sec(s: object) -> str:
            try:
                n = int(s)
            except (TypeError, ValueError):
                return str(s)
            if n < 60:
                return f"{n}s"
            if n < 3600:
                return f"{n // 60}min {n % 60}s" if n % 60 else f"{n // 60}min"
            h = n // 3600
            m = (n % 3600) // 60
            return f"{h}h {m}min" if m else f"{h}h"

        label_map = {
            "batch_send_sec":        "Batch Event Send",
            "send_events_sec":       "Event Send",
            "update_interval_sec":   "Policy Update Check",
            "connectivity_check_sec":"Connectivity Check",
            "send_metrics_sec":      "Metrics Send",
            "state_update_sec":      "State Update",
        }
        lines += [
            "### Communication Intervals",
            "",
            "| Setting | Interval |",
            "|---------|----------|",
        ]
        for key, label in label_map.items():
            val = ctx.comm_intervals.get(key)
            if val is not None:
                lines.append(f"| {label} | `{_fmt_sec(val)}` |")
        lines.append("")

    # ── Telemetry timeline ────────────────────────────────────────────────────
    if ctx.mr_daily_counts:
        from datetime import timedelta
        daily = ctx.mr_daily_counts
        dates = sorted(daily.keys())
        total_files = sum(daily.values())
        try:
            d0 = datetime.strptime(dates[0], "%Y-%m-%d").date()
            d1 = datetime.strptime(dates[-1], "%Y-%m-%d").date()
            span_days = (d1 - d0).days + 1
        except (ValueError, IndexError):
            span_days = len(dates)
            d0 = d1 = None

        avg_per_day = total_files / max(span_days, 1)
        days_with_data = len(dates)

        lines += [
            "### Match Report Telemetry Timeline",
            "",
            f"- **Period:** {dates[0]} → {dates[-1]}",
            f"- **Total files:** {total_files:,}",
            f"- **Days with reports:** {days_with_data} / {span_days} calendar days",
            f"- **Average per day:** {avg_per_day:.1f}",
            "",
        ]

        # Gap detection: consecutive ≥3 days with zero reports
        gaps: list[tuple[str, str, int]] = []
        if d0 and d1:
            gap_start = None
            gap_len = 0
            cur = d0
            while cur <= d1:
                ds = cur.strftime("%Y-%m-%d")
                if daily.get(ds, 0) == 0:
                    if gap_start is None:
                        gap_start = ds
                    gap_len += 1
                else:
                    if gap_start and gap_len >= 3:
                        gaps.append((gap_start, (cur - timedelta(days=1)).strftime("%Y-%m-%d"), gap_len))
                    gap_start = None
                    gap_len = 0
                cur += timedelta(days=1)
            if gap_start and gap_len >= 3:
                gaps.append((gap_start, d1.strftime("%Y-%m-%d"), gap_len))

        if gaps:
            lines += [
                f"**Telemetry Gaps ({len(gaps)} gap(s) ≥ 3 consecutive days):**",
                "",
                "| Gap Start | Gap End | Duration |",
                "|-----------|---------|----------|",
            ]
            for gs, ge, gl in gaps:
                lines.append(f"| {gs} | {ge} | {gl} days |")
            lines.append("")
        else:
            lines += ["> No significant telemetry gaps detected (no stretch ≥ 3 days with zero reports).", ""]

    lines += ["---", ""]


def _network_context(lines: list, ctx: SystemContext) -> None:
    """Network interfaces, active connections, and DNS configuration."""
    if not ctx.ifconfig_interfaces and not ctx.network_connections and not ctx.dns_servers:
        return

    lines += [
        "## Network Context",
        "",
        "*Active network interfaces (ifconfig), established connections and listening ports (lsof-i, netstat-anW), "
        "and configured DNS servers at dump time. LISTEN = open port awaiting connections. "
        "ESTABLISHED = active connection to a remote host. "
        "Look for exposed services or connections to unrecognized hosts.*",
        "",
    ]

    if ctx.ifconfig_interfaces:
        lines += [
            "### Active Network Interfaces",
            "",
            "| Interface | IPv4 | IPv6 | MAC | Status |",
            "|-----------|------|------|-----|--------|",
        ]
        for iface in ctx.ifconfig_interfaces:
            lines.append(
                f"| `{iface['name']}` | `{iface.get('ipv4') or '-'}` "
                f"| `{iface.get('ipv6_global') or '-'}` "
                f"| `{iface.get('mac') or '-'}` | {iface.get('status', '')} |"
            )
        lines.append("")

    if ctx.dns_servers:
        lines += [
            "### Configured DNS Servers",
            "",
            ", ".join(f"`{s}`" for s in ctx.dns_servers),
            "",
        ]

    listen = [c for c in ctx.network_connections if c["state"] == "LISTEN"]
    established = [c for c in ctx.network_connections if c["state"] == "ESTABLISHED"]

    if listen:
        lines += [
            f"### Listening Ports ({len(listen)})",
            "",
            "| Process | PID | User | Protocol | Address |",
            "|---------|-----|------|----------|---------|",
        ]
        for c in listen[:30]:
            lines.append(
                f"| `{c['command']}` | {c['pid']} | `{c['user']}` "
                f"| {c['proto']} | `{c['name']}` |"
            )
        if len(listen) > 30:
            lines.append(f"| *... +{len(listen) - 30} more* | | | | |")
        lines.append("")

    if established:
        lines += [
            f"### Established Connections ({len(established)})",
            "",
            "| Process | PID | User | Connection |",
            "|---------|-----|------|------------|",
        ]
        for c in established[:30]:
            lines.append(
                f"| `{c['command']}` | {c['pid']} | `{c['user']}` | `{c['name']}` |"
            )
        if len(established) > 30:
            lines.append(f"| *... +{len(established) - 30} more* | | | |")
        lines.append("")

    # Netstat connections (from netstat-anW.txt — port-level detail)
    ns_listen = [c for c in ctx.netstat_connections if c["state"] == "LISTEN"]
    ns_estab  = [c for c in ctx.netstat_connections if c["state"] == "ESTABLISHED"]

    if ns_listen:
        lines += [
            f"### Listening Ports — netstat ({len(ns_listen)})",
            "",
            "| Proto | Addr | Port |",
            "|-------|------|------|",
        ]
        for c in ns_listen[:40]:
            lines.append(
                f"| {c['proto']} | `{c['local_addr']}` | **{c['local_port']}** |"
            )
        if len(ns_listen) > 40:
            lines.append(f"| *... +{len(ns_listen) - 40} more* | | |")
        lines.append("")

    if ns_estab:
        lines += [
            f"### Established Connections — netstat ({len(ns_estab)})",
            "",
            "| Proto | Local | Port | Remote | Port |",
            "|-------|-------|------|--------|------|",
        ]
        for c in ns_estab[:40]:
            lines.append(
                f"| {c['proto']} | `{c['local_addr']}` | {c['local_port']} "
                f"| `{c['remote_addr']}` | {c['remote_port']} |"
            )
        if len(ns_estab) > 40:
            lines.append(f"| *... +{len(ns_estab) - 40} more* | | | | |")
        lines.append("")

    lines += ["---", ""]


def _third_party_services(lines: list, ctx: SystemContext) -> None:
    """Third-party LaunchDaemons, system extensions, disk volumes, users."""
    has_services = bool(ctx.third_party_services)
    has_ext = bool(ctx.system_extensions)
    has_vols = bool(ctx.disk_volumes)
    has_users = bool(ctx.local_users)

    if not (has_services or has_ext or has_vols or has_users):
        return

    lines += [
        "## Services, Extensions & Storage",
        "",
        "*Third-party services running at startup (LaunchAgents = per-user, LaunchDaemons = system-wide), "
        "system extensions and storage usage. "
        "Non-Apple entries warrant verification — they can be legitimate or malicious persistence mechanisms.*",
        "",
    ]

    if has_users:
        lines += [
            "### Local User Accounts",
            "",
            "| User | UID |",
            "|------|-----|",
        ]
        for u in ctx.local_users:
            lines.append(f"| `{u['name']}` | {u['uid']} |")
        lines.append("")

    if has_services:
        enabled = [s for s in ctx.third_party_services if s["enabled"]]
        disabled = [s for s in ctx.third_party_services if not s["enabled"]]
        lines += [
            f"### Third-Party Services (LaunchDaemons/Agents) — {len(ctx.third_party_services)} entries",
            "",
        ]
        if enabled:
            lines += [f"**Enabled ({len(enabled)}):**", ""]
            for s in enabled:
                lines.append(f"- `{s['name']}`")
            lines.append("")
        if disabled:
            lines += [f"**Disabled ({len(disabled)}):**", ""]
            for s in disabled:
                lines.append(f"- `{s['name']}`")
            lines.append("")

    if has_ext:
        lines += [
            f"### System Extensions ({len(ctx.system_extensions)})",
            "",
            "| Team | Bundle | Name | State |",
            "|------|--------|------|-------|",
        ]
        for ext in ctx.system_extensions:
            active_mark = "✓" if ext.get("active") else ""
            lines.append(
                f"| `{ext['team_id']}` | `{ext['bundle_id']}` "
                f"| {ext['name']} | {ext.get('state', '')} {active_mark} |"
            )
        lines.append("")

    if has_vols:
        lines += [
            "### Disk Volumes",
            "",
            "| Volume | Size | Used | Available | Capacity | Mount Point |",
            "|--------|------|------|-----------|----------|-------------|",
        ]
        for v in ctx.disk_volumes:
            cap = v["capacity"]
            flag = " ⚠️" if cap >= 80 else ""
            lines.append(
                f"| `{v['filesystem']}` | {v['size']} | {v['used']} "
                f"| {v['avail']} | **{cap}%**{flag} | `{v['mounted']}` |"
            )
        lines.append("")

    lines += ["---", ""]


def _findings_section(lines: list, findings: list[Finding]) -> None:
    lines += [
        "## Security Findings",
        "",
        "*Results of detection rules applied to the dump data. "
        "Each finding describes the triggered rule, its severity, the involved process, "
        "and the underlying observed events. The MITRE ATT&CK code links to the official technique database.*",
        "",
    ]

    if not findings:
        lines += ["*No findings.*", "", "---", ""]
        return

    current_severity: str | None = None
    for f in findings:
        if f.severity != current_severity:
            current_severity = f.severity
            icon = SEVERITY_ICON.get(f.severity, "")
            lines += [f"### {icon} {f.severity}", ""]
        _finding_block(lines, f)

    lines += ["---", ""]


def _finding_block(lines: list, f: Finding) -> None:
    mitre_part = ""
    if f.mitre_id:
        tech_path = f.mitre_id.replace(".", "/")
        mitre_part = f" | MITRE: [{f.mitre_id}](https://attack.mitre.org/techniques/{tech_path}) {f.mitre_name or ''}"

    lines += [
        f"#### [{f.rule_id}] {f.rule_name}",
        "",
        f"**Severity:** {f.severity}{mitre_part}  ",
        f"**Process:** `{f.process}`  ",
    ]

    if f.first_seen:
        lines.append(f"**First Detected:** {f.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    if f.last_seen and f.last_seen != f.first_seen:
        lines.append(f"**Last Detected:** {f.last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")

    lines += [
        "",
        f"**Description:** {f.description}",
        "",
        f"**Recommendation:** {f.recommendation}",
        "",
    ]

    if f.evidence:
        lines += [
            f"**Evidence ({len(f.evidence)} events):**",
            "",
            "| Timestamp UTC | Type | Category | Target |",
            "|---------------|------|----------|--------|",
        ]
        for ev in f.evidence[:10]:
            ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            cat = ev.behavior_category or ev.event_type or ""
            target = (ev.target_path or "")[:60]
            lines.append(f"| `{ts}` | {ev.event_type} | `{cat}` | `{target}` |")
        if len(f.evidence) > 10:
            lines.append(f"| *... +{len(f.evidence) - 10} additional events* | | | |")
        lines.append("")


def _process_profiles(
    lines: list, findings: list[Finding], events: list[Event]
) -> None:
    """Per-process behavior deep-dive for processes appearing in findings."""
    if not findings:
        return

    suspicious_processes = {}
    for f in findings:
        if f.severity in ("CRITICAL", "HIGH", "MEDIUM") and f.process:
            suspicious_processes.setdefault(f.process, []).append(f)

    if not suspicious_processes:
        return

    lines += [
        "## Process Behavior Profiles",
        "",
        "*Process-centric view: each profile groups all findings linked to the same process. "
        "A process accumulating multiple high-severity findings is a strong indicator of malicious activity. "
        "Associated MITRE ATT&CK techniques are listed per process.*",
        "",
    ]

    mr_events = [e for e in events if e.source_type == "match_report"]

    for proc_name, proc_findings in list(suspicious_processes.items())[:10]:
        proc_events = [
            e for e in mr_events
            if e.process_name == proc_name or proc_name in e.process_path
        ]

        lines += [f"### `{proc_name}`", ""]

        lines += [
            f"**Associated findings ({len(proc_findings)}):**",
            "",
        ]
        for f in proc_findings:
            lines.append(
                f"- `[{f.rule_id}]` {SEVERITY_ICON.get(f.severity, '')} "
                f"**{f.severity}** — {f.rule_name}"
            )
        lines.append("")

        if proc_events:
            cats: dict[str, int] = {}
            for e in proc_events:
                if e.behavior_category:
                    cats[e.behavior_category] = cats.get(e.behavior_category, 0) + 1

            lines += [
                f"**Behavioral activity ({len(proc_events)} events):**",
                "",
                "| Category | Count |",
                "|----------|-------|",
            ]
            for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
                lines.append(f"| `{cat}` | {count} |")
            lines.append("")

            targets = list({
                e.target_path for e in proc_events
                if e.target_path and e.target_path != proc_name
            })[:20]
            if targets:
                lines += ["**Target paths (sample):**", ""]
                for t in targets:
                    lines.append(f"- `{t}`")
                lines.append("")

            group_ids = list({e.group_id for e in proc_events if e.group_id})[:5]
            if group_ids:
                lines += ["**Group UUIDs (behavioral sessions):**", ""]
                for gid in group_ids:
                    lines.append(f"- `{gid}`")
                lines.append("")

    lines += ["---", ""]


def _ioc_summary(
    lines: list, findings: list[Finding], events: list[Event]
) -> None:
    """Consolidated IOC list: suspicious paths, processes, group UUIDs."""
    if not findings:
        return

    mr_events = [e for e in events if e.source_type == "match_report"]

    ioc_paths: set[str] = set()
    ioc_procs: set[str] = set()
    ioc_groups: set[str] = set()

    for f in findings:
        if f.severity not in ("CRITICAL", "HIGH"):
            continue
        if f.process:
            ioc_procs.add(f.process)
        for ev in f.evidence:
            if ev.target_path:
                ioc_paths.add(ev.target_path)
            if ev.group_id:
                ioc_groups.add(ev.group_id)

    for e in mr_events:
        if e.process_name in ioc_procs and e.group_id:
            ioc_groups.add(e.group_id)

    if not (ioc_paths or ioc_procs or ioc_groups):
        return

    lines += [
        "## IOC Summary (CRITICAL/HIGH)",
        "",
        "*Consolidated Indicators of Compromise (IoCs) from CRITICAL and HIGH findings. "
        "Suspicious processes, involved file paths, and SentinelOne behavioral sessions "
        "(group UUIDs linking events from the same incident). "
        "These can be fed into your SIEM or verified on VirusTotal / AbuseIPDB.*",
        "",
    ]

    if ioc_procs:
        lines += [
            f"### Suspicious Processes ({len(ioc_procs)})",
            "",
        ]
        for p in sorted(ioc_procs):
            lines.append(f"- `{p}`")
        lines.append("")

    if ioc_paths:
        lines += [
            f"### Suspicious File Paths ({len(ioc_paths)})",
            "",
        ]
        for p in sorted(ioc_paths)[:50]:
            lines.append(f"- `{p}`")
        if len(ioc_paths) > 50:
            lines.append(f"- *... +{len(ioc_paths) - 50} more*")
        lines.append("")

    if ioc_groups:
        lines += [
            f"### Group UUIDs — Behavioral Sessions ({len(ioc_groups)})",
            "",
        ]
        for g in sorted(ioc_groups)[:20]:
            lines.append(f"- `{g}`")
        if len(ioc_groups) > 20:
            lines.append(f"- *... +{len(ioc_groups) - 20} more*")
        lines.append("")

    lines += ["---", ""]


def _timeline_section(lines: list, events: list[Event]) -> None:
    lines += [
        "## Event Timeline (50 most recent)",
        "",
        "*Chronological view of behavioral events extracted from match_reports, sorted newest to oldest. "
        "The behavioral category is SentinelOne's classification of the action "
        "(e.g. fileCreation, networkConnection, moduleLoad). The target is the file or resource involved.*",
        "",
    ]

    mr_events = [e for e in events if e.source_type == "match_report"]
    if not mr_events:
        lines += ["*No events.*", ""]
        return

    sorted_events = sorted(mr_events, key=lambda e: e.timestamp, reverse=True)
    lines += [
        f"**{len(mr_events)} behavioral events** over the analyzed period.",
        "",
        "| Timestamp UTC | Process | Category | Target |",
        "|---------------|---------|----------|--------|",
    ]

    for ev in sorted_events[:50]:
        ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        target = (ev.target_path or "")[:50]
        cat = ev.behavior_category or ""
        lines.append(f"| `{ts}` | `{ev.process_name}` | `{cat}` | `{target}` |")

    if len(sorted_events) > 50:
        lines.append(f"| *... +{len(sorted_events) - 50} additional events* | | | |")

    lines += ["", "---", ""]


def _statistics(
    lines: list,
    ctx: SystemContext,
    findings: list[Finding],
    events: list[Event],
) -> None:
    mr_events = [e for e in events if e.source_type == "match_report"]
    lines += [
        "## Statistics",
        "",
        "*Ingestion and processing metrics for the dump: files parsed, events extracted, "
        "rules applied, and findings generated. "
        "Charts show the dominant behavioral categories (TTPs), "
        "the most active processes, and the temporal distribution of events.*",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| match_reports files | {ctx.parse_stats.get('match_reports_files', 0)} |",
        f"| match_reports events | {ctx.parse_stats.get('match_reports_events', 0)} |",
        f"| UI log events | {ctx.parse_stats.get('ui_log_events', 0)} |",
        f"| Crash reports | {ctx.parse_stats.get('crash_events', 0)} |",
        f"| Rules applied | {ctx.parse_stats.get('rules_count', 0)} |",
        f"| Total findings | {ctx.parse_stats.get('total_findings', 0)} |",
        f"| Findings after filtering | {ctx.parse_stats.get('filtered_findings', 0)} |",
        "",
    ]

    if mr_events:
        cat_counts: dict[str, int] = {}
        for e in mr_events:
            if e.behavior_category:
                cat_counts[e.behavior_category] = cat_counts.get(e.behavior_category, 0) + 1

        lines += [
            "### Top 15 — Behavioral Categories",
            "",
            "| Category | Count |",
            "|----------|-------|",
        ]
        for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1])[:15]:
            lines.append(f"| `{cat}` | {count} |")
        lines.append("")

        proc_counts: dict[str, int] = {}
        for e in mr_events:
            proc_counts[e.process_name] = proc_counts.get(e.process_name, 0) + 1

        lines += [
            "### Top 10 — Processes by Detected Events",
            "",
            "| Process | Events |",
            "|---------|--------|",
        ]
        for proc, count in sorted(proc_counts.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"| `{proc}` | {count} |")
        lines.append("")

        month_counts: dict[str, int] = {}
        for e in mr_events:
            month = e.timestamp.strftime("%Y-%m")
            month_counts[month] = month_counts.get(month, 0) + 1

        lines += [
            "### Temporal Distribution (by month)",
            "",
            "| Month | Events |",
            "|-------|--------|",
        ]
        for month, count in sorted(month_counts.items()):
            lines.append(f"| {month} | {count} |")
        lines += ["", "---", ""]


_SOURCE_LABEL_MD = {
    "app_store":     "App Store",
    "auto_update":   "Auto-update",
    "system_update": "System Update",
    "sentinel":      "SentinelOne",
    "manual":        "⚠️ Manual",
    "unknown":       "Unknown",
}


def _system_activity(lines: list, ctx: SystemContext) -> None:
    """Software installation history, boot/session timeline from logs/install.log and asl.log."""
    history = ctx.install_history
    sessions = ctx.system_sessions
    stats = ctx.install_stats

    if not history and not sessions and not stats:
        return

    lines += [
        "## System Activity Log",
        "",
        "*Software installation history (install.log) and system events — "
        "boots, shutdowns, user sessions — (asl.log). "
        "The source indicates the installation origin: App Store, automatic update, "
        "macOS system, or manual install.*",
        "",
    ]

    # ── Operational statistics ────────────────────────────────────────────────
    if stats:
        period_start = stats.get("log_period_start", "—")
        period_end   = stats.get("log_period_end",   "—")
        period_note  = f"{period_start} → {period_end}" if period_start != "—" else "—"
        lines += [
            "### Operational Statistics",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Log Period | {period_note} |",
            f"| Package Installs | {stats.get('total_installs', 0)} |",
            f"| Software Update Checks | {stats.get('update_checks', 0)} |",
            f"| XProtect Updates | {stats.get('xprotect_updates', 0)} |",
            f"| System Boot Events | {stats.get('boot_count', 0)} |",
            f"| Sleep Events | {stats.get('sleep_count', 0)} |",
        ]
        sentinel_date = stats.get("sentinel_install_date")
        if sentinel_date:
            lines.append(f"| SentinelOne Installed | {sentinel_date} |")
        lines.append("")

    # ── Software installation history ─────────────────────────────────────────
    if history:
        lines += [
            f"### Software Installation History ({len(history)} events)",
            "",
            "| Date | Package | Version | Source | Path |",
            "|------|---------|---------|--------|------|",
        ]
        for e in history:
            src = _SOURCE_LABEL_MD.get(e.get("source_type", "unknown"), "Unknown")
            ver = e.get("version", "") or "—"
            path = e.get("source_path", "")[:80]
            lines.append(
                f"| {e.get('date', '')} | **{e.get('package_name', '')}** "
                f"| `{ver}` | {src} | `{path}` |"
            )
        lines.append("")

    # ── Boot/session events from asl.log ──────────────────────────────────────
    if sessions:
        _EV_ICON = {"boot": "🟢", "shutdown": "🔴", "login": "👤", "logout": "🔒"}
        lines += [
            f"### Boot & Session Events ({len(sessions)} total, asl.log)",
            "",
            "| Timestamp | Event |",
            "|-----------|-------|",
        ]
        for s in sessions[:50]:
            icon = _EV_ICON.get(s.get("event_type", ""), "•")
            lines.append(
                f"| `{s.get('timestamp', '')}` "
                f"| {icon} {s.get('event_type', '').upper()} |"
            )
        if len(sessions) > 50:
            lines.append(f"| *... +{len(sessions) - 50} more events* | |")
        lines.append("")

    lines += ["---", ""]


def _threat_intel(lines: list, ctx: SystemContext) -> None:
    """Threat Intelligence versions + Agent Configuration from plist sources."""
    has_intel = bool(ctx.intelligence_metadata)
    has_config = bool(ctx.agent_config)
    if not has_intel and not has_config:
        return

    lines += [
        "## Threat Intelligence & Configuration",
        "",
        "*Versions of signature databases and detection engines embedded in the agent, "
        "extracted from plist metadata files. "
        "Outdated signatures may indicate an isolated agent or a blocked update. "
        "The Deep Visibility configuration shows which event types are collected.*",
        "",
    ]

    if has_intel:
        lines += [
            "### Intelligence Engine Versions",
            "",
            "| Component | Version | Content Version | Build | Update Date |",
            "|-----------|---------|-----------------|-------|-------------|",
        ]
        pretty = {
            "dynamicEngine":    "Dynamic Engine",
            "staticSignatures": "Static Signatures",
            "StaticAILibrary":  "Static AI Library",
        }
        _VER_KEYS = ("version", "Version", "ContentVersion", "BuildNumber")
        for name, entry in sorted(ctx.intelligence_metadata.items()):
            label = pretty.get(name, name)
            ver     = entry.get("version",        entry.get("Version",        "—"))
            content = entry.get("ContentVersion", "—")
            build   = entry.get("BuildNumber",    "—")
            date    = entry.get("UpdateDate",     "—")
            lines.append(f"| **{label}** | `{ver}` | `{content}` | `{build}` | {date} |")
        lines.append("")

    if has_config:
        cfg = ctx.agent_config
        lines += ["### Agent Configuration", ""]

        cfg_rows: list[tuple[str, str]] = []

        anti_tamper = cfg.get("anti_tamper_disabled")
        if anti_tamper is not None:
            status = "**DISABLED** ⚠️" if anti_tamper else "ENABLED ✓"
            cfg_rows.append(("Anti-Tamper Protection", status))

        remote_shell = cfg.get("remote_shell_enabled")
        if remote_shell is not None:
            status = "ENABLED ⚠️" if remote_shell else "disabled"
            cfg_rows.append(("Remote Shell", status))

        cpu_limit = cfg.get("cpu_consumption_limit")
        if cpu_limit is not None:
            cfg_rows.append(("CPU Consumption Limit", f"`{cpu_limit} ms/sec`"))

        update_int = cfg.get("update_interval")
        if update_int is not None:
            cfg_rows.append(("Update Interval", f"`{update_int}s`"))

        mgmt = cfg.get("management_server")
        if mgmt:
            cfg_rows.append(("Management Server (config)", f"`{mgmt}`"))

        site_key = cfg.get("site_key_suffix")
        if site_key:
            cfg_rows.append(("Site Key (masked)", f"`{site_key}`"))

        scan_new = cfg.get("scan_new_apps")
        if scan_new is not None:
            cfg_rows.append(("Scan New Applications", f"`{scan_new}`"))

        if cfg_rows:
            lines += [
                "| Setting | Value |",
                "|---------|-------|",
            ]
            for label, val in cfg_rows:
                lines.append(f"| {label} | {val} |")
            lines.append("")

        dv_flags = cfg.get("dv_collect_flags", {})
        if dv_flags:
            enabled_dv  = sorted(k.replace("Collect", "") for k, v in dv_flags.items() if v)
            disabled_dv = sorted(k.replace("Collect", "") for k, v in dv_flags.items() if not v)
            lines += ["### Deep Visibility Collection", ""]
            if enabled_dv:
                lines.append(f"**Active ({len(enabled_dv)}):** " + ", ".join(f"`{k}`" for k in enabled_dv))
            else:
                lines.append("*No active collection flags.*")
            if disabled_dv:
                lines.append(f"**Disabled ({len(disabled_dv)}):** " + ", ".join(f"`{k}`" for k in disabled_dv))
            lines.append("")

    lines += ["---", ""]


def _blind_spots(lines: list, ctx: SystemContext) -> None:
    lines += [
        "## Blind Spots & Limitations",
        "",
        "*Undecoded formats and known offline analysis limitations. "
        "These items are not included in findings — their absence does not mean no threat exists. "
        "Path exclusions and Deep Visibility exclusions define the areas not monitored by the agent.*",
        "",
    ]

    spots = []
    if ctx.sentinelctl_error:
        spots.append(
            f"**macOS log archive unavailable:** `{ctx.sentinelctl_error}` — "
            "The macOS unified log archive could not be opened during dump collection. "
            "SentinelOne detection events (match_reports) are unaffected."
        )

    spots += [
        "**Unparsed formats:** `.ips` (Apple binary crash), `.core_analytics`, "
        "`system_logs.logarchive` (requires native macOS `log` command).",
        "**Binary ML plists:** `global-assets/dynamicEngine.plist`, "
        "`StaticAILibrary.plist` — models not decodable offline.",
    ]

    if ctx.sip_enabled is False:
        spots.append(
            "**SIP disabled:** system file modifications cannot be "
            "distinguished from legitimate access with certainty."
        )

    for spot in spots:
        lines.append(f"- {spot}")
    lines.append("")

    # Path exclusions — show actual list if decoded, fallback note otherwise
    if ctx.path_exclusions:
        lines += [
            f"**Path Exclusions ({len(ctx.path_exclusions)})** "
            f"— `assets/pathExclusion.plist`:",
            "",
        ]
        for p in ctx.path_exclusions[:50]:
            lines.append(f"- `{p}`")
        if len(ctx.path_exclusions) > 50:
            lines.append(f"- *... +{len(ctx.path_exclusions) - 50} more*")
        lines.append("")
    else:
        lines += [
            "- **Path exclusions:** `assets/pathExclusion.plist` uses a proprietary "
            "SentinelOne encrypted format and cannot be decoded offline. "
            "Review exclusions in the SentinelOne management console.",
            "",
        ]

    # DV exclusions — show actual list if decoded, fallback note otherwise
    if ctx.dv_exclusions:
        lines += [
            f"**Deep Visibility Exclusions ({len(ctx.dv_exclusions)})** "
            f"— `assets/dvExclusionsConsole.plist`:",
            "",
        ]
        for p in ctx.dv_exclusions[:30]:
            lines.append(f"- `{p}`")
        if len(ctx.dv_exclusions) > 30:
            lines.append(f"- *... +{len(ctx.dv_exclusions) - 30} more*")
        lines.append("")
    else:
        lines += [
            "- **Deep Visibility exclusions:** `assets/dvExclusionsConsole.plist` uses a proprietary "
            "SentinelOne encrypted format and cannot be decoded offline. "
            "Review DV exclusions in the management console.",
            "",
        ]

    lines += ["", "---", ""]
    lines.append(f"*Report generated by [SentinelOne macOS Log Analyzer {APP_VERSION}](https://github.com/Flor1an-B/sentinelone-macos-log-analyzer)*")


# ─── Operational Alerts ───────────────────────────────────────────────────────

def _operational_alerts(lines: list, ctx: SystemContext) -> None:
    """Prioritized operational alerts synthesized from all parsed data sources."""
    alerts = getattr(ctx, "operational_alerts", [])
    if not alerts:
        return

    _LEVEL_ICON = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "💡", "INFO": "ℹ️"}

    lines += ["## Operational Alerts", ""]
    crit_count = sum(1 for a in alerts if a.get("level") == "CRITICAL")
    high_count  = sum(1 for a in alerts if a.get("level") == "HIGH")
    if crit_count or high_count:
        parts = []
        if crit_count:
            parts.append(f"**{crit_count} CRITICAL**")
        if high_count:
            parts.append(f"**{high_count} HIGH**")
        lines += [
            f"> {' · '.join(parts)} — address before proceeding with further analysis.",
            "",
        ]

    for a in alerts:
        lvl    = a.get("level", "INFO")
        title  = a.get("title", "")
        detail = a.get("detail", "")
        action = a.get("action", "")
        icon   = _LEVEL_ICON.get(lvl, "ℹ️")
        lines += [f"### {icon} [{lvl}] {title}", ""]
        if detail:
            lines += [detail, ""]
        if action:
            lines += [f"> **Action:** {action}", ""]

    lines += ["---", ""]


# ─── System Performance ───────────────────────────────────────────────────────

def _system_performance(lines: list, ctx: SystemContext) -> None:
    """System resource metrics: memory, CPU load, power state, and agent DB health."""
    vm    = ctx.vm_memory or {}
    load  = ctx.system_load or {}
    power = ctx.power_state or {}
    db    = ctx.sentinel_db_health or {}

    if not vm and not load and not power and not db:
        return

    lines += ["## System Performance", ""]

    # Memory pressure
    if vm:
        pressure = vm.get("pressure_level", "OK")
        flag = " ⚠️" if pressure in ("CRITICAL", "WARNING") else ""
        lines += [f"### Memory Pressure: {pressure}{flag}", ""]
        rows = [("free_mb", "Free"), ("active_mb", "Active"),
                ("wired_mb", "Wired"), ("compressed_mb", "Compressed")]
        lines += ["| Type | MB |", "|------|----|"]
        for key, label in rows:
            if vm.get(key):
                lines.append(f"| {label} | {round(vm[key])} MB |")
        si, so = vm.get("swapins", 0), vm.get("swapouts", 0)
        if si or so:
            swap_warn = " ⚠️ high swap activity" if (si + so) > 5000 else ""
            lines.append(f"| Swap ins/outs | {si:,} / {so:,}{swap_warn} |")
        lines.append("")

    # CPU / load
    if load:
        cores = ctx.cpu_count or 1
        l1 = load.get("load_1", 0)
        l5 = load.get("load_5", 0)
        l15= load.get("load_15", 0)
        idle = load.get("cpu_idle_pct", 0)
        used_pct = round(100 - idle) if idle else 0
        flag = " ⚠️" if used_pct > 85 else ""
        lines += [f"### CPU & Load Average ({cores} cores){flag}", ""]
        lines += [
            "| Period | Load |",
            "|--------|------|",
            f"| 1 min  | {l1:.2f} |",
            f"| 5 min  | {l5:.2f} |",
            f"| 15 min | {l15:.2f} |",
        ]
        if used_pct:
            lines.append(f"| CPU Used | {used_pct}%{flag} |")
        if load.get("physmem_used_mb") and load.get("physmem_free_mb"):
            total_gb = round((load["physmem_used_mb"] + load["physmem_free_mb"]) / 1024, 1)
            used_gb  = round(load["physmem_used_mb"] / 1024, 1)
            lines.append(f"| Physical RAM | {used_gb} GB used / {total_gb} GB total |")
        lines.append("")

    # Power / battery
    if power:
        on_battery = power.get("on_battery", False)
        batt_pct   = power.get("battery_pct", None)
        src = "Battery" if on_battery else "AC Power"
        lines += [f"### Power State: {src}", ""]
        if batt_pct is not None:
            batt_flag = " ⚠️ LOW" if batt_pct < 20 else ""
            lines.append(f"- Battery: **{batt_pct}%**{batt_flag} "
                         + (f"— {power.get('battery_status','')}" if power.get("battery_status") else "")
                         + (f" · {power.get('battery_remaining','')} remaining" if power.get("battery_remaining") else ""))
        if power.get("low_power_mode"):
            lines.append("- **Low Power Mode** active")
        sp = power.get("sleep_preventing", [])
        if sp:
            lines.append(f"- Sleep prevented by: {', '.join(f'`{s}`' for s in sp[:4])}"
                         + (f" (+{len(sp)-4} more)" if len(sp) > 4 else ""))
        lines.append("")

    # Agent DB health
    if db:
        lines += ["### Agent DB Health", ""]
        if db.get("has_wonky"):
            lines += [
                f"> ⚠️ **state.wonky detected** ({db.get('wonky_db_mb', 0):.1f} MB) — "
                "LevelDB recovery file indicating the state DB was not cleanly closed. "
                "Likely follows an agent crash or forced kill.",
                "",
            ]
        rows_db: list[tuple[str, str]] = []
        if db.get("state_db_mb"):
            rows_db.append(("state.db size", f"{db['state_db_mb']:.1f} MB"))
        if db.get("total_db_mb"):
            rows_db.append(("Total agent dir", f"{db['total_db_mb']:.1f} MB"))
        if db.get("db_read_gib") or db.get("db_write_gib"):
            since = f" (since {db['db_stats_since']})" if db.get("db_stats_since") else ""
            w_flag = " ⚠️ HIGH" if db.get("db_write_gib", 0) > 10 else ""
            rows_db.append(("DB Read", f"{db.get('db_read_gib',0):.1f} GiB{since}"))
            rows_db.append(("DB Write", f"{db.get('db_write_gib',0):.1f} GiB{w_flag}"))
        if rows_db:
            lines += ["| Metric | Value |", "|--------|-------|"]
            for k, v in rows_db:
                lines.append(f"| {k} | {v} |")
            lines.append("")

    lines += ["---", ""]
