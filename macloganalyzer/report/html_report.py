"""html_report.py — Generates a dynamic, self-contained HTML security report."""
from __future__ import annotations
import html
import json
import re
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from macloganalyzer.models.context import SystemContext
from macloganalyzer.models.finding import Finding
from macloganalyzer.models.event import Event
from macloganalyzer.report.console import APP_VERSION

# ─── Security helpers ────────────────────────────────────────────────────────

def _esc(s: object) -> str:
    """HTML-escape any value before embedding in HTML context."""
    return html.escape(str(s) if s is not None else "", quote=True)


def _json_safe(data: object) -> str:
    """Serialize to JSON safe for <script> block embedding (no </script> injection)."""
    return json.dumps(data, ensure_ascii=False, default=str).replace("</", "<\\/")


_MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _mitre_url(mitre_id: str | None) -> str | None:
    if not mitre_id or not _MITRE_RE.match(mitre_id):
        return None
    return f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/"


# ─── Period filtering helpers ────────────────────────────────────────────────

def _period_ref_ts(ctx: "SystemContext", mr_events: "list | None" = None) -> datetime:
    """Compute reference timestamp = latest activity in the dump (NOT wall-clock now).

    Priority:
      1. log_period_end from agent_log / install_stats (most precise)
      2. Latest mr_event timestamp
      3. Latest timestamp in install_history / system_sessions
      4. datetime.now() as last resort
    """
    candidates = [
        ctx.agent_log.get("log_period_end", ""),
        ctx.install_stats.get("log_period_end", ""),
    ]
    ts_str = max((s for s in candidates if s), default="")
    if ts_str:
        try:
            return datetime.fromisoformat(ts_str[:19]).replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            pass
    # Use latest event timestamp from match_reports
    if mr_events:
        try:
            latest = max(e.timestamp for e in mr_events)
            return latest if latest.tzinfo else latest.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            pass
    # Use latest timestamp from install/session data
    all_ts: list[str] = []
    for i in ctx.install_history:
        ts = i.get("timestamp") or i.get("date") or ""
        if ts:
            all_ts.append(ts[:19])
    for s in ctx.system_sessions:
        ts = s.get("timestamp") or s.get("date") or ""
        if ts:
            all_ts.append(ts[:19])
    if all_ts:
        try:
            return datetime.fromisoformat(max(all_ts)).replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            pass
    return datetime.now(timezone.utc)


def _period_cutoff(ref_ts: datetime, days: int) -> "datetime | None":
    """Return cutoff datetime for the given window, or None for 'all'."""
    from datetime import timedelta
    if days == 0:
        return None
    return ref_ts - timedelta(days=days)


def _filter_findings_by_period(
    findings: "list[Finding]", cutoff: "datetime | None"
) -> "list[Finding]":
    if cutoff is None:
        return findings
    return [
        f for f in findings
        if f.first_seen and f.first_seen.replace(tzinfo=timezone.utc) >= cutoff
    ]


def _filter_events_by_period(
    events: "list[Event]", cutoff: "datetime | None"
) -> "list[Event]":
    if cutoff is None:
        return events
    return [
        e for e in events
        if e.timestamp.replace(tzinfo=timezone.utc) >= cutoff
    ]


def _ctx_for_period(ctx: "SystemContext", cutoff: "datetime | None") -> "SystemContext":
    """Return a shallow copy of ctx with time-series fields filtered to the cutoff."""
    if cutoff is None:
        return ctx
    from dataclasses import replace as _dc_replace
    cutoff_date = cutoff.date().isoformat()
    cutoff_str  = cutoff.strftime("%Y-%m-%d %H:%M:%S")

    def _ts_ok(ts: str) -> bool:
        return bool(ts) and ts[:19] >= cutoff_str

    def _date_ok(d: str) -> bool:
        return bool(d) and d[:10] >= cutoff_date

    filtered_install = [
        i for i in ctx.install_history
        if _ts_ok(i.get("timestamp") or "") or _date_ok(i.get("date") or "")
    ]
    filtered_sessions = [
        s for s in ctx.system_sessions
        if _ts_ok(s.get("timestamp") or "") or _date_ok(s.get("date") or "")
    ]
    filtered_daily = {
        d: c for d, c in ctx.mr_daily_counts.items() if d >= cutoff_date
    }
    agent_log = dict(ctx.agent_log)
    if "rcp_requests" in agent_log:
        agent_log["rcp_requests"] = [
            r for r in agent_log["rcp_requests"]
            if _ts_ok(r.get("timestamp") or "")
        ]
    if "keep_alive_recent" in agent_log:
        agent_log["keep_alive_recent"] = [
            ts for ts in agent_log["keep_alive_recent"] if _ts_ok(ts or "")
        ]
    if "asset_updates" in agent_log:
        agent_log["asset_updates"] = [
            u for u in agent_log["asset_updates"]
            if _ts_ok(u.get("timestamp") or "")
        ]
    return _dc_replace(
        ctx,
        install_history=filtered_install,
        system_sessions=filtered_sessions,
        mr_daily_counts=filtered_daily,
        agent_log=agent_log,
    )


def _no_section_id(html_str: str) -> str:
    """Strip the id attribute from the first <section …> tag (wrapper div owns it)."""
    return re.sub(r'(<section)\s+id="[^"]*"', r'\1', html_str, count=1)


# ─── Section description helper ──────────────────────────────────────────────

def _sdesc(source: str, tips: str = "", **extra_rows: str) -> str:
    """
    Render a formatted section description block.
    source: HTML for the Source row
    tips:   HTML for the "What to look for" row (optional)
    extra_rows: keyword args as label=html for additional rows (e.g. memory="...", load="...")
    """
    rows = f'<div class="sdesc-row"><span class="sdesc-lbl">Source</span><span>{source}</span></div>'
    if tips:
        rows += (
            f'<div class="sdesc-row"><span class="sdesc-lbl">What to look for</span>'
            f'<span>{tips}</span></div>'
        )
    for label, content in extra_rows.items():
        rows += (
            f'<div class="sdesc-row"><span class="sdesc-lbl">{_esc(label.replace("_"," "))}</span>'
            f'<span>{content}</span></div>'
        )
    return f'<div class="section-desc">{rows}</div>'


# ─── Risk scoring ────────────────────────────────────────────────────────────

# Severity base points — first occurrence in a category
_SEV_BASE = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}

# Category confidence: fraction of findings that are truly malicious (vs expected/normal)
_CAT_CONF = {
    "CHAIN":   1.00,  # Multi-step attack chains — very high signal
    "CRED":    0.90,  # Credential access — high signal
    "EVADE":   0.85,  # Defense evasion — high signal
    "EXFIL":   0.85,  # Exfiltration — high signal
    "PRIV":    0.75,  # Privilege escalation
    "PERSIST": 0.70,  # Persistence — common in legitimate software
    "CONF":    0.55,  # Configuration gaps — many are expected states
    "RECON":   0.45,  # Reconnaissance — very common in normal operations
}

# Per-category contribution caps — prevents one category from dominating
_CAT_CAP = {
    "CHAIN":   30, "CRED":    25, "EVADE":   20, "EXFIL":   20,
    "PRIV":    15, "PERSIST": 15, "CONF":    10, "RECON":   10,
}


def _risk_score(
    findings: list[Finding],
    ctx: "SystemContext | None" = None,
) -> tuple[int, str]:
    """Multi-criteria risk score: category confidence + diminishing returns + context."""
    from collections import defaultdict

    cat_findings: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        cat = f.rule_id.split("-")[0].upper() if "-" in f.rule_id else "OTHER"
        cat_findings[cat].append(f)

    raw_total = 0.0
    for cat, cat_flist in cat_findings.items():
        conf = _CAT_CONF.get(cat, 0.60)
        cap  = _CAT_CAP.get(cat, 12)
        # Sort highest-weight first so diminishing returns hit duplicates
        cat_flist_sorted = sorted(
            cat_flist, key=lambda f: _SEV_BASE.get(f.severity, 0), reverse=True
        )
        cat_score = 0.0
        for i, f in enumerate(cat_flist_sorted):
            decay = max(0.2, 1.0 - i * 0.25)
            cat_score += _SEV_BASE.get(f.severity, 0) * conf * decay
        raw_total += min(cat_score, cap)

    # Context multipliers — environmental factors that amplify residual risk
    multiplier = 1.0
    bonus = 0.0
    if ctx is not None:
        if ctx.sip_enabled is False:
            multiplier += 0.15  # SIP disabled significantly raises exploitation ease
        # Remote shell / remote script execution enabled in policy
        for section_data in (ctx.policy_config or {}).values():
            if isinstance(section_data, dict):
                if section_data.get("RemoteShell", "").strip() in ("1", "true", "yes", "enabled"):
                    bonus += 8.0
                    break
        # Agent management connectivity lost
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


SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#0284c7",
    "INFO":     "#64748b",
    "MINIMAL":  "#16a34a",
}

SEV_TOOLTIP = {
    "CRITICAL": "Threat requiring immediate response. Indicates active compromise or imminent risk.",
    "HIGH":     "Significant threat requiring prompt investigation within 24h.",
    "MEDIUM":   "Suspicious activity warranting review. May indicate reconnaissance or an early-stage attack.",
    "LOW":      "Minor anomaly. Low-confidence detection or informational signal.",
    "INFO":     "Informational finding with no immediate threat impact.",
    "MINIMAL":  "No significant threat detected with current filter settings.",
}

# ─── Agent Health Score ───────────────────────────────────────────────────────

_HEALTH_COLOR = {
    "CRITICAL": "#dc2626",
    "DEGRADED":  "#d97706",
    "HEALTHY":   "#16a34a",
}

_HEALTH_TOOLTIP = {
    "CRITICAL": (
        "Agent is fundamentally broken — endpoint is NOT protected. "
        "Immediate action required: check operational state, asset signatures, "
        "and management connectivity."
    ),
    "DEGRADED": (
        "Agent is running but at reduced capacity. "
        "Some detections may be blind. "
        "Address not-ready daemons, DB integrity, or permission issues."
    ),
    "HEALTHY": (
        "Agent operational state is normal. "
        "All daemons ready, asset signatures valid, management connected."
    ),
}


def _agent_health_score(ctx: "SystemContext") -> tuple[str, str, list[str]]:
    """
    Compute an operational agent health level from the agent's actual running state.

    Returns (level, color, reasons) where level is CRITICAL / DEGRADED / HEALTHY.

    Principle: reflect whether SentinelOne is actually protecting the endpoint,
    not whether every optional feature is enabled. sentineld running and healthy
    is the primary signal.

    CRITICAL — core protection is genuinely broken:
      • sentineld process not running (verified in running_processes or integrity check)
      • Protection subsystem explicitly disabled in management policy
      • Core detection assets invalid (signatures, sha1/sha256, arbiter, blacklist/whitelist)
      • Management console explicitly disconnected (no policy updates possible)

    DEGRADED — agent running but detection coverage is reduced:
      • Coverage-affecting services not ready:
          - Lib Hooks Service (filesystem behavioral hooks — needs Full Disk Access)
          - Lib Logs Service (log-based detection — needs Full Disk Access)
          - Framework (ES Framework — kernel-level events)
      • Feature assets with invalid signature (DV exclusions, path exclusions, etc.)
      • Missing system authorizations
      • state.wonky (DB not cleanly closed — possible data loss on last crash)
      • SIP disabled (reduces OS-level tamper protection)
      • Memory pressure CRITICAL/WARNING (may cause agent instability)
      • Abnormal DB write volume > 10 GiB

    NOT flagged (expected / on-demand behavior):
      • sentineld_shell "not running" — activates only during active remote shell sessions
      • Empty assets (blacklist empty = no items configured, which is normal)
      • sentineld_guard, sentineld_helper running = good, watchdog is active
    """
    critical_reasons: list[str] = []
    degraded_reasons: list[str] = []

    st = ctx.sentinel_status or {}
    agent = st.get("agent", {}) if st else {}
    daemons = st.get("daemons", {}) if st else {}
    integrity = daemons.get("integrity", {})
    services  = daemons.get("services", {})

    # ── CRITICAL: sentineld not running ──────────────────────────────────────
    # Check process list first (most reliable), then integrity section
    sentineld_running = any(
        "sentineld" == p.get("binary", "").lower().split("/")[-1]
        for p in (ctx.running_processes or [])
    )
    sentineld_integrity = integrity.get("sentineld", "").lower()
    if not sentineld_running and sentineld_integrity not in ("ok", "running", ""):
        critical_reasons.append(
            f"sentineld not running (integrity: {integrity.get('sentineld', 'absent')})"
        )
    elif sentineld_integrity and sentineld_integrity not in ("ok", "running", "not running"):
        # Explicit bad state (not the on-demand "not running" pattern)
        critical_reasons.append(f"sentineld integrity check failed: {sentineld_integrity}")

    # ── CRITICAL: Protection subsystem explicitly disabled in policy ──────────
    pc = ctx.policy_config or {}
    protection = pc.get("General", {}).get("Protection", "")
    if protection == "0":
        critical_reasons.append("Protection subsystem explicitly DISABLED in management policy")

    # ── CRITICAL: Core detection assets invalid ───────────────────────────────
    # These are the actual detection engine files — invalid = detection is compromised
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
        critical_reasons.append(
            f"Core detection asset(s) invalid: {', '.join(invalid_core[:3])}"
            + (f" (+{len(invalid_core)-3} more)" if len(invalid_core) > 3 else "")
        )

    # ── CRITICAL: Management explicitly disconnected ──────────────────────────
    mgmt = st.get("management", {}) if st else {}
    mgmt_connected = str(mgmt.get("Connected", "")).strip().lower()
    if mgmt_connected in ("disconnected", "no", "false"):
        critical_reasons.append(
            "Agent disconnected from management console — "
            "local Static/Behavioral AI continues protecting the endpoint, "
            "but policy updates, STAR rules, threat intelligence sync, "
            "Remote Shell, and console visibility are unavailable"
        )

    # ── DEGRADED: sentineld_guard (watchdog) not running ─────────────────────
    # sentineld_guard is the anti-tamper watchdog that relaunches sentineld if killed.
    # Without it, killing sentineld leaves the endpoint unprotected until next reboot.
    sentineld_guard_running = any(
        "sentineld_guard" == p.get("binary", "").lower().split("/")[-1]
        for p in (ctx.running_processes or [])
    )
    guard_integrity = integrity.get("sentineld_guard", "").lower()
    if not sentineld_guard_running and guard_integrity not in ("ok", "running", ""):
        degraded_reasons.append(
            "sentineld_guard (watchdog) not running — "
            "agent is not self-healing; killing sentineld would leave the endpoint unprotected until reboot"
        )

    # ── DEGRADED: Coverage-reducing service states ────────────────────────────
    # Services whose absence directly reduces detection coverage
    _COVERAGE_SERVICES = {
        # NOTE: Lib Hooks Service and Lib Logs Service are no longer used by the
        # agent and will be removed in a future release — intentionally excluded.
        "Framework":
            "ES Framework (Apple Endpoint Security) not ready — "
            "kernel-level event visibility reduced",
        "Network Extension":
            "Network Extension not loaded — Deep Visibility network events blind, "
            "Firewall Control and Network Quarantine unavailable",
    }
    # Services that are on-demand or deprecated and NOT flagged when not running
    _ON_DEMAND_SERVICES = frozenset({
        "sentineld_shell",      # activates only during remote shell sessions
        "Lib Hooks Service",    # deprecated — no longer used by the agent
        "Lib Logs Service",     # deprecated — no longer used by the agent
    })

    for svc_name, svc_desc in _COVERAGE_SERVICES.items():
        svc_state = services.get(svc_name, "").lower()
        if svc_state in ("not ready", "not running"):
            degraded_reasons.append(f"{svc_name} not ready — {svc_desc}")
        # Also check integrity section
        int_state = integrity.get(svc_name, "").lower()
        if int_state and int_state not in ("ok", "running", "not running") and svc_name not in services:
            degraded_reasons.append(f"{svc_name} integrity: {int_state}")

    # ── DEGRADED: Feature asset signatures invalid ────────────────────────────
    if invalid_feature:
        degraded_reasons.append(
            f"Feature asset(s) with invalid signature: {', '.join(invalid_feature[:3])}"
            + (f" (+{len(invalid_feature)-3} more)" if len(invalid_feature) > 3 else "")
            + " (affects specific features, not core protection)"
        )

    # ── DEGRADED: Missing system authorizations ───────────────────────────────
    if st.get("missing_authorizations"):
        degraded_reasons.append(
            "Missing system authorizations — grant Full Disk Access and/or "
            "Accessibility permissions in System Settings > Privacy & Security"
        )

    # ── DEGRADED: DB integrity ────────────────────────────────────────────────
    if (ctx.sentinel_db_health or {}).get("has_wonky"):
        degraded_reasons.append(
            "state.wonky DB recovery file present — agent state DB was not cleanly closed, "
            "typically caused by a crash or forced kill"
        )

    # ── DEGRADED: System conditions affecting agent stability ─────────────────
    if ctx.sip_enabled is False:
        degraded_reasons.append(
            "SIP (System Integrity Protection) disabled — "
            "reduces OS-level tamper protection for the agent"
        )

    pressure = (ctx.vm_memory or {}).get("pressure_level", "")
    if pressure in ("CRITICAL", "WARNING"):
        degraded_reasons.append(
            f"Memory pressure: {pressure} — may cause agent process instability or slowdowns"
        )

    db_write = (ctx.sentinel_db_health or {}).get("db_write_gib", 0)
    if db_write > 10:
        degraded_reasons.append(
            f"Abnormal DB write volume: {db_write:.1f} GiB — "
            "may indicate scan runaway or log flooding"
        )

    # ── Determine level ───────────────────────────────────────────────────────
    if critical_reasons:
        level = "CRITICAL"
        reasons = critical_reasons + degraded_reasons
    elif degraded_reasons:
        level = "DEGRADED"
        reasons = degraded_reasons
    else:
        level = "HEALTHY"
        reasons = ["sentineld running · all core services ready · assets valid · console connected"]

    return level, _HEALTH_COLOR[level], reasons

# ─── CSS ─────────────────────────────────────────────────────────────────────

_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f1f4f9;--bg2:#e8ecf3;--card:#ffffff;--card-hover:#f8fafc;
  --border:#e2e8f0;--border2:#cbd5e1;
  --text:#1e2840;--text2:#475569;--text3:#94a3b8;
  --crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#0284c7;--info:#64748b;--ok:#16a34a;
  --cyan:#0ea5e9;--purple:#7c3aed;
  --sidebar-w:230px;--radius:12px;--trans:.18s ease;
}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  font-size:14px;line-height:1.6;min-height:100vh;overflow-x:hidden}
code,pre,.mono{font-family:'Cascadia Code','Consolas','Fira Code',monospace;font-size:.82em}
a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}

/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#f1f4f9}
::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#94a3b8}

/* Canvas background — hidden in light theme */
#particles-bg{display:none}

/* ── Dark mode ─────────────────────────────────────────────────────────────── */
[data-theme="dark"]{
  --bg:#0d1520;--bg2:#111d2e;--card:#162033;--card-hover:#1c2a42;
  --border:rgba(255,255,255,.07);--border2:rgba(255,255,255,.12);
  --text:#e2e8f0;--text2:#94a3b8;--text3:#4e6080;
}
[data-theme="dark"] body{background:var(--bg)}
[data-theme="dark"] #particles-bg{
  display:block;position:fixed;top:0;left:0;width:100%;height:100%;
  z-index:-1;pointer-events:none;opacity:.7
}
[data-theme="dark"] .main-content{background:transparent}
[data-theme="dark"] .hero{
  background:linear-gradient(135deg,rgba(22,32,51,.9) 0%,rgba(13,21,32,.95) 100%);
  border-color:rgba(56,189,248,.15);
  box-shadow:0 2px 32px rgba(0,0,0,.4),inset 0 1px 0 rgba(255,255,255,.05);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)
}
[data-theme="dark"] .card{
  background:rgba(22,32,51,.7);border-color:rgba(255,255,255,.07);
  backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px)
}
[data-theme="dark"] .sev-card{
  background:rgba(22,32,51,.75);border-color:rgba(255,255,255,.08);
  backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)
}
[data-theme="dark"] .finding-card{
  background:rgba(22,32,51,.7);border-color:rgba(255,255,255,.07);
  backdrop-filter:blur(8px)
}
[data-theme="dark"] .finding-card[data-sev="CRITICAL"]{
  box-shadow:0 0 0 1px rgba(220,38,38,.35),0 0 24px rgba(220,38,38,.18),0 4px 20px rgba(0,0,0,.3)
}
[data-theme="dark"] .stat-card,.process-card{
  background:rgba(22,32,51,.7);border-color:rgba(255,255,255,.07)
}
[data-theme="dark"] .data-table th{background:rgba(255,255,255,.04)}
[data-theme="dark"] .data-table tbody tr:hover td{background:rgba(255,255,255,.03)}
[data-theme="dark"] .data-table td code{background:rgba(255,255,255,.07);border-color:rgba(255,255,255,.12);color:var(--text)}
[data-theme="dark"] .timeline-table td.cat code{background:rgba(255,255,255,.07);border-color:rgba(255,255,255,.12);color:var(--text)}
[data-theme="dark"] .finding-proc{background:rgba(255,255,255,.07);color:var(--text2)}
[data-theme="dark"] .top-item-id{background:rgba(255,255,255,.07);color:var(--text3)}
[data-theme="dark"] .app-tag{background:rgba(255,255,255,.07);color:var(--text2)}
[data-theme="dark"] .ioc-item:hover{background:rgba(255,255,255,.05)}
[data-theme="dark"] .inline-code{background:rgba(255,255,255,.07);border-color:rgba(255,255,255,.12);color:var(--text)}
[data-theme="dark"] .hero-val code{background:rgba(56,189,248,.1);border-color:rgba(56,189,248,.2);color:#7dd3fc}
/* ── Performance cards ──────────────────────────────────────────────────────── */
.perf-card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px;height:100%}
.perf-card-header{display:flex;align-items:center;gap:8px;border-bottom:1px solid var(--border);padding-bottom:10px}
.perf-card-icon{font-size:18px;line-height:1}
.perf-card-title{font-weight:600;font-size:13px;color:var(--text)}
[data-theme="dark"] .perf-card{background:rgba(22,32,51,.6);border-color:rgba(255,255,255,.07)}
/* ── Operational alert cards dark mode ─────────────────────────────────────── */
[data-theme="dark"] .ops-alert-card{
  background:var(--alert-bg-dark,rgba(255,255,255,.04)) !important;
  border-left-color:var(--alert-border-dark) !important}
[data-theme="dark"] .finding-header:hover{background:rgba(255,255,255,.03)}
[data-theme="dark"] .collapse-panel summary{background:rgba(255,255,255,.04)}
[data-theme="dark"] .timeline-table tbody tr:hover td{background:rgba(255,255,255,.03)}
[data-theme="dark"] .group-sep-label{background:var(--bg2);border-color:var(--border)}
[data-theme="dark"] .search-box input{background:rgba(22,32,51,.8);color:var(--text);border-color:var(--border2)}
[data-theme="dark"] .sev-btn{background:rgba(22,32,51,.8);color:var(--text2);border-color:var(--border2)}
[data-theme="dark"] .badge-ok{background:rgba(22,163,74,.15);border-color:rgba(22,163,74,.3)}
[data-theme="dark"] .badge-warn{background:rgba(202,138,4,.15);border-color:rgba(202,138,4,.3)}
[data-theme="dark"] .badge-err{background:rgba(220,38,38,.15);border-color:rgba(220,38,38,.3)}
[data-theme="dark"] .badge-info{background:rgba(100,116,139,.15);border-color:rgba(100,116,139,.3)}
[data-theme="dark"] .alert-crit{background:rgba(220,38,38,.1);border-color:rgba(220,38,38,.3)}
[data-theme="dark"] .alert-warn{background:rgba(202,138,4,.1);border-color:rgba(202,138,4,.3)}
[data-theme="dark"] .alert-info{background:rgba(14,165,233,.1);border-color:rgba(14,165,233,.3)}
[data-theme="dark"] .ioc-item{background:rgba(22,32,51,.8)}
[data-theme="dark"] .blindspot-item{background:rgba(22,32,51,.8)}
[data-theme="dark"] #particles-bg{opacity:.6}

/* ── Gauge glow ─────────────────────────────────────────────────────────────── */
[data-theme="dark"] #gauge-svg{filter:drop-shadow(0 0 12px var(--gauge-glow,rgba(14,165,233,.35)))}

/* ── Theme toggle button ─────────────────────────────────────────────────────── */
.theme-toggle{
  display:flex;align-items:center;gap:8px;padding:8px 20px;margin-top:auto;
  background:none;border:none;cursor:pointer;font-size:12px;
  color:rgba(255,255,255,.4);transition:color .2s;text-align:left;width:100%
}
.theme-toggle:hover{color:rgba(255,255,255,.75)}
.theme-toggle-icon{font-size:14px;flex-shrink:0}

/* ── Category MITRE breakdown ────────────────────────────────────────────────── */
.mitre-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin-top:8px}
.mitre-cat-card{
  padding:12px 14px;border-radius:10px;border:1px solid var(--border);
  background:var(--card);text-align:center;position:relative;overflow:hidden;
  transition:transform var(--trans),box-shadow var(--trans)
}
.mitre-cat-card:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,.12)}
.mitre-cat-card::before{
  content:'';position:absolute;top:0;left:0;right:0;height:3px;
  background:var(--cat-color,var(--cyan))
}
.mitre-cat-count{font-size:26px;font-weight:800;color:var(--cat-color,var(--cyan));line-height:1}
.mitre-cat-name{font-size:10px;font-weight:700;color:var(--text3);letter-spacing:.08em;
  text-transform:uppercase;margin-top:4px}
.mitre-cat-desc{font-size:10px;color:var(--text3);margin-top:2px;line-height:1.35}
[data-theme="dark"] .mitre-cat-card{
  background:rgba(22,32,51,.75);backdrop-filter:blur(8px)
}

/* ── Activity heatmap (daily calendar) ───────────────────────────────────────── */
.heatmap-wrap{overflow-x:auto;padding:4px 0}
.heatmap-grid{display:flex;gap:3px;align-items:flex-end}
.heatmap-col{display:flex;flex-direction:column;gap:3px}
.heatmap-cell{
  width:16px;height:16px;border-radius:3px;border:1px solid rgba(0,0,0,.06);
  transition:transform .15s;cursor:default;flex-shrink:0
}
.heatmap-cell:hover{transform:scale(1.3);z-index:1;position:relative}
.hm-0{background:#f1f4f9}
.hm-1{background:#bfdbfe}
.hm-2{background:#60a5fa}
.hm-3{background:#2563eb}
.hm-4{background:#1e40af}
[data-theme="dark"] .hm-0{background:rgba(255,255,255,.05)}
[data-theme="dark"] .hm-1{background:rgba(56,189,248,.2)}
[data-theme="dark"] .hm-2{background:rgba(56,189,248,.45)}
[data-theme="dark"] .hm-3{background:rgba(56,189,248,.7)}
[data-theme="dark"] .hm-4{background:rgba(56,189,248,.95)}
.heatmap-months{display:flex;gap:3px;margin-bottom:4px;font-size:9px;color:var(--text3)}
.heatmap-month-label{white-space:nowrap}

/* Layout */
.layout{display:flex;min-height:100vh}

/* Sidebar — stays dark navy for contrast */
.sidebar{width:var(--sidebar-w);min-height:100vh;position:sticky;top:0;height:100vh;
  overflow-y:auto;flex-shrink:0;background:#1a2340;
  border-right:1px solid rgba(255,255,255,.06);padding:24px 0;display:flex;flex-direction:column;gap:2px}
.sidebar-brand{padding:8px 20px 20px;border-bottom:1px solid rgba(255,255,255,.07);margin-bottom:8px}
.sidebar-brand h1{font-size:13px;font-weight:700;color:#38bdf8;letter-spacing:.08em;text-transform:uppercase}
.sidebar-brand p{font-size:11px;color:rgba(255,255,255,.35);margin-top:2px}
.sidebar-score{display:flex;align-items:center;gap:8px;padding:10px 20px;margin-bottom:4px}
.sidebar-score-label{font-size:11px;color:rgba(255,255,255,.45)}
.sidebar-score-val{font-size:18px;font-weight:800;letter-spacing:-.02em}
.sidebar-indicators{display:flex;flex-direction:column;gap:0;padding:8px 12px;margin-bottom:4px;
  border-bottom:1px solid rgba(255,255,255,.06)}
.sidebar-indicator{display:flex;align-items:center;justify-content:space-between;
  padding:5px 8px;border-radius:7px;cursor:default}
.sidebar-indicator:hover{background:rgba(255,255,255,.04)}
.sidebar-indicator-label{font-size:10.5px;font-weight:600;color:rgba(255,255,255,.40);
  letter-spacing:.03em;text-transform:uppercase}
.sidebar-indicator-val{font-size:13px;font-weight:800;letter-spacing:-.01em}
.nav-group{padding:8px 12px 2px;font-size:10px;font-weight:700;color:rgba(255,255,255,.25);
  letter-spacing:.1em;text-transform:uppercase;margin-top:4px}
.nav-group:first-of-type{margin-top:0}

/* Section group separators in main content */
.group-sep{display:flex;align-items:center;gap:14px;margin:0 0 36px;padding-top:4px}
.group-sep::before,.group-sep::after{content:'';flex:1;height:1px;background:var(--border)}
.group-sep-label{font-size:10px;font-weight:700;color:var(--text3);letter-spacing:.1em;
  text-transform:uppercase;white-space:nowrap;padding:3px 10px;border:1px solid var(--border);
  border-radius:20px;background:var(--bg2)}
.nav-link{display:flex;align-items:center;gap:8px;padding:7px 20px;font-size:12px;
  color:rgba(255,255,255,.55);border-left:2px solid transparent;transition:var(--trans);cursor:pointer;
  text-decoration:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nav-link:hover{color:rgba(255,255,255,.85);background:rgba(255,255,255,.05);border-left-color:rgba(255,255,255,.2)}
.nav-link.active{color:#38bdf8;background:rgba(56,189,248,.08);border-left-color:#38bdf8}
.nav-link .nav-icon{width:15px;text-align:center;opacity:.7;flex-shrink:0}
.nav-badge{margin-left:auto;font-size:10px;padding:1px 6px;border-radius:9px;font-weight:700;flex-shrink:0}

/* Main content */
.main-content{flex:1;padding:32px 40px;min-width:0;overflow-x:auto;background:var(--bg)}

/* Sections */
.section{margin-bottom:52px;animation:fadeInUp .35s ease both}
.section-header{display:flex;align-items:center;gap:12px;margin-bottom:20px;
  padding-bottom:12px;border-bottom:2px solid var(--border)}
.section-icon{font-size:20px;opacity:.85}
.section-title{font-size:18px;font-weight:700;color:var(--text);letter-spacing:-.02em}
.section-subtitle{font-size:12px;color:var(--text3);margin-left:auto}
.section-desc{margin:-8px 0 16px}
.sdesc-row{display:flex;gap:10px;margin-bottom:5px;font-size:12px;color:var(--text2);
  line-height:1.6;align-items:flex-start}
.sdesc-row:last-child{margin-bottom:0}
.sdesc-lbl{flex-shrink:0;font-size:10px;font-weight:700;text-transform:uppercase;
  letter-spacing:.07em;color:var(--text1);background:var(--bg2);border:1px solid var(--border);
  border-radius:4px;padding:2px 7px;margin-top:1px;white-space:nowrap}
.section-guide{font-size:11.5px;color:var(--text2);line-height:1.6;max-width:900px}
.section-guide strong{color:var(--text)}
.section-guide ul{margin:6px 0 6px 18px}
.section-guide li{margin-bottom:3px}
.guide-panel{background:var(--bg2);border:1px solid var(--border);border-radius:10px;margin-bottom:20px;overflow:hidden}
.guide-panel summary{padding:10px 16px;cursor:pointer;font-weight:600;font-size:12px;color:var(--text2);user-select:none;list-style:none;display:flex;align-items:center;gap:8px}
.guide-panel summary::-webkit-details-marker{display:none}
.guide-panel summary::before{content:"▶";font-size:10px;transition:transform .2s}
details[open].guide-panel summary::before{content:"▶";transform:rotate(90deg)}
.guide-panel-body{padding:0 16px 16px;border-top:1px solid var(--border)}
[data-theme="dark"] .guide-panel{background:rgba(22,32,51,.5)}
[data-theme="dark"] .app-tag{background:rgba(255,255,255,.05);border-color:var(--border)}
/* ── Period filter — sidebar block ─────────────────────────────────────────── */
.sidebar-period{padding:8px 12px 10px;border-bottom:1px solid rgba(255,255,255,.06);margin-bottom:4px}
.sidebar-period-label{display:block;font-size:10px;font-weight:700;text-transform:uppercase;
  letter-spacing:.08em;color:rgba(255,255,255,.25);padding:0 4px;margin-bottom:6px}
.sidebar-period-btns{display:grid;grid-template-columns:1fr 1fr;gap:4px}
.period-btn{padding:5px 0;border-radius:7px;font-size:11px;font-weight:600;cursor:pointer;
  border:1px solid var(--border);background:var(--bg2);color:var(--text2);
  transition:all .15s;outline:none;text-align:center;width:100%}
.period-btn:hover{border-color:var(--cyan);color:var(--cyan)}
.period-btn.active{background:var(--cyan);border-color:var(--cyan);color:#fff}
.period-view{}
:root:not([data-theme="dark"]) .sidebar-period-label{color:rgba(30,40,64,.35)}

/* Collapsible panels */
.collapse-panel{border:1px solid var(--border);border-radius:8px;margin:8px 0;overflow:hidden}
.collapse-panel summary{padding:10px 14px;font-size:12px;font-weight:600;color:var(--text2);
  cursor:pointer;background:var(--bg2);list-style:none;display:flex;align-items:center;gap:8px;
  user-select:none}
.collapse-panel summary::-webkit-details-marker{display:none}
.collapse-panel summary::before{content:'▶';font-size:10px;transition:transform .2s;flex-shrink:0}
.collapse-panel[open] summary::before{transform:rotate(90deg)}
.collapse-panel .collapse-body{padding:12px 14px;border-top:1px solid var(--border)}

/* Hero */
.hero{background:linear-gradient(135deg,#ffffff 0%,#eef4ff 100%);
  border:1px solid #d1ddf5;border-radius:var(--radius);padding:28px 32px;
  margin-bottom:36px;position:relative;overflow:hidden;
  box-shadow:0 2px 16px rgba(30,40,100,.07)}
.hero::before{content:'';position:absolute;top:-60px;right:-60px;width:220px;height:220px;
  background:radial-gradient(circle,rgba(14,165,233,.07) 0%,transparent 70%);pointer-events:none}
.hero-grid{display:grid;grid-template-columns:1fr auto;gap:24px;align-items:center}
.hero-meta{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:8px}
.hero-row{display:flex;gap:8px;align-items:baseline}
.hero-key{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;min-width:130px;flex-shrink:0}
.hero-val{font-size:13px;color:var(--text);font-weight:500}
.hero-val code{background:#f0f4ff;padding:1px 6px;border-radius:4px;border:1px solid #dde8ff}

/* Risk gauge */
.gauge-wrap{display:flex;flex-direction:column;align-items:center;gap:8px;flex-shrink:0}
.gauge-svg{filter:drop-shadow(0 2px 8px rgba(0,0,0,.12))}
.gauge-label{font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
  color:var(--text2)}

/* Severity summary cards */
.sev-cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.sev-card{flex:1;min-width:90px;background:var(--card);border:1px solid var(--border);
  border-radius:var(--radius);padding:14px 16px;text-align:center;
  border-top:3px solid var(--sev-c);transition:var(--trans);cursor:default;
  box-shadow:0 1px 4px rgba(0,0,0,.05)}
.sev-card:hover{transform:translateY(-2px);
  box-shadow:0 6px 20px rgba(0,0,0,.1),0 0 0 1px var(--sev-c)}
.sev-card-count{font-size:28px;font-weight:800;color:var(--sev-c);line-height:1}
.sev-card-label{font-size:10px;font-weight:700;color:var(--text3);letter-spacing:.08em;
  text-transform:uppercase;margin-top:4px}

/* Cards */
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
  box-shadow:0 1px 4px rgba(0,0,0,.05);overflow:hidden}
.card-body{padding:20px 24px}

/* Tables */
.data-table{width:100%;border-collapse:collapse;font-size:13px}
.data-table th{padding:8px 12px;text-align:left;font-size:10px;font-weight:700;
  text-transform:uppercase;letter-spacing:.07em;color:var(--text3);
  border-bottom:1px solid var(--border);background:#f8fafc;white-space:nowrap}
.data-table td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
.data-table tr:last-child td{border-bottom:none}
.data-table tbody tr:hover td{background:#f8fafc}
.data-table td code{background:#f0f4f8;padding:1px 5px;border-radius:3px;
  font-size:.82em;word-break:break-all;border:1px solid var(--border)}
.table-wrap{overflow-x:auto;border-radius:8px;border:1px solid var(--border)}

/* Status badges */
.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:20px;
  font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap}
.badge-ok{background:#dcfce7;color:#16a34a;border:1px solid #bbf7d0}
.badge-warn{background:#fef9c3;color:#ca8a04;border:1px solid #fde68a}
.badge-err{background:#fee2e2;color:#dc2626;border:1px solid #fecaca}
.badge-info{background:#f1f5f9;color:#64748b;border:1px solid #e2e8f0}
.inline-code{background:#f0f4f8;border:1px solid #e2e8f0;border-radius:3px;font-family:monospace;font-size:.85em}

/* Severity badges */
.sev-badge{display:inline-flex;align-items:center;padding:2px 9px;border-radius:20px;
  font-size:10px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;
  border:1px solid currentColor;white-space:nowrap}

/* Findings toolbar */
.findings-toolbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
.search-box{flex:1;min-width:200px;position:relative}
.search-box input{width:100%;background:var(--card);border:1px solid var(--border2);
  border-radius:8px;padding:8px 12px 8px 34px;color:var(--text);font-size:13px;
  outline:none;transition:var(--trans)}
.search-box input:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(14,165,233,.12)}
.search-box::before{content:'🔍';position:absolute;left:10px;top:50%;transform:translateY(-50%);
  font-size:13px;pointer-events:none;opacity:.5}
.sev-filter{display:flex;gap:6px;flex-wrap:wrap}
.sev-btn{padding:5px 12px;border-radius:20px;border:1px solid var(--border2);background:var(--card);
  color:var(--text2);font-size:11px;font-weight:600;letter-spacing:.05em;cursor:pointer;
  text-transform:uppercase;transition:var(--trans)}
.sev-btn:hover{background:var(--bg2);color:var(--text);border-color:var(--border2)}
.sev-btn.active{border-color:currentColor;background:#f0f7ff;color:var(--cyan)}
.findings-count{font-size:12px;color:var(--text3);margin-left:auto;white-space:nowrap}

/* Finding cards */
.finding-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
  border-left:3px solid var(--sev-c,var(--border2));margin-bottom:8px;
  transition:box-shadow var(--trans),transform var(--trans);animation:fadeInUp .3s ease both;
  box-shadow:0 1px 3px rgba(0,0,0,.05)}
.finding-card:hover{box-shadow:0 4px 16px rgba(0,0,0,.1);transform:translateX(2px)}
.finding-card[data-sev="CRITICAL"]{animation:fadeInUp .3s ease both,pulse-crit 3s ease-in-out infinite}
.finding-header{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;user-select:none}
.finding-header:hover{background:#f8fafc}
.finding-rule-id{font-size:10px;font-weight:700;color:var(--text3);letter-spacing:.08em;
  text-transform:uppercase;font-family:monospace;flex-shrink:0}
.finding-name{font-size:13px;font-weight:600;color:var(--text);flex:1;min-width:0;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.finding-proc{font-size:11px;color:var(--text2);font-family:monospace;
  background:#f0f4f8;padding:1px 7px;border-radius:4px;border:1px solid var(--border);
  flex-shrink:0;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.finding-chevron{margin-left:auto;color:var(--text3);font-size:12px;
  transition:transform var(--trans);flex-shrink:0}
.finding-card.open .finding-chevron{transform:rotate(90deg)}
.finding-body{display:none;padding:0 16px 16px;border-top:1px solid var(--border)}
.finding-card.open .finding-body{display:block}
.finding-field{margin-top:12px}
.finding-field-label{font-size:10px;font-weight:700;color:var(--text3);
  text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px}
.finding-field-val{font-size:13px;color:var(--text2);line-height:1.5}
.finding-mitre{display:inline-flex;align-items:center;gap:5px;margin-top:8px;
  padding:3px 10px;border-radius:6px;background:#f5f0ff;
  border:1px solid #ddd6fe;font-size:11px;color:var(--purple)}
.evidence-table-wrap{overflow-x:auto;margin-top:8px;border-radius:8px;border:1px solid var(--border)}

/* IOC */
.ioc-list{display:flex;flex-direction:column;gap:4px}
.ioc-item{display:flex;align-items:center;gap:8px;padding:6px 10px;
  background:#f8fafc;border-radius:6px;border:1px solid var(--border);transition:var(--trans)}
.ioc-item:hover{background:#f0f4f8;border-color:var(--border2)}
.ioc-text{font-family:monospace;font-size:12px;color:var(--text2);word-break:break-all;flex:1}
.ioc-copy{flex-shrink:0;padding:2px 8px;border-radius:4px;border:1px solid var(--border2);
  background:var(--card);color:var(--text3);font-size:10px;cursor:pointer;transition:var(--trans)}
.ioc-copy:hover{background:var(--bg2);color:var(--text);border-color:var(--border2)}

/* Timeline */
.timeline-wrap{overflow-x:auto;border-radius:var(--radius);border:1px solid var(--border)}
.timeline-table{width:100%;border-collapse:collapse;font-size:12px;min-width:700px}
.timeline-table th{padding:8px 12px;text-align:left;font-size:10px;font-weight:700;
  text-transform:uppercase;letter-spacing:.07em;color:var(--text3);
  background:#f8fafc;border-bottom:1px solid var(--border);white-space:nowrap}
.timeline-table td{padding:7px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
.timeline-table tr:last-child td{border-bottom:none}
.timeline-table tbody tr:hover td{background:#f8fafc}
.timeline-table td.ts{color:var(--text3);font-family:monospace;font-size:11px;white-space:nowrap}
.timeline-table td.proc{font-family:monospace;color:var(--cyan);white-space:nowrap}
.timeline-table td.cat code{background:#f0f4f8;padding:1px 5px;border-radius:3px;white-space:nowrap;border:1px solid var(--border)}
.timeline-table td.target{color:var(--text2);font-family:monospace;font-size:11px;
  word-break:break-all;min-width:200px}

/* Charts */
.chart-row{display:flex;flex-direction:column;gap:0}
.chart-item{display:flex;flex-direction:column;gap:2px;padding:5px 0;border-bottom:1px solid var(--border)}
.chart-item:last-child{border-bottom:none}
.chart-label{font-size:11px;color:var(--text2);font-family:monospace;
  width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chart-bar-row{display:flex;align-items:center;gap:8px}
.chart-bar-wrap{flex:1;background:#e8ecf3;border-radius:3px;height:10px;overflow:hidden;min-width:40px}
.chart-bar{height:100%;border-radius:3px;transition:width .8s cubic-bezier(.22,.61,.36,1);
  background:linear-gradient(90deg,var(--cyan),var(--purple))}
.chart-val{font-size:11px;color:var(--text3);width:45px;text-align:right;flex-shrink:0;font-family:monospace}

/* Donut chart */
.summary-grid{display:grid;grid-template-columns:1fr auto;gap:24px;align-items:center}
.donut-container{flex-shrink:0}
.donut-legend{display:flex;flex-direction:column;gap:8px}
.legend-item{display:flex;align-items:center;gap:8px;font-size:12px;cursor:default}
.legend-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.legend-name{color:var(--text2);min-width:70px}
.legend-count{font-size:18px;font-weight:800;line-height:1}

/* Alert box */
.alert{display:flex;gap:10px;padding:12px 16px;border-radius:8px;
  border:1px solid currentColor;margin-bottom:12px;font-size:13px;line-height:1.5}
.alert-icon{font-size:16px;flex-shrink:0;margin-top:1px}
.alert-crit{background:#fff1f2;color:var(--crit);border-color:#fecdd3}
.alert-warn{background:#fffbeb;color:#b45309;border-color:#fde68a}
.alert-info{background:#f0f9ff;color:var(--cyan);border-color:#bae6fd}

/* Blind spots */
.blindspot-item{display:flex;gap:10px;padding:10px 14px;border-radius:8px;
  background:#f8fafc;border:1px solid var(--border);margin-bottom:8px;
  font-size:13px;line-height:1.5;color:var(--text2)}
.blindspot-icon{flex-shrink:0;margin-top:2px}

/* Tooltip */
.tooltip-bubble{position:fixed;z-index:9999;max-width:320px;padding:9px 13px;
  background:#1e2840;border:1px solid rgba(56,189,248,.3);
  border-radius:9px;font-size:12px;line-height:1.6;color:#e2e8f0;
  pointer-events:none;display:none;white-space:pre-line;
  box-shadow:0 8px 24px rgba(0,0,0,.25)}
.tooltip-bubble.visible{display:block;animation:tooltipFade .15s ease}

/* Copy toast */
.copy-toast{position:fixed;bottom:24px;right:24px;background:#dcfce7;
  border:1px solid #bbf7d0;color:#16a34a;padding:8px 18px;
  border-radius:8px;font-size:13px;font-weight:600;z-index:9999;
  opacity:0;transform:translateY(8px);transition:opacity .2s ease,transform .2s ease;
  pointer-events:none}
.copy-toast.show{opacity:1;transform:translateY(0)}

/* Footer */
.report-footer{text-align:center;padding:24px 0 8px;font-size:11px;color:var(--text3);
  border-top:1px solid var(--border);margin-top:16px}

/* Empty state */
.empty-state{text-align:center;padding:40px 20px;color:var(--text3)}
.empty-state-icon{font-size:36px;margin-bottom:12px}
.empty-state p{font-size:14px}

/* Top-findings */
.top-item{display:flex;gap:10px;align-items:flex-start;padding:8px 0;border-bottom:1px solid var(--border)}
.top-item:last-child{border-bottom:none}
.top-item-id{font-size:10px;font-weight:700;font-family:monospace;color:var(--text3);
  padding:2px 6px;background:#f0f4f8;border-radius:4px;border:1px solid var(--border);
  flex-shrink:0;margin-top:2px}
.top-item-name{font-size:13px;font-weight:600;color:var(--text);line-height:1.3}
.top-item-proc{font-size:11px;color:var(--text2);font-family:monospace}
.top-item-date{font-size:10px;color:var(--text3);margin-left:auto;flex-shrink:0;margin-top:3px;white-space:nowrap}

/* Stats */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:20px}
.stat-card{background:var(--card);border:1px solid var(--border);
  border-radius:var(--radius);padding:16px 20px;box-shadow:0 1px 4px rgba(0,0,0,.05)}
.stat-card-title{font-size:11px;font-weight:700;color:var(--text3);
  text-transform:uppercase;letter-spacing:.08em;margin-bottom:14px}

/* Animations */
@keyframes fadeInUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes pulse-crit{0%,100%{box-shadow:0 1px 3px rgba(0,0,0,.05)}
  50%{box-shadow:0 0 0 3px rgba(220,38,38,.15),0 4px 16px rgba(220,38,38,.12)}}
@keyframes tooltipFade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}

/* ── Quick Brief ─────────────────────────────────────────────────────────── */
.brief-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
@media(max-width:900px){.brief-grid{grid-template-columns:1fr}}
.risk-factor-list{display:flex;flex-direction:column;gap:6px;margin-top:10px}
.risk-factor-item{display:flex;gap:10px;align-items:flex-start;padding:10px 12px;
  border-radius:8px;border:1px solid var(--border)}
.rf-p0{background:#fff5f5;border-color:#fecaca!important}
.rf-p1{background:#fff7ed;border-color:#fed7aa!important}
.rf-p2{background:#fffbeb;border-color:#fde68a!important}
.rf-p3{background:#f0f9ff;border-color:#bae6fd!important}
.rf-badge{font-size:9px;font-weight:800;letter-spacing:.08em;padding:2px 7px;
  border-radius:4px;white-space:nowrap;flex-shrink:0;margin-top:2px;font-family:monospace}
.rf-p0 .rf-badge{background:#fee2e2;color:var(--crit)}
.rf-p1 .rf-badge{background:#ffedd5;color:var(--high)}
.rf-p2 .rf-badge{background:#fef9c3;color:#b45309}
.rf-p3 .rf-badge{background:#e0f2fe;color:var(--low)}
.rf-title{font-size:13px;font-weight:600;color:var(--text);line-height:1.3}
.rf-desc{font-size:12px;color:var(--text2);margin-top:3px;line-height:1.45}
.action-list{display:flex;flex-direction:column;gap:6px;margin-top:10px;
  padding-left:0;list-style:none;counter-reset:action-counter}
.action-item{display:flex;gap:10px;align-items:flex-start;padding:8px 12px;
  border-radius:8px;border:1px solid var(--border);counter-increment:action-counter}
.action-item::before{content:counter(action-counter);min-width:20px;height:20px;
  border-radius:50%;display:flex;align-items:center;justify-content:center;
  font-size:10px;font-weight:800;flex-shrink:0;margin-top:1px}
.ac-p0{background:#fff5f5;border-color:#fecaca!important}
.ac-p0::before{background:#fee2e2;color:var(--crit)!important}
.ac-p1{background:#fff7ed;border-color:#fed7aa!important}
.ac-p1::before{background:#ffedd5;color:var(--high)!important}
.ac-p2{background:#fffbeb;border-color:#fde68a!important}
.ac-p2::before{background:#fef9c3;color:#b45309!important}
.action-text{font-size:12px;color:var(--text2);line-height:1.45}
.action-text strong,.action-text code{color:var(--text)}
.corr-item{display:flex;gap:10px;padding:10px 14px;border-radius:8px;
  background:#faf5ff;border:1px solid #e9d5ff;margin-bottom:8px}
.corr-icon{flex-shrink:0;font-size:14px;margin-top:2px}
.corr-body{color:var(--text2);line-height:1.5;font-size:12px}
.corr-body strong{color:var(--text)}

/* ── Apps categories ─────────────────────────────────────────────────────── */
.app-categories{display:flex;flex-direction:column;gap:10px;margin-top:10px}
.app-cat-row{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}
.app-cat-label{font-size:10px;font-weight:700;color:var(--text3);letter-spacing:.07em;
  text-transform:uppercase;min-width:110px;flex-shrink:0}
.app-tag{display:inline-block;background:#f0f4f8;padding:2px 8px;
  border-radius:4px;margin:2px;font-size:11px;font-family:monospace;
  border:1px solid var(--border);transition:border-color var(--trans);
  max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  vertical-align:middle;cursor:default}
.app-tag:hover{border-color:var(--border2);background:#e8ecf3}
.app-tag-security{background:#fee2e2;color:var(--crit);border-color:#fecaca}
.app-tag-warn{background:#fef9c3;color:#b45309;border-color:#fde68a}

/* ── Process Analysis ────────────────────────────────────────────────────── */
.process-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:12px}
.process-card{background:var(--card);border:1px solid var(--border);
  border-radius:var(--radius);padding:14px 16px;
  border-top:3px solid var(--proc-c,var(--border));
  transition:box-shadow var(--trans),transform var(--trans);
  box-shadow:0 1px 4px rgba(0,0,0,.05)}
.process-card:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,.1)}
.process-name{font-size:12px;font-weight:700;color:var(--text);font-family:monospace;
  word-break:break-all;margin-bottom:10px;line-height:1.4}
.process-counts{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px}
.process-count-badge{font-size:10px;font-weight:700;padding:2px 8px;
  border-radius:12px;border:1px solid currentColor;white-space:nowrap}
.process-patterns{font-size:11px;color:var(--text2);margin-top:6px;line-height:1.4}
.process-mitre{display:flex;gap:3px;flex-wrap:wrap;margin-top:8px}
.process-mitre-tag{font-size:9px;padding:1px 6px;border-radius:4px;
  background:#f5f0ff;color:var(--purple);
  border:1px solid #ddd6fe;font-family:monospace;white-space:nowrap}
.process-range{font-size:10px;color:var(--text3);margin-top:8px;font-family:monospace}

/* Responsive */
@media(max-width:1024px){.main-content{padding:24px 24px}}
@media(max-width:768px){
  .sidebar{display:none}
  .main-content{padding:20px 16px}
  .hero-grid{grid-template-columns:1fr}
  .gauge-wrap{display:none}
  .summary-grid{grid-template-columns:1fr}
  .donut-container{display:none}
  .sev-cards{gap:8px}
  .brief-grid{grid-template-columns:1fr}
  .process-grid{grid-template-columns:1fr}
}

/* ── NEW HERO BANNER ─────────────────────────────────────────────────────── */
.hero-banner{
  background:linear-gradient(135deg,#0f1d35 0%,#0d1520 60%,#0a1628 100%);
  border:1px solid rgba(56,189,248,.12);border-radius:var(--radius);
  margin-bottom:36px;overflow:hidden;position:relative;
  box-shadow:0 4px 32px rgba(0,0,0,.4),inset 0 1px 0 rgba(255,255,255,.04)}
.hero-banner::before{content:'';position:absolute;top:-80px;right:-80px;
  width:300px;height:300px;border-radius:50%;
  background:radial-gradient(circle,rgba(14,165,233,.07) 0%,transparent 65%);
  pointer-events:none}
.hero-banner::after{content:'';position:absolute;bottom:-60px;left:20%;
  width:200px;height:200px;border-radius:50%;
  background:radial-gradient(circle,rgba(124,58,237,.05) 0%,transparent 65%);
  pointer-events:none}
.hero-banner-inner{padding:28px 32px 24px;position:relative;z-index:1}
.hero-top{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;margin-bottom:20px}
.hero-identity{flex:1;min-width:0}
.hero-identity-title{font-size:16px;font-weight:700;color:#e2e8f0;
  letter-spacing:-.02em;margin-bottom:14px}
.hero-identity-sep{opacity:.3;margin:0 6px}
.hero-meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:4px 24px}
.hero-meta-row{display:flex;gap:8px;align-items:baseline;min-width:0}
.hero-meta-key{font-size:10px;font-weight:700;color:rgba(255,255,255,.3);
  text-transform:uppercase;letter-spacing:.07em;min-width:70px;flex-shrink:0}
.hero-meta-val{font-size:12px;color:rgba(255,255,255,.75);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hero-code{background:rgba(56,189,248,.1);padding:1px 6px;border-radius:4px;
  border:1px solid rgba(56,189,248,.2);color:#7dd3fc;font-family:monospace;font-size:.9em}

/* Dual indicators */
.hero-indicators{display:flex;gap:20px;flex-wrap:wrap;margin-bottom:16px;align-items:flex-start}
.indicator-block{flex:1;min-width:160px}
.indicator-label{font-size:10px;font-weight:700;color:rgba(255,255,255,.35);
  text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px}
.indicator-value{font-size:22px;font-weight:800;letter-spacing:-.03em;line-height:1.1}
.indicator-sub{font-size:10px;color:rgba(255,255,255,.35);margin-top:3px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:260px}
:root:not([data-theme="dark"]) .indicator-label{color:rgba(30,40,64,.40)}
:root:not([data-theme="dark"]) .indicator-sub{color:rgba(30,40,64,.45)}

/* Risk bar */
.risk-bar-section{margin-bottom:16px}
.risk-bar-header{display:flex;align-items:baseline;justify-content:space-between;
  margin-bottom:6px}
.risk-bar-title{font-size:10px;font-weight:700;color:rgba(255,255,255,.35);
  text-transform:uppercase;letter-spacing:.1em}
.risk-bar-score{font-size:22px;font-weight:800;letter-spacing:-.04em}
.risk-bar-track{height:8px;background:rgba(255,255,255,.06);border-radius:4px;
  overflow:hidden;position:relative}
.risk-bar-fill{height:100%;border-radius:4px;
  transition:width 1.6s cubic-bezier(.22,.61,.36,1);
  box-shadow:0 0 12px currentColor}
.risk-bar-label{font-size:10px;font-weight:700;letter-spacing:.1em;
  text-transform:uppercase;margin-top:4px;display:block;text-align:right}

/* Stat chips */
.hero-chips{display:flex;gap:10px;flex-wrap:wrap;margin-top:4px}
.hero-chip{display:flex;flex-direction:column;align-items:center;
  padding:10px 18px;border-radius:10px;min-width:64px;
  background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);
  transition:transform var(--trans),background var(--trans)}
.hero-chip:hover{transform:translateY(-2px);background:rgba(255,255,255,.07)}
.hero-chip-val{font-size:22px;font-weight:800;color:var(--chip-c,#38bdf8);line-height:1}
.hero-chip-label{font-size:9px;font-weight:700;color:rgba(255,255,255,.35);
  text-transform:uppercase;letter-spacing:.09em;margin-top:3px}

/* ── Light-mode hero overrides ──────────────────────────────────────────── */
:root:not([data-theme="dark"]) .hero-banner{
  background:linear-gradient(135deg,#ffffff 0%,#eef4ff 60%,#e6f0ff 100%);
  border-color:#c7d9f5;
  box-shadow:0 2px 20px rgba(30,40,100,.08),inset 0 1px 0 rgba(255,255,255,.9)}
:root:not([data-theme="dark"]) .hero-banner::before{
  background:radial-gradient(circle,rgba(14,165,233,.06) 0%,transparent 65%)}
:root:not([data-theme="dark"]) .hero-identity-title{color:#1e2840}
:root:not([data-theme="dark"]) .hero-meta-key{color:rgba(30,40,64,.45)}
:root:not([data-theme="dark"]) .hero-meta-val{color:#1e2840}
:root:not([data-theme="dark"]) .hero-code{background:#e8f0ff;border-color:#c0d0f0;color:#1d4ed8}
:root:not([data-theme="dark"]) .risk-bar-title{color:rgba(30,40,64,.45)}
:root:not([data-theme="dark"]) .risk-bar-track{background:rgba(30,40,64,.08)}
:root:not([data-theme="dark"]) .hero-chip{
  background:rgba(30,40,64,.05);border-color:rgba(30,40,64,.1)}
:root:not([data-theme="dark"]) .hero-chip:hover{background:rgba(30,40,64,.09)}
:root:not([data-theme="dark"]) .hero-chip-label{color:rgba(30,40,64,.45)}
/* Gauge track + sub-label — theme-aware via class */
.gauge-track{stroke:rgba(255,255,255,.08)}
.gauge-sub{fill:rgba(255,255,255,.35)}
:root:not([data-theme="dark"]) .gauge-track{stroke:#e2e8f0}
:root:not([data-theme="dark"]) .gauge-sub{fill:#94a3b8}

/* ── SVG Area Chart ──────────────────────────────────────────────────────── */
.area-chart-outer{padding:16px 0 8px;overflow:hidden}
.area-chart-svg{width:100%;height:180px;display:block;overflow:visible}
.area-chart-axis{font-size:10px;fill:var(--text3);font-family:monospace}
.area-chart-grid-line{stroke:var(--border);stroke-width:1}
.area-chart-area{fill:url(#area-gradient)}
.area-chart-line{fill:none;stroke:var(--cyan);stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.area-chart-dot{fill:var(--cyan);stroke:var(--card);stroke-width:2;r:4;cursor:default;
  transition:r .15s}
.area-chart-dot:hover{r:6}

/* ── Category contribution breakdown ─────────────────────────────────────── */
.cat-breakdown-list{display:flex;flex-direction:column;gap:8px;margin-top:8px}
.cat-breakdown-row{display:flex;align-items:center;gap:10px}
.cat-breakdown-name{font-size:11px;font-weight:700;color:var(--text2);
  width:100px;flex-shrink:0;font-family:monospace;letter-spacing:.03em}
.cat-breakdown-track{flex:1;height:20px;background:rgba(255,255,255,.05);
  border-radius:4px;overflow:hidden;position:relative;border:1px solid var(--border)}
.cat-breakdown-fill{height:100%;border-radius:3px;
  transition:width 1s cubic-bezier(.22,.61,.36,1);
  display:flex;align-items:center;padding-left:6px;white-space:nowrap}
.cat-breakdown-fill-text{font-size:10px;font-weight:700;color:rgba(255,255,255,.9)}
.cat-breakdown-pts{font-size:11px;font-weight:700;color:var(--text3);
  width:50px;text-align:right;flex-shrink:0;font-family:monospace}
.cat-breakdown-conf{font-size:9px;color:var(--text3);width:36px;flex-shrink:0;text-align:right}

/* ── Section staggered entrance ─────────────────────────────────────────── */
.section{animation-delay:calc(var(--i,0)*60ms)}
.section:nth-child(1){--i:0}.section:nth-child(2){--i:1}
.section:nth-child(3){--i:2}.section:nth-child(4){--i:3}
.section:nth-child(5){--i:4}.section:nth-child(6){--i:5}

/* ── Gauge glow (dark mode only) ─────────────────────────────────────────── */
"""

# ─── JavaScript ───────────────────────────────────────────────────────────────

_JS = r"""
(function() {
  const DATA = window.REPORT_DATA;

  // ── Particles ──────────────────────────────────────────────────────────────
  const canvas = document.getElementById('particles-bg');
  if (canvas) {
    const ctx = canvas.getContext('2d');
    let W, H, pts = [];
    const N = 60, MAX_D = 120;
    function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
    function init() {
      pts = Array.from({length: N}, () => ({
        x: Math.random() * W, y: Math.random() * H,
        vx: (Math.random() - .5) * .35, vy: (Math.random() - .5) * .35,
        r: Math.random() * 1.5 + .4
      }));
    }
    function draw() {
      ctx.clearRect(0, 0, W, H);
      pts.forEach(p => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > W) p.vx *= -1;
        if (p.y < 0 || p.y > H) p.vy *= -1;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(14,165,233,.3)'; ctx.fill();
      });
      for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          const dx = pts[i].x - pts[j].x, dy = pts[i].y - pts[j].y;
          const d = Math.sqrt(dx*dx + dy*dy);
          if (d < MAX_D) {
            ctx.beginPath(); ctx.moveTo(pts[i].x, pts[i].y); ctx.lineTo(pts[j].x, pts[j].y);
            ctx.strokeStyle = `rgba(14,165,233,${.08*(1-d/MAX_D)})`; ctx.lineWidth = .5; ctx.stroke();
          }
        }
      }
      requestAnimationFrame(draw);
    }
    window.addEventListener('resize', () => { resize(); init(); });
    resize(); init(); draw();
  }

  // ── Risk Gauge ─────────────────────────────────────────────────────────────
  const gaugeSvg = document.getElementById('gauge-svg');
  if (gaugeSvg && DATA) {
    const score = DATA.risk_score;
    const arc = gaugeSvg.querySelector('#gauge-arc');
    const txt = gaugeSvg.querySelector('#gauge-txt');
    const R = 58, C = 2 * Math.PI * R;
    arc.setAttribute('stroke-dasharray', C);
    arc.setAttribute('stroke-dashoffset', C);
    const colors = {CRITICAL:'#dc2626',HIGH:'#ea580c',MEDIUM:'#d97706',LOW:'#0284c7',MINIMAL:'#16a34a'};
    const col = colors[DATA.risk_label] || '#64748b';
    arc.setAttribute('stroke', col);
    setTimeout(() => {
      arc.style.transition = 'stroke-dashoffset 1.4s cubic-bezier(.22,.61,.36,1)';
      arc.setAttribute('stroke-dashoffset', C * (1 - score / 100));
      if (txt) { txt.textContent = score; txt.setAttribute('fill', col); }
    }, 400);
    const lbl = gaugeSvg.closest('.gauge-wrap') && gaugeSvg.closest('.gauge-wrap').querySelector('.gauge-label');
    if (lbl) { lbl.textContent = DATA.risk_label; lbl.style.color = col; }
  }

  // ── Risk progress bar animation ─────────────────────────────────────────────
  const riskBar = document.getElementById('risk-bar-fill');
  if (riskBar && DATA) {
    const target = parseInt(riskBar.dataset.target, 10);
    setTimeout(() => { riskBar.style.width = target + '%'; }, 300);
  }

  // ── SVG Area Chart — rendered server-side in Python (see _render_area_chart_svg)
  // JS rendering removed: getElementById only found one of 4 period-view copies,
  // and entries.length >= 2 caused blank charts for single-month dumps.
  if (false && DATA && DATA.monthly_counts) {
    const entries = Object.entries(DATA.monthly_counts).sort((a,b) => a[0].localeCompare(b[0]));
    if (entries.length >= 2) {
      const W = 700, H = 160, padL = 44, padR = 16, padT = 10, padB = 28;
      const vals = entries.map(e => e[1]);
      const maxV = Math.max(...vals) || 1;
      const scaleX = i => padL + i * (W - padL - padR) / (entries.length - 1);
      const scaleY = v => padT + (H - padT - padB) * (1 - v / maxV);
      // Build path points
      const pts = entries.map((e, i) => [scaleX(i), scaleY(e[1])]);
      const linePath = pts.map((p, i) => (i === 0 ? `M${p[0]},${p[1]}` : `L${p[0]},${p[1]}`)).join(' ');
      const areaPath = `${linePath} L${pts[pts.length-1][0]},${H-padB} L${pts[0][0]},${H-padB} Z`;
      // Grid lines
      const gridVals = [0, Math.round(maxV*0.25), Math.round(maxV*0.5), Math.round(maxV*0.75), maxV];
      let svgHtml = `<defs>
        <linearGradient id="area-gradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#0ea5e9" stop-opacity="0.25"/>
          <stop offset="100%" stop-color="#0ea5e9" stop-opacity="0"/>
        </linearGradient>
        <clipPath id="area-clip">
          <rect x="${padL}" y="${padT}" width="${W-padL-padR}" height="${H-padT-padB}" rx="2"/>
        </clipPath>
      </defs>`;
      // Grid
      gridVals.forEach(v => {
        const y = scaleY(v);
        svgHtml += `<line class="area-chart-grid-line" x1="${padL}" y1="${y}" x2="${W-padR}" y2="${y}"/>`;
        svgHtml += `<text class="area-chart-axis" x="${padL-4}" y="${y+3}" text-anchor="end">${v}</text>`;
      });
      // X axis labels (show every label or every other if many)
      const step = entries.length > 8 ? Math.ceil(entries.length / 8) : 1;
      entries.forEach((e, i) => {
        if (i % step === 0 || i === entries.length - 1) {
          svgHtml += `<text class="area-chart-axis" x="${scaleX(i)}" y="${H-padB+14}" text-anchor="middle">${e[0]}</text>`;
        }
      });
      // Area + line with clip
      svgHtml += `<g clip-path="url(#area-clip)">`;
      svgHtml += `<path class="area-chart-area" d="${areaPath}"/>`;
      svgHtml += `<path class="area-chart-line" id="area-line-path" d="${linePath}" stroke-dasharray="9999" stroke-dashoffset="9999"/>`;
      svgHtml += `</g>`;
      // Dots with tooltips
      pts.forEach((p, i) => {
        svgHtml += `<circle class="area-chart-dot" cx="${p[0]}" cy="${p[1]}" r="4" data-tip="${entries[i][0]}: ${entries[i][1]} events"/>`;
      });
      areaChartEl.innerHTML = svgHtml;
      // Animate line drawing
      const linePath2 = areaChartEl.querySelector('#area-line-path');
      if (linePath2) {
        const len = linePath2.getTotalLength ? linePath2.getTotalLength() : 9999;
        linePath2.setAttribute('stroke-dasharray', len);
        linePath2.setAttribute('stroke-dashoffset', len);
        setTimeout(() => {
          linePath2.style.transition = 'stroke-dashoffset 1.8s cubic-bezier(.22,.61,.36,1)';
          linePath2.setAttribute('stroke-dashoffset', 0);
        }, 500);
      }
    }
  }

  // ── Category breakdown bars ─────────────────────────────────────────────────
  document.querySelectorAll('.cat-breakdown-fill[data-pct]').forEach(bar => {
    bar.style.width = '0%';
    const obs = new IntersectionObserver(entries => {
      if (!entries[0].isIntersecting) return;
      obs.disconnect();
      setTimeout(() => { bar.style.width = bar.dataset.pct + '%'; }, 120);
    }, {threshold: .1});
    obs.observe(bar);
  });

  // ── Donut Chart ────────────────────────────────────────────────────────────
  const donutSvg = document.getElementById('donut-svg');
  if (donutSvg && DATA) {
    const sevs = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
    const colors = {CRITICAL:'#dc2626',HIGH:'#ea580c',MEDIUM:'#d97706',LOW:'#0284c7',INFO:'#64748b'};
    const bySev = DATA.by_severity || {};
    const total = Object.values(bySev).reduce((a,b)=>a+b, 0);
    if (total > 0) {
      let offset = -90, r = 40, cx = 60, cy = 60, strokeW = 18;
      const C2 = 2 * Math.PI * r;
      sevs.forEach((s, idx) => {
        const count = bySev[s] || 0;
        if (!count) return;
        const pct = count / total, dash = pct * C2, gap = C2 - dash;
        const circle = document.createElementNS('http://www.w3.org/2000/svg','circle');
        circle.setAttribute('cx', cx); circle.setAttribute('cy', cy); circle.setAttribute('r', r);
        circle.setAttribute('fill','none'); circle.setAttribute('stroke', colors[s]);
        circle.setAttribute('stroke-width', strokeW);
        circle.setAttribute('stroke-dasharray', `0 ${C2}`);
        circle.setAttribute('stroke-dashoffset', -(offset / 360) * C2);
        circle.style.transition = `stroke-dasharray .9s cubic-bezier(.22,.61,.36,1) ${idx*.1}s`;
        donutSvg.insertBefore(circle, donutSvg.querySelector('#donut-center'));
        setTimeout(() => { circle.setAttribute('stroke-dasharray', `${dash} ${gap}`); }, 300);
        offset += pct * 360;
      });
    }
  }

  // ── Animated Counters ──────────────────────────────────────────────────────
  document.querySelectorAll('[data-counter]').forEach(el => {
    const val = parseInt(el.dataset.counter, 10);
    if (isNaN(val)) return;
    const obs = new IntersectionObserver(entries => {
      if (!entries[0].isIntersecting) return;
      obs.disconnect();
      let cur = 0; const steps = 60, inc = val / steps;
      const t = setInterval(() => {
        cur = Math.min(cur + inc, val);
        el.textContent = Math.round(cur).toLocaleString();
        if (cur >= val) clearInterval(t);
      }, 16);
    }, {threshold: .3});
    obs.observe(el);
  });

  // ── Sidebar active link ────────────────────────────────────────────────────
  const navLinks = document.querySelectorAll('.nav-link[href^="#"]');
  const _visibleSections = new Set();
  let _clickLock = false;

  function _setActiveLink(id) {
    navLinks.forEach(l => l.classList.toggle('active', l.getAttribute('href') === '#' + id));
  }

  function _pickBestSection() {
    // Among all currently intersecting sections, pick the one whose top is
    // closest to the top of the viewport — avoids flicker when multiple
    // sections are simultaneously in view.
    let best = null, bestDist = Infinity;
    _visibleSections.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      const dist = Math.abs(el.getBoundingClientRect().top);
      if (dist < bestDist) { bestDist = dist; best = id; }
    });
    if (best) _setActiveLink(best);
  }

  const observer = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) _visibleSections.add(e.target.id);
      else _visibleSections.delete(e.target.id);
    });
    // Don't override the active state right after a click — let the
    // scroll settle first (100 ms lock).
    if (!_clickLock) _pickBestSection();
  }, {threshold: 0.1, rootMargin: '-5% 0px -50% 0px'});

  document.querySelectorAll('.section[id]').forEach(s => observer.observe(s));

  // On click: immediately highlight the target link, then lock briefly so the
  // observer doesn't override it while the smooth-scroll animation runs.
  navLinks.forEach(link => {
    link.addEventListener('click', () => {
      _setActiveLink(link.getAttribute('href').slice(1));
      _clickLock = true;
      setTimeout(() => { _clickLock = false; _pickBestSection(); }, 800);
    });
  });

  // ── Findings filter — radio behaviour (one severity at a time) ─────────────
  const findingsContainer = document.getElementById('findings-list');
  const searchInput = document.getElementById('findings-search');
  const sevBtns = document.querySelectorAll('.sev-btn');
  const countLabel = document.getElementById('findings-count');
  let activeFilter = 'ALL'; // single active severity or 'ALL'

  if (findingsContainer) {
    function renderFindings() {
      const q = searchInput ? searchInput.value.toLowerCase().trim() : '';
      let shown = 0;
      findingsContainer.querySelectorAll('.finding-card').forEach(card => {
        const sevOk = activeFilter === 'ALL' || card.dataset.sev === activeFilter;
        const qOk   = !q || (card.dataset.search || '').includes(q);
        const show  = sevOk && qOk;
        card.style.display = show ? '' : 'none';
        if (show) shown++;
      });
      if (countLabel) countLabel.textContent = shown + ' finding' + (shown !== 1 ? 's' : '');
    }

    if (searchInput) searchInput.addEventListener('input', renderFindings);

    sevBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const sev = btn.dataset.sev;
        if (sev === 'ALL' || sev === activeFilter) {
          // Clicking ALL or re-clicking active filter → reset to ALL
          activeFilter = 'ALL';
        } else {
          // Single-select: show only this severity
          activeFilter = sev;
        }
        sevBtns.forEach(b => b.classList.toggle('active', b.dataset.sev === activeFilter));
        renderFindings();
      });
    });

    renderFindings();
  }

  // ── Expand/collapse finding cards ─────────────────────────────────────────
  document.addEventListener('click', e => {
    const hdr = e.target.closest('.finding-header');
    if (hdr) hdr.closest('.finding-card').classList.toggle('open');
  });

  // ── Bar charts ─────────────────────────────────────────────────────────────
  document.querySelectorAll('.chart-bar[data-pct]').forEach(bar => {
    bar.style.width = '0%';
    const obs = new IntersectionObserver(entries => {
      if (!entries[0].isIntersecting) return;
      obs.disconnect();
      setTimeout(() => { bar.style.width = bar.dataset.pct + '%'; }, 100);
    }, {threshold: .1});
    obs.observe(bar);
  });

  // ── Tooltips ───────────────────────────────────────────────────────────────
  const tip = document.getElementById('tooltip-el');
  if (tip) {
    let tipTO = null;
    document.addEventListener('mousemove', e => {
      const target = e.target.closest('[data-tip]');
      if (target && target.dataset.tip) {
        clearTimeout(tipTO);
        tip.textContent = target.dataset.tip;
        tip.classList.add('visible');
        tip.style.left = Math.min(e.clientX + 14, window.innerWidth - 320) + 'px';
        tip.style.top  = Math.min(e.clientY + 14, window.innerHeight - 80) + 'px';
      } else {
        tipTO = setTimeout(() => tip.classList.remove('visible'), 80);
      }
    });
    document.addEventListener('mouseleave', () => tip.classList.remove('visible'));
  }

  // ── System Activity search ─────────────────────────────────────────────────
  const actSrch = document.getElementById('activity-search');
  if (actSrch) {
    const actClear  = document.getElementById('activity-search-clear');
    const actCount  = document.getElementById('activity-count');
    const actNone   = document.getElementById('activity-no-results');
    const actTbody  = document.getElementById('activity-install-tbody');
    function runActivityFilter(q) {
      if (!actTbody) return;
      const term = q.toLowerCase().trim();
      let vis = 0, total = 0;
      actTbody.querySelectorAll('tr[data-search]').forEach(row => {
        total++;
        const match = !term || row.dataset.search.includes(term);
        row.style.display = match ? '' : 'none';
        if (match) vis++;
      });
      if (actCount) actCount.textContent = term ? vis + ' / ' + total + ' results' : '';
      if (actNone)  actNone.style.display = (term && vis === 0) ? '' : 'none';
      if (actClear) actClear.style.display = term ? '' : 'none';
    }
    actSrch.addEventListener('input', e => runActivityFilter(e.target.value));
    if (actClear) actClear.addEventListener('click', () => {
      actSrch.value = ''; runActivityFilter(''); actSrch.focus();
    });
  }

  // ── Copy to clipboard ─────────────────────────────────────────────────────
  const toast = document.getElementById('copy-toast');
  document.addEventListener('click', e => {
    const btn = e.target.closest('.ioc-copy');
    if (!btn) return;
    const text = btn.closest('.ioc-item')?.querySelector('.ioc-text')?.textContent?.trim() || '';
    navigator.clipboard.writeText(text).then(() => {
      if (toast) { toast.classList.add('show'); setTimeout(() => toast.classList.remove('show'), 1800); }
    });
  });

  // ── Dark / Light theme toggle ──────────────────────────────────────────────
  const themeToggle = document.getElementById('theme-toggle');
  const html = document.documentElement;
  const THEME_KEY = 'mla-theme';
  function applyTheme(theme) {
    html.setAttribute('data-theme', theme);
    if (themeToggle) {
      themeToggle.querySelector('.theme-toggle-icon').textContent = theme === 'dark' ? '☀️' : '🌙';
      themeToggle.querySelector('.theme-toggle-text').textContent = theme === 'dark' ? 'Light mode' : 'Dark mode';
    }
    // Update gauge glow color based on current risk color
    const gaugeSvgEl = document.getElementById('gauge-svg');
    if (gaugeSvgEl && DATA) {
      const glowColors = {CRITICAL:'rgba(220,38,38,.4)',HIGH:'rgba(234,88,12,.4)',MEDIUM:'rgba(217,119,6,.4)',LOW:'rgba(2,132,199,.4)',MINIMAL:'rgba(22,163,74,.4)'};
      gaugeSvgEl.style.setProperty('--gauge-glow', glowColors[DATA.risk_label] || 'rgba(14,165,233,.35)');
    }
  }
  const saved = localStorage.getItem(THEME_KEY) || 'dark';
  applyTheme(saved);
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      localStorage.setItem(THEME_KEY, next);
      applyTheme(next);
    });
  }

  // ── Activity heatmap — rendered server-side in Python (see _render_heatmap_html)
  // JS rendering removed: getElementById only found the first period-view copy.
  if (false && DATA && DATA.mr_daily_counts) {
    const counts = DATA.mr_daily_counts;
    const dates  = Object.keys(counts).sort();
    if (dates.length > 0) {
      const maxVal = Math.max(...Object.values(counts));
      function hmLevel(v) {
        if (!v) return 0;
        const r = v / maxVal;
        if (r < .25) return 1;
        if (r < .50) return 2;
        if (r < .75) return 3;
        return 4;
      }
      // Build a map from date string → count
      const dateMap = counts;
      // Determine range: first Sunday before first date → last Saturday after last date
      const first = new Date(dates[0] + 'T00:00:00Z');
      const last  = new Date(dates[dates.length-1] + 'T00:00:00Z');
      // Start from Sunday of week containing first date
      const startDay = new Date(first);
      startDay.setUTCDate(first.getUTCDate() - first.getUTCDay());
      // End on Saturday of week containing last date
      const endDay = new Date(last);
      endDay.setUTCDate(last.getUTCDate() + (6 - last.getUTCDay()));

      // Render month labels + columns
      let html_str = '<div class="heatmap-wrap">';
      // Month row
      html_str += '<div style="display:flex;gap:3px;margin-bottom:4px;padding-left:0">';
      let cur = new Date(startDay), prevMonth = -1, colIdx = 0, monthLabels = [];
      while (cur <= endDay) {
        if (cur.getUTCMonth() !== prevMonth) {
          monthLabels.push({col: colIdx, label: cur.toLocaleString('en', {month:'short',timeZone:'UTC'})});
          prevMonth = cur.getUTCMonth();
        }
        cur.setUTCDate(cur.getUTCDate() + 7);
        colIdx++;
      }
      const totalCols = colIdx;
      // Build month label spans
      let mlHtml = '';
      for (let i = 0; i < monthLabels.length; i++) {
        const span = (i + 1 < monthLabels.length ? monthLabels[i+1].col : totalCols) - monthLabels[i].col;
        mlHtml += `<span class="heatmap-month-label" style="width:${span * 19}px;display:inline-block">${monthLabels[i].label}</span>`;
      }
      html_str += mlHtml + '</div>';
      // Cells
      html_str += '<div class="heatmap-grid">';
      cur = new Date(startDay);
      for (let col = 0; col < totalCols; col++) {
        html_str += '<div class="heatmap-col">';
        for (let row = 0; row < 7; row++) {
          const d = new Date(cur); d.setUTCDate(cur.getUTCDate() + row);
          const ds = d.toISOString().slice(0,10);
          const v  = dateMap[ds] || 0;
          const lvl = hmLevel(v);
          const tip = v ? `${ds}: ${v} event${v!==1?'s':''}` : ds;
          html_str += `<div class="heatmap-cell hm-${lvl}" data-tip="${tip}"></div>`;
        }
        html_str += '</div>';
        cur.setUTCDate(cur.getUTCDate() + 7);
      }
      html_str += '</div></div>';
      heatmapEl.innerHTML = html_str;
    }
  }

  // ── Period filter — swaps pre-computed server-side analysis blocks ───────────
  var _PERIOD_COLS = {CRITICAL:'#dc2626',HIGH:'#ea580c',MEDIUM:'#d97706',LOW:'#0284c7',MINIMAL:'#16a34a'};
  window.filterPeriod = function(days) {
    // Update button active state
    document.querySelectorAll('.period-btn').forEach(function(b) {
      b.classList.toggle('active', parseInt(b.dataset.days) === days);
    });
    // Show the matching period-view, hide all others
    document.querySelectorAll('.period-view').forEach(function(el) {
      el.style.display = parseInt(el.dataset.period) === days ? 'block' : 'none';
    });
    // Update the "ref" label in the period bar
    var lbl = document.getElementById('period-active-label');
    if (lbl) {
      var names = {0: 'All', 1: '24 hours', 7: '7 days', 30: '30 days'};
      lbl.textContent = names[days] || '';
    }
    // ── Update all dynamic indicators from pre-computed period data ──────────
    if (DATA && DATA.periods) {
      var pd = DATA.periods[String(days)];
      if (pd) {
        var score = pd.score;
        var label = pd.label;
        var count = pd.count;
        var bySev = pd.by_sev || {};
        var col = _PERIOD_COLS[label] || '#64748b';
        // Nav findings badge
        var badge = document.getElementById('nav-findings-badge');
        if (badge) {
          badge.textContent = count;
          badge.style.display = count > 0 ? '' : 'none';
        }
        // Nav risk score
        var navScore = document.getElementById('nav-risk-score');
        if (navScore) {
          navScore.textContent = score + '/100';
          navScore.style.color = col;
        }
        // Hero gauge arc + text
        var arc = document.getElementById('gauge-arc');
        var gaugeTxt = document.getElementById('gauge-txt');
        if (arc) {
          var R = 58, C = 2 * Math.PI * R;
          arc.setAttribute('stroke', col);
          arc.style.transition = 'stroke-dashoffset .8s cubic-bezier(.22,.61,.36,1)';
          arc.setAttribute('stroke-dasharray', String(C));
          arc.setAttribute('stroke-dashoffset', String(C * (1 - score / 100)));
        }
        if (gaugeTxt) { gaugeTxt.textContent = score; gaugeTxt.setAttribute('fill', col); }
        // Hero risk bar
        var riskBar = document.getElementById('risk-bar-fill');
        if (riskBar) { riskBar.style.background = col; riskBar.style.width = score + '%'; }
        // Hero risk score number
        var riskNum = document.getElementById('risk-score-num');
        if (riskNum) { riskNum.textContent = score; }
        // Hero chips
        var totalChip = document.getElementById('hero-chip-total');
        if (totalChip) {
          var tv = totalChip.querySelector('.hero-chip-val');
          if (tv) tv.textContent = count;
        }
        ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].forEach(function(s) {
          var chip = document.getElementById('hero-chip-' + s.toLowerCase());
          if (chip) {
            var cnt = bySev[s] || 0;
            var v = chip.querySelector('.hero-chip-val');
            if (v) v.textContent = cnt;
            chip.style.display = cnt > 0 ? '' : 'none';
          }
        });
      }
    }
    try { sessionStorage.setItem('periodFilter', String(days)); } catch(e) {}
  };

  // Restore saved period on load (default: Tout = 0)
  (function() {
    var saved = sessionStorage.getItem('periodFilter');
    window.filterPeriod(saved !== null ? parseInt(saved) : 0);
  })();

})();
"""

# ─── Section builders ─────────────────────────────────────────────────────────

def _nav(findings: list[Finding], by_sev: dict[str, int], ctx: "SystemContext | None" = None) -> str:
    score, label = _risk_score(findings, ctx)
    col = SEV_COLOR.get(label, "#64748b")
    health_level, health_col, _ = _agent_health_score(ctx) if ctx else ("HEALTHY", "#16a34a", [])
    count = len(findings)
    # Items: tuple of (id, icon, label) for links; tuple of (label,) for group headers
    items: list = [
        ("s-header",    "&#x1F3E0;", "Report"),
        ("s-alerts",    "&#x1F6A8;", "Alerts"),
        ("s-brief",     "&#x1F4CB;", "Quick Brief"),
        ("s-summary",   "&#x1F4CA;", "Summary"),
        ("System",),
        ("s-system",    "&#x1F4BB;", "System Context"),
        ("s-perf",      "&#x1F4CA;", "Performance"),
        ("s-network",   "&#x1F310;", "Network"),
        ("s-services",  "&#x2699;",  "Services"),
        ("s-activity",  "&#x1F4E6;", "System Activity"),
        ("SentinelOne Agent",),
        ("s-agent",     "&#x1F6E1;", "S1 Agent"),
        ("s-comms",     "&#x1F4E1;", "Comm. Analysis"),
        ("Security Analysis",),
        ("s-processes", "&#x1F50E;", "Processes"),
        ("s-findings",  "&#x1F4A1;", "Findings"),
        ("s-ioc",       "&#x26A0;",  "IOC"),
        ("s-timeline",  "&#x1F4C5;", "Timeline"),
        ("s-stats",     "&#x1F4C8;", "Statistics"),
        ("s-intel",     "&#x1F9EC;", "Threat Intel"),
        ("s-blindspots","&#x1F441;", "Blind Spots"),
    ]
    links = ""
    for item in items:
        if len(item) == 1:
            links += f'<div class="nav-group">{_esc(item[0])}</div>'
        else:
            sid, icon, lbl = item
            if sid == "s-findings":
                _hide = ';display:none' if not count else ''
                badge = (
                    f'<span id="nav-findings-badge" class="nav-badge"'
                    f' style="background:#fee2e2;color:#dc2626{_hide}">{count}</span>'
                )
            else:
                badge = ""
            links += (
                f'<a class="nav-link" href="#{sid}">'
                f'<span class="nav-icon">{icon}</span>{_esc(lbl)}{badge}</a>'
            )
    health_tip = _esc(_HEALTH_TOOLTIP.get(health_level, ""))
    sec_tip    = _esc(SEV_TOOLTIP.get(label, ""))
    return (
        f'<nav class="sidebar">'
        f'<div class="sidebar-brand"><h1>S1 macOS Log Analyzer</h1>'
        f'<p>SentinelOne Report</p>'
        f'<p style="font-size:10px;color:rgba(255,255,255,.25);margin-top:3px">by Florian Bertaux · v{APP_VERSION}</p>'
        f'</div>'
        f'<div class="sidebar-indicators">'
        # Agent Health indicator
        f'<div class="sidebar-indicator" data-tip="{health_tip}">'
        f'<span class="sidebar-indicator-label">Agent Health</span>'
        f'<span class="sidebar-indicator-val" style="color:{_esc(health_col)}">{_esc(health_level)}</span>'
        f'</div>'
        # Security Risk indicator
        f'<div class="sidebar-indicator" data-tip="{sec_tip}">'
        f'<span class="sidebar-indicator-label">Security Risk</span>'
        f'<span id="nav-risk-score" class="sidebar-indicator-val" style="color:{_esc(col)}">{score}/100</span>'
        f'</div>'
        f'</div>'
        f'<div class="sidebar-period">'
        f'<span class="sidebar-period-label">Analysis Period</span>'
        f'<div class="sidebar-period-btns">'
        f'<button class="period-btn" data-days="1" onclick="filterPeriod(1)">24h</button>'
        f'<button class="period-btn" data-days="7" onclick="filterPeriod(7)">7 days</button>'
        f'<button class="period-btn" data-days="30" onclick="filterPeriod(30)">30 days</button>'
        f'<button class="period-btn active" data-days="0" onclick="filterPeriod(0)">All</button>'
        f'</div>'
        f'</div>'
        f'{links}'
        f'<button id="theme-toggle" class="theme-toggle">'
        f'<span class="theme-toggle-icon">🌙</span>'
        f'<span class="theme-toggle-text">Dark mode</span>'
        f'</button>'
        f'</nav>'
    )


def _hero(ctx: SystemContext, score: int, risk_label: str, now: datetime,
          findings: "list[Finding]" = None, by_sev: "dict[str,int]" = None,
          health_level: str = "HEALTHY", health_col: str = "#16a34a",
          health_reasons: "list[str]" = None) -> str:
    findings = findings or []
    by_sev   = by_sev or {}
    health_reasons = health_reasons or []
    col      = SEV_COLOR.get(risk_label, "#64748b")
    dump_date = _esc(ctx.parse_stats.get("dump_date", "Unknown"))

    # ── Stat chips ───────────────────────────────────────────────────────────
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    chip_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706",
                   "LOW": "#0284c7", "INFO": "#64748b"}
    chips_html = (
        f'<div class="hero-chip" id="hero-chip-total" style="--chip-c:#38bdf8">'
        f'<span class="hero-chip-val" data-counter="{len(findings)}">{len(findings)}</span>'
        f'<span class="hero-chip-label">Total</span>'
        f'</div>'
    ) + "".join(
        (
            f'<div class="hero-chip" id="hero-chip-{s.lower()}"'
            f' style="--chip-c:{chip_colors.get(s,"#64748b")}'
            + (';display:none' if not by_sev.get(s, 0) else '')
            + f'">'
            f'<span class="hero-chip-val" data-counter="{by_sev.get(s,0)}">{by_sev.get(s,0)}</span>'
            f'<span class="hero-chip-label">{s.title()}</span>'
            f'</div>'
        )
        for s in sev_order
    )

    # ── Dual indicator bar (Agent Health + Security Risk) ─────────────────────
    health_tip_str = _esc(_HEALTH_TOOLTIP.get(health_level, ""))
    health_reasons_str = _esc(" · ".join(health_reasons[:3]))
    _HEALTH_ICON = {"CRITICAL": "&#x1F534;", "DEGRADED": "&#x1F7E1;", "HEALTHY": "&#x1F7E2;"}
    health_icon = _HEALTH_ICON.get(health_level, "&#x26AA;")

    agent_health_block = (
        f'<div class="indicator-block" data-tip="{health_tip_str}">'
        f'<div class="indicator-label">Agent Health</div>'
        f'<div class="indicator-value" style="color:{_esc(health_col)}">'
        f'{health_icon} {_esc(health_level)}</div>'
        + (f'<div class="indicator-sub">{health_reasons_str}</div>' if health_reasons_str else '')
        + f'</div>'
    )

    risk_bar = (
        f'<div class="hero-indicators">'
        f'{agent_health_block}'
        f'<div class="indicator-block">'
        f'<div class="indicator-label">Security Risk</div>'
        f'<div class="indicator-value" style="color:{_esc(col)}"'
        f' data-tip="{_esc(SEV_TOOLTIP.get(risk_label, ""))}">'
        f'<span id="risk-score-num" data-counter="{score}">{score}</span>'
        f'<span style="font-weight:400;font-size:.65em;opacity:.55">/100 · {_esc(risk_label)}</span>'
        f'</div>'
        f'<div class="risk-bar-track" style="margin-top:6px">'
        f'<div class="risk-bar-fill" id="risk-bar-fill" style="background:{_esc(col)};width:0%"'
        f' data-target="{score}"></div>'
        f'</div>'
        f'</div>'
        f'</div>'
    )

    # ── Machine meta (compact two-column) ────────────────────────────────────
    meta_pairs = [
        ("Host", f'<strong>{_esc(ctx.hostname)}</strong> · {_esc(ctx.model)}'),
        ("OS",   _esc(f"{ctx.os_version} ({ctx.arch})")),
        ("User", f'<code class="hero-code">{_esc(ctx.primary_user)}</code>'),
        ("S1 Agent", _esc(ctx.agent_version) or "—"),
        ("Dump", dump_date),
        ("Analyzed", _esc(now.strftime("%Y-%m-%d %H:%M UTC"))),
    ]
    meta_html = "".join(
        f'<div class="hero-meta-row">'
        f'<span class="hero-meta-key">{_esc(k)}</span>'
        f'<span class="hero-meta-val">{v}</span>'
        f'</div>'
        for k, v in meta_pairs
    )

    # ── Gauge — Security Risk circular arc ───────────────────────────────────
    gauge = (
        '<div class="gauge-wrap" data-tip="Security Risk Score: weighted sum of detection findings">'
        '<svg id="gauge-svg" class="gauge-svg" width="130" height="130" viewBox="0 0 150 150">'
        '<circle class="gauge-track" cx="75" cy="75" r="58" fill="none" stroke-width="14"/>'
        '<circle id="gauge-arc" cx="75" cy="75" r="58" fill="none" stroke-width="14"'
        ' stroke-linecap="round" transform="rotate(-90 75 75)"'
        f' stroke="{_esc(col)}" stroke-dasharray="364.4" stroke-dashoffset="364.4"/>'
        f'<text id="gauge-txt" x="75" y="68" text-anchor="middle" dominant-baseline="middle"'
        f' font-size="30" font-weight="800" fill="{_esc(col)}">{score}</text>'
        '<text class="gauge-sub" x="75" y="87" text-anchor="middle" dominant-baseline="middle"'
        ' font-size="9">Security Risk</text>'
        '</svg>'
        '</div>'
    )

    return (
        f'<section id="s-header" class="section">'
        f'<div class="hero-banner">'
        f'<div class="hero-banner-inner">'
        f'<div class="hero-top">'
        f'<div class="hero-identity">'
        f'<div class="hero-identity-title">🛡 SentinelOne macOS Log Analyzer <span class="hero-identity-sep">·</span>'
        f' <span style="font-weight:400;opacity:.6;font-size:.85em">Security Report</span></div>'
        f'<div class="hero-meta-grid">{meta_html}</div>'
        f'</div>'
        f'{gauge}'
        f'</div>'
        f'{risk_bar}'
        f'<div class="hero-chips">{chips_html}</div>'
        f'</div>'
        f'</div>'
        f'</section>'
    )


def _summary(findings: list[Finding], by_sev: dict[str, int]) -> str:
    sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    cards = "".join(
        f'<div class="sev-card" style="--sev-c:{_esc(SEV_COLOR.get(s, "#445"))}"'
        f' data-tip="{_esc(SEV_TOOLTIP.get(s, ""))}">'
        f'<div class="sev-card-count" data-counter="{by_sev.get(s, 0)}">{by_sev.get(s, 0)}</div>'
        f'<div class="sev-card-label">{_esc(s)}</div>'
        f'</div>'
        for s in sevs
    )
    donut = (
        '<svg id="donut-svg" width="120" height="120" viewBox="0 0 120 120">'
        '<circle cx="60" cy="60" r="40" fill="none" stroke="#e2e8f0" stroke-width="18"/>'
        '<g id="donut-center">'
        f'<text x="60" y="56" text-anchor="middle" font-size="20" font-weight="800" fill="#dde4f0">{len(findings)}</text>'
        '<text x="60" y="70" text-anchor="middle" font-size="9" fill="rgba(255,255,255,.4)">findings</text>'
        '</g></svg>'
    )
    legend = "".join(
        f'<div class="legend-item" data-tip="{_esc(SEV_TOOLTIP.get(s, ""))}">'
        f'<span class="legend-dot" style="background:{_esc(SEV_COLOR.get(s,"#445"))};'
        f'color:{_esc(SEV_COLOR.get(s,"#445"))}"></span>'
        f'<span class="legend-name">{_esc(s)}</span>'
        f'<span class="legend-count" style="color:{_esc(SEV_COLOR.get(s,"#445"))}">{by_sev.get(s, 0)}</span>'
        f'</div>'
        for s in sevs if by_sev.get(s, 0)
    )
    top = [f for f in findings if f.severity in ("CRITICAL", "HIGH")][:5]
    top_html = ""
    if top:
        items_html = "".join(
            f'<div class="top-item">'
            f'<span class="top-item-id">{_esc(f.rule_id)}</span>'
            f'<div><div class="top-item-name">{_esc(f.rule_name)}</div>'
            f'<div class="top-item-proc">{_esc(f.process)}</div></div>'
            f'<span class="top-item-date">'
            f'{_esc(f.first_seen.strftime("%Y-%m-%d %H:%M")) if f.first_seen else "-"}'
            f'</span></div>'
            for f in top
        )
        top_html = (
            f'<div class="card" style="margin-top:20px"><div class="card-body">'
            f'<div class="stat-card-title">Immediate Action Items (CRITICAL / HIGH)</div>'
            f'{items_html}</div></div>'
        )
    return (
        f'<section id="s-summary" class="section">'
        f'<div class="section-header"><span class="section-icon">📊</span>'
        f'<h2 class="section-title">Executive Summary</h2></div>'
        + _sdesc(
            "All detection rules applied to match_reports, process data, configuration files, and system state.",
            "CRITICAL and HIGH counts drive the risk score. A large MEDIUM count with zero HIGH/CRITICAL may indicate "
            "normal operational noise. Each severity card links directly to its findings below. "
            "Rules are mapped to MITRE ATT&amp;CK tactics — hover any rule ID for the technique ID."
        )
        + f'<div class="sev-cards">{cards}</div>'
        f'<div class="card"><div class="card-body">'
        f'<div class="summary-grid"><div class="donut-legend">{legend}</div>'
        f'<div class="donut-container">{donut}</div></div>'
        f'</div></div>{top_html}'
        f'</section>'
    )


def _kv_table(rows: list[tuple[str, str]], tip: dict[str, str] | None = None) -> str:
    tip = tip or {}
    cells = "".join(
        f'<tr><td style="color:var(--text3);width:200px;font-size:12px;white-space:nowrap"'
        f' data-tip="{_esc(tip.get(k, ""))}">{_esc(k)}</td>'
        f'<td>{v}</td></tr>'
        for k, v in rows
    )
    return f'<table class="data-table"><tbody>{cells}</tbody></table>'


def _system_section(ctx: SystemContext) -> str:
    sip_status = (
        f'<span class="badge badge-ok">Enabled</span>' if ctx.sip_enabled
        else (f'<span class="badge badge-err">DISABLED</span>' if ctx.sip_enabled is False
              else '<span class="badge badge-info">Unknown</span>')
    )
    tip = {
        "SIP":            "System Integrity Protection — protects macOS system files from unauthorized modification, even by root.",
        "Boot Args":      "Kernel boot arguments. Non-empty values may indicate a modified or non-standard configuration.",
        "Agent UUID":     "Unique identifier for the SentinelOne agent on this endpoint.",
        "Console":        "URL of the SentinelOne management console this agent is registered to.",
        "Architecture":   "CPU architecture. arm64 = Apple Silicon; x86_64 = Intel.",
        "Serial Number":  "Hardware serial number from ioreg.txt (IOPlatformSerialNumber). Use to uniquely identify the physical device.",
        "Sleep Blocked":  "Processes currently preventing system sleep (from pmset-live.txt). Persistent non-system processes here may indicate background monitoring activity.",
    }
    sleep_blockers = (ctx.power_state or {}).get("sleep_preventing", [])
    sleep_html = (
        ", ".join(f'<code>{_esc(s)}</code>' for s in sleep_blockers)
        if sleep_blockers else '<span style="color:var(--text3)">None</span>'
    )
    rows = [
        ("Hostname",       f'<code>{_esc(ctx.hostname)}</code>'),
        ("Serial Number",  f'<code>{_esc(ctx.serial_number)}</code>' if ctx.serial_number else '<span style="color:var(--text3)">Not found</span>'),
        ("Model",          _esc(ctx.model)),
        ("OS",             _esc(ctx.os_version)),
        ("Architecture",   _esc(ctx.arch)),
        ("CPU",            _esc(f"{ctx.cpu_count} core(s)")),
        ("SIP",            sip_status),
        ("Boot Args",      f'<code>{_esc(ctx.boot_args or "(none)")}</code>'),
        ("Sleep Blocked",  sleep_html),
        ("Agent UUID",     f'<code>{_esc(ctx.agent_uuid or "Not found")}</code>'),
        ("Console",        (f'<a href="{_esc(ctx.console_url)}" target="_blank" rel="noopener">'
                            f'{_esc(ctx.console_url)}</a>') if ctx.console_url else "Not found"),
        ("Agent",          _esc(ctx.agent_version)),
    ]
    # ── Installed applications (categorized) ────────────────────────────────
    apps_html = ""
    if ctx.installed_apps:
        categorized = _categorize_apps(ctx.installed_apps)
        dual_av = [a for a in ctx.installed_apps if any(kw in a.lower() for kw in _DUAL_AV_NAMES)]
        dual_av_banner = ""
        if dual_av:
            dual_av_banner = (
                f'<div class="alert alert-warn" style="margin-bottom:10px">'
                f'<span class="alert-icon">&#9888;</span>'
                f'<div><strong>Dual Security Products Detected</strong> — '
                f'{", ".join(f"<code>{_esc(a)}</code>" for a in dual_av)} is installed alongside '
                f'SentinelOne. This may cause Endpoint Security Framework conflicts.</div></div>'
            )
        def _app_tooltip(name: str) -> str:
            m = ctx.installed_apps_meta.get(name)
            if not m:
                return _esc(name)
            install_label = (
                f"System install (owner: {m['owner']})"
                if m["install_type"] == "system"
                else f"User install (owner: {m['owner']})"
            )
            return _esc(
                f"{name}\n"
                f"Install type: {install_label}\n"
                f"Last modified: {m['modified']}\n"
                f"Group: {m['group']}"
            )

        rows_cats = ""
        for cat, apps_in_cat in categorized.items():
            is_security = cat == "Security"
            tags = "".join(
                f'<span class="app-tag {"app-tag-security" if is_security and any(kw in a.lower() for kw in _DUAL_AV_NAMES) else ""}"'
                f' data-tip="{_app_tooltip(a)}">{_esc(a)}</span>'
                for a in apps_in_cat
            )
            rows_cats += (
                f'<div class="app-cat-row">'
                f'<span class="app-cat-label">{_esc(cat)}</span>'
                f'<div>{tags}</div>'
                f'</div>'
            )
        apps_html = (
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label" data-tip="Applications installed in /Applications at dump time.">'
            f'Installed Applications ({len(ctx.installed_apps)})</div>'
            f'<div style="margin-top:8px">{dual_av_banner}'
            f'<div class="app-categories">{rows_cats}</div></div></div>'
        )

    # ── Privileged helper tools ──────────────────────────────────────────────
    helpers_html = ""
    if ctx.privileged_helpers:
        helper_tags = "".join(
            f'<span class="app-tag app-tag-warn" data-tip="Runs with elevated (root) privileges">'
            f'{_esc(h)}</span>'
            for h in ctx.privileged_helpers
        )
        helpers_html = (
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label" '
            f'data-tip="Tools registered as privileged helpers — they run as root and are started on demand.">'
            f'Privileged Helper Tools ({len(ctx.privileged_helpers)})</div>'
            f'<div style="margin-top:6px">{helper_tags}</div></div>'
        )

    # ── Kernel extensions ────────────────────────────────────────────────────
    kexts_html = ""
    if ctx.kernel_extensions:
        apple_kexts  = [k for k in ctx.kernel_extensions if k.startswith("com.apple")]
        s1_kexts     = [k for k in ctx.kernel_extensions if k.startswith("com.sentinelone")]
        third_kexts  = [k for k in ctx.kernel_extensions
                        if not k.startswith("com.apple") and not k.startswith("com.sentinelone")]
        kext_rows = ""
        for label, klist, css in (
            ("Apple", apple_kexts, ""),
            ("SentinelOne", s1_kexts, "style='color:var(--cyan)'"),
            ("Third-party", third_kexts, "style='color:var(--med)'"),
        ):
            if klist:
                tags = "".join(
                    f'<span class="app-tag {"app-tag-warn" if label == "Third-party" else ""}">'
                    f'{_esc(k)}</span>'
                    for k in klist
                )
                kext_rows += (
                    f'<div class="app-cat-row">'
                    f'<span class="app-cat-label" {css}>{_esc(label)} ({len(klist)})</span>'
                    f'<div>{tags}</div></div>'
                )
        warning = ""
        if third_kexts:
            warning = (
                f'<div class="alert alert-warn" style="margin-bottom:8px">'
                f'<span class="alert-icon">&#9888;</span>'
                f'<div><strong>{len(third_kexts)} third-party kernel extension(s) loaded</strong> — '
                f'kexts run in kernel space (ring 0) and bypass user-space isolation.</div></div>'
            )
        kexts_html = (
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label" '
            f'data-tip="Loaded kernel extensions — third-party kexts run in ring 0 and are a high-value attack target.">'
            f'Kernel Extensions ({len(ctx.kernel_extensions)})</div>'
            f'<div style="margin-top:8px">{warning}'
            f'<div class="app-categories">{kext_rows}</div></div></div>'
        )

    # ── Launch daemons ───────────────────────────────────────────────────────
    daemons_html = ""
    if ctx.launch_daemons:
        sentinel_d = [d for d in ctx.launch_daemons if "sentinel" in d.lower()]
        other_d    = [d for d in ctx.launch_daemons if "sentinel" not in d.lower()]
        dl = ""
        if sentinel_d:
            dl += f'<div style="font-size:10px;font-weight:700;color:var(--cyan);margin-bottom:4px;letter-spacing:.06em">SENTINELONE</div>'
            dl += "".join(
                f'<div style="padding:3px 0;border-bottom:1px solid var(--border);'
                f'font-family:monospace;font-size:11px;color:var(--text2)">{_esc(d)}</div>'
                for d in sentinel_d
            )
        if other_d:
            dl += f'<div style="font-size:10px;font-weight:700;color:var(--text3);margin:8px 0 4px;letter-spacing:.06em">OTHER</div>'
            dl += "".join(
                f'<div style="padding:3px 0;border-bottom:1px solid var(--border);'
                f'font-family:monospace;font-size:11px;color:var(--text2)">{_esc(d)}</div>'
                for d in other_d[:12]
            )
        more = (f'<div style="font-size:11px;color:var(--text3);padding-top:6px">'
                f'+ {len(other_d)-12} more</div>') if len(other_d) > 12 else ""
        daemons_html = (
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label">LaunchDaemons ({len(ctx.launch_daemons)})</div>'
            f'<div style="margin-top:6px;max-height:260px;overflow-y:auto">{dl}{more}</div></div>'
        )

    # ── Third-party kexts (runtime state from kextstat.txt) ──────────────────
    kext_runtime_html = ""
    if ctx.third_party_kexts:
        kext_rt_rows = "".join(
            f'<tr><td><code style="font-size:11px">{_esc(k["name"])}</code></td>'
            f'<td style="color:var(--text3);font-size:11px">{_esc(k["version"])}</td>'
            f'<td style="font-family:monospace;font-size:10px;color:var(--text3)">'
            f'{_esc(k["uuid"])}</td></tr>'
            for k in ctx.third_party_kexts
        )
        kext_runtime_html = (
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label" '
            f'data-tip="Non-Apple/non-SentinelOne kernel extensions currently loaded at runtime (kextstat.txt).">'
            f'Third-Party Kexts — Runtime State ({len(ctx.third_party_kexts)})</div>'
            f'<div class="table-wrap" style="margin-top:8px">'
            f'<table class="data-table"><thead>'
            f'<tr><th>Bundle ID</th><th>Version</th><th>UUID</th></tr>'
            f'</thead><tbody>{kext_rt_rows}</tbody></table></div></div>'
        )

    # ── Mounted volumes ───────────────────────────────────────────────────────
    volumes_html = ""
    if ctx.mounted_volumes:
        vol_rows = "".join(
            f'<tr><td style="font-family:monospace;font-size:11px">{_esc(v["device"])}</td>'
            f'<td><code style="font-size:11px">{_esc(v["mountpoint"])}</code></td>'
            f'<td style="color:var(--text3);font-size:11px">{_esc(v["fstype"])}</td>'
            f'<td style="font-size:10px;color:var(--text3)">'
            f'{_esc(", ".join(v.get("options", [])))}</td></tr>'
            for v in ctx.mounted_volumes
        )
        volumes_html = (
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label" data-tip="Mounted APFS/HFS volumes from mount.txt.">'
            f'Mounted Volumes ({len(ctx.mounted_volumes)})</div>'
            f'<div class="table-wrap" style="margin-top:8px">'
            f'<table class="data-table"><thead>'
            f'<tr><th>Device</th><th>Mount Point</th><th>Type</th><th>Options</th></tr>'
            f'</thead><tbody>{vol_rows}</tbody></table></div></div>'
        )

    # ── Security packages (pkgutil.txt) ─────────────────────────────────────
    pkg_html = ""
    pkgs = ctx.security_packages
    if pkgs:
        _PKG_GROUPS = [("XProtect", "XProtect"), ("Gatekeeper", "Gatekeeper"), ("MRT", "MRT")]
        group_spans = []
        for label, kw in _PKG_GROUPS:
            matched = sorted({p for p in pkgs if kw in p}, reverse=True)[:3]
            if matched:
                versions = [p.rsplit(".", 1)[-1] for p in matched]
                group_spans.append(
                    f'<span style="font-size:12px;color:var(--text2)">'
                    f'<strong>{_esc(label)}:</strong> '
                    + ", ".join(f'<code>{_esc(v)}</code>' for v in versions[:2]) + f'</span>'
                )
        if group_spans:
            pkg_html = (
                f'<div style="margin-top:16px">'
                f'<div class="finding-field-label" '
                f'data-tip="Security package versions from pkgutil.txt.">'
                f'Security Package Versions</div>'
                f'<div style="display:flex;flex-wrap:wrap;gap:14px;margin-top:8px">'
                + "".join(group_spans) + f'</div></div>'
            )

    # ── Running processes (ps.txt) ───────────────────────────────────────────
    proc_html = ""
    procs = ctx.running_processes
    if procs:
        s1_procs = [p for p in procs
                    if "sentinel" in p["binary"].lower()
                    or "sentinel" in p["command"].lower()[:40]]
        top_cpu = procs[:15]
        proc_rows = "".join(
            f'<tr>'
            f'<td style="font-size:11px;color:var(--text3)">{_esc(p["pid"])}</td>'
            f'<td><code style="font-size:11px">{_esc(p["binary"][:40])}</code></td>'
            f'<td style="font-size:11px;color:var(--text3)">{_esc(p["user"])}</td>'
            f'<td style="text-align:right;font-weight:600;'
            f'{"color:#d97706" if p["cpu"] > 5 else "color:var(--text2)"}">{p["cpu"]}%</td>'
            f'<td style="text-align:right;color:var(--text2)">{p["mem"]}%</td>'
            f'</tr>'
            for p in top_cpu
        )
        s1_rows_html = ""
        if s1_procs:
            s1_rows_html = (
                f'<div class="finding-field-label" style="margin-top:12px">SentinelOne Processes</div>'
                f'<div class="table-wrap" style="margin-top:6px"><table class="data-table">'
                f'<thead><tr><th>PID</th><th>Process</th>'
                f'<th style="text-align:right">CPU%</th><th style="text-align:right">MEM%</th>'
                f'</tr></thead><tbody>'
                + "".join(
                    f'<tr>'
                    f'<td style="font-size:11px;color:var(--text3)">{_esc(p["pid"])}</td>'
                    f'<td><code style="font-size:11px">{_esc(p["binary"][:50])}</code></td>'
                    f'<td style="text-align:right">{p["cpu"]}%</td>'
                    f'<td style="text-align:right">{p["mem"]}%</td>'
                    f'</tr>'
                    for p in s1_procs
                )
                + f'</tbody></table></div>'
            )
        proc_html = (
            f'<details class="collapse-panel" style="margin-top:16px">'
            f'<summary>Running Processes at Dump Time — {len(procs)} total'
            f'<span style="margin-left:auto;font-size:11px;font-weight:400;color:var(--text3)">'
            f'Snapshot from ps.txt</span></summary>'
            f'<div class="collapse-body">'
            f'<p style="font-size:12px;color:var(--text2);margin:0 0 10px">'
            f'Process state captured at dump collection time. '
            f'Cross-reference with behavioral detections to identify processes of interest.</p>'
            f'<div class="finding-field-label">Top 15 by CPU</div>'
            f'<div class="table-wrap" style="margin-top:6px"><table class="data-table">'
            f'<thead><tr><th>PID</th><th>Process</th><th>User</th>'
            f'<th style="text-align:right">CPU%</th><th style="text-align:right">MEM%</th>'
            f'</tr></thead><tbody>{proc_rows}</tbody></table></div>'
            + s1_rows_html
            + f'</div></details>'
        )

    return (
        f'<section id="s-system" class="section">'
        f'<div class="section-header"><span class="section-icon">&#x1F4BB;</span>'
        f'<h2 class="section-title">System Context</h2></div>'
        + _sdesc(
            "system_profile.txt / sw_vers.txt (OS), sysctl.txt (hardware), ioreg.txt (serial number), "
            "whoami.txt / users.txt (user), pkgutil.txt (installed packages), "
            "kextstat.txt / systemextensionsctl.txt (extensions), diskutil.txt (volumes), pmset-live.txt (power).",
            "OS version determines which vulnerabilities may be exploitable — unsupported macOS versions "
            "(older than the last 3 releases) are a risk factor. "
            "Serial number uniquely identifies the physical hardware — use it when correlating with asset management. "
            "<strong>Sleep Blocked</strong> lists processes actively preventing system sleep — "
            "non-system processes here may indicate background surveillance or persistence mechanisms. "
            "Check installed applications for known malicious or dual-use tools. "
            "Kernel extensions from unknown vendors bypass the macOS security model and warrant close scrutiny. "
            "Mounted volumes may reveal external media or hidden partitions."
        )
        + f'<div class="card"><div class="card-body">'
        f'{_kv_table(rows, tip)}{apps_html}{helpers_html}{kexts_html}{kext_runtime_html}'
        f'{daemons_html}{volumes_html}{pkg_html}{proc_html}'
        f'</div></div></section>'
    )


def _agent_health_section(ctx: SystemContext) -> str:
    st = ctx.sentinel_status
    if not st and not ctx.daemon_states and not ctx.asset_signatures:
        return ""
    agent = st.get("agent", {}) if st else {}
    mgmt = st.get("management", {}) if st else {}
    degraded = st.get("degraded_services", []) if st else []
    missing_auth = st.get("missing_authorizations", False) if st else False
    tip = {
        "Agent Operational State": "Overall agent state. 'enabled' means active protection.",
        "Protection":              "Is real-time protection active?",
        "ES Framework":            "Endpoint Security Framework — the Apple kernel detection component required by SentinelOne.",
        "Agent Network Monitoring":"Network traffic monitoring by the agent.",
        "Network Extension":       "macOS network extension used for connection filtering.",
        "Compatible OS":           "Is the agent compatible with the installed macOS version?",
        "Infected":                "Whether the endpoint is flagged as infected.",
        "Network Quarantine":      "Whether the endpoint is in network quarantine mode.",
    }
    rows = []
    for key in ("Version","ID","Install Date","Agent Operational State","Protection",
                "Ready","Infected","Network Quarantine","Compatible OS",
                "ES Framework","Agent Network Monitoring","Network Extension"):
        val = agent.get(key, "")
        if val:
            rows.append((key, f'<code>{_esc(val)}</code>'))
    if mgmt.get("Server"):
        rows.append(("Management Server", f'<code>{_esc(mgmt["Server"])}</code>'))
    if mgmt.get("Connected"):
        rows.append(("Connected", f'<code>{_esc(mgmt["Connected"])}</code>'))
    if mgmt.get("Last Seen"):
        rows.append(("Last Seen", f'<code>{_esc(mgmt["Last Seen"])}</code>'))

    alert_html = ""
    if missing_auth:
        alert_html = (
            '<div class="alert alert-crit">'
            '<span class="alert-icon">⚠️</span>'
            '<div><strong>Missing Authorizations</strong> — The agent is missing critical system permissions. '
            'Some detections may be blind.</div></div>'
        )

    daemons = st.get("daemons", {}) if st else {}
    services = daemons.get("services", {})
    integrity = daemons.get("integrity", {})

    svc_html = ""
    _DEPRECATED_SERVICES = frozenset({"Lib Hooks Service", "Lib Logs Service"})
    if services:
        rows_svc = "".join(
            f'<tr><td><code>{_esc(k)}</code></td><td>'
            f'<span class="badge {"badge-ok" if v.lower() in ("ready","running") else "badge-err"}">{_esc(v)}</span>'
            f'</td></tr>'
            for k, v in sorted(services.items())
            if k not in _DEPRECATED_SERVICES
        )
        svc_html = (
            f'<div style="margin-top:20px"><div class="finding-field-label">Internal Services</div>'
            f'<table class="data-table" style="margin-top:8px">'
            f'<thead><tr><th>Service</th><th>State</th></tr></thead>'
            f'<tbody>{rows_svc}</tbody></table></div>'
        )
    int_html = ""
    _ON_DEMAND_INTEGRITY = frozenset({"sentineld_shell"})
    if integrity:
        def _int_badge(name: str, state: str) -> str:
            if name in _ON_DEMAND_INTEGRITY:
                return (
                    f'<span class="badge badge-info" '
                    f'title="On-demand — activates only during remote shell sessions; not running is normal">'
                    f'{_esc(state)}</span>'
                )
            cls = "badge-ok" if state.lower() == "ok" else "badge-err"
            return f'<span class="badge {cls}">{_esc(state)}</span>'

        rows_int = "".join(
            f'<tr><td><code>{_esc(k)}</code></td><td>'
            f'{_int_badge(k, v)}</td></tr>'
            for k, v in sorted(integrity.items())
        )
        int_html = (
            f'<div style="margin-top:16px"><div class="finding-field-label">Process Integrity</div>'
            f'<table class="data-table" style="margin-top:8px">'
            f'<thead><tr><th>Process</th><th>Integrity</th></tr></thead>'
            f'<tbody>{rows_int}</tbody></table></div>'
        )
    degraded_html = ""
    if degraded:
        degraded_html = (
            f'<div class="alert alert-warn" style="margin-top:16px">'
            f'<span class="alert-icon">⚠️</span>'
            f'<div><strong>{len(degraded)} degraded service(s):</strong> '
            f'{_esc(", ".join(degraded))}</div></div>'
        )
    # ── Detection policies (sentinelctl-policies.txt) ─────────────────────────
    policies_html = ""
    if ctx.detection_policies:
        from collections import Counter
        action_counts = Counter(p["action"] for p in ctx.detection_policies)
        _ACTION_COLOR = {
            "mitigate": "var(--ok)",
            "inform":   "var(--cyan)",
            "validate": "var(--med)",
            "disabled": "var(--crit)",
        }
        action_pills = "".join(
            f'<span style="display:inline-flex;align-items:center;gap:4px;'
            f'background:#f8fafc;border:1px solid var(--border);border-radius:8px;'
            f'padding:4px 10px;font-size:12px;font-weight:600;color:{_ACTION_COLOR.get(a,"var(--text2)")}">'
            f'{_esc(a.upper())} <span style="font-weight:800;font-size:14px">{c}</span></span>'
            for a, c in sorted(action_counts.items())
        )
        policies_html = (
            f'<div class="finding-field" style="margin-top:20px">'
            f'<div class="finding-field-label" '
            f'data-tip="Detection rule actions from sentinelctl-policies.txt. '
            f'MITIGATE = active blocking. INFORM = detect only (logged). '
            f'VALIDATE = prompt user. DISABLED = no detection.">'
            f'Detection Policy Coverage ({len(ctx.detection_policies)} rules)</div>'
            f'<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:8px">{action_pills}</div>'
            f'</div>'
        )

    # ── Management Policy Configuration ──────────────────────────────────────
    policy_html = ""
    pc = ctx.policy_config
    if pc:
        _FEATURES = [
            ("DeepVisibility",          "Deep Visibility",      "Behavioral telemetry & event collection"),
            ("Firewall",                 "Firewall",             "Network connection filtering"),
            ("Ranger",                   "Ranger Discovery",     "Passive network asset discovery"),
            ("DeviceControl",            "Device Control",       "USB / peripheral access control"),
            ("LogCollection",            "Log Collection",       "System log forwarding"),
            ("Location",                 "Location Tracking",    "Geolocation reporting"),
            ("RemoteShell",              "Remote Shell",         "Operator remote shell on this endpoint"),
            ("RemoteScriptOrchestration","Remote Script Exec",   "Remote script execution by operator"),
        ]
        feature_pills = ""
        for key, label, ftip in _FEATURES:
            enabled = pc.get(key, {}).get("Enabled", "?")
            if enabled == "1":
                col, badge_label = "#16a34a", "Enabled"
                if key == "RemoteShell":
                    col, badge_label = "#d97706", "ENABLED ⚠"
            elif enabled == "0":
                col, badge_label = "#94a3b8", "Disabled"
            else:
                col, badge_label = "#64748b", "?"
            feature_pills += (
                f'<div style="display:flex;flex-direction:column;align-items:center;gap:2px;'
                f'padding:8px 12px;border:1px solid var(--border);border-radius:8px;'
                f'background:var(--bg2);min-width:120px;flex-shrink:0" data-tip="{_esc(ftip)}">'
                f'<span style="font-size:11px;font-weight:600;color:var(--text2);text-align:center">'
                f'{_esc(label)}</span>'
                f'<span style="font-size:12px;font-weight:700;color:{col}">{badge_label}</span>'
                f'</div>'
            )

        # Protection + remediation
        prot = pc.get("General", {}).get("Protection", "?")
        prot_badge = (
            '<span style="color:#16a34a;font-weight:700">Active</span>' if prot == "1"
            else '<span style="color:#dc2626;font-weight:700">INACTIVE</span>'
        )
        auto_resp = pc.get("Remediation", {}).get("AutomaticResponses", [])
        auto_html = ""
        if auto_resp:
            action_badges = "".join(
                f'<span style="background:#16a34a20;color:#16a34a;border:1px solid #16a34a40;'
                f'padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;margin-right:4px">'
                f'{_esc(a)}</span>'
                for a in auto_resp
            )
            auto_html = (
                f'<div style="margin-top:8px;font-size:12px;color:var(--text2)">'
                f'<strong>Auto-remediation:</strong> {action_badges}</div>'
            )

        # Deep Visibility collection detail
        dv = pc.get("DeepVisibility", {})
        dv_events = {k: v for k, v in dv.items() if k.startswith("Collect")}
        dv_detail_html = ""
        if dv_events:
            _DV_LABEL = {"0": "Off", "1": "Local", "2": "Cloud"}
            _DV_COLOR = {"0": "#94a3b8", "1": "#d97706", "2": "#16a34a"}
            on_count = sum(1 for v in dv_events.values() if v != "0")
            off_events = [k[7:] for k, v in dv_events.items() if v == "0"]
            dv_rows = "".join(
                f'<tr><td style="font-size:11px"><code>{_esc(k[7:])}</code></td>'
                f'<td><span style="color:{_DV_COLOR.get(v,"#64748b")};font-weight:600;font-size:11px">'
                f'{_DV_LABEL.get(v,v)}</span></td></tr>'
                for k, v in sorted(dv_events.items())
            )
            blind_note = ""
            if off_events:
                blind_note = (
                    f'<div style="font-size:11px;color:#d97706;margin-bottom:8px">'
                    f'Not collected: {_esc(", ".join(off_events[:12]))}'
                    + (f' (+{len(off_events)-12} more)' if len(off_events) > 12 else '')
                    + f'</div>'
                )
            dv_detail_html = (
                f'<details class="collapse-panel" style="margin-top:10px">'
                f'<summary>Deep Visibility Event Collection — {on_count}/{len(dv_events)} active'
                f'<span style="margin-left:auto;font-size:11px;font-weight:400;color:var(--text3)">'
                f'0=Off · 1=Local · 2=Cloud</span></summary>'
                f'<div class="collapse-body">{blind_note}'
                f'<div class="table-wrap"><table class="data-table">'
                f'<thead><tr><th>Event Type</th><th>Collection</th></tr></thead>'
                f'<tbody>{dv_rows}</tbody></table></div></div></details>'
            )

        ext_url = pc.get("ExternalServices", {}).get("LogCollectionServiceURL", "")
        ext_html = ""
        if ext_url:
            ext_html = (
                f'<div style="margin-top:8px;font-size:12px;color:var(--text2)">'
                f'<strong>Log Ingestion URL:</strong> <code>{_esc(ext_url)}</code></div>'
            )

        policy_html = (
            f'<div style="margin-top:20px">'
            f'<div class="finding-field-label" '
            f'data-tip="Management policy from sentinelctl-config_policy.txt. Shows which features are enabled by the console.">'
            f'Management Policy</div>'
            f'<div style="margin-top:6px;font-size:12px;color:var(--text2)">'
            f'Protection subsystem: {prot_badge}</div>'
            f'<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px">'
            f'{feature_pills}</div>'
            + auto_html + dv_detail_html + ext_html
            + f'</div>'
        )

    # ── Sentinel operational stats ────────────────────────────────────────────
    ops_html = ""
    ops = ctx.sentinel_operational
    if ops:
        ops_rows: list[tuple[str, str]] = []
        if ops.get("scan_info_raw"):
            ops_rows.append(("Last Disk Scan", _esc(ops["scan_info_raw"][:120])))
        if ops.get("db_stats_start"):
            ops_rows.append(("DB Stats Since", _esc(ops["db_stats_start"])))
        if ops.get("db_bytes_read"):
            ops_rows.append(("DB Bytes Read", f'<code>{_esc(ops["db_bytes_read"])}</code>'))
        if ops.get("db_bytes_written"):
            ops_rows.append(("DB Bytes Written", f'<code>{_esc(ops["db_bytes_written"])}</code>'))
        if ops_rows:
            ops_html = (
                f'<div style="margin-top:16px">'
                f'<div class="finding-field-label" data-tip="Operational statistics from sentinelctl-scan-info.txt and sentinelctl-stats.txt.">'
                f'Operational Statistics</div>'
                f'{_kv_table(ops_rows, {})}</div>'
            )

    # ── Daemon states (from ctx.daemon_states) ────────────────────────────────
    daemon_states_html = ""
    if ctx.daemon_states:
        _ON_DEMAND_DAEMONS  = frozenset({"sentineld_shell", "Shell"})
        _DEPRECATED_DAEMONS = frozenset({"Lib Hooks Service", "Lib Logs Service"})
        not_ready = [
            d for d in ctx.daemon_states
            if not d.get("ready", True)
            and d["name"] not in _ON_DEMAND_DAEMONS
            and d["name"] not in _DEPRECATED_DAEMONS
        ]
        def _daemon_row(d: dict) -> str:
            is_on_demand = d["name"] in _ON_DEMAND_DAEMONS
            name_html = f'<code style="font-size:11px">{_esc(d["name"])}</code>'
            if is_on_demand:
                name_html += '<span style="font-size:10px;color:var(--text3);margin-left:4px">(on-demand)</span>'
                status_icon = '&#x23F8;&#xFE0F;'
                badge_cls   = "badge-warn"
                badge_label = "On-demand"
            else:
                status_icon = "&#x2705;" if d.get("ready") else "&#x274C;"
                badge_cls   = "badge-ok" if d.get("ready") else "badge-err"
                badge_label = "Ready" if d.get("ready") else "Not Ready"
            return (
                f'<tr>'
                f'<td>{name_html}</td>'
                f'<td style="text-align:center"><span style="font-size:15px">{status_icon}</span></td>'
                f'<td><span class="badge {badge_cls}">{badge_label}</span></td>'
                f'</tr>'
            )
        rows_d = "".join(
            _daemon_row(d)
            for d in sorted(ctx.daemon_states, key=lambda x: (x.get("ready", True), x["name"]))
            if d["name"] not in _DEPRECATED_DAEMONS
        )
        warn_note = ""
        if not_ready:
            names = ", ".join(d["name"] for d in not_ready[:4])
            warn_note = (
                f'<div class="alert alert-warn" style="margin-bottom:10px">'
                f'<span class="alert-icon">&#x26A0;&#xFE0F;</span>'
                f'<div><strong>{len(not_ready)} daemon(s) not ready:</strong> {_esc(names)}'
                + (f' (+{len(not_ready)-4} more)' if len(not_ready) > 4 else '')
                + f' — may indicate missing Full Disk Access or system permission not granted.</div></div>'
            )
        daemon_states_html = (
            f'<div style="margin-top:20px">'
            f'<div class="finding-field-label" '
            f'data-tip="Individual daemon ready states from sentinelctl-status.txt. '
            f'Not-ready daemons reduce detection coverage.">'
            f'Daemon States ({len(ctx.daemon_states)} total)</div>'
            f'<div style="margin-top:8px">{warn_note}</div>'
            f'<div class="table-wrap"><table class="data-table" style="margin-top:4px">'
            f'<thead><tr><th>Daemon</th><th style="text-align:center">Status</th>'
            f'<th>State</th></tr></thead>'
            f'<tbody>{rows_d}</tbody></table></div></div>'
        )

    # ── Asset signatures (from ctx.asset_signatures) ──────────────────────────
    asset_sigs_html = ""
    if ctx.asset_signatures:
        # Assets where "empty" is expected — no console configuration means no content
        _OPTIONAL_ASSETS = frozenset({
            "blacklist", "whitelist", "certexclusion", "scopedetails",
            "blacklistadd", "blacklistbase", "whitelistadd", "whitelistbase",
            "whitelistextended",
        })
        _SIG_COLOR = {"valid": "#16a34a", "signed": "#0284c7", "invalid": "#dc2626",
                      "empty": "#d97706", "empty_optional": "#64748b"}
        _SIG_BADGE = {"valid": "badge-ok", "signed": "badge-ok", "invalid": "badge-err",
                      "empty": "badge-warn", "empty_optional": "badge-info"}

        def _effective_status(a: dict) -> str:
            """Return 'empty_optional' for optional assets with empty status."""
            st = a.get("status", "").lower()
            if st == "empty" and a["name"].lower() in _OPTIONAL_ASSETS:
                return "empty_optional"
            return st

        # Only truly invalid signatures warrant an alert — not "not configured" assets
        invalids = [
            a for a in ctx.asset_signatures
            if _effective_status(a) == "invalid"
        ]

        def _sig_row(a: dict) -> str:
            st = _effective_status(a)
            tr_style = 'style="background:#fef2f2"' if st == "invalid" else ""
            badge_cls = _SIG_BADGE.get(st, "")
            sig_color = _SIG_COLOR.get(st, "#64748b")
            label = "NOT CONFIGURED" if st == "empty_optional" else a.get("status", "").upper()
            tip = ' title="No items configured in console — expected when blacklist/whitelist/exclusions are not in use"' if st == "empty_optional" else ""
            return (
                f'<tr {tr_style}>'
                f'<td><code style="font-size:11px">{_esc(a["name"])}</code></td>'
                f'<td><span class="badge {badge_cls}" style="color:{sig_color}"{tip}>'
                f'{_esc(label)}</span></td>'
                f'</tr>'
            )
        rows_a = "".join(
            _sig_row(a)
            for a in sorted(ctx.asset_signatures, key=lambda x: (
                0 if _effective_status(x) == "invalid" else
                1 if _effective_status(x) == "empty" else
                2 if _effective_status(x) == "empty_optional" else 3,
                x["name"]
            ))
        )
        warn_sig = ""
        if invalids:
            warn_sig = (
                f'<div class="alert alert-crit" style="margin-bottom:10px">'
                f'<span class="alert-icon">&#x1F6A8;</span>'
                f'<div><strong>{len(invalids)} asset signature(s) invalid:</strong> '
                f'{_esc(", ".join(a["name"] for a in invalids[:3]))}'
                + (f' (+{len(invalids)-3} more)' if len(invalids) > 3 else '')
                + f' — corrupted or tampered asset files.</div></div>'
            )
        asset_sigs_html = (
            f'<div style="margin-top:20px">'
            f'<div class="finding-field-label" '
            f'data-tip="Asset signature integrity from sentinelctl-status.txt. '
            f'INVALID signatures indicate corrupted or tampered SentinelOne asset files.">'
            f'Asset Signatures ({len(ctx.asset_signatures)} assets)</div>'
            f'<div style="margin-top:8px">{warn_sig}</div>'
            f'<div class="table-wrap"><table class="data-table" style="margin-top:4px">'
            f'<thead><tr><th>Asset</th><th>Signature</th></tr></thead>'
            f'<tbody>{rows_a}</tbody></table></div></div>'
        )

    return (
        f'<section id="s-agent" class="section">'
        f'<div class="section-header"><span class="section-icon">🛡️</span>'
        f'<h2 class="section-title">SentinelOne Agent Health</h2></div>'
        + _sdesc(
            "sentinelctl-status.txt, sentinelctl-policies.txt, sentinelctl-config_policy.txt, "
            "sentinelctl-scan-info.txt, sentinelctl-stats.txt.",
            "(1) <em>sentineld</em> — core protection daemon (Static AI &amp; Behavioral AI via Apple ES Framework). "
            "Must be running for any detection or blocking. "
            "(2) <em>sentineld_guard</em> — anti-tamper watchdog; without it, killing sentineld leaves the endpoint unprotected until reboot. "
            "(3) <em>Lib Hooks / Lib Logs Service</em> — require Full Disk Access (FDA). Not-ready = FDA not granted. "
            "Reduces behavioral coverage but does not disable core engines. "
            "(4) <em>Network Extension</em> not loaded = Deep Visibility network events blind, Firewall Control unavailable. Core blocking still works. "
            "(5) <em>sentineld_shell</em> — Remote Shell LaunchDaemon; only executes on console trigger. 'Not running' is normal. "
            "(6) <em>Asset Signatures</em> — INVALID on core assets (signatures, sha256, arbiter) compromises detection; "
            "INVALID on feature assets (dvExclusionsConsole, pathExclusion) only affects those specific features. "
            "(7) <em>Detection Policies</em> — DISABLED policies with active findings = critical coverage gap. "
            "(8) <em>DB writes &gt;10 GiB</em> — indicates abnormal scan activity or log flooding."
        )
        + f'<div class="card"><div class="card-body">'
        f'{alert_html}{_kv_table(rows, tip)}{svc_html}{int_html}{degraded_html}'
        f'{policies_html}{policy_html}{ops_html}'
        f'{daemon_states_html}{asset_sigs_html}'
        f'</div></div></section>'
    )


def _system_performance_section(ctx: SystemContext) -> str:
    """System resource metrics: memory pressure, CPU load, power state, and agent DB health."""
    vm    = ctx.vm_memory or {}
    load  = ctx.system_load or {}
    power = ctx.power_state or {}
    db    = ctx.sentinel_db_health or {}

    if not vm and not load and not power and not db:
        return ""

    # ── Memory pressure ───────────────────────────────────────────────────────
    mem_html = ""
    if vm:
        pressure = vm.get("pressure_level", "OK")
        _PRESS_COL = {"CRITICAL": "#dc2626", "WARNING": "#ea580c", "MODERATE": "#d97706", "OK": "#16a34a"}
        p_col = _PRESS_COL.get(pressure, "#64748b")
        total_mb = (
            vm.get("free_mb", 0) + vm.get("active_mb", 0) +
            vm.get("wired_mb", 0) + vm.get("compressed_mb", 0)
        ) or 1
        used_mb = vm.get("active_mb", 0) + vm.get("wired_mb", 0) + vm.get("compressed_mb", 0)
        used_pct = min(100, round(used_mb * 100 / total_mb))

        def _bar(pct: int, color: str, label: str, mb: float) -> str:
            return (
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'
                f'<div style="width:90px;font-size:11px;color:var(--text2);text-align:right">{_esc(label)}</div>'
                f'<div style="flex:1;height:10px;background:var(--bg2);border-radius:5px;overflow:hidden">'
                f'<div style="height:100%;width:{pct}%;background:{_esc(color)};border-radius:5px;'
                f'transition:width .4s ease"></div></div>'
                f'<div style="width:60px;font-size:11px;color:var(--text2);text-align:right">'
                f'{round(mb)} MB</div></div>'
            )

        bars = ""
        if vm.get("active_mb"):
            bars += _bar(round(vm["active_mb"]*100/total_mb), "#0284c7", "Active", vm["active_mb"])
        if vm.get("wired_mb"):
            bars += _bar(round(vm["wired_mb"]*100/total_mb), "#7c3aed", "Wired", vm["wired_mb"])
        if vm.get("compressed_mb"):
            bars += _bar(round(vm["compressed_mb"]*100/total_mb), "#d97706", "Compressed", vm["compressed_mb"])
        if vm.get("free_mb"):
            bars += _bar(round(vm["free_mb"]*100/total_mb), "#16a34a", "Free", vm["free_mb"])

        swap_info = ""
        si = vm.get("swapins", 0)
        so = vm.get("swapouts", 0)
        if si or so:
            swap_color = "#dc2626" if (si + so) > 10000 else "#d97706" if (si + so) > 1000 else "#16a34a"
            swap_info = (
                f'<div style="font-size:11px;color:{swap_color};margin-top:6px">'
                f'Swap: {si:,} ins / {so:,} outs'
                + (' — high swap activity may degrade performance' if (si + so) > 5000 else '')
                + f'</div>'
            )

        mem_html = (
            f'<div class="perf-card">'
            f'<div class="perf-card-header">'
            f'<span class="perf-card-icon">&#x1F4BE;</span>'
            f'<span class="perf-card-title">Memory Pressure</span>'
            f'<span style="margin-left:auto;font-weight:700;font-size:13px;color:{p_col}">{_esc(pressure)}</span>'
            f'</div>'
            f'<div style="margin-top:12px">{bars}</div>'
            f'{swap_info}'
            f'</div>'
        )

    # ── CPU / Load average ────────────────────────────────────────────────────
    cpu_html = ""
    if load:
        l1 = load.get("load_1", 0)
        l5 = load.get("load_5", 0)
        l15= load.get("load_15", 0)
        cores = ctx.cpu_count or 1
        idle  = load.get("cpu_idle_pct", 0)
        used_pct_cpu = round(100 - idle) if idle else 0
        cpu_col = "#dc2626" if used_pct_cpu > 85 else "#d97706" if used_pct_cpu > 60 else "#16a34a"

        def _load_chip(val: float, period: str) -> str:
            chip_col = "#dc2626" if val > cores else "#d97706" if val > cores * 0.7 else "#16a34a"
            return (
                f'<div style="text-align:center;padding:8px 14px;border-radius:8px;'
                f'background:var(--bg2);border:1px solid var(--border)">'
                f'<div style="font-size:18px;font-weight:700;color:{chip_col}">{val:.2f}</div>'
                f'<div style="font-size:10px;color:var(--text2);margin-top:2px">{_esc(period)}</div>'
                f'</div>'
            )

        load_chips = (
            _load_chip(l1,  "1 min") +
            _load_chip(l5,  "5 min") +
            _load_chip(l15, "15 min")
        )
        cpu_bar = (
            f'<div style="margin-top:12px;display:flex;align-items:center;gap:8px">'
            f'<div style="font-size:11px;color:var(--text2);width:70px">CPU Used</div>'
            f'<div style="flex:1;height:10px;background:var(--bg2);border-radius:5px;overflow:hidden">'
            f'<div style="height:100%;width:{used_pct_cpu}%;background:{cpu_col};border-radius:5px;'
            f'transition:width .4s ease"></div></div>'
            f'<div style="font-size:11px;color:var(--text2);width:40px;text-align:right">'
            f'{used_pct_cpu}%</div></div>'
        ) if idle else ""

        mem_row = ""
        if load.get("physmem_used_mb") and load.get("physmem_free_mb"):
            used_m = load["physmem_used_mb"]
            free_m = load["physmem_free_mb"]
            tot_m  = used_m + free_m
            mem_row = (
                f'<div style="margin-top:8px;font-size:12px;color:var(--text2)">'
                f'Physical RAM: {round(used_m/1024,1)} GB used / {round(tot_m/1024,1)} GB total</div>'
            )

        cpu_html = (
            f'<div class="perf-card">'
            f'<div class="perf-card-header">'
            f'<span class="perf-card-icon">&#x26A1;</span>'
            f'<span class="perf-card-title">CPU & Load</span>'
            f'<span style="margin-left:auto;font-size:11px;color:var(--text2)">{cores} cores</span>'
            f'</div>'
            f'<div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">{load_chips}</div>'
            f'{cpu_bar}{mem_row}'
            f'</div>'
        )

    # ── Power / Battery ───────────────────────────────────────────────────────
    power_html = ""
    if power:
        on_battery = power.get("on_battery", False)
        batt_pct   = power.get("battery_pct", None)
        batt_status= power.get("battery_status", "")
        batt_rem   = power.get("battery_remaining", "")
        sleep_prev = power.get("sleep_preventing", [])
        low_power  = power.get("low_power_mode", False)
        hibmode    = power.get("hibernatemode", None)

        src_icon = "&#x1F50B;" if on_battery else "&#x1F50C;"
        src_label = "Battery" if on_battery else "AC Power"

        batt_html = ""
        if batt_pct is not None:
            batt_col = "#dc2626" if batt_pct < 20 else "#d97706" if batt_pct < 40 else "#16a34a"
            batt_html = (
                f'<div style="display:flex;align-items:center;gap:8px;margin-top:10px">'
                f'<div style="font-size:11px;color:var(--text2);width:70px">Battery</div>'
                f'<div style="flex:1;height:10px;background:var(--bg2);border-radius:5px;overflow:hidden">'
                f'<div style="height:100%;width:{batt_pct}%;background:{batt_col};border-radius:5px"></div></div>'
                f'<div style="font-size:12px;font-weight:700;color:{batt_col};width:40px;text-align:right">'
                f'{batt_pct}%</div>'
                f'</div>'
            )
            if batt_status or batt_rem:
                batt_html += (
                    f'<div style="font-size:11px;color:var(--text2);margin-top:4px">'
                    f'{_esc(batt_status)}'
                    + (f' · {_esc(batt_rem)} remaining' if batt_rem else '')
                    + f'</div>'
                )

        sleep_html = ""
        if sleep_prev:
            sleep_html = (
                f'<div style="margin-top:8px;font-size:11px;color:#d97706">'
                f'Sleep prevented by: {_esc(", ".join(sleep_prev[:4]))}'
                + (f' (+{len(sleep_prev)-4} more)' if len(sleep_prev) > 4 else '')
                + f'</div>'
            )

        flags_html = ""
        flags = []
        if low_power:
            flags.append('<span style="color:#d97706;font-size:11px;font-weight:600">Low Power Mode</span>')
        if hibmode is not None and hibmode != 3:
            flags.append(f'<span style="font-size:11px;color:var(--text2)">hibernatemode={hibmode}</span>')
        if flags:
            flags_html = (
                f'<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">'
                + "".join(flags) + f'</div>'
            )

        power_html = (
            f'<div class="perf-card">'
            f'<div class="perf-card-header">'
            f'<span class="perf-card-icon">{src_icon}</span>'
            f'<span class="perf-card-title">Power State</span>'
            f'<span style="margin-left:auto;font-size:12px;font-weight:600;color:var(--text2)">'
            f'{_esc(src_label)}</span>'
            f'</div>'
            f'{batt_html}{sleep_html}{flags_html}'
            f'</div>'
        )

    # ── Disk capacity ─────────────────────────────────────────────────────────
    disk_html = ""
    _REAL_MOUNTS = {"/", "/System/Volumes/Data", "/System/Volumes/Update"}
    disk_vols = [
        v for v in (ctx.disk_volumes or [])
        if (
            v.get("mounted", "") != "/dev"
            and not v.get("filesystem", "").startswith("devfs")
            and not v.get("filesystem", "").startswith("map ")
            and v.get("size", "")
            and v["size"][-1] in ("G", "T")
        )
    ]
    if disk_vols:
        disk_bars = ""
        for vol in disk_vols[:4]:
            mp  = vol.get("mounted", "?")
            cap = vol.get("capacity", 0)
            sz  = vol.get("size", "?")
            used = vol.get("used", "?")
            d_col = "#dc2626" if cap >= 95 else "#ea580c" if cap >= 90 else "#d97706" if cap >= 85 else "#16a34a"
            disk_bars += (
                f'<div style="margin-bottom:10px">'
                f'<div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text2);margin-bottom:3px">'
                f'<code style="font-size:11px">{_esc(mp)}</code>'
                f'<span style="color:{d_col};font-weight:700">{cap}%</span></div>'
                f'<div style="display:flex;align-items:center;gap:8px">'
                f'<div style="flex:1;height:10px;background:var(--bg2);border-radius:5px;overflow:hidden">'
                f'<div style="height:100%;width:{cap}%;background:{d_col};border-radius:5px;transition:width .4s ease"></div></div>'
                f'<div style="font-size:11px;color:var(--text2);width:70px;text-align:right">'
                f'{_esc(used)} / {_esc(sz)}</div></div></div>'
            )
        disk_html = (
            f'<div class="perf-card">'
            f'<div class="perf-card-header">'
            f'<span class="perf-card-icon">&#x1F4C0;</span>'
            f'<span class="perf-card-title">Disk Space</span>'
            f'</div>'
            f'<div style="margin-top:10px">{disk_bars}</div>'
            f'</div>'
        )

    # ── Agent DB health ───────────────────────────────────────────────────────
    db_html = ""
    if db:
        state_mb = db.get("state_db_mb", 0)
        wonky_mb = db.get("wonky_db_mb", 0)
        has_wonky= db.get("has_wonky", False)
        total_db = db.get("total_db_mb", 0)
        read_gib = db.get("db_read_gib", 0)
        write_gib= db.get("db_write_gib", 0)
        since    = db.get("db_stats_since", "")

        wonky_html = ""
        if has_wonky:
            wonky_html = (
                f'<div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;'
                f'padding:8px 12px;margin-top:10px;font-size:12px;color:#b91c1c">'
                f'<strong>&#x26A0; state.wonky detected</strong> ({wonky_mb:.1f} MB) — '
                f'LevelDB recovery file indicates the state DB was not cleanly closed. '
                f'This typically follows an agent crash or forced kill.</div>'
            )

        db_rows_html = ""
        if state_mb:
            db_rows_html += (
                f'<div style="display:flex;justify-content:space-between;'
                f'font-size:12px;color:var(--text2);padding:3px 0">'
                f'<span>state.db</span><span><strong>{state_mb:.1f} MB</strong></span></div>'
            )
        if total_db:
            db_rows_html += (
                f'<div style="display:flex;justify-content:space-between;'
                f'font-size:12px;color:var(--text2);padding:3px 0">'
                f'<span>Total agent dir</span><span><strong>{total_db:.1f} MB</strong></span></div>'
            )
        io_row = ""
        if read_gib or write_gib:
            w_color = "#dc2626" if write_gib > 10 else "#d97706" if write_gib > 2 else "var(--text2)"
            io_row = (
                f'<div style="display:flex;justify-content:space-between;'
                f'font-size:12px;color:var(--text2);padding:3px 0">'
                f'<span>DB I/O{(" since "+_esc(since)) if since else ""}</span>'
                f'<span>&#x2B06; {read_gib:.1f} GiB &nbsp; '
                f'<span style="color:{w_color}">&#x2B07; {write_gib:.1f} GiB</span></span></div>'
            )

        db_html = (
            f'<div class="perf-card">'
            f'<div class="perf-card-header">'
            f'<span class="perf-card-icon">&#x1F5C4;&#xFE0F;</span>'
            f'<span class="perf-card-title">Agent DB Health</span>'
            f'</div>'
            f'<div style="margin-top:10px">{db_rows_html}{io_row}</div>'
            f'{wonky_html}'
            f'</div>'
        )

    body = (
        f'<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));'
        f'gap:16px;margin-top:4px">'
        f'{mem_html}{cpu_html}{power_html}{disk_html}{db_html}'
        f'</div>'
    )

    return (
        f'<section id="s-perf" class="section">'
        f'<div class="section-header"><span class="section-icon">&#x1F4CA;</span>'
        f'<h2 class="section-title">System Performance</h2></div>'
        + _sdesc(
            "vm_stat.txt (memory), top.txt (CPU/load), pmset-live.txt + pmset-ps.txt (power), "
            "SentinelDirectorySize.txt + sentinelctl-stats.txt (DB). "
            "All metrics captured at dump collection time — they represent a snapshot, not an average.",
            "<strong>Memory:</strong> High compression or swap activity indicates memory pressure — "
            "can cause agent slowdowns or OS-level termination. "
            "<strong>Load averages:</strong> Compare to core count — load &gt; cores × 2 warrants investigation. "
            "<strong>DB Health:</strong> state.wonky = LevelDB recovery marker (DB was not cleanly closed, typically after a crash or forced kill). "
            "Agent auto-recovers on reboot; persistent reappearance requires reinstall. "
            "DB writes &gt;10 GiB = scan runaway or log flooding condition."
        )
        + f'<div class="card"><div class="card-body">{body}</div></div></section>'
    )


def _network_section(ctx: SystemContext) -> str:
    if not ctx.ifconfig_interfaces and not ctx.network_connections and not ctx.dns_servers:
        return ""
    blocks = []

    if ctx.ifconfig_interfaces:
        rows_if = "".join(
            f'<tr><td><code>{_esc(i["name"])}</code></td>'
            f'<td><code>{_esc(i.get("ipv4") or "-")}</code></td>'
            f'<td style="color:var(--text3)"><code>{_esc(i.get("ipv6_global") or "-")}</code></td>'
            f'<td style="color:var(--text3)"><code>{_esc(i.get("mac") or "-")}</code></td>'
            f'<td>{_esc(i.get("status",""))}</td></tr>'
            for i in ctx.ifconfig_interfaces
        )
        blocks.append(
            f'<div class="finding-field-label">Active Network Interfaces</div>'
            f'<div class="table-wrap" style="margin-top:8px">'
            f'<table class="data-table">'
            f'<thead><tr><th>Interface</th><th>IPv4</th><th>IPv6</th><th>MAC</th><th>Status</th></tr></thead>'
            f'<tbody>{rows_if}</tbody></table></div>'
        )

    if ctx.dns_servers:
        dns_tags = "".join(
            f'<code class="inline-code" style="padding:2px 8px;'
            f'border-radius:4px;margin:2px;border:1px solid var(--border)">{_esc(s)}</code>'
            for s in ctx.dns_servers
        )
        blocks.append(
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label">Configured DNS Servers</div>'
            f'<div style="margin-top:6px">{dns_tags}</div></div>'
        )

    listen = [c for c in ctx.network_connections if c["state"] == "LISTEN"]
    estab  = [c for c in ctx.network_connections if c["state"] == "ESTABLISHED"]

    if listen:
        rows_l = "".join(
            f'<tr><td><code>{_esc(c["command"])}</code></td>'
            f'<td style="color:var(--text3)">{_esc(c["pid"])}</td>'
            f'<td style="color:var(--text3)"><code>{_esc(c["user"])}</code></td>'
            f'<td style="color:var(--text3)">{_esc(c["proto"])}</td>'
            f'<td><code>{_esc(c["name"])}</code></td></tr>'
            for c in listen[:30]
        )
        blocks.append(
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label">Listening Ports ({len(listen)})</div>'
            f'<div class="table-wrap" style="margin-top:8px;max-height:280px;overflow-y:auto">'
            f'<table class="data-table"><thead><tr>'
            f'<th>Process</th><th>PID</th><th>User</th><th>Proto</th><th>Address</th>'
            f'</tr></thead><tbody>{rows_l}</tbody></table></div></div>'
        )

    if estab:
        rows_e = "".join(
            f'<tr><td><code>{_esc(c["command"])}</code></td>'
            f'<td style="color:var(--text3)">{_esc(c["pid"])}</td>'
            f'<td style="color:var(--text3)"><code>{_esc(c["user"])}</code></td>'
            f'<td><code>{_esc(c["name"])}</code></td></tr>'
            for c in estab[:30]
        )
        blocks.append(
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label">Established Connections ({len(estab)})</div>'
            f'<div class="table-wrap" style="margin-top:8px;max-height:280px;overflow-y:auto">'
            f'<table class="data-table"><thead><tr>'
            f'<th>Process</th><th>PID</th><th>User</th><th>Connection</th>'
            f'</tr></thead><tbody>{rows_e}</tbody></table></div></div>'
        )

    # ── netstat-anW.txt connections ───────────────────────────────────────────
    ns_listen = [c for c in ctx.netstat_connections if c["state"] == "LISTEN"]
    ns_estab  = [c for c in ctx.netstat_connections if c["state"] == "ESTABLISHED"]

    if ns_listen:
        rows_nsl = "".join(
            f'<tr><td style="color:var(--text3);font-size:11px">{_esc(c["proto"])}</td>'
            f'<td><code style="font-size:11px">{_esc(c["local_addr"])}</code></td>'
            f'<td style="font-weight:700;color:var(--med)">{_esc(c["local_port"])}</td></tr>'
            for c in ns_listen[:40]
        )
        more_ns = (f'<tr><td colspan="3" style="color:var(--text3);font-size:11px;text-align:center">'
                   f'+ {len(ns_listen)-40} more</td></tr>') if len(ns_listen) > 40 else ""
        blocks.append(
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label" data-tip="Listening sockets from netstat-anW.txt. Shows services accepting inbound connections.">'
            f'Listening Ports — netstat ({len(ns_listen)})</div>'
            f'<div class="table-wrap" style="margin-top:8px;max-height:280px;overflow-y:auto">'
            f'<table class="data-table"><thead><tr>'
            f'<th>Proto</th><th>Addr</th><th>Port</th>'
            f'</tr></thead><tbody>{rows_nsl}{more_ns}</tbody></table></div></div>'
        )

    if ns_estab:
        rows_nse = "".join(
            f'<tr><td style="color:var(--text3);font-size:11px">{_esc(c["proto"])}</td>'
            f'<td><code style="font-size:11px">{_esc(c["local_addr"])}</code></td>'
            f'<td style="color:var(--text3);font-size:11px">{_esc(c["local_port"])}</td>'
            f'<td><code style="font-size:11px">{_esc(c["remote_addr"])}</code></td>'
            f'<td style="font-size:11px">{_esc(c["remote_port"])}</td></tr>'
            for c in ns_estab[:40]
        )
        more_nse = (f'<tr><td colspan="5" style="color:var(--text3);font-size:11px;text-align:center">'
                    f'+ {len(ns_estab)-40} more</td></tr>') if len(ns_estab) > 40 else ""
        blocks.append(
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label" data-tip="Established TCP connections from netstat-anW.txt.">'
            f'Established Connections — netstat ({len(ns_estab)})</div>'
            f'<div class="table-wrap" style="margin-top:8px;max-height:280px;overflow-y:auto">'
            f'<table class="data-table"><thead><tr>'
            f'<th>Proto</th><th>Local Addr</th><th>Local Port</th>'
            f'<th>Remote Addr</th><th>Remote Port</th>'
            f'</tr></thead><tbody>{rows_nse}{more_nse}</tbody></table></div></div>'
        )

    return (
        f'<section id="s-network" class="section">'
        f'<div class="section-header"><span class="section-icon">🌐</span>'
        f'<h2 class="section-title">Network Context</h2></div>'
        + _sdesc(
            "ifconfig.txt (interfaces + IPs), lsof-i.txt / netstat-anW.txt (connections + ports), "
            "scutil-dns.txt (DNS resolvers). Snapshot at dump collection time — connections may have changed.",
            "<strong>LISTEN</strong> = open port accepting inbound connections — verify each is expected. "
            "<strong>ESTABLISHED</strong> = active connection to a remote host — look for unusual destinations or ports. "
            "Ports listening on 0.0.0.0 (all interfaces) are more exposed than 127.0.0.1 (loopback only). "
            "DNS servers pointing to non-corporate or residential IPs may indicate DNS hijacking. "
            "Multiple ESTABLISHED connections to the same unknown IP warrant correlation with findings. "
            "<em>SentinelOne:</em> Network Extension (com.sentinelone.network-monitoring) provides Deep Visibility IP events, "
            "Firewall Control, and Network Quarantine — its presence in the process list is normal."
        )
        + f'<div class="card"><div class="card-body">{"".join(blocks)}</div></div>'
        f'</section>'
    )


def _services_section(ctx: SystemContext) -> str:
    parts = []

    if ctx.local_users:
        rows_u = "".join(
            f'<tr><td><code>{_esc(u["name"])}</code></td>'
            f'<td style="color:var(--text3)">{_esc(u["uid"])}</td></tr>'
            for u in ctx.local_users
        )
        parts.append(
            f'<div class="finding-field-label">Local User Accounts</div>'
            f'<table class="data-table" style="margin-top:8px">'
            f'<thead><tr><th>User</th><th>UID</th></tr></thead>'
            f'<tbody>{rows_u}</tbody></table>'
        )

    if ctx.third_party_services:
        enabled  = [s for s in ctx.third_party_services if s["enabled"]]
        disabled = [s for s in ctx.third_party_services if not s["enabled"]]
        def _svc_list(svcs: list) -> str:
            return "".join(
                f'<div style="padding:3px 0;border-bottom:1px solid var(--border);'
                f'font-family:monospace;font-size:12px;color:var(--text2)">{_esc(s["name"])}</div>'
                for s in svcs
            )
        tp_html = ""
        if enabled:
            tp_html += f'<div style="margin-top:8px"><strong style="font-size:12px">Enabled ({len(enabled)})</strong>{_svc_list(enabled)}</div>'
        if disabled:
            tp_html += f'<div style="margin-top:8px"><strong style="font-size:12px;color:var(--text3)">Disabled ({len(disabled)})</strong>{_svc_list(disabled)}</div>'
        parts.append(
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label">Third-Party Services ({len(ctx.third_party_services)})</div>'
            f'{tp_html}</div>'
        )

    if ctx.system_extensions:
        rows_ext = "".join(
            f'<tr><td><code>{_esc(ext["team_id"])}</code></td>'
            f'<td style="color:var(--text3)"><code>{_esc(ext["bundle_id"])}</code></td>'
            f'<td>{_esc(ext["name"])}</td>'
            f'<td><span class="badge {"badge-ok" if ext.get("active") else "badge-info"}">'
            f'{_esc(ext.get("state",""))}</span></td></tr>'
            for ext in ctx.system_extensions
        )
        parts.append(
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label">System Extensions ({len(ctx.system_extensions)})</div>'
            f'<div class="table-wrap" style="margin-top:8px">'
            f'<table class="data-table"><thead><tr>'
            f'<th>Team ID</th><th>Bundle ID</th><th>Name</th><th>State</th>'
            f'</tr></thead><tbody>{rows_ext}</tbody></table></div></div>'
        )

    if ctx.disk_volumes:
        rows_v = "".join(
            f'<tr><td><code>{_esc(v["filesystem"])}</code></td>'
            f'<td>{_esc(v["size"])}</td><td>{_esc(v["used"])}</td><td>{_esc(v["avail"])}</td>'
            f'<td><span class="badge {"badge-err" if v["capacity"]>=80 else "badge-ok"}">'
            f'{_esc(v["capacity"])}%</span></td>'
            f'<td><code>{_esc(v["mounted"])}</code></td></tr>'
            for v in ctx.disk_volumes
        )
        parts.append(
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label"'
            f' data-tip="Capacity ≥ 80% risks disk saturation that may impact logging.">Disk Volumes</div>'
            f'<div class="table-wrap" style="margin-top:8px">'
            f'<table class="data-table"><thead><tr>'
            f'<th>Volume</th><th>Size</th><th>Used</th><th>Available</th><th>Capacity</th><th>Mount Point</th>'
            f'</tr></thead><tbody>{rows_v}</tbody></table></div></div>'
        )

    if not parts:
        return ""
    return (
        f'<section id="s-services" class="section">'
        f'<div class="section-header"><span class="section-icon">⚙️</span>'
        f'<h2 class="section-title">Services, Extensions &amp; Storage</h2></div>'
        + _sdesc(
            "launchctl list + plist files from /Library/LaunchAgents, /Library/LaunchDaemons, "
            "~/Library/LaunchAgents (persistence locations), kextstat.txt, systemextensionsctl.txt, df.txt. "
            "<strong>LaunchAgents</strong> run as the logged-in user; <strong>LaunchDaemons</strong> run as root at boot — "
            "daemons are higher-privilege and a more impactful persistence location.",
            "Non-Apple entries should be verified against known-good software. "
            "Persistence plists pointing to paths in /tmp, /var/folders, or user home directories are suspicious. "
            "Kernel extensions require approval in macOS 10.15+ — any unsigned or unrecognized kext is a red flag. "
            "System extensions (DriverKit) run in user space and are lower risk but still warrant review."
        )
        + f'<div class="card"><div class="card-body">{"".join(parts)}</div></div>'
        f'</section>'
    )


def _findings_section(findings: list[Finding]) -> str:
    sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    btns = (
        '<button class="sev-btn active" data-sev="ALL">All</button>'
        + "".join(
            f'<button class="sev-btn" data-sev="{_esc(s)}" style="color:{_esc(SEV_COLOR.get(s,"#445"))}"'
            f' data-tip="{_esc(SEV_TOOLTIP.get(s, ""))}">{_esc(s)}</button>'
            for s in sevs
        )
    )
    toolbar = (
        f'<div class="findings-toolbar">'
        f'<div class="search-box">'
        f'<input type="search" id="findings-search" placeholder="Search by name, process, rule…" autocomplete="off"/>'
        f'</div>'
        f'<div class="sev-filter">{btns}</div>'
        f'<span class="findings-count" id="findings-count">{len(findings)} findings</span>'
        f'</div>'
    )
    cards_html = ""
    for f in findings:
        col = SEV_COLOR.get(f.severity, "#445")
        sev_badge = (
            f'<span class="sev-badge" style="color:{_esc(col)};border-color:{_esc(col)}"'
            f' data-tip="{_esc(SEV_TOOLTIP.get(f.severity, ""))}">{_esc(f.severity)}</span>'
        )
        mitre_html = ""
        if f.mitre_id:
            url = _mitre_url(f.mitre_id)
            mitre_tip = (f"MITRE ATT&CK {_esc(f.mitre_id)}: {_esc(f.mitre_name or '')} — "
                         "Click to view the official technique page.")
            mitre_html = (
                f'<div class="finding-mitre" data-tip="{mitre_tip}"><span>🔗</span>'
                + (f'<a href="{_esc(url)}" target="_blank" rel="noopener">'
                   f'MITRE {_esc(f.mitre_id)} — {_esc(f.mitre_name or "")}</a>'
                   if url else f'MITRE {_esc(f.mitre_id)} — {_esc(f.mitre_name or "")}')
                + '</div>'
            )
        ts_first = f.first_seen.strftime("%Y-%m-%d %H:%M:%S UTC") if f.first_seen else "-"
        ts_last  = f.last_seen.strftime("%Y-%m-%d %H:%M:%S UTC") if f.last_seen and f.last_seen != f.first_seen else ""
        ev_html = ""
        if f.evidence:
            rows_ev = "".join(
                f'<tr>'
                f'<td style="font-family:monospace;font-size:11px;color:var(--text3);white-space:nowrap">'
                f'{_esc(ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"))}</td>'
                f'<td><code>{_esc(ev.event_type or "")}</code></td>'
                f'<td><code>{_esc(ev.behavior_category or "")}</code></td>'
                f'<td style="font-family:monospace;font-size:11px;color:var(--text2);word-break:break-all">'
                f'{_esc(ev.target_path or "")}</td>'
                f'</tr>'
                for ev in f.evidence[:10]
            )
            more_ev = (
                f'<tr><td colspan="4" style="color:var(--text3);font-size:11px;text-align:center;padding:6px">'
                f'+ {len(f.evidence)-10} additional events</td></tr>'
            ) if len(f.evidence) > 10 else ""
            ev_html = (
                f'<div class="finding-field">'
                f'<div class="finding-field-label"'
                f' data-tip="Events from the dump that triggered this detection rule.">'
                f'Evidence ({len(f.evidence)} events)</div>'
                f'<div class="evidence-table-wrap">'
                f'<table class="data-table"><thead>'
                f'<tr><th>Timestamp UTC</th><th>Type</th><th>Category</th><th>Target</th></tr>'
                f'</thead><tbody>{rows_ev}{more_ev}</tbody></table></div></div>'
            )
        search_str = f"{f.rule_id} {f.rule_name} {f.process} {f.severity} {f.description}".lower()
        cards_html += (
            f'<div class="finding-card" data-sev="{_esc(f.severity)}"'
            f' style="--sev-c:{_esc(col)}" data-search="{_esc(search_str)}">'
            f'<div class="finding-header">'
            f'<span class="finding-rule-id">{_esc(f.rule_id)}</span>'
            f'{sev_badge}'
            f'<span class="finding-name">{_esc(f.rule_name)}</span>'
            f'<code class="finding-proc" data-tip="Process that triggered this detection">{_esc(f.process)}</code>'
            f'<span class="finding-chevron">▶</span>'
            f'</div>'
            f'<div class="finding-body">'
            f'<div class="finding-field"><div class="finding-field-label">Description</div>'
            f'<div class="finding-field-val">{_esc(f.description)}</div></div>'
            f'<div class="finding-field"><div class="finding-field-label">Recommendation</div>'
            f'<div class="finding-field-val">{_esc(f.recommendation)}</div></div>'
            f'<div class="finding-field"><div class="finding-field-label">First Detected</div>'
            f'<div class="finding-field-val">{_esc(ts_first)}'
            f'{"  →  " + _esc(ts_last) if ts_last else ""}'
            f'</div></div>'
            f'{mitre_html}{ev_html}'
            f'</div></div>'
        )
    if not cards_html:
        cards_html = (
            '<div class="empty-state">'
            '<div class="empty-state-icon">✅</div>'
            '<p>No findings detected with the current filter settings.</p>'
            '</div>'
        )
    return (
        f'<section id="s-findings" class="section">'
        f'<div class="section-header"><span class="section-icon">🔍</span>'
        f'<h2 class="section-title">Security Findings</h2>'
        f'<span class="section-subtitle">{len(findings)} findings</span>'
        f'</div>'
        + _sdesc(
            "Detection rules applied to match_reports, process data, configuration files, and agent state. "
            "Each finding maps to one triggered rule.",
            "The <em>Rule ID</em> identifies the specific detection logic. "
            "The <em>Evidence</em> block shows the raw observed events — ground truth for validating or dismissing the finding. "
            "The <em>MITRE ATT&amp;CK code</em> (e.g. T1055) links to the official technique database. "
            "<strong>False positives:</strong> MEDIUM and LOW findings from known-good software (Homebrew, developer tools) are common — "
            "verify the process path and signing before escalating. Use the severity filter buttons to focus on CRITICAL/HIGH first."
        )
        + f'{toolbar}'
        f'<div id="findings-list">{cards_html}</div>'
        f'</section>'
    )


def _ioc_section(findings: list[Finding], mr_events: list[Event]) -> str:
    ioc_paths:  set[str] = set()
    ioc_procs:  set[str] = set()
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
        return ""

    def _ioc_list(items: list[str], icon: str) -> str:
        return "".join(
            f'<div class="ioc-item">'
            f'<span style="flex-shrink:0">{icon}</span>'
            f'<span class="ioc-text">{_esc(p)}</span>'
            f'<button class="ioc-copy" data-tip="Copy to clipboard">⎘ Copy</button>'
            f'</div>'
            for p in items
        )

    blocks = []
    if ioc_procs:
        blocks.append(
            f'<div class="finding-field-label"'
            f' data-tip="Processes involved in CRITICAL or HIGH findings.">Suspicious Processes ({len(ioc_procs)})</div>'
            f'<div class="ioc-list" style="margin-top:8px">{_ioc_list(sorted(ioc_procs), "⚡")}</div>'
        )
    if ioc_paths:
        shown = sorted(ioc_paths)[:50]
        more_txt = (f'<div style="font-size:11px;color:var(--text3);padding:4px 0">'
                    f'+ {len(ioc_paths)-50} additional paths</div>') if len(ioc_paths) > 50 else ""
        blocks.append(
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label"'
            f' data-tip="File paths targeted in CRITICAL or HIGH findings.">Suspicious File Paths ({len(ioc_paths)})</div>'
            f'<div class="ioc-list" style="margin-top:8px;max-height:300px;overflow-y:auto">'
            f'{_ioc_list(shown, "📄")}{more_txt}</div></div>'
        )
    if ioc_groups:
        shown_g = sorted(ioc_groups)[:20]
        more_txt_g = (f'<div style="font-size:11px;color:var(--text3);padding:4px 0">'
                      f'+ {len(ioc_groups)-20} additional UUIDs</div>') if len(ioc_groups) > 20 else ""
        blocks.append(
            f'<div class="finding-field" style="margin-top:16px">'
            f'<div class="finding-field-label"'
            f' data-tip="SentinelOne behavioral session UUIDs. A single UUID groups events belonging to the same attack sequence.">Behavioral Sessions ({len(ioc_groups)})</div>'
            f'<div class="ioc-list" style="margin-top:8px">{_ioc_list(shown_g, "🆔")}{more_txt_g}</div></div>'
        )
    return (
        f'<section id="s-ioc" class="section">'
        f'<div class="section-header"><span class="section-icon">☠️</span>'
        f'<h2 class="section-title">IOC Summary — CRITICAL / HIGH</h2></div>'
        + _sdesc(
            "Extracted from CRITICAL and HIGH findings only (lower severities excluded to reduce noise). "
            "IOC types: suspicious <em>process names/paths</em>, <em>file paths</em>, "
            "<em>network addresses</em> (IPs and domains), <em>SHA256 hashes</em>, "
            "and <em>group UUIDs</em> (SentinelOne behavioral session IDs linking events from the same incident).",
            "Submit hashes to VirusTotal. Submit IPs/domains to AbuseIPDB, Shodan, or your threat intel platform. "
            "Search group UUIDs in the SentinelOne console to pull the full incident timeline. "
            "Feed IOCs into your SIEM for cross-endpoint correlation."
        )
        + f'<div class="card"><div class="card-body">{"".join(blocks)}</div></div>'
        f'</section>'
    )


def _render_area_chart_svg(month_counts: dict[str, int], uid: str = "") -> str:
    """Render the Event Timeline SVG area chart entirely in Python.

    Works for any number of months ≥ 1, avoiding the JS getElementById / >= 2
    bugs that caused blank charts when all events fall in a single month.
    ``uid`` is appended to the gradient id to avoid SVG id collisions across
    the four period-view copies that coexist in the DOM.
    """
    if not month_counts:
        return ""
    entries = sorted(month_counts.items())   # [(YYYY-MM, count), ...]
    W, H   = 700, 160
    padL, padR, padT, padB = 44, 16, 10, 28
    max_v  = max(v for _, v in entries) or 1
    gid    = f"ag{uid}"                      # unique gradient id per period

    grid_vals = [0, round(max_v * 0.25), round(max_v * 0.5), round(max_v * 0.75), max_v]

    def sx(i: int) -> float:
        if len(entries) == 1:
            return (W + padL - padR) / 2     # centre the single point
        return padL + i * (W - padL - padR) / (len(entries) - 1)

    def sy(v: int) -> float:
        return padT + (H - padT - padB) * (1 - v / max_v)

    pts = [(sx(i), sy(v)) for i, (_, v) in enumerate(entries)]

    # SVG defs — gradient
    svgc = (
        f'<defs>'
        f'<linearGradient id="{gid}" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0%" stop-color="#0ea5e9" stop-opacity="0.25"/>'
        f'<stop offset="100%" stop-color="#0ea5e9" stop-opacity="0"/>'
        f'</linearGradient>'
        f'</defs>'
    )

    # Grid lines + Y-axis labels
    for v in grid_vals:
        y = sy(v)
        svgc += (
            f'<line class="area-chart-grid-line"'
            f' x1="{padL}" y1="{y:.1f}" x2="{W - padR}" y2="{y:.1f}"/>'
            f'<text class="area-chart-axis"'
            f' x="{padL - 4}" y="{y + 3:.1f}" text-anchor="end">{v}</text>'
        )

    if len(entries) == 1:
        # Single month — render as a centred bar instead of an area line
        x, y  = pts[0]
        month, count = entries[0]
        bar_h = H - padB - y
        svgc += (
            f'<rect x="{x - 20:.1f}" y="{y:.1f}" width="40" height="{bar_h:.1f}"'
            f' fill="url(#{gid})" stroke="#0ea5e9" stroke-width="1.5" rx="3"/>'
            f'<text class="area-chart-axis" x="{x:.1f}" y="{H - padB + 14}"'
            f' text-anchor="middle">{_esc(month)}</text>'
            f'<circle class="area-chart-dot" cx="{x:.1f}" cy="{y:.1f}" r="4"'
            f' data-tip="{_esc(month)}: {count} events"/>'
        )
        return svgc

    # Multi-month — area fill + line + dots
    line_d = " ".join(
        f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y) in enumerate(pts)
    )
    area_d = (
        f"{line_d}"
        f" L{pts[-1][0]:.1f},{H - padB}"
        f" L{pts[0][0]:.1f},{H - padB} Z"
    )

    # X-axis labels (max 8 labels to avoid overlap)
    step = max(1, (len(entries) + 7) // 8)
    for i, (month, _) in enumerate(entries):
        if i % step == 0 or i == len(entries) - 1:
            svgc += (
                f'<text class="area-chart-axis"'
                f' x="{sx(i):.1f}" y="{H - padB + 14}" text-anchor="middle">'
                f'{_esc(month)}</text>'
            )

    svgc += (
        f'<path class="area-chart-area" fill="url(#{gid})" d="{_esc(area_d)}"/>'
        f'<path class="area-chart-line" d="{_esc(line_d)}"/>'
    )
    for (month, count), (x, y) in zip(entries, pts):
        svgc += (
            f'<circle class="area-chart-dot" cx="{x:.1f}" cy="{y:.1f}" r="4"'
            f' data-tip="{_esc(month)}: {count} events"/>'
        )
    return svgc


def _render_heatmap_html(daily_counts: dict[str, int]) -> str:
    """Render the Daily Detection Activity heatmap grid entirely in Python.

    Replaces the JS getElementById approach that only rendered the heatmap for
    the first period-view in the DOM, leaving all others blank.
    """
    if not daily_counts:
        return ""
    dates = sorted(daily_counts.keys())
    if not dates:
        return ""

    max_val = max(daily_counts.values()) or 1

    def hm_level(v: int) -> int:
        if not v:
            return 0
        r = v / max_val
        if r < 0.25: return 1
        if r < 0.50: return 2
        if r < 0.75: return 3
        return 4

    first = date.fromisoformat(dates[0])
    last  = date.fromisoformat(dates[-1])

    # Sunday of the week containing first date (Python weekday: Mon=0, Sun=6)
    days_to_sunday = (first.weekday() + 1) % 7
    start_day = first - timedelta(days=days_to_sunday)

    # Saturday of the week containing last date
    days_to_saturday = (5 - last.weekday()) % 7
    end_day = last + timedelta(days=days_to_saturday)

    # Build week columns (start = Sunday of each week)
    weeks: list[date] = []
    cur = start_day
    while cur <= end_day:
        weeks.append(cur)
        cur += timedelta(weeks=1)

    # Month labels: track which column a new month starts in
    prev_month = -1
    month_labels: list[tuple[int, str]] = []   # (col_idx, abbrev)
    for col_idx, week_start in enumerate(weeks):
        if week_start.month != prev_month:
            month_labels.append((col_idx, week_start.strftime("%b")))
            prev_month = week_start.month

    total_cols = len(weeks)
    ml_html = ""
    for i, (col, label) in enumerate(month_labels):
        span = (month_labels[i + 1][0] if i + 1 < len(month_labels) else total_cols) - col
        ml_html += (
            f'<span class="heatmap-month-label"'
            f' style="width:{span * 19}px;display:inline-block">{_esc(label)}</span>'
        )

    # Grid cells (7 rows = Sun…Sat per column)
    grid_html = ""
    for week_start in weeks:
        grid_html += '<div class="heatmap-col">'
        for row in range(7):
            day = week_start + timedelta(days=row)
            ds  = day.isoformat()
            v   = daily_counts.get(ds, 0)
            lvl = hm_level(v)
            tip = f"{ds}: {v} event{'s' if v != 1 else ''}" if v else ds
            grid_html += f'<div class="heatmap-cell hm-{lvl}" data-tip="{_esc(tip)}"></div>'
        grid_html += '</div>'

    return (
        f'<div class="heatmap-wrap">'
        f'<div style="display:flex;gap:3px;margin-bottom:4px">{ml_html}</div>'
        f'<div class="heatmap-grid">{grid_html}</div>'
        f'</div>'
    )


def _timeline_section(mr_events: list[Event]) -> str:
    if not mr_events:
        return (
            f'<section id="s-timeline" class="section">'
            f'<div class="section-header"><span class="section-icon">📅</span>'
            f'<h2 class="section-title">Event Timeline</h2></div>'
            f'<div class="empty-state"><div class="empty-state-icon">📭</div><p>No events.</p></div>'
            f'</section>'
        )
    sorted_evs = sorted(mr_events, key=lambda e: e.timestamp, reverse=True)[:100]
    rows_html = "".join(
        f'<tr data-ts="{_esc(e.timestamp.strftime("%Y-%m-%d %H:%M:%S"))}">'
        f'<td class="ts">{_esc(e.timestamp.strftime("%Y-%m-%d %H:%M:%S"))}</td>'
        f'<td class="proc">{_esc(e.process_name)}</td>'
        f'<td class="cat"><code>{_esc(e.behavior_category or "")}</code></td>'
        f'<td class="target">{_esc(e.target_path or "")}</td>'
        f'</tr>'
        for e in sorted_evs
    )
    more_html = (
        f'<tr><td colspan="4" style="text-align:center;color:var(--text3);font-size:11px;padding:10px">'
        f'+ {len(mr_events) - 100} additional events not shown</td></tr>'
    ) if len(mr_events) > 100 else ""
    return (
        f'<section id="s-timeline" class="section">'
        f'<div class="section-header"><span class="section-icon">📅</span>'
        f'<h2 class="section-title">Event Timeline</h2>'
        f'<span class="section-subtitle">{len(mr_events):,} behavioral events</span>'
        f'</div>'
        + _sdesc(
            "match_reports/ JSON files — raw behavioral telemetry collected by the SentinelOne agent. "
            "Each row is one discrete OS event. Sorted newest to oldest; capped at 100 entries for display performance. "
            "Behavioral categories: <code>fileCreation/fileModification</code> = disk writes; "
            "<code>networkConnection</code> = network activity; "
            "<code>moduleLoad</code> = dylib loaded into memory; "
            "<code>processCreation</code> = new process spawned.",
            "Clusters of events around the same timestamp suggest a scripted or automated action. "
            "Gaps in the timeline (days with no events) may indicate agent suspension. "
            "Cross-reference the <em>Process</em> column with the Findings section for the same process name."
        )
        + f'<div class="timeline-wrap">'
        f'<table class="timeline-table">'
        f'<thead><tr>'
        f'<th data-tip="UTC timestamp of the event from the SentinelOne dump.">Timestamp UTC</th>'
        f'<th data-tip="Name of the process that generated the behavioral event.">Process</th>'
        f'<th data-tip="SentinelOne behavioral category — maps to detection rules.">Category</th>'
        f'<th data-tip="Target file path or resource involved in the event.">Target</th>'
        f'</tr></thead>'
        f'<tbody>{rows_html}{more_html}</tbody>'
        f'</table></div>'
        f'</section>'
    )


def _stats_section(
    ctx: SystemContext,
    findings: list[Finding],
    mr_events: list[Event],
    period_uid: str = "",
) -> str:
    stats = ctx.parse_stats
    stat_items = [
        ("match_reports_files",  "match_reports files",   "Number of JSONL match_reports files parsed from the dump."),
        ("match_reports_events", "match_reports events",  "Number of behavioral events parsed from JSONL files."),
        ("ui_log_events",        "UI log events",         "Events from the SentinelOne agent UI logs."),
        ("crash_events",         "Crash reports",         "Application crash reports found in the dump."),
        ("rules_count",          "Rules applied",         "Number of detection rules executed against the dump data."),
        ("total_findings",       "Total findings",        "Number of findings before severity filtering."),
        ("filtered_findings",    "Filtered findings",     "Findings remaining after minimum severity filter."),
    ]
    kpis = "".join(
        f'<div class="sev-card" style="--sev-c:var(--cyan);min-width:110px" data-tip="{_esc(tip)}">'
        f'<div class="sev-card-count" data-counter="{stats.get(k,0)}">{stats.get(k,0):,}</div>'
        f'<div class="sev-card-label">{_esc(label)}</div>'
        f'</div>'
        for k, label, tip in stat_items
    )

    def _bar_chart(data: dict[str, int], title: str, tip: str) -> str:
        if not data:
            return ""
        mx = max(data.values()) or 1
        rows = "".join(
            f'<div class="chart-item">'
            f'<span class="chart-label" data-tip="{_esc(k)}">{_esc(k)}</span>'
            f'<div class="chart-bar-row">'
            f'<div class="chart-bar-wrap">'
            f'<div class="chart-bar" data-pct="{round(v/mx*100,1)}" style="width:0%"></div>'
            f'</div>'
            f'<span class="chart-val">{v:,}</span>'
            f'</div>'
            f'</div>'
            for k, v in sorted(data.items(), key=lambda x: -x[1])
        )
        return (
            f'<div class="stat-card">'
            f'<div class="stat-card-title" data-tip="{_esc(tip)}">{_esc(title)}</div>'
            f'<div class="chart-row">{rows}</div>'
            f'</div>'
        )

    cat_counts:  dict[str, int] = {}
    proc_counts: dict[str, int] = {}
    day_counts:  dict[str, int] = {}
    mon_counts:  dict[str, int] = {}
    for e in mr_events:
        if e.behavior_category:
            cat_counts[e.behavior_category] = cat_counts.get(e.behavior_category, 0) + 1
        proc_counts[e.process_name] = proc_counts.get(e.process_name, 0) + 1
        day_key = e.timestamp.strftime("%Y-%m-%d")
        mon_key = e.timestamp.strftime("%Y-%m")
        day_counts[day_key] = day_counts.get(day_key, 0) + 1
        mon_counts[mon_key] = mon_counts.get(mon_key, 0) + 1

    top_cats  = dict(sorted(cat_counts.items(),  key=lambda x: -x[1])[:15])
    top_procs = dict(sorted(proc_counts.items(), key=lambda x: -x[1])[:10])

    # Adaptive granularity: daily when span ≤ 60 days, monthly beyond that
    use_daily   = len(day_counts) <= 60
    time_counts = dict(sorted(day_counts.items())) if use_daily else dict(sorted(mon_counts.items()))
    time_label  = "by day" if use_daily else "by month"

    charts = (
        f'<div class="stats-grid" style="margin-top:20px">'
        f'{_bar_chart(top_cats,  "Top 15 — Behavioral Categories", "Frequency of behavioral categories in match_reports. Most frequent categories indicate dominant TTPs.")}'
        f'{_bar_chart(top_procs, "Top 10 — Processes by Events",   "Processes generating the most behavioral events. High frequency may indicate persistent or malicious activity.")}'
        f'{_bar_chart(time_counts, f"Temporal Distribution ({time_label})", "Event distribution over time. Unusual spikes may signal a compromise or incident.")}'
        f'</div>'
    )
    # ── MITRE ATT&CK category breakdown ──────────────────────────────────────
    _CAT_META = {
        "CHAIN":   ("#7c3aed", "Attack Chains",    "Multi-stage attack sequences"),
        "CRED":    ("#dc2626", "Credential Access", "Keychain, keys, bypass"),
        "EVADE":   ("#b45309", "Evasion",           "Log tampering, hidden binaries"),
        "EXFIL":   ("#ea580c", "Exfiltration",      "Archives, staging, tools"),
        "PRIV":    ("#d97706", "Privilege Escal.",  "sudo, chmod, setuid"),
        "PERSIST": ("#0284c7", "Persistence",       "Crontab, plists, daemons"),
        "CONF":    ("#64748b", "Configuration",     "SIP, agent health, kexts"),
        "RECON":   ("#16a34a", "Reconnaissance",    "Enumeration, discovery"),
    }
    cat_finding_counts: dict[str, int] = {}
    for f in findings:
        cat = f.rule_id.split("-")[0].upper() if "-" in f.rule_id else "OTHER"
        cat_finding_counts[cat] = cat_finding_counts.get(cat, 0) + 1

    mitre_cards = ""
    for cat, (color, label, desc) in _CAT_META.items():
        count = cat_finding_counts.get(cat, 0)
        mitre_cards += (
            f'<div class="mitre-cat-card" style="--cat-color:{_esc(color)}"'
            f' data-tip="{_esc(desc)}">'
            f'<div class="mitre-cat-count" data-counter="{count}">{count}</div>'
            f'<div class="mitre-cat-name">{_esc(label)}</div>'
            f'</div>'
        )
    mitre_section = (
        f'<div class="card" style="margin-bottom:20px"><div class="card-body">'
        f'<div class="stat-card-title">Detection Categories — MITRE ATT&CK Mapping</div>'
        f'<div class="mitre-grid">{mitre_cards}</div>'
        f'</div></div>'
    )

    # ── Activity heatmap (rendered in Python — avoids JS getElementById collision) ──
    heatmap_section = ""
    heatmap_html = _render_heatmap_html(ctx.mr_daily_counts)
    if heatmap_html:
        heatmap_section = (
            f'<div class="card" style="margin-bottom:20px"><div class="card-body">'
            f'<div class="stat-card-title" data-tip="Each cell is one calendar day. '
            f'Color intensity reflects the number of match_report events on that day.">'
            f'Daily Detection Activity</div>'
            f'<p style="font-size:11px;color:var(--text3);margin:4px 0 8px">Darker cells = more events detected. '
            f'Hover a cell for date and count.</p>'
            f'{heatmap_html}'
            f'</div></div>'
        )

    # ── Risk Score Breakdown ──────────────────────────────────────────────────
    _CAT_CONF_LOCAL = {
        "CHAIN": 1.00, "CRED": 0.90, "EVADE": 0.85, "EXFIL": 0.85,
        "PRIV": 0.75, "PERSIST": 0.70, "CONF": 0.55, "RECON": 0.45,
    }
    _CAT_CAP_LOCAL = {
        "CHAIN": 30, "CRED": 25, "EVADE": 20, "EXFIL": 20,
        "PRIV": 15, "PERSIST": 15, "CONF": 10, "RECON": 10,
    }
    _SEV_BASE_LOCAL = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}
    _CAT_COLORS = {
        "CHAIN": "#7c3aed", "CRED": "#dc2626", "EVADE": "#b45309", "EXFIL": "#ea580c",
        "PRIV": "#d97706", "PERSIST": "#0284c7", "CONF": "#64748b", "RECON": "#16a34a",
    }
    from collections import defaultdict as _dd2
    _cat_f: dict[str, list] = _dd2(list)
    for f in findings:
        cat = f.rule_id.split("-")[0].upper() if "-" in f.rule_id else "OTHER"
        _cat_f[cat].append(f)
    cat_contribs = []
    for cat, flist in _cat_f.items():
        conf = _CAT_CONF_LOCAL.get(cat, 0.6)
        cap = _CAT_CAP_LOCAL.get(cat, 12)
        _sorted = sorted(flist, key=lambda f: _SEV_BASE_LOCAL.get(f.severity, 0), reverse=True)
        raw = sum(
            _SEV_BASE_LOCAL.get(f.severity, 0) * conf * max(0.2, 1.0 - i * 0.25)
            for i, f in enumerate(_sorted)
        )
        contrib = min(raw, cap)
        if contrib > 0:
            cat_contribs.append((cat, contrib, len(flist), conf))
    cat_contribs.sort(key=lambda x: -x[1])
    max_contrib = max((c[1] for c in cat_contribs), default=1)

    breakdown_rows = ""
    for cat, contrib, count, conf in cat_contribs:
        pct = round(contrib / max_contrib * 100, 1)
        color = _CAT_COLORS.get(cat, "#64748b")
        conf_pct = f"{round(conf*100)}%"
        breakdown_rows += (
            f'<div class="cat-breakdown-row">'
            f'<span class="cat-breakdown-name" style="color:{_esc(color)}">{_esc(cat)}</span>'
            f'<div class="cat-breakdown-track">'
            f'<div class="cat-breakdown-fill" data-pct="{pct}" style="background:{_esc(color)};width:0%">'
            f'<span class="cat-breakdown-fill-text">{count} finding{"s" if count!=1 else ""}</span>'
            f'</div>'
            f'</div>'
            f'<span class="cat-breakdown-pts" data-tip="Raw contribution before cap">'
            f'{round(contrib, 1)} pts</span>'
            f'<span class="cat-breakdown-conf" data-tip="Category confidence factor — '
            f'how often these findings indicate real threats">×{conf_pct}</span>'
            f'</div>'
        )
    breakdown_html = ""
    if breakdown_rows:
        breakdown_html = (
            f'<div class="card" style="margin-bottom:20px"><div class="card-body">'
            f'<div class="stat-card-title">Risk Score Breakdown — Contribution by Category</div>'
            f'<p style="font-size:11px;color:var(--text3);margin:2px 0 12px">'
            f'Wider bar = higher contribution to risk score. '
            f'Confidence factor (×%) accounts for false-positive rate per category.</p>'
            f'<div class="cat-breakdown-list">{breakdown_rows}</div>'
            f'</div></div>'
        )

    # ── SVG area chart (rendered in Python — avoids JS getElementById collision) ──
    area_chart_html = ""
    svg_content = _render_area_chart_svg(time_counts, uid=period_uid)
    if svg_content:
        chart_title = f"Event Timeline — Distribution ({time_label})"
        chart_desc  = (
            f"Behavioral events from match_reports, grouped {time_label}. "
            "Spikes indicate a campaign or incident window. "
            "Gaps indicate agent inactivity or periods without detections."
        )
        area_chart_html = (
            f'<div class="card" style="margin-bottom:20px"><div class="card-body">'
            f'<div class="stat-card-title">{_esc(chart_title)}</div>'
            f'<p style="font-size:11px;color:var(--text3);margin:2px 0 8px">{_esc(chart_desc)}</p>'
            f'<div class="area-chart-outer">'
            f'<svg class="area-chart-svg" viewBox="0 0 700 160" preserveAspectRatio="xMinYMin meet">'
            f'{svg_content}'
            f'</svg>'
            f'</div>'
            f'</div></div>'
        )

    return (
        f'<section id="s-stats" class="section">'
        f'<div class="section-header"><span class="section-icon">📈</span>'
        f'<h2 class="section-title">Statistics</h2></div>'
        + _sdesc(
            "Processing metadata from the analysis run itself — not from the dump. "
            "KPIs show totals: files parsed, events extracted, detection rules evaluated, and findings generated.",
            "<strong>Behavioral chart:</strong> distribution of OS event types (file, network, process, module). "
            "A heavily network-dominant profile on a workstation warrants review. "
            "<strong>Process activity:</strong> most active processes by event count — legitimate heavy-hitters "
            "(Spotlight, Time Machine) appear here, but so do malicious ones. "
            "<strong>Temporal chart:</strong> events per time bucket — a sharp spike signals a specific incident moment. "
            "Flat-zero periods indicate agent inactivity or data gaps. "
            "<strong>MITRE ATT&amp;CK heatmap:</strong> tactic/technique combinations observed — "
            "a cluster in Lateral Movement + C2 is a critical escalation signal."
        )
        + f'<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px">{kpis}</div>'
        f'{breakdown_html}'
        f'{area_chart_html}'
        f'{mitre_section}'
        f'{heatmap_section}'
        f'{charts}'
        f'</section>'
    )


# ─── App categorization ───────────────────────────────────────────────────────

_APP_CATEGORIES: dict[str, list[str]] = {
    "Security":       ["kaspersky", "sentinelone", "protonvpn", "malwarebytes", "avast",
                       "bitdefender", "norton", "1password", "bitwarden", "keepassxc",
                       "little snitch", "lulu", "blockblock", "knockknock", "radiosilence",
                       "cleanmymac", "sophos", "crowdstrike"],
    "Browser":        ["chrome", "brave", "firefox", "safari", "opera", "edge", "arc",
                       "vivaldi", "tor browser", "orion"],
    "Development":    ["xcode", "terminal", "ghostty", "iterm", "vscode", "visual studio",
                       "cursor", "intellij", "pycharm", "android studio", "sublime",
                       "nova", "docker", "sequel", "tableplus", "postico", "postman",
                       "insomnia", "instruments"],
    "AI / ML":        ["claude", "comfyui", "ollama", "lm studio", "diffusion",
                       "chatgpt", "copilot"],
    "Cloud / Sync":   ["dropbox", "onedrive", "icloud", "google drive", "box", "sync",
                       "backblaze", "arq"],
    "Communication":  ["zoom", "teams", "slack", "discord", "whatsapp", "telegram",
                       "signal", "skype", "facetime", "messages"],
    "Office":         ["word", "excel", "powerpoint", "outlook", "pages", "numbers",
                       "keynote", "libreoffice", "affinity", "acrobat"],
    "Media":          ["vlc", "infuse", "handbrake", "plex", "spotify", "audacity",
                       "final cut", "davinci", "resolve", "logic", "screenflow"],
}

_OTHER_LABEL = "Other"

# Security-critical packages that warrant a specific warning tag
_DUAL_AV_NAMES = {"kaspersky", "malwarebytes", "avast", "bitdefender", "norton",
                  "crowdstrike", "sophos", "eset", "f-secure", "symantec"}


def _categorize_apps(apps: list[str]) -> dict[str, list[str]]:
    """Return apps grouped by category. Unmatched apps go to 'Other'."""
    result: dict[str, list[str]] = {cat: [] for cat in _APP_CATEGORIES}
    result[_OTHER_LABEL] = []
    for app in sorted(apps):
        low = app.lower()
        matched = False
        for cat, keywords in _APP_CATEGORIES.items():
            if any(kw in low for kw in keywords):
                result[cat].append(app)
                matched = True
                break
        if not matched:
            result[_OTHER_LABEL].append(app)
    return {k: v for k, v in result.items() if v}


# ─── Report Guide ─────────────────────────────────────────────────────────────

def _report_guide() -> str:
    """Collapsible orientation guide shown at the top of every report."""
    return (
        '<details class="guide-panel" style="margin:0 0 4px">'
        '<summary>&#x1F4D6; How to read this report — click to expand</summary>'
        '<div class="guide-panel-body">'
        '<div class="section-guide" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px;padding-top:12px">'

        '<div>'
        '<strong>&#x1F3AF; Risk Score (0–100)</strong>'
        '<ul>'
        '<li><strong>0</strong> — No significant findings</li>'
        '<li><strong>1–24</strong> — LOW — informational signals only</li>'
        '<li><strong>25–49</strong> — MEDIUM — suspicious activity, review recommended</li>'
        '<li><strong>50–74</strong> — HIGH — significant threat, investigate within 24h</li>'
        '<li><strong>≥ 75</strong> — CRITICAL — immediate response required</li>'
        '</ul>'
        'Score is weighted by category confidence (attack chains count more than recon), '
        'with diminishing returns for repeated findings. SIP-disabled and disconnected-agent '
        'states add a multiplier.'
        '</div>'

        '<div>'
        '<strong>&#x26A0; Finding Severity Levels</strong>'
        '<ul>'
        '<li><strong>CRITICAL</strong> — Active compromise or imminent risk. Escalate immediately.</li>'
        '<li><strong>HIGH</strong> — Significant threat requiring investigation within 24h.</li>'
        '<li><strong>MEDIUM</strong> — Suspicious activity; may be early-stage attack or misconfiguration.</li>'
        '<li><strong>LOW</strong> — Low-confidence signal; review in next maintenance window.</li>'
        '<li><strong>INFO</strong> — Telemetry annotation with no threat impact.</li>'
        '</ul>'
        '</div>'

        '<div>'
        '<strong>&#x1F5FA; Report Sections</strong>'
        '<ul>'
        '<li><strong>Operational Alerts</strong> — Auto-generated priority alerts. Start here.</li>'
        '<li><strong>Quick Brief</strong> — 1-page summary for L1 triage and escalation decisions.</li>'
        '<li><strong>System / Network / Services</strong> — Baseline environment and posture.</li>'
        '<li><strong>S1 Agent Health</strong> — Agent operational state and permission gaps.</li>'
        '<li><strong>Comm. Analysis</strong> — Console connectivity and telemetry health.</li>'
        '<li><strong>Processes / Findings / IOC</strong> — Threat evidence and indicators.</li>'
        '<li><strong>Timeline / Statistics</strong> — Event chronology and trends.</li>'
        '<li><strong>Blind Spots</strong> — What this report cannot see.</li>'
        '</ul>'
        '</div>'

        '<div>'
        '<strong>&#x1F50E; L1 / L2 / L3 Guidance</strong>'
        '<ul>'
        '<li><strong>L1</strong> — Read Operational Alerts + Quick Brief. Escalate if CRITICAL/HIGH.</li>'
        '<li><strong>L2</strong> — Validate agent health, check Comm. Analysis and Processes sections. '
        'Correlate findings with Timeline.</li>'
        '<li><strong>L3</strong> — Deep-dive Findings, IOC, Threat Intel, and Blind Spots. '
        'Use Statistics for trend analysis. Cross-reference with MITRE ATT&amp;CK links.</li>'
        '</ul>'
        '</div>'

        '</div>'
        '</div>'
        '</details>'
    )


# ─── Operational Alerts ───────────────────────────────────────────────────────

def _operational_alerts_section(ctx: "SystemContext") -> str:
    """Auto-generated prioritized operational alerts synthesized from all parsed data."""
    alerts = getattr(ctx, "operational_alerts", [])
    if not alerts:
        return ""

    _LEVEL_CONFIG = {
        "CRITICAL": ("#dc2626", "#fef2f2", "&#x1F6A8;", "border-left:4px solid #dc2626"),
        "HIGH":     ("#ea580c", "#fff7ed", "&#x26A0;&#xFE0F;", "border-left:4px solid #ea580c"),
        "MEDIUM":   ("#d97706", "#fffbeb", "&#x1F4A1;", "border-left:4px solid #d97706"),
        "INFO":     ("#0284c7", "#eff6ff", "&#x2139;&#xFE0F;", "border-left:4px solid #0284c7"),
    }
    _LEVEL_DARK = {
        "CRITICAL": ("rgba(220,38,38,.15)", "rgba(220,38,38,.35)"),
        "HIGH":     ("rgba(234,88,12,.12)", "rgba(234,88,12,.30)"),
        "MEDIUM":   ("rgba(217,119,6,.12)",  "rgba(217,119,6,.30)"),
        "INFO":     ("rgba(2,132,199,.10)",  "rgba(2,132,199,.25)"),
    }

    cards_html = ""
    for a in alerts:
        lvl   = a.get("level", "INFO")
        title = a.get("title", "")
        detail= a.get("detail", "")
        action= a.get("action", "")
        col, bg_light, icon, border_style = _LEVEL_CONFIG.get(lvl, _LEVEL_CONFIG["INFO"])
        dark_bg, dark_border_color = _LEVEL_DARK.get(lvl, _LEVEL_DARK["INFO"])

        action_html = ""
        if action:
            action_html = (
                f'<div class="alert-action-box" style="margin-top:8px;padding:6px 10px;'
                f'border-radius:6px;background:rgba(0,0,0,.04);font-size:12px;'
                f'color:var(--text2);border:1px solid var(--border)">'
                f'<strong>Action:</strong> {_esc(action)}</div>'
            )

        cards_html += (
            f'<div class="ops-alert-card" data-level="{_esc(lvl)}" style="'
            f'padding:12px 16px;border-radius:10px;{border_style};'
            f'background:{bg_light};margin-bottom:10px;'
            f'--alert-bg-dark:{dark_bg};--alert-border-dark:{dark_border_color}">'
            f'<div style="display:flex;align-items:flex-start;gap:10px">'
            f'<span style="font-size:18px;line-height:1;flex-shrink:0">{icon}</span>'
            f'<div style="flex:1;min-width:0">'
            f'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px">'
            f'<span style="font-size:11px;font-weight:700;letter-spacing:.5px;'
            f'color:{col};background:{bg_light};padding:2px 7px;border-radius:4px;'
            f'border:1px solid {col}40">{_esc(lvl)}</span>'
            f'<span style="font-weight:600;font-size:13px;color:var(--text)">{_esc(title)}</span>'
            f'</div>'
            f'<div style="font-size:12px;color:var(--text2);line-height:1.5">{_esc(detail)}</div>'
            f'{action_html}'
            f'</div></div></div>'
        )

    crit_count = sum(1 for a in alerts if a.get("level") == "CRITICAL")
    high_count = sum(1 for a in alerts if a.get("level") == "HIGH")
    summary_chips = ""
    if crit_count:
        summary_chips += (
            f'<span style="background:#fef2f2;color:#dc2626;border:1px solid #fca5a5;'
            f'padding:3px 10px;border-radius:8px;font-size:12px;font-weight:700">'
            f'{crit_count} CRITICAL</span>'
        )
    if high_count:
        summary_chips += (
            f'<span style="background:#fff7ed;color:#ea580c;border:1px solid #fdba74;'
            f'padding:3px 10px;border-radius:8px;font-size:12px;font-weight:700;margin-left:6px">'
            f'{high_count} HIGH</span>'
        )

    return (
        f'<section id="s-alerts" class="section">'
        f'<div class="section-header"><span class="section-icon">&#x1F6A8;</span>'
        f'<h2 class="section-title">Operational Alerts</h2>'
        f'<div style="margin-left:auto;display:flex;gap:6px;align-items:center">{summary_chips}</div>'
        f'</div>'
        + _sdesc(
            "Synthesized from all parsed data sources: sentinelctl-status, sentinelctl-stats, "
            "SentinelDirectorySize, vm_stat, sentinelctl-log, installed apps.",
            "Address CRITICAL alerts before any other analysis — they indicate active failures that may invalidate "
            "findings below. HIGH alerts should be resolved within the same support session. "
            "Each alert includes a recommended action in the grey box."
        )
        + f'<div class="card"><div class="card-body">{cards_html}</div></div></section>'
    )


# ─── Quick Brief ──────────────────────────────────────────────────────────────

def _quick_brief_section(
    ctx: SystemContext,
    findings: list[Finding],
    mr_events: list[Event],
) -> str:
    """Auto-generated analyst brief: risk factors, action items, correlations."""
    agent     = ctx.sentinel_status.get("agent", {})
    degraded  = ctx.sentinel_status.get("degraded_services", [])
    by_sev    = defaultdict(int)
    for f in findings:
        by_sev[f.severity] += 1

    # ── Risk factors ────────────────────────────────────────────────────────
    risks: list[tuple[str, str, str, str]] = []  # (css_class, badge, title, desc_html)

    if ctx.sip_enabled is False:
        risks.append(("rf-p0", "P0 CRITICAL",
            "SIP Disabled",
            "System Integrity Protection is OFF. macOS cannot protect core system files from "
            "modification — persistence mechanisms are harder to detect and remove."))

    agent_state = agent.get("Agent Operational State", "")
    if agent_state and agent_state.lower() not in ("enabled", "active", "running"):
        risks.append(("rf-p0", "P0 CRITICAL",
            "Agent Not Operational",
            f"SentinelOne agent state: <code>{_esc(agent_state)}</code>. "
            "Real-time threat detection may be inactive."))

    if ctx.sentinel_status.get("missing_authorizations"):
        risks.append(("rf-p0", "P0 HIGH",
            "Missing System Authorizations",
            "The agent lacks critical macOS permissions (Full Disk Access or Accessibility). "
            "Some detection categories are blind."))

    n_crit = by_sev.get("CRITICAL", 0)
    if n_crit:
        procs = list(dict.fromkeys(f.process for f in findings if f.severity == "CRITICAL" and f.process))[:3]
        proc_html = ", ".join(f'<code>{_esc(p)}</code>' for p in procs)
        risks.append(("rf-p0", "P0 CRITICAL",
            f"{n_crit} Critical Finding(s)",
            f"Critical detections recorded for: {proc_html}."))

    if degraded:
        risks.append(("rf-p1", "P1 HIGH",
            f"{len(degraded)} Degraded S1 Service(s)",
            f"Internal SentinelOne services are not running: "
            f"{_esc(', '.join(degraded[:4]))}"))

    n_high = by_sev.get("HIGH", 0)
    if n_high:
        procs = list(dict.fromkeys(f.process for f in findings if f.severity == "HIGH" and f.process))[:3]
        proc_html = ", ".join(f'<code>{_esc(p)}</code>' for p in procs)
        risks.append(("rf-p1", "P1 HIGH",
            f"{n_high} High Severity Finding(s)",
            f"High-severity detections involving: {proc_html}."))

    if ctx.sentinelctl_error:
        risks.append(("rf-p2", "P2 MEDIUM",
            "macOS Log Archive Unavailable",
            f"<code>{_esc(ctx.sentinelctl_error[:120])}</code> — "
            "The macOS unified log archive could not be opened during dump collection. "
            "SentinelOne detection events (match_reports) are unaffected."))

    dual_av = [a for a in ctx.installed_apps if any(kw in a.lower() for kw in _DUAL_AV_NAMES)]
    if dual_av:
        risks.append(("rf-p2", "P2 MEDIUM",
            "Multiple Security Products Detected",
            f"Third-party AV/security software found alongside SentinelOne: "
            f"{', '.join(f'<code>{_esc(a)}</code>' for a in dual_av[:3])}. "
            "Dual-AV configurations can cause Endpoint Security Framework conflicts."))

    dv_flags = ctx.agent_config.get("dv_collect_flags", {})
    if dv_flags and not any(dv_flags.values()):
        risks.append(("rf-p2", "P2 MEDIUM",
            "Deep Visibility Collection Fully Disabled",
            "All Deep Visibility collection flags are OFF. "
            "Behavioral telemetry is not being forwarded to the management console."))

    kexts_3p = [k for k in ctx.kernel_extensions
                if not any(k.startswith(p) for p in ("com.apple", "com.sentinelone"))]
    if kexts_3p:
        risks.append(("rf-p3", "P3 LOW",
            f"{len(kexts_3p)} Third-Party Kernel Extension(s)",
            f"Loaded: {', '.join(f'<code>{_esc(k)}</code>' for k in kexts_3p[:3])}. "
            "Kernel extensions run in ring 0 and represent elevated attack surface."))

    if ctx.path_exclusions:
        risks.append(("rf-p3", "P3 LOW",
            f"{len(ctx.path_exclusions)} Monitoring Exclusion(s) Active",
            f"The agent has {len(ctx.path_exclusions)} path exclusions configured — "
            "these locations are NOT monitored for threats and could be used as safe harbors."))

    rf_html = "".join(
        f'<div class="risk-factor-item {cls}">'
        f'<span class="rf-badge">{_esc(badge)}</span>'
        f'<div><div class="rf-title">{_esc(title)}</div>'
        f'<div class="rf-desc">{desc}</div></div>'
        f'</div>'
        for cls, badge, title, desc in risks
    ) if risks else '<div style="color:var(--ok);font-size:13px">No risk factors identified.</div>'

    # ── Action items ────────────────────────────────────────────────────────
    actions: list[tuple[str, str]] = []  # (css_class, text_html)

    if ctx.sip_enabled is False:
        actions.append(("ac-p0",
            "Re-enable SIP: boot into macOS Recovery and run <code>csrutil enable</code>. "
            "If SIP must remain disabled, document and escalate the business justification."))

    if agent_state and agent_state.lower() not in ("enabled", "active", "running"):
        actions.append(("ac-p0",
            f"Investigate why the agent is in state <strong>{_esc(agent_state)}</strong>. "
            "Check the SentinelOne management console for endpoint alerts and restart the agent."))

    if ctx.sentinel_status.get("missing_authorizations"):
        actions.append(("ac-p0",
            "Grant SentinelOne Full Disk Access: <strong>System Settings → Privacy &amp; Security "
            "→ Full Disk Access</strong>. A reboot may be required."))

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    top_findings = sorted(
        [f for f in findings if f.severity in sev_order],
        key=lambda f: (sev_order[f.severity], -(f.first_seen.timestamp() if f.first_seen else 0))
    )
    seen_procs: set[str] = set()
    for f in top_findings:
        if len(actions) >= 8:
            break
        proc_key = f.process or f.rule_name
        if proc_key in seen_procs:
            continue
        seen_procs.add(proc_key)
        css = "ac-p0" if f.severity == "CRITICAL" else "ac-p1"
        rec = f.recommendation or f.description[:100]
        actions.append((css,
            f'Investigate <code>{_esc(proc_key)}</code>: '
            f'<strong>{_esc(f.rule_name)}</strong> — {_esc(rec)}'))

    if degraded:
        actions.append(("ac-p1",
            f"Restart degraded services from the management console or endpoint: "
            f"{_esc(', '.join(degraded[:3]))}"))
    if dual_av:
        actions.append(("ac-p2",
            f"Review whether <code>{_esc(dual_av[0])}</code> is compatible with SentinelOne. "
            "Consult the SentinelOne compatibility matrix and consider removing conflicting AV."))
    if ctx.path_exclusions:
        actions.append(("ac-p2",
            f"Audit {len(ctx.path_exclusions)} path exclusion(s) — verify each is still "
            "required and that no suspicious process paths fall within excluded locations."))
    if ctx.sentinelctl_error:
        actions.append(("ac-p2",
            "The macOS unified log archive was unavailable during dump collection — "
            "this is expected and does not affect SentinelOne detection data. "
            "To collect system logs, use <code>log collect</code> on the live endpoint."))

    actions_html = "".join(
        f'<li class="action-item {cls}"><span class="action-text">{text}</span></li>'
        for cls, text in actions
    ) if actions else '<li style="color:var(--ok);font-size:13px">No immediate actions required.</li>'

    # ── Correlations ────────────────────────────────────────────────────────
    correlations: list[str] = []

    # 1. Process in both crashes and behavioral findings on the same day
    crash_day: dict[tuple, int] = defaultdict(int)
    for e in mr_events:
        if e.source_type == "crash" and e.process_name and e.timestamp:
            crash_day[(e.process_name.lower(), e.timestamp.date())] += 1

    for f in findings:
        if not f.first_seen or not f.process:
            continue
        proc_low = f.process.lower()
        # Match crash by process name fragment (basename)
        proc_base = proc_low.split("/")[-1]
        for (crash_proc, crash_date), cnt in crash_day.items():
            crash_base = crash_proc.split("/")[-1]
            if (proc_base in crash_base or crash_base in proc_base) and crash_date == f.first_seen.date():
                correlations.append(
                    f'<strong>{_esc(f.process.split("/")[-1])}</strong> crashed on '
                    f'<code>{_esc(str(crash_date))}</code> and triggered a behavioral '
                    f'detection (<strong>{_esc(f.rule_name)}</strong>) on the same day. '
                    f'May indicate instability caused by malicious activity or detection evasion.'
                )
                break

    # 2. Single process spanning multiple attack categories
    def _rule_cat(rule_id: str) -> str:
        return rule_id.split("-")[0].upper() if "-" in rule_id else rule_id[:6].upper()

    proc_cats: dict[str, set[str]] = defaultdict(set)
    proc_findings: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.process:
            proc_cats[f.process].add(_rule_cat(f.rule_id))
            proc_findings[f.process].append(f)

    for proc, cats in proc_cats.items():
        if len(cats) >= 3:
            max_sev = min(proc_findings[proc], key=lambda f:
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f.severity, 5)).severity
            correlations.append(
                f'<strong>{_esc(proc.split("/")[-1])}</strong> triggered detections across '
                f'<strong>{len(cats)} rule categories</strong> '
                f'({_esc(", ".join(sorted(cats)))}), suggesting a '
                f'<strong>multi-stage attack pattern</strong>. Max severity: {_esc(max_sev)}.'
            )

    # 3. Single-day burst: 5+ findings from same process on one day
    proc_day_count: dict[tuple, int] = defaultdict(int)
    for f in findings:
        if f.first_seen and f.process:
            proc_day_count[(f.process, f.first_seen.date())] += 1
    for (proc, day), count in proc_day_count.items():
        if count >= 5:
            correlations.append(
                f'<strong>{_esc(proc.split("/")[-1])}</strong> generated '
                f'<strong>{count} detections on {_esc(str(day))}</strong> — '
                f'high-density single-day activity may indicate automated execution or a rapid attack sequence.'
            )

    # Deduplicate correlations
    seen_corr: set[str] = set()
    unique_corr: list[str] = []
    for c in correlations:
        key = re.sub(r'<[^>]+>', '', c)[:60]
        if key not in seen_corr:
            seen_corr.add(key)
            unique_corr.append(c)

    corr_html = ""
    if unique_corr:
        items = "".join(
            f'<div class="corr-item">'
            f'<span class="corr-icon">&#x1F517;</span>'
            f'<div class="corr-body">{c}</div></div>'
            for c in unique_corr[:8]
        )
        corr_html = (
            f'<div style="margin-top:16px">'
            f'<div class="finding-field-label" data-tip="Auto-detected correlations between crashes, '
            f'behavioral patterns, and attack categories.">Detected Correlations</div>'
            f'<div style="margin-top:10px">{items}</div></div>'
        )

    # ── Data reliability note ────────────────────────────────────────────────
    reliability_items: list[str] = []
    if ctx.sentinelctl_error:
        reliability_items.append(
            f'macOS log archive unavailable: <code>{_esc(ctx.sentinelctl_error[:100])}</code>. '
            'SentinelOne detection events (match_reports) are unaffected — '
            'only macOS system log context is missing.'
        )
    if not mr_events:
        reliability_items.append('No match_reports events parsed — behavioral detection data unavailable.')
    if not ctx.sentinel_status:
        reliability_items.append('sentinelctl-status.txt could not be parsed — agent health unknown.')

    rel_html = ""
    if reliability_items:
        items = "".join(
            f'<div class="alert alert-warn" style="margin-top:6px">'
            f'<span class="alert-icon">&#9888;</span>'
            f'<div style="font-size:12px">{item}</div></div>'
            for item in reliability_items
        )
        rel_html = (
            f'<div style="margin-top:16px">'
            f'<div class="finding-field-label">Data Reliability Warnings</div>'
            f'{items}</div>'
        )

    return (
        f'<section id="s-brief" class="section">'
        f'<div class="section-header"><span class="section-icon">&#x1F4CB;</span>'
        f'<h2 class="section-title">Analyst Quick Brief</h2>'
        f'<span class="section-subtitle">Auto-generated from dump data</span></div>'
        + _sdesc(
            "Computed from all dump sources — findings, agent health, connectivity, performance, and system state. "
            "Designed for fast L1 triage: read this section to decide whether to escalate.",
            "<strong>Risk factors</strong> are ranked P0–P3 (P0 = immediate critical action required). "
            "<strong>Recommended actions</strong> are ordered by urgency — complete in order. "
            "<strong>Cross-source correlations</strong> flag cases where multiple independent data sources "
            "point to the same problem (e.g. high findings + agent disconnected + SIP disabled) — "
            "significantly increases confidence. If all items show green, the agent is healthy and no immediate threat evidence exists."
        )
        + f'<div class="brief-grid">'
        f'<div class="card card-body">'
        f'<div class="finding-field-label">Key Risk Factors</div>'
        f'<div class="risk-factor-list">{rf_html}</div>'
        f'</div>'
        f'<div class="card card-body">'
        f'<div class="finding-field-label">Recommended Actions</div>'
        f'<ol class="action-list">{actions_html}</ol>'
        f'</div>'
        f'</div>'
        f'<div class="card card-body">{corr_html}{rel_html}'
        + ('' if corr_html or rel_html else
           '<div style="color:var(--text3);font-size:13px">No correlations detected.</div>')
        + f'</div>'
        f'</section>'
    )


# ─── Process Analysis ─────────────────────────────────────────────────────────

def _process_analysis_section(findings: list[Finding]) -> str:
    """Group all findings by process — a process-centric view for threat hunting."""
    if not findings:
        return ""

    SEV_ORD = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    # Aggregate per process
    proc_data: dict[str, dict] = {}
    for f in findings:
        key = f.process or "(unknown)"
        if key not in proc_data:
            proc_data[key] = {
                "findings": [],
                "severities": defaultdict(int),
                "rule_names": [],
                "mitre": {},           # id → name
                "first": None,
                "last":  None,
            }
        d = proc_data[key]
        d["findings"].append(f)
        d["severities"][f.severity] += 1
        if f.rule_name and f.rule_name not in d["rule_names"]:
            d["rule_names"].append(f.rule_name)
        if f.mitre_id:
            d["mitre"][f.mitre_id] = f.mitre_name or f.mitre_id
        if f.first_seen:
            d["first"] = f.first_seen if d["first"] is None else min(d["first"], f.first_seen)
        if f.last_seen:
            d["last"] = f.last_seen if d["last"] is None else max(d["last"], f.last_seen)

    # Sort: by worst severity, then by count
    def _sort_key(item: tuple) -> tuple:
        d = item[1]
        worst = min((SEV_ORD.get(s, 9) for s in d["severities"]), default=9)
        return (worst, -len(d["findings"]))

    sorted_procs = sorted(proc_data.items(), key=_sort_key)[:20]

    def _top_color(sevs: dict) -> str:
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sevs.get(s, 0):
                return SEV_COLOR.get(s, "#445")
        return "#445"

    cards = []
    for proc, d in sorted_procs:
        col = _top_color(d["severities"])
        proc_display = proc.split("/")[-1] if "/" in proc else proc
        full_path   = proc if "/" in proc else ""

        # Severity badges
        sev_badges = "".join(
            f'<span class="process-count-badge" style="color:{_esc(SEV_COLOR.get(s,"#445"))}">'
            f'{d["severities"][s]} {_esc(s)}</span>'
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            if d["severities"].get(s, 0)
        )

        # Top 3 rule names
        top_rules = d["rule_names"][:3]
        rules_html = "".join(
            f'<div style="color:var(--text2);font-size:11px;padding:1px 0">'
            f'&#x25B8; {_esc(r)}</div>'
            for r in top_rules
        )
        if len(d["rule_names"]) > 3:
            rules_html += (f'<div style="font-size:10px;color:var(--text3);margin-top:2px">'
                           f'+ {len(d["rule_names"]) - 3} more rule(s)</div>')

        # MITRE tags (max 4)
        mitre_tags = "".join(
            f'<a class="process-mitre-tag" href="{_esc(_mitre_url(mid) or "")}"'
            f' target="_blank" rel="noopener" data-tip="{_esc(mname)}"'
            f'{"" if _mitre_url(mid) else " style=\'cursor:default\'"}'
            f'>{_esc(mid)}</a>'
            for mid, mname in list(d["mitre"].items())[:4]
        )

        # Date range
        first_s = d["first"].strftime("%Y-%m-%d") if d["first"] else "?"
        last_s  = d["last"].strftime("%Y-%m-%d")  if d["last"]  else "?"
        range_html = (f'<span title="{_esc(first_s)} → {_esc(last_s)}">'
                      f'{_esc(first_s)}'
                      + (f' → {_esc(last_s)}' if last_s != first_s else '')
                      + '</span>')

        path_html = (f'<div style="font-size:10px;color:var(--text3);margin-top:4px;'
                     f'word-break:break-all;font-family:monospace">{_esc(full_path)}</div>'
                     if full_path and full_path != proc_display else "")

        cards.append(
            f'<div class="process-card" style="--proc-c:{_esc(col)}">'
            f'<div class="process-name">{_esc(proc_display)}{path_html}</div>'
            f'<div class="process-counts">{sev_badges}</div>'
            f'<div class="process-patterns">{rules_html}</div>'
            + (f'<div class="process-mitre">{mitre_tags}</div>' if mitre_tags else '')
            + f'<div class="process-range">&#128197; {range_html}</div>'
            f'</div>'
        )

    if len(proc_data) > 20:
        cards.append(
            f'<div style="grid-column:1/-1;text-align:center;padding:12px;'
            f'color:var(--text3);font-size:12px">'
            f'+ {len(proc_data) - 20} more processes — see full findings list below</div>'
        )

    return (
        f'<section id="s-processes" class="section">'
        f'<div class="section-header"><span class="section-icon">&#x1F50E;</span>'
        f'<h2 class="section-title">Process Analysis</h2>'
        f'<span class="section-subtitle">'
        f'{len(proc_data)} distinct process(es) · sorted by severity</span></div>'
        + _sdesc(
            "Findings data grouped by process name (from match_reports and process analysis). "
            "Each card aggregates all findings, TTPs, and evidence for one process.",
            "A single process accumulating findings across multiple MITRE tactics "
            "(e.g. both Execution and Defense Evasion) is a strong indicator of malicious activity — "
            "legitimate software rarely triggers rules across multiple tactic categories. "
            "Compare the process path against known-good locations: system binaries in /usr/bin, "
            "/System/Library, or /Applications — processes in /tmp, /var, or home directories are suspicious. "
            "Sort cards by severity to prioritize review."
        )
        + f'<div class="process-grid">{"".join(cards)}</div>'
        f'</section>'
    )


def _system_activity_section(ctx: SystemContext) -> str:
    """Software installation history, boot/session timeline, operational statistics."""
    history = ctx.install_history
    sessions = ctx.system_sessions
    stats = ctx.install_stats
    power_events = stats.get("power_events", [])

    if not history and not sessions and not stats:
        return ""

    blocks: list[str] = []

    # ── Operational statistics KPIs ─────────────────────────────────────────
    period_start = stats.get("log_period_start", "—")
    period_end   = stats.get("log_period_end",   "—")
    period_note  = (f"{period_start} → {period_end}"
                    if period_start != "—" else "—")

    kpi_defs = [
        ("total_installs",   "Package Installs",      "Total packages installed over the log period."),
        ("update_checks",    "Update Checks",         "Number of automatic software update checks by softwareupdated."),
        ("xprotect_updates", "XProtect Updates",      "Apple XProtect malware signature updates applied."),
        ("boot_count",       "System Boot Events",    "Number of times the system powered on during the log period."),
        ("sleep_count",      "Sleep Events",          "Number of system sleep events recorded."),
    ]
    kpis = "".join(
        f'<div class="sev-card" style="--sev-c:var(--cyan);min-width:110px" data-tip="{_esc(tip)}">'
        f'<div class="sev-card-count">{stats.get(k, 0):,}</div>'
        f'<div class="sev-card-label">{_esc(label)}</div>'
        f'</div>'
        for k, label, tip in kpi_defs
    )
    period_badge = (
        f'<div style="font-size:11px;color:var(--text3);margin-top:8px">'
        f'Log period: <code>{_esc(period_note)}</code></div>'
    ) if period_note != "—" else ""

    sentinel_date = stats.get("sentinel_install_date")
    s1_badge = (
        f'<div style="font-size:12px;margin-top:10px;color:var(--text2)">'
        f'SentinelOne agent installed: '
        f'<strong><code>{_esc(sentinel_date)}</code></strong></div>'
    ) if sentinel_date else ""

    blocks.append(
        f'<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px">{kpis}</div>'
        f'{period_badge}{s1_badge}'
    )

    # ── Software installation table (always shown) ───────────────────────────
    if True:
        _SOURCE_COLOR = {
            "app_store":     "var(--ok)",
            "auto_update":   "var(--cyan)",
            "system_update": "var(--cyan)",
            "sentinel":      "var(--purple)",
            "manual":        "var(--high)",
            "unknown":       "var(--text3)",
        }
        _SOURCE_LABEL = {
            "app_store":     "App Store",
            "auto_update":   "Auto-update",
            "system_update": "System Update",
            "sentinel":      "SentinelOne",
            "manual":        "⚠️ Manual",
            "unknown":       "Unknown",
        }
        if history:
            rows = "".join(
                f'<tr data-ts="{_esc(e.get("timestamp", e.get("date",""))[:19])}" '
                f'data-search="{_esc(" ".join(filter(None, [e.get("date",""), e.get("package_name",""), e.get("version",""), e.get("source_path",""), _SOURCE_LABEL.get(e.get("source_type","unknown"),"")])).lower())}">'
                f'<td style="font-size:11px;color:var(--text3);white-space:nowrap;font-family:monospace">'
                f'{_esc(e.get("date",""))}</td>'
                f'<td><strong>{_esc(e.get("package_name",""))}</strong></td>'
                f'<td><code style="font-size:11px">{_esc(e.get("version","") or "—")}</code></td>'
                f'<td><span style="color:{_SOURCE_COLOR.get(e.get("source_type","unknown"),"var(--text3)")};'
                f'font-size:11px;font-weight:600">'
                f'{_esc(_SOURCE_LABEL.get(e.get("source_type","unknown"),"Unknown"))}</span></td>'
                f'<td style="font-family:monospace;font-size:10px;color:var(--text3);'
                f'word-break:break-all;max-width:300px">'
                f'{_esc(e.get("source_path",""))}</td>'
                f'</tr>'
                for e in history
            )
        else:
            rows = (
                f'<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--text3);'
                f'font-style:italic">No package installations recorded in install.log for this log period '
                f'({stats.get("log_period_start","?")}&nbsp;→&nbsp;{stats.get("log_period_end","?")}).'
                f'</td></tr>'
            )
        no_results_row = (
            f'<tr id="activity-no-results" style="display:none">'
            f'<td colspan="5" style="text-align:center;padding:20px;color:var(--text3);'
            f'font-style:italic">No matching installations found.</td></tr>'
        )
        search_bar = (
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;'
            f'position:relative;max-width:420px">'
            f'<span style="position:absolute;left:10px;color:var(--text3);font-size:14px;'
            f'pointer-events:none">&#x1F50D;</span>'
            f'<input id="activity-search" type="search" placeholder="Search by app, path, source…" '
            f'autocomplete="off" spellcheck="false" '
            f'style="width:100%;padding:8px 34px 8px 32px;border:1px solid var(--border);'
            f'border-radius:8px;background:var(--bg2);color:var(--text1);font-size:13px;'
            f'outline:none;transition:border-color .15s" '
            f'onfocus="this.style.borderColor=\'var(--cyan)\'" '
            f'onblur="this.style.borderColor=\'var(--border)\'">'
            f'<button id="activity-search-clear" title="Clear search" '
            f'style="display:none;position:absolute;right:8px;background:none;border:none;'
            f'cursor:pointer;color:var(--text3);font-size:16px;padding:0 4px;line-height:1">'
            f'&#x2715;</button>'
            f'<span id="activity-count" style="white-space:nowrap;font-size:11px;'
            f'color:var(--cyan);font-weight:600;min-width:80px"></span>'
            f'</div>'
        )
        blocks.append(
            f'<div style="margin-top:20px">'
            f'<div class="finding-field-label" data-tip="All package installations recorded in logs/install.log. Use the search box to filter by application name, path, or source.">'
            f'Software Installation History ({len(history)} events)</div>'
            f'<div style="margin-top:10px">{search_bar}</div>'
            f'<div class="table-wrap">'
            f'<table class="data-table"><thead>'
            f'<tr><th>Date</th><th>Package</th><th>Version</th>'
            f'<th>Source</th><th>Path</th></tr>'
            f'</thead><tbody id="activity-install-tbody">{rows}{no_results_row}</tbody>'
            f'</table></div></div>'
        )

    # ── Boot/sleep activity chart ───────────────────────────────────────────
    if power_events:
        # Group by date
        by_date: dict[str, int] = {}
        for ev in power_events:
            d = ev.get("timestamp", "")[:10]
            if d:
                by_date[d] = by_date.get(d, 0) + 1

        if by_date:
            mx = max(by_date.values()) or 1
            rows_power = "".join(
                f'<div class="chart-item" data-ts="{_esc(d)}">'
                f'<span class="chart-label">{_esc(d)}</span>'
                f'<div class="chart-bar-row">'
                f'<div class="chart-bar-wrap">'
                f'<div class="chart-bar" data-pct="{round(c/mx*100,1)}" style="width:0%"></div>'
                f'</div><span class="chart-val">{c}</span>'
                f'</div></div>'
                for d, c in sorted(by_date.items())
            )
            blocks.append(
                f'<div style="margin-top:20px">'
                f'<div class="finding-field-label" data-tip="System wake/boot events per day from logs/install.log. '
                f'Indicates system availability and activity patterns.">'
                f'System Wake Activity</div>'
                f'<div class="stat-card" style="margin-top:8px">'
                f'<div class="chart-row">{rows_power}</div>'
                f'</div></div>'
            )

    # ── Boot/session timeline from asl.log ──────────────────────────────────
    if sessions:
        _EV_ICON = {"boot": "🟢", "shutdown": "🔴", "login": "👤", "logout": "🔒"}
        session_rows = "".join(
            f'<tr data-ts="{_esc(s.get("timestamp","")[:19])}">'
            f'<td style="font-size:11px;color:var(--text3);font-family:monospace;white-space:nowrap">'
            f'{_esc(s.get("timestamp",""))}</td>'
            f'<td>{_esc(_EV_ICON.get(s.get("event_type",""), "•"))} '
            f'<strong>{_esc(s.get("event_type","").upper())}</strong></td>'
            f'</tr>'
            for s in sessions[:50]
        )
        more = (f'<tr><td colspan="2" style="text-align:center;color:var(--text3);'
                f'font-size:11px">+ {len(sessions)-50} more events</td></tr>'
                ) if len(sessions) > 50 else ""
        blocks.append(
            f'<div style="margin-top:20px">'
            f'<div class="finding-field-label" data-tip="Boot, shutdown, login and logout events from logs/asl.log.">'
            f'Boot &amp; Session Events ({len(sessions)} total)</div>'
            f'<div class="table-wrap" style="margin-top:8px">'
            f'<table class="data-table"><thead>'
            f'<tr><th>Timestamp</th><th>Event</th></tr>'
            f'</thead><tbody>{session_rows}{more}</tbody></table></div></div>'
        )

    inner = "".join(blocks)
    return (
        f'<section id="s-activity" class="section">'
        f'<div class="section-header"><span class="section-icon">📦</span>'
        f'<h2 class="section-title">System Activity Log</h2>'
        f'<span class="section-subtitle" data-tip="Data from logs/install.log and logs/asl.log.">'
        f'install.log · asl.log</span></div>'
        + _sdesc(
            "logs/install.log (software installation history from macOS Installer) "
            "and logs/asl.log (Apple System Log — boots, shutdowns, authentication events, user sessions).",
            "Each install entry shows: timestamp, package identifier (reverse-DNS, e.g. com.example.app), version, and install source. "
            "Install source: <em>App Store</em> = Apple-vetted; <em>macOS Update</em> = OS component; "
            "<em>Manual</em> = user-initiated download — these warrant the most scrutiny. "
            "Software installed shortly before or during a suspicious event timeline is a strong correlation signal. "
            "Unknown package identifiers (especially non-reverse-DNS format) may indicate malware droppers."
        )
        + f'<div class="card"><div class="card-body">{inner}</div></div>'
        f'</section>'
    )


def _threat_intel_section(ctx: SystemContext) -> str:
    """Threat Intelligence versions + Agent Configuration from extended plist sources."""
    has_intel = bool(ctx.intelligence_metadata)
    has_config = bool(ctx.agent_config)
    if not has_intel and not has_config:
        return ""

    blocks = []

    # ── Intelligence metadata ────────────────────────────────────────────────
    if has_intel:
        pretty_names = {
            "dynamicEngine":      "Dynamic Engine",
            "staticSignatures":   "Static Signatures",
            "StaticAILibrary":    "Static AI Library",
        }
        _VERSION_KEYS = ("version", "Version", "ContentVersion", "BuildNumber")
        _DATE_KEYS    = ("UpdateDate",)
        rows_ti = "".join(
            f'<tr><td><strong>{_esc(pretty_names.get(name, name))}</strong></td>'
            + "".join(
                f'<td><code>{_esc(entry.get(k, "—"))}</code></td>'
                for k in _VERSION_KEYS
            )
            + f'<td style="color:var(--text3)">{_esc(entry.get("UpdateDate", "—"))}</td>'
            f'</tr>'
            for name, entry in sorted(ctx.intelligence_metadata.items())
        )
        blocks.append(
            f'<div class="finding-field-label" data-tip="Threat intelligence engine and signature versions '
            f'parsed from global-assets/ metadata plists.">Threat Intelligence Versions</div>'
            f'<div class="table-wrap" style="margin-top:8px">'
            f'<table class="data-table">'
            f'<thead><tr><th>Component</th><th>Version</th><th>Content Version</th>'
            f'<th>Build</th><th>Update Date</th></tr></thead>'
            f'<tbody>{rows_ti}</tbody></table></div>'
        )

    # ── Agent configuration ──────────────────────────────────────────────────
    if has_config:
        cfg = ctx.agent_config
        cfg_rows = []

        anti_tamper = cfg.get("anti_tamper_disabled")
        if anti_tamper is not None:
            badge = '<span class="badge badge-err">DISABLED</span>' if anti_tamper else '<span class="badge badge-ok">ENABLED</span>'
            cfg_rows.append(("Anti-Tamper Protection", badge,
                "Prevents the agent from being stopped or modified by non-root processes."))

        remote_shell = cfg.get("remote_shell_enabled")
        if remote_shell is not None:
            badge = '<span class="badge badge-warn">ENABLED</span>' if remote_shell else '<span class="badge badge-info">DISABLED</span>'
            cfg_rows.append(("Remote Shell", badge,
                "Remote Shell allows SentinelOne console operators to execute commands on this endpoint."))

        cpu_limit = cfg.get("cpu_consumption_limit")
        if cpu_limit is not None:
            cfg_rows.append(("CPU Consumption Limit", f'<code>{_esc(str(cpu_limit))} ms/sec</code>',
                "Maximum CPU the agent is allowed to consume per second."))

        update_int = cfg.get("update_interval")
        if update_int is not None:
            cfg_rows.append(("Update Interval", f'<code>{_esc(str(update_int))}s</code>',
                "How often the agent polls the management server for updates."))

        mgmt_server = cfg.get("management_server")
        if mgmt_server:
            cfg_rows.append(("Management Server (config)", f'<code>{_esc(str(mgmt_server))}</code>',
                "Management server URL from local agent configuration."))

        site_key = cfg.get("site_key_suffix")
        if site_key:
            cfg_rows.append(("Site Key (masked)", f'<code>{_esc(str(site_key))}</code>',
                "Last 4 characters of the site registration token."))

        scan_new = cfg.get("scan_new_apps")
        if scan_new is not None:
            cfg_rows.append(("Scan New Applications", f'<code>{_esc(str(scan_new))}</code>',
                "Whether newly installed applications are scanned on first execution."))

        dv_flags = cfg.get("dv_collect_flags", {})
        enabled_dv  = [k for k, v in dv_flags.items() if v]
        disabled_dv = [k for k, v in dv_flags.items() if not v]

        rows_cfg = "".join(
            f'<tr><td data-tip="{_esc(tip)}">{_esc(label)}</td><td>{val}</td></tr>'
            for label, val, tip in cfg_rows
        )

        dv_html = ""
        if dv_flags:
            en_tags = "".join(
                f'<code style="background:#dcfce7;color:var(--ok);border:1px solid #bbf7d0;'
                f'padding:1px 7px;border-radius:4px;margin:2px;display:inline-block">'
                f'{_esc(k.replace("Collect",""))}</code>'
                for k in sorted(enabled_dv)
            )
            dis_tags = "".join(
                f'<code class="inline-code" style="color:var(--text3);border:1px solid var(--border);'
                f'padding:1px 7px;border-radius:4px;margin:2px;display:inline-block">'
                f'{_esc(k.replace("Collect",""))}</code>'
                for k in sorted(disabled_dv)
            )
            dv_html = (
                f'<div style="margin-top:16px">'
                f'<div class="finding-field-label" data-tip="Deep Visibility event collection flags from DeepVisibility_defaults.plist.">'
                f'Deep Visibility Collection</div>'
                f'<div style="margin-top:8px">'
                + (f'<div style="margin-bottom:6px"><span style="font-size:11px;color:var(--text3);'
                   f'margin-right:6px">Active:</span>{en_tags}</div>' if en_tags else
                   '<div style="margin-bottom:6px;font-size:12px;color:var(--text3)">No active collection flags.</div>')
                + (f'<div><span style="font-size:11px;color:var(--text3);margin-right:6px">Disabled:</span>{dis_tags}</div>'
                   if dis_tags else "")
                + '</div></div>'
            )

        blocks.append(
            f'<div style="margin-top:{20 if has_intel else 0}px">'
            f'<div class="finding-field-label" data-tip="Agent configuration parsed from config_s1/ plist files.">Agent Configuration</div>'
            + (f'<table class="data-table" style="margin-top:8px">'
               f'<thead><tr><th>Setting</th><th>Value</th></tr></thead>'
               f'<tbody>{rows_cfg}</tbody></table>'
               if rows_cfg else "")
            + dv_html
            + '</div>'
        )

    inner = "".join(blocks)
    return (
        f'<section id="s-intel" class="section">'
        f'<div class="section-header"><span class="section-icon">🧬</span>'
        f'<h2 class="section-title">Threat Intelligence &amp; Configuration</h2>'
        f'<span class="section-subtitle" data-tip="Data parsed from global-assets/ and config_s1/ plist files.">'
        f'global-assets · config_s1</span></div>'
        + _sdesc(
            "Plist metadata files from the global-assets/ and config_s1/ directories inside the agent dump. "
            "Embedded databases and configuration files — not live console data.",
            "<strong>Signature databases:</strong> SentinelOne uses multiple detection engines — static signatures, "
            "behavioral rules, and cloud-lookup hashes. Each has its own version and update timestamp. "
            "Dates significantly older than the dump collection date indicate the agent has not received updates "
            "(possible network isolation, policy block, or intentional tampering). "
            "<strong>Deep Visibility configuration:</strong> lists which event categories the agent is collecting. "
            "Disabled categories create blind spots — if 'networkConnection' is off, the Timeline and Findings sections "
            "will have no network-based evidence. Cross-reference disabled categories with the Blind Spots section."
        )
        + f'<div class="card"><div class="card-body">{inner}</div></div>'
        f'</section>'
    )


def _console_comms_section(ctx: SystemContext) -> str:
    """Console communication analysis: heartbeat, intervals, telemetry timeline."""
    mgmt = ctx.sentinel_status.get("management", {})
    intervals = ctx.comm_intervals
    daily = ctx.mr_daily_counts

    agent_log  = ctx.agent_log
    proxy_cfg  = ctx.proxy_config

    if not mgmt and not intervals and not daily and not agent_log:
        return ""

    blocks: list[str] = []

    # ── Agent log summary ────────────────────────────────────────────────────
    if agent_log:
        total  = agent_log.get("total_lines", 0)
        errors = agent_log.get("error_count", 0)
        err_pct = f"{100*errors//total}%" if total else "—"
        period_s = agent_log.get("log_period_start", "")[:19]
        period_e = agent_log.get("log_period_end", "")[:19]

        # Level counts pills
        _LVL_META = [
            ("I",  "#16a34a", "Info",    "Informational log lines — normal agent activity"),
            ("E",  "#dc2626", "Error",   "Error log lines — agent-reported failures or unexpected states"),
            ("Df", "#94a3b8", "Debug",   "Debug/verbose log lines — detailed internal tracing"),
            ("W",  "#d97706", "Warning", "Warning log lines — non-critical issues worth investigating"),
        ]
        level_pills = ""
        for lvl, col, label, tip in _LVL_META:
            cnt = agent_log.get("level_counts", {}).get(lvl, 0)
            if cnt:
                level_pills += (
                    f'<span data-tip="{_esc(tip)}" style="background:{col}20;color:{col};border:1px solid {col}40;'
                    f'padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;margin-right:4px;cursor:default">'
                    f'{_esc(label)}&nbsp;{cnt:,}</span>'
                )

        # RCP communication table
        rcp_counts = agent_log.get("rcp_type_counts", {})
        rcp_rows = ""
        rcp_req_list = agent_log.get("rcp_requests", [])
        if rcp_counts:
            # Compute avg interval for Status requests
            status_ts = [
                r["timestamp"] for r in rcp_req_list if r["req_type"] == "Status"
            ]
            avg_interval_str = ""
            if len(status_ts) >= 2:
                from datetime import datetime as _dt
                try:
                    dts = [_dt.strptime(t[:19], "%Y-%m-%d %H:%M:%S") for t in status_ts]
                    deltas = [(dts[i+1]-dts[i]).seconds for i in range(len(dts)-1)]
                    avg_s = sum(deltas) // len(deltas)
                    avg_interval_str = f" — avg interval {avg_s//60}m{avg_s%60:02d}s"
                except Exception:
                    pass
            for rtype, cnt in sorted(rcp_counts.items(), key=lambda x: -x[1]):
                extra = avg_interval_str if rtype == "Status" else ""
                rcp_rows += (
                    f'<tr><td><code>{_esc(rtype)}</code></td>'
                    f'<td>{cnt:,} requests{_esc(extra)}</td>'
                    f'<td style="font-size:11px;color:var(--text3)">'
                    f'{_esc(rcp_req_list[-1]["timestamp"][:19]) if rcp_req_list else "—"}</td></tr>'
                )

        rcp_html = ""
        if rcp_rows:
            rcp_html = (
                f'<div class="finding-field-label" style="margin-top:12px" '
                f'data-tip="RCP = Remote Control Protocol. Requests received from the management console.">'
                f'Console → Agent RCP Requests</div>'
                f'<div class="table-wrap" style="margin-top:6px">'
                f'<table class="data-table"><thead><tr>'
                f'<th>Request Type</th><th>Count</th><th>Last Seen</th>'
                f'</tr></thead><tbody>{rcp_rows}</tbody></table></div>'
            )

        # Keep-alive
        ka_count = agent_log.get("keep_alive_count", 0)
        ka_recent = agent_log.get("keep_alive_recent", [])
        ka_html = ""
        if ka_count:
            ka_html = (
                f'<div style="margin-top:10px;font-size:12px;color:var(--text2)">'
                f'<strong>Keep-alive events:</strong> {ka_count:,} total'
                + (f' — last at <code>{_esc(ka_recent[-1][:19])}</code>' if ka_recent else "")
                + f'</div>'
            )

        # Error breakdown
        err_components = agent_log.get("error_by_component", {})
        err_html = ""
        if err_components:
            top_err = list(err_components.items())[:6]
            rows_e = "".join(
                f'<tr><td><code>{_esc(comp)}</code></td>'
                f'<td style="text-align:right;color:#dc2626">{cnt:,}</td></tr>'
                for comp, cnt in top_err
            )
            asserts = agent_log.get("unique_asserts", {})
            assert_html = ""
            if asserts:
                for msg, cnt in list(asserts.items())[:3]:
                    assert_html += (
                        f'<div style="font-size:11px;color:var(--text3);margin-top:3px">'
                        f'× {cnt:,} — <code>{_esc(msg[:100])}</code></div>'
                    )
            err_html = (
                f'<div class="finding-field-label" style="margin-top:12px;color:#dc2626" '
                f'data-tip="Error lines (level E) in the agent log, grouped by internal component.">'
                f'Agent Errors by Component ({errors:,} total — {err_pct})</div>'
                f'<div class="table-wrap" style="margin-top:6px">'
                f'<table class="data-table"><thead><tr>'
                f'<th>Component</th><th style="text-align:right">Errors</th>'
                f'</tr></thead><tbody>{rows_e}</tbody></table></div>'
                + assert_html
            )

        # Proxy config
        proxy_html = ""
        if proxy_cfg:
            if proxy_cfg.get("has_proxy"):
                proxy_html = (
                    f'<div style="margin-top:10px;font-size:12px;color:var(--text2)">'
                    f'<strong>Proxy:</strong> <code>{_esc(proxy_cfg["proxy_server"])}</code></div>'
                )
            else:
                excl = ", ".join(proxy_cfg.get("exceptions", []))
                proxy_html = (
                    f'<div style="margin-top:10px;font-size:12px;color:var(--text2)">'
                    f'<strong>Proxy:</strong> Direct internet access '
                    f'<span style="color:var(--text3)">(exceptions: {_esc(excl) or "none"})</span></div>'
                )

        # Asset updates
        asset_html = ""
        assets = agent_log.get("asset_updates", [])
        if assets:
            asset_rows = "".join(
                f'<tr data-ts="{_esc(a["timestamp"][:19])}">'
                f'<td><code>{_esc(a["name"])}</code></td>'
                f'<td style="font-family:monospace;font-size:11px">{_esc(a["version"])}</td>'
                f'<td style="font-size:11px;color:var(--text3)">{_esc(a["timestamp"][:19])}</td></tr>'
                for a in assets
            )
            asset_html = (
                f'<div class="finding-field-label" style="margin-top:12px" '
                f'data-tip="Detection asset versions loaded by the agent during the log period.">'
                f'Detection Asset Updates</div>'
                f'<div class="table-wrap" style="margin-top:6px">'
                f'<table class="data-table"><thead><tr>'
                f'<th>Asset</th><th>Version</th><th>Loaded At</th>'
                f'</tr></thead><tbody>{asset_rows}</tbody></table></div>'
            )

        # Dynamic Detection Matches
        detection_html = ""
        technique_counts_data = agent_log.get("technique_counts", {})
        detection_total = agent_log.get("detection_total", 0)
        if detection_total:
            tech_rows = "".join(
                f'<tr><td><code>{_esc(tech)}</code></td>'
                f'<td style="text-align:right">{cnt:,}</td></tr>'
                for tech, cnt in list(technique_counts_data.items())[:20]
            )
            matches = agent_log.get("detection_matches", [])
            sample_rows = "".join(
                f'<tr data-ts="{_esc(m["timestamp"][:19])}">'
                f'<td style="font-size:11px;color:var(--text3)">{_esc(m["timestamp"][:19])}</td>'
                f'<td><code style="font-size:11px">{_esc(m["technique"])}</code></td>'
                f'<td style="font-size:11px;word-break:break-all">{_esc(m["primary_path"] or m["origin_path"])}</td></tr>'
                for m in matches[:50]
            )
            sample_note = (
                f'<div style="font-size:11px;color:var(--text3);margin-top:4px">'
                f'Showing first 50 of {detection_total:,} events.</div>'
                if detection_total > 50 else ""
            )
            detection_html = (
                f'<details class="collapse-panel" style="margin-top:12px">'
                f'<summary>Dynamic Detection Matches — {detection_total:,} events'
                f'<span style="margin-left:auto;font-size:11px;font-weight:400;color:var(--text3)">'
                f'Behavioral MITRE-mapped detections fired by the agent</span></summary>'
                f'<div class="collapse-body">'
                f'<p style="font-size:12px;color:var(--text2);margin:0 0 10px">'
                f'Detections logged by the agent\'s behavioral engine. Each entry maps to a MITRE ATT&CK technique. '
                f'High counts on a specific technique may indicate active exploitation or persistent tooling.</p>'
                f'<div class="table-wrap">'
                f'<table class="data-table"><thead><tr><th>Technique</th><th style="text-align:right">Count</th>'
                f'</tr></thead><tbody>{tech_rows}</tbody></table></div>'
                + (
                    f'<div class="finding-field-label" style="margin-top:12px">Recent Events (sample)</div>'
                    f'<div class="table-wrap"><table class="data-table"><thead><tr>'
                    f'<th>Timestamp</th><th>Technique</th><th>Primary Path</th>'
                    f'</tr></thead><tbody>{sample_rows}</tbody></table></div>'
                    + sample_note
                    if sample_rows else ""
                )
                + f'</div></details>'
            )

        # Integrity Protection Blocks
        integrity_html = ""
        invoker_counts_data = agent_log.get("invoker_counts", {})
        integrity_total = agent_log.get("integrity_total", 0)
        if integrity_total:
            inv_rows = "".join(
                f'<tr><td style="word-break:break-all;font-size:11px"><code>{_esc(inv)}</code></td>'
                f'<td style="text-align:right">{cnt:,}</td></tr>'
                for inv, cnt in list(invoker_counts_data.items())[:20]
            )
            iblocks = agent_log.get("integrity_blocks", [])
            ib_sample_rows = "".join(
                f'<tr data-ts="{_esc(b["timestamp"][:19])}">'
                f'<td style="font-size:11px;color:var(--text3)">{_esc(b["timestamp"][:19])}</td>'
                f'<td style="font-size:11px;word-break:break-all">{_esc(b["invoker_path"])}</td>'
                f'<td style="font-size:11px;word-break:break-all">{_esc(b["target_path"])}</td></tr>'
                for b in iblocks[:50]
            )
            ib_note = (
                f'<div style="font-size:11px;color:var(--text3);margin-top:4px">'
                f'Showing first 50 of {integrity_total:,} events.</div>'
                if integrity_total > 50 else ""
            )
            integrity_html = (
                f'<details class="collapse-panel" style="margin-top:8px">'
                f'<summary>Integrity Protection Blocks — {integrity_total:,} events'
                f'<span style="margin-left:auto;font-size:11px;font-weight:400;color:var(--text3)">'
                f'Processes denied access to SentinelOne agent</span></summary>'
                f'<div class="collapse-body">'
                f'<p style="font-size:12px;color:var(--text2);margin:0 0 10px">'
                f'Anti-tamper protection blocks: processes that attempted to interact with SentinelOne agent processes '
                f'and were denied. Frequent blocks from the same invoker may indicate evasion attempts.</p>'
                f'<div class="table-wrap">'
                f'<table class="data-table"><thead><tr><th>Invoking Process</th><th style="text-align:right">Blocks</th>'
                f'</tr></thead><tbody>{inv_rows}</tbody></table></div>'
                + (
                    f'<div class="finding-field-label" style="margin-top:12px">Recent Events (sample)</div>'
                    f'<div class="table-wrap"><table class="data-table"><thead><tr>'
                    f'<th>Timestamp</th><th>Invoker</th><th>Target</th>'
                    f'</tr></thead><tbody>{ib_sample_rows}</tbody></table></div>'
                    + ib_note
                    if ib_sample_rows else ""
                )
                + f'</div></details>'
            )

        # Device Control status
        device_ctrl_html = ""
        dc_events = agent_log.get("device_control_events", [])
        if dc_events:
            latest_dc = dc_events[-1]
            def _yn_badge(val: str) -> str:
                col = "#16a34a" if val == "yes" else "#94a3b8"
                label = "Enabled" if val == "yes" else "Disabled"
                return (f'<span style="background:{col}20;color:{col};border:1px solid {col}40;'
                        f'padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600">{label}</span>')
            dc_rows_html = (
                f'<tr><td>USB</td><td>{_yn_badge(latest_dc["usb"])}</td></tr>'
                f'<tr><td>Thunderbolt</td><td>{_yn_badge(latest_dc["thunderbolt"])}</td></tr>'
                f'<tr><td>Bluetooth</td><td>{_yn_badge(latest_dc["bluetooth"])}</td></tr>'
                f'<tr><td>Bluetooth Low Energy</td><td>{_yn_badge(latest_dc["ble"])}</td></tr>'
            )
            device_ctrl_html = (
                f'<div class="finding-field-label" style="margin-top:12px" '
                f'data-tip="Device control policy state as reported by the agent ({len(dc_events)} status events).">'
                f'Device Control Policy</div>'
                f'<div class="table-wrap" style="margin-top:6px">'
                f'<table class="data-table"><thead><tr><th>Interface</th><th>State</th>'
                f'</tr></thead><tbody>{dc_rows_html}</tbody></table></div>'
                f'<div style="font-size:11px;color:var(--text3);margin-top:3px">'
                f'Last status at {_esc(latest_dc["timestamp"][:19])} '
                f'({len(dc_events)} events in log period)</div>'
            )

        # Mount events
        mount_html = ""
        m_events = agent_log.get("mount_events", [])
        if m_events:
            denied = [e for e in m_events if not e["allowed"]]
            allowed = [e for e in m_events if e["allowed"]]
            mount_rows_html = "".join(
                f'<tr data-ts="{_esc(e["timestamp"][:19])}">'
                f'<td style="font-size:11px;color:var(--text3)">{_esc(e["timestamp"][:19])}</td>'
                f'<td style="font-size:11px"><code>{_esc(e["device"])}</code></td>'
                f'<td>{"<span style=\'color:#16a34a\'>Allow</span>" if e["allowed"] else "<span style=\'color:#dc2626\'>Deny</span>"}</td>'
                f'</tr>'
                for e in m_events[:30]
            )
            mount_html = (
                f'<details class="collapse-panel" style="margin-top:8px">'
                f'<summary>Mount Requests — {len(m_events)} events '
                f'({len(allowed)} allowed, {len(denied)} denied)'
                f'<span style="margin-left:auto;font-size:11px;font-weight:400;color:var(--text3)">'
                f'Device mount decisions</span></summary>'
                f'<div class="collapse-body">'
                f'<div class="table-wrap"><table class="data-table"><thead><tr>'
                f'<th>Timestamp</th><th>Device</th><th>Decision</th>'
                f'</tr></thead><tbody>{mount_rows_html}</tbody></table></div>'
                + (f'<div style="font-size:11px;color:var(--text3);margin-top:4px">Showing first 30 of {len(m_events)} events.</div>' if len(m_events) > 30 else "")
                + f'</div></details>'
            )

        # CPU high-water mark events
        cpu_html = ""
        c_events = agent_log.get("cpu_events", [])
        if c_events:
            exceeds_events = [e for e in c_events if e["exceeds"]]
            cpu_rows_html = "".join(
                f'<tr data-ts="{_esc(e["timestamp"][:19])}">'
                f'<td style="font-size:11px;color:var(--text3)">{_esc(e["timestamp"][:19])}</td>'
                f'<td><code style="font-size:11px">{_esc(e["process"])}</code></td>'
                f'<td style="text-align:right;{"color:#d97706" if e["exceeds"] else "color:#16a34a"}">'
                f'{"▲" if e["exceeds"] else "▼"} {e["value"]}%</td>'
                f'<td style="text-align:right;font-size:11px;color:var(--text3)">{e["threshold"]}%</td>'
                f'</tr>'
                for e in c_events[:30]
            )
            cpu_html = (
                f'<details class="collapse-panel" style="margin-top:8px">'
                f'<summary>CPU High-Water Mark Events — {len(c_events)} events '
                f'({len(exceeds_events)} threshold exceeded)'
                f'<span style="margin-left:auto;font-size:11px;font-weight:400;color:var(--text3)">'
                f'Per-process CPU threshold crossings</span></summary>'
                f'<div class="collapse-body">'
                f'<p style="font-size:12px;color:var(--text2);margin:0 0 10px">'
                f'Events logged when a process crosses its CPU usage threshold. '
                f'Repeated ▲ exceeded events without corresponding ▼ recovery may indicate runaway processes.</p>'
                f'<div class="table-wrap"><table class="data-table"><thead><tr>'
                f'<th>Timestamp</th><th>Process</th><th style="text-align:right">CPU%</th>'
                f'<th style="text-align:right">Threshold</th>'
                f'</tr></thead><tbody>{cpu_rows_html}</tbody></table></div>'
                + (f'<div style="font-size:11px;color:var(--text3);margin-top:4px">Showing first 30 of {len(c_events)} events.</div>' if len(c_events) > 30 else "")
                + f'</div></details>'
            )

        blocks.append(
            f'<div>'
            f'<div class="finding-field-label" '
            f'data-tip="Summary of logs/sentinelctl-log.txt — the SentinelOne agent internal log.">'
            f'Agent Log — sentinelctl-log.txt</div>'
            f'<div style="margin-top:8px;font-size:12px;color:var(--text2)">'
            f'Period: <code>{_esc(period_s)}</code> → <code>{_esc(period_e)}</code> · '
            f'{total:,} lines — {level_pills}</div>'
            + proxy_html
            + rcp_html
            + ka_html
            + err_html
            + asset_html
            + detection_html
            + integrity_html
            + device_ctrl_html
            + mount_html
            + cpu_html
            + f'</div>'
        )

    # ── Connectivity status ──────────────────────────────────────────────────
    if mgmt:
        connected = mgmt.get("Connected", "").lower() == "yes"
        conn_badge = (
            f'<span class="badge badge-ok">✓ Connected</span>'
            if connected else
            f'<span class="badge badge-err">✗ Not Connected</span>'
        )
        server = mgmt.get("Server", "—")
        last_seen = mgmt.get("Last Seen", "—")
        site_key = mgmt.get("Site Key", "")
        # Mask site key — show only prefix (e.g. "g_08435…")
        site_key_display = (site_key[:12] + "…") if len(site_key) > 12 else site_key

        conn_rows = [
            ("Status",       conn_badge),
            ("Server",       f'<code>{_esc(server)}</code>'),
            ("Last Heartbeat", f'<code>{_esc(last_seen)}</code>'),
        ]
        if site_key_display:
            conn_rows.append(("Site Key", f'<code>{_esc(site_key_display)}</code>'))

        # DV server from agent_config
        dv_server = ctx.agent_config.get("management_server", "")
        if dv_server and dv_server != server:
            conn_rows.append(("Deep Visibility Server",
                              f'<code style="font-size:11px">{_esc(dv_server)}</code>'))

        blocks.append(
            f'<div class="finding-field-label" '
            f'data-tip="Connection status and last heartbeat from sentinelctl-status.txt.">'
            f'Management Console Connectivity</div>'
            f'{_kv_table(conn_rows, {})}'
        )

    # ── Communication intervals ──────────────────────────────────────────────
    if intervals:
        def _fmt_sec(s: int) -> str:
            if s >= 3600:
                return f"{s // 3600}h"
            if s >= 60:
                return f"{s // 60}min"
            return f"{s}s"

        # Recommended ranges (min_sec, max_sec) for each interval key.
        # Values > 5× max are flagged "potentially isolated"; < 0.5× min are flagged "debug mode".
        _interval_recommended: dict[str, tuple[int, int]] = {
            "send_events_sec":        (60,  120),
            "batch_send_sec":         (30,  60),
            "connectivity_check_sec": (120, 300),
            "state_update_sec":       (60,  120),
        }

        def _interval_badge(key: str, val: int) -> str:
            if key not in _interval_recommended:
                return ""
            lo, hi = _interval_recommended[key]
            if val > hi * 5:
                return (
                    f'<span style="background:#dc262620;color:#dc2626;border:1px solid #dc262640;'
                    f'padding:1px 6px;border-radius:8px;font-size:10px;font-weight:600;'
                    f'margin-top:3px;display:inline-block" '
                    f'data-tip="Value is >5× the recommended maximum ({hi}s). '
                    f'This may indicate the agent is operating in a degraded or isolated state.">possibly isolated</span>'
                )
            if val < lo // 2:
                return (
                    f'<span style="background:#d9770620;color:#d97706;border:1px solid #d9770640;'
                    f'padding:1px 6px;border-radius:8px;font-size:10px;font-weight:600;'
                    f'margin-top:3px;display:inline-block" '
                    f'data-tip="Value is <0.5× the recommended minimum ({lo}s). '
                    f'This may indicate a debug or stress-test configuration.">debug mode</span>'
                )
            return ""

        int_defs = [
            ("batch_send_sec",          "Batch Send",         "Minimum interval between telemetry batches sent to console."),
            ("send_events_sec",         "Event Send",         "How often detection events are flushed to the management server."),
            ("update_interval_sec",     "Policy Sync",        "Frequency at which the agent checks for policy updates from console."),
            ("connectivity_check_sec",  "Connectivity Check", "How often the agent verifies its connection to the management server."),
            ("send_metrics_sec",        "Metrics Upload",     "Frequency of operational metrics sent to the management server."),
            ("state_update_sec",        "State Update",       "Full agent state reconciliation with the management server."),
        ]
        int_cards = "".join(
            f'<div class="sev-card" style="--sev-c:var(--cyan);min-width:100px" data-tip="{_esc(tip)}">'
            f'<div class="sev-card-count" style="font-size:18px">{_fmt_sec(intervals[k])}</div>'
            f'<div class="sev-card-label">{_esc(label)}</div>'
            f'{_interval_badge(k, intervals[k])}'
            f'</div>'
            for k, label, tip in int_defs
            if k in intervals
        )
        blocks.append(
            f'<div style="margin-top:20px">'
            f'<div class="finding-field-label" '
            f'data-tip="Communication timing configuration from sentinelctl-config.txt.">'
            f'Communication Intervals</div>'
            f'<div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:8px">{int_cards}</div>'
            f'</div>'
        )

    # ── Match reports telemetry timeline ─────────────────────────────────────
    if daily:
        sorted_dates = sorted(daily.keys())
        first_date, last_date = sorted_dates[0], sorted_dates[-1]
        total_files = sum(daily.values())
        span_days = (
            __import__("datetime").date.fromisoformat(last_date)
            - __import__("datetime").date.fromisoformat(first_date)
        ).days + 1
        avg_per_day = total_files / max(span_days, 1)

        # Gap detection: consecutive days with no reports (≥ 3 days)
        from datetime import date as _date, timedelta as _td
        gaps: list[dict] = []
        d = _date.fromisoformat(first_date)
        last_d = _date.fromisoformat(last_date)
        gap_start: _date | None = None
        while d <= last_d:
            ds = d.isoformat()
            if ds not in daily:
                if gap_start is None:
                    gap_start = d
            else:
                if gap_start is not None:
                    gap_len = (d - gap_start).days
                    if gap_len >= 3:
                        gaps.append({
                            "from": gap_start.isoformat(),
                            "to": (d - _td(days=1)).isoformat(),
                            "days": gap_len,
                        })
                    gap_start = None
            d += _td(days=1)

        # Summary stats row
        stats_html = (
            f'<div style="display:flex;gap:16px;flex-wrap:wrap;margin:8px 0 12px">'
            f'<div><span style="font-size:11px;color:var(--text3)">Total files</span>'
            f'<div style="font-size:20px;font-weight:700;color:var(--cyan)">{total_files:,}</div></div>'
            f'<div><span style="font-size:11px;color:var(--text3)">Period</span>'
            f'<div style="font-size:13px;font-weight:600;color:var(--text1)">'
            f'<code>{_esc(first_date)}</code> → <code>{_esc(last_date)}</code></div></div>'
            f'<div><span style="font-size:11px;color:var(--text3)">Days covered</span>'
            f'<div style="font-size:20px;font-weight:700;color:var(--text1)">'
            f'{len(sorted_dates)} / {span_days}</div></div>'
            f'<div><span style="font-size:11px;color:var(--text3)">Avg / day</span>'
            f'<div style="font-size:20px;font-weight:700;color:var(--text1)">'
            f'{avg_per_day:.1f}</div></div>'
            f'</div>'
        )

        # Gap alerts
        gaps_html = ""
        if gaps:
            gap_items = "".join(
                f'<div class="alert alert-warn" style="padding:6px 12px;margin-bottom:6px">'
                f'<span class="alert-icon">⚠️</span>'
                f'<div>No match reports for <strong>{g["days"]} days</strong>: '
                f'<code>{_esc(g["from"])}</code> → <code>{_esc(g["to"])}</code> — '
                f'possible telemetry gap or system offline period.</div></div>'
                for g in gaps[:10]
            )
            more = (f'<div style="font-size:11px;color:var(--text3);margin-top:4px">'
                    f'+ {len(gaps)-10} more gaps</div>') if len(gaps) > 10 else ""
            gaps_html = f'<div style="margin-bottom:12px">{gap_items}{more}</div>'
        else:
            gaps_html = (
                f'<div class="alert alert-ok" style="padding:6px 12px;margin-bottom:12px">'
                f'<span class="alert-icon">✓</span>'
                f'<div>No significant gaps detected — continuous telemetry throughout the reporting period.</div>'
                f'</div>'
            )

        # Bar chart — last 60 days
        recent_dates = sorted_dates[-60:]
        mx = max((daily.get(d, 0) for d in recent_dates), default=1) or 1
        chart_bars = "".join(
            f'<div class="chart-item" data-ts="{_esc(d)}">'
            f'<span class="chart-label" style="font-size:9px">{_esc(d)}</span>'
            f'<div class="chart-bar-row">'
            f'<div class="chart-bar-wrap">'
            f'<div class="chart-bar" data-pct="{round(daily.get(d,0)/mx*100,1)}" '
            f'style="width:0%;background:{"var(--ok)" if daily.get(d,0) else "var(--crit)"}">'
            f'</div></div>'
            f'<span class="chart-val">{daily.get(d, 0)}</span>'
            f'</div></div>'
            for d in recent_dates
        )
        chart_label = f"Last {len(recent_dates)} days" if len(sorted_dates) > 60 else "All days"
        blocks.append(
            f'<div style="margin-top:20px">'
            f'<div class="finding-field-label" '
            f'data-tip="Match report files generated per day. Each file represents a batch of behavioral events sent to the console.">'
            f'Telemetry Submission Timeline</div>'
            f'{stats_html}{gaps_html}'
            f'<div style="display:flex;align-items:center;gap:16px;margin-bottom:4px">'
            f'<span style="font-size:11px;color:var(--text3)">{_esc(chart_label)} — reports per day</span>'
            f'<span style="display:flex;gap:10px;font-size:11px;color:var(--text3)">'
            f'<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;'
            f'background:#16a34a;vertical-align:middle;margin-right:3px"></span>Reports received</span>'
            f'<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;'
            f'background:#dc2626;vertical-align:middle;margin-right:3px"></span>No reports (gap)</span>'
            f'</span></div>'
            f'<div class="stat-card"><div class="chart-row">{chart_bars}</div></div>'
            f'</div>'
        )

    # ATS connectivity test removed — test-the-catchall.sentinelone.net does not
    # resolve (NXDOMAIN), making all results systematically non-informative.

    inner = "".join(blocks)
    return (
        f'<section id="s-comms" class="section">'
        f'<div class="section-header"><span class="section-icon">📡</span>'
        f'<h2 class="section-title">Console Communication</h2>'
        f'<span class="section-subtitle" '
        f'data-tip="Agent connectivity, communication intervals, and telemetry submission analysis.">'
        f'sentinelctl-status · sentinelctl-config · match_reports</span></div>'
        + _sdesc(
            "sentinelctl-status.txt (connectivity + last heartbeat), sentinelctl-config.txt (communication intervals), "
            "match_reports/ directory (telemetry file dates), sentinelctl-log.txt (RCP requests, agent errors), "
            "ats-connectivity.txt (endpoint reachability).",
            "'Not Connected' at dump time does not necessarily mean a persistent outage — check the Last Heartbeat timestamp. "
            "<strong>Offline behavior:</strong> Static AI and Behavioral AI continue protecting the endpoint using locally cached policy. "
            "What stops working offline: STAR custom detection rules, cloud threat intelligence sync, Deep Visibility hunt queries, Remote Shell, and console alerting. "
            "<strong>Telemetry timeline:</strong> <span style=\"color:#16a34a;font-weight:600\">green</span> = reports received; "
            "<span style=\"color:#dc2626;font-weight:600\">red</span> = no reports. A gap ≥ 3 consecutive days is flagged. "
            "<strong>Communication intervals:</strong> very high values may indicate misconfiguration or intentional slowdown. "
            "<strong>ATS tests:</strong> verify reachability of SentinelOne cloud endpoints from the machine."
        )
        + f'<div class="card"><div class="card-body">{inner}</div></div>'
        f'</section>'
    )


def _blindspots_section(ctx: SystemContext) -> str:
    spots = []
    if ctx.sentinelctl_error:
        spots.append((
            "⚠️",
            f"<strong>macOS log archive unavailable:</strong> <code>{_esc(ctx.sentinelctl_error)}</code> — "
            "The macOS unified log archive could not be opened during dump collection. "
            "SentinelOne behavioral detection events (match_reports) are <strong>unaffected</strong> — "
            "only macOS system log context is unavailable."
        ))
    spots += [
        ("📦", "Unparsed formats: <code>.ips</code> (Apple binary crash), <code>.core_analytics</code>, "
               "<code>system_logs.logarchive</code> (requires native macOS <code>log</code> command)."),
        ("🤖", "Binary ML plists: <code>global-assets/dynamicEngine.plist</code>, "
               "<code>StaticAILibrary.plist</code> — models not decodable offline."),
    ]
    if ctx.sip_enabled is False:
        spots.append((
            "🔓",
            "<strong>SIP disabled:</strong> system file modifications cannot be distinguished "
            "from legitimate access with certainty."
        ))
    items_html = "".join(
        f'<div class="blindspot-item"><span class="blindspot-icon">{icon}</span>'
        f'<span>{text}</span></div>'
        for icon, text in spots
    )

    # Path exclusions — show actual decoded list or fallback note
    if ctx.path_exclusions:
        excl_tags = "".join(
            f'<div style="padding:2px 0;font-family:monospace;font-size:11px;'
            f'color:var(--text2);word-break:break-all">{_esc(p)}</div>'
            for p in ctx.path_exclusions[:50]
        )
        more = f'<div style="font-size:11px;color:var(--text3);margin-top:4px">+ {len(ctx.path_exclusions)-50} more…</div>' \
               if len(ctx.path_exclusions) > 50 else ""
        path_excl_html = (
            f'<div class="blindspot-item" style="flex-direction:column;gap:8px">'
            f'<div style="display:flex;gap:10px"><span class="blindspot-icon">🚫</span>'
            f'<strong>Path Exclusions ({len(ctx.path_exclusions)})</strong> — '
            f'Paths excluded from SentinelOne monitoring (<code>assets/pathExclusion.plist</code>).</div>'
            f'<div style="padding-left:26px">{excl_tags}{more}</div>'
            f'</div>'
        )
    else:
        path_excl_html = (
            '<div class="blindspot-item"><span class="blindspot-icon">🚫</span>'
            '<span>Path exclusions: <code>assets/pathExclusion.plist</code> uses a proprietary '
            'SentinelOne encrypted format and cannot be decoded offline. '
            'Review exclusions in the SentinelOne management console.</span></div>'
        )

    # DV exclusions
    if ctx.dv_exclusions:
        dv_tags = "".join(
            f'<div style="padding:2px 0;font-family:monospace;font-size:11px;'
            f'color:var(--text2);word-break:break-all">{_esc(p)}</div>'
            for p in ctx.dv_exclusions[:30]
        )
        more_dv = f'<div style="font-size:11px;color:var(--text3);margin-top:4px">+ {len(ctx.dv_exclusions)-30} more…</div>' \
                  if len(ctx.dv_exclusions) > 30 else ""
        dv_excl_html = (
            f'<div class="blindspot-item" style="flex-direction:column;gap:8px">'
            f'<div style="display:flex;gap:10px"><span class="blindspot-icon">📡</span>'
            f'<strong>Deep Visibility Exclusions ({len(ctx.dv_exclusions)})</strong> — '
            f'Paths excluded from Deep Visibility telemetry (<code>assets/dvExclusionsConsole.plist</code>).</div>'
            f'<div style="padding-left:26px">{dv_tags}{more_dv}</div>'
            f'</div>'
        )
    else:
        dv_excl_html = (
            '<div class="blindspot-item"><span class="blindspot-icon">📡</span>'
            '<span>Deep Visibility exclusions: <code>assets/dvExclusionsConsole.plist</code> uses a proprietary '
            'SentinelOne encrypted format and cannot be decoded offline. '
            'Review DV exclusions in the management console.</span></div>'
        )

    return (
        f'<section id="s-blindspots" class="section">'
        f'<div class="section-header"><span class="section-icon">👁️</span>'
        f'<h2 class="section-title">Blind Spots &amp; Limitations</h2></div>'
        + _sdesc(
            "This report is bounded by what was present in the dump and what the offline analyzer can decode. "
            "Items listed here are explicitly <strong>not analyzed</strong> — their absence from findings does not mean "
            "no threat exists in those areas.",
            "<strong>Undecoded formats:</strong> binary or encrypted files that could not be parsed (Protobuf blobs, encrypted caches). "
            "<strong>Offline limitations:</strong> cloud-based lookups (hash reputation, IP reputation) are not available. "
            "<strong>Path exclusions:</strong> directories explicitly excluded from SentinelOne monitoring by policy — "
            "any threat operating within an excluded path is invisible to the agent. "
            "Verify exclusions are intentional and not abnormally broad (e.g. excluding /Users/ entirely). "
            "<strong>Deep Visibility exclusions:</strong> event types or paths excluded from telemetry. "
            "If you suspect evasion, review exclusions carefully — attackers sometimes add exclusions via admin access before executing payloads."
        )
        + f'{items_html}'
        f'{path_excl_html}'
        f'{dv_excl_html}'
        f'</section>'
    )


# ─── Entry point ──────────────────────────────────────────────────────────────

def generate_html(
    ctx: SystemContext,
    findings: list[Finding],
    events: list[Event],
    output_path: Path,
) -> None:
    now = datetime.now(timezone.utc)
    score, risk_label = _risk_score(findings, ctx)
    health_level, health_col, health_reasons = _agent_health_score(ctx)
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    mr_events = [e for e in events if e.source_type == "match_report"]

    def _group_sep(label: str) -> str:
        return (
            f'<div class="group-sep">'
            f'<span class="group-sep-label">{_esc(label)}</span>'
            f'</div>'
        )

    # ── Pre-compute period data slices ────────────────────────────────────────
    # Periods: 1=24h, 7=7j, 30=30j, 0=Tout (all)
    _PERIOD_DAYS = [1, 7, 30, 0]
    ref_ts = _period_ref_ts(ctx, mr_events)
    _pdata: dict[int, dict] = {}
    for _days in _PERIOD_DAYS:
        _cutoff = _period_cutoff(ref_ts, _days)
        _pf = _filter_findings_by_period(findings, _cutoff)
        _pe = _filter_events_by_period(mr_events, _cutoff)
        _pc = _ctx_for_period(ctx, _cutoff)
        _ps, _pl = _risk_score(_pf, _pc)
        _pbs: dict[str, int] = {}
        for _f in _pf:
            _pbs[_f.severity] = _pbs.get(_f.severity, 0) + 1
        _pdata[_days] = {
            "f": _pf, "e": _pe, "ctx": _pc,
            "score": _ps, "label": _pl, "by_sev": _pbs,
        }

    def _pwrap(section_id: str, renders: dict) -> str:
        """Wrap 4 period renders in a container div; only 'Tout' (0) visible by default."""
        parts = [f'<div id="{section_id}">']
        for _d in _PERIOD_DAYS:
            _vis = 'block' if _d == 0 else 'none'
            parts += [
                f'<div class="period-view" data-period="{_d}" style="display:{_vis}">',
                renders[_d],
                '</div>',
            ]
        parts.append('</div>')
        return ''.join(parts)

    sections = "\n".join([
        # ── Overview — hero + static alerts always visible ────────────────────
        _hero(ctx, score, risk_label, now, findings, by_sev, health_level, health_col, health_reasons),
        _report_guide(),
        _operational_alerts_section(ctx),
        # ── Period-sensitive: Quick Brief ──────────────────────────────────────
        _pwrap("s-brief", {
            d: _no_section_id(_quick_brief_section(_pdata[d]["ctx"], _pdata[d]["f"], _pdata[d]["e"]))
            for d in _PERIOD_DAYS
        }),
        # ── Period-sensitive: Executive Summary ────────────────────────────────
        _pwrap("s-summary", {
            d: _no_section_id(_summary(_pdata[d]["f"], _pdata[d]["by_sev"]))
            for d in _PERIOD_DAYS
        }),
        # ── System — snapshot sections (no period filtering) ──────────────────
        _group_sep("System"),
        _system_section(ctx),
        _system_performance_section(ctx),
        _network_section(ctx),
        _services_section(ctx),
        # ── Period-sensitive: System Activity ──────────────────────────────────
        _pwrap("s-activity", {
            d: _no_section_id(_system_activity_section(_pdata[d]["ctx"]))
            for d in _PERIOD_DAYS
        }),
        # ── SentinelOne Agent ─────────────────────────────────────────────────
        _group_sep("SentinelOne Agent"),
        _agent_health_section(ctx),   # snapshot — current daemon / asset state
        # ── Period-sensitive: Console Communication ────────────────────────────
        _pwrap("s-comms", {
            d: _no_section_id(_console_comms_section(_pdata[d]["ctx"]))
            for d in _PERIOD_DAYS
        }),
        # ── Security Analysis ─────────────────────────────────────────────────
        _group_sep("Security Analysis"),
        # ── Period-sensitive: Process Analysis ─────────────────────────────────
        _pwrap("s-processes", {
            d: _no_section_id(_process_analysis_section(_pdata[d]["f"]))
            for d in _PERIOD_DAYS
        }),
        # ── Period-sensitive: Findings ─────────────────────────────────────────
        _pwrap("s-findings", {
            d: _no_section_id(_findings_section(_pdata[d]["f"]))
            for d in _PERIOD_DAYS
        }),
        # ── Period-sensitive: IOC Summary ──────────────────────────────────────
        _pwrap("s-ioc", {
            d: _no_section_id(_ioc_section(_pdata[d]["f"], _pdata[d]["e"]))
            for d in _PERIOD_DAYS
        }),
        # ── Period-sensitive: Event Timeline ───────────────────────────────────
        _pwrap("s-timeline", {
            d: _no_section_id(_timeline_section(_pdata[d]["e"]))
            for d in _PERIOD_DAYS
        }),
        # ── Period-sensitive: Statistics ───────────────────────────────────────
        _pwrap("s-stats", {
            d: _no_section_id(_stats_section(_pdata[d]["ctx"], _pdata[d]["f"], _pdata[d]["e"], period_uid=str(d)))
            for d in _PERIOD_DAYS
        }),
        # ── Static: Threat Intel + Blind Spots ────────────────────────────────
        _threat_intel_section(ctx),
        _blindspots_section(ctx),
    ])

    # Build monthly counts for area chart (all-time data for the hero chart)
    _monthly: dict[str, int] = {}
    for e in mr_events:
        k = e.timestamp.strftime("%Y-%m")
        _monthly[k] = _monthly.get(k, 0) + 1

    js_data = {
        "risk_score": score,
        "risk_label": risk_label,
        "health_level": health_level,
        "by_severity": by_sev,
        "mr_daily_counts": ctx.mr_daily_counts,
        "monthly_counts": dict(sorted(_monthly.items())),
        "periods": {
            str(d): {
                "score": _pdata[d]["score"],
                "label": _pdata[d]["label"],
                "count": len(_pdata[d]["f"]),
                "by_sev": _pdata[d]["by_sev"],
            }
            for d in _PERIOD_DAYS
        },
    }
    title = _esc(f"S1 macOS Log Analyzer — {ctx.hostname} | Security Report")

    doc = (
        f'<!DOCTYPE html>\n'
        f'<html lang="en" data-theme="dark">\n'
        f'<head>\n'
        f'<meta charset="UTF-8">\n'
        f'<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f'<title>{title}</title>\n'
        f'<style>{_CSS}</style>\n'
        f'</head>\n'
        f'<body>\n'
        f'<canvas id="particles-bg"></canvas>\n'
        f'<div class="layout">\n'
        f'{_nav(findings, by_sev, ctx)}\n'
        f'<main class="main-content">\n'
        f'{sections}\n'
        f'<footer class="report-footer">\n'
        f'<p>Generated by <strong>SentinelOne macOS Log Analyzer {APP_VERSION}</strong>'
        f' &nbsp;·&nbsp; Florian Bertaux'
        f' &nbsp;·&nbsp; {_esc(now.strftime("%Y-%m-%d %H:%M UTC"))}</p>\n'
        f'</footer>\n'
        f'</main>\n'
        f'</div>\n'
        f'<div id="tooltip-el" class="tooltip-bubble" role="tooltip" aria-hidden="true"></div>\n'
        f'<div id="copy-toast" class="copy-toast">&#10003; Copied!</div>\n'
        f'<script>window.REPORT_DATA = {_json_safe(js_data)};</script>\n'
        f'<script>{_JS}</script>\n'
        f'</body>\n'
        f'</html>\n'
    )
    output_path.write_text(doc, encoding="utf-8")
