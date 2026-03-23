# Architecture

Technical reference for SentinelOne macOS Log Analyzer internals.

---

## Table of Contents

- [Package Layout](#package-layout)
- [Pipeline](#pipeline)
- [Data Models](#data-models)
- [Ingest Layer](#ingest-layer)
- [Correlation Layer](#correlation-layer)
- [Detection Rules](#detection-rules)
- [Report Layer](#report-layer)
- [Key Design Decisions](#key-design-decisions)

---

## Package Layout

```
macloganalyzer/
├── __main__.py              CLI entry point (argparse, progress bar, orchestration)
├── pipeline.py              6-step analysis pipeline — single call returns (ctx, findings, events)
├── config.py                Shared constants (severity weights, file markers, etc.)
│
├── models/
│   ├── context.py           SystemContext — 100+ fields, hub for all parsed data
│   ├── finding.py           Finding — rule output with evidence, MITRE link, timestamps
│   └── event.py             Event — normalized atomic event from any log source
│
├── ingest/                  Parsers — each adds fields to SystemContext
│   ├── text_parser.py       Root text files (Applications.txt, df.txt, etc.)
│   ├── jsonl_parser.py      match_reports/*.jsonl → [Event]
│   ├── plist_parser.py      Plist files (XML + binary via biplist)
│   ├── ui_log_parser.py     logs/ui-logs/ → agent state events
│   ├── crash_parser.py      crashes/*.diag → crash Events
│   ├── install_log_parser.py logs/install.log + asl.log → install history / sessions
│   └── extended_text_parser.py Policies, netstat, kexts, ps, DB stats, proxy, etc.
│
├── correlate/               Indexes built over [Event] before rule evaluation
│   ├── timeline.py          Chronologically sorted event index
│   ├── process_index.py     process_name → [Event] mapping
│   └── group_index.py       group_id → [Event] mapping (match_reports dedup)
│
├── analyze/
│   └── alerts.py            Operational alert engine — queries SystemContext, returns [dict]
│
├── rules/                   Detection rules — auto-discovered via registry
│   ├── base.py              BaseRule abstract class
│   ├── registry.py          Dynamic rule discovery (importlib + __subclasses__)
│   ├── conf/                9 Configuration rules (CONF-001 … CONF-009)
│   ├── recon/               5 Reconnaissance rules (RECON-001 … RECON-005)
│   ├── priv/                2 Privilege Escalation rules
│   ├── persist/             4 Persistence rules
│   ├── cred/                3 Credential Access rules
│   ├── exfil/               3 Exfiltration rules
│   ├── evade/               4 Evasion rules
│   └── chain/               2 Attack Chain rules
│
└── report/
    ├── console.py           Rich terminal output (banner, summary)
    ├── html_report.py       Self-contained interactive HTML report
    ├── markdown.py          Static Markdown report
    └── json_report.py       Machine-readable JSON export
```

---

## Pipeline

`pipeline.run_pipeline()` is the single entry point from `__main__.py`. It runs 6 sequential steps and returns `(SystemContext, list[Finding], list[Event])`.

### Step 1 — Ingest system files

Parsers run in order against the dump root:

1. `text_parser` — reads root `.txt` files into `SystemContext` (apps, daemons, agents, kexts, network, disk, users, SIP state, boot args)
2. `plist_parser` — reads `bundle/`, `preferences_system/`, `assets/`, `config_s1/` plist files (agent version, UUID, exclusions, policy config, DB metadata)
3. `install_log_parser` — parses `logs/install.log` (package installs) and `logs/asl.log` (boot/shutdown/login events)
4. `extended_text_parser` — reads secondary text sources (sentinelctl outputs, netstat, kextstat, ps, top, vm_stat, pmset, scutil, ioreg, pkgutil, curl_ns_ats)
5. `alerts.generate_operational_alerts(ctx)` — synthesizes all parsed state into prioritized operational alerts stored in `ctx.operational_alerts`

### Step 2 — Parse match_reports

`jsonl_parser` reads every `.jsonl` file under `match_reports/`. Each line is a behavioral detection event. Output is a flat `list[Event]` with:

- `source_type = "match_report"`
- `process_path`, `process_name`, `timestamp`, `event_type`, `behavior_category`
- `group_id` for correlation across related events
- `target_path`, `extra` dict for raw fields

Daily file counts are stored in `ctx.mr_daily_counts` (used for the heatmap chart).

### Step 3 — Parse UI logs + crash reports

`ui_log_parser` reads `logs/ui-logs/` for agent UI state messages.
`crash_parser` reads `crashes/*.diag` for crash events with process, PID, action taken.

Both produce `Event` objects appended to the main events list.

### Step 4 — Agent internal log

`extended_text_parser` (called in step 1) also parses `logs/sentinelctl-log.txt` into `ctx.agent_log` with error counts, ASSERT failures, RCP requests, keep-alive events, and asset update history.

### Step 5 — Correlate & apply rules

1. **Date/process filtering** — all events filtered by `--since`, `--until`, `--process`
2. **Index building:**
   - `Timeline` — events sorted by timestamp
   - `ProcessIndex` — `{process_name: [events]}`
   - `GroupIndex` — `{group_id: [events]}` for match_report correlation
3. **Rule evaluation** — `registry.load_rules()` discovers all `BaseRule` subclasses; each rule's `.evaluate(ctx, timeline, process_index, group_index)` returns zero or more `Finding` objects
4. **Severity filtering** — findings below `--severity` threshold dropped
5. **Sorting** — findings sorted by severity weight then timestamp descending

### Step 6 — Report generation

Called from `__main__.py` after the pipeline returns:

- `generate_html()` — builds self-contained HTML with pre-computed period slices (1d / 7d / 30d / all)
- `generate_markdown()` — flat Markdown document
- `generate_json()` — JSON array of finding dicts
- `print_summary()` — Rich console output (banner, alerts, system overview, stats, output paths)

---

## Data Models

### `Event`

Normalized atomic event from any log source.

```python
@dataclass
class Event:
    source_file: str          # Originating file path (relative to dump root)
    source_type: str          # "match_report" | "ui_log" | "crash_diag"
    timestamp: datetime       # UTC-aware timestamp
    process_path: str         # Full binary path
    process_name: str         # Binary name (basename of process_path)
    event_type: str           # file_modified | process_attach | network_flow | …
    behavior_category: str | None  # MITRE tactic hint from SentinelOne
    target_path: str | None   # File, network addr, or path affected
    group_id: str | None      # Match-report group ID for correlation
    extra: dict               # Raw additional fields from the source
```

### `Finding`

Output of a single rule evaluation.

```python
@dataclass
class Finding:
    rule_id: str              # e.g. "CONF-001"
    rule_name: str            # Human-readable rule name
    severity: str             # CRITICAL | HIGH | MEDIUM | LOW | INFO
    description: str          # Explanation of what was detected
    recommendation: str       # Remediation action
    process: str              # Associated process name (empty if N/A)
    mitre_id: str | None      # e.g. "T1562.001"
    mitre_name: str | None    # e.g. "Disable or Modify Tools"
    evidence: list[Event]     # Linked events supporting this finding
    first_seen: datetime | None
    last_seen: datetime | None
```

### `SystemContext`

Central data hub populated by all parsers, queried by all rules.

Key field groups:

| Group | Fields |
|---|---|
| **Identity** | `hostname`, `model`, `os_version`, `arch`, `primary_user`, `serial_number` |
| **Agent** | `agent_version`, `agent_uuid`, `console_url`, `sip_enabled`, `boot_args` |
| **Installed** | `installed_apps`, `launch_daemons`, `launch_agents`, `kernel_extensions` |
| **Network** | `network_interfaces`, `ifconfig_interfaces`, `network_connections`, `dns_servers`, `proxy_config` |
| **Disk** | `disk_volumes`, `mounted_volumes` |
| **S1 Status** | `sentinel_status`, `daemon_states`, `asset_signatures`, `sentinel_db_health`, `sentinel_operational` |
| **S1 Config** | `agent_config`, `policy_config`, `mgmt_config`, `comm_intervals`, `path_exclusions`, `dv_exclusions` |
| **Logs** | `agent_log`, `install_history`, `system_sessions`, `install_stats`, `mr_daily_counts` |
| **Connectivity** | `ats_results`, `third_party_services`, `detection_policies` |
| **Performance** | `vm_memory`, `system_load`, `power_state` |
| **Security** | `security_packages`, `privileged_helpers`, `third_party_kexts`, `running_processes` |
| **Computed** | `operational_alerts`, `parse_stats`, `parse_warnings` |

---

## Ingest Layer

Each parser is a standalone module with a single public function that takes the dump path and a `SystemContext`, mutates the context in place, and returns nothing (or a list of events for event-producing parsers).

| Parser | Key sources | Output |
|---|---|---|
| `text_parser` | Applications.txt, LaunchDaemons/Agents.txt, KernelExtensions.txt, df.txt, ifconfig.txt, lsof-i.txt, users.txt, csrutil_status.txt, boot_args.txt, uname.txt | `ctx.*` system fields |
| `plist_parser` | bundle/sentinel-agent.plist, assets/*.plist, config_s1/*.plist, global-assets/*-metadata.plist | `ctx.agent_version`, `ctx.agent_config`, `ctx.intelligence_metadata`, `ctx.path_exclusions`, etc. |
| `install_log_parser` | logs/install.log, logs/asl.log | `ctx.install_history`, `ctx.system_sessions`, `ctx.install_stats` |
| `extended_text_parser` | sentinelctl-*.txt, netstat-anW.txt, kextstat.txt, ps.txt, top.txt, vm_stat.txt, pmset-*.txt, scutil_*.txt, ioreg.txt, pkgutil.txt, curl_ns_ats.txt, mount.txt | `ctx.sentinel_status`, `ctx.agent_log`, `ctx.netstat_connections`, `ctx.sentinel_db_health`, `ctx.vm_memory`, `ctx.system_load`, `ctx.power_state`, etc. |
| `jsonl_parser` | match_reports/*.jsonl | `list[Event]`, `ctx.mr_daily_counts`, `ctx.parse_stats` |
| `ui_log_parser` | logs/ui-logs/*.log | `list[Event]`, `ctx.ui_agent_states` |
| `crash_parser` | crashes/*.diag | `list[Event]`, `ctx.parse_stats["crash_events"]` |

---

## Correlation Layer

Three indexes are built from the event list before rules run:

### `Timeline`
Chronologically sorted list of all events. Rules use it to detect activity within a time window (e.g. recon chain: N different recon techniques within 60 minutes).

### `ProcessIndex`
`dict[str, list[Event]]` keyed by `process_name`. Rules use it to find all activity by a specific binary.

### `GroupIndex`
`dict[str, list[Event]]` keyed by `group_id`. Match-report events with the same group ID belong to the same detection context. Rules use this to retrieve all correlated events for a given detection group and avoid counting the same group twice.

---

## Detection Rules

### BaseRule

```python
class BaseRule:
    rule_id: str
    rule_name: str
    severity: str
    mitre_id: str | None
    mitre_name: str | None

    def evaluate(
        self,
        ctx: SystemContext,
        timeline: Timeline,
        process_index: ProcessIndex,
        group_index: GroupIndex,
    ) -> list[Finding]: ...
```

### Rule registry

`registry.load_rules()` uses `importlib` to import all modules under `rules/` and returns instances of every `BaseRule` subclass. Adding a new rule only requires creating a new `.py` file in the appropriate subdirectory — no registration needed.

### Rule categories

| Prefix | MITRE tactic | Count |
|---|---|---|
| `CONF` | Defense Evasion / Impact (configuration) | 9 |
| `RECON` | Discovery | 5 |
| `PRIV` | Privilege Escalation | 2 |
| `PERSIST` | Persistence | 4 |
| `CRED` | Credential Access | 3 |
| `EXFIL` | Exfiltration | 3 |
| `EVADE` | Defense Evasion | 4 |
| `CHAIN` | Multiple | 2 |

See [`rules.md`](rules.md) for the complete rule reference.

---

## Report Layer

### HTML report (`html_report.py`)

The HTML report is generated as a **self-contained single file** — all CSS, JS, and data are inlined.

**Period filtering architecture:**
Rather than aggregating data in the browser, the Python generator pre-computes four complete versions of every time-sensitive section (1 day / 7 days / 30 days / all-time). Each version is wrapped in a `<div class="period-view" data-period="N">` container. JavaScript simply toggles `display` on the matching container — zero client-side data processing.

**Reference timestamp:**
The period cutoff is computed relative to the latest activity in the dump (`log_period_end` from the agent log, then the latest event timestamp) — never relative to wall-clock now. This ensures correct filtering on historical dumps.

**Key JS data object:**
`window.REPORT_DATA` is embedded as a `<script>` tag and contains:
- `risk_score`, `risk_label`, `by_severity` — all-time values
- `periods` — per-period `{score, label, count, by_sev}` for sidebar/gauge updates
- `mr_daily_counts` — daily event counts for the heatmap
- `monthly_counts` — monthly counts for the area chart

### Console output (`console.py`)

Uses the `rich` library. Sections rendered after analysis:
1. Banner (app name, version, author)
2. Operational alerts panel (if any CRITICAL/HIGH)
3. System Overview panel
4. Parse statistics
5. Output file paths

---

## Key Design Decisions

**Single-pass pipeline, no intermediate files.**
All parsers write directly to `SystemContext`. No intermediate serialization. Keeps I/O minimal and the pipeline fast even on large dumps.

**Pre-computed period slices in HTML.**
Client-side aggregation would require embedding raw event data (potentially MBs). Pre-computing 4 complete renders in Python keeps the JS trivial and the HTML fully self-contained.

**Dynamic rule discovery.**
Rules are loaded via `importlib` + `__subclasses__()`. No central registry file to maintain — adding a rule file is enough.

**Graceful degradation.**
Every parser catches exceptions at the file level and logs warnings rather than aborting. A dump with missing or malformed files still produces a partial but valid report.

**SystemContext as the single source of truth.**
All parsed data flows into one dataclass. Rules, alert engine, and report generators all read from the same object — no hidden state, easy to test.
