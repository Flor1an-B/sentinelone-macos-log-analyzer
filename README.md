# SentinelOne macOS Log Analyzer

[![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.2.2-informational)]()
[![Platform](https://img.shields.io/badge/runs%20on-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?logo=python&logoColor=white)]()
[![Analyzes](https://img.shields.io/badge/analyzes-macOS%20SentinelOne%20dumps-blue?logo=apple)]()


> **Offline forensic analysis tool for SentinelOne diagnostic log dumps on macOS.**
> Parses a dump directory, applies 33 detection rules mapped to MITRE ATT&CK, and generates interactive HTML, Markdown, and JSON reports — no console access required.

**Author:** Florian Bertaux &nbsp;·&nbsp; **Requires:** Python 3.11+

---

## Table of Contents

- [Overview](#overview)
- [Requirements & Installation](#requirements--installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Output Files](#output-files)
- [HTML Report](#html-report)
- [Detection Rules](#detection-rules)
- [Risk Score](#risk-score)
- [Expected Dump Structure](#expected-dump-structure)
- [Architecture](#architecture)
- [Development](#development)

---

## Overview

**SentinelOne macOS Log Analyzer** processes a SentinelOne diagnostic dump and produces a full security analysis without requiring access to the management console. It is designed for:

- **L1/L2/L3 triage** — quickly assess whether a SentinelOne agent on a macOS endpoint is healthy and whether there are active threats
- **Incident response** — correlate behavioral detections, process chains, and agent log errors into prioritized findings
- **Compliance checks** — verify SIP status, agent version, policy enforcement, and configuration integrity

The tool is entirely **offline and self-contained**: the HTML report is a single file with no external dependencies.

### How to obtain a diagnostic dump

From the SentinelOne management console: **Endpoints → select device → Actions → Fetch Logs**. The downloaded archive contains the dump directory expected by this tool.

---

## Requirements & Installation

**Runtime requirements:**

| Requirement | Version |
|---|---|
| Python | 3.11+ |
| `biplist` | ≥ 1.0.3 |
| `rich` | ≥ 13.0 |

```bash
# Clone the repository
git clone https://github.com/Flor1an-B/sentinelone-macos-log-analyzer.git
cd sentinelone-macos-log-analyzer

# Install
pip install -e .

# Or install dependencies directly
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Analyze a dump — generates HTML + Markdown + JSON
macloganalyzer ./SentinelLog_2026.03.19_17.40.14_root

# Without installing (run from repo root)
python -m macloganalyzer ./SentinelLog_2026.03.19_17.40.14_root
```

The report is written to `SentinelLog_2026.03.19_17.40.14_root_report/` next to the dump.

---

## CLI Reference

```
macloganalyzer <dump_path> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `dump_path` | Path to the SentinelOne dump directory |

### Options

| Option | Default | Description |
|---|---|---|
| `-o, --output-dir PATH` | `<dump_name>_report/` | Output directory (created if missing) |
| `--format {md,json,html,all}` | `all` | Report format(s) to generate |
| `--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}` | `LOW` | Minimum severity threshold |
| `--since YYYY-MM-DD` | — | Include only events after this date (UTC) |
| `--until YYYY-MM-DD` | — | Include only events before this date (UTC) |
| `--process NAME` | — | Filter on process name (partial match, case-insensitive) |
| `-v, --verbose` | — | Enable detailed parsing logs |
| `--version` | — | Show version and exit |
| `--update` | — | Check for updates and download changed files from GitHub |

### Examples

```bash
# Check for updates (downloads only changed files)
macloganalyzer --update

# HTML report only, HIGH severity and above
macloganalyzer ./dump --format html --severity HIGH

# Scope to a specific date range
macloganalyzer ./dump --since 2026-03-15 --until 2026-03-19

# Focus on a specific process
macloganalyzer ./dump --process curl

# Custom output directory
macloganalyzer ./dump -o ./reports/incident-2026-03-19

# Verbose mode (shows parsing debug logs)
macloganalyzer ./dump --verbose
```

---

## Output Files

All output is written to `<dump_name>_report/` (or the path specified with `-o`):

| File | Format | Description |
|---|---|---|
| `<name>_report.html` | HTML | Interactive report — sidebar navigation, period filter, charts |
| `<name>_report.md` | Markdown | Static report for documentation or sharing |
| `<name>_findings.json` | JSON | Machine-readable findings export (SIEM-ready) |

---

## HTML Report

The HTML report is a **self-contained single file** with no external dependencies. It includes:

- **Analysis Period filter** — sidebar buttons (24h / 7 days / 30 days / All) dynamically re-render all time-sensitive sections without reloading
- **Security Risk gauge** — 0–100 score with animated arc, updates with selected period
- **Operational Alerts** — auto-generated prioritized alerts (CRITICAL → INFO) with remediation actions
- **Sidebar navigation** — jump directly to any section; findings badge and risk score update with the selected period
- **Dark / Light mode** — toggle available in the sidebar

### Report Sections

**Overview**
| Section | Content |
|---|---|
| Analyst Quick Brief | 1-page triage summary — key findings, agent health, connectivity, scan status |
| Executive Summary | Severity breakdown with donut chart and finding counts |

**System**
| Section | Content |
|---|---|
| System Context | Hardware model, OS version, architecture, SIP state, primary user |
| Performance | CPU load, memory pressure, disk usage, power state |
| Network | Interfaces, active connections, DNS servers, proxy configuration |
| Services | Launch daemons, launch agents, third-party kernel extensions |
| System Activity | Boot/shutdown events, package installs, login/logout history |

**SentinelOne Agent**
| Section | Content |
|---|---|
| S1 Agent Health | Version, daemon states, asset integrity, DB health, exclusions |
| Comm. Analysis | Management connectivity, RCP requests, keep-alive events, DV config errors |

**Security Analysis**
| Section | Content |
|---|---|
| Processes | Process profiles with linked detection events and MITRE techniques |
| Findings | All rule findings, filterable by severity and keyword |
| IOC | Indicators of Compromise extracted from behavioral detections |
| Timeline | Chronological event timeline across all sources |
| Statistics | Detection frequency, process rankings, heatmap, behavioral trends |
| Threat Intel | Threat intelligence asset versions from the agent |
| Blind Spots | Coverage gaps and detection limitations for the analyzed endpoint |

---

## Detection Rules

33 rules across 8 MITRE ATT&CK-mapped categories:

| Category | Rules | Examples |
|---|---|---|
| **CONF** — Configuration | 9 | SIP disabled, agent degradation, dual AV, unsigned kernel extensions |
| **RECON** — Reconnaissance | 5 | Account enumeration, service discovery, `/etc/hosts` access |
| **PRIV** — Privilege Escalation | 2 | Permissions modification, sudo patterns |
| **PERSIST** — Persistence | 4 | Crontab, login hooks, plist persistence, undiscovered daemons |
| **CRED** — Credential Access | 3 | Keychain access, private key files, library validation bypass |
| **EXFIL** — Exfiltration | 3 | Archive creation, data staging, ingress tools (curl/wget) |
| **EVADE** — Evasion | 4 | Log tampering, timestamp modification, hidden Mach-O binaries |
| **CHAIN** — Attack Chains | 2 | Multi-process recon chains, crash-correlated detections |

Each finding includes: Rule ID · Severity · MITRE ATT&CK technique · Description · Recommendation · Linked evidence events with timestamps.

See [`docs/rules.md`](docs/rules.md) for the complete rule reference.

---

## Risk Score

The report displays a **0–100 risk score** computed from the weighted sum of findings:

| Severity | Weight | Label threshold |
|---|---|---|
| CRITICAL | 25 pts | ≥ 75 → CRITICAL |
| HIGH | 10 pts | ≥ 50 → HIGH |
| MEDIUM | 4 pts | ≥ 25 → MEDIUM |
| LOW | 1 pt | > 0 → LOW |
| INFO | 0 pts | 0 → MINIMAL |

Score is capped at 100. The score updates dynamically in the HTML report when changing the analysis period.

---

## Expected Dump Structure

The tool expects a directory produced by `sentinelctl` or the SentinelOne console log-fetch action. Auto-detection looks for `match_reports/`, `sentinelctl-status.txt`, or `csrutil_status.txt` — and will descend one level if a wrapper directory is given.

```
SentinelLog_2026.03.19_17.40.14_root/
├── sentinelctl-status.txt        ← Agent status & management config
├── sentinelctl-config.txt        ← Communication timing config
├── sentinelctl-config_policy.txt ← Policy feature settings
├── sentinelctl-config_local.txt  ← Local config overrides (if any)
├── sentinelctl-scan-info.txt     ← Last scan status
├── sentinelctl-stats.txt         ← DB read/write statistics
├── sentinelctl-policies.txt      ← Detection rule actions
├── csrutil_status.txt            ← System Integrity Protection state
├── ifconfig.txt                  ← Network interfaces
├── lsof-i.txt                    ← Active network connections
├── netstat-anW.txt               ← All sockets (listening + established)
├── df.txt                        ← Disk volumes and capacity
├── ps.txt                        ← Running processes at dump time
├── top.txt                       ← System load and memory summary
├── vm_stat.txt                   ← Memory pressure metrics
├── pmset-live.txt / pmset-ps.txt ← Power and battery state
├── scutil_proxy.txt              ← Proxy configuration
├── scutil_dns.txt                ← DNS servers
├── kextstat.txt                  ← Loaded kernel extensions
├── mount.txt                     ← Mounted volumes
├── pkgutil.txt                   ← Security packages (XProtect, Gatekeeper)
├── ioreg.txt                     ← Hardware serial number
├── users.txt                     ← Local user accounts
├── Applications.txt              ← Installed applications
├── LaunchDaemons.txt             ← System launch daemons
├── LaunchAgents.txt              ← User launch agents
├── KernelExtensions.txt          ← Kernel extension list
├── PrivilegedHelperTools.txt     ← Privileged helper tools
├── SentinelDirectorySize.txt     ← Agent DB directory sizes
├── match_reports/                ← Behavioral detections (JSONL)
│   └── *.jsonl
├── logs/
│   ├── sentinelctl-log.txt       ← SentinelOne agent internal log
│   ├── install.log               ← Package installation history
│   ├── asl.log                   ← Boot/shutdown/login events
│   └── ui-logs/                  ← Agent UI state logs
├── crashes/                      ← Crash reports (.diag)
├── assets/                       ← Protection policies & exclusions
│   ├── pathExclusion.plist
│   ├── dvExclusionsConsole.plist
│   └── mgmtConfig.plist
├── config_s1/                    ← Agent configuration plists
├── global-assets/                ← ML models & threat intelligence
│   └── *-metadata.plist
└── bundle/
    └── sentinel-agent.plist      ← Agent version and UUID
```

> **Note:** Dumps 1 and 2 of a collection set often have a truncated `sentinelctl-log.txt` (`log: Could not open local log store`). Agent log sections (dynamic detections, integrity protection blocks, CPU events) will only be populated for dumps with valid log content.

---

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full technical reference.

**Pipeline overview:**

```
Dump directory
      │
      ▼
┌─────────────────┐
│  1. Ingest      │  text_parser · plist_parser · extended_text_parser
│                 │  install_log_parser → SystemContext
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  2. Parse       │  jsonl_parser (match_reports/) → [Event]
│                 │  ui_log_parser · crash_parser
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  3. Correlate   │  Timeline · ProcessIndex · GroupIndex
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  4. Rules       │  33 rules × AnalysisContext → [Finding]
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  5. Filter      │  severity · date range · process
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  6. Report      │  HTML · Markdown · JSON · Console
└─────────────────┘
```

---

## Development

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=macloganalyzer

# Analyze a local dump without installing (run from repo root)
python -m macloganalyzer ./dump_path

# Verbose mode (debug-level parsing logs)
python -m macloganalyzer ./dump_path --verbose
```

### Project layout

```
macloganalyzer/
├── __main__.py          Entry point & CLI
├── pipeline.py          6-step analysis pipeline
├── config.py            Shared constants
├── models/              Event · Finding · SystemContext
├── ingest/              7 source parsers
├── correlate/           Timeline · ProcessIndex · GroupIndex
├── analyze/             Operational alert engine
├── rules/               33 detection rules (8 categories)
└── report/              HTML · Markdown · JSON · Console
```

---

## Disclaimer

This tool is an independent community project and is not affiliated with, endorsed by, or supported by SentinelOne, Inc. SentinelOne is a registered trademark of SentinelOne, Inc.
