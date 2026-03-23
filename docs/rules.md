# Detection Rules Reference

Complete reference for all 33 detection rules in SentinelOne macOS Log Analyzer.

Each rule maps to a MITRE ATT&CK technique and produces a `Finding` with severity, description, and remediation recommendation.

---

## Table of Contents

- [CONF — Configuration](#conf--configuration)
- [RECON — Reconnaissance](#recon--reconnaissance)
- [PRIV — Privilege Escalation](#priv--privilege-escalation)
- [PERSIST — Persistence](#persist--persistence)
- [CRED — Credential Access](#cred--credential-access)
- [EXFIL — Exfiltration](#exfil--exfiltration)
- [EVADE — Evasion](#evade--evasion)
- [CHAIN — Attack Chains](#chain--attack-chains)
- [Severity Reference](#severity-reference)

---

## CONF — Configuration

Rules that detect misconfiguration or degradation of the endpoint's security posture. These fire on `SystemContext` fields rather than behavioral events.

| ID | Name | Severity | MITRE |
|---|---|---|---|
| CONF-001 | SIP Disabled | CRITICAL | T1562.010 |
| CONF-002 | Agent Degraded | HIGH | T1562.001 |
| CONF-003 | Agent Not Operational | MEDIUM | T1562.001 |
| CONF-004 | Agent Version Mismatch | MEDIUM | — |
| CONF-005 | Agent Log Errors | MEDIUM | — |
| CONF-006 | Boot Arguments Modified | MEDIUM | T1562.010 |
| CONF-007 | Dual AV Installed | MEDIUM | — |
| CONF-008 | Unsigned Kernel Extensions | HIGH | T1215 |
| CONF-009 | Manual Software Installation | MEDIUM | T1072 |

### CONF-001 — SIP Disabled

**Severity:** CRITICAL &nbsp;·&nbsp; **MITRE:** T1562.010 — Disable or Modify Tools

System Integrity Protection is disabled on this endpoint. SIP prevents unauthorized modification of system files and protects SentinelOne's kernel-level components from tampering.

**Triggers:** `ctx.sip_enabled is False`

---

### CONF-002 — Agent Degraded

**Severity:** HIGH &nbsp;·&nbsp; **MITRE:** T1562.001 — Disable or Modify Tools

One or more SentinelOne agent services are in a degraded or not-ready state, indicating partial loss of protection coverage.

**Triggers:** Daemon states from `ctx.daemon_states` with `ready = False` (excluding on-demand daemons)

---

### CONF-003 — Agent Not Operational

**Severity:** MEDIUM &nbsp;·&nbsp; **MITRE:** T1562.001

The agent's operational state is not "enabled" or "active" per `sentinelctl status`.

**Triggers:** `ctx.sentinel_status.agent.Agent Operational State` not in (`enabled`, `active`, `running`)

---

### CONF-004 — Agent Version Mismatch

**Severity:** MEDIUM

The agent version reported in `sentinelctl status` does not match the version in the agent bundle plist. May indicate a failed upgrade or tampered binary.

**Triggers:** `ctx.agent_version` mismatch across sources

---

### CONF-005 — Agent Log Errors

**Severity:** MEDIUM

The agent internal log (`sentinelctl-log.txt`) contains ASSERT failures or a high error rate, indicating internal instability or schema mismatches.

**Triggers:** `ctx.agent_log.unique_asserts` non-empty or error rate above threshold

---

### CONF-006 — Boot Arguments Modified

**Severity:** MEDIUM &nbsp;·&nbsp; **MITRE:** T1562.010

Non-standard boot arguments are set in NVRAM (e.g. `-no_compat_check`, `amfi_get_out_of_my_way`). These can disable security enforcement at the kernel level.

**Triggers:** `ctx.boot_args` contains known security-disabling flags

---

### CONF-007 — Dual AV Installed

**Severity:** MEDIUM

A competing endpoint protection product is detected alongside SentinelOne. Running multiple EDR/AV solutions simultaneously is unsupported and may cause conflicts, false positives, or agent instability.

**Triggers:** Known AV/EDR signatures found in `ctx.installed_apps` or `ctx.third_party_services`

---

### CONF-008 — Unsigned Kernel Extensions

**Severity:** HIGH &nbsp;·&nbsp; **MITRE:** T1215 — Kernel Modules and Extensions

Third-party kernel extensions not signed by Apple or a known trusted vendor are loaded. Kernel extensions run at the highest privilege level and can bypass all user-space security controls.

**Triggers:** `ctx.third_party_kexts` contains extensions with untrusted signatures

---

### CONF-009 — Manual Software Installation

**Severity:** MEDIUM &nbsp;·&nbsp; **MITRE:** T1072 — Software Deployment Tools

Software was installed manually (outside of App Store or auto-update mechanisms) with elevated privileges. This may indicate unauthorized software deployment.

**Triggers:** `ctx.install_history` entries with `source_type = "manual"` and `uid = 0`

---

## RECON — Reconnaissance

Rules that detect Discovery techniques — processes probing the system, users, services, or network topology.

| ID | Name | Severity | MITRE |
|---|---|---|---|
| RECON-001 | Service Discovery | MEDIUM | T1007 |
| RECON-002 | Account Enumeration | MEDIUM | T1087 |
| RECON-003 | /etc/hosts Access | MEDIUM | T1016 |
| RECON-004 | SIP Status Query | LOW | T1082 |
| RECON-005 | Reconnaissance Chain | HIGH | T1082 |

### RECON-001 — Service Discovery

**Severity:** MEDIUM &nbsp;·&nbsp; **MITRE:** T1007 — System Service Discovery

A process queried running services or daemons (e.g. via `launchctl`, `systemextensionsctl`). Common in early-stage reconnaissance.

---

### RECON-002 — Account Enumeration

**Severity:** MEDIUM &nbsp;·&nbsp; **MITRE:** T1087 — Account Discovery

A process accessed local user account information (e.g. via `dscl`, `/etc/passwd`, `id`, `who`).

---

### RECON-003 — /etc/hosts Access

**Severity:** MEDIUM &nbsp;·&nbsp; **MITRE:** T1016 — System Network Configuration Discovery

A non-system process read or modified `/etc/hosts`. This file controls local DNS resolution and is a common target for redirect attacks.

---

### RECON-004 — SIP Status Query

**Severity:** LOW &nbsp;·&nbsp; **MITRE:** T1082 — System Information Discovery

A process queried System Integrity Protection status via `csrutil`. This is a common recon step to determine whether SIP is disabled before attempting privileged operations.

---

### RECON-005 — Reconnaissance Chain

**Severity:** HIGH &nbsp;·&nbsp; **MITRE:** T1082

Multiple distinct reconnaissance techniques were observed within a short time window from the same or related processes. This pattern is consistent with systematic pre-attack enumeration.

**Triggers:** 3+ different recon event types within 60 minutes in the Timeline index

---

## PRIV — Privilege Escalation

Rules detecting attempts to gain elevated privileges.

| ID | Name | Severity | MITRE |
|---|---|---|---|
| PRIV-001 | Sudo Usage | MEDIUM | T1548.003 |
| PRIV-002 | Permissions Modification | MEDIUM | T1222 |

### PRIV-001 — Sudo Usage

**Severity:** MEDIUM &nbsp;·&nbsp; **MITRE:** T1548.003 — Sudo and Sudo Caching

`sudo` was used by an unexpected process or at an unusual frequency. Elevated to MEDIUM if combined with other suspicious activity.

---

### PRIV-002 — Permissions Modification

**Severity:** MEDIUM &nbsp;·&nbsp; **MITRE:** T1222 — File and Directory Permissions Modification

A process modified file permissions (`chmod`, `chown`) on sensitive paths.

---

## PERSIST — Persistence

Rules detecting mechanisms used to maintain access across reboots.

| ID | Name | Severity | MITRE |
|---|---|---|---|
| PERSIST-001 | Crontab Modification | HIGH | T1053.003 |
| PERSIST-002 | Login Hook Installation | HIGH | T1037.002 |
| PERSIST-003 | Plist Modification | MEDIUM | T1543.001 |
| PERSIST-004 | Undiscovered Daemon | HIGH | T1543.004 |

### PERSIST-001 — Crontab Modification

**Severity:** HIGH &nbsp;·&nbsp; **MITRE:** T1053.003 — Cron

A process created or modified a crontab entry. Cron jobs survive reboots and run with the owner's privileges.

---

### PERSIST-002 — Login Hook Installation

**Severity:** HIGH &nbsp;·&nbsp; **MITRE:** T1037.002 — Login Hook

A Login Hook was installed in the system or user preferences. Login hooks execute arbitrary scripts at each login and are a well-known macOS persistence technique.

---

### PERSIST-003 — Plist Modification

**Severity:** MEDIUM &nbsp;·&nbsp; **MITRE:** T1543.001 — Launch Agent

A process wrote to a LaunchAgent or LaunchDaemon plist outside of known installer paths. This may indicate persistence installation.

---

### PERSIST-004 — Undiscovered Daemon

**Severity:** HIGH &nbsp;·&nbsp; **MITRE:** T1543.004 — Launch Daemon

A LaunchDaemon or LaunchAgent is present on disk that was not installed by any logged installer event and is not part of a known vendor. This is a strong indicator of unauthorized persistence.

---

## CRED — Credential Access

Rules detecting attempts to steal or access credentials.

| ID | Name | Severity | MITRE |
|---|---|---|---|
| CRED-001 | Keychain Access | MEDIUM | T1555.001 |
| CRED-002 | Private Key Access | HIGH | T1552.004 |
| CRED-003 | Library Validation Bypass | HIGH | T1574.006 |

### CRED-001 — Keychain Access

**Severity:** MEDIUM &nbsp;·&nbsp; **MITRE:** T1555.001 — Keychain

A non-system process accessed the macOS Keychain. The Keychain stores passwords, certificates, and cryptographic keys.

---

### CRED-002 — Private Key Access

**Severity:** HIGH &nbsp;·&nbsp; **MITRE:** T1552.004 — Private Keys

A process accessed files with `.pem`, `.key`, `.p12`, or similar extensions outside of known certificate management paths.

---

### CRED-003 — Library Validation Bypass

**Severity:** HIGH &nbsp;·&nbsp; **MITRE:** T1574.006 — Dynamic Linker Hijacking

Evidence of library validation being bypassed (e.g. via `DYLD_INSERT_LIBRARIES`, `CS_ALLOW_UNSIGNED_EXECUTABLE_MEMORY`). Used to inject unsigned code into processes.

---

## EXFIL — Exfiltration

Rules detecting data collection and transmission behaviors.

| ID | Name | Severity | MITRE |
|---|---|---|---|
| EXFIL-001 | Ingress Tool Transfer | HIGH | T1105 |
| EXFIL-002 | Archive Creation | MEDIUM | T1560.001 |
| EXFIL-003 | Data Collection / Staging | MEDIUM | T1074 |

### EXFIL-001 — Ingress Tool Transfer

**Severity:** HIGH &nbsp;·&nbsp; **MITRE:** T1105 — Ingress Tool Transfer

`curl`, `wget`, or similar tools were used to download content from external URLs. May indicate tool download or C2 communication.

---

### EXFIL-002 — Archive Creation

**Severity:** MEDIUM &nbsp;·&nbsp; **MITRE:** T1560.001 — Archive via Utility

A process created compressed archives (`.zip`, `.tar`, `.gz`, `.7z`) in unusual locations. Archive creation is a common pre-exfiltration step.

---

### EXFIL-003 — Data Collection / Staging

**Severity:** MEDIUM &nbsp;·&nbsp; **MITRE:** T1074 — Data Staged

Evidence of files being aggregated to a staging directory before potential exfiltration.

---

## EVADE — Evasion

Rules detecting defense evasion techniques.

| ID | Name | Severity | MITRE |
|---|---|---|---|
| EVADE-001 | Log Tampering | CRITICAL | T1070.002 |
| EVADE-002 | Timestamp Modification | HIGH | T1070.006 |
| EVADE-003 | Hidden Mach-O Binaries | HIGH | T1564.001 |
| EVADE-004 | Steganography Indicators | LOW | T1027.003 |

### EVADE-001 — Log Tampering

**Severity:** CRITICAL &nbsp;·&nbsp; **MITRE:** T1070.002 — Clear Linux or Mac System Logs

A process modified, cleared, or deleted system log files. Log tampering is a strong indicator of post-exploitation activity attempting to cover tracks.

---

### EVADE-002 — Timestamp Modification

**Severity:** HIGH &nbsp;·&nbsp; **MITRE:** T1070.006 — Timestomp

A process modified file timestamps (`touch -t`, `SetFile`). Timestomping is used to make malicious files appear older and blend with legitimate files.

---

### EVADE-003 — Hidden Mach-O Binaries

**Severity:** HIGH &nbsp;·&nbsp; **MITRE:** T1564.001 — Hidden Files and Directories

Executable Mach-O binaries were found in hidden directories (prefixed with `.`) or locations not typical for legitimate software.

---

### EVADE-004 — Steganography Indicators

**Severity:** LOW &nbsp;·&nbsp; **MITRE:** T1027.003 — Steganography

Tools or behaviors consistent with steganography were detected (hiding data inside image or media files for covert communication).

---

## CHAIN — Attack Chains

Rules that correlate multiple individual signals into a higher-confidence multi-stage attack pattern.

| ID | Name | Severity | MITRE |
|---|---|---|---|
| CHAIN-001 | Multi-process Recon Chain | HIGH | T1082 |
| CHAIN-002 | Crash Correlation | MEDIUM | — |

### CHAIN-001 — Multi-process Recon Chain

**Severity:** HIGH &nbsp;·&nbsp; **MITRE:** T1082

Multiple processes were observed performing reconnaissance activities in a coordinated sequence within a short time window. This pattern is consistent with an automated attack tool or scripted enumeration phase.

**Triggers:** ProcessIndex shows 3+ distinct processes each performing recon events within 60 minutes

---

### CHAIN-002 — Crash Correlation

**Severity:** MEDIUM

A process that appears in behavioral detection events also produced crash reports. This may indicate exploit attempts (triggering application crashes), sandbox escapes, or unstable injected code.

**Triggers:** Intersection of `group_index` process names with crash report process names from `ctx.system_sessions`

---

## Severity Reference

| Severity | Weight | Meaning |
|---|---|---|
| **CRITICAL** | 25 pts | Immediate threat — active protection bypass or system compromise indicator |
| **HIGH** | 10 pts | Strong indicator of malicious activity or significant security gap |
| **MEDIUM** | 4 pts | Suspicious behavior or notable misconfiguration requiring investigation |
| **LOW** | 1 pt | Weak signal — noteworthy but likely benign in isolation |
| **INFO** | 0 pts | Informational finding — no scoring impact, contextual only |

Risk score = min(100, Σ weights). Labels: `MINIMAL` (0) · `LOW` (1–24) · `MEDIUM` (25–49) · `HIGH` (50–74) · `CRITICAL` (≥ 75).
