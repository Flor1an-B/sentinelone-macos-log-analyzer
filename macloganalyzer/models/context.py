from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class SystemContext:
    dump_path: str = ""
    hostname: str = "Unknown"
    model: str = "Unknown"
    os_version: str = "Unknown"
    arch: str = "Unknown"
    primary_user: str = "Unknown"
    agent_version: str = "Unknown"
    agent_uuid: str = ""
    console_url: str = ""
    sip_enabled: bool | None = None
    boot_args: str = ""
    cpu_count: int = 0
    disk_usage: str = ""
    installed_apps: list[str] = field(default_factory=list)
    # Metadata per app name — keys: owner, group, modified, install_type ("system"|"user")
    installed_apps_meta: dict = field(default_factory=dict)
    launch_daemons: list[str] = field(default_factory=list)
    launch_agents: list[str] = field(default_factory=list)
    kernel_extensions: list[str] = field(default_factory=list)
    network_interfaces: list[dict] = field(default_factory=list)
    ui_agent_states: list[str] = field(default_factory=list)
    sentinelctl_error: str | None = None
    parse_warnings: list[str] = field(default_factory=list)
    parse_stats: dict = field(default_factory=dict)

    # ── New enriched fields ──────────────────────────────────────────────────
    # Parsed from sentinelctl-status.txt
    sentinel_status: dict = field(default_factory=dict)
    # Parsed from ifconfig.txt  – list of {name, ipv4, ipv6, mac, status}
    ifconfig_interfaces: list[dict] = field(default_factory=list)
    # Parsed from lsof-i.txt – list of {command, pid, user, proto, name, state}
    network_connections: list[dict] = field(default_factory=list)
    # Parsed from users.txt – list of {name, uid}
    local_users: list[dict] = field(default_factory=list)
    # Parsed from launchctl-print-disabled.txt – list of {name, enabled}
    third_party_services: list[dict] = field(default_factory=list)
    # Parsed from df.txt – list of {filesystem, size, used, avail, capacity, mounted}
    disk_volumes: list[dict] = field(default_factory=list)
    # Parsed from scutil_dns.txt
    dns_servers: list[str] = field(default_factory=list)
    # Parsed from systemextensionsctl_list.txt – list of {team_id, bundle_id, name, state}
    system_extensions: list[dict] = field(default_factory=list)

    # ── Extended sources ──────────────────────────────────────────────────────
    # Parsed from config_s1/ key plist files — agent configuration summary
    agent_config: dict = field(default_factory=dict)
    # Parsed from global-assets/*-metadata.plist — threat intelligence versions
    intelligence_metadata: dict = field(default_factory=dict)
    # Parsed from assets/pathExclusion.plist — monitored path exclusions
    path_exclusions: list[str] = field(default_factory=list)
    # Parsed from assets/dvExclusionsConsole.plist — Deep Visibility exclusions
    dv_exclusions: list[str] = field(default_factory=list)
    # Parsed from assets/mgmtConfig.plist — management configuration
    mgmt_config: dict = field(default_factory=dict)
    # Parsed from PrivilegedHelperTools.txt — tools with elevated privileges
    privileged_helpers: list[str] = field(default_factory=list)

    # ── logs/ directory ───────────────────────────────────────────────────────
    # Parsed from logs/install.log — package installation events
    # Each: {timestamp, date, package_name, bundle_id, version,
    #         source_type, source_path, trust_level, uid}
    # source_type: "app_store"|"auto_update"|"system_update"|"manual"|"sentinel"|"unknown"
    install_history: list[dict] = field(default_factory=list)
    # Parsed from logs/asl.log — boot/shutdown/login/logout events
    # Each: {event_type, timestamp, unix_time, pid}
    system_sessions: list[dict] = field(default_factory=list)
    # Aggregate statistics from install.log + asl.log
    # Keys: total_installs, update_checks, xprotect_updates, boot_count,
    #       sentinel_install_date, log_period_start, log_period_end, sleep_count
    install_stats: dict = field(default_factory=dict)

    # ── Extended text sources ─────────────────────────────────────────────────
    # Parsed from sentinelctl-policies.txt — detection rule actions
    # Each: {name: str, action: str}  action: "mitigate"|"inform"|"validate"|"disabled"
    detection_policies: list[dict] = field(default_factory=list)
    # Parsed from netstat-anW.txt — active network connections + listening ports
    # Each: {proto, local_addr, local_port, remote_addr, remote_port, state}
    netstat_connections: list[dict] = field(default_factory=list)
    # Parsed from kextstat.txt — third-party (non-Apple) kernel extensions
    # Each: {name: str, version: str, uuid: str}
    third_party_kexts: list[dict] = field(default_factory=list)
    # Parsed from sentinelctl-scan-info.txt + sentinelctl-stats.txt
    # Keys: last_scan_status, active_scans, db_stats_start, db_bytes_read, db_bytes_written
    sentinel_operational: dict = field(default_factory=dict)
    # Parsed from mount.txt — mounted APFS/HFS volumes
    # Each: {device: str, mountpoint: str, fstype: str, options: list[str]}
    mounted_volumes: list[dict] = field(default_factory=list)

    # ── Console communication analysis ────────────────────────────────────────
    # Parsed from sentinelctl-config.txt — communication timing configuration
    # Keys: send_events_sec, batch_send_sec, connectivity_check_sec,
    #        state_update_sec, send_metrics_sec, update_interval_sec
    comm_intervals: dict = field(default_factory=dict)
    # Parsed from curl_ns_ats.txt — ATS network connectivity test results
    # Each: {test: str, result: str}  result: "PASS"|"FAIL"
    ats_results: list[dict] = field(default_factory=list)
    # Computed in pipeline from match_reports filenames — reports per calendar day
    # Keys: date_str ("YYYY-MM-DD") → count (int)
    mr_daily_counts: dict = field(default_factory=dict)

    # Parsed from logs/sentinelctl-log.txt — agent internal log
    # Keys: log_period_start, log_period_end, total_lines, error_count,
    #       level_counts {I/E/Df/W → int}, error_by_component {component → int},
    #       unique_asserts {msg → count}, rcp_requests [{timestamp, req_type, req_id}],
    #       rcp_type_counts {type → count}, keep_alive_count, keep_alive_recent [ts],
    #       asset_updates [{timestamp, name, version}]
    agent_log: dict = field(default_factory=dict)

    # Parsed from scutil_proxy.txt — system proxy configuration
    # Keys: has_proxy (bool), proxy_server (str), exceptions (list[str])
    proxy_config: dict = field(default_factory=dict)

    # Parsed from sentinelctl-config_policy.txt — management policy feature settings
    # Keys: section_name → {key: value} e.g. "DeepVisibility" → {"Enabled": "1", ...}
    policy_config: dict = field(default_factory=dict)

    # Parsed from ps.txt — running processes at dump time
    # Each: {user, pid, cpu, mem, binary, command}
    running_processes: list[dict] = field(default_factory=list)

    # Parsed from pkgutil.txt — security-relevant installed packages
    # Each: package identifier string (XProtect, Gatekeeper, MRT, etc.)
    security_packages: list[str] = field(default_factory=list)

    # ── System performance ────────────────────────────────────────────────────
    # Parsed from vm_stat.txt — memory pressure metrics
    # Keys: free_mb, active_mb, wired_mb, compressed_mb, pressure_level,
    #        swapins, swapouts, compressions, decompressions
    vm_memory: dict = field(default_factory=dict)
    # Parsed from top.txt — load averages and physical memory summary
    # Keys: load_1, load_5, load_15, cpu_idle_pct, physmem_used_mb,
    #        physmem_free_mb, physmem_wired_mb, physmem_compressor_mb,
    #        processes_total, threads_total, disk_read_gb, disk_write_gb
    system_load: dict = field(default_factory=dict)
    # Parsed from pmset-live.txt + pmset-ps.txt — power and battery state
    # Keys: on_battery (bool), battery_pct (int), battery_status (str),
    #        battery_remaining (str), sleep_preventing (list[str]),
    #        low_power_mode (bool), hibernatemode (int)
    power_state: dict = field(default_factory=dict)

    # ── Agent daemon and asset diagnostics ───────────────────────────────────
    # Parsed from sentinelctl-status.txt — individual daemon ready/not-ready states
    # Each: {name: str, ready: bool}
    daemon_states: list[dict] = field(default_factory=list)
    # Parsed from sentinelctl-status.txt — asset integrity signatures
    # Each: {name: str, status: str}  status: "valid"|"invalid"|"empty"|"signed"
    asset_signatures: list[dict] = field(default_factory=list)
    # Parsed from SentinelDirectorySize.txt + sentinelctl-stats.txt — DB health
    # Keys: state_db_mb, wonky_db_mb, has_wonky (bool), total_db_mb,
    #        db_read_gib, db_write_gib, db_stats_since
    sentinel_db_health: dict = field(default_factory=dict)

    # ── Hardware identity ─────────────────────────────────────────────────────
    # Parsed from ioreg.txt — Apple IOPlatformSerialNumber
    serial_number: str = ""
    # Parsed from sentinelctl-config_local.txt — True if non-empty (unauthorized local override)
    local_config_modified: bool = False

    # ── Operational alerts (auto-generated by alert engine) ───────────────────
    # Each: {level: str, title: str, detail: str, action: str}
    # level: "CRITICAL"|"HIGH"|"MEDIUM"|"INFO"
    operational_alerts: list[dict] = field(default_factory=list)
