"""extended_text_parser.py — Parses additional root-level text files in SentinelOne dumps.

Sources:
  - sentinelctl-policies.txt      → detection rule action breakdown
  - sentinelctl-config_policy.txt → management policy feature settings
  - netstat-anW.txt               → active network connections + listening ports
  - kextstat.txt                  → third-party (non-Apple) kernel extensions
  - sentinelctl-scan-info.txt     → last full disk scan status
  - sentinelctl-stats.txt         → LevelDB I/O statistics
  - mount.txt                     → mounted APFS/HFS volumes
  - ps.txt                        → running process snapshot
  - pkgutil.txt                   → security-relevant installed packages
"""
from __future__ import annotations
import re
from pathlib import Path

from macloganalyzer.models.context import SystemContext


# ─── sentinelctl-policies.txt ─────────────────────────────────────────────────

_POLICY_RE = re.compile(r'^([\w_]+):\s+(mitigate|inform|validate|disabled)(.*)')


def _parse_policies(path: Path) -> list[dict]:
    """Parse detection policy name → action.

    Format: ``policy_name: action`` or
            ``policy_name: inform - (verbosity level: N)``
    """
    policies: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _POLICY_RE.match(line.strip())
            if not m:
                continue
            policies.append({"name": m.group(1), "action": m.group(2)})
    except OSError:
        pass
    return policies


# ─── netstat-anW.txt ──────────────────────────────────────────────────────────

# tcp4/tcp6/tcp46/udp4/udp6  0  0  local_addr.port  foreign_addr.port  (state)
_NETSTAT_RE = re.compile(
    r'^(tcp\d*|udp\d*)\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+(\w+))?'
)


def _split_addr_port(addr: str) -> tuple[str, str]:
    """Split 'addr.port' or '*.*' into (addr, port).
    Port is the last component after the last dot."""
    if addr in ("*.*", "*."):
        return "*", "*"
    idx = addr.rfind(".")
    if idx == -1:
        return addr, ""
    return addr[:idx], addr[idx + 1:]


def _parse_netstat(path: Path) -> list[dict]:
    """Return LISTEN + ESTABLISHED entries with addr/port split."""
    connections: list[dict] = []
    seen: set[tuple] = set()
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _NETSTAT_RE.match(line.strip())
            if not m:
                continue
            proto = m.group(1)
            local_raw = m.group(2)
            remote_raw = m.group(3)
            state = m.group(4) or ""
            if state not in ("LISTEN", "ESTABLISHED"):
                continue
            local_addr, local_port = _split_addr_port(local_raw)
            remote_addr, remote_port = _split_addr_port(remote_raw)
            key = (proto, local_addr, local_port, remote_addr, remote_port, state)
            if key in seen:
                continue
            seen.add(key)
            connections.append({
                "proto": proto,
                "local_addr": local_addr,
                "local_port": local_port,
                "remote_addr": remote_addr,
                "remote_port": remote_port,
                "state": state,
            })
    except OSError:
        pass
    return connections


# ─── kextstat.txt ─────────────────────────────────────────────────────────────

_KEXT_LINE_RE = re.compile(
    r'^\s*\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+'
    r'(\S+)\s+\(([^)]+)\)\s+([0-9A-Fa-f-]+)'
)


def _parse_kextstat(path: Path) -> list[dict]:
    """Return non-Apple/non-sentinelone kernel extensions with version + UUID."""
    kexts: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _KEXT_LINE_RE.match(line)
            if not m:
                continue
            name = m.group(1)
            version = m.group(2)
            uuid = m.group(3)
            # Skip all Apple and SentinelOne kexts — only keep true third-party
            if (name.startswith("com.apple.")
                    or name.startswith("com.sentinelone.")):
                continue
            kexts.append({"name": name, "version": version, "uuid": uuid})
    except OSError:
        pass
    return kexts


# ─── sentinelctl-scan-info.txt + sentinelctl-stats.txt ───────────────────────

_BYTES_RE = re.compile(r'Bytes (read|written):\s+([\d,]+)\s+bytes\s+\(([^)]+)\)')
_STATS_START_RE = re.compile(r'Stats start:\s+(.+)')


def _parse_sentinel_operational(dump_path: Path) -> dict:
    result: dict = {}

    # sentinelctl-scan-info.txt
    scan_path = dump_path / "sentinelctl-scan-info.txt"
    if scan_path.exists():
        try:
            text = scan_path.read_text(encoding="utf-8", errors="replace").strip()
            result["scan_info_raw"] = text
        except OSError:
            pass

    # sentinelctl-stats.txt
    stats_path = dump_path / "sentinelctl-stats.txt"
    if stats_path.exists():
        try:
            text = stats_path.read_text(encoding="utf-8", errors="replace")
            m = _STATS_START_RE.search(text)
            if m:
                result["db_stats_start"] = m.group(1).strip()
            for m in _BYTES_RE.finditer(text):
                direction = m.group(1)  # "read" or "written"
                human = m.group(3)       # e.g. "245.3 GiB"
                if direction == "read":
                    result["db_bytes_read"] = human
                else:
                    result["db_bytes_written"] = human
        except OSError:
            pass

    return result


# ─── mount.txt ────────────────────────────────────────────────────────────────

_MOUNT_RE = re.compile(r'^(\S+) on (\S+) \(([^)]+)\)')


def _parse_mount(path: Path) -> list[dict]:
    """Return real (non-devfs/map/auto) mounted volumes."""
    volumes: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _MOUNT_RE.match(line.strip())
            if not m:
                continue
            device = m.group(1)
            mountpoint = m.group(2)
            opts_raw = m.group(3)
            opts = [o.strip() for o in opts_raw.split(",")]
            fstype = opts[0] if opts else ""
            # Skip pseudo-filesystems
            if fstype in ("devfs", "autofs") or device.startswith("map "):
                continue
            volumes.append({
                "device": device,
                "mountpoint": mountpoint,
                "fstype": fstype,
                "options": opts[1:],
            })
    except OSError:
        pass
    return volumes


# ─── sentinelctl-config.txt — communication intervals ────────────────────────

_COMM_KEYS = {
    "SendEventsInterval":       "send_events_sec",
    "BatchSendInterval":        "batch_send_sec",
    "ConnectivityUpdateInterval": "connectivity_check_sec",
    "StateUpdateInterval":      "state_update_sec",
    "SendMetricsInterval":      "send_metrics_sec",
    "UpdateInterval":           "update_interval_sec",
}
_CONF_KV_RE = re.compile(r"^\s+(\w+):\s+(\S+)")


def _parse_comm_intervals(path: Path) -> dict:
    """Extract timing/interval settings from sentinelctl-config.txt."""
    result: dict = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _CONF_KV_RE.match(line)
            if not m:
                continue
            key, val = m.group(1), m.group(2)
            if key in _COMM_KEYS:
                try:
                    result[_COMM_KEYS[key]] = int(val)
                except ValueError:
                    result[_COMM_KEYS[key]] = val
    except OSError:
        pass
    return result


# NOTE: curl_ns_ats.txt / ATS connectivity test removed in v1.2.0.
# test-the-catchall.sentinelone.net does not resolve (domain non-existent),
# making all 16 tests systematically FAIL regardless of network conditions.
# The results were non-informative and have been suppressed.


# ─── logs/sentinelctl-log.txt ────────────────────────────────────────────────

_LOG_LINE_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+'  # timestamp
    r'(\w+)\s+'                                           # level (I, E, Df, W…)
    r'(\S+)\[\d+:\w+\]\s+'                               # process[pid:tid]
    r'\[com\.sentinelone\.agent:([^\]]+)\]\s+'            # [component]
    r'(.*)'                                               # message
)
_RCP_REQUEST_RE  = re.compile(r'Received request: (\w+), ReqId: (\d+)')
_ASSET_RE        = re.compile(r"Asset '([^']+)' - Loaded\. Internal-Version: (\S+)")
_KEEP_ALIVE_RE   = re.compile(r'Send keep alive')
_SEND_RE         = re.compile(r'Send (users|system trace) because')
_DYNAMIC_MATCH_RE = re.compile(
    r"Match \(final\) (\w+) - origin\.pid=\[[\d-]+\]; origin\.path='([^']*)'; "
    r"primary\.pid=\[[\d-]+\]; primary\.path='([^']*)'"
)
_INTEGRITY_BLOCK_RE = re.compile(
    r"Process '([^']+)' \[(\d+)\] is targeting '([^']+)' \[(\d+)\]\. Denied\."
)
_DEVICE_CTRL_RE = re.compile(
    r"Device control activation status - USB: (yes|no), Thunderbolt: (yes|no), "
    r"Bluetooth: (yes|no), Bluetooth Low Energy: (yes|no)"
)
_MOUNT_REQ_RE = re.compile(r"Mount request device:'([^']+)', allow:'([01])'")
_CPU_HWM_RE   = re.compile(
    r"CPU usage for '([^']+)' (exceeds|fell below) high water mark "
    r"\((\d+(?:\.\d+)?) [>=<]+ (\d+)\)"
)


def _parse_agent_log(path: Path) -> dict:
    """Parse logs/sentinelctl-log.txt for communication and error data."""
    result: dict = {}
    level_counts: dict[str, int] = {}
    error_by_component: dict[str, int] = {}
    unique_asserts: dict[str, int] = {}  # deduped assert messages → count
    rcp_requests: list[dict] = []
    keep_alive_events: list[str] = []
    asset_updates: list[dict] = []
    first_ts: str = ""
    last_ts: str = ""

    # Extended event collections (capped to avoid memory pressure)
    detection_matches: list[dict] = []
    technique_counts: dict[str, int] = {}
    integrity_blocks: list[dict] = []
    invoker_counts: dict[str, int] = {}
    device_control_events: list[dict] = []
    mount_events: list[dict] = []
    cpu_events: list[dict] = []

    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _LOG_LINE_RE.match(line)
            if not m:
                continue
            ts, level, _proc, component, message = (
                m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
            )
            if not first_ts:
                first_ts = ts
            last_ts = ts

            level_counts[level] = level_counts.get(level, 0) + 1

            # Error accounting
            if level == "E":
                error_by_component[component] = error_by_component.get(component, 0) + 1
                # Capture unique ASSERT messages (deduped)
                if "[ASSERT]" in message:
                    # Normalize: strip trailing detail after colon
                    key = message.split(":")[0].strip()[:120]
                    unique_asserts[key] = unique_asserts.get(key, 0) + 1

            # RCP communication from console
            mr = _RCP_REQUEST_RE.search(message)
            if mr:
                rcp_requests.append({
                    "timestamp": ts,
                    "req_type": mr.group(1),
                    "req_id": mr.group(2),
                })

            # Keep-alive / session sync events
            if _KEEP_ALIVE_RE.search(message):
                keep_alive_events.append(ts)

            # Asset version updates
            ma = _ASSET_RE.search(message)
            if ma:
                asset_updates.append({
                    "timestamp": ts,
                    "name": ma.group(1),
                    "version": ma.group(2),
                })

            # Dynamic detection matches
            md = _DYNAMIC_MATCH_RE.search(message)
            if md:
                technique = md.group(1)
                technique_counts[technique] = technique_counts.get(technique, 0) + 1
                if len(detection_matches) < 200:
                    detection_matches.append({
                        "timestamp": ts,
                        "technique": technique,
                        "origin_path": md.group(2),
                        "primary_path": md.group(3),
                    })

            # Integrity protection blocks
            mib = _INTEGRITY_BLOCK_RE.search(message)
            if mib:
                invoker = mib.group(1)
                invoker_counts[invoker] = invoker_counts.get(invoker, 0) + 1
                if len(integrity_blocks) < 200:
                    integrity_blocks.append({
                        "timestamp": ts,
                        "invoker_path": invoker,
                        "invoker_pid": mib.group(2),
                        "target_path": mib.group(3),
                        "target_pid": mib.group(4),
                    })

            # Device control status events
            mdc = _DEVICE_CTRL_RE.search(message)
            if mdc:
                device_control_events.append({
                    "timestamp": ts,
                    "usb": mdc.group(1),
                    "thunderbolt": mdc.group(2),
                    "bluetooth": mdc.group(3),
                    "ble": mdc.group(4),
                })

            # Mount request decisions
            mmr = _MOUNT_REQ_RE.search(message)
            if mmr:
                mount_events.append({
                    "timestamp": ts,
                    "device": mmr.group(1),
                    "allowed": mmr.group(2) == "1",
                })

            # CPU high-water mark events
            mhw = _CPU_HWM_RE.search(message)
            if mhw:
                cpu_events.append({
                    "timestamp": ts,
                    "process": mhw.group(1),
                    "exceeds": mhw.group(2) == "exceeds",
                    "value": float(mhw.group(3)),
                    "threshold": int(mhw.group(4)),
                })

    except OSError:
        return result

    result["log_period_start"] = first_ts
    result["log_period_end"]   = last_ts
    result["total_lines"]      = sum(level_counts.values())
    result["level_counts"]     = level_counts
    result["error_count"]      = level_counts.get("E", 0)

    # Top error components (sorted by count)
    result["error_by_component"] = dict(
        sorted(error_by_component.items(), key=lambda x: -x[1])
    )
    # Deduped asserts, sorted by frequency
    result["unique_asserts"] = dict(
        sorted(unique_asserts.items(), key=lambda x: -x[1])
    )

    # RCP: only keep distinct request types and compute intervals
    result["rcp_requests"] = rcp_requests
    rcp_type_counts: dict[str, int] = {}
    for r in rcp_requests:
        rcp_type_counts[r["req_type"]] = rcp_type_counts.get(r["req_type"], 0) + 1
    result["rcp_type_counts"] = rcp_type_counts

    # Keep-alive: store count + timestamps of last 5
    result["keep_alive_count"]  = len(keep_alive_events)
    result["keep_alive_recent"] = keep_alive_events[-5:]

    # Asset updates (deduplicated per asset name: latest only)
    seen_assets: dict[str, dict] = {}
    for a in asset_updates:
        seen_assets[a["name"]] = a  # last occurrence wins (most recent)
    result["asset_updates"] = list(seen_assets.values())

    # Dynamic detection matches
    result["detection_matches"]  = detection_matches
    result["technique_counts"]   = dict(sorted(technique_counts.items(), key=lambda x: -x[1]))
    result["detection_total"]    = sum(technique_counts.values())

    # Integrity protection blocks
    result["integrity_blocks"]   = integrity_blocks
    result["invoker_counts"]     = dict(sorted(invoker_counts.items(), key=lambda x: -x[1]))
    result["integrity_total"]    = sum(invoker_counts.values())

    # Device control & mount events
    result["device_control_events"] = device_control_events
    result["mount_events"]          = mount_events

    # CPU high-water marks
    result["cpu_events"]            = cpu_events

    return result


# ─── scutil_proxy.txt ─────────────────────────────────────────────────────────

_PROXY_SERVER_RE   = re.compile(r'(HTTPSProxy|HTTPProxy)\s*:\s*(\S+)')
_PROXY_PORT_RE     = re.compile(r'(HTTPSPort|HTTPPort)\s*:\s*(\d+)')
_PROXY_ENABLED_RE  = re.compile(r'(HTTPSEnable|HTTPEnable)\s*:\s*(\d+)')


def _parse_proxy(path: Path) -> dict:
    """Parse scutil_proxy.txt for proxy configuration."""
    result: dict = {"has_proxy": False, "proxy_server": "", "exceptions": []}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        ms = _PROXY_SERVER_RE.search(text)
        me = _PROXY_ENABLED_RE.search(text)
        if ms and me and me.group(2) == "1":
            result["has_proxy"]    = True
            result["proxy_server"] = ms.group(2)
            mp = _PROXY_PORT_RE.search(text)
            if mp:
                result["proxy_server"] += f":{mp.group(2)}"
        # Extract exceptions
        exceptions = re.findall(r'\d+\s*:\s*(\S+)', text)
        result["exceptions"] = exceptions
    except OSError:
        pass
    return result


# ─── Entry point ─────────────────────────────────────────────────────────────

# ─── sentinelctl-config_policy.txt ──────────────────────────────────────────

_POLICY_SECTION_RE = re.compile(r'^(\w+)\s*$')
_POLICY_KV_RE      = re.compile(r'^\s+(\w+):\s+(.*?)\s+policy\s*$')
_POLICY_ARRAY_RE   = re.compile(r'^\s+(\w+):\s+\(\s*$')  # "Key: (" without "policy" on same line


def _parse_policy_config(path: Path) -> dict:
    """Parse management policy settings into {section → {key → value/list}}."""
    result: dict = {}
    current_section: str | None = None
    in_multi = False
    current_key: str | None = None
    current_array: list = []

    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue

            # Section header: no leading whitespace
            if line[0] not in (" ", "\t"):
                if in_multi and current_section and current_key:
                    result[current_section][current_key] = current_array
                    in_multi = False
                    current_array = []
                    current_key = None
                m = _POLICY_SECTION_RE.match(line.strip())
                if m:
                    current_section = m.group(1)
                    result[current_section] = {}
                continue

            stripped = line.strip()

            if in_multi:
                # End of array: line starts with ")" optionally followed by "policy"
                if stripped.startswith(")"):
                    if current_section and current_key:
                        result[current_section][current_key] = current_array
                    in_multi = False
                    current_array = []
                    current_key = None
                elif not stripped.startswith(("{", "}")):
                    val = stripped.rstrip(",").strip('"')
                    if val:
                        current_array.append(val)
                continue

            # "Key: (" without "policy" on same line (array starts on next lines)
            ma = _POLICY_ARRAY_RE.match(line)
            if ma and current_section is not None:
                in_multi = True
                current_key = ma.group(1)
                current_array = []
                continue

            # "Key: value   policy"
            m = _POLICY_KV_RE.match(line)
            if m and current_section is not None:
                key, val = m.group(1), m.group(2).strip()
                # Inline single-line array: "Key: ( item1, item2 )  policy"
                if val.startswith("(") and val.endswith(")"):
                    items = [v.strip().strip('"') for v in val[1:-1].split(",") if v.strip()]
                    result[current_section][key] = items
                elif val not in ("{", "}"):
                    result[current_section][key] = val
    except OSError:
        pass
    return result


# ─── ps.txt ──────────────────────────────────────────────────────────────────

_PS_HDR_RE = re.compile(r'^\s*USER\s+PID')


def _parse_ps(path: Path) -> list[dict]:
    """Parse ps.txt into [{user, pid, cpu, mem, binary, command}], sorted by cpu desc."""
    procs: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if _PS_HDR_RE.match(line) or not line.strip():
                continue
            # First 10 fixed tokens: USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            user, pid, cpu_str, mem_str = parts[0], parts[1], parts[2], parts[3]
            rest = parts[10]
            try:
                cpu = float(cpu_str)
                mem = float(mem_str)
            except ValueError:
                continue
            # Full command is after "  PID  PPID  TT  STAT  TIME  CMD" repeat
            m = re.search(
                r'\s+' + re.escape(pid) + r'\s+\d+\s+\S+\s+\S+\s+\S+\s+(.+)$', rest
            )
            full_cmd = m.group(1).strip() if m else rest.strip()
            cmd_parts = full_cmd.split()
            binary = cmd_parts[0].rsplit("/", 1)[-1] if cmd_parts else ""
            procs.append({
                "user":    user,
                "pid":     pid,
                "cpu":     cpu,
                "mem":     mem,
                "binary":  binary,
                "command": full_cmd,
            })
    except OSError:
        pass
    return sorted(procs, key=lambda p: -p["cpu"])


# ─── pkgutil.txt ─────────────────────────────────────────────────────────────

_SECURITY_PKG_PREFIXES = (
    "com.apple.pkg.XProtect",
    "com.apple.pkg.Gatekeeper",
    "com.apple.pkg.MRT",
    "com.sentinelone",
    "com.apple.pkg.MobileAssets",
)


def _parse_pkgutil(path: Path) -> list[str]:
    """Return security-relevant installed package identifiers."""
    packages: list[str] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            pkg = line.strip()
            if pkg and any(pkg.startswith(p) for p in _SECURITY_PKG_PREFIXES):
                packages.append(pkg)
    except OSError:
        pass
    return packages


def _parse_vm_stat(path: Path) -> dict:
    """Parse vm_stat.txt → memory pressure metrics."""
    result: dict = {}
    try:
        text = path.read_text(errors="replace")
        PAGE_SIZE = 16384  # 16 KB pages on Apple Silicon (also typical on Intel)

        def _pages(key: str) -> int:
            m = re.search(rf"{re.escape(key)}:\s+([\d,]+)", text)
            return int(m.group(1).replace(",", "")) if m else 0

        to_mb = lambda p: round(p * PAGE_SIZE / (1024 * 1024))

        free      = _pages("Pages free")
        active    = _pages("Pages active")
        wired     = _pages("Pages wired down")
        inactive  = _pages("Pages inactive")
        compressed = _pages("Pages occupied by compressor")
        compressions   = _pages("Compressions")
        decompressions = _pages("Decompressions")
        swapins   = _pages("Swapins")
        swapouts  = _pages("Swapouts")

        free_mb = to_mb(free)
        if free_mb < 300:
            pressure = "CRITICAL"
        elif free_mb < 800:
            pressure = "WARNING"
        elif free_mb < 1500:
            pressure = "MODERATE"
        else:
            pressure = "OK"

        result = {
            "free_mb": free_mb,
            "active_mb": to_mb(active),
            "inactive_mb": to_mb(inactive),
            "wired_mb": to_mb(wired),
            "compressed_mb": to_mb(compressed),
            "swapins": swapins,
            "swapouts": swapouts,
            "compressions": compressions,
            "decompressions": decompressions,
            "pressure_level": pressure,
        }
    except Exception:
        pass
    return result


def _parse_top_summary(path: Path) -> dict:
    """Parse top.txt header lines → load, memory, disk totals."""
    result: dict = {}
    try:
        lines = path.read_text(errors="replace").splitlines()
        for line in lines[:15]:
            # Processes: 460 total, 5 running, 455 sleeping, 2441 threads
            m = re.match(r"Processes:\s+(\d+)\s+total.*?(\d+)\s+threads", line)
            if m:
                result["processes_total"] = int(m.group(1))
                result["threads_total"]   = int(m.group(2))
            # Load Avg: 2.60, 2.86, 2.66
            m = re.search(r"Load Avg:\s+([\d.]+),\s*([\d.]+),\s*([\d.]+)", line)
            if m:
                result["load_1"]  = float(m.group(1))
                result["load_5"]  = float(m.group(2))
                result["load_15"] = float(m.group(3))
            # CPU usage: 8.6% user, 3.56% sys, 88.37% idle
            m = re.search(r"([\d.]+)%\s+idle", line)
            if m:
                result["cpu_idle_pct"] = float(m.group(1))
            # PhysMem: 7345M used (1311M wired, 2399M compressor), 287M unused.
            if "PhysMem:" in line:
                m_used  = re.search(r"(\d+)M\s+used",       line)
                m_free  = re.search(r"(\d+)M\s+unused",     line)
                m_wired = re.search(r"\((\d+)M\s+wired",    line)
                m_comp  = re.search(r"(\d+)M\s+compressor", line)
                if m_used:  result["physmem_used_mb"]       = int(m_used.group(1))
                if m_free:  result["physmem_free_mb"]       = int(m_free.group(1))
                if m_wired: result["physmem_wired_mb"]      = int(m_wired.group(1))
                if m_comp:  result["physmem_compressor_mb"] = int(m_comp.group(1))
            # Disks: 13008043/382G read, 2688603/88G written.
            m = re.search(r"Disks:.*?/(\d+)G\s+read.*?/(\d+)G\s+written", line)
            if m:
                result["disk_read_gb"]  = int(m.group(1))
                result["disk_write_gb"] = int(m.group(2))
    except Exception:
        pass
    return result


def _parse_pmset(live_path: Path, ps_path: Path) -> dict:
    """Parse pmset-live.txt + pmset-ps.txt → power and battery state."""
    result: dict = {"sleep_preventing": [], "on_battery": False}
    try:
        if live_path.exists():
            text = live_path.read_text(errors="replace")
            # sleep 1 (sleep prevented by sharingd, powerd)
            m = re.search(r"sleep\s+\d+\s+\(sleep prevented by ([^)]+)\)", text)
            if m:
                result["sleep_preventing"] = [s.strip() for s in m.group(1).split(",")]
            m = re.search(r"hibernatemode\s+(\d+)", text)
            if m:
                result["hibernatemode"] = int(m.group(1))
            result["low_power_mode"] = bool(re.search(r"lowpowermode\s+1", text))
        if ps_path.exists():
            text = ps_path.read_text(errors="replace")
            result["on_battery"] = "Battery Power" in text
            # -InternalBattery-0 (id=36438115)	81%; discharging; 7:35 remaining present: true
            m = re.search(
                r"InternalBattery[^:]*[:\t]\s*(\d+)%;\s*(\w+);\s*(\d+:\d+)\s+remaining",
                text,
            )
            if m:
                result["battery_pct"]       = int(m.group(1))
                result["battery_status"]    = m.group(2)   # charging | discharging
                result["battery_remaining"] = m.group(3)   # e.g. "7:35"
    except Exception:
        pass
    return result


def _parse_sentinel_db_health(dir_size_path: Path, stats_path: Path) -> dict:
    """Parse SentinelDirectorySize.txt + sentinelctl-stats.txt → DB health."""
    result: dict = {"has_wonky": False, "state_db_mb": 0, "wonky_db_mb": 0, "total_db_mb": 0}
    try:
        if dir_size_path.exists():
            text = dir_size_path.read_text(errors="replace")
            if "state.wonky" in text:
                result["has_wonky"] = True
                m = re.search(r"(\d+)M\s+[^\n]*/state\.wonky", text)
                if m:
                    result["wonky_db_mb"] = int(m.group(1))
            # /Library/Sentinel/_sentinel/db/state  (directory)
            m = re.search(r"(\d+)M\s+[^\n]*/db/state\s*$", text, re.MULTILINE)
            if m:
                result["state_db_mb"] = int(m.group(1))
            # /Library/Sentinel/_sentinel/db  total
            m = re.search(r"(\d+)M\s+[^\n]*/db\s*$", text, re.MULTILINE)
            if m:
                result["total_db_mb"] = int(m.group(1))
        if stats_path.exists():
            text = stats_path.read_text(errors="replace")
            m = re.search(r"Stats start:\s+(.+)", text)
            if m:
                result["db_stats_since"] = m.group(1).strip()
            m = re.search(r"Bytes read:\s+\d+ bytes \(([\d.]+) GiB\)", text)
            if m:
                result["db_read_gib"] = float(m.group(1))
            m = re.search(r"Bytes written:\s+\d+ bytes \(([\d.]+) GiB\)", text)
            if m:
                result["db_write_gib"] = float(m.group(1))
    except Exception:
        pass
    return result


def parse_extended_text(dump_path: Path, ctx: SystemContext) -> None:
    """Parse additional root-level text files into ctx."""

    policies_path = dump_path / "sentinelctl-policies.txt"
    if policies_path.exists() and policies_path.stat().st_size > 0:
        ctx.detection_policies = _parse_policies(policies_path)

    netstat_path = dump_path / "netstat-anW.txt"
    if netstat_path.exists() and netstat_path.stat().st_size > 0:
        ctx.netstat_connections = _parse_netstat(netstat_path)

    kextstat_path = dump_path / "kextstat.txt"
    if kextstat_path.exists() and kextstat_path.stat().st_size > 0:
        ctx.third_party_kexts = _parse_kextstat(kextstat_path)

    sentinel_ops = _parse_sentinel_operational(dump_path)
    if sentinel_ops:
        ctx.sentinel_operational = sentinel_ops

    mount_path = dump_path / "mount.txt"
    if mount_path.exists() and mount_path.stat().st_size > 0:
        ctx.mounted_volumes = _parse_mount(mount_path)

    config_path = dump_path / "sentinelctl-config.txt"
    if config_path.exists() and config_path.stat().st_size > 0:
        ctx.comm_intervals = _parse_comm_intervals(config_path)

    # curl_ns_ats.txt intentionally not parsed — see note above.

    agent_log_path = dump_path / "logs" / "sentinelctl-log.txt"
    if agent_log_path.exists() and agent_log_path.stat().st_size > 0:
        ctx.agent_log = _parse_agent_log(agent_log_path)

    proxy_path = dump_path / "scutil_proxy.txt"
    if proxy_path.exists() and proxy_path.stat().st_size > 0:
        ctx.proxy_config = _parse_proxy(proxy_path)

    policy_path = dump_path / "sentinelctl-config_policy.txt"
    if policy_path.exists() and policy_path.stat().st_size > 0:
        ctx.policy_config = _parse_policy_config(policy_path)

    ps_path = dump_path / "ps.txt"
    if ps_path.exists() and ps_path.stat().st_size > 0:
        ctx.running_processes = _parse_ps(ps_path)

    pkgutil_path = dump_path / "pkgutil.txt"
    if pkgutil_path.exists() and pkgutil_path.stat().st_size > 0:
        ctx.security_packages = _parse_pkgutil(pkgutil_path)

    vm_stat_path = dump_path / "vm_stat.txt"
    if vm_stat_path.exists() and vm_stat_path.stat().st_size > 0:
        ctx.vm_memory = _parse_vm_stat(vm_stat_path)

    top_path = dump_path / "top.txt"
    if top_path.exists() and top_path.stat().st_size > 0:
        ctx.system_load = _parse_top_summary(top_path)

    ctx.power_state = _parse_pmset(
        dump_path / "pmset-live.txt",
        dump_path / "pmset-ps.txt",
    )

    ctx.sentinel_db_health = _parse_sentinel_db_health(
        dump_path / "SentinelDirectorySize.txt",
        dump_path / "sentinelctl-stats.txt",
    )
