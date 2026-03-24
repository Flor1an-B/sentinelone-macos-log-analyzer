from __future__ import annotations
import re
from pathlib import Path

from macloganalyzer.models.context import SystemContext


def parse_text_files(dump_path: Path, ctx: SystemContext) -> None:
    """Parse root-level text files and populate ctx."""
    for item in dump_path.iterdir():
        if item.is_dir():
            continue
        name = item.name.strip()  # filenames may have leading spaces in some dumps
        try:
            if name == "Applications.txt":
                ctx.installed_apps, ctx.installed_apps_meta = _parse_apps(item)
            elif name == "LaunchDaemons.txt":
                ctx.launch_daemons = _parse_ls_la_file(item)
            elif name == "LaunchAgents.txt":
                ctx.launch_agents = _parse_ls_la_file(item)
            elif name == "KernelExtensions.txt":
                ctx.kernel_extensions = _parse_ls_la_file(item)
            elif name == "PrivilegedHelperTools.txt":
                ctx.privileged_helpers = _parse_ls_la_file(item)
            elif name == "uname.txt":
                _parse_uname(item, ctx)
            elif name == "csrutil_status.txt":
                content = item.read_text(errors="replace").lower()
                ctx.sip_enabled = "enabled" in content and "disabled" not in content
            elif name == "boot_args.txt":
                raw = item.read_text(errors="replace").strip()
                # nvram returns this error on Apple Silicon when no custom boot-args are set
                ctx.boot_args = "" if "data was not found" in raw or raw.startswith("nvram:") else raw
            elif name == "cpu_count.txt":
                try:
                    ctx.cpu_count = int(item.read_text(errors="replace").strip())
                except ValueError:
                    pass
            elif name == "df.txt":
                ctx.disk_usage = item.read_text(errors="replace").strip()
                ctx.disk_volumes = _parse_df(item)
            elif name == "ifconfig.txt":
                ctx.ifconfig_interfaces = _parse_ifconfig(item)
            elif name == "lsof-i.txt":
                ctx.network_connections = _parse_lsof_i(item)
            elif name == "users.txt":
                ctx.local_users = _parse_users(item)
                # Also infer primary user from real (non-system) accounts
                if not ctx.primary_user or ctx.primary_user == "Unknown":
                    real = [u for u in ctx.local_users if u["uid"] >= 500]
                    if real:
                        ctx.primary_user = real[0]["name"]
            elif name == "launchctl-print-disabled.txt":
                ctx.third_party_services = _parse_launchctl_disabled(item)
            elif name == "scutil_dns.txt":
                ctx.dns_servers = _parse_dns(item)
            elif name == "systemextensionsctl_list.txt":
                ctx.system_extensions = _parse_sysext(item)
            elif name.startswith("macOS "):
                ctx.os_version = name
            elif name == "arm64":
                ctx.arch = "arm64"
            elif name == "arm64e":
                ctx.arch = "arm64e"
            elif name == "x86_64":
                ctx.arch = "x86_64"
            elif re.match(r"MacBook|iMac|Mac(Pro|Mini|Studio)", name):
                ctx.model = name
            elif name == "ioreg.txt":
                _parse_ioreg(item, ctx)
        except Exception:
            pass

    # sentinelctl-config_local.txt — check for unauthorized local overrides
    local_cfg = dump_path / "sentinelctl-config_local.txt"
    if local_cfg.exists():
        try:
            content = local_cfg.read_text(errors="replace").strip()
            if content:
                ctx.local_config_modified = True
        except Exception:
            pass

    # sentinelctl-log.txt is in logs/
    sentinelctl = dump_path / "logs" / "sentinelctl-log.txt"
    if sentinelctl.exists():
        try:
            content = sentinelctl.read_text(errors="replace").strip()
            if content:
                ctx.sentinelctl_error = content[:500]
        except Exception:
            pass

    # sentinelctl-status.txt — detailed agent health
    status_file = dump_path / "sentinelctl-status.txt"
    if status_file.exists():
        try:
            parsed = _parse_sentinelctl_status(status_file)
            ctx.sentinel_status = parsed
            if parsed.get("daemon_states"):
                ctx.daemon_states = parsed["daemon_states"]
            if parsed.get("asset_signatures"):
                ctx.asset_signatures = parsed["asset_signatures"]
        except Exception:
            pass

    # Infer primary user from Applications.txt ownership (lefbe)
    apps_file = dump_path / "Applications.txt"
    if apps_file.exists() and not ctx.primary_user or ctx.primary_user == "Unknown":
        try:
            text = apps_file.read_text(errors="replace")
            user_match = re.search(r'\d+\s+(\w+)\s+admin', text)
            if user_match:
                candidate = user_match.group(1)
                if candidate not in ("root", "wheel"):
                    ctx.primary_user = candidate
        except Exception:
            pass


def _parse_uname(path: Path, ctx: SystemContext) -> None:
    """
    Parse uname.txt (Darwin kernel version string) to fill OS version and arch.
    Example: Darwin Kernel Version 25.3.0: ...; root:xnu-12377.91.3~2/RELEASE_ARM64_T8103
    """


def _parse_ioreg(path: Path, ctx: SystemContext) -> None:
    """Extract IOPlatformSerialNumber from ioreg.txt."""
    try:
        text = path.read_text(errors="replace")
        m = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', text)
        if m:
            ctx.serial_number = m.group(1)
    except Exception:
        pass
    try:
        text = path.read_text(errors="replace").strip()
        # Architecture from RELEASE_ARM64 / RELEASE_X86_64
        arch_m = re.search(r'RELEASE_(ARM64E?|X86_64)', text, re.IGNORECASE)
        if arch_m and ctx.arch in ("Unknown", ""):
            ctx.arch = arch_m.group(1).lower()
        # Kernel version number
        ver_m = re.search(r'Darwin Kernel Version (\d+\.\d+\.\d+)', text)
        if ver_m and ctx.os_version in ("Unknown", ""):
            ctx.os_version = f"Darwin {ver_m.group(1)}"
    except Exception:
        pass


def _parse_apps(path: Path) -> tuple[list[str], dict]:
    """Parse ls -la output to extract .app names and metadata.

    ls -la format: perms links owner group size month day year/time name...
    The filename starts at index 8 and may contain spaces (e.g. "Boom 3D.app").
    Symlinks (name -> target) are handled by splitting on ' -> '.

    Returns:
        (apps, meta) where apps is list[str] of names and meta is
        dict[name -> {owner, group, modified, install_type}].
    """
    apps: list[str] = []
    meta: dict[str, dict] = {}
    try:
        for line in path.read_text(errors="replace").splitlines():
            parts = line.strip().split()
            if len(parts) < 9:
                continue
            # Reconstruct full filename (may contain spaces)
            raw_name = " ".join(parts[8:])
            # Symlink: "App Name.app -> /some/target"
            if " -> " in raw_name:
                raw_name = raw_name.split(" -> ")[0].strip()
            if not raw_name.endswith(".app") or raw_name.startswith("."):
                continue

            app_name = raw_name[:-4]
            owner     = parts[2]
            group     = parts[3]
            # Date: month day year-or-time (parts[5..7])
            month, day, year_or_time = parts[5], parts[6], parts[7]
            modified  = f"{month} {day} {year_or_time}"
            install_type = "system" if owner == "root" else "user"

            apps.append(app_name)
            meta[app_name] = {
                "owner":        owner,
                "group":        group,
                "modified":     modified,
                "install_type": install_type,
            }
    except Exception:
        pass
    return apps, meta


def _parse_ls_la_file(path: Path) -> list[str]:
    """
    Parse ls -la output to extract the filename from the last column.
    Skips total/. /.. lines and non-file lines.
    """
    entries = []
    try:
        for line in path.read_text(errors="replace").splitlines():
            parts = line.strip().split()
            if not parts or parts[0] in ("total", "#"):
                continue
            # ls -la lines start with permissions like -rw-r--r-- or drwxr-xr-x
            if not re.match(r'^[-dlcbsp]', parts[0]):
                continue
            name = parts[-1]
            if name in (".", ".."):
                continue
            entries.append(name)
    except Exception:
        pass
    return entries


def _parse_list_file(path: Path) -> list[str]:
    """Parse a simple text file, one entry per line."""
    lines = []
    try:
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    except Exception:
        pass
    return lines


def _parse_sentinelctl_status(path: Path) -> dict:
    """
    Parse sentinelctl-status.txt into a structured dict.
    Format: indented sections with key: value pairs.
    """
    result: dict = {
        "agent": {},
        "daemons": {},
        "launchd": {},
        "management": {},
        "degraded_services": [],
        "missing_authorizations": False,
        "daemon_states": [],
        "asset_signatures": [],
    }
    try:
        lines = path.read_text(errors="replace").splitlines()
        section = ""
        subsection = ""
        _missing_auth_indent = 3  # indent level of the "Missing Authorizations" header
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            # Detect top-level section (no leading spaces, no colon)
            indent = len(line) - len(line.lstrip())
            if indent == 0 and stripped and ":" not in stripped:
                section = stripped.lower()
                subsection = ""
                continue
            # Detect "Missing Authorizations" section header — only flag True
            # when there is actual content listed DEEPER (more indented) beneath it.
            # The standalone label "   Missing Authorizations" (no colon, no value)
            # appears in sentinelctl-status.txt even when NO authorizations are missing.
            # Sibling Agent keys that follow (same indent, e.g. "ES Framework: started")
            # must NOT be mistaken for missing auth entries.
            if "Missing Authorizations" in stripped and ":" not in stripped:
                section = "missing_authorizations_section"
                _missing_auth_indent = indent
                subsection = ""
                continue
            # If we're in missing_authorizations_section and encounter a key:value:
            #   - deeper indent  → actual missing authorization entry → flag True
            #   - same/shallower → sibling Agent key, exit missing_auth section silently
            if section == "missing_authorizations_section":
                if indent > _missing_auth_indent:
                    result["missing_authorizations"] = True
                    # fall through to also record the key:value
                else:
                    section = "agent"
                    # fall through to parse this line as a regular Agent key
            # Subsection inside Daemons (e.g. "Services", "Integrity")
            if section == "daemons" and indent == 3 and ":" not in stripped:
                subsection = stripped.lower()
                continue
            # Key: Value pair
            if ":" in stripped:
                key, _, val = stripped.partition(":")
                key = key.strip()
                val = val.strip()
                target = result.get(section, {})
                if isinstance(target, dict):
                    if subsection:
                        target.setdefault(subsection, {})[key] = val
                    else:
                        target[key] = val
                # Track daemon states (all, not just degraded)
                if section == "daemons" and subsection in ("services", "integrity"):
                    result["daemon_states"].append({
                        "name": key,
                        "ready": val.lower() not in ("not ready", "not running"),
                    })
                    # Excluded from degraded_services:
                    #   - sentineld_shell / Shell: on-demand, only activates during remote shell sessions
                    #   - Lib Hooks Service / Lib Logs Service: deprecated, no longer used by the agent
                    _NOT_DEGRADED = frozenset({
                        "sentineld_shell",
                        "Shell",
                        "Lib Hooks Service",
                        "Lib Logs Service",
                    })
                    if val.lower() in ("not ready", "not running") and key not in _NOT_DEGRADED:
                        result["degraded_services"].append(f"{key}: {val}")
                # Track asset signatures from "assets" section
                if section == "assets":
                    status_lower = val.lower()
                    if "invalid" in status_lower:
                        sig_status = "invalid"
                    elif "empty" in status_lower:
                        sig_status = "empty"
                    elif "signed" in status_lower:
                        sig_status = "signed"
                    elif status_lower in ("valid",):
                        sig_status = "valid"
                    else:
                        sig_status = status_lower
                    result["asset_signatures"].append({
                        "name": key,
                        "status": sig_status,
                    })
    except Exception:
        pass
    return result


def _parse_ifconfig(path: Path) -> list[dict]:
    """
    Parse ifconfig.txt output.
    Returns list of {name, ipv4, ipv6, mac, flags, status}.
    Only includes interfaces that have an IP address.
    """
    interfaces = []
    current: dict | None = None
    try:
        for line in path.read_text(errors="replace").splitlines():
            # New interface block: starts at column 0
            iface_match = re.match(r'^(\S+):\s+flags=\S+\s+(.+)', line)
            if iface_match:
                if current and (current.get("ipv4") or current.get("ipv6_global")):
                    interfaces.append(current)
                current = {
                    "name": iface_match.group(1),
                    "flags": iface_match.group(2),
                    "ipv4": "",
                    "ipv6_global": "",
                    "mac": "",
                    "status": "unknown",
                }
                if "UP" in iface_match.group(2):
                    current["status"] = "up"
                else:
                    current["status"] = "down"
                continue
            if current is None:
                continue
            stripped = line.strip()
            # IPv4
            m = re.match(r'inet (\d+\.\d+\.\d+\.\d+)', stripped)
            if m:
                current["ipv4"] = m.group(1)
                continue
            # IPv6 global (not link-local fe80)
            m = re.match(r'inet6 ([0-9a-fA-F:]+) prefixlen', stripped)
            if m and not m.group(1).startswith("fe80") and m.group(1) != "::1":
                current["ipv6_global"] = m.group(1)
                continue
            # MAC
            m = re.match(r'ether ([0-9a-fA-F:]{17})', stripped)
            if m:
                current["mac"] = m.group(1)
                continue
        if current and (current.get("ipv4") or current.get("ipv6_global")):
            interfaces.append(current)
    except Exception:
        pass
    return interfaces


def _parse_lsof_i(path: Path) -> list[dict]:
    """
    Parse lsof -i output. Returns LISTEN + ESTABLISHED connections,
    deduplicating by (command, name).
    """
    connections: list[dict] = []
    seen: set[tuple] = set()
    try:
        lines = path.read_text(errors="replace").splitlines()
        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) < 9:
                continue
            command = parts[0]
            pid = parts[1]
            user = parts[2]
            proto = parts[7]
            name = parts[8]
            state = ""
            if len(parts) >= 10:
                state = parts[9].strip("()")
            if state not in ("LISTEN", "ESTABLISHED"):
                continue
            key = (command, name, state)
            if key in seen:
                continue
            seen.add(key)
            connections.append({
                "command": command,
                "pid": pid,
                "user": user,
                "proto": proto,
                "name": name,
                "state": state,
            })
    except Exception:
        pass
    return connections


def _parse_users(path: Path) -> list[dict]:
    """
    Parse users.txt (dscl output: username<tab>uid).
    Skip system accounts (uid < 500) and _ prefixed accounts.
    """
    users: list[dict] = []
    try:
        for line in path.read_text(errors="replace").splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                name = parts[0]
                try:
                    uid = int(parts[1])
                except ValueError:
                    uid = -1
                if name.startswith("_") or uid < 500:
                    continue
                users.append({"name": name, "uid": uid})
    except Exception:
        pass
    return users


def _parse_launchctl_disabled(path: Path) -> list[dict]:
    """
    Parse launchctl print-disabled output.
    Returns third-party services (excluding com.apple.*).
    Format: "service.name" => enabled|disabled
    """
    services: list[dict] = []
    try:
        for line in path.read_text(errors="replace").splitlines():
            m = re.match(r'\s*"([^"]+)"\s*=>\s*(enabled|disabled)', line)
            if not m:
                continue
            name = m.group(1)
            enabled = m.group(2) == "enabled"
            if name.startswith("com.apple."):
                continue
            services.append({"name": name, "enabled": enabled})
    except Exception:
        pass
    return services


def _parse_df(path: Path) -> list[dict]:
    """
    Parse df -H output into structured volume list.
    """
    volumes: list[dict] = []
    try:
        lines = path.read_text(errors="replace").splitlines()
        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) < 6:
                continue
            try:
                cap_str = parts[4].rstrip("%")
                capacity = int(cap_str)
            except ValueError:
                capacity = 0
            volumes.append({
                "filesystem": parts[0],
                "size": parts[1],
                "used": parts[2],
                "avail": parts[3],
                "capacity": capacity,
                "mounted": parts[-1],  # last column is mount point
            })
    except Exception:
        pass
    return volumes


def _parse_dns(path: Path) -> list[str]:
    """Extract nameserver IPs from scutil --dns output."""
    servers: list[str] = []
    seen: set[str] = set()
    try:
        for line in path.read_text(errors="replace").splitlines():
            m = re.match(r'\s*nameserver\[\d+\]\s*:\s*(\S+)', line)
            if m:
                ip = m.group(1)
                if ip not in seen:
                    seen.add(ip)
                    servers.append(ip)
    except Exception:
        pass
    return servers


def _parse_sysext(path: Path) -> list[dict]:
    """
    Parse systemextensionsctl list output.
    Returns list of {team_id, bundle_id, name, state, enabled, active}.
    """
    extensions: list[dict] = []
    try:
        lines = path.read_text(errors="replace").splitlines()
        for line in lines:
            # Header lines start with * or blank
            parts = line.strip().split("\t")
            if len(parts) < 5:
                continue
            enabled = parts[0].strip() == "*"
            active = len(parts) > 1 and parts[1].strip() == "*"
            team_id = parts[2].strip() if len(parts) > 2 else ""
            # Skip the header row
            if team_id == "teamID":
                continue
            bundle_version = parts[3].strip() if len(parts) > 3 else ""
            name = parts[4].strip() if len(parts) > 4 else ""
            state = ""
            if len(parts) > 5:
                m = re.search(r'\[([^\]]+)\]', parts[5])
                if m:
                    state = m.group(1)
            # Extract bundle_id without version
            bundle_id = re.sub(r'\s*\(.*\)', '', bundle_version).strip()
            if bundle_id:
                extensions.append({
                    "team_id": team_id,
                    "bundle_id": bundle_id,
                    "name": name,
                    "state": state,
                    "enabled": enabled,
                    "active": active,
                })
    except Exception:
        pass
    return extensions
