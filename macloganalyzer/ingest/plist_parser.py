from __future__ import annotations
import plistlib
import logging
from pathlib import Path

from macloganalyzer.models.context import SystemContext

logger = logging.getLogger(__name__)

try:
    import biplist
    HAS_BIPLIST = True
except ImportError:
    HAS_BIPLIST = False
    logger.warning("biplist not available; binary plists will be skipped")


def load_plist(path: Path) -> dict | None:
    """Load a plist (XML or binary). Returns None on failure."""
    try:
        return plistlib.loads(path.read_bytes())
    except Exception:
        if HAS_BIPLIST:
            try:
                return biplist.readPlist(str(path))
            except Exception as e:
                logger.debug(f"biplist failed on {path.name}: {e}")
    return None


def parse_plist_sources(dump_path: Path, ctx: SystemContext) -> None:
    """Extract context info from plist files."""
    # Agent version from bundle/
    bundle_plist = dump_path / "bundle" / "sentinel-agent.plist"
    if bundle_plist.exists():
        data = load_plist(bundle_plist)
        if data and isinstance(data, dict):
            ver = data.get("CFBundleShortVersionString") or data.get("CFBundleVersion", "")
            if ver and ctx.agent_version in ("Unknown", ""):
                ctx.agent_version = str(ver)

    # Network interfaces
    sys_conf = dump_path / "preferences_system" / "SystemConfiguration"
    if sys_conf.exists():
        _parse_network_interfaces(sys_conf, ctx)
        _parse_preferences(sys_conf, ctx)

    # Infer hostname from crash report filenames
    _infer_hostname(dump_path, ctx)

    # Extended sources
    _parse_config_s1(dump_path, ctx)
    _parse_intelligence_metadata(dump_path, ctx)
    _parse_exclusions(dump_path, ctx)


def _parse_network_interfaces(sys_conf_path: Path, ctx: SystemContext) -> None:
    ni_plist = sys_conf_path / "NetworkInterfaces.plist"
    if not ni_plist.exists():
        return
    data = load_plist(ni_plist)
    if not data or not isinstance(data, dict):
        return
    for iface in data.get("Interfaces", []):
        if not isinstance(iface, dict):
            continue
        ctx.network_interfaces.append({
            "bsd_name": iface.get("BSD Name", ""),
            "type": iface.get("SCNetworkInterfaceType", ""),
            "builtin": iface.get("IOBuiltin", False),
            "active": iface.get("Active", False),
        })


def _parse_preferences(sys_conf_path: Path, ctx: SystemContext) -> None:
    prefs_plist = sys_conf_path / "preferences.plist"
    if not prefs_plist.exists():
        return
    data = load_plist(prefs_plist)
    if not data or not isinstance(data, dict):
        return
    if "Model" in data and ctx.model in ("Unknown", ""):
        ctx.model = str(data["Model"])


def _infer_hostname(dump_path: Path, ctx: SystemContext) -> None:
    """Infer hostname from crash report filenames: ProcessName_DATE_HOSTNAME.diag"""
    crashes_dir = dump_path / "crashes"
    if not crashes_dir.exists():
        return
    for diag in crashes_dir.rglob("*.diag"):
        # Remove suffixes like .cpu_resource, .memory, etc. before splitting
        stem = diag.stem
        for suffix in (".cpu_resource", ".memory_resource", ".hang", ".wakeups_resource"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break

        parts = stem.split("_")
        if len(parts) >= 3:
            hostname = parts[-1]
            # Hostname has letters and dashes, not pure digits
            if hostname and not hostname[0].isdigit() and "-" in hostname:
                ctx.hostname = hostname
                return
        # Fallback: any part with dashes
        for part in reversed(parts):
            if "-" in part and not part[0].isdigit() and len(part) > 4:
                ctx.hostname = part
                return


def _parse_config_s1(dump_path: Path, ctx: SystemContext) -> None:
    """Parse XML plists from config_s1/ for agent configuration summary."""
    config_dir = dump_path / "config_s1"
    if not config_dir.exists():
        return

    result: dict = {}

    # General_defaults.plist — anti-tamper, CPU limit
    general = load_plist(config_dir / "General_defaults.plist")
    if general and isinstance(general, dict):
        result["anti_tamper_disabled"] = bool(general.get("AntiTamperDisabled", False))
        result["cpu_consumption_limit"] = general.get("CPUConsumptionLimit")
        result["scan_new_apps"] = general.get("ScanNewApps")
        result["threat_remediation"] = general.get("ThreatRemediation")

    # RemoteShell_defaults.plist
    remote_shell = load_plist(config_dir / "RemoteShell_defaults.plist")
    if remote_shell and isinstance(remote_shell, dict):
        result["remote_shell_enabled"] = bool(remote_shell.get("Enabled", False))

    # Server_defaults.plist — update interval, site key
    server = load_plist(config_dir / "Server_defaults.plist")
    if server and isinstance(server, dict):
        result["update_interval"] = server.get("UpdateInterval")
        site_key = server.get("SiteKey") or server.get("site_key") or server.get("Token")
        if site_key:
            # Mask all but last 4 chars
            s = str(site_key)
            result["site_key_suffix"] = "***" + s[-4:] if len(s) > 4 else "****"
        result["management_server"] = server.get("ManagementServer") or server.get("Url")

    # DeepVisibility_defaults.plist — Collect* event flags
    dv = load_plist(config_dir / "DeepVisibility_defaults.plist")
    if dv and isinstance(dv, dict):
        collect_flags = {
            k: bool(v) for k, v in dv.items()
            if k.startswith("Collect") and isinstance(v, (bool, int))
        }
        if collect_flags:
            result["dv_collect_flags"] = collect_flags

    if result:
        ctx.agent_config = result


def _parse_intelligence_metadata(dump_path: Path, ctx: SystemContext) -> None:
    """Parse binary metadata plists from global-assets/ for threat intelligence versions."""
    assets_dir = dump_path / "global-assets"
    if not assets_dir.exists():
        return

    result: dict = {}
    _METADATA_KEYS = ("version", "Version", "BuildNumber", "UpdateDate", "ContentVersion")

    for plist_path in assets_dir.glob("*-metadata.plist"):
        data = load_plist(plist_path)
        if not data or not isinstance(data, dict):
            continue
        name = plist_path.stem.replace("-metadata", "")
        entry = {k: str(data[k]) for k in _METADATA_KEYS if k in data}
        if entry:
            result[name] = entry

    if result:
        ctx.intelligence_metadata = result


def _parse_exclusions(dump_path: Path, ctx: SystemContext) -> None:
    """Parse binary exclusion plists from assets/ directory."""
    assets_dir = dump_path / "assets"
    if not assets_dir.exists():
        return

    # Path exclusions
    path_excl = load_plist(assets_dir / "pathExclusion.plist")
    if path_excl and isinstance(path_excl, dict):
        entries = path_excl.get("ExclusionsList") or path_excl.get("exclusions") or []
        if isinstance(entries, list):
            ctx.path_exclusions = [str(e) for e in entries if e]

    # Deep Visibility exclusions
    dv_excl = load_plist(assets_dir / "dvExclusionsConsole.plist")
    if dv_excl and isinstance(dv_excl, dict):
        entries = dv_excl.get("ExclusionsList") or dv_excl.get("exclusions") or []
        if isinstance(entries, list):
            ctx.dv_exclusions = [str(e) for e in entries if e]

    # Management config
    mgmt = load_plist(assets_dir / "mgmtConfig.plist")
    if mgmt and isinstance(mgmt, dict):
        ctx.mgmt_config = {
            k: v for k, v in mgmt.items()
            if isinstance(v, (str, int, float, bool))
        }
