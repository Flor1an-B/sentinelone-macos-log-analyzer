from __future__ import annotations
import os
from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

# Use only the narrower persistence-specific categories, not data_collection_script
# (which fires on many legitimate system utilities)
_PERSIST_SPECIFIC = frozenset({
    "preferences_modification",
    "plist_file_modification",
    "launchctl_proc",
})

# Broad set of system binaries/daemons that legitimately perform plist or launchctl operations
_SYSTEM_BINARIES = frozenset({
    # Shell / core utils
    "launchctl", "launchd", "installd", "softwareupdated", "osinstallersetupd",
    "installer", "pkgutil", "xpcproxy", "mdmclient", "mdmd",
    "bash", "sh", "zsh", "python", "python3", "ruby", "perl", "node",
    "cp", "mv", "cat", "rm", "ln", "chmod", "chown", "install",
    # Network utils
    "arp", "netstat", "ifconfig", "route", "ping", "curl", "wget",
    "networksetup", "scutil", "nesessionmanager", "nehelper",
    # Apple daemons / services
    "coreaudiod", "coreaudiod_x86", "contactsd", "cloudkeychainproxy",
    "keychain circle notification", "desktopserviceshelper",
    "installcoordinationd", "interiorserviced", "internetsharing",
    "sharedfilelist", "helpd", "loginwindow", "coresymbolicationd",
    "coreservicesd", "cfprefsd", "configd", "nsurlsessiond",
    "mdnsresponder", "diskarbitrationd", "diskmanagementd",
    "storagekitd", "sharingd", "nfd", "accountsd",
    "parentalcontrolsd", "authd", "securityd", "trustd",
    "syspolicyd", "endpointsecurity", "extensionkit",
    "systemextensionsserver", "photolibraryd", "mediaanalysisd",
    "photos", "imagecaptureext", "phonenumberlookupd",
    "cloudd", "bird", "icloudpairing",
    # Software update / packaging
    "storeaccountd", "storedownloadd", "storebookkeeperd",
    "com.apple.streamingunzipservice", "shipit",
    "com.apple.mobilesoftwareupdate.updatebranchservice",
    "com.apple.streamingunzipservice.privileged",
    "softwareupdate", "update",
    # SentinelOne own processes
    "sentineld", "sentineld-guard", "sentineld-helper", "sentineld-shell",
    "sentinel-extensions", "sentinelone", "sentinelctl",
})


def _basename(path: str) -> str:
    return os.path.basename(path.split()[0]) if path else ""


def _is_system_path(path: str) -> bool:
    """Return True for paths that are clearly macOS system locations."""
    lower = path.lower()
    return any(lower.startswith(p) for p in (
        "/system/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/",
        "/bin/", "/sbin/", "/private/var/db/", "/private/var/folders/",
        "/library/apple/", "/library/caches/",
    ))


class UndiscoveredDaemonRule(BaseRule):
    id = "PERSIST-004"
    name = "Potential Undiscovered Persistent Process"
    severity = "HIGH"
    mitre_id = "T1543.004"
    mitre_name = "Launch Daemon"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        # Build a set of basenames from known daemons + agents inventory
        known_basenames: set[str] = set()
        for entry in ctx.system.launch_daemons + ctx.system.launch_agents:
            b = _basename(entry)
            if b:
                known_basenames.add(b.lower())

        findings: list[Finding] = []
        seen_procs: set[str] = set()

        for e in ctx.timeline.events:
            if e.source_type != "match_report":
                continue
            if e.behavior_category not in _PERSIST_SPECIFIC:
                continue

            proc_name = _basename(e.process_path).lower()
            if not proc_name or proc_name in seen_procs:
                continue
            if proc_name in _SYSTEM_BINARIES:
                continue
            if _is_system_path(e.process_path):
                continue
            if any(proc_name.startswith(p) for p in ("sentinel", "com.apple.")):
                continue
            if proc_name in known_basenames:
                continue

            proc_events = [
                ev for ev in ctx.timeline.events
                if ev.source_type == "match_report"
                and ev.behavior_category in _PERSIST_SPECIFIC
                and _basename(ev.process_path).lower() == proc_name
            ]

            # Require at least 2 events to reduce single-occurrence noise
            if len(proc_events) < 2:
                continue

            seen_procs.add(proc_name)
            findings.append(self._make_finding(
                ctx,
                description=(
                    f"`{e.process_name}` triggered persistence-related behavior "
                    f"({len(proc_events)} event(s)) but is not listed in LaunchDaemons.txt "
                    "or LaunchAgents.txt. This may indicate a stealthy persistence mechanism "
                    "that bypasses standard LaunchDaemon inventory."
                ),
                recommendation=(
                    f"Search for `{e.process_name}` in /Library/LaunchDaemons/, "
                    "/Library/LaunchAgents/, ~/Library/LaunchAgents/, and /System/Library/. "
                    f"Use `launchctl list | grep {e.process_name}` to check runtime registration. "
                    "If unknown, treat as suspicious and escalate."
                ),
                process=e.process_name,
                evidence=proc_events,
            ))

        return findings
