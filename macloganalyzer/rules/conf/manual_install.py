from __future__ import annotations
from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

# Auto-update daemons whose packages may temporarily land in /tmp or /var/folders
_TRUSTED_AUTO_UPDATE = frozenset({
    "onedrivedaemonupdate", "com.microsoft.autoupdate",
    "zoom.us/updater", "application support/zoom.us",
    "application%20support/zoom.us",
    "com.apple.softwareupdate", "swcdn.apple.com",
    "com.apple.appstoreagent",
})


class ManualInstallRule(BaseRule):
    id = "CONF-009"
    name = "Manual Package Installation Detected"
    severity = "LOW"
    mitre_id = "T1204.002"
    mitre_name = "User Execution: Malicious File"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        manual = [
            e for e in ctx.system.install_history
            if e.get("source_type") == "manual"
        ]
        if not manual:
            return []

        findings: list[Finding] = []
        for entry in manual:
            pkg = entry.get("package_name", "Unknown")
            path = entry.get("source_path", "")
            version = entry.get("version", "")
            date = entry.get("date", "")
            uid = entry.get("uid")
            uid_note = f" (installed by uid={uid})" if uid is not None else ""

            findings.append(self._make_finding(
                ctx,
                description=(
                    f"`{pkg}`{(' ' + version) if version else ''} was installed on {date} "
                    f"from a user-controlled path: `{path}`{uid_note}. "
                    "Manual .pkg installations bypass App Store review and can include "
                    "preinstall/postinstall scripts executed as root. "
                    "This is a common vector for trojanized installers on macOS."
                ),
                recommendation=(
                    f"Verify the authenticity of `{pkg}` — confirm the package was "
                    "intentionally downloaded from the official vendor website. "
                    "Check the package signature: `pkgutil --check-signature <path>`. "
                    "Review preinstall/postinstall scripts if the .pkg is still available. "
                    "Correlate with SentinelOne behavioral events on the same date."
                ),
                process="installer",
            ))

        return findings
