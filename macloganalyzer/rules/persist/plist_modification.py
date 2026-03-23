from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

SYSTEM_PLIST_PATHS = (
    "/Library/LaunchDaemons/",
    "/Library/LaunchAgents/",
    "/System/Library/",
    "/private/etc/",
)


class PlistModificationRule(BaseRule):
    id = "PERSIST-002"
    name = "System Plist File Modification"
    severity = "MEDIUM"
    mitre_id = "T1647"
    mitre_name = "Plist File Modification"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.behavior_category == "plist_file_modification"
            and e.source_type == "match_report"
        ]

        # Filter to system paths if possible
        system_events = [
            e for e in events
            if e.target_path and any(p in e.target_path for p in SYSTEM_PLIST_PATHS)
        ]
        if system_events:
            events = system_events

        if not events:
            return []

        by_process: dict[str, list] = {}
        for e in events:
            by_process.setdefault(e.process_name, []).append(e)

        findings: list[Finding] = []
        for proc, proc_events in by_process.items():
            findings.append(self._make_finding(
                ctx,
                description=(
                    f"{proc} modified {len(proc_events)} system plist file(s). "
                    "Possible persistence mechanism."
                ),
                recommendation=(
                    "Inspect modified plists for persistence entries "
                    "(LaunchDaemons, LaunchAgents, startup scripts)."
                ),
                process=proc,
                evidence=proc_events[:10],
            ))

        return findings
