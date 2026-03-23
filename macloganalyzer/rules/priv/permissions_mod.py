from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

PERM_PROCS = frozenset({"chown", "chmod", "chgrp"})
SYSTEM_PATHS = ("/Library/", "/System/", "/usr/", "/private/", "/etc/")


class PermissionsModRule(BaseRule):
    id = "PRIV-002"
    name = "System File Permission Modification"
    severity = "MEDIUM"
    mitre_id = "T1222.002"
    mitre_name = "File and Directory Permissions Modification"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if any(p in e.process_path.lower() for p in PERM_PROCS)
            and e.source_type == "match_report"
        ]

        # Prefer events targeting system paths
        system_events = [
            e for e in events
            if e.target_path and any(sp in e.target_path for sp in SYSTEM_PATHS)
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
                    f"{proc} modified permissions on {len(proc_events)} file(s). "
                    "Possible privilege escalation or exploitation preparation."
                ),
                recommendation=(
                    "Check modified permissions and whether they allow "
                    "privilege escalation or unauthorized access."
                ),
                process=proc,
                evidence=proc_events[:10],
            ))

        return findings
