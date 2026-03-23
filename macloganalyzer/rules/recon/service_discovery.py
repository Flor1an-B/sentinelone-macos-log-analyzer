from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class ServiceDiscoveryRule(BaseRule):
    id = "RECON-003"
    name = "System Service Discovery"
    severity = "MEDIUM"
    mitre_id = "T1007"
    mitre_name = "System Service Discovery"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.behavior_category == "system_service_discovery"
            and e.source_type == "match_report"
        ]

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
                    f"{proc} performed {len(proc_events)} system service discovery "
                    "requests via launchctl."
                ),
                recommendation=(
                    "Verify whether this process has a legitimate reason to query "
                    "the list of system services."
                ),
                process=proc,
                evidence=proc_events[:20],
            ))

        return findings
