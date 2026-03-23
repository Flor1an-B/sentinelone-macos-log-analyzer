from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class SudoUsageRule(BaseRule):
    id = "PRIV-001"
    name = "sudo Usage"
    severity = "MEDIUM"
    mitre_id = "T1548.003"
    mitre_name = "Sudo and Sudo Caching"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if "sudo" in e.process_path.lower()
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
                    f"sudo used ({len(proc_events)} times). "
                    "Potential privilege escalation."
                ),
                recommendation=(
                    "Verify commands executed via sudo and their justification. "
                    "Inspect /var/log/sudo.log or system logs."
                ),
                process=proc,
                evidence=proc_events[:10],
            ))

        return findings
