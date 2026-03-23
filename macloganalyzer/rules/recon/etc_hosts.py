from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class EtcHostsAccessRule(BaseRule):
    id = "RECON-004"
    name = "Access to /etc/hosts File"
    severity = "MEDIUM"
    mitre_id = "T1565.001"
    mitre_name = "Stored Data Manipulation"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.behavior_category == "etc_hosts_access"
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
                    f"{proc} accessed /etc/hosts {len(proc_events)} times. "
                    "Possible local DNS resolution manipulation."
                ),
                recommendation=(
                    "Check /etc/hosts content for suspicious entries. "
                    "Unexpected entries may redirect network traffic."
                ),
                process=proc,
                evidence=proc_events[:10],
            ))

        return findings
