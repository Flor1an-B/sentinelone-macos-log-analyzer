from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

LOG_CATS = frozenset({
    "user_logs_modified",
    "indicators_modified_logs",
    "modified_system_logs",
})


class LogTamperingRule(BaseRule):
    id = "EVADE-002"
    name = "System Log Modification/Deletion"
    severity = "HIGH"
    mitre_id = "T1070.002"
    mitre_name = "Clear Linux or Mac System Logs"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.behavior_category in LOG_CATS
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
                    f"{proc} modified system log files "
                    f"({len(proc_events)} events). Possible evidence erasure."
                ),
                recommendation=(
                    "Compare system logs with backups or SIEM exports. "
                    "Check modification dates of log files."
                ),
                process=proc,
                evidence=proc_events[:10],
            ))

        return findings
