from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class TimestampModRule(BaseRule):
    id = "EVADE-001"
    name = "Timestomp (Temporal Evasion)"
    severity = "HIGH"
    mitre_id = "T1070.006"
    mitre_name = "Timestomp"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.behavior_category == "time_based_evasion"
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
                    f"{proc} performed temporal evasion ({len(proc_events)} events). "
                    "Timestamp manipulation to bypass detection or forensic analysis."
                ),
                recommendation=(
                    "Analyze actions preceding and following this evasion in the timeline. "
                    "Compare file metadata with backups."
                ),
                process=proc,
                evidence=proc_events,
            ))

        return findings
