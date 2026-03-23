from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class DataCollectionRule(BaseRule):
    id = "EXFIL-003"
    name = "Automated Data Collection Script"
    severity = "MEDIUM"
    mitre_id = "T1119"
    mitre_name = "Automated Collection"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.behavior_category == "data_collection_script"
            and e.source_type == "match_report"
            and "crontab" not in (e.process_path + (e.target_path or "")).lower()
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
                    f"{proc} executed automated data collection scripts "
                    f"({len(proc_events)} events)."
                ),
                recommendation=(
                    "Identify what data was collected and its potential destination. "
                    "Inspect scripts executed by this process."
                ),
                process=proc,
                evidence=proc_events[:10],
            ))

        return findings
