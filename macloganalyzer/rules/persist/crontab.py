from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class CrontabRule(BaseRule):
    id = "PERSIST-003"
    name = "Scheduling via Crontab"
    severity = "HIGH"
    mitre_id = "T1053.003"
    mitre_name = "Cron"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.source_type == "match_report"
            and "crontab" in (e.process_path + (e.target_path or "")).lower()
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
                    f"Crontab usage by {proc} — potential persistence mechanism. "
                    f"{len(proc_events)} events detected."
                ),
                recommendation=(
                    "Inspect crontabs for all users: `crontab -l -u <user>`. "
                    "Check /var/at/tabs/ for suspicious scheduled tasks."
                ),
                process=proc,
                evidence=proc_events,
            ))

        return findings
