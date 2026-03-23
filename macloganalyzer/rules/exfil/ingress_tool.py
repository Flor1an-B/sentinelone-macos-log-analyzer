from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class IngressToolRule(BaseRule):
    id = "EXFIL-001"
    name = "Tool Transfer via curl"
    severity = "HIGH"
    mitre_id = "T1105"
    mitre_name = "Ingress Tool Transfer"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if "curl" in e.process_path.lower()
            and e.source_type == "match_report"
            and e.event_type in ("file_modified", "file_open", "process_attach")
        ]

        if not events:
            return []

        by_process: dict[str, list] = {}
        for e in events:
            by_process.setdefault(e.process_name, []).append(e)

        findings: list[Finding] = []
        for proc, proc_events in by_process.items():
            targets = sorted(set(e.target_path for e in proc_events if e.target_path))
            findings.append(self._make_finding(
                ctx,
                description=(
                    f"curl used to transfer files ({len(proc_events)} events). "
                    f"Targets: {', '.join(targets[:5]) or 'unspecified'}"
                ),
                recommendation=(
                    "Analyze curl parent processes to understand context. "
                    "Inspect downloaded files and URLs used."
                ),
                process=proc,
                evidence=proc_events[:10],
            ))

        return findings
