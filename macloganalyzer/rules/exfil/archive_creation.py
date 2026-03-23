from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

ARCHIVE_PROCS = frozenset({"bzip2", "tar", "zip", "gzip", "7z", "compress", "pigz"})


class ArchiveCreationRule(BaseRule):
    id = "EXFIL-002"
    name = "Archive Creation"
    severity = "MEDIUM"
    mitre_id = "T1560.001"
    mitre_name = "Archive via Utility"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if any(p in e.process_path.lower() for p in ARCHIVE_PROCS)
            and e.source_type == "match_report"
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
                    f"{proc} created archives ({len(proc_events)} events). "
                    f"Files: {', '.join(targets[:3]) or 'unspecified'}"
                ),
                recommendation=(
                    "Identify what was archived and whether the archives were "
                    "transferred externally. Cross-reference with curl/network events."
                ),
                process=proc,
                evidence=proc_events[:10],
            ))

        return findings
