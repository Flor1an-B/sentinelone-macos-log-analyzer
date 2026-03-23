from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

TMP_PATHS = ("/private/tmp/", "/tmp/", "/var/tmp/")


class HiddenMachoRule(BaseRule):
    id = "EVADE-004"
    name = "Executable in Temporary Directory"
    severity = "HIGH"
    mitre_id = "T1564"
    mitre_name = "Hide Artifacts"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.source_type == "match_report"
            and (
                e.behavior_category == "vm_sensitive_file_mount"
                or (
                    e.target_path
                    and any(p in e.target_path for p in TMP_PATHS)
                    and e.event_type in ("file_modified", "file_open", "process_attach")
                )
            )
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
                    f"{proc} created or accessed files in a temporary directory "
                    f"({len(proc_events)} events). "
                    f"Paths: {', '.join(targets[:3]) or 'unspecified'}"
                ),
                recommendation=(
                    "Check /private/tmp/ content on the source machine. "
                    "Executables in /tmp/ do not persist after reboot but may be active in memory."
                ),
                process=proc,
                evidence=proc_events[:10],
            ))

        return findings
