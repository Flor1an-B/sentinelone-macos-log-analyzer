from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

LIB_VALIDATION_CATS = frozenset({
    "library_validation_entitlement_usage",
    "library_validation_entitlement_usage_internal",
})


class LibValidationRule(BaseRule):
    id = "CRED-003"
    name = "Library Validation Bypass"
    severity = "HIGH"
    mitre_id = "T1574"
    mitre_name = "Hijack Execution Flow"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.behavior_category in LIB_VALIDATION_CATS
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
                    f"{proc} uses library validation bypass entitlements "
                    f"({len(proc_events)} events). "
                    "May allow loading of unsigned libraries."
                ),
                recommendation=(
                    "Analyze binary entitlements: "
                    "`codesign -d --entitlements - /path/to/binary`. "
                    "Check com.apple.security.cs.disable-library-validation."
                ),
                process=proc,
                evidence=proc_events,
            ))

        return findings
