from __future__ import annotations
from datetime import timedelta

from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

WINDOW = timedelta(hours=24)


class CrashCorrelationRule(BaseRule):
    id = "CHAIN-002"
    name = "Behavior/Crash Correlation"
    severity = "HIGH"
    description = (
        "A process showing behavioral detections also crashed. "
        "May indicate exploitation or instability caused by malicious behavior."
    )

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []

        for crash in ctx.crash_events:
            crash_proc = crash.process_name.lower()

            related = [
                e for e in ctx.timeline.events
                if e.source_type == "match_report"
                and crash_proc in e.process_name.lower()
                and abs((e.timestamp - crash.timestamp).total_seconds()) <= WINDOW.total_seconds()
            ]

            if related:
                findings.append(self._make_finding(
                    ctx,
                    description=(
                        f"{crash.process_name} crashed "
                        f"({crash.extra.get('diag_file', 'crash report')}) "
                        f"and shows {len(related)} behavioral detections "
                        "within ±24h around the crash."
                    ),
                    recommendation=(
                        f"Analyze the crash report of {crash.process_name} to verify "
                        "whether the crash is related to detected behaviors. "
                        "A crash may indicate an exploitation attempt or "
                        "abnormal activity causing instability."
                    ),
                    process=crash.process_name,
                    evidence=[crash] + related[:10],
                ))

        return findings
