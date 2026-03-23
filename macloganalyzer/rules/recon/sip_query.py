from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class SIPQueryRule(BaseRule):
    id = "RECON-005"
    name = "SIP Status Query"
    severity = "HIGH"
    mitre_id = "T1082"
    mitre_name = "System Information Discovery"
    description = (
        "A process queried SIP status, typical behavior of a tool "
        "checking whether the system is vulnerable."
    )

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.behavior_category == "system_information_discovery"
            and e.source_type == "match_report"
            and (
                (e.target_path and "csrutil" in e.target_path.lower())
                or "csrutil" in e.process_path.lower()
            )
        ]

        if not events:
            return []

        by_process: dict[str, list] = {}
        for e in events:
            by_process.setdefault(e.process_name, []).append(e)

        sip_status = "disabled" if ctx.system.sip_enabled is False else "enabled"

        findings: list[Finding] = []
        for proc, proc_events in by_process.items():
            findings.append(self._make_finding(
                ctx,
                description=(
                    f"{proc} queried SIP status (currently {sip_status}). "
                    "This behavior may indicate an attempt to find exploitation opportunities."
                ),
                recommendation=(
                    "Investigate why this process is checking SIP status. "
                    "If SIP is disabled, re-enabling it is a priority."
                ),
                process=proc,
                evidence=proc_events,
            ))

        return findings
