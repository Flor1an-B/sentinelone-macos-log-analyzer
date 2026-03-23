from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class PrivateKeysRule(BaseRule):
    id = "CRED-002"
    name = "Private Key Access"
    severity = "HIGH"
    mitre_id = "T1552.004"
    mitre_name = "Private Keys"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.behavior_category == "read_private_keys_ext"
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
                    f"{proc} accessed private key files "
                    f"({len(proc_events)} accesses). "
                    f"Files: {', '.join(targets[:3]) or 'unspecified'}"
                ),
                recommendation=(
                    "Identify which private keys were accessed. "
                    "If unauthorized, consider immediate key rotation."
                ),
                process=proc,
                evidence=proc_events,
            ))

        return findings
