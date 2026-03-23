from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

KEYCHAIN_CATS = frozenset({"keychain_read", "open_loginkeychain_db"})
THRESHOLD = 5


class KeychainAccessRule(BaseRule):
    id = "CRED-001"
    name = "Frequent Keychain Access"
    severity = "HIGH"
    mitre_id = "T1555.001"
    mitre_name = "Keychain"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.behavior_category in KEYCHAIN_CATS
            and e.source_type == "match_report"
        ]

        if not events:
            return []

        by_process: dict[str, list] = {}
        for e in events:
            by_process.setdefault(e.process_name, []).append(e)

        findings: list[Finding] = []
        for proc, proc_events in by_process.items():
            if len(proc_events) >= THRESHOLD:
                targets = sorted(set(
                    e.target_path for e in proc_events if e.target_path
                ))
                findings.append(self._make_finding(
                    ctx,
                    description=(
                        f"{proc} accessed the Keychain {len(proc_events)} times "
                        f"(threshold: {THRESHOLD}). "
                        f"Targets: {', '.join(targets[:3]) or 'unspecified'}"
                    ),
                    recommendation=(
                        "Verify whether this process has a legitimate reason to access "
                        "the Keychain that frequently. "
                        "Repeated access may indicate credential extraction."
                    ),
                    process=proc,
                    evidence=proc_events[:20],
                ))

        return findings
