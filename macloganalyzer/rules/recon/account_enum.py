from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

ACCOUNT_CATS = frozenset({
    "account_discovery", "local_groups_discovery", "system_users_discovery_od_access"
})
ACCOUNT_PROCS = frozenset({"dscl", "id", "lsof", "groups", "dscacheutil", "dsmemberutil"})


class AccountEnumRule(BaseRule):
    id = "RECON-002"
    name = "Local Account Enumeration"
    severity = "MEDIUM"
    mitre_id = "T1087.001"
    mitre_name = "Local Account"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        seen_processes: set[str] = set()

        for event in ctx.timeline.events:
            if event.source_type != "match_report":
                continue
            if event.behavior_category not in ACCOUNT_CATS:
                continue

            pname = event.process_name.lower()
            is_recon_proc = any(p in pname for p in ACCOUNT_PROCS)

            if event.process_name not in seen_processes and is_recon_proc:
                seen_processes.add(event.process_name)
                related = [
                    e for e in ctx.timeline.events
                    if e.behavior_category in ACCOUNT_CATS
                    and e.process_name == event.process_name
                ]
                findings.append(self._make_finding(
                    ctx,
                    description=(
                        f"{event.process_name} performed local account enumeration "
                        f"({len(related)} events)"
                    ),
                    recommendation=(
                        "Verify whether this process has a legitimate reason to enumerate accounts. "
                        "Cross-reference with LaunchDaemons and Applications entries."
                    ),
                    process=event.process_name,
                    evidence=related[:20],
                ))

        return findings
