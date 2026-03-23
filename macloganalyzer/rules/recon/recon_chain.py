from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding
from macloganalyzer.config import RECON_CATEGORIES


class ReconChainRule(BaseRule):
    id = "RECON-001"
    name = "Complete Reconnaissance Chain"
    severity = "HIGH"
    mitre_id = "TA0007"
    mitre_name = "Discovery"
    description = "A process performed ≥4 distinct system reconnaissance categories in the same session (group UUID)."

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        seen_groups: set[str] = set()

        for group_id in ctx.group_index.all_groups():
            if group_id in seen_groups:
                continue

            categories = ctx.group_index.categories_for_group(group_id)
            recon_cats = categories & RECON_CATEGORIES

            if len(recon_cats) >= 4:
                seen_groups.add(group_id)
                events = ctx.group_index.events_for_group(group_id)
                primary = ctx.group_index.primary_for_group(group_id)
                process_name = events[0].process_name if events else primary

                findings.append(self._make_finding(
                    ctx,
                    description=(
                        f"Session {group_id[:8]}... — {len(recon_cats)} reconnaissance categories: "
                        f"{', '.join(sorted(recon_cats))}"
                    ),
                    recommendation=(
                        "Investigate the primary process and its parent execution chain. "
                        "Verify whether this behavior is expected for this application."
                    ),
                    process=process_name or primary,
                    evidence=events,
                ))

        return findings
