from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class SIPDisabledRule(BaseRule):
    id = "CONF-001"
    name = "SIP (System Integrity Protection) Disabled"
    severity = "CRITICAL"
    mitre_id = "T1562.010"
    mitre_name = "Disable or Modify Tools"
    description = "System Integrity Protection is disabled. The system no longer has native protection against modification of system files."

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        if ctx.system.sip_enabled is False:
            return [self._make_finding(
                ctx,
                description=self.description,
                recommendation=(
                    "Re-enable SIP via `csrutil enable` in Recovery mode. "
                    "Investigate why it was disabled and when."
                ),
                process="csrutil",
            )]
        return []
