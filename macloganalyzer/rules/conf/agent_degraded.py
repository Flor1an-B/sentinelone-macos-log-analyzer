from __future__ import annotations

from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class AgentServicesDegradedRule(BaseRule):
    id = "CONF-010"
    name = "SentinelOne Daemon Services Degraded"
    severity = "HIGH"
    mitre_id = "T1562.001"
    mitre_name = "Impair Defenses: Disable or Modify Tools"
    description = (
        "One or more internal SentinelOne agent services are in a degraded state "
        "(not ready / not running). Detection capability may be reduced."
    )

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        degraded = ctx.system.sentinel_status.get("degraded_services", [])
        missing_auth = ctx.system.sentinel_status.get("missing_authorizations", False)

        issues: list[str] = list(degraded)
        if missing_auth:
            issues.append("Missing Authorizations")

        if not issues:
            return []

        detail = "\n".join(f"  • {s}" for s in issues)
        return [self._make_finding(
            ctx,
            description=(
                f"Degraded services detected ({len(issues)}):\n{detail}\n\n"
                "These degradations may indicate agent tampering, missing permissions, "
                "or a partial disable attempt."
            ),
            recommendation=(
                "1. Check system authorizations: System Settings → "
                "Privacy & Security → System Extensions and Full Disk Access.\n"
                "2. Restart degraded services: `sudo sentinelctl restart`.\n"
                "3. If the issue persists, reinstall the agent from the SentinelOne console."
            ),
            process="sentineld",
        )]
