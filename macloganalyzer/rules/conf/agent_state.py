from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class AgentDisabledRule(BaseRule):
    id = "CONF-006"
    name = "SentinelOne Agent Disabled"
    severity = "CRITICAL"
    description = "The SentinelOne agent has been disabled (agentDisabled detected in UI logs). Endpoint protection is inactive."

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        if "agentDisabled" in ctx.system.ui_agent_states:
            return [self._make_finding(
                ctx,
                description=self.description,
                recommendation="Re-enable the SentinelOne agent from the management console or via `sentinelctl start`.",
                process="agent-ui",
            )]
        return []


class AntiTamperOffRule(BaseRule):
    id = "CONF-005"
    name = "Anti-Tamper Disabled"
    severity = "HIGH"
    description = "SentinelOne anti-tamper protection is disabled. The agent can be modified or stopped without alerts."

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        if "antiTamperOff" in ctx.system.ui_agent_states:
            return [self._make_finding(
                ctx,
                description=self.description,
                recommendation="Re-enable anti-tamper from the SentinelOne console → Policy → Anti-Tamper.",
                process="agent-ui",
            )]
        return []


class MissingPermissionsRule(BaseRule):
    id = "CONF-007"
    name = "Agent Missing Permissions"
    severity = "HIGH"
    description = "The SentinelOne agent is missing system permissions. Its detection and protection capability is degraded."

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        if "missingPermissions" in ctx.system.ui_agent_states:
            return [self._make_finding(
                ctx,
                description=self.description,
                recommendation=(
                    "Grant required permissions via System Settings → Privacy & Security. "
                    "System extensions, Full Disk Access and other required entitlements."
                ),
                process="agent-ui",
            )]
        return []
