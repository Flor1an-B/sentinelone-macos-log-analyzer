from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class AgentLogErrorRule(BaseRule):
    id = "CONF-004"
    name = "Agent Log Store Error"
    severity = "MEDIUM"
    description = "The macOS unified log archive could not be opened during dump collection."

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        if ctx.system.sentinelctl_error:
            return [self._make_finding(
                ctx,
                description=(
                    f"sentinelctl-log.txt: {ctx.system.sentinelctl_error} — "
                    "This error originates from the macOS `log` command failing to open the unified "
                    "log archive (.logarchive), not from SentinelOne itself. "
                    "SentinelOne behavioral detection events (match_reports) are unaffected."
                ),
                recommendation=(
                    "This is expected in most SentinelOne log dumps — the macOS log archive is not "
                    "included in the collected package. To capture macOS system logs, run "
                    "`log collect --output /tmp/system.logarchive` on the live endpoint separately."
                ),
                process="sentinelctl",
            )]
        return []
