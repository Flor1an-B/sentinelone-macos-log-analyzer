from __future__ import annotations
from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

# Update this constant quarterly when new agent versions are released.
# Last verified: 2026-03-20 — SentinelOne macOS agent GA release line.
_KNOWN_MIN_VERSION = (24, 0, 0)  # anything older than 24.x is considered stale


def _parse_version(v: str) -> tuple[int, ...] | None:
    """Parse 'major.minor.patch[.build]' into an integer tuple. Returns None if unparseable."""
    try:
        parts = v.strip().split(".")
        return tuple(int(x) for x in parts[:3])
    except (ValueError, AttributeError):
        return None


class AgentVersionRule(BaseRule):
    id = "CONF-008"
    name = "Outdated SentinelOne Agent Version"
    severity = "MEDIUM"
    mitre_id = None

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        raw = ctx.system.agent_version
        if not raw or raw in ("Unknown", ""):
            return []

        parsed = _parse_version(raw)
        if parsed is None:
            return []

        if parsed >= _KNOWN_MIN_VERSION:
            return []

        min_str = ".".join(str(x) for x in _KNOWN_MIN_VERSION)
        return [self._make_finding(
            ctx,
            description=(
                f"SentinelOne agent version {raw} is below the known minimum recommended "
                f"version {min_str}. Older agents may lack detection capabilities for recent "
                "threat patterns and may contain unpatched vulnerabilities."
            ),
            recommendation=(
                "Upgrade the SentinelOne agent from the management console "
                "(Endpoints → Actions → Update Agent Policy). "
                "Prioritize endpoints running agents older than the current GA release."
            ),
            process="sentineld",
        )]
