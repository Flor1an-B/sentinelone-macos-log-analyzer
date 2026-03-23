from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

KNOWN_AV = {
    "kaspersky": "Kaspersky",
    "kl_": "Kaspersky",
    "eset": "ESET",
    "bitdefender": "Bitdefender",
    "norton": "Norton",
    "malwarebytes": "Malwarebytes",
    "crowdstrike": "CrowdStrike",
    "cylance": "Cylance",
    "carbonblack": "Carbon Black",
    "sophos": "Sophos",
    "f-secure": "F-Secure",
}


class DualAVRule(BaseRule):
    id = "CONF-003"
    name = "Dual Security Agent Detected"
    severity = "MEDIUM"
    description = "SentinelOne and another antivirus are active simultaneously, which may cause conflicts and detection blind spots."

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        daemons_text = " ".join(ctx.system.launch_daemons).lower()
        others: list[str] = []
        for key, name in KNOWN_AV.items():
            if key in daemons_text:
                others.append(name)

        if others:
            others_str = ", ".join(sorted(set(others)))
            return [self._make_finding(
                ctx,
                description=f"SentinelOne coexists with: {others_str}. Both agents may interfere with each other.",
                recommendation=(
                    f"Verify compatibility between SentinelOne and {others_str}. "
                    "Disable one if redundant to avoid detection conflicts."
                ),
                process="sentineld",
            )]
        return []
