from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

APPLE_PREFIXES = ("com.apple.", "io.apple.", "com.vmware.", "com.microsoft.")


class ThirdPartyKextRule(BaseRule):
    id = "CONF-009"
    name = "Third-Party Kernel Extensions Present"
    severity = "INFO"
    description = "Third-party kernel extensions (kext) from third-party vendors are loaded."

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        third_party = [
            k for k in ctx.system.kernel_extensions
            if not any(k.lower().startswith(p.lower()) for p in APPLE_PREFIXES)
        ]
        if third_party:
            return [self._make_finding(
                ctx,
                description=f"Third-party kexts loaded: {', '.join(third_party)}",
                recommendation="Verify these kexts are legitimate, signed and necessary.",
                process="kernel",
            )]
        return []
