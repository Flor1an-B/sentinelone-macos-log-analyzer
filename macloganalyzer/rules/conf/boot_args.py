from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class BootArgsRule(BaseRule):
    id = "CONF-002"
    name = "Custom Boot Arguments Present"
    severity = "HIGH"
    mitre_id = "T1562.010"
    mitre_name = "Disable or Modify Tools"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        raw = ctx.system.boot_args.strip()
        if not raw or raw.lower().startswith("nvram: error"):
            return []

        return [self._make_finding(
            ctx,
            description=(
                f"Non-default boot arguments are set: `{raw}`. "
                "Custom boot args can disable security features such as SIP, KEXT signing, "
                "or enable kernel debugging — all of which weaken the system security posture."
            ),
            recommendation=(
                "Review the boot args value. If not intentionally set by IT, "
                "clear them via `sudo nvram -d boot-args` in Recovery mode. "
                "Common dangerous values: `amfi_get_out_of_my_way=1`, `kext-dev-mode=1`, `cs_enforcement_disable=1`."
            ),
            process="nvram",
        )]
