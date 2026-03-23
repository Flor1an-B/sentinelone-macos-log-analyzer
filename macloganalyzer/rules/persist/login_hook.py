from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding


class LoginHookRule(BaseRule):
    id = "PERSIST-001"
    name = "Login Hook Creation"
    severity = "HIGH"
    mitre_id = "T1547.011"
    mitre_name = "Plist Modification"
    description = "Modification of loginwindow.plist detected — persistence mechanism via login hook."

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.behavior_category in ("preferences_modification", "plist_file_modification")
            and e.target_path and "loginwindow" in e.target_path.lower()
            and e.source_type == "match_report"
        ]

        if not events:
            return []

        by_process: dict[str, list] = {}
        for e in events:
            by_process.setdefault(e.process_name, []).append(e)

        findings: list[Finding] = []
        for proc, proc_events in by_process.items():
            findings.append(self._make_finding(
                ctx,
                description=f"{proc} modified loginwindow.plist. Check LoginHook and LogoutHook keys.",
                recommendation=(
                    "Inspect /Library/Preferences/com.apple.loginwindow.plist. "
                    "The LoginHook and LogoutHook keys allow script execution at login."
                ),
                process=proc,
                evidence=proc_events,
            ))

        return findings
