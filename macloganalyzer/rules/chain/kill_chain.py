from __future__ import annotations
from datetime import timedelta

from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding
from macloganalyzer.config import RECON_CATEGORIES, PERSIST_CATEGORIES

WINDOW = timedelta(hours=1)

# System binaries that routinely perform discovery + service operations —
# exclude them to avoid overwhelming false positives from the kill chain rule.
SYSTEM_PROCESS_PREFIXES = (
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
    "/System/", "/usr/libexec/",
)
SYSTEM_PROCESS_NAMES = frozenset({
    "launchctl", "bash", "zsh", "sh", "fish",
    "ifconfig", "netstat", "ps", "id", "uname",
    "security", "dscl", "diskutil", "lsof", "top",
    "sysctl", "sw_vers", "system_profiler",
    "cfprefsd", "nsurlsessiond", "trustd",
})


class KillChainRule(BaseRule):
    id = "CHAIN-001"
    name = "Complete Kill Chain Detected"
    severity = "CRITICAL"
    mitre_id = "TA0002"
    mitre_name = "Execution → Discovery → Persistence"
    description = (
        "A primary process chained reconnaissance AND persistence behaviors "
        "within a 1-hour window."
    )

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        seen_primaries: set[str] = set()

        # Group events by primary process
        primary_events: dict[str, list] = {}
        for event in ctx.timeline.events:
            if event.source_type != "match_report":
                continue
            primary = event.extra.get("primary") or event.process_path
            if primary:
                primary_events.setdefault(primary, []).append(event)

        for primary, events in primary_events.items():
            if primary in seen_primaries:
                continue

            # Skip known macOS system utilities (high false-positive rate)
            primary_name = events[0].process_name if events else ""
            if primary_name.lower() in SYSTEM_PROCESS_NAMES:
                continue
            if any(primary.startswith(p) for p in SYSTEM_PROCESS_PREFIXES):
                continue

            events_sorted = sorted(events, key=lambda e: e.timestamp)

            for i, start_event in enumerate(events_sorted):
                window_end = start_event.timestamp + WINDOW
                window_events = [
                    e for e in events_sorted[i:]
                    if e.timestamp <= window_end
                ]

                window_cats = {
                    e.behavior_category
                    for e in window_events
                    if e.behavior_category
                }
                recon_hits = window_cats & RECON_CATEGORIES
                persist_hits = window_cats & PERSIST_CATEGORIES

                if recon_hits and persist_hits:
                    seen_primaries.add(primary)
                    process_name = events[0].process_name

                    findings.append(self._make_finding(
                        ctx,
                        description=(
                            f"Kill chain detected for {process_name}:\n"
                            f"  • Reconnaissance ({len(recon_hits)}): "
                            f"{', '.join(sorted(recon_hits))}\n"
                            f"  • Persistence ({len(persist_hits)}): "
                            f"{', '.join(sorted(persist_hits))}\n"
                            f"  • Start: "
                            f"{start_event.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC"
                        ),
                        recommendation=(
                            "Immediately investigate this process. "
                            "Verify parent processes, binary provenance, "
                            "and associated network connections. "
                            "Consider machine isolation if behavior is confirmed."
                        ),
                        process=process_name,
                        evidence=window_events[:30],
                    ))
                    break

        return findings
