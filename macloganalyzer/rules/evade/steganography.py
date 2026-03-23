from macloganalyzer.rules.base import BaseRule, AnalysisContext
from macloganalyzer.models.finding import Finding

_STEGO_CATEGORIES = frozenset({
    "steganography",
    "html_smuggling",
    "steganograph",
    "image_steganography",
})

# macOS system processes that legitimately process images — not suspicious for stego
_IMAGE_SYSTEM_PROCS = frozenset({
    "photolibraryd", "mediaanalysisd", "imagecaptureext",
    "com.apple.photos.imageconversionservice", "photoanalysisd",
    "corespotlightd", "mds", "mdworker", "photos",
    "maps", "numbers", "pages", "keynote", "preview",
    "quicklookd", "quicklooksatellite", "qlmanage",
    "iconservicesagent", "iconservicesdaemon", "coreservicesd",
    "storagekitd", "diskimages-helper", "diskimagemounter",
    "desktopserviceshelper", "com.apple.streamingunzipservice.privileged",
    "com.apple.streamingunzipservice", "phone", "facetime",
    "cp", "mv", "ditto", "rsync",
})


class SteganographyRule(BaseRule):
    id = "EVADE-003"
    name = "Steganography / HTML Smuggling Detected"
    severity = "MEDIUM"
    mitre_id = "T1027.003"
    mitre_name = "Steganography"

    def evaluate(self, ctx: AnalysisContext) -> list[Finding]:
        events = [
            e for e in ctx.timeline.events
            if e.source_type == "match_report"
            and any(cat in (e.behavior_category or "").lower() for cat in _STEGO_CATEGORIES)
            and e.process_name.lower() not in _IMAGE_SYSTEM_PROCS
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
                description=(
                    f"{proc} triggered a steganography or HTML smuggling detection "
                    f"({len(proc_events)} event(s)). "
                    "Steganography hides payloads inside images or HTML blobs to evade "
                    "content-based detection and network inspection."
                ),
                recommendation=(
                    "Isolate and inspect files accessed by this process at the time of detection. "
                    "Scan with an offline tool (e.g., stegdetect, binwalk) for hidden payloads. "
                    "Review browser downloads and email attachments around this timestamp."
                ),
                process=proc,
                evidence=proc_events,
            ))

        return findings
