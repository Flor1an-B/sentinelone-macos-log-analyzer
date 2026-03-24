# Changelog

## [1.2.3] — 2026-03-24

### Fixed
- **Architecture detection — `x86_64` always reported as `Unknown`** — dump directories contain an empty file named `x86_64` (or `arm64`) to signal the machine architecture, but only `arm64` and `arm64e` were handled; `x86_64` had no matching branch and fell through silently. Added the missing case so Intel machines are now correctly identified.

---

## [1.2.2] — 2026-03-23

### Fixed
- **Statistics — Event Timeline chart not updating on period change** — chart used monthly buckets (`%Y-%m`) regardless of period; when all dumps fall in the same calendar month, all periods produced an identical single-bar chart. Chart now uses **daily granularity** when the data spans ≤ 60 distinct days (adapts to monthly beyond that). Switching between 24h / 7 days / 30 days / All now shows visibly different distributions

---

## [1.2.1] — 2026-03-23

### Fixed
- **Statistics — Event Timeline chart blank** — two root causes: (1) JS condition `entries.length >= 2` prevented rendering when all events fell in a single calendar month; (2) `_stats_section` is rendered once per period (4 copies in DOM) each with `id="events-area-chart"` / `id="activity-heatmap"` — `getElementById` only found the first, leaving the visible period empty. Both charts now rendered entirely in Python (`_render_area_chart_svg`, `_render_heatmap_html`) with unique SVG gradient IDs per period — no JS dependency, no ID collisions

---

## [1.2.0] — 2026-03-23

### Added
- **Self-updater** — `macloganalyzer --update` checks the latest GitHub release, computes git blob SHA1 checksums to identify changed files, and downloads only the diff. Each file is integrity-verified before being written to disk. Features a styled banner (name, author, GitHub URL, current version), a change table (added / modified / removed), a confirmation prompt, and a per-file progress bar.

---

## [1.1.0] — 2026-03-23

### Fixed
- **Agent health scoring** — `Lib Hooks Service` and `Lib Logs Service` (deprecated, no longer used by the agent) no longer trigger a DEGRADED score
- **Agent health scoring** — `sentineld_shell: not running` correctly treated as on-demand (activates only during remote shell sessions); no longer causes DEGRADED
- **Missing Authorizations false positive** — parser bug where sibling Agent keys (e.g. `ES Framework: started`) were mistakenly parsed as missing authorization entries due to shared indentation level with the `Missing Authorizations` header
- **Application name parsing** — multi-word app names (e.g. `Boom 3D`, `Brave Browser`, `Google Chrome`, `NTFS for Mac`) were truncated to their last word; now correctly reconstructed from `ls -la` output
- **Boot Args display** — nvram error message on Apple Silicon (`nvram: Error getting variable - 'boot-args': (iokit/common) data was not found`) now normalized to `(none)` — expected behavior when no custom boot args are set
- **Asset signatures** — `empty asset` status on optional assets (`blacklist`, `whitelist`, `certExclusion`, `scopeDetails`) no longer triggers a warning; displayed as "NOT CONFIGURED" (gray) rather than being counted as corrupted
- **Dark mode** — multiple elements with hardcoded light backgrounds (`#f0f4f8`) were invisible in dark mode: `data-table td code`, `timeline-table td.cat code`, `.finding-proc`, `.top-item-id`, `.app-tag`, `.ioc-item:hover`, DNS server tags, DV disabled tags
- **Sidebar navigation** — active link indicator would get stuck on a previous selection; replaced single-entry `IntersectionObserver` with a Set-based tracker that always selects the section closest to the viewport top; click events now apply active state immediately with an 800 ms lock to prevent observer override during smooth scroll

### Changed
- **Report UI** — `Lib Hooks Service` and `Lib Logs Service` removed entirely from the Services and Daemon States sections (deprecated services add no analytical value)
- **Asset signatures** — warning banner now reads "N invalid" (invalid only) instead of "N invalid/empty" — empty optional assets excluded from the count
- **Process Integrity table** — `sentineld_shell` displayed with a neutral gray badge and tooltip instead of a red `NOT RUNNING` badge
- **ATS section removed** — `curl_ns_ats.txt` parsing and the "ATS Network Connectivity Tests" section have been removed from all report formats (HTML, Markdown) and from operational alerts. The test target (`test-the-catchall.sentinelone.net`) does not resolve (NXDOMAIN), making all test results meaningless noise

### Added
- **Application tooltips** — hovering an installed application now shows: install type (system vs user), owner, last modified date, and group — sourced from `Applications.txt` `ls -la` metadata
- **Installed apps metadata** — new `installed_apps_meta: dict[str, dict]` field in `SystemContext`
- **Sidebar branding** — developer name and version now visible in the sidebar (`by Florian Bertaux · v1.1.0`)
- **Tooltip multi-line support** — `.tooltip-bubble` now uses `white-space: pre-line` to render line breaks in tooltip content

---

## [1.0.0] — 2026-03-19

Initial release.
