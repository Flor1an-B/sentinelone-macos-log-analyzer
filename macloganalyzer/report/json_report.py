from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path

from macloganalyzer.models.context import SystemContext
from macloganalyzer.models.finding import Finding
from macloganalyzer.models.event import Event


class _Encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def _event_to_dict(e: Event) -> dict:
    return {
        "source_type": e.source_type,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "process_name": e.process_name,
        "process_path": e.process_path,
        "event_type": e.event_type,
        "behavior_category": e.behavior_category,
        "target_path": e.target_path,
        "group_id": e.group_id,
    }


def _finding_to_dict(f: Finding) -> dict:
    return {
        "rule_id": f.rule_id,
        "rule_name": f.rule_name,
        "severity": f.severity,
        "mitre_id": f.mitre_id,
        "mitre_name": f.mitre_name,
        "description": f.description,
        "recommendation": f.recommendation,
        "process": f.process,
        "first_seen": f.first_seen.isoformat() if f.first_seen else None,
        "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        "evidence_count": len(f.evidence),
        "evidence": [_event_to_dict(e) for e in f.evidence[:20]],
    }


def generate_json(
    ctx: SystemContext,
    findings: list[Finding],
    events: list[Event],
    output_path: Path,
) -> None:
    mr_events = [e for e in events if e.source_type == "match_report"]
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    date_range: dict = {}
    if mr_events:
        sorted_evs = sorted(mr_events, key=lambda e: e.timestamp)
        date_range = {
            "start": sorted_evs[0].timestamp.isoformat(),
            "end": sorted_evs[-1].timestamp.isoformat(),
        }

    payload = {
        "meta": {
            "tool": "sentinelone-macos-log-analyzer",
            "version": "1.2.2",
            "dump_path": ctx.dump_path,
            "dump_date": ctx.parse_stats.get("dump_date"),
            "analysis_date": datetime.utcnow().isoformat() + "Z",
        },
        "system_context": {
            "hostname": ctx.hostname,
            "model": ctx.model,
            "os_version": ctx.os_version,
            "arch": ctx.arch,
            "primary_user": ctx.primary_user,
            "agent_version": ctx.agent_version,
            "agent_uuid": ctx.agent_uuid,
            "console_url": ctx.console_url,
            "sip_enabled": ctx.sip_enabled,
            "boot_args": ctx.boot_args,
            "cpu_count": ctx.cpu_count,
            "installed_apps": ctx.installed_apps,
            "launch_daemons": ctx.launch_daemons,
            "network_interfaces": ctx.network_interfaces,
            "ui_agent_states": ctx.ui_agent_states,
            "sentinelctl_error": ctx.sentinelctl_error,
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_sev,
            "total_events_parsed": len(events),
            "match_report_events": len(mr_events),
            "date_range": date_range,
            "parse_stats": ctx.parse_stats,
        },
        "findings": [_finding_to_dict(f) for f in findings],
        "timeline": [
            _event_to_dict(e)
            for e in sorted(mr_events, key=lambda e: e.timestamp, reverse=True)[:500]
        ],
    }

    output_path.write_text(
        json.dumps(payload, indent=2, cls=_Encoder, ensure_ascii=False),
        encoding="utf-8",
    )
