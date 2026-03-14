from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from .models import TrafficEvent


def build_summary(events: list[TrafficEvent], findings: list[dict], source_path: str | None = None) -> dict:
    protocols = Counter(event.protocol for event in events)
    top_sources = Counter(event.src_ip for event in events).most_common(5)
    top_destinations = Counter(event.dst_ip for event in events).most_common(5)
    severities = Counter(finding["severity"] for finding in findings)
    return {
        "source_path": source_path,
        "total_events": len(events),
        "total_findings": len(findings),
        "protocols": dict(protocols),
        "top_sources": [{"ip": ip, "count": count} for ip, count in top_sources],
        "top_destinations": [{"ip": ip, "count": count} for ip, count in top_destinations],
        "severity_breakdown": dict(severities),
    }


def write_json_report(path: str | Path, summary: dict, findings: list[dict]) -> None:
    payload = {"summary": summary, "findings": findings}
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_text_report(path: str | Path, summary: dict, findings: list[dict]) -> None:
    lines = [
        "NetSentry Security Report",
        "",
        f"Source file: {summary['source_path']}",
        f"Total events: {summary['total_events']}",
        f"Total findings: {summary['total_findings']}",
        f"Protocols: {summary['protocols']}",
        f"Severity breakdown: {summary['severity_breakdown']}",
        "",
        "Findings:",
    ]
    if not findings:
        lines.append("No anomalies detected.")
    else:
        for index, finding in enumerate(findings, start=1):
            lines.append(
                f"{index}. [{finding['severity'].upper()}] {finding['type']}: {finding['reason']}"
            )
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_csv_report(path: str | Path, findings: list[dict]) -> None:
    fieldnames = ["type", "severity", "src_ip", "dst_port", "count", "window_start", "reason"]
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            writer.writerow({name: finding.get(name, "") for name in fieldnames})


def write_summary_csv(path: str | Path, summary: dict) -> None:
    rows = [
        {"metric": "source_path", "value": summary["source_path"]},
        {"metric": "total_events", "value": summary["total_events"]},
        {"metric": "total_findings", "value": summary["total_findings"]},
    ]
    rows.extend(
        {"metric": f"protocol_{protocol}", "value": count}
        for protocol, count in summary["protocols"].items()
    )
    rows.extend(
        {"metric": f"severity_{severity}", "value": count}
        for severity, count in summary["severity_breakdown"].items()
    )

    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "value"])
        writer.writeheader()
        writer.writerows(rows)


def format_console_summary(summary: dict, findings: list[dict]) -> str:
    lines = [
        "NetSentry Summary",
        f"Source: {summary['source_path']}",
        f"Events: {summary['total_events']}",
        f"Findings: {summary['total_findings']}",
        f"Severity breakdown: {summary['severity_breakdown'] or 'none'}",
    ]
    if findings:
        lines.append("Top findings:")
        for finding in findings[:3]:
            lines.append(f"- [{finding['severity'].upper()}] {finding['reason']}")
    return "\n".join(lines)
