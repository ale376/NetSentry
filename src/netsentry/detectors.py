from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from .models import TrafficEvent

COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 587, 993, 995, 3306, 3389}


def detect_spikes(events: list[TrafficEvent], window_seconds: int = 60, threshold: int = 5) -> list[dict]:
    windows: dict[tuple[str, object], int] = defaultdict(int)
    findings: list[dict] = []
    for event in events:
        bucket = event.timestamp - timedelta(
            seconds=event.timestamp.second % window_seconds,
            microseconds=event.timestamp.microsecond,
        )
        windows[(event.src_ip, bucket)] += 1

    for (src_ip, bucket), count in windows.items():
        if count >= threshold:
            findings.append(
                {
                    "type": "traffic_spike",
                    "severity": "medium",
                    "src_ip": src_ip,
                    "window_start": bucket.isoformat(),
                    "count": count,
                    "reason": f"{count} connections from {src_ip} in {window_seconds}s window",
                }
            )
    return findings


def detect_unusual_ports(events: list[TrafficEvent]) -> list[dict]:
    port_counts = Counter(event.dst_port for event in events if event.dst_port)
    findings: list[dict] = []
    for port, count in port_counts.items():
        if port not in COMMON_PORTS and count >= 2:
            findings.append(
                {
                    "type": "unusual_port_usage",
                    "severity": "high" if count >= 4 else "medium",
                    "dst_port": port,
                    "count": count,
                    "reason": f"Port {port} is uncommon in baseline and appeared {count} times",
                }
            )
    return findings


def detect_top_talkers(events: list[TrafficEvent], threshold: int = 3) -> list[dict]:
    src_counts = Counter(event.src_ip for event in events)
    findings: list[dict] = []
    for src_ip, count in src_counts.items():
        if count >= threshold:
            findings.append(
                {
                    "type": "high_volume_source",
                    "severity": "medium",
                    "src_ip": src_ip,
                    "count": count,
                    "reason": f"{src_ip} initiated {count} connections",
                }
            )
    return findings


def run_all_detectors(
    events: list[TrafficEvent],
    spike_threshold: int = 5,
    spike_window_seconds: int = 60,
    unusual_port_threshold: int = 2,
    talker_threshold: int = 3,
) -> list[dict]:
    findings: list[dict] = []
    findings.extend(
        detect_spikes(
            events,
            window_seconds=spike_window_seconds,
            threshold=spike_threshold,
        )
    )
    findings.extend(detect_unusual_ports(events))
    findings.extend(detect_top_talkers(events, threshold=talker_threshold))
    filtered_findings = [
        finding
        for finding in findings
        if finding["type"] != "unusual_port_usage" or finding["count"] >= unusual_port_threshold
    ]
    return sorted(filtered_findings, key=lambda finding: (finding["severity"], finding["type"], finding["reason"]))
