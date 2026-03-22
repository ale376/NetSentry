from pathlib import Path

from netsentry.detectors import run_all_detectors
from netsentry.parsers import load_csv_events, load_events
from netsentry.reports import build_summary


def test_pipeline_detects_anomalies() -> None:
    sample_path = Path(__file__).resolve().parents[1] / "data" / "samples" / "sample_traffic.csv"
    events = load_csv_events(sample_path)
    findings = run_all_detectors(events)
    summary = build_summary(events, findings, source_path=str(sample_path))

    assert len(events) == 8
    assert summary["total_events"] == 8
    assert summary["total_findings"] == len(findings)
    assert any(finding["type"] == "unusual_port_usage" for finding in findings)
    assert any(finding["type"] == "traffic_spike" for finding in findings)


def test_thresholds_can_suppress_findings() -> None:
    sample_path = Path(__file__).resolve().parents[1] / "data" / "samples" / "sample_traffic.csv"
    events = load_csv_events(sample_path)
    findings = run_all_detectors(
        events,
        spike_threshold=10,
        unusual_port_threshold=10,
        talker_threshold=10,
    )

    assert findings == []


def test_zeek_conn_log_can_be_loaded() -> None:
    sample_path = Path(__file__).resolve().parents[1] / "data" / "samples" / "sample_conn.log"
    events = load_events(sample_path, input_format="zeek-conn")

    assert len(events) == 6
    assert events[0].protocol == "UDP"
    assert events[1].src_ip == "10.0.0.5"


def test_raw_wireshark_csv_can_be_loaded() -> None:
    sample_path = Path(__file__).resolve().parents[1] / "data" / "samples" / "traffic_export_converted.csv"
    events = load_csv_events(sample_path)

    assert len(events) > 100
    assert events[0].protocol in {"NTP", "TCP", "ARP", "MDNS", "DNS", "TLSV1.3", "TLSV1.2", "ICMPV6"}
