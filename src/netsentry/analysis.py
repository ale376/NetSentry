from __future__ import annotations

from pathlib import Path

from .detectors import run_all_detectors
from .parsers import load_events
from .reports import build_summary


def analyze_file(
    input_path: str | Path,
    input_format: str = "csv",
    spike_threshold: int = 5,
    spike_window_seconds: int = 60,
    unusual_port_threshold: int = 2,
    talker_threshold: int = 3,
) -> tuple[list, list[dict], dict]:
    events = load_events(input_path, input_format=input_format)
    findings = run_all_detectors(
        events,
        spike_threshold=spike_threshold,
        spike_window_seconds=spike_window_seconds,
        unusual_port_threshold=unusual_port_threshold,
        talker_threshold=talker_threshold,
    )
    summary = build_summary(events, findings, source_path=f"{Path(input_path).resolve()} ({input_format})")
    return events, findings, summary
