from __future__ import annotations

import argparse
from pathlib import Path

from netsentry.detectors import run_all_detectors
from netsentry.parsers import load_events
from netsentry.reports import build_summary, write_csv_report, write_json_report, write_text_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NetSentry network anomaly detector")
    parser.add_argument("--input", required=True, help="Path to CSV traffic log")
    parser.add_argument(
        "--input-format",
        choices=["csv", "zeek-conn"],
        default="csv",
        help="Input log format",
    )
    parser.add_argument(
        "--report-format",
        choices=["json", "txt", "csv"],
        default="json",
        help="Output report format",
    )
    parser.add_argument(
        "--output",
        help="Output report path. Defaults to report.json, report.txt, or report.csv in the current directory.",
    )
    parser.add_argument("--spike-threshold", type=int, default=5, help="Minimum connections in a window to flag a spike")
    parser.add_argument("--spike-window", type=int, default=60, help="Spike detection time window in seconds")
    parser.add_argument(
        "--port-threshold",
        type=int,
        default=2,
        help="Minimum hits on an unusual destination port before reporting it",
    )
    parser.add_argument(
        "--talker-threshold",
        type=int,
        default=3,
        help="Minimum connections from a source IP before flagging it as high-volume",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.spike_threshold < 1 or args.spike_window < 1 or args.port_threshold < 1 or args.talker_threshold < 1:
        raise SystemExit("All threshold values must be positive integers.")

    events = load_events(args.input, input_format=args.input_format)
    findings = run_all_detectors(
        events,
        spike_threshold=args.spike_threshold,
        spike_window_seconds=args.spike_window,
        unusual_port_threshold=args.port_threshold,
        talker_threshold=args.talker_threshold,
    )
    summary = build_summary(events, findings, source_path=f"{Path(args.input).resolve()} ({args.input_format})")

    suffix = args.report_format
    output_path = Path(args.output) if args.output else Path(f"report.{suffix}")

    if args.report_format == "json":
        write_json_report(output_path, summary, findings)
    elif args.report_format == "csv":
        write_csv_report(output_path, findings)
    else:
        write_text_report(output_path, summary, findings)

    print(f"Processed {len(events)} events and found {len(findings)} anomalies.")
    print(f"Report written to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
