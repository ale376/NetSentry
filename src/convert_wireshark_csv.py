from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


PORT_PATTERN = re.compile(r"^\s*(\d+)\s+>\s+(\d+)\b")


def parse_ports(info: str) -> tuple[int, int]:
    match = PORT_PATTERN.match(info or "")
    if not match:
        return 0, 0
    return int(match.group(1)), int(match.group(2))


def normalize_timestamp(value: str) -> str:
    # Wireshark CSV exports already use an ISO-like format that Python can parse.
    return value.strip().replace(" ", "T", 1)


def convert_wireshark_csv(input_path: str | Path, output_path: str | Path) -> int:
    rows_written = 0
    with Path(input_path).open(newline="", encoding="utf-8") as src_handle:
        reader = csv.DictReader(src_handle)
        with Path(output_path).open("w", newline="", encoding="utf-8") as dst_handle:
            fieldnames = [
                "timestamp",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "bytes_sent",
            ]
            writer = csv.DictWriter(dst_handle, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:
                src_port, dst_port = parse_ports(row.get("Info", ""))
                writer.writerow(
                    {
                        "timestamp": normalize_timestamp(row["Time"]),
                        "src_ip": row["Source"],
                        "dst_ip": row["Destination"],
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": row["Protocol"].upper(),
                        "bytes_sent": row["Length"],
                    }
                )
                rows_written += 1
    return rows_written


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Convert Wireshark CSV export into NetSentry CSV format")
    parser.add_argument("--input", required=True, help="Path to Wireshark CSV export")
    parser.add_argument("--output", required=True, help="Path to write NetSentry-formatted CSV")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    row_count = convert_wireshark_csv(args.input, args.output)
    print(f"Wrote {row_count} rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
