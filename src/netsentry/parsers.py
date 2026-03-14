from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from .models import TrafficEvent


def _parse_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_timestamp(value: str) -> datetime:
    # Expect ISO timestamps in the MVP sample files.
    return datetime.fromisoformat(value)


def load_csv_events(path: str | Path) -> list[TrafficEvent]:
    events: list[TrafficEvent] = []
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            events.append(
                TrafficEvent(
                    timestamp=_parse_timestamp(row["timestamp"]),
                    src_ip=row["src_ip"],
                    dst_ip=row["dst_ip"],
                    src_port=_parse_int(row.get("src_port")),
                    dst_port=_parse_int(row.get("dst_port")),
                    protocol=row.get("protocol", "UNKNOWN").upper(),
                    bytes_sent=_parse_int(row.get("bytes_sent")),
                )
            )
    return events


def load_zeek_conn_events(path: str | Path) -> list[TrafficEvent]:
    events: list[TrafficEvent] = []
    fields: list[str] = []

    with Path(path).open(encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue

            values = line.split("\t")
            row = dict(zip(fields, values))
            timestamp = datetime.fromtimestamp(float(row["ts"]))
            events.append(
                TrafficEvent(
                    timestamp=timestamp,
                    src_ip=row["id.orig_h"],
                    dst_ip=row["id.resp_h"],
                    src_port=_parse_int(row.get("id.orig_p")),
                    dst_port=_parse_int(row.get("id.resp_p")),
                    protocol=row.get("proto", "UNKNOWN").upper(),
                    bytes_sent=_parse_int(row.get("orig_bytes")),
                )
            )

    return events


def load_events(path: str | Path, input_format: str) -> list[TrafficEvent]:
    if input_format == "csv":
        return load_csv_events(path)
    if input_format == "zeek-conn":
        return load_zeek_conn_events(path)
    raise ValueError(f"Unsupported input format: {input_format}")
