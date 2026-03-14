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

