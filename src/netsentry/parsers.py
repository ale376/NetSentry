from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
import re

from .models import TrafficEvent

WIRESHARK_PORT_PATTERN = re.compile(r"^\s*(\d+)\s+>\s+(\d+)\b")


def _parse_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_timestamp(value: str) -> datetime:
    # Python 3.10 only supports up to 6 fractional second digits.
    normalized = value.strip()
    if "." in normalized:
        head, tail = normalized.split(".", 1)
        fractional = "".join(ch for ch in tail if ch.isdigit())
        suffix = tail[len(fractional) :]
        normalized = f"{head}.{fractional[:6]}{suffix}"
    return datetime.fromisoformat(normalized)


def _parse_ports_from_info(value: str) -> tuple[int, int]:
    match = WIRESHARK_PORT_PATTERN.match(value or "")
    if not match:
        return 0, 0
    return int(match.group(1)), int(match.group(2))


def _build_event_from_netsentry_row(row: dict[str, str]) -> TrafficEvent:
    return TrafficEvent(
        timestamp=_parse_timestamp(row["timestamp"]),
        src_ip=row["src_ip"],
        dst_ip=row["dst_ip"],
        src_port=_parse_int(row.get("src_port")),
        dst_port=_parse_int(row.get("dst_port")),
        protocol=row.get("protocol", "UNKNOWN").upper(),
        bytes_sent=_parse_int(row.get("bytes_sent")),
    )


def _build_event_from_wireshark_row(row: dict[str, str]) -> TrafficEvent:
    src_port, dst_port = _parse_ports_from_info(row.get("Info", ""))
    return TrafficEvent(
        timestamp=_parse_timestamp(row["Time"].replace(" ", "T", 1)),
        src_ip=row["Source"],
        dst_ip=row["Destination"],
        src_port=src_port,
        dst_port=dst_port,
        protocol=row.get("Protocol", "UNKNOWN").upper(),
        bytes_sent=_parse_int(row.get("Length")),
    )


def load_csv_events(path: str | Path) -> list[TrafficEvent]:
    events: list[TrafficEvent] = []
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = set(reader.fieldnames or [])
        if {"timestamp", "src_ip", "dst_ip", "protocol", "bytes_sent"}.issubset(fieldnames):
            row_builder = _build_event_from_netsentry_row
        elif {"Time", "Source", "Destination", "Protocol", "Length", "Info"}.issubset(fieldnames):
            row_builder = _build_event_from_wireshark_row
        else:
            raise ValueError(
                "Unsupported CSV format. Expected NetSentry columns "
                "(timestamp, src_ip, dst_ip, src_port, dst_port, protocol, bytes_sent) "
                "or Wireshark export columns (Time, Source, Destination, Protocol, Length, Info)."
            )
        for row in reader:
            events.append(row_builder(row))
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
