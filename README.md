# NetSentry

NetSentry is a defensive network traffic anomaly detection and security reporting tool for networking and data security coursework.

## MVP features

- Parse normalized CSV traffic logs
- Detect traffic spikes in short time windows
- Detect repeated use of unusual destination ports
- Flag high-volume source IPs
- Generate JSON, TXT, or CSV security reports
- Tune thresholds directly from the CLI

## Project structure

- `src/main.py`: CLI entry point
- `src/netsentry/parsers.py`: input parsing
- `src/netsentry/detectors.py`: anomaly detection rules
- `src/netsentry/reports.py`: report builders and writers
- `data/samples/sample_traffic.csv`: sample dataset
- `tests/test_pipeline.py`: minimal end-to-end test

## Input format

The MVP expects CSV input with these headers:

```text
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes_sent
```

`timestamp` should be ISO-8601 formatted, for example `2026-03-13T10:00:00`.

## Run locally

```bash
cd /Users/alekhyamysore/Documents/New\ project/NetSentry
PYTHONPATH=src python src/main.py --input data/samples/sample_traffic.csv --report-format json
```

For a text report:

```bash
PYTHONPATH=src python src/main.py --input data/samples/sample_traffic.csv --report-format txt
```

For a CSV findings export with custom thresholds:

```bash
PYTHONPATH=src python src/main.py \
  --input data/samples/sample_traffic.csv \
  --report-format csv \
  --spike-threshold 4 \
  --talker-threshold 4 \
  --port-threshold 2
```

## Test

```bash
cd /Users/alekhyamysore/Documents/New\ project/NetSentry
PYTHONPATH=src pytest
```

## Next improvements

- Add Zeek `conn.log`, `http.log`, and `dns.log` parsers
- Support configurable thresholds from the CLI
- Export CSV reports
- Add charts or a small dashboard
