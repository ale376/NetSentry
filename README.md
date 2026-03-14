# NetSentry

NetSentry is a defensive network traffic anomaly detection and security reporting tool.

## Planned scope

- Parse Wireshark/tshark CSV exports and Zeek logs
- Detect suspicious patterns and traffic anomalies
- Generate TXT, JSON, and CSV reports
- Provide a simple CLI-first workflow

## Initial structure

- `src/` for application code
- `tests/` for test coverage
- `data/samples/` for sample inputs

## Next steps

1. Build the CLI entry point
2. Add log parsers
3. Implement anomaly detectors
4. Generate structured reports
