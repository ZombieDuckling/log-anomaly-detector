# Log anomaly detector

A beginner-friendly **blue team portfolio project** that parses authentication
logs and raises alerts for brute-force-like behavior in a rolling time window.

## Portfolio summary

This project shows that you can:

- parse and normalize security-relevant telemetry,
- implement threshold-based detections,
- produce simple SOC-friendly alert artifacts.

### MITRE ATT&CK mapping (high level)

- **T1110: Brute Force**

## Features

The detector reads auth events and alerts when failed logins from the same IP
exceed a threshold in a defined time window.

- parses simple auth log format,
- tracks failed attempts by source IP,
- exports findings to JSON and CSV.

## Project structure

```text
.
├── detector.py
├── sample_auth.log
└── README.md
```

## Quick start

Use Python 3.10+.

```bash
python3 detector.py --log sample_auth.log --threshold 5 --window 10
```

Export alert files:

```bash
python3 detector.py --log sample_auth.log --json-out alerts.json --csv-out alerts.csv
```

## Sample output

```text
Detected 1 alert(s):
- possible_bruteforce ip=185.23.10.2 count=5 window=10m
```

## Log format

Expected line format:

```text
2026-03-09T09:15:01Z auth failed user=admin ip=192.168.1.10
```

## What I learned

- Good detections start with clean parsing and clear assumptions.
- Rolling windows reduce noise versus static counters.
- Alert context (count, first seen, last seen) helps triage speed.

## Roadmap

- Add user-account anomaly checks.
- Add allowlist/suppressions for noisy internal scanners.
- Add geolocation enrichment and severity scoring.
- Add Sigma-style rule export.
