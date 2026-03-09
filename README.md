# Log anomaly detector

This project is a beginner-friendly blue team portfolio project. It parses
authentication logs and alerts on possible brute-force behavior.

## What this project does

This script reads log lines, tracks failed authentication attempts by IP,
and raises an alert when failures exceed a threshold in a rolling time window.

- Parses simple auth log lines.
- Detects brute-force-like bursts.
- Exports alerts to JSON or CSV.

## Run it

Use the sample log to test quickly:

```bash
python3 detector.py --log sample_auth.log --threshold 5 --window 10
```

To export alerts:

```bash
python3 detector.py --log sample_auth.log --json-out alerts.json --csv-out alerts.csv
```

## Log format

Expected format per line:

```text
2026-03-09T09:15:01Z auth failed user=admin ip=192.168.1.10
```

## Next steps

You can extend this project by:

- Tracking user-level anomalies.
- Adding geolocation enrichment.
- Mapping alerts to MITRE ATT&CK techniques.
