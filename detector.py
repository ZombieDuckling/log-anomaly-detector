#!/usr/bin/env python3
import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta

# Example line:
# 2026-03-09T09:15:01Z auth failed user=admin ip=192.168.1.10
LOG_RE = re.compile(
    r"(?P<ts>\S+)\s+auth\s+(?P<status>failed|success)\s+user=(?P<user>\S+)\s+ip=(?P<ip>\S+)"
)


def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def detect(log_path: str, threshold: int, window_minutes: int):
    events = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            m = LOG_RE.search(line.strip())
            if not m:
                continue
            events.append(
                {
                    "ts": parse_ts(m.group("ts")),
                    "status": m.group("status"),
                    "user": m.group("user"),
                    "ip": m.group("ip"),
                }
            )

    events.sort(key=lambda x: x["ts"])
    by_ip = defaultdict(list)

    alerts = []
    window = timedelta(minutes=window_minutes)

    for e in events:
        if e["status"] != "failed":
            continue
        ip = e["ip"]
        by_ip[ip].append(e["ts"])

        # keep only timestamps in rolling window
        cutoff = e["ts"] - window
        by_ip[ip] = [t for t in by_ip[ip] if t >= cutoff]

        if len(by_ip[ip]) >= threshold:
            alerts.append(
                {
                    "type": "possible_bruteforce",
                    "ip": ip,
                    "count": len(by_ip[ip]),
                    "window_minutes": window_minutes,
                    "first_seen": by_ip[ip][0].isoformat(),
                    "last_seen": by_ip[ip][-1].isoformat(),
                }
            )
            by_ip[ip].clear()  # prevent duplicate noisy alerts

    return alerts


def main():
    p = argparse.ArgumentParser(description="Basic auth log anomaly detector")
    p.add_argument("--log", required=True, help="Path to auth log file")
    p.add_argument("--threshold", type=int, default=5, help="Failed attempts before alert")
    p.add_argument("--window", type=int, default=10, help="Rolling window in minutes")
    p.add_argument("--json-out", help="Write alerts to JSON")
    p.add_argument("--csv-out", help="Write alerts to CSV")
    args = p.parse_args()

    alerts = detect(args.log, args.threshold, args.window)

    if not alerts:
        print("No anomalies detected.")
    else:
        print(f"Detected {len(alerts)} alert(s):")
        for a in alerts:
            print(
                f"- {a['type']} ip={a['ip']} count={a['count']} "
                f"window={a['window_minutes']}m"
            )

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as jf:
            json.dump(alerts, jf, indent=2)

    if args.csv_out:
        with open(args.csv_out, "w", newline="", encoding="utf-8") as cf:
            w = csv.DictWriter(cf, fieldnames=["type", "ip", "count", "window_minutes", "first_seen", "last_seen"])
            w.writeheader()
            for a in alerts:
                w.writerow(a)


if __name__ == "__main__":
    main()
