import csv
import json
import subprocess
import sys
from pathlib import Path

import detector


SAMPLE_LINES = [
    "2026-03-09T09:00:01Z auth failed user=admin ip=185.23.10.2",
    "2026-03-09T09:01:00Z auth failed user=admin ip=185.23.10.2",
    "2026-03-09T09:02:10Z auth failed user=admin ip=185.23.10.2",
    "2026-03-09T09:03:20Z auth failed user=admin ip=185.23.10.2",
    "2026-03-09T09:04:30Z auth failed user=admin ip=185.23.10.2",
    "2026-03-09T09:07:00Z auth success user=alice ip=196.11.2.5",
    "2026-03-09T09:09:10Z auth failed user=root ip=10.0.0.5",
]


def write_log(tmp_path: Path, lines: list[str]) -> Path:
    log_path = tmp_path / "auth.log"
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return log_path


def test_detect_matches_documented_sample(tmp_path):
    log_path = write_log(tmp_path, SAMPLE_LINES)

    alerts = detector.detect(str(log_path), threshold=5, window_minutes=10)

    assert alerts == [
        {
            "type": "possible_bruteforce",
            "ip": "185.23.10.2",
            "count": 5,
            "window_minutes": 10,
            "first_seen": "2026-03-09T09:00:01+00:00",
            "last_seen": "2026-03-09T09:04:30+00:00",
        }
    ]


def test_success_events_do_not_increment_failed_attempt_count(tmp_path):
    log_path = write_log(
        tmp_path,
        [
            "2026-03-09T09:00:00Z auth failed user=admin ip=198.51.100.9",
            "2026-03-09T09:01:00Z auth success user=admin ip=198.51.100.9",
            "2026-03-09T09:02:00Z auth failed user=admin ip=198.51.100.9",
        ],
    )

    assert detector.detect(str(log_path), threshold=3, window_minutes=10) == []


def test_window_boundary_counts_failures_at_exact_cutoff(tmp_path):
    log_path = write_log(
        tmp_path,
        [
            "2026-03-09T09:00:00Z auth failed user=admin ip=203.0.113.5",
            "2026-03-09T09:05:00Z auth failed user=root ip=203.0.113.5",
            "2026-03-09T09:10:00Z auth failed user=guest ip=203.0.113.5",
        ],
    )

    alerts = detector.detect(str(log_path), threshold=3, window_minutes=10)

    assert len(alerts) == 1
    assert alerts[0]["count"] == 3
    assert alerts[0]["first_seen"] == "2026-03-09T09:00:00+00:00"
    assert alerts[0]["last_seen"] == "2026-03-09T09:10:00+00:00"


def test_old_failures_roll_outside_window(tmp_path):
    log_path = write_log(
        tmp_path,
        [
            "2026-03-09T09:00:00Z auth failed user=admin ip=203.0.113.7",
            "2026-03-09T09:11:00Z auth failed user=root ip=203.0.113.7",
            "2026-03-09T09:12:00Z auth failed user=guest ip=203.0.113.7",
        ],
    )

    assert detector.detect(str(log_path), threshold=3, window_minutes=10) == []


def test_ignores_malformed_lines_and_sorts_unsorted_events(tmp_path):
    log_path = write_log(
        tmp_path,
        [
            "not an auth event",
            "2026-03-09T09:02:00Z auth failed user=admin ip=192.0.2.4",
            "2026-03-09T09:00:00Z auth failed user=root ip=192.0.2.4",
            "2026-03-09T09:01:00Z auth failed user=guest ip=192.0.2.4",
        ],
    )

    alerts = detector.detect(str(log_path), threshold=3, window_minutes=10)

    assert len(alerts) == 1
    assert alerts[0]["first_seen"] == "2026-03-09T09:00:00+00:00"
    assert alerts[0]["last_seen"] == "2026-03-09T09:02:00+00:00"


def test_cli_writes_json_and_csv_outputs(tmp_path):
    log_path = write_log(tmp_path, SAMPLE_LINES)
    json_path = tmp_path / "alerts.json"
    csv_path = tmp_path / "alerts.csv"

    result = subprocess.run(
        [
            sys.executable,
            "detector.py",
            "--log",
            str(log_path),
            "--threshold",
            "5",
            "--window",
            "10",
            "--json-out",
            str(json_path),
            "--csv-out",
            str(csv_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "Detected 1 alert(s):" in result.stdout
    assert "possible_bruteforce ip=185.23.10.2 count=5 window=10m" in result.stdout

    json_alerts = json.loads(json_path.read_text(encoding="utf-8"))
    assert json_alerts[0]["ip"] == "185.23.10.2"

    with csv_path.open(newline="", encoding="utf-8") as csv_file:
        rows = list(csv.DictReader(csv_file))
    assert rows == [
        {
            "type": "possible_bruteforce",
            "ip": "185.23.10.2",
            "count": "5",
            "window_minutes": "10",
            "first_seen": "2026-03-09T09:00:01+00:00",
            "last_seen": "2026-03-09T09:04:30+00:00",
        }
    ]
