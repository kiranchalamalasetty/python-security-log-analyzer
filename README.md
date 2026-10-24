
# Python Security Monitoring & Log Analyzer

A beginner-friendly defensive security project that parses
authentication logs, summarizes login activity, detects repeated
failed-login patterns, and generates text and JSON reports.

## Features

- Parses timestamps, login status, usernames, source IPs, and ports.
- Counts successful and failed login events.
- Tracks failed attempts by source IP.
- Flags IPs with three or more failed attempts.
- Tracks failed SSH login attempts on port 22.
- Generates text and JSON security reports.
- Includes automated unit tests for parsing and detection.

## Technology

- Python 3
- Ubuntu Linux
- Regular expressions
- JSON
- Python unittest

## Project Structure

```text
security-log-analyzer/
├── main.py
├── README.md
├── requirements.txt
├── .gitignore
├── sample_logs/
│   └── auth.log
├── reports/
│   ├── security_report.txt
│   └── security_report.json
└── tests/
    └── test_analyzer.py
```

## Setup

```bash
git clone <YOUR_REPOSITORY_URL>
cd security-log-analyzer
python3 -m venv .venv
source .venv/bin/activate
python main.py
```

The project uses Python standard-library modules, so no
third-party dependencies are required for the current version.

## Run Tests

```bash
python -m unittest discover -s tests -v
```

## Expected Sample Results

The included seven-event training dataset should produce:

- Total events: 7
- Successful logins: 2
- Failed logins: 5
- Unique usernames: 4
- Unique source IPs: 5
- Repeated-failure alert: 192.168.1.50

The detection threshold is three failed attempts across the
entire input file, not a rolling time window.

## Limitations

- The parser supports the included training-log format only.
- Alerts identify patterns for investigation; they do not prove
  malicious activity.
- This is a local educational analyzer, not a real-time SIEM.
- The sample events are fictional.

## Future Improvements

- Support common Linux authentication-log formats.
- Add time-window-based detection.
- Validate timestamps and IP addresses.
- Add configurable input and output paths.
- Analyze exported AWS CloudTrail events in a future extension.
