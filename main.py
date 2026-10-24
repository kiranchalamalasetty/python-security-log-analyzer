
import json
import re
from pathlib import Path
from collections import Counter

LOG_FILE = Path("sample_logs/auth.log")
REPORT_DIR = Path("reports")
TEXT_REPORT = REPORT_DIR / "security_report.txt"
JSON_REPORT = REPORT_DIR / "security_report.json"

FAILED_LOGIN_THRESHOLD = 3

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"(?P<status>Failed|Successful) login "
    r"for user (?P<username>\S+) "
    r"from (?P<ip>\S+) "
    r"on port (?P<port>\d+)$"
)


def parse_log_line(line):
    """Extract fields from one training log line."""
    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    record = match.groupdict()
    record["port"] = int(record["port"])
    return record


def analyze_events(events):
    """Summarize events and identify repeated failed logins."""
    status_counts = Counter()
    failed_by_ip = Counter()
    failed_ssh_by_ip = Counter()
    users = set()
    ips = set()

    for event in events:
        status_counts[event["status"]] += 1
        users.add(event["username"])
        ips.add(event["ip"])

        if event["status"] == "Failed":
            failed_by_ip[event["ip"]] += 1

            if event["port"] == 22:
                failed_ssh_by_ip[event["ip"]] += 1

    alerts = []

    for ip, count in failed_by_ip.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "ip": ip,
                "failed_attempts": count,
                "severity": "HIGH",
                "reason": f"{count} failed login attempts from {ip}",
            })

    return {
        "total_events": len(events),
        "successful_logins": status_counts["Successful"],
        "failed_logins": status_counts["Failed"],
        "unique_users": len(users),
        "unique_ips": len(ips),
        "invalid_lines": 0,
        "failed_by_ip": dict(failed_by_ip),
        "failed_ssh_by_ip": dict(failed_ssh_by_ip),
        "alerts": alerts,
    }


def write_reports(report):
    """Save the same analysis as readable text and JSON."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    text_lines = [
        "SECURITY MONITORING REPORT",
        "==========================",
        f"Total events: {report['total_events']}",
        f"Successful logins: {report['successful_logins']}",
        f"Failed logins: {report['failed_logins']}",
        f"Unique users: {report['unique_users']}",
        f"Unique IP addresses: {report['unique_ips']}",
        f"Invalid lines: {report['invalid_lines']}",
        "",
        "FAILED LOGINS BY IP",
    ]

    for ip, count in report["failed_by_ip"].items():
        text_lines.append(f"{ip}: {count}")

    text_lines.append("")
    text_lines.append("FAILED SSH LOGINS BY IP")

    for ip, count in report["failed_ssh_by_ip"].items():
        text_lines.append(f"{ip}: {count}")

    text_lines.extend(["", "ALERTS"])

    if not report["alerts"]:
        text_lines.append("No IPs met the alert threshold.")
    else:
        for alert in report["alerts"]:
            text_lines.append(
                f"[{alert['severity']}] {alert['reason']}"
            )

    TEXT_REPORT.write_text(
        "\n".join(text_lines) + "\n",
        encoding="utf-8",
    )

    JSON_REPORT.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )


def main():
    if not LOG_FILE.is_file():
        print(f"Error: log file not found: {LOG_FILE}")
        return

    events = []
    invalid_lines = 0

    with LOG_FILE.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            if not line.strip():
                continue

            event = parse_log_line(line)

            if event is None:
                invalid_lines += 1
                print(f"[WARNING] Could not parse line {line_number}")
                continue

            events.append(event)

    report = analyze_events(events)
    report["invalid_lines"] = invalid_lines
    write_reports(report)

    print("\n=== SECURITY LOG SUMMARY ===")
    print(f"Total events:        {report['total_events']}")
    print(f"Successful logins:   {report['successful_logins']}")
    print(f"Failed logins:       {report['failed_logins']}")
    print(f"Unique users:        {report['unique_users']}")
    print(f"Unique IP addresses: {report['unique_ips']}")
    print(f"Invalid lines:       {report['invalid_lines']}")

    print("\n=== ALERTS ===")
    if not report["alerts"]:
        print("No IPs met the alert threshold.")
    else:
        for alert in report["alerts"]:
            print(f"[{alert['severity']}] {alert['reason']}")

    print("\nReports saved:")
    print(f"- {TEXT_REPORT}")
    print(f"- {JSON_REPORT}")


if __name__ == "__main__":
    main()
