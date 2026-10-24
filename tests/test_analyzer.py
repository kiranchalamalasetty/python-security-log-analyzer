
import unittest

from main import parse_log_line, analyze_events


class TestSecurityAnalyzer(unittest.TestCase):

    def test_valid_log_line(self):
        line = (
            "2026-10-22 09:00:01 Failed login for user admin "
            "from 192.168.1.50 on port 22"
        )
        event = parse_log_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["username"], "admin")
        self.assertEqual(event["ip"], "192.168.1.50")
        self.assertEqual(event["port"], 22)
        self.assertEqual(event["status"], "Failed")

    def test_invalid_log_line(self):
        self.assertIsNone(parse_log_line("not a valid log entry"))

    def test_detection_threshold(self):
        events = []

        for _ in range(3):
            events.append({
                "timestamp": "2026-10-22 09:00:01",
                "status": "Failed",
                "username": "admin",
                "ip": "192.168.1.50",
                "port": 22,
            })

        report = analyze_events(events)

        self.assertEqual(report["failed_logins"], 3)
        self.assertEqual(len(report["alerts"]), 1)
        self.assertEqual(report["alerts"][0]["ip"], "192.168.1.50")


if __name__ == "__main__":
    unittest.main()

