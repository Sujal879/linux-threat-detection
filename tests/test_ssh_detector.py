
import unittest

from src.detectors.ssh_detector import (
    SSHBruteForceDetector,
    load_config,
)


class TestSSHBruteForceDetector(unittest.TestCase):

    def setUp(self):
        self.detector = SSHBruteForceDetector(load_config())

    def make_event(self, source_ip="192.0.2.10"):
        return {
            "event_type": "ssh_failed_login",
            "source_ip": source_ip,
            "username": "testuser",
        }

    def test_low_threshold(self):
        result = None

        for timestamp in range(1000, 1005):
            result = self.detector.process_event(
                self.make_event(),
                now=timestamp,
            )

        self.assertEqual(result["failed_attempts"], 5)
        self.assertEqual(result["severity"], "LOW")

    def test_medium_threshold(self):
        result = None

        for timestamp in range(1000, 1010):
            result = self.detector.process_event(
                self.make_event(),
                now=timestamp,
            )

        self.assertEqual(result["failed_attempts"], 10)
        self.assertEqual(result["severity"], "MEDIUM")

    def test_high_threshold(self):
        result = None

        for timestamp in range(1000, 1015):
            result = self.detector.process_event(
                self.make_event(),
                now=timestamp,
            )

        self.assertEqual(result["failed_attempts"], 15)
        self.assertEqual(result["severity"], "HIGH")

    def test_old_attempts_expire(self):
        for timestamp in range(1000, 1005):
            self.detector.process_event(
                self.make_event(),
                now=timestamp,
            )

        result = self.detector.process_event(
            self.make_event(),
            now=1305,
        )

        self.assertEqual(result["failed_attempts"], 1)
        self.assertEqual(result["severity"], "NORMAL")

    def test_ips_are_tracked_separately(self):
        for timestamp in range(1000, 1005):
            self.detector.process_event(
                self.make_event("192.0.2.10"),
                now=timestamp,
            )

        result = self.detector.process_event(
            self.make_event("192.0.2.20"),
            now=1005,
        )

        self.assertEqual(result["source_ip"], "192.0.2.20")
        self.assertEqual(result["failed_attempts"], 1)
        self.assertEqual(result["severity"], "NORMAL")

    def test_non_failed_event_is_ignored(self):
        event = {
            "event_type": "ssh_auth_success",
            "source_ip": "192.0.2.10",
        }

        result = self.detector.process_event(event, now=1000)

        self.assertIsNone(result)

    def test_missing_source_ip_is_ignored(self):
        event = {
            "event_type": "ssh_failed_login",
            "username": "testuser",
        }

        result = self.detector.process_event(event, now=1000)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()

