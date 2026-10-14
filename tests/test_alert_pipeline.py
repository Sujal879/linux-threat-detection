
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.detectors.ssh_detector import (
    SSHBruteForceDetector,
    load_config,
)
from src.alerting.console_alert import print_security_alert
from src.alerting.report_writer import save_security_alert


class TestAlertPipeline(unittest.TestCase):

    def test_five_failed_logins_generate_and_save_alert(self):

        detector = SSHBruteForceDetector(load_config())

        fake_event = {
            "event_type": "ssh_failed_login",
            "username": "test_user",
            "source_ip": "192.0.2.10",
        }

        with tempfile.TemporaryDirectory() as temp_dir:

            test_report = Path(temp_dir) / "test_alerts.json"

            with patch(
                "src.alerting.report_writer.REPORT_FILE",
                test_report,
            ):

                detection = None

                for second in range(5):
                    detection = detector.process_event(
                        fake_event,
                        now=1000 + second,
                    )

                self.assertIsNotNone(detection)
                self.assertEqual(detection["severity"], "LOW")
                self.assertEqual(detection["failed_attempts"], 5)

                with patch(
                    "builtins.print"
                ) as mocked_print:
                    print_security_alert(detection)
                    mocked_print.assert_called()

                saved_alert = save_security_alert(detection)

                self.assertTrue(test_report.exists())

                with test_report.open(
                    "r", encoding="utf-8"
                ) as file:
                    saved_data = json.load(file)

                self.assertEqual(len(saved_data), 1)
                self.assertEqual(
                    saved_data[0]["severity"], "LOW"
                )
                self.assertEqual(
                    saved_data[0]["source_ip"], "192.0.2.10"
                )

                self.assertEqual(
                    saved_alert["severity"], "LOW"
                )


if __name__ == "__main__":
    unittest.main()
