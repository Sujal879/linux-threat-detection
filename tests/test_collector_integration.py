
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.collector import journal_collector


class TestCollectorIntegration(unittest.TestCase):

    def test_failed_login_state_and_cursor_are_saved(self):
        fake_entries = [
            {
                "__CURSOR": "cursor-test-001",
                "__REALTIME_TIMESTAMP": "1791969859000000",
                "MESSAGE": (
                    "Failed password for invalid user admin "
                    "from 192.0.2.10 port 54321 ssh2"
                ),
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            state_file = Path(temp_dir) / "collector_state.json"

            with (
                patch.object(
                    journal_collector,
                    "STATE_DIR",
                    Path(temp_dir),
                ),
                patch.object(
                    journal_collector,
                    "STATE_FILE",
                    state_file,
                ),
                patch.object(
                    journal_collector,
                    "collect_ssh_logs",
                    return_value=fake_entries,
                ),
                patch.object(
                    journal_collector,
                    "print_security_alert",
                ),
                patch.object(
                    journal_collector,
                    "save_security_alert",
                ),
            ):
                journal_collector.process_logs()

                self.assertTrue(state_file.exists())

                with state_file.open(
                    "r", encoding="utf-8"
                ) as file:
                    saved_state = json.load(file)

                self.assertEqual(
                    saved_state["last_cursor"],
                    "cursor-test-001",
                )

                self.assertIn(
                    "192.0.2.10",
                    saved_state["failed_attempts"],
                )

                timestamps = saved_state["failed_attempts"][
                    "192.0.2.10"
                ]

                self.assertEqual(len(timestamps), 1)
                self.assertEqual(
                    timestamps[0],
                    1791969859.0,
                )
    def test_saved_state_restores_recent_failed_attempts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_file = Path(temp_dir) / "collector_state.json"

            with (
                patch.object(
                    journal_collector, "STATE_DIR", Path(temp_dir)
                ),
                patch.object(
                    journal_collector, "STATE_FILE", state_file
                ),
            ):
                journal_collector.save_collector_state(
                    "cursor-restore-001",
                    {"192.0.2.10": [1000.0]},
                )

                loaded_state = journal_collector.load_collector_state()

                self.assertEqual(
                    loaded_state["last_cursor"],
                    "cursor-restore-001",
                )

                detector = journal_collector.SSHBruteForceDetector(
                    journal_collector.load_config()
                )
                detector.load_state(
                    loaded_state["failed_attempts"],
                    now=1001.0,
                )

                restored_state = detector.export_state()
                self.assertEqual(
                    restored_state["192.0.2.10"],
                    [1000.0],
                )

                detection = detector.process_event(
                    {
                        "event_type": "ssh_failed_login",
                        "source_ip": "192.0.2.10",
                    },
                    now=1002.0,
                )

                self.assertEqual(detection["failed_attempts"], 2)

if __name__ == "__main__":
    unittest.main()
