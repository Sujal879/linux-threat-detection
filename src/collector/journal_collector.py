
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.collector.log_parser import parse_ssh_log
from src.detectors.ssh_detector import (
    SSHBruteForceDetector,
    load_config,
)
from src.alerting.console_alert import print_security_alert
from src.alerting.report_writer import save_security_alert


STATE_DIR = PROJECT_ROOT / ".state"
STATE_FILE = STATE_DIR / "collector_state.json"



def load_collector_state():
    if not STATE_FILE.exists():
        return {
            "last_cursor": None,
            "failed_attempts": {},
        }

    with STATE_FILE.open("r", encoding="utf-8") as file:
        state = json.load(file)

    return {
        "last_cursor": state.get("last_cursor"),
        "failed_attempts": state.get("failed_attempts", {}),
    }


def save_collector_state(cursor, failed_attempts):
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    state = {
        "last_cursor": cursor,
        "failed_attempts": failed_attempts,
    }

    temporary_file = STATE_FILE.with_suffix(".tmp")

    with temporary_file.open("w", encoding="utf-8") as file:
        json.dump(state, file, indent=4)

    temporary_file.replace(STATE_FILE)



def collect_ssh_logs():
    last_cursor = load_collector_state()["last_cursor"]

    command = [
        "sudo",
        "journalctl",
        "-u", "ssh",
        "--no-pager",
        "--output=json",
    ]

    if last_cursor:
        command.append(f"--after-cursor={last_cursor}")
    else:
        # First run: bootstrap from the latest 50 entries.
        command.extend(["-n", "50"])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    entries = []

    for line in result.stdout.splitlines():
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return entries



def process_logs():
    state = load_collector_state()

    detector = SSHBruteForceDetector(load_config())
    detector.load_state(state["failed_attempts"])

    entries = collect_ssh_logs()

    if not entries:
        print("No new SSH journal entries.")
        return

    processed = 0
    last_cursor = state["last_cursor"]

    for entry in entries:
        cursor = entry.get("__CURSOR")
        message = entry.get("MESSAGE", "")
        raw_timestamp = entry.get("__REALTIME_TIMESTAMP")

        event_timestamp = None

        if raw_timestamp is not None:
            try:
                event_timestamp = int(raw_timestamp) / 1_000_000
            except (ValueError, TypeError):
                event_timestamp = None

        event = parse_ssh_log(
            message,
            timestamp=event_timestamp,
        )

        if event:
            print("\nEvent detected:")
            print(event)

            if (
                event["event_type"] == "ssh_failed_login"
                and event_timestamp is not None
            ):
                detection = detector.process_event(
                    event,
                    now=event_timestamp,
                )

                if (
                    detection
                    and detection["severity"] != "NORMAL"
                ):
                    print_security_alert(detection)
                    save_security_alert(detection)

        if cursor:
            last_cursor = cursor

        save_collector_state(
            last_cursor,
            detector.export_state(),
        )

        processed += 1

    print(f"\nProcessed {processed} new journal entries.")



if __name__ == "__main__":
    process_logs()
