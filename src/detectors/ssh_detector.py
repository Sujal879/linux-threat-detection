import json
import time
from bisect import bisect_right
from collections import defaultdict, deque
from pathlib import Path


CONFIG_PATH = (
    Path(__file__).resolve().parents[2]
    / "config"
    / "detection_rules.json"
)


def load_config():
    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        config = json.load(file)

    return config["ssh_failed_login"]


class SSHBruteForceDetector:

    def __init__(self, config):
        self.window_seconds = config["window_seconds"]

        thresholds = config["thresholds"]
        self.low_threshold = thresholds["low"]
        self.medium_threshold = thresholds["medium"]
        self.high_threshold = thresholds["high"]

        self.failed_attempts = defaultdict(deque)

    def export_state(self):
        """Export recent failed-login timestamps for persistence."""
        return {
            source_ip: list(timestamps)
            for source_ip, timestamps in self.failed_attempts.items()
        }

    def load_state(self, state, now=None):
        """Restore recent failed-login timestamps from saved state."""
        current_time = time.time() if now is None else now
        cutoff = current_time - self.window_seconds

        self.failed_attempts.clear()

        for source_ip, timestamps in state.items():
            if not isinstance(source_ip, str) or not isinstance(timestamps, list):
                continue

            valid_timestamps = []

            for timestamp in timestamps:
                if isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool):
                    if cutoff <= timestamp <= current_time:
                        valid_timestamps.append(float(timestamp))

            if valid_timestamps:
                self.failed_attempts[source_ip] = deque(
                    sorted(valid_timestamps)
                )

    def process_event(self, event, now=None):
        """
        Process one failed SSH login event.

        'now' is the event's timestamp in Unix seconds when supplied.
        It defaults to the current time for backward compatibility.
        """

        if event.get("event_type") != "ssh_failed_login":
            return None

        source_ip = event.get("source_ip")

        if not source_ip:
            return None

        current_time = time.time() if now is None else now

        attempts = self.failed_attempts[source_ip]

        # Insert timestamps in chronological order.
        # This also handles events arriving out of order.
        position = bisect_right(attempts, current_time)
        attempts.insert(position, current_time)

        # Remove events older than the detection window.
        cutoff = current_time - self.window_seconds

        while attempts and attempts[0] < cutoff:
            attempts.popleft()

        # Count only events inside the window and not later
        # than the event currently being processed.
        count = sum(
            cutoff <= timestamp <= current_time
            for timestamp in attempts
        )

        if count >= self.high_threshold:
            severity = "HIGH"
        elif count >= self.medium_threshold:
            severity = "MEDIUM"
        elif count >= self.low_threshold:
            severity = "LOW"
        else:
            severity = "NORMAL"

        return {
            "source_ip": source_ip,
            "failed_attempts": count,
            "window_seconds": self.window_seconds,
            "severity": severity,
        }


if __name__ == "__main__":

    detector = SSHBruteForceDetector(load_config())

    test_event = {
        "event_type": "ssh_failed_login",
        "username": "admin",
        "source_ip": "192.168.1.100",
    }

    print("Test 1: 16 attempts within 5 minutes")
    print("--------------------------------------")

    base_time = 1000

    for offset in range(16):
        result = detector.process_event(
            test_event,
            now=base_time + offset,
        )
        print(result)

    print("\nTest 2: New event after the old window expires")
    print("-----------------------------------------------")

    result = detector.process_event(
        test_event,
        now=base_time + 400,
    )
    print(result)
