import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORT_FILE = PROJECT_ROOT / "reports" / "security_alerts.json"


def save_security_alert(detection):

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detection": "SSH Brute Force",
        "source_ip": detection["source_ip"],
        "failed_attempts": detection["failed_attempts"],
        "window_seconds": detection["window_seconds"],
        "severity": detection["severity"]
    }

    # Read existing alerts, if the report already exists
    if REPORT_FILE.exists():
        with REPORT_FILE.open("r", encoding="utf-8") as file:
            alerts = json.load(file)
    else:
        alerts = []

    alerts.append(alert)

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print(f"Alert saved to: {REPORT_FILE}")

    return alert


if __name__ == "__main__":

    test_detection = {
        "source_ip": "10.0.2.100",
        "failed_attempts": 15,
        "window_seconds": 300,
        "severity": "HIGH"
    }

    saved_alert = save_security_alert(test_detection)

    print(json.dumps(saved_alert, indent=4))
