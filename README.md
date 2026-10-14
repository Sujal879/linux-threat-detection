# Linux Security Monitoring & SSH Brute-Force Detection Engine

A Python-based Linux security monitoring project that collects SSH authentication logs, identifies repeated failed login attempts, assigns alert severity, and saves security alerts in JSON format.

## Overview

This project demonstrates core security engineering concepts through a Linux-based monitoring lab. It uses the systemd journal to collect SSH service logs and applies configurable detection rules to identify potential SSH brute-force activity.

The project is designed for learning and demonstration in a controlled Ubuntu lab environment.

## Features

- **SSH log parsing:** Extracts failed and successful SSH authentication events, usernames, source IP addresses, and timestamps.
- **Brute-force detection:** Tracks failed login attempts separately for each source IP.
- **Configurable detection rules:** Uses a rolling five-minute detection window with configurable severity thresholds.
- **Incremental log collection:** Uses journal cursors to collect new journal entries after the previously processed position.
- **Persistent detection state:** Saves the collector cursor and recent failed-login timestamps to local JSON state.
- **Security alerting:** Displays alerts in the terminal and saves alert records to JSON.
- **Automated testing:** Includes unit and integration tests for detection logic, state persistence, and alert generation.

## Architecture

```text
Ubuntu SSH Service
        |
        v
systemd Journal (journalctl)
        |
        v
Journal Collector
        |
        v
SSH Log Parser
        |
        v
SSH Brute-Force Detector
        |
        v
Severity Evaluation
        |
        v
Console Alert + JSON Report

Collector Cursor and Detection State
        |
        v
Local JSON State File
```

## Technology Stack

- Python
- Ubuntu Linux
- OpenSSH
- systemd journal / journalctl
- JSON
- Python unittest

## Detection Rules

The default rules are configured in `config/detection_rules.json`.

| Setting | Default |
|---|---:|
| Detection window | 300 seconds |
| LOW severity threshold | 5 failed attempts |
| MEDIUM severity threshold | 10 failed attempts |
| HIGH severity threshold | 15 failed attempts |

Severity is determined using the number of failed login attempts from an individual source IP within the configured time window.

These thresholds are configurable and are intended for lab testing, not as universal production security thresholds.

## Project Structure

```text
linux-threat-detection/
├── config/
│   └── detection_rules.json
├── src/
│   ├── alerting/
│   │   ├── console_alert.py
│   │   └── report_writer.py
│   ├── collector/
│   │   ├── journal_collector.py
│   │   └── log_parser.py
│   └── detectors/
│       └── ssh_detector.py
├── tests/
│   ├── test_alert_pipeline.py
│   ├── test_collector_integration.py
│   └── test_ssh_detector.py
├── .gitignore
├── requirements.txt
└── README.md
```

## Prerequisites

- Ubuntu Linux with systemd.
- Python 3.10 or later.
- OpenSSH server and `journalctl`.
- Permission to read the SSH service journal.

## Setup

Clone the repository:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd linux-threat-detection
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

The current implementation uses Python's standard library and does not require third-party packages.

## Running the Collector

Allow `sudo` to authenticate before starting the collector:

```bash
sudo -v
```

Run the collector from the project root:

```bash
python -m src.collector.journal_collector
```

On the first run, the collector reads a limited batch of recent SSH journal entries. Subsequent runs use the saved journal cursor to request newer entries.

If no new entries are available, the collector reports:

```text
No new SSH journal entries.
```

The collector processes journal entries; it does not continuously run as a background service.

## Running Tests

Run the complete test suite:

```bash
python -m unittest discover -s tests -v
```

Run detector tests only:

```bash
python -m unittest discover -s tests -p "test_ssh_detector.py" -v
```

Run collector integration tests:

```bash
python -m unittest discover -s tests -p "test_collector_integration.py" -v
```

Run alert pipeline tests:

```bash
python -m unittest discover -s tests -p "test_alert_pipeline.py" -v
```

The current test suite has passed 10 tests in the development environment.

## Alerts and State

Runtime files are generated locally:

- `reports/security_alerts.json` — saved security alert records.
- `.state/collector_state.json` — journal cursor and recent failed-login timestamps.

These directories are excluded from version control to avoid committing machine-specific state and generated reports.

## Current Scope and Limitations

- Focuses on SSH authentication events and brute-force detection.
- Uses configurable threshold-based rules rather than machine learning.
- The current log parser primarily supports IPv4 source addresses.
- Detection depends on relevant events being available in the system journal and recognized by the parser.
- It does not currently implement file integrity monitoring, user/privilege-change detection, automated IP blocking, or a web dashboard.
- It is a learning and portfolio project, not a production-ready security monitoring platform.

## Future Improvements

- Add Linux user and privilege-change detection.
- Add file integrity monitoring.
- Support IPv6 log parsing.
- Improve alert correlation and reporting.
- Add more automated end-to-end tests.

## Security and Responsible Use

Use this project in a system or lab environment you own or are authorized to administer. Detection thresholds should be reviewed and tuned before use in any real environment.

## Author

**Sujal Shah**

GitHub: [Sujal879](https://github.com/Sujal879)

LinkedIn: [Sujal Shah](https://www.linkedin.com/in/sujal-shah-9a1980239/)
