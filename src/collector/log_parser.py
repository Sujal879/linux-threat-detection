
import re


def parse_ssh_log(log_line, timestamp=None):
    """
    Parse SSH authentication messages.

    timestamp: optional Unix timestamp supplied by journalctl.
    """

    # Support the older syslog-style timestamp for parser tests.
    legacy_match = re.search(
        r"(\w+\s+\d+\s+\d+:\d+:\d+)",
        log_line,
    )

    event_timestamp = timestamp

    if event_timestamp is None and legacy_match:
        event_timestamp = legacy_match.group(1)

    # Failed password authentication
    failed_pattern = (
        r"Failed password for (?:invalid user )?"
        r"(\w+) from ([0-9.]+)"
    )

    failed_match = re.search(failed_pattern, log_line)

    if failed_match:
        return {
            "event_type": "ssh_failed_login",
            "timestamp": event_timestamp,
            "username": failed_match.group(1),
            "source_ip": failed_match.group(2),
        }

    # Successful password authentication
    success_pattern = (
        r"Accepted password for (\w+) from ([0-9.]+)"
    )

    success_match = re.search(success_pattern, log_line)

    if success_match:
        return {
            "event_type": "ssh_auth_success",
            "timestamp": event_timestamp,
            "username": success_match.group(1),
            "source_ip": success_match.group(2),
        }

    return None


if __name__ == "__main__":

    failed_log = (
        "Oct 08 10:15:33 security-lab "
        "sshd-session[2001]: "
        "Failed password for invalid user admin "
        "from 10.0.2.100 port 54321 ssh2"
    )

    success_log = (
        "Oct 08 09:31:39 security-lab "
        "sshd-session[1439]: "
        "Accepted password for sujal "
        "from 10.0.2.2 port 57698 ssh2"
    )

    print("Failed login test:")
    print(parse_ssh_log(failed_log))

    print("\nSuccessful login test:")
    print(parse_ssh_log(success_log))

    print("\nUnix timestamp test:")
    print(
        parse_ssh_log(
            "Failed password for admin from 192.0.2.10",
            timestamp=1791530400.0,
        )
    )
