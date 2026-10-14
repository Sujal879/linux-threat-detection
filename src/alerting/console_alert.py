def print_security_alert(detection):

    print("\n")
    print("=" * 45)
    print("          🚨 SECURITY ALERT")
    print("=" * 45)

    print(f"Detection : SSH Brute Force")
    print(f"Source IP : {detection['source_ip']}")
    print(f"Attempts  : {detection['failed_attempts']}")
    print(f"Window    : {detection['window_seconds']} seconds")
    print(f"Severity  : {detection['severity']}")

    print("=" * 45)
