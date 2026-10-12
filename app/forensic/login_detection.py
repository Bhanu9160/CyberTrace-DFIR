import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path


# Project paths
BASE_DIR = Path(__file__).resolve().parents[2]
EVENT_FILE = BASE_DIR / "data" / "live_events" / "windows_events.jsonl"
ALERT_FILE = BASE_DIR / "reports" / "login_alerts.json"

# Detection settings
FAILED_EVENT_ID = 4625
SUCCESS_EVENT_ID = 4624
FAILURE_THRESHOLD = 5
TIME_WINDOW_MINUTES = 10


def parse_timestamp(value):
    """Parse an event timestamp into a timezone-aware datetime."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def get_event_id(event):
    """Read the Windows event ID from a normalized event."""
    value = event.get("event_id", event.get("Id"))

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_event_timestamp(event):
    """Support the timestamp fields used by the collector."""
    return parse_timestamp(
        event.get("timestamp_utc")
        or event.get("timestamp")
        or event.get("TimeCreated")
        or event.get("time")
    )


def get_username(event):
    """Extract a username when the collector provides one."""
    return (
        event.get("username")
        or event.get("user")
        or event.get("User")
        or event.get("target_user")
        or "Unknown"
    )


def detect_login_activity(events):
    """
    Detect five or more failed logons for the same user
    within a rolling ten-minute window.

    Also report successful logons that follow a recent
    failed logon sequence for the same user.

    Username matching is a basic heuristic, not proof
    that the same person performed both activities.
    """
    failures_by_user = defaultdict(list)
    alerts = []
    seen_alerts = set()

    # Normalize the login events.
    login_events = []

    for event in events:
        event_id = get_event_id(event)

        if event_id not in (FAILED_EVENT_ID, SUCCESS_EVENT_ID):
            continue

        timestamp = get_event_timestamp(event)

        if timestamp is None:
            continue

        username = get_username(event)

        login_events.append({
            "event_id": event_id,
            "timestamp": timestamp,
            "username": username,
            "host": event.get("host", "Unknown"),
            "source": event.get("source_ip")
                      or event.get("src_ip")
                      or event.get("ip_address"),
            "message": event.get("message", ""),
        })

    login_events.sort(key=lambda item: item["timestamp"])
    window = timedelta(minutes=TIME_WINDOW_MINUTES)

    # Identify repeated failed logons.
    for event in login_events:
        if event["event_id"] != FAILED_EVENT_ID:
            continue

        username = event["username"]
        timestamp = event["timestamp"]

        failures_by_user[username].append(timestamp)

        recent = [
            item for item in failures_by_user[username]
            if timestamp - window <= item <= timestamp
        ]

        if len(recent) >= FAILURE_THRESHOLD:
            alert_key = (
                "Repeated Failed Logins",
                username,
                event["host"],
                timestamp.isoformat(),
            )

            if alert_key not in seen_alerts:
                alerts.append({
                    "alert_type": "Repeated Failed Logins",
                    "severity": "High",
                    "username": username,
                    "host": event["host"],
                    "failed_attempts": len(recent),
                    "window_minutes": TIME_WINDOW_MINUTES,
                    "timestamp_utc": timestamp.isoformat(),
                    "source": event["source"],
                    "description": (
                        f"{len(recent)} failed logon events for "
                        f"{username} within "
                        f"{TIME_WINDOW_MINUTES} minutes."
                    ),
                })

                seen_alerts.add(alert_key)

    # Identify a successful logon after repeated failures.
    for event in login_events:
        if event["event_id"] != SUCCESS_EVENT_ID:
            continue

        username = event["username"]
        timestamp = event["timestamp"]

        recent_failures = [
            failed_time
            for failed_time in failures_by_user.get(username, [])
            if timestamp - window <= failed_time < timestamp
        ]

        if len(recent_failures) >= FAILURE_THRESHOLD:
            alert_key = (
                "Failures Followed by Successful Logon",
                username,
                event["host"],
                timestamp.isoformat(),
            )

            if alert_key not in seen_alerts:
                alerts.append({
                    "alert_type": (
                        "Failures Followed by Successful Logon"
                    ),
                    "severity": "High",
                    "username": username,
                    "host": event["host"],
                    "failed_attempts": len(recent_failures),
                    "window_minutes": TIME_WINDOW_MINUTES,
                    "timestamp_utc": timestamp.isoformat(),
                    "source": event["source"],
                    "description": (
                        f"A successful logon for {username} followed "
                        f"{len(recent_failures)} failed logons within "
                        f"{TIME_WINDOW_MINUTES} minutes."
                    ),
                })

                seen_alerts.add(alert_key)

    return alerts


def load_events():
    """Read stored Windows events from JSONL."""
    if not EVENT_FILE.is_file():
        raise FileNotFoundError(
            f"Event file not found: {EVENT_FILE}"
        )

    events = []

    with EVENT_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            try:
                event = json.loads(line)

                if isinstance(event, dict):
                    events.append(event)

            except json.JSONDecodeError:
                print(
                    f"Warning: skipped invalid JSON "
                    f"at line {line_number}"
                )

    return events


def main():
    try:
        events = load_events()
        alerts = detect_login_activity(events)

        ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

        ALERT_FILE.write_text(
            json.dumps(alerts, indent=2),
            encoding="utf-8",
        )

        login_event_count = sum(
            1 for event in events
            if get_event_id(event)
            in (FAILED_EVENT_ID, SUCCESS_EVENT_ID)
        )

        print("=== CyberTrace-DFIR Login Detection ===")
        print(f"Total events examined: {len(events)}")
        print(f"Login events examined: {login_event_count}")
        print(f"Alerts generated: {len(alerts)}")

        for alert in alerts:
            print(
                f"[{alert['severity']}] {alert['alert_type']} | "
                f"User: {alert['username']} | "
                f"Host: {alert['host']} | "
                f"Failures: {alert['failed_attempts']}"
            )

        print(f"Alert report saved to: {ALERT_FILE}")

    except (OSError, ValueError) as error:
        print(f"Error: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()