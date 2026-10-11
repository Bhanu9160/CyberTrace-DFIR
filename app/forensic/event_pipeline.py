from datetime import datetime, timezone
from typing import Any
import hashlib
import json


SUPPORTED_SOURCES = {
    "windows_security",
    "sysmon",
    "linux_auth",
    "linux_system",
    "firewall",
    "network",
    "file_analysis",
}


def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert an incoming event into a common format."""

    if not isinstance(raw, dict):
        raise ValueError("Event must be a dictionary")

    source = str(raw.get("source", "")).strip().lower()

    if source not in SUPPORTED_SOURCES:
        raise ValueError(f"Unsupported event source: {source}")

    event_type = str(raw.get("event_type", "unknown")).strip()
    host = str(raw.get("host", "unknown")).strip()
    message = str(raw.get("message", "")).strip()

    timestamp = raw.get("timestamp")

    if timestamp:
        try:
            parsed = datetime.fromisoformat(
                str(timestamp).replace("Z", "+00:00")
            )
            if parsed.tzinfo is None:
                raise ValueError("Timestamp must include a timezone")
            timestamp_utc = parsed.astimezone(timezone.utc).isoformat()
        except ValueError as exc:
            raise ValueError("Invalid event timestamp") from exc
    else:
        timestamp_utc = datetime.now(timezone.utc).isoformat()

    event = {
        "timestamp_utc": timestamp_utc,
        "source": source,
        "host": host or "unknown",
        "event_type": event_type or "unknown",
        "event_id": str(raw.get("event_id", "")),
        "username": str(raw.get("username", "unknown")),
        "src_ip": str(raw.get("src_ip", "")),
        "dst_ip": str(raw.get("dst_ip", "")),
        "severity": str(raw.get("severity", "Informational")),
        "message": message,
    }

    # Stable ID helps prevent duplicate ingestion of the same event.
    identity = json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    event["event_uid"] = hashlib.sha256(identity).hexdigest()

    return event