import hashlib
import json
import re
import subprocess
import time
from datetime import datetime, timezone

from app.forensic.event_store import save_events


def normalize_windows_timestamp(value):
    """Convert Windows timestamps to UTC ISO format."""
    if not value:
        return None

    match = re.fullmatch(
        r"/Date\((-?\d+)(?:[+-]\d{4})?\)/",
        str(value),
    )

    if match:
        milliseconds = int(match.group(1))
        return datetime.fromtimestamp(
            milliseconds / 1000,
            tz=timezone.utc,
        ).isoformat()

    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc).isoformat()

    except ValueError:
        return str(value)


def collect_windows_events(max_events=100, log_name="System"):
    """Collect recent Windows events and normalize their fields."""

    allowed_logs = {"System", "Security", "Application"}

    if log_name not in allowed_logs:
        raise ValueError(
            f"Choose one of these logs: {sorted(allowed_logs)}"
        )

    if not isinstance(max_events, int) or not 1 <= max_events <= 1000:
        raise ValueError("max_events must be between 1 and 1000.")

    powershell_script = f"""
$ErrorActionPreference = 'Stop'

$events = @(
    Get-WinEvent -LogName '{log_name}' -MaxEvents {max_events} |
    Select-Object RecordId, TimeCreated, Id, ProviderName,
                  LevelDisplayName, MachineName, Message
)

$events | ConvertTo-Json -Depth 4 -Compress
"""

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            powershell_script,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"PowerShell collection failed: {result.stderr.strip()}"
        )

    output = result.stdout.strip()

    if not output:
        return []

    try:
        raw_events = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Could not parse PowerShell output: {exc}"
        ) from exc

    if isinstance(raw_events, dict):
        raw_events = [raw_events]

    normalized_events = []

    for raw in raw_events:
        host = raw.get("MachineName") or "unknown-host"
        record_id = raw.get("RecordId")
        event_id = raw.get("Id")
        provider = raw.get("ProviderName") or "unknown-provider"

        timestamp = normalize_windows_timestamp(
            raw.get("TimeCreated")
        )

        event = {
            "timestamp_utc": timestamp,
            "source": "windows_event_log",
            "host": host,
            "log_name": log_name,
            "record_id": record_id,
            "event_id": event_id,
            "provider": provider,
            "severity": raw.get("LevelDisplayName") or "Unknown",
            "message": raw.get("Message") or "",
        }

        # Prefer the Windows record ID for deduplication.
        if record_id is not None:
            unique_key = f"{host}|{log_name}|{record_id}"
        else:
            unique_key = (
                f"{host}|{log_name}|{timestamp}|"
                f"{provider}|{event_id}"
            )

        event["event_uid"] = hashlib.sha256(
            unique_key.encode("utf-8")
        ).hexdigest()

        normalized_events.append(event)

    return normalized_events


def run_continuous_collection(
    log_name="System",
    max_events=100,
    interval_seconds=10,
):
    """Poll Windows events continuously until Ctrl+C is pressed."""

    print("CyberTrace-DFIR event collector started.")
    print(f"Windows log: {log_name}")
    print(f"Polling interval: {interval_seconds} seconds")
    print("Press Ctrl+C to stop.\n")

    while True:
        try:
            events = collect_windows_events(
                max_events=max_events,
                log_name=log_name,
            )

            saved = save_events(
                events,
                "windows_events.jsonl",
            )

            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"Collected: {len(events)} | "
                f"New events saved: {saved}"
            )

        except (
            RuntimeError,
            ValueError,
            subprocess.SubprocessError,
        ) as exc:
            print(f"Collection error: {exc}")

        time.sleep(interval_seconds)


if __name__ == "__main__":
    try:
        run_continuous_collection(
            log_name="System",
            max_events=100,
            interval_seconds=10,
        )
    except KeyboardInterrupt:
        print("\nCyberTrace-DFIR collection stopped.")