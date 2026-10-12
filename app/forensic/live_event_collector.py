import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from app.forensic.event_store import save_events


BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_LOGS = ("System", "Security", "Application")


def normalize_windows_timestamp(value):
    """Normalize common PowerShell/.NET timestamps to ISO 8601 UTC."""
    if not value:
        return datetime.now(timezone.utc).isoformat()

    value = str(value)

    # PowerShell ConvertTo-Json may serialize DateTime as /Date(ms)/.
    if value.startswith("/Date(") and value.endswith(")/"):
        try:
            milliseconds = int(value[6:-2].split("+")[0].split("-")[0])
            return datetime.fromtimestamp(
                milliseconds / 1000,
                tz=timezone.utc,
            ).isoformat()
        except (ValueError, OverflowError, OSError):
            pass

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return value


def collect_windows_events(log_name="System", max_events=100):
    """Collect recent events from one Windows Event Log."""
    if log_name not in DEFAULT_LOGS:
        raise ValueError(
            f"Unsupported log: {log_name}. "
            f"Choose from {', '.join(DEFAULT_LOGS)}."
        )

    # PowerShell script: retrieve recent records and serialize to JSON.
    script = r"""
$ErrorActionPreference = 'Stop'
$log = $env:CTDFIR_LOG_NAME
$limit = [int]$env:CTDFIR_MAX_EVENTS

$events = @(
    Get-WinEvent -FilterHashtable @{ LogName = $log } `
        -MaxEvents $limit -ErrorAction Stop |
    Select-Object `
        @{Name='timestamp_utc';Expression={$_.TimeCreated.ToUniversalTime().ToString('o')}},
        @{Name='event_id';Expression={$_.Id}},
        @{Name='provider';Expression={$_.ProviderName}},
        @{Name='severity';Expression={$_.LevelDisplayName}},
        @{Name='host';Expression={$_.MachineName}},
        @{Name='log_name';Expression={$_.LogName}},
        @{Name='record_id';Expression={$_.RecordId}},
        @{Name='message';Expression={$_.Message}}
)

ConvertTo-Json -InputObject $events -Depth 4 -Compress
"""

    import os

    env = os.environ.copy()
    env["CTDFIR_LOG_NAME"] = log_name
    env["CTDFIR_MAX_EVENTS"] = str(max_events)

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
    )

    if result.returncode != 0:
        error_text = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(
            f"Failed to collect {log_name} events: {error_text}"
        )

    output = result.stdout.strip()

    if not output:
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"Could not parse PowerShell JSON for {log_name}: {error}"
        ) from error

    if isinstance(data, dict):
        data = [data]

    normalized = []

    for event in data:
        if not isinstance(event, dict):
            continue

        event["timestamp_utc"] = normalize_windows_timestamp(
            event.get("timestamp_utc")
        )

        record_id = event.get("record_id")
        host = event.get("host", "Unknown")
        event["event_uid"] = hashlib.sha256(
            f"{host}|{log_name}|{record_id}".encode("utf-8")
        ).hexdigest()

        normalized.append(event)

    return normalized


def collect_all_logs(max_events=100):
    """Collect events from each configured log."""
    collected = []

    for log_name in DEFAULT_LOGS:
        try:
            events = collect_windows_events(
                log_name=log_name,
                max_events=max_events,
            )
            collected.extend(events)
            print(f"{log_name}: retrieved {len(events)} events")

        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            print(f"Warning: could not collect {log_name}: {error}")

    return collected


def run_continuous_collection(
    max_events=100,
    interval_seconds=10,
):
    """Continuously poll logs and save new records to JSONL."""
    print("CyberTrace-DFIR Windows event collector started.")
    print(f"Polling configured logs every {interval_seconds} seconds.")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            events = collect_all_logs(max_events=max_events)
            saved = save_events(events)

            print(
                f"{datetime.now(timezone.utc).isoformat()} | "
                f"Retrieved: {len(events)} | Saved new events: {saved}"
            )

            time.sleep(interval_seconds)

    except KeyboardInterrupt:
        print("\nWindows event collection stopped.")


def main():
    run_continuous_collection()


if __name__ == "__main__":
    main()