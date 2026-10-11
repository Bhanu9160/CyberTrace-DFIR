import json
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[2]
EVENT_DIR = BASE_DIR / "data" / "live_events"
EVENT_DIR.mkdir(parents=True, exist_ok=True)


def save_events(
    events: list[dict[str, Any]],
    filename: str = "windows_events.jsonl",
) -> int:
    """Append events to a JSON Lines file, skipping known event IDs."""

    output_path = EVENT_DIR / filename

    # Load previously stored identifiers to avoid duplicate records.
    known_ids: set[str] = set()

    if output_path.exists():
        with output_path.open("r", encoding="utf-8") as file:
            for line in file:
                try:
                    record = json.loads(line)
                    event_id = record.get("event_uid")
                    if event_id:
                        known_ids.add(event_id)
                except json.JSONDecodeError:
                    continue

    saved = 0

    with output_path.open("a", encoding="utf-8") as file:
        for event in events:
            if not isinstance(event, dict):
                continue

            event_id = event.get("event_uid")

            # Without a stable identifier, don't risk falsely
            # treating two different events as identical.
            if not event_id:
                file.write(json.dumps(event, ensure_ascii=False) + "\n")
                saved += 1
                continue

            if event_id in known_ids:
                continue

            file.write(json.dumps(event, ensure_ascii=False) + "\n")
            known_ids.add(event_id)
            saved += 1

    return saved