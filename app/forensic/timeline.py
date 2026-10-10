import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def generate_timeline(input_file):
    input_path = Path(input_file)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Chain-of-custody file not found: {input_path}"
        )

    events = json.loads(input_path.read_text(encoding="utf-8"))

    if not isinstance(events, list):
        raise ValueError("Expected a JSON list of custody events.")

    timeline = []

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Each event must be a JSON object.")

        timestamp = event.get("timestamp_utc")

        if not timestamp:
            raise ValueError("An event is missing timestamp_utc.")

        parsed_time = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

        if parsed_time.tzinfo is None:
            raise ValueError(
                "Event timestamp must include a timezone."
            )

        timeline.append({
            **event,
            "_sort_time": parsed_time.astimezone(timezone.utc),
        })

    timeline.sort(key=lambda event: event["_sort_time"])

    for event in timeline:
        event["timestamp_utc"] = (
            event.pop("_sort_time")
            .isoformat()
        )

    return timeline


def main():
    parser = argparse.ArgumentParser(
        description="Generate a forensic event timeline."
    )
    parser.add_argument(
        "--input",
        default="reports/chain_of_custody.json",
        help="Path to the chain-of-custody JSON file",
    )
    parser.add_argument(
        "--output",
        default="reports/forensic_timeline.json",
        help="Path for the generated timeline",
    )
    args = parser.parse_args()

    try:
        timeline = generate_timeline(args.input)

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(
            json.dumps(timeline, indent=4),
            encoding="utf-8",
        )

        print("=== CyberTrace-DFIR: Forensic Timeline ===")
        print(f"Events processed: {len(timeline)}")

        for event in timeline:
            print(
                f"{event['timestamp_utc']} | "
                f"{event.get('evidence_id', 'Unknown evidence')} | "
                f"{event.get('action', 'Unknown action')} | "
                f"{event.get('handler', 'Unknown handler')}"
            )

        print(f"Timeline saved to: {output_path}")

    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Error: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()