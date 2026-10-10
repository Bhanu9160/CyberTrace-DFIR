import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_OUTPUT = Path("reports/chain_of_custody.json")


def record_event(evidence_id, handler, action, reason, output):
    output = Path(output)

    if output.exists():
        events = json.loads(output.read_text(encoding="utf-8"))
        if not isinstance(events, list):
            raise ValueError("Custody record must contain a JSON list.")
    else:
        events = []

    event = {
        "evidence_id": evidence_id,
        "handler": handler,
        "action": action,
        "reason": reason,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    events.append(event)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(events, indent=4),
        encoding="utf-8",
    )

    return event


def main():
    parser = argparse.ArgumentParser(
        description="Record a CyberTrace-DFIR chain-of-custody event."
    )
    parser.add_argument("--evidence-id", required=True)
    parser.add_argument("--handler", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
    )

    args = parser.parse_args()

    try:
        event = record_event(
            args.evidence_id,
            args.handler,
            args.action,
            args.reason,
            args.output,
        )

        print("=== Chain of Custody ===")
        print(f"Evidence ID: {event['evidence_id']}")
        print(f"Handler: {event['handler']}")
        print(f"Action: {event['action']}")
        print(f"Timestamp (UTC): {event['timestamp_utc']}")
        print(f"Record saved to: {args.output}")

    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Error: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()