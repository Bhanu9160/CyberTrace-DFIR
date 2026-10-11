import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def read_json(path: Path):
    if not path.is_file():
        raise FileNotFoundError(f"Report not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def build_summary(inventory_path, indicators_path=None, custody_path=None):
    inventory = read_json(inventory_path)
    files = inventory.get("files", [])

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "summary_type": "DFIR Investigation Summary",
        "source_inventory": str(inventory_path),
        "total_files": len(files),
        "files_with_hashes": sum(
            1 for item in files if item.get("sha256")
        ),
        "files_with_errors": sum(
            1 for item in files if item.get("error")
        ),
        "indicator_findings": None,
        "chain_of_custody_events": 0,
        "review_required": True,
        "analyst_note": (
            "Automated summary only. Validate findings manually; "
            "indicators do not independently prove malicious activity."
        ),
    }

    if indicators_path:
        indicators = read_json(indicators_path)
        summary["indicator_findings"] = indicators

    if custody_path:
        custody = read_json(custody_path)
        if not isinstance(custody, list):
            raise ValueError("Chain-of-custody report must be a JSON list.")
        summary["chain_of_custody_events"] = len(custody)

    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Generate a CyberTrace-DFIR investigation summary."
    )
    parser.add_argument(
        "--inventory",
        default="reports/evidence_inventory.json",
    )
    parser.add_argument("--indicators")
    parser.add_argument("--custody")
    parser.add_argument(
        "--output",
        default="reports/investigation_summary.json",
    )
    args = parser.parse_args()

    try:
        summary = build_summary(
            Path(args.inventory),
            Path(args.indicators) if args.indicators else None,
            Path(args.custody) if args.custody else None,
        )

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(summary, indent=2),
            encoding="utf-8",
        )

        print(f"Summary saved to: {output_path}")
        print(f"Files inventoried: {summary['total_files']}")
        print(f"Files hashed: {summary['files_with_hashes']}")
        print(f"Files with errors: {summary['files_with_errors']}")

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Error: {exc}")


if __name__ == "__main__":
    main()