import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from app.forensic.hashing import calculate_sha256
from app.forensic.metadata import analyze_metadata
from app.forensic.signatures import analyze_file_type
from app.forensic.indicators import scan_text_file


def build_case_report(file_path: str, case_id: str) -> dict:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Evidence path is not a file: {path}")

    report = {
        "case_id": case_id,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "tool": "CyberTrace-DFIR",
        "evidence": {
            "metadata": analyze_metadata(str(path)),
            "sha256": calculate_sha256(str(path)),
            "file_signature": analyze_file_type(str(path)),
        },
        "indicator_scan": None,
        "notes": [
            "Automated findings require analyst review.",
            "A suspicious indicator alone does not prove malicious activity.",
        ],
    }

    # Scan only likely text-based evidence files.
    if path.suffix.lower() in {".txt", ".log", ".csv"}:
        report["indicator_scan"] = scan_text_file(str(path))

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Generate a CyberTrace-DFIR case report."
    )
    parser.add_argument("file_path", help="Path to the evidence file")
    parser.add_argument(
        "--case-id",
        default="CASE-001",
        help="Investigation case identifier",
    )
    parser.add_argument(
        "--output",
        default="reports/case_report.json",
        help="Where to save the report",
    )
    args = parser.parse_args()

    try:
        report = build_case_report(args.file_path, args.case_id)

        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, indent=4),
            encoding="utf-8",
        )

        print("=== CyberTrace-DFIR: Case Report ===")
        print(f"Case ID: {report['case_id']}")
        print(f"Evidence: {report['evidence']['metadata']['file_name']}")
        print(f"SHA-256: {report['evidence']['sha256']}")
        print(f"Report saved to: {output}")

    except (OSError, ValueError) as error:
        print(f"Error: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()