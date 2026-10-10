import argparse
import json
import re
from pathlib import Path


PATTERNS = {
    "IPv4 address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "URL": r"https?://[^\s]+",
    "Suspicious keyword": (
        r"(?i)\b(?:powershell\.exe|cmd\.exe|"
        r"encodedcommand|mimikatz|rundll32\.exe)\b"
    ),
}


def scan_text_file(file_path: str) -> dict:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    content = path.read_text(encoding="utf-8", errors="replace")
    findings = []

    for indicator_type, pattern in PATTERNS.items():
        matches = re.findall(pattern, content)

        for match in matches:
            findings.append({
                "type": indicator_type,
                "value": match,
            })

    return {
        "file_name": path.name,
        "findings_count": len(findings),
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Scan a text file for basic forensic indicators."
    )
    parser.add_argument("file_path", help="Path to the text evidence file")
    parser.add_argument(
        "--output",
        default="reports/indicator_report.json",
        help="JSON report output path",
    )
    args = parser.parse_args()

    try:
        result = scan_text_file(args.file_path)

        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, indent=4),
            encoding="utf-8",
        )

        print("=== CyberTrace-DFIR: Indicator Scan ===")
        print(f"File: {result['file_name']}")
        print(f"Findings: {result['findings_count']}")

        for finding in result["findings"]:
            print(f"- {finding['type']}: {finding['value']}")

        print(f"Report saved to: {output}")

    except (OSError, ValueError) as error:
        print(f"Error: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()