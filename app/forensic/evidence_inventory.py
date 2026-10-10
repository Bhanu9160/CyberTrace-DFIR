import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from app.forensic.hashing import calculate_sha256
from app.forensic.signatures import analyze_file_type


def build_inventory(folder_path):
    folder = Path(folder_path)

    if not folder.is_dir():
        raise NotADirectoryError(
            f"Evidence folder not found: {folder}"
        )

    records = []

    for path in sorted(folder.rglob("*")):
        if not path.is_file():
            continue

        try:
            record = {
                "file_name": path.name,
                "relative_path": str(path.relative_to(folder)),
                "file_size_bytes": path.stat().st_size,
                "sha256": calculate_sha256(str(path)),
                "file_signature": analyze_file_type(str(path)),
            }

            records.append(record)

        except OSError as error:
            records.append({
                "file_name": path.name,
                "relative_path": str(path.relative_to(folder)),
                "error": str(error),
            })

    return {
        "tool": "CyberTrace-DFIR",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "evidence_folder": str(folder.resolve()),
        "total_files": len(records),
        "files": records,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Create a forensic evidence inventory."
    )
    parser.add_argument(
        "folder",
        help="Folder containing evidence files",
    )
    parser.add_argument(
        "--output",
        default="reports/evidence_inventory.json",
        help="Output JSON file",
    )
    args = parser.parse_args()

    try:
        inventory = build_inventory(args.folder)

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(inventory, indent=4),
            encoding="utf-8",
        )

        print("=== CyberTrace-DFIR: Evidence Inventory ===")
        print(f"Files processed: {inventory['total_files']}")

        for item in inventory["files"]:
            if "sha256" in item:
                print(
                    f"{item['relative_path']} | "
                    f"{item['file_size_bytes']} bytes | "
                    f"SHA-256: {item['sha256']}"
                )
            else:
                print(
                    f"{item['relative_path']} | "
                    f"ERROR: {item['error']}"
                )

        print(f"Inventory saved to: {output_path}")

    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Error: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()