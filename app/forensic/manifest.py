import argparse
import json
from pathlib import Path

from app.forensic.hashing import calculate_sha256
from app.forensic.signatures import analyze_file_type


def build_record(file_path: str) -> dict:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Evidence path is not a file: {path}")

    signature_info = analyze_file_type(str(path))

    return {
        "file_name": path.name,
        "file_path": str(path),
        "file_size_bytes": path.stat().st_size,
        "sha256": calculate_sha256(str(path)),
        "extension": path.suffix or "(no extension)",
        "detected_format": signature_info["detected_format"],
    }


def create_manifest(file_paths: list[str], output_path: str) -> None:
    records = [build_record(file_path) for file_path in file_paths]

    manifest = {
        "tool": "CyberTrace-DFIR",
        "manifest_version": 1,
        "evidence_count": len(records),
        "evidence": records,
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(manifest, indent=4),
        encoding="utf-8",
    )

    print(f"Manifest saved to: {output}")
    print(f"Evidence files recorded: {len(records)}")


def verify_manifest(manifest_path: str) -> None:
    manifest = json.loads(
        Path(manifest_path).read_text(encoding="utf-8")
    )

    for record in manifest["evidence"]:
        path = Path(record["file_path"])

        if not path.is_file():
            print(f"MISSING: {record['file_name']}")
            continue

        current_hash = calculate_sha256(str(path))

        if current_hash == record["sha256"]:
            print(f"UNCHANGED: {record['file_name']}")
        else:
            print(f"CHANGED: {record['file_name']}")


def main():
    parser = argparse.ArgumentParser(
        description="Create and verify a digital evidence manifest."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser(
        "create", help="Create an evidence manifest"
    )
    create_parser.add_argument(
        "files", nargs="+", help="Evidence file paths"
    )
    create_parser.add_argument(
        "--output",
        default="reports/evidence_manifest.json",
        help="Output JSON path",
    )

    verify_parser = subparsers.add_parser(
        "verify", help="Verify files against a saved manifest"
    )
    verify_parser.add_argument(
        "manifest", help="Path to the saved JSON manifest"
    )

    args = parser.parse_args()

    try:
        if args.command == "create":
            create_manifest(args.files, args.output)
        elif args.command == "verify":
            verify_manifest(args.manifest)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()