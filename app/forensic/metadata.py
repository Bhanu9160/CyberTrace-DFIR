import argparse
from datetime import datetime
from pathlib import Path


def analyze_metadata(file_path: str) -> dict:
    """
    Extract basic filesystem metadata from a file.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Evidence path is not a file: {path}")

    stat = path.stat()

    return {
        "file_name": path.name,
        "extension": path.suffix or "(no extension)",
        "file_size_bytes": stat.st_size,
        "created_time": datetime.fromtimestamp(
            stat.st_ctime
        ).astimezone().isoformat(timespec="seconds"),
        "modified_time": datetime.fromtimestamp(
            stat.st_mtime
        ).astimezone().isoformat(timespec="seconds"),
        "accessed_time": datetime.fromtimestamp(
            stat.st_atime
        ).astimezone().isoformat(timespec="seconds"),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Extract basic metadata from a digital evidence file."
    )

    parser.add_argument(
        "file_path",
        help="Path to the evidence file"
    )

    args = parser.parse_args()

    try:
        metadata = analyze_metadata(args.file_path)

        print("\n=== CyberTrace-DFIR: File Metadata ===")

        for key, value in metadata.items():
            print(f"{key.replace('_', ' ').title()}: {value}")

    except (FileNotFoundError, ValueError, PermissionError, OSError) as error:
        print(f"Error: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()