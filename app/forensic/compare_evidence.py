import argparse
from pathlib import Path

from app.forensic.hashing import calculate_sha256


def compare_evidence(file1, file2):
    path1 = Path(file1)
    path2 = Path(file2)

    if not path1.is_file():
        raise FileNotFoundError(f"First file not found: {path1}")

    if not path2.is_file():
        raise FileNotFoundError(f"Second file not found: {path2}")

    hash1 = calculate_sha256(str(path1))
    hash2 = calculate_sha256(str(path2))

    return {
        "file1": str(path1),
        "file2": str(path2),
        "sha256_file1": hash1,
        "sha256_file2": hash2,
        "identical_content": hash1 == hash2,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Compare two evidence files using SHA-256."
    )
    parser.add_argument("file1", help="Path to the first evidence file")
    parser.add_argument("file2", help="Path to the second evidence file")
    args = parser.parse_args()

    try:
        result = compare_evidence(args.file1, args.file2)

        print("=== CyberTrace-DFIR: Evidence Comparison ===")
        print(f"File 1: {result['file1']}")
        print(f"SHA-256: {result['sha256_file1']}")
        print()
        print(f"File 2: {result['file2']}")
        print(f"SHA-256: {result['sha256_file2']}")
        print()

        if result["identical_content"]:
            print("RESULT: MATCH - file contents are identical.")
        else:
            print("RESULT: MISMATCH - file contents differ.")

    except (OSError, ValueError) as error:
        print(f"Error: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()