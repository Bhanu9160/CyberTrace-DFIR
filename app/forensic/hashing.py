import hashlib
from pathlib import Path


def calculate_sha256(file_path: str) -> str:
    """
    Calculate the SHA-256 hash of a file.

    Reads the file in chunks so that large files
    do not need to be loaded into memory all at once.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Evidence path is not a file: {path}")

    sha256 = hashlib.sha256()

    with path.open("rb") as evidence_file:
        for chunk in iter(lambda: evidence_file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Calculate the SHA-256 hash of a digital evidence file."
    )
    parser.add_argument("file_path", help="Path to the evidence file")
    args = parser.parse_args()

    try:
        digest = calculate_sha256(args.file_path)
        print(f"Evidence file: {Path(args.file_path).name}")
        print(f"SHA-256: {digest}")
    except (FileNotFoundError, ValueError, PermissionError, OSError) as error:
        print(f"Error: {error}")
        raise SystemExit(1)