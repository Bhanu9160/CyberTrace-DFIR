import argparse
from pathlib import Path

SIGNATURES = {
    "JPEG Image": bytes.fromhex("FFD8FF"),
    "PNG Image": bytes.fromhex("89504E470D0A1A0A"),
    "PDF Document": bytes.fromhex("25504446"),
    "ZIP Archive": bytes.fromhex("504B0304"),
}


def analyze_file_type(file_path: str) -> dict:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Evidence path is not a file: {path}")

    with path.open("rb") as file:
        header = file.read(16)

    detected_format = "Unknown / Unrecognized"
    signature_hex = header.hex().upper()

    for file_type, signature in SIGNATURES.items():
        if header.startswith(signature):
            detected_format = file_type
            break

    return {
        "file_name": path.name,
        "extension": path.suffix or "(no extension)",
        "detected_format": detected_format,
        "signature_hex": signature_hex,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Identify a file's format using its signature."
    )
    parser.add_argument("file_path", help="Path to the evidence file")
    args = parser.parse_args()

    try:
        result = analyze_file_type(args.file_path)

        print("\n=== CyberTrace-DFIR: File Signature Analysis ===")
        for key, value in result.items():
            print(f"{key.replace('_', ' ').title()}: {value}")

        if result["detected_format"] == "Unknown / Unrecognized":
            print("Note: The signature is not recognized by this tool.")

    except (FileNotFoundError, ValueError, PermissionError, OSError) as error:
        print(f"Error: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()