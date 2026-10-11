import hashlib

from app.forensic.hashing import calculate_sha256


def test_sha256_matches_known_value(tmp_path):
    evidence = tmp_path / "evidence.txt"
    evidence.write_bytes(b"CyberTrace test")

    expected = hashlib.sha256(b"CyberTrace test").hexdigest()

    assert calculate_sha256(evidence) == expected


def test_modified_file_has_different_hash(tmp_path):
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"

    first.write_bytes(b"original evidence")
    second.write_bytes(b"modified evidence")

    assert calculate_sha256(first) != calculate_sha256(second)