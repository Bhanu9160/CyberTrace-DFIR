
# CyberTrace-DFIR

A Python-based Digital Forensics and Incident Response toolkit

CyberTrace-DFIR is an educational DFIR project designed to help analysts examine digital evidence, verify file integrity, identify basic indicators, and organize investigation records.

Features

- SHA-256 hashing: Calculate file hashes for integrity verification.
- File metadata: Extract basic file properties and timestamps.
- File-signature detection: Compare file headers against selected known signatures.
- Evidence manifests: Record evidence hashes and verify whether files have changed.
- Indicator scanning: Search supported text files for selected IP addresses, URLs, and suspicious keywords.
- Case reports: Consolidate available evidence analysis results.
- Chain of custody: Record evidence-handling events.
- Forensic timelines: Organize recorded events chronologically.
- Evidence comparison: Compare file hashes to identify differences.
- Evidence inventory: Collect information about files in an examination folder.
- Investigation summaries: Consolidate inventory statistics and optional reports.
- Automated tests: Validate selected forensic functions.

Technology Stack

- Python
- hashlib
- pathlib
- argparse
- JSON
- pytest

Project Structure

CyberTrace-DFIR/
├── app/
│   └── forensic/
├── data/
├── samples/
├── reports/
├── tests/
├── requirements.txt
├── .gitignore
└── README.md

Setup

1. Install Python.
2. Clone the repository and open its directory.
3. Create and activate a virtual environment.

python -m venv .venv
.\.venv\Scripts\Activate.ps1

4. Install dependencies.

python -m pip install -r requirements.txt

5. Run an example hash calculation.

python -m app.forensic.hashing .\samples\sample.txt

Replace "sample.txt" with an existing file in your samples directory.

Example Workflows

Calculate a file hash

python -m app.forensic.hashing .\samples\sample.txt

Detect a known file signature

python -m app.forensic.signatures .\samples\sample.jpg

Compare two evidence files

python -m app.forensic.compare_evidence .\samples\original.txt .\samples\copy.txt

Generate an evidence inventory

python -m app.forensic.evidence_inventory .\samples

Generate an investigation summary

python -m app.forensic.investigation_summary

Run automated tests

python -m pytest -v

Use filenames and optional arguments that match the files and CLI options implemented in your local version.

Security and Limitations

- Use only evidence you are authorized to examine.
- Preserve original evidence and analyze working copies where practical.
- A matching SHA-256 hash supports content-integrity verification against a trusted reference; it does not establish authenticity by itself.
- File-signature checks and text-based indicators are basic heuristics, not proof of malware or compromise.
- JSON manifests and chain-of-custody logs are not inherently tamper-proof.
- This project is educational and is not a replacement for validated forensic tools or formal evidence-handling procedures.

Future Improvements

- Streamlit web dashboard and evidence upload interface.
- Case management with persistent storage.
- Stronger audit logging and evidence access controls.
- Expanded automated tests and report formats.

Author

Bhanu Prakash Battula

Cybersecurity | Digital Forensics | Incident Response | Python
