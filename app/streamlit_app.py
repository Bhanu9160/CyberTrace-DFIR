import streamlit as st
from pathlib import Path
import json
import hashlib
import pandas as pd
from datetime import datetime, timezone
from app.forensic.severity_classifier import classify_event
from streamlit_autorefresh import st_autorefresh

from app.forensic.hashing import calculate_sha256
from app.forensic.metadata import analyze_metadata
from app.forensic.signatures import analyze_file_type
from app.forensic.severity_classifier import classify_event


# --------------------------------------------------
# PATHS AND CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"
UPLOAD_DIR = BASE_DIR / "data" / "uploads"

LIVE_EVENTS_FILE = (
    BASE_DIR / "data" / "live_events" / "windows_events.jsonl"
)

LOGIN_ALERTS_FILE = REPORT_DIR / "login_alerts.json"
TIMELINE_FILE = REPORT_DIR / "forensic_timeline.json"

REPORT_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
LIVE_EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)

st.set_page_config(
    page_title="CyberTrace-DFIR",
    page_icon="🔎",
    layout="wide",
)


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def load_live_events():
    """Load normalized Windows events from JSONL storage."""
    events = []

    if not LIVE_EVENTS_FILE.exists():
        return events

    try:
        with LIVE_EVENTS_FILE.open("r", encoding="utf-8") as file:
            for line in file:
                try:
                    record = json.loads(line)

                    if isinstance(record, dict):
                        events.append(record)

                except json.JSONDecodeError:
                    continue

    except OSError as exc:
        st.error(f"Could not read live events: {exc}")

    return events


def load_evidence_records():
    """Load evidence records created by the upload workflow."""
    records = []

    for report_path in REPORT_DIR.glob("*.json"):
        if report_path.name in {
            "chain_of_custody.json",
            "login_alerts.json",
            "forensic_timeline.json",
        }:
            continue

        try:
            data = json.loads(
                report_path.read_text(encoding="utf-8")
            )

            if (
                isinstance(data, dict)
                and data.get("evidence_id")
                and data.get("sha256")
            ):
                records.append(data)

        except (OSError, json.JSONDecodeError):
            continue

    return records


def load_json_report(path):
    """Load a JSON report safely."""
    if not path.exists():
        return None

    try:
        return json.loads(
            path.read_text(encoding="utf-8")
        )

    except (OSError, json.JSONDecodeError) as exc:
        st.warning(f"Could not read {path.name}: {exc}")
        return None


def display_report(report, title):
    """Display JSON reports as tables where possible."""
    st.subheader(title)

    if report is None:
        st.info(
            "Report not found. Run the corresponding module first."
        )
        return

    if isinstance(report, list):
        if not report:
            st.info("No entries are present in this report.")
            return

        df = pd.json_normalize(report)

        timestamp_column = next(
            (
                column
                for column in df.columns
                if column.lower() in {
                    "timestamp",
                    "timestamp_utc",
                    "time",
                    "time_utc",
                }
            ),
            None,
        )

        if timestamp_column:
            df = df.sort_values(
                timestamp_column,
                ascending=False,
                na_position="last",
            )

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )

    elif isinstance(report, dict):
        # Support common report formats with nested lists.
        list_key = next(
            (
                key
                for key in (
                    "alerts",
                    "events",
                    "timeline",
                    "entries",
                    "records",
                )
                if isinstance(report.get(key), list)
            ),
            None,
        )

        if list_key is not None:
            entries = report[list_key]

            if entries:
                df = pd.json_normalize(entries)

                st.dataframe(
                    df,
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info(f"No entries found in '{list_key}'.")

            with st.expander("View complete report"):
                st.json(report)

        else:
            st.json(report)

    else:
        st.warning(
            "The report has an unsupported JSON structure."
        )


# --------------------------------------------------
# APPLICATION HEADER
# --------------------------------------------------

st.title("🔎 CyberTrace-DFIR")
st.caption("Digital Forensics & Incident Response Workbench")

st.sidebar.title("Navigation")

page = st.sidebar.radio(
    "Select a page",
    [
        "Dashboard",
        "Live Monitoring",
        "Evidence Upload",
        "Forensic Analysis",
        "Case Management",
        "Chain of Custody",
        "Reports",
    ],
)

evidence_files = [
    p for p in UPLOAD_DIR.rglob("*") if p.is_file()
]

report_files = list(REPORT_DIR.glob("*.json"))


# --------------------------------------------------
# 1. DASHBOARD
# --------------------------------------------------

if page == "Dashboard":
    st.header("Investigation Overview")

    col1, col2, col3 = st.columns(3)

    col1.metric("Stored evidence files", len(evidence_files))
    col2.metric("JSON reports", len(report_files))
    col3.metric("Application", "Running")

    st.divider()

    st.subheader("Quick Start")

    st.write(
        "Use Evidence Upload to add authorized evidence files. "
        "Forensic Analysis displays recorded hashes and analysis "
        "information. Case Management organizes evidence by case. "
        "Live Monitoring displays collected Windows events, "
        "login detection alerts, and the investigation timeline."
    )


# --------------------------------------------------
# 2. LIVE MONITORING
# --------------------------------------------------

elif page == "Live Monitoring":
    st.header("🖥️ Live Windows Event Monitoring")

    st.caption(
        "Events collected by the CyberTrace-DFIR Windows collector"
    )

    refresh_enabled = st.toggle(
        "Refresh automatically every 10 seconds",
        value=True,
    )

    if refresh_enabled:
        st_autorefresh(
            interval=10_000,
            key="cybertrace_live_refresh",
        )

    events = load_live_events()
    events_df = pd.DataFrame(events)

    if not events_df.empty:
        events_df["Severity"] = events_df.apply(
        lambda row: classify_event(row.to_dict()),
        axis=1
    )

    if not events:
        st.info(
            "No events found yet. Start the Windows event collector "
            "in a separate terminal."
        )

        st.code(
            "python -m app.forensic.live_event_collector",
            language="powershell",
        )

    else:
        df = pd.DataFrame(events)

        # ------------------------------
        # FILTERS
        # ------------------------------

        filter_col1, filter_col2, filter_col3 = st.columns(3)

        if "log_name" in df.columns:
            log_names = sorted(
                str(value)
                for value in df["log_name"].dropna().unique()
            )

            selected_log = filter_col1.selectbox(
                "Windows log",
                ["All"] + log_names,
            )
        else:
            selected_log = "All"

        if "severity" in df.columns:
            severities = sorted(
                str(value)
                for value in df["severity"].dropna().unique()
            )

            selected_severity = filter_col2.selectbox(
                "Severity",
                ["All"] + severities,
            )
        else:
            selected_severity = "All"

        search_text = filter_col3.text_input(
            "Search event messages",
            placeholder="Enter a keyword...",
        )

        filtered_df = df.copy()

        if (
            selected_log != "All"
            and "log_name" in filtered_df.columns
        ):
            filtered_df = filtered_df[
                filtered_df["log_name"].astype(str)
                == selected_log
            ]

        if (
            selected_severity != "All"
            and "severity" in filtered_df.columns
        ):
            filtered_df = filtered_df[
                filtered_df["severity"].astype(str)
                == selected_severity
            ]

        if search_text:
            searchable_columns = [
                column
                for column in [
                    "message",
                    "provider",
                    "host",
                    "event_id",
                ]
                if column in filtered_df.columns
            ]

            if searchable_columns:
                matches = pd.Series(
                    False,
                    index=filtered_df.index,
                )

                for column in searchable_columns:
                    matches |= filtered_df[column].astype(
                        str
                    ).str.contains(
                        search_text,
                        case=False,
                        regex=False,
                        na=False,
                    )

                filtered_df = filtered_df[matches]

        # ------------------------------
        # METRICS
        # ------------------------------

        st.divider()

        col1, col2, col3 = st.columns(3)

        col1.metric("Stored events", len(df))

        if "event_id" in df.columns:
            col2.metric(
                "Distinct event types",
                df["event_id"].nunique(),
            )
        else:
            col2.metric("Distinct event types", "N/A")

        if "host" in df.columns:
            col3.metric(
                "Hosts",
                df["host"].nunique(),
            )
        else:
            col3.metric("Hosts", "N/A")

        # ------------------------------
        # EVENT TABLE
        # ------------------------------

        st.subheader("Collected Events")

        st.caption(
            f"Showing {min(len(filtered_df), 100)} of "
            f"{len(filtered_df)} filtered events. "
            "The underlying JSONL file contains the stored records."
        )

        if "timestamp_utc" in filtered_df.columns:
            filtered_df = filtered_df.sort_values(
                "timestamp_utc",
                ascending=False,
                na_position="last",
            )

        display_columns = [
            column
            for column in [
                "timestamp_utc",
                "host",
                "log_name",
                "event_id",
                "record_id",
                "severity",
                "provider",
                "message",
            ]
            if column in filtered_df.columns
        ]

        if filtered_df.empty:
            st.warning("No events match the selected filters.")

        else:
            st.dataframe(
                filtered_df[display_columns].head(100),
                use_container_width=True,
                hide_index=True,
            )

            st.download_button(
                "Download filtered events as CSV",
                data=filtered_df[display_columns].to_csv(
                    index=False
                ),
                file_name="cybertrace_windows_events.csv",
                mime="text/csv",
            )

        with st.expander("View raw event record"):
            if not filtered_df.empty:
                st.json(
                    filtered_df.iloc[0].to_dict()
                )

    # ------------------------------
    # LOGIN DETECTION ALERTS
    # ------------------------------

    st.divider()

    display_report(
        load_json_report(LOGIN_ALERTS_FILE),
        "🚨 Login Detection Alerts",
    )

    # ------------------------------
    # INVESTIGATION TIMELINE
    # ------------------------------

    st.divider()

    display_report(
        load_json_report(TIMELINE_FILE),
        "🕒 Investigation Timeline",
    )

    st.caption(
        "The collector, login detector, and timeline generator "
        "run separately. This dashboard reads their saved output "
        "and does not automatically execute those modules."
    )


# --------------------------------------------------
# 3. EVIDENCE UPLOAD
# --------------------------------------------------

elif page == "Evidence Upload":
    st.header("Evidence Upload")

    st.write(
        "Upload an authorized file for forensic examination."
    )

    case_id = st.text_input(
        "Case ID",
        value="CASE-001",
    )

    uploaded_file = st.file_uploader(
        "Choose an evidence file",
        type=None,
    )

    if uploaded_file is not None:
        st.write("Filename:", uploaded_file.name)

        st.write(
            "File size:",
            f"{uploaded_file.size:,} bytes",
        )

        if uploaded_file.size > 20 * 1024 * 1024:
            st.error("File exceeds the 20 MB limit.")

        elif st.button(
            "Save and analyze",
            type="primary",
        ):
            if not case_id.strip():
                st.error("Enter a Case ID.")

            else:
                evidence_id = datetime.now(
                    timezone.utc
                ).strftime("EVD-%Y%m%dT%H%M%S%fZ")

                evidence_dir = UPLOAD_DIR / evidence_id

                evidence_dir.mkdir(
                    parents=True,
                    exist_ok=False,
                )

                safe_name = Path(uploaded_file.name).name
                evidence_path = evidence_dir / safe_name

                content = uploaded_file.getvalue()

                evidence_path.write_bytes(content)

                digest = hashlib.sha256(
                    content
                ).hexdigest()

                record = {
                    "case_id": case_id.strip(),
                    "evidence_id": evidence_id,
                    "filename": safe_name,
                    "size_bytes": len(content),
                    "sha256": digest,
                    "received_at_utc": datetime.now(
                        timezone.utc
                    ).isoformat(),
                }

                report_path = (
                    REPORT_DIR / f"{evidence_id}.json"
                )

                report_path.write_text(
                    json.dumps(record, indent=2),
                    encoding="utf-8",
                )

                st.success(
                    "Evidence saved successfully!"
                )

                st.write("Evidence ID:", evidence_id)

                st.write("SHA-256:")
                st.code(digest)

                st.download_button(
                    "Download evidence report",
                    data=json.dumps(record, indent=2),
                    file_name=f"{evidence_id}_report.json",
                    mime="application/json",
                )


# --------------------------------------------------
# 4. FORENSIC ANALYSIS
# --------------------------------------------------

elif page == "Forensic Analysis":
    st.header("🔎 Forensic Analysis")

    st.write(
        "Examine evidence already stored in CyberTrace-DFIR."
    )

    evidence_items = load_evidence_records()

    if not evidence_items:
        st.info(
            "Upload evidence first to begin analysis."
        )

    else:
        selected_id = st.selectbox(
            "Select evidence",
            options=[
                item["evidence_id"]
                for item in evidence_items
            ],
        )

        record = next(
            item
            for item in evidence_items
            if item["evidence_id"] == selected_id
        )

        st.subheader("Evidence details")

        col1, col2 = st.columns(2)

        col1.metric(
            "Case ID",
            record.get("case_id", "Unknown"),
        )

        col2.metric(
            "File size",
            f"{record.get('size_bytes', 0):,} bytes",
        )

        st.write(
            "Filename:",
            record.get("filename", "Unknown"),
        )

        st.write(
            "Evidence ID:",
            record["evidence_id"],
        )

        st.subheader("Recorded SHA-256")
        st.code(record["sha256"])

        st.subheader("Recorded metadata")
        st.json(record.get("metadata", {}))

        st.subheader("File signature analysis")
        st.json(record.get("file_type_analysis", {}))

        if st.button("Verify stored evidence integrity"):
            evidence_path = (
                UPLOAD_DIR
                / record["evidence_id"]
                / record.get("filename", "")
            )

            if not evidence_path.is_file():
                st.error(
                    "Stored evidence file is missing."
                )

            else:
                current_hash = hashlib.sha256(
                    evidence_path.read_bytes()
                ).hexdigest()

                if current_hash == record["sha256"]:
                    st.success(
                        "Integrity check passed: the stored file "
                        "matches its recorded SHA-256 hash."
                    )

                else:
                    st.error(
                        "INTEGRITY MISMATCH: the stored file differs "
                        "from its recorded SHA-256 hash."
                    )

                st.write("Current SHA-256")
                st.code(current_hash)


# --------------------------------------------------
# 5. CASE MANAGEMENT
# --------------------------------------------------

elif page == "Case Management":
    st.header("📁 Case Management")

    st.write(
        "Review investigation cases and their evidence records."
    )

    records = load_evidence_records()

    records = [
        record
        for record in records
        if record.get("case_id")
    ]

    cases = sorted({
        record["case_id"]
        for record in records
    })

    col1, col2 = st.columns(2)

    col1.metric("Cases found", len(cases))
    col2.metric("Evidence records", len(records))

    st.divider()
    st.subheader("Investigation cases")

    if not cases:
        st.info(
            "No evidence records found yet. Upload a file and "
            "assign a Case ID first."
        )

    else:
        selected_case = st.selectbox(
            "Select a case",
            cases,
        )

        case_records = [
            record
            for record in records
            if record["case_id"] == selected_case
        ]

        st.subheader(f"Case: {selected_case}")

        st.write(
            f"Evidence items: {len(case_records)}"
        )

        rows = []

        for record in case_records:
            metadata = record.get("metadata", {})

            rows.append({
                "Evidence ID": record["evidence_id"],
                "Filename": record.get(
                    "filename",
                    metadata.get("file_name", "Unknown"),
                ),
                "Size (bytes)": record.get(
                    "size_bytes",
                    metadata.get("file_size_bytes", 0),
                ),
                "SHA-256": record["sha256"],
                "Received UTC": record.get(
                    "received_at_utc",
                    "Not recorded",
                ),
            })

        st.dataframe(
            rows,
            use_container_width=True,
        )

        export_data = {
            "case_id": selected_case,
            "evidence_count": len(case_records),
            "evidence": case_records,
        }

        st.download_button(
            "Download case evidence summary",
            data=json.dumps(export_data, indent=2),
            file_name=f"{selected_case}_evidence.json",
            mime="application/json",
        )

        st.caption(
            "This page reads evidence records from JSON reports. "
            "It does not yet provide persistent case editing or "
            "a tamper-resistant audit trail."
        )
        # --------------------------------------------------
# 6. CHAIN OF CUSTODY
# --------------------------------------------------

elif page == "Chain of Custody":
    st.header("🔐 Chain of Custody")

    st.write(
        "Record evidence-handling events for an investigation."
    )

    custody_path = REPORT_DIR / "chain_of_custody.json"

    if custody_path.exists():
        try:
            events = json.loads(
                custody_path.read_text(encoding="utf-8")
            )

            if not isinstance(events, list):
                events = []

        except (OSError, json.JSONDecodeError):
            events = []
        except (OSError, json.JSONDecodeError):
            events = []

            st.error(
                "Could not read the custody log."
            )

    else:
        events = []

    with st.form("custody_form"):
        evidence_id = st.text_input("Evidence ID")

        case_id = st.text_input(
            "Case ID",
            value="CASE-001",
        )

        handler = st.text_input(
            "Analyst / Handler"
        )

        action = st.selectbox(
            "Action",
            [
                "Evidence received",
                "Hash calculated",
                "Evidence examined",
                "Evidence transferred",
                "Evidence returned",
            ],
        )
        reason = st.text_area("Reason for action")

        submitted = st.form_submit_button(
            "Record event"
        )

    if submitted:
        if not all([
            evidence_id.strip(),
            case_id.strip(),
            handler.strip(),
            reason.strip(),
        ]):
            st.error(
                "Complete all fields before recording."
            )

        else:
            event = {
                "event_id": f"CUST-{len(events) + 1:04d}",
                "evidence_id": evidence_id.strip(),
                "case_id": case_id.strip(),
                "handler": handler.strip(),
                "action": action,
                "reason": reason.strip(),
                "timestamp_utc": datetime.now(
                    timezone.utc
                ).isoformat(),
            }
            events.append(event)

            custody_path.write_text(
                json.dumps(events, indent=2),
                encoding="utf-8",
            )

            st.success(
                "Custody event recorded."
            )

            st.rerun()

    st.divider()
    st.subheader("Custody history")

    if events:
        st.dataframe(
            events,
            use_container_width=True,
        )

        st.download_button(
            "Download chain-of-custody log",
            data=json.dumps(events, indent=2),
            file_name="chain_of_custody.json",
            mime="application/json",
        )

    else:
        st.info(
            "No custody events recorded yet."
        )
        # --------------------------------------------------
# 7. REPORTS
# --------------------------------------------------

elif page == "Reports":
    st.header("📄 Investigation Reports")

    case_id = st.text_input(
        "Case ID",
        value="CASE-001",
        key="report_case_id",
    )

    evidence_records = [
        record
        for record in load_evidence_records()
        if record.get("case_id") == case_id.strip()
    ]

    custody_path = REPORT_DIR / "chain_of_custody.json"
    custody_events = []

    if custody_path.exists():
        try:
            events = json.loads(
                custody_path.read_text(encoding="utf-8")
            )
            if isinstance(events, list):
                custody_events = [
                    event
                    for event in events
                    if isinstance(event, dict)
                    and event.get("case_id") == case_id.strip()
                ]

        except (OSError, json.JSONDecodeError):
            st.error(
                "Could not read the chain-of-custody log."
            )

    col1, col2 = st.columns(2)

    col1.metric(
        "Evidence records",
        len(evidence_records),
    )

    col2.metric(
        "Custody events",
        len(custody_events),
    )

    if st.button("Generate investigation report"):
        if not case_id.strip():
            st.error(
                "Enter a valid Case ID."
            )
        else:
            report = {
                "report_type": (
                    "CyberTrace-DFIR Investigation Report"
                ),
                "case_id": case_id.strip(),
                "generated_at_utc": datetime.now(
                    timezone.utc
                ).isoformat(),
                "evidence_count": len(evidence_records),
                "evidence": evidence_records,
                "custody_event_count": len(custody_events),
                "chain_of_custody": custody_events,
                "limitations": [
                    "Analyst review is required.",
                    "SHA-256 supports integrity verification "
                    "against a trusted reference.",
                    "JSON records are editable and are not "
                    "tamper-proof.",
                ],
            }

            st.session_state["consolidated_report"] = json.dumps(
                report,
                indent=2,
            )
            st.success(
                "Investigation report generated."
            )

    report_json = st.session_state.get(
        "consolidated_report"
    )

    if report_json:
        try:
            report_data = json.loads(report_json)

            if report_data.get("case_id") == case_id.strip():
                st.subheader("Report preview")
                st.json(report_data)

                st.download_button(
                    "Download investigation report",
                    data=report_json,
                    file_name=(
                        f"{case_id.strip()}_investigation_report.json"
                    ),
                    mime="application/json",
                )

        except json.JSONDecodeError:
            st.error(
                "The generated report could not be decoded."
            )