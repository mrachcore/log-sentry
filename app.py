import html
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from utils.detection_rules import calculate_detection_summary, run_detection_rules
from utils.log_parser import (
    count_severity_keywords,
    detect_log_type,
    extract_ipv4_addresses,
    load_sample_log,
    preview_lines,
    read_uploaded_log,
    split_lines,
)
from utils.report_generator import findings_to_csv, generate_text_report


APP_DIR = Path(__file__).parent
LOGO_PATH = APP_DIR / "assets" / "logo.png"
SAMPLE_LOGS_DIR = APP_DIR / "sample_logs"
SUSPICIOUS_PATHS = ["/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/config", "/backup"]
KEYWORDS = ["error", "failed", "denied", "timeout", "unauthorized"]


st.set_page_config(
    page_title="LogSentry by mrachcore",
    page_icon=str(LOGO_PATH),
    layout="wide",
    initial_sidebar_state="expanded",
)


def apply_custom_css():
    """Add custom dark dashboard styling."""
    st.markdown(
        """
        <style>
        :root {
            --bg: #07111f;
            --panel: #0e1b2d;
            --panel-soft: #13233a;
            --border: rgba(120, 190, 255, 0.18);
            --text: #edf6ff;
            --muted: #9fb4c8;
            --cyan: #33d6ff;
            --blue: #4f8dff;
            --amber: #f6b73c;
            --orange: #ff7a2f;
            --red: #ff4d5a;
        }

        .stApp {
            background:
                radial-gradient(circle at top left, rgba(51, 214, 255, 0.12), transparent 34%),
                linear-gradient(135deg, #06101d 0%, #081522 45%, #0b111b 100%);
            color: var(--text);
        }

        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #081421 0%, #0b1726 100%);
            border-right: 1px solid var(--border);
        }

        [data-testid="stSidebar"] img {
            border-radius: 12px;
            box-shadow: 0 0 26px rgba(51, 214, 255, 0.18);
        }

        h1, h2, h3 {
            color: var(--text);
            letter-spacing: 0;
        }

        p, li, span, div {
            color: inherit;
        }

        .main-header {
            display: flex;
            gap: 22px;
            align-items: center;
            padding: 18px 20px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: linear-gradient(135deg, rgba(19, 35, 58, 0.92), rgba(8, 19, 33, 0.96));
            margin-bottom: 22px;
            box-shadow: 0 18px 42px rgba(0, 0, 0, 0.22);
        }

        .header-logo {
            width: 88px;
            height: 88px;
            object-fit: cover;
            border-radius: 8px;
            border: 1px solid rgba(51, 214, 255, 0.35);
        }

        .title {
            font-size: 2.4rem;
            font-weight: 800;
            line-height: 1.05;
            margin: 0;
        }

        .subtitle {
            color: var(--cyan);
            font-size: 1rem;
            margin-top: 4px;
        }

        .tagline {
            color: var(--muted);
            margin-top: 8px;
        }

        .card, .metric-card, .finding-card, .report-box {
            border: 1px solid var(--border);
            border-radius: 8px;
            background: rgba(14, 27, 45, 0.92);
            padding: 18px;
            box-shadow: 0 12px 28px rgba(0, 0, 0, 0.18);
        }

        .metric-card {
            min-height: 112px;
        }

        .metric-label {
            color: var(--muted);
            font-size: 0.82rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        .metric-value {
            color: var(--text);
            font-size: 2rem;
            font-weight: 800;
            margin-top: 8px;
        }

        .metric-note {
            color: var(--muted);
            font-size: 0.86rem;
            margin-top: 4px;
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 0.78rem;
            font-weight: 700;
            border: 1px solid transparent;
        }

        .badge-info { color: #bdeeff; background: rgba(51, 214, 255, 0.14); border-color: rgba(51, 214, 255, 0.35); }
        .badge-warning { color: #ffe2a6; background: rgba(246, 183, 60, 0.14); border-color: rgba(246, 183, 60, 0.4); }
        .badge-high { color: #ffd3bd; background: rgba(255, 122, 47, 0.16); border-color: rgba(255, 122, 47, 0.42); }
        .badge-critical { color: #ffd1d5; background: rgba(255, 77, 90, 0.16); border-color: rgba(255, 77, 90, 0.45); }

        .terminal-box {
            background: #030912;
            color: #d7ecff;
            border: 1px solid rgba(51, 214, 255, 0.22);
            border-radius: 8px;
            padding: 16px;
            font-family: Consolas, "Courier New", monospace;
            font-size: 0.9rem;
            line-height: 1.55;
            max-height: 430px;
            overflow: auto;
            white-space: pre-wrap;
        }

        .finding-card {
            margin-bottom: 14px;
        }

        .finding-meta {
            color: var(--muted);
            font-size: 0.86rem;
            margin-top: 6px;
        }

        .report-box {
            white-space: pre-wrap;
            font-family: Consolas, "Courier New", monospace;
            background: #08111e;
        }

        div[data-testid="stMetric"] {
            background: rgba(14, 27, 45, 0.92);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
        }

        .stDataFrame, .stTable {
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def initialize_state():
    """Create session-state values the first time the app runs."""
    defaults = {
        "log_content": "",
        "file_name": "",
        "file_size": 0,
        "log_type": "",
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def render_header():
    """Render the shared app header."""
    col_logo, col_text = st.columns([1, 6])
    with col_logo:
        if LOGO_PATH.exists():
            st.image(str(LOGO_PATH), use_container_width=True)
    with col_text:
        st.markdown(
            """
            <div class="card">
                <div class="title">LogSentry</div>
                <div class="subtitle">by mrachcore</div>
                <div class="tagline">Local log investigation & incident analysis dashboard</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_metric_card(label, value, note=""):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{html.escape(str(label))}</div>
            <div class="metric-value">{html.escape(str(value))}</div>
            <div class="metric-note">{html.escape(str(note))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_status_badge(severity):
    css_name = severity.lower().replace(" ", "-")
    return f'<span class="badge badge-{css_name}">{html.escape(severity)}</span>'


def render_terminal_box(text):
    st.markdown(f'<div class="terminal-box">{html.escape(text)}</div>', unsafe_allow_html=True)


def render_finding_card(finding):
    st.markdown(
        f"""
        <div class="finding-card">
            {render_status_badge(finding.get("severity", "INFO"))}
            <strong style="margin-left: 8px;">{html.escape(finding.get("category", "Unknown"))}</strong>
            <div style="margin-top: 10px;">{html.escape(finding.get("description", ""))}</div>
            <div class="finding-meta">Line {finding.get("line_number", "-")}: {html.escape(finding.get("line_preview", ""))}</div>
            <div class="finding-meta">Recommendation: {html.escape(finding.get("recommendation", ""))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def get_current_lines():
    return split_lines(st.session_state.get("log_content", ""))


def has_log():
    return bool(st.session_state.get("log_content", "").strip())


def show_no_log_message():
    st.info("No log file is loaded yet. Go to Upload Logs and upload a .log/.txt file or load a sample log.")


def build_overview(lines):
    severity_counts = count_severity_keywords(lines)
    ip_addresses = extract_ipv4_addresses(lines)

    return {
        "total_lines": len(lines),
        "empty_lines": sum(1 for line in lines if not line.strip()),
        "error_count": severity_counts.get("ERROR", 0) + severity_counts.get("ERR", 0),
        "warning_count": severity_counts.get("WARNING", 0) + severity_counts.get("WARN", 0),
        "critical_count": severity_counts.get("CRITICAL", 0),
        "failed_denied_count": severity_counts.get("FAILED", 0) + severity_counts.get("DENIED", 0),
        "detected_ip_count": len(ip_addresses),
        "unique_ip_count": len(set(ip_addresses)),
        "severity_counts": severity_counts,
    }


def build_ip_summary(lines):
    ip_addresses = extract_ipv4_addresses(lines)
    ip_counter = Counter(ip_addresses)
    failed_ip_counter = Counter()
    path_counter = Counter()
    keyword_counter = Counter()

    for line in lines:
        lower_line = line.lower()

        if any(pattern in lower_line for pattern in ["failed password", "authentication failure", "login failed", "invalid user"]):
            failed_ip_counter.update(extract_ipv4_addresses([line]))

        for path in SUSPICIOUS_PATHS:
            if path in lower_line:
                path_counter[path] += 1

        for keyword in KEYWORDS:
            if keyword in lower_line:
                keyword_counter[keyword] += 1

    return {
        "ip_counter": ip_counter,
        "top_ips": ip_counter.most_common(10),
        "failed_login_ips": failed_ip_counter.most_common(10),
        "top_patterns": path_counter.most_common(10),
        "keyword_counts": keyword_counter,
    }


def dashboard_page():
    render_header()
    st.markdown("A local dashboard for investigating log files and detecting suspicious patterns.")

    features = [
        ("Log upload", "Load .log or .txt files directly from your laptop."),
        ("Severity overview", "Count INFO, WARNING, ERROR, CRITICAL, FAILED, and DENIED events."),
        ("Failed login detection", "Spot authentication failures and repeated login attempts."),
        ("IP extraction", "Find IPv4 addresses and identify repeated sources."),
        ("Suspicious patterns", "Detect risky paths, HTTP errors, and threat keywords."),
        ("Incident report export", "Generate a simple TXT report and CSV findings table."),
    ]

    cols = st.columns(3)
    for index, (title, description) in enumerate(features):
        with cols[index % 3]:
            st.markdown(f'<div class="card"><h3>{title}</h3><p>{description}</p></div>', unsafe_allow_html=True)

    st.subheader("How to Use")
    st.markdown(
        """
        1. Upload a log file
        2. Review log overview
        3. Run detection rules
        4. Analyze IPs and patterns
        5. Export incident report
        """
    )


def upload_logs_page():
    render_header()
    st.subheader("Upload Logs")

    uploaded_file = st.file_uploader("Upload a .log or .txt file", type=["log", "txt"])

    if uploaded_file is not None:
        suffix = Path(uploaded_file.name).suffix.lower()
        if suffix not in [".log", ".txt"]:
            st.error("Invalid file type. Please upload a .log or .txt file.")
        else:
            content = read_uploaded_log(uploaded_file)
            if not content.strip():
                st.warning("The uploaded file is empty or could not be read.")
            else:
                st.session_state.log_content = content
                st.session_state.file_name = uploaded_file.name
                st.session_state.file_size = uploaded_file.size
                st.session_state.log_type = detect_log_type(content)
                st.success(f"Loaded {uploaded_file.name}")
                if uploaded_file.size > 5 * 1024 * 1024:
                    st.warning("This file is larger than 5 MB. Analysis still runs locally, but charts and tables may take longer to render.")

    st.markdown("#### Or load a sample log")
    sample_options = {
        "Authentication sample": SAMPLE_LOGS_DIR / "auth_sample.log",
        "Web server sample": SAMPLE_LOGS_DIR / "web_sample.log",
        "System sample": SAMPLE_LOGS_DIR / "system_sample.log",
    }
    selected_sample = st.selectbox("Sample log", list(sample_options.keys()))
    if st.button("Load selected sample"):
        sample_path = sample_options[selected_sample]
        content = load_sample_log(sample_path)
        st.session_state.log_content = content
        st.session_state.file_name = sample_path.name
        st.session_state.file_size = len(content.encode("utf-8"))
        st.session_state.log_type = detect_log_type(content)
        st.success(f"Loaded {sample_path.name}")

    if has_log():
        lines = get_current_lines()
        st.subheader("File Metadata")
        cols = st.columns(4)
        with cols[0]:
            render_metric_card("File name", st.session_state.file_name or "Unknown")
        with cols[1]:
            render_metric_card("File size", f"{st.session_state.file_size:,} bytes")
        with cols[2]:
            render_metric_card("Total lines", len(lines))
        with cols[3]:
            render_metric_card("Detected type", st.session_state.log_type or "Unknown")

        st.subheader("Raw Preview")
        render_terminal_box("\n".join(preview_lines(lines, 80)))


def log_overview_page():
    render_header()
    st.subheader("Log Overview")

    if not has_log():
        show_no_log_message()
        return

    lines = get_current_lines()
    overview = build_overview(lines)

    cols = st.columns(4)
    metrics = [
        ("Total lines", overview["total_lines"], "All parsed rows"),
        ("Empty lines", overview["empty_lines"], "Blank rows"),
        ("Errors", overview["error_count"], "ERROR / ERR"),
        ("Warnings", overview["warning_count"], "WARNING / WARN"),
        ("Critical", overview["critical_count"], "CRITICAL"),
        ("Failed / denied", overview["failed_denied_count"], "FAILED / DENIED"),
        ("IP mentions", overview["detected_ip_count"], "All IPv4 matches"),
        ("Unique IPs", overview["unique_ip_count"], "Distinct IPv4s"),
    ]

    for index, metric in enumerate(metrics):
        with cols[index % 4]:
            render_metric_card(*metric)

    st.subheader("Severity Keyword Distribution")
    severity_df = pd.DataFrame(
        [{"keyword": keyword, "count": count} for keyword, count in overview["severity_counts"].items()]
    )
    if severity_df.empty:
        st.info("No severity keywords were detected.")
    else:
        st.dataframe(severity_df, use_container_width=True)
        st.bar_chart(severity_df.set_index("keyword"))

    st.subheader("First 100 Lines")
    render_terminal_box("\n".join(preview_lines(lines, 100)))


def detection_rules_page():
    render_header()
    st.subheader("Detection Rules")

    if not has_log():
        show_no_log_message()
        return

    lines = get_current_lines()
    findings = run_detection_rules(lines)
    summary = calculate_detection_summary(findings)

    cols = st.columns(4)
    with cols[0]:
        render_metric_card("Total findings", summary["total_findings"])
    with cols[1]:
        render_metric_card("High", summary["by_severity"].get("HIGH", 0))
    with cols[2]:
        render_metric_card("Critical", summary["by_severity"].get("CRITICAL", 0))
    with cols[3]:
        render_metric_card("Categories", len(summary["by_category"]))

    if not findings:
        st.success("No suspicious patterns were detected by the current rules.")
        return

    st.subheader("Findings Table")
    st.dataframe(pd.DataFrame(findings), use_container_width=True)

    st.subheader("Finding Details")
    severity_filter = st.multiselect(
        "Filter by severity",
        ["INFO", "WARNING", "HIGH", "CRITICAL"],
        default=["INFO", "WARNING", "HIGH", "CRITICAL"],
    )
    for finding in findings:
        if finding["severity"] in severity_filter:
            render_finding_card(finding)


def ip_pattern_analysis_page():
    render_header()
    st.subheader("IP & Pattern Analysis")

    if not has_log():
        show_no_log_message()
        return

    lines = get_current_lines()
    ip_summary = build_ip_summary(lines)
    ip_counter = ip_summary["ip_counter"]

    cols = st.columns(3)
    with cols[0]:
        render_metric_card("Total IP mentions", sum(ip_counter.values()))
    with cols[1]:
        render_metric_card("Unique IPs", len(ip_counter))
    with cols[2]:
        render_metric_card("Failed-login IPs", len(ip_summary["failed_login_ips"]))

    if ip_counter:
        top_ip_df = pd.DataFrame(ip_summary["top_ips"], columns=["ip_address", "count"])
        st.subheader("Top 10 IPs by Frequency")
        st.dataframe(top_ip_df, use_container_width=True)
        st.bar_chart(top_ip_df.set_index("ip_address"))

        selected_ip = st.selectbox("Show lines related to IP", list(ip_counter.keys()))
        related_lines = [f"{number}: {line}" for number, line in enumerate(lines, start=1) if selected_ip in line]
        render_terminal_box("\n".join(related_lines[:80]))
    else:
        st.info("No IPv4 addresses were found in this log.")

    st.subheader("IPs with Repeated Failed Login Attempts")
    failed_login_ips = ip_summary["failed_login_ips"]
    if failed_login_ips:
        st.dataframe(pd.DataFrame(failed_login_ips, columns=["ip_address", "failed_login_count"]), use_container_width=True)
    else:
        st.info("No repeated failed login IPs were detected.")

    st.subheader("Top Suspicious Paths")
    if ip_summary["top_patterns"]:
        paths_df = pd.DataFrame(ip_summary["top_patterns"], columns=["path", "count"])
        st.dataframe(paths_df, use_container_width=True)
        st.bar_chart(paths_df.set_index("path"))
    else:
        st.info("No suspicious web paths were detected.")

    st.subheader("Common Investigation Keywords")
    keyword_df = pd.DataFrame(
        [{"keyword": keyword, "count": count} for keyword, count in ip_summary["keyword_counts"].items()]
    )
    if keyword_df.empty:
        st.info("No selected investigation keywords were detected.")
    else:
        st.dataframe(keyword_df, use_container_width=True)
        st.bar_chart(keyword_df.set_index("keyword"))


def incident_report_page():
    render_header()
    st.subheader("Incident Report")

    if not has_log():
        show_no_log_message()
        return

    lines = get_current_lines()
    overview = build_overview(lines)
    findings = run_detection_rules(lines)
    ip_summary = build_ip_summary(lines)
    metadata = {
        "audit_datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file_name": st.session_state.file_name or "Unknown",
        "log_type": st.session_state.log_type or "Unknown",
    }
    report = generate_text_report(metadata, overview, findings, ip_summary)

    st.markdown(f'<div class="report-box">{html.escape(report)}</div>', unsafe_allow_html=True)

    col_report, col_csv = st.columns(2)
    with col_report:
        st.download_button(
            "Download report as TXT",
            data=report,
            file_name="logsentry_incident_report.txt",
            mime="text/plain",
        )
    with col_csv:
        st.download_button(
            "Download findings as CSV",
            data=findings_to_csv(findings),
            file_name="logsentry_findings.csv",
            mime="text/csv",
            disabled=not findings,
        )


def about_page():
    render_header()
    st.subheader("About LogSentry")
    st.markdown(
        """
        LogSentry is a local log investigation and incident analysis dashboard created as part of my learning path
        during my Ausbildung as Fachinformatiker fuer Systemintegration.

        Purpose:
        - analyze log files
        - detect suspicious patterns
        - identify repeated failed logins
        - extract IP addresses
        - generate incident reports
        """
    )

    badges = ["Python", "Streamlit", "Regex", "Log Analysis", "Incident Response", "pandas", "Reporting", "Sysadmin Tools"]
    st.markdown(" ".join(render_status_badge(badge if badge in ["INFO", "WARNING", "HIGH", "CRITICAL"] else "INFO").replace(">INFO<", f">{badge}<") for badge in badges), unsafe_allow_html=True)

    st.markdown("GitHub: https://github.com/mrachcore/log-sentry")
    st.warning("This tool does not upload files anywhere. All checks are performed locally.")


def render_sidebar():
    if LOGO_PATH.exists():
        st.sidebar.image(str(LOGO_PATH), use_container_width=True)
    st.sidebar.markdown("## LogSentry")
    st.sidebar.caption("by mrachcore")
    st.sidebar.caption("Local log investigation & incident analysis dashboard")
    st.sidebar.divider()

    pages = [
        "Dashboard",
        "Upload Logs",
        "Log Overview",
        "Detection Rules",
        "IP & Pattern Analysis",
        "Incident Report",
        "About",
    ]
    page = st.sidebar.radio("Navigation", pages)

    st.sidebar.divider()
    if has_log():
        st.sidebar.success(f"Loaded: {st.session_state.file_name}")
        st.sidebar.caption(st.session_state.log_type or "Unknown log type")
    else:
        st.sidebar.info("No log loaded")

    return page


def main():
    apply_custom_css()
    initialize_state()
    page = render_sidebar()

    if page == "Dashboard":
        dashboard_page()
    elif page == "Upload Logs":
        upload_logs_page()
    elif page == "Log Overview":
        log_overview_page()
    elif page == "Detection Rules":
        detection_rules_page()
    elif page == "IP & Pattern Analysis":
        ip_pattern_analysis_page()
    elif page == "Incident Report":
        incident_report_page()
    elif page == "About":
        about_page()


if __name__ == "__main__":
    main()
