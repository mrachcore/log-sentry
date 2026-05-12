import io
import pandas as pd


def generate_text_report(metadata, overview, findings, ip_summary):
    """Build a clean plain-text incident report."""
    lines = [
        "LogSentry Incident Report",
        "by mrachcore",
        "=" * 32,
        "",
        f"Audit date/time: {metadata.get('audit_datetime', 'Unknown')}",
        f"File name: {metadata.get('file_name', 'Unknown')}",
        f"Detected log type: {metadata.get('log_type', 'Unknown')}",
        f"Total lines: {overview.get('total_lines', 0)}",
        "",
        "Severity Summary",
        "-" * 16,
    ]

    severity_summary = overview.get("severity_counts", {})
    if severity_summary:
        for severity, count in severity_summary.items():
            lines.append(f"{severity}: {count}")
    else:
        lines.append("No severity keywords detected.")

    lines.extend([
        "",
        f"Total findings: {len(findings)}",
        "",
        "Top IP Addresses",
        "-" * 16,
    ])

    top_ips = ip_summary.get("top_ips", [])
    if top_ips:
        for ip, count in top_ips:
            lines.append(f"{ip}: {count} mention(s)")
    else:
        lines.append("No IP addresses detected.")

    lines.extend([
        "",
        "Top Suspicious Patterns",
        "-" * 24,
    ])

    top_patterns = ip_summary.get("top_patterns", [])
    if top_patterns:
        for pattern, count in top_patterns:
            lines.append(f"{pattern}: {count}")
    else:
        lines.append("No repeated suspicious patterns detected.")

    lines.extend([
        "",
        "High / Critical Findings",
        "-" * 24,
    ])

    important_findings = [item for item in findings if item.get("severity") in ["HIGH", "CRITICAL"]]
    if important_findings:
        for finding in important_findings:
            lines.append("")
            lines.append(f"[{finding.get('severity')}] {finding.get('category')}")
            lines.append(f"Finding: {finding.get('description')}")
            lines.append(f"Line: {finding.get('line_number')}")
            lines.append(f"Preview: {finding.get('line_preview')}")
            lines.append(f"Recommendation: {finding.get('recommendation')}")
    else:
        lines.append("No high or critical findings detected.")

    lines.extend([
        "",
        "Recommendations",
        "-" * 15,
        "- Review repeated failed logins and denied access events.",
        "- Investigate high and critical findings first.",
        "- Check top source IP addresses for repeated suspicious behavior.",
        "- Correlate suspicious log lines with the affected system and time window.",
        "- Keep logs locally and avoid uploading sensitive production data to unknown services.",
        "",
        "Disclaimer",
        "-" * 10,
        "This report is based on simple local pattern matching and should support, not replace, manual investigation.",
    ])

    return "\n".join(lines)


def findings_to_csv(findings):
    """Convert findings to CSV text for download."""
    output = io.StringIO()
    dataframe = pd.DataFrame(findings)
    dataframe.to_csv(output, index=False)
    return output.getvalue()
