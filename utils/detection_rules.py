import re
from collections import Counter


def make_finding(severity, category, description, line_number, line, recommendation):
    """Create one finding as a simple dictionary for pandas and reporting."""
    return {
        "severity": severity,
        "category": category,
        "description": description,
        "line_number": line_number,
        "line_preview": line.strip()[:220],
        "recommendation": recommendation,
    }


def find_patterns(lines, patterns, severity, category, description, recommendation):
    """Search lines for regex patterns and return matching findings."""
    findings = []

    for index, line in enumerate(lines, start=1):
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(make_finding(severity, category, description, index, line, recommendation))
                break

    return findings


def detect_failed_logins(lines):
    patterns = [
        r"failed password",
        r"authentication failure",
        r"login failed",
        r"invalid user",
    ]
    return find_patterns(
        lines,
        patterns,
        "HIGH",
        "Authentication",
        "Failed login attempt detected",
        "Review the source IP and check for repeated login failures.",
    )


def detect_admin_root_attempts(lines):
    patterns = [r"\broot\b", r"\badministrator\b", r"\badmin\b"]
    return find_patterns(
        lines,
        patterns,
        "WARNING",
        "Authentication",
        "Root or admin account activity detected",
        "Check if this privileged account activity was expected.",
    )


def detect_permission_issues(lines):
    patterns = [r"permission denied", r"access denied", r"\bdenied\b"]
    return find_patterns(
        lines,
        patterns,
        "HIGH",
        "Access Control",
        "Permission or access denial detected",
        "Review affected user, service, and file or resource permissions.",
    )


def detect_web_scanning(lines):
    patterns = [r"/admin\b", r"/wp-login\.php", r"/\.env\b", r"/phpmyadmin\b", r"/config\b", r"/backup\b"]
    return find_patterns(
        lines,
        patterns,
        "HIGH",
        "Web Security",
        "Suspicious web path requested",
        "Check the source IP and consider blocking repeated scanning activity.",
    )


def detect_http_errors(lines):
    patterns = [r"\b403\b", r"\b404\b", r"\b500\b", r"\b502\b", r"\b503\b"]
    return find_patterns(
        lines,
        patterns,
        "WARNING",
        "Web Server",
        "HTTP error status detected",
        "Review the endpoint, response code, and repeated client activity.",
    )


def detect_suspicious_keywords(lines):
    patterns = [
        r"brute force",
        r"exploit",
        r"injection",
        r"unauthorized",
        r"suspicious",
        r"malware",
        r"ransomware",
    ]
    return find_patterns(
        lines,
        patterns,
        "CRITICAL",
        "Threat Indicator",
        "Suspicious security keyword detected",
        "Investigate this line immediately and correlate with surrounding events.",
    )


def detect_service_problems(lines):
    patterns = [r"service failed", r"\bstopped\b", r"\bcrashed\b", r"\btimeout\b"]
    return find_patterns(
        lines,
        patterns,
        "WARNING",
        "Service Health",
        "Service problem detected",
        "Check service status, recent changes, and related system logs.",
    )


def run_detection_rules(lines):
    """Run all detection checks and return one combined findings list."""
    findings = []
    findings.extend(detect_failed_logins(lines))
    findings.extend(detect_admin_root_attempts(lines))
    findings.extend(detect_permission_issues(lines))
    findings.extend(detect_web_scanning(lines))
    findings.extend(detect_http_errors(lines))
    findings.extend(detect_suspicious_keywords(lines))
    findings.extend(detect_service_problems(lines))
    return findings


def calculate_detection_summary(findings):
    """Count findings by severity and category for summary widgets."""
    severity_counts = Counter(finding["severity"] for finding in findings)
    category_counts = Counter(finding["category"] for finding in findings)

    return {
        "total_findings": len(findings),
        "by_severity": dict(severity_counts),
        "by_category": dict(category_counts),
    }
