import re
from collections import Counter
from pathlib import Path


SEVERITY_KEYWORDS = ["INFO", "WARNING", "WARN", "ERROR", "ERR", "CRITICAL", "FAILED", "DENIED"]
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def read_uploaded_log(uploaded_file):
    """Read an uploaded Streamlit file and return decoded text."""
    if uploaded_file is None:
        return ""

    raw_data = uploaded_file.getvalue()
    if not raw_data:
        return ""

    # Try UTF-8 first. If that fails, replace unreadable characters gracefully.
    try:
        return raw_data.decode("utf-8")
    except UnicodeDecodeError:
        return raw_data.decode("utf-8", errors="replace")


def load_sample_log(path):
    """Load a sample log file from disk."""
    sample_path = Path(path)
    return sample_path.read_text(encoding="utf-8", errors="replace")


def split_lines(content):
    """Split log content into lines and support Linux or Windows line endings."""
    if not content:
        return []
    return content.splitlines()


def count_severity_keywords(lines):
    """Count common severity keywords in a case-insensitive way."""
    counts = Counter()

    for line in lines:
        upper_line = line.upper()
        for keyword in SEVERITY_KEYWORDS:
            if keyword in upper_line:
                counts[keyword] += 1

    return dict(counts)


def extract_ipv4_addresses(lines):
    """Extract valid-looking IPv4 addresses from log lines."""
    addresses = []

    for line in lines:
        for match in IPV4_PATTERN.findall(line):
            parts = match.split(".")
            if all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                addresses.append(match)

    return addresses


def detect_log_type(content):
    """Guess the log type from simple keywords and patterns."""
    text = content.lower()

    if any(word in text for word in ["failed password", "sshd", "authentication failure", "invalid user"]):
        return "Authentication log"

    if any(word in text for word in ["get /", "post /", "http/1.1", " 404 ", " 500 "]):
        return "Web server log"

    if any(word in text for word in ["service", "systemd", "disk", "kernel", "critical"]):
        return "System log"

    return "Unknown / mixed log"


def preview_lines(lines, max_lines=100):
    """Return the first lines for preview without changing the original list."""
    return lines[:max_lines]
