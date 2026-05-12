# LogSentry

![LogSentry logo](assets/logo.png)

**Local log investigation and incident analysis dashboard built with Python and Streamlit.**

LogSentry is a beginner-friendly but professional portfolio project by **mrachcore**. It helps junior sysadmins investigate uploaded log files, detect suspicious patterns, identify repeated errors, extract IP addresses, and generate simple incident reports.

The app runs fully locally on a normal laptop. It does not use paid APIs, cloud services, databases, Docker, AI APIs, external services, or real production integrations.

## Overview

LogSentry is designed for local analysis of `.log` and `.txt` files. It provides a dark SOC-style dashboard for reviewing logs, finding suspicious events, and exporting readable incident reports.

This project was created as part of a learning path during the Ausbildung as **Fachinformatiker fuer Systemintegration**.

## Features

- Upload `.log` and `.txt` files
- Load included fictional sample logs
- Preview raw log content in a terminal-style box
- Detect log type when possible
- Show severity and keyword statistics
- Detect failed logins, denied access, web scanning paths, HTTP errors, service problems, and suspicious keywords
- Extract IPv4 addresses with regex
- Show top IP addresses by frequency
- Detect IPs with repeated failed login attempts
- Generate incident reports as TXT
- Export findings as CSV
- Fully local file analysis

## Tech Stack

| Technology | Purpose |
| --- | --- |
| Python 3 | Main programming language |
| Streamlit | Local dashboard UI |
| pandas | Tables and CSV export |
| re | Pattern matching with regular expressions |
| datetime | Report timestamps |
| collections.Counter | Counting severities, IPs, and patterns |
| io | CSV text generation |
| pathlib | File path handling |

## Installation

Clone or download the project, then open a terminal in the project folder:

```powershell
cd log-sentry
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate the virtual environment on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the dependencies:

```powershell
pip install -r requirements.txt
```

## Run the App

```powershell
streamlit run app.py
```

Streamlit will show a local URL, usually:

```text
http://localhost:8501
```

## Project Structure

```text
log-sentry/
  app.py
  requirements.txt
  README.md
  sample_logs/
    auth_sample.log
    web_sample.log
    system_sample.log
  assets/
    logo.png
  screenshots/
  utils/
    log_parser.py
    detection_rules.py
    report_generator.py
```

## Screenshots

Add screenshots after running the app:

- `screenshots/dashboard.png`
- `screenshots/upload-logs.png`
- `screenshots/log-overview.png`
- `screenshots/detection-rules.png`
- `screenshots/ip-pattern-analysis.png`
- `screenshots/incident-report.png`

## Sample Logs

The `sample_logs` folder contains fictional logs for testing:

- `auth_sample.log`: successful logins, failed passwords, root/admin attempts, denied access, repeated IPs
- `web_sample.log`: HTTP 200, 403, 404, 500, suspicious paths, repeated IPs
- `system_sample.log`: INFO, WARNING, ERROR, CRITICAL, service restart, disk warnings, permission denied

These files are safe training data and do not contain real production information.

## Notes

- This tool uses simple pattern matching, not advanced SIEM correlation.
- Results should support manual investigation, not replace it.
- Very large files may take longer to render in Streamlit.
- Non-UTF8 files are decoded with replacement characters so the app can still continue.

## Future Improvements

- Add timestamp extraction and timeline charts
- Add custom user-defined detection rules
- Add severity scoring per source IP
- Add support for exporting PDF reports
- Add filters for date ranges and categories
- Add saved investigation notes

## Disclaimer

This tool does not upload files anywhere. All checks are performed locally.

## Author

**mrachcore**

GitHub placeholder: https://github.com/mrachcore/log-sentry

## Suggested GitHub Topics

`python` `streamlit` `log-analysis` `incident-response` `security` `sysadmin` `dashboard` `regex` `pandas` `portfolio-project` `fachinformatiker` `soc`
