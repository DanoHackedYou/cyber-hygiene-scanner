# Cyber Hygiene Scanner

A safe command-line tool that performs basic web security hygiene checks against a public website.

It helps developers quickly review HTTPS usage, common security headers, exposed technology headers and common open ports.

> This project is designed for learning, portfolio use and defensive security awareness. It does not perform exploitation, brute force, vulnerability exploitation or intrusive scanning.

## Features

- Analyze any public domain or URL.
- Check HTTPS usage.
- Detect whether traffic redirects to HTTPS.
- Review common security headers:
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- Detect exposed `Server` and `X-Powered-By` headers.
- Scan a small set of common TCP ports.
- Generate a score from 0 to 100.
- Classify the risk level.
- Print a clean terminal report.
- Export results as JSON.
- Includes tests, Docker and GitHub Actions.

## Tech Stack

- Python
- Typer
- Rich
- Requests
- Pydantic
- Pytest
- Docker
- GitHub Actions

## Project Structure

```txt
cyber-hygiene-scanner/
├── .github/
│   └── workflows/
│       └── ci.yml
├── cyber_hygiene_scanner/
│   ├── services/
│   │   ├── http_checks.py
│   │   ├── port_scanner.py
│   │   ├── scanner.py
│   │   └── scorer.py
│   ├── utils/
│   │   └── targets.py
│   ├── __init__.py
│   ├── cli.py
│   └── models.py
├── tests/
│   ├── test_scorer.py
│   └── test_targets.py
├── .env.example
├── .gitignore
├── Dockerfile
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Installation

### Windows

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### macOS/Linux

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Run a basic scan:

```bash
python -m cyber_hygiene_scanner.cli scan https://example.com
```

Scan a domain without writing the protocol:

```bash
python -m cyber_hygiene_scanner.cli scan example.com
```

Skip port checks:

```bash
python -m cyber_hygiene_scanner.cli scan example.com --skip-ports
```

Export the result to JSON:

```bash
python -m cyber_hygiene_scanner.cli scan example.com --output report.json
```

Show version:

```bash
python -m cyber_hygiene_scanner.cli --version
```

## Docker Usage

Build the image:

```bash
docker build -t cyber-hygiene-scanner .
```

Run a scan:

```bash
docker run --rm cyber-hygiene-scanner scan https://example.com
```

## Example Output

```txt
Cyber Hygiene Summary
Target: https://example.com
Score: 82/100
Risk level: Low
HTTPS: Yes

Security Headers
- Strict-Transport-Security: Missing
- Content-Security-Policy: Present
...

Recommendations
1. Add HSTS to force browsers to use HTTPS.
2. Add a Referrer-Policy to limit sensitive referrer leakage.
```

## Running Tests

```bash
pytest
```

## Responsible Use

Use this tool only against:

- Your own websites.
- Public websites where basic connection checks are acceptable.
- Environments where you have permission.

The scanner only performs basic HTTP requests and a limited common-port connection check. It does not exploit vulnerabilities or bypass access controls.

## Roadmap

- Add CSV export.
- Add HTML report export.
- Add TLS certificate expiry check.
- Add robots.txt and security.txt detection.
- Add optional API mode with FastAPI.
- Add severity labels per recommendation.
- Add historical scan comparison.

## GitHub Topics

Recommended repository topics:

```txt
cybersecurity
python
cli
typer
rich
security-tools
portfolio-project
http-headers
docker
github-actions
```

## Status

MVP completed and ready for portfolio use.

## License

MIT License.

## Author

Created by DanoHackedYou.
