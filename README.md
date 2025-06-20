# Zulu Zscaler URL Analyzer

**This tool is intended for educational purposes only.**

A Python script for automated risk assessment of URLs using the Zulu Zscaler web service.

> This tool allows you to automate the risk assessment of URLs, which you would otherwise have to enter manually at [zulu.zscaler.com](https://zulu.zscaler.com). It fetches and parses the same results you would see in the browser, making it easy to integrate Zulu Zscaler's analysis into your own workflows.

## Features
- Automated URL analysis via Zulu Zscaler
- Customizable list of known safe domains (to skip analysis)
- SSL certificate verification enabled by default
- Option to disable SSL verification with `--no-verify`
- Command-line interface (CLI) for easy usage

## Requirements
- Python 3.8+
- `requests` library

## Installation
Clone this repository and install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Command Line

```bash
python zulu_analyze.py <url> [--safe-domains domain1 domain2 ...] [--no-verify]
```

#### Arguments
- `<url>`: The URL to analyze (e.g. `https://github.com`)
- `--safe-domains`: (Optional) List of domains considered safe (skips analysis if matched)
- `--no-verify`: (Optional) Disable SSL certificate verification (not recommended)

#### Examples
Analyze a URL with default settings:
```bash
python zulu_analyze.py https://github.com
```

Analyze a URL and skip analysis for custom safe domains:
```bash
python zulu_analyze.py https://github.com --safe-domains github.com example.com
```

Analyze a URL and disable SSL verification:
```bash
python zulu_analyze.py https://github.com --no-verify
```

<details>
<summary>Example output (click to expand)</summary>

```json
{
  "url": "https://github.com",
  "status_code": 200,
  "content_type": "text/html; charset=UTF-8",
  "last_performed": "2025-06-19 11:46:51.250761",
  "score": 0,
  "classification": "Benign",
  "analysis": {
    "redirections": "https://github.com/",
    "http_status": "200",
    "content_size": "286919 bytes",
    "content_type": "text/html; charset=utf-8",
    "ip_address": "140.82.112.4",
    "country": "US",
    "web_server": "github.com",
    "domain_history": [
      {
        "date": "2025-05-22",
        "report_id": "6f9b5b13-e869-4489-b542-b04d5546dd3b",
        "url": "https://github.com/readme"
      },
      {
        "date": "2025-05-22",
        "report_id": "4f69cf70-d551-4c7d-a0f6-50323a81e632",
        "url": "https://resources.github.com/learn/pathways"
      },
      {
        "date": "2025-05-22",
        "report_id": "2496b0b-5663-4b38-98a0-9cd2336ec6d3",
        "url": "https://github.com/customer-stories/figma"
      },
      {
        "date": "2025-05-22",
        "report_id": "2539b0d1-33f9-4c57-9e7e-8b840e1a1417",
        "url": "https://codeload.github.com/northerntrust-internal/apm000130"
      },
      {
        "date": "2025-05-22",
        "report_id": "cdc7c0f8-a749-4802-a6e8-7af29b8661e5",
        "url": "https://www.github.com"
      }
    ]
  },
  "content_checks": [
    {
      "test": "Known Bad Hash",
      "description": "56f98d3a14064e12f64471ad364401ad",
      "risk": "0"
    },
    {
      "test": "Phishing Heuristic",
      "description": "Not a phishing page",
      "risk": "0"
    },
    {
      "test": "Content Inspection",
      "description": "No match",
      "risk": "0"
    },
    {
      "test": "Park/Disabled Domain",
      "description": "No match",
      "risk": "0"
    }
  ],
  "url_checks": [
    {
      "test": "Non-Standard Port",
      "description": "HTTP",
      "risk": "0"
    },
    {
      "test": "SSL-Cert Check",
      "description": "Valid Certificate",
      "risk": "-15"
    },
    {
      "test": "Suspicious URL Pattern",
      "description": "No match",
      "risk": "0"
    },
    {
      "test": "Top-Level Domain Risk",
      "description": "No match",
      "risk": "0"
    },
    {
      "test": "File-Type Risk",
      "description": "",
      "risk": "0"
    },
    {
      "test": "Zscaler Inline",
      "description": "No match",
      "risk": "0"
    },
    {
      "test": "VirusTotal Content Check",
      "description": "Positives: 0",
      "risk": "0"
    },
    {
      "test": "Geo-location Risk",
      "description": "",
      "risk": "0"
    },
    {
      "test": "Zscaler Malicious URL",
      "description": "No Match",
      "risk": "0"
    }
  ],
  "host_checks": [
    {
      "test": "Zscaler Malicious IP",
      "description": "",
      "risk": "0"
    },
    {
      "test": "NetBlock Size Risk",
      "description": "Netblock size: 4096",
      "risk": "0"
    },
    {
      "test": "VirusTotal IP Submission",
      "description": "Badness ratio: 0.0",
      "risk": "0"
    },
    {
      "test": "SURBL Block",
      "description": "No match",
      "risk": "0"
    },
    {
      "test": "Autonomous System Risk",
      "description": "ASN:",
      "risk": "0"
    }
  ]
}
```
</details>

## Code Structure
- `ZuluZscaler` class: Handles session, safe domain logic, and parsing of Zulu Zscaler results.
- `main()` function: CLI entry point, argument parsing, and result output.

## Security Notice
- SSL certificate verification is enabled by default for your safety.
- Only use `--no-verify` if you understand the risks (e.g. for debugging in trusted environments).

## Contribution
Feel free to open issues or pull requests for improvements, bug fixes, or new features!

## Credits & Attribution
- This project uses the public web service provided by [Zulu Zscaler](https://zulu.zscaler.com) for URL risk analysis.
- All credit for the analysis engine and data goes to Zscaler, Inc. See their website for more information and terms of use.

## License
MIT License

---

*This project is not affiliated with or endorsed by Zscaler. Use at your own risk.*

**Note to Zscaler:** If you are a representative of Zscaler and wish for this repository to be taken down, please contact the maintainer and it will be removed promptly.

**Please note:** Only individual, occasional queries are permitted. Automated mass queries, scraping, or any use that could degrade the Zulu Zscaler service or violate their Acceptable Use Policy is strictly prohibited. Always respect the terms of service of [zulu.zscaler.com](https://help.zscaler.com/legal/acceptable-use-policy) and use this tool responsibly.
