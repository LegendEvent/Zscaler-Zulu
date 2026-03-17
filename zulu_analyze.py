from typing import Any
import requests
import re
import json
import time
import sys
import ipaddress
from urllib.parse import urljoin, urlparse
import argparse

from exceptions import (
    ZuluException,
    URLValidationError,
    RateLimitError,
    AnalysisError,
    NetworkError,
)
from logging_config import get_logger, configure_logging
from result_types import (
    create_safe_domain_result,
    create_rate_limited_result,
)

configure_logging()
logger = get_logger(__name__)


class ZuluZscaler:
    """
    Automated analysis of URLs with Zulu Zscaler.
    For open source: You can provide your own safe domains list.
    """

    DEFAULT_SAFE_DOMAINS = [
        "example.com",
        "example.org",
        "example.net",
        "testdomain.local",
        "mycompany.com",
    ]

    def poll_until_completed(
        self,
        url: str,
        timeout: float = 600,
        interval: float = 5,
        max_interval: float = 30,
        max_retries: int = 100,
        force_rescan: bool = False,
        verbose: bool = False,
    ) -> dict:
        """
        Poll analyze_url with exponential backoff until status is 'Completed' or timeout.

        Args:
            url: URL to analyze
            timeout: Maximum time in seconds to wait (default: 600)
            interval: Initial polling interval in seconds (default: 5)
            max_interval: Maximum polling interval in seconds (default: 30)
            max_retries: Maximum number of polling attempts (default: 100)
            force_rescan: Force a fresh scan instead of cached results (default: False)
            verbose: Print status updates (default: False)

        Returns:
            The final result dict (with analysis) or the last result if timeout/max_retries.
        """
        start = time.time()
        current_interval = interval
        retries = 0
        force_used = False  # Only use force_rescan on first call

        while True:
            # Only pass force_rescan=True on the first call
            use_force = force_rescan and not force_used
            if use_force:
                force_used = True
            result = self.analyze_url(url, force_rescan=use_force)
            status = result.get("Status", "").lower() if result.get("Status") else ""

            if verbose:
                status_display = result.get("Status", "Unknown")
                if use_force:
                    status_display += " (forced rescan)"
                print(f"Status: {status_display}")

            if status == "completed":
                return result

            retries += 1
            if retries >= max_retries:
                if verbose:
                    print(f"Max retries ({max_retries}) reached")
                result["max_retries_reached"] = True
                return result

            elapsed = time.time() - start
            if elapsed > timeout:
                if verbose:
                    print(f"Timeout reached after {elapsed:.1f}s")
                result["timeout_reached"] = True
                return result

            time.sleep(current_interval)
            # Exponential backoff with cap
            current_interval = min(current_interval * 1.5, max_interval)

    REQUEST_TIMEOUT = 30

    def __init__(
        self, default_safe_domains: list[str] | None = None, verify_ssl: bool = True
    ):
        """
        Initialize the Zulu Zscaler analyzer.

        Args:
            default_safe_domains: Optional custom list of safe domains (overrides DEFAULT_SAFE_DOMAINS)
            verify_ssl: Enable or disable SSL certificate verification (default: True)
        """
        self.safe_domains = (
            default_safe_domains
            if default_safe_domains is not None
            else self.DEFAULT_SAFE_DOMAINS
        )
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if not verify_ssl:
            import urllib3

            # Show warning instead of suppressing - user should know about MITM risk
            logger.warning(
                "SSL certificate verification is disabled. This exposes you to MITM attacks."
            )
        self.base_url = "https://zulu.zscaler.com"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Ch-Ua": '"Microsoft Edge";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }
        self.csrf_token = None

    def init_session(self) -> str:
        """Initialize session and get initial cookies and CSRF token"""
        response = self.session.get(
            self.base_url, headers=self.headers, timeout=self.REQUEST_TIMEOUT
        )

        csrf_patterns = [
            r'name="csrf_token"\s+value="([^"]+)"',
            r'name="csrf-token" content="([^"]+)"',
            r'name="_csrf" value="([^"]+)"',
            r'csrf-token:\s*["\']([^"]+)["\']',
        ]

        for pattern in csrf_patterns:
            match = re.search(pattern, response.text)
            if match:
                self.csrf_token = match.group(1)
                break

        return response.text

    @staticmethod
    def _validate_url(url: str) -> str:
        """Validate and normalize URL. Returns normalized URL or raises ValueError."""
        if not url or not isinstance(url, str):
            raise ValueError("URL must be a non-empty string")

        url = url.strip()

        # Check scheme BEFORE adding prefix - detect dangerous schemes
        # urlparse('file:///etc/passwd').scheme == 'file'
        # urlparse('javascript:alert(1)').scheme == 'javascript'
        temp_parsed = urlparse(url)
        if temp_parsed.scheme and temp_parsed.scheme.lower() not in (
            "http",
            "https",
            "",
        ):
            raise ValueError(
                f"Only http/https schemes are allowed, got: '{temp_parsed.scheme}'"
            )

        # Add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # Parse and validate
        parsed = urlparse(url)

        if not parsed.netloc:
            raise ValueError(f"Invalid URL: could not extract domain from '{url}'")

        hostname = parsed.netloc.split(":")[0]  # Remove port if present

        # Block direct IP addresses to prevent SSRF attacks
        # Use a flag to avoid catching our own ValueError
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            pass  # Not an IP address, continue validation

        if is_ip:
            raise ValueError(
                f"Direct IP addresses are not allowed for security reasons: '{hostname}'"
            )

        # Validate hostname characters (alphanumeric, hyphens, dots only)
        if not re.match(
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$",
            hostname,
        ):
            raise ValueError(
                f"Invalid hostname: '{hostname}' contains invalid characters"
            )

        return url

    def is_safe_domain(self, url: str) -> bool:
        """Check if the domain is in the known safe domains list"""
        try:
            # Ensure URL has a scheme
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            domain = urlparse(url).netloc.lower()
            if not domain:  # If netloc is empty, the URL itself might be the domain
                domain = url.lower()

            # Remove 'www.' if present
            if domain.startswith("www."):
                domain = domain[4:]

            return domain in self.safe_domains
        except Exception as e:
            # Log error but don't crash - treat unknown domains as not safe
            import sys

            logger.warning("Could not check domain safety: %s", str(e))
            return False

    def analyze_url(self, url: str, force_rescan: bool = False) -> dict:
        """
        Analyze a URL using Zulu Zscaler.

        Args:
            url: The URL to analyze
            force_rescan: If True, force a fresh scan instead of using cached results

        Returns:
            Dict containing analysis results including status, score, classification, etc.
        """
        # Validate and normalize URL
        url = self._validate_url(url)

        # Check if URL is from a known safe domain
        if self.is_safe_domain(url):
            return {
                "url": url,
                "status": "safe",
                "message": "Domain is in the known safe list",
            }

        main_page = self.init_session()

        form_pattern = r'<form[^>]*action="([^"]+)"[^>]*>'
        form_match = re.search(form_pattern, main_page)

        if form_match:
            analyze_endpoint = form_match.group(1)
            if not analyze_endpoint.startswith("http"):
                analyze_endpoint = urljoin(self.base_url, analyze_endpoint)
        else:
            analyze_endpoint = urljoin(self.base_url, "/")

        headers = {
            **self.headers,
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://zulu.zscaler.com",
            "Referer": self.base_url,
        }

        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token

        data = {"url": url, "csrf_token": self.csrf_token}

        response = self.session.post(
            analyze_endpoint,
            headers=headers,
            data=data,
            allow_redirects=True,
            timeout=self.REQUEST_TIMEOUT,
        )

        # Check for rate limiting
        if response.status_code == 429:
            return {
                "url": url,
                "status_code": 429,
                "error": "Rate limited - too many requests. Please wait before retrying.",
                "Status": "Rate Limited",
            }

        # Handle force_rescan: trigger a fresh analysis
        if force_rescan:
            # Extract report ID from the redirect URL
            # Extract parent_id from page (more reliable than URL)
            parent_id_match = re.search(
                r'id=["\']parent_id["\'][^>]*>([^<]+)<', response.text
            )
            report_id_from_url = re.search(r"/report/([a-f0-9-]+)", response.url)

            # Use parent_id from page if available, fall back to URL report ID
            original_report_id = (
                parent_id_match.group(1)
                if parent_id_match
                else (report_id_from_url.group(1) if report_id_from_url else None)
            )

            if original_report_id:
                # POST to /reanalyze endpoint (must use form data, not JSON)
                reanalyze_headers = {
                    **self.headers,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-CSRF-Token": self.csrf_token,
                    "Referer": response.url,
                }

                reanalyze_response = self.session.post(
                    f"{self.base_url}/reanalyze",
                    headers=reanalyze_headers,
                    data={"id": original_report_id},
                    timeout=self.REQUEST_TIMEOUT,
                )

                if reanalyze_response.status_code == 200:
                    try:
                        new_report = reanalyze_response.json()
                        if new_report and isinstance(new_report, dict):
                            new_report_id = new_report.get("id")
                            if new_report_id:
                                # Fetch the new submission page
                                response = self.session.get(
                                    f"{self.base_url}/submission/{new_report_id}",
                                    headers=self.headers,
                                    timeout=self.REQUEST_TIMEOUT,
                                )
                    except (json.JSONDecodeError, KeyError, TypeError):
                        pass  # Fall back to original response
        status_match = re.search(
            r'<span class="left">Status</span>\s*<span[^>]*>([^<]+)</span>',
            response.text,
        )
        scan_status = status_match.group(1).strip() if status_match else None

        result = {
            "url": url,
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type"),
            "Status": scan_status,
        }

        # Only parse and return analysis if status is Completed
        if scan_status and scan_status.lower() == "completed":
            # Extract last performed date
            performed_match = re.search(r"Performed on ([^<]+)", response.text)
            if performed_match:
                result["last_performed"] = performed_match.group(1).strip()

            # Extract score and classification
            score_match = re.search(
                r'<span id="jscore"[^>]*>(\d+)</span>', response.text
            )
            if score_match:
                result["score"] = int(score_match.group(1))

            class_match = re.search(
                r'<span class="report-icon [^"]+">([^<]+)</span>', response.text
            )
            if class_match:
                result["classification"] = class_match.group(1)

            # Extract Analysis section
            analysis = {}

            # Basic Analysis
            fields = {
                "redirections": r'id="rep-redir">([^<]+)</span>',
                "http_status": r'id="rep-code">([^<]+)</span>',
                "content_size": r'id="rep-size">([^<]+)</span>',
                "content_type": r'id="rep-cont-type">([^<]+)</span>',
                "ip_address": r'id="rep-ip">([^<]+)</span>',
                "country": r'id="rep-country">([^<]+)</span>',
                "web_server": r'id="rep-web-server">([^<]+)</span>',
            }

            for key, pattern in fields.items():
                match = re.search(pattern, response.text)
                if match:
                    analysis[key] = match.group(1).strip()

            # Domain History
            domain_history = []
            history_pattern = r'<p class="" id="rep-domain-hist">\s*<span class="first fg-color-mid-gray">([^<]+)</span>\s*<span class="second[^"]*"><a href="([^"]+)">([^<]+)</a></span>'
            for match in re.finditer(history_pattern, response.text):
                domain_history.append(
                    {
                        "date": match.group(1).strip(),
                        "report_id": match.group(2).strip("/report/"),
                        "url": match.group(3).strip(" .."),
                    }
                )
            if domain_history:
                analysis["domain_history"] = domain_history

            result["analysis"] = analysis

            # Extract sections with checks
            sections = {
                "external_elements": "External Elements</h1>",
                "content_checks": "Content Checks</h1>",
                "url_checks": "URL Checks</h1>",
                "host_checks": "Host Checks</h1>",
            }

            for section_key, section_header in sections.items():
                items = []
                # Fix escape sequence and improve pattern to find table content
                section_pattern = f'<h1 class="margin-bottom-16">{section_header.replace("</h1>", "")}.*?<table.*?<tbody.*?>(.*?)</tbody>'
                section = re.search(section_pattern, response.text, re.DOTALL)

                if section:
                    if section_key == "external_elements":
                        # Pattern für externe Elemente mit Links
                        pattern = r'<tr>\s*<td class="link"><a[^>]*>([^<]+)</a></td>\s*<td><span[^>]*>([^<]+)</span></td>\s*</tr>'
                        for match in re.finditer(pattern, section.group(1)):
                            items.append(
                                {
                                    "url": match.group(1).strip(" .."),
                                    "risk": match.group(2).strip(),
                                }
                            )
                    else:
                        # Pattern für Content, URL und Host Checks - berücksichtigt leere Descriptions
                        pattern = r'<tr>\s*<td[^>]*><span class="report-icon-after">([^<]+)</span></td>\s*<td>([^<]*)</td>\s*<td class="fixed">([^<]+)</td>\s*</tr>'
                        for match in re.finditer(pattern, section.group(1)):
                            test = match.group(1).strip()
                            description = match.group(2).strip()
                            risk = match.group(3).strip()
                            items.append(
                                {"test": test, "description": description, "risk": risk}
                            )
                if items:
                    result[section_key] = items
        else:
            result["analysis"] = {}

        return result


def main():
    """
    Example usage for CLI and as a module. You can provide your own safe domains via --safe-domains.
    """
    parser = argparse.ArgumentParser(description="Analyze URLs with Zulu Zscaler.")
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument(
        "--safe-domains",
        nargs="*",
        default=None,
        help="List of known safe domains (optional)",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable SSL certificate verification (not recommended)",
    )
    parser.add_argument(
        "--force-rescan",
        action="store_true",
        help="Force a fresh scan instead of using cached results",
    )
    args = parser.parse_args()

    zulu = ZuluZscaler(
        default_safe_domains=args.safe_domains, verify_ssl=not args.no_verify
    )
    try:
        result = zulu.poll_until_completed(args.url, force_rescan=args.force_rescan)
        print(json.dumps(result, indent=2))
    except Exception as e:
        logger.error("Error: %s", str(e))
        logger.error(
            "Note: Check if the Zulu Zscaler website is reachable and you are not hitting rate limits."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
