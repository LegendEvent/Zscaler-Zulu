from typing import Any
import requests
import re
import json
import time
import sys
import ipaddress
from dataclasses import dataclass
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
    UrlAnalysisResult,
    create_safe_domain_result,
    create_rate_limited_result,
    create_error_result,
)

__all__ = [
    "ZuluZscaler",
    "main",
    "PollConfig",
]

logger = get_logger(__name__)


ALLOWED_SCHEMES = ("http", "https")


@dataclass
class PollConfig:
    """Configuration for polling URL analysis completion."""

    timeout: float = 600  # Maximum time in seconds to wait
    interval: float = 5  # Initial polling interval in seconds
    max_interval: float = 30  # Maximum polling interval in seconds
    max_retries: int = 100  # Maximum number of polling attempts
    verbose: bool = False  # Print status updates


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

    BASE_URL = "https://zulu.zscaler.com"

    def poll_until_completed(
        self,
        url: str,
        force_rescan: bool = False,
        config: PollConfig | None = None,
    ) -> UrlAnalysisResult:
        """
        Poll analyze_url with exponential backoff until status is 'Completed' or timeout.

        Args:
            url: URL to analyze
            force_rescan: Force a fresh scan instead of cached results (default: False)
            config: PollConfig object with polling parameters (default: PollConfig())

        Returns:
            The final result dict (with analysis) or the last result if timeout/max_retries.
        """
        if config is None:
            config = PollConfig()

        start = time.time()
        current_interval = config.interval
        retries = 0
        force_used = False  # Only use force_rescan on first call

        while True:
            # Only pass force_rescan=True on the first call
            use_force = force_rescan and not force_used
            if use_force:
                force_used = True
            try:
                result = self.analyze_url(url, force_rescan=use_force)
            except NetworkError:
                retries += 1
                if retries >= config.max_retries:
                    if config.verbose:
                        print(
                            f"Max retries ({config.max_retries}) reached due to network errors"
                        )
                    return {
                        "url": url,
                        "status": "error",
                        "error": "Network error during polling",
                        "max_retries_reached": True,
                    }
                if config.verbose:
                    print(
                        f"Network error during polling, retrying ({retries}/{config.max_retries})..."
                    )
                time.sleep(current_interval)
                current_interval = min(current_interval * 1.5, config.max_interval)
                continue
            status = result.get("status", "").lower() if result.get("status") else ""

            if config.verbose:
                status_display = result.get("status", "Unknown")
                if use_force:
                    status_display += " (forced rescan)"
                print(f"Status: {status_display}")

            if status == "completed":
                return result

            retries += 1
            if retries >= config.max_retries:
                if config.verbose:
                    print(f"Max retries ({config.max_retries}) reached")
                return {**result, "max_retries_reached": True}

            elapsed = time.time() - start
            if elapsed > config.timeout:
                if config.verbose:
                    print(f"Timeout reached after {elapsed:.1f}s")
                return {**result, "timeout_reached": True}

            time.sleep(current_interval)
            # Exponential backoff with cap
            current_interval = min(current_interval * 1.5, config.max_interval)

    REQUEST_TIMEOUT = 60

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
            # Show warning instead of suppressing - user should know about MITM risk
            logger.warning(
                "[SECURITY_AUDIT] SSL certificate verification is disabled. "
                f"verify_ssl={verify_ssl}. This exposes you to MITM attacks."
            )
        self.base_url = self.BASE_URL
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
        """Validate and normalize URL. Returns normalized URL or raises URLValidationError."""
        if not url or not isinstance(url, str):
            raise URLValidationError("URL must be a non-empty string")

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
            raise URLValidationError(
                f"Only http/https schemes are allowed, got: '{temp_parsed.scheme}'"
            )

        # Add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # Parse and validate
        parsed = urlparse(url)

        if not parsed.netloc:
            raise URLValidationError(
                f"Invalid URL: could not extract domain from '{url}'"
            )

        hostname = parsed.netloc.split(":")[0]  # Remove port if present

        # Block direct IP addresses to prevent SSRF attacks
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            raise URLValidationError(
                f"Direct IP addresses are not allowed for security reasons: '{hostname}'"
            )

        # Block obfuscated IP addresses (SSRF bypass via hex, octal, decimal, leading zeros)
        if re.match(r"^0x[0-9a-fA-F]+$", hostname):
            raise URLValidationError(
                f"Hexadecimal IP addresses are not allowed for security reasons: '{hostname}'"
            )
        if re.match(r"^0[0-7]+$", hostname):
            raise URLValidationError(
                f"Octal IP addresses are not allowed for security reasons: '{hostname}'"
            )
        if re.match(r"^\d{1,10}$", hostname):
            try:
                if 0 <= int(hostname) <= 4294967295:
                    raise URLValidationError(
                        f"Decimal IP addresses are not allowed for security reasons: '{hostname}'"
                    )
            except URLValidationError:
                raise
            except ValueError:
                pass
        if re.match(r"^\d+\.0\d+", hostname):
            raise URLValidationError(
                f"IP addresses with leading zeros are not allowed for security reasons: '{hostname}'"
            )

        # Block known localhost-redirecting domains (SSRF bypass)
        _localhost_blocklist = (
            "localtest.me",
            "vcap.me",
            "nip.io",
            "sslip.io",
            "pointer.to",
            "lvh.me",
            "customercloud.app",
        )
        for blocked in _localhost_blocklist:
            if hostname == blocked or hostname.endswith("." + blocked):
                raise URLValidationError(
                    f"Domain '{hostname}' is blocked as it may redirect to localhost"
                )

        # Validate hostname characters (alphanumeric, hyphens, dots only)
        if not re.match(
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$",
            hostname,
        ):
            raise URLValidationError(
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
        except (ValueError, AttributeError) as e:
            logger.warning("Could not check domain safety: %s", str(e))
            return False

    def _extract_form_endpoint(self, html: str) -> str:
        """Extract the form action endpoint from HTML."""
        form_pattern = r'<form[^>]*action="([^"]+)"[^>]*>'
        form_match = re.search(form_pattern, html)
        if form_match:
            endpoint = form_match.group(1)
            if not endpoint.startswith(("http://", "https://")):
                endpoint = urljoin(self.base_url, endpoint)
            parsed = urlparse(endpoint)
            base_parsed = urlparse(self.base_url)
            if parsed.scheme not in ("http", "https") or (
                parsed.netloc and parsed.netloc != base_parsed.netloc
            ):
                return urljoin(self.base_url, "/")
            return endpoint
        return urljoin(self.base_url, "/")

    def _parse_scan_status(self, html: str) -> str | None:
        """Extract scan status from HTML."""
        status_match = re.search(
            r'<span class="left">Status</span>\s*<span[^>]*>([^<]+)</span>', html
        )
        return status_match.group(1).strip() if status_match else None

    def _parse_basic_analysis(self, html: str) -> dict[str, Any]:
        """Parse basic analysis fields from HTML."""
        analysis = {}
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
            match = re.search(pattern, html)
            if match:
                analysis[key] = match.group(1).strip()
        return analysis

    def _parse_domain_history(self, html: str) -> list[dict[str, str]]:
        """Parse domain history from HTML."""
        domain_history = []
        pattern = r'<p class="" id="rep-domain-hist">\s*<span class="first fg-color-mid-gray">([^<]+)</span>\s*<span class="second[^"]*"><a href="([^"]+)">([^<]+)</a></span>'
        for match in re.finditer(pattern, html):
            domain_history.append(
                {
                    "date": match.group(1).strip(),
                    "report_id": match.group(2).strip("/report/"),
                    "url": match.group(3).strip(" .."),
                }
            )
        return domain_history

    def _parse_check_section(
        self, html: str, section_key: str, section_header: str
    ) -> list[dict[str, str]]:
        """Parse a single check section from HTML."""
        items = []
        section_pattern = f'<h1 class="margin-bottom-16">{section_header.replace("</h1>", "")}.*?<table.*?<tbody.*?>(.*?)</tbody>'
        section = re.search(section_pattern, html, re.DOTALL)

        if not section:
            return items

        section_content = section.group(1)
        if section_key == "external_elements":
            pattern = r'<tr>\s*<td class="link"><a[^>]*>([^<]+)</a></td>\s*<td><span[^>]*>([^<]+)</span></td>\s*</tr>'
            for match in re.finditer(pattern, section_content):
                items.append(
                    {
                        "url": match.group(1).strip(" .."),
                        "risk": match.group(2).strip(),
                    }
                )
        else:
            pattern = r'<tr>\s*<td[^>]*><span class="report-icon-after">([^<]+)</span></td>\s*<td>([^<]*)</td>\s*<td class="fixed">([^<]+)</td>\s*</tr>'
            for match in re.finditer(pattern, section_content):
                items.append(
                    {
                        "test": match.group(1).strip(),
                        "description": match.group(2).strip(),
                        "risk": match.group(3).strip(),
                    }
                )
        return items

    def _parse_all_check_sections(self, html: str) -> dict[str, list[dict[str, str]]]:
        """Parse all check sections from HTML."""
        sections = {
            "external_elements": "External Elements</h1>",
            "content_checks": "Content Checks</h1>",
            "url_checks": "URL Checks</h1>",
            "host_checks": "Host Checks</h1>",
        }
        result = {}
        for section_key, section_header in sections.items():
            items = self._parse_check_section(html, section_key, section_header)
            if items:
                result[section_key] = items
        return result

    def _build_initial_result(
        self, url: str, response: requests.Response, scan_status: str | None
    ) -> dict[str, Any]:
        """Build initial result dict with URL, status code, and scan status.

        Args:
            url: The analyzed URL
            response: HTTP response object
            scan_status: Parsed scan status from HTML

        Returns:
            Initial result dictionary with basic response information
        """
        status_value = scan_status.lower() if scan_status else ""
        return {
            "url": url,
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type"),
            "status": status_value,
        }

    def _handle_force_rescan(
        self, response: requests.Response, url: str
    ) -> requests.Response:
        """
        Handle force rescan logic by triggering a fresh analysis.

        Args:
            response: The initial analysis response
            url: The URL being analyzed

        Returns:
            Response object - either the new submission page or the original response
        """
        parent_id_match = re.search(
            r'id=["\']parent_id["\'][^>]*>([^<]+)<', response.text
        )
        report_id_from_url = re.search(r"/report/([a-f0-9-]+)", response.url)

        original_report_id = (
            parent_id_match.group(1)
            if parent_id_match
            else (report_id_from_url.group(1) if report_id_from_url else None)
        )

        if not original_report_id:
            return response

        reanalyze_headers = {
            **self.headers,
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": response.url,
        }
        if self.csrf_token:
            reanalyze_headers["X-CSRF-Token"] = self.csrf_token

        reanalyze_response = self.session.post(
            f"{self.base_url}/reanalyze",
            headers=reanalyze_headers,
            data={"id": original_report_id},
            timeout=self.REQUEST_TIMEOUT,
        )

        if reanalyze_response.status_code != 200:
            return response

        try:
            new_report = reanalyze_response.json()
            if new_report and isinstance(new_report, dict):
                new_report_id = new_report.get("id")
                if new_report_id:
                    return self.session.get(
                        f"{self.base_url}/submission/{new_report_id}",
                        headers=self.headers,
                        timeout=self.REQUEST_TIMEOUT,
                    )
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.debug("Failed to parse reanalyze response: %s", str(e))

        return response

    def _build_analyze_request_headers(self) -> dict[str, str]:
        """
        Build headers for the analysis POST request.

        Returns:
            Dictionary of headers for the analyze endpoint request.
        """
        headers = {
            **self.headers,
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.base_url,
            "Referer": self.base_url,
        }

        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token

        return headers

    def _fetch_analysis_page(
        self, url: str, analyze_endpoint: str, headers: dict[str, str]
    ) -> requests.Response:
        """
        Fetch the analysis page by POSTing the URL to the analyze endpoint.

        Args:
            url: The URL to analyze
            analyze_endpoint: The endpoint URL for the analysis request
            headers: Headers to include in the request

        Returns:
            Response object from the analysis POST request.
        """
        data = {"url": url}
        if self.csrf_token:
            data["csrf_token"] = self.csrf_token

        return self.session.post(
            analyze_endpoint,
            headers=headers,
            data=data,
            allow_redirects=True,
            timeout=self.REQUEST_TIMEOUT,
        )

    def analyze_url(self, url: str, force_rescan: bool = False) -> UrlAnalysisResult:
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
            return create_safe_domain_result(url, "Domain is in the known safe list")

        if self.csrf_token is None:
            try:
                main_page = self.init_session()
            except requests.exceptions.RequestException as e:
                raise NetworkError(
                    f"Failed to connect to Zulu Zscaler: {e}",
                    url=url,
                    original_exception=e,
                ) from e
        else:
            main_page = self.session.get(
                self.base_url, headers=self.headers, timeout=self.REQUEST_TIMEOUT
            ).text

        analyze_endpoint = self._extract_form_endpoint(main_page)

        headers = self._build_analyze_request_headers()

        response = self._fetch_analysis_page(url, analyze_endpoint, headers)

        # Check for rate limiting
        if response.status_code == 429:
            return create_rate_limited_result(
                url,
                "Rate limited - too many requests. Please wait before retrying.",
            )

        if response.status_code >= 400:
            return create_error_result(
                url,
                f"HTTP {response.status_code} from Zulu Zscaler",
                response.status_code,
                retryable=response.status_code >= 500,
            )

        # Handle force_rescan: trigger a fresh analysis
        if force_rescan:
            response = self._handle_force_rescan(response, url)

        scan_status = self._parse_scan_status(response.text)
        result = self._build_initial_result(url, response, scan_status)

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

            # Parse analysis sections using existing helper methods
            analysis = self._parse_basic_analysis(response.text)

            # Parse domain history using existing helper method
            domain_history = self._parse_domain_history(response.text)
            if domain_history:
                analysis["domain_history"] = domain_history

            result["analysis"] = analysis

            # Parse all check sections using existing helper method
            sections_data = self._parse_all_check_sections(response.text)
            for section_key, items in sections_data.items():
                if items:
                    result[section_key] = items
        else:
            result["analysis"] = {}

        return result


def main() -> None:
    """Entry point for CLI usage."""
    configure_logging()
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
    except (ZuluException, requests.exceptions.RequestException) as e:
        logger.error("Error: %s", str(e))
        logger.error(
            "Note: Check if the Zulu Zscaler website is reachable and you are not hitting rate limits."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
