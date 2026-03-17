#!/usr/bin/env python3
"""
Unit tests for zulu_analyze.py - Security and URL validation tests.

Run with: python -m pytest test_zulu_analyze.py -v
Or: python test_zulu_analyze.py
"""

import unittest
import sys
from io import StringIO

from zulu_analyze import ZuluZscaler


class TestURLValidation(unittest.TestCase):
    """Tests for URL validation and SSRF protection."""

    def setUp(self):
        self.zulu = ZuluZscaler()

    # Valid URLs that should pass
    def test_valid_https_url(self):
        """Valid HTTPS URL should pass validation."""
        result = ZuluZscaler._validate_url("https://example.com")
        self.assertEqual(result, "https://example.com")

    def test_valid_http_url(self):
        """Valid HTTP URL should pass validation."""
        result = ZuluZscaler._validate_url("http://example.com")
        self.assertEqual(result, "http://example.com")

    def test_url_without_scheme_adds_https(self):
        """URL without scheme should get https:// prefix."""
        result = ZuluZscaler._validate_url("example.com")
        self.assertEqual(result, "https://example.com")

    def test_url_with_path(self):
        """URL with path should pass validation."""
        result = ZuluZscaler._validate_url("https://example.com/path/to/page")
        self.assertEqual(result, "https://example.com/path/to/page")

    def test_url_with_query(self):
        """URL with query string should pass validation."""
        result = ZuluZscaler._validate_url("https://example.com/page?query=value")
        self.assertEqual(result, "https://example.com/page?query=value")

    def test_url_with_port(self):
        """URL with port should pass validation."""
        result = ZuluZscaler._validate_url("https://example.com:8080")
        self.assertEqual(result, "https://example.com:8080")

    def test_subdomain(self):
        """Subdomain should pass validation."""
        result = ZuluZscaler._validate_url("https://sub.example.com")
        self.assertEqual(result, "https://sub.example.com")

    # SSRF Protection Tests - IP addresses should be blocked
    def test_block_localhost_ip(self):
        """127.0.0.1 should be blocked."""
        with self.assertRaises(ValueError) as ctx:
            ZuluZscaler._validate_url("http://127.0.0.1")
        self.assertIn("IP addresses", str(ctx.exception))

    def test_block_private_ip_10_range(self):
        """10.x.x.x private IP should be blocked."""
        with self.assertRaises(ValueError) as ctx:
            ZuluZscaler._validate_url("http://10.0.0.1")
        self.assertIn("IP addresses", str(ctx.exception))

    def test_block_private_ip_192_168_range(self):
        """192.168.x.x private IP should be blocked."""
        with self.assertRaises(ValueError) as ctx:
            ZuluZscaler._validate_url("http://192.168.1.1")
        self.assertIn("IP addresses", str(ctx.exception))

    def test_block_private_ip_172_range(self):
        """172.16.x.x private IP should be blocked."""
        with self.assertRaises(ValueError) as ctx:
            ZuluZscaler._validate_url("http://172.16.0.1")
        self.assertIn("IP addresses", str(ctx.exception))

    def test_block_aws_metadata_endpoint(self):
        """AWS metadata IP 169.254.169.254 should be blocked."""
        with self.assertRaises(ValueError) as ctx:
            ZuluZscaler._validate_url("http://169.254.169.254")
        self.assertIn("IP addresses", str(ctx.exception))

    def test_block_public_ip(self):
        """Even public IP addresses should be blocked."""
        with self.assertRaises(ValueError) as ctx:
            ZuluZscaler._validate_url("http://8.8.8.8")
        self.assertIn("IP addresses", str(ctx.exception))

    # Scheme Validation Tests
    def test_block_file_scheme(self):
        """file:// scheme should be blocked."""
        with self.assertRaises(ValueError) as ctx:
            ZuluZscaler._validate_url("file:///etc/passwd")
        self.assertIn("http/https", str(ctx.exception).lower())

    def test_block_javascript_scheme(self):
        """javascript: scheme should be blocked."""
        with self.assertRaises(ValueError) as ctx:
            ZuluZscaler._validate_url("javascript:alert(1)")
        self.assertIn("http/https", str(ctx.exception).lower())

    def test_block_ftp_scheme(self):
        """ftp:// scheme should be blocked."""
        with self.assertRaises(ValueError) as ctx:
            ZuluZscaler._validate_url("ftp://example.com/file")
        self.assertIn("http/https", str(ctx.exception).lower())

    def test_block_gopher_scheme(self):
        """gopher:// scheme should be blocked."""
        with self.assertRaises(ValueError) as ctx:
            ZuluZscaler._validate_url("gopher://example.com")
        self.assertIn("http/https", str(ctx.exception).lower())

    # Invalid Input Tests
    def test_empty_url(self):
        """Empty URL should raise ValueError."""
        with self.assertRaises(ValueError):
            ZuluZscaler._validate_url("")

    def test_none_url(self):
        """None URL should raise ValueError."""
        with self.assertRaises(ValueError):
            ZuluZscaler._validate_url(None)

    def test_whitespace_only_url(self):
        """Whitespace-only URL should raise ValueError after trim."""
        with self.assertRaises(ValueError):
            ZuluZscaler._validate_url("   ")

    def test_invalid_hostname_chars(self):
        """Hostname with invalid characters should be blocked."""
        with self.assertRaises(ValueError):
            ZuluZscaler._validate_url("http://example_.com")

    def test_hostname_starts_with_hyphen(self):
        """Hostname starting with hyphen should be blocked."""
        with self.assertRaises(ValueError):
            ZuluZscaler._validate_url("http://-example.com")


class TestSafeDomains(unittest.TestCase):
    """Tests for safe domain checking."""

    def test_default_safe_domain(self):
        """Default safe domain should be recognized."""
        zulu = ZuluZscaler()
        self.assertTrue(zulu.is_safe_domain("example.com"))

    def test_custom_safe_domains(self):
        """Custom safe domains should be recognized."""
        zulu = ZuluZscaler(default_safe_domains=["trusted.com", "safe.org"])
        self.assertTrue(zulu.is_safe_domain("trusted.com"))
        self.assertTrue(zulu.is_safe_domain("safe.org"))
        self.assertFalse(zulu.is_safe_domain("untrusted.com"))

    def test_safe_domain_with_www(self):
        """Safe domain check should handle www prefix."""
        zulu = ZuluZscaler(default_safe_domains=["example.com"])
        self.assertTrue(zulu.is_safe_domain("www.example.com"))

    def test_non_safe_domain(self):
        """Non-safe domain should return False."""
        zulu = ZuluZscaler()
        self.assertFalse(zulu.is_safe_domain("malicious.com"))


class TestSSLWarning(unittest.TestCase):
    """Tests for SSL verification behavior."""

    def test_ssl_warning_on_no_verify(self):
        """Warning should be logged when SSL verification is disabled."""
        with self.assertLogs("zulu_analyze", level="WARNING") as cm:
            ZuluZscaler(verify_ssl=False)
        self.assertTrue(any("SSL" in msg for msg in cm.output))
        self.assertTrue(any("MITM" in msg for msg in cm.output))

    def test_no_warning_with_ssl_verify(self):
        """No warning should be printed when SSL verification is enabled."""
        captured_output = StringIO()
        sys.stderr = captured_output

        ZuluZscaler(verify_ssl=True)

        sys.stderr = sys.__stderr__
        output = captured_output.getvalue()
        self.assertNotIn("WARNING", output)


class TestPolling(unittest.TestCase):
    """Tests for polling functionality."""

    def test_max_retries_parameter_exists(self):
        """poll_until_completed should accept max_retries parameter via PollConfig."""
        # This is a smoke test - we're just checking that PollConfig has max_retries
        from zulu_analyze import PollConfig

        # Check that PollConfig has max_retries attribute
        self.assertTrue(hasattr(PollConfig, "__annotations__"))
        self.assertIn("max_retries", PollConfig.__annotations__)
        self.assertEqual(PollConfig.__annotations__["max_retries"], int)

        # Also verify the method signature uses config parameter
        import inspect

        sig = inspect.signature(ZuluZscaler.poll_until_completed)
        params = list(sig.parameters.keys())
        self.assertIn("config", params)

    def test_force_rescan_parameter_exists(self):
        """poll_until_completed should accept force_rescan parameter."""
        import inspect

        sig = inspect.signature(ZuluZscaler.poll_until_completed)
        params = list(sig.parameters.keys())
        self.assertIn("force_rescan", params)

    def test_analyze_url_force_rescan_parameter_exists(self):
        """analyze_url should accept force_rescan parameter."""
        import inspect

        sig = inspect.signature(ZuluZscaler.analyze_url)
        params = list(sig.parameters.keys())
        self.assertIn("force_rescan", params)
