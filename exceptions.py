"""
Custom exception classes for Zscaler-Zulu.

This module provides a hierarchy of custom exceptions for better error handling
and type safety in the Zscaler-Zulu URL analysis tool.
"""

from typing import Optional


class ZuluException(Exception):
    """Base exception class for all Zscaler-Zulu errors.

    Attributes:
        message: The error message.
        url: Optional URL related to the error.
        original_exception: The original exception that caused this error, if any.
    """

    def __init__(
        self,
        message: str,
        url: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        """Initialize ZuluException.

        Args:
            message: The error message.
            url: Optional URL related to the error.
            original_exception: The original exception that caused this error.
        """
        self.message = message
        self.url = url
        self.original_exception = original_exception

        # Build error message with context (handled in base class)
        super().__init__(message, url, original_exception)

    def __str__(self) -> str:
        parts = [self.message]
        if self.url:
            parts.append(f"URL: {self.url}")
        if self.original_exception:
            parts.append(
                f"Caused by: {type(self.original_exception).__name__}: {self.original_exception}"
            )
        return " | ".join(parts)


class URLValidationError(ZuluException, ValueError):
    """Exception raised for invalid URL validation errors.

    This includes errors related to:
    - Invalid or missing URL scheme
    - Invalid or malformed hostname
    - Blocked IP addresses
    - Malformed URL structure
    """

    def __init__(
        self,
        message: str = "URL validation failed",
        url: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        """Initialize URLValidationError.

        Args:
            message: The error message (default: "URL validation failed").
            url: Optional URL that failed validation.
            original_exception: The original exception, if any.
        """
        super().__init__(message, url, original_exception)


class RateLimitError(ZuluException):
    """Exception raised when HTTP 429 rate limit is exceeded.

    This exception indicates that the API or service is rate-limiting requests.
    The client should wait before retrying or back off appropriately.
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded (HTTP 429)",
        url: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        """Initialize RateLimitError.

        Args:
            message: The error message (default: "Rate limit exceeded (HTTP 429)").
            url: Optional URL that was rate-limited.
            original_exception: The original exception, if any.
        """
        super().__init__(message, url, original_exception)


class AnalysisError(ZuluException):
    """Exception raised for analysis/parsing failures.

    This includes errors related to:
    - HTML parsing failures
    - Content extraction failures
    - Schema validation errors
    - Data structure inconsistencies
    """

    def __init__(
        self,
        message: str = "Analysis failed",
        url: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        """Initialize AnalysisError.

        Args:
            message: The error message (default: "Analysis failed").
            url: Optional URL that failed analysis.
            original_exception: The original exception, if any.
        """
        super().__init__(message, url, original_exception)


class NetworkError(ZuluException):
    """Exception raised for network-related issues.

    This includes errors related to:
    - DNS resolution failures
    - Connection timeouts
    - Connection refused
    - SSL/TLS certificate errors
    - Other HTTP/HTTPS transport layer issues
    """

    def __init__(
        self,
        message: str = "Network error occurred",
        url: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ) -> None:
        """Initialize NetworkError.

        Args:
            message: The error message (default: "Network error occurred").
            url: Optional URL that failed to connect.
            original_exception: The original exception, if any.
        """
        super().__init__(message, url, original_exception)


__all__ = [
    "ZuluException",
    "URLValidationError",
    "RateLimitError",
    "AnalysisError",
    "NetworkError",
]
