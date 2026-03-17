"""
Standardized result types for Zscaler-Zulu URL analysis.

Provides consistent return shapes from analyze_url() and related functions.
Uses TypedDict for type checking while maintaining backward compatibility.
"""

from __future__ import annotations

from typing import Dict, Any, Optional, Literal, Union
from typing_extensions import TypedDict, Required, NotRequired


# Base fields present in all result types
class _BaseFields(TypedDict):
    """Base fields common to all result types."""

    url: str
    status: str
    Status: str  # Backward compatibility with existing callers


class SafeDomainResult(_BaseFields, TypedDict):
    """Result for URLs that match the safe domain list."""

    url: str
    status: Required[Literal["safe"]]
    Status: str
    message: str


class RateLimitedResult(_BaseFields, TypedDict):
    """Result when rate limit is hit."""

    url: str
    status: Required[Literal["rate_limited"]]
    Status: str
    status_code: Required[int]
    error: str
    retry_after: NotRequired[int]  # Optional: seconds to wait


class ErrorResult(_BaseFields, TypedDict):
    """Result for error cases."""

    url: str
    status: Required[Literal["error"]]
    Status: str
    status_code: int
    error: str
    retryable: NotRequired[bool]  # Optional: whether to retry


class InProgressResult(_BaseFields, TypedDict):
    """Result for polling async analysis status."""

    url: str
    status: Required[Literal["in_progress"]]
    Status: str


class AnalysisResult(_BaseFields, TypedDict):
    """Full analysis result with all fields from completed analysis."""

    url: str
    status: Required[Literal["completed", "failed"]]
    Status: str
    status_code: int
    score: int
    classification: str
    analysis: Dict[str, Any]  # Contains detailed analysis data
    content_checks: NotRequired[Dict[str, Any]]
    url_checks: NotRequired[Dict[str, Any]]
    host_checks: NotRequired[Dict[str, Any]]
    error: NotRequired[str]
    message: NotRequired[str]


# Union type for all possible result types
UrlAnalysisResult = Union[
    SafeDomainResult,
    RateLimitedResult,
    ErrorResult,
    InProgressResult,
    AnalysisResult,
]


# ============================================================================
# Factory Functions
# ============================================================================


def create_safe_domain_result(url: str, message: str) -> SafeDomainResult:
    """
    Create a safe domain result.

    Args:
        url: The analyzed URL
        message: Explanation of why the domain is safe

    Returns:
        SafeDomainResult dict with status="safe"
    """
    return SafeDomainResult(
        url=url,
        status="safe",
        Status="Safe",
        message=message,
    )


def create_rate_limited_result(
    url: str,
    error: str,
    status_code: int = 429,
    retry_after: Optional[int] = None,
) -> RateLimitedResult:
    """
    Create a rate limit result.

    Args:
        url: The analyzed URL
        error: Error message
        status_code: HTTP status code (default: 429)
        retry_after: Optional seconds to wait before retry

    Returns:
        RateLimitedResult dict with status="rate_limited"
    """
    result: RateLimitedResult = RateLimitedResult(
        url=url,
        status="rate_limited",
        Status="Rate Limited",
        status_code=status_code,
        error=error,
    )
    if retry_after is not None:
        result["retry_after"] = retry_after
    return result


def create_error_result(
    url: str,
    error: str,
    status_code: int,
    retryable: bool = False,
) -> ErrorResult:
    """
    Create an error result.

    Args:
        url: The analyzed URL
        error: Error message
        status_code: HTTP status code
        retryable: Whether the operation can be retried (default: False)

    Returns:
        ErrorResult dict with status="error"
    """
    result: ErrorResult = ErrorResult(
        url=url,
        status="error",
        Status="Error",
        status_code=status_code,
        error=error,
    )
    if retryable:
        result["retryable"] = retryable
    return result


def create_in_progress_result(url: str) -> InProgressResult:
    """
    Create an in-progress result for polling.

    Args:
        url: The analyzed URL

    Returns:
        InProgressResult dict with status="in_progress"
    """
    return InProgressResult(
        url=url,
        status="in_progress",
        Status="In Progress",
    )


def create_analysis_result(
    url: str,
    status_code: int,
    score: int,
    classification: str,
    analysis: Dict[str, Any],
    content_checks: Optional[Dict[str, Any]] = None,
    url_checks: Optional[Dict[str, Any]] = None,
    host_checks: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
    message: Optional[str] = None,
) -> AnalysisResult:
    """
    Create a full analysis result from completed URL analysis.

    Args:
        url: The analyzed URL
        status_code: HTTP status code
        score: Risk score (0-100)
        classification: Risk classification (e.g., "safe", "suspicious", "malicious")
        analysis: Detailed analysis data dict
        content_checks: Optional content check results
        url_checks: Optional URL check results
        host_checks: Optional host check results
        error: Optional error message
        message: Optional additional message

    Returns:
        AnalysisResult dict with status="completed" or "failed"
    """
    # Determine status based on error presence
    status_value: Literal["completed", "failed"] = "failed" if error else "completed"

    result: AnalysisResult = AnalysisResult(
        url=url,
        status=status_value,
        Status=status_value.replace("_", " ").title(),
        status_code=status_code,
        score=score,
        classification=classification,
        analysis=analysis,
    )

    # Add optional fields if provided
    if content_checks is not None:
        result["content_checks"] = content_checks
    if url_checks is not None:
        result["url_checks"] = url_checks
    if host_checks is not None:
        result["host_checks"] = host_checks
    if error is not None:
        result["error"] = error
    if message is not None:
        result["message"] = message

    return result


# ============================================================================
# Helper Functions
# ============================================================================


def get_status(result: UrlAnalysisResult) -> str:
    """
    Get the status from any result type.

    Args:
        result: Any UrlAnalysisResult type

    Returns:
        The status string
    """
    return result["status"]


def is_safe(result: UrlAnalysisResult) -> bool:
    """
    Check if the result indicates a safe URL.

    Args:
        result: Any UrlAnalysisResult type

    Returns:
        True if the URL is safe
    """
    return result["status"] == "safe" or (
        result.get("classification", "").lower() == "safe" and not result.get("error")
    )


def is_error(result: UrlAnalysisResult) -> bool:
    """
    Check if the result indicates an error state.

    Args:
        result: Any UrlAnalysisResult type

    Returns:
        True if the result is an error or rate limited
    """
    return result["status"] in ("error", "rate_limited")
