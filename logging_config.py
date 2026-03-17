"""
Logging configuration module for Zscaler-Zulu.

This module provides centralized logging utilities to replace stderr print statements.
It supports both standard text logging and optional JSON structured logging.

Usage:
    from logging_config import get_logger, configure_logging

    configure_logging(level=logging.INFO)
    logger = get_logger(__name__)
    logger.info("Application started")
"""

import logging
import sys
from typing import Optional
import json
from datetime import datetime

# Module-level configuration
_logging_configured = False
_log_format: Optional[str] = None
_json_output: bool = False


def configure_logging(
    level: int = logging.INFO,
    format: Optional[str] = None,
    json_output: bool = False,
) -> None:
    """
    Configure the root logger for the application.

    This function should be called once at application startup to set up
    consistent logging behavior across all modules.

    Args:
        level: Logging level (e.g., logging.DEBUG, logging.INFO, logging.WARNING).
               Defaults to logging.INFO.
        format: Custom format string for log messages. If None, uses the default:
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        json_output: If True, logs will be output in JSON format for structured
                     logging. Defaults to False.

    Example:
        configure_logging(level=logging.DEBUG)
        configure_logging(level=logging.INFO, json_output=True)
    """
    global _logging_configured, _log_format, _json_output

    _log_format = format or "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    _json_output = json_output

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove any existing handlers
    root_logger.handlers.clear()

    # Create the appropriate handler based on output format
    if _json_output:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(_log_format))

    root_logger.addHandler(handler)

    _logging_configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module or component.

    This is the primary way to obtain a logger throughout the application.
    The logger will inherit the configuration set by configure_logging().

    Args:
        name: The name of the logger, typically __name__ for the calling module.

    Returns:
        A configured logger instance ready for use.

    Example:
        logger = get_logger(__name__)
        logger.info("Processing started")
        logger.error("An error occurred: %s", error_message)
    """
    return logging.getLogger(name)


class JsonFormatter(logging.Formatter):
    """
    Custom formatter that outputs log messages in JSON format.

    This formatter creates structured log records suitable for log aggregation
    tools and cloud logging services. Each log entry becomes a JSON object
    with consistent field names.
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record as a JSON string.

        Args:
            record: The log record to format.

        Returns:
            A JSON string representation of the log record.
        """
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


# Module-level logger for the main module
def get_main_logger() -> logging.Logger:
    """
    Get a logger specifically for the main Zscaler-Zulu module.

    This is a convenience function for getting a logger for the main
    application entry point.

    Returns:
        A logger instance named 'zulu'.

    Example:
        logger = get_main_logger()
        logger.info("Zscaler-Zulu analyzer initialized")
    """
    return get_logger("zulu")


# Default configuration (will be applied when logging is first used)
_default_level = logging.INFO
_default_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
