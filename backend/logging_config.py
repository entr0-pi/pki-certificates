"""
Centralized logging configuration for PKI Management System.

Provides ISO 8601 formatted logs with consistent timestamp, level, and message format
across application logs, Uvicorn HTTP access logs, and utility scripts.

Format: 2026-03-15T15:34:57.734Z - INFO - message
"""

import logging
import os
from datetime import datetime, timezone


class ISO8601Formatter(logging.Formatter):
    """Custom logging formatter that produces ISO 8601 timestamps."""

    def format(self, record):
        # Create ISO 8601 timestamp with milliseconds and Z suffix
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        iso_timestamp = dt.strftime('%Y-%m-%dT%H:%M:%S') + f'.{int(record.msecs):03d}Z'

        # Format: timestamp - level - message
        return f"{iso_timestamp} - {record.levelname} - {record.getMessage()}"


def configure_app_logging():
    """Configure application logging with ISO 8601 format."""
    log_level = os.environ.get("PKI_LOG_LEVEL", "INFO").upper()
    log_level_obj = getattr(logging, log_level, logging.INFO)

    # Get root logger and remove any existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler with ISO 8601 formatter
    handler = logging.StreamHandler()
    handler.setFormatter(ISO8601Formatter())

    root_logger.addHandler(handler)
    root_logger.setLevel(log_level_obj)


def get_uvicorn_log_config():
    """
    Get Uvicorn logging configuration dict in Uvicorn's standard format.

    Returns a configuration compatible with uvicorn.run(log_config=...)
    """
    log_level = os.environ.get("PKI_LOG_LEVEL", "INFO").upper()

    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "iso8601": {
                "()": ISO8601Formatter,
            },
        },
        "handlers": {
            "default": {
                "formatter": "iso8601",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
            },
            "access": {
                "formatter": "iso8601",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "uvicorn": {"handlers": ["default"], "level": log_level},
            "uvicorn.access": {"handlers": ["access"], "level": log_level, "propagate": False},
        },
    }
