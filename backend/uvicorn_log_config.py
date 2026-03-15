"""
Uvicorn logging configuration for PKI Management System.

Integrates with the centralized logging_config to provide ISO 8601 formatted
access logs and application logs.

This module can be passed to uvicorn via the --log-config flag.
"""

import os
import sys
from logging_config import ISO8601Formatter

# Get log level from environment
log_level = os.environ.get("PKI_LOG_LEVEL", "INFO").upper()

# Uvicorn-compatible logging config dictionary
LOGGING_CONFIG = {
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
        "uvicorn.error": {"handlers": ["default"], "level": log_level},
    },
}
