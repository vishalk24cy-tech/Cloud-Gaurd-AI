"""
CloudGuardAI structured security logging.

Production-safe logging:
- JSON logs for ingestion by Render/AWS/ELK/Datadog/etc.
- Never logs passwords, JWTs, Authorization headers, cookies, AWS secrets,
  or request bodies.
- Supports request correlation through X-Request-ID.
- Writes to stdout by default; optionally to a rotating local file.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler
from typing import Any

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "set-cookie",
    "api_key",
    "apikey",
    "client_secret",
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "private_key",
}

LOGGER_NAME = "cloudguardai"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.getenv("LOG_FILE", "").strip()


def _sanitize(value: Any, key: str | None = None) -> Any:
    """Recursively remove/replace sensitive values before logging."""
    if key and key.lower().replace("-", "_") in {
        item.replace("-", "_") for item in SENSITIVE_KEYS
    }:
        return "[REDACTED]"

    if isinstance(value, dict):
        return {str(k): _sanitize(v, str(k)) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(value)


class JsonFormatter(logging.Formatter):
    """Compact structured JSON formatter."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        event = getattr(record, "event", None)
        if event:
            payload["event"] = event

        fields = getattr(record, "fields", None)
        if fields:
            payload.update(_sanitize(fields))

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging() -> logging.Logger:
    """Configure the application logger once."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    logger.propagate = False

    if getattr(logger, "_cloudguard_configured", False):
        return logger

    formatter = JsonFormatter()

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    if LOG_FILE:
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger._cloudguard_configured = True
    return logger


logger = configure_logging()


def log_event(
    level: int,
    event: str,
    *,
    request_id: str | None = None,
    **fields: Any,
) -> None:
    """Write a sanitized structured security/application event."""
    safe_fields = _sanitize(fields)
    if request_id:
        safe_fields["request_id"] = request_id

    logger.log(
        level,
        event,
        extra={
            "event": event,
            "fields": safe_fields,
        },
    )


def log_request(
    *,
    request_id: str,
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    client_ip: str | None,
    user_id: str | None = None,
) -> None:
    """Log a completed HTTP request without sensitive request data."""
    level = logging.INFO if status_code < 500 else logging.ERROR

    log_event(
        level,
        "REQUEST_COMPLETED",
        request_id=request_id,
        method=method,
        path=path,
        status_code=status_code,
        duration_ms=round(duration_ms, 2),
        client_ip=client_ip or "unknown",
        user_id=user_id,
    )


def log_exception(
    *,
    request_id: str,
    method: str,
    path: str,
    status_code: int,
    exception_type: str,
) -> None:
    log_event(
        logging.ERROR,
        "REQUEST_EXCEPTION",
        request_id=request_id,
        method=method,
        path=path,
        status_code=status_code,
        exception_type=exception_type,
    )
