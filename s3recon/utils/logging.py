"""Structured logging setup. Never logs secrets."""

from __future__ import annotations

import logging
import sys

SENSITIVE_KEYS = {
    "password", "secret", "token", "api_key", "apikey",
    "access_key", "secret_key", "authorization", "credential", "private_key",
}


class SecretFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            lower = record.msg.lower()
            for key in SENSITIVE_KEYS:
                if key in lower:
                    record.msg = "[REDACTED - potential secret in log message]"
                    break
        return True


def setup_logging(level: str = "INFO", verbose: bool = False) -> None:
    log_level = logging.DEBUG if verbose else getattr(logging, level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(log_level)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    handler.addFilter(SecretFilter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
