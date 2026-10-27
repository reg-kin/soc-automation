"""Allowlisted JSON logging. Untrusted messages and exception text are never emitted."""

import json
import logging
from datetime import UTC, datetime
from typing import TextIO

# Callers supply event codes, never raw alerts, credentials, URLs, or headers.
EVENTS = frozenset({"config_valid", "database_initialized", "healthcheck_ok", "command_failed"})


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = record.msg if isinstance(record.msg, str) and record.msg in EVENTS else "redacted"
        return json.dumps(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "level": record.levelname
                if record.levelname in logging._nameToLevel
                else "UNKNOWN",
                "event": event,
            },
            separators=(",", ":"),
        )


def configure_logging(level: str, stream: TextIO | None = None) -> logging.Logger:
    logger = logging.getLogger("soc_automation")
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.handlers[:] = [handler]
    logger.setLevel(level)
    logger.propagate = False
    return logger
