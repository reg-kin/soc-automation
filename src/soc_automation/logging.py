"""Allowlisted JSON logging. Untrusted messages and exception text are never emitted."""

import json
import logging
import math
import re
from datetime import UTC, datetime
from typing import TextIO

# Callers supply event codes, never raw alerts, credentials, URLs, or headers.
EVENTS = frozenset({"config_valid", "database_initialized", "healthcheck_ok", "command_failed"})


OPERATIONAL_EVENTS = frozenset(
    {
        "job_claim",
        "job_completed",
        "investigation_partial",
        "retry_scheduled",
        "job_failed",
        "engine_mismatch",
        "lease_renewal_failed",
        "execution_deadline",
        "expired_lease_recovery",
    }
)
DIAGNOSTICS = frozenset(
    {
        "claimed",
        "completed",
        "partial",
        "transient",
        "permanent",
        "engine_mismatch",
        "lease_renewal_failed",
        "execution_deadline",
        "lease_expired",
    }
)


def operational_event(event, job, *, code, duration=None):
    fields = {
        "job_id": job["id"],
        "worker_id": job.get("lease_owner"),
        "lease_generation": job["lease_generation"],
        "attempt_number": job["attempt_count"],
        "queue_state": job["state"],
        "diagnostic_code": code,
        "investigation_id": job.get("investigation_id"),
        "duration_seconds": duration,
    }
    logging.getLogger("soc_automation").info(event, extra={"operational": fields})


def safe_fields(fields):
    if not isinstance(fields, dict):
        return {}
    result = {}
    for key in ("job_id", "worker_id", "investigation_id"):
        value = fields.get(key)
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
            result[key] = value
    for key in ("lease_generation", "attempt_number"):
        value = fields.get(key)
        if type(value) is int and value >= 0:
            result[key] = value
    if isinstance(fields.get("queue_state"), str) and fields["queue_state"] in {
        "queued",
        "leased",
        "retry_wait",
        "completed",
        "failed",
    }:
        result["queue_state"] = fields["queue_state"]
    if isinstance(fields.get("diagnostic_code"), str) and fields["diagnostic_code"] in DIAGNOSTICS:
        result["diagnostic_code"] = fields["diagnostic_code"]
    value = fields.get("duration_seconds")
    if type(value) in (int, float) and math.isfinite(value) and value >= 0:
        result["duration_seconds"] = value
    return result


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = (
            record.msg
            if isinstance(record.msg, str) and record.msg in EVENTS | OPERATIONAL_EVENTS
            else "redacted"
        )
        return json.dumps(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "level": record.levelname
                if record.levelname in logging._nameToLevel
                else "UNKNOWN",
                "event": event,
                **(
                    safe_fields(getattr(record, "operational", None))
                    if event in OPERATIONAL_EVENTS
                    else {}
                ),
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
