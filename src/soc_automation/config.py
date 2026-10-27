"""Strict configuration, supplied exclusively through the environment."""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


class ConfigurationError(ValueError):
    """Configuration is missing, unknown, or unsafe."""


@dataclass(frozen=True)
class Settings:
    database_path: Path
    log_level: str = "INFO"
    database_timeout_seconds: int = 5

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        values = os.environ if env is None else env
        allowed = {"SOC_DATABASE_PATH", "SOC_LOG_LEVEL", "SOC_DATABASE_TIMEOUT_SECONDS"}
        if any(key.startswith("SOC_") and key not in allowed for key in values):
            raise ConfigurationError("Unknown SOC_ configuration variable")
        raw_path = values.get("SOC_DATABASE_PATH", "")
        if not raw_path or raw_path != raw_path.strip() or "\x00" in raw_path:
            raise ConfigurationError("SOC_DATABASE_PATH must be an absolute file path")
        path = Path(raw_path)
        if not path.is_absolute() or path.name != "soc_automation.db" or path.is_dir():
            raise ConfigurationError(
                "SOC_DATABASE_PATH must be absolute and name soc_automation.db"
            )
        level = values.get("SOC_LOG_LEVEL", "INFO")
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigurationError("SOC_LOG_LEVEL is invalid")
        timeout = values.get("SOC_DATABASE_TIMEOUT_SECONDS", "5")
        if not timeout.isascii() or not timeout.isdecimal() or not 1 <= int(timeout) <= 60:
            raise ConfigurationError("SOC_DATABASE_TIMEOUT_SECONDS must be an integer from 1 to 60")
        return cls(path, level, int(timeout))
