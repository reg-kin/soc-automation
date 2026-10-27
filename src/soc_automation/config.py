"""Strict configuration, supplied exclusively through the environment."""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
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
        allowed.update(ES_PREFIX + name for name in ES_NAMES)
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
        if any(key.startswith(ES_PREFIX) for key in values):
            ElasticsearchSettings.from_env(values)
        return cls(path, level, int(timeout))


ES_PREFIX = "SOC_ELASTICSEARCH_"
ES_NAMES = {
    "URL",
    "API_KEY",
    "ALERT_INDICES",
    "SOURCE_INDICES",
    "CA_PATH",
    "CONNECT_TIMEOUT",
    "READ_TIMEOUT",
    "MAX_DOCUMENTS",
    "MAX_RESPONSE_BYTES",
    "MAX_DOCUMENT_BYTES",
    "RETRIES",
    "BACKOFF",
}


@dataclass(frozen=True)
class ElasticsearchSettings:
    url: str
    api_key: str = field(repr=False)
    alert_indices: tuple[str, ...] = ()
    source_indices: tuple[str, ...] = ()
    ca_path: Path | None = None
    connect_timeout: int = 5
    read_timeout: int = 10
    max_documents: int = 100
    max_response_bytes: int = 1_048_576
    max_document_bytes: int = 262_144
    retries: int = 2
    backoff: int = 1

    def __post_init__(self):
        import base64
        import re
        import ssl
        from urllib.parse import urlsplit

        try:
            url = urlsplit(self.url)
            if (
                url.scheme != "https"
                or not url.hostname
                or url.username
                or url.password
                or url.query
                or url.fragment
                or url.path not in ("", "/")
                or any(ord(c) <= 32 or ord(c) >= 127 for c in self.url)
                or any(c in self.url for c in "\\?#")
                or not re.fullmatch(r"[A-Za-z0-9.:-]+", url.hostname)
                or url.port == 0
            ):
                raise ValueError
            if not isinstance(self.api_key, str) or len(self.api_key) > 8192:
                raise ValueError
            decoded = base64.b64decode(self.api_key, validate=True).decode("ascii")
            if not re.fullmatch(r"[!-9;-~]+:[!-9;-~]+", decoded):
                raise ValueError
            for indices in (self.alert_indices, self.source_indices):
                if not isinstance(indices, tuple) or not indices or len(indices) > 100:
                    raise ValueError
                for index in indices:
                    if (
                        not isinstance(index, str)
                        or index in {"*", ".", ".."}
                        or not re.fullmatch(r"[a-z0-9_.-][a-z0-9_.*?-]{0,254}", index)
                        or not any(c.isalnum() for c in index)
                    ):
                        raise ValueError
            bounds = {
                "connect_timeout": (1, 60),
                "read_timeout": (1, 120),
                "max_documents": (1, 100),
                "max_response_bytes": (1, 16_777_216),
                "max_document_bytes": (1, 262_144),
                "retries": (0, 3),
                "backoff": (0, 5),
            }
            for name, (low, high) in bounds.items():
                value = getattr(self, name)
                if type(value) is not int or not low <= value <= high:
                    raise ValueError
            if self.ca_path is not None:
                if not self.ca_path.is_absolute() or not self.ca_path.is_file():
                    raise ValueError
                ssl.create_default_context(cafile=str(self.ca_path))
        except (ValueError, TypeError, OSError, UnicodeError):
            raise ConfigurationError("Invalid Elasticsearch configuration") from None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ElasticsearchSettings":
        values = os.environ if env is None else env
        try:
            if any(
                key.startswith(ES_PREFIX) and key[len(ES_PREFIX) :] not in ES_NAMES
                for key in values
            ):
                raise ValueError
            kwargs = {}
            for name in ES_NAMES:
                value = values.get(ES_PREFIX + name)
                if value is None:
                    continue
                key = name.lower()
                if name in {"ALERT_INDICES", "SOURCE_INDICES"}:
                    value = tuple(value.split(","))
                elif name == "CA_PATH":
                    value = Path(value) if value else Path("")
                elif name not in {"URL", "API_KEY"}:
                    value = int(value)
                kwargs[key] = value
            return cls(**kwargs)
        except (ValueError, TypeError):
            raise ConfigurationError("Invalid Elasticsearch configuration") from None
