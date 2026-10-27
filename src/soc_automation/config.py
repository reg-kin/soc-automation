"""Strict configuration, supplied exclusively through the environment."""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path


class ConfigurationError(ValueError):
    """Configuration is missing, unknown, or unsafe."""


def _validate_https_url(value: str):
    import re
    from urllib.parse import urlsplit

    url = urlsplit(value)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in ("", "/")
        or any(ord(c) <= 32 or ord(c) >= 127 for c in value)
        or any(c in value for c in "\\?#")
        or not re.fullmatch(r"[A-Za-z0-9.:-]+", url.hostname)
        or url.port == 0
    ):
        raise ValueError


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
        allowed.update(KIBANA_PREFIX + name for name in KIBANA_NAMES)
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
        if any(key.startswith(KIBANA_PREFIX) for key in values):
            KibanaTargetSettings.from_env(values)
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

        try:
            _validate_https_url(self.url)
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


KIBANA_PREFIX = "SOC_KIBANA_"
KIBANA_NAMES = {
    "URL",
    "API_KEY",
    "SPACE",
    "CA_PATH",
    "CONNECT_TIMEOUT",
    "READ_TIMEOUT",
    "MAX_RESPONSE_BYTES",
}


@dataclass(frozen=True)
class KibanaTargetSettings:
    """Validated destination identity without credentials or transport setup."""

    url: str
    space: str = "default"

    def __post_init__(self):
        try:
            _validate_https_url(self.url)
        except (ValueError, TypeError, UnicodeError):
            raise ConfigurationError("Invalid Kibana target configuration") from None
        if self.space != "default":
            raise ConfigurationError("Only the default Kibana space is supported")

    @property
    def target(self):
        from urllib.parse import urlsplit

        url = urlsplit(self.url)
        host = url.hostname.lower()
        if ":" in host:
            host = "[" + host + "]"
        port = "" if url.port in {None, 443} else ":" + str(url.port)
        return "https://" + host + port + "/default/securitySolution"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None):
        values = os.environ if env is None else env
        if any(
            key.startswith(KIBANA_PREFIX) and key[len(KIBANA_PREFIX) :] not in KIBANA_NAMES
            for key in values
        ):
            raise ConfigurationError("Unknown Kibana configuration variable")
        return cls(values.get("SOC_KIBANA_URL", ""), values.get("SOC_KIBANA_SPACE", "default"))


@dataclass(frozen=True)
class KibanaSettings:
    url: str
    api_key: str = field(repr=False)
    space: str = "default"
    ca_path: Path | None = None
    connect_timeout: int = 5
    read_timeout: int = 10
    max_response_bytes: int = 1_048_576

    def __post_init__(self):
        # Reuse strict HTTPS, encoded API key and TLS validation without ES credentials.
        ElasticsearchSettings(
            self.url,
            self.api_key,
            ("unused",),
            ("unused",),
            self.ca_path,
            self.connect_timeout,
            self.read_timeout,
            max_response_bytes=self.max_response_bytes,
        )
        KibanaTargetSettings(self.url, self.space)

    @property
    def target(self):
        return KibanaTargetSettings(self.url, self.space).target

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None):
        values = os.environ if env is None else env
        try:
            kwargs = {}
            for key, value in values.items():
                if not key.startswith(KIBANA_PREFIX):
                    continue
                name = key[len(KIBANA_PREFIX) :]
                if name not in KIBANA_NAMES:
                    raise ValueError
                if name == "CA_PATH":
                    value = Path(value)
                elif name in {"CONNECT_TIMEOUT", "READ_TIMEOUT", "MAX_RESPONSE_BYTES"}:
                    value = int(value)
                kwargs[name.lower()] = value
            return cls(**kwargs)
        except (ValueError, TypeError, OSError):
            raise ConfigurationError("Invalid Kibana configuration") from None
