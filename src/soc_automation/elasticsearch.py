"""Bounded exact-document Elasticsearch reads. No discovery or write operations."""

import http.client
import ssl
import time
from fnmatch import fnmatchcase
from urllib.parse import quote, urlsplit

from soc_automation.config import ConfigurationError, ElasticsearchSettings
from soc_automation.evidence import Reference, Retrieval, validate
from soc_automation.ingestion import InputError, Limits, encode, normalize, parse


class ElasticsearchError(ValueError):
    """Only fixed diagnostic codes cross the transport boundary."""


class ElasticsearchProvider:
    def __init__(self, settings: ElasticsearchSettings):
        self.settings = settings
        try:
            self._context = ssl.create_default_context(
                cafile=str(settings.ca_path) if settings.ca_path else None
            )
        except (OSError, ValueError):
            raise ConfigurationError("Invalid Elasticsearch TLS configuration") from None

    def _get(self, reference: Reference, indices: tuple[str, ...]) -> Retrieval:
        if not any(fnmatchcase(reference.index, pattern) for pattern in indices):
            return Retrieval(reference, "failed", reason="index_not_permitted")
        reason = "transport_failure"
        for attempt in range(self.settings.retries + 1):
            url = urlsplit(self.settings.url)
            connection = http.client.HTTPSConnection(
                url.hostname, url.port, timeout=self.settings.connect_timeout, context=self._context
            )
            retry = False
            phase = "connect"
            try:
                connection.connect()
                connection.sock.settimeout(self.settings.read_timeout)
                phase = "read"
                path = f"/{quote(reference.index, safe='')}/_doc/{quote(reference.id, safe='')}"
                connection.request(
                    "GET",
                    path,
                    headers={
                        "Authorization": "ApiKey " + self.settings.api_key,
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                    },
                )
                response = connection.getresponse()
                status = response.status
                if status == 404:
                    return Retrieval(reference, "missing", reason="document_missing")
                if status != 200:
                    reason = {
                        401: "authentication_failed",
                        403: "authorization_failed",
                        429: "rate_limited",
                        500: "server_error",
                        502: "server_error",
                        503: "server_error",
                        504: "server_error",
                    }.get(status, "http_error")
                    retry = status in {429, 500, 502, 503, 504}
                else:
                    if response.getheader("Content-Encoding", "identity") != "identity":
                        return Retrieval(reference, "failed", reason="unexpected_encoding")
                    data = response.read(self.settings.max_response_bytes + 1)
                    if len(data) > self.settings.max_response_bytes:
                        return Retrieval(reference, "failed", reason="response_size_exceeded")
                    try:
                        items = parse(data, Limits(input_bytes=self.settings.max_response_bytes))
                        if len(items) != 1 or not isinstance(items[0].get("_source"), dict):
                            raise InputError("Unexpected structure")
                        document = items[0]
                        if document.get("found") is False:
                            raise InputError("Contradictory response")
                        if len(encode(document).encode()) > self.settings.max_document_bytes:
                            return Retrieval(reference, "failed", reason="document_size_exceeded")
                        return validate(Retrieval(reference, "found", document), reference)
                    except (ValueError, TypeError, RecursionError):
                        return Retrieval(reference, "failed", reason="invalid_response")
            except ssl.SSLError:
                reason = "tls_verification_failed"
            except TimeoutError:
                reason = "connection_timeout" if phase == "connect" else "read_timeout"
                retry = True
            except (OSError, http.client.HTTPException):
                reason = "transport_failure"
                retry = True
            finally:
                connection.close()
            if not retry or attempt == self.settings.retries:
                break
            time.sleep(self.settings.backoff * (2**attempt))
        return Retrieval(reference, "failed", reason=reason)

    def fetch_alert(self, reference: Reference) -> dict:
        result = self._get(reference, self.settings.alert_indices)
        if result.status != "found":
            raise ElasticsearchError(result.reason) from None
        normalize(result.document)  # Reuse ingestion validation without persistence.
        return result.document

    def retrieve(self, reference: Reference) -> Retrieval:
        return self._get(reference, self.settings.source_indices)

    def retrieve_many(self, references: list[Reference]) -> list[Retrieval]:
        if not references or len(references) > self.settings.max_documents:
            raise InputError("Evidence batch limit exceeded")
        cache = {}
        for reference in references:
            if reference not in cache:
                cache[reference] = self.retrieve(reference)
        return [cache[reference] for reference in references]
