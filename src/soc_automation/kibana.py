"""Bounded verified HTTPS Cases create/read adapter. No retries or redirects."""

import http.client
import re
import ssl
from urllib.parse import urlencode, urlsplit

from soc_automation.ingestion import Limits, encode, parse


class KibanaError(ValueError):
    """Fixed diagnostic only; remote bodies and credentials never escape."""


class KibanaClient:
    def __init__(self, settings):
        self.settings = settings
        self.context = ssl.create_default_context(
            cafile=str(settings.ca_path) if settings.ca_path else None
        )

    def _request(self, method, path, payload=None):
        if not (
            (method == "POST" and path == "/api/cases")
            or (
                method == "GET"
                and (
                    path.startswith("/api/cases/_find?")
                    or re.fullmatch(r"/api/cases/[A-Za-z0-9-]{1,128}", path)
                )
            )
        ):
            raise KibanaError("unsafe_request")
        url = urlsplit(self.settings.url)
        connection = http.client.HTTPSConnection(
            url.hostname, url.port, timeout=self.settings.connect_timeout, context=self.context
        )
        try:
            connection.connect()
            connection.sock.settimeout(self.settings.read_timeout)
            connection.request(
                method,
                path,
                body=encode(payload).encode() if payload else None,
                headers={
                    "Authorization": "ApiKey " + self.settings.api_key,
                    "kbn-xsrf": "soc-automation",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Accept-Encoding": "identity",
                },
            )
            response = connection.getresponse()
            if response.status not in ({200} if method == "GET" else {200, 201}):
                raise KibanaError("http_failure")
            if response.getheader("Content-Encoding", "identity") != "identity":
                raise KibanaError("unexpected_encoding")
            data = response.read(self.settings.max_response_bytes + 1)
            items = parse(data, Limits(input_bytes=self.settings.max_response_bytes))
            if len(items) != 1:
                raise KibanaError("invalid_response")
            return items[0]
        except (OSError, http.client.HTTPException, ValueError, TypeError, RecursionError):
            raise KibanaError("kibana_request_failed") from None
        finally:
            connection.close()

    def create(self, payload):
        return self._request("POST", "/api/cases", payload)

    def validate(self):
        """One read-only default-space search; no publication or case data escapes."""
        result = self._request(
            "GET",
            "/api/cases/_find?" + urlencode({"owner": "securitySolution", "page": 1, "perPage": 1}),
        )
        if (
            not isinstance(result, dict)
            or type(result.get("total")) is not int
            or result["total"] < 0
            or type(result.get("page")) is not int
            or result["page"] != 1
            or type(result.get("per_page")) is not int
            or result["per_page"] != 1
            or not isinstance(result.get("cases"), list)
            or len(result["cases"]) != min(result["total"], 1)
            or any(
                not isinstance(case, dict)
                or not isinstance(case.get("id"), str)
                or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", case["id"])
                or case.get("owner") != "securitySolution"
                for case in result["cases"]
            )
        ):
            raise KibanaError("invalid_search_response")
        return {
            "status": "validated",
            "read_only": True,
            "tls_verified": True,
            "api_key_authenticated": True,
            "space": "default",
            "owner": "securitySolution",
            "cases_search": "validated",
            "contract_target": "8.19.20",
            "server_version_verified": False,
        }

    def find(self, marker):
        if not re.fullmatch(r"soc-publication-[a-f0-9]{64}", marker):
            raise KibanaError("invalid_marker")
        return self._request(
            "GET",
            "/api/cases/_find?"
            + urlencode(
                {
                    "owner": "securitySolution",
                    "tags": marker,
                    "page": 1,
                    "perPage": 100,
                }
            ),
        )

    def get(self, case_id):
        if not isinstance(case_id, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", case_id):
            raise KibanaError("invalid_case_id")
        return self._request("GET", "/api/cases/" + case_id)
