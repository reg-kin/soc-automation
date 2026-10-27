"""Read-only Cases diagnostic, with all networking mocked or forbidden."""

import base64
import json
import ssl
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest

from soc_automation.cli import main
from soc_automation.config import KibanaSettings
from soc_automation.kibana import KibanaClient, KibanaError


@pytest.fixture
def diagnostic(monkeypatch):
    key = base64.b64encode(b"diagnostic:key").decode()
    monkeypatch.setenv("SOC_KIBANA_URL", "https://kibana.example.test")
    monkeypatch.setenv("SOC_KIBANA_API_KEY", key)
    with patch("soc_automation.kibana.http.client.HTTPSConnection") as transport:
        connection = transport.return_value
        response = connection.getresponse.return_value
        response.status = 200
        response.getheader.return_value = "identity"
        response.read.return_value = json.dumps(
            {"page": 1, "per_page": 1, "total": 0, "cases": []}
        ).encode()
        yield transport, connection, response, key


@pytest.mark.parametrize("populated", [False, True])
def test_validation_no_database_or_writes(diagnostic, capsys, populated):
    transport, connection, response, key = diagnostic
    if populated:
        response.read.return_value = json.dumps(
            {
                "page": 1,
                "per_page": 1,
                "total": 12,
                "cases": [{"id": "case-123", "owner": "securitySolution", "title": "PRIVATE"}],
            }
        ).encode()
    with patch("soc_automation.cli.Store", side_effect=AssertionError("No database")):
        assert main(["validate-kibana"]) == 0
    output = capsys.readouterr().out
    assert key not in output and "PRIVATE" not in output and "case-123" not in output
    assert json.loads(output)["server_version_verified"] is False
    assert json.loads(output)["status"] == "validated"
    connection.request.assert_called_once()
    args, kwargs = connection.request.call_args
    assert args[0] == "GET"
    assert urlsplit(args[1]).path == "/api/cases/_find"
    assert parse_qs(urlsplit(args[1]).query) == {
        "owner": ["securitySolution"],
        "page": ["1"],
        "perPage": ["1"],
    }
    assert kwargs["body"] is None
    assert kwargs["headers"]["Authorization"] == "ApiKey " + key
    context = transport.call_args.kwargs["context"]
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    connection.sock.settimeout.assert_called_once_with(10)
    response.read.assert_called_once_with(1_048_577)
    connection.close.assert_called_once()


@pytest.mark.parametrize("status", [201, 302, 401, 403, 404, 500])
def test_validation_http_failure(diagnostic, status, capsys):
    _, connection, response, key = diagnostic
    response.status = status
    # GET must specifically return 200, including when another accepted write status appears.
    assert main(["validate-kibana"]) == 1
    assert key not in capsys.readouterr().out
    connection.request.assert_called_once()
    connection.close.assert_called_once()


@pytest.mark.parametrize(
    "body",
    [
        b"{}",
        b"[]",
        b"{",
        b'{"total":true,"cases":[]}',
        b'{"page":1,"per_page":1,"total":1,"cases":[]}',
        b'{"page":1,"per_page":1,"total":0,"cases":{}}',
        b'{"page":1,"per_page":1,"total":1,"cases":[{"id":"x","owner":"other"}]}',
        b'{"page":1,"per_page":1,"total":-1,"cases":[]}',
    ],
)
def test_validation_bad_response(diagnostic, body):
    diagnostic[2].read.return_value = body
    with pytest.raises(KibanaError):
        KibanaClient(KibanaSettings.from_env()).validate()


@pytest.mark.parametrize("failure", [ssl.SSLCertVerificationError, TimeoutError])
def test_validation_connection_failure(diagnostic, failure):
    diagnostic[1].connect.side_effect = failure("private detail")
    with pytest.raises(KibanaError, match="^kibana_request_failed$"):
        KibanaClient(KibanaSettings.from_env()).validate()
    diagnostic[1].request.assert_not_called()
    diagnostic[1].close.assert_called_once()
