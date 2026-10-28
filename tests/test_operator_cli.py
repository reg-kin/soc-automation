"""Synthetic local operator protocol contracts; IP and DNS restrictions remain active."""

import io
import json
import socket
import struct
import threading
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from test_approval_socket import decisions as socket_decisions
from test_approval_socket import setup  # noqa: F401

from soc_automation import approval_client, cli
from soc_automation.approval_client import ClientError, exchange
from soc_automation.operator_cli import COMMANDS

decisions = socket_decisions

pytestmark = pytest.mark.unix_socket
TARGET = 'https://example.test/default/securitySolution'


def arguments(path, operation='approve'):
    command = next(key for key, value in COMMANDS.items() if value == operation)
    result = [command, '--socket-path', str(path), '--target', TARGET]
    if operation != 'health':
        values = dict(publication_id='publication-1', request_id='immutable-1',
                      expected_state='prepared', expected_previous_event_id='null',
                      expected_payload_sha256='a' * 64, expected_report_sha256='b' * 64,
                      expected_renderer_version='soc-case/2',
                      expected_review_policy_version='review/1')
        for key, value in values.items():
            result += ['--' + key.replace('_', '-'), value]
        if operation != 'approve':
            result += ['--reason-code', 'operator_declined' if operation == 'decline'
                       else 'operator_revoked']
    return result


@contextmanager
def endpoint(tmp_path, response):
    path = tmp_path / 'operator.sock'
    requests, errors = [], []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen(2)
        listener.settimeout(2)

        def serve():
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(2)
                    raw = bytearray()
                    while chunk := connection.recv(4096):
                        raw.extend(chunk)
                    size = struct.unpack('!I', raw[:4])[0]
                    assert size == len(raw[4:])
                    requests.append(json.loads(raw[4:]))
                    if response is not None:
                        data = (response if isinstance(response, bytes)
                                else json.dumps(response).encode())
                        connection.sendall(struct.pack('!I', len(data)) + data)
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            yield path, requests
        finally:
            thread.join(3)
            assert not thread.is_alive()
            assert not errors


@pytest.mark.parametrize('operation,outcome', [('health', None), ('approve', 'approved'),
                                               ('decline', 'declined'), ('revoke', 'revoked')])
def test_success(tmp_path, capsys, operation, outcome):
    response = dict(version=1, ok=True)
    response.update(dict(event_id=12, outcome=outcome, historical=True) if outcome
                    else dict(operation='health'))
    with (endpoint(tmp_path, response) as (path, requests),
        patch('soc_automation.cli.Settings.from_env', side_effect=AssertionError),
        patch('soc_automation.cli.Store', side_effect=AssertionError),
        patch('sqlite3.connect', side_effect=AssertionError),
        patch('soc_automation.cli.KibanaClient', side_effect=AssertionError),
        patch('soc_automation.cli.publish_case', side_effect=AssertionError),
    ):
        args = arguments(path, operation) + (['--confirm'] if outcome else [])
        assert cli.main(args) == 0
    assert len(requests) == 1
    assert requests[0]['operation'] == operation
    result = json.loads(capsys.readouterr().out)
    if outcome:
        assert result['request_id'] == requests[0]['request_id'] == 'immutable-1'
        assert result['historical'] is True
        assert requests[0]['confirmed'] is True


@pytest.mark.parametrize('interactive,answer,expected', [
    (True, 'yes\n', 0), (True, '\n', 3), (True, 'no\n', 3), (False, 'yes\n', 3),
])
def test_confirmation(tmp_path, capsys, interactive, answer, expected):
    stdin = io.StringIO(answer)
    with (patch('sys.stdin', stdin), patch.object(stdin, 'isatty', return_value=interactive),
          patch('soc_automation.operator_cli.exchange', return_value={
              'version': 1, 'ok': True, 'event_id': 1, 'historical': True,
              'outcome': 'approved'}) as send):
        assert cli.main(arguments(tmp_path / 's')) == expected
        assert send.call_count == (expected == 0)
    shown = capsys.readouterr().err
    for value in ('publication-1', TARGET, 'immutable-1', 'a' * 64, 'b' * 64,
                  'expected_previous_event_id', 'review/1', 'soc-case/2', 'prepared'):
        assert value in shown


@pytest.mark.parametrize('operation', ['approve', 'decline', 'revoke'])
@pytest.mark.parametrize('error', [OSError('private terminal error details'), KeyboardInterrupt()])
def test_confirmation_read_failure(tmp_path, capsys, operation, error):
    stdin = io.StringIO()
    with (patch('sys.stdin', stdin), patch.object(stdin, 'isatty', return_value=True),
          patch.object(stdin, 'readline', side_effect=error) as read,
          patch('soc_automation.operator_cli.exchange') as send):
        assert cli.main(arguments(tmp_path / 's', operation)) == 3
        read.assert_called_once_with()
        send.assert_not_called()
    captured = capsys.readouterr()
    shown = captured.out + captured.err
    assert 'Traceback' not in shown
    assert 'private terminal error details' not in shown
    assert captured.out == ''
    assert 'cancelled: no decision request sent' in captured.err
    if isinstance(error, OSError):
        assert 'terminal confirmation read failed' in captured.err


@pytest.mark.parametrize('option,value', [
    ('publication-id', ''), ('publication-id', '\n'), ('request-id', ''),
    ('request-id', 'x' * 257), ('expected-payload-sha256', 'A' * 64),
    ('expected-report-sha256', 'x'), ('expected-previous-event-id', '-1'),
    ('expected-previous-event-id', 'true'), ('reason-code', 'free prose'),
    ('expected-renderer-version', '?'), ('expected-review-policy-version', ''),
    ('target', 'http://example.test'), ('timeout-seconds', 'nan'),
    ('socket-path', 'relative'), ('expected-state', 'sending'),
])
def test_invalid_arguments(tmp_path, option, value):
    args = arguments(tmp_path / 's') + ['--confirm', '--' + option, value]
    with patch('soc_automation.operator_cli.exchange', side_effect=AssertionError):
        try:
            assert cli.main(args) == 2
        except SystemExit as error:
            assert error.code == 2


@pytest.mark.parametrize('option', ['publication-id', 'request-id', 'expected-state',
                                   'expected-previous-event-id', 'expected-payload-sha256',
                                   'expected-report-sha256', 'expected-renderer-version',
                                   'expected-review-policy-version'])
def test_missing_bindings(tmp_path, option):
    args = arguments(tmp_path / 's')
    index = args.index('--' + option)
    del args[index:index + 2]
    with pytest.raises(SystemExit) as error:
        cli.main(args)
    assert error.value.code == 2


@pytest.mark.parametrize('option', ['--actor-uid=0', '--principal=root',
                                   '--authentication-method=x', '--payload={}', '--policy=x'])
def test_no_authority_overrides(tmp_path, option):
    with pytest.raises(SystemExit) as error:
        cli.main(arguments(tmp_path / 's') + [option])
    assert error.value.code == 2


@pytest.mark.parametrize('response', [b'{', b'{"version":1,"version":1}',
    dict(version=1, ok=True, event_id=1, outcome='approved', historical=True, extra=1),
    dict(version=True, ok=True, operation='health'),
    dict(version=1, ok=True, event_id=True, outcome='approved', historical=True),
    dict(version=1, ok=False, error='private exception'), None])
def test_bad_or_missing_response(tmp_path, response, capsys):
    with endpoint(tmp_path, response) as (path, requests):
        assert cli.main(arguments(path) + ['--confirm']) == 9
    assert len(requests) == 1
    assert 'SAME request ID' in capsys.readouterr().err


@pytest.mark.parametrize('error,code', approval_client.ERROR_EXITS.items())
def test_server_error_exit(tmp_path, error, code, capsys):
    with endpoint(tmp_path, dict(version=1, ok=False, error=error)) as (path, _):
        assert cli.main(arguments(path) + ['--confirm']) == code
    assert error in capsys.readouterr().err


def test_connection_failure(tmp_path):
    assert cli.main(arguments(tmp_path / 'absent') + ['--confirm']) == 8
    regular = tmp_path / 'regular'
    regular.touch()
    assert cli.main(arguments(regular) + ['--confirm']) == 8


def test_read_timeout(tmp_path, capsys):
    path = tmp_path / 'slow'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen(1)
        assert cli.main(arguments(path) + ['--confirm', '--timeout-seconds=.05']) == 9
    assert 'SAME request ID' in capsys.readouterr().err


def test_write_timeout_and_no_retry(tmp_path):
    path = tmp_path / 's'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        request = dict(version=1, operation='health', target=TARGET)
        with patch('soc_automation.approval_client.socket.socket') as factory:
            connection = factory.return_value.__enter__.return_value
            connection.sendall.side_effect = TimeoutError('private')
            with pytest.raises(ClientError) as error:
                exchange(path, request)
            assert error.value.exit_code == 9
            assert factory.call_count == connection.connect.call_count == 1
            assert connection.sendall.call_count == 1


def test_identical_retry_after_uncertainty(tmp_path, capsys):
    args = None
    received = []
    for index, response in enumerate([None, dict(version=1, ok=True, event_id=1,
                                                outcome='approved', historical=True)]):
        directory = tmp_path / str(index)
        directory.mkdir()
        with endpoint(directory, response) as (path, requests):
            args = arguments(path) + ['--confirm']
            assert cli.main(args) == (9 if index == 0 else 0)
        received += requests
    assert received[0] == received[1]
    assert received[0]['request_id'] == 'immutable-1'
    assert 'historical' in capsys.readouterr().out


def test_oversized_request(tmp_path):
    args = arguments(tmp_path / 's') + ['--confirm', '--publication-id', '\U0001f600' * 256,
                                      '--request-id', '\U0001f600' * 256]
    with patch('soc_automation.operator_cli.exchange', side_effect=AssertionError):
        assert cli.main(args) == 2


def test_real_service_lifecycle(decisions, capsys):
    service, store, request, _, _ = decisions
    before = store.review_case_publication(request['publication_id'])
    with store._connection(readonly=True) as conn:
        before_dump = list(conn.iterdump())
    for operation, previous, reason in [('approve', None, None),
                                        ('revoke', 1, 'operator_revoked'),
                                        ('decline', 2, 'operator_declined')]:
        args = arguments(service.settings.path, operation)
        replacements = dict(request, operation=operation,
                            request_id='cli-' + operation,
                            expected_previous_event_id=previous, reason_code=reason)
        for key, value in replacements.items():
            flag = '--' + key.replace('_', '-')
            if flag in args:
                args[args.index(flag) + 1] = 'null' if value is None else str(value)
        with (patch('soc_automation.cli.Settings.from_env', side_effect=AssertionError),
              patch('soc_automation.cli.Store', side_effect=AssertionError),
              patch('soc_automation.cli.publish_case', side_effect=AssertionError)):
            assert cli.main(args + ['--confirm']) == 0
            assert cli.main(args + ['--confirm']) == 0
    after = store.review_case_publication(request['publication_id'])
    assert after['state'] == before['state'] == 'prepared'
    assert after['payload'] == before['payload']
    assert after['audit'] == before['audit']
    assert len(after['review_history']) == 3
    assert [item['decision'] for item in after['review_history']] == [
        'approved', 'revoked', 'declined']
    assert capsys.readouterr().out.count('historical event receipt') == 6
    with store._connection(readonly=True) as conn:
        after_dump = list(conn.iterdump())
    assert all(line in after_dump for line in before_dump)
    assert all(line.startswith('INSERT INTO "case_review_events"')
               for line in after_dump if line not in before_dump)


@pytest.mark.parametrize('raw', [struct.pack('!I', 4097), struct.pack('!I', 0),
                                struct.pack('!I', 10) + b'{}',
                                struct.pack('!I', 2) + b'{}extra'])
def test_bad_response_framing(tmp_path, raw):
    path = tmp_path / 'framing'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen(1)

        def serve():
            with listener.accept()[0] as connection:
                while connection.recv(4096):
                    pass
                connection.sendall(raw)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            assert cli.main(arguments(path) + ['--confirm']) == 9
        finally:
            thread.join(2)
        assert not thread.is_alive()


def test_operator_options_before_command_fail_without_configuration():
    with patch('soc_automation.cli.Settings.from_env', side_effect=AssertionError):
        with pytest.raises(SystemExit) as error:
            cli.main(['--target', TARGET, 'approval-service-health'])
    assert error.value.code == 2
