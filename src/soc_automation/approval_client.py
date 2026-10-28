"""Bounded version-1 Unix socket operator transport; no persistence or retries."""

import json
import math
import os
import socket
import stat
import struct
import time

from soc_automation.approval_policy import _parts, strict_object
from soc_automation.approval_socket import REQUEST_LIMIT, validate_request

RESPONSE_LIMIT = 4096
ERROR_EXITS = {
    'authentication_failure': 4, 'unauthorized': 4,
    'stale_publication_state': 5, 'invalid_review_transition': 5,
    'evidence_verification_failure': 5, 'policy_unavailable': 6,
    'conflicting_request_id': 7, 'timeout': 9,
    'internal_failure': 10, 'unavailable': 10, 'busy': 10,
    'invalid_request': 2, 'unsupported_version': 2,
    'request_too_large': 2, 'truncated_request': 2,
}


class ClientError(Exception):
    """Sanitized stable client failure."""

    def __init__(self, code, exit_code):
        self.code, self.exit_code = code, exit_code
        super().__init__(code)


def encode_request(request):
    data = json.dumps(request, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(',', ':')).encode('utf-8')
    if not 1 <= len(data) <= REQUEST_LIMIT:
        raise ValueError('Request exceeds 4096 bytes')
    validate_request(data)
    return data


def validate_endpoint(path, seconds):
    _parts(path)
    if (not os.fspath(path).strip('/') or len(os.fsencode(path)) > 107
            or type(seconds) not in (int, float) or not math.isfinite(seconds)
            or not 0.05 <= seconds <= 30):
        raise ValueError('Invalid socket path or timeout')


def _response(data, request):
    try:
        value = strict_object(data.decode('utf-8'))
        if type(value.get('version')) is not int or value['version'] != 1:
            raise ValueError
        if type(value.get('ok')) is not bool:
            raise ValueError
        if not value['ok']:
            if set(value) != {'version', 'ok', 'error'}:
                raise ValueError
            if type(value['error']) is not str or value['error'] not in ERROR_EXITS:
                raise ValueError
        elif request['operation'] == 'health':
            if (set(value) != {'version', 'ok', 'operation'}
                    or value['operation'] != 'health'):
                raise ValueError
        elif (set(value) != {'version', 'ok', 'event_id', 'outcome', 'historical'}
              or type(value['event_id']) is not int or not 1 <= value['event_id'] <= 2**63 - 1
              or value['historical'] is not True
              or value['outcome'] != {'approve': 'approved', 'decline': 'declined',
                                      'revoke': 'revoked'}[request['operation']]):
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ClientError('invalid_response_uncertain', 9) from None


def exchange(path, request, *, seconds=2.0):
    """One attempt only. Any failure after connect may hide a committed decision."""
    validate_endpoint(path, seconds)
    data = encode_request(request)
    try:
        if not stat.S_ISSOCK(os.lstat(path).st_mode):
            raise ClientError('unsafe_socket_endpoint', 8)
    except OSError:
        raise ClientError('connection_failure', 8) from None
    connected = False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            deadline = time.monotonic() + seconds

            def bound():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                connection.settimeout(remaining)

            def read(count):
                result = bytearray()
                while len(result) < count:
                    bound()
                    chunk = connection.recv(count - len(result))
                    if not chunk:
                        raise ClientError('disconnected_uncertain', 9)
                    result.extend(chunk)
                return bytes(result)

            bound()
            connection.connect(os.fspath(path))
            connected = True
            bound()
            connection.sendall(struct.pack('!I', len(data)) + data)
            connection.shutdown(socket.SHUT_WR)
            size = struct.unpack('!I', read(4))[0]
            if not 1 <= size <= RESPONSE_LIMIT:
                raise ClientError('invalid_response_uncertain', 9)
            result = _response(read(size), request)
            bound()
            if connection.recv(1):
                raise ClientError('invalid_response_uncertain', 9)
            return result
    except TimeoutError:
        raise ClientError('timeout_uncertain', 9) from None
    except OSError:
        raise ClientError('disconnected_uncertain' if connected else 'connection_failure',
                          9 if connected else 8) from None
