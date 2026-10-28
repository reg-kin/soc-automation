"""Forbid networking during every unit test."""

import os
import socket

import pytest


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch, request):
    for key in list(os.environ):
        if key.startswith("SOC_"):
            monkeypatch.delenv(key)

    def blocked(*args, **kwargs):
        raise AssertionError("Network access is forbidden in foundation tests")

    real_socket = socket.socket

    def unix_only(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, fileno=None):
        if family != socket.AF_UNIX or type != socket.SOCK_STREAM or proto != 0:
            return blocked()
        if fileno is not None:
            # Inspect an owned duplicate, never taking ownership of the caller's fd.
            duplicate = os.dup(fileno)
            try:
                probe = real_socket(fileno=duplicate)
            except BaseException:
                os.close(duplicate)
                raise
            with probe:
                if (probe.family != socket.AF_UNIX
                        or probe.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
                        != socket.SOCK_STREAM):
                    return blocked()
        return real_socket(family, type, proto, fileno=fileno)

    replacement = unix_only if request.node.get_closest_marker("unix_socket") else blocked
    monkeypatch.setattr(socket, "socket", replacement)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
