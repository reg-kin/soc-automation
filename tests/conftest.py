"""Forbid networking during every unit test."""

import os
import socket

import pytest


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    for key in list(os.environ):
        if key.startswith("SOC_"):
            monkeypatch.delenv(key)

    def blocked(*args, **kwargs):
        raise AssertionError("Network access is forbidden in foundation tests")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
