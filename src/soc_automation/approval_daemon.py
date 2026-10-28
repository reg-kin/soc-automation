"""Fixed production composition; no environment configuration or administrative writes."""

import argparse
import grp
import os
import pwd
import signal
import socket
import sqlite3
import stat
import sys
from pathlib import Path

from soc_automation.approval_policy import PolicySource, protected_directory
from soc_automation.approval_socket import ApprovalSocketService, SocketSettings
from soc_automation.preflight import (
    close_inherited_descriptors,
    require_clean_launcher,
    restrict_filesystem_writes,
)
from soc_automation.state import StateError, Store

DATABASE = Path('/var/lib/soc-approval/soc_automation.db')
POLICY = Path('/etc/soc-approval/review-policy.json')
SOCKET = Path('/run/soc-approval/operator.sock')


def composition():
    """Validate provisioned identity and state without creating or migrating anything."""
    uid = pwd.getpwnam('soc-approval').pw_uid
    gid = grp.getgrnam('soc-approval-operators').gr_gid
    if uid == 0 or os.getuid() != uid or os.geteuid() != uid:
        raise ValueError('Dedicated unprivileged account required')
    if gid not in {os.getegid(), *os.getgroups()}:
        raise ValueError('Operator group membership required for socket creation')
    parent = protected_directory(DATABASE.parent, {0, uid})
    try:
        info = os.fstat(parent)
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('Private service state directory required')
        info = os.stat(DATABASE.name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('Private existing service database required')
        # SQLite may open these alongside the database. Never adopt foreign sidecars.
        for suffix in ('-wal', '-shm', '-journal'):
            try:
                sidecar = os.stat(DATABASE.name + suffix, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if (not stat.S_ISREG(sidecar.st_mode) or sidecar.st_uid != uid
                    or sidecar.st_nlink != 1 or stat.S_IMODE(sidecar.st_mode) != 0o600):
                raise ValueError('Unsafe SQLite sidecar')
    finally:
        os.close(parent)
    runtime = protected_directory(SOCKET.parent, {0, uid})
    try:
        info = os.fstat(runtime)
        if (info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != 0o750):
            raise ValueError('Restricted operator runtime directory required')
    finally:
        os.close(runtime)
    settings = SocketSettings(SOCKET, uid, gid)
    source, store = PolicySource(POLICY), Store(DATABASE, timeout=0.1)
    source.load(store)
    if POLICY.lstat().st_mode & 0o007:
        raise ValueError('Policy must not be accessible to other accounts')
    return settings, source, store


def notify_ready():
    """Signal the supervisor only after a successful bind; no application config from env."""
    address = os.environ.get('NOTIFY_SOCKET')
    if address is None:
        return
    if not address or address[0] not in '/@':
        raise ValueError('Invalid supervisor notification address')
    if address.startswith('@'):
        address = '\0' + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notification:
        notification.settimeout(1)
        notification.connect(address)
        notification.sendall(b'READY=1')


def preflight():
    """Confine only a child; preserve the writable service process."""
    try:
        require_clean_launcher()
        pid = os.fork()
    except BaseException:
        return 1
    if pid == 0:
        result = 1
        try:
            close_inherited_descriptors()
            require_clean_launcher()
            restrict_filesystem_writes()
            composition()
            result = 0
        except BaseException:
            # No inherited diagnostic stream, including on unexpected failure.
            result = 1
        finally:
            os._exit(result)
    try:
        _, status = os.waitpid(pid, 0)
    except BaseException:
        return 1
    return 0 if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--check', action='store_true',
                        help='Validate identity, existing schema and active policy; do not listen')
    args = parser.parse_args(argv)
    if args.check:
        # Preflight communicates only by status, including launcher failures.
        return preflight()
    try:
        settings, source, store = composition()
        service = ApprovalSocketService(settings, source, store)
        previous = {}
        try:
            # A handler only sets an event: close() takes locks and must run outside handlers.
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous[signum] = signal.signal(
                    signum, lambda _signum, _frame: service.stopping.set())
            service.start()
            notify_ready()
            service.serve_forever()
        finally:
            try:
                service.close()
            finally:
                for signum, handler in previous.items():
                    signal.signal(signum, handler)
        return 0
    except (OSError, ValueError, StateError, sqlite3.Error, KeyError):
        # Never print policy, database contents or internal exception text to the journal.
        print('approval_service_startup_or_runtime_failure', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
