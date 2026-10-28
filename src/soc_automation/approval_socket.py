"""Linux-only authenticated health transport. No approval mutation dispatch."""

import fcntl
import json
import os
import socket
import stat
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from soc_automation.approval import TrustedIdentity, _uid
from soc_automation.approval_policy import (
    PolicySource,
    _parts,
    protected_directory,
    strict_object,
    verify_authority,
)
from soc_automation.state import Store

REQUEST_LIMIT = 4096


class AdmissionError(ValueError):
    """Stable public error code; never transmit internal exception text."""


@dataclass(frozen=True)
class SocketSettings:
    """Explicit trusted configuration; never constructed from a client or environment."""

    path: Path
    service_uid: int
    operator_gid: int
    administrator_uid: int = 0
    special_uids: frozenset[int] = frozenset()
    max_clients: int = 8
    connection_seconds: float = 2.0

    def __post_init__(self):
        _parts(self.path)
        if not isinstance(self.path, Path) or not self.path.name:
            raise ValueError('Explicit socket file path required')
        for value in (self.service_uid, self.operator_gid, self.administrator_uid):
            _uid(value)
        if type(self.special_uids) is not frozenset:
            raise ValueError('Explicit special UID exceptions required')
        for value in self.special_uids:
            _uid(value)
        if not self.special_uids <= {0, self.service_uid}:
            raise ValueError('Only root and service UID exceptions supported')
        if (type(self.max_clients) is not int or not 1 <= self.max_clients <= 64
                or type(self.connection_seconds) not in (int, float)
                or not 0.05 <= self.connection_seconds <= 30):
            raise ValueError('Invalid connection bounds')


def peer_credentials(connection):
    if connection.family != socket.AF_UNIX or connection.type != socket.SOCK_STREAM:
        raise AdmissionError('unauthorized')
    pid, uid, gid = struct.unpack('iII', connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('iII')))
    if pid <= 0 or uid < 0 or gid < 0:
        raise AdmissionError('unauthorized')
    return pid, uid, gid


def authorize_peer(credentials, policy, settings, *, operation, target):
    _, uid, _ = credentials
    principal = dict(policy.principals).get(uid)
    if (principal is None or operation != 'health' or target not in policy.targets
            or (uid in {0, settings.service_uid} and uid not in settings.special_uids)):
        raise AdmissionError('unauthorized')
    return TrustedIdentity.from_verified_peer_credentials(uid=uid, principal=principal)


def validate_request(data):
    try:
        request = strict_object(data.decode('utf-8'))
        if set(request) != {'version', 'operation', 'target'}:
            raise ValueError
        if type(request['version']) is not int:
            raise ValueError
        if request['version'] != 1:
            raise AdmissionError('unsupported_version')
        if (type(request['operation']) is not str or request['operation'] != 'health'
                or type(request['target']) is not str):
            raise ValueError
        return request
    except AdmissionError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise AdmissionError('invalid_request') from None


class ApprovalSocketService:
    """Single accept loop and bounded workers. Call start before other process threads.

    Each connection carries one 4-byte network-order length and one UTF-8 object,
    followed by client SHUT_WR (EOF). Responses use the same length framing.
    close() may be called from another thread; serve_forever() is the accept loop.
    """

    def __init__(self, settings: SocketSettings, source: PolicySource, store):
        self.settings, self.source = settings, source
        # Read-only admission checks have a short SQLite busy bound independent of
        # the caller's persistence configuration. No mutation API is dispatched.
        self.store = Store(store.path, timeout=min(0.1, settings.connection_seconds))
        self.policy = None
        self.listener = None
        self.directory = None
        self.lock = None
        self.bound_inode = None
        self.stopping = threading.Event()
        self.slots = threading.BoundedSemaphore(settings.max_clients)
        self.workers = set()
        self.guard = threading.Lock()

    def start(self):
        if self.directory is not None or self.stopping.is_set():
            raise ValueError('Service already started or closed')
        settings = self.settings
        self.policy = self.source.load(self.store)
        try:
            self.directory = protected_directory(
                settings.path.parent, {0, settings.administrator_uid, settings.service_uid})
            info = os.fstat(self.directory)
            if (info.st_uid != settings.service_uid or info.st_gid != settings.operator_gid
                    or info.st_mode & 0o007):
                raise ValueError('Socket directory must be service-owned with no other access')
            # Persistent lock inode: never unlink it, including on clean shutdown.
            self.lock = os.open(settings.path.name + '.lock', os.O_CREAT | os.O_RDWR
                                | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                0o600, dir_fd=self.directory)
            info = os.fstat(self.lock)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != settings.service_uid
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise ValueError('Unsafe listener lock')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                os.stat(settings.path.name, dir_fd=self.directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('Socket path already exists; administrative recovery required')
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            # Linux procfs anchors bind to the validated directory inode.
            address = f'/proc/self/fd/{self.directory}/{settings.path.name}'
            old_mask = os.umask(0o177)
            try:
                self.listener.bind(address)
            finally:
                os.umask(old_mask)
            info = os.stat(settings.path.name, dir_fd=self.directory, follow_symlinks=False)
            self.bound_inode = (info.st_dev, info.st_ino)
            if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != settings.service_uid
                    or self.listener.getsockname() != address):
                raise ValueError('Unexpected listener ownership or address')
            os.chown(settings.path.name, -1, settings.operator_gid, dir_fd=self.directory,
                     follow_symlinks=False)
            os.chmod(settings.path.name, 0o660, dir_fd=self.directory, follow_symlinks=False)
            self.listener.listen(settings.max_clients)
            self.listener.settimeout(0.2)
            return self
        except BaseException:
            self.close()
            raise

    def _timeout(self, connection, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        connection.settimeout(remaining)

    def _read(self, connection, count, deadline):
        data = bytearray()
        while len(data) < count:
            self._timeout(connection, deadline)
            chunk = connection.recv(count - len(data))
            if not chunk:
                raise AdmissionError('truncated_request')
            data.extend(chunk)
        return bytes(data)

    def _respond(self, connection, response, deadline):
        data = json.dumps(response, sort_keys=True, separators=(',', ':')).encode()
        self._timeout(connection, deadline)
        connection.sendall(struct.pack('!I', len(data)) + data)

    def _handle(self, connection, deadline):
        try:
            credentials = peer_credentials(connection)
            size = struct.unpack('!I', self._read(connection, 4, deadline))[0]
            if not 1 <= size <= REQUEST_LIMIT:
                raise AdmissionError('request_too_large')
            data = self._read(connection, size, deadline)
            self._timeout(connection, deadline)
            if connection.recv(1):
                raise AdmissionError('invalid_request')
            request = validate_request(data)
            authorize_peer(credentials, self.policy, self.settings,
                           operation=request['operation'], target=request['target'])
            try:
                verify_authority(self.store, self.policy, deadline=deadline)
            except Exception:
                raise AdmissionError('policy_unavailable') from None
            response = {'version': 1, 'ok': True, 'operation': 'health'}
        except TimeoutError:
            response = {'version': 1, 'ok': False, 'error': 'timeout'}
        except AdmissionError as exc:
            response = {'version': 1, 'ok': False, 'error': str(exc)}
        except Exception:
            response = {'version': 1, 'ok': False, 'error': 'unavailable'}
        try:
            # Reserve a bounded error-write window after an input timeout.
            self._respond(connection, response, min(deadline + 0.1, time.monotonic() + 0.1))
        except (OSError, TimeoutError):
            pass
        finally:
            connection.close()
            self.slots.release()
            with self.guard:
                self.workers.discard(threading.current_thread())

    def serve_forever(self):
        try:
            self._serve_forever()
        except BaseException:
            # Resource exhaustion is fatal; release the listener and lock as well.
            self.close()
            raise

    def _serve_forever(self):
        if self.listener is None:
            raise ValueError('Start listener first')
        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self.stopping.is_set():
                    break
                raise
            deadline = time.monotonic() + self.settings.connection_seconds
            with self.guard:
                if self.stopping.is_set():
                    connection.close()
                    break
                admitted = self.slots.acquire(blocking=False)
                if admitted:
                    worker = None
                    try:
                        worker = threading.Thread(target=self._handle,
                                                  args=(connection, deadline), daemon=True)
                        self.workers.add(worker)
                        worker.start()
                    except BaseException:
                        # close() cannot observe an unstarted worker under this guard.
                        # A started worker owns its socket and semaphore slot.
                        if worker is None or worker.ident is None:
                            self.workers.discard(worker)
                            connection.close()
                            self.slots.release()
                        raise
            if not admitted:
                try:
                    self._respond(connection, {'version': 1, 'ok': False, 'error': 'busy'},
                                  time.monotonic() + 0.1)
                except OSError:
                    pass
                finally:
                    connection.close()
                continue

    def close(self):
        with self.guard:
            self.stopping.set()
            if self.listener is not None:
                self.listener.close()
            workers = list(self.workers)
        for worker in workers:
            worker.join(self.settings.connection_seconds + 0.2)
        # Fatal accept-loop cleanup can race an external shutdown.
        with self.guard:
            if self.directory is not None:
                try:
                    info = os.stat(self.settings.path.name, dir_fd=self.directory,
                                   follow_symlinks=False)
                    if ((info.st_dev, info.st_ino) == self.bound_inode
                            and stat.S_ISSOCK(info.st_mode)):
                        os.unlink(self.settings.path.name, dir_fd=self.directory)
                except FileNotFoundError:
                    pass
                finally:
                    if self.lock is not None:
                        os.close(self.lock)
                        self.lock = None
                    os.close(self.directory)
                    self.directory = None
