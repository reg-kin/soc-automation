"""Internal root administration evidence only; no database or policy access.

The CLI deliberately does not invoke these primitives yet.
"""

import fcntl
import json
import os
import re
import secrets
import stat
import threading
from contextlib import contextmanager
from functools import wraps

ADMIN_PATH = '/var/lib/soc-policy-admin'
LOCK_PATH = ADMIN_PATH + '/admin.lock'
OPERATIONS_PATH = ADMIN_PATH + '/operations'
MANIFEST_LIMIT = 4096
OPERATION_LIMIT = 1024
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class EvidenceError(ValueError):
    """Unsafe, corrupt, contradictory or unresolved administrative evidence."""


# Registry contains only module-owned descriptors. Serialize fork with setup,
# cleanup and handle operations, including temporary manifest descriptors.
_fork_gate = threading.RLock()
_owned_fds = set()
# The gate excludes other threads, not signal handlers on its owning thread.
# A nonzero depth means the registry cannot describe the inherited fd table.
_fd_transitions = 0


def _after_fork_child():
    global _fork_gate, _fd_transitions
    if _fd_transitions:
        # An open result may not even be available to Python yet. Process exit
        # is the only safe cleanup: do not resume the interrupted transition.
        os._exit(1)
    # Cleanup itself is a descriptor transition, including reentrant signal forks.
    _fd_transitions = 1
    try:
        for fd in _owned_fds:
            os.close(fd)  # Never LOCK_UN: the open file description is shared.
    except BaseException:
        # at-fork callback exceptions are otherwise ignored by Python.
        os._exit(1)
    _owned_fds.clear()
    _fork_gate = threading.RLock()
    _fd_transitions = 0


try:
    os.register_at_fork(before=lambda: _fork_gate.acquire(),
                        after_in_parent=lambda: _fork_gate.release(),
                        after_in_child=_after_fork_child)
    _fork_ready = True
except (AttributeError, OSError, RuntimeError):
    _fork_ready = False


def _serialized(method):
    @wraps(method)
    def call(*args, **kwargs):
        with _fork_gate:
            return method(*args, **kwargs)
    return call


def _open(*args, **kwargs):
    global _fd_transitions
    with _fork_gate:
        _fd_transitions += 1
        try:
            fd = os.open(*args, **kwargs)
            try:
                _owned_fds.add(fd)
            except BaseException:
                os.close(fd)
                raise
            return fd
        finally:
            _fd_transitions -= 1


def _close(fd):
    global _fd_transitions
    with _fork_gate:
        _fd_transitions += 1
        try:
            # Remove before close: Linux releases the fd number even when close
            # reports an error. Never retry it or retain a potentially reused fd.
            _owned_fds.remove(fd)
            os.close(fd)
        finally:
            _fd_transitions -= 1


def _process(pid):
    if os.getpid() != pid:
        raise EvidenceError('Inherited administration context')


def _root():
    if os.getuid() != 0 or os.geteuid() != 0:
        raise PermissionError('Real and effective root required')


def _id(value):
    if type(value) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value) is None:
        raise EvidenceError('Invalid operation ID')
    return value


def _safe(info, *, directory, private=True):
    mode = stat.S_IMODE(info.st_mode)
    if (info.st_uid != 0 or (not stat.S_ISDIR(info.st_mode) if directory
                            else not stat.S_ISREG(info.st_mode))
            or (mode != (0o700 if directory else 0o600) if private else mode & 0o022)
            or (not directory and info.st_nlink != 1)):
        raise EvidenceError('Unsafe administrative path')


def _same(parent, name, fd, *, directory, private=True):
    opened = os.fstat(fd)
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _safe(opened, directory=directory, private=private)
    _safe(named, directory=directory, private=private)
    if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
        raise EvidenceError('Administrative path changed')


def _directory(parent, name, *, create=False):
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        os.fsync(parent)  # Also synchronize an entry left by a failed attempt.
    fd = _open(name, DIR_FLAGS, dir_fd=parent)
    try:
        _same(parent, name, fd, directory=True)
        return fd
    except BaseException:
        _close(fd)
        raise


def _manifest(value):
    fields = {'version', 'operation_id', 'operation', 'change_reference', 'state',
              'expected_generation', 'expected_current_sha256', 'candidate_sha256',
              'candidate_version', 'candidate_size'}
    if type(value) is not dict or set(value) != fields:
        raise EvidenceError('Invalid manifest fields')
    _id(value['operation_id'])
    if (type(value['version']) is not int or value['version'] != 1
            or value['operation'] not in ('install', 'rotate')
            or value['state'] not in ('prepared', 'completed')
            or type(value['change_reference']) is not str
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}',
                            value['change_reference']) is None):
        raise EvidenceError('Invalid manifest header')
    generation = value['expected_generation']
    current = value['expected_current_sha256']
    digest = value['candidate_sha256']
    if (type(generation) is not int or not 0 <= generation < 2**63 - 1
            or (value['operation'] == 'install') != (generation == 0)
            or (current is not None if generation == 0 else
                type(current) is not str or re.fullmatch('[0-9a-f]{64}', current) is None)
            or type(digest) is not str or re.fullmatch('[0-9a-f]{64}', digest) is None
            or type(value['candidate_version']) is not str
            or not 1 <= len(value['candidate_version'].encode('utf-8')) <= 256
            or any(ord(c) < 32 for c in value['candidate_version'])
            or type(value['candidate_size']) is not int
            or not 1 <= value['candidate_size'] <= 65536):
        raise EvidenceError('Inconsistent manifest expectations')
    data = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    if len(data) > MANIFEST_LIMIT:
        raise EvidenceError('Manifest too large')
    return data


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError('Duplicate manifest key')
        value[key] = item
    return value


def _reject_number(value):
    raise EvidenceError('Noninteger manifest number')


def _only_manifest(directory):
    # Inspect at most two entries, including interrupted temporary files.
    with os.scandir(directory) as entries:
        first = next(entries, None)
        return (first is not None and first.name == 'manifest.json'
                and next(entries, None) is None)


class _Evidence:
    """Context-bound evidence handle. Completion is historical evidence, never authority."""

    def __init__(self, operations, check):
        self._pid = os.getpid()
        self._fd = operations
        self._check = check
        self._active = True

    def _guard(self):
        _process(self._pid)
        _root()
        if not self._active:
            raise EvidenceError('Closed administration context')
        self._check()

    @_serialized
    def discover(self):
        """Return ID -> completed/unresolved/corrupt; empty mapping means no operation."""
        self._guard()
        result = {}
        with os.scandir(self._fd) as entries:
            for entry in entries:
                if len(result) >= OPERATION_LIMIT:
                    raise EvidenceError('Too many operations')
                name = entry.name
                try:
                    _id(name)
                    fd = _directory(self._fd, name)
                    try:
                        if not _only_manifest(fd):
                            raise EvidenceError('Incomplete or unexpected evidence')
                        value = self._read(fd, name)
                        _same(self._fd, name, fd, directory=True)
                        result[name] = ('completed' if value['state'] == 'completed'
                                        else 'unresolved')
                    finally:
                        _close(fd)
                except (ValueError, OSError, RecursionError):
                    result[name] = 'corrupt'
        self._guard()
        return result

    @_serialized
    def _read(self, directory, operation_id):
        self._guard()
        fd = _open('manifest.json', os.O_RDONLY | FILE_FLAGS, dir_fd=directory)
        try:
            _same(directory, 'manifest.json', fd, directory=False)
            before = os.fstat(fd)
            if before.st_size > MANIFEST_LIMIT:
                raise EvidenceError('Manifest too large')
            data = os.read(fd, MANIFEST_LIMIT + 1)
            after = os.fstat(fd)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                      'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if (any(getattr(before, key) != getattr(after, key) for key in fields)
                    or len(data) != before.st_size or len(data) > MANIFEST_LIMIT):
                raise EvidenceError('Manifest changed')
            _same(directory, 'manifest.json', fd, directory=False)
            value = json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                               parse_float=_reject_number, parse_constant=_reject_number)
            _manifest(value)
            if value['operation_id'] != operation_id:
                raise EvidenceError('Contradictory operation ID')
            return value
        finally:
            _close(fd)

    @_serialized
    def prepare(self, value):
        """Persist metadata intent only, refusing any previous evidence."""
        self._guard()
        data = _manifest(value)
        if value['state'] != 'prepared':
            raise EvidenceError('Preparation requires prepared state')
        if self.discover():
            raise EvidenceError('Previous evidence requires authoritative admission')
        name = value['operation_id']
        os.mkdir(name, 0o700, dir_fd=self._fd)  # Exclusive; never reuse an ID.
        os.fsync(self._fd)
        fd = _directory(self._fd, name)
        try:
            self._write(fd, data)
            _same(self._fd, name, fd, directory=True)
            self._guard()
        finally:
            _close(fd)

    @_serialized
    def update(self, value):
        """Durably update evidence; caller must independently establish completion.

        No manifest label proves a ledger commit or authorizes installation.
        """
        self._guard()
        data = _manifest(value)
        name = value['operation_id']
        fd = _directory(self._fd, name)
        try:
            if not _only_manifest(fd):
                raise EvidenceError('Unexpected evidence')
            old = self._read(fd, name)
            if old['state'] != 'prepared' or any(
                    old[key] != value[key] for key in old if key != 'state'):
                raise EvidenceError('Contradictory evidence update')
            self._write(fd, data)
            _same(self._fd, name, fd, directory=True)
            self._guard()
        finally:
            _close(fd)

    @_serialized
    def _write(self, directory, data):
        self._guard()
        name = '.manifest-' + secrets.token_hex(16)
        fd = _open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | FILE_FLAGS,
                     0o600, dir_fd=directory)
        try:
            _same(directory, name, fd, directory=False)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError('Short manifest write')
                view = view[written:]
            os.fsync(fd)
            _same(directory, name, fd, directory=False)
            os.rename(name, 'manifest.json', src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            _close(fd)
        # Failed temporary writes are deliberately retained as blocking evidence.


@contextmanager
def _locked_at(base, check_parent):
    """Internal descriptor seam for disposable tests; production uses administration()."""
    _root()
    if not _fork_ready:
        raise EvidenceError('Fork safety unavailable')
    pid = os.getpid()
    _safe(os.fstat(base), directory=True)
    lock = operations = None
    evidence = None
    try:
        with _fork_gate:
            lock = _open('admin.lock', os.O_RDWR | os.O_CREAT | FILE_FLAGS, 0o600, dir_fd=base)
            _same(base, 'admin.lock', lock, directory=False)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fsync(lock)
            os.fsync(base)
            operations = _directory(base, 'operations', create=True)

            def check():
                _process(pid)
                _root()
                _safe(os.fstat(base), directory=True)
                check_parent()
                _same(base, 'admin.lock', lock, directory=False)
                _same(base, 'operations', operations, directory=True)

            check()
            evidence = _Evidence(operations, check)
        yield evidence
        with _fork_gate:
            check()
    finally:
        # Child hook closed these already; numeric descriptors may be reused.
        if os.getpid() == pid:
            with _fork_gate:
                if evidence is not None:
                    evidence._active = False
                if operations is not None:
                    _close(operations)
                if lock is not None:
                    _close(lock)  # Never unlink or replace the persistent inode.


@contextmanager
def administration():
    """Fixed production context, held across all caller work and evidence updates."""
    _root()  # Before even opening /.
    if not _fork_ready:
        raise EvidenceError('Fork safety unavailable')
    pid = os.getpid()
    descriptors = []
    links = []
    try:
        with _fork_gate:
            fd = _open('/', DIR_FLAGS)
            descriptors.append(fd)
            _safe(os.fstat(fd), directory=True, private=False)
            for name in ('var', 'lib', 'soc-policy-admin'):
                parent = fd
                if name == 'soc-policy-admin':
                    fd = _directory(parent, name, create=True)
                else:
                    fd = _open(name, DIR_FLAGS, dir_fd=parent)
                descriptors.append(fd)
                private = name == 'soc-policy-admin'
                _same(parent, name, fd, directory=True, private=private)
                links.append((parent, name, fd, private))

            def check():
                _root()
                _safe(os.fstat(descriptors[0]), directory=True, private=False)
                for parent, name, child, private in links:
                    _same(parent, name, child, directory=True, private=private)

        with _locked_at(fd, check) as evidence:
            yield evidence
    finally:
        if os.getpid() == pid:
            with _fork_gate:
                for fd in reversed(descriptors):
                    _close(fd)
