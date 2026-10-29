"""Internal protected candidate staging; no database or live-policy access.

The CLI deliberately does not invoke these primitives yet.
"""

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import threading
from contextlib import ExitStack, contextmanager
from functools import wraps

from soc_automation.approval import _policy_content
from soc_automation.approval_policy import policy_from_content

POLICY_LIMIT = 65536

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
            or (not directory and not private and mode & 0o7111)
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
    if (type(value['version']) is not int or value['version'] not in (1, 2)
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


_METADATA = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
             'st_size', 'st_mtime_ns', 'st_ctime_ns')


def _read_bytes(parent, name, fd, *, limit, private=True):
    """Bound allocation and check both the pinned inode and its named binding."""
    _same(parent, name, fd, directory=False, private=private)
    before = os.fstat(fd)
    if before.st_size > limit:
        raise EvidenceError('File too large')
    chunks = []
    size = 0
    while size <= limit:
        chunk = os.read(fd, min(8192, limit + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    after = os.fstat(fd)
    if (any(getattr(before, key) != getattr(after, key) for key in _METADATA)
            or size != before.st_size or size > limit):
        raise EvidenceError('File changed or too large')
    _same(parent, name, fd, directory=False, private=private)
    return b''.join(chunks)


@_serialized
def _source_bytes(path):
    """Read an explicit protected source with registered, pinned ancestors."""
    _root()
    if not _fork_ready:
        raise EvidenceError('Fork safety unavailable')
    if (type(path) is not str or not path.startswith('/') or '\x00' in path
            or len(path.encode('utf-8')) > 4096
            or any(part in ('', '.', '..') for part in path.split('/')[1:])):
        raise EvidenceError('Explicit normalized absolute source required')
    parts = path.split('/')[1:]
    descriptors = []
    links = []
    pid = os.getpid()
    try:
        fd = _open('/', DIR_FLAGS)
        descriptors.append(fd)
        _safe(os.fstat(fd), directory=True, private=False)
        for name in parts[:-1]:
            parent = fd
            fd = _open(name, DIR_FLAGS, dir_fd=parent)
            descriptors.append(fd)
            _same(parent, name, fd, directory=True, private=False)
            links.append((parent, name, fd))
        parent = fd
        fd = _open(parts[-1], os.O_RDONLY | FILE_FLAGS, dir_fd=parent)
        descriptors.append(fd)
        data = _read_bytes(parent, parts[-1], fd, limit=POLICY_LIMIT, private=False)
        _safe(os.fstat(descriptors[0]), directory=True, private=False)
        for parent, name, child in links:
            _same(parent, name, child, directory=True, private=False)
        return data
    finally:
        if os.getpid() == pid:
            with ExitStack() as cleanup:
                for fd in descriptors:
                    cleanup.callback(_close, fd)


def _canonical(data):
    policy = policy_from_content(data.decode('utf-8'))
    content = _policy_content(policy).encode('utf-8')
    if not 1 <= len(content) <= POLICY_LIMIT:
        raise EvidenceError('Canonical policy too large')
    return policy, content


def _binding(value, data):
    policy, canonical = _canonical(data)
    if (canonical != data or value['candidate_size'] != len(data)
            or value['candidate_sha256'] != hashlib.sha256(data).hexdigest()
            or value['candidate_version'] != policy.version):
        raise EvidenceError('Contradictory candidate binding')


@contextmanager
def _scandir(directory):
    """Protect runtime-owned aliases from construction through iterator close.

    scandir(fd) duplicates fd before returning its iterator. Exhaustion or close
    releases that alias; closing fd itself does not. Keep the unsafe depth set
    during construction and context exit too, so a reentrant Python fork exits
    in its child callback before resuming.
    """
    global _fd_transitions
    with _fork_gate:
        _fd_transitions += 1
        try:
            with os.scandir(directory) as entries:
                yield entries
        finally:
            _fd_transitions -= 1


def _entries(directory, expected):
    # Bounded inspection also detects interrupted temporary publications.
    with _scandir(directory) as entries:
        names = set()
        for entry in entries:
            names.add(entry.name)
            if len(names) > len(expected):
                raise EvidenceError('Unexpected evidence')
    if names != expected:
        raise EvidenceError('Incomplete or unexpected evidence')


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
        with _scandir(self._fd) as entries:
            for entry in entries:
                if len(result) >= OPERATION_LIMIT:
                    raise EvidenceError('Too many operations')
                name = entry.name
                try:
                    _id(name)
                    fd = _directory(self._fd, name)
                    try:
                        value = self._read(fd, name)
                        self._verify(fd, value)
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
            data = _read_bytes(directory, 'manifest.json', fd, limit=MANIFEST_LIMIT)
            value = json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                               parse_float=_reject_number, parse_constant=_reject_number)
            _manifest(value)
            if value['operation_id'] != operation_id:
                raise EvidenceError('Contradictory operation ID')
            return value
        finally:
            _close(fd)

    @_serialized
    def prepare(self, value, source_path):
        """Persist a verified immutable candidate, refusing any previous evidence."""
        self._guard()
        data = _manifest(value)
        if value['version'] != 2:
            raise EvidenceError('New preparation requires manifest version 2')
        _, candidate = _canonical(_source_bytes(source_path))
        _binding(value, candidate)
        if value['state'] != 'prepared':
            raise EvidenceError('Preparation requires prepared state')
        if self.discover():
            raise EvidenceError('Previous evidence requires authoritative admission')
        name = value['operation_id']
        os.mkdir(name, 0o700, dir_fd=self._fd)  # Exclusive; never reuse an ID.
        os.fsync(self._fd)
        fd = _directory(self._fd, name)
        try:
            candidate_fd = _open('candidate.json',
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | FILE_FLAGS,
                                 0o600, dir_fd=fd)
            try:
                _same(fd, 'candidate.json', candidate_fd, directory=False)
                self._write_all(candidate_fd, candidate)
                os.fsync(candidate_fd)
                _same(fd, 'candidate.json', candidate_fd, directory=False)
            finally:
                _close(candidate_fd)
            os.fsync(fd)
            self._verify(fd, value, preparing=True)
            self._publish(fd, name, value, data)
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
            old = self._read(fd, name)
            self._verify(fd, old)
            if old['state'] != 'prepared' or any(
                    old[key] != value[key] for key in old if key != 'state'):
                raise EvidenceError('Contradictory evidence update')
            self._publish(fd, name, value, data)
            _same(self._fd, name, fd, directory=True)
            self._guard()
        finally:
            _close(fd)

    @_serialized
    def _publish(self, directory, name, value, data):
        self._guard()
        before = (os.stat('candidate.json', dir_fd=directory, follow_symlinks=False)
                  if value['version'] == 2 else None)
        self._write(directory, data)
        persisted = self._read(directory, name)
        if persisted != value:
            raise EvidenceError('Manifest publication changed')
        self._verify(directory, persisted)
        if before is not None:
            after = os.stat('candidate.json', dir_fd=directory, follow_symlinks=False)
            if any(getattr(before, key) != getattr(after, key) for key in _METADATA):
                raise EvidenceError('Candidate changed during publication')

    @_serialized
    def _verify(self, directory, value, *, preparing=False):
        self._guard()
        expected = set() if preparing else {'manifest.json'}
        if value['version'] == 1:
            _entries(directory, expected)
            return None
        expected.add('candidate.json')
        _entries(directory, expected)
        fd = _open('candidate.json', os.O_RDONLY | FILE_FLAGS, dir_fd=directory)
        try:
            before = os.fstat(fd)
            data = _read_bytes(directory, 'candidate.json', fd, limit=POLICY_LIMIT)
            _binding(value, data)
            after = os.fstat(fd)
            if any(getattr(before, key) != getattr(after, key) for key in _METADATA):
                raise EvidenceError('Candidate changed during validation')
            _same(directory, 'candidate.json', fd, directory=False)
            _entries(directory, expected)
            return data
        finally:
            _close(fd)

    @_serialized
    def read_candidate(self, operation_id):
        """Return verified immutable bytes, never a descriptor or pathname."""
        self._guard()
        name = _id(operation_id)
        fd = _directory(self._fd, name)
        try:
            value = self._read(fd, name)
            if value['version'] != 2:
                raise EvidenceError('Legacy metadata has no staged candidate')
            data = self._verify(fd, value)
            _same(self._fd, name, fd, directory=True)
            self._guard()
            return data
        finally:
            _close(fd)

    @staticmethod
    def _write_all(fd, data):
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError('Short evidence write')
            view = view[written:]

    @_serialized
    def _write(self, directory, data):
        self._guard()
        name = '.manifest-' + secrets.token_hex(16)
        fd = _open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | FILE_FLAGS,
                     0o600, dir_fd=directory)
        try:
            _same(directory, name, fd, directory=False)
            self._write_all(fd, data)
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
