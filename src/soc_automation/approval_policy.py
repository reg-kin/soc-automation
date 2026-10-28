"""Protected Linux policy input; no environment lookup or implicit installation."""

import fcntl
import hashlib
import json
import os
import selectors
import sqlite3
import stat
import struct
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from soc_automation.approval import ReviewPolicy, _policy_content, _uid
from soc_automation.deadline import check_deadline, current_deadline
from soc_automation.publication_review import _object
from soc_automation.state import StateError

SNAPSHOT_LIMIT = 64 * 1024 * 1024
IPC_LIMIT = SNAPSHOT_LIMIT + 8
COPY_CHUNK = 65536

POLICY_LIMIT = 65536
RAW_POLICY_LIMIT = POLICY_LIMIT
CANONICAL_POLICY_LIMIT = POLICY_LIMIT


def strict_object(data):
    """Integer-only JSON objects, rejecting duplicate keys and nonfinite numbers."""
    def no_float(value):
        raise ValueError('Floating point numbers are unsupported')

    # _object supplies the existing duplicate-key and constant rejection convention.
    json.loads(data, parse_float=no_float, parse_constant=no_float)
    return _object(data)


def policy_from_content(data):
    if type(data) is not str or len(data.encode("utf-8")) > RAW_POLICY_LIMIT:
        raise ValueError("Policy raw input too large or invalid")
    value = strict_object(data)
    fields = set(ReviewPolicy.__dataclass_fields__)
    if set(value) != fields:
        raise ValueError('Complete policy fields required')
    for name in ('principals', 'targets', 'decisions', 'reason_requirements'):
        if type(value[name]) is not list:
            raise ValueError('Policy array required')
    for name in ('targets', 'decisions'):
        items = value[name]
        if any(type(item) is not str for item in items) or len(items) != len(set(items)):
            raise ValueError('Unique policy strings required')
        value[name] = frozenset(items)
    principals = []
    for pair in value['principals']:
        if type(pair) is not list or len(pair) != 2:
            raise ValueError('Invalid principal mapping')
        principals.append(tuple(pair))
    value['principals'] = tuple(principals)
    reasons = []
    for pair in value['reason_requirements']:
        if (type(pair) is not list or len(pair) != 2 or type(pair[0]) is not str
                or type(pair[1]) is not list
                or any(type(item) is not str for item in pair[1])
                or len(pair[1]) != len(set(pair[1]))):
            raise ValueError('Invalid reason mapping')
        reasons.append((pair[0], frozenset(pair[1])))
    value['reason_requirements'] = tuple(reasons)
    policy = ReviewPolicy(**value)
    if len(_policy_content(policy).encode("utf-8")) > CANONICAL_POLICY_LIMIT:
        raise ValueError("Canonical policy too large")
    return policy


def _parts(path):
    raw = os.fspath(path)
    if raw == '/':
        return []
    if (not raw.startswith('/') or '\x00' in raw
            or any(part in ('', '.', '..') for part in raw.split('/')[1:])):
        raise ValueError('Explicit absolute normalized path required')
    return raw.split('/')[1:]


def _protected(info, owners, *, directory):
    if (info.st_uid not in owners or info.st_mode & 0o022
            or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or (not directory and (info.st_mode & 0o7111 or info.st_nlink != 1))):
        raise ValueError('Unsafe protected path')


def protected_directory(path, owners):
    """Walk from / with openat + O_NOFOLLOW; caller owns returned pinned fd."""
    parts = _parts(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        _protected(os.fstat(fd), owners, directory=True)
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
            _protected(os.fstat(fd), owners, directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


@dataclass(frozen=True)
class PolicySource:
    """Trusted composition only. Production owner_uid is the administrator (usually 0)."""

    path: Path
    owner_uid: int = 0

    def __post_init__(self):
        _parts(self.path)
        if not isinstance(self.path, Path) or not self.path.name:
            raise ValueError('Explicit policy file path required')
        _uid(self.owner_uid)

    def read_candidate(self):
        """Protected parsing only, for separate trusted administrative installation."""
        parent = protected_directory(self.path.parent, {0, self.owner_uid})
        try:
            fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                         | os.O_CLOEXEC, dir_fd=parent)
            try:
                before = os.fstat(fd)
                _protected(before, {self.owner_uid}, directory=False)
                if before.st_size > POLICY_LIMIT:
                    raise ValueError('Policy too large')
                with os.fdopen(os.dup(fd), 'rb') as stream:
                    data = stream.read(POLICY_LIMIT + 1)
                after = os.fstat(fd)
                fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode',
                          'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                if (len(data) > POLICY_LIMIT
                        or any(getattr(before, key) != getattr(after, key) for key in fields)):
                    raise ValueError('Policy changed or too large')
                return policy_from_content(data.decode('utf-8'))
            finally:
                os.close(fd)
        finally:
            os.close(parent)

    def load(self, store):
        policy = self.read_candidate()
        verify_authority(store, policy)
        return policy


@dataclass(frozen=True)
class PolicyGeneration:
    generation: int
    version: str
    content: str
    content_sha256: str
    installed_at: str


@dataclass(frozen=True)
class PolicyLedger:
    """Validated snapshot evidence, never an independent policy authority."""

    generations: tuple[PolicyGeneration, ...]

    @property
    def active(self):
        return self.generations[-1] if self.generations else None


def inspect_policy_ledger(store, *, deadline=None):
    """Validate an existing ledger read-only, without a live file.

    Empty is valid. Never initializes/migrates. Returns immutable snapshot evidence.
    Invalid/unavailable authority raises sanitized StateError; deadlines raise TimeoutError.
    """
    token = current_deadline.set(deadline)
    try:
        result = _authority_snapshot(store, deadline=deadline, inspection=True)
        check_deadline(deadline)
        return result
    finally:
        current_deadline.reset(token)


def verify_authority(store, policy, *, deadline=None):
    """Require validated history and an exact nonempty active policy match."""
    if type(policy) is not ReviewPolicy:
        raise StateError('Policy authority unavailable')
    _authority_snapshot(store, policy=policy, deadline=deadline)


def _authority_snapshot(store, *, policy=None, deadline=None, inspection=False):
    """Read-only snapshot; validate *all* ledger semantics, then exact active content."""
    while True:
        check_deadline(deadline)
        try:
            return _inspect_policy_ledger_snapshot(
                store, policy=policy, deadline=deadline, inspection=inspection)
        except TimeoutError:
            raise
        except (sqlite3.OperationalError, StateError) as exc:
            # The ledger helper preserves the originating SQLite error.
            cause = exc.__cause__ if isinstance(exc, StateError) else exc
            # Extended BUSY codes (including BUSY_SNAPSHOT) are contention too.
            # The context manager has rolled back and closed the old connection.
            # Never retry statements within its potentially stale read snapshot.
            if (deadline is None or not isinstance(cause, sqlite3.Error)
                    or (getattr(cause, 'sqlite_errorcode', 0) & 0xff) != sqlite3.SQLITE_BUSY):
                if (inspection and isinstance(exc, StateError)
                        and str(exc).startswith('Policy inspection unavailable:')):
                    raise
                raise StateError('Policy authority unavailable') from exc
            check_deadline(deadline)
            time.sleep(min(0.005, max(0, deadline - time.monotonic())))
        except Exception as exc:
            raise StateError('Policy authority unavailable') from exc


def _locked_inspection_bytes(path, *, deadline):
    """Copy rollback state under Linux OFD locks that conflict with SQLite locks."""
    if sys.platform != 'linux' or not hasattr(fcntl, 'F_OFD_SETLK'):
        raise StateError('Policy inspection unavailable: unsupported platform')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise StateError('Policy inspection unavailable: unsupported file')
        lock = struct.pack('@hhqqi', fcntl.F_RDLCK, os.SEEK_SET, 0x40000000, 512, 0)
        while True:
            check_deadline(deadline)
            try:
                fcntl.fcntl(fd, fcntl.F_OFD_SETLK, lock)
                break
            except BlockingIOError:
                if deadline is None:
                    raise StateError('Policy inspection unavailable: database busy') from None
                time.sleep(min(0.005, max(0, deadline - time.monotonic())))
        size = os.fstat(fd).st_size
        if size > SNAPSHOT_LIMIT:
            raise StateError('Policy inspection unavailable: snapshot size limit')
        header = os.pread(fd, 100, 0)
        if (len(header) != 100 or header[:16] != b'SQLite format 3\x00'
                or header[18:20] != b'\x01\x01'
                or any(os.path.lexists(str(path) + suffix)
                       for suffix in ('-journal', '-wal', '-shm'))):
            raise StateError('Policy inspection unavailable: unsupported journal state')
        data = bytearray()
        while len(data) < size:
            check_deadline(deadline)
            chunk = os.pread(fd, min(COPY_CHUNK, size - len(data)), len(data))
            if not chunk:
                raise StateError('Policy inspection unavailable: snapshot changed')
            data.extend(chunk)
        if os.fstat(fd).st_size != size or os.pread(fd, 1, size):
            raise StateError('Policy inspection unavailable: snapshot changed')
        check_deadline(deadline)
        return data
    finally:
        os.close(fd)


def _inspection_output(program, path, deadline):
    """Bound retained IPC to IPC_LIMIT+1; discard stderr without buffering."""
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter/program, no shell
        [sys.executable, '-c', program, str(path), str(deadline)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    data = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                check_deadline(deadline)
                remaining = None if deadline is None else max(0, deadline - time.monotonic())
                if not selector.select(remaining):
                    check_deadline(deadline)
                    continue
                chunk = os.read(process.stdout.fileno(), min(COPY_CHUNK, IPC_LIMIT + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > IPC_LIMIT or (len(data) >= 8 and
                        int.from_bytes(data[:8], 'big') > SNAPSHOT_LIMIT):
                    raise StateError('Policy inspection unavailable: snapshot size limit')
        try:
            code = process.wait(timeout=None if deadline is None else
                                max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise TimeoutError from None
        check_deadline(deadline)
        if code == 3:
            raise StateError('Policy inspection unavailable: snapshot size limit')
        if code:
            raise StateError('Policy inspection unavailable: unsupported or busy database state')
        if len(data) < 8 or int.from_bytes(data[:8], 'big') != len(data) - 8:
            raise StateError('Policy inspection unavailable: malformed snapshot IPC')
        return data[8:]
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


@contextmanager
def _inspection_connection(store, *, deadline):
    # Separate process: closing any source fd in this process could release
    # POSIX locks held by same-process runtime SQLite connections.
    check_deadline(deadline)
    program = """
import sys
from pathlib import Path
from soc_automation.approval_policy import _locked_inspection_bytes
from soc_automation.state import StateError
try:
    data = _locked_inspection_bytes(
        Path(sys.argv[1]), deadline=None if sys.argv[2] == 'None' else float(sys.argv[2]))
except StateError as exc:
    sys.exit(3 if str(exc) == 'Policy inspection unavailable: snapshot size limit' else 4)
sys.stdout.buffer.write(len(data).to_bytes(8, 'big'))
sys.stdout.buffer.write(data)
"""
    data = _inspection_output(program, store.path, deadline)
    check_deadline(deadline)
    conn = sqlite3.connect(':memory:', isolation_level=None)
    interrupted = False

    def progress():
        nonlocal interrupted
        interrupted = deadline is not None and time.monotonic() >= deadline
        return int(interrupted)

    try:
        conn.deserialize(data)
        check_deadline(deadline)
        conn.row_factory = sqlite3.Row
        if deadline is not None:
            conn.set_progress_handler(progress, 100)
        conn.execute('PRAGMA query_only=ON')
        conn.execute('BEGIN')
        yield conn
    except (sqlite3.Error, StateError) as exc:
        cause = exc
        seen = set()
        while isinstance(cause, StateError) and id(cause) not in seen:
            seen.add(id(cause))
            cause = cause.__cause__
        if (interrupted and deadline is not None and time.monotonic() >= deadline
                and isinstance(cause, sqlite3.Error)
                and (getattr(cause, 'sqlite_errorcode', 0) & 0xff)
                == sqlite3.SQLITE_INTERRUPT):
            raise TimeoutError('Policy inspection deadline expired') from exc
        raise
    finally:
        conn.close()


def _inspect_policy_ledger_snapshot(store, *, policy=None, deadline, inspection=False):
    connection = (_inspection_connection(store, deadline=deadline) if inspection
                  else store._connection(readonly=True, deadline=deadline))
    with connection as conn:
        if deadline is not None and not inspection:
            conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 100)
        store._validate(conn)
        oversized = conn.execute(
            'SELECT 1 FROM review_policy_generations '
            'WHERE length(CAST(content AS BLOB))>? LIMIT 1', (POLICY_LIMIT,)
        ).fetchone()
        if oversized:
            raise ValueError('Oversized authority')
        store._active_policy_generation(conn)
        generations = []
        versions = set()
        for row in conn.execute('SELECT * FROM review_policy_generations ORDER BY generation'):
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError
            content = row['content']
            if len(content.encode()) > POLICY_LIMIT:
                raise ValueError('Oversized authority')
            candidate = policy_from_content(content)
            if (content != _policy_content(candidate) or candidate.version in versions
                    or candidate.version != row['version']
                    or hashlib.sha256(content.encode()).hexdigest() != row['content_sha256']):
                raise ValueError('Inconsistent authority')
            versions.add(candidate.version)
            generations.append(PolicyGeneration(**dict(row)))
        ledger = PolicyLedger(tuple(generations))
        if policy is not None and (
                ledger.active is None or ledger.active.content != _policy_content(policy)):
            raise ValueError('Missing or superseded authority')
        check_deadline(deadline)
        return ledger
