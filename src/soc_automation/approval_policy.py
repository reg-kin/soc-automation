"""Protected Linux policy input; no environment lookup or implicit installation."""

import hashlib
import json
import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from soc_automation.approval import ReviewPolicy, _policy_content, _uid
from soc_automation.deadline import check_deadline
from soc_automation.publication_review import _object
from soc_automation.state import StateError

POLICY_LIMIT = 65536


def strict_object(data):
    """Integer-only JSON objects, rejecting duplicate keys and nonfinite numbers."""
    def no_float(value):
        raise ValueError('Floating point numbers are unsupported')

    # _object supplies the existing duplicate-key and constant rejection convention.
    json.loads(data, parse_float=no_float, parse_constant=no_float)
    return _object(data)


def policy_from_content(data):
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
    return ReviewPolicy(**value)


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


def verify_authority(store, policy, *, deadline=None):
    """Read-only snapshot; validate *all* ledger semantics, then exact active content."""
    while True:
        check_deadline(deadline)
        try:
            return _verify_authority_snapshot(store, policy, deadline=deadline)
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
                raise StateError('Policy authority unavailable') from exc
            check_deadline(deadline)
            time.sleep(min(0.005, max(0, deadline - time.monotonic())))
        except Exception as exc:
            raise StateError('Policy authority unavailable') from exc


def _verify_authority_snapshot(store, policy, *, deadline):
    with store._connection(readonly=True, deadline=deadline) as conn:
        if deadline is not None:
            conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 100)
        store._validate(conn)
        oversized = conn.execute(
            'SELECT 1 FROM review_policy_generations '
            'WHERE length(CAST(content AS BLOB))>? LIMIT 1', (POLICY_LIMIT,)
        ).fetchone()
        if oversized:
            raise ValueError('Oversized authority')
        active = store._active_policy_generation(conn)
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
        if active is None or active['content'] != _policy_content(policy):
            raise ValueError('Missing or superseded authority')
