"""Cooperative monotonic deadlines scoped to the current transaction/context."""

import hashlib
import time
from contextvars import ContextVar

current_deadline = ContextVar('decision_deadline', default=None)


def check_deadline(deadline=None):
    bound = current_deadline.get() if deadline is None else deadline
    if bound is not None and time.monotonic() >= bound:
        raise TimeoutError('Decision deadline expired')


def sha256_text(value):
    """Bound hashing work between chunks; encoding itself is synchronous."""
    digest = hashlib.sha256()
    for offset in range(0, len(value), 65536):
        check_deadline()
        digest.update(value[offset:offset + 65536].encode('utf-8'))
    check_deadline()
    return digest.hexdigest()
