"""Linux Landlock confinement for the disposable, content/namespace write-confined preflight."""

import ctypes
import errno
import os
import platform
import re


def restrict_filesystem_writes():
    """Deny filesystem writes before opening policy or SQLite, including sidecars.

    Landlock leaves reads and file locking available. SQLite must open SHM read-only
    or fail; it cannot create missing sidecars or recover a journal. No database
    descriptors may be inherited into this process from the launcher.
    This denies content and namespace writes, not chmod/chown/utime/xattr or
    read-induced atime updates. See docs/secure-approval-deployment.md for the
    clean launcher contract and limits; this is not general process isolation.
    """
    if platform.machine() not in {'x86_64', 'aarch64'}:
        raise OSError(errno.ENOSYS, 'Unsupported Landlock syscall architecture')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    def call(number, *args):
        result = libc.syscall(ctypes.c_long(number), *args)
        if result < 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        return result

    # These architectures use the generic Linux Landlock syscall numbers.
    abi = call(444, ctypes.c_void_p(), ctypes.c_size_t(0), ctypes.c_uint(1))
    # ABI 3 supplies TRUNCATE, needed to cover every ordinary file write path.
    if abi < 3:
        raise OSError(errno.ENOSYS, 'Landlock ABI 3 required')
    rights = (1 << 1) | sum(1 << bit for bit in range(4, 15))
    if abi >= 5:
        rights |= 1 << 15  # IOCTL_DEV
    ruleset = ctypes.c_uint64(rights)
    fd = call(444, ctypes.byref(ruleset), ctypes.c_size_t(8), ctypes.c_uint(0))
    try:
        if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        # Empty allowlist: no path is granted any handled write right.
        call(446, ctypes.c_int(fd), ctypes.c_uint(0))
    finally:
        os.close(fd)


def require_clean_launcher():
    """Reject threads and potentially writable shared mappings before inspection.

    Use the fresh installed executable before opening application resources.
    procfs is required to detect native threads and shared mappings. Private
    mappings are copy-on-write across fork; shared mappings may be writable or
    later upgraded with mprotect.
    """
    if len(os.listdir('/proc/self/task')) != 1:
        raise OSError(errno.EPERM, 'Single-threaded preflight launcher required')
    # smaps exposes VM_MAYWRITE (mw), including read-only shared mappings
    # that could later be upgraded by mprotect after their descriptor is closed.
    pending_shared = False
    seen_mapping = False
    with open('/proc/self/smaps', encoding='ascii') as mappings:
        for line in mappings:
            if re.match(r'^[0-9a-f]+-[0-9a-f]+ ', line):
                seen_mapping = True
                if pending_shared:
                    raise OSError(errno.EPERM, 'Missing shared mapping flags')
                permissions = line.split()[1]
                pending_shared = permissions[3] == 's'
                if pending_shared and permissions[1] == 'w':
                    raise OSError(errno.EPERM, 'Writable shared mapping in launcher')
            elif line.startswith('VmFlags:') and pending_shared:
                if 'mw' in line.split()[1:]:
                    raise OSError(errno.EPERM, 'Upgradeable shared mapping in launcher')
                pending_shared = False
    if pending_shared or not seen_mapping:
        raise OSError(errno.EPERM, 'Incomplete mapping information')


def close_inherited_descriptors():
    """Close all inherited descriptors, including 0, 1 and 2, in the child.

    Exit status is the sole bounded parent channel. CLOEXEC does not protect
    across fork. procfs enumeration must succeed or inspection fails closed.
    """
    descriptors = [int(name) for name in os.listdir('/proc/self/fd')]
    for fd in descriptors:
        try:
            os.close(fd)
        except OSError as exc:
            # listdir's own descriptor has already been closed.
            if exc.errno != errno.EBADF:
                raise
