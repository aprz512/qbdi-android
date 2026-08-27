"""Per-device/package advisory session locks."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from qtrace.errors import ErrorCode, QtraceError


_SAFE_TARGET = re.compile(r"[A-Za-z0-9._:@-]+\Z")


class TargetLock:
    def __init__(self, runtime_dir: Path | None = None) -> None:
        self._runtime_dir = runtime_dir

    def _root(self) -> Path:
        base = self._runtime_dir or Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp"))
        root = base / f"qtrace-{os.getuid()}"
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = root.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise QtraceError("session.lock_invalid", "lock", "lock root is unsafe")
        os.chmod(root, 0o700)
        info = root.stat()
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise QtraceError("session.lock_invalid", "lock", "lock root mode is unsafe")
        return root

    @contextmanager
    def acquire(self, serial: str, package: str) -> Iterator[None]:
        if not isinstance(serial, str) or not _SAFE_TARGET.fullmatch(serial):
            raise QtraceError("session.lock_invalid", "lock", "device serial is invalid")
        if not isinstance(package, str) or not _SAFE_TARGET.fullmatch(package):
            raise QtraceError("session.lock_invalid", "lock", "package is invalid")
        digest = hashlib.sha256((serial + "\0" + package).encode("utf-8")).hexdigest()
        flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self._root() / f"{digest}.lock", flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise QtraceError("session.lock_invalid", "lock", "lock file is unsafe")
            os.fchmod(descriptor, 0o600)
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
                raise QtraceError("session.lock_invalid", "lock", "lock file mode is unsafe")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EAGAIN}:
                    raise QtraceError(ErrorCode.SESSION_BUSY, "lock", "a session already owns this device/package") from error
                raise
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
