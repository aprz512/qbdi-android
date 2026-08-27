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


_SAFE_SERIAL = re.compile(r"[A-Za-z0-9._:@+-]+\Z")
_PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z")


class TargetLock:
    def __init__(self, runtime_dir: Path | None = None) -> None:
        self._runtime_dir = runtime_dir

    def _root(self) -> int:
        base = self._runtime_dir or Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp"))
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        if any(part == ".." for part in base.parts):
            raise QtraceError("session.lock_invalid", "lock", "lock base is unsafe")
        descriptor = os.open("/" if base.is_absolute() else ".", flags)
        try:
            for component in base.parts[1 if base.is_absolute() else 0:]:
                if component in {"", "."}:
                    continue
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.getuid()}:
                raise QtraceError("session.lock_invalid", "lock", "lock base is unsafe")
            base_fd = descriptor
        except OSError as error:
            os.close(descriptor)
            raise QtraceError("session.lock_invalid", "lock", "lock base is unsafe") from error
        name = f"qtrace-{os.getuid()}"
        try:
            try:
                os.mkdir(name, 0o700, dir_fd=base_fd)
            except FileExistsError:
                pass
            try:
                root = os.open(name, flags, dir_fd=base_fd)
            except OSError as error:
                raise QtraceError("session.lock_invalid", "lock", "lock root is unsafe") from error
        finally:
            os.close(base_fd)
        try:
            info = os.fstat(root)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise QtraceError("session.lock_invalid", "lock", "lock root is unsafe")
            os.fchmod(root, 0o700)
            if stat.S_IMODE(os.fstat(root).st_mode) != 0o700:
                raise QtraceError("session.lock_invalid", "lock", "lock root mode is unsafe")
            return root
        except Exception:
            os.close(root)
            raise

    @contextmanager
    def acquire(self, serial: str, package: str) -> Iterator[None]:
        if not isinstance(serial, str) or not _SAFE_SERIAL.fullmatch(serial):
            raise QtraceError("session.lock_invalid", "lock", "device serial is invalid")
        if not isinstance(package, str) or not _PACKAGE.fullmatch(package):
            raise QtraceError("session.lock_invalid", "lock", "package is invalid")
        digest = hashlib.sha256((serial + "\0" + package).encode("utf-8")).hexdigest()
        flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        root = self._root()
        descriptor = os.open(f"{digest}.lock", flags, 0o600, dir_fd=root)
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
            os.close(root)
