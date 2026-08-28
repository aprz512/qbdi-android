"""Bounded canonical identity for the historical qtrace benchmark target."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
import time
from typing import Callable, Sequence

try:
    from scripts.bounded_process import capture_bounded
except ModuleNotFoundError:  # Support direct execution from scripts/.
    from bounded_process import capture_bounded  # type: ignore[no-redef]


HISTORICAL_COMMIT = "2d6b1022a14ae554804a57e267544c12dea29353"
HISTORICAL_RAW_TARGET_SHA256 = "5f1a970825ae8bacb17d8dd656e01bd1fe7172638ba3ddcacd82ffaaad6e62c0"
HISTORICAL_CANONICAL_TARGET_SHA256, NDK_VERSION = "0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169", "26.1.10909125"
MAX_TARGET_BYTES = 64 * 1024 * 1024
MAX_OBJCOPY_OUTPUT_BYTES = 1024 * 1024


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("canonicalization deadline expired")
    return remaining


def _pinned_objcopy(android_home: Path | None) -> Path:
    root = android_home or Path(os.environ.get("ANDROID_HOME", ""))
    if not str(root):
        raise ValueError("ANDROID_HOME is required for canonicalization")
    return root / "ndk" / NDK_VERSION / "toolchains" / "llvm" / "prebuilt" / "linux-x86_64" / "bin" / "llvm-objcopy"


def _write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_regular_elf(path: Path, deadline: float) -> bytes:
    _remaining(deadline)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise ValueError("canonical output is not a regular file")
        if details.st_size <= 0:
            raise ValueError("canonical output is empty")
        if details.st_size > MAX_TARGET_BYTES:
            raise ValueError("canonical output exceeds 64 MiB")
        with os.fdopen(descriptor, "rb") as input_file:
            descriptor = -1
            result = input_file.read(MAX_TARGET_BYTES + 1)
        _remaining(deadline)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(result) > MAX_TARGET_BYTES:
        raise ValueError("canonical output exceeds 64 MiB")
    if not result.startswith(b"\x7fELF"):
        raise ValueError("canonical output is not an ELF file")
    return result


def canonical_elf_sha256(elf: bytes, *, deadline: float,
                         android_home: Path | None = None,
                         capture: Callable[[Sequence[str]], bytes] = capture_bounded) -> str:
    """Canonicalize one bounded ELF with the pinned NDK tool and hash its output."""
    if not elf:
        raise ValueError("canonical target is empty")
    if len(elf) > MAX_TARGET_BYTES:
        raise ValueError("canonical target exceeds 64 MiB")
    if not elf.startswith(b"\x7fELF"):
        raise ValueError("canonical target is not an ELF file")
    _remaining(deadline)
    objcopy = _pinned_objcopy(android_home)
    try:
        details = objcopy.lstat()
    except OSError as error:
        raise ValueError(f"pinned llvm-objcopy tool is unavailable: {objcopy}") from error
    if not stat.S_ISREG(details.st_mode) or not os.access(objcopy, os.X_OK):
        raise ValueError(f"pinned llvm-objcopy tool is not executable: {objcopy}")

    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []
    try:
        with tempfile.TemporaryDirectory(prefix="qtrace-canonical-", dir=None) as directory:
            os.chmod(directory, 0o700)
            root = Path(directory)
            source = root / "target.elf"
            destination = root / "target.canonical.elf"
            _write_exclusive(source, elf)
            _write_exclusive(destination, b"")
            try:
                capture(
                    [str(objcopy), "--strip-debug", "--remove-section=.note.gnu.build-id",
                     str(source), str(destination)],
                    maximum_bytes=MAX_OBJCOPY_OUTPUT_BYTES, timeout=_remaining(deadline),
                )
                return hashlib.sha256(_read_regular_elf(destination, deadline)).hexdigest()
            finally:
                for path in (destination, source):
                    try:
                        path.unlink(missing_ok=True)
                    except OSError as error:
                        cleanup_errors.append(str(error))
    except BaseException as error:
        primary_error = error
    if cleanup_errors:
        raise RuntimeError(
            f"{primary_error}; canonicalization cleanup failed: {'; '.join(cleanup_errors)}"
        ) from primary_error
    assert primary_error is not None
    raise primary_error
