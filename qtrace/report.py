"""Bounded, durable publication for qtrace session reports."""

from __future__ import annotations

import dataclasses
import ctypes
import errno
import json
import os
import secrets
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping


_MAX_REPORT_BYTES = 1_048_576
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _exchange(directory: int, left: str, right: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(directory, left.encode(), directory, right.encode(), 2) != 0:
        failure = ctypes.get_errno()
        raise OSError(failure, os.strerror(failure))


class ConditionalReplaceRecoveryError(FileExistsError):
    """A conditional report exchange left a recovery file for explicit handling."""

    def __init__(self, recovery_name: str, primary: BaseException,
                 recovery: BaseException | None = None) -> None:
        if recovery is None:
            detail = ("conditional report replacement was rolled back after "
                      f"{primary}: recovery file is {recovery_name}")
        else:
            detail = ("conditional report recovery failed after "
                      f"{primary}: recovery file is {recovery_name}; recovery was {recovery}")
        super().__init__(detail)
        self.recovery_name = recovery_name


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _recovery_note(error: BaseException, recovery_name: str) -> None:
    error.add_note("conditional report exchange may have completed; "
                   f"recovery file for the prior report is {recovery_name}")


def _discard_owned_temporary(directory: int, temporary: str,
                             primary: BaseException | None = None) -> None:
    try:
        os.unlink(temporary, dir_fd=directory)
    except FileNotFoundError:
        pass
    except BaseException as cleanup:
        if primary is None:
            raise
        primary.add_note(f"could not remove owned report temporary {temporary}: {cleanup}")


def conditional_replace_at(directory: int, temporary: str, target: str,
                           expected_identity: tuple[int, int]) -> bool:
    """Atomically replace *target* only if its inode matches, taking temp ownership.

    From entry onward this module owns ``temporary``. It removes it after a
    safe rejection or completed exchange; ambiguous exchanges retain it as a
    recovery file and propagate the original interruption/error.
    """
    try:
        try:
            existing = os.stat(target, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
    except BaseException as error:
        _discard_owned_temporary(directory, temporary, error)
        raise
    if (existing is None or not stat.S_ISREG(existing.st_mode)
            or _identity(existing) != expected_identity):
        _discard_owned_temporary(directory, temporary)
        return False

    try:
        temporary_before = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
    except BaseException as error:
        _discard_owned_temporary(directory, temporary, error)
        raise
    if not stat.S_ISREG(temporary_before.st_mode):
        _discard_owned_temporary(directory, temporary)
        raise ValueError("report temporary file is unsafe")
    temporary_identity = _identity(temporary_before)
    try:
        _exchange(directory, temporary, target)
    except BaseException as error:
        try:
            unchanged = _identity(os.stat(temporary, dir_fd=directory,
                                          follow_symlinks=False)) == temporary_identity
        except BaseException:
            unchanged = False
        if unchanged:
            _discard_owned_temporary(directory, temporary, error)
        else:
            _recovery_note(error, temporary)
        raise

    try:
        old = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
        matched = _identity(old) == expected_identity
    except BaseException as primary:
        try:
            _exchange(directory, temporary, target)
        except BaseException as rollback:
            raise ConditionalReplaceRecoveryError(temporary, primary, rollback) from rollback
        _recovery_note(primary, temporary)
        primary.add_note(f"report replacement was rolled back; retained recovery file {temporary}")
        raise
    if not matched:
        primary = RuntimeError("conditional report target changed")
        try:
            _exchange(directory, temporary, target)
        except BaseException as rollback:
            raise ConditionalReplaceRecoveryError(temporary, primary, rollback) from rollback
        raise ConditionalReplaceRecoveryError(temporary, primary)
    os.unlink(temporary, dir_fd=directory)
    return True


class SessionStage(str, Enum):
    PREFLIGHT = "preflight"
    RESOLVING_TARGET = "resolving_target"
    BUILDING_TRACER = "building_tracer"
    DEPLOYING = "deploying"
    INJECTING = "injecting"
    INSTALLING_HOOKS = "installing_hooks"
    RUNNING = "running"
    STOPPING = "stopping"
    SEALED = "sealed"
    MONITORING = "monitoring"
    PULLING = "pulling"
    COMPLETED = "completed"


@dataclass(frozen=True)
class SessionReport:
    schema: int
    session_id: str
    mode: str
    status: str
    stage: str
    package: str
    serial: str
    pid: int | None
    started_at: str
    finished_at: str
    timeline: tuple[Mapping[str, object], ...]
    device: Mapping[str, object]
    tracer: Mapping[str, object]
    target: Mapping[str, object]
    effective_config: Mapping[str, object]
    native: Mapping[str, object]
    artifacts: tuple[Mapping[str, object], ...]
    warnings: tuple[Mapping[str, object], ...]
    error: Mapping[str, object] | None
    outputs: tuple[str, ...]


def _normalize(value: object) -> object:
    if dataclasses.is_dataclass(value):
        return {field.name: _normalize(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return _normalize(value.value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _normalize(member) for key, member in value.items()}
    if isinstance(value, (tuple, list)):
        return [_normalize(member) for member in value]
    if value is None or type(value) in {str, int, bool}:
        return value
    return str(value)[:1024]


def _check_directory(descriptor: int) -> None:
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError("report destination directory must not be a symlink")


def _trusted_parent(path: Path) -> int:
    """Open/create every component using only trusted directory descriptors."""
    if path.is_absolute():
        descriptor = os.open("/", _DIR_FLAGS)
        components = path.parts[1:]
    else:
        descriptor = os.open(".", _DIR_FLAGS)
        components = path.parts
    try:
        _check_directory(descriptor)
        for component in components:
            if component in {"", "."}:
                continue
            if component == "..":
                raise ValueError("report destination must not contain parent traversal")
            created = False
            try:
                child = os.open(component, _DIR_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    pass
                try:
                    child = os.open(component, _DIR_FLAGS, dir_fd=descriptor)
                except OSError as error:
                    if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise ValueError("report destination directory must not be a symlink") from error
                    raise
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError("report destination directory must not be a symlink") from error
                raise
            try:
                _check_directory(child)
                if created:
                    os.fchmod(child, 0o700)
                if created and stat.S_IMODE(os.fstat(child).st_mode) != 0o700:
                    raise ValueError("report destination directory mode is unsafe")
            except Exception:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


class ReportWriter:
    @staticmethod
    def _encode(report: SessionReport) -> bytes:
        encoded = json.dumps(_normalize(report), sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
        if not encoded or len(encoded) > _MAX_REPORT_BYTES:
            raise ValueError("report exceeds the 1 MiB publication limit")
        return encoded

    def write_atomic_at(self, directory: int, name: str, report: SessionReport, *,
                        no_replace: bool = False,
                        expected_identity: tuple[int, int] | None = None) -> bool:
        """Publish through a held directory fd; False means a concurrent replacement won."""
        if name in {"", ".", ".."} or "/" in name:
            raise ValueError("report destination has no filename")
        encoded = self._encode(report)
        directory = os.dup(directory)
        temporary = f".{name}.{secrets.token_hex(16)}"
        descriptor = -1
        try:
            _check_directory(directory)
            try:
                existing = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if expected_identity is not None:
                if (existing is None or not stat.S_ISREG(existing.st_mode)
                        or (existing.st_dev, existing.st_ino) != expected_identity):
                    return False
            if existing is not None and (stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)):
                raise ValueError("report destination must be a regular non-symlink file")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
            try:
                offset = 0
                while offset < len(encoded):
                    written = os.write(descriptor, encoded[offset:])
                    if written <= 0:
                        raise OSError("report temporary write made no progress")
                    offset += written
                os.fsync(descriptor)
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                    raise ValueError("report temporary file is unsafe")
            finally:
                os.close(descriptor)
                descriptor = -1
            if no_replace:
                try:
                    os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory,
                            follow_symlinks=False)
                except FileExistsError:
                    raise ValueError("report destination already exists")
                os.unlink(temporary, dir_fd=directory)
            elif expected_identity is not None:
                owned_temporary = temporary
                temporary = ""
                if not conditional_replace_at(directory, owned_temporary, name, expected_identity):
                    return False
            else:
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            temporary = ""
            os.fsync(directory)
            return True
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
            os.close(directory)

    def write_atomic(self, output: Path, report: SessionReport, *, no_replace: bool = False) -> None:
        output = Path(output)
        if output.name in {"", ".", ".."}:
            raise ValueError("report destination has no filename")
        directory = _trusted_parent(output.parent)
        try:
            self.write_atomic_at(directory, output.name, report, no_replace=no_replace)
        finally:
            os.close(directory)
