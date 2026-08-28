"""Bounded canonical identity for the historical qtrace benchmark target."""

from __future__ import annotations

import hashlib
import multiprocessing
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time
import zipfile
import zlib
from dataclasses import dataclass, field
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
MAX_ARCHIVE_BYTES, MAX_ARCHIVE_MEMBERS = 8 * 1024 * 1024, 256
MAX_ARCHIVE_FILE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_PATH_BYTES, MAX_ARCHIVE_COMPONENTS = 512, 32
MAX_APK_BYTES = 128 * 1024 * 1024
MAX_ZIP_ENTRIES = 4096
MAX_ZIP_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
BUILD_TOOLS_VERSION = "35.0.0"
MAX_GRADLE_OUTPUT_BYTES = 4 * 1024 * 1024
FILE_WORKER_TIMEOUT = 30.0
_TARGET_ENTRY = "lib/arm64-v8a/libdemo_target.so"


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("canonicalization deadline expired")
    return remaining


def _pinned_objcopy(android_home: Path | None) -> Path:
    if android_home is None:
        configured = os.environ.get("ANDROID_HOME")
        if not configured:
            raise ValueError("ANDROID_HOME is required for canonicalization")
        root = Path(configured)
    else:
        root = android_home
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


class HistoricalBenchmarkError(RuntimeError):
    """A bounded historical-build failure with machine-readable diagnostics."""

    def __init__(self, message: str, *, report: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.report = dict(report or {})


def _historical_error(phase: str, message: str, **details: object) -> HistoricalBenchmarkError:
    report: dict[str, object] = {"phase": phase, "commit": HISTORICAL_COMMIT}
    report.update(details)
    return HistoricalBenchmarkError(message, report=report)


def _append_cleanup_failure(primary: BaseException, cleanup_error: BaseException) -> None:
    diagnostic = str(cleanup_error)
    if isinstance(primary, HistoricalBenchmarkError):
        primary.report.setdefault("cleanup_failures", []).append(diagnostic)
    if hasattr(primary, "add_note"):
        primary.add_note(f"historical cleanup failed: {diagnostic}")


def _strict_tar_text(field: bytes, label: str) -> str:
    first_nul = field.find(b"\0")
    if first_nul >= 0:
        if any(field[first_nul + 1:]):
            raise _historical_error("archive", f"archive {label} contains an embedded NUL alias")
        field = field[:first_nul]
    try:
        return field.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise _historical_error("archive", f"archive {label} is not UTF-8") from error


def _tar_number(field: bytes, label: str) -> int:
    if field and field[0] & 0x80:
        raise _historical_error("archive", f"archive {label} uses unsupported base-256 encoding")
    value = field.rstrip(b"\0 ").lstrip(b" ")
    if not value:
        return 0
    if any(byte not in b"01234567" for byte in value):
        raise _historical_error("archive", f"archive {label} is not octal")
    return int(value, 8)


def _validate_relative_path(name: str, *, archive: bool) -> tuple[str, ...]:
    label = "archive" if archive else "APK"
    encoded = name.encode("utf-8", errors="strict")
    if not name or name.startswith("/") or "\\" in name:
        raise _historical_error(label.lower(), f"unsafe {label} path {name!r}")
    components = name.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise _historical_error(label.lower(), f"unsafe {label} path {name!r}")
    if archive and len(encoded) > MAX_ARCHIVE_PATH_BYTES:
        raise _historical_error("archive", "archive path exceeds 512 UTF-8 bytes")
    if archive and len(components) > MAX_ARCHIVE_COMPONENTS:
        raise _historical_error("archive", "archive path exceeds 32 components")
    return tuple(components)


def _archive_path_allowed(name: str) -> bool:
    if name in {"build.gradle", "settings.gradle", "gradle.properties", "gradlew", "app", "gradle", "gradle/wrapper"}:
        return True
    return name.startswith("app/") or name.startswith("gradle/wrapper/")


def _parse_historical_archive(archive_bytes: bytes) -> list[dict[str, object]]:
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise _historical_error("archive", "historical archive exceeds 8 MiB")
    members: list[dict[str, object]] = []
    by_path: dict[str, str] = {}
    total_size = 0
    offset = 0
    saw_zero = False
    while offset < len(archive_bytes):
        if offset + 512 > len(archive_bytes):
            raise _historical_error("archive", "historical archive has a truncated header")
        header = archive_bytes[offset:offset + 512]
        offset += 512
        if header == b"\0" * 512:
            saw_zero = True
            if any(archive_bytes[offset:]):
                raise _historical_error("archive", "historical archive has data after its terminator")
            break
        if saw_zero:
            raise _historical_error("archive", "historical archive has a malformed terminator")
        if len(members) >= MAX_ARCHIVE_MEMBERS:
            raise _historical_error("archive", "historical archive exceeds 256 members")
        checksum = _tar_number(header[148:156], "checksum")
        calculated = sum(header[:148]) + (32 * 8) + sum(header[156:])
        if checksum != calculated:
            raise _historical_error("archive", "historical archive header checksum is invalid")
        type_flag = header[156:157]
        size = _tar_number(header[124:136], "size")
        padded = ((size + 511) // 512) * 512
        if offset + padded > len(archive_bytes):
            raise _historical_error("archive", "archive member is truncated")
        payload = archive_bytes[offset:offset + size]
        padding = archive_bytes[offset + size:offset + padded]
        offset += padded
        if not members:
            expected = f"comment={HISTORICAL_COMMIT}\n".encode("ascii")
            separator = payload.find(b" ")
            length_field = payload[:separator] if separator >= 0 else b""
            if (type_flag != b"g" or not length_field
                    or any(byte not in b"0123456789" for byte in length_field)
                    or length_field != str(len(payload)).encode("ascii")
                    or payload[separator + 1:] != expected or any(padding)):
                raise _historical_error(
                    "archive", "historical archive is missing its exact pinned PAX envelope"
                )
            members.append({
                "type": "global_pax",
                "size": size,
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
            continue
        name = _strict_tar_text(header[:100], "name")
        prefix = _strict_tar_text(header[345:500], "prefix")
        if not name:
            raise _historical_error("archive", "archive name field is empty")
        if type_flag in (b"\0", b"0"):
            kind = "file"
        elif type_flag == b"5":
            kind = "directory"
        else:
            raise _historical_error("archive", f"unsupported archive member type {type_flag!r}")
        if prefix:
            name = f"{prefix}/{name}"
        if name.endswith("/"):
            if kind != "directory":
                raise _historical_error("archive", "only archive directories may end in slash")
            name = name[:-1]
        _validate_relative_path(name, archive=True)
        if not _archive_path_allowed(name):
            raise _historical_error("archive", f"archive path is outside the allowlist: {name}")
        if name in by_path:
            raise _historical_error("archive", f"duplicate archive path: {name}")
        for prior, prior_type in by_path.items():
            if (prior_type == "file" and name.startswith(prior + "/")):
                raise _historical_error("archive", f"archive file/child collision: {prior}")
        if kind == "file" and any(prior.startswith(name + "/") for prior in by_path):
            raise _historical_error("archive", f"archive child/file collision: {name}")
        if kind == "directory" and size != 0:
            raise _historical_error("archive", f"archive directory has a payload: {name}")
        if size > MAX_ARCHIVE_FILE_BYTES:
            raise _historical_error("archive", "archive file exceeds 2 MiB")
        if kind == "file":
            total_size += size
            if total_size > MAX_ARCHIVE_BYTES:
                raise _historical_error("archive", "archive regular payload exceeds 8 MiB")
        by_path[name] = kind
        members.append({
            "path": name,
            "type": kind,
            "size": size,
            "sha256": hashlib.sha256(payload).hexdigest() if kind == "file" else None,
            "payload": payload,
        })
    if not saw_zero:
        raise _historical_error("archive", "historical archive has no terminator")
    if not members:
        raise _historical_error("archive", "historical archive is missing its PAX envelope")
    return members


def _open_child_directory(parent_descriptor: int, component: str, *, create: bool) -> int:
    if create:
        try:
            os.mkdir(component, 0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            pass
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(component, flags, dir_fd=parent_descriptor)
    details = os.fstat(descriptor)
    if not stat.S_ISDIR(details.st_mode):
        os.close(descriptor)
        raise _historical_error("archive", "archive parent is not a directory")
    os.fchmod(descriptor, 0o700)
    return descriptor


def _ensure_archive_parent(root_descriptor: int, components: tuple[str, ...]) -> int:
    current = os.dup(root_descriptor)
    try:
        for component in components:
            following = _open_child_directory(current, component, create=True)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


def _extract_historical_archive(archive_bytes: bytes, root: Path) -> list[dict[str, object]]:
    """Validate the complete raw tar before securely publishing any member."""
    members = _parse_historical_archive(archive_bytes)
    os.chmod(root, 0o700, follow_symlinks=False)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    root_descriptor = os.open(root, flags)
    try:
        for member in members:
            if member["type"] == "global_pax":
                continue
            path = str(member["path"])
            components = tuple(path.split("/"))
            if member["type"] == "directory":
                descriptor = _ensure_archive_parent(root_descriptor, components)
                os.close(descriptor)
                continue
            parent = _ensure_archive_parent(root_descriptor, components[:-1])
            descriptor = -1
            try:
                mode = 0o700 if path == "gradlew" else 0o600
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(components[-1], flags, mode, dir_fd=parent)
                os.fchmod(descriptor, mode)
                payload = memoryview(member["payload"])
                while payload:
                    written = os.write(descriptor, payload)
                    if written <= 0:
                        raise OSError("archive write made no progress")
                    payload = payload[written:]
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                os.close(parent)
    except BaseException as error:
        if isinstance(error, HistoricalBenchmarkError):
            raise
        raise _historical_error("archive", f"secure archive extraction failed: {error}") from error
    finally:
        os.close(root_descriptor)
    return [
        ({key: member[key] for key in ("type", "size", "sha256")}
         if member["type"] == "global_pax"
         else {key: member[key] for key in ("path", "type", "size", "sha256")})
        for member in members
    ]


def _worker_inspect_path(path: str, held_descriptor: int, sender) -> None:
    pathname_descriptor = -1
    result: dict[str, object] | None = None
    failure: str | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        pathname_descriptor = os.open(path, flags)
        held = os.fstat(held_descriptor)
        pathname = os.fstat(pathname_descriptor)
        for details in (held, pathname):
            if not stat.S_ISREG(details.st_mode):
                raise ValueError("APK is not a regular file")
            if details.st_size <= 0:
                raise ValueError("APK is empty")
            if details.st_size > MAX_APK_BYTES:
                raise ValueError("APK exceeds 128 MiB")

        def hash_to_eof(descriptor: int, label: str) -> tuple[int, str]:
            digest = hashlib.sha256()
            offset = 0
            while True:
                chunk = os.pread(
                    descriptor, min(1024 * 1024, MAX_APK_BYTES - offset + 1), offset
                )
                if not chunk:
                    return offset, digest.hexdigest()
                offset += len(chunk)
                if offset > MAX_APK_BYTES:
                    raise ValueError(f"{label} exceeds 128 MiB")
                digest.update(chunk)

        descriptor_size, descriptor_sha256 = hash_to_eof(
            held_descriptor, "APK descriptor"
        )
        path_size, path_sha256 = hash_to_eof(pathname_descriptor, "APK pathname")
        held_after = os.fstat(held_descriptor)
        pathname_after = os.fstat(pathname_descriptor)
        for before, after, read_size, label in (
            (held, held_after, descriptor_size, "APK descriptor"),
            (pathname, pathname_after, path_size, "APK pathname"),
        ):
            if (not stat.S_ISREG(after.st_mode)
                    or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
                    or after.st_size != before.st_size or read_size != after.st_size):
                raise ValueError(f"{label} changed while hashing")
        result = {
            "descriptor_identity": (held.st_dev, held.st_ino),
            "path_identity": (pathname.st_dev, pathname.st_ino),
            "descriptor_size": held.st_size,
            "path_size": pathname.st_size,
            "descriptor_sha256": descriptor_sha256,
            "path_sha256": path_sha256,
        }
    except BaseException as error:
        failure = f"{type(error).__name__}: {error}"
    if pathname_descriptor >= 0:
        try:
            os.close(pathname_descriptor)
        except BaseException as error:
            cleanup = f"descriptor cleanup failed: {type(error).__name__}: {error}"
            failure = f"{failure}; {cleanup}" if failure is not None else cleanup
    try:
        sender.send((failure is None, result if failure is None else failure))
    finally:
        sender.close()


def _worker_copy_path(source: str, destination: str, sender) -> None:
    source_descriptor = destination_descriptor = -1
    result: dict[str, object] | None = None
    failure: str | None = None
    try:
        read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        read_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        source_descriptor = os.open(source, read_flags)
        details = os.fstat(source_descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size <= 0:
            raise ValueError("historical APK is not a nonempty regular file")
        if details.st_size > MAX_APK_BYTES:
            raise ValueError("historical APK exceeds 128 MiB")
        write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        write_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        destination_descriptor = os.open(destination, write_flags, 0o600)
        os.fchmod(destination_descriptor, 0o600)
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_APK_BYTES:
                raise ValueError("historical APK grew beyond 128 MiB")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise OSError("snapshot write made no progress")
                view = view[written:]
        if total != details.st_size:
            raise ValueError("historical APK changed size while snapshotting")
        result = {"size": total, "sha256": digest.hexdigest()}
    except BaseException as error:
        failure = f"{type(error).__name__}: {error}"
    for descriptor in (destination_descriptor, source_descriptor):
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup = f"descriptor cleanup failed: {type(error).__name__}: {error}"
                failure = f"{failure}; {cleanup}" if failure is not None else cleanup
    try:
        sender.send((failure is None, result if failure is None else failure))
    finally:
        sender.close()


def _run_file_worker(target, arguments: tuple[object, ...], timeout: float,
                     *, phase: str) -> dict[str, object]:
    absolute_deadline = time.monotonic() + timeout
    cleanup_reserve = min(0.2, max(0.01, timeout * 0.2))
    work_deadline = absolute_deadline - cleanup_reserve
    context = multiprocessing.get_context("fork")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=target, args=(*arguments, sender), daemon=True)
    process.start()
    sender.close()
    try:
        work_remaining = max(0.0, work_deadline - time.monotonic())
        if not receiver.poll(work_remaining):
            process.kill()
            process.join(max(0.0, absolute_deadline - time.monotonic()))
            raise _historical_error(phase, f"{phase} file worker exceeded its deadline",
                                    worker_pid=process.pid, reaped=not process.is_alive())
        try:
            ok, result = receiver.recv()
        except EOFError as error:
            process.join(max(0.0, work_deadline - time.monotonic()))
            raise _historical_error(
                phase, f"{phase} file worker exited without a result",
                worker_pid=process.pid, worker_exitcode=process.exitcode,
            ) from error
        process.join(max(0.0, work_deadline - time.monotonic()))
        if process.is_alive():
            process.kill()
            process.join(max(0.0, absolute_deadline - time.monotonic()))
            raise _historical_error(
                phase, f"{phase} file worker did not exit after publishing a result",
                worker_pid=process.pid, reaped=not process.is_alive(),
            )
        if process.exitcode != 0:
            raise _historical_error(
                phase, f"{phase} file worker exited with status {process.exitcode}",
                worker_pid=process.pid, worker_exitcode=process.exitcode,
                worker_result=result,
            )
        if not ok:
            raise _historical_error(phase, f"{phase} file worker failed: {result}")
        return result
    finally:
        receiver.close()
        if process.is_alive():
            process.kill()
            process.join(max(0.0, absolute_deadline - time.monotonic()))


def _open_regular_nofollow(path: Path, *, phase: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise ValueError("not a regular file")
        return descriptor
    except BaseException as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise _historical_error(phase, f"cannot hold regular file {path}: {error}") from error


def _inspect_held_path(path: Path, descriptor: int, *, phase: str,
                       timeout: float | None = None) -> dict[str, object]:
    return _run_file_worker(_worker_inspect_path, (str(path), descriptor),
                            FILE_WORKER_TIMEOUT if timeout is None else timeout,
                            phase=phase)


@dataclass
class HistoricalBenchmarkApk:
    path: Path
    apk_sha256: str
    target_raw_sha256: str
    target_canonical_sha256: str
    archive_manifest: tuple[tuple[tuple[str, object], ...], ...] = ()
    archive_sha256: str = ""
    _descriptor: int = field(init=False, repr=False, compare=False)
    _snapshot_root: Path = field(init=False, repr=False, compare=False)
    _closed: bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self._snapshot_root = self.path.parent
        self._descriptor = _open_regular_nofollow(self.path, phase="hold-apk")
        try:
            inspected = _inspect_held_path(self.path, self._descriptor, phase="hold-apk")
            self._identity = inspected["descriptor_identity"]
            self._size = inspected["descriptor_size"]
            if inspected["descriptor_sha256"] != self.apk_sha256:
                raise _historical_error("hold-apk", "held APK SHA-256 does not match validation")
            self._require_inspection(inspected)
        except BaseException as error:
            try:
                os.close(self._descriptor)
            except OSError as cleanup_error:
                _append_cleanup_failure(error, cleanup_error)
            self._descriptor = -1
            raise

    def _require_inspection(self, inspected: dict[str, object]) -> None:
        if inspected["descriptor_identity"] != inspected["path_identity"]:
            raise _historical_error("verify-apk", "held APK pathname identity changed")
        if inspected["descriptor_identity"] != self._identity:
            raise _historical_error("verify-apk", "held APK descriptor identity changed")
        if inspected["descriptor_size"] != self._size or inspected["path_size"] != self._size:
            raise _historical_error("verify-apk", "held APK size changed")
        if (inspected["descriptor_sha256"] != self.apk_sha256
                or inspected["path_sha256"] != self.apk_sha256):
            raise _historical_error("verify-apk", "held APK SHA-256 changed")

    def verify_path(self) -> None:
        """Require the held fd and pathname to retain type, identity, size, and SHA."""
        if self._closed or self._descriptor < 0:
            raise _historical_error("verify-apk", "historical APK is closed")
        inspected = _inspect_held_path(
            self.path, self._descriptor, phase="verify-apk", timeout=FILE_WORKER_TIMEOUT
        )
        self._require_inspection(inspected)

    def close(self) -> None:
        """Close the held descriptor and remove the private snapshot tree once."""
        if self._closed:
            return
        self._closed = True
        failures: list[str] = []
        if self._descriptor >= 0:
            try:
                os.close(self._descriptor)
            except OSError as error:
                failures.append(f"descriptor close: {error}")
            self._descriptor = -1
        try:
            shutil.rmtree(self._snapshot_root)
        except FileNotFoundError:
            pass
        except OSError as error:
            failures.append(f"snapshot cleanup: {error}")
        if failures:
            raise _historical_error("close-apk", "historical APK cleanup failed",
                                    cleanup_failures=failures)


def _pinned_aapt2(android_home: Path) -> Path:
    tool = android_home / "build-tools" / BUILD_TOOLS_VERSION / "aapt2"
    try:
        details = tool.lstat()
    except OSError as error:
        raise _historical_error("validate-apk", f"pinned aapt2 is unavailable: {tool}") from error
    if not stat.S_ISREG(details.st_mode) or not os.access(tool, os.X_OK):
        raise _historical_error("validate-apk", f"pinned aapt2 is not executable: {tool}")
    return tool


def _validate_historical_apk(apk_path: Path, *, deadline: float,
                             android_home: Path) -> dict[str, object]:
    descriptor = _open_regular_nofollow(apk_path, phase="validate-apk")
    try:
        before = _inspect_held_path(
            apk_path, descriptor, phase="validate-apk",
            timeout=min(FILE_WORKER_TIMEOUT, _remaining(deadline)),
        )
        aapt2 = _pinned_aapt2(android_home)
        argv = [str(aapt2), "dump", "badging", str(apk_path)]
        try:
            badging = capture_bounded(
                argv, maximum_bytes=MAX_OBJCOPY_OUTPUT_BYTES,
                timeout=_remaining(deadline),
            )
        except BaseException as error:
            report = {"argv": argv}
            for name in ("returncode", "stdout", "stderr"):
                if hasattr(error, name):
                    value = getattr(error, name)
                    report[name] = (value.decode("utf-8", errors="replace")
                                    if isinstance(value, bytes) else value)
            raise _historical_error("aapt2", f"pinned aapt2 validation failed: {error}",
                                    command=report) from error
        after_aapt = _inspect_held_path(
            apk_path, descriptor, phase="validate-apk",
            timeout=min(FILE_WORKER_TIMEOUT, _remaining(deadline)),
        )
        if before != after_aapt:
            raise _historical_error("validate-apk", "APK changed while aapt2 consumed it")
        package_match = re.search(rb"(?:^|\n)package:\s+name='([^']+)'", badging)
        if package_match is None or package_match.group(1) != b"com.aprz.qbdiandroid":
            raise _historical_error("validate-apk", "historical APK has the wrong package")

        names: set[str] = set()
        total_uncompressed = 0
        target_info: zipfile.ZipInfo | None = None
        duplicate = os.dup(descriptor)
        try:
            with os.fdopen(duplicate, "rb") as held_file:
                duplicate = -1
                with zipfile.ZipFile(held_file) as archive:
                    infos = archive.infolist()
                    if len(infos) > MAX_ZIP_ENTRIES:
                        raise _historical_error("validate-apk", "APK exceeds 4096 entries")
                    for info in infos:
                        name = info.filename[:-1] if info.is_dir() else info.filename
                        _validate_relative_path(name, archive=False)
                        if name in names:
                            raise _historical_error("validate-apk", f"duplicate APK entry: {name}")
                        names.add(name)
                        unix_mode = (info.external_attr >> 16) & 0xFFFF
                        unix_type = stat.S_IFMT(unix_mode)
                        if unix_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                            raise _historical_error("validate-apk", f"unsafe APK entry type: {name}")
                        if info.file_size > MAX_APK_BYTES:
                            raise _historical_error("validate-apk", "APK entry exceeds 128 MiB")
                        total_uncompressed += info.file_size
                        if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
                            raise _historical_error("validate-apk", "APK exceeds 512 MiB uncompressed")
                        if name == _TARGET_ENTRY:
                            target_info = info
                        elif (name.startswith("lib/")
                              and name.endswith("/libdemo_target.so")):
                            raise _historical_error("validate-apk", "APK contains target in another ABI")
                    if target_info is None:
                        raise _historical_error("validate-apk", "APK is missing the arm64 target")
                    if target_info.file_size <= 0:
                        raise _historical_error("validate-apk", "APK target is empty")
                    if target_info.file_size > MAX_TARGET_BYTES:
                        raise _historical_error("validate-apk", "APK target exceeds 64 MiB")
                    raw_target = bytearray()
                    crc = 0
                    with archive.open(target_info) as target:
                        while True:
                            chunk = target.read(min(1024 * 1024,
                                                    MAX_TARGET_BYTES + 1 - len(raw_target)))
                            if not chunk:
                                break
                            raw_target.extend(chunk)
                            crc = zlib.crc32(chunk, crc)
                            if len(raw_target) > MAX_TARGET_BYTES:
                                raise _historical_error("validate-apk", "APK target exceeds 64 MiB")
                    if len(raw_target) != target_info.file_size or crc & 0xFFFFFFFF != target_info.CRC:
                        raise _historical_error("validate-apk", "APK target size or CRC is invalid")
        except HistoricalBenchmarkError:
            raise
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
            raise _historical_error("validate-apk", f"invalid historical APK ZIP: {error}") from error
        finally:
            if duplicate >= 0:
                os.close(duplicate)
        after_zip = _inspect_held_path(
            apk_path, descriptor, phase="validate-apk",
            timeout=min(FILE_WORKER_TIMEOUT, _remaining(deadline)),
        )
        if before != after_zip:
            raise _historical_error("validate-apk", "APK changed while ZIP metadata was consumed")
        raw = bytes(raw_target)
        canonical = canonical_elf_sha256(
            raw, deadline=deadline, android_home=android_home
        )
        if canonical != HISTORICAL_CANONICAL_TARGET_SHA256:
            raise _historical_error(
                "validate-apk", "historical target canonical SHA-256 does not match",
                target_canonical_sha256=canonical,
            )
        return {
            "apk_sha256": before["descriptor_sha256"],
            "target_raw_sha256": hashlib.sha256(raw).hexdigest(),
            "target_canonical_sha256": canonical,
            "apk_identity": before["descriptor_identity"],
            "apk_size": before["descriptor_size"],
        }
    finally:
        active_error = sys.exc_info()[1]
        try:
            os.close(descriptor)
        except OSError as cleanup_error:
            if active_error is None:
                raise _historical_error(
                    "validate-apk", "historical APK descriptor cleanup failed",
                    cleanup_failures=[str(cleanup_error)],
                ) from cleanup_error
            _append_cleanup_failure(active_error, cleanup_error)


def _open_held_directory(path: Path, *, phase: str) -> tuple[int, tuple[int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        held = os.fstat(descriptor)
        pathname = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISDIR(held.st_mode) or not stat.S_ISDIR(pathname.st_mode)
                or (held.st_dev, held.st_ino) != (pathname.st_dev, pathname.st_ino)):
            raise ValueError("directory identity changed")
        return descriptor, (held.st_dev, held.st_ino)
    except BaseException as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise _historical_error(phase, f"cannot hold directory {path}: {error}") from error


def _verify_held_directory(path: Path, descriptor: int,
                           identity: tuple[int, int], *, phase: str) -> None:
    try:
        held = os.fstat(descriptor)
        pathname = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISDIR(held.st_mode) or not stat.S_ISDIR(pathname.st_mode)
                or (held.st_dev, held.st_ino) != identity
                or (pathname.st_dev, pathname.st_ino) != identity):
            raise ValueError("directory identity changed")
    except BaseException as error:
        raise _historical_error(phase, f"held repository changed: {error}") from error


def build_historical_benchmark_apk(repository: Path, *, deadline: float) -> HistoricalBenchmarkApk:
    """Build, validate, snapshot, and hold the fixed historical benchmark APK."""
    repository = Path(repository)
    report: dict[str, object] = {"phase": "repository", "commit": HISTORICAL_COMMIT}
    repository_descriptor = -1
    build_root: Path | None = None
    snapshot_root: Path | None = None
    result: HistoricalBenchmarkApk | None = None
    cleanup_failures: list[str] = []
    try:
        repository_descriptor, repository_identity = _open_held_directory(
            repository, phase="repository"
        )

        def run(argv: list[str], *, maximum_bytes: int, timeout: float,
                cwd: Path | None = None) -> bytes:
            report["command"] = {"argv": list(argv)}
            try:
                output = capture_bounded(
                    argv, maximum_bytes=maximum_bytes, timeout=timeout, cwd=cwd
                ) if cwd is not None else capture_bounded(
                    argv, maximum_bytes=maximum_bytes, timeout=timeout
                )
            except BaseException as error:
                command_report = dict(report["command"])
                for name in ("returncode", "stdout", "stderr"):
                    if hasattr(error, name):
                        value = getattr(error, name)
                        command_report[name] = (value.decode("utf-8", errors="replace")
                                                if isinstance(value, bytes) else value)
                report["command"] = command_report
                raise
            _verify_held_directory(
                repository, repository_descriptor, repository_identity,
                phase=str(report["phase"]),
            )
            return output

        report["phase"] = "commit"
        run(
            ["git", "-C", str(repository), "cat-file", "-e",
             f"{HISTORICAL_COMMIT}^{{commit}}"],
            maximum_bytes=64 * 1024,
            timeout=_remaining(deadline),
        )
        report["phase"] = "archive"
        archive_bytes = run(
            ["git", "-C", str(repository), "archive", "--format=tar",
             HISTORICAL_COMMIT, "--", "app", "build.gradle", "settings.gradle",
             "gradle.properties", "gradlew", "gradle/wrapper"],
            maximum_bytes=MAX_ARCHIVE_BYTES,
            timeout=_remaining(deadline),
        )
        build_root = Path(tempfile.mkdtemp(prefix="qtrace-historical-build-"))
        os.chmod(build_root, 0o700)
        manifest = _extract_historical_archive(archive_bytes, build_root)
        report["manifest"] = manifest
        report["archive_sha256"] = hashlib.sha256(archive_bytes).hexdigest()

        report["phase"] = "gradle"
        run(
            ["./gradlew", ":app:assembleDebug", "--no-daemon", "--offline"],
            maximum_bytes=MAX_GRADLE_OUTPUT_BYTES,
            timeout=min(900.0, _remaining(deadline)),
            cwd=build_root,
        )
        apk_path = build_root / "app/build/outputs/apk/debug/app-debug.apk"
        configured = os.environ.get("ANDROID_HOME")
        if not configured:
            raise _historical_error("validate-apk", "ANDROID_HOME is required")
        report["phase"] = "validate-apk"
        validated = _validate_historical_apk(
            apk_path, deadline=deadline, android_home=Path(configured)
        )
        report.update(validated)

        report["phase"] = "snapshot-apk"
        snapshot_root = Path(tempfile.mkdtemp(prefix="qtrace-historical-apk-"))
        os.chmod(snapshot_root, 0o700)
        snapshot_path = snapshot_root / "historical-benchmark.apk"
        copied = _run_file_worker(
            _worker_copy_path, (str(apk_path), str(snapshot_path)),
            min(FILE_WORKER_TIMEOUT, _remaining(deadline)), phase="snapshot-apk",
        )
        if (copied["sha256"] != validated["apk_sha256"]
                or copied["size"] != validated["apk_size"]):
            raise _historical_error("snapshot-apk", "APK changed while snapshotting",
                                    validated=validated, copied=copied)
        result = HistoricalBenchmarkApk(
            snapshot_path,
            str(validated["apk_sha256"]),
            str(validated["target_raw_sha256"]),
            str(validated["target_canonical_sha256"]),
            archive_manifest=tuple(tuple(item.items()) for item in manifest),
            archive_sha256=str(report["archive_sha256"]),
        )
        result.verify_path()
        shutil.rmtree(build_root)
        build_root = None
        return result
    except BaseException as error:
        if isinstance(error, HistoricalBenchmarkError):
            merged = dict(report)
            merged.update(error.report)
            error.report = merged
            primary: HistoricalBenchmarkError = error
        else:
            primary = HistoricalBenchmarkError(
                f"historical benchmark build failed during {report['phase']}: {error}",
                report=dict(report),
            )
        if result is not None:
            try:
                result.close()
            except BaseException as cleanup_error:
                cleanup_failures.append(str(cleanup_error))
        raise primary from error
    finally:
        if repository_descriptor >= 0:
            try:
                os.close(repository_descriptor)
            except OSError as error:
                cleanup_failures.append(f"repository descriptor: {error}")
        for root in (build_root, snapshot_root if result is None else None):
            if root is not None:
                try:
                    shutil.rmtree(root)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    cleanup_failures.append(f"tree {root}: {error}")
        active = sys.exc_info()[1]
        if cleanup_failures:
            if active is None:
                if result is not None:
                    try:
                        result.close()
                    except BaseException as cleanup_error:
                        cleanup_failures.append(f"result cleanup: {cleanup_error}")
                raise HistoricalBenchmarkError(
                    "historical benchmark build cleanup failed",
                    report={**report, "cleanup_failures": cleanup_failures},
                )
            if isinstance(active, HistoricalBenchmarkError):
                active.report.setdefault("cleanup_failures", []).extend(cleanup_failures)
            if hasattr(active, "add_note"):
                for failure in cleanup_failures:
                    active.add_note(f"historical builder cleanup failed: {failure}")
