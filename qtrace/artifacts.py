"""Bounded, ownership-aware qtrace artifact collection and publication."""

from __future__ import annotations

import hashlib
import ctypes
import dataclasses
import errno
import inspect
import json
import math
import os
import re
import shutil
import stat
import time
import unicodedata
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from qtrace.errors import EXIT_PARTIAL, QtraceError
from qtrace.report import ConditionalReplaceRecoveryError, conditional_replace_at
from qtrace.status import (NativeStatusValidationError, StrictJsonLoadError,
                           load_strict_json, validate_status_shape)

_UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z")
_TRACE_SUFFIXES = (".trace.bin.lz4", ".trace.bin", ".trace.txt.lz4", ".trace.txt", ".flight.bin")
_SIDE_SUFFIXES = (".metrics", ".crash")
_MAX_NAME_BYTES = 255
_MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
_MAX_STATUS_BYTES = 64 * 1024
_FORMAT4_COMPLETED_TERMINAL = re.compile(
    r"TRACE_END status=completed return_valid=1 return=0x[0-9a-fA-F]+ elapsed_ms=\d+ "
    r"instructions=\d+ encoded_bytes=\d+ compressed_bytes=\d+ cache_hits=\d+ "
    r"cache_misses=\d+ cache_collisions=\d+ buffer_swaps=\d+ producer_waits=\d+ "
    r"producer_wait_ns=\d+ effective_buffer_bytes=\d+\Z"
)
_FORMAT4_STOPPED_TERMINAL = re.compile(
    r"TRACE_END status=stopped reason=duration_elapsed return_valid=0 elapsed_ms=\d+ "
    r"instructions=\d+ encoded_bytes=\d+ compressed_bytes=\d+ cache_hits=\d+ "
    r"cache_misses=\d+ cache_collisions=\d+ buffer_swaps=\d+ producer_waits=\d+ "
    r"producer_wait_ns=\d+ effective_buffer_bytes=\d+\Z"
)
_LEGACY_OK_TERMINAL = re.compile(
    r"TRACE_END status=ok ret=0x[0-9a-fA-F]+ elapsed_ms=\d+ "
    r"(?:bytes=\d+|instructions=\d+ raw_bytes=\d+ cache_hit_rate=\d+\.\d{6} "
    r"buffer_swaps=\d+ producer_waits=\d+ producer_wait_ns=\d+)\Z"
)


@dataclass(frozen=True)
class PulledArtifact:
    remote_name: str
    local_path: Path
    sha256: str
    size: int


@dataclass(frozen=True)
class ArtifactResult:
    output_dir: Path
    files: tuple[Path, ...]
    errors: tuple[Mapping[str, str], ...]
    exit_code: int


def _close_descriptor(descriptor: int) -> None:
    if descriptor >= 0:
        os.close(descriptor)


def _unlink_if_present(directory: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=directory)
    except FileNotFoundError:
        pass


def _cleanup_exhaustively(actions: Sequence[tuple[str, Callable[[], None]]],
                          primary: BaseException | None = None) -> None:
    """Run every already-transferred cleanup action without masking a body failure."""
    failures: list[tuple[str, BaseException]] = []
    for label, action in actions:
        try:
            action()
        except BaseException as error:
            failures.append((label, error))
    if primary is not None:
        for label, error in failures:
            primary.add_note(f"artifact cleanup failed for {label}: {error}")
        return
    if failures:
        raise failures[0][1]


@dataclass
class _PublicationToken:
    """Opaque, fd-backed claim to one collector-created report inode."""
    session_id: str
    output_path: Path
    parent: int
    directory: int
    parent_identity: tuple[int, int]
    report_identity: tuple[int, int]

    def close(self) -> None:
        actions: list[tuple[str, Callable[[], None]]] = []
        for attribute in ("directory", "parent"):
            descriptor = getattr(self, attribute)
            setattr(self, attribute, -1)
            if descriptor >= 0:
                actions.append((f"publication token {attribute}",
                                lambda descriptor=descriptor: _close_descriptor(descriptor)))
        _cleanup_exhaustively(actions)

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    def visible_path(self, name: str) -> Path:
        try:
            current = os.stat(self.output_path, follow_symlinks=False)
        except OSError:
            current = None
        if current is None or (current.st_dev, current.st_ino) != self.parent_identity:
            raise _error("artifact.destination_replaced", "collector output identity changed before report merge")
        return self.output_path / name


def _collector_token(parent: int, session_id: str, output: _OutputDirectory,
                     expected_report_identity: tuple[int, int]) -> _PublicationToken:
    held_parent = os.dup(parent)
    directory = -1
    try:
        directory = os.open(session_id, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                            getattr(os, "O_NOFOLLOW", 0), dir_fd=held_parent)
        report = os.stat("report.json", dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(report.st_mode)
                or (report.st_dev, report.st_ino) != expected_report_identity):
            raise FileExistsError("collector report changed before token issuance")
        parent_info = os.fstat(held_parent)
        return _PublicationToken(session_id, output.path, held_parent, directory,
                                 (parent_info.st_dev, parent_info.st_ino),
                                 expected_report_identity)
    except BaseException as primary:
        held_directory, directory = directory, -1
        parent_to_close, held_parent = held_parent, -1
        actions: list[tuple[str, Callable[[], None]]] = []
        if held_directory >= 0:
            actions.append(("collector token directory", lambda: _close_descriptor(held_directory)))
        if parent_to_close >= 0:
            actions.append(("collector token parent", lambda: _close_descriptor(parent_to_close)))
        _cleanup_exhaustively(actions, primary)
        raise


def publish_collector_report(token: object, writer: Any, report: object) -> tuple[object, Path, bool]:
    """Conditionally replace only the fragment inode issued by this collector."""
    if not isinstance(token, _PublicationToken):
        raise ValueError("collector token is invalid")
    descriptor = -1
    primary: BaseException | None = None
    try:
        try:
            descriptor = os.open("report.json", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                                 dir_fd=token.directory)
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != token.report_identity:
                raise FileExistsError("collector report was replaced concurrently")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(64 * 1024, 1024 * 1024 + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > 1024 * 1024:
                    raise _error("artifact.report_too_large", "collector report exceeds size bound")
            fragment = json.loads(b"".join(chunks).decode("utf-8"))
            records = fragment.get("artifacts", []) if type(fragment) is dict else []
            errors = fragment.get("errors", []) if type(fragment) is dict else []
            merged = list(getattr(report, "artifacts"))
            for item in (*records, *errors):
                if isinstance(item, dict) and item not in merged:
                    merged.append(item)
            if merged:
                report = dataclasses.replace(report, artifacts=tuple(merged))
            if writer.write_atomic_at(token.directory, "report.json", report,
                                      expected_identity=token.report_identity):
                return report, token.visible_path(f"{token.session_id}/report.json"), True
            raise FileExistsError("collector report was replaced concurrently")
        except (ConditionalReplaceRecoveryError, FileExistsError) as concurrent:
            detail = "collector report changed concurrently"
            recovery_name = getattr(concurrent, "recovery_name", None)
            if type(recovery_name) is str and recovery_name:
                detail += f"; rollback recovery file is {recovery_name}"
            marker = {"code": "artifact.concurrent_report", "detail": detail}
            report = dataclasses.replace(report, artifacts=tuple((*getattr(report, "artifacts"), marker)))
            name = f"{token.session_id}.error.{uuid.uuid4()}.report.json"
            writer.write_atomic_at(token.parent, name, report, no_replace=True)
            return report, token.visible_path(name), False
    except BaseException as error:
        primary = error
        raise
    finally:
        held_descriptor, descriptor = descriptor, -1
        actions: list[tuple[str, Callable[[], None]]] = []
        if held_descriptor >= 0:
            actions.append(("collector report descriptor",
                            lambda: _close_descriptor(held_descriptor)))
        actions.append(("collector publication token", token.close))
        _cleanup_exhaustively(actions, primary)


@dataclass
class _OutputDirectory:
    """A held output-directory identity, not a path that can be swapped mid-pull."""
    path: Path
    descriptor: int
    device: int
    inode: int

    def assert_identity(self) -> None:
        try:
            current = os.stat(self.path, follow_symlinks=False)
        except OSError as error:
            raise _error("artifact.destination_replaced", "output directory is no longer available") from error
        if (not stat.S_ISDIR(current.st_mode)
                or (current.st_dev, current.st_ino) != (self.device, self.inode)):
            raise _error("artifact.destination_replaced", "output directory identity changed during pull")
    def result_path(self, child: str) -> Path:
        self.assert_identity()
        return self.path / child

    def close(self) -> None:
        descriptor, self.descriptor = self.descriptor, -1
        _cleanup_exhaustively([("output directory", lambda: _close_descriptor(descriptor))])


class PullMode(str, Enum):
    LATEST = "latest"
    NAME = "name"
    ALL = "all"


@dataclass(frozen=True)
class PullSelection:
    mode: PullMode = PullMode.LATEST
    name: str | None = None
    compressed_only: bool = False


def _error(code: str, detail: str, *, partial: bool = False) -> QtraceError:
    return QtraceError(code, "artifacts", detail, exit_code=EXIT_PARTIAL if partial else 1)


def _valid_name(value: object, *, trace: bool = False) -> bool:
    if type(value) is not str or not value or value in {".", ".."}:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if len(encoded) > _MAX_NAME_BYTES or "/" in value or "\\" in value:
        return False
    if any(unicodedata.category(ch).startswith("C") for ch in value):
        return False
    return (not trace) or value.endswith(_TRACE_SUFFIXES)


def validate_artifact_name(value: object, *, trace: bool = False) -> str:
    """Validate and return one device artifact basename for legacy callers."""
    if not _valid_name(value, trace=trace):
        raise _error("artifact.name_invalid", "artifact name is not a safe basename")
    return value  # type: ignore[return-value]


def _package(value: object) -> str:
    if type(value) is not str or _PACKAGE.fullmatch(value) is None:
        raise _error("artifact.package_invalid", "package name is invalid")
    return value


def _name(value: object, *, trace: bool = False) -> str:
    return validate_artifact_name(value, trace=trace)


def _unlink_quiet(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except BaseException:
        pass


def _call(method: Any, *args: Any, timeout: float | None = None, **kwargs: Any) -> Any:
    """Call an adapter once, selecting its timeout capability before invocation."""
    if timeout is None:
        return method(*args, **kwargs)
    try:
        parameters = inspect.signature(method).parameters.values()
        supports_timeout = any(parameter.name == "timeout" or
                               parameter.kind is parameter.VAR_KEYWORD
                               for parameter in parameters)
    except (TypeError, ValueError):
        supports_timeout = True
    if supports_timeout:
        return method(*args, timeout=timeout, **kwargs)
    return method(*args, **kwargs)


def _client_for(device: object, package: str, factory: Any | None) -> object:
    if factory is not None:
        if not callable(factory):
            raise _error("artifact.client_invalid", "artifact client factory is not callable")
        client = factory(device, package)
        if not hasattr(client, "list_names") or not (hasattr(client, "stream_file") or hasattr(client, "read_file")):
            raise _error("artifact.client_invalid", "artifact client lacks bounded capabilities")
        return client
    if hasattr(device, "artifact_client"):
        return device.artifact_client(package)
    if all(hasattr(device, name) for name in ("list_names", "read_file", "stream_file")):
        return device
    if hasattr(device, "target_shell"):
        return _BoundDeviceClient(device, package)
    raise _error("artifact.client_invalid", "device has no bound artifact client")


class _BoundDeviceClient:
    """Adapter that retains the AdbDevice's already-bound run-as/root identity."""

    def __init__(self, device: object, package: str) -> None:
        self.device = device
        self.directory = f"/data/data/{package}/files/qbdi-traces"

    def list_names(self, *, timeout: float) -> list[str]:
        raw = self.device.target_shell("ls", "-1t", self.directory,
                                       timeout=timeout, maximum_bytes=1024 * 1024)
        try:
            return raw.decode("utf-8").splitlines()
        except UnicodeDecodeError as error:
            raise _error("artifact.list_invalid", "artifact listing is not UTF-8") from error

    def read_file(self, name: str, *, timeout: float) -> bytes:
        _name(name)
        return self.device.target_shell("head", "-c", str(64 * 1024 + 1),
                                        f"{self.directory}/{name}", timeout=timeout,
                                        maximum_bytes=64 * 1024 + 1)

    def size(self, name: str, *, timeout: float) -> int:
        _name(name)
        raw = self.device.target_shell("wc", "-c", f"{self.directory}/{name}",
                                       timeout=timeout, maximum_bytes=128)
        try:
            value = int(raw.decode("ascii").split()[0])
        except (UnicodeDecodeError, ValueError, IndexError) as error:
            raise _error("artifact.size_invalid", "remote size is malformed") from error
        if value < 0:
            raise _error("artifact.size_invalid", "remote size is negative")
        return value

    def stream_file(self, name: str, output: Any, *, timeout: float) -> None:
        _name(name)
        data = self.device.target_shell("cat", f"{self.directory}/{name}", timeout=timeout,
                                        maximum_bytes=_MAX_ARTIFACT_BYTES + 1)
        if len(data) > _MAX_ARTIFACT_BYTES:
            raise _error("artifact.truncated", "artifact exceeds maximum size", partial=True)
        output.write(data)


def pull_named_artifacts(client: object, package: str, names: Sequence[str], destination: Path,
                         *, timeout: float) -> tuple[PulledArtifact, ...]:
    _package(package)
    if type(timeout) not in {int, float} or not math.isfinite(float(timeout)) or timeout <= 0:
        raise _error("artifact.timeout_invalid", "timeout must be finite and positive")
    if type(names) not in {list, tuple} or any(type(item) is not str for item in names):
        raise _error("artifact.name_invalid", "artifact names must be unique")
    if len(set(names)) != len(names):
        raise _error("artifact.name_invalid", "artifact names must be unique")
    output = _open_output(Path(destination))
    destination = Path(f"/proc/self/fd/{output.descriptor}")
    result: list[PulledArtifact] = []
    try:
      for raw_name in names:
        name = _name(raw_name)
        temporary = destination / ("." + name + ".qtrace-pull")
        final = destination / name
        published = False
        try:
            with temporary.open("xb") as stream:
                method = getattr(client, "stream_file", None)
                if method is not None:
                    _call(method, name, stream, timeout=float(timeout))
                else:
                    reader = getattr(client, "read_file", None)
                    if reader is None:
                        raise _error("artifact.client_invalid", "artifact client cannot read artifacts")
                    data = _call(reader, name, timeout=float(timeout))
                    if not isinstance(data, bytes) or len(data) > _MAX_ARTIFACT_BYTES:
                        raise _error("artifact.truncated", "artifact bytes exceed bound", partial=True)
                    stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if temporary.stat().st_size > _MAX_ARTIFACT_BYTES:
                raise _error("artifact.truncated", "artifact exceeds maximum size", partial=True)
            if final.exists() or final.is_symlink():
                raise _error("artifact.destination_exists", f"destination exists: {final}")
            os.link(temporary, final)
            published = True
            temporary.unlink()
            digest = hashlib.sha256()
            size = 0
            with final.open("rb") as input_file:
                for block in iter(lambda: input_file.read(1024 * 1024), b""):
                    size += len(block)
                    digest.update(block)
            output.assert_identity()
            result.append(PulledArtifact(name, Path(output.path / name), digest.hexdigest(), size))
        except QtraceError:
            _unlink_quiet(temporary)
            if published:
                _unlink_quiet(final)
            raise
        except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
            _unlink_quiet(temporary)
            if published:
                _unlink_quiet(final)
            try:
                output.assert_identity()
            except QtraceError:
                raise
            raise _error("artifact.pull_failed", str(error), partial=True) from error
        except BaseException:
            _unlink_quiet(temporary)
            if published:
                _unlink_quiet(final)
            raise
      output.assert_identity()
      return tuple(result)
    finally:
      output.close()


def _status_name(name: str) -> str | None:
    if not name.startswith("session-") or not name.endswith(".status.json"):
        return None
    value = name[len("session-"):-len(".status.json")]
    return value if _UUID4.fullmatch(value) else None


def _temporary_name(name: str) -> bool:
    return (name.startswith(".") or name.endswith((".tmp", ".partial", ".current", ".writer"))
            or re.search(r"\.tmp\.\d+\.\d+\Z", name) is not None
            or re.search(r"\.writing\.\d+\Z", name) is not None
            or ".qtrace-stage-" in name)


def _json_status(raw: bytes, session_id: str, package: str | None) -> Mapping[str, object]:
    try:
        value = load_strict_json(raw, maximum_bytes=_MAX_STATUS_BYTES)
    except StrictJsonLoadError as error:
        raise _error("artifact.status_invalid", error.detail) from error
    try:
        status = validate_status_shape(value)
    except NativeStatusValidationError as error:
        raise _error("artifact.status_invalid", error.detail) from error
    if status["sessionId"] != session_id or (package is not None and status["packageName"] != package):
        raise _error("artifact.status_identity", "native status identity does not match")
    for item in status["artifacts"]:
        try:
            _name(item, trace=True)
        except QtraceError as error:
            raise _error("artifact.status_invalid", "native status artifact basename is invalid") from error
        uuids = re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", item,
                           flags=re.IGNORECASE)
        if any(found != session_id for found in uuids):
            raise _error("artifact.status_identity", "foreign artifact UUID")
    return status


def _trace_roots(names: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    roots: list[str] = []
    for raw in names:
        name = _name(raw)
        if name in seen:
            raise _error("artifact.duplicate", f"duplicate artifact listing: {name}")
        seen.add(name)
        if name.endswith(_TRACE_SUFFIXES):
            roots.append(name)
        elif not name.endswith(_SIDE_SUFFIXES) and not name.endswith(".status.json"):
            raise _error("artifact.name_invalid", f"unexpected artifact suffix: {name}")
    return roots


def _validate_listing(names: Sequence[str]) -> list[str]:
    validated: list[str] = []
    for raw in names:
        name = _name(raw)
        if not (name.endswith(_TRACE_SUFFIXES) or name.endswith(_SIDE_SUFFIXES)
                or name.endswith(".status.json")):
            raise _error("artifact.name_invalid", f"unexpected artifact suffix: {name}")
        if name.endswith(".status.json") and _status_name(name) is None:
            raise _error("artifact.status_invalid", f"invalid native status name: {name}")
        validated.append(name)
    return validated


def _remote_size(client: object, name: str, timeout: float) -> int | None:
    for method_name in ("stat_file", "file_size", "size"):
        method = getattr(client, method_name, None)
        if method is None:
            continue
        value = _call(method, name, timeout=timeout)
        if type(value) is not int or value < 0:
            raise _error("artifact.size_invalid", "remote size is invalid")
        return value
    return None


def _text_complete(path: Path) -> bool:
    try:
        data = path.read_bytes()
    except OSError:
        return False
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return False
    if not lines:
        return False
    def terminal(line: str) -> bool:
        return any(pattern.fullmatch(line) is not None for pattern in (
            _FORMAT4_COMPLETED_TERMINAL, _FORMAT4_STOPPED_TERMINAL, _LEGACY_OK_TERMINAL,
        ))
    if any("TRACE_END" in line and not terminal(line) for line in lines):
        return False
    matches = [line for line in lines if terminal(line)]
    return len(matches) == 1 and lines[-1] == matches[0]


def _write_json(path: Path, value: object) -> None:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    if len(encoded) > 1024 * 1024:
        raise _error("artifact.report_too_large", "report exceeds size bound")
    with path.open("xb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())


def _refresh_payload(session_id: str, records: Sequence[Mapping[str, object]],
                     errors: Sequence[Mapping[str, str]]) -> bytes:
    payload = json.dumps({"schema": 1, "sessionId": session_id,
                          "artifacts": list(records), "errors": list(errors)},
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    if len(payload) > 1024 * 1024:
        raise _error("artifact.report_too_large", "report refresh exceeds size bound")
    return payload


def _rewrite_published_report(parent: int, session_id: str,
                              records: Sequence[Mapping[str, object]],
                              errors: Sequence[Mapping[str, str]], *,
                              expected_identity: tuple[int, int]) -> tuple[int, int]:
    """Refresh the committed diagnostic through the held directory descriptor."""
    payload = _refresh_payload(session_id, records, errors)
    directory = os.open(session_id, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                        getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
    descriptor = -1
    temporary = ".report-" + uuid.uuid4().hex + ".tmp"
    primary: BaseException | None = None
    try:
        write_primary: BaseException | None = None
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                                 0o600, dir_fd=directory)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("short report refresh write")
                offset += written
            os.fsync(descriptor)
        except BaseException as error:
            write_primary = error
            raise
        finally:
            held_descriptor, descriptor = descriptor, -1
            actions: list[tuple[str, Callable[[], None]]] = []
            if held_descriptor >= 0:
                actions.append(("report refresh descriptor",
                                lambda: _close_descriptor(held_descriptor)))
            _cleanup_exhaustively(actions, write_primary)
        replacement = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(replacement.st_mode):
            raise _error("artifact.report_invalid", "refresh replacement is not a regular file")
        replacement_identity = (replacement.st_dev, replacement.st_ino)
        owned_temporary = temporary
        temporary = ""
        if not conditional_replace_at(directory, owned_temporary, "report.json", expected_identity):
            raise FileExistsError("collector report changed during refresh")
        os.fsync(directory)
        return replacement_identity
    except BaseException as error:
        primary = error
        raise
    finally:
        owned_temporary, temporary = temporary, ""
        held_directory, directory = directory, -1
        actions = []
        if owned_temporary:
            actions.append(("report refresh temporary",
                            lambda: _unlink_if_present(held_directory, owned_temporary)))
        actions.append(("report refresh directory", lambda: _close_descriptor(held_directory)))
        _cleanup_exhaustively(actions, primary)


def _write_refresh_error_report_at(directory: int, session_id: str,
                                   records: Sequence[Mapping[str, object]],
                                   errors: Sequence[Mapping[str, str]], *,
                                   parent_sibling: bool) -> tuple[str, tuple[int, int]]:
    """Write one bounded, no-replace refresh diagnostic through an owned directory fd."""
    payload = _refresh_payload(session_id, records, errors)
    descriptor = -1
    name = ""
    committed = False
    primary: BaseException | None = None
    try:
        for _ in range(32):
            if parent_sibling:
                candidate = session_id + ".error." + str(uuid.uuid4()) + ".report.json"
            else:
                candidate = "report.error." + uuid.uuid4().hex + ".json"
            try:
                descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                     getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                                     0o600, dir_fd=directory)
            except FileExistsError:
                continue
            name = candidate
            break
        if descriptor < 0:
            raise _error("artifact.report_refresh", "unable to allocate refresh error report")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short refresh error report write")
            offset += written
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise _error("artifact.report_invalid", "refresh error report is unsafe")
        os.fsync(directory)
        committed = True
        return name, (info.st_dev, info.st_ino)
    except BaseException as error:
        primary = error
        raise
    finally:
        held_descriptor, descriptor = descriptor, -1
        actions = []
        if held_descriptor >= 0:
            actions.append(("refresh error report descriptor",
                            lambda: _close_descriptor(held_descriptor)))
        if name and not committed:
            actions.append(("refresh error report temporary",
                            lambda: _unlink_if_present(directory, name)))
        _cleanup_exhaustively(actions, primary)


def _write_refresh_error_report(parent: int, session_id: str,
                                records: Sequence[Mapping[str, object]],
                                errors: Sequence[Mapping[str, str]]) -> str:
    """Durably add a no-replace diagnostic beside a failed canonical refresh."""
    directory = os.open(session_id, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                        getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
    primary: BaseException | None = None
    try:
        name, _identity = _write_refresh_error_report_at(
            directory, session_id, records, errors, parent_sibling=False)
        return name
    except BaseException as error:
        primary = error
        raise
    finally:
        held_directory, directory = directory, -1
        _cleanup_exhaustively([("refresh error report directory",
                                lambda: _close_descriptor(held_directory))], primary)


def _write_parent_refresh_error_report(parent: int, session_id: str,
                                       records: Sequence[Mapping[str, object]],
                                       errors: Sequence[Mapping[str, str]]) -> tuple[str, tuple[int, int]]:
    """Persist a last-resort refresh diagnostic beside the committed session."""
    return _write_refresh_error_report_at(parent, session_id, records, errors,
                                          parent_sibling=True)


def _safe_output(path: Path) -> Path:
    output = _open_output(path)
    try:
        return output.path
    finally:
        output.close()


def _open_output(path: Path) -> _OutputDirectory:
    """Create/open output components once with openat no-follow semantics."""
    path = Path(path)
    internal_fd = path.is_absolute() and path.parts[:4] == ("/", "proc", "self", "fd")
    if internal_fd:
        try:
            source = int(path.parts[4])
        except (IndexError, ValueError) as error:
            raise _error("artifact.destination_invalid", "output descriptor path is invalid") from error
        parts = path.parts[5:]
    else:
        parts = path.parts[1:] if path.is_absolute() else path.parts
    if any(component in {"", ".", ".."} for component in parts):
        raise _error("artifact.destination_invalid", "output contains an unsafe component")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.dup(source) if internal_fd else os.open(
            path.anchor if path.is_absolute() else ".", flags)
        for component in parts:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise _error("artifact.destination_invalid", "output must be a directory")
        return _OutputDirectory(path, descriptor, info.st_dev, info.st_ino)
    except QtraceError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise _error("artifact.destination_invalid", "output contains a symlink or non-directory") from error


def _rename_noreplace(parent: int, stage_name: str, final_name: str) -> None:
    """Atomically publish a complete staging directory without replacing anything."""
    if os.name != "posix":
        raise _error("artifact.atomic_unsupported", "atomic no-replace publication is unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise _error("artifact.atomic_unsupported", "Linux renameat2 is unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(parent, stage_name.encode(), parent, final_name.encode(), 1)
    if result != 0:
        failure = ctypes.get_errno()
        if failure == errno.EEXIST:
            raise _error("artifact.destination_exists", "session destination already exists")
        raise OSError(failure, os.strerror(failure))


def _remove_tree_at(parent: int, name: str,
                    expected_identity: tuple[int, int] | None = None) -> None:
    """Remove a tree only while its parent entry names the opened directory inode."""
    try:
        root = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                       getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
    except FileNotFoundError:
        if expected_identity is not None:
            raise OSError("tree identity changed before opening")
        return
    except OSError as error:
        if expected_identity is not None:
            raise OSError("tree identity changed before opening") from error
        raise
    try:
        root_info = os.fstat(root)
        root_identity = (root_info.st_dev, root_info.st_ino)
        if (not stat.S_ISDIR(root_info.st_mode)
                or (expected_identity is not None and root_identity != expected_identity)):
            raise OSError("tree identity changed after opening")
        for child in os.listdir(root):
            info = os.stat(child, dir_fd=root, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                _remove_tree_at(root, child, expected_identity=(info.st_dev, info.st_ino))
            else:
                os.unlink(child, dir_fd=root)
    finally:
        os.close(root)
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino) != root_identity):
        raise OSError("tree identity changed before final rmdir")
    os.rmdir(name, dir_fd=parent)


def _restore_untrusted_quarantine(parent: int, quarantine: str, original_name: str,
                                  primary: BaseException) -> OSError:
    """Return a diagnostic after a no-replace attempt to restore unknown data."""
    try:
        _rename_noreplace(parent, quarantine, original_name)
    except BaseException as rollback:
        return OSError(
            f"{primary}; recovery entry {quarantine} retained after safe rollback failed: {rollback}")
    return OSError(
        f"{primary}; recovery entry {quarantine} was safely restored to {original_name}")


def _reclaim_parent_fallback_sibling(parent: int, name: str,
                                     expected_identity: tuple[int, int]) -> None:
    """Remove a parent fallback only after an atomic handoff to a private name."""
    quarantine = ""
    for _ in range(32):
        candidate = ".qtrace-reclaim-sibling-" + uuid.uuid4().hex
        try:
            _rename_noreplace(parent, name, candidate)
        except QtraceError as error:
            if error.code == "artifact.destination_exists":
                continue
            raise OSError(f"parent fallback identity changed before quarantine rename: {error}") from error
        except OSError as error:
            raise OSError(f"parent fallback identity changed before quarantine rename: {error}") from error
        quarantine = candidate
        break
    if not quarantine:
        raise OSError("parent fallback quarantine allocation exhausted")

    probe = -1
    try:
        probe = os.open(quarantine, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                        getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
        quarantined = os.fstat(probe)
    except BaseException as error:
        raise _restore_untrusted_quarantine(
            parent, quarantine, name,
            OSError(f"parent fallback identity changed after quarantine rename: {error}")) from error
    finally:
        _close_descriptor(probe)
    if (not stat.S_ISREG(quarantined.st_mode)
            or (quarantined.st_dev, quarantined.st_ino) != expected_identity):
        raise _restore_untrusted_quarantine(
            parent, quarantine, name,
            OSError("parent fallback identity changed after quarantine rename"))
    try:
        os.unlink(quarantine, dir_fd=parent)
        os.fsync(parent)
    except BaseException as error:
        raise _restore_untrusted_quarantine(parent, quarantine, name, OSError(str(error))) from error


def _note_parent_fallback_cleanup_failure(primary: BaseException,
                                          failure: BaseException) -> None:
    detail = f"parent fallback sibling cleanup failed: {failure}"
    if isinstance(primary, QtraceError):
        normalized = QtraceError(primary.code, primary.stage,
                                 f"{primary.detail}; {detail}", exit_code=primary.exit_code)
        primary.detail = normalized.detail
        primary.args = (primary.detail,)
    if hasattr(primary, "add_note"):
        primary.add_note(detail)


def _reclaim_committed_session(parent: int, directory: int, session_id: str) -> None:
    """Quarantine a held committed directory before recursively removing only its inode."""
    expected = os.fstat(directory)
    if not stat.S_ISDIR(expected.st_mode):
        raise OSError("committed session identity changed before reclaim")
    expected_identity = (expected.st_dev, expected.st_ino)
    quarantine = ""
    for _ in range(32):
        candidate = ".qtrace-reclaim-" + uuid.uuid4().hex
        try:
            _rename_noreplace(parent, session_id, candidate)
        except QtraceError as error:
            if error.code == "artifact.destination_exists":
                continue
            raise OSError(f"committed session identity changed before quarantine rename: {error}") from error
        except OSError as error:
            raise OSError(f"committed session identity changed before quarantine rename: {error}") from error
        quarantine = candidate
        break
    if not quarantine:
        raise OSError("committed session quarantine allocation exhausted")

    probe = -1
    try:
        probe = os.open(quarantine, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                        getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
        quarantined = os.fstat(probe)
    except BaseException as error:
        raise _restore_untrusted_quarantine(
            parent, quarantine, session_id,
            OSError(f"committed session identity changed after quarantine rename: {error}")) from error
    finally:
        _close_descriptor(probe)
    if (not stat.S_ISDIR(quarantined.st_mode)
            or (quarantined.st_dev, quarantined.st_ino) != expected_identity):
        raise _restore_untrusted_quarantine(
            parent, quarantine, session_id,
            OSError("committed session identity changed after quarantine rename"))
    try:
        _remove_tree_at(parent, quarantine, expected_identity=expected_identity)
    except BaseException as error:
        raise _restore_untrusted_quarantine(
            parent, quarantine, session_id,
            OSError(str(error))) from error
    os.fsync(parent)


def _note_committed_cleanup_failure(primary: BaseException, failure: BaseException) -> None:
    """Keep a destination replacement primary while making any orphan risk explicit."""
    detail = f"committed session cleanup failed: {failure}"
    if isinstance(primary, QtraceError):
        normalized = QtraceError(primary.code, primary.stage,
                                 f"{primary.detail}; {detail}", exit_code=primary.exit_code)
        primary.detail = normalized.detail
        primary.args = (primary.detail,)
    if hasattr(primary, "add_note"):
        primary.add_note(detail)


def _close_token_and_reclaim(parent: int, directory: int, session_id: str,
                             token: _PublicationToken | None,
                             primary: BaseException | None = None) -> None:
    """Close result capabilities, then reclaim the held committed directory if still ours."""
    failures: list[BaseException] = []
    if token is not None:
        try:
            token.close()
        except BaseException as error:
            failures.append(error)
    try:
        _reclaim_committed_session(parent, directory, session_id)
    except BaseException as error:
        failures.append(error)
    if primary is None:
        if failures:
            raise failures[0]
        return
    for failure in failures:
        _note_committed_cleanup_failure(primary, failure)


def _new_stage(output: _OutputDirectory) -> tuple[Path, int, int, str]:
    """Create stage and artifacts using one trusted output directory descriptor."""
    parent = os.dup(output.descriptor)
    try:
        for _ in range(32):
            name = ".qtrace-stage-" + uuid.uuid4().hex
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                continue
            try:
                stage_fd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                                   getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
            except BaseException:
                _remove_tree_at(parent, name)
                raise
            try:
                os.mkdir("artifacts", 0o700, dir_fd=stage_fd)
            except BaseException:
                os.close(stage_fd)
                _remove_tree_at(parent, name)
                raise
            # Keep every subsequent Path operation rooted at the held descriptor;
            # the proc fd remains valid even if an attacker swaps output names.
            return Path(f"/proc/self/fd/{stage_fd}"), parent, stage_fd, name
        raise _error("artifact.stage_failed", "unable to allocate a unique staging directory")
    except BaseException:
        os.close(parent)
        raise


class ArtifactProcessor:
    def __init__(self, *, client_factory: Any | None = None) -> None:
        self._client_factory = client_factory

    def _publish(self, stage: Path, output: _OutputDirectory, session_id: str, files: list[Path],
                 errors: list[Mapping[str, str]], records: list[Mapping[str, object]],
                 *, parent: int | None = None, stage_fd: int | None = None,
                 stage_name: str | None = None) -> Path:
        owned_parent = parent is None
        if parent is None:
            parent = os.dup(output.descriptor)
        if stage_name is None:
            stage_name = stage.name
        committed = False
        try:
            for directory_name in (".", "artifacts"):
                if stage_fd is not None and directory_name == ".":
                    descriptor = stage_fd
                elif stage_fd is not None:
                    descriptor = os.open(directory_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                                          getattr(os, "O_NOFOLLOW", 0), dir_fd=stage_fd)
                else:
                    descriptor = os.open(stage if directory_name == "." else stage / directory_name,
                                         os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                                         getattr(os, "O_NOFOLLOW", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    if not (directory_name == "." and stage_fd is not None):
                        os.close(descriptor)
            output.assert_identity()
            _rename_noreplace(parent, stage_name, session_id)
            committed = True
            final = output.result_path(session_id)
            descriptor = os.open(session_id, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                                 getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(parent)
        except BaseException as error:
            if committed and isinstance(error, QtraceError) and error.code == "artifact.destination_replaced":
                if stage_fd is not None:
                    _close_token_and_reclaim(parent, stage_fd, session_id, None, error)
                raise
            if committed:
                failure = {"name": "", "code": "artifact.commit_durable",
                           "detail": f"published session durability is uncertain: {error}"[:256]}
                errors.append(failure)
                records.append(failure)
                return output.result_path(session_id)
            raise
        finally:
            if owned_parent and parent is not None:
                os.close(parent)
        return final

    def _collect(self, device: object, package: str, session_id: str, names: list[str],
                 output: Path, timeout: float, status: Mapping[str, object] | None,
                 *, initial_errors: Sequence[Mapping[str, str]] = (), compressed_only: bool = False,
                 create_token: bool = False,
                 root_statuses: Mapping[str, Mapping[str, object]] | None = None) -> ArtifactResult:
        client = _client_for(device, package, self._client_factory)
        root_statuses = {} if root_statuses is None else root_statuses
        errors: list[Mapping[str, str]] = list(initial_errors)
        records: list[Mapping[str, object]] = []
        files: list[Path] = []
        validated_roots: set[str] = set()
        output_handle = _open_output(Path(output))
        try:
            stage_root, parent_fd, stage_fd, stage_name = _new_stage(output_handle)
        except BaseException as primary:
            held_output, output_handle = output_handle, None
            _cleanup_exhaustively([("collector output directory", held_output.close)], primary)
            raise
        stage_artifacts = stage_root / "artifacts"
        published = False
        token: _PublicationToken | None = None
        parent_fallback: tuple[str, tuple[int, int]] | None = None
        primary: BaseException | None = None

        def reclaim_published_resources(error: BaseException) -> None:
            nonlocal token, parent_fallback
            if not published:
                return
            held_token, token = token, None
            try:
                _close_token_and_reclaim(parent_fd, stage_fd, session_id, held_token, error)
            except BaseException as cleanup:
                _note_committed_cleanup_failure(error, cleanup)
            if parent_fallback is not None:
                held_fallback, parent_fallback = parent_fallback, None
                try:
                    _reclaim_parent_fallback_sibling(parent_fd, *held_fallback)
                except BaseException as cleanup:
                    _note_parent_fallback_cleanup_failure(error, cleanup)

        try:
            active = (status is not None and status.get("_native_present", True)
                      and status.get("state") not in {"sealed", "stop_incomplete"})
            if status is not None and status.get("state") == "stop_incomplete":
                errors.append({"name": "", "code": "artifact.incomplete",
                               "detail": "native stop did not seal all artifacts"})
            if active:
                errors.append({"code": "artifact.incomplete", "name": "", "detail": "native trace is still active"})
                pulled = ()
            else:
                pulled_list: list[PulledArtifact] = []
                for name in names:
                    try:
                        remote_before = _remote_size(client, name, timeout)
                        pulled_list.extend(pull_named_artifacts(client, package, [name], stage_artifacts,
                                                                 timeout=timeout))
                        remote_after = _remote_size(client, name, timeout)
                        if remote_before is not None and (remote_before != remote_after or
                                                          remote_before != pulled_list[-1].size):
                            raise _error("artifact.truncated", "remote artifact changed during pull", partial=True)
                    except QtraceError as error:
                        if error.code in {"artifact.pull_failed", "artifact.truncated", "artifact.size_invalid"}:
                            raise
                        failure = {"name": name, "code": error.code, "detail": error.detail}
                        errors.append(failure)
                        records.append(failure)
                pulled = tuple(pulled_list)
            for artifact in pulled:
                local = artifact.local_path
                remote_size = _remote_size(client, artifact.remote_name, timeout)
                artifact_status = root_statuses.get(next((root for root in root_statuses
                                                           if artifact.remote_name == root or artifact.remote_name.startswith(root + ".")), ""), status)
                record: dict[str, object] = {"remote_name": artifact.remote_name, "local_path": "artifacts/" + artifact.remote_name,
                    "source_size": remote_size, "destination_size": None, "sha256": artifact.sha256,
                    "decoder": None, "termination": None,
                    "stop_reason": artifact_status.get("reason") if artifact_status is not None else None,
                    "metrics_schema": None,
                    "producer_waits": None, "producer_wait_ns": None, "conversion_ms": None,
                    "native_stop_acknowledged": artifact_status.get("stopAcknowledged") if artifact_status is not None else None,
                    "host_observed_ack_ms": status.get("_hostAckMs") if status is not None else None}
                if local.name.endswith(".metrics") or local.name.endswith(".crash"):
                    if not local.exists():
                        continue
                    try:
                        if local.name.endswith(".metrics"):
                            from scripts.trace_metrics import parse_metrics
                            parse_metrics(local.read_bytes(), local.name.removesuffix(".metrics"))
                        else:
                            from scripts.pull_trace import parse_crash_marker
                            parse_crash_marker(local.read_bytes())
                    except Exception as error:
                        _unlink_quiet(local)
                        failure = {"name": artifact.remote_name, "code": "artifact.invalid",
                                   "detail": str(error)[:256]}
                        errors.append(failure)
                        records.append(failure)
                        continue
                    record["destination_size"] = local.stat().st_size
                    record["decoder"] = "sidecar"
                    records.append(record)
                    continue
                before_members = set(stage_artifacts.iterdir())
                try:
                    if compressed_only and not local.name.endswith((".trace.bin.lz4", ".trace.txt.lz4")):
                        raise ValueError("compressed-only selection contains an uncompressed artifact")
                    if local.name.endswith((".trace.bin", ".trace.bin.lz4")):
                        from scripts.trace_convert import convert_binary_file
                        from scripts.trace_metrics import parse_metrics
                        from scripts.pull_trace import parse_crash_marker
                        text = stage_artifacts / (local.name.removesuffix(".trace.bin.lz4").removesuffix(".trace.bin") + ".trace.txt")
                        lz4 = shutil.which("lz4") if local.name.endswith(".lz4") else None
                        crash_sidecar = local.with_name(local.name + ".crash")
                        crash_marked = False
                        if crash_sidecar.exists():
                            crash_marked = parse_crash_marker(crash_sidecar.read_bytes()) is not None
                        started = time.monotonic()
                        stats = convert_binary_file(local, text, lz4=lz4, crash_marked=crash_marked)
                        record.update(decoder="qtrb", termination=stats.termination,
                                     conversion_ms=round((time.monotonic() - started) * 1000, 3))
                        if not compressed_only:
                            files.append(text)
                        else:
                            text.unlink(missing_ok=True)
                        metrics = local.with_name(local.name + ".metrics")
                        if metrics.exists():
                            values = parse_metrics(metrics.read_bytes(), local.name)
                            record["metrics_schema"] = values.get("metrics_version", 1)
                            record["producer_waits"] = values.get("producer_waits")
                            record["producer_wait_ns"] = values.get("producer_wait_ns")
                    elif local.name.endswith(".flight.bin"):
                        from scripts.flight_convert import publish_flight_outputs, recovery_status
                        derived = publish_flight_outputs(local, stage_artifacts, force=False)
                        summary = json.loads(derived[-1].read_text(encoding="utf-8"))
                        if type(summary) is not dict or type(summary.get("complete")) is not bool:
                            raise ValueError("flight recovery summary is malformed")
                        record.update(decoder="flight", termination=summary.get("termination"),
                                     recovery_status=recovery_status(summary))
                        if not summary["complete"]:
                            failure = {"name": artifact.remote_name, "code": "artifact.incomplete",
                                       "detail": "flight recovery reports damage or incomplete committed data"}
                            errors.append(failure)
                            records.append(failure)
                        files.extend(derived)
                    elif local.name.endswith(".trace.txt.lz4"):
                        from scripts.lz4_frames import decode_lz4_file
                        lz4 = shutil.which("lz4")
                        if lz4 is None:
                            raise ValueError("host lz4 CLI is required for compressed text traces")
                        text = stage_artifacts / local.name.removesuffix(".lz4")
                        truncated = decode_lz4_file(local, text, lz4)
                        if truncated or not _text_complete(text):
                            raise ValueError("compressed text trace is incomplete")
                        record.update(decoder="lz4-text", termination="completed")
                        if not compressed_only:
                            files.append(text)
                        else:
                            text.unlink(missing_ok=True)
                    else:
                        if not _text_complete(local):
                            raise ValueError("legacy text trace has no terminal marker")
                        record["decoder"] = "legacy"
                    files.append(local)
                    record["destination_size"] = local.stat().st_size
                    records.append(record)
                    validated_roots.add(artifact.remote_name)
                except Exception as error:
                    if isinstance(error, QtraceError) and error.code in {
                            "artifact.pull_failed", "artifact.truncated", "artifact.size_invalid"}:
                        raise
                    for member in stage_artifacts.iterdir():
                        if member not in before_members:
                            _unlink_quiet(member)
                    _unlink_quiet(local)
                    for sidecar in (local.with_name(local.name + ".metrics"),
                                    local.with_name(local.name + ".crash")):
                        _unlink_quiet(sidecar)
                    files[:] = [path for path in files if path.exists()]
                    failure = {"name": artifact.remote_name, "code": "artifact.invalid", "detail": str(error)[:256]}
                    errors.append(failure)
                    records.append(failure)
            for artifact in pulled:
                if artifact.remote_name.endswith(_SIDE_SUFFIXES):
                    root = next((artifact.remote_name.removesuffix(suffix) for suffix in _SIDE_SUFFIXES
                                 if artifact.remote_name.endswith(suffix)), "")
                    if root in validated_roots and artifact.local_path.exists():
                        files.append(artifact.local_path)
            # Only successfully validated members are returned/published.  Sidecars
            # are recorded by their validated root path, never as recovery ghosts.
            recorded_paths = {record.get("local_path") for record in records if isinstance(record, Mapping)}
            for path in files:
                if not path.exists():
                    continue
                relative = "artifacts/" + path.name if path.parent == stage_artifacts else path.name
                if relative in recorded_paths:
                    continue
                data = path.read_bytes()
                records.append({"remote_name": path.name, "local_path": relative,
                                "source_size": None, "destination_size": len(data),
                                "sha256": hashlib.sha256(data).hexdigest(), "decoder": None,
                                "termination": None, "stop_reason": None, "metrics_schema": None,
                                "producer_waits": None, "producer_wait_ns": None,
                                "conversion_ms": None, "native_stop_acknowledged": None,
                                "host_observed_ack_ms": None})
            native_status = None
            host_context: Mapping[str, object] = {}
            if status is not None and status.get("_native_present", True):
                native_status = {key: value for key, value in status.items()
                                 if key not in {"_native_present", "snapshot", "effectiveConfig", "device", "hostAckMs", "_hostAckMs"}}
                host_context = {"snapshot": status.get("snapshot", []),
                                "effectiveConfig": status.get("effectiveConfig"),
                                "device": status.get("device"),
                                "hostAckMs": status.get("_hostAckMs")}
            elif status is not None:
                host_context = {"snapshot": status.get("snapshot", []),
                                "effectiveConfig": status.get("effectiveConfig"),
                                "device": status.get("device"),
                                "hostAckMs": status.get("_hostAckMs")}
            _write_json(stage_root / "session.json", {"schema": 1, "sessionId": session_id, "packageName": package,
                                                        "status": native_status, "host": host_context})
            effective = status.get("effectiveConfig") if status is not None else None
            if effective is None:
                effective = None
            _write_json(stage_root / "effective-config.json", effective)
            device_metadata = {
                "serial": getattr(device, "serial", None),
                "package": package,
                "access_mode": getattr(device, "access_mode", None),
                "root_strategy": getattr(device, "root_strategy", None),
                "target_strategy": getattr(device, "target_strategy", None),
                "package_uid": getattr(device, "package_uid", None),
            }
            if status is not None and isinstance(status.get("device"), Mapping):
                device_metadata.update(status["device"])
            _write_json(stage_root / "device.json", device_metadata)
            _write_json(stage_root / "report.json", {"schema": 1, "sessionId": session_id, "artifacts": records, "errors": errors})
            staged_report = os.stat("report.json", dir_fd=stage_fd, follow_symlinks=False)
            canonical_report_identity = (staged_report.st_dev, staged_report.st_ino)
            relative_files = tuple(path.relative_to(stage_root) for path in files)
            error_count = len(errors)
            final = self._publish(stage_root, output_handle, session_id, files, errors, records,
                                  parent=parent_fd, stage_fd=stage_fd, stage_name=stage_name)
            published = True
            refresh_failed = False
            refresh_error_path: Path | None = None
            if len(errors) != error_count:
                try:
                    canonical_report_identity = _rewrite_published_report(
                        parent_fd, session_id, records, errors,
                        expected_identity=canonical_report_identity)
                except BaseException as error:
                    recovery_name = getattr(error, "recovery_name", None)
                    detail = f"committed report refresh failed: {error}"
                    if type(recovery_name) is str:
                        detail += f"; recovery file={recovery_name}"
                    failure = {"name": "", "code": "artifact.report_refresh",
                               "detail": detail[:256]}
                    errors.append(failure)
                    records.append(failure)
                    refresh_failed = True
                    try:
                        refresh_error_path = final / _write_refresh_error_report(
                            parent_fd, session_id, records, errors)
                    except BaseException as persistence_error:
                        persistence_failure = {
                            "name": "", "code": "artifact.report_refresh_persist",
                            "detail": f"failed to persist refresh diagnostic: {persistence_error}"[:256],
                        }
                        errors.append(persistence_failure)
                        records.append(persistence_failure)
                        try:
                            parent_fallback = _write_parent_refresh_error_report(
                                parent_fd, session_id, records, errors)
                        except BaseException as sibling_error:
                            if not isinstance(error, Exception):
                                error.add_note(
                                    f"session refresh diagnostic failed: {persistence_error}")
                                error.add_note(
                                    f"parent refresh diagnostic failed: {sibling_error}")
                                raise
                            terminal = _error(
                                "artifact.report_refresh_persist",
                                "refresh failed: " + str(error) + "; session diagnostic failed: "
                                + str(persistence_error) + "; parent diagnostic failed: "
                                + str(sibling_error))
                            terminal.add_note(f"original report refresh failed: {error}")
                            terminal.add_note(
                                f"session refresh diagnostic failed: {persistence_error}")
                            raise terminal from sibling_error
                    if not isinstance(error, Exception):
                        raise
            if create_token and not refresh_failed:
                token = _collector_token(parent_fd, session_id, output_handle,
                                         canonical_report_identity)
            output_handle.assert_identity()
            result_files = tuple(final / path for path in relative_files)
            if refresh_error_path is not None:
                result_files += (refresh_error_path,)
            if parent_fallback is not None:
                result_files += (output_handle.result_path(parent_fallback[0]),)
            result = ArtifactResult(final, result_files, tuple(errors),
                                   EXIT_PARTIAL if errors else 0)
            object.__setattr__(result, "_records", tuple(records))
            if token is not None:
                returned_token, token = token, None
                object.__setattr__(result, "_publication_token", returned_token)
            parent_fallback = None
            return result
        except QtraceError as error:
            primary = error
            reclaim_published_resources(error)
            raise
        except Exception as error:
            primary = _error("artifact.collect_failed", str(error), partial=True)
            reclaim_published_resources(primary)
            raise primary from error
        except BaseException as error:
            primary = error
            reclaim_published_resources(error)
            raise
        finally:
            held_stage, stage_fd = stage_fd, -1
            held_parent, parent_fd = parent_fd, -1
            held_output, output_handle = output_handle, None
            actions = []
            if not published:
                actions.append(("collector staging tree",
                                lambda: _remove_tree_at(held_parent, stage_name)))
            if held_stage >= 0:
                actions.append(("collector stage descriptor", lambda: _close_descriptor(held_stage)))
            if held_parent >= 0:
                actions.append(("collector parent descriptor", lambda: _close_descriptor(held_parent)))
            if held_output is not None:
                actions.append(("collector output directory", held_output.close))
            if token is not None:
                actions.append(("collector unreturned token", token.close))
            _cleanup_exhaustively(actions, primary)

    def collect_session(self, device: object, package: str, session_id: str, status: Mapping[str, object] | None,
                        output: Path, timeout: float) -> ArtifactResult:
        _package(package)
        if type(session_id) is not str or not _UUID4.fullmatch(session_id):
            raise _error("artifact.session_invalid", "session ID is not lowercase UUIDv4")
        if status is None:
            status = {"_native_present": False, "artifacts": [], "snapshot": []}
        if type(status) is not dict:
            raise _error("artifact.status_missing", "session collection requires native status")
        native_present = status.get("_native_present", True)
        if type(native_present) is not bool:
            raise _error("artifact.status_invalid", "native presence marker is invalid")
        if native_present and (status.get("sessionId") != session_id or status.get("packageName") != package):
            raise _error("artifact.status_identity", "native status identity does not match")
        if native_present and status.get("state") not in {"sealed", "stop_incomplete"}:
            raise _error("artifact.incomplete", "native status is not terminal")
        declared = status.get("artifacts")
        if not native_present:
            declared = []
        if (type(declared) is not list or any(type(item) is not str for item in declared)
                or len(set(declared)) != len(declared)):
            raise _error("artifact.status_invalid", "native status has no artifact list")
        client = _client_for(device, package, self._client_factory)
        raw_listing = list(_call(getattr(client, "list_names"), timeout=timeout))
        if any(type(item) is not str for item in raw_listing) or len(set(raw_listing)) != len(raw_listing):
            raise _error("artifact.duplicate", "device listing contains duplicate or invalid names")
        temporary_names = [_name(item) for item in raw_listing if _temporary_name(_name(item))]
        listing = _validate_listing([_name(item) for item in raw_listing if not _temporary_name(_name(item))])
        available = set(listing)
        snapshot = status.get("snapshot", ())
        if type(snapshot) not in {list, tuple} or any(type(item) is not str for item in snapshot):
            raise _error("artifact.snapshot_invalid", "snapshot ownership context is invalid")
        snapshot_set = set(snapshot)
        selected: list[str] = []
        initial_errors: list[Mapping[str, str]] = []
        initial_errors.extend({"name": name, "code": "artifact.incomplete",
                               "detail": "temporary/current-writer artifact was not eligible for pull"}
                              for name in temporary_names)
        if not native_present:
            initial_errors.append({"name": "", "code": "artifact.status_missing",
                                   "detail": "native status unavailable; recovered listing is partial"})
            declared = [name for name in listing if name.endswith(_TRACE_SUFFIXES)
                        and name not in snapshot_set]
        names = [_name(name, trace=True) for name in declared]
        for name in names:
            if name in snapshot_set:
                initial_errors.append({"name": name, "code": "artifact.ownership", "detail": "artifact predates this session"})
                continue
            if name not in available:
                initial_errors.append({"name": name, "code": "artifact.missing", "detail": "declared artifact is absent"})
                continue
            selected.append(name)
            for side in (name + ".metrics", name + ".crash"):
                if side in available and side not in snapshot_set:
                    selected.append(side)
        return self._collect(device, package, session_id, selected, output, timeout, status,
                             initial_errors=initial_errors, create_token=True)

    def pull_manual(self, device: object, package: str, selection: PullSelection, output: Path,
                    timeout: float) -> ArtifactResult:
        _package(package)
        if type(selection) is not PullSelection or type(selection.mode) is not PullMode:
            raise _error("artifact.selection_invalid", "selection is invalid")
        if type(selection.compressed_only) is not bool:
            raise _error("artifact.selection_invalid", "compressed_only must be boolean")
        client = _client_for(device, package, self._client_factory)
        listing = list(_call(getattr(client, "list_names"), timeout=timeout))
        if any(type(item) is not str for item in listing):
            raise _error("artifact.list_invalid", "device listing contains a non-string name")
        if len(set(listing)) != len(listing):
            raise _error("artifact.duplicate", "device listing contains duplicate names")
        temporary_names = [_name(item) for item in listing if _temporary_name(_name(item))]
        listing = _validate_listing([_name(item) for item in listing if not _temporary_name(_name(item))])
        initial_errors: list[Mapping[str, str]] = [
            {"name": name, "code": "artifact.incomplete",
             "detail": "temporary/current-writer artifact was not eligible for pull"}
            for name in temporary_names
        ]
        status: Mapping[str, object] | None = None
        manual_root_statuses: Mapping[str, Mapping[str, object]] = {}
        session_id: str | None = None
        if selection.mode is PullMode.LATEST:
            status_candidates = [item for item in listing if _status_name(item) is not None]
            for candidate in listing:
                sid = _status_name(candidate)
                if sid is None:
                    continue
                try:
                    candidate_status = _json_status(
                        _call(getattr(client, "read_file"), candidate, timeout=timeout), sid, None)
                except QtraceError:
                    continue
                except (OSError, RuntimeError, TimeoutError, TypeError) as error:
                    raise _error("artifact.pull_failed", str(error), partial=True) from error
                if candidate_status.get("packageName") != package:
                    continue
                status = candidate_status
                session_id = sid
                break
            if status is not None:
                roots = [name for name in status["artifacts"] if _valid_name(name, trace=True)]
            else:
                raise _error("artifact.status_missing", "latest requires a valid native status")
        elif selection.mode is PullMode.NAME:
            if selection.name is None:
                raise _error("artifact.selection_invalid", "name mode requires a name")
            root = _name(selection.name, trace=True)
            if root not in listing:
                raise _error("artifact.not_found", f"remote trace does not exist: {root}")
            if selection.compressed_only and not root.endswith(".lz4"):
                raise _error("artifact.selection_invalid", "compressed-only rejects uncompressed artifact")
            roots = [root]
        else:
            if selection.name is not None:
                raise _error("artifact.selection_invalid", "all mode does not accept a name")
            roots = _trace_roots(listing)
        roots = [name for name in roots if name in listing]
        if selection.compressed_only:
            roots = [name for name in roots if name.endswith(".lz4")]
        if not roots:
            raise _error("artifact.not_found", "no eligible trace artifacts were found")
        # A UUID-bearing manual artifact is session-owned evidence.  Require the
        # corresponding strict native status and its explicit declaration before
        # allowing NAME/ALL to pull it.
        uuid_values = {found.lower() for root in roots
                       for found in re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", root,
                                               flags=re.IGNORECASE)}
        if uuid_values:
            if selection.mode is PullMode.ALL and len(uuid_values) > 1:
                root_statuses: dict[str, Mapping[str, object]] = {}
                for candidate_id in uuid_values:
                    candidate_name = f"session-{candidate_id}.status.json"
                    if candidate_name not in listing:
                        raise _error("artifact.status_missing", "UUID-bearing artifact has no matching native status")
                    try:
                        candidate_status = _json_status(_call(getattr(client, "read_file"), candidate_name,
                                                               timeout=timeout), candidate_id, package)
                    except QtraceError as error:
                        raise _error("artifact.status_missing", "matching native status is invalid") from error
                    owned = [root for root in roots if candidate_id in root.lower()]
                    if any(root not in candidate_status["artifacts"] for root in owned):
                        raise _error("artifact.ownership", "native status does not declare UUID-bearing artifact")
                    root_statuses.update({root: candidate_status for root in owned})
                eligible: list[str] = []
                for root in roots:
                    if root not in root_statuses:
                        eligible.append(root)
                        continue
                    candidate_status = root_statuses[root]
                    state = candidate_status["state"]
                    if state == "sealed":
                        eligible.append(root)
                    else:
                        initial_errors.append({"name": root, "code": "artifact.incomplete",
                                               "detail": f"native session is {state}; artifact is not sealed"})
                roots = eligible
                manual_root_statuses = {root: root_statuses[root] for root in roots if root in root_statuses}
                # Multiple independently proven roots share a generated manual pull session.
                session_id = None
            elif len(uuid_values) != 1:
                raise _error("artifact.status_missing", "UUID-bearing artifacts belong to multiple sessions")
            else:
                candidate_id = next(iter(uuid_values))
                candidate_name = f"session-{candidate_id}.status.json"
                if candidate_name not in listing:
                    raise _error("artifact.status_missing", "UUID-bearing artifact has no matching native status")
                try:
                    candidate_status = _json_status(_call(getattr(client, "read_file"), candidate_name,
                                                           timeout=timeout), candidate_id, package)
                except QtraceError as error:
                    raise _error("artifact.status_missing", "matching native status is invalid") from error
                owned = [root for root in roots if candidate_id in root.lower()]
                all_owned = len(owned) == len(roots)
                if any(root not in candidate_status["artifacts"] for root in owned):
                    raise _error("artifact.ownership", "native status does not declare UUID-bearing artifact")
                if selection.mode is PullMode.ALL and candidate_status["state"] != "sealed":
                    roots = [root for root in roots if root not in owned]
                    initial_errors.extend({"name": root, "code": "artifact.incomplete",
                                           "detail": f"native session is {candidate_status['state']}; artifact is not sealed"}
                                          for root in owned)
                if all_owned:
                    status, session_id = candidate_status, candidate_id
                elif selection.mode is PullMode.ALL:
                    manual_root_statuses = {root: candidate_status for root in owned}
        if session_id is None:
            session_id = str(uuid.uuid4())
        selected = list(roots)
        for root in roots:
            for side in (root + ".metrics", root + ".crash"):
                if side in listing:
                    selected.append(side)
        return self._collect(device, package, session_id, selected, Path(output), timeout, status,
                             initial_errors=initial_errors,
                             compressed_only=selection.compressed_only, root_statuses=manual_root_statuses)
