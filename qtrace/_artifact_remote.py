"""Bound device reads, stable pulled snapshots, and remote listing rules."""

from __future__ import annotations

import hashlib
import inspect
import math
import os
import re
from pathlib import Path
from typing import Any, Sequence

from qtrace._artifact_common import (PulledArtifact, PullMode, PullSelection,
                                     _MAX_ARTIFACT_BYTES, _SIDE_SUFFIXES,
                                     _STATUS_TRANSACTION_SUFFIXES, _TRACE_SUFFIXES,
                                     _UUID4, _error, _name, _package, _unlink_quiet)
from qtrace._artifact_publication import _open_output
from qtrace.device import BoundTargetDevice
from qtrace.errors import QtraceError


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


def _client_for(device: BoundTargetDevice, package: str, factory: Any | None) -> object:
    if factory is not None:
        if not callable(factory):
            raise _error("artifact.client_invalid", "artifact client factory is not callable")
        client = factory(device, package)
        if not hasattr(client, "list_names") or not (hasattr(client, "stream_file") or hasattr(client, "read_file")):
            raise _error("artifact.client_invalid", "artifact client lacks bounded capabilities")
        return client
    return _BoundDeviceClient(device, package)


class _BoundDeviceClient:
    """Adapter that retains the AdbDevice's already-bound run-as/root identity."""

    def __init__(self, device: BoundTargetDevice, package: str) -> None:
        self.device = device
        if device.package != package:
            raise _error(
                "artifact.binding_invalid",
                "bound device package does not match artifact package",
            )
        self.directory = device.trace_directory

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
                                       timeout=timeout, maximum_bytes=8192)
        try:
            value = int(raw.decode("ascii").split()[0])
        except (UnicodeDecodeError, ValueError, IndexError) as error:
            raise _error("artifact.size_invalid", "remote size is malformed") from error
        if value < 0:
            raise _error("artifact.size_invalid", "remote size is negative")
        return value

    def stream_file(self, name: str, output: Any, *, timeout: float) -> None:
        _name(name)
        self.device.stream_target_file(
            f"{self.directory}/{name}", output,
            timeout=timeout, maximum_bytes=_MAX_ARTIFACT_BYTES,
        )


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


def _status_transaction_name(name: str) -> str | None:
    for suffix in _STATUS_TRANSACTION_SUFFIXES:
        if name.endswith(suffix):
            return _status_name(name[:-len(suffix)] + ".status.json")
    return None


def _temporary_name(name: str) -> bool:
    return (name.startswith(".") or name.endswith((".tmp", ".partial", ".current", ".writer"))
            or re.search(r"\.tmp\.\d+\.\d+\Z", name) is not None
            or re.search(r"\.writing\.\d+\Z", name) is not None
            or ".qtrace-stage-" in name)


def _temporary_status_session(name: str) -> str | None:
    if not _temporary_name(name) or not name.startswith("session-"):
        return None
    remainder = name[len("session-"):]
    session_id = remainder[:36]
    return (session_id if _UUID4.fullmatch(session_id) is not None and
            remainder[36:].startswith(".status.json.") else None)


def _relevant_manual_temporaries(
    temporary_names: Sequence[str],
    selection: PullSelection,
    roots: Sequence[str],
    session_id: str | None,
) -> list[str]:
    if selection.mode is PullMode.ALL:
        return list(temporary_names)
    sessions = ({session_id} if session_id is not None else set())
    sessions.update(found.lower() for root in roots for found in re.findall(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        root, flags=re.IGNORECASE,
    ))
    return [name for name in temporary_names
            if _temporary_status_session(name) in sessions or
            any(name.startswith(root + ".") for root in roots)]


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
        if _status_transaction_name(name) is not None:
            continue
        if name.endswith(_STATUS_TRANSACTION_SUFFIXES):
            raise _error("artifact.status_invalid",
                         f"invalid native status transaction name: {name}")
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
