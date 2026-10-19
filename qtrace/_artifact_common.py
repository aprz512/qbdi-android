"""Shared artifact values, basename rules, and exhaustive descriptor cleanup."""

from __future__ import annotations

import os
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Sequence

from qtrace.errors import EXIT_PARTIAL, QtraceError


_UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")


_PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z")


_TRACE_SUFFIXES = (".trace.bin.lz4", ".trace.bin", ".trace.txt.lz4", ".trace.txt", ".flight.bin")


_SIDE_SUFFIXES = (".metrics", ".crash")


_MAX_NAME_BYTES = 255


_MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


_MAX_STATUS_BYTES = 64 * 1024


_STATUS_TRANSACTION_SUFFIXES = (
    ".status.json.backup.prepare",
    ".status.json.backup",
    ".status.json.restore",
    ".status.json.rollback",
    ".status.json.commit",
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
