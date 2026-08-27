"""Bounded, durable publication for qtrace session reports."""

from __future__ import annotations

import dataclasses
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping


_MAX_REPORT_BYTES = 1_048_576


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


def _regular_or_missing(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise ValueError("report destination must be a regular non-symlink file")


def _safe_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    current = path
    while True:
        mode = current.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise ValueError("report destination directory must not be a symlink")
        if current == current.parent:
            return
        current = current.parent


class ReportWriter:
    def write_atomic(self, output: Path, report: SessionReport) -> None:
        output = Path(output)
        if output.name in {"", ".", ".."}:
            raise ValueError("report destination has no filename")
        _safe_directory(output.parent)
        _regular_or_missing(output)
        def normalize(value: object) -> object:
            if dataclasses.is_dataclass(value):
                return {field.name: normalize(getattr(value, field.name)) for field in dataclasses.fields(value)}
            if isinstance(value, Enum):
                return normalize(value.value)
            if isinstance(value, Path):
                return str(value)
            if isinstance(value, Mapping):
                return {str(key): normalize(member) for key, member in value.items()}
            if isinstance(value, (tuple, list)):
                return [normalize(member) for member in value]
            if value is None or type(value) in {str, int, bool}:
                return value
            return str(value)[:1024]
        encoded = json.dumps(normalize(report), sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
        if not encoded or len(encoded) > _MAX_REPORT_BYTES:
            raise ValueError("report exceeds the 1 MiB publication limit")
        descriptor = -1
        temporary: Path | None = None
        try:
            descriptor, name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
            temporary = Path(name)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = -1
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            _regular_or_missing(output)
            os.replace(temporary, output)
            temporary = None
            directory = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
