#!/usr/bin/env python3
"""Render and transactionally publish recovered flight-recorder outputs."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from scripts.flight_trace import FlightEvent, FlightRecovery, FlightTraceError, recover_flight


def _stem(source: Path) -> str:
    if not source.name.endswith(".flight.bin"):
        raise FlightTraceError("flight input must end in .flight.bin")
    value = source.name.removesuffix(".flight.bin")
    if not value:
        raise FlightTraceError("flight input has an empty basename")
    return value


def _format_value(value: object) -> str:
    if isinstance(value, int):
        return f"0x{value:x}"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _render_event(event: FlightEvent) -> str:
    suffix = " ".join(
        f"{key}={_format_value(value)}" for key, value in sorted(event.data.items())
    )
    line = f"EVENT seq={event.global_seq} tid={event.tid} kind={event.kind}"
    return line + (" " + suffix if suffix else "")


def _render(recovery: FlightRecovery, events: tuple[FlightEvent, ...], *,
            tid: int | None) -> str:
    identity = recovery.summary
    scope = "merged" if tid is None else f"tid-{tid}"
    lines = [
        "FLIGHT_BEGIN "
        f"format=1 scope={scope} run_id={identity['run_id']} pid={identity['pid']} "
        f"module_generation={identity['module_generation']} "
        f"target={json.dumps(identity['target_module'], ensure_ascii=False)}"
    ]
    lines.extend(_render_event(event) for event in events)
    lines.append(
        f"FLIGHT_END complete={str(bool(identity['complete'])).lower()} "
        f"events={len(events)}"
    )
    return "\n".join(lines) + "\n"


def _temporary(directory: Path, suffix: str) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=".flight-convert-", suffix=suffix, dir=directory)
    os.close(descriptor)
    return Path(name)


def _write_temporary(directory: Path, suffix: str, data: str) -> Path:
    temporary = _temporary(directory, suffix)
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        return temporary
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _path_exists(path: Path) -> bool:
    return os.path.lexists(path)


def _cleanup_context(failures: list[str], artifacts: list[Path]) -> str:
    parts = []
    if failures:
        parts.append("rollback cleanup failures: " + "; ".join(failures))
    if artifacts:
        unique = dict.fromkeys(str(path) for path in artifacts)
        parts.append("recovery artifacts preserved: " + ", ".join(unique))
    return "; " + "; ".join(parts) if parts else ""


def _record_cleanup_failure(path: Path, error: BaseException, failures: list[str],
                            artifacts: list[Path]) -> None:
    failures.append(f"{path}: {type(error).__name__}: {error}")
    artifacts.append(path)


def _annotate(error: BaseException, context: str) -> None:
    if context:
        error.add_note(context.removeprefix("; "))


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_no_replace(pairs: list[tuple[Path, Path]]) -> None:
    for _, destination in pairs:
        if _path_exists(destination):
            raise FileExistsError(f"flight output already exists: {destination.name}")
    attempted: list[tuple[Path, tuple[int, int]]] = []
    try:
        for temporary, destination in pairs:
            identity = temporary.stat()
            attempted.append((destination, (identity.st_dev, identity.st_ino)))
            os.link(temporary, destination)
        if pairs:
            _fsync_directory(pairs[0][1].parent)
    except BaseException as error:
        failures: list[str] = []
        artifacts: list[Path] = []
        for destination, identity in reversed(attempted):
            try:
                current = destination.lstat()
                if (current.st_dev, current.st_ino) == identity:
                    destination.unlink()
            except FileNotFoundError:
                pass
            except BaseException as cleanup_error:
                _record_cleanup_failure(destination, cleanup_error,
                                        failures, artifacts)
        if pairs:
            try:
                _fsync_directory(pairs[0][1].parent)
            except BaseException as cleanup_error:
                failures.append(
                    f"{pairs[0][1].parent}: {type(cleanup_error).__name__}: {cleanup_error}"
                )
        context = _cleanup_context(failures, artifacts)
        if isinstance(error, FileExistsError):
            _annotate(error, context)
            raise
        if isinstance(error, OSError):
            raise FlightTraceError(
                f"flight output publication failure: {error}{context}"
            ) from error
        _annotate(error, context)
        raise


def _backup(destination: Path) -> Path | None:
    if not _path_exists(destination):
        return None
    backup = _temporary(destination.parent, ".backup")
    try:
        backup.unlink()
        os.link(destination, backup, follow_symlinks=False)
    except BaseException as error:
        try:
            backup.unlink(missing_ok=True)
        except BaseException as cleanup_error:
            _annotate(error, _cleanup_context(
                [f"{backup}: {type(cleanup_error).__name__}: {cleanup_error}"],
                [backup],
            ))
        raise
    return backup


def _publish_force(pairs: list[tuple[Path, Path]]) -> None:
    backups: dict[Path, Path | None] = {}
    try:
        for _, destination in pairs:
            backups[destination] = _backup(destination)
    except BaseException as error:
        failures: list[str] = []
        artifacts: list[Path] = []
        for backup in backups.values():
            if backup is not None and _path_exists(backup):
                try:
                    backup.unlink()
                except BaseException as cleanup_error:
                    _record_cleanup_failure(backup, cleanup_error, failures, artifacts)
        if pairs:
            try:
                _fsync_directory(pairs[0][1].parent)
            except BaseException as cleanup_error:
                failures.append(
                    f"{pairs[0][1].parent}: {type(cleanup_error).__name__}: {cleanup_error}"
                )
        context = _cleanup_context(failures, artifacts)
        if isinstance(error, OSError):
            raise FlightTraceError(f"flight output backup failure: {error}{context}") from error
        _annotate(error, context)
        raise

    attempted: list[tuple[Path, tuple[int, int]]] = []
    try:
        for temporary, destination in pairs:
            identity = temporary.stat()
            attempted.append((destination, (identity.st_dev, identity.st_ino)))
            os.replace(temporary, destination)
        if pairs:
            _fsync_directory(pairs[0][1].parent)
    except BaseException as error:
        failures = []
        artifacts = []
        failed_restores: set[Path] = set()
        for destination, identity in reversed(attempted):
            backup = backups[destination]
            if backup is not None:
                try:
                    backup_state = backup.lstat()
                    backup_identity = (backup_state.st_dev, backup_state.st_ino)
                    try:
                        current = destination.lstat()
                        current_identity = (current.st_dev, current.st_ino)
                    except FileNotFoundError:
                        current_identity = None
                    if current_identity == identity or current_identity is None:
                        os.replace(backup, destination)
                        backups[destination] = None
                    elif current_identity != backup_identity:
                        failures.append(
                            f"{destination}: destination changed during rollback"
                        )
                        artifacts.append(backup)
                        failed_restores.add(backup)
                except BaseException as cleanup_error:
                    _record_cleanup_failure(backup, cleanup_error, failures, artifacts)
                    failed_restores.add(backup)
            else:
                try:
                    current = destination.lstat()
                    if (current.st_dev, current.st_ino) == identity:
                        destination.unlink()
                except FileNotFoundError:
                    pass
                except BaseException as cleanup_error:
                    _record_cleanup_failure(destination, cleanup_error,
                                            failures, artifacts)
        for destination, backup in backups.items():
            if (backup is not None and backup not in failed_restores and
                    _path_exists(backup)):
                try:
                    backup.unlink()
                    backups[destination] = None
                except BaseException as cleanup_error:
                    _record_cleanup_failure(backup, cleanup_error, failures, artifacts)
        if pairs:
            try:
                _fsync_directory(pairs[0][1].parent)
            except BaseException as cleanup_error:
                failures.append(
                    f"{pairs[0][1].parent}: {type(cleanup_error).__name__}: {cleanup_error}"
                )
        context = _cleanup_context(failures, artifacts)
        if isinstance(error, OSError):
            raise FlightTraceError(
                f"flight output publication failure: {error}{context}"
            ) from error
        _annotate(error, context)
        raise
    failures = []
    artifacts = []
    removed_backup = False
    for backup in backups.values():
        if backup is not None and _path_exists(backup):
            try:
                backup.unlink()
                removed_backup = True
            except BaseException as cleanup_error:
                _record_cleanup_failure(backup, cleanup_error, failures, artifacts)
    if pairs and removed_backup:
        try:
            _fsync_directory(pairs[0][1].parent)
        except BaseException as cleanup_error:
            failures.append(
                f"{pairs[0][1].parent}: {type(cleanup_error).__name__}: {cleanup_error}"
            )
    context = _cleanup_context(failures, artifacts)
    if context:
        raise FlightTraceError(f"flight output backup cleanup failure{context}")


def publish_flight_outputs(source: Path, output_dir: Path,
                           force: bool) -> tuple[Path, ...]:
    """Recover once, then publish merged, per-TID, and summary files as one set."""
    basename = _stem(source)
    try:
        with source.open("rb") as binary:
            recovery = recover_flight(binary)
    except FlightTraceError:
        raise
    except FileNotFoundError as error:
        raise FlightTraceError(f"flight artifact does not exist: {source}") from error
    except OSError as error:
        raise FlightTraceError(f"cannot read flight artifact {source}: {error}") from error

    destinations = [output_dir / f"{basename}.merged.trace.txt"]
    destinations.extend(
        output_dir / f"{basename}.tid-{tid}.trace.txt" for tid in sorted(recovery.threads)
    )
    destinations.append(output_dir / f"{basename}.flight.json")
    if not force:
        existing = next((path for path in destinations if _path_exists(path)), None)
        if existing is not None:
            raise FileExistsError(f"flight output already exists: {existing.name}")

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise FlightTraceError(f"cannot create flight output directory: {error}") from error
    if not output_dir.is_dir():
        raise FlightTraceError("flight output path is not a directory")

    contents = [_render(recovery, recovery.merged, tid=None)]
    contents.extend(
        _render(recovery, recovery.threads[tid].events, tid=tid)
        for tid in sorted(recovery.threads)
    )
    contents.append(json.dumps(recovery.summary, ensure_ascii=False, sort_keys=True,
                               indent=2) + "\n")
    temporaries: list[Path] = []
    try:
        for destination, content in zip(destinations, contents, strict=True):
            temporaries.append(_write_temporary(output_dir, destination.suffix, content))
        pairs = list(zip(temporaries, destinations, strict=True))
        if force:
            _publish_force(pairs)
        else:
            _publish_no_replace(pairs)
        return tuple(destinations)
    except FileExistsError:
        raise
    except FlightTraceError:
        raise
    except OSError as error:
        raise FlightTraceError(f"flight output preparation failure: {error}") from error
    finally:
        failures: list[str] = []
        artifacts: list[Path] = []
        removed_temporary = False
        for temporary in temporaries:
            if not _path_exists(temporary):
                continue
            try:
                temporary.unlink()
                removed_temporary = True
            except BaseException as cleanup_error:
                _record_cleanup_failure(temporary, cleanup_error, failures, artifacts)
        if removed_temporary:
            try:
                _fsync_directory(output_dir)
            except BaseException as cleanup_error:
                failures.append(
                    f"{output_dir}: {type(cleanup_error).__name__}: {cleanup_error}"
                )
        context = _cleanup_context(failures, artifacts)
        if context:
            active = sys.exception()
            if active is not None:
                _annotate(active, context)
            else:
                raise FlightTraceError(f"flight output temporary cleanup failure{context}")
