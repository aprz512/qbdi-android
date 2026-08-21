#!/usr/bin/env python3
"""Render and transactionally publish recovered flight-recorder outputs."""

from __future__ import annotations

import json
import os
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


def _same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except (FileNotFoundError, OSError):
        return False


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _best_effort_fsync(directory: Path) -> None:
    try:
        _fsync_directory(directory)
    except OSError:
        pass


def _publish_no_replace(pairs: list[tuple[Path, Path]]) -> None:
    for _, destination in pairs:
        if destination.exists():
            raise FileExistsError(f"flight output already exists: {destination.name}")
    published: list[tuple[Path, Path]] = []
    try:
        for temporary, destination in pairs:
            os.link(temporary, destination)
            published.append((temporary, destination))
        if pairs:
            _fsync_directory(pairs[0][1].parent)
    except FileExistsError:
        for temporary, destination in reversed(published):
            if _same_file(temporary, destination):
                destination.unlink()
        if pairs:
            _best_effort_fsync(pairs[0][1].parent)
        raise
    except OSError as error:
        for temporary, destination in reversed(published):
            if _same_file(temporary, destination):
                destination.unlink()
        if pairs:
            _best_effort_fsync(pairs[0][1].parent)
        raise FlightTraceError(f"flight output publication failure: {error}") from error


def _backup(destination: Path) -> Path | None:
    if not destination.exists():
        return None
    backup = _temporary(destination.parent, ".backup")
    backup.unlink()
    try:
        os.link(destination, backup)
    except BaseException:
        backup.unlink(missing_ok=True)
        raise
    return backup


def _publish_force(pairs: list[tuple[Path, Path]]) -> None:
    backups: dict[Path, Path | None] = {}
    try:
        for _, destination in pairs:
            backups[destination] = _backup(destination)
    except OSError as error:
        for backup in backups.values():
            if backup is not None:
                backup.unlink(missing_ok=True)
        raise FlightTraceError(f"flight output backup failure: {error}") from error

    published: list[tuple[Path, tuple[int, int]]] = []
    try:
        for temporary, destination in pairs:
            identity = temporary.stat()
            os.replace(temporary, destination)
            published.append((destination, (identity.st_dev, identity.st_ino)))
        if pairs:
            _fsync_directory(pairs[0][1].parent)
    except OSError as error:
        for destination, identity in reversed(published):
            backup = backups[destination]
            if backup is not None:
                os.replace(backup, destination)
                backups[destination] = None
            else:
                try:
                    current = destination.stat()
                    if (current.st_dev, current.st_ino) == identity:
                        destination.unlink()
                except FileNotFoundError:
                    pass
        for destination, backup in backups.items():
            if backup is not None:
                backup.unlink(missing_ok=True)
        if pairs:
            _best_effort_fsync(pairs[0][1].parent)
        raise FlightTraceError(f"flight output publication failure: {error}") from error
    for backup in backups.values():
        if backup is not None:
            backup.unlink(missing_ok=True)
    if pairs:
        _best_effort_fsync(pairs[0][1].parent)


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
        existing = next((path for path in destinations if path.exists()), None)
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
        for temporary in temporaries:
            temporary.unlink(missing_ok=True)
