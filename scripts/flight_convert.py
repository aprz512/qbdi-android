#!/usr/bin/env python3
"""Render and transactionally publish recovered flight-recorder outputs."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import itertools
from pathlib import Path

try:
    from scripts.flight_trace import FlightEvent, FlightRecovery, FlightTraceError, recover_flight
except ModuleNotFoundError:  # Support import from directly executed scripts/pull_trace.py.
    from flight_trace import (  # type: ignore[no-redef]
        FlightEvent,
        FlightRecovery,
        FlightTraceError,
        recover_flight,
    )


def recovery_status(summary: dict[str, object]) -> str:
    """Map the recovery completeness verdict to the pull-tool status vocabulary."""
    return "complete" if summary.get("complete") is True else "incomplete"


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


def _render_lines(recovery, events, *, tid):
    identity = recovery.summary
    scope = "merged" if tid is None else f"tid-{tid}"
    yield (
        "FLIGHT_BEGIN "
        f"format=1 scope={scope} run_id={identity['run_id']} pid={identity['pid']} "
        f"module_generation={identity['module_generation']} "
        f"target={json.dumps(identity['target_module'], ensure_ascii=False)}"
    ) + "\n"
    for event in events:
        yield _render_event(event) + "\n"
    yield (
        f"FLIGHT_END complete={str(bool(identity['complete'])).lower()} "
        f"events={len(events)}"
    ) + "\n"


def _render(recovery: FlightRecovery, events: tuple[FlightEvent, ...], *, tid: int | None) -> str:
    return "".join(_render_lines(recovery, events, tid=tid))


def _temporary(directory: Path, suffix: str) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=".flight-convert-", suffix=suffix, dir=directory)
    os.close(descriptor)
    return Path(name)


def _write_temporary(directory: Path, suffix: str, data) -> Path:
    temporary = _temporary(directory, suffix)
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as output:
            if isinstance(data, str):
                output.write(data)
            else:
                for part in data:
                    output.write(part)
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


def publish_flight_file_set(pairs: list[tuple[Path, Path]], force: bool) -> None:
    """Publish a prepared flight artifact set with one rollback boundary."""
    if not pairs:
        return
    parent = pairs[0][1].parent
    if any(destination.parent != parent for _, destination in pairs):
        raise FlightTraceError("flight output set must share one destination directory")
    if force:
        _publish_force(pairs)
    else:
        _publish_no_replace(pairs)


def compact_summary(summary):
    """Session metadata without materializing the physical-record projection."""
    keys = ("complete", "termination", "scene_lifecycle", "scene_lifecycle_omitted", "scene_lifecycle_invalid")
    result = {key: summary[key] for key in keys}
    result["missing_sequence_ranges"] = len(summary["lost_sequences"])
    result["coverage_gap_count"] = len(summary["coverage_gaps"])
    return result


def publish_flight_outputs(source: Path, output_dir: Path, force: bool, *,
                           after_sequence=0, until_sequence=2**64 - 1, max_events=None,
                           max_spool_bytes=16 * 1024**3, summary_out=None) -> tuple[Path, ...]:
    """Strictly recover using disk spill, then atomically stream the output set."""
    _stem(source)
    if not (type(after_sequence) is int and type(until_sequence) is int and
            0 <= after_sequence <= until_sequence <= 2**64 - 1 and
            (max_events is None or type(max_events) is int and max_events > 0)):
        raise FlightTraceError("invalid Flight output sequence range or event limit")
    try:
        try:
            from scripts.flight_storage import spooled_recovery
        except ModuleNotFoundError:
            from flight_storage import spooled_recovery
        with source.open("rb") as binary:
            before = os.fstat(binary.fileno())

            def verify_source():
                after = os.fstat(binary.fileno())
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise FlightTraceError("Flight source changed during conversion")

            with spooled_recovery(binary, max_spool_bytes=max_spool_bytes) as recovery:
                return _publish_recovery(source, output_dir, force, recovery,
                    after_sequence=after_sequence, until_sequence=until_sequence,
                    max_events=max_events, summary_out=summary_out, verify_source=verify_source)
    except FlightTraceError:
        raise
    except FileExistsError:
        raise
    except FileNotFoundError as error:
        raise FlightTraceError(f"flight artifact does not exist: {source}") from error
    except OSError as error:
        raise FlightTraceError(f"cannot read flight artifact {source}: {error}") from error


def _publish_recovery(source, output_dir, force, recovery, *, after_sequence,
                      until_sequence, max_events, summary_out, verify_source):
    basename = _stem(source)
    scoped = after_sequence != 0 or until_sequence != 2**64 - 1 or max_events is not None
    has_more = False
    if scoped:
        selected = recovery.merged.storage.list()
        for event in recovery.merged:
            if not after_sequence < event.global_seq <= until_sequence:
                continue
            if max_events is not None and len(selected) >= max_events:
                has_more = True
                break
            selected.append(event)
        selected.sort()
        first = selected[0].global_seq if selected else None
        last = selected[-1].global_seq if selected else None
        summary = dict(recovery.summary)
        summary.update(source_complete=summary["complete"], complete=False, provider_complete=False,
            output_scope={"after_sequence": after_sequence, "until_sequence": until_sequence,
                "max_events": max_events, "emitted_events": len(selected),
                "first_sequence": first, "last_sequence": last, "has_more": has_more})
        summary["physical_records"] = recovery.merged.storage.list(
            row for row in summary["physical_records"]
            if first is not None and first <= row["global_seq"] <= last)
        recovery = FlightRecovery(selected, {
            tid: type(thread)(tid, selected.for_tid(tid), thread.registers)
            for tid, thread in recovery.threads.items()}, summary)
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

    contents = itertools.chain(
        (_render_lines(recovery, recovery.merged, tid=None),),
        (_render_lines(recovery, recovery.threads[tid].events, tid=tid) for tid in sorted(recovery.threads)),
        (itertools.chain(json.JSONEncoder(ensure_ascii=False, sort_keys=True, indent=2).iterencode(recovery.summary), ("\n",)),))
    temporaries: list[Path] = []
    try:
        for destination, content in zip(destinations, contents, strict=True):
            temporaries.append(_write_temporary(output_dir, destination.suffix, content))
        verify_source()
        pairs = list(zip(temporaries, destinations, strict=True))
        if force:
            _publish_force(pairs)
        else:
            _publish_no_replace(pairs)
        if summary_out is not None:
            summary_out.update(compact_summary(recovery.summary))
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
