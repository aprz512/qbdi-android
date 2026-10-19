"""Bounded report fragments, inode-conditional refresh, and collector merge tokens."""

from __future__ import annotations

import dataclasses
import json
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from qtrace._artifact_common import (_cleanup_exhaustively, _close_descriptor, _error,
                                     _unlink_if_present)
from qtrace._artifact_publication import _OutputDirectory
from qtrace.report import ConditionalReplaceRecoveryError, conditional_replace_at


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
