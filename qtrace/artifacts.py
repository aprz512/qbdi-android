"""Artifact selection and lifecycle; internal owners handle reads, validation, publication, reports."""

from __future__ import annotations

import os
import re
import stat
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

from qtrace._artifact_common import (ArtifactResult, PulledArtifact, PullMode, PullSelection,
                                     _SIDE_SUFFIXES, _TRACE_SUFFIXES, _UUID4,
                                     _cleanup_exhaustively, _close_descriptor, _error,
                                     _name, _package, _valid_name, validate_artifact_name)
from qtrace._artifact_publication import (_OutputDirectory, _close_token_and_reclaim,
                                         _new_stage, _note_committed_cleanup_failure,
                                         _note_parent_fallback_cleanup_failure, _open_output,
                                         _reclaim_committed_session,
                                         _reclaim_parent_fallback_sibling, _remove_tree_at,
                                         _rename_noreplace, publish_stage)
from qtrace._artifact_remote import (_call, _client_for, _relevant_manual_temporaries,
                                    _remote_size, _status_name, _temporary_name,
                                    _trace_roots, _validate_listing, pull_named_artifacts)
from qtrace._artifact_reports import (_PublicationToken, _collector_token,
                                     _rewrite_published_report, _write_json,
                                     _write_parent_refresh_error_report,
                                     _write_refresh_error_report, publish_collector_report)
from qtrace._artifact_validation import _json_status, validate_pulled_artifacts
from qtrace.device import BoundTargetDevice
from qtrace.errors import EXIT_PARTIAL, QtraceError
from qtrace.lifecycle import summarize_lifecycle


class ArtifactProcessor:
    def __init__(self, *, client_factory: Any | None = None) -> None:
        self._client_factory = client_factory

    def _publish(self, stage: Path, output: _OutputDirectory, session_id: str, files: list[Path],
                 errors: list[Mapping[str, str]], records: list[Mapping[str, object]],
                 *, parent: int | None = None, stage_fd: int | None = None,
                 stage_name: str | None = None) -> Path:
        """Keep the processor publication seam while directory ownership lives separately."""
        return publish_stage(stage, output, session_id, files, errors, records,
                             parent=parent, stage_fd=stage_fd, stage_name=stage_name)
    def _collect(self, device: BoundTargetDevice, package: str, session_id: str, names: list[str],
                 output: Path, timeout: float, status: Mapping[str, object] | None,
                 *, initial_errors: Sequence[Mapping[str, str]] = (), compressed_only: bool = False,
                 create_token: bool = False,
                 root_statuses: Mapping[str, Mapping[str, object]] | None = None) -> ArtifactResult:
        client = _client_for(device, package, self._client_factory)
        root_statuses = {} if root_statuses is None else root_statuses
        errors: list[Mapping[str, str]] = list(initial_errors)
        records: list[Mapping[str, object]] = []
        files: list[Path] = []
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
                      and not status.get("_process_exited", False)
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
            files, validated_records, validation_errors = validate_pulled_artifacts(
                pulled, stage_artifacts, status, compressed_only=compressed_only,
                root_statuses=root_statuses,
                source_size=lambda name: _remote_size(client, name, timeout))
            records.extend(validated_records)
            errors.extend(validation_errors)
            native_status = None
            host_context: Mapping[str, object] = {}
            if status is not None and status.get("_native_present", True):
                native_status = {key: value for key, value in status.items()
                                 if key not in {"_native_present", "_process_exited", "snapshot", "effectiveConfig", "device", "hostAckMs", "_hostAckMs"}}
                host_context = {"snapshot": status.get("snapshot", []),
                                "effectiveConfig": status.get("effectiveConfig"),
                                "device": status.get("device"),
                                "hostAckMs": status.get("_hostAckMs"),
                                "processExited": status.get("_process_exited", False)}
            elif status is not None:
                host_context = {"snapshot": status.get("snapshot", []),
                                "effectiveConfig": status.get("effectiveConfig"),
                                "device": status.get("device"),
                                "hostAckMs": status.get("_hostAckMs"),
                                "processExited": status.get("_process_exited", False)}
            _write_json(stage_root / "session.json", {"schema": 1, "sessionId": session_id, "packageName": package,
                                                        "status": native_status, "host": host_context,
                                                        "lifecycle": summarize_lifecycle(status, records,
                                                            process_exited=bool(status and status.get("_process_exited") is True))})
            effective = status.get("effectiveConfig") if status is not None else None
            if effective is None:
                effective = None
            _write_json(stage_root / "effective-config.json", effective)
            device_metadata = {
                "serial": device.serial,
                "package": package,
                "access_mode": device.access_mode,
                "root_strategy": device.root_strategy,
                "target_strategy": device.target_strategy,
                "package_uid": device.package_uid,
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

    def collect_session(self, device: BoundTargetDevice, package: str, session_id: str, status: Mapping[str, object] | None,
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
        process_exited = status.get("_process_exited", False)
        if type(process_exited) is not bool:
            raise _error("artifact.status_invalid", "process exit marker is invalid")
        if native_present and (status.get("sessionId") != session_id or status.get("packageName") != package):
            raise _error("artifact.status_identity", "native status identity does not match")
        if (native_present and status.get("state") not in {"sealed", "stop_incomplete"} and
                not (process_exited and status.get("state") == "running")):
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
        if native_present and process_exited and status.get("state") == "running" and not declared:
            initial_errors.append({"name": "", "code": "artifact.incomplete",
                                   "detail": "process exited without a declared trace artifact"})
        initial_errors.extend({"name": name, "code": "artifact.incomplete",
                               "detail": "temporary/current-writer artifact was not eligible for pull"}
                              for name in temporary_names if name not in snapshot_set)
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

    def pull_manual(self, device: BoundTargetDevice, package: str, selection: PullSelection, output: Path,
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
        initial_errors: list[Mapping[str, str]] = []
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
        initial_errors[0:0] = [
            {"name": name, "code": "artifact.incomplete",
             "detail": "temporary/current-writer artifact was not eligible for pull"}
            for name in _relevant_manual_temporaries(
                temporary_names, selection, roots, session_id,
            )
        ]
        selected = list(roots)
        for root in roots:
            for side in (root + ".metrics", root + ".crash"):
                if side in listing:
                    selected.append(side)
        return self._collect(device, package, session_id, selected, Path(output), timeout, status,
                             initial_errors=initial_errors,
                             compressed_only=selection.compressed_only, root_statuses=manual_root_statuses)
