"""Strict status, trace completeness, sidecars, and derived-file validation."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
from pathlib import Path
from typing import Callable, Mapping, Sequence

from qtrace._artifact_common import (PulledArtifact, _MAX_STATUS_BYTES, _SIDE_SUFFIXES,
                                     _error, _name, _unlink_quiet)
from qtrace.errors import QtraceError
from qtrace.status import (NativeStatusValidationError, StrictJsonLoadError,
                           load_strict_json, validate_status_shape)


_FORMAT4_COMPLETED_TERMINAL = re.compile(
    r"TRACE_END status=completed return_valid=1 return=0x[0-9a-fA-F]+ elapsed_ms=\d+ "
    r"instructions=\d+ encoded_bytes=\d+ compressed_bytes=\d+ cache_hits=\d+ "
    r"cache_misses=\d+ cache_collisions=\d+ buffer_swaps=\d+ producer_waits=\d+ "
    r"producer_wait_ns=\d+ effective_buffer_bytes=\d+\Z"
)


_FORMAT4_STOPPED_TERMINAL = re.compile(
    r"TRACE_END status=stopped reason=(?:duration_elapsed|thread_exit|process_exit|exec_boundary) return_valid=0 elapsed_ms=\d+ "
    r"instructions=\d+ encoded_bytes=\d+ compressed_bytes=\d+ cache_hits=\d+ "
    r"cache_misses=\d+ cache_collisions=\d+ buffer_swaps=\d+ producer_waits=\d+ "
    r"producer_wait_ns=\d+ effective_buffer_bytes=\d+\Z"
)


_LEGACY_OK_TERMINAL = re.compile(
    r"TRACE_END status=ok ret=0x[0-9a-fA-F]+ elapsed_ms=\d+ "
    r"(?:bytes=\d+|instructions=\d+ raw_bytes=\d+ cache_hit_rate=\d+\.\d{6} "
    r"buffer_swaps=\d+ producer_waits=\d+ producer_wait_ns=\d+)\Z"
)


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


def validate_pulled_artifacts(
    pulled: Sequence[PulledArtifact], stage_artifacts: Path,
    status: Mapping[str, object] | None, *, compressed_only: bool,
    root_statuses: Mapping[str, Mapping[str, object]],
    source_size: Callable[[str], int | None],
) -> tuple[list[Path], list[Mapping[str, object]], list[Mapping[str, str]]]:
    """Validate private files; retain only proven roots and their derived members.

    Caller owns staging cleanup and publication. The size callback reads provenance
    without giving the validator ownership of the transport or output directory.
    """
    files: list[Path] = []
    records: list[Mapping[str, object]] = []
    errors: list[Mapping[str, str]] = []
    validated_roots: set[str] = set()
    for artifact in pulled:
        local = artifact.local_path
        remote_size = source_size(artifact.remote_name)
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
                             target_stop_reason=stats.stop_reason,
                             target_returned_in_capture=stats.termination == "completed" and not stats.partial,
                             scene_name=stats.scene, tid=stats.tid, target_offset=stats.target_offset,
                             conversion_ms=round((time.monotonic() - started) * 1000, 3))
                if crash_marked:
                    record["recovery_classification"] = "crash_marker"
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
                summary = {}
                derived = publish_flight_outputs(local, stage_artifacts, force=False, summary_out=summary)
                if type(summary) is not dict or type(summary.get("complete")) is not bool:
                    raise ValueError("flight recovery summary is malformed")
                record.update(decoder="flight", termination=summary.get("termination"),
                             target_returned_in_capture=None,
                             scene_lifecycle=summary.get("scene_lifecycle", []),
                             scene_lifecycle_omitted=summary.get("scene_lifecycle_omitted"),
                             scene_lifecycle_invalid=summary.get("scene_lifecycle_invalid"),
                             missing_sequence_ranges=summary.get("missing_sequence_ranges"),
                             coverage_gap_count=summary.get("coverage_gap_count"),
                             recovery_status=recovery_status(summary))
                process_exited = (status is not None and
                                  status.get("_process_exited") is True)
                if summary["complete"] and process_exited:
                    record["recovery_classification"] = "flight"
                if not summary["complete"] or process_exited:
                    failure = {"name": artifact.remote_name, "code": "artifact.incomplete",
                               "detail": (
                                   "flight recorder was recovered after monitored process exit"
                                   if process_exited else
                                   "flight recovery reports damage or incomplete committed data"
                               )}
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
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as binary:
            while block := binary.read(1024 * 1024):
                digest.update(block)
                size += len(block)
        records.append({"remote_name": path.name, "local_path": relative,
                        "source_size": None, "destination_size": size,
                        "sha256": digest.hexdigest(), "decoder": None,
                        "termination": None, "stop_reason": None, "metrics_schema": None,
                        "producer_waits": None, "producer_wait_ns": None,
                        "conversion_ms": None, "native_stop_acknowledged": None,
                        "host_observed_ack_ms": None})
    return files, records, errors
