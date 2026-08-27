#!/usr/bin/env python3
"""Manual, rooted-device qtrace release acceptance.  This is never a CI job."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence
from scripts.bounded_process import BoundedProcessError, capture_bounded
from scripts.pull_trace import AdbArtifactClient, MAX_METRICS_BYTES
from qtrace.status import load_strict_json, validate_status_shape


PACKAGE = "com.aprz.qbdiandroid"
ACTIVITY = "com.aprz.qbdiandroid/.MainActivity"
SEED = 5855319310239641971
ITERATIONS = 30
BASELINE_PATH = f"/data/data/{PACKAGE}/files/qtrace-acceptance-baseline.json"
RECEIPT_PATH = f"/data/data/{PACKAGE}/files/qtrace-acceptance-receipt.json"
ENTRY_STATUS_PATH = f"/data/data/{PACKAGE}/files/qtrace-acceptance-entry-status.json"
_UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)


class AcceptanceNotReadyError(RuntimeError):
    """The fixture has not yet atomically published a pollable result."""


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    returncode: int


@dataclass(frozen=True)
class RegularFileStat:
    size: int
    identity: tuple[int, int]


class Runner(Protocol):
    def run(self, command: Sequence[str], *, timeout: float, cwd: Path | None = None,
            allowed: tuple[int, ...] = (0,)) -> CommandResult: ...
    def read_text(self, path: Path, *, timeout: float) -> str: ...
    def read_text_beneath(self, root: Path | RootedReader, relative: Path, *, timeout: float) -> str: ...


class RootedReader:
    """A fixed output directory capability, immune to later pathname rebinding."""

    def __init__(self, root: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(root, flags)
            details = os.fstat(descriptor)
            if not stat.S_ISDIR(details.st_mode):
                raise OSError("trusted output root is not a directory")
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            raise RuntimeError("trusted output root is not a directory") from error
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        self._descriptor = descriptor
        self.path = root
        self._identity = (details.st_dev, details.st_ino)

    def __enter__(self) -> "RootedReader":
        return self

    def __exit__(self, *_unused: object) -> None:
        self.close()

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1

    def _open_regular(self, relative: Path | str) -> tuple[int, os.stat_result]:
        candidate = Path(relative)
        if (self._descriptor < 0 or candidate.is_absolute() or not candidate.parts or
                ".." in candidate.parts):
            raise RuntimeError("reported output path is unsafe")
        directory = -1
        descriptor = -1
        try:
            root_details = os.fstat(self._descriptor)
            if (root_details.st_dev, root_details.st_ino) != self._identity:
                raise RuntimeError("trusted output root identity changed")
            directory = os.dup(self._descriptor)
            for part in candidate.parts[:-1]:
                child = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                                getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
                os.close(directory)
                directory = child
            descriptor = os.open(
                candidate.parts[-1],
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode):
                raise RuntimeError("reported output is not a regular file")
            result, descriptor = descriptor, -1
            return result, details
        except OSError as error:
            raise RuntimeError("reported output is outside the trusted directory") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if directory >= 0:
                os.close(directory)

    def stat_regular(self, relative: Path | str) -> RegularFileStat:
        descriptor, details = self._open_regular(relative)
        try:
            return RegularFileStat(details.st_size, (details.st_dev, details.st_ino))
        finally:
            os.close(descriptor)

    def read_bytes(self, relative: Path | str, maximum_bytes: int = 1_048_576,
                   *, deadline: float | None = None) -> bytes:
        descriptor, details = self._open_regular(relative)
        try:
            if details.st_size > maximum_bytes:
                raise RuntimeError("reported output is not a bounded regular file")
            data = bytearray()
            while len(data) < details.st_size:
                if deadline is not None and time.monotonic() >= deadline:
                    raise RuntimeError("reported output read exceeded deadline")
                block = os.read(descriptor, min(64 * 1024, details.st_size - len(data)))
                if not block:
                    raise RuntimeError("reported output changed while being read")
                data.extend(block)
            if deadline is not None and time.monotonic() >= deadline:
                raise RuntimeError("reported output read exceeded deadline")
            return bytes(data)
        finally:
            os.close(descriptor)


class SubprocessRunner:
    """Bounded process/read adapter; the one-shot failure hook is acceptance-only."""

    def __init__(self, device: str, *, inject_first_read_failure: bool = True) -> None:
        self.device = device
        self.inject_first_read_failure = inject_first_read_failure

    def run(self, command: Sequence[str], *, timeout: float, cwd: Path | None = None,
            allowed: tuple[int, ...] = (0,)) -> CommandResult:
        if cwd is not None:
            raise ValueError("bounded acceptance commands do not support a working directory")
        try:
            output = capture_bounded(command, maximum_bytes=1_048_576, timeout=timeout)
        except BoundedProcessError as error:
            if error.returncode in allowed:
                return CommandResult(
                    error.stdout.decode("utf-8", errors="strict"),
                    error.stderr.decode("utf-8", errors="replace"), error.returncode,
                )
            raise RuntimeError(str(error)) from error
        return CommandResult(output.decode("utf-8", errors="strict"), "", 0)

    def read_text(self, path: Path, *, timeout: float) -> str:
        if self.inject_first_read_failure:
            self.inject_first_read_failure = False
            raise ConnectionError("injected one-shot ADB read failure")
        if str(path).startswith("/data/data/"):
            try:
                return self.run(
                    ("adb", "-s", self.device, "exec-out", "run-as", PACKAGE, "cat", str(path)),
                    timeout=timeout,
                ).stdout
            except RuntimeError as error:
                if str(path) == BASELINE_PATH:
                    raise AcceptanceNotReadyError("timed baseline is not published") from error
                raise
        deadline = time.monotonic() + timeout
        if timeout <= 0:
            raise RuntimeError("host report read timeout must be positive")
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as error:
            raise RuntimeError("host report is not a bounded regular file") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
                raise RuntimeError("host report is not a bounded regular file")
            chunks = bytearray()
            while len(chunks) < metadata.st_size:
                if time.monotonic() >= deadline:
                    raise RuntimeError("host report read exceeded timeout")
                chunk = os.read(descriptor, min(64 * 1024, metadata.st_size - len(chunks)))
                if not chunk:
                    raise RuntimeError("host report changed during bounded read")
                chunks.extend(chunk)
            if time.monotonic() >= deadline:
                raise RuntimeError("host report read exceeded timeout")
        finally:
            os.close(descriptor)
        if len(chunks) != metadata.st_size:
            raise RuntimeError("host report is not a bounded regular file")
        return bytes(chunks).decode("utf-8", errors="strict")

    def read_text_beneath(self, root: Path | RootedReader, relative: Path, *, timeout: float) -> str:
        if timeout <= 0:
            raise RuntimeError("bounded report read timeout must be positive")
        deadline = time.monotonic() + timeout
        value = _read_root(root, str(relative), deadline=deadline)
        if time.monotonic() >= deadline:
            raise RuntimeError("bounded report read exceeded timeout")
        return value.decode("utf-8", errors="strict")


class OneShotArtifactRead:
    """Acceptance-only wrapper: fail exactly one artifact read, never disturb adbd."""
    def __init__(self, client: object) -> None:
        self.client = client
        self.failed = False

    def read_file(self, name: str, *, maximum_bytes: int) -> bytes:
        if not self.failed:
            self.failed = True
            raise ConnectionError("injected acceptance artifact read failure")
        return self.client.read_file(name, maximum_bytes=maximum_bytes)


def _read_retry(runner: Runner, path: Path, *, timeout: float,
                deadline: float | None = None) -> str:
    if timeout <= 0:
        raise ValueError("read timeout must be positive")
    final_deadline = time.monotonic() + timeout if deadline is None else deadline
    def read_once() -> str:
        remaining = final_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("read deadline elapsed before retry")
        return runner.read_text(path, timeout=remaining)
    try:
        return read_once()
    except ConnectionError:
        return read_once()


def _read_retry_beneath(runner: Runner, root: Path, relative: Path, *, timeout: float,
                        deadline: float | None = None) -> str:
    """Read a local acceptance result only through its trusted output root."""
    if timeout <= 0:
        raise ValueError("read timeout must be positive")
    final_deadline = time.monotonic() + timeout if deadline is None else deadline

    def read_once() -> str:
        remaining = final_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("read deadline elapsed before retry")
        return runner.read_text_beneath(root, relative, timeout=remaining)

    try:
        return read_once()
    except ConnectionError:
        return read_once()


def _strict_json(raw: str) -> dict[str, object]:
    def duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def nonfinite(_: str) -> object:
        raise ValueError("non-finite JSON number")
    value = json.loads(raw, object_pairs_hook=duplicate, parse_constant=nonfinite)
    if type(value) is not dict:
        raise ValueError("JSON root is not an object")
    return value


def _strict_report(runner: Runner, root: Path, relative: Path) -> dict[str, object]:
    try:
        return _strict_json(_read_retry_beneath(runner, root, relative, timeout=5.0))
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("qtrace report is not strict JSON") from error


_SESSION_REPORT_KEYS = frozenset((
    "artifacts", "device", "effective_config", "error", "finished_at", "mode", "native",
    "outputs", "package", "pid", "schema", "serial", "session_id", "stage", "started_at",
    "status", "target", "timeline", "tracer", "warnings",
))
_PULL_REPORT_KEYS = frozenset(("schema", "sessionId", "artifacts", "errors"))
_PULL_ARTIFACT_KEYS = frozenset((
    "remote_name", "local_path", "source_size", "destination_size", "sha256", "decoder",
    "termination", "stop_reason", "metrics_schema", "producer_waits", "producer_wait_ns",
    "conversion_ms", "native_stop_acknowledged", "host_observed_ack_ms",
))
_PULL_FLIGHT_ARTIFACT_KEYS = _PULL_ARTIFACT_KEYS | {"recovery_status"}


def _strict_session_report(runner: Runner, root: Path, relative: Path) -> dict[str, object]:
    value = _strict_report(runner, root, relative)
    if set(value) != _SESSION_REPORT_KEYS:
        raise RuntimeError("session report has unexpected fields")
    if (value.get("schema") != 1 or not isinstance(value.get("session_id"), str) or
            not isinstance(value.get("status"), str) or not isinstance(value.get("stage"), str) or
            not isinstance(value.get("package"), str) or type(value.get("pid")) is not int or
            not isinstance(value.get("artifacts"), list) or not isinstance(value.get("outputs"), list) or
            not isinstance(value.get("timeline"), list) or not isinstance(value.get("native"), dict)):
        raise RuntimeError("session report has invalid field types")
    return value


def _strict_pull_report(runner: Runner, root: Path, relative: Path) -> dict[str, object]:
    value = _strict_report(runner, root, relative)
    if set(value) != _PULL_REPORT_KEYS or value.get("schema") != 1:
        raise RuntimeError("pull report has unexpected fields")
    if (not isinstance(value.get("sessionId"), str) or not isinstance(value.get("artifacts"), list)
            or not isinstance(value.get("errors"), list)):
        raise RuntimeError("pull report has invalid field types")
    return value


def _wait_for_baseline(runner: Runner) -> dict[str, object]:
    deadline = time.monotonic() + 15.0
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            value = _strict_json(_read_retry(
                runner, Path(BASELINE_PATH), timeout=min(2.0, remaining), deadline=deadline,
            ))
            if (type(value) is dict and value.get("iterations") == ITERATIONS and
                    value.get("seed") == SEED and isinstance(value.get("result"), str)):
                return value
            raise ValueError("baseline has an invalid fixture result")
        except (AcceptanceNotReadyError, ConnectionError, OSError, ValueError,
                json.JSONDecodeError) as error:
            last_error = error
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.25, remaining))
    raise RuntimeError(f"timed baseline was not available within 15 seconds: {last_error}")


def _report_path(stdout: str, root: Path | RootedReader) -> Path:
    candidates = [Path(line.strip()) for line in stdout.splitlines() if line.strip().endswith("report.json")]
    if len(candidates) != 1:
        raise RuntimeError("qtrace demo did not publish exactly one report path")
    report = candidates[0]
    try:
        root_path = root.path if isinstance(root, RootedReader) else root
        relative = report.relative_to(root_path) if report.is_absolute() else report
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ValueError("unsafe report path")
    except ValueError as error:
        raise RuntimeError("qtrace reported a path outside its trusted output directory") from error
    return relative


def _published_report_path(stdout: str, root: Path | RootedReader) -> Path:
    if not stdout.strip():
        raise RuntimeError("qtrace command did not publish a report path")
    return _report_path(stdout, root)


def _trusted_output(path: Path, root: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve())
        metadata = resolved.lstat()
    except (OSError, ValueError) as error:
        raise RuntimeError("reported output is outside the trusted directory") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError("reported output is not a regular non-symlink file")
    return resolved


def _read_beneath(root: Path, relative: str, maximum_bytes: int = 1_048_576,
                  *, deadline: float | None = None) -> bytes:
    """Read one regular file through held no-follow directory descriptors."""
    candidate = Path(relative)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        raise RuntimeError("reported output path is unsafe")
    directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                        getattr(os, "O_NOFOLLOW", 0))
    try:
        for part in candidate.parts[:-1]:
            child = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                            getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(candidate.parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                             dir_fd=directory)
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_size > maximum_bytes:
                raise RuntimeError("reported output is not a bounded regular file")
            data = bytearray()
            while len(data) < details.st_size:
                if deadline is not None and time.monotonic() >= deadline:
                    raise RuntimeError("reported output read exceeded deadline")
                block = os.read(descriptor, min(64 * 1024, details.st_size - len(data)))
                if not block:
                    raise RuntimeError("reported output changed while being read")
                data.extend(block)
            if deadline is not None and time.monotonic() >= deadline:
                raise RuntimeError("reported output read exceeded deadline")
            return bytes(data)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise RuntimeError("reported output is outside the trusted directory") from error
    finally:
        os.close(directory)


def _read_root(root: Path | RootedReader, relative: str, maximum_bytes: int = 1_048_576,
               *, deadline: float | None = None) -> bytes:
    if isinstance(root, RootedReader):
        return root.read_bytes(relative, maximum_bytes, deadline=deadline)
    return _read_beneath(root, relative, maximum_bytes, deadline=deadline)


def _validated_timed_report(runner: Runner, root: Path | RootedReader, relative: Path) -> tuple[dict[str, object], str]:
    value = _strict_session_report(runner, root, relative)
    if (type(value) is not dict or value.get("schema") != 1 or value.get("status") != "sealed" or
            value.get("stage") != "completed" or value.get("package") != PACKAGE):
        raise RuntimeError("timed qtrace report is incomplete")
    if relative != Path(value["session_id"]) / "report.json":
        raise RuntimeError("session report is not in its session directory")
    native = value.get("native")
    status = native.get("status") if isinstance(native, dict) else None
    if (not isinstance(status, dict) or status.get("state") != "sealed" or
            status.get("reason") != "duration_elapsed" or status.get("stopAcknowledged") is not True):
        raise RuntimeError("timed trace did not detach/seal after native duration stop")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeError("timed report has no artifact records")
    for record in artifacts:
        if not isinstance(record, dict):
            raise RuntimeError("timed report has an invalid artifact record")
        name = record.get("remote_name")
        if name is not None and (not isinstance(name, str) or not name or "/" in name or "\\" in name
                                 or any(ord(character) < 32 or ord(character) == 127 for character in name)):
            raise RuntimeError("timed report artifact is not a safe basename")
        local = record.get("local_path")
        if local is not None and (not isinstance(local, str) or not local.startswith("artifacts/")
                                  or local == "artifacts/" or ".." in Path(local).parts):
            raise RuntimeError("timed report artifact path is unsafe")
    roots = [record.get("remote_name") for record in artifacts if isinstance(record, dict) and
             isinstance(record.get("remote_name"), str) and
             (record["remote_name"].endswith(".trace.bin") or
              record["remote_name"].endswith(".trace.bin.lz4"))]
    if len(roots) != 1:
        raise RuntimeError("timed report lacks a trusted binary artifact name")
    artifact = roots[0]
    if "/" in artifact or "\\" in artifact or artifact in {"", ".", ".."}:
        raise RuntimeError("timed report artifact is not a safe basename")
    names = {record.get("remote_name") for record in artifacts if isinstance(record, dict)}
    if artifact + ".metrics" not in names:
        raise RuntimeError("timed binary root has no matching metrics sidecar record")
    if type(value.get("pid")) is not int or value["pid"] <= 0:
        raise RuntimeError("timed report does not retain its traced app PID")
    timeline = value.get("timeline")
    stages = [item.get("stage") for item in timeline] if isinstance(timeline, list) and all(isinstance(item, dict) for item in timeline) else []
    if "installing_hooks" not in stages or "running" not in stages or stages.index("installing_hooks") > stages.index("running"):
        raise RuntimeError("report lacks installed-action-before-running detach evidence")
    return value, artifact


def _validated_monitor_report(runner: Runner, root: Path | RootedReader, relative: Path, *, status: str) -> dict[str, object]:
    report = _strict_session_report(runner, root, relative)
    if report.get("schema") != 1 or report.get("package") != PACKAGE or report.get("status") != status:
        raise RuntimeError("monitor report has an invalid classification")
    if relative != Path(report["session_id"]) / "report.json":
        raise RuntimeError("session report is not in its session directory")
    return report


def _validate_timed_fixture_receipt(
    report: dict[str, object], receipt_raw: str, entry_status_raw: str,
) -> None:
    try:
        receipt = _strict_json(receipt_raw)
        entry_status = validate_status_shape(load_strict_json(
            entry_status_raw.encode("utf-8"), maximum_bytes=64 * 1024,
        ))
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("timed fixture entry evidence is not strict native JSON") from error
    if (set(receipt) != {"sessionId", "nonce", "entryMonotonicNs"} or
            receipt.get("sessionId") != report.get("session_id") or
            type(receipt.get("nonce")) is not str or _UUID4.fullmatch(receipt["nonce"]) is None or
            type(receipt.get("entryMonotonicNs")) is not int or receipt["entryMonotonicNs"] < 0):
        raise RuntimeError("timed fixture receipt does not identify native entry")
    final_native = report.get("native")
    final_status = final_native.get("status") if isinstance(final_native, dict) else None
    if (not isinstance(final_status, dict) or
            entry_status["sessionId"] != report.get("session_id") or
            entry_status["pid"] != report.get("pid") or
            entry_status["generation"] != final_status.get("generation") or
            entry_status["normalizedScenes"] != final_status.get("normalizedScenes") or
            entry_status["state"] != "running" or entry_status["reason"] != "" or
            entry_status["stopAcknowledged"] is not False or
            entry_status["transitionMonotonicNs"] > receipt["entryMonotonicNs"]):
        raise RuntimeError("timed fixture entry status does not prove armed native entry")
    timeline = report.get("timeline")
    if not isinstance(timeline, list) or not any(
            isinstance(item, dict) and item.get("stage") == "installing_hooks" and
            item.get("cleanup_detached") is True for item in timeline):
        raise RuntimeError("timed report lacks injector cleanup/detach receipt")


def _convert_snapshot_bounded(snapshot: Path, destination: Path, *, lz4: str | None,
                              deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("timed artifact conversion exceeded deadline")
    command = [sys.executable, "-m", "scripts.trace_convert", str(snapshot), "--output",
               str(destination), "--force"]
    if lz4 is not None:
        command.extend(("--lz4", lz4))
    try:
        capture_bounded(command, maximum_bytes=64 * 1024, timeout=remaining)
    except (BoundedProcessError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("timed artifact conversion failed within deadline") from error


def _validate_timed_artifact_semantics(runner: Runner, report: dict[str, object], root: Path | RootedReader, *,
                                       converter=None) -> None:
    deadline = time.monotonic() + 15.0
    records = report.get("artifacts")
    if not isinstance(records, list):
        raise RuntimeError("timed report has no artifact semantics")
    binary = [record for record in records if isinstance(record, dict) and
              isinstance(record.get("remote_name"), str) and
              (record["remote_name"].endswith(".trace.bin") or
               record["remote_name"].endswith(".trace.bin.lz4"))]
    if len(binary) != 1:
        raise RuntimeError("timed trace must publish exactly one binary artifact")
    record = binary[0]
    remote_name = record.get("remote_name")
    local_path = record.get("local_path")
    if (not isinstance(remote_name, str) or not isinstance(local_path, str) or
            Path(local_path).name != remote_name):
        raise RuntimeError("timed binary record has no trusted local artifact identity")
    binary_bytes = _read_root(root, local_path, deadline=deadline)
    metrics_name = remote_name + ".metrics"
    if not any(isinstance(item, dict) and item.get("remote_name") == metrics_name
               for item in records):
        raise RuntimeError("timed binary root has no matching metrics sidecar record")
    metrics_relative = local_path + ".metrics"
    metrics_bytes = _read_root(root, metrics_relative, MAX_METRICS_BYTES, deadline=deadline)
    if (record.get("termination") != "stopped" or record.get("metrics_schema") != 3 or
            record.get("native_stop_acknowledged") is not True):
        raise RuntimeError("binary TRACE_STOP/metrics-v3 native-stop contract failed")
    with tempfile.TemporaryDirectory(prefix=".qtrace-acceptance-validate-") as staging:
        snapshot = Path(staging) / remote_name
        snapshot.write_bytes(binary_bytes)
        Path(str(snapshot) + ".metrics").write_bytes(metrics_bytes)
        converted = Path(staging) / "converted.trace.txt"
        if converter is None:
            _convert_snapshot_bounded(snapshot, converted,
                                      lz4="lz4" if remote_name.endswith(".lz4") else None,
                                      deadline=deadline)
        else:
            stats = converter(snapshot, converted,
                              lz4="lz4" if remote_name.endswith(".lz4") else None,
                              crash_marked=False)
            if getattr(stats, "termination", None) != "stopped" or getattr(stats, "partial", True):
                raise RuntimeError("timed binary conversion was not a complete stopped trace")
        text = _read_root(Path(staging), converted.name, deadline=deadline).decode("utf-8", errors="strict")
        lines = text.splitlines()
        terminals = [line for line in lines if line.startswith("TRACE_END ")]
        if (not lines or not lines[0].startswith("TRACE_BEGIN format=4 ") or len(terminals) != 1 or
                not terminals[0].startswith(
                    "TRACE_END status=stopped reason=duration_elapsed return_valid=0 ")):
            raise RuntimeError("timed binary does not contain one duration_elapsed TRACE_STOP terminal")


def _verify_artifact_read_recovery(device: str, report: dict[str, object], root: Path | RootedReader, *,
                                   artifact_client_factory=AdbArtifactClient) -> None:
    """Exercise one real app-private artifact read failure without restarting adbd."""
    records = report.get("artifacts")
    if not isinstance(records, list):
        raise RuntimeError("timed report has no artifact records for recovery verification")
    binary = [record for record in records if isinstance(record, dict) and
              isinstance(record.get("remote_name"), str) and
              (record["remote_name"].endswith(".trace.bin") or
               record["remote_name"].endswith(".trace.bin.lz4"))]
    if len(binary) != 1 or not isinstance(binary[0].get("local_path"), str):
        raise RuntimeError("timed report has no trusted binary identity for recovery verification")
    local_path = Path(binary[0]["local_path"])
    metrics_name = str(binary[0]["remote_name"]) + ".metrics"
    metrics_relative = Path(str(local_path) + ".metrics")
    before = _read_root(root, str(metrics_relative), MAX_METRICS_BYTES)
    client = artifact_client_factory(package=PACKAGE, device=device)
    wrapped = OneShotArtifactRead(client)
    try:
        wrapped.read_file(metrics_name, maximum_bytes=MAX_METRICS_BYTES)
    except ConnectionError:
        # The first failure is deliberately before delegating; verify the same
        # trusted session evidence remains intact before retrying the same client.
        if _read_root(root, str(metrics_relative), MAX_METRICS_BYTES) != before:
            raise RuntimeError("artifact evidence changed after injected read failure")
    else:
        raise RuntimeError("injected artifact read unexpectedly succeeded")
    remote = wrapped.read_file(metrics_name, maximum_bytes=MAX_METRICS_BYTES)
    if remote != before:
        raise RuntimeError("artifact retry did not recover the same metrics evidence")


def _demo_command(device: str, scenario: str, form: str, output: Path) -> tuple[str, ...]:
    return ("python3", "-m", "qtrace", "demo", "--scenario", scenario,
            *( ("--duration", "2s") if scenario == "timed" else () ),
            "--scene-form", form, "--device", device, "--output", str(output))


def _verify_pull_outputs(root: Path) -> None:
    """Pull itself validates binary terminal/metrics/text conversion contracts.

    The report is the authoritative artifact selector; no device directory listing is used here.
    """
    expected = ("latest", "name", "all", "compressed")
    missing = [name for name in expected if not (root / name).exists()]
    if missing:
        raise RuntimeError("manual pull did not publish output directories: " + ",".join(missing))


def _validated_pull_report(runner: Runner, stdout: str, root: Path | RootedReader, *, named: str | None = None,
                           compressed_only: bool = False) -> dict[str, object]:
    relative = _published_report_path(stdout, root)
    report = _strict_pull_report(runner, root, relative)
    session_id = report["sessionId"]
    if (_UUID4.fullmatch(session_id) is None or
            relative != Path(session_id) / "report.json"):
        raise RuntimeError("pull report is not in its session directory")
    if report["errors"] != []:
        raise RuntimeError("manual pull report contains errors")
    records = report.get("artifacts")
    if not isinstance(records, list) or not records:
        raise RuntimeError("manual pull report has no artifact records")
    names: set[str] = set()
    for item in records:
        if not isinstance(item, dict) or set(item) not in {
                _PULL_ARTIFACT_KEYS, _PULL_FLIGHT_ARTIFACT_KEYS}:
            raise RuntimeError("manual pull report has an invalid artifact record")
        name, local = item["remote_name"], item["local_path"]
        local_parts = Path(local).parts if isinstance(local, str) else ()
        if (not isinstance(name, str) or not name or Path(name).name != name or
                local_parts != ("artifacts", name)):
            raise RuntimeError("manual pull report has an unsafe artifact path")
        if (type(item["source_size"]) not in {int, type(None)} or
                type(item["destination_size"]) is not int or
                any(value is not None and value < 0 for value in
                    (item["source_size"], item["destination_size"])) or
                not isinstance(item["sha256"], str) or len(item["sha256"]) != 64 or
                any(character not in "0123456789abcdef" for character in item["sha256"])):
            raise RuntimeError("manual pull report has invalid artifact metadata")
        decoder = item["decoder"]
        if decoder not in {None, "qtrb", "flight", "lz4-text", "legacy", "sidecar"}:
            raise RuntimeError("manual pull report has invalid artifact status")
        if item["stop_reason"] is not None and type(item["stop_reason"]) is not str:
            raise RuntimeError("manual pull report has invalid artifact status")
        if any(value is not None and type(value) is not int for value in (
                item["metrics_schema"], item["producer_waits"], item["producer_wait_ns"])) or \
                any(value is not None and (type(value) not in {int, float} or
                                           not math.isfinite(value) or value < 0) for value in (
                    item["conversion_ms"], item["host_observed_ack_ms"])):
            raise RuntimeError("manual pull report has invalid artifact counters")
        if any(value is not None and value < 0 for value in (
                item["metrics_schema"], item["producer_waits"], item["producer_wait_ns"])):
            raise RuntimeError("manual pull report has invalid artifact counters")
        if item["native_stop_acknowledged"] is not None and type(item["native_stop_acknowledged"]) is not bool:
            raise RuntimeError("manual pull report has invalid stop acknowledgement")
        termination = item["termination"]
        if decoder == "flight":
            recovery = item.get("recovery_status")
            if (set(item) != _PULL_FLIGHT_ARTIFACT_KEYS or recovery != "complete" or
                    type(termination) is not dict or
                    set(termination) != {"cause", "initiator_tid"} or
                    termination.get("cause") not in {"unknown", "termination_intent"} or
                    (termination["cause"] == "unknown" and
                     termination.get("initiator_tid") is not None) or
                    (termination["cause"] == "termination_intent" and
                     (type(termination.get("initiator_tid")) is not int or
                      termination["initiator_tid"] <= 0))):
                raise RuntimeError("manual pull report has invalid flight recovery status")
        elif (set(item) != _PULL_ARTIFACT_KEYS or
              (decoder == "qtrb" and termination not in {"completed", "stopped"}) or
              (decoder == "lz4-text" and termination != "completed") or
              (decoder in {None, "legacy", "sidecar"} and termination is not None)):
            raise RuntimeError("manual pull report has invalid decoder status")
        if isinstance(root, RootedReader):
            details = root.stat_regular(relative.parent / local)
        else:
            with RootedReader(root) as held:
                details = held.stat_regular(relative.parent / local)
        if details.size != item["destination_size"]:
            raise RuntimeError("manual pull artifact destination size does not match report")
        if name in names:
            raise RuntimeError("manual pull report repeats an artifact name")
        names.add(name)
    if named is not None and named not in names:
        raise RuntimeError("named pull report omitted the trusted artifact")
    if compressed_only and any(isinstance(name, str) and name.endswith(".trace.txt") for name in names):
        raise RuntimeError("compressed-only pull published a decoded text artifact")
    return report


def run_acceptance(device: str, directory: Path, *, runner: Runner,
                   converter=None, artifact_client_factory=AdbArtifactClient) -> int:
    if not device:
        raise ValueError("--device is required for manual acceptance")
    directory.mkdir(parents=True, exist_ok=True)
    runner.run(("./gradlew", "nativeHostTest", "--no-daemon"), timeout=900.0)
    runner.run(("python3", "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"), timeout=300.0)
    runner.run(("./gradlew", ":app:assembleDebug", "--no-daemon"), timeout=900.0)
    runner.run(("adb", "-s", device, "install", "-r", "app/build/outputs/apk/debug/app-debug.apk"), timeout=120.0)
    runner.run(("adb", "-s", device, "shell", "am", "force-stop", PACKAGE), timeout=30.0)
    runner.run(("adb", "-s", device, "shell", "am", "start", "-n", ACTIVITY,
                "--ez", "qtrace_acceptance", "true", "--es", "qtrace_acceptance_mode", "timed",
                "--el", "qtrace_acceptance_seed", str(SEED), "--el", "qtrace_acceptance_iterations", str(ITERATIONS)), timeout=30.0)
    baseline = _wait_for_baseline(runner)
    runner.run(("python3", "scripts/benchmark_trace.py", "--device", device, "--profile", "fast", "--runs", "5",
                "--candidate-tracer", "out/arm64-v8a/libqbdi_tracer.so", "--compare", "docs/benchmarks/binary-trace-baseline.md"), timeout=900.0)
    with ExitStack() as held_roots:
        reports: dict[str, tuple[RootedReader, Path]] = {}
        timed_evidence: dict[str, tuple[str, str]] = {}
        for scenario, form, name in (("timed", "offset", "offset"), ("timed", "symbol", "symbol"), ("monitor-exit", "offset", "exit"), ("flight-crash", "offset", "crash")):
            output = directory / name
            published = runner.run(_demo_command(device, scenario, form, output), timeout=180.0,
                                   allowed=(0, 2) if scenario == "flight-crash" else (0,))
            held = held_roots.enter_context(RootedReader(output))
            reports[name] = (held, _published_report_path(published.stdout, held))
            if scenario == "timed":
                timed_evidence[name] = (
                    _read_retry(runner, Path(RECEIPT_PATH), timeout=5.0),
                    _read_retry(runner, Path(ENTRY_STATUS_PATH), timeout=5.0),
                )
            if scenario == "flight-crash" and published.returncode != 2:
                raise RuntimeError("flight-crash must publish crash recovery with exit code 2")
        timed, artifact = _validated_timed_report(runner, *reports["offset"])
        _validate_timed_fixture_receipt(timed, *timed_evidence["offset"])
        symbol, _ = _validated_timed_report(runner, *reports["symbol"])
        _validate_timed_fixture_receipt(symbol, *timed_evidence["symbol"])
        _validate_timed_artifact_semantics(
            runner, timed, reports["offset"][0], converter=converter,
        )
        _verify_artifact_read_recovery(
            device, timed, reports["offset"][0],
            artifact_client_factory=artifact_client_factory,
        )
        timed_status = timed["native"]["status"]  # validated above
        symbol_status = symbol["native"]["status"]
        if timed_status["normalizedScenes"] != symbol_status["normalizedScenes"]:
            raise RuntimeError("offset and symbol timed scenes did not normalize identically")
        _validated_monitor_report(runner, *reports["exit"], status="process_exited")
        _validated_monitor_report(runner, *reports["crash"], status="crash_recovered")
    runner.run(("adb", "-s", device, "shell", "kill", "-0", str(timed["pid"])), timeout=10.0)
    timed_oracle = json.loads(_read_retry(runner, Path(
        f"/data/data/{PACKAGE}/files/qtrace-acceptance-timed.json"), timeout=5.0))
    if timed_oracle != baseline:
        raise RuntimeError("long timed target did not return the baseline oracle value")
    pulls = (("latest", ("--latest",), None, False), ("name", ("--name", artifact), artifact, False), ("all", ("--all",), None, False), ("compressed", ("--all", "--compressed-only"), None, True))
    for name, selector, expected, compressed in pulls:
        output = directory / name
        result = runner.run(("python3", "-m", "qtrace", "pull", "--package", PACKAGE, *selector, "--device", device, "--output", str(output)), timeout=180.0)
        with RootedReader(output) as held:
            _validated_pull_report(runner, result.stdout, held, named=expected,
                                   compressed_only=compressed)
    _verify_pull_outputs(directory)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True, help="explicit rooted arm64 device serial")
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)
    parent = Path.cwd() / "qtrace-acceptance-failures"
    parent.mkdir(mode=0o700, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise RuntimeError("acceptance failure parent is unsafe")
    temporary = tempfile.TemporaryDirectory(prefix=".qtrace-device-acceptance-", dir=parent)
    root = Path(temporary.name)
    try:
        result = run_acceptance(arguments.device, root, runner=SubprocessRunner(arguments.device))
    except BaseException as error:
        retained = parent / uuid.uuid4().hex
        root.rename(retained)
        temporary.cleanup()
        print(f"qtrace acceptance failed; generated reports remain at: {retained}", file=sys.stderr)
        print(str(error), file=sys.stderr)
        return 1
    temporary.cleanup()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
