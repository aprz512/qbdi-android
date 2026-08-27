"""Strict, one-shot orchestration for timed and monitored qtrace sessions."""

from __future__ import annotations

import json
import math
import subprocess
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol

from qtrace.errors import EXIT_PARTIAL, EXIT_STOP_INCOMPLETE, ErrorCode, QtraceError
from scripts.bounded_process import BoundedProcessError
from qtrace.injector import InjectionRequest, InjectionResult
from qtrace.lock import TargetLock
from qtrace.models import AppConfig, OffsetScene, ResolvedScene, ResolvedTarget, SymbolScene, TargetConfig, TracerConfig, UserConfig
from qtrace.report import ReportWriter, SessionReport, SessionStage


_STATUS_KEYS = {
    "schemaVersion", "sessionId", "generation", "packageName", "pid", "state", "reason",
    "transitionMonotonicNs", "normalizedScenes", "activeScenes", "artifacts",
    "stopAcknowledged", "warnings", "errors",
}
_STATE_ORDER = {"installed": 0, "running": 1, "stop_requested": 2, "stopping": 3,
                "sealed": 4, "stop_incomplete": 4}
_UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_ANY_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TRACER_ARTIFACT_SUFFIXES = (".trace.bin", ".trace.bin.lz4", ".flight.bin")
_PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z")
_SERIAL = re.compile(r"[A-Za-z0-9._:@+-]+\Z")


class Clock(Protocol):
    def monotonic(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...
    def utc_timestamp(self) -> str: ...


class InstalledAction(Protocol):
    def __call__(self, device: object, pid: int) -> None: ...


@dataclass(frozen=True)
class RunRequest:
    config: UserConfig
    device: str | None
    output: Path
    duration_ms: int
    setup_timeout: float
    stop_timeout: float
    adb_timeout: float
    pull_timeout: float
    installed_action: InstalledAction | None = None


@dataclass(frozen=True)
class MonitorRequest:
    config: UserConfig
    device: str | None
    output: Path
    setup_timeout: float
    adb_timeout: float
    pull_timeout: float
    installed_action: InstalledAction | None = None


@dataclass(frozen=True)
class SessionResult:
    session_id: str
    exit_code: int
    report: Path
    outputs: tuple[Path, ...]


def _integer(value: object, field: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or (positive and value == 0):
        raise QtraceError("session.status_invalid", "session.status", f"{field} is not a valid integer")
    return value


def _text(value: object, field: str, limit: int) -> str:
    try:
        valid = isinstance(value, str) and len(value.encode("utf-8")) <= limit and not any(
            unicodedata.category(character).startswith("C") for character in value)
    except UnicodeEncodeError:
        valid = False
    if not valid:
        raise QtraceError("session.status_invalid", "session.status", f"{field} is not valid text")
    return value


def _artifact_basename(value: object) -> bool:
    try:
        return (isinstance(value, str) and value not in {"", ".", ".."} and
                len(value.encode("utf-8")) <= 255 and "/" not in value and "\\" not in value and
                not any(unicodedata.category(character).startswith("C") for character in value))
    except UnicodeEncodeError:
        return False


def _process_failure(error: BaseException) -> BoundedProcessError | None:
    if isinstance(error, QtraceError) and error.code == "process.failed" and isinstance(error.__cause__, BoundedProcessError):
        return error.__cause__
    return None


def _missing_remote(error: BaseException, path: str) -> bool:
    """Only the bound-device ENOENT wrapper represents an empty trace directory/file."""
    failure = _process_failure(error)
    if failure is None:
        return isinstance(error, FileNotFoundError)
    stderr = failure.stderr.decode("utf-8", errors="replace")
    return failure.returncode != 0 and path in stderr and "No such file or directory" in stderr


def _transient_adb(error: BaseException) -> bool:
    if isinstance(error, QtraceError) and error.code == ErrorCode.ADB_UNAVAILABLE.value:
        return True
    if isinstance(error, QtraceError) and error.code == "process.timeout" and isinstance(error.__cause__, subprocess.TimeoutExpired):
        return True
    failure = _process_failure(error)
    if failure is None:
        return False
    stderr = failure.stderr.decode("utf-8", errors="replace").lower()
    return any(token in stderr for token in ("device offline", "device not found", "transport closed", "transport error"))


def _issues(value: object, field: str) -> None:
    if type(value) is not list or len(value) > 256:
        raise QtraceError("session.status_invalid", "session.status", f"{field} is invalid")
    for issue in value:
        if type(issue) is not dict or set(issue) != {"code", "path", "message"} or any(
            not isinstance(issue[key], str) for key in issue
        ):
            raise QtraceError("session.status_invalid", "session.status", f"{field} has an invalid issue")
        for key in issue:
            _text(issue[key], f"{field}.{key}", 1024)


def _expected_scenes(scenes: tuple[ResolvedScene, ...]) -> list[dict[str, object]]:
    return [{"name": scene.name, "startOffset": scene.start_offset, "endOffset": scene.end_offset}
            for scene in scenes]


def parse_status(value: object, session_id: str, package: str, generation: int, pid: int,
                 scenes: tuple[ResolvedScene, ...], previous: Mapping[str, object] | None) -> dict[str, object]:
    if type(value) is not dict or set(value) != _STATUS_KEYS:
        raise QtraceError("session.status_invalid", "session.status", "status does not have the exact schema")
    if value.get("schemaVersion") != 1 or value.get("sessionId") != session_id or value.get("packageName") != package:
        raise QtraceError("session.status_identity", "session.status", "status identity does not match the session")
    if _integer(value.get("generation"), "generation", positive=True) != generation or _integer(value.get("pid"), "pid", positive=True) != pid:
        raise QtraceError("session.status_identity", "session.status", "status process identity does not match")
    state = value.get("state")
    if not isinstance(state, str) or state not in _STATE_ORDER:
        raise QtraceError("session.status_invalid", "session.status", "status state or reason is invalid")
    _text(state, "state", 64)
    _text(value.get("reason"), "reason", 256)
    transition = _integer(value.get("transitionMonotonicNs"), "transitionMonotonicNs")
    if value.get("normalizedScenes") != _expected_scenes(scenes):
        raise QtraceError("session.status_identity", "session.status", "normalized scenes do not match")
    active = value.get("activeScenes")
    if type(active) is not list or len(active) > 256:
        raise QtraceError("session.status_invalid", "session.status", "active scenes are invalid")
    active_identity: set[tuple[int, int]] = set()
    for entry in active:
        if type(entry) is not dict or set(entry) != {"sceneIndex", "tid", "sealed"}:
            raise QtraceError("session.status_invalid", "session.status", "active scene is invalid")
        index = _integer(entry.get("sceneIndex"), "active scene index")
        if index >= len(scenes) or _integer(entry.get("tid"), "active scene tid", positive=True) <= 0 or type(entry.get("sealed")) is not bool:
            raise QtraceError("session.status_invalid", "session.status", "active scene is invalid")
        identity = (index, entry["tid"])
        if identity in active_identity:
            raise QtraceError("session.status_invalid", "session.status", "active scene identity is duplicated")
        active_identity.add(identity)
    artifacts = value.get("artifacts")
    if type(artifacts) is not list or len(artifacts) > 256 or len(set(artifacts)) != len(artifacts) or any(
        not _artifact_basename(name) or not name.endswith(_TRACER_ARTIFACT_SUFFIXES) or
        any(found.group(0) != session_id for found in _ANY_UUID.finditer(name)) for name in artifacts
    ):
        raise QtraceError("session.status_invalid", "session.status", "artifacts are not safe unique basenames")
    if type(value.get("stopAcknowledged")) is not bool:
        raise QtraceError("session.status_invalid", "session.status", "stop acknowledgement is invalid")
    reason, acknowledged = value["reason"], value["stopAcknowledged"]
    if state in {"installed", "running"}:
        valid_terminal = reason == "" and acknowledged is False
    elif state in {"stop_requested", "stopping", "stop_incomplete"}:
        valid_terminal = reason == "duration_elapsed" and acknowledged is False
    else:
        valid_terminal = reason == "duration_elapsed" and acknowledged is True
    if not valid_terminal:
        raise QtraceError("session.status_invalid", "session.status", "status reason/acknowledgement does not match state")
    _issues(value.get("warnings"), "warnings")
    _issues(value.get("errors"), "errors")
    if previous is not None:
        old_state, old_transition = previous["state"], previous["transitionMonotonicNs"]
        if ((old_state in {"sealed", "stop_incomplete"} and state != old_state) or
                _STATE_ORDER[state] < _STATE_ORDER[old_state] or transition < old_transition or
                (state != old_state and transition <= old_transition)):
            raise QtraceError("session.status_regression", "session.status", "native status regressed")
    return dict(value)


def _strict_json(raw: bytes) -> object:
    def reject_constant(value: str) -> object:
        raise ValueError("non-finite JSON number")

    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8"), parse_constant=reject_constant,
                          object_pairs_hook=reject_duplicate)
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise QtraceError("session.status_invalid", "session.status", "status is not valid strict UTF-8 JSON") from error


def _timeout(value: object, field: str) -> float:
    if type(value) not in {int, float} or not math.isfinite(float(value)) or value <= 0:
        raise QtraceError("session.request_invalid", "session.request", f"{field} must be finite and positive")
    return float(value)


def _request_config(config: object) -> UserConfig:
    if not isinstance(config, UserConfig) or config.schema_version != 1 or type(config.app) is not AppConfig or \
            type(config.target) is not TargetConfig or type(config.tracer) is not TracerConfig or type(config.scenes) is not tuple:
        raise QtraceError("session.request_invalid", "session.request", "config has an invalid shape")
    if not isinstance(config.app.package, str) or _PACKAGE.fullmatch(config.app.package) is None or \
            not isinstance(config.target.module, str) or not config.target.module:
        raise QtraceError("session.request_invalid", "session.request", "config package or module is invalid")
    tracer = config.tracer
    if tracer.profile not in {"fast", "balanced", "full"} or type(tracer.compression) is not bool or \
            type(tracer.flight_enabled) is not bool or (tracer.library is None) != (tracer.companion is None):
        raise QtraceError("session.request_invalid", "session.request", "tracer configuration is invalid")
    if not 1 <= len(config.scenes) <= 256 or len({scene.name for scene in config.scenes if hasattr(scene, "name")}) != len(config.scenes):
        raise QtraceError("session.request_invalid", "session.request", "scenes are invalid")
    names: set[str] = set()
    for scene in config.scenes:
        if type(scene) is OffsetScene:
            valid = type(scene.start_offset) is int and type(scene.end_offset) is int and 0 < scene.start_offset < scene.end_offset and scene.start_offset % 4 == 0 and scene.end_offset % 4 == 0
        elif type(scene) is SymbolScene:
            valid = isinstance(scene.symbol, str) and bool(scene.symbol)
        else:
            valid = False
        try:
            valid_name = isinstance(scene.name, str) and bool(scene.name) and len(scene.name.encode("utf-8")) <= 128 and not any(
                unicodedata.category(character) in {"Cc", "Cf", "Zl", "Zp"} for character in scene.name)
        except UnicodeEncodeError:
            valid_name = False
        if not valid or not valid_name or scene.name in names:
            raise QtraceError("session.request_invalid", "session.request", "scene is invalid")
        names.add(scene.name)
    if tracer.flight_enabled != (tracer.flight_entry_scene is not None) or (tracer.flight_entry_scene is not None and tracer.flight_entry_scene not in names):
        raise QtraceError("session.request_invalid", "session.request", "flight entry scene is invalid")
    return config


def _safe_output(path: Path) -> None:
    if any(part == ".." for part in path.parts):
        raise QtraceError("session.request_invalid", "session.request", "output contains parent traversal")
    current = Path(path.anchor) if path.is_absolute() else Path(".")
    for part in path.parts[1 if path.is_absolute() else 0:]:
        current /= part
        try:
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise QtraceError("session.request_invalid", "session.request", "output ancestor is unsafe")
        except FileNotFoundError:
            break
        except OSError as error:
            raise QtraceError("session.request_invalid", "session.request", "output path is invalid") from error


def _validate_request(request: object, timed: bool, session_id: str) -> RunRequest | MonitorRequest:
    expected = RunRequest if timed else MonitorRequest
    if not isinstance(request, expected):
        raise QtraceError("session.request_invalid", "session.request", "request type does not match command")
    if not isinstance(request.output, Path) or (request.device is not None and (not isinstance(request.device, str) or _SERIAL.fullmatch(request.device) is None)) or \
            (request.installed_action is not None and not callable(request.installed_action)):
        raise QtraceError("session.request_invalid", "session.request", "config and output are invalid")
    _request_config(request.config)
    _safe_output(request.output)
    _timeout(request.setup_timeout, "setup timeout")
    _timeout(request.adb_timeout, "ADB timeout")
    _timeout(request.pull_timeout, "pull timeout")
    if timed:
        assert isinstance(request, RunRequest)
        _timeout(request.stop_timeout, "stop timeout")
        if type(request.duration_ms) is not int or not 100 <= request.duration_ms <= 86_400_000:
            raise QtraceError("session.duration_invalid", "session.request", "duration must be 100 ms through 24 hours")
    if not _UUID4.fullmatch(session_id):
        raise QtraceError("session.id_invalid", "session.request", "session ID factory returned a non-lowercase UUIDv4")
    return request


def build_native_request(config: UserConfig, resolved: ResolvedTarget, session_id: str,
                         duration_ms: int | None) -> dict[str, object]:
    session: dict[str, object] = {"id": session_id}
    if duration_ms is not None:
        if type(duration_ms) is not int or not 100 <= duration_ms <= 86_400_000:
            raise QtraceError("session.duration_invalid", "session.request", "duration must be 100 ms through 24 hours")
        session["durationMs"] = duration_ms
    return {
        "schemaVersion": 1,
        "packageName": config.app.package,
        "targetModule": resolved.module,
        "trace": {"profile": config.tracer.profile, "compression": config.tracer.compression,
                  "lz4Level": 2, "autoBuffer": True, "bufferMb": 0, "hexdumpLimit": 32},
        "flight": {"enabled": config.tracer.flight_enabled,
                   "entryScene": config.tracer.flight_entry_scene or "", "capacityMb": 512,
                   "chunkKb": 256, "maxThreads": 256, "protectedChunks": 4},
        "scenes": [{"name": scene.name, "location": {"offset": f"0x{scene.start_offset:x}",
                                                           "endOffset": f"0x{scene.end_offset:x}"}}
                   for scene in resolved.scenes],
        "session": session,
    }


class SessionOrchestrator:
    def __init__(self, preflight: object, resolver_factory: Callable[[object], object], builder: object,
                 deployer: object, injector_factory: Callable[[object], object], collector: object,
                 clock: Clock, uuid_factory: Callable[[], str], *, report_writer: ReportWriter | None = None,
                 lock: TargetLock | None = None, device_selector: Callable[[str | None, float], object]) -> None:
        self._preflight, self._resolver_factory, self._builder, self._deployer = preflight, resolver_factory, builder, deployer
        self._injector_factory, self._collector, self._clock, self._uuid_factory = injector_factory, collector, clock, uuid_factory
        self._report_writer, self._lock = report_writer or ReportWriter(), lock or TargetLock()
        self._device_selector = device_selector

    def run(self, request: RunRequest) -> SessionResult:
        return self._execute("run", request, None)

    def monitor(self, request: MonitorRequest) -> SessionResult:
        return self._execute("monitor", request, None)

    def _execute(self, mode: str, request: RunRequest | MonitorRequest, duration_ms: int | None) -> SessionResult:
        session_id = self._uuid_factory()
        request = _validate_request(request, mode == "run", session_id)
        duration_ms = request.duration_ms if isinstance(request, RunRequest) else None
        timeline, started = [], self._clock.utc_timestamp()
        device = None
        pid: int | None = None
        resumed = False
        stage = SessionStage.PREFLIGHT
        status: Mapping[str, object] | None = None
        snapshot: tuple[str, ...] = ()
        identity = artifacts = deployment = resolved = native = None
        report_path = Path(request.output) / session_id / "report.json"

        def mark(next_stage: SessionStage) -> None:
            nonlocal stage
            stage = next_stage
            timeline.append({"stage": stage.value, "at": self._clock.utc_timestamp()})

        def publish(outcome: str, exit_code: int, error: QtraceError | None = None,
                    outputs: tuple[Path, ...] = ()) -> SessionResult:
            report = SessionReport(1, session_id, mode, outcome, stage.value, request.config.app.package,
                                   getattr(device, "serial", ""), pid, started, self._clock.utc_timestamp(), tuple(timeline),
                                   {"identity": identity}, {"artifacts": artifacts, "deployment": deployment},
                                   {"resolved": resolved}, {"config": request.config},
                                   {"request": native, "status": dict(status or {})}, (), (),
                                   None if error is None else {"code": error.code, "stage": error.stage, "detail": error.detail},
                                   tuple(str(item) for item in outputs))
            self._report_writer.write_atomic(report_path, report)
            return SessionResult(session_id, exit_code, report_path, outputs)

        context = None
        try:
            select = getattr(self._device_selector, "select", self._device_selector)
            device = select(request.device, timeout=request.adb_timeout)
            selected_device = getattr(device, "serial", None)
            if not isinstance(selected_device, str) or not selected_device:
                raise QtraceError("session.selector_invalid", "selector", "selector did not return a bound device serial")
            context = self._lock.acquire(selected_device, request.config.app.package)
            context.__enter__()
            mark(SessionStage.PREFLIGHT)
            device, identity = self._preflight.run(request.config, selected_device,
                                                    setup_timeout=request.setup_timeout, adb_timeout=request.adb_timeout)
            mark(SessionStage.RESOLVING_TARGET)
            resolved = self._resolver_factory(device).resolve(request.config)
            mark(SessionStage.BUILDING_TRACER)
            artifacts = self._builder.select_or_build(request.config.tracer, timeout=request.setup_timeout)
            mark(SessionStage.DEPLOYING)
            deployment = self._deployer.deploy(device, session_id, artifacts)
            snapshot = self._snapshot_artifacts(device, request, session_id)
            native = build_native_request(request.config, resolved, session_id, duration_ms)
            mark(SessionStage.INJECTING)
            mark(SessionStage.INSTALLING_HOOKS)
            result: InjectionResult = self._injector_factory(device).install(InjectionRequest(
                request.config.app.package, session_id, deployment.tracer_so, deployment.companion,
                native, request.setup_timeout,
            ))
            pid = result.pid
            resumed = True
            if request.installed_action is not None:
                request.installed_action(device, pid)
            if mode == "run":
                mark(SessionStage.RUNNING)
                status, host_stop_timeout = self._wait_for_seal(
                    device, request, result, session_id,
                    lambda: mark(SessionStage.STOPPING) if stage == SessionStage.RUNNING else None,
                )
                if host_stop_timeout or status["state"] == "stop_incomplete":
                    mark(SessionStage.PULLING)
                    _exit, outputs = self._collect(device, request, session_id, snapshot, status)
                    mark(SessionStage.COMPLETED)
                    return publish("stop_incomplete", EXIT_STOP_INCOMPLETE, outputs=outputs)
                mark(SessionStage.SEALED)
                mark(SessionStage.PULLING)
                exit_code, outputs = self._collect(device, request, session_id, snapshot, status)
                mark(SessionStage.COMPLETED)
                return publish("sealed", exit_code, outputs=outputs)
            mark(SessionStage.MONITORING)
            self._wait_for_exit(device, request, pid)
            mark(SessionStage.PULLING)
            final_status = self._read_final_status(device, request, result, session_id)
            status = final_status
            exit_code, outputs = self._collect(device, request, session_id, snapshot, final_status)
            mark(SessionStage.COMPLETED)
            return publish("crash_recovered" if exit_code == EXIT_PARTIAL else "process_exited", exit_code, outputs=outputs)
        except BaseException as primary:
            def note(publication_error: Exception) -> None:
                if hasattr(primary, "add_note"):
                    primary.add_note(f"report publication failed: {publication_error}")
            if isinstance(primary, KeyboardInterrupt) and resumed:
                command = f"qtrace pull --package {request.config.app.package} --latest --device {device.serial}"
                try:
                    publish("interrupted", 130, outputs=(command,))
                except Exception as publication_error:
                    note(publication_error)
                finally:
                    print(command, file=sys.stderr)
            elif isinstance(primary, QtraceError):
                try:
                    publish("error", primary.exit_code, primary)
                except Exception as publication_error:
                    note(publication_error)
            else:
                try:
                    publish("error", 1, QtraceError("session.unexpected", "session", str(primary)))
                except Exception as publication_error:
                    note(publication_error)
            raise
        finally:
            if context is not None:
                context.__exit__(*sys.exc_info())

    def _status_path(self, package: str, session_id: str) -> str:
        return f"/data/data/{package}/files/qbdi-traces/session-{session_id}.status.json"

    def _snapshot_artifacts(self, device: object, request: RunRequest | MonitorRequest,
                            session_id: str) -> tuple[str, ...]:
        directory = f"/data/data/{request.config.app.package}/files/qbdi-traces"
        target_shell = getattr(device, "target_shell", None)
        if target_shell is not None:
            try:
                raw = target_shell("ls", "-1", directory, maximum_bytes=1_048_576,
                                   timeout=request.adb_timeout)
            except BaseException as error:
                if _missing_remote(error, directory):
                    return ()
                raise
            try:
                names = tuple(line for line in raw.decode("utf-8").splitlines() if line)
            except (AttributeError, UnicodeDecodeError) as error:
                raise QtraceError("session.snapshot_invalid", "session.snapshot", "artifact snapshot is not UTF-8") from error
        else:
            raise QtraceError("session.snapshot_invalid", "session.snapshot", "bound target identity cannot list tracer artifacts")
        if len(names) > 256 or len(set(names)) != len(names) or any(
            not _artifact_basename(name) for name in names
        ):
            raise QtraceError("session.snapshot_invalid", "session.snapshot", "artifact snapshot has unsafe names")
        return names

    def _current_pid(self, device: object, package: str, timeout: float) -> int | None:
        target_shell = getattr(device, "target_shell", None)
        if target_shell is None:
            return device.pid(package)
        try:
            raw = target_shell("pidof", package, maximum_bytes=4096, timeout=timeout)
        except BaseException as error:
            failure = _process_failure(error)
            if failure is not None and failure.returncode == 1 and failure.stderr == b"":
                return None
            raise
        try:
            text = raw.decode("ascii").strip()
        except (AttributeError, UnicodeDecodeError) as error:
            raise QtraceError("session.pid_invalid", "session.pid", "pidof output is malformed") from error
        if not text:
            return None
        if not text.isdigit() or int(text) <= 0:
            raise QtraceError("session.pid_invalid", "session.pid", "pidof output is malformed")
        return int(text)

    def _read_status(self, device: object, request: RunRequest | MonitorRequest, result: InjectionResult,
                     session_id: str, previous: Mapping[str, object] | None, timeout: float | None = None) -> dict[str, object]:
        path = self._status_path(request.config.app.package, session_id)
        target_shell = getattr(device, "target_shell", None)
        timeout = request.adb_timeout if timeout is None else timeout
        raw = (target_shell("cat", path, maximum_bytes=1_048_576, timeout=timeout)
               if target_shell is not None else
               device.read_file(path, 1_048_576, timeout=timeout))
        decoded = _strict_json(raw)
        return parse_status(decoded, session_id, request.config.app.package, result.generation, result.pid,
                            result.normalized_scenes, previous)

    def _read_final_status(self, device: object, request: MonitorRequest, result: InjectionResult,
                           session_id: str) -> Mapping[str, object] | None:
        try:
            path = self._status_path(request.config.app.package, session_id)
            return self._read_status(device, request, result, session_id, None)
        except BaseException as error:
            if _missing_remote(error, path):
                return None
            raise

    def _wait_for_seal(self, device: object, request: RunRequest, result: InjectionResult,
                       session_id: str, on_stopping: Callable[[], None]) -> tuple[Mapping[str, object], bool]:
        deadline = self._clock.monotonic() + request.duration_ms / 1000.0 + request.stop_timeout
        previous = None
        saw_stop = False
        transient_count = 0
        while self._clock.monotonic() < deadline:
            try:
                remaining = deadline - self._clock.monotonic()
                timeout = min(request.adb_timeout, remaining)
                if timeout <= 0:
                    break
                current_pid = self._current_pid(device, request.config.app.package, timeout)
                if current_pid is None:
                    raise QtraceError("session.process_exited", "session.running", "injected process exited before seal")
                if current_pid != result.pid:
                    raise QtraceError("session.pid_replaced", "session.running", "package PID changed after injection")
                remaining = deadline - self._clock.monotonic()
                timeout = min(request.adb_timeout, remaining)
                if timeout <= 0:
                    break
                current = self._read_status(device, request, result, session_id, previous, timeout)
                previous, transient_count = current, 0
                if current["state"] in {"stop_requested", "stopping", "stop_incomplete", "sealed"}:
                    saw_stop = True
                    on_stopping()
                if current["state"] == "sealed":
                    if current["reason"] != "duration_elapsed" or current["stopAcknowledged"] is not True:
                        raise QtraceError(ErrorCode.STOP_NOT_ACKNOWLEDGED, "session.stop", "sealed status did not acknowledge duration stop")
                    return current, False
                if current["state"] == "stop_incomplete":
                    return current, False
            except QtraceError as error:
                if not _transient_adb(error):
                    raise
                transient_count += 1
            except (OSError, TimeoutError):
                transient_count += 1
            if transient_count >= 3 and self._clock.monotonic() + 0.1 > deadline:
                raise QtraceError(ErrorCode.ADB_UNAVAILABLE, "session.status", "ADB status polling deadline exhausted")
            self._clock.sleep(min(0.1, max(0.0, deadline - self._clock.monotonic())))
        if not saw_stop:
            if transient_count:
                raise QtraceError(ErrorCode.ADB_UNAVAILABLE, "session.status", "ADB status polling deadline exhausted")
            raise QtraceError("session.run_timeout", "session.running", "native stop did not begin before the deadline")
        assert previous is not None
        return previous, True

    def _wait_for_exit(self, device: object, request: MonitorRequest, pid: int) -> None:
        outage_deadline: float | None = None
        transient_count = 0
        while True:
            candidate_deadline = self._clock.monotonic() + request.setup_timeout
            try:
                deadline = candidate_deadline if outage_deadline is None else outage_deadline
                remaining = deadline - self._clock.monotonic()
                if remaining <= 0:
                    raise QtraceError(ErrorCode.ADB_UNAVAILABLE, "session.monitor", "ADB process polling deadline exhausted")
                current = self._current_pid(device, request.config.app.package, min(request.adb_timeout, remaining))
                transient_count, outage_deadline = 0, None
                if current is None:
                    return
                if current != pid:
                    raise QtraceError("session.pid_replaced", "session.monitor", "package PID changed after injection")
            except QtraceError as error:
                if not _transient_adb(error):
                    raise
                transient_count += 1
            except (OSError, TimeoutError):
                transient_count += 1
                if outage_deadline is None:
                    outage_deadline = self._clock.monotonic() + request.setup_timeout
            if transient_count:
                if outage_deadline is None:
                    outage_deadline = candidate_deadline
                if self._clock.monotonic() >= outage_deadline:
                    raise QtraceError(ErrorCode.ADB_UNAVAILABLE, "session.monitor", "ADB process polling deadline exhausted")
            sleep = 0.1 if outage_deadline is None else min(0.1, max(0.0, outage_deadline - self._clock.monotonic()))
            self._clock.sleep(sleep)

    def _collect(self, device: object, request: RunRequest | MonitorRequest, session_id: str,
                 snapshot: tuple[str, ...], status: Mapping[str, object] | None) -> tuple[int, tuple[Path, ...]]:
        owned = None if status is None else {**status, "artifacts": [
            name for name in status.get("artifacts", []) if name not in snapshot
        ]}
        value = self._collector.collect_session(device, request.config.app.package, session_id, owned,
                                                Path(request.output), request.pull_timeout)
        if type(value) is tuple and len(value) == 2:
            return int(value[0]), tuple(Path(item) for item in value[1])
        return int(value.exit_code), tuple(Path(item) for item in value.files)
