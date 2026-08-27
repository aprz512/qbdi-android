"""One-shot Frida startup injection with immediate connection cleanup."""

from __future__ import annotations

import json
import ipaddress
import math
import multiprocessing
import re
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from qtrace.device import AdbDevice
from qtrace.errors import ErrorCode, QtraceError
from qtrace.models import ResolvedScene


_PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z")
_UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_REMOTE_COMPONENT = re.compile(r"[A-Za-z0-9._~@:+,=-]+\Z")
_HEX_ADDRESS = re.compile(r"0x[0-9a-f]+\Z")
_AGENT_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_MAX_NATIVE_REQUEST_BYTES = 1024 * 1024
_MAX_STARTUP_ENVELOPE_BYTES = _MAX_NATIVE_REQUEST_BYTES + 64 * 1024
_MAX_MESSAGE_DETAIL_BYTES = 512
_ADB_OUTPUT_BYTES = 64 * 1024
_CLEANUP_TIMEOUT_SECONDS = 1.0
_WORKER_REAP_SECONDS = 0.2
_FRIDA_REMOTE_PORT = 27042
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_AGENT_SOURCE = Path(__file__).with_name("agent.js")


@dataclass(frozen=True)
class InjectionRequest:
    package: str
    session_id: str
    tracer_so: str
    companion: str
    native_request: Mapping[str, object]
    setup_timeout: float


@dataclass(frozen=True)
class InjectionResult:
    pid: int
    session_id: str
    generation: int
    normalized_scenes: tuple[ResolvedScene, ...]


class FridaProvider:
    """Lazy default provider; callers may inject a structural fake instead."""

    def get_device(self, device: AdbDevice, timeout: float) -> object:
        try:
            import frida  # type: ignore[import-not-found]
        except ImportError as error:
            raise QtraceError(
                "frida.python_missing",
                "inject.frida",
                "Frida Python bindings are required for injection",
            ) from error
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            _fail("frida.timeout_invalid", "inject.frida", "Frida timeout must be finite and positive")
        try:
            endpoint = _remote_frida_endpoint(device.serial)
            if endpoint is not None:
                return frida.get_device_manager().add_remote_device(endpoint)
            return frida.get_device(device.serial, timeout=float(timeout))
        except QtraceError:
            raise
        except Exception as error:
            wrapped = QtraceError(
                "frida.device_failed",
                "inject.frida",
                f"Frida device lookup failed: {error}",
            )
            raise wrapped from error


def _valid_hostname(value: str) -> bool:
    return (
        0 < len(value) <= 253
        and all(_HOST_LABEL.fullmatch(label) is not None for label in value.split("."))
    )


def _remote_frida_endpoint(serial: object) -> str | None:
    if not isinstance(serial, str) or not serial:
        _fail("frida.endpoint_invalid", "inject.frida", "ADB serial is invalid")
    if ":" not in serial:
        return None
    if serial.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:([0-9]+)", serial)
        if match is None:
            _fail("frida.endpoint_invalid", "inject.frida", "bracketed ADB endpoint is invalid")
        host, adb_port = match.groups()
        try:
            ipaddress.IPv6Address(host)
        except ipaddress.AddressValueError as error:
            wrapped = QtraceError("frida.endpoint_invalid", "inject.frida", "ADB IPv6 endpoint is invalid")
            raise wrapped from error
        rendered_host = f"[{host}]"
    else:
        host, separator, adb_port = serial.rpartition(":")
        if not separator or not host or not adb_port.isascii() or not adb_port.isdigit():
            _fail("frida.endpoint_invalid", "inject.frida", "ADB remote endpoint is invalid")
        if ":" in host:
            try:
                ipaddress.IPv6Address(host)
            except ipaddress.AddressValueError as error:
                wrapped = QtraceError("frida.endpoint_invalid", "inject.frida", "ADB IPv6 endpoint is invalid")
                raise wrapped from error
            rendered_host = f"[{host}]"
        else:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if not _valid_hostname(host):
                    _fail("frida.endpoint_invalid", "inject.frida", "ADB remote host is invalid")
            rendered_host = host
    port = int(adb_port, 10)
    if not 1 <= port <= 65535:
        _fail("frida.endpoint_invalid", "inject.frida", "ADB remote port is invalid")
    return f"{rendered_host}:{_FRIDA_REMOTE_PORT}"


def _fail(code: ErrorCode | str, stage: str, detail: str) -> None:
    raise QtraceError(code, stage, detail)


def _safe_remote_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "//" in value:
        _fail("inject.request_invalid", "inject.validate", f"{field} must be an absolute path")
    parts = value.split("/")[1:]
    if (
        not parts
        or any(
            not part
            or part in {".", ".."}
            or _REMOTE_COMPONENT.fullmatch(part) is None
            for part in parts
        )
        or str(PurePosixPath(value)) != value
    ):
        _fail("inject.request_invalid", "inject.validate", f"{field} is not a safe normalized path")
    return value


def _json_value(value: object, location: str, *, depth: int = 0) -> object:
    if depth > 64:
        _fail("inject.request_invalid", "inject.validate", "native request nesting is too deep")
    if value is None or type(value) in {bool, str}:
        return value
    if type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            _fail("inject.request_invalid", "inject.validate", f"{location} is not finite")
        return value
    if isinstance(value, Mapping):
        copied: dict[str, object] = {}
        for key, member in value.items():
            if type(key) is not str:
                _fail("inject.request_invalid", "inject.validate", f"{location} has a non-string key")
            copied[key] = _json_value(member, f"{location}.{key}", depth=depth + 1)
        return copied
    if type(value) in {list, tuple}:
        return [
            _json_value(member, f"{location}[{index}]", depth=depth + 1)
            for index, member in enumerate(value)
        ]
    _fail("inject.request_invalid", "inject.validate", f"{location} is not JSON-safe")


def _parse_hex(value: object, location: str) -> int:
    if not isinstance(value, str) or _HEX_ADDRESS.fullmatch(value) is None:
        _fail("inject.protocol_invalid", "inject.protocol", f"{location} is not normalized hexadecimal")
    return int(value, 16)


def _expected_scenes(native_request: Mapping[str, object]) -> tuple[ResolvedScene, ...]:
    scenes = native_request.get("scenes")
    if type(scenes) is not list or not scenes:
        _fail("inject.request_invalid", "inject.validate", "native request scenes must be a nonempty array")
    normalized: list[ResolvedScene] = []
    for index, value in enumerate(scenes):
        if type(value) is not dict or set(value) != {"name", "location"}:
            _fail("inject.request_invalid", "inject.validate", f"native scene {index} has invalid shape")
        name = value.get("name")
        location = value.get("location")
        if not isinstance(name, str) or not name or type(location) is not dict:
            _fail("inject.request_invalid", "inject.validate", f"native scene {index} has invalid fields")
        if set(location) != {"offset", "endOffset"}:
            _fail("inject.request_invalid", "inject.validate", f"native scene {index} is not an offset range")
        start = _request_hex(location.get("offset"), f"native scene {index} offset")
        end = _request_hex(location.get("endOffset"), f"native scene {index} end offset")
        if start <= 0 or end <= start:
            _fail("inject.request_invalid", "inject.validate", f"native scene {index} range is invalid")
        normalized.append(ResolvedScene(name, start, end))
    if len({scene.name for scene in normalized}) != len(normalized):
        _fail("inject.request_invalid", "inject.validate", "native scene names must be unique")
    return tuple(normalized)


def _request_hex(value: object, location: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-fA-F]+", value) is None:
        _fail("inject.request_invalid", "inject.validate", f"{location} is not hexadecimal")
    return int(value, 16)


@dataclass(frozen=True)
class _ValidatedRequest:
    request: InjectionRequest
    native_request: dict[str, object]
    expected_scenes: tuple[ResolvedScene, ...]
    request_device: AdbDevice


def _validate_request(request: InjectionRequest, device: AdbDevice) -> _ValidatedRequest:
    if not isinstance(request, InjectionRequest):
        _fail("inject.request_invalid", "inject.validate", "request must be an InjectionRequest")
    if not isinstance(request.package, str) or _PACKAGE.fullmatch(request.package) is None:
        _fail("inject.request_invalid", "inject.validate", "package name is invalid")
    bound_package = getattr(device, "package", None)
    if bound_package is not None and bound_package != request.package:
        _fail("inject.request_invalid", "inject.validate", "package does not match the selected device binding")
    if not isinstance(request.session_id, str) or _UUID4.fullmatch(request.session_id) is None:
        _fail("inject.request_invalid", "inject.validate", "session ID must be a lowercase UUIDv4")
    _safe_remote_path(request.tracer_so, "tracer path")
    _safe_remote_path(request.companion, "companion path")
    if (
        isinstance(request.setup_timeout, bool)
        or not isinstance(request.setup_timeout, (int, float))
        or not math.isfinite(request.setup_timeout)
        or request.setup_timeout <= 0
    ):
        _fail("inject.request_invalid", "inject.validate", "setup timeout must be finite and positive")
    if not isinstance(request.native_request, Mapping):
        _fail("inject.request_invalid", "inject.validate", "native request must be an object")
    copied = _json_value(request.native_request, "native request")
    assert type(copied) is dict
    if copied.get("packageName") != request.package:
        _fail("inject.request_invalid", "inject.validate", "native package does not match injection package")
    target_module = copied.get("targetModule")
    if not isinstance(target_module, str) or not target_module:
        _fail("inject.request_invalid", "inject.validate", "native target module is invalid")
    native_session = copied.get("session")
    if type(native_session) is not dict or native_session.get("id") != request.session_id:
        _fail("inject.request_invalid", "inject.validate", "native session does not match injection session")
    expected_scenes = _expected_scenes(copied)
    try:
        encoded = json.dumps(
            copied,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        wrapped = QtraceError("inject.request_invalid", "inject.validate", f"native request is not JSON-safe: {error}")
        raise wrapped from error
    if not encoded or len(encoded) > _MAX_NATIVE_REQUEST_BYTES:
        _fail("inject.request_invalid", "inject.validate", "serialized native request exceeds 1 MiB")
    return _ValidatedRequest(request, copied, expected_scenes, device)


def _exact_object(value: object, keys: set[str], location: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        _fail("inject.protocol_invalid", "inject.protocol", f"{location} has invalid shape")
    return value


def _validate_session(value: object, validated: _ValidatedRequest) -> None:
    session = _exact_object(value, {"id", "durationMs"}, "native session")
    native_session = validated.native_request["session"]
    assert type(native_session) is dict
    expected_duration = native_session.get("durationMs", 0)
    if (
        session.get("id") != validated.request.session_id
        or type(session.get("durationMs")) is not int
        or session.get("durationMs") != expected_duration
    ):
        _fail("inject.protocol_invalid", "inject.protocol", "native session does not match the request")


def _common_status(
    value: object,
    validated: _ValidatedRequest,
    *,
    generation: int | None,
    final: bool,
) -> dict[str, object]:
    keys = {
        "responseSchemaVersion",
        "ok",
        "generation",
        "state",
        "targetModule",
        "session",
        "scenes",
        "warnings",
    }
    if final:
        keys.add("moduleBase")
    status = _exact_object(value, keys, "native status")
    status_generation = status.get("generation")
    if (
        type(status.get("responseSchemaVersion")) is not int
        or status.get("responseSchemaVersion") != 1
        or status.get("ok") is not True
        or type(status_generation) is not int
        or status_generation <= 0
    ):
        _fail("inject.protocol_invalid", "inject.protocol", "native status header is invalid")
    if generation is not None and status_generation != generation:
        _fail("inject.protocol_invalid", "inject.protocol", "native generation changed during setup")
    if status.get("targetModule") != validated.native_request.get("targetModule"):
        _fail("inject.protocol_invalid", "inject.protocol", "native target module does not match the request")
    if type(status.get("warnings")) is not list:
        _fail("inject.protocol_invalid", "inject.protocol", "native warnings are malformed")
    _validate_session(status.get("session"), validated)
    return status


def _validate_initialized(
    payload: dict[str, object], validated: _ValidatedRequest
) -> tuple[int, tuple[ResolvedScene, ...]]:
    if set(payload) != {"type", "sessionId", "generation", "status"}:
        _fail("inject.protocol_invalid", "inject.protocol", "initialized message has invalid shape")
    if payload.get("sessionId") != validated.request.session_id:
        _fail("inject.protocol_invalid", "inject.protocol", "initialized session ID is invalid")
    generation = payload.get("generation")
    if type(generation) is not int or generation <= 0:
        _fail("inject.protocol_invalid", "inject.protocol", "initialized generation is invalid")
    status = _common_status(payload.get("status"), validated, generation=generation, final=False)
    if status.get("state") != "waiting_for_module":
        _fail("inject.protocol_invalid", "inject.protocol", "initial native state is not waiting_for_module")
    scenes = status.get("scenes")
    if type(scenes) is not list or len(scenes) != len(validated.expected_scenes):
        _fail("inject.protocol_invalid", "inject.protocol", "initialized scenes are malformed")
    normalized: list[ResolvedScene] = []
    for index, (value, expected) in enumerate(zip(scenes, validated.expected_scenes)):
        scene = _exact_object(value, {"name", "offset", "endOffset"}, f"initialized scene {index}")
        start = _parse_hex(scene.get("offset"), f"initialized scene {index} offset")
        end = _parse_hex(scene.get("endOffset"), f"initialized scene {index} end offset")
        current = ResolvedScene(str(scene.get("name")), start, end)
        if current != expected:
            _fail("inject.protocol_invalid", "inject.protocol", "initialized scenes do not match the request")
        normalized.append(current)
    return generation, tuple(normalized)


def _optional_runtime_address(value: object, location: str) -> None:
    if value is not None:
        _parse_hex(value, location)


def _validate_installed(
    payload: dict[str, object],
    validated: _ValidatedRequest,
    generation: int,
    normalized_scenes: tuple[ResolvedScene, ...],
) -> None:
    if set(payload) != {"type", "sessionId", "generation", "status"}:
        _fail("inject.protocol_invalid", "inject.protocol", "installed message has invalid shape")
    if payload.get("sessionId") != validated.request.session_id or payload.get("generation") != generation:
        _fail("inject.protocol_invalid", "inject.protocol", "installed identity does not match initialization")
    status = _common_status(payload.get("status"), validated, generation=generation, final=True)
    if status.get("state") != "installed":
        _fail("inject.protocol_invalid", "inject.protocol", "final native state is not installed")
    _optional_runtime_address(status.get("moduleBase"), "native module base")
    scenes = status.get("scenes")
    if type(scenes) is not list or len(scenes) != len(normalized_scenes):
        _fail("inject.protocol_invalid", "inject.protocol", "installed scenes are malformed")
    for index, (value, expected) in enumerate(zip(scenes, normalized_scenes)):
        scene = _exact_object(
            value,
            {"name", "offset", "runtimeAddress", "runtimeEnd", "state", "warnings"},
            f"installed scene {index}",
        )
        if (
            scene.get("name") != expected.name
            or _parse_hex(scene.get("offset"), f"installed scene {index} offset") != expected.start_offset
            or scene.get("state") != "installed"
            or type(scene.get("warnings")) is not list
        ):
            _fail("inject.protocol_invalid", "inject.protocol", "installed scenes do not match initialization")
        _optional_runtime_address(scene.get("runtimeAddress"), f"installed scene {index} runtime address")
        _optional_runtime_address(scene.get("runtimeEnd"), f"installed scene {index} runtime end")


class _Mailbox:
    def __init__(self, validated: _ValidatedRequest, pid: int):
        self.validated = validated
        self.pid = pid
        self.event = threading.Event()
        self.lock = threading.Lock()
        self.events: list[tuple[object, ...]] = []
        self.posted = False
        self.resume_phase = "before"
        self.initialized = False
        self.installed = False
        self.generation: int | None = None
        self.normalized_scenes: tuple[ResolvedScene, ...] | None = None

    def mark_posted(self) -> None:
        with self.lock:
            self.posted = True

    def mark_resume_started(self) -> None:
        with self.lock:
            self.resume_phase = "resuming"

    def mark_resumed(self) -> None:
        with self.lock:
            self.resume_phase = "resumed"

    def on_message(self, message: object, data: object) -> None:
        with self.lock:
            self.events.append(("message", message, data, self.posted, self.resume_phase))
            self.event.set()

    def on_detached(self, reason: object, *details: object) -> None:
        with self.lock:
            self.events.append(("detached", reason, details))
            self.event.set()

    def wait_for(self, phase: str, deadline: float) -> None:
        while True:
            with self.lock:
                events = self.events
                self.events = []
                self.event.clear()
            detached = next((event for event in events if event[0] == "detached"), None)
            if detached is not None:
                self._raise_detached(detached[1])
            for event in events:
                if event[0] == "message":
                    self._accept(event[1], event[2], event[3], event[4])
            reached = self.initialized if phase == "initialized" else self.installed
            if reached:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.event.wait(remaining):
                _fail("inject.timeout", "inject.wait", "setup deadline expired")

    def _raise_detached(self, reason: object) -> None:
        if reason == "process-terminated":
            _fail(
                ErrorCode.PROCESS_EXITED_DURING_SETUP,
                "inject.wait",
                f"spawned PID {self.pid} exited during setup: process-terminated",
            )
        _fail(
            "frida.session_detached",
            "inject.wait",
            f"Frida session for PID {self.pid} detached during setup: {reason}",
        )

    def _accept(
        self,
        message: object,
        data: object,
        posted: bool,
        arrival_resume_phase: object,
    ) -> None:
        if not posted:
            _fail("inject.protocol_invalid", "inject.protocol", "agent message arrived before startup request")
        if data is not None:
            _fail("inject.protocol_invalid", "inject.protocol", "agent message data must be empty")
        if type(message) is not dict:
            _fail("inject.protocol_invalid", "inject.protocol", "agent message must be an object")
        outer_type = message.get("type")
        if outer_type == "error":
            detail = message.get("description", "Frida script error")
            _fail("frida.script_error", "inject.agent", f"Frida script failed: {detail}")
        if outer_type != "send" or set(message) != {"type", "payload"}:
            _fail("inject.protocol_invalid", "inject.protocol", "agent message outer shape is invalid")
        payload = message.get("payload")
        if type(payload) is not dict:
            _fail("inject.protocol_invalid", "inject.protocol", "agent payload must be an object")
        message_type = payload.get("type")
        if message_type == "error":
            if set(payload) != {"type", "stage", "code", "detail"}:
                _fail("inject.protocol_invalid", "inject.protocol", "agent error has invalid shape")
            stage, code, detail = payload.get("stage"), payload.get("code"), payload.get("detail")
            if (
                not isinstance(stage, str)
                or not stage
                or not isinstance(code, str)
                or _AGENT_ERROR_CODE.fullmatch(code) is None
                or not isinstance(detail, str)
                or not detail
                or len(detail.encode("utf-8", errors="replace")) > _MAX_MESSAGE_DETAIL_BYTES
            ):
                _fail("inject.protocol_invalid", "inject.protocol", "agent error fields are invalid")
            _fail(code, f"inject.agent.{stage}", detail)
        if message_type == "initialized":
            if self.initialized or self.installed:
                _fail("inject.protocol_invalid", "inject.protocol", "duplicate or late initialized message")
            generation, scenes = _validate_initialized(payload, self.validated)
            self.generation = generation
            self.normalized_scenes = scenes
            self.initialized = True
            return
        if message_type == "installed":
            if not self.initialized:
                _fail("inject.protocol_invalid", "inject.protocol", "installed message preceded initialization")
            if arrival_resume_phase == "before" or self.resume_phase != "resumed":
                _fail("inject.protocol_invalid", "inject.protocol", "installed message preceded successful resume")
            if self.installed:
                _fail("inject.protocol_invalid", "inject.protocol", "duplicate installed message")
            assert self.generation is not None and self.normalized_scenes is not None
            _validate_installed(
                payload,
                self.validated,
                self.generation,
                self.normalized_scenes,
            )
            self.installed = True
            return
        _fail("inject.protocol_invalid", "inject.protocol", "agent payload type is not allowed")


def _external(code: str, stage: str, operation):
    try:
        return operation()
    except QtraceError:
        raise
    except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
        wrapped = QtraceError(code, stage, f"operation failed: {error}")
        raise wrapped from error


def _send_worker_event(channel: Any, kind: str, payload: object) -> None:
    try:
        channel.send((kind, payload))
    except (BrokenPipeError, EOFError, OSError):
        pass


def _serialize_worker_error(error: BaseException) -> dict[str, object]:
    if isinstance(error, QtraceError):
        return {
            "kind": "qtrace",
            "code": error.code,
            "stage": error.stage,
            "detail": error.detail,
            "exitCode": error.exit_code,
        }
    if isinstance(error, KeyboardInterrupt):
        return {"kind": "keyboard_interrupt"}
    if isinstance(error, SystemExit):
        return {"kind": "system_exit", "code": error.code}
    wrapped = QtraceError("inject.failed", "inject", f"injection failed: {error}")
    return {
        "kind": "qtrace",
        "code": wrapped.code,
        "stage": wrapped.stage,
        "detail": wrapped.detail,
        "exitCode": wrapped.exit_code,
    }


def _restore_worker_error(payload: object) -> BaseException:
    if type(payload) is not dict or not isinstance(payload.get("kind"), str):
        return QtraceError("frida.worker_protocol_invalid", "inject.worker", "worker error payload is malformed")
    if payload["kind"] == "keyboard_interrupt" and set(payload) == {"kind"}:
        return KeyboardInterrupt()
    if payload["kind"] == "system_exit" and set(payload) == {"kind", "code"}:
        return SystemExit(payload.get("code"))
    if payload["kind"] == "qtrace" and set(payload) == {
        "kind", "code", "stage", "detail", "exitCode",
    }:
        code, stage, detail, exit_code = (
            payload.get("code"), payload.get("stage"), payload.get("detail"), payload.get("exitCode")
        )
        if (
            isinstance(code, str)
            and isinstance(stage, str)
            and isinstance(detail, str)
            and type(exit_code) is int
        ):
            return QtraceError(code, stage, detail, exit_code=exit_code)
    return QtraceError("frida.worker_protocol_invalid", "inject.worker", "worker error payload is malformed")


def _run_injection_worker(
    validated: _ValidatedRequest,
    source: str,
    provider: FridaProvider,
    deadline: float,
    channel: Any,
) -> None:
    request = validated.request
    session: Any | None = None
    script: Any | None = None
    primary: BaseException | None = None
    result: InjectionResult | None = None

    def budget() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail("inject.timeout", "inject.wait", "setup deadline expired")
        return remaining

    try:
        frida_device = _external(
            "frida.device_failed",
            "inject.frida",
            lambda: provider.get_device(validated.request_device, budget()),
        )
        pid_value = _external(
            "frida.spawn_failed",
            "inject.spawn",
            lambda: frida_device.spawn([request.package]),
        )
        if type(pid_value) is not int or pid_value <= 0:
            _fail("frida.spawn_failed", "inject.spawn", "Frida returned an invalid spawned PID")
        pid = pid_value
        _send_worker_event(channel, "pid", pid)
        session = _external(
            "frida.attach_failed",
            "inject.attach",
            lambda: frida_device.attach(pid),
        )
        mailbox = _Mailbox(validated, pid)
        _external(
            "frida.handler_failed",
            "inject.attach",
            lambda: session.on("detached", mailbox.on_detached),
        )
        script = _external(
            "frida.script_failed",
            "inject.load",
            lambda: session.create_script(source),
        )
        _external(
            "frida.handler_failed",
            "inject.load",
            lambda: script.on("message", mailbox.on_message),
        )
        _external("frida.load_failed", "inject.load", script.load)
        remaining_ms = max(1, int(budget() * 1000))
        envelope = {
            "package": request.package,
            "sessionId": request.session_id,
            "tracerSo": request.tracer_so,
            "companion": request.companion,
            "nativeRequest": validated.native_request,
            "setupTimeoutMs": remaining_ms,
        }
        envelope_size = len(json.dumps(
            envelope,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8"))
        if envelope_size > _MAX_STARTUP_ENVELOPE_BYTES:
            _fail("inject.request_invalid", "inject.validate", "startup envelope exceeds its size bound")
        mailbox.mark_posted()
        _external(
            "frida.post_failed",
            "inject.initialize",
            lambda: script.post({"type": "qtrace-startup", "payload": envelope}),
        )
        mailbox.wait_for("initialized", deadline)
        mailbox.mark_resume_started()
        _external(
            "frida.resume_failed",
            "inject.resume",
            lambda: frida_device.resume(pid),
        )
        mailbox.mark_resumed()
        _send_worker_event(channel, "resumed", pid)
        mailbox.wait_for("installed", deadline)
        assert mailbox.generation is not None and mailbox.normalized_scenes is not None
        result = InjectionResult(
            pid=pid,
            session_id=request.session_id,
            generation=mailbox.generation,
            normalized_scenes=mailbox.normalized_scenes,
        )
    except BaseException as error:
        primary = error
    finally:
        if primary is not None:
            _send_worker_event(channel, "error", _serialize_worker_error(primary))
        else:
            _send_worker_event(channel, "result", result)
        cleanup_error: BaseException | None = None
        for callback in (
            getattr(script, "unload", None) if script is not None else None,
            getattr(session, "detach", None) if session is not None else None,
        ):
            if callback is None:
                continue
            try:
                callback()
            except BaseException as error:
                cleanup_error = cleanup_error or error
        _send_worker_event(
            channel,
            "complete",
            None if cleanup_error is None else _serialize_worker_error(
                QtraceError("frida.cleanup_failed", "inject.cleanup", f"Frida cleanup failed: {cleanup_error}")
            ),
        )
        channel.close()


@dataclass
class _WorkerState:
    pid: int | None = None
    resumed: bool = False
    outcome_kind: str | None = None
    outcome: object = None
    complete: bool = False
    cleanup_error: object = None


def _record_worker_event(state: _WorkerState, event: object) -> None:
    if type(event) is not tuple or len(event) != 2:
        _fail("frida.worker_protocol_invalid", "inject.worker", "worker event is malformed")
    kind, payload = event
    if state.complete:
        _fail("frida.worker_protocol_invalid", "inject.worker", "worker event followed completion")
    if kind == "pid":
        if state.pid is not None or state.outcome_kind is not None or type(payload) is not int or payload <= 0:
            _fail("frida.worker_protocol_invalid", "inject.worker", "worker PID event is invalid")
        state.pid = payload
        return
    if kind == "resumed":
        if state.pid is None or state.resumed or state.outcome_kind is not None or payload != state.pid:
            _fail("frida.worker_protocol_invalid", "inject.worker", "worker resumed event is invalid")
        state.resumed = True
        return
    if kind == "result":
        if (
            state.pid is None
            or not state.resumed
            or state.outcome_kind is not None
            or not isinstance(payload, InjectionResult)
            or payload.pid != state.pid
        ):
            _fail("frida.worker_protocol_invalid", "inject.worker", "worker result event is invalid")
        state.outcome_kind = "result"
        state.outcome = payload
        return
    if kind == "error":
        if state.outcome_kind is not None:
            _fail("frida.worker_protocol_invalid", "inject.worker", "worker error event is duplicate")
        state.outcome_kind = "error"
        state.outcome = payload
        return
    if kind == "complete":
        if state.outcome_kind is None:
            _fail("frida.worker_protocol_invalid", "inject.worker", "worker completed before an outcome")
        if payload is not None and type(payload) is not dict:
            _fail("frida.worker_protocol_invalid", "inject.worker", "worker cleanup payload is malformed")
        state.complete = True
        state.cleanup_error = payload
        return
    _fail("frida.worker_protocol_invalid", "inject.worker", "worker event type is unknown")


def _kill_and_reap_worker(worker: Any, graceful_timeout: float) -> bool:
    worker.join(max(0.0, graceful_timeout))
    if not worker.is_alive():
        return False
    worker.kill()
    worker.join(_WORKER_REAP_SECONDS)
    if worker.is_alive():
        worker.kill()
        worker.join(_WORKER_REAP_SECONDS)
    if worker.is_alive():
        _fail("frida.worker_reap_failed", "inject.worker", "Frida worker survived SIGKILL")
    return True


class FridaInjector:
    def __init__(self, device: AdbDevice, frida_provider: FridaProvider):
        self._device = device
        self._frida_provider: FridaProvider | None = frida_provider

    def install(self, request: InjectionRequest) -> InjectionResult:
        validated = _validate_request(request, self._device)
        try:
            source = _AGENT_SOURCE.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            wrapped = QtraceError("inject.agent_unavailable", "inject.prepare", f"cannot read fixed agent: {error}")
            raise wrapped from error
        if not hasattr(multiprocessing, "get_context") or "fork" not in multiprocessing.get_all_start_methods():
            _fail("frida.isolation_unavailable", "inject.worker", "Frida injection requires POSIX fork isolation")
        provider = self._frida_provider
        self._frida_provider = None
        if provider is None:
            _fail("frida.provider_unavailable", "inject.frida", "injector has already consumed its Frida provider")
        deadline = time.monotonic() + float(request.setup_timeout)

        def budget() -> float:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("inject.timeout", "inject.wait", "setup deadline expired")
            return remaining

        _external(
            "device.force_stop_failed",
            "inject.force_stop",
            lambda: self._device.shell(
                "am", "force-stop", request.package,
                timeout=budget(), maximum_bytes=_ADB_OUTPUT_BYTES,
            ),
        )
        context = multiprocessing.get_context("fork")
        receiver, sender = context.Pipe(duplex=False)
        worker = context.Process(
            target=_run_injection_worker,
            args=(validated, source, provider, deadline, sender),
            name="qtrace-frida-owner",
        )
        state = _WorkerState()
        worker_started = False
        forced = False
        timed_out = False
        monitor_error: BaseException | None = None
        worker_exitcode: int | None = None
        try:
            worker.start()
            worker_started = True
            sender.close()
            provider = None
            while not state.complete:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not receiver.poll(remaining):
                    timed_out = True
                    break
                try:
                    event = receiver.recv()
                except EOFError:
                    break
                _record_worker_event(state, event)
        except BaseException as error:
            monitor_error = error
        finally:
            if worker_started and (timed_out or monitor_error is not None or not state.complete):
                for _index in range(32):
                    if not receiver.poll(0):
                        break
                    try:
                        _record_worker_event(state, receiver.recv())
                    except EOFError:
                        break
                    except BaseException as error:
                        monitor_error = monitor_error or error
                        break
            try:
                if worker_started:
                    graceful = max(0.0, deadline - time.monotonic()) if state.complete else 0.0
                    forced = _kill_and_reap_worker(worker, graceful)
                    worker_exitcode = worker.exitcode
            except BaseException as error:
                monitor_error = monitor_error or error
            finally:
                receiver.close()
                sender.close()
                if worker_started and not worker.is_alive():
                    worker.close()

        cleanup_error: BaseException | None = None
        if state.pid is not None and not state.resumed:
            try:
                self._device.target_shell(
                    "kill", "-9", str(state.pid),
                    timeout=min(_CLEANUP_TIMEOUT_SECONDS, float(request.setup_timeout)),
                    maximum_bytes=_ADB_OUTPUT_BYTES,
                )
            except BaseException as error:
                cleanup_error = error

        if monitor_error is not None:
            raise monitor_error
        if state.outcome_kind == "error":
            raise _restore_worker_error(state.outcome)
        if timed_out or forced or not state.complete:
            _fail("inject.timeout", "inject.wait", "Frida setup worker exceeded the setup deadline")
        if worker_exitcode != 0:
            _fail("frida.worker_failed", "inject.worker", f"Frida worker exited with status {worker_exitcode}")
        if cleanup_error is not None:
            if isinstance(cleanup_error, QtraceError):
                raise cleanup_error
            wrapped = QtraceError("device.kill_failed", "inject.cleanup", f"spawned PID cleanup failed: {cleanup_error}")
            raise wrapped from cleanup_error
        if state.cleanup_error is not None:
            raise _restore_worker_error(state.cleanup_error)
        if state.outcome_kind != "result" or not isinstance(state.outcome, InjectionResult):
            _fail("frida.worker_failed", "inject.worker", "Frida worker exited without a result")
        return state.outcome
