"""Validated, bounded ADB access for qtrace."""

from __future__ import annotations

import math
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from scripts.bounded_process import BoundedProcessError

from qtrace.errors import ErrorCode, QtraceError


_SAFE_SHELL_TOKEN = re.compile(r"[A-Za-z0-9._/@:+,=-]+\Z")
_SAFE_PATH_COMPONENT = re.compile(r"[A-Za-z0-9._@:+,=-]+\Z")
_SAFE_SERIAL = re.compile(r"[A-Za-z0-9._:@+-]+\Z")
_PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z")
_MAX_ADB_LIST_BYTES = 64 * 1024
_ADB_LIST_TIMEOUT_SECONDS = 10.0
_MAX_APK_MEMBER_BYTES = 512 * 1024 * 1024


class CommandRunner(Protocol):
    def capture(
        self, command, *, maximum_bytes: int, timeout: float
    ) -> bytes: ...


@dataclass(frozen=True)
class DeviceIdentity:
    serial: str
    abi: str
    api_level: int
    access_mode: str
    frida_host_version: str
    frida_server_version: str
    free_bytes: int


def _fail(code: ErrorCode | str, stage: str, detail: str) -> None:
    raise QtraceError(code, stage, detail)


def _validate_serial(serial: str) -> str:
    if not isinstance(serial, str) or _SAFE_SERIAL.fullmatch(serial) is None:
        _fail("device.serial_invalid", "device.select", "device serial is unsafe or empty")
    return serial


def _validate_package(package: str) -> str:
    if not isinstance(package, str) or _PACKAGE.fullmatch(package) is None:
        _fail("device.package_invalid", "device", "package name is invalid")
    return package


def _validate_remote_path(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or "//" in path:
        _fail("device.path_invalid", "device", "remote path must be an absolute normalized path")
    parts = path.split("/")[1:]
    if not parts or any(
        not part or part in {".", ".."} or _SAFE_PATH_COMPONENT.fullmatch(part) is None
        for part in parts
    ):
        _fail("device.path_invalid", "device", "remote path contains an unsafe component")
    normalized = str(PurePosixPath(path))
    if normalized != path:
        _fail("device.path_invalid", "device", "remote path must be normalized")
    return path


def _validate_archive_member(member: str) -> str:
    if not isinstance(member, str) or member.startswith("/") or "//" in member:
        _fail("device.member_invalid", "device.pull_member", "APK member path is invalid")
    parts = member.split("/")
    if not parts or any(
        not part or part in {".", ".."} or _SAFE_PATH_COMPONENT.fullmatch(part) is None
        for part in parts
    ):
        _fail("device.member_invalid", "device.pull_member", "APK member path is unsafe")
    return member


def _shell_tokens(arguments: tuple[str, ...]) -> tuple[str, ...]:
    """The sole device-shell composition seam; every token is allow-listed."""
    if not arguments:
        _fail("device.shell_invalid", "device.shell", "shell command must not be empty")
    for token in arguments:
        if not isinstance(token, str) or _SAFE_SHELL_TOKEN.fullmatch(token) is None:
            _fail("device.shell_token_unsafe", "device.shell", "shell token contains unsafe characters")
    return arguments


def _decode(output: bytes, *, stage: str) -> str:
    if not isinstance(output, bytes):
        _fail("device.output_malformed", stage, "ADB returned non-byte output")
    try:
        return output.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _fail("device.output_malformed", stage, "ADB output is not UTF-8")


def _regular_file(path: Path, *, stage: str) -> Path:
    candidate = Path(path)
    try:
        mode = candidate.lstat().st_mode
    except (OSError, TypeError, ValueError) as error:
        _fail("host.file_invalid", stage, f"host file is unavailable: {error}")
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        _fail("host.file_invalid", stage, "host path must be a regular non-symlink file")
    return candidate


def _validate_limits(maximum_bytes: int, timeout: float, *, stage: str) -> tuple[int, float]:
    if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or maximum_bytes <= 0:
        _fail("device.bound_invalid", stage, "output bound must be a positive integer")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        _fail("device.timeout_invalid", stage, "timeout must be finite and positive")
    return maximum_bytes, float(timeout)


class AdbDevice:
    def __init__(self, serial: str, runner: CommandRunner):
        self.serial = _validate_serial(serial)
        self.runner = runner
        self._package: str | None = None
        self._access_mode: str | None = None

    @property
    def package(self) -> str | None:
        return self._package

    @property
    def access_mode(self) -> str | None:
        return self._access_mode

    def bind_package(self, package: str, access_mode: str) -> None:
        """Bind validated deployment identity once; conflicting reuse is forbidden."""
        validated = _validate_package(package)
        if access_mode not in {"root", "run-as"}:
            _fail("device.access_mode_invalid", "device.bind", "access mode is invalid")
        binding = (validated, access_mode)
        if self._package is None and self._access_mode is None:
            self._package, self._access_mode = binding
            return
        if (self._package, self._access_mode) != binding:
            _fail(
                "device.binding_conflict",
                "device.bind",
                "device is already bound to a different package or access mode",
            )

    def command(self, *args: str) -> list[str]:
        if any(not isinstance(argument, str) or not argument or "\0" in argument for argument in args):
            _fail("device.command_invalid", "device", "ADB arguments must be nonempty strings without NUL")
        if args and args[0] == "shell":
            _shell_tokens(tuple(args[1:]))
        return ["adb", "-s", self.serial, *args]

    def _capture(
        self,
        arguments: tuple[str, ...],
        *,
        timeout: float,
        maximum_bytes: int,
        stage: str,
    ) -> bytes:
        maximum_bytes, timeout = _validate_limits(maximum_bytes, timeout, stage=stage)
        try:
            return self.runner.capture(
                self.command(*arguments),
                maximum_bytes=maximum_bytes,
                timeout=timeout,
            )
        except QtraceError:
            raise
        except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
            wrapped = QtraceError("device.command_failed", stage, f"ADB command failed: {error}")
            raise wrapped from error

    def shell(
        self,
        *args: str,
        timeout: float = 30.0,
        maximum_bytes: int = 1_048_576,
    ) -> bytes:
        tokens = _shell_tokens(tuple(args))
        return self._capture(
            ("shell", *tokens),
            timeout=timeout,
            maximum_bytes=maximum_bytes,
            stage="device.shell",
        )

    def package_apk_paths(
        self, package: str, *, timeout: float = 30.0
    ) -> tuple[str, ...]:
        package = _validate_package(package)
        output = self.shell("pm", "path", package, timeout=timeout, maximum_bytes=256 * 1024)
        text = _decode(output, stage="preflight.package")
        paths: list[str] = []
        for line in text.splitlines():
            if not line.startswith("package:") or line.count("package:") != 1:
                _fail("device.output_malformed", "preflight.package", "malformed pm path output")
            path = _validate_remote_path(line[len("package:"):])
            if path in paths:
                _fail("device.output_malformed", "preflight.package", "duplicate package path")
            paths.append(path)
        if not paths:
            _fail(
                ErrorCode.PACKAGE_NOT_INSTALLED,
                "preflight.package",
                f"package is not installed: {package}",
            )
        return tuple(paths)

    def pid(self, package: str) -> int | None:
        package = _validate_package(package)
        try:
            output = self.shell("pidof", package, maximum_bytes=4096)
        except QtraceError as error:
            cause = error.__cause__
            no_match = (
                isinstance(cause, BoundedProcessError)
                and cause.returncode == 1
                and not cause.stderr.strip()
            )
            if no_match:
                return None
            raise
        try:
            text = _decode(output, stage="device.pid").strip()
        except QtraceError as error:
            wrapped = QtraceError("device.pid_malformed", "device.pid", "pidof output is malformed")
            raise wrapped from error
        if not text:
            return None
        if not text.isascii() or not text.isdigit():
            _fail("device.pid_malformed", "device.pid", "pidof output is malformed")
        value = int(text, 10)
        if value <= 0:
            _fail("device.pid_malformed", "device.pid", "pidof returned a non-positive PID")
        return value

    def install(self, apk: Path, *, timeout: float = 30.0) -> None:
        apk = _regular_file(Path(apk), stage="preflight.install")
        output = self._capture(
            ("install", "-r", str(apk)),
            timeout=timeout,
            maximum_bytes=256 * 1024,
            stage="preflight.install",
        )
        text = _decode(output, stage="preflight.install").strip()
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines or lines[-1] != "Success" or any(line.startswith("Failure") for line in lines):
            _fail("device.install_failed", "preflight.install", "adb install did not report success")

    def push(self, source: Path, destination: str, *, timeout: float = 30.0) -> None:
        source = _regular_file(Path(source), stage="deploy.push")
        destination = _validate_remote_path(destination)
        self._capture(
            ("push", str(source), destination),
            timeout=timeout,
            maximum_bytes=256 * 1024,
            stage="deploy.push",
        )

    def read_file(
        self,
        path: str,
        maximum_bytes: int = 1_048_576,
        *,
        timeout: float = 30.0,
    ) -> bytes:
        path = _validate_remote_path(path)
        return self.shell("cat", path, timeout=timeout, maximum_bytes=maximum_bytes)

    def pull_member(
        self,
        apk_path: str,
        member: str,
        destination: Path,
        *,
        timeout: float = 30.0,
    ) -> Path:
        apk_path = _validate_remote_path(apk_path)
        member = _validate_archive_member(member)
        output = self._capture(
            ("exec-out", "unzip", "-p", apk_path, member),
            timeout=timeout,
            maximum_bytes=_MAX_APK_MEMBER_BYTES,
            stage="device.pull_member",
        )
        if not output:
            _fail("device.member_missing", "device.pull_member", "APK member is empty or missing")
        destination = Path(destination)
        try:
            try:
                destination_mode = destination.lstat().st_mode
            except FileNotFoundError:
                destination_mode = None
            if destination_mode is not None and stat.S_ISLNK(destination_mode):
                _fail(
                    "host.destination_invalid",
                    "device.pull_member",
                    "destination must not be a symlink",
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(output)
        except QtraceError:
            raise
        except (OSError, TypeError, ValueError) as error:
            wrapped = QtraceError(
                "host.write_failed",
                "device.pull_member",
                f"cannot write extracted APK member: {error}",
            )
            raise wrapped from error
        return destination


class DeviceSelector:
    def __init__(self, runner: CommandRunner):
        self.runner = runner

    def select(
        self, requested_device: str | None, *, timeout: float = _ADB_LIST_TIMEOUT_SECONDS
    ) -> AdbDevice:
        if requested_device is not None:
            _validate_serial(requested_device)
        _maximum_bytes, timeout = _validate_limits(
            _MAX_ADB_LIST_BYTES, timeout, stage="device.select"
        )
        try:
            output = self.runner.capture(
                ("adb", "devices"),
                maximum_bytes=_MAX_ADB_LIST_BYTES,
                timeout=timeout,
            )
        except QtraceError as error:
            wrapped = QtraceError(ErrorCode.ADB_UNAVAILABLE, "device.select", error.detail)
            raise wrapped from error
        except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
            wrapped = QtraceError(ErrorCode.ADB_UNAVAILABLE, "device.select", f"adb devices failed: {error}")
            raise wrapped from error

        text = _decode(output, stage="device.select")
        lines = text.splitlines()
        if not lines or lines[0].strip() != "List of devices attached":
            _fail("device.output_malformed", "device.select", "malformed adb devices heading")

        states: dict[str, str] = {}
        known_states = {"device", "offline", "unauthorized", "recovery", "sideload", "bootloader"}
        for line in lines[1:]:
            if not line.strip():
                continue
            fields = line.split()
            if len(fields) < 2 or fields[1] not in known_states:
                _fail("device.output_malformed", "device.select", "malformed adb device row")
            serial = _validate_serial(fields[0])
            if serial in states:
                _fail("device.output_malformed", "device.select", "duplicate adb device row")
            states[serial] = fields[1]

        online = tuple(serial for serial, state in states.items() if state == "device")
        if requested_device is None:
            if len(online) != 1:
                _fail(
                    ErrorCode.DEVICE_NOT_FOUND,
                    "device.select",
                    "exactly one online device is required when --device is omitted",
                )
            selected = online[0]
        else:
            if states.get(requested_device) != "device":
                _fail(
                    ErrorCode.DEVICE_NOT_FOUND,
                    "device.select",
                    "requested device is absent, offline, or unauthorized",
                )
            selected = requested_device
        return AdbDevice(selected, self.runner)
