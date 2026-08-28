"""Validated, bounded ADB access for qtrace."""

from __future__ import annotations

import fcntl
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from scripts.bounded_process import BoundedProcessError

from qtrace.errors import ErrorCode, QtraceError


_SAFE_SHELL_TOKEN = re.compile(r"[A-Za-z0-9._/@:+,=-]+\Z")
_SAFE_REMOTE_PATH_COMPONENT = re.compile(r"[A-Za-z0-9._~@:+,=-]+\Z")
_SAFE_ARCHIVE_COMPONENT = re.compile(r"[A-Za-z0-9._@:+,=-]+\Z")
_SAFE_SERIAL = re.compile(r"[A-Za-z0-9._:@+-]+\Z")
_PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z")
_MAX_ADB_LIST_BYTES = 64 * 1024
_ADB_LIST_TIMEOUT_SECONDS = 10.0
_MAX_APK_MEMBER_BYTES = 512 * 1024 * 1024


class CommandRunner(Protocol):
    def capture(
        self, command, *, maximum_bytes: int, timeout: float,
        pass_fds: tuple[int, ...] = (),
    ) -> bytes: ...
    def stream(
        self, command, output: object, *, maximum_bytes: int, timeout: float
    ) -> None: ...


@dataclass(frozen=True)
class DeviceIdentity:
    serial: str
    abi: str
    api_level: int
    access_mode: str
    frida_host_version: str
    frida_server_version: str
    free_bytes: int
    android_user: int
    package_data_dir: str


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


def _is_valid_remote_path(path: object) -> bool:
    if not isinstance(path, str) or not path.startswith("/") or "//" in path:
        return False
    parts = path.split("/")[1:]
    if not parts or any(
        not part
        or part in {".", ".."}
        or _SAFE_REMOTE_PATH_COMPONENT.fullmatch(part) is None
        for part in parts
    ):
        return False
    return str(PurePosixPath(path)) == path


def _validate_remote_path(path: str) -> str:
    if not _is_valid_remote_path(path):
        _fail("device.path_invalid", "device", "remote path must be an absolute normalized path")
    return path


def _validate_archive_member(member: str) -> str:
    if not isinstance(member, str) or member.startswith("/") or "//" in member:
        _fail("device.member_invalid", "device.pull_member", "APK member path is invalid")
    parts = member.split("/")
    if not parts or any(
        not part or part in {".", ".."} or _SAFE_ARCHIVE_COMPONENT.fullmatch(part) is None
        for part in parts
    ):
        _fail("device.member_invalid", "device.pull_member", "APK member path is unsafe")
    return member


def _shell_tokens(arguments: tuple[str, ...]) -> tuple[str, ...]:
    """The sole device-shell composition seam; every token is allow-listed."""
    if not arguments:
        _fail("device.shell_invalid", "device.shell", "shell command must not be empty")
    for token in arguments:
        # Android package paths can contain literal ``~`` inside an absolute path.
        # Keep it out of the generic shell alphabet (where a leading tilde has
        # expansion semantics) and accept it only after full path normalization.
        fixed_stat_format = token == "%u"
        safe = isinstance(token, str) and (
            _SAFE_SHELL_TOKEN.fullmatch(token) is not None
            or _is_valid_remote_path(token)
            or fixed_stat_format
        )
        if not safe:
            _fail("device.shell_token_unsafe", "device.shell", "shell token contains unsafe characters")
    return arguments


def _compose_su_command(arguments: tuple[str, ...]) -> str:
    """Validate each interpolated token before building the fixed ``su -c`` operand."""
    # adb concatenates the remote-shell argv. Single quotes (which interpolated
    # tokens cannot contain) preserve the validated command as one ``-c`` value.
    return "'" + " ".join(_shell_tokens(arguments)) + "'"


def _validate_package_uid(uid: int) -> int:
    if isinstance(uid, bool) or not isinstance(uid, int) or uid <= 0:
        _fail("device.uid_invalid", "device.bind", "package UID must be a positive integer")
    return uid


def _validate_android_user(user: int) -> int:
    if isinstance(user, bool) or not isinstance(user, int) or user < 0:
        _fail("device.user_invalid", "device.bind", "Android user must be a non-negative integer")
    return user


def _run_as_argv(
    package: str, android_user: int, *command: str,
) -> tuple[str, ...]:
    package = _validate_package(package)
    android_user = _validate_android_user(android_user)
    prefix = (
        ("run-as", package)
        if android_user == 0
        else ("run-as", package, "--user", str(android_user))
    )
    return _shell_tokens((*prefix, *command))


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


def _read_only_regular_descriptor(descriptor: int, *, stage: str) -> int:
    if type(descriptor) is not int or descriptor <= 2:
        _fail("host.fd_invalid", stage, "host descriptor must be a non-standard integer")
    try:
        details = os.fstat(descriptor)
        access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
    except OSError as error:
        _fail("host.fd_invalid", stage, f"host descriptor is unavailable: {error}")
    if not stat.S_ISREG(details.st_mode) or access_mode != os.O_RDONLY:
        _fail(
            "host.fd_invalid", stage,
            "host descriptor must be an open read-only regular file",
        )
    return descriptor


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
        self._root_strategy: str | None = None
        self._package_uid: int | None = None
        self._target_strategy: str | None = None
        self._android_user: int | None = None
        self._package_data_dir: str | None = None

    @property
    def package(self) -> str | None:
        return self._package

    @property
    def access_mode(self) -> str | None:
        return self._access_mode

    @property
    def root_strategy(self) -> str | None:
        return self._root_strategy

    @property
    def package_uid(self) -> int | None:
        return self._package_uid

    @property
    def target_strategy(self) -> str | None:
        return self._target_strategy

    @property
    def android_user(self) -> int | None:
        return self._android_user

    @property
    def package_data_dir(self) -> str | None:
        return self._package_data_dir

    def bind_package(
        self,
        package: str,
        access_mode: str,
        *,
        root_strategy: str,
        package_uid: int,
        target_strategy: str,
        android_user: int,
        package_data_dir: str,
    ) -> None:
        """Bind control and target identities once; conflicting reuse is forbidden."""
        validated = _validate_package(package)
        if access_mode not in {"root", "run-as"}:
            _fail("device.access_mode_invalid", "device.bind", "access mode is invalid")
        uid = _validate_package_uid(package_uid)
        user = _validate_android_user(android_user)
        expected_data_dir = f"/data/user/{user}/{validated}"
        if package_data_dir != expected_data_dir or not _is_valid_remote_path(package_data_dir):
            _fail(
                "device.data_dir_invalid", "device.bind",
                "package data directory does not match the bound Android user",
            )
        if uid // 100_000 != user:
            _fail(
                "device.uid_user_mismatch", "device.bind",
                "package UID does not belong to the bound Android user",
            )
        if root_strategy not in {"direct", "su", "none"}:
            _fail("device.root_strategy_invalid", "device.bind", "root strategy is invalid")
        if target_strategy not in {"run-as", "su-uid"}:
            _fail("device.target_strategy_invalid", "device.bind", "target strategy is invalid")
        if access_mode == "run-as" and (root_strategy != "none" or target_strategy != "run-as"):
            _fail(
                "device.binding_invalid",
                "device.bind",
                "run-as access cannot carry a root or su-uid strategy",
            )
        if access_mode == "root" and root_strategy == "none":
            _fail("device.binding_invalid", "device.bind", "root access requires a root strategy")
        if target_strategy == "su-uid" and access_mode != "root":
            _fail("device.binding_invalid", "device.bind", "su-uid requires root access")
        binding = (
            validated, access_mode, root_strategy, uid, target_strategy, user,
            expected_data_dir,
        )
        current = (
            self._package,
            self._access_mode,
            self._root_strategy,
            self._package_uid,
            self._target_strategy,
            self._android_user,
            self._package_data_dir,
        )
        if all(value is None for value in current):
            (
                self._package,
                self._access_mode,
                self._root_strategy,
                self._package_uid,
                self._target_strategy,
                self._android_user,
                self._package_data_dir,
            ) = binding
            return
        if current != binding:
            _fail(
                "device.binding_conflict",
                "device.bind",
                "device is already bound to a different identity strategy",
            )

    def _host_command(self, *args: str) -> list[str]:
        if any(not isinstance(argument, str) or not argument or "\0" in argument for argument in args):
            _fail("device.command_invalid", "device", "ADB arguments must be nonempty strings without NUL")
        return ["adb", "-s", self.serial, *args]

    def command(self, *args: str) -> list[str]:
        command = self._host_command(*args)
        if args and args[0] == "shell":
            _shell_tokens(tuple(args[1:]))
        return command

    def _capture(
        self,
        arguments: tuple[str, ...],
        *,
        timeout: float,
        maximum_bytes: int,
        stage: str,
        composed_shell: bool = False,
        pass_fds: tuple[int, ...] = (),
    ) -> bytes:
        maximum_bytes, timeout = _validate_limits(maximum_bytes, timeout, stage=stage)
        try:
            command = (
                self._host_command(*arguments)
                if composed_shell
                else self.command(*arguments)
            )
            if pass_fds:
                return self.runner.capture(
                    command,
                    maximum_bytes=maximum_bytes,
                    timeout=timeout,
                    pass_fds=pass_fds,
                )
            return self.runner.capture(
                command, maximum_bytes=maximum_bytes, timeout=timeout,
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

    def su_shell(
        self,
        *args: str,
        timeout: float = 30.0,
        maximum_bytes: int = 1_048_576,
    ) -> bytes:
        command = _compose_su_command(tuple(args))
        return self._capture(
            ("shell", "su", "-c", command),
            timeout=timeout,
            maximum_bytes=maximum_bytes,
            stage="device.shell",
            composed_shell=True,
        )

    def su_uid_shell(
        self,
        uid: int,
        *args: str,
        timeout: float = 30.0,
        maximum_bytes: int = 1_048_576,
    ) -> bytes:
        uid = _validate_package_uid(uid)
        command = _compose_su_command(tuple(args))
        return self._capture(
            ("shell", "su", str(uid), "-c", command),
            timeout=timeout,
            maximum_bytes=maximum_bytes,
            stage="device.shell",
            composed_shell=True,
        )

    def root_shell(
        self,
        *args: str,
        timeout: float = 30.0,
        maximum_bytes: int = 1_048_576,
    ) -> bytes:
        if self._access_mode != "root" or self._root_strategy is None:
            _fail("device.unbound", "device.root_shell", "root identity is not bound")
        if self._root_strategy == "direct":
            return self.shell(*args, timeout=timeout, maximum_bytes=maximum_bytes)
        if self._root_strategy == "su":
            return self.su_shell(*args, timeout=timeout, maximum_bytes=maximum_bytes)
        _fail("device.binding_invalid", "device.root_shell", "bound root strategy is invalid")

    def target_shell(
        self,
        *args: str,
        timeout: float = 30.0,
        maximum_bytes: int = 1_048_576,
    ) -> bytes:
        if self._package is None or self._package_uid is None or self._target_strategy is None:
            _fail("device.unbound", "device.target_shell", "target identity is not bound")
        if self._target_strategy == "run-as":
            return self.shell(
                *_run_as_argv(self._package, self._android_user, *args),
                timeout=timeout, maximum_bytes=maximum_bytes,
            )
        if self._target_strategy == "su-uid":
            return self.su_uid_shell(
                self._package_uid, *args,
                timeout=timeout, maximum_bytes=maximum_bytes,
            )
        _fail("device.binding_invalid", "device.target_shell", "bound target strategy is invalid")

    def stream_target_file(
        self,
        path: str,
        output: object,
        *,
        maximum_bytes: int,
        timeout: float,
    ) -> None:
        path = _validate_remote_path(path)
        maximum_bytes, timeout = _validate_limits(
            maximum_bytes, timeout, stage="device.target_stream"
        )
        if self._package is None or self._package_uid is None or self._target_strategy is None:
            _fail("device.unbound", "device.target_stream", "target identity is not bound")
        if self._target_strategy == "run-as":
            arguments = (
                "exec-out", *_run_as_argv(
                    self._package, self._android_user, "cat", path,
                ),
            )
        elif self._target_strategy == "su-uid":
            command = _compose_su_command(("cat", path))
            arguments = ("exec-out", "su", str(self._package_uid), "-c", command)
        else:
            _fail("device.binding_invalid", "device.target_stream", "bound target strategy is invalid")
        stream = getattr(self.runner, "stream", None)
        if not callable(stream):
            _fail("device.streaming_unavailable", "device.target_stream", "bounded streaming transport is unavailable")
        try:
            stream(
                self._host_command(*arguments), output,
                maximum_bytes=maximum_bytes, timeout=timeout,
            )
        except QtraceError:
            raise
        except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
            wrapped = QtraceError(
                "device.command_failed", "device.target_stream",
                f"ADB stream failed: {error}",
            )
            raise wrapped from error

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

    def push_open_file(
        self, source_descriptor: int, destination: str, *, timeout: float = 30.0,
    ) -> None:
        """Push one held read-only file without taking ownership of its descriptor."""
        source_descriptor = _read_only_regular_descriptor(
            source_descriptor, stage="deploy.push",
        )
        destination = _validate_remote_path(destination)
        self._capture(
            ("push", f"/proc/self/fd/{source_descriptor}", destination),
            timeout=timeout,
            maximum_bytes=256 * 1024,
            stage="deploy.push",
            pass_fds=(source_descriptor,),
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
            # Android's unzip exits successfully with no bytes for a missing member.
            # Match DeviceFileProvider's absence contract so the resolver tries splits.
            raise FileNotFoundError(member)
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
