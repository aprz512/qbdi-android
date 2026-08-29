"""Bounded device and host prerequisites for qtrace sessions."""

from __future__ import annotations

import math
import re
import shutil
import stat
import time
from pathlib import Path
from typing import Callable, Protocol

from qtrace.device import (
    AdbDevice, BoundTargetDevice, DeviceIdentity, DeviceSelector, TargetBinding,
    _run_as_argv, _validate_package,
)
from qtrace.errors import ErrorCode, QtraceError
from qtrace.models import UserConfig


_SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
_MIN_API_LEVEL = 24
_DEFAULT_ARTIFACT_SET_BYTES = 64 * 1024 * 1024


class FridaProbe(Protocol):
    def versions(self, device: AdbDevice, timeout: float) -> tuple[str, str]: ...


def _fail(code: ErrorCode | str, stage: str, detail: str) -> None:
    raise QtraceError(code, stage, detail)


def _positive_finite(value: float, name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        _fail("preflight.timeout_invalid", "preflight", f"{name} must be finite and positive")
    return float(value)


def _one_line(output: bytes, *, code: str, stage: str, field: str) -> str:
    if not isinstance(output, bytes):
        _fail(code, stage, f"{field} returned non-byte output")
    try:
        text = output.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        _fail(code, stage, f"{field} output is not UTF-8")
    if not text or "\n" in text or "\r" in text:
        _fail(code, stage, f"{field} output is malformed")
    return text


def _numeric_uid(output: bytes, *, field: str, allow_root: bool = False) -> int:
    text = _one_line(
        output,
        code="device.access_malformed",
        stage="preflight.access",
        field=field,
    )
    if not text.isascii() or not text.isdigit():
        _fail("device.access_malformed", "preflight.access", f"{field} is not numeric")
    uid = int(text, 10)
    if uid < 0 or (uid == 0 and not allow_root):
        _fail("device.access_malformed", "preflight.access", f"{field} is not a package UID")
    return uid


def _normalize_semver(value: object, side: str) -> str:
    if not isinstance(value, str):
        _fail("frida.version_invalid", "preflight.frida", f"{side} Frida version is not text")
    match = _SEMVER.fullmatch(value.strip())
    if match is None:
        _fail("frida.version_invalid", "preflight.frida", f"{side} Frida version is invalid")
    return ".".join(match.groups()[:3])


def _existing_apk(path: Path) -> Path:
    candidate = Path(path)
    try:
        mode = candidate.lstat().st_mode
    except (OSError, TypeError, ValueError) as error:
        _fail("app.apk_invalid", "preflight.install", f"APK is unavailable: {error}")
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        _fail("app.apk_invalid", "preflight.install", "APK must be a regular non-symlink file")
    return candidate


def _required_free_bytes(config: UserConfig) -> int:
    paths = (config.tracer.library, config.tracer.companion)
    if all(path is not None for path in paths):
        try:
            artifact_set = sum(Path(path).stat().st_size for path in paths if path is not None)
        except (OSError, TypeError, ValueError):
            artifact_set = _DEFAULT_ARTIFACT_SET_BYTES
        artifact_set = max(artifact_set, 1)
    else:
        artifact_set = _DEFAULT_ARTIFACT_SET_BYTES
    return artifact_set * 2


def _parse_free_bytes(output: bytes) -> int:
    if not isinstance(output, bytes):
        _fail("device.space_malformed", "preflight.space", "df returned non-byte output")
    try:
        lines = [line for line in output.decode("utf-8", errors="strict").splitlines() if line.strip()]
    except UnicodeDecodeError:
        _fail("device.space_malformed", "preflight.space", "df output is not UTF-8")
    if len(lines) != 2:
        _fail("device.space_malformed", "preflight.space", "df output has an unexpected row count")
    header = lines[0].split()
    fields = lines[1].split()
    if "Available" not in header or len(fields) <= header.index("Available"):
        _fail("device.space_malformed", "preflight.space", "df output columns are malformed")
    available_index = header.index("Available")
    available = fields[available_index]
    if not available.isascii() or not available.isdigit():
        _fail("device.space_malformed", "preflight.space", "df available blocks are malformed")
    return int(available, 10) * 1024


def _external(stage: str, operation):
    try:
        return operation()
    except QtraceError:
        raise
    except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
        wrapped = QtraceError("device.command_failed", stage, f"device operation failed: {error}")
        raise wrapped from error


def _discover_package_access(
    device: AdbDevice,
    package: str,
    budget: Callable[[], float],
) -> TargetBinding:
    """Discover the target identity shared by run, monitor, and pull."""
    package = _validate_package(package)
    android_user = _numeric_uid(
        _external(
            "preflight.access",
            lambda: device.shell(
                "cmd", "activity", "get-current-user",
                timeout=budget(), maximum_bytes=4096,
            ),
        ),
        field="current Android user",
        allow_root=True,
    )
    package_data_dir = f"/data/user/{android_user}/{package}"
    root_strategy: str | None = None
    try:
        root_uid = _numeric_uid(
            _external(
                "preflight.access",
                lambda: device.shell("id", "-u", timeout=budget(), maximum_bytes=4096),
            ),
            field="root identity",
            allow_root=True,
        )
        if root_uid == 0:
            root_strategy = "direct"
    except QtraceError as error:
        if error.code == "preflight.timeout":
            raise

    if root_strategy is None:
        try:
            su_uid = _numeric_uid(
                _external(
                    "preflight.access",
                    lambda: device.su_shell(
                        "id", "-u", timeout=budget(), maximum_bytes=4096
                    ),
                ),
                field="su root identity",
                allow_root=True,
            )
            if su_uid == 0:
                root_strategy = "su"
        except QtraceError as error:
            if error.code == "preflight.timeout":
                raise

    package_uid: int | None = None
    target_strategy: str | None = None
    try:
        package_uid = _numeric_uid(
            _external(
                "preflight.access",
                lambda: device.shell(
                    *_run_as_argv(package, android_user, "id", "-u"),
                    timeout=budget(), maximum_bytes=4096,
                ),
            ),
            field="run-as identity",
        )
        target_strategy = "run-as"
    except QtraceError as error:
        if error.code == "preflight.timeout":
            raise

    if root_strategy is not None and target_strategy is None:
        private_data = package_data_dir
        try:
            root_stat = device.shell if root_strategy == "direct" else device.su_shell
            package_uid = _numeric_uid(
                _external(
                    "preflight.access",
                    lambda: root_stat(
                        "stat", "-c", "%u", private_data,
                        timeout=budget(), maximum_bytes=4096,
                    ),
                ),
                field="package data owner",
            )
            proven_uid = _numeric_uid(
                _external(
                    "preflight.access",
                    lambda: device.su_uid_shell(
                        package_uid, "id", "-u",
                        timeout=budget(), maximum_bytes=4096,
                    ),
                ),
                field="su package identity",
            )
            if proven_uid != package_uid:
                _fail(
                    "device.access_malformed",
                    "preflight.access",
                    "su package identity does not match the package data owner",
                )
            target_strategy = "su-uid"
        except QtraceError as error:
            if error.code == "preflight.timeout":
                raise

    if root_strategy is not None and package_uid is not None and target_strategy is not None:
        access_mode = "root"
    elif package_uid is not None and target_strategy == "run-as":
        access_mode = "run-as"
        root_strategy = "none"
    else:
        _fail(
            "device.access_denied",
            "preflight.access",
            "neither a complete root nor run-as package identity is available",
        )

    assert root_strategy is not None and package_uid is not None and target_strategy is not None
    if package_uid // 100_000 != android_user:
        _fail(
            "device.uid_user_mismatch", "preflight.access",
            "package UID does not belong to the current Android user",
        )
    return TargetBinding(
        package=package,
        access_mode=access_mode,
        root_strategy=root_strategy,
        package_uid=package_uid,
        target_strategy=target_strategy,
        android_user=android_user,
        package_data_dir=package_data_dir,
    )


def bind_package_access(
    device: AdbDevice, package: str, *, timeout: float
) -> BoundTargetDevice:
    """Return one package-bound device without config, build, Frida, or app launch work."""
    timeout = _positive_finite(timeout, "timeout")
    deadline = time.monotonic() + timeout

    def budget() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail("preflight.timeout", "preflight", "package access time budget was exhausted")
        return remaining

    package = _validate_package(package)
    _external(
        "preflight.package",
        lambda: device.package_apk_paths(package, timeout=budget()),
    )
    binding = _discover_package_access(device, package, budget)
    return _external("preflight.bind", lambda: device.bind_target(binding))


class Preflight:
    def __init__(self, selector: DeviceSelector, frida_probe: FridaProbe):
        self._selector = selector
        self._frida_probe = frida_probe

    def run(
        self,
        config: UserConfig,
        requested_device: str | None,
        *,
        setup_timeout: float,
        adb_timeout: float,
    ) -> tuple[BoundTargetDevice, DeviceIdentity]:
        setup_timeout = _positive_finite(setup_timeout, "setup_timeout")
        adb_timeout = _positive_finite(adb_timeout, "adb_timeout")
        deadline = time.monotonic() + setup_timeout

        def budget() -> float:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("preflight.timeout", "preflight", "setup time budget was exhausted")
            return min(adb_timeout, remaining)

        try:
            device = self._selector.select(requested_device, timeout=budget())
        except QtraceError:
            raise
        except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
            wrapped = QtraceError(
                ErrorCode.ADB_UNAVAILABLE, "device.select", f"device selection failed: {error}"
            )
            raise wrapped from error
        package = config.app.package

        if config.app.apk is not None:
            _external(
                "preflight.install",
                lambda: device.install(_existing_apk(config.app.apk), timeout=budget()),
            )

        _external(
            "preflight.package",
            lambda: device.package_apk_paths(package, timeout=budget()),
        )

        abi = _one_line(
            _external(
                "preflight.abi",
                lambda: device.shell(
                    "getprop", "ro.product.cpu.abi", timeout=budget(), maximum_bytes=4096
                ),
            ),
            code="device.abi_malformed",
            stage="preflight.abi",
            field="device ABI",
        )
        if abi != "arm64-v8a":
            _fail(ErrorCode.UNSUPPORTED_ABI, "preflight.abi", f"unsupported device ABI: {abi}")

        api_text = _one_line(
            _external(
                "preflight.api",
                lambda: device.shell(
                    "getprop", "ro.build.version.sdk", timeout=budget(), maximum_bytes=4096
                ),
            ),
            code="device.api_malformed",
            stage="preflight.api",
            field="device API level",
        )
        if not api_text.isascii() or not api_text.isdigit():
            _fail("device.api_malformed", "preflight.api", "device API level is malformed")
        api_level = int(api_text, 10)
        if api_level < _MIN_API_LEVEL:
            _fail("device.api_unsupported", "preflight.api", "device API level must be at least 24")

        access_binding = _discover_package_access(device, package, budget)
        access_mode = access_binding.access_mode

        free_bytes = _parse_free_bytes(
            _external(
                "preflight.space",
                lambda: device.shell(
                    "df", "-Pk", "/data/local/tmp",
                    timeout=budget(), maximum_bytes=64 * 1024,
                ),
            )
        )
        required_bytes = _required_free_bytes(config)
        if free_bytes < required_bytes:
            _fail(
                "device.space_insufficient",
                "preflight.space",
                f"device has {free_bytes} free bytes; {required_bytes} are required",
            )

        if config.tracer.compression:
            try:
                lz4 = shutil.which("lz4")
            except (OSError, TypeError, ValueError) as error:
                wrapped = QtraceError(
                    "host.lz4_probe_failed", "preflight.host", f"cannot locate host lz4: {error}"
                )
                raise wrapped from error
            if lz4 is None:
                _fail("host.lz4_missing", "preflight.host", "host lz4 executable is required")

        try:
            versions = self._frida_probe.versions(device, budget())
        except QtraceError:
            raise
        except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
            wrapped = QtraceError(
                "frida.handshake_failed", "preflight.frida", f"Frida handshake failed: {error}"
            )
            raise wrapped from error
        if not isinstance(versions, tuple) or len(versions) != 2:
            _fail("frida.version_invalid", "preflight.frida", "Frida probe returned malformed versions")
        host_version = _normalize_semver(versions[0], "host")
        server_version = _normalize_semver(versions[1], "server")
        if host_version != server_version:
            _fail(
                ErrorCode.FRIDA_VERSION_MISMATCH,
                "preflight.frida",
                f"Frida host {host_version} does not match server {server_version}",
            )

        # Deployment is allowed only after every prerequisite succeeds. The one-time
        # binding prevents a selected device from being silently reused for another app.
        bound_device = _external("preflight.bind", lambda: device.bind_target(access_binding))
        return bound_device, DeviceIdentity(
            serial=bound_device.serial,
            abi=abi,
            api_level=api_level,
            access_mode=access_mode,
            frida_host_version=host_version,
            frida_server_version=server_version,
            free_bytes=free_bytes,
            android_user=access_binding.android_user,
            package_data_dir=access_binding.package_data_dir,
        )
