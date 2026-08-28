"""Fixture adapter for qtrace's repository-owned Android demo application.

Nothing in this module is part of the generic device/runtime path.  It merely
turns the repository fixture into a normal ``UserConfig`` and an
``InstalledAction`` consumed by ``SessionOrchestrator``.
"""

from __future__ import annotations

import os
import shutil
import stat
import uuid
import zipfile
import math
from dataclasses import dataclass
from pathlib import Path

from qtrace.elf import ElfInspector
from qtrace.errors import QtraceError
from qtrace.models import AppConfig, OffsetScene, SymbolScene, TargetConfig, TracerConfig, UserConfig
from qtrace.process import BoundedRunner
from qtrace.session import InstalledAction, InstalledActionReceipt


_APK_RELATIVE = Path("app/build/outputs/apk/debug/app-debug.apk")
_TARGET_MEMBER = "lib/arm64-v8a/libdemo_target.so"
_TARGET_OUTPUT = Path("build/qtrace-demo/arm64-v8a/libdemo_target.so")
_PACKAGE = "com.aprz.qbdiandroid"
_MODULE = "libdemo_target.so"
_ACTIVITY = "com.aprz.qbdiandroid/.MainActivity"
_MAX_MEMBER_BYTES = 512 * 1024 * 1024
_BUILD_OUTPUT_BYTES = 4 * 1024 * 1024
_GRADLE_IDLE_BOUND = "-Dorg.gradle.daemon.idletimeout=1000"


@dataclass(frozen=True)
class DemoFixture:
    apk: Path
    target_binary: Path
    target_parent_identity: "_PathIdentity | None" = None
    target_identity: "_PathIdentity | None" = None


@dataclass(frozen=True)
class _PathIdentity:
    device: int
    inode: int


@dataclass(frozen=True)
class _ExtractedTarget:
    path: Path
    parent_identity: _PathIdentity
    target_identity: _PathIdentity


def _identity(metadata: os.stat_result) -> _PathIdentity:
    return _PathIdentity(metadata.st_dev, metadata.st_ino)


def _regular(path: Path, stage: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise QtraceError("demo.file_missing", stage, f"fixture file is unavailable: {error}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise QtraceError("demo.file_invalid", stage, "fixture file must be a regular non-symlink")
    return path


def _open_safe_directory(path: Path, *, create: bool) -> int:
    """Open/create an absolute directory path without ever following a symlink."""
    candidate = Path(path)
    if not candidate.is_absolute() or not hasattr(os, "O_NOFOLLOW"):
        raise QtraceError("demo.output_unsafe", "demo.extract",
                          "fixture output directory must support no-follow traversal")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
    descriptor = os.open(candidate.anchor, flags)
    try:
        for part in candidate.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            try:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            except OSError as error:
                raise QtraceError("demo.output_unsafe", "demo.extract",
                                  "fixture output directory contains an unsafe parent") from error
            os.close(descriptor)
            descriptor = next_descriptor
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _extract_target(apk: Path, destination: Path) -> _ExtractedTarget:
    directory = _open_safe_directory(destination.parent, create=True)
    temporary = f".qtrace-demo-{uuid.uuid4().hex}.so"
    descriptor = -1
    target_descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        with os.fdopen(descriptor, "wb") as target, zipfile.ZipFile(apk) as archive:
            descriptor = -1
            try:
                info = archive.getinfo(_TARGET_MEMBER)
            except KeyError as error:
                raise QtraceError("demo.target_missing", "demo.extract",
                                  f"fixture APK does not contain {_TARGET_MEMBER}") from error
            if info.is_dir() or info.file_size <= 0 or info.file_size > _MAX_MEMBER_BYTES:
                raise QtraceError("demo.target_invalid", "demo.extract",
                                  "fixture target member has an unsupported size")
            with archive.open(info, "r") as source:
                remaining = info.file_size
                while remaining:
                    block = source.read(min(1024 * 1024, remaining))
                    if not block:
                        raise QtraceError("demo.target_invalid", "demo.extract",
                                          "fixture target member is truncated")
                    target.write(block)
                    remaining -= len(block)
                if source.read(1):
                    raise QtraceError("demo.target_invalid", "demo.extract",
                                      "fixture target member exceeds its declared size")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, destination.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        target_descriptor = os.open(destination.name, os.O_RDONLY | os.O_NOFOLLOW,
                                    dir_fd=directory)
        target_metadata = os.fstat(target_descriptor)
        if not stat.S_ISREG(target_metadata.st_mode):
            raise QtraceError("demo.target_invalid", "demo.extract",
                              "published fixture target is not a regular file")
        parent_identity = _identity(os.fstat(directory))
        target_identity = _identity(target_metadata)
    except (OSError, zipfile.BadZipFile) as error:
        raise QtraceError("demo.extract_failed", "demo.extract", f"cannot extract fixture target: {error}") from error
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except OSError:
            pass
        if descriptor >= 0:
            os.close(descriptor)
        if target_descriptor >= 0:
            os.close(target_descriptor)
        os.close(directory)
    return _ExtractedTarget(destination, parent_identity, target_identity)


def build_demo_fixture(repo_root: Path, runner: BoundedRunner, timeout: float) -> DemoFixture:
    """Build the fixture APK and atomically expose its stable arm64 target ELF."""
    root = Path(repo_root).resolve()
    gradlew = _regular(root / "gradlew", "demo.build")
    environment_executable = shutil.which("env")
    if environment_executable is None or not os.path.isabs(environment_executable):
        raise QtraceError("demo.build_failed", "demo.build", "env executable is unavailable")
    environment_executable = str(_regular(Path(environment_executable), "demo.build"))
    inherited_gradle_options = os.environ.get("GRADLE_OPTS", "")
    gradle_options = (
        f"{inherited_gradle_options} {_GRADLE_IDLE_BOUND}"
        if inherited_gradle_options else _GRADLE_IDLE_BOUND
    )
    try:
        runner.capture((
            environment_executable,
            f"GRADLE_OPTS={gradle_options}",
            str(gradlew),
            ":app:assembleDebug",
            "--no-daemon",
        ),
                       maximum_bytes=_BUILD_OUTPUT_BYTES, timeout=timeout)
    except QtraceError:
        raise
    except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
        raise QtraceError("demo.build_failed", "demo.build", f"fixture build failed: {error}") from error
    apk = _regular(root / _APK_RELATIVE, "demo.build")
    extracted = _extract_target(apk, root / _TARGET_OUTPUT)
    return DemoFixture(apk=apk, target_binary=extracted.path,
                       target_parent_identity=extracted.parent_identity,
                       target_identity=extracted.target_identity)


def _scene_symbol(scenario: str) -> str:
    if scenario == "flight-crash":
        return "demo_flight_acceptance_case"
    if scenario in {"timed", "monitor-exit"}:
        return "demo_timed_acceptance_case"
    raise QtraceError("demo.scenario_invalid", "demo.config", "unknown fixture scenario")


def make_demo_config(fixture: DemoFixture, inspector: ElfInspector, scene_form: str,
                     scenario: str) -> UserConfig:
    """Make a normal configuration; only this adapter knows fixture identities."""
    if type(fixture) is not DemoFixture:
        raise QtraceError("demo.fixture_invalid", "demo.config", "fixture has an invalid shape")
    apk = _regular(fixture.apk, "demo.config")
    target = _fixture_target(fixture)
    symbol = _scene_symbol(scenario)
    if scene_form == "offset":
        start, end = inspector.symbol_range(target, symbol)
        scene = OffsetScene("fixture-entry", start, end)
    elif scene_form == "symbol":
        scene = SymbolScene("fixture-entry", symbol)
    else:
        raise QtraceError("demo.scene_form_invalid", "demo.config", "scene form must be offset or symbol")
    _fixture_target(fixture)
    flight = scenario == "flight-crash"
    return UserConfig(
        schema_version=1,
        app=AppConfig(_PACKAGE, apk),
        target=TargetConfig(_MODULE, target),
        tracer=TracerConfig("full" if flight else "balanced", True, flight,
                            "fixture-entry" if flight else None, None, None),
        scenes=(scene,),
    )


def _fixture_target(fixture: DemoFixture) -> Path:
    """Re-bind built fixture paths before another component can inspect them."""
    target = Path(fixture.target_binary)
    expected_parent, expected_target = fixture.target_parent_identity, fixture.target_identity
    if expected_parent is None and expected_target is None:
        return _regular(target, "demo.config")
    if type(expected_parent) is not _PathIdentity or type(expected_target) is not _PathIdentity:
        raise QtraceError("demo.fixture_identity", "demo.config", "fixture target identity is malformed")
    try:
        directory = _open_safe_directory(target.parent, create=False)
    except QtraceError as error:
        raise QtraceError("demo.fixture_identity", "demo.config", "fixture target identity changed") from error
    descriptor = -1
    try:
        if _identity(os.fstat(directory)) != expected_parent:
            raise QtraceError("demo.fixture_identity", "demo.config", "fixture target parent identity changed")
        descriptor = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or _identity(metadata) != expected_target:
            raise QtraceError("demo.fixture_identity", "demo.config", "fixture target identity changed")
    except OSError as error:
        raise QtraceError("demo.fixture_identity", "demo.config", "fixture target identity changed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)
    return target


def make_demo_action(mode: str, seed: int, iterations: int = 30, worker: int = 0,
                     *, adb_timeout: float = 30.0) -> InstalledAction:
    """Return the generic post-detach action which starts the fixture intent."""
    intents = {"timed": "timed", "monitor-exit": "exit", "flight-crash": "flight-crash"}
    if mode not in intents:
        raise QtraceError("demo.action_invalid", "demo.action", "unknown fixture scenario")
    if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFFFFFFFFFF:
        raise QtraceError("demo.action_invalid", "demo.action", "seed must be an unsigned 64-bit integer")
    if type(iterations) is not int or iterations <= 0 or type(worker) is not int or worker < 0:
        raise QtraceError("demo.action_invalid", "demo.action", "iterations and worker are invalid")
    if (isinstance(adb_timeout, bool) or not isinstance(adb_timeout, (int, float)) or
            not math.isfinite(adb_timeout) or adb_timeout <= 0):
        raise QtraceError("demo.action_invalid", "demo.action", "ADB timeout must be finite and positive")

    nonce = str(uuid.uuid4())
    activity_flags = (("--activity-clear-task",)
                      if mode in {"monitor-exit", "flight-crash"} else ())

    def action(device: object, _pid: int, session_id: str) -> InstalledActionReceipt:
        shell = getattr(device, "shell", None)
        if not callable(shell):
            raise QtraceError("demo.device_invalid", "demo.action", "device cannot start the fixture activity")
        shell("am", "start", "-n", _ACTIVITY, *activity_flags,
              "--ez", "qtrace_acceptance", "true",
              "--es", "qtrace_acceptance_mode", intents[mode],
              "--el", "qtrace_acceptance_seed", str(seed),
              "--el", "qtrace_acceptance_iterations", str(iterations),
              "--ei", "qtrace_acceptance_worker", str(worker),
              "--es", "qtrace_acceptance_session_id", session_id,
              "--es", "qtrace_acceptance_nonce", nonce,
              timeout=float(adb_timeout), maximum_bytes=64 * 1024)
        return InstalledActionReceipt(nonce)

    return action
