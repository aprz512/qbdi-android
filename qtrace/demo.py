"""Fixture adapter for qtrace's repository-owned Android demo application.

Nothing in this module is part of the generic device/runtime path.  It merely
turns the repository fixture into a normal ``UserConfig`` and an
``InstalledAction`` consumed by ``SessionOrchestrator``.
"""

from __future__ import annotations

import os
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from qtrace.elf import ElfInspector
from qtrace.errors import QtraceError
from qtrace.models import AppConfig, OffsetScene, SymbolScene, TargetConfig, TracerConfig, UserConfig
from qtrace.process import BoundedRunner
from qtrace.session import InstalledAction


_APK_RELATIVE = Path("app/build/outputs/apk/debug/app-debug.apk")
_TARGET_MEMBER = "lib/arm64-v8a/libdemo_target.so"
_TARGET_OUTPUT = Path("build/qtrace-demo/arm64-v8a/libdemo_target.so")
_PACKAGE = "com.aprz.qbdiandroid"
_MODULE = "libdemo_target.so"
_ACTIVITY = "com.aprz.qbdiandroid/.MainActivity"
_MAX_MEMBER_BYTES = 512 * 1024 * 1024
_BUILD_OUTPUT_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class DemoFixture:
    apk: Path
    target_binary: Path


def _regular(path: Path, stage: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise QtraceError("demo.file_missing", stage, f"fixture file is unavailable: {error}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise QtraceError("demo.file_invalid", stage, "fixture file must be a regular non-symlink")
    return path


def _extract_target(apk: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".qtrace-demo-", suffix=".so", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as target, zipfile.ZipFile(apk) as archive:
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
        os.replace(temporary, destination)
    except (OSError, zipfile.BadZipFile) as error:
        raise QtraceError("demo.extract_failed", "demo.extract", f"cannot extract fixture target: {error}") from error
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    return _regular(destination, "demo.extract")


def build_demo_fixture(repo_root: Path, runner: BoundedRunner, timeout: float) -> DemoFixture:
    """Build the fixture APK and atomically expose its stable arm64 target ELF."""
    root = Path(repo_root).resolve()
    gradlew = _regular(root / "gradlew", "demo.build")
    try:
        runner.capture((str(gradlew), ":app:assembleDebug"), maximum_bytes=_BUILD_OUTPUT_BYTES,
                       timeout=timeout)
    except QtraceError:
        raise
    except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
        raise QtraceError("demo.build_failed", "demo.build", f"fixture build failed: {error}") from error
    apk = _regular(root / _APK_RELATIVE, "demo.build")
    return DemoFixture(apk=apk, target_binary=_extract_target(apk, root / _TARGET_OUTPUT))


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
    target = _regular(fixture.target_binary, "demo.config")
    symbol = _scene_symbol(scenario)
    if scene_form == "offset":
        start, end = inspector.symbol_range(target, symbol)
        scene = OffsetScene("fixture-entry", start, end)
    elif scene_form == "symbol":
        scene = SymbolScene("fixture-entry", symbol)
    else:
        raise QtraceError("demo.scene_form_invalid", "demo.config", "scene form must be offset or symbol")
    flight = scenario == "flight-crash"
    return UserConfig(
        schema_version=1,
        app=AppConfig(_PACKAGE, apk),
        target=TargetConfig(_MODULE, target),
        tracer=TracerConfig("full" if flight else "balanced", True, flight,
                            "fixture-entry" if flight else None, None, None),
        scenes=(scene,),
    )


def make_demo_action(mode: str, seed: int, iterations: int = 30, worker: int = 0) -> InstalledAction:
    """Return the generic post-detach action which starts the fixture intent."""
    intents = {"timed": "timed", "monitor-exit": "exit", "flight-crash": "flight-crash"}
    if mode not in intents:
        raise QtraceError("demo.action_invalid", "demo.action", "unknown fixture scenario")
    if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFFFFFFFFFF:
        raise QtraceError("demo.action_invalid", "demo.action", "seed must be an unsigned 64-bit integer")
    if type(iterations) is not int or iterations <= 0 or type(worker) is not int or worker < 0:
        raise QtraceError("demo.action_invalid", "demo.action", "iterations and worker are invalid")

    def action(device: object, _pid: int) -> None:
        shell = getattr(device, "shell", None)
        if not callable(shell):
            raise QtraceError("demo.device_invalid", "demo.action", "device cannot start the fixture activity")
        shell("am", "start", "-n", _ACTIVITY,
              "--ez", "qtrace_acceptance", "true",
              "--es", "qtrace_acceptance_mode", intents[mode],
              "--el", "qtrace_acceptance_seed", str(seed),
              "--el", "qtrace_acceptance_iterations", str(iterations),
              "--ei", "qtrace_acceptance_worker", str(worker),
              timeout=30.0, maximum_bytes=64 * 1024)

    return action
