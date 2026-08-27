"""Command-line entry points for one-shot qtrace sessions."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

from qtrace.artifacts import ArtifactProcessor, PullMode, PullSelection
from qtrace.config import load_config, parse_duration_ms
from qtrace.demo import build_demo_fixture, make_demo_action, make_demo_config
from qtrace.device import DeviceSelector
from qtrace.elf import ElfInspector, TargetResolver
from qtrace.errors import EXIT_INTERRUPTED, QtraceError
from qtrace.process import BoundedRunner
from qtrace.session import MonitorRequest, RunRequest, SessionOrchestrator


_DEFAULT_SETUP_TIMEOUT = 90.0
_DEFAULT_STOP_TIMEOUT = 10.0
_DEFAULT_ADB_TIMEOUT = 30.0
_DEFAULT_PULL_TIMEOUT = 60.0
_DEFAULT_OUTPUT = Path("qtrace-output")


def _positive_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be finite and positive") from error
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("timeout must be finite and positive")
    return parsed


def _duration(value: str) -> int:
    try:
        return parse_duration_ms(value)
    except QtraceError as error:
        raise argparse.ArgumentTypeError(error.detail) from error


def _add_common(command: argparse.ArgumentParser, *, config: bool) -> None:
    if config:
        command.add_argument("--config", type=Path, required=True,
                             help="strict qtrace target configuration JSON")
    command.add_argument("--device", help="ADB serial; required when more than one device is online")
    command.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT,
                         help="directory for reports and artifacts (default: qtrace-output)")
    command.add_argument("--json", action="store_true", help="emit one machine-readable result object")


def _add_setup_timeout(command: argparse.ArgumentParser) -> None:
    command.add_argument("--setup-timeout", type=_positive_timeout, default=_DEFAULT_SETUP_TIMEOUT,
                         metavar="SECONDS", help="setup/build deadline in seconds (default: 90)")


def _add_adb_timeout(command: argparse.ArgumentParser) -> None:
    command.add_argument("--adb-timeout", type=_positive_timeout, default=_DEFAULT_ADB_TIMEOUT,
                         metavar="SECONDS", help="per-ADB-command deadline in seconds (default: 30)")


def _add_pull_timeout(command: argparse.ArgumentParser) -> None:
    command.add_argument("--pull-timeout", type=_positive_timeout, default=_DEFAULT_PULL_TIMEOUT,
                         metavar="SECONDS", help="artifact pull deadline in seconds (default: 60)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qtrace", description="Trace one Android app session with QBDI.")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="run a duration-bounded trace session")
    _add_common(run, config=True)
    run.add_argument("--duration", type=_duration, required=True, metavar="DURATION",
                     help="duration from 100ms through 24h (for example 30s)")
    _add_setup_timeout(run)
    run.add_argument("--stop-timeout", type=_positive_timeout, default=_DEFAULT_STOP_TIMEOUT,
                     metavar="SECONDS", help="native stop deadline in seconds (default: 10)")
    _add_adb_timeout(run)
    _add_pull_timeout(run)

    monitor = commands.add_parser("monitor", help="trace until the app process exits")
    _add_common(monitor, config=True)
    _add_setup_timeout(monitor)
    _add_adb_timeout(monitor)
    _add_pull_timeout(monitor)

    pull = commands.add_parser("pull", help="manually collect already-written trace artifacts")
    _add_common(pull, config=False)
    pull.add_argument("--package", required=True, help="installed Android package name")
    selection = pull.add_mutually_exclusive_group()
    selection.add_argument("--latest", dest="selection", action="store_const", const="latest",
                           help="collect the latest terminal session (default)")
    selection.add_argument("--name", metavar="ARTIFACT", help="collect one trace artifact")
    selection.add_argument("--all", dest="selection", action="store_const", const="all",
                           help="collect every eligible trace artifact")
    pull.set_defaults(selection="latest")
    pull.add_argument("--compressed-only", action="store_true",
                      help="retain only compressed trace artifacts")
    _add_adb_timeout(pull)
    _add_pull_timeout(pull)

    demo = commands.add_parser("demo", help="run the repository fixture for device acceptance only")
    _add_common(demo, config=False)
    demo.add_argument("--scenario", choices=("timed", "monitor-exit", "flight-crash"), default="timed",
                      help="fixture scenario (default: timed)")
    demo.add_argument("--duration", type=_duration, metavar="DURATION",
                      help="timed fixture duration (default: 10s; forbidden for monitor scenarios)")
    demo.add_argument("--scene-form", choices=("offset", "symbol"), default="offset",
                      help="fixture scene representation (default: offset)")
    _add_setup_timeout(demo)
    demo.add_argument("--stop-timeout", type=_positive_timeout,
                      metavar="SECONDS", help="timed native stop deadline in seconds (default: 10)")
    _add_adb_timeout(demo)
    _add_pull_timeout(demo)
    return parser


class _Clock:
    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def utc_timestamp(self) -> str:
        return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class _FridaRuntime:
    """Lazy bridge shared by preflight and the post-preflight injector."""

    def get_device(self, device: object, timeout: float) -> object:
        from qtrace.injector import FridaProvider

        return FridaProvider().get_device(device, timeout)

    def versions(self, device: object, timeout: float) -> tuple[str, str]:
        try:
            import frida  # type: ignore[import-not-found]
        except ImportError as error:
            raise QtraceError("frida.python_missing", "preflight.frida",
                              "Frida Python bindings are required for injection") from error
        remote = self.get_device(device, timeout)
        try:
            parameters = remote.query_system_parameters()
            server = parameters["version"]
            host = frida.__version__
        except (AttributeError, KeyError, TypeError, RuntimeError) as error:
            raise QtraceError("frida.handshake_failed", "preflight.frida",
                              f"cannot query Frida server version: {error}") from error
        return str(host), str(server)


def _ndk_bin() -> Path:
    root = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    if not root:
        raise QtraceError("ndk.not_configured", "target.inspect",
                          "set ANDROID_NDK_HOME or ANDROID_NDK_ROOT to use qtrace")
    host_tags = ("linux-x86_64", "darwin-x86_64", "darwin-arm64", "windows-x86_64")
    base = Path(root) / "toolchains" / "llvm" / "prebuilt"
    for tag in host_tags:
        candidate = base / tag / "bin"
        if candidate.is_dir():
            return candidate
    raise QtraceError("ndk.tool_missing", "target.inspect", "NDK llvm tools are unavailable")


def _make_inspector(runner: BoundedRunner) -> ElfInspector:
    return ElfInspector(runner, _ndk_bin())


def _make_orchestrator(repo_root: Path, inspector: ElfInspector | None = None) -> SessionOrchestrator:
    # These imports intentionally stay behind run/monitor construction.  Manual
    # pull needs neither Gradle nor Frida's Python package.
    from qtrace.build import ArtifactBuilder, Deployer
    from qtrace.injector import FridaInjector
    from qtrace.preflight import Preflight

    runner = BoundedRunner()
    selector = DeviceSelector(runner)
    inspector = inspector or _make_inspector(runner)
    frida = _FridaRuntime()
    return SessionOrchestrator(
        Preflight(selector, frida),
        lambda device: TargetResolver(inspector, device),
        ArtifactBuilder(runner, repo_root),
        Deployer(),
        lambda device: FridaInjector(device, frida),
        ArtifactProcessor(),
        _Clock(),
        lambda: str(uuid.uuid4()),
        device_selector=selector,
    )


def _select_device(serial: str | None, runner: BoundedRunner, timeout: float) -> object:
    return DeviceSelector(runner).select(serial, timeout=timeout)


def _selection(arguments: argparse.Namespace) -> PullSelection:
    if arguments.name is not None:
        return PullSelection(PullMode.NAME, arguments.name, arguments.compressed_only)
    mode = PullMode.ALL if arguments.selection == "all" else PullMode.LATEST
    return PullSelection(mode, None, arguments.compressed_only)


def _progress(message: str) -> None:
    print(f"qtrace: {message}", file=sys.stderr)


def _emit_result(report: Path, artifacts: Sequence[Path], exit_code: int, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"report": str(report), "artifacts": [str(item) for item in artifacts],
                          "exitCode": exit_code}, separators=(",", ":"), ensure_ascii=False))
        return
    print(report)
    for artifact in artifacts:
        print(artifact)


def _run(arguments: argparse.Namespace, repo_root: Path) -> int:
    request = RunRequest(load_config(arguments.config), arguments.device, arguments.output,
                         arguments.duration, arguments.setup_timeout, arguments.stop_timeout,
                         arguments.adb_timeout, arguments.pull_timeout)
    _progress("starting timed session")
    result = _make_orchestrator(repo_root).run(request)
    _emit_result(result.report, result.outputs, result.exit_code, arguments.json)
    return result.exit_code


def _monitor(arguments: argparse.Namespace, repo_root: Path) -> int:
    request = MonitorRequest(load_config(arguments.config), arguments.device, arguments.output,
                             arguments.setup_timeout, arguments.adb_timeout, arguments.pull_timeout)
    _progress("starting monitor session")
    result = _make_orchestrator(repo_root).monitor(request)
    _emit_result(result.report, result.outputs, result.exit_code, arguments.json)
    return result.exit_code


def _pull(arguments: argparse.Namespace) -> int:
    _progress("collecting artifacts")
    runner = BoundedRunner()
    device = _select_device(arguments.device, runner, arguments.adb_timeout)
    result = ArtifactProcessor().pull_manual(device, arguments.package, _selection(arguments),
                                             arguments.output, arguments.pull_timeout)
    _emit_result(result.output_dir / "report.json", result.files, result.exit_code, arguments.json)
    return result.exit_code


def _demo(arguments: argparse.Namespace, repo_root: Path) -> int:
    is_timed = arguments.scenario == "timed"
    if not is_timed and arguments.duration is not None:
        raise QtraceError("demo.duration_forbidden", "demo", "--duration is valid only for the timed scenario")
    if not is_timed and arguments.stop_timeout is not None:
        raise QtraceError("demo.stop_timeout_forbidden", "demo",
                          "--stop-timeout is valid only for the timed scenario")
    duration = (arguments.duration if arguments.duration is not None else _duration("10s")) if is_timed else None
    stop_timeout = arguments.stop_timeout if arguments.stop_timeout is not None else _DEFAULT_STOP_TIMEOUT
    runner = BoundedRunner()
    _progress("building fixture artifacts")
    fixture = build_demo_fixture(repo_root, runner, arguments.setup_timeout)
    inspector = _make_inspector(runner)
    config = make_demo_config(fixture, inspector, arguments.scene_form, arguments.scenario)
    action = make_demo_action(arguments.scenario, 5855319310239641971)
    orchestrator = _make_orchestrator(repo_root, inspector)
    if is_timed:
        assert duration is not None
        result = orchestrator.run(RunRequest(config, arguments.device, arguments.output, duration,
                                             arguments.setup_timeout, stop_timeout,
                                             arguments.adb_timeout, arguments.pull_timeout, action))
    else:
        result = orchestrator.monitor(MonitorRequest(config, arguments.device, arguments.output,
                                                     arguments.setup_timeout, arguments.adb_timeout,
                                                     arguments.pull_timeout, action))
    _emit_result(result.report, result.outputs, result.exit_code, arguments.json)
    return result.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        if arguments.command == "run":
            return _run(arguments, repo_root)
        if arguments.command == "monitor":
            return _monitor(arguments, repo_root)
        if arguments.command == "pull":
            return _pull(arguments)
        if arguments.command == "demo":
            return _demo(arguments, repo_root)
        raise AssertionError(f"unknown command {arguments.command}")
    except QtraceError as error:
        print(str(error), file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
