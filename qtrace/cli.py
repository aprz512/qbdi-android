"""Command-line entry points for one-shot qtrace sessions."""

from __future__ import annotations

import argparse
import json
import math
import multiprocessing
import os
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Mapping, Sequence

from qtrace.artifacts import ArtifactProcessor, PullMode, PullSelection
from qtrace.config import load_config, parse_duration_ms
from qtrace.demo import build_demo_fixture, make_demo_action, make_demo_config
from qtrace.device import DeviceSelector
from qtrace.elf import ElfInspector, TargetResolver
from qtrace.errors import EXIT_INTERRUPTED, QtraceError
from qtrace.preflight import bind_package_access
from qtrace.process import BoundedRunner
from qtrace.report import SessionReport
from qtrace.session import MonitorRequest, RunRequest, SessionOrchestrator
from qtrace.summary import format_capture_summary


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
        command.add_argument("--abi-report", type=Path,
                             help="require a passing device ABI report matching this tracer and device")
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

    inspect = commands.add_parser("inspect-flight", help="preview Flight metadata within fixed memory/time bounds")
    inspect.add_argument("path", type=Path)
    inspect.add_argument("--timeout", type=_positive_timeout, default=5.0)
    inspect.add_argument("--json", action="store_true")
    inspect.add_argument("--index", type=Path, help="include a source-bound scene index summary without scanning payload")

    scenes = commands.add_parser("scenes-flight", help="query actual scene monotonic timestamps within fixed bounds")
    scenes.add_argument("path", type=Path)
    scenes.add_argument("--since-ns", type=int, default=0)
    scenes.add_argument("--until-ns", type=int, default=2**64 - 1)
    scenes.add_argument("--after-sequence", type=int, default=0)
    scenes.add_argument("--limit", type=int, default=2000)
    scenes.add_argument("--timeout", type=_positive_timeout, default=5.0)
    scenes.add_argument("--index", type=Path, help="query an existing source-bound scene index")

    events = commands.add_parser("events-flight", help="page events in whole scenes overlapping a captured time range")
    events.add_argument("path", type=Path)
    events.add_argument("--since-ns", type=int, default=0)
    events.add_argument("--until-ns", type=int, default=2**64 - 1)
    events.add_argument("--after-sequence", type=int, default=0)
    events.add_argument("--limit", type=int, default=2000)
    events.add_argument("--timeout", type=_positive_timeout, default=30.0)

    tail = commands.add_parser("tail-flight", help="read the last raw Flight events without requiring a closed scene")
    tail.add_argument("path", type=Path)
    tail.add_argument("--after-sequence", type=int, default=0)
    tail.add_argument("--until-sequence", type=int, default=2**64 - 1)
    tail.add_argument("--limit", type=int, default=30)
    tail.add_argument("--timeout", type=_positive_timeout, default=30.0)

    index = commands.add_parser("index-flight", help="build a bounded, reusable Flight scene index")
    index.add_argument("path", type=Path)
    index.add_argument("--index", type=Path, required=True)
    index.add_argument("--max-scan-bytes", type=int, default=4 * 1024**3)
    index.add_argument("--timeout", type=_positive_timeout, default=300.0)
    index.add_argument("--force", action="store_true")

    scene_at = commands.add_parser("scene-at-flight", help="find scenes containing a sequence using an existing index")
    scene_at.add_argument("path", type=Path)
    scene_at.add_argument("--index", type=Path, required=True)
    scene_at.add_argument("--sequence", type=int, required=True)
    scene_at.add_argument("--tid", type=int)
    scene_at.add_argument("--limit", type=int, default=2000)

    convert = commands.add_parser("convert-flight", help="stream strict Flight recovery to an atomic output set")
    convert.add_argument("path", type=Path)
    convert.add_argument("--output", type=Path, required=True)
    convert.add_argument("--after-sequence", type=int, default=0)
    convert.add_argument("--until-sequence", type=int, default=2**64 - 1)
    convert.add_argument("--max-events", type=int)
    convert.add_argument("--max-spool-bytes", type=int, default=16 * 1024**3)
    convert.add_argument("--force", action="store_true")
    convert.add_argument("--json", action="store_true")

    payload = commands.add_parser("inspect-payload", help="verify payload SHA-256 and a recorded build identity")
    payload.add_argument("--library", type=Path, required=True)
    payload.add_argument("--companion", type=Path, required=True)
    payload.add_argument("--identity", type=Path)
    payload.add_argument("--json", action="store_true")

    deploy = commands.add_parser("deploy", help="deploy payload and native JSON into app-private storage without Frida")
    deploy.add_argument("--package", required=True)
    deploy.add_argument("--library", type=Path, required=True)
    deploy.add_argument("--companion", type=Path, required=True)
    deploy.add_argument("--config", type=Path, required=True, help="existing native JSON, not the public CLI config")
    deploy.add_argument("--identity", type=Path)
    deploy.add_argument("--abi-report", type=Path)
    deploy.add_argument("--device")
    deploy.add_argument("--output", type=Path, required=True, help="new local deployment receipt JSON")
    _add_adb_timeout(deploy)

    run = commands.add_parser("run", help="run a duration-bounded trace session")
    _add_common(run, config=True)
    run.add_argument("--duration", type=_duration, required=True, metavar="DURATION",
                     help="duration from 100ms through 24h (for example 30s)")
    _add_setup_timeout(run)
    run.add_argument("--detach-before-resume", action="store_true",
                     help="detach Frida before app startup and verify installation through native status")
    run.add_argument("--stop-timeout", type=_positive_timeout, default=_DEFAULT_STOP_TIMEOUT,
                     metavar="SECONDS", help="native stop deadline in seconds (default: 10)")
    _add_adb_timeout(run)
    _add_pull_timeout(run)

    monitor = commands.add_parser("monitor", help="trace until the app process exits")
    _add_common(monitor, config=True)
    _add_setup_timeout(monitor)
    monitor.add_argument("--detach-before-resume", action="store_true",
                         help="detach Frida before app startup and verify installation through native status")
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


def _query_frida_versions(runtime: "_FridaRuntime", device: object,
                          timeout: float) -> tuple[str, str]:
    try:
        import frida  # type: ignore[import-not-found]
    except ImportError as error:
        raise QtraceError("frida.python_missing", "preflight.frida",
                          "Frida Python bindings are required for injection") from error
    remote = runtime.get_device(device, timeout)
    try:
        parameters = remote.query_system_parameters()
        if not isinstance(parameters, dict):
            raise TypeError("Frida system parameters are not a dictionary")
        server = parameters.get("version")
        if server is None:
            messages: list[object] = []
            session = remote.attach(0)
            script = None
            try:
                script = session.create_script(
                    "send({type: 'qtrace-frida-version', version: Frida.version});"
                )
                script.on("message", lambda message, _data: messages.append(message))
                script.load()
                if len(messages) != 1 or not isinstance(messages[0], dict):
                    raise RuntimeError("Frida system version probe returned no unique message")
                message = messages[0]
                payload = message.get("payload")
                if (message.get("type") != "send" or not isinstance(payload, dict) or
                        set(payload) != {"type", "version"} or
                        payload.get("type") != "qtrace-frida-version" or
                        not isinstance(payload.get("version"), str)):
                    raise RuntimeError("Frida system version probe returned an invalid message")
                server = payload["version"]
            finally:
                if script is not None:
                    script.unload()
                session.detach()
        host = frida.__version__
    except (AttributeError, KeyError, TypeError, RuntimeError) as error:
        raise QtraceError("frida.handshake_failed", "preflight.frida",
                          f"cannot query Frida server version: {error}") from error
    return str(host), str(server)


def _frida_version_worker(runtime: "_FridaRuntime", device: object,
                          timeout: float, channel: object) -> None:
    try:
        host, server = _query_frida_versions(runtime, device, timeout)
        payload: tuple[object, ...] = ("result", host, server)
    except QtraceError as error:
        payload = ("qtrace-error", error.code, error.stage, error.detail, error.exit_code)
    except BaseException as error:
        payload = ("error", type(error).__name__, str(error))
    try:
        channel.send(payload)
    finally:
        channel.close()


class _FridaRuntime:
    """Lazy bridge shared by preflight and the post-preflight injector."""

    def get_device(self, device: object, timeout: float) -> object:
        from qtrace.injector import FridaProvider

        return FridaProvider().get_device(device, timeout)

    def versions(self, device: object, timeout: float) -> tuple[str, str]:
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or
                not math.isfinite(timeout) or timeout <= 0):
            raise QtraceError("frida.handshake_failed", "preflight.frida",
                              "Frida version probe timeout must be finite and positive")
        if (not hasattr(multiprocessing, "get_context") or
                "fork" not in multiprocessing.get_all_start_methods()):
            raise QtraceError("frida.handshake_failed", "preflight.frida",
                              "isolated Frida version probing requires POSIX fork")
        deadline = time.monotonic() + float(timeout)
        context = multiprocessing.get_context("fork")
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(
            target=_frida_version_worker,
            args=(self, device, float(timeout), sender),
            name="qtrace-frida-version-probe",
        )
        started = False
        message: object = None
        timed_out = False
        try:
            process.start()
            started = True
            sender.close()
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not receiver.poll(remaining):
                timed_out = True
            else:
                try:
                    message = receiver.recv()
                except EOFError:
                    message = None
            remaining = max(0.0, deadline - time.monotonic())
            process.join(remaining)
            if process.is_alive():
                timed_out = True
                process.kill()
                process.join(0.2)
            if process.is_alive():
                raise QtraceError("frida.handshake_failed", "preflight.frida",
                                  "Frida version probe worker could not be reaped")
            if timed_out:
                raise QtraceError("frida.handshake_failed", "preflight.frida",
                                  "Frida version probe exceeded the setup deadline")
            if process.exitcode != 0:
                raise QtraceError("frida.handshake_failed", "preflight.frida",
                                  f"Frida version probe exited with status {process.exitcode}")
        finally:
            receiver.close()
            sender.close()
            if started and not process.is_alive():
                process.close()
        if type(message) is not tuple or not message:
            raise QtraceError("frida.handshake_failed", "preflight.frida",
                              "Frida version probe returned an invalid result")
        if (len(message) == 3 and message[0] == "result" and
                isinstance(message[1], str) and isinstance(message[2], str)):
            return message[1], message[2]
        if (len(message) == 5 and message[0] == "qtrace-error" and
                all(isinstance(value, str) for value in message[1:4]) and
                type(message[4]) is int):
            raise QtraceError(message[1], message[2], message[3], exit_code=message[4])
        if (len(message) == 3 and message[0] == "error" and
                isinstance(message[1], str) and isinstance(message[2], str)):
            raise QtraceError("frida.handshake_failed", "preflight.frida",
                              f"Frida version probe failed: {message[1]}: {message[2]}")
        raise QtraceError("frida.handshake_failed", "preflight.frida",
                          "Frida version probe returned an invalid result")


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


def _make_orchestrator(repo_root: Path, inspector: ElfInspector | None = None, *,
                       flight_capacity_mb: int = 512) -> SessionOrchestrator:
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
        flight_capacity_mb=flight_capacity_mb,
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


def _emit_result(report: Path, artifacts: Sequence[Path], exit_code: int, as_json: bool, *,
                 session_report: SessionReport | None = None,
                 records: Sequence[Mapping[str, object]] = ()) -> None:
    if as_json:
        print(json.dumps({"report": str(report), "artifacts": [str(item) for item in artifacts],
                          "exitCode": exit_code}, separators=(",", ":"), ensure_ascii=False))
        return
    if session_report is not None:
        records = session_report.artifacts
    lifecycle = session_report.native.get("lifecycle") if session_report is not None else None
    for line in format_capture_summary(exit_code, records, lifecycle=lifecycle):
        _progress(line)
    print(report)
    for artifact in artifacts:
        print(artifact)


def _run(arguments: argparse.Namespace, repo_root: Path) -> int:
    request = RunRequest(load_config(arguments.config), arguments.device, arguments.output,
                         arguments.duration, arguments.setup_timeout, arguments.stop_timeout,
                         arguments.adb_timeout, arguments.pull_timeout,
                         detach_before_resume=arguments.detach_before_resume,
                         abi_report=arguments.abi_report)
    _progress("starting timed session")
    result = _make_orchestrator(repo_root).run(request)
    _emit_result(result.report, result.outputs, result.exit_code, arguments.json,
                 session_report=result.session_report)
    return result.exit_code


def _monitor(arguments: argparse.Namespace, repo_root: Path) -> int:
    request = MonitorRequest(load_config(arguments.config), arguments.device, arguments.output,
                             arguments.setup_timeout, arguments.adb_timeout, arguments.pull_timeout,
                             detach_before_resume=arguments.detach_before_resume,
                             abi_report=arguments.abi_report)
    _progress("starting monitor session")
    result = _make_orchestrator(repo_root).monitor(request)
    _emit_result(result.report, result.outputs, result.exit_code, arguments.json,
                 session_report=result.session_report)
    return result.exit_code


def _pull(arguments: argparse.Namespace) -> int:
    _progress("collecting artifacts")
    runner = BoundedRunner()
    device = _select_device(arguments.device, runner, arguments.adb_timeout)
    device = bind_package_access(device, arguments.package, timeout=arguments.adb_timeout)
    result = ArtifactProcessor().pull_manual(device, arguments.package, _selection(arguments),
                                             arguments.output, arguments.pull_timeout)
    _emit_result(result.output_dir / "report.json", result.files, result.exit_code, arguments.json,
                 records=getattr(result, "_records", ()))
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
    action = make_demo_action(arguments.scenario, 5855319310239641971,
                              adb_timeout=arguments.adb_timeout)
    orchestrator = _make_orchestrator(
        repo_root, inspector,
        **({"flight_capacity_mb": 64}
           if arguments.scenario == "flight-crash" else {}),
    )
    if is_timed:
        assert duration is not None
        result = orchestrator.run(RunRequest(config, arguments.device, arguments.output, duration,
                                             arguments.setup_timeout, stop_timeout,
                                             arguments.adb_timeout, arguments.pull_timeout, action))
    else:
        result = orchestrator.monitor(MonitorRequest(config, arguments.device, arguments.output,
                                                     arguments.setup_timeout, arguments.adb_timeout,
                                                     arguments.pull_timeout, action))
    _emit_result(result.report, result.outputs, result.exit_code, arguments.json,
                 session_report=result.session_report)
    return result.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        if arguments.command in {"inspect-payload", "deploy"}:
            from qtrace.build import TracerArtifacts
            from qtrace.manual_deploy import deploy_manual, payload_identity, read_manual_config
            try:
                artifacts = TracerArtifacts(arguments.library, arguments.companion)
                identity = payload_identity(artifacts, arguments.identity)
                if arguments.command == "deploy":
                    read_manual_config(arguments.config, arguments.output, arguments.package)
                    runner = BoundedRunner()
                    device = _select_device(arguments.device, runner, arguments.adb_timeout)
                    device = bind_package_access(device, arguments.package, timeout=arguments.adb_timeout)
                    result = deploy_manual(device, artifacts, arguments.config, arguments.output,
                        identity_path=arguments.identity, abi_report=arguments.abi_report,
                        timeout=arguments.adb_timeout)
                    print(json.dumps(result, ensure_ascii=False))
                elif arguments.json:
                    print(json.dumps(identity, ensure_ascii=False))
                else:
                    for name, digest in identity["artifacts"].items():
                        print(f"{name}: {digest}")
                    recorded = identity["build_identity"]
                    print(f"Source: {recorded['source'] if recorded else 'unknown (no matching build identity)'}")
            except (OSError, ValueError) as error:
                raise QtraceError("deploy.input_invalid", "deploy", str(error)) from error
            return 0
        if arguments.command == "convert-flight":
            from scripts.flight_convert import publish_flight_outputs
            from scripts.flight_trace import FlightTraceError
            try:
                paths = publish_flight_outputs(arguments.path, arguments.output, arguments.force,
                    after_sequence=arguments.after_sequence, until_sequence=arguments.until_sequence,
                    max_events=arguments.max_events, max_spool_bytes=arguments.max_spool_bytes)
            except (OSError, FlightTraceError) as error:
                raise QtraceError("flight.convert_failed", "flight.convert", str(error)) from error
            _emit_result(paths[-1], paths[:-1], 0, arguments.json)
            return 0
        if arguments.command in {"index-flight", "scene-at-flight"}:
            from qtrace.flight_scene_index import build_scene_index, scene_at
            from scripts.flight_trace import FlightTraceError
            try:
                if arguments.command == "index-flight":
                    result = build_scene_index(arguments.path, arguments.index,
                        timeout=arguments.timeout, max_payload_bytes=arguments.max_scan_bytes,
                        force=arguments.force)
                else:
                    result = scene_at(arguments.path, arguments.index, sequence=arguments.sequence,
                        tid=arguments.tid, limit=arguments.limit)
            except (OSError, FlightTraceError) as error:
                raise QtraceError("flight.index_failed", "flight.index", str(error)) from error
            print(json.dumps(result, ensure_ascii=False))
            return 0
        if arguments.command == "tail-flight":
            from qtrace.flight_tail import query_tail_path
            from scripts.flight_trace import FlightTraceError
            try:
                result = query_tail_path(arguments.path, after_sequence=arguments.after_sequence,
                    until_sequence=arguments.until_sequence, limit=arguments.limit, timeout=arguments.timeout)
            except (OSError, FlightTraceError) as error:
                raise QtraceError("flight.tail_failed", "flight.tail", str(error)) from error
            print(json.dumps(result, ensure_ascii=False))
            return 0
        if arguments.command == "events-flight":
            from qtrace.flight_scene_events import query_scene_events_path
            from scripts.flight_trace import FlightTraceError
            try:
                result = query_scene_events_path(arguments.path, since_ns=arguments.since_ns,
                    until_ns=arguments.until_ns, after_sequence=arguments.after_sequence,
                    limit=arguments.limit, timeout=arguments.timeout)
            except (OSError, FlightTraceError) as error:
                raise QtraceError("flight.scene_events_failed", "flight.scene_events", str(error)) from error
            print(json.dumps(result, ensure_ascii=False))
            return 0
        if arguments.command == "scenes-flight":
            from qtrace.flight_inspection import query_scene_path
            from scripts.flight_trace import FlightTraceError
            try:
                if arguments.index is not None:
                    from qtrace.flight_scene_index import query_indexed_boundaries
                    result = query_indexed_boundaries(arguments.path, arguments.index,
                        since_ns=arguments.since_ns, until_ns=arguments.until_ns,
                        after_sequence=arguments.after_sequence, limit=arguments.limit, timeout=arguments.timeout)
                else:
                    result = query_scene_path(arguments.path, since_ns=arguments.since_ns,
                        until_ns=arguments.until_ns, after_sequence=arguments.after_sequence,
                        limit=arguments.limit, timeout=arguments.timeout)
            except (OSError, FlightTraceError) as error:
                raise QtraceError("flight.scene_query_failed", "flight.scene_query", str(error)) from error
            print(json.dumps(result, ensure_ascii=False))
            return 0
        if arguments.command == "inspect-flight":
            from qtrace.flight_inspection import inspect_path
            from scripts.flight_trace import FlightTraceError
            try:
                result = inspect_path(arguments.path, timeout=arguments.timeout)
                if arguments.index is not None:
                    from qtrace.flight_scene_index import indexed_summary
                    result["scene_summary"] = indexed_summary(arguments.path, arguments.index)
            except (OSError, FlightTraceError) as error:
                raise QtraceError("flight.inspect_failed", "flight.inspect", str(error)) from error
            if arguments.json:
                print(json.dumps(result, ensure_ascii=False))
            else:
                print(f"{result['target_module']} PID {result['pid']}: {result['artifact_bytes']} bytes, "
                      f"{result['sealed_chunks']} sealed chunks, {result['active_chunks']} active chunks")
                if "scene_summary" in result:
                    summary = result["scene_summary"]
                    print(f"Scene index: {summary['scene_count']} scenes, "
                          f"{summary['returns_observed']} returns observed, "
                          f"{summary['unpaired_scenes']} unpaired; "
                          f"{summary['instruction_count']} instructions.")
                    print("Installation and threads outside the capture: unknown.")
                else:
                    print("Metadata preview; event payloads and target return are unverified.")
            return 0
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
