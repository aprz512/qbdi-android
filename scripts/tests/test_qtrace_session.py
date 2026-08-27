import contextlib
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from qtrace.errors import EXIT_PARTIAL, EXIT_STOP_INCOMPLETE, ErrorCode, QtraceError
from qtrace.models import (
    AppConfig, ElfIdentity, OffsetScene, ResolvedScene, ResolvedTarget, SymbolScene, TargetConfig, TracerConfig, UserConfig,
)
from qtrace.session import (
    MonitorRequest, RunRequest, SessionOrchestrator, _strict_json, build_native_request, parse_status,
)
from qtrace.lock import TargetLock
from scripts.bounded_process import BoundedProcessError


SESSION_ID = "123e4567-e89b-42d3-a456-426614174000"
PACKAGE = "com.example.app"
SCENES = (ResolvedScene("work", 0x120, 0x180),)


def config() -> UserConfig:
    return UserConfig(1, AppConfig(PACKAGE, None), TargetConfig("libwork.so", None),
                      TracerConfig("balanced", True, False, None, None, None), (OffsetScene("work", 0x120, 0x180),))


def target() -> ResolvedTarget:
    return ResolvedTarget(PACKAGE, "libwork.so", Path("/host/libwork.so"), "/app/libwork.so",
                          ElfIdentity("ELF64", "AArch64", "ab", ((0x100, 0x200),)), SCENES)


def status(state: str, *, transition: int, pid: int = 4242, reason: str = "",
           acknowledged: bool = False, artifacts: list[str] | None = None) -> dict[str, object]:
    if state in {"stop_requested", "stopping", "stop_incomplete"} and reason == "":
        reason = "duration_elapsed"
    return {
        "schemaVersion": 1, "sessionId": SESSION_ID, "generation": 7, "packageName": PACKAGE,
        "pid": pid, "state": state, "reason": reason, "transitionMonotonicNs": transition,
        "normalizedScenes": [{"name": "work", "startOffset": 0x120, "endOffset": 0x180}],
        "activeScenes": [], "artifacts": artifacts or ["run.trace.bin.lz4"],
        "stopAcknowledged": acknowledged, "warnings": [], "errors": [],
    }


def process_failed(returncode: int, stderr: bytes) -> QtraceError:
    error = QtraceError("process.failed", "process", "command failed")
    error.__cause__ = BoundedProcessError("command failed", returncode=returncode, stderr=stderr)
    return error


def process_timeout() -> QtraceError:
    error = QtraceError("process.timeout", "process", "timed out")
    error.__cause__ = subprocess.TimeoutExpired(("adb",), 0.1)
    return error


class ManualClock:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds

    def utc_timestamp(self) -> str:
        return "2026-08-27T00:00:00Z"


class FakeDevice:
    serial = "device-1"

    def __init__(self, statuses: list[object], pids: list[int | None]) -> None:
        self.statuses, self.pids = list(statuses), list(pids)
        self.read_paths: list[str] = []
        self.shell_timeouts: list[tuple[str, float]] = []
        self.killed: list[int] = []

    def read_file(self, path: str, maximum_bytes: int, *, timeout: float) -> bytes:
        self.read_paths.append(path)
        value = self.statuses.pop(0) if self.statuses else status("sealed", transition=4,
                                                                  reason="duration_elapsed", acknowledged=True)
        if isinstance(value, Exception):
            raise value
        return json.dumps(value).encode("utf-8")

    def pid(self, package: str) -> int | None:
        return self.pids.pop(0) if self.pids else 4242

    def target_shell(self, *args: str, timeout: float, maximum_bytes: int) -> bytes:
        self.shell_timeouts.append((args[0], timeout))
        if args[:2] == ("ls", "-1"):
            return b"old.trace.bin.lz4\n"
        if args[0] == "cat":
            return self.read_file(args[1], maximum_bytes, timeout=timeout)
        if args[0] == "pidof":
            current = self.pid(args[1])
            return b"" if current is None else str(current).encode("ascii")
        raise AssertionError(args)

    def kill(self, pid: int) -> None:
        self.killed.append(pid)

    def list_tracer_artifacts(self, package: str, *, timeout: float) -> tuple[str, ...]:
        return ("old.trace.bin.lz4",)


class FakePreflight:
    def __init__(self, device: FakeDevice) -> None:
        self.device = device

    def run(self, config: UserConfig, requested_device: str | None, *, setup_timeout: float,
            adb_timeout: float):
        return self.device, object()


@dataclass(frozen=True)
class Artifacts:
    tracer_so: Path = Path("/host/tracer.so")
    companion: Path = Path("/host/companion.so")


@dataclass(frozen=True)
class Deployment:
    tracer_so: str = "/data/tracer.so"
    companion: str = "/data/companion.so"


class FakeBuilder:
    def select_or_build(self, tracer: TracerConfig, *, timeout: float) -> Artifacts:
        return Artifacts()


class FakeDeployer:
    def deploy(self, device: FakeDevice, session_id: str, artifacts: Artifacts) -> Deployment:
        return Deployment()


class FakeInjector:
    def __init__(self) -> None:
        self.requests = []

    def install(self, request):
        self.requests.append(request)
        from qtrace.injector import InjectionResult
        return InjectionResult(4242, SESSION_ID, 7, SCENES)


class FakeCollector:
    def __init__(self, exit_code: int = 0) -> None:
        self.exit_code = exit_code
        self.calls = []

    def collect_session(self, device, package, session_id, status, output, timeout):
        self.calls.append(status)
        return self.exit_code, ()


def orchestrator(device: FakeDevice, clock: ManualClock, collector: FakeCollector | None = None):
    injector = FakeInjector()
    return SessionOrchestrator(
        FakePreflight(device), lambda selected: type("Resolver", (), {"resolve": lambda self, _: target()})(),
        FakeBuilder(), FakeDeployer(), lambda selected: injector, collector or FakeCollector(), clock,
        lambda: SESSION_ID, device_selector=lambda _requested, *, timeout: device,
    ), injector


class NativeRequestTests(unittest.TestCase):
    def test_builds_exact_native_request_without_host_or_absolute_fields(self) -> None:
        request = build_native_request(config(), target(), SESSION_ID, 250)
        self.assertEqual(1, request["schemaVersion"])
        self.assertEqual(250, request["session"]["durationMs"])
        self.assertEqual({"packageName", "targetModule", "trace", "flight", "scenes", "session", "schemaVersion"}, set(request))
        self.assertEqual({"name": "work", "location": {"offset": "0x120", "endOffset": "0x180"}}, request["scenes"][0])

    def test_monitor_request_omits_duration(self) -> None:
        self.assertNotIn("durationMs", build_native_request(config(), target(), SESSION_ID, None)["session"])


class StatusTests(unittest.TestCase):
    def test_accepts_only_exact_matching_native_status(self) -> None:
        parsed = parse_status(status("sealed", transition=4, reason="duration_elapsed", acknowledged=True),
                              SESSION_ID, PACKAGE, 7, 4242, SCENES, None)
        self.assertEqual("sealed", parsed["state"])

    def test_rejects_extra_bool_and_unsafe_artifact_fields(self) -> None:
        for mutate in (
            lambda value: value.update({"extra": 1}),
            lambda value: value.update({"generation": True}),
            lambda value: value.update({"artifacts": ["../escape"]}),
        ):
            value = status("running", transition=1)
            mutate(value)
            with self.subTest(value=value), self.assertRaises(QtraceError):
                parse_status(value, SESSION_ID, PACKAGE, 7, 4242, SCENES, None)

    def test_rejects_state_regression_and_changed_same_transition(self) -> None:
        previous = parse_status(status("stopping", transition=3), SESSION_ID, PACKAGE, 7, 4242, SCENES, None)
        for later in (status("running", transition=4), status("sealed", transition=3)):
            with self.subTest(later=later), self.assertRaises(QtraceError):
                parse_status(later, SESSION_ID, PACKAGE, 7, 4242, SCENES, previous)

    def test_rejects_terminal_state_switch_duplicate_active_and_unsafe_text(self) -> None:
        sealed = parse_status(status("sealed", transition=3, reason="duration_elapsed", acknowledged=True),
                              SESSION_ID, PACKAGE, 7, 4242, SCENES, None)
        invalid = (
            status("stop_incomplete", transition=4),
            {**status("running", transition=1), "activeScenes": [
                {"sceneIndex": 0, "tid": 8, "sealed": False},
                {"sceneIndex": 0, "tid": 8, "sealed": False},
            ]},
            status("running", transition=1, reason="bad\u0000reason"),
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate), self.assertRaises(QtraceError):
                parse_status(candidate, SESSION_ID, PACKAGE, 7, 4242, SCENES,
                             sealed if candidate["state"] == "stop_incomplete" else None)

    def test_strict_json_rejects_duplicate_nonfinite_and_non_utf8_input(self) -> None:
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(QtraceError):
                _strict_json(raw)


class SessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def run_request(self) -> RunRequest:
        return RunRequest(config(), None, Path(self.directory.name), 250, 2.0, 2.0, 0.5, 1.0)

    def test_timed_run_polls_native_seal_once_and_never_stops_app(self) -> None:
        device = FakeDevice([status("running", transition=1), status("stopping", transition=2),
                             status("sealed", transition=3, reason="duration_elapsed", acknowledged=True)], [4242])
        clock = ManualClock()
        runner, injector = orchestrator(device, clock)
        result = runner.run(self.run_request())
        self.assertEqual(0, result.exit_code)
        self.assertEqual(1, len(injector.requests))
        self.assertEqual(250, injector.requests[0].native_request["session"]["durationMs"])
        self.assertEqual([], device.killed)
        timeline = json.loads(result.report.read_text(encoding="utf-8"))["timeline"]
        self.assertEqual(
            ["preflight", "resolving_target", "building_tracer", "deploying", "injecting",
             "installing_hooks", "running", "stopping", "sealed", "pulling", "completed"],
            [entry["stage"] for entry in timeline],
        )
        document = json.loads(result.report.read_text(encoding="utf-8"))
        self.assertTrue(document["device"]["identity"])
        self.assertTrue(document["tracer"]["artifacts"])
        self.assertTrue(document["tracer"]["deployment"])
        self.assertTrue(document["target"]["resolved"])
        self.assertTrue(document["effective_config"]["config"])
        self.assertTrue(document["native"]["request"])
        self.assertEqual(7, document["native"]["status"]["generation"])

    def test_timed_stop_timeout_is_partial_without_reinjection(self) -> None:
        device = FakeDevice([status("stop_requested", transition=1)] * 100, [4242])
        clock = ManualClock()
        runner, injector = orchestrator(device, clock)
        result = runner.run(self.run_request())
        self.assertEqual(EXIT_STOP_INCOMPLETE, result.exit_code)
        self.assertEqual(1, len(injector.requests))
        self.assertEqual([], device.killed)

    def test_timed_run_rejects_pid_replacement_before_accepting_a_seal(self) -> None:
        device = FakeDevice([status("sealed", transition=2, reason="duration_elapsed", acknowledged=True)], [9000])
        runner, _ = orchestrator(device, ManualClock())
        with self.assertRaisesRegex(QtraceError, "session.pid_replaced"):
            runner.run(self.run_request())

    def test_timed_deadline_without_native_stop_is_an_error_not_a_fabricated_partial(self) -> None:
        device = FakeDevice([status("running", transition=1)] * 100, [4242])
        runner, _ = orchestrator(device, ManualClock())
        with self.assertRaisesRegex(QtraceError, "session.run_timeout"):
            runner.run(self.run_request())

    def test_monitor_waits_for_owned_pid_exit_and_classifies_normal_collection(self) -> None:
        device = FakeDevice([status("running", transition=1)], [4242, None])
        runner, _ = orchestrator(device, ManualClock())
        request = MonitorRequest(config(), None, Path(self.directory.name), 2.0, 0.5, 1.0)
        result = runner.monitor(request)
        self.assertEqual(0, result.exit_code)

    def test_monitor_pid_replacement_fails_without_new_injection(self) -> None:
        device = FakeDevice([status("running", transition=1)], [4242, 9000])
        runner, injector = orchestrator(device, ManualClock())
        request = MonitorRequest(config(), None, Path(self.directory.name), 2.0, 0.5, 1.0)
        with self.assertRaisesRegex(QtraceError, "session.pid_replaced"):
            runner.monitor(request)
        self.assertEqual(1, len(injector.requests))
        self.assertEqual([], device.killed)

    def test_monitor_recovery_is_partial_and_does_not_invent_terminal(self) -> None:
        device = FakeDevice([status("running", transition=1)], [4242, None])
        runner, _ = orchestrator(device, ManualClock(), FakeCollector(EXIT_PARTIAL))
        request = MonitorRequest(config(), None, Path(self.directory.name), 2.0, 0.5, 1.0)
        self.assertEqual(EXIT_PARTIAL, runner.monitor(request).exit_code)

    def test_transient_adb_failures_retry_to_phase_deadline_without_reinjecting(self) -> None:
        device = FakeDevice([OSError("disconnect")] * 100, [4242])
        runner, injector = orchestrator(device, ManualClock())
        with self.assertRaisesRegex(QtraceError, ErrorCode.ADB_UNAVAILABLE.value):
            runner.run(self.run_request())
        self.assertEqual(1, len(injector.requests))
        self.assertEqual([], device.killed)

    def test_keyboard_interrupt_after_resume_publishes_pullable_report_and_reraises(self) -> None:
        device = FakeDevice([status("running", transition=1)], [4242])
        runner, _ = orchestrator(device, ManualClock())
        request = RunRequest(config(), None, Path(self.directory.name), 250, 2.0, 2.0, 0.5, 1.0,
                             installed_action=lambda _device, _pid: (_ for _ in ()).throw(KeyboardInterrupt()))
        with self.assertRaises(KeyboardInterrupt):
            runner.run(request)
        report = Path(self.directory.name) / SESSION_ID / "report.json"
        document = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual("interrupted", document["status"])
        self.assertEqual(["qtrace pull --package com.example.app --latest --device device-1"], document["outputs"])
        self.assertEqual([], device.killed)

    def test_keyboard_interrupt_prints_pull_command_when_report_fails(self) -> None:
        device = FakeDevice([], [])
        class FailingWriter:
            def write_atomic(self, *_args):
                raise OSError("disk unavailable")
        runner, _ = orchestrator(device, ManualClock())
        runner._report_writer = FailingWriter()  # explicit publication seam
        request = RunRequest(config(), None, Path(self.directory.name), 250, 2.0, 2.0, 0.5, 1.0,
                             installed_action=lambda _device, _pid: (_ for _ in ()).throw(KeyboardInterrupt()))
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(KeyboardInterrupt):
            runner.run(request)
        self.assertIn("qtrace pull --package com.example.app", stderr.getvalue())

    def test_invalid_request_and_uuid_do_not_call_selector(self) -> None:
        calls: list[object] = []
        device = FakeDevice([], [])
        invalid = RunRequest(config(), None, Path(self.directory.name), 99, 2.0, 2.0, 0.5, 1.0)
        runner = SessionOrchestrator(
            FakePreflight(device), lambda _selected: None, FakeBuilder(), FakeDeployer(),
            lambda _selected: FakeInjector(), FakeCollector(), ManualClock(), lambda: "not-a-uuid",
            device_selector=lambda *_args, **_kwargs: calls.append("selector"),
        )
        with self.assertRaises(QtraceError):
            runner.run(invalid)
        self.assertEqual([], calls)

    def test_invalid_action_package_and_output_have_zero_selector_calls(self) -> None:
        device = FakeDevice([], [])
        calls: list[str] = []
        runner, _ = orchestrator(device, ManualClock())
        runner._device_selector = lambda *_args, **_kwargs: calls.append("select")
        regular = Path(self.directory.name) / "regular"
        regular.write_text("x", encoding="utf-8")
        invalid = (
            RunRequest(config(), None, Path(self.directory.name), 250, 2, 2, .5, 1, installed_action=object()),
            RunRequest(UserConfig(1, AppConfig("bad package", None), TargetConfig("x", None), config().tracer, config().scenes), None, Path(self.directory.name), 250, 2, 2, .5, 1),
            RunRequest(config(), None, regular / "out", 250, 2, 2, .5, 1),
        )
        for request in invalid:
            with self.assertRaises(QtraceError):
                runner.run(request)
        self.assertEqual([], calls)

    def test_adversarial_normalized_config_has_zero_selector_calls(self) -> None:
        calls: list[str] = []
        runner, _ = orchestrator(FakeDevice([], []), ManualClock())
        runner._device_selector = lambda *_args, **_kwargs: calls.append("select")
        base = config()
        invalid = (
            UserConfig(True, base.app, base.target, base.tracer, base.scenes),
            UserConfig(1, base.app, TargetConfig("../bad", None), base.tracer, base.scenes),
            UserConfig(1, base.app, base.target, TracerConfig([], True, False, None, None, None), base.scenes),
            UserConfig(1, base.app, base.target, base.tracer, ()),
        )
        for value in invalid:
            request = RunRequest(value, None, Path(self.directory.name), 250, 2, 2, .5, 1)
            with self.assertRaises(QtraceError):
                runner.run(request)
        self.assertEqual([], calls)

    def test_all_optional_host_paths_are_absolute_regular_non_symlinks_before_selection(self) -> None:
        calls: list[str] = []
        runner, _ = orchestrator(FakeDevice([], []), ManualClock())
        runner._device_selector = lambda *_args, **_kwargs: calls.append("select")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "valid.so"
            valid.write_bytes(b"valid")
            link = root / "link.so"
            link.symlink_to(valid)
            invalid_paths = (Path("relative.so"), root, link, root / "missing.so")

            for field in ("apk", "binary", "library", "companion"):
                for invalid_path in invalid_paths:
                    app = AppConfig(PACKAGE, invalid_path if field == "apk" else None)
                    target_config = TargetConfig("libwork.so", invalid_path if field == "binary" else None)
                    library = invalid_path if field == "library" else valid
                    companion = invalid_path if field == "companion" else valid
                    tracer = TracerConfig("balanced", True, False, None, library, companion)
                    candidate = UserConfig(1, app, target_config, tracer, config().scenes)
                    request = RunRequest(candidate, None, root, 250, 2, 2, .5, 1)
                    with self.subTest(field=field, path=invalid_path):
                        with self.assertRaises(QtraceError):
                            runner.run(request)
            self.assertEqual([], calls)

    def test_normalized_config_rejects_string_subclasses_at_every_string_boundary(self) -> None:
        class StringSubclass(str):
            pass

        calls: list[str] = []
        runner, _ = orchestrator(FakeDevice([], []), ManualClock())
        runner._device_selector = lambda *_args, **_kwargs: calls.append("select")
        base = config()
        candidates = (
            UserConfig(1, AppConfig(StringSubclass(PACKAGE), None), base.target, base.tracer, base.scenes),
            UserConfig(1, base.app, TargetConfig(StringSubclass("libwork.so"), None), base.tracer, base.scenes),
            UserConfig(1, base.app, base.target,
                       TracerConfig(StringSubclass("balanced"), True, False, None, None, None), base.scenes),
            UserConfig(1, base.app, base.target, base.tracer,
                       (OffsetScene(StringSubclass("work"), 0x120, 0x180),)),
            UserConfig(1, base.app, base.target, base.tracer,
                       (SymbolScene("work", StringSubclass("symbol")),)),
            UserConfig(1, base.app, base.target,
                       TracerConfig("balanced", True, True, StringSubclass("work"), None, None),
                       base.scenes),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(QtraceError):
                runner.run(RunRequest(candidate, None, Path(self.directory.name), 250, 2, 2, .5, 1))
        with self.assertRaises(QtraceError):
            runner.run(RunRequest(base, StringSubclass("device-1"), Path(self.directory.name), 250, 2, 2, .5, 1))
        self.assertEqual([], calls)

    def test_transient_after_stop_request_is_adb_error_and_does_not_collect(self) -> None:
        device = FakeDevice(
            [status("stop_requested", transition=1), process_timeout()], [4242]
        )
        clock = ManualClock()
        collector = FakeCollector()
        runner, _ = orchestrator(device, clock, collector)
        request = RunRequest(config(), None, Path(self.directory.name), 100, 2, .001, .5, 1)
        with self.assertRaisesRegex(QtraceError, ErrorCode.ADB_UNAVAILABLE.value):
            runner.run(request)
        self.assertEqual([], collector.calls)

    def test_selector_and_lock_enter_failures_publish_without_masking(self) -> None:
        device = FakeDevice([], [])
        publications: list[str] = []
        class Writer:
            def write_atomic(self, _path, report): publications.append(report.status)
        runner, _ = orchestrator(device, ManualClock())
        runner._report_writer = Writer()
        runner._device_selector = lambda *_args, **_kwargs: (_ for _ in ()).throw(QtraceError("selector.failed", "selector", "no"))
        with self.assertRaisesRegex(QtraceError, "selector.failed"):
            runner.run(self.run_request())
        self.assertEqual(["error"], publications)
        class BadLock:
            def acquire(self, *_args):
                class Context:
                    def __enter__(_self): raise QtraceError("lock.failed", "lock", "no")
                    def __exit__(_self, *_args): raise AssertionError("exit after failed enter")
                return Context()
        runner, _ = orchestrator(device, ManualClock())
        runner._report_writer, runner._lock = Writer(), BadLock()
        with self.assertRaisesRegex(QtraceError, "lock.failed"):
            runner.run(self.run_request())
        self.assertEqual(["error", "error"], publications)

    def test_selector_is_a_required_constructor_dependency(self) -> None:
        device = FakeDevice([], [])
        with self.assertRaises(TypeError):
            SessionOrchestrator(
                FakePreflight(device), lambda _selected: None, FakeBuilder(), FakeDeployer(),
                lambda _selected: FakeInjector(), FakeCollector(), ManualClock(), lambda: SESSION_ID,
            )

    def test_selector_lock_preflight_order_and_no_fallback(self) -> None:
        events: list[str] = []
        device = FakeDevice([status("sealed", transition=2, reason="duration_elapsed", acknowledged=True)], [4242])

        class OrderedPreflight(FakePreflight):
            def run(self, *args, **kwargs):
                events.append("preflight")
                return super().run(*args, **kwargs)

        class OrderedLock:
            def acquire(self, serial, package):
                self.serial, self.package = serial, package
                class Context:
                    def __enter__(_self): events.append("lock"); return None
                    def __exit__(_self, *_args): events.append("unlock")
                return Context()

        runner = SessionOrchestrator(
            OrderedPreflight(device), lambda _selected: type("Resolver", (), {"resolve": lambda self, _: target()})(),
            FakeBuilder(), FakeDeployer(), lambda _selected: FakeInjector(), FakeCollector(), ManualClock(),
            lambda: SESSION_ID, lock=OrderedLock(), device_selector=lambda requested, *, timeout: (events.append("select") or device),
        )
        runner.run(self.run_request())
        self.assertEqual(["select", "lock", "preflight"], events[:3])

    def test_real_selector_shape_uses_keyword_timeout(self) -> None:
        device = FakeDevice([status("sealed", transition=2, reason="duration_elapsed", acknowledged=True)], [4242])
        calls = []
        class Selector:
            def select(self, requested_device, *, timeout):
                calls.append((requested_device, timeout))
                return device
        runner = SessionOrchestrator(
            FakePreflight(device), lambda _selected: type("Resolver", (), {"resolve": lambda self, _: target()})(),
            FakeBuilder(), FakeDeployer(), lambda _selected: FakeInjector(), FakeCollector(), ManualClock(),
            lambda: SESSION_ID, device_selector=Selector(),
        )
        runner.run(self.run_request())
        self.assertEqual([(None, 0.5)], calls)

    def test_none_request_and_surrogate_status_are_stable_qtrace_errors(self) -> None:
        runner, _ = orchestrator(FakeDevice([], []), ManualClock())
        with self.assertRaises(QtraceError):
            runner.run(None)  # type: ignore[arg-type]
        malformed = status("running", transition=1, reason="\ud800")
        with self.assertRaises(QtraceError):
            parse_status(malformed, SESSION_ID, PACKAGE, 7, 4242, SCENES, None)

    def test_wrapped_enoent_snapshot_and_final_status_are_absent_only(self) -> None:
        device = FakeDevice([], [4242, None])
        original_shell = device.target_shell
        def shell(*args, **kwargs):
            if args[0] == "ls" or args[0] == "cat":
                raise process_failed(1, f"{args[-1]}: No such file or directory".encode())
            return original_shell(*args, **kwargs)
        device.target_shell = shell  # type: ignore[method-assign]
        runner, _ = orchestrator(device, ManualClock())
        self.assertEqual(0, runner.monitor(MonitorRequest(config(), None, Path(self.directory.name), 2.0, 0.5, 1.0)).exit_code)

    def test_pidof_exact_empty_rc1_means_process_exited(self) -> None:
        device = FakeDevice([], [])
        original_shell = device.target_shell
        def shell(*args, **kwargs):
            if args[0] == "pidof":
                raise process_failed(1, b"")
            return original_shell(*args, **kwargs)
        device.target_shell = shell  # type: ignore[method-assign]
        runner, _ = orchestrator(device, ManualClock())
        self.assertIsNone(runner._current_pid(device, PACKAGE, 0.5))

    def test_target_shell_status_receives_explicit_clipped_timeout(self) -> None:
        device = FakeDevice([status("running", transition=1)], [4242])
        runner, _ = orchestrator(device, ManualClock())
        from qtrace.injector import InjectionResult
        request = self.run_request()
        runner._read_status(device, request, InjectionResult(4242, SESSION_ID, 7, SCENES), SESSION_ID, None, 0.125)
        self.assertEqual(("cat", 0.125), device.shell_timeouts[-1])

    def test_monitor_outage_sleep_does_not_overshoot_deadline(self) -> None:
        device = FakeDevice([], [4242])
        device.pids = [process_timeout()] * 2
        # target_shell uses pid(), so make each pid query a production timeout.
        def shell(*args, **kwargs):
            if args[0] == "ls": return b""
            if args[0] == "pidof": raise process_timeout()
            raise AssertionError(args)
        device.target_shell = shell  # type: ignore[method-assign]
        clock = ManualClock(); runner, _ = orchestrator(device, clock)
        with self.assertRaisesRegex(QtraceError, ErrorCode.ADB_UNAVAILABLE.value):
            runner.monitor(MonitorRequest(config(), None, Path(self.directory.name), .05, .5, 1))
        self.assertLessEqual(clock.monotonic(), .05)

    def test_tiny_timed_deadline_timeout_is_adb_unavailable(self) -> None:
        device = FakeDevice([], [4242])
        clock = ManualClock()
        original_shell = device.target_shell
        def shell(*args, **kwargs):
            if args[0] == "pidof":
                clock.sleep(kwargs["timeout"])
                raise process_timeout()
            return original_shell(*args, **kwargs)
        device.target_shell = shell  # type: ignore[method-assign]
        runner, injector = orchestrator(device, clock)
        request = RunRequest(config(), None, Path(self.directory.name), 100, 2, .001, .5, 1)
        with self.assertRaisesRegex(QtraceError, ErrorCode.ADB_UNAVAILABLE.value):
            runner.run(request)
        self.assertLessEqual(clock.monotonic(), .101)
        self.assertEqual(1, len(injector.requests))

    def test_error_and_interrupt_reports_are_published_before_unlock_and_never_mask_primary(self) -> None:
        for primary in (QtraceError("session.boom", "test", "boom"), KeyboardInterrupt(), ValueError("raw")):
            with self.subTest(primary=type(primary).__name__):
                events: list[str] = []
                device = FakeDevice([], [])

                class RecordingLock:
                    def acquire(self, *_args):
                        class Context:
                            def __enter__(_self): events.append("lock")
                            def __exit__(_self, *_args): events.append("unlock")
                        return Context()

                class FailingWriter:
                    def write_atomic(self, *_args):
                        events.append("publish")
                        raise OSError("report failed")

                def fail_install(_request):
                    raise primary

                injector = type("Injector", (), {"install": staticmethod(fail_install)})()
                runner = SessionOrchestrator(
                    FakePreflight(device), lambda _selected: type("Resolver", (), {"resolve": lambda self, _: target()})(),
                    FakeBuilder(), FakeDeployer(), lambda _selected: injector, FakeCollector(), ManualClock(),
                    lambda: SESSION_ID, lock=RecordingLock(), report_writer=FailingWriter(),
                    device_selector=lambda _requested, *, timeout: device,
                )
                with self.assertRaises(type(primary)):
                    runner.run(self.run_request())
                self.assertLess(events.index("publish"), events.index("unlock"))

    def test_monitor_has_no_total_runtime_deadline_and_reads_final_status(self) -> None:
        device = FakeDevice([status("sealed", transition=4, reason="duration_elapsed", acknowledged=True)],
                            [4242] * 25 + [None])
        clock, collector = ManualClock(), FakeCollector()
        runner, _ = orchestrator(device, clock, collector)
        result = runner.monitor(MonitorRequest(config(), None, Path(self.directory.name), 0.2, 0.5, 1.0))
        self.assertGreater(clock.monotonic(), 0.2)
        self.assertEqual("sealed", collector.calls[-1]["state"])
        self.assertEqual("sealed", json.loads(result.report.read_text(encoding="utf-8"))["native"]["status"]["state"])

    def test_wrapped_transient_qtrace_error_retries_without_reinjection(self) -> None:
        device = FakeDevice([QtraceError(ErrorCode.ADB_UNAVAILABLE, "adb", "lost"),
                             status("sealed", transition=2, reason="duration_elapsed", acknowledged=True)], [4242])
        runner, injector = orchestrator(device, ManualClock())
        self.assertEqual(0, runner.run(self.run_request()).exit_code)
        self.assertEqual(1, len(injector.requests))


class LockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def test_same_target_conflicts_but_different_targets_do_not(self) -> None:
        first = TargetLock(Path(self.directory.name))
        second = TargetLock(Path(self.directory.name))
        with first.acquire("device-1", PACKAGE):
            with self.assertRaisesRegex(QtraceError, ErrorCode.SESSION_BUSY.value):
                with second.acquire("device-1", PACKAGE):
                    pass
            with second.acquire("device-2", PACKAGE):
                pass

    def test_interrupt_releases_the_advisory_lock(self) -> None:
        lock = TargetLock(Path(self.directory.name))
        with self.assertRaises(KeyboardInterrupt):
            with lock.acquire("device-1", PACKAGE):
                raise KeyboardInterrupt()
        with lock.acquire("device-1", PACKAGE):
            pass

    def test_refuses_symlinked_lock_root(self) -> None:
        runtime = Path(self.directory.name)
        target = runtime / "target"
        target.mkdir()
        (runtime / f"qtrace-{__import__('os').getuid()}").symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(QtraceError, "session.lock_invalid"):
            with TargetLock(runtime).acquire("device-1", PACKAGE):
                pass

    def test_refuses_intermediate_symlinked_runtime_component(self) -> None:
        runtime = Path(self.directory.name) / "runtime"
        actual = Path(self.directory.name) / "actual"
        runtime.mkdir(); actual.mkdir()
        (runtime / "link").symlink_to(actual, target_is_directory=True)
        with self.assertRaises(QtraceError):
            with TargetLock(runtime / "link" / "sub").acquire("device-1", PACKAGE):
                pass
        self.assertFalse(any(actual.glob("qtrace-*")))

    def test_preexisting_digest_symlink_is_stable_across_repeated_attempts(self) -> None:
        runtime = Path(self.directory.name)
        root = runtime / f"qtrace-{os.getuid()}"
        root.mkdir()
        digest = hashlib.sha256(("device-1" + "\0" + PACKAGE).encode("utf-8")).hexdigest()
        lock_path = root / f"{digest}.lock"
        target = runtime / "target.lock"
        target.write_text("keep", encoding="utf-8")
        lock_path.symlink_to(target)
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(12):
            with self.assertRaisesRegex(QtraceError, "session.lock_invalid"):
                with TargetLock(runtime).acquire("device-1", PACKAGE):
                    pass
        after = len(os.listdir("/proc/self/fd"))
        self.assertLessEqual(after, before + 1)
        self.assertTrue(lock_path.is_symlink())
        self.assertEqual("keep", target.read_text(encoding="utf-8"))

    def test_lock_cleanup_does_not_mask_non_oserror_primary(self) -> None:
        lock = TargetLock(Path(self.directory.name))
        real_close = os.close
        armed = False

        def close_then_fail(fd: int) -> None:
            real_close(fd)
            if armed:
                raise OSError("close failed")

        def fchmod_then_interrupt(*_args: object) -> None:
            nonlocal armed
            armed = True
            raise KeyboardInterrupt()

        with patch("qtrace.lock.os.fchmod", side_effect=fchmod_then_interrupt), \
                patch("qtrace.lock.os.close", side_effect=close_then_fail):
            with self.assertRaises(KeyboardInterrupt):
                lock._root()

    def test_lock_file_open_closes_root_and_maps_only_oserrors(self) -> None:
        lock = TargetLock(Path(self.directory.name))
        for failure, expected in ((OSError("open failed"), QtraceError),
                                  (KeyboardInterrupt(), KeyboardInterrupt)):
            with self.subTest(failure=type(failure).__name__):
                with patch.object(TargetLock, "_root", return_value=123), \
                        patch("qtrace.lock.os.open", side_effect=failure), \
                        patch("qtrace.lock.os.close") as close:
                    with self.assertRaises(expected):
                        with lock.acquire("device-1", PACKAGE):
                            pass
                    close.assert_called_once_with(123)


if __name__ == "__main__":
    unittest.main()
