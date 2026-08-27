import json
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from qtrace.errors import EXIT_PARTIAL, EXIT_STOP_INCOMPLETE, ErrorCode, QtraceError
from qtrace.models import (
    AppConfig, ElfIdentity, ResolvedScene, ResolvedTarget, TargetConfig, TracerConfig, UserConfig,
)
from qtrace.session import (
    MonitorRequest, RunRequest, SessionOrchestrator, build_native_request, parse_status,
)
from qtrace.lock import TargetLock


SESSION_ID = "123e4567-e89b-42d3-a456-426614174000"
PACKAGE = "com.example.app"
SCENES = (ResolvedScene("work", 0x120, 0x180),)


def config() -> UserConfig:
    return UserConfig(1, AppConfig(PACKAGE, None), TargetConfig("libwork.so", None),
                      TracerConfig("balanced", True, False, None, None, None), ())


def target() -> ResolvedTarget:
    return ResolvedTarget(PACKAGE, "libwork.so", Path("/host/libwork.so"), "/app/libwork.so",
                          ElfIdentity("ELF64", "AArch64", "ab", ((0x100, 0x200),)), SCENES)


def status(state: str, *, transition: int, pid: int = 4242, reason: str = "",
           acknowledged: bool = False, artifacts: list[str] | None = None) -> dict[str, object]:
    return {
        "schemaVersion": 1, "sessionId": SESSION_ID, "generation": 7, "packageName": PACKAGE,
        "pid": pid, "state": state, "reason": reason, "transitionMonotonicNs": transition,
        "normalizedScenes": [{"name": "work", "startOffset": 0x120, "endOffset": 0x180}],
        "activeScenes": [], "artifacts": artifacts or ["run.trace.bin.lz4"],
        "stopAcknowledged": acknowledged, "warnings": [], "errors": [],
    }


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

    def collect_session(self, device, package, session_id, initial_artifacts, status, output, timeout):
        self.calls.append((initial_artifacts, status))
        return self.exit_code, ()


def orchestrator(device: FakeDevice, clock: ManualClock, collector: FakeCollector | None = None):
    injector = FakeInjector()
    return SessionOrchestrator(
        FakePreflight(device), lambda selected: type("Resolver", (), {"resolve": lambda self, _: target()})(),
        FakeBuilder(), FakeDeployer(), lambda selected: injector, collector or FakeCollector(), clock,
        lambda: SESSION_ID,
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


if __name__ == "__main__":
    unittest.main()
