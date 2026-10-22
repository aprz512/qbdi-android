import contextlib
import builtins
import io
import json
import multiprocessing
import os
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from qtrace.artifacts import ArtifactResult, PullMode
from qtrace.demo import (DemoFixture, _TARGET_MEMBER, _extract_target,
                         build_demo_fixture, make_demo_action, make_demo_config)
from qtrace.errors import QtraceError
from qtrace.models import AppConfig, OffsetScene, TargetConfig, TracerConfig, UserConfig
from qtrace.session import SessionResult


def config() -> UserConfig:
    return UserConfig(
        1,
        AppConfig("com.example.app", None),
        TargetConfig("libtarget.so", None),
        TracerConfig("fast", True, False, None, None, None),
        (OffsetScene("target", 0x100, 0x140),),
    )


class QtraceCliTests(unittest.TestCase):
    def test_config_errors_identify_interface_field_and_guide_before_setup(self):
        from qtrace import cli

        valid = {
            "schemaVersion": 1, "app": {"package": "com.example.app"},
            "target": {"module": "libtarget.so"},
            "scenes": [{"name": "target", "symbol": "target_function"}],
        }
        cases = (
            ({**valid, "app": {}}, "CONFIG_MISSING_FIELD", "app", "package"),
            ({**valid, "app": {"package": 7}}, "CONFIG_TYPE_INVALID", "app.package", "string"),
            ({**valid, "tracer": {"followThreads": False}}, "CONFIG_UNKNOWN_FIELD", "tracer", "followThreads"),
            ({**valid, "tracer": {"long" * 200: True}}, "CONFIG_UNKNOWN_FIELD", "tracer", "longlong"),
            ({"schemaVersion": 1, "packageName": "com.example.app"},
             "CONFIG_UNKNOWN_FIELD", "root", "packageName"),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.json"
            for payload, code, field, detail in cases:
                path.write_text(json.dumps(payload), encoding="utf-8")
                for command in ("run", "monitor"):
                    arguments = [command, "--config", str(path), "--json"]
                    if command == "run":
                        arguments += ["--duration", "1s"]
                    with self.subTest(code=code, command=command), \
                            patch.object(cli, "_make_orchestrator") as setup, \
                            contextlib.redirect_stdout(stdout := io.StringIO()), \
                            contextlib.redirect_stderr(stderr := io.StringIO()):
                        self.assertEqual(1, cli.main(arguments))
                    setup.assert_not_called()
                    self.assertEqual("", stdout.getvalue())
                    self.assertEqual(1, len(stderr.getvalue().splitlines()))
                    for expected in (code, field, detail, "CLI --config", "native JSON", "docs/usage.md"):
                        self.assertIn(expected, stderr.getvalue())

    def test_missing_bindings_fail_before_ndk_build_or_device_selection(self):
        from qtrace import cli

        with patch.object(cli, "load_config", return_value=config()), \
                patch.dict(sys.modules, {"frida": None}), \
                patch("importlib.util.find_spec", return_value=None), \
                patch.object(cli, "_make_inspector") as inspector, \
                patch.object(cli.DeviceSelector, "select") as select, \
                contextlib.redirect_stdout(stdout := io.StringIO()), \
                contextlib.redirect_stderr(stderr := io.StringIO()):
            self.assertEqual(1, cli.main(["run", "--config", "target.json", "--duration", "1s"]))
        inspector.assert_not_called()
        select.assert_not_called()
        self.assertEqual("", stdout.getvalue())
        for expected in ("frida.python_missing", sys.executable, "docs/usage.md"):
            self.assertIn(expected, stderr.getvalue())

    def test_binding_availability_check_does_not_initialize_frida(self):
        from qtrace.injector import FridaProvider

        original_import = builtins.__import__

        def checked_import(name, *args, **kwargs):
            if name in {"frida", "_frida"}:
                raise AssertionError("Frida must initialize only in the isolated worker")
            return original_import(name, *args, **kwargs)

        with patch.dict(sys.modules, {"frida": None}), \
                patch("importlib.util.find_spec", return_value=object()), \
                patch("builtins.__import__", side_effect=checked_import):
            FridaProvider.check_host()

    def test_generic_orchestrator_keeps_default_flight_capacity(self):
        from qtrace import cli

        with patch.object(cli, "SessionOrchestrator", return_value=Mock()) as constructor, \
                patch("qtrace.injector.FridaProvider.check_host"):
            cli._make_orchestrator(Path.cwd(), Mock())

        self.assertEqual(512, constructor.call_args.kwargs["flight_capacity_mb"])

    def test_blocked_frida_version_probe_is_killed_and_reaped_at_the_deadline(self):
        from qtrace import cli

        blocked_read, blocked_write = os.pipe()
        try:
            with tempfile.TemporaryDirectory() as directory:
                observed_pid = Path(directory) / "blocked-frida-probe.pid"

                class Remote:
                    def query_system_parameters(self):
                        observed_pid.write_text(str(os.getpid()), encoding="ascii")
                        os.read(blocked_read, 1)
                        return {"version": "17.17.0"}

                runtime = cli._FridaRuntime()
                started = time.monotonic()
                with patch.object(runtime, "get_device", return_value=Remote()), patch.dict(
                    sys.modules, {"frida": SimpleNamespace(__version__="17.17.0")}
                ), self.assertRaisesRegex(QtraceError, "exceeded the setup deadline"):
                    runtime.versions(object(), 0.05)

                self.assertLess(time.monotonic() - started, 0.5)
                worker_pid = int(observed_pid.read_text(encoding="ascii"))
                with self.assertRaises(ProcessLookupError):
                    os.kill(worker_pid, 0)
                self.assertFalse(any(
                    child.name == "qtrace-frida-version-probe"
                    for child in multiprocessing.active_children()
                ))
        finally:
            os.close(blocked_read)
            os.close(blocked_write)

    def test_frida_version_handshake_does_not_initialize_frida_in_the_parent(self):
        from qtrace import cli

        with tempfile.TemporaryDirectory() as directory:
            observed_pid = Path(directory) / "frida-probe.pid"

            class Remote:
                def query_system_parameters(self):
                    observed_pid.write_text(str(os.getpid()), encoding="ascii")
                    return {"version": "17.17.0"}

            runtime = cli._FridaRuntime()
            with patch.object(runtime, "get_device", return_value=Remote()), patch.dict(
                sys.modules, {"frida": SimpleNamespace(__version__="17.17.0")}
            ):
                self.assertEqual(("17.17.0", "17.17.0"), runtime.versions(object(), 5.0))

            self.assertNotEqual(os.getpid(), int(observed_pid.read_text(encoding="ascii")))

    def test_frida_17_runtime_reads_server_version_from_a_clean_system_probe(self):
        from qtrace import cli

        events = []

        class Script:
            def on(self, signal, callback):
                self.callback = callback
                events.append(("on", signal))

            def load(self):
                events.append(("load",))
                self.callback({
                    "type": "send",
                    "payload": {"type": "qtrace-frida-version", "version": "17.17.0"},
                }, None)

            def unload(self):
                events.append(("unload",))

        class Session:
            def create_script(self, source):
                events.append(("create", source))
                return Script()

            def detach(self):
                events.append(("detach",))

        class Remote:
            def query_system_parameters(self):
                return {"arch": "arm64", "os": {"id": "android"}}

            def attach(self, pid):
                events.append(("attach", pid))
                return Session()

        runtime = cli._FridaRuntime()
        with patch.object(runtime, "get_device", return_value=Remote()), patch.dict(
            sys.modules, {"frida": SimpleNamespace(__version__="17.17.0")}
        ):
            self.assertEqual(
                ("17.17.0", "17.17.0"),
                cli._query_frida_versions(runtime, object(), 5.0),
            )

        self.assertEqual(("attach", 0), events[0])
        self.assertEqual(("on", "message"), events[2])
        self.assertEqual(("unload",), events[-2])
        self.assertEqual(("detach",), events[-1])

    def test_demo_build_bounds_gradle_daemon_lifetime_inside_bounded_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gradlew = root / "gradlew"
            gradlew.write_text("#!/bin/sh\n", encoding="utf-8")
            apk = root / "app/build/outputs/apk/debug/app-debug.apk"
            apk.parent.mkdir(parents=True)
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr(_TARGET_MEMBER, b"fixture-target")
            runner = Mock()
            runner.capture.return_value = b""

            with patch.dict(os.environ, {"GRADLE_OPTS": "-Ddemo.existing=true"}):
                build_demo_fixture(root, runner, 12.5)

            self.assertEqual(
                (
                    "/usr/bin/env",
                    "GRADLE_OPTS=-Ddemo.existing=true -Dorg.gradle.daemon.idletimeout=1000",
                    str(gradlew),
                    ":app:assembleDebug",
                    "--no-daemon",
                ),
                runner.capture.call_args.args[0],
            )
            self.assertEqual(12.5, runner.capture.call_args.kwargs["timeout"])

    def test_run_parses_duration_and_explicit_timeouts_into_run_request(self):
        from qtrace import cli

        orchestrator = Mock()
        orchestrator.run.return_value = SessionResult(
            "123e4567-e89b-42d3-a456-426614174000", 0,
            Path("results/report.json"), (Path("results/artifacts/run.trace.bin"),),
        )
        with patch.object(cli, "load_config", return_value=config()), \
                patch.object(cli, "_make_orchestrator", return_value=orchestrator):
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = cli.main([
                    "run", "--config", "target.json", "--duration", "30s",
                    "--device", "serial", "--output", "results", "--setup-timeout", "91",
                    "--stop-timeout", "11", "--adb-timeout", "31", "--pull-timeout", "61",
                    "--detach-before-resume",
                ])

        self.assertEqual(0, exit_code)
        request = orchestrator.run.call_args.args[0]
        self.assertEqual(30_000, request.duration_ms)
        self.assertTrue(request.detach_before_resume)
        self.assertEqual((91.0, 11.0, 31.0, 61.0),
                         (request.setup_timeout, request.stop_timeout,
                          request.adb_timeout, request.pull_timeout))
        self.assertEqual("serial", request.device)
        self.assertEqual(Path("results"), request.output)

    def test_monitor_rejects_duration_and_uses_indefinite_monitor_request(self):
        from qtrace import cli

        with self.assertRaises(SystemExit) as caught, contextlib.redirect_stderr(io.StringIO()):
            cli.main(["monitor", "--config", "target.json", "--duration", "1s"])
        self.assertEqual(2, caught.exception.code)

        orchestrator = Mock()
        orchestrator.monitor.return_value = SessionResult(
            "123e4567-e89b-42d3-a456-426614174000", 0, Path("out/report.json"), (),
        )
        with patch.object(cli, "load_config", return_value=config()), \
                patch.object(cli, "_make_orchestrator", return_value=orchestrator):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, cli.main(["monitor", "--config", "target.json"]))
        self.assertEqual("MonitorRequest", type(orchestrator.monitor.call_args.args[0]).__name__)

    def test_pull_is_config_and_frida_independent_and_defaults_to_latest(self):
        from qtrace import cli

        class SelectedDevice:
            serial = "serial"

            def __init__(self):
                self.forbidden_calls = []

            def install(self, *args, **kwargs):
                self.forbidden_calls.append("install")
                raise AssertionError("pull must not install an app")

            def shell(self, *args, **kwargs):
                self.forbidden_calls.append("shell")
                raise AssertionError("pull must not start an app")

            def target_shell(self, *args, **kwargs):
                self.forbidden_calls.append("target_shell")
                raise AssertionError("pull must not start an app")

        selected = SelectedDevice()
        bound = SimpleNamespace(serial="serial", package="com.example.app")
        result = ArtifactResult(Path("out/session"), (Path("out/session/artifacts/run.trace.bin"),), (), 0)
        real_import = builtins.__import__

        def reject_runtime_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "frida" or name.startswith(("qtrace.build", "qtrace.injector", "qtrace.preflight")):
                raise AssertionError(f"pull must not import {name}")
            return real_import(name, globals, locals, fromlist, level)

        with patch.object(cli, "load_config", side_effect=AssertionError("must not load config")), \
                patch.object(cli, "_select_device", return_value=selected), \
                patch.object(cli, "_make_orchestrator", side_effect=AssertionError("must not construct session")) as orchestrator, \
                patch.object(cli, "_make_inspector", side_effect=AssertionError("must not inspect target")) as inspector, \
                patch.object(cli, "build_demo_fixture", side_effect=AssertionError("must not build fixture")) as fixture, \
                patch.object(cli, "make_demo_config", side_effect=AssertionError("must not configure fixture")) as demo_config, \
                patch.object(cli, "make_demo_action", side_effect=AssertionError("must not start fixture")) as demo_action, \
                patch.object(cli, "bind_package_access") as binder, \
                patch.object(cli, "ArtifactProcessor") as processor, \
                patch("builtins.__import__", side_effect=reject_runtime_import):
            binder.return_value = bound

            def pull_manual(device, *_args, **_kwargs):
                self.assertIs(bound, device)
                return result

            processor.return_value.pull_manual.side_effect = pull_manual
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, cli.main(["pull", "--package", "com.example.app", "--output", "out"]))

        binder.assert_called_once_with(selected, "com.example.app", timeout=30.0)
        selection = processor.return_value.pull_manual.call_args.args[2]
        self.assertIs(PullMode.LATEST, selection.mode)
        self.assertFalse(selection.compressed_only)
        orchestrator.assert_not_called()
        inspector.assert_not_called()
        fixture.assert_not_called()
        demo_config.assert_not_called()
        demo_action.assert_not_called()
        self.assertEqual([], selected.forbidden_calls)

    def test_pull_binding_failure_publishes_nothing_and_never_constructs_processor(self):
        from qtrace import cli

        selected = SimpleNamespace(serial="serial")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "pull-output"
            with patch.object(cli, "_select_device", return_value=selected), \
                    patch.object(cli, "bind_package_access", side_effect=QtraceError(
                        "device.access_denied", "preflight.access", "no package identity",
                    )), \
                    patch.object(cli, "ArtifactProcessor") as processor, \
                    patch.object(cli, "_emit_result") as emit, \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertNotEqual(0, cli.main([
                    "pull", "--package", "com.example.app", "--output", str(output),
                ]))

            processor.assert_not_called()
            emit.assert_not_called()
            self.assertFalse(output.exists())

    def test_pull_selection_is_exclusive_but_compressed_only_is_orthogonal(self):
        from qtrace import cli

        parser = cli.build_parser()
        parsed = parser.parse_args(["pull", "--package", "com.example.app", "--name", "one.trace.bin", "--compressed-only"])
        self.assertEqual("one.trace.bin", parsed.name)
        self.assertTrue(parsed.compressed_only)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            parser.parse_args(["pull", "--package", "com.example.app", "--latest", "--all"])

    def test_json_output_is_one_object_and_qtrace_error_is_one_stderr_line(self):
        from qtrace import cli

        orchestrator = Mock()
        orchestrator.run.return_value = SessionResult(
            "123e4567-e89b-42d3-a456-426614174000", 0, Path("out/report.json"), (Path("out/trace.bin"),),
        )
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(cli, "load_config", return_value=config()), \
                patch.object(cli, "_make_orchestrator", return_value=orchestrator), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(0, cli.main(["run", "--config", "target.json", "--duration", "1s", "--json"]))
        self.assertEqual({"report", "artifacts", "exitCode"}, set(json.loads(stdout.getvalue())))
        self.assertEqual("qtrace: starting timed session\n", stderr.getvalue())

        with patch.object(cli, "load_config", side_effect=QtraceError("bad", "config", "bad\ninput")), \
                contextlib.redirect_stderr(stderr := io.StringIO()):
            self.assertEqual(1, cli.main(["run", "--config", "target.json", "--duration", "1s"]))
        self.assertEqual(1, len(stderr.getvalue().splitlines()))

    def test_human_output_distinguishes_sealed_capture_from_target_return(self):
        from qtrace import cli

        lifecycle = {
            "capture_state": "sealed", "process_state": "unknown",
            "open_scenes": [{"scene": "wait", "tid": 42, "capture_sealed": True,
                             "state": "open_at_snapshot", "target_returned": None}],
        }
        result = SimpleNamespace(
            exit_code=0, report=Path("out/report.json"), outputs=(Path("out/run.trace.bin"),),
            session_report=SimpleNamespace(native={"lifecycle": lifecycle}, artifacts=({
                "decoder": "qtrb", "remote_name": "run.trace.bin", "termination": "stopped",
                "target_stop_reason": "duration_elapsed", "target_returned_in_capture": False,
            },)),
        )
        orchestrator = Mock()
        orchestrator.run.return_value = result
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(cli, "load_config", return_value=config()), \
                patch.object(cli, "_make_orchestrator", return_value=orchestrator), \
                patch.object(Path, "open", side_effect=AssertionError("must reuse in-memory evidence")), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(0, cli.main(["run", "--config", "target.json", "--duration", "1s"]))

        self.assertEqual("out/report.json\nout/run.trace.bin\n", stdout.getvalue())
        self.assertIn("Capture: sealed; process: unknown", stderr.getvalue())
        self.assertIn("wait (TID 42): open at status snapshot; capture sealed; return unknown", stderr.getvalue())
        self.assertIn("target return unknown; duration_elapsed", stderr.getvalue())

    def test_pull_displays_retained_flight_evidence_without_claiming_target_return(self):
        from qtrace import cli

        result = ArtifactResult(Path("out/session"), (), (), 0)
        object.__setattr__(result, "_records", ({
            "decoder": "flight", "remote_name": "run.flight.bin", "recovery_status": "complete",
            "scene_lifecycle": [{"state": "capture_stopped", "target_returned": None}],
            "scene_lifecycle_omitted": 2, "scene_lifecycle_invalid": 1,
            "missing_sequence_ranges": 3, "coverage_gap_count": 4,
        },))
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(cli, "_select_device", return_value=Mock()), \
                patch.object(cli, "bind_package_access", return_value=Mock()), \
                patch.object(cli, "ArtifactProcessor") as processor, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            processor.return_value.pull_manual.return_value = result
            self.assertEqual(0, cli.main(["pull", "--package", "com.example.app"]))

        self.assertEqual("out/session/report.json\n", stdout.getvalue())
        self.assertIn("retained data complete", stderr.getvalue())
        self.assertIn("scene returns observed 0; unconfirmed 1", stderr.getvalue())
        self.assertIn("omitted 2; invalid 1", stderr.getvalue())
        self.assertIn("missing sequence ranges 3; coverage gaps 4", stderr.getvalue())
        self.assertIn("File completeness does not prove target return", stderr.getvalue())

    def test_json_result_skips_human_summary_even_with_capture_evidence(self):
        from qtrace import cli

        stdout, stderr = io.StringIO(), io.StringIO()
        report = SimpleNamespace(native={"lifecycle": {}}, artifacts=({"decoder": "flight"},))
        with patch.object(cli, "format_capture_summary", side_effect=AssertionError("human output only")), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            cli._emit_result(Path("out/report.json"), (), 2, True, session_report=report)

        self.assertEqual({"report": "out/report.json", "artifacts": [], "exitCode": 2},
                         json.loads(stdout.getvalue()))
        self.assertEqual("", stderr.getvalue())

    def test_monitor_channels_keep_observed_returns_and_stopped_scenes_distinct(self):
        from qtrace import cli

        report = SimpleNamespace(native={"lifecycle": {
            "capture_state": "sealed", "process_state": "exited", "open_scenes": [],
        }}, artifacts=({
            "decoder": "flight", "remote_name": "narrow.flight.bin", "recovery_status": "complete",
            "scene_lifecycle": [
                {"state": "returned", "target_returned": True},
                {"state": "capture_stopped", "target_returned": None},
            ],
            "scene_lifecycle_omitted": 0, "scene_lifecycle_invalid": 0,
            "missing_sequence_ranges": 0, "coverage_gap_count": 0,
        },))
        result = SessionResult("123e4567-e89b-42d3-a456-426614174000", 0,
                               Path("out/report.json"), (Path("out/narrow.flight.bin"),), report)
        for as_json in (False, True):
            orchestrator = Mock()
            orchestrator.monitor.return_value = result
            arguments = ["monitor", "--config", "target.json"] + (["--json"] if as_json else [])
            with self.subTest(as_json=as_json), \
                    patch.object(cli, "load_config", return_value=config()), \
                    patch.object(cli, "_make_orchestrator", return_value=orchestrator), \
                    contextlib.redirect_stdout(stdout := io.StringIO()), \
                    contextlib.redirect_stderr(stderr := io.StringIO()):
                self.assertEqual(0, cli.main(arguments))
                if as_json:
                    self.assertEqual({"report": "out/report.json", "artifacts": ["out/narrow.flight.bin"],
                                      "exitCode": 0}, json.loads(stdout.getvalue()))
                    self.assertEqual("qtrace: starting monitor session\n", stderr.getvalue())
                else:
                    self.assertEqual("out/report.json\nout/narrow.flight.bin\n", stdout.getvalue())
                    self.assertIn("scene returns observed 1; unconfirmed 1", stderr.getvalue())
                    self.assertIn("Capture: sealed; process: exited", stderr.getvalue())
                    self.assertIn("File completeness does not prove target return", stderr.getvalue())

    def test_keyboard_interrupt_maps_to_130_after_orchestrator_returns_control(self):
        from qtrace import cli

        orchestrator = Mock()
        orchestrator.run.side_effect = KeyboardInterrupt()
        with patch.object(cli, "load_config", return_value=config()), \
                patch.object(cli, "_make_orchestrator", return_value=orchestrator), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(130, cli.main(["run", "--config", "target.json", "--duration", "1s"]))

    def test_demo_uses_the_normal_orchestrator_and_timeout_validation_is_finite_positive(self):
        from qtrace import cli

        parser = cli.build_parser()
        for value in ("0", "-1", "nan", "inf"):
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["run", "--config", "target.json", "--duration", "1s", "--adb-timeout", value])

        orchestrator = Mock()
        orchestrator.run.return_value = SessionResult(
            "123e4567-e89b-42d3-a456-426614174000", 0, Path("out/report.json"), (),
        )
        fixture = Mock(apk=Path("demo.apk"), target_binary=Path("demo.so"))
        with patch.object(cli, "build_demo_fixture", return_value=fixture), \
                patch.object(cli, "_make_inspector", return_value=Mock()), \
                patch.object(cli, "make_demo_config", return_value=config()), \
                patch.object(cli, "make_demo_action", return_value=Mock()), \
                patch.object(cli, "_make_orchestrator", return_value=orchestrator):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, cli.main(["demo", "--duration", "1s"]))
        self.assertEqual(1, orchestrator.run.call_count)

    def test_demo_monitor_scenarios_reject_timed_only_options(self):
        from qtrace import cli

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(1, cli.main(["demo", "--scenario", "monitor-exit", "--duration", "1s"]))
            self.assertEqual(1, cli.main(["demo", "--scenario", "monitor-exit", "--stop-timeout", "1"]))

    def test_demo_monitor_scenarios_use_monitor_and_preserve_scenario_action_mapping(self):
        from qtrace import cli

        for scenario in ("monitor-exit", "flight-crash"):
            with self.subTest(scenario=scenario):
                orchestrator = Mock()
                orchestrator.monitor.return_value = SessionResult(
                    "123e4567-e89b-42d3-a456-426614174000", 0, Path("out/report.json"), (),
                )
                action = Mock()
                fixture = Mock(apk=Path("demo.apk"), target_binary=Path("demo.so"))
                with patch.object(cli, "build_demo_fixture", return_value=fixture), \
                        patch.object(cli, "_make_inspector", return_value=Mock()), \
                        patch.object(cli, "make_demo_config", return_value=config()) as make_config, \
                        patch.object(cli, "make_demo_action", return_value=action) as make_action, \
                        patch.object(cli, "_make_orchestrator", return_value=orchestrator) as make_orchestrator, \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(0, cli.main(["demo", "--scenario", scenario, "--adb-timeout", "17"]))
                orchestrator.run.assert_not_called()
                request = orchestrator.monitor.call_args.args[0]
                self.assertEqual("MonitorRequest", type(request).__name__)
                self.assertFalse(hasattr(request, "duration_ms"))
                self.assertIs(action, request.installed_action)
                self.assertEqual(scenario, make_config.call_args.args[3])
                self.assertEqual(scenario, make_action.call_args.args[0])
                self.assertEqual(17.0, make_action.call_args.kwargs["adb_timeout"])
                self.assertEqual(
                    {"flight_capacity_mb": 64} if scenario == "flight-crash" else {},
                    make_orchestrator.call_args.kwargs,
                )

    def test_demo_action_uses_configured_adb_timeout(self):
        device = Mock()

        action = make_demo_action("timed", 7, adb_timeout=17.0)
        receipt = action(device, 42, "123e4567-e89b-42d3-a456-426614174000")

        self.assertEqual(17.0, device.shell.call_args.kwargs["timeout"])
        arguments = device.shell.call_args.args
        nonce_index = arguments.index("qtrace_acceptance_nonce")
        self.assertEqual(receipt.nonce, arguments[nonce_index + 1])

    def test_demo_monitor_actions_use_distinct_fixture_intent_modes(self):
        for scenario, expected_mode in (("monitor-exit", "exit"),
                                        ("flight-crash", "flight-crash")):
            with self.subTest(scenario=scenario):
                device = Mock()

                make_demo_action(scenario, 7)(device, 42, "123e4567-e89b-42d3-a456-426614174000")

                arguments = device.shell.call_args.args
                mode_index = arguments.index("qtrace_acceptance_mode")
                self.assertEqual(expected_mode, arguments[mode_index + 1])
                self.assertIn("--activity-clear-task", arguments)
                self.assertNotIn("--activity-new-task", arguments)

        timed = Mock()
        make_demo_action("timed", 7)(
            timed, 42, "123e4567-e89b-42d3-a456-426614174000",
        )
        self.assertNotIn("--activity-clear-task", timed.shell.call_args.args)
        self.assertNotIn("--activity-new-task", timed.shell.call_args.args)

    def test_demo_target_extraction_rejects_symlink_parent_without_writing_escape_target(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            apk = root / "fixture.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr(_TARGET_MEMBER, b"fixture-target")
            (root / "build").symlink_to(outside, target_is_directory=True)
            destination = root / "build/qtrace-demo/arm64-v8a/libdemo_target.so"
            escaped = Path(outside) / "qtrace-demo/arm64-v8a/libdemo_target.so"

            with self.assertRaisesRegex(QtraceError, "unsafe"):
                _extract_target(apk, destination)

            self.assertFalse(escaped.exists())

    def test_demo_fixture_rejects_parent_replacement_after_held_fd_publication(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            apk = root / "fixture.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr(_TARGET_MEMBER, b"fixture-target")
            destination = root / "build/qtrace-demo/arm64-v8a/libdemo_target.so"
            outside_target = Path(outside) / "qtrace-demo/arm64-v8a/libdemo_target.so"
            outside_target.parent.mkdir(parents=True)
            outside_target.write_bytes(b"external-target")
            real_replace = os.replace

            def publish_then_swap(source, target, *args, **kwargs):
                result = real_replace(source, target, *args, **kwargs)
                real_replace(root / "build", root / "build-held")
                (root / "build").symlink_to(outside, target_is_directory=True)
                return result

            with patch("qtrace.demo.os.replace", side_effect=publish_then_swap):
                extracted = _extract_target(apk, destination)

            inspector = Mock()
            fixture = DemoFixture(apk, extracted.path, extracted.parent_identity,
                                  extracted.target_identity)
            with self.assertRaisesRegex(QtraceError, "identity"):
                make_demo_config(fixture, inspector, "offset", "timed")
            inspector.symbol_range.assert_not_called()


if __name__ == "__main__":
    unittest.main()
