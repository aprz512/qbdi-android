import contextlib
import builtins
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from qtrace.artifacts import ArtifactResult, PullMode
from qtrace.demo import (DemoFixture, _TARGET_MEMBER, _extract_target,
                         make_demo_action, make_demo_config)
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
                ])

        self.assertEqual(0, exit_code)
        request = orchestrator.run.call_args.args[0]
        self.assertEqual(30_000, request.duration_ms)
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
                patch.object(cli, "ArtifactProcessor") as processor, \
                patch("builtins.__import__", side_effect=reject_runtime_import):
            processor.return_value.pull_manual.return_value = result
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, cli.main(["pull", "--package", "com.example.app", "--output", "out"]))

        selection = processor.return_value.pull_manual.call_args.args[2]
        self.assertIs(PullMode.LATEST, selection.mode)
        self.assertFalse(selection.compressed_only)
        orchestrator.assert_not_called()
        inspector.assert_not_called()
        fixture.assert_not_called()
        demo_config.assert_not_called()
        demo_action.assert_not_called()
        self.assertEqual([], selected.forbidden_calls)

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
                        patch.object(cli, "_make_orchestrator", return_value=orchestrator), \
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

    def test_demo_action_uses_configured_adb_timeout(self):
        device = Mock()

        action = make_demo_action("timed", 7, adb_timeout=17.0)
        action(device, 42)

        self.assertEqual(17.0, device.shell.call_args.kwargs["timeout"])

    def test_demo_monitor_actions_use_distinct_fixture_intent_modes(self):
        for scenario, expected_mode in (("monitor-exit", "exit"),
                                        ("flight-crash", "flight-crash")):
            with self.subTest(scenario=scenario):
                device = Mock()

                make_demo_action(scenario, 7)(device, 42)

                arguments = device.shell.call_args.args
                mode_index = arguments.index("qtrace_acceptance_mode")
                self.assertEqual(expected_mode, arguments[mode_index + 1])

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
