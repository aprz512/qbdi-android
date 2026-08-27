import contextlib
import io
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from qtrace.artifacts import ArtifactResult, PullMode
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

        selected = Mock()
        selected.serial = "serial"
        result = ArtifactResult(Path("out/session"), (Path("out/session/artifacts/run.trace.bin"),), (), 0)
        with patch.object(cli, "load_config", side_effect=AssertionError("must not load config")), \
                patch.object(cli, "_select_device", return_value=selected), \
                patch.object(cli, "ArtifactProcessor") as processor:
            processor.return_value.pull_manual.return_value = result
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, cli.main(["pull", "--package", "com.example.app", "--output", "out"]))

        selection = processor.return_value.pull_manual.call_args.args[2]
        self.assertIs(PullMode.LATEST, selection.mode)
        self.assertFalse(selection.compressed_only)

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


if __name__ == "__main__":
    unittest.main()
