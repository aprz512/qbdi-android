"""Host contracts for the manual qtrace device-acceptance gate."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qtrace.config import load_config
from qtrace.errors import ConfigError
from qtrace.status import STATUS_KEYS, validate_status_shape


ROOT = Path(__file__).resolve().parents[2]
SESSION = "123e4567-e89b-42d3-a456-426614174000"


def status(state: str) -> dict[str, object]:
    terminal = state in {"sealed"}
    stopping = state in {"stop_requested", "stopping", "stop_incomplete"}
    return {
        "schemaVersion": 1,
        "sessionId": SESSION,
        "generation": 1,
        "packageName": "com.aprz.qbdiandroid",
        "pid": 4242,
        "state": state,
        "reason": "duration_elapsed" if terminal or stopping else "",
        "transitionMonotonicNs": 100,
        "normalizedScenes": [{"name": "fixture-entry", "startOffset": 16, "endOffset": 32}],
        "activeScenes": [],
        "artifacts": [f"{SESSION}.trace.bin.lz4"],
        "stopAcknowledged": terminal,
        "warnings": [],
        "errors": [],
    }


class SchemaContractsTests(unittest.TestCase):
    def load_schema(self, name: str) -> dict[str, object]:
        return json.loads((ROOT / "docs" / name).read_text(encoding="utf-8"))

    def test_config_schema_matches_the_strict_configuration_field_sets(self):
        schema = self.load_schema("qtrace-config.schema.json")
        self.assertEqual(1, schema["properties"]["schemaVersion"]["const"])
        self.assertEqual({"schemaVersion", "app", "target", "tracer", "scenes"}, set(schema["properties"]))
        self.assertEqual(["schemaVersion", "app", "target", "scenes"], schema["required"])
        self.assertFalse(schema["additionalProperties"])
        definitions = schema["$defs"]
        self.assertEqual({"package", "apk"}, set(definitions["app"]["properties"]))
        self.assertEqual(["package"], definitions["app"]["required"])
        self.assertFalse(definitions["app"]["additionalProperties"])
        self.assertEqual({"module", "binary"}, set(definitions["target"]["properties"]))
        self.assertEqual(["module"], definitions["target"]["required"])
        self.assertFalse(definitions["target"]["additionalProperties"])
        tracer = definitions["tracer"]
        self.assertEqual(
            {"profile", "compression", "flightEnabled", "flightEntryScene", "library", "companion"},
            set(tracer["properties"]),
        )
        self.assertFalse(tracer["additionalProperties"])
        self.assertEqual(["fast", "balanced", "full"], tracer["properties"]["profile"]["enum"])
        self.assertEqual(1, schema["properties"]["scenes"]["minItems"])
        self.assertEqual(256, schema["properties"]["scenes"]["maxItems"])
        forms = definitions["scene"]["oneOf"]
        self.assertEqual({"name", "symbol"}, set(forms[0]["properties"]))
        self.assertEqual({"name", "startOffset", "endOffset"}, set(forms[1]["properties"]))
        self.assertTrue(all(not form["additionalProperties"] for form in forms))
        self.assertEqual(
            ["UTF-8 byte limits", "scene names are unique", "offset ranges are nonzero, aligned, and ordered"],
            schema["x-qtrace-runtime-invariants"],
        )

    def test_status_schema_matches_the_strict_native_status_parser(self):
        schema = self.load_schema("qtrace-session-status.schema.json")
        self.assertEqual(set(STATUS_KEYS), set(schema["properties"]))
        self.assertEqual(set(STATUS_KEYS), set(schema["required"]))
        self.assertFalse(schema["additionalProperties"])
        properties = schema["properties"]
        self.assertEqual(1, properties["schemaVersion"]["const"])
        self.assertEqual("uuid", properties["sessionId"]["format"])
        self.assertEqual(1, properties["generation"]["minimum"])
        self.assertEqual(1, properties["pid"]["minimum"])
        self.assertEqual(0, properties["transitionMonotonicNs"]["minimum"])
        self.assertEqual(
            ["installed", "running", "stop_requested", "stopping", "sealed", "stop_incomplete"],
            properties["state"]["enum"],
        )
        self.assertFalse(properties["normalizedScenes"]["items"]["additionalProperties"])
        self.assertFalse(properties["activeScenes"]["items"]["additionalProperties"])
        issue = schema["$defs"]["issue"]
        self.assertFalse(issue["additionalProperties"])
        self.assertEqual({"code", "path", "message"}, set(issue["properties"]))
        self.assertEqual(
            ["UTF-8 byte limits", "normalized scene names are unique", "active (sceneIndex, tid) pairs are unique and bounded by normalizedScenes"],
            schema["x-qtrace-runtime-invariants"],
        )

    def test_every_native_status_state_has_a_valid_golden_document(self):
        for state_name in ("installed", "running", "stop_requested", "stopping", "sealed", "stop_incomplete"):
            with self.subTest(state=state_name):
                self.assertEqual(status(state_name), validate_status_shape(status(state_name)))

    def test_status_state_reason_acknowledgement_corpus_is_rejected(self):
        invalid = (
            ("running", "duration_elapsed", True),
            ("stop_requested", "", False),
            ("sealed", "duration_elapsed", False),
        )
        for state_name, reason, acknowledgement in invalid:
            with self.subTest(state=state_name):
                document = status(state_name)
                document["reason"] = reason
                document["stopAcknowledged"] = acknowledgement
                with self.assertRaises(ValueError):
                    validate_status_shape(document)

    def test_runtime_corpus_rejects_offset_zero_misalignment_and_reversed_ranges(self):
        for start, end in (("0x0", "0x4"), ("0x2", "0x4"), ("0x8", "0x4")):
            with self.subTest(start=start, end=end), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "config.json"
                path.write_text(json.dumps({"schemaVersion": 1, "app": {"package": "com.example.app"}, "target": {"module": "libx.so"}, "scenes": [{"name": "x", "startOffset": start, "endOffset": end}]}))
                with self.assertRaises(ConfigError):
                    load_config(path)


class FakeRunner:
    def __init__(self, *, fail_first_read: bool = False):
        self.commands: list[tuple[str, ...]] = []
        self.fail_first_read = fail_first_read
        self.reads = 0

    def run(self, command, *, timeout, cwd=None, allowed=(0,)):
        self.commands.append(tuple(command))
        if "flight-crash" in command:
            return __import__("scripts.qtrace_device_acceptance", fromlist=["CommandResult"]).CommandResult("", "", 2)
        return __import__("scripts.qtrace_device_acceptance", fromlist=["CommandResult"]).CommandResult("", "", 0)

    def read_text(self, path: Path, *, timeout: float) -> str:
        self.reads += 1
        if self.fail_first_read and self.reads == 1:
            raise ConnectionError("injected one-shot ADB read failure")
        if path.name == "qtrace-acceptance-baseline.json":
            return json.dumps({"iterations": 30, "seed": 5855319310239641971, "result": "0x42"})
        if path.name == "qtrace-acceptance-timed.json":
            return json.dumps({"iterations": 30, "seed": 5855319310239641971, "result": "0x42"})
        if path.name == "fixture.trace.txt":
            return "TRACE_BEGIN format=4 scene=fixture-entry\nTRACE_END status=stopped reason=duration_elapsed return_valid=0 elapsed_ms=2000\n"
        if path.name == "report.json":
            report_status = "sealed"
            if path.parent.name == "exit":
                report_status = "process_exited"
            elif path.parent.name == "crash":
                report_status = "crash_recovered"
            return json.dumps({
                "schema": 1, "session_id": SESSION, "status": report_status, "stage": "completed",
                "package": "com.aprz.qbdiandroid", "pid": 4242,
                "native": {"status": status("sealed")},
                "outputs": ["fixture.trace.bin.lz4", "fixture.trace.bin.lz4.metrics", "/tmp/fixture.trace.txt"],
                "artifacts": [{"remote_name": "fixture.trace.bin.lz4", "termination": "stopped", "metrics_schema": 3, "native_stop_acknowledged": True}],
            })
        return ""


class AcceptanceHarnessTests(unittest.TestCase):
    def test_timed_report_selects_one_binary_root_among_sidecars(self):
        from scripts.qtrace_device_acceptance import _validated_timed_report

        runner = FakeRunner()
        document = json.loads(runner.read_text(Path("report.json"), timeout=1))
        document["artifacts"].extend([
            {"remote_name": "fixture.trace.bin.lz4.metrics", "decoder": "sidecar"},
            {"remote_name": "fixture.trace.txt", "decoder": "qtrb"},
        ])
        runner.read_text = lambda _path, *, timeout: json.dumps(document)  # type: ignore[method-assign]
        report, artifact = _validated_timed_report(runner, Path("report.json"))
        self.assertEqual(document, report)
        self.assertEqual("fixture.trace.bin.lz4", artifact)

    def test_requires_an_explicit_device(self):
        from scripts.qtrace_device_acceptance import main

        self.assertEqual(2, main([]))

    def test_acceptance_runs_bounded_workflow_and_retries_one_read(self):
        from scripts.qtrace_device_acceptance import run_acceptance

        runner = FakeRunner(fail_first_read=True)
        with tempfile.TemporaryDirectory() as temporary:
            for name in ("latest", "name", "all", "compressed"):
                (Path(temporary) / name).mkdir()
            self.assertEqual(0, run_acceptance("SERIAL", Path(temporary), runner=runner))
        commands = runner.commands
        self.assertEqual(("./gradlew", "nativeHostTest", "--no-daemon"), commands[0])
        self.assertEqual(("python3", "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"), commands[1])
        self.assertEqual(("./gradlew", ":app:assembleDebug", "--no-daemon"), commands[2])
        self.assertEqual(("adb", "-s", "SERIAL", "install", "-r", "app/build/outputs/apk/debug/app-debug.apk"), commands[3])
        self.assertEqual(("adb", "-s", "SERIAL", "shell", "am", "force-stop", "com.aprz.qbdiandroid"), commands[4])
        self.assertEqual(
            ("adb", "-s", "SERIAL", "shell", "am", "start", "-n", "com.aprz.qbdiandroid/.MainActivity",
             "--ez", "qtrace_acceptance", "true", "--es", "qtrace_acceptance_mode", "timed",
             "--el", "qtrace_acceptance_seed", "5855319310239641971", "--el", "qtrace_acceptance_iterations", "30"),
            commands[5],
        )
        self.assertEqual(("python3", "scripts/benchmark_trace.py", "--device", "SERIAL", "--profile", "fast", "--runs", "5", "--candidate-tracer", "out/arm64-v8a/libqbdi_tracer.so", "--compare", "docs/benchmarks/binary-trace-baseline.md"), commands[6])
        self.assertEqual(16, len(commands))
        self.assertEqual(8, runner.reads)  # baseline retry, all scenario reports, text semantics, and native oracle
        self.assertEqual(("adb", "-s", "SERIAL", "shell", "kill", "-0", "4242"), commands[11])
        self.assertIn("--name", commands[13])
        self.assertIn("fixture.trace.bin.lz4", commands[13])
        self.assertEqual("--compressed-only", commands[15][-5])


if __name__ == "__main__":
    unittest.main()
