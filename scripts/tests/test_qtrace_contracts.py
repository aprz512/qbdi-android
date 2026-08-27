"""Host contracts for the manual qtrace device-acceptance gate."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from qtrace.config import load_config
from qtrace.errors import ConfigError
from qtrace.status import STATUS_KEYS, validate_status_shape
from scripts.tests.test_pull_trace import stopped_binary_stream
from scripts.tests.test_trace_convert import metrics_sidecar


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

    def test_status_invariant_corpus_matches_runtime(self):
        documents = []
        end = status("running"); end["normalizedScenes"] = [{"name": "x", "startOffset": 4, "endOffset": 4}]; documents.append(end)
        duplicate = status("running"); duplicate["activeScenes"] = [{"sceneIndex": 0, "tid": 1, "sealed": False}, {"sceneIndex": 0, "tid": 1, "sealed": False}]; documents.append(duplicate)
        outside = status("running"); outside["activeScenes"] = [{"sceneIndex": 1, "tid": 1, "sealed": False}]; documents.append(outside)
        for document in documents:
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
        self.offset_root: Path | None = None

    def run(self, command, *, timeout, cwd=None, allowed=(0,)):
        self.commands.append(tuple(command))
        if "--output" in command and "qtrace" in command and "demo" in command:
            output = Path(command[command.index("--output") + 1])
            if output.name == "offset":
                self.offset_root = output
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
            if path.parent.name in {"latest", "name", "all", "compressed"}:
                return json.dumps({"schema": 1, "sessionId": SESSION, "artifacts": [
                    {"remote_name": "fixture.trace.bin.lz4"}], "errors": []})
            report_status = "sealed"
            if path.parent.name == "exit":
                report_status = "process_exited"
            elif path.parent.name == "crash":
                report_status = "crash_recovered"
            return json.dumps({
                "schema": 1, "session_id": SESSION, "status": report_status, "stage": "completed",
                "package": "com.aprz.qbdiandroid", "pid": 4242,
                "device": {}, "effective_config": {}, "error": None, "finished_at": 1,
                "mode": "run", "serial": "SERIAL", "started_at": 0, "target": {},
                "tracer": {}, "warnings": [],
                "timeline": [{"stage": "installing_hooks"}, {"stage": "running"}],
                "native": {"status": status("sealed")},
                "outputs": ["fixture.trace.bin.lz4", "fixture.trace.bin.lz4.metrics", str((self.offset_root or Path("/tmp")) / "fixture.trace.txt")],
                "artifacts": [{"remote_name": "fixture.trace.bin.lz4", "local_path": "artifacts/fixture.trace.bin.lz4", "termination": "stopped", "metrics_schema": 3, "native_stop_acknowledged": True}, {"remote_name": "fixture.trace.bin.lz4.metrics", "decoder": "sidecar"}],
            })
        if path.exists():
            return path.read_text(encoding="utf-8")
        return ""


class FakeArtifactClient:
    def __init__(self, root: Path):
        self.root = root
        self.calls: list[tuple[str, int]] = []
        self.evidence_present_during_retry: list[bool] = []

    def read_file(self, name: str, *, maximum_bytes: int) -> bytes:
        self.calls.append((name, maximum_bytes))
        path = self.root / "artifacts" / name
        self.evidence_present_during_retry.append(path.is_file())
        return path.read_bytes()


class AcceptanceHarnessTests(unittest.TestCase):
    def test_subprocess_runner_uses_bounded_capture_for_allowed_crash_exit(self):
        from scripts.bounded_process import BoundedProcessError
        from scripts.qtrace_device_acceptance import SubprocessRunner

        with patch("scripts.qtrace_device_acceptance.capture_bounded", side_effect=BoundedProcessError(
                "crashed", returncode=2, stderr=b"recovering")) as capture:
            result = SubprocessRunner("SERIAL", inject_first_read_failure=False).run(
                ("qtrace", "demo"), timeout=3.0, allowed=(0, 2),
            )
        self.assertEqual(("", "recovering", 2), (result.stdout, result.stderr, result.returncode))
        self.assertEqual(1_048_576, capture.call_args.kwargs["maximum_bytes"])

    def test_host_reads_are_nofollow_bounded_and_timeout_checked(self):
        from scripts.qtrace_device_acceptance import SubprocessRunner

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            oversized = root / "oversized.json"
            oversized.write_bytes(b"x" * (1_048_576 + 1))
            safe = root / "safe.json"
            safe.write_text("safe")
            link = root / "link.json"
            link.symlink_to(safe)
            runner = SubprocessRunner("SERIAL", inject_first_read_failure=False)
            with self.assertRaisesRegex(RuntimeError, "bounded regular file"):
                runner.read_text(oversized, timeout=1.0)
            with self.assertRaisesRegex(RuntimeError, "bounded regular file"):
                runner.read_text(link, timeout=1.0)

    def test_retry_clips_second_read_to_the_shared_deadline(self):
        from scripts.qtrace_device_acceptance import _read_retry

        class Runner:
            def __init__(self): self.timeouts = []
            def read_text(self, _path, *, timeout):
                self.timeouts.append(timeout)
                if len(self.timeouts) == 1:
                    raise ConnectionError("once")
                return "ok"

        runner = Runner()
        with patch("scripts.qtrace_device_acceptance.time.monotonic", side_effect=(100.0, 100.0, 101.5)):
            self.assertEqual("ok", _read_retry(runner, Path("result"), timeout=5.0))
        self.assertEqual([5.0, 3.5], runner.timeouts)

    def test_baseline_sleep_is_clipped_to_the_absolute_deadline(self):
        from scripts.qtrace_device_acceptance import _wait_for_baseline

        class Runner:
            def read_text(self, _path, *, timeout):
                raise ValueError("not ready")

        with patch("scripts.qtrace_device_acceptance.time.monotonic", side_effect=(
                100.0, 100.0, 100.0, 100.0, 114.95, 115.0)), \
                patch("scripts.qtrace_device_acceptance.time.sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "within 15 seconds"):
                _wait_for_baseline(Runner())
        sleep.assert_called_once_with(0.04999999999999716)

    def test_timed_semantics_reparses_a_real_stopped_qtrb_and_metrics_v3_sidecar(self):
        from scripts.qtrace_device_acceptance import _validate_timed_artifact_semantics

        report = {"artifacts": [{
            "remote_name": "fixture.trace.bin",
            "local_path": "artifacts/fixture.trace.bin",
            "termination": "stopped",
            "metrics_schema": 3,
            "native_stop_acknowledged": True,
        }, {"remote_name": "fixture.trace.bin.metrics", "decoder": "sidecar"}]}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            source = artifacts / "fixture.trace.bin"
            source.write_bytes(stopped_binary_stream(compression=0))
            (artifacts / "fixture.trace.bin.metrics").write_text(
                metrics_sidecar(source, termination="stopped", return_valid=0,
                                return_value="0x0", instructions=1),
                encoding="utf-8",
            )

            _validate_timed_artifact_semantics(FakeRunner(), report, root)

            self.assertEqual([], list(root.glob(".qtrace-acceptance-validate-*.trace.txt")))

    def test_timed_semantics_reconverts_trusted_binary_and_removes_validation_text(self):
        from scripts.qtrace_device_acceptance import _validate_timed_artifact_semantics

        runner = FakeRunner()
        report = {
            "artifacts": [{
                "remote_name": "fixture.trace.bin.lz4",
                "local_path": "artifacts/fixture.trace.bin.lz4",
                "termination": "stopped",
                "metrics_schema": 3,
                "native_stop_acknowledged": True,
            }, {"remote_name": "fixture.trace.bin.lz4.metrics", "decoder": "sidecar"}],
        }
        calls: list[tuple[Path, Path, str | None, bool]] = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            source = artifacts / "fixture.trace.bin.lz4"
            source.write_bytes(b"fixture qtrb bytes")
            (artifacts / "fixture.trace.bin.lz4.metrics").write_text("metrics")

            def converter(binary: Path, destination: Path, *, lz4: str | None,
                          crash_marked: bool):
                calls.append((binary, destination, lz4, crash_marked))
                destination.write_text(
                    "TRACE_BEGIN format=4 scene=fixture-entry\n"
                    "TRACE_END status=stopped reason=duration_elapsed return_valid=0 elapsed_ms=2000\n",
                    encoding="utf-8",
                )
                return SimpleNamespace(termination="stopped", partial=False)

            _validate_timed_artifact_semantics(runner, report, root, converter=converter)

            self.assertEqual([(source, calls[0][1], "lz4", False)], calls)
            self.assertEqual(root, calls[0][1].parent)
            self.assertFalse(calls[0][1].exists())

    def test_timed_semantics_propagates_binary_conversion_failure(self):
        from scripts.qtrace_device_acceptance import _validate_timed_artifact_semantics

        report = {"artifacts": [{
            "remote_name": "fixture.trace.bin",
            "local_path": "artifacts/fixture.trace.bin",
            "termination": "stopped",
            "metrics_schema": 3,
            "native_stop_acknowledged": True,
        }, {"remote_name": "fixture.trace.bin.metrics", "decoder": "sidecar"}]}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            (artifacts / "fixture.trace.bin").write_bytes(b"fixture qtrb bytes")
            (artifacts / "fixture.trace.bin.metrics").write_text("metrics")
            with self.assertRaisesRegex(RuntimeError, "invalid qtrb"):
                _validate_timed_artifact_semantics(
                    FakeRunner(), report, root,
                    converter=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("invalid qtrb")),
                )

    def test_one_shot_artifact_read_preserves_evidence_for_retry(self):
        from scripts.qtrace_device_acceptance import OneShotArtifactRead
        class Client:
            def __init__(self): self.calls = []
            def read_file(self, name, *, maximum_bytes):
                self.calls.append((name, maximum_bytes)); return b"evidence"
        client = Client()
        wrapped = OneShotArtifactRead(client)
        with self.assertRaises(ConnectionError):
            wrapped.read_file("fixture.trace.bin.lz4", maximum_bytes=1)
        self.assertEqual([], client.calls)
        self.assertEqual(b"evidence", wrapped.read_file("fixture.trace.bin.lz4", maximum_bytes=1))
        self.assertEqual([("fixture.trace.bin.lz4", 1)], client.calls)
    def test_trusted_output_rejects_escape_and_symlink(self):
        from scripts.qtrace_device_acceptance import _trusted_output
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            outside = Path(temporary) / "outside"
            outside.write_text("x")
            link = root / "link"
            link.symlink_to(outside)
            with self.assertRaises(RuntimeError):
                _trusted_output(outside, root)
            with self.assertRaises(RuntimeError):
                _trusted_output(link, root)
    def test_strict_report_rejects_duplicate_keys_and_nonfinite_numbers(self):
        from scripts.qtrace_device_acceptance import _strict_json

        for payload in ('{"schema":1,"schema":1}', '{"schema":NaN}'):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    _strict_json(payload)

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

    def test_timed_report_rejects_extra_key_before_artifact_reads(self):
        from scripts.qtrace_device_acceptance import _validated_timed_report

        runner = FakeRunner()
        document = json.loads(runner.read_text(Path("report.json"), timeout=1))
        document["unexpected"] = True
        reads: list[Path] = []
        runner.read_text = lambda path, *, timeout: (reads.append(path), json.dumps(document))[1]  # type: ignore[method-assign]
        with self.assertRaisesRegex(RuntimeError, "unexpected fields"):
            _validated_timed_report(runner, Path("report.json"))
        self.assertEqual([Path("report.json")], reads)

    def test_requires_an_explicit_device(self):
        from scripts.qtrace_device_acceptance import main

        self.assertEqual(2, main([]))

    def test_acceptance_runs_bounded_workflow_and_retries_one_read(self):
        from scripts.qtrace_device_acceptance import run_acceptance

        runner = FakeRunner(fail_first_read=True)
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / "offset").mkdir()
            (Path(temporary) / "offset" / "fixture.trace.txt").write_text("fixture")
            artifacts = Path(temporary) / "offset" / "artifacts"
            artifacts.mkdir()
            (artifacts / "fixture.trace.bin.lz4").write_bytes(b"fixture qtrb bytes")
            (artifacts / "fixture.trace.bin.lz4.metrics").write_text("metrics")
            artifact_client = FakeArtifactClient(Path(temporary) / "offset")
            for name in ("latest", "name", "all", "compressed"):
                (Path(temporary) / name).mkdir()
            def converter(_source, destination, *, lz4, crash_marked):
                self.assertEqual("lz4", lz4)
                self.assertFalse(crash_marked)
                destination.write_text(
                    "TRACE_BEGIN format=4 scene=fixture-entry\n"
                    "TRACE_END status=stopped reason=duration_elapsed return_valid=0 elapsed_ms=2000\n",
                    encoding="utf-8",
                )
                return SimpleNamespace(termination="stopped", partial=False)
            self.assertEqual(0, run_acceptance(
                "SERIAL", Path(temporary), runner=runner, converter=converter,
                artifact_client_factory=lambda **_kwargs: artifact_client,
            ))
            self.assertEqual([("fixture.trace.bin.lz4.metrics", 64 * 1024)], artifact_client.calls)
            self.assertEqual([True], artifact_client.evidence_present_during_retry)
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
        self.assertEqual(12, runner.reads)  # baseline retry, scenario reports, text/oracle, and four pull reports
        self.assertEqual(("adb", "-s", "SERIAL", "shell", "kill", "-0", "4242"), commands[11])
        self.assertIn("--name", commands[13])
        self.assertIn("fixture.trace.bin.lz4", commands[13])
        self.assertEqual("--compressed-only", commands[15][-5])


if __name__ == "__main__":
    unittest.main()
