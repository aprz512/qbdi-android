import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from qtrace.artifacts import (ArtifactProcessor, ArtifactResult, PullMode,
                              PullSelection, PulledArtifact,
                              pull_named_artifacts)
from qtrace.errors import QtraceError


class FakeClient:
    def __init__(self, files):
        self.files = dict(files)
        self.calls = []

    def list_names(self, timeout=None):
        self.calls.append(("list", timeout))
        return list(self.files)

    def read_file(self, name, maximum_bytes=None, timeout=None):
        self.calls.append(("read", name, timeout))
        return self.files[name]

    def stream_file(self, name, output, timeout=None):
        self.calls.append(("stream", name, timeout))
        output.write(self.files[name])


class ArtifactTests(unittest.TestCase):
    def test_named_pull_hashes_and_is_durable(self):
        client = FakeClient({"trace.trace.bin": b"payload"})
        with tempfile.TemporaryDirectory() as root:
            result = pull_named_artifacts(client, "com.example.app", ["trace.trace.bin"],
                                          Path(root), timeout=1.5)
            self.assertEqual(("trace.trace.bin",), tuple(item.remote_name for item in result))
            item = result[0]
            self.assertEqual(hashlib.sha256(b"payload").hexdigest(), item.sha256)
            self.assertEqual(7, item.size)
            self.assertEqual(b"payload", item.local_path.read_bytes())
            self.assertTrue(all(call[-1] == 1.5 for call in client.calls))

    def test_public_shapes_and_selection(self):
        self.assertEqual(PullMode.LATEST, PullSelection().mode)
        self.assertEqual((Path("x"),), ArtifactResult(Path("."), (Path("x"),), (), 0).files)

    def test_latest_uses_matching_native_status_and_exact_layout(self):
        status = {"schemaVersion": 1, "sessionId": "11111111-1111-4111-8111-111111111111",
                  "packageName": "com.example.app", "generation": 1, "pid": 123,
                  "state": "sealed", "reason": "duration_elapsed", "transitionMonotonicNs": 1,
                  "normalizedScenes": [], "activeScenes": [], "artifacts": ["run.trace.bin.lz4"],
                  "stopAcknowledged": True, "warnings": [], "errors": []}
        client = FakeClient({
            "session-11111111-1111-4111-8111-111111111111.status.json": json.dumps(status).encode(),
            "run.trace.bin.lz4": b"not-a-qtrb",
        })
        with tempfile.TemporaryDirectory() as root:
            result = ArtifactProcessor(client_factory=lambda _d, _p: client).pull_manual(
                "SERIAL", "com.example.app", PullSelection(PullMode.LATEST), Path(root), 1.0)
            self.assertEqual(2, result.exit_code)
            self.assertTrue((result.output_dir / "session.json").is_file())
            self.assertTrue((result.output_dir / "effective-config.json").is_file())
            self.assertTrue((result.output_dir / "device.json").is_file())
            self.assertTrue((result.output_dir / "artifacts").is_dir())
            self.assertTrue((result.output_dir / "report.json").is_file())

    def test_name_rejects_uncompressed_when_requested(self):
        client = FakeClient({"run.trace.bin": b"x"})
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(Exception):
                ArtifactProcessor(client_factory=lambda _d, _p: client).pull_manual(
                    "SERIAL", "com.example.app",
                    PullSelection(PullMode.NAME, "run.trace.bin", True), Path(root), 1.0)

    def test_existing_destination_is_never_overwritten(self):
        client = FakeClient({"run.trace.bin": b"x"})
        with tempfile.TemporaryDirectory() as root:
            destination = Path(root) / "generated"
            destination.mkdir()
            marker = destination / "marker"
            marker.write_text("keep")
            result = ArtifactProcessor(client_factory=lambda _d, _p: client).pull_manual(
                "SERIAL", "com.example.app", PullSelection(PullMode.NAME, "run.trace.bin"),
                Path(root), 1.0)
            self.assertEqual(2, result.exit_code)
            self.assertEqual("keep", marker.read_text())

    def _processor(self, client):
        return ArtifactProcessor(client_factory=lambda _d, _p: client)

    def _status(self, session="11111111-1111-4111-8111-111111111111", **extra):
        value = {"schemaVersion": 1, "sessionId": session, "packageName": "com.example.app",
                 "generation": 1, "pid": 123, "state": "sealed", "reason": "duration_elapsed",
                 "transitionMonotonicNs": 1, "normalizedScenes": [], "activeScenes": [],
                 "artifacts": ["run.trace.txt"], "stopAcknowledged": True, "warnings": [], "errors": []}
        value.update(extra)
        return value

    def test_session_missing_declared_artifact_is_partial(self):
        status = self._status(artifacts=["missing.trace.txt"])
        client = FakeClient({})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).collect_session("d", "com.example.app", status["sessionId"],
                                                             status, Path(root), 1)
            self.assertNotEqual(0, result.exit_code)

    def test_pre_spawn_snapshot_sidecar_is_not_admitted(self):
        status = self._status(artifacts=["run.trace.txt"], snapshot=["run.trace.txt.metrics"])
        client = FakeClient({"run.trace.txt": b"complete", "run.trace.txt.metrics": b"old"})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).collect_session("d", "com.example.app", status["sessionId"],
                                                             status, Path(root), 1)
            self.assertNotIn("run.trace.txt.metrics", [p.name for p in result.files])

    def test_missing_native_status_recovers_listing_as_partial(self):
        client = FakeClient({"old.trace.txt": b"TRACE_END status=completed\n",
                             "new.trace.txt": b"TRACE_END status=completed\n"})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).collect_session(
                "d", "com.example.app", "11111111-1111-4111-8111-111111111111", None,
                Path(root), 1)
            self.assertEqual(2, result.exit_code)
            self.assertIn("new.trace.txt", [path.name for path in result.files])
            self.assertIn("artifact.status_missing", {error["code"] for error in result.errors})

    def test_latest_rejects_non_strict_status_instead_of_fallback(self):
        session = "11111111-1111-4111-8111-111111111111"
        value = self._status(session, generation=float("nan"))
        client = FakeClient({f"session-{session}.status.json": json.dumps(value).encode(),
                             "run.trace.txt": b"complete"})
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(QtraceError):
                self._processor(client).pull_manual("d", "com.example.app", PullSelection(), Path(root), 1)

    def test_latest_does_not_fallback_when_status_belongs_to_another_package(self):
        session = "11111111-1111-4111-8111-111111111111"
        value = self._status(session, packageName="com.other.app")
        client = FakeClient({f"session-{session}.status.json": json.dumps(value).encode(),
                             "run.trace.txt": b"complete"})
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(QtraceError):
                self._processor(client).pull_manual("d", "com.example.app", PullSelection(), Path(root), 1)

    def test_temporary_listing_is_skipped_as_incomplete(self):
        client = FakeClient({".qtrace-stage-1.trace.bin": b"bad", "run.trace.txt": b"complete"})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual("d", "com.example.app",
                                                         PullSelection(PullMode.ALL), Path(root), 1)
            self.assertNotIn(".qtrace-stage-1.trace.bin", [call[1] for call in client.calls if call[0] == "stream"])
            self.assertEqual(2, result.exit_code)

    def test_unmarked_legacy_text_must_have_terminal_evidence(self):
        client = FakeClient({"run.trace.txt": b"unterminated"})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual("d", "com.example.app",
                                                         PullSelection(PullMode.NAME, "run.trace.txt"), Path(root), 1)
            self.assertEqual(2, result.exit_code)

    def test_flight_recovery_publishes_summary_and_records_recovery(self):
        client = FakeClient({"run.flight.bin": b"not-a-flight"})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual("d", "com.example.app",
                                                         PullSelection(PullMode.NAME, "run.flight.bin"), Path(root), 1)
            self.assertEqual(2, result.exit_code)
            self.assertFalse((result.output_dir / "artifacts" / "run.flight.json").exists())

    def test_recoverable_flight_publishes_committed_summary(self):
        from scripts.tests.test_pull_trace import recoverable_flight_artifact
        client = FakeClient({"run.flight.bin": recoverable_flight_artifact()})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual("d", "com.example.app",
                                                         PullSelection(PullMode.NAME, "run.flight.bin"), Path(root), 1)
            self.assertEqual(0, result.exit_code)
            self.assertTrue((result.output_dir / "artifacts" / "run.flight.json").is_file())

    def test_corrupt_member_is_not_in_published_files(self):
        client = FakeClient({"bad.trace.bin": b"bad", "good.trace.txt": b"TRACE_END status=completed\n"})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual("d", "com.example.app",
                                                         PullSelection(PullMode.ALL), Path(root), 1)
            self.assertNotIn("bad.trace.bin", [p.name for p in result.files])
            self.assertIn("good.trace.txt", [p.name for p in result.files])

    def test_transport_timeout_leaves_no_final_session_directory(self):
        class TimeoutClient(FakeClient):
            def stream_file(self, name, output, timeout=None):
                raise TimeoutError("timed out")
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(QtraceError):
                self._processor(TimeoutClient({"run.trace.txt": b"x"})).pull_manual(
                    "d", "com.example.app", PullSelection(PullMode.NAME, "run.trace.txt"), Path(root), 1)
            self.assertEqual([], list(Path(root).iterdir()))

    def test_artifact_report_uses_actual_device_metadata(self):
        class Device:
            serial = "SERIAL"
            access_mode = "root"
            target_strategy = "su-uid"
        client = FakeClient({"run.trace.txt": b"TRACE_END status=completed\n"})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual(Device(), "com.example.app",
                                                         PullSelection(PullMode.NAME, "run.trace.txt"), Path(root), 1)
            document = json.loads((result.output_dir / "device.json").read_text())
            self.assertEqual("SERIAL", document["serial"])
            self.assertEqual("su-uid", document["target_strategy"])

    def test_unicode_legacy_basename_is_accepted_by_client(self):
        client = FakeClient({"合法.trace.txt": b"TRACE_END status=completed\n"})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual("d", "com.example.app",
                                                         PullSelection(PullMode.NAME, "合法.trace.txt"), Path(root), 1)
            self.assertIn("合法.trace.txt", [p.name for p in result.files])

    def test_adapter_type_error_after_write_is_not_retried(self):
        class OneCallClient(FakeClient):
            def __init__(self, files):
                super().__init__(files)
                self.count = 0
            def stream_file(self, name, output, timeout=None):
                self.count += 1
                output.write(self.files[name])
                raise TypeError("timeout unsupported")
        client = OneCallClient({"run.trace.txt": b"x"})
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(QtraceError):
                pull_named_artifacts(client, "com.example.app", ["run.trace.txt"], Path(root), timeout=1)
            self.assertEqual(1, client.count)

    def test_pull_result_does_not_claim_remote_size_as_destination_size(self):
        client = FakeClient({"run.trace.txt": b"TRACE_END status=completed\n"})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual("d", "com.example.app",
                                                         PullSelection(PullMode.NAME, "run.trace.txt"), Path(root), 1)
            report = json.loads((result.output_dir / "report.json").read_text())
            self.assertIsNone(report["artifacts"][0]["source_size"])
            self.assertEqual(len(b"TRACE_END status=completed\n"), report["artifacts"][0]["destination_size"])
            self.assertIn("remote_name", report["artifacts"][0])


if __name__ == "__main__":
    unittest.main()
