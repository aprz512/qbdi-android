import hashlib
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from qtrace.artifacts import (ArtifactProcessor, ArtifactResult, PullMode,
                              PullSelection, PulledArtifact,
                              pull_named_artifacts)
from qtrace.errors import QtraceError
from qtrace.report import ReportWriter, SessionReport


COMPLETE_TERMINAL = (
    b"TRACE_END status=completed return_valid=1 return=0x0 elapsed_ms=0 "
    b"instructions=0 encoded_bytes=0 compressed_bytes=0 cache_hits=0 cache_misses=0 "
    b"cache_collisions=0 buffer_swaps=0 producer_waits=0 producer_wait_ns=0 "
    b"effective_buffer_bytes=0\n"
)


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
    @staticmethod
    def _report(session: str, status: str) -> SessionReport:
        return SessionReport(1, session, "run", status, "completed", "com.example.app", "d", None,
                             "start", "finish", (), {}, {}, {}, {}, {}, (), (), None, ())

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
        client = FakeClient({"old.trace.txt": COMPLETE_TERMINAL,
                             "new.trace.txt": COMPLETE_TERMINAL})
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
        client = FakeClient({"bad.trace.bin": b"bad", "good.trace.txt": COMPLETE_TERMINAL})
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

    def test_output_directory_replacement_never_returns_attacker_path(self):
        session = "11111111-1111-4111-8111-111111111111"
        status = self._status(session, artifacts=["run.trace.txt"])
        client = FakeClient({"run.trace.txt": COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            output = root_path / "output"
            attacker = root_path / "attacker"
            original = root_path / "original"
            output.mkdir()
            attacker.mkdir()
            real_new_stage = __import__("qtrace.artifacts", fromlist=["_new_stage"])._new_stage

            def replace_output(path):
                stage = real_new_stage(path)
                output.rename(original)
                attacker.rename(output)
                return stage

            with patch("qtrace.artifacts._new_stage", side_effect=replace_output):
                with self.assertRaises(QtraceError) as raised:
                    self._processor(client).collect_session(
                        "d", "com.example.app", session, status, output, 1)
            self.assertEqual("artifact.destination_replaced", raised.exception.code)
            self.assertFalse((output / session).exists())
            self.assertFalse((original / session).exists())

    def test_artifact_report_uses_actual_device_metadata(self):
        class Device:
            serial = "SERIAL"
            access_mode = "root"
            target_strategy = "su-uid"
        client = FakeClient({"run.trace.txt": COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual(Device(), "com.example.app",
                                                         PullSelection(PullMode.NAME, "run.trace.txt"), Path(root), 1)
            document = json.loads((result.output_dir / "device.json").read_text())
            self.assertEqual("SERIAL", document["serial"])
            self.assertEqual("su-uid", document["target_strategy"])

    def test_unicode_legacy_basename_is_accepted_by_client(self):
        client = FakeClient({"合法.trace.txt": COMPLETE_TERMINAL})
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
        client = FakeClient({"run.trace.txt": COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual("d", "com.example.app",
                                                         PullSelection(PullMode.NAME, "run.trace.txt"), Path(root), 1)
            report = json.loads((result.output_dir / "report.json").read_text())
            self.assertIsNone(report["artifacts"][0]["source_size"])
            self.assertEqual(len(COMPLETE_TERMINAL), report["artifacts"][0]["destination_size"])
            self.assertIn("remote_name", report["artifacts"][0])

    def test_stopping_status_must_not_acknowledge_before_seal(self):
        status = self._status(state="stopping", reason="duration_elapsed", stopAcknowledged=True)
        client = FakeClient({"session-11111111-1111-4111-8111-111111111111.status.json":
                             json.dumps(status).encode(), "run.trace.txt": COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(QtraceError) as raised:
                self._processor(client).pull_manual("d", "com.example.app", PullSelection(), Path(root), 1)
            self.assertEqual("artifact.status_missing", raised.exception.code)

    def test_active_identity_allows_distinct_threads_on_one_scene(self):
        status = self._status(state="running", reason="", stopAcknowledged=False,
                              normalizedScenes=[{"name": "s", "startOffset": 4, "endOffset": 8}],
                              activeScenes=[{"sceneIndex": 0, "tid": 11, "sealed": False},
                                            {"sceneIndex": 0, "tid": 12, "sealed": False}],
                              artifacts=["run.trace.txt"])
        client = FakeClient({"session-11111111-1111-4111-8111-111111111111.status.json":
                             json.dumps(status).encode(), "run.trace.txt": COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual("d", "com.example.app", PullSelection(), Path(root), 1)
            self.assertEqual(2, result.exit_code)
            self.assertTrue(any(error["code"] == "artifact.incomplete" for error in result.errors))

    def test_stop_incomplete_is_published_as_partial(self):
        status = self._status(state="stop_incomplete", reason="duration_elapsed", stopAcknowledged=False)
        client = FakeClient({"run.trace.txt": COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).collect_session("d", "com.example.app", status["sessionId"],
                                                             status, Path(root), 1)
            self.assertEqual(2, result.exit_code)
            self.assertIn("artifact.incomplete", {error["code"] for error in result.errors})

    def test_manual_uuid_artifact_requires_matching_native_status(self):
        name = "11111111-1111-4111-8111-111111111111.trace.txt"
        client = FakeClient({name: COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(QtraceError) as raised:
                self._processor(client).pull_manual("d", "com.example.app",
                                                    PullSelection(PullMode.NAME, name), Path(root), 1)
            self.assertEqual("artifact.status_missing", raised.exception.code)

    def test_all_uses_each_matching_status_for_multiple_uuid_roots(self):
        first = "11111111-1111-4111-8111-111111111111"
        second = "22222222-2222-4222-8222-222222222222"
        generated = "33333333-3333-4333-8333-333333333333"
        first_root = f"{first}.trace.txt"
        second_root = f"{second}.trace.txt"
        client = FakeClient({
            f"session-{first}.status.json": json.dumps(
                self._status(first, artifacts=[first_root])).encode(),
            f"session-{second}.status.json": json.dumps(
                self._status(second, artifacts=[second_root])).encode(),
            first_root: COMPLETE_TERMINAL,
            second_root: COMPLETE_TERMINAL,
        })
        with tempfile.TemporaryDirectory() as root, patch(
                "qtrace.artifacts.uuid.uuid4", return_value=uuid.UUID(generated)):
            result = self._processor(client).pull_manual(
                "d", "com.example.app", PullSelection(PullMode.ALL), Path(root), 1)
            self.assertEqual({first_root, second_root}, {path.name for path in result.files})
            self.assertEqual(generated, json.loads(
                (result.output_dir / "session.json").read_text())["sessionId"])
            reads = [call[1] for call in client.calls if call[0] == "read"]
            self.assertIn(f"session-{first}.status.json", reads)
            self.assertIn(f"session-{second}.status.json", reads)

    def test_all_keeps_only_sealed_uuid_roots_and_marks_active_partial(self):
        sealed = "11111111-1111-4111-8111-111111111111"
        active = "22222222-2222-4222-8222-222222222222"
        sealed_root, active_root = f"{sealed}.trace.txt", f"{active}.trace.txt"
        active_status = self._status(active, state="running", reason="", stopAcknowledged=False,
                                     artifacts=[active_root])
        client = FakeClient({
            f"session-{sealed}.status.json": json.dumps(self._status(sealed, artifacts=[sealed_root])).encode(),
            f"session-{active}.status.json": json.dumps(active_status).encode(),
            sealed_root: COMPLETE_TERMINAL, active_root: COMPLETE_TERMINAL,
        })
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual(
                "d", "com.example.app", PullSelection(PullMode.ALL), Path(root), 1)
            self.assertEqual(2, result.exit_code)
            self.assertIn(sealed_root, [path.name for path in result.files])
            self.assertNotIn(active_root, [path.name for path in result.files])
            self.assertIn("artifact.incomplete", {item["code"] for item in result.errors})

    def test_validated_root_returns_existing_metrics_sidecar(self):
        from scripts.tests.test_pull_trace import current_complete_stream, v3_sidecar
        session = "11111111-1111-4111-8111-111111111111"
        root = "run.trace.bin"
        status = self._status(session, artifacts=[root])
        binary = current_complete_stream(compression=0)
        metrics = v3_sidecar(termination="completed", return_valid=1, profile="full",
                             instructions=0, elapsed_ms=17, encoded_bytes=len(binary),
                             compressed_bytes=len(binary))
        client = FakeClient({root: binary, root + ".metrics": metrics})
        with tempfile.TemporaryDirectory() as directory:
            result = self._processor(client).collect_session(
                "d", "com.example.app", session, status, Path(directory), 1)
            self.assertIn(root + ".metrics", [path.name for path in result.files])
            self.assertTrue(all(path.exists() for path in result.files))

    def test_all_mixes_uuid_owned_and_legacy_roots(self):
        session = "11111111-1111-4111-8111-111111111111"
        owned, legacy = f"{session}.trace.txt", "legacy.trace.txt"
        client = FakeClient({f"session-{session}.status.json": json.dumps(
            self._status(session, artifacts=[owned])).encode(), owned: COMPLETE_TERMINAL,
            legacy: COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual(
                "d", "com.example.app", PullSelection(PullMode.ALL), Path(root), 1)
            self.assertEqual({owned, legacy}, {path.name for path in result.files})

    def test_all_excludes_running_single_uuid_but_keeps_legacy_root(self):
        session = "11111111-1111-4111-8111-111111111111"
        owned, legacy = f"{session}.trace.txt", "legacy.trace.txt"
        running = self._status(session, state="running", reason="", stopAcknowledged=False,
                               artifacts=[owned])
        client = FakeClient({f"session-{session}.status.json": json.dumps(running).encode(),
                             owned: COMPLETE_TERMINAL, legacy: COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual(
                "d", "com.example.app", PullSelection(PullMode.ALL), Path(root), 1)
            self.assertEqual(2, result.exit_code)
            self.assertEqual([legacy], [path.name for path in result.files])

    def test_text_terminal_rejects_unversioned_or_extra_terminal_fields(self):
        invalid = (
            b"TRACE_END status=ok\n",
            b"TRACE_END status=completed extra=untrusted\n",
            b"TRACE_END status=stopped reason=duration_elapsed return_valid=0\n",
        )
        for payload in invalid:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as root:
                result = self._processor(FakeClient({"run.trace.txt": payload})).pull_manual(
                    "d", "com.example.app", PullSelection(PullMode.NAME, "run.trace.txt"), Path(root), 1)
                self.assertEqual(2, result.exit_code)
                self.assertFalse((result.output_dir / "artifacts" / "run.trace.txt").exists())

    def test_text_terminal_accepts_exact_legacy_and_stopped_forms(self):
        valid = (
            b"TRACE_END status=ok ret=0x0 elapsed_ms=0 bytes=0\n",
            b"TRACE_END status=stopped reason=duration_elapsed return_valid=0 elapsed_ms=0 "
            b"instructions=0 encoded_bytes=0 compressed_bytes=0 cache_hits=0 cache_misses=0 "
            b"cache_collisions=0 buffer_swaps=0 producer_waits=0 producer_wait_ns=0 "
            b"effective_buffer_bytes=0\n",
        )
        for payload in valid:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as root:
                result = self._processor(FakeClient({"run.trace.txt": payload})).pull_manual(
                    "d", "com.example.app", PullSelection(PullMode.NAME, "run.trace.txt"), Path(root), 1)
                self.assertEqual(0, result.exit_code)
                self.assertTrue((result.output_dir / "artifacts" / "run.trace.txt").exists())

    def test_current_writer_is_retained_as_bounded_incomplete_evidence(self):
        client = FakeClient({"run.trace.txt.current": b"partial", "good.trace.txt": COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual("d", "com.example.app",
                                                         PullSelection(PullMode.ALL), Path(root), 1)
            self.assertEqual(2, result.exit_code)
            self.assertIn("artifact.incomplete", {error["code"] for error in result.errors})
            self.assertIn("good.trace.txt", [path.name for path in result.files])

    def test_text_requires_one_terminal_line_at_eof_and_rejects_crashed(self):
        for payload in (b"prefix TRACE_END status=completed suffix\nTRACE_END status=completed\n",
                        b"TRACE_END status=crashed\n"):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as root:
                result = self._processor(FakeClient({"run.trace.txt": payload})).pull_manual(
                    "d", "com.example.app", PullSelection(PullMode.NAME, "run.trace.txt"), Path(root), 1)
                self.assertEqual(2, result.exit_code)
                self.assertFalse((result.output_dir / "artifacts" / "run.trace.txt").exists())

    def test_corrupt_root_removes_sidecars_but_preserves_valid_sibling(self):
        client = FakeClient({"bad.trace.bin": b"bad", "bad.trace.bin.metrics": b"old",
                             "good.trace.txt": COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).pull_manual("d", "com.example.app",
                                                         PullSelection(PullMode.ALL), Path(root), 1)
            self.assertEqual(2, result.exit_code)
            self.assertIn("good.trace.txt", [path.name for path in result.files])
            self.assertFalse((result.output_dir / "artifacts" / "bad.trace.bin.metrics").exists())

    def test_post_rename_fsync_failure_returns_committed_partial(self):
        sid = "11111111-1111-4111-8111-111111111111"
        status = self._status(sid)
        client = FakeClient({"run.trace.txt": COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            real_fsync = __import__("os").fsync
            final = output / sid

            def fsync(descriptor):
                if final.exists():
                    raise OSError("directory fsync failed after commit")
                return real_fsync(descriptor)

            with patch("qtrace.artifacts.os.fsync", side_effect=fsync):
                result = self._processor(client).collect_session("d", "com.example.app", sid,
                                                                 status, output, 1)
            self.assertEqual(2, result.exit_code)
            self.assertTrue(final.is_dir())
            self.assertIn("artifact.commit_durable", {error["code"] for error in result.errors})

    def test_report_refresh_preserves_committed_report_and_propagates_interrupt(self):
        session = "11111111-1111-4111-8111-111111111111"
        status = self._status(session, artifacts=["run.trace.txt"])
        client = FakeClient({"run.trace.txt": COMPLETE_TERMINAL})
        processor = self._processor(client)
        original_publish = processor._publish

        def publish_with_late_error(*args, **kwargs):
            args[4].append({"name": "", "code": "artifact.late", "detail": "late diagnostic"})
            return original_publish(*args, **kwargs)

        with tempfile.TemporaryDirectory() as root, patch.object(
                processor, "_publish", side_effect=publish_with_late_error), patch(
                "qtrace.artifacts._rewrite_published_report", side_effect=OSError("refresh failed")):
            result = processor.collect_session("d", "com.example.app", session, status, Path(root), 1)
            report = json.loads((result.output_dir / "report.json").read_text())
            self.assertIn("artifact.report_refresh", {error["code"] for error in result.errors})
            self.assertNotIn("artifact.report_refresh", {error["code"] for error in report["errors"]})

        processor = self._processor(client)
        original_publish = processor._publish
        with tempfile.TemporaryDirectory() as root, patch.object(
                processor, "_publish", side_effect=publish_with_late_error), patch(
                "qtrace.artifacts._rewrite_published_report", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                processor.collect_session("d", "com.example.app", session, status, Path(root), 1)

    def test_collector_token_never_overwrites_a_concurrent_report_inode(self):
        from qtrace.artifacts import publish_collector_report
        session = "11111111-1111-4111-8111-111111111111"
        status = self._status(session, artifacts=["run.trace.txt"])
        client = FakeClient({"run.trace.txt": COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).collect_session(
                "d", "com.example.app", session, status, Path(root), 1)
            token = getattr(result, "_publication_token")
            writer = ReportWriter()
            writer.write_atomic(result.output_dir / "report.json", self._report(session, "concurrent"))

            _report, error_path, merged = publish_collector_report(
                token, writer, self._report(session, "sealed"))

            self.assertFalse(merged)
            self.assertEqual("concurrent", json.loads(
                (result.output_dir / "report.json").read_text())["status"])
            self.assertTrue(error_path.is_file())
            self.assertIn("artifact.concurrent_report", json.loads(
                error_path.read_text())["artifacts"][-1]["code"])

    def test_conditional_report_exchange_rolls_back_last_moment_replacement(self):
        from qtrace import report as report_module
        session = "11111111-1111-4111-8111-111111111111"
        writer = ReportWriter()
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            target = directory / "report.json"
            writer.write_atomic(target, self._report(session, "original"))
            identity = (target.stat().st_dev, target.stat().st_ino)
            (directory / "racer").write_text("concurrent", encoding="utf-8")
            real_exchange = report_module._exchange
            first = True

            def exchange(fd, left, right):
                nonlocal first
                if first:
                    first = False
                    __import__("os").replace("racer", right, src_dir_fd=fd, dst_dir_fd=fd)
                real_exchange(fd, left, right)

            fd = __import__("os").open(directory, __import__("os").O_RDONLY)
            try:
                with patch("qtrace.report._exchange", side_effect=exchange):
                    self.assertFalse(writer.write_atomic_at(fd, "report.json", self._report(session, "new"),
                                                          expected_identity=identity))
            finally:
                __import__("os").close(fd)
            self.assertEqual("concurrent", target.read_text(encoding="utf-8"))

    def test_statusless_session_json_uses_null_native_status(self):
        client = FakeClient({"run.trace.txt": COMPLETE_TERMINAL})
        with tempfile.TemporaryDirectory() as root:
            result = self._processor(client).collect_session(
                "d", "com.example.app", "11111111-1111-4111-8111-111111111111", None,
                Path(root), 1)
            document = json.loads((result.output_dir / "session.json").read_text())
            self.assertIsNone(document["status"])

    def test_shared_legacy_validator_accepts_space_emoji_and_punctuation(self):
        from scripts.pull_trace import _validate_artifact_name
        for name in ("trace with space.trace.txt", "trace😀.trace.txt", "trace·mark.trace.txt"):
            with self.subTest(name=name):
                _validate_artifact_name(name)


if __name__ == "__main__":
    unittest.main()
