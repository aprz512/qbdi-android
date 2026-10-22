import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from qtrace import cli
from qtrace.diagnostics import capture_snapshot, validate_snapshot, _worker
from qtrace.errors import QtraceError
from scripts.tests.test_bounded_process import ProcessIdentityServer, _PUBLISH_IDENTITY_SOURCE


def snapshot():
    return {"schema": 1, "ok": True, "reason": "", "pid": 42, "starttime": "99",
            "startedMonotonicNs": 100, "finishedMonotonicNs": 101,
            "mappings": {"status": "available", "reason": "", "truncated": False, "rows": [
                {"start": "0x1000", "end": "0x2000", "offset": "0x0", "permissions": "r-xp",
                 "path": "/apex/libart.so", "classification": "art_runtime_name_match"}]},
            "nativeThreads": {"status": "available", "reason": "", "truncated": False, "rows": [
                {"tid": 42, "name": "main", "nameAvailable": True}]},
            "java": {"status": "available", "reason": "", "truncated": False, "rows": [
                {"javaId": "1", "name": "main", "nameTruncated": False,
                 "frames": ["example.Main.main(Main.java:1)"], "framesTruncated": False}]}}


def envelope(value=None, error=None, cleanup=()):
    return json.dumps({"snapshot": value or snapshot(), "error": error, "cleanupErrors": list(cleanup)}).encode()


class DiagnosticsTests(unittest.TestCase):
    def test_validation_rejects_wrong_epoch_types_unknown_fields_and_unbounded_rows(self):
        changes = [("pid", True), ("starttime", "100"), ("extra", 1), ("schema", True),
                   ("finishedMonotonicNs", 99)]
        values = [{**snapshot(), key: value} for key, value in changes]
        for name, key, value in (("java", "status", []), ("java", "truncated", 1),
                                 ("java", "rows", snapshot()["java"]["rows"] * 33),
                                 ("nativeThreads", "reason", "contradiction")):
            item = snapshot(); item[name][key] = value; values.append(item)
        item = snapshot(); item["java"]["rows"][0]["frames"] *= 33; values.append(item)
        item = snapshot(); item["nativeThreads"]["rows"] *= 2; values.append(item)
        item = snapshot(); item["java"]["rows"][0]["name"] = '\ud800'; values.append(item)
        for value in values:
            with self.subTest(value=value), self.assertRaises(QtraceError):
                validate_snapshot(value, 42, "99")
        self.assertEqual(snapshot(), validate_snapshot(snapshot(), 42, "99"))

    def test_absence_is_structured_and_java_can_be_explicitly_disabled(self):
        for status, reason, include in (("unavailable", "vm_unavailable", True),
                                        ("disabled", "not_requested", False)):
            value = snapshot(); value["java"] = {"status": status, "reason": reason, "truncated": False, "rows": []}
            self.assertEqual(value, validate_snapshot(value, 42, "99", include_java=include))
        with self.assertRaisesRegex(QtraceError, "process_identity_mismatch"):
            validate_snapshot({"schema": 1, "ok": False, "reason": "process_identity_mismatch"}, 42, "99")

    @patch("qtrace.diagnostics.FridaProvider.check_host")
    def test_success_publishes_only_validated_new_file_and_preserves_existing_output(self, check):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "snapshot.json"
            runner = Mock(); runner.capture.return_value = envelope()
            result = capture_snapshot(SimpleNamespace(serial="serial-1"), 42, "99", output, runner=runner)
            self.assertEqual(result, json.loads(output.read_text()))
            command = runner.capture.call_args.args[0]
            self.assertEqual(1, command.count("qtrace.diagnostics"))
            self.assertIn("99", command)
            with self.assertRaisesRegex(QtraceError, "already exists"):
                capture_snapshot(SimpleNamespace(serial="serial-1"), 42, "99", output, runner=runner)
            self.assertEqual(1, runner.capture.call_count)
            self.assertEqual([output], list(output.parent.iterdir()))

    @patch("qtrace.diagnostics.FridaProvider.check_host")
    def test_worker_failures_duplicates_and_cleanup_failures_publish_nothing(self, check):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "snapshot.json"
            runner = Mock()
            for raw in (envelope(error="primary", cleanup=["detach"]), envelope(cleanup=["unload"]),
                        b'{"snapshot":null,"snapshot":null,"error":null,"cleanupErrors":[]}',
                        envelope({**snapshot(), "starttime": "100"})):
                runner.capture.return_value = raw
                with self.subTest(raw=raw), self.assertRaises(QtraceError):
                    capture_snapshot(SimpleNamespace(serial="s"), 42, "99", output, runner=runner)
                self.assertFalse(output.exists())
            runner.capture.side_effect = QtraceError("process.timeout", "process", "deadline")
            with self.assertRaisesRegex(QtraceError, "target completion is unconfirmed"):
                capture_snapshot(SimpleNamespace(serial="s"), 42, "99", output, runner=runner)
            self.assertFalse(output.exists())

    def test_worker_attaches_once_and_preserves_primary_error_during_cleanup(self):
        arguments = SimpleNamespace(serial="s", pid=42, starttime="99", timeout=1,
                                    max_threads=3, max_frames=4, no_java_stacks=False)
        provider = Mock(); remote = provider.get_device.return_value
        session = remote.attach.return_value; script = session.create_script.return_value
        script.exports_sync.snapshot.side_effect = RuntimeError("primary")
        script.unload.side_effect = RuntimeError("unload")
        session.detach.side_effect = RuntimeError("detach")
        result = _worker(arguments, provider)
        self.assertEqual("primary", result["error"])
        self.assertEqual(["unload", "detach"], result["cleanupErrors"])
        remote.attach.assert_called_once_with(42)
        remote.spawn.assert_not_called()
        remote.kill.assert_not_called()
        script.exports_sync.snapshot.assert_called_once_with({"schema": 1, "expectedPid": 42,
            "expectedStarttime": "99", "includeJava": True, "maxThreads": 3, "maxFrames": 4})

    @patch("qtrace.diagnostics.FridaProvider.check_host")
    def test_real_worker_timeout_reaps_host_process_and_never_creates_output(self, check):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); endpoint = root / "identity.sock"
            (root / "frida.py").write_text(
                "import time\n" + _PUBLISH_IDENTITY_SOURCE +
                f"def get_device(*args,**kwargs):\n publish_identity('worker',{str(endpoint)!r})\n time.sleep(60)\n")
            # The runner uses a PID namespace. SO_PEERCRED supplies a host PID;
            # os.getpid() inside the worker cannot identify it in this process.
            with ProcessIdentityServer(endpoint, {"worker"}) as identities:
                with patch.dict(os.environ, {"PYTHONPATH": str(root)}), self.assertRaisesRegex(QtraceError, "unconfirmed"):
                    capture_snapshot(SimpleNamespace(serial="s"), 42, "99", root / "result.json", timeout=2)
                pid, _epoch = identities.wait()["worker"]
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            self.assertFalse((root / "result.json").exists())

    def test_cli_preserves_path_stdout_and_json_channel_contracts(self):
        for machine in (False, True):
            with patch.object(cli, "_select_device", return_value=SimpleNamespace(serial="s")), \
                    patch("qtrace.diagnostics.capture_snapshot", return_value=snapshot()) as capture, \
                    contextlib.redirect_stdout(stdout := io.StringIO()), \
                    contextlib.redirect_stderr(stderr := io.StringIO()):
                code = cli.main(["snapshot", "--pid", "42", "--starttime", "99", "--output", "snapshot.json",
                                 *(["--json"] if machine else [])])
            self.assertEqual(0, code)
            capture.assert_called_once()
            if machine:
                self.assertEqual({"snapshot": "snapshot.json", "pid": 42, "starttime": "99", "exitCode": 0},
                                 json.loads(stdout.getvalue()))
                self.assertEqual("", stderr.getvalue())
            else:
                self.assertEqual("snapshot.json\n", stdout.getvalue())
                self.assertIn("java=available", stderr.getvalue())
