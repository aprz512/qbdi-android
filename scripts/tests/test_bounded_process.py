import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.bounded_process as bounded_process
from scripts.bounded_process import BoundedProcessError, capture_bounded


class FakeStream:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self):
        self.stdout = FakeStream()
        self.stderr = FakeStream()
        self.returncode = None
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_calls = 0

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminate_calls += 1
        self.returncode = -15

    def kill(self):
        self.kill_calls += 1
        self.returncode = -9

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


class FakeSelector:
    def __init__(self, *, fail_register=0, select_error=None, close_error=None):
        self.fail_register = fail_register
        self.select_error = select_error
        self.close_error = close_error
        self.register_calls = 0
        self.entries = {}

    def register(self, stream, _events, data):
        self.register_calls += 1
        if self.register_calls == self.fail_register:
            raise OSError(f"register {self.register_calls}")
        self.entries[stream] = data

    def get_map(self):
        return self.entries

    def select(self, _timeout):
        if self.select_error is not None:
            raise self.select_error
        return []

    def close(self):
        if self.close_error is not None:
            raise self.close_error


class BoundedProcessTests(unittest.TestCase):
    def assert_reaped(self, process):
        self.assertEqual(1, process.terminate_calls)
        self.assertGreaterEqual(process.wait_calls, 1)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_selector_constructor_failure_reaps_child_and_preserves_error(self):
        process = FakeProcess()
        primary = RuntimeError("selector constructor")
        with patch.object(bounded_process.subprocess, "Popen", return_value=process), \
             patch.object(bounded_process.selectors, "DefaultSelector", side_effect=primary):
            with self.assertRaisesRegex(RuntimeError, "selector constructor") as caught:
                capture_bounded(["fake"], maximum_bytes=1, timeout=1)

        self.assertIs(primary, caught.exception)
        self.assert_reaped(process)

    def test_starts_a_new_session_so_timeout_reaps_decoder_descendants(self):
        process = FakeProcess()
        primary = RuntimeError("selector constructor")
        with patch.object(bounded_process.subprocess, "Popen", return_value=process) as popen, \
             patch.object(bounded_process.selectors, "DefaultSelector", side_effect=primary):
            with self.assertRaises(RuntimeError):
                capture_bounded(["fake"], maximum_bytes=1, timeout=1)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_each_selector_registration_failure_reaps_child(self):
        for registration in (1, 2):
            with self.subTest(registration=registration):
                process = FakeProcess()
                selector = FakeSelector(fail_register=registration)
                with patch.object(bounded_process.subprocess, "Popen", return_value=process), \
                     patch.object(bounded_process.selectors, "DefaultSelector",
                                  return_value=selector):
                    with self.assertRaisesRegex(OSError, f"register {registration}"):
                        capture_bounded(["fake"], maximum_bytes=1, timeout=1)
                self.assert_reaped(process)

    def test_selector_close_failure_cannot_mask_primary_or_skip_reaping(self):
        process = FakeProcess()
        primary = ValueError("primary selector failure")
        selector = FakeSelector(
            select_error=primary, close_error=OSError("selector close failure")
        )
        with patch.object(bounded_process.subprocess, "Popen", return_value=process), \
             patch.object(bounded_process.selectors, "DefaultSelector", return_value=selector):
            with self.assertRaisesRegex(ValueError, "primary selector failure") as caught:
                capture_bounded(["fake"], maximum_bytes=1, timeout=1)

        self.assertIs(primary, caught.exception)
        self.assert_reaped(process)

    def test_terminates_and_reaps_a_producer_immediately_at_the_limit(self):
        command = [
            sys.executable, "-c",
            "import os\nwhile True: os.write(1, b'x' * 65536)",
        ]
        started = time.monotonic()
        with self.assertRaisesRegex(BoundedProcessError, "size limit"):
            capture_bounded(command, maximum_bytes=1024, timeout=5)
        self.assertLess(time.monotonic() - started, 2)

    def test_timeout_kills_pipe_inheriting_descendant_after_leader_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "descendant.pid"
            command = [
                sys.executable,
                "-c",
                (
                    "import os, pathlib, time\n"
                    "child = os.fork()\n"
                    f"if child:\n pathlib.Path({str(pid_path)!r}).write_text(str(child))\n"
                    "else:\n time.sleep(30)\n"
                ),
            ]
            child_pid = None
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    capture_bounded(command, maximum_bytes=1024, timeout=0.1)
                child_pid = int(pid_path.read_text(encoding="utf-8"))

                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    try:
                        os.kill(child_pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.01)
                else:
                    self.fail(f"descendant {child_pid} survived timeout cleanup")
            finally:
                if child_pid is not None:
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_success_returns_stdout(self):
        with patch.object(bounded_process.os, "killpg") as kill_group:
            output = capture_bounded(
                [sys.executable, "-c", "import os; os.write(1, b'ok')"],
                maximum_bytes=1024,
                timeout=5,
            )

        self.assertEqual(b"ok", output)
        kill_group.assert_not_called()

    def test_nonzero_error_preserves_stdout(self):
        with self.assertRaises(BoundedProcessError) as caught:
            capture_bounded(
                [
                    sys.executable,
                    "-c",
                    "import os; os.write(1, b'partial'); os.write(2, b'boom'); raise SystemExit(7)",
                ],
                maximum_bytes=1024,
                timeout=5,
            )

        self.assertEqual(7, caught.exception.returncode)
        self.assertEqual(b"partial", caught.exception.stdout)
        self.assertEqual(b"boom", caught.exception.stderr)

    def test_reaps_timeout_and_reports_bounded_stderr(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            capture_bounded(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                maximum_bytes=1024, timeout=0.05,
            )
        with self.assertRaisesRegex(BoundedProcessError, "boom"):
            capture_bounded(
                [sys.executable, "-c", "import os; os.write(2, b'boom'); raise SystemExit(7)"],
                maximum_bytes=1024, timeout=5,
            )
