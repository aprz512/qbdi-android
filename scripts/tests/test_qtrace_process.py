import math
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.bounded_process import BoundedProcessError

from qtrace.errors import QtraceError
from qtrace.process import BoundedRunner


class BoundedRunnerTests(unittest.TestCase):
    def test_real_fake_adb_reads_a_caller_owned_descriptor_in_the_target_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "held-snapshot.so"
            source.write_bytes(b"validated snapshot bytes")
            fake_adb = root / "adb"
            fake_adb.write_text(
                f"#!{sys.executable}\n"
                "import os, sys\n"
                "descriptor = os.open(sys.argv[-2], os.O_RDONLY)\n"
                "try:\n"
                "    os.write(1, os.read(descriptor, 4096))\n"
                "finally:\n"
                "    os.close(descriptor)\n",
                encoding="utf-8",
            )
            fake_adb.chmod(0o755)
            descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
            try:
                output = BoundedRunner().capture(
                    [
                        str(fake_adb), "-s", "SERIAL", "push",
                        f"/proc/self/fd/{descriptor}", "/data/local/tmp/tracer.so",
                    ],
                    maximum_bytes=4096,
                    timeout=3.0,
                    pass_fds=(descriptor,),
                )

                self.assertEqual(b"validated snapshot bytes", output)
                self.assertEqual(source.stat().st_ino, os.fstat(descriptor).st_ino)
            finally:
                os.close(descriptor)

    def test_forwards_argument_array_and_explicit_bounds(self):
        with patch("qtrace.process.capture_bounded", return_value=b"ok") as capture:
            output = BoundedRunner().capture(
                ["tool", "argument with spaces"], maximum_bytes=1234, timeout=2.5
            )

        self.assertEqual(b"ok", output)
        capture.assert_called_once_with(
            ("tool", "argument with spaces"), maximum_bytes=1234, timeout=2.5
        )

    def test_defaults_are_finite_and_bounded(self):
        with patch("qtrace.process.capture_bounded", return_value=b"") as capture:
            BoundedRunner().capture(["tool"])

        kwargs = capture.call_args.kwargs
        self.assertEqual(1_048_576, kwargs["maximum_bytes"])
        self.assertEqual(30.0, kwargs["timeout"])

    def test_rejects_strings_empty_commands_and_invalid_limits(self):
        invalid = (
            ("tool", 1, 1.0),
            ([], 1, 1.0),
            (["tool", "bad\0arg"], 1, 1.0),
            (["tool"], 0, 1.0),
            (["tool"], 1, 0.0),
            (["tool"], 1, math.inf),
        )
        for command, maximum_bytes, timeout in invalid:
            with self.subTest(command=command, maximum_bytes=maximum_bytes, timeout=timeout):
                with self.assertRaises(QtraceError):
                    BoundedRunner().capture(
                        command, maximum_bytes=maximum_bytes, timeout=timeout
                    )

    def test_maps_process_failures_to_bounded_single_line_qtrace_errors(self):
        failures = (
            OSError("cannot start\nsecret"),
            subprocess.TimeoutExpired(["tool"], 1),
            BoundedProcessError("failed\ndetail", returncode=7, stderr=b"detail"),
        )
        for failure in failures:
            with self.subTest(failure=failure), patch(
                "qtrace.process.capture_bounded", side_effect=failure
            ):
                with self.assertRaises(QtraceError) as caught:
                    BoundedRunner().capture(["tool"], maximum_bytes=8, timeout=1)
                self.assertEqual("process", caught.exception.stage)
                self.assertNotIn("\n", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
