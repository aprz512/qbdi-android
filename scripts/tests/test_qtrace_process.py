import math
import subprocess
import unittest
from unittest.mock import patch

from scripts.bounded_process import BoundedProcessError

from qtrace.errors import QtraceError
from qtrace.process import BoundedRunner


class BoundedRunnerTests(unittest.TestCase):
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
