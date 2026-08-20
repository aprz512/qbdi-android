import subprocess
import sys
import time
import unittest

from scripts.bounded_process import BoundedProcessError, capture_bounded


class BoundedProcessTests(unittest.TestCase):
    def test_terminates_and_reaps_a_producer_immediately_at_the_limit(self):
        command = [
            sys.executable, "-c",
            "import os\nwhile True: os.write(1, b'x' * 65536)",
        ]
        started = time.monotonic()
        with self.assertRaisesRegex(BoundedProcessError, "size limit"):
            capture_bounded(command, maximum_bytes=1024, timeout=5)
        self.assertLess(time.monotonic() - started, 2)

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
