from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from scripts.jni_abi_acceptance import cleanup_probe, device_guard, evaluate_probe, main


class ProbeEvaluationTests(unittest.TestCase):
    def test_fixed_floating_checks_require_all_values_in_call_order(self):
        fields = [("FloatField", "jfloat", -1.5), ("DoubleField", "jdouble", -3.25),
                  ("StaticFloatField", "jfloat", 1.25), ("StaticDoubleField", "jdouble", -2.5)]
        calls = [[(category, prefix + field, f"{kind} : 0x1234 ({value})")
                  for prefix, category in [("Set", "jni-enter"), ("Get", "jni-leave")]
                  for field, kind, value in fields] for _ in range(3)]
        checks, _ = evaluate_probe({}, [], calls)
        self.assertTrue(checks["fixed_floating_argument_text"])
        self.assertTrue(checks["fixed_floating_return_text"])
        for change in ("missing", "wrong_value", "wrong_type", "wrong_order"):
            with self.subTest(change=change):
                changed = [list(artifact) for artifact in calls]
                category, name, detail = changed[1][0]
                if change == "missing":
                    changed[1].pop(0)
                elif change == "wrong_order":
                    changed[1][0], changed[1][1] = changed[1][1], changed[1][0]
                else:
                    changed[1][0] = (category, name, detail.replace("-1.5", "0.0") if change == "wrong_value"
                                     else detail.replace("jfloat", "jdouble"))
                checks, _ = evaluate_probe({}, [], changed)
                self.assertFalse(checks["fixed_floating_argument_text"])
                self.assertTrue(checks["fixed_floating_return_text"])

    def test_no_floating_records_cannot_pass_the_gate(self):
        checks, _ = evaluate_probe({}, [], [[]])
        self.assertFalse(checks["fixed_floating_argument_text"])
        self.assertFalse(checks["fixed_floating_return_text"])


class ProbeGuardTests(unittest.TestCase):
    @staticmethod
    def stat(epoch):
        return ("42 (probe) S " + "0 " * 18 + str(epoch)).encode()

    def test_cleanup_does_not_treat_an_adb_error_as_process_exit(self):
        replies = iter([SimpleNamespace(stdout=b"42"), SimpleNamespace(stdout=self.stat(99)),
                        SimpleNamespace(returncode=1, stdout=b"", stderr=b"error: device offline")])
        commands = []

        def root(command, **options):
            commands.append(command)
            return next(replies)

        with self.assertRaisesRegex(RuntimeError, "process query failed"):
            cleanup_probe(root, "/owned/probe", "/owned/data", True)
        self.assertFalse(any(command[0] in ("kill", "rm") for command in commands))

    def test_cleanup_never_kills_a_reused_pid(self):
        replies = iter([SimpleNamespace(stdout=b"42"), SimpleNamespace(stdout=self.stat(99)),
                        SimpleNamespace(returncode=0, stdout=self.stat(100), stderr=b""),
                        SimpleNamespace(returncode=0)])
        commands = []

        def root(command, **options):
            commands.append(command)
            return next(replies)

        receipt = cleanup_probe(root, "/owned/probe", "/owned/data", True)
        self.assertEqual("pid_reused", receipt["process"])
        self.assertFalse(any(command[0] == "kill" for command in commands))
        self.assertEqual(["rm", "-rf", "/owned/probe", "/owned/data"], commands[-1])

    def test_same_server_and_serial_cannot_acquire_a_second_guard(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as endpoint:
            endpoint.bind(("127.0.0.1", 0))
            endpoint.listen(4)
            server = "tcp:127.0.0.1:" + str(endpoint.getsockname()[1])
            with device_guard(Path(directory), server, "serial-1"):
                with self.assertRaises(BlockingIOError):
                    with device_guard(Path(directory), server, "serial-1"):
                        self.fail("second guard acquired")
            with device_guard(Path(directory), server, "serial-1") as reservation:
                reservation.mkdir()
            with self.assertRaisesRegex(RuntimeError, "unresolved cleanup"):
                with device_guard(Path(directory), server, "serial-1"):
                    self.fail("reservation ignored")
            self.assertTrue(reservation.is_dir())

    def test_missing_server_records_unavailable_without_invoking_adb(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = ["jni_abi_acceptance", "--serial", "serial-1", "--adb", "/unused/adb",
                         "--guard-root", str(root / "guard"), "--tracer", "/unused/tracer.so",
                         "--companion", "/unused/companion.so", "--output", str(root / "result")]
            with patch("sys.argv", arguments), patch("socket.create_connection", side_effect=OSError("offline")), \
                    patch("subprocess.run") as process, redirect_stdout(io.StringIO()):
                self.assertEqual(1, main())
            process.assert_not_called()
            report = json.loads((root / "result/report.json").read_text())
            self.assertEqual("unavailable", report["result"])
            self.assertEqual("offline", report["error"]["detail"])
            self.assertFalse(report["cleanup"])


if __name__ == "__main__":
    unittest.main()
