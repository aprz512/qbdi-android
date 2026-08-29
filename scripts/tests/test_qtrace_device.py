import math
import io
import os
import tempfile
import unittest
from dataclasses import FrozenInstanceError, dataclass
from pathlib import Path

from scripts.bounded_process import BoundedProcessError

from qtrace.device import AdbDevice, BoundTargetDevice, DeviceSelector, TargetBinding
from qtrace.errors import ErrorCode, QtraceError


def target_binding(**changes):
    values = {
        "package": "com.example.one",
        "access_mode": "root",
        "root_strategy": "su",
        "package_uid": 10905,
        "target_strategy": "run-as",
        "android_user": 0,
        "package_data_dir": "/data/user/0/com.example.one",
    }
    values.update(changes)
    return TargetBinding(**values)


PIXEL_BASE_APK = (
    "/data/app/~~9lCyyVYNZiRf1LlUj274Jg==/"
    "com.aprz.qbdiandroid-hCRBTRTLLT7gbWeO0joMXA==/base.apk"
)


@dataclass(frozen=True)
class Call:
    command: tuple[str, ...]
    maximum_bytes: int
    timeout: float
    pass_fds: tuple[int, ...] = ()


class FakeRunner:
    def __init__(self, outputs=None):
        self.outputs = dict(outputs or {})
        self.calls: list[Call] = []

    def capture(self, command, *, maximum_bytes, timeout, pass_fds=()):
        if isinstance(command, (str, bytes)):
            raise AssertionError("commands must be argument arrays")
        if not isinstance(maximum_bytes, int) or maximum_bytes <= 0:
            raise AssertionError("missing finite output bound")
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise AssertionError("missing finite timeout")
        call = Call(tuple(command), maximum_bytes, float(timeout), tuple(pass_fds))
        self.calls.append(call)
        result = self.outputs.get(call.command)
        if isinstance(result, BaseException):
            raise result
        if result is None:
            raise AssertionError(f"unexpected command: {call.command!r}")
        return result

    def stream(self, command, output, *, maximum_bytes, timeout):
        if maximum_bytes <= 0 or not math.isfinite(timeout) or timeout <= 0:
            raise AssertionError("missing stream bounds")
        call = Call(tuple(command), maximum_bytes, float(timeout))
        self.calls.append(call)
        result = self.outputs.get(call.command)
        if isinstance(result, BaseException):
            raise result
        if not isinstance(result, tuple) or any(not isinstance(chunk, bytes) for chunk in result):
            raise AssertionError(f"unexpected stream command: {call.command!r}")
        for chunk in result:
            output.write(chunk)


class DeviceSelectorTests(unittest.TestCase):
    def test_selects_unique_device_and_prefixes_every_command(self):
        runner = FakeRunner({("adb", "devices"): b"List of devices attached\nSERIAL\tdevice\n"})
        device = DeviceSelector(runner).select("SERIAL", timeout=2.5)

        self.assertEqual("SERIAL", device.serial)
        self.assertEqual(
            ["adb", "-s", "SERIAL", "shell", "id", "-u"],
            device.command("shell", "id", "-u"),
        )
        self.assertTrue(all(call.timeout > 0 and call.maximum_bytes > 0 for call in runner.calls))
        self.assertEqual(2.5, runner.calls[0].timeout)

    def test_requires_explicit_unique_online_selection(self):
        cases = (
            (b"List of devices attached\n", None),
            (b"List of devices attached\nA\tdevice\nB\tdevice\n", None),
            (b"List of devices attached\nA\toffline\n", "A"),
            (b"List of devices attached\nA\tunauthorized\n", "A"),
            (b"List of devices attached\nA\tdevice\n", "B"),
        )
        for output, requested in cases:
            with self.subTest(output=output, requested=requested):
                runner = FakeRunner({("adb", "devices"): output})
                with self.assertRaises(QtraceError) as caught:
                    DeviceSelector(runner).select(requested)
                self.assertEqual(ErrorCode.DEVICE_NOT_FOUND.value, caught.exception.code)

    def test_rejects_malformed_or_duplicate_device_rows(self):
        for output in (
            b"not the adb heading\nA\tdevice\n",
            b"List of devices attached\nmalformed\n",
            b"List of devices attached\nA\tdevice\nA\tdevice\n",
            b"List of devices attached\nA\tunknown-state\n",
            b"\xff",
        ):
            with self.subTest(output=output):
                with self.assertRaisesRegex(QtraceError, "device.output_malformed"):
                    DeviceSelector(FakeRunner({("adb", "devices"): output})).select(None)

    def test_maps_runner_failure_to_adb_unavailable(self):
        for error in (
            OSError("adb absent\nraw"),
            BoundedProcessError("adb failed", returncode=7, stderr=b"offline"),
        ):
            with self.subTest(error=error):
                runner = FakeRunner({("adb", "devices"): error})
                with self.assertRaises(QtraceError) as caught:
                    DeviceSelector(runner).select(None)
                self.assertEqual(ErrorCode.ADB_UNAVAILABLE.value, caught.exception.code)
                self.assertNotIn("\n", str(caught.exception))


class AdbDeviceTests(unittest.TestCase):
    def test_bind_target_returns_a_new_bound_device_without_mutating_selected_device(self):
        selected = AdbDevice("SERIAL", FakeRunner())

        bound = selected.bind_target(target_binding())

        self.assertIsInstance(bound, BoundTargetDevice)
        self.assertIsNot(selected, bound)
        self.assertIs(selected.runner, bound.runner)
        self.assertFalse(hasattr(selected, "package"))
        self.assertFalse(hasattr(selected, "target_shell"))
        self.assertEqual("com.example.one", bound.package)
        self.assertEqual("root", bound.access_mode)
        self.assertEqual("su", bound.root_strategy)
        self.assertEqual(10905, bound.package_uid)
        self.assertEqual("run-as", bound.target_strategy)
        self.assertEqual(0, bound.android_user)
        self.assertEqual("/data/user/0/com.example.one", bound.package_data_dir)
        self.assertEqual(
            "/data/user/0/com.example.one/files/qbdi-traces",
            bound.trace_directory,
        )
        with self.assertRaises(FrozenInstanceError):
            bound.binding.package = "com.example.other"

    def test_target_binding_rejects_inconsistent_identity_fields_with_stable_codes(self):
        cases = (
            ({"access_mode": "invalid"}, "device.access_mode_invalid"),
            ({"root_strategy": "invalid"}, "device.root_strategy_invalid"),
            ({"target_strategy": "invalid"}, "device.target_strategy_invalid"),
            ({"access_mode": "run-as"}, "device.binding_invalid"),
            ({"root_strategy": "none"}, "device.binding_invalid"),
            ({"target_strategy": "su-uid", "access_mode": "run-as", "root_strategy": "none"},
             "device.binding_invalid"),
            ({"android_user": 1}, "device.data_dir_invalid"),
            ({"package_uid": 10000, "android_user": 1,
              "package_data_dir": "/data/user/1/com.example.one"},
             "device.uid_user_mismatch"),
        )
        for changes, code in cases:
            with self.subTest(changes=changes), self.assertRaises(QtraceError) as caught:
                target_binding(**changes)
            self.assertEqual(code, caught.exception.code)

    def test_secondary_user_run_as_places_the_package_before_the_user_option(self):
        path = "/data/user/10/com.example.app/files/qbdi-traces/run.trace.bin"
        shell_command = (
            "adb", "-s", "SERIAL", "shell", "run-as", "com.example.app",
            "--user", "10", "id", "-u",
        )
        stream_command = (
            "adb", "-s", "SERIAL", "exec-out", "run-as", "com.example.app",
            "--user", "10", "cat", path,
        )
        runner = FakeRunner({shell_command: b"1010905\n", stream_command: (b"trace",)})
        selected = AdbDevice("SERIAL", runner)
        device = selected.bind_target(TargetBinding(
            package="com.example.app", access_mode="run-as", root_strategy="none", package_uid=1_010_905,
            target_strategy="run-as", android_user=10,
            package_data_dir="/data/user/10/com.example.app",
        ))

        self.assertEqual(b"1010905\n", device.target_shell("id", "-u"))
        output = io.BytesIO()
        device.stream_target_file(path, output, maximum_bytes=512, timeout=1.5)

        self.assertEqual(b"trace", output.getvalue())
        self.assertEqual(
            [Call(shell_command, 1_048_576, 30.0), Call(stream_command, 512, 1.5)],
            runner.calls,
        )

    def test_push_open_file_uses_its_own_proc_fd_and_preserves_caller_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "held.so"
            source.write_bytes(b"held")
            descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
            destination = "/data/local/tmp/qtrace/held.so"
            command = (
                "adb", "-s", "SERIAL", "push",
                f"/proc/self/fd/{descriptor}", destination,
            )
            runner = FakeRunner({command: b"ok\n"})
            try:
                AdbDevice("SERIAL", runner).push_open_file(
                    descriptor, destination, timeout=1.5,
                )

                self.assertEqual(
                    [Call(command, 256 * 1024, 1.5, (descriptor,))], runner.calls,
                )
                self.assertEqual(source.stat().st_ino, os.fstat(descriptor).st_ino)
            finally:
                os.close(descriptor)

    def test_bound_target_stream_uses_one_direct_bounded_runner_contract(self):
        path = "/data/user/0/com.example.app/files/qbdi-traces/run.trace.bin"
        command = (
            "adb", "-s", "SERIAL", "exec-out", "run-as",
            "com.example.app", "cat", path,
        )
        runner = FakeRunner({command: (b"first", b"second")})
        selected = AdbDevice("SERIAL", runner)
        device = selected.bind_target(TargetBinding(
            package="com.example.app", access_mode="run-as", root_strategy="none", package_uid=10_905,
            target_strategy="run-as", android_user=0,
            package_data_dir="/data/user/0/com.example.app",
        ))
        output = io.BytesIO()

        device.stream_target_file(path, output, maximum_bytes=512, timeout=1.5)

        self.assertEqual(b"firstsecond", output.getvalue())
        self.assertEqual([Call(command, 512, 1.5)], runner.calls)
    def test_accepts_literal_tildes_in_normalized_absolute_pixel_apk_path(self):
        command = (
            "adb", "-s", "SERIAL", "shell", "pm", "path", "com.aprz.qbdiandroid"
        )
        device = AdbDevice(
            "SERIAL", FakeRunner({command: f"package:{PIXEL_BASE_APK}\n".encode()})
        )

        self.assertEqual((PIXEL_BASE_APK,), device.package_apk_paths("com.aprz.qbdiandroid"))
        with self.assertRaises(QtraceError):
            device.shell("echo", "~")

    def test_package_paths_pid_install_push_and_read_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "external.apk"
            source = Path(directory) / "libqbdi_tracer.so"
            apk.write_bytes(b"apk")
            source.write_bytes(b"so")
            prefix = ("adb", "-s", "SERIAL")
            runner = FakeRunner({
                prefix + ("shell", "pm", "path", "com.example.app"):
                    b"package:/data/app/com.example/base.apk\npackage:/data/app/com.example/split.apk\n",
                prefix + ("shell", "pidof", "com.example.app"): b"1234\n",
                prefix + ("install", "-r", str(apk)): b"Success\n",
                prefix + ("push", str(source), "/data/local/tmp/qtrace/id/lib.so"): b"ok\n",
                prefix + ("shell", "cat", "/data/local/tmp/qtrace/id/status.json"): b"{}",
            })
            device = AdbDevice("SERIAL", runner)

            self.assertEqual(
                ("/data/app/com.example/base.apk", "/data/app/com.example/split.apk"),
                device.package_apk_paths("com.example.app"),
            )
            self.assertEqual(1234, device.pid("com.example.app"))
            device.install(apk)
            device.push(source, "/data/local/tmp/qtrace/id/lib.so")
            self.assertEqual(
                b"{}", device.read_file("/data/local/tmp/qtrace/id/status.json", 1024)
            )
            self.assertTrue(all(call.maximum_bytes > 0 and call.timeout > 0 for call in runner.calls))

    def test_install_accepts_the_standard_streaming_preamble(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "external.apk"
            apk.write_bytes(b"apk")
            command = ("adb", "-s", "SERIAL", "install", "-r", str(apk))
            AdbDevice(
                "SERIAL",
                FakeRunner({command: b"Performing Streamed Install\nSuccess\n"}),
            ).install(apk)

    def test_pull_member_uses_bounded_exec_out_and_writes_only_the_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "extracted" / "libtarget.so"
            prefix = ("adb", "-s", "SERIAL")
            runner = FakeRunner({
                prefix + (
                    "exec-out",
                    "unzip",
                    "-p",
                    "/data/app/com.example/base.apk",
                    "lib/arm64-v8a/libtarget.so",
                ): b"ELF bytes",
            })

            result = AdbDevice("SERIAL", runner).pull_member(
                "/data/app/com.example/base.apk",
                "lib/arm64-v8a/libtarget.so",
                destination,
            )

            self.assertEqual(destination, result)
            self.assertEqual(b"ELF bytes", destination.read_bytes())
            self.assertEqual(512 * 1024 * 1024, runner.calls[0].maximum_bytes)

    def test_empty_unzip_output_signals_missing_member_without_publishing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "libtarget.so"
            command = (
                "adb", "-s", "SERIAL", "exec-out", "unzip", "-p",
                PIXEL_BASE_APK, "lib/arm64-v8a/libtarget.so",
            )
            device = AdbDevice("SERIAL", FakeRunner({command: b""}))

            with self.assertRaises(FileNotFoundError):
                device.pull_member(
                    PIXEL_BASE_APK,
                    "lib/arm64-v8a/libtarget.so",
                    destination,
                )
            self.assertFalse(destination.exists())

    def test_package_query_transport_failure_is_not_package_absence(self):
        command = (
            "adb", "-s", "SERIAL", "shell", "pm", "path", "com.example.app"
        )
        transport = QtraceError("process.timeout", "process", "adb transport timed out")
        with self.assertRaises(QtraceError) as caught:
            AdbDevice("SERIAL", FakeRunner({command: transport})).package_apk_paths(
                "com.example.app"
            )
        self.assertIs(transport, caught.exception)

    def test_device_identity_is_exported_by_the_device_boundary(self):
        from qtrace.device import DeviceIdentity

        identity = DeviceIdentity(
            "SERIAL", "arm64-v8a", 34, "root", "16.3.3", "16.3.3", 1, 0,
            "/data/user/0/com.example.app",
        )
        self.assertEqual("SERIAL", identity.serial)

    def test_pidof_no_match_is_none_and_malformed_output_is_stable_error(self):
        prefix = ("adb", "-s", "SERIAL", "shell", "pidof", "com.example.app")
        def pidof_no_match():
            try:
                raise QtraceError(
                    "process.failed", "process", "subprocess failed (1)"
                ) from BoundedProcessError(
                    "subprocess failed (1)", returncode=1, stderr=b""
                )
            except QtraceError as error:
                return error

        no_match = pidof_no_match()
        self.assertIsNone(AdbDevice("SERIAL", FakeRunner({prefix: no_match})).pid("com.example.app"))

        for output in (b"0\n", b"12 13\n", b"pid\n", b"\xff"):
            with self.subTest(output=output), self.assertRaisesRegex(
                QtraceError, "device.pid_malformed"
            ):
                AdbDevice("SERIAL", FakeRunner({prefix: output})).pid("com.example.app")

    def test_pidof_transport_failure_is_not_misreported_as_no_match(self):
        prefix = ("adb", "-s", "SERIAL", "shell", "pidof", "com.example.app")
        transport = QtraceError("process.failed", "process", "subprocess failed (1)")
        with self.assertRaises(QtraceError) as caught:
            AdbDevice("SERIAL", FakeRunner({prefix: transport})).pid("com.example.app")
        self.assertIs(transport, caught.exception)

    def test_rejects_unsafe_serial_package_shell_tokens_and_remote_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.so"
            source.write_bytes(b"so")
            for serial in ("", "SERIAL;reboot", "../serial", "bad serial"):
                with self.subTest(serial=serial), self.assertRaises(QtraceError):
                    AdbDevice(serial, FakeRunner())
            device = AdbDevice("SERIAL", FakeRunner())
            for package in ("com.example.app;id", "../app", "one", ""):
                with self.subTest(package=package), self.assertRaises(QtraceError):
                    device.package_apk_paths(package)
            for token in ("hello world", "$(id)", "a;id", "a'b"):
                with self.subTest(token=token), self.assertRaises(QtraceError):
                    device.shell("echo", token)
                with self.subTest(command_token=token), self.assertRaises(QtraceError):
                    device.command("shell", "echo", token)
            for path in ("relative/path", "/data/local/tmp/../escape", "/data/local/tmp/a b"):
                with self.subTest(path=path), self.assertRaises(QtraceError):
                    device.push(source, path)

    def test_root_and_target_shells_use_the_bound_validated_identity_strategy(self):
        prefix = ("adb", "-s", "SERIAL", "shell")
        runner = FakeRunner({
            prefix + ("su", "-c", "'id -u'"): b"0\n",
            prefix + ("su", "-c", "'mkdir -p /data/local/tmp/qtrace'"): b"",
            prefix + ("run-as", "com.example.one", "id", "-u"): b"10905\n",
            prefix + ("su", "10905", "-c", "'id -u'"): b"10905\n",
        })
        device = AdbDevice("SERIAL", runner)

        self.assertEqual(b"0\n", device.su_shell("id", "-u"))
        device = device.bind_target(TargetBinding(
            package="com.example.one", access_mode="root",
            root_strategy="su", package_uid=10905, target_strategy="run-as",
            android_user=0, package_data_dir="/data/user/0/com.example.one",
        ))
        device.root_shell("mkdir", "-p", "/data/local/tmp/qtrace")
        self.assertEqual(b"10905\n", device.target_shell("id", "-u"))

        uid_device = AdbDevice("SERIAL", runner)
        uid_device = uid_device.bind_target(TargetBinding(
            package="com.example.one", access_mode="root",
            root_strategy="su", package_uid=10905, target_strategy="su-uid",
            android_user=0, package_data_dir="/data/user/0/com.example.one",
        ))
        self.assertEqual(b"10905\n", uid_device.target_shell("id", "-u"))

        with self.assertRaises(QtraceError):
            device.su_shell("echo", "unsafe;id")


if __name__ == "__main__":
    unittest.main()
