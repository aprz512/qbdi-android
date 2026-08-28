import math
import io
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from scripts.bounded_process import BoundedProcessError

from qtrace.device import AdbDevice, DeviceSelector
from qtrace.errors import ErrorCode, QtraceError


PIXEL_BASE_APK = (
    "/data/app/~~9lCyyVYNZiRf1LlUj274Jg==/"
    "com.aprz.qbdiandroid-hCRBTRTLLT7gbWeO0joMXA==/base.apk"
)


@dataclass(frozen=True)
class Call:
    command: tuple[str, ...]
    maximum_bytes: int
    timeout: float


class FakeRunner:
    def __init__(self, outputs=None):
        self.outputs = dict(outputs or {})
        self.calls: list[Call] = []

    def capture(self, command, *, maximum_bytes, timeout):
        if isinstance(command, (str, bytes)):
            raise AssertionError("commands must be argument arrays")
        if not isinstance(maximum_bytes, int) or maximum_bytes <= 0:
            raise AssertionError("missing finite output bound")
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise AssertionError("missing finite timeout")
        call = Call(tuple(command), maximum_bytes, float(timeout))
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
    def test_bound_target_stream_uses_one_direct_bounded_runner_contract(self):
        path = "/data/user/0/com.example.app/files/qbdi-traces/run.trace.bin"
        command = (
            "adb", "-s", "SERIAL", "exec-out", "run-as",
            "com.example.app", "cat", path,
        )
        runner = FakeRunner({command: (b"first", b"second")})
        device = AdbDevice("SERIAL", runner)
        device.bind_package(
            "com.example.app", "run-as", root_strategy="none", package_uid=10_905,
            target_strategy="run-as", android_user=0,
            package_data_dir="/data/user/0/com.example.app",
        )
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

    def test_validated_package_binding_is_idempotent_but_cannot_be_retargeted(self):
        device = AdbDevice("SERIAL", FakeRunner())
        binding = {
            "root_strategy": "su",
            "package_uid": 10905,
            "target_strategy": "run-as",
            "android_user": 0,
            "package_data_dir": "/data/user/0/com.example.one",
        }
        device.bind_package("com.example.one", "root", **binding)
        device.bind_package("com.example.one", "root", **binding)

        for package, access_mode, overrides in (
            ("com.example.two", "root", {}),
            ("com.example.one", "run-as", {"root_strategy": "none"}),
            ("com.example.one", "root", {"package_uid": 10906}),
            ("com.example.one", "root", {"target_strategy": "su-uid"}),
        ):
            candidate = dict(binding)
            candidate["package_data_dir"] = f"/data/user/0/{package}"
            candidate.update(overrides)
            with self.subTest(package=package, access_mode=access_mode), self.assertRaisesRegex(
                QtraceError, "device.binding_conflict"
            ):
                device.bind_package(package, access_mode, **candidate)
        self.assertEqual("com.example.one", device.package)
        self.assertEqual("root", device.access_mode)
        self.assertEqual("su", device.root_strategy)
        self.assertEqual(10905, device.package_uid)
        self.assertEqual("run-as", device.target_strategy)

        fresh = AdbDevice("SERIAL", FakeRunner())
        for user, uid, directory in (
            (1, 10905, "/data/user/1/com.example.one"),
            (0, 10905, "/data/user/1/com.example.one"),
        ):
            with self.subTest(user=user, uid=uid, directory=directory), self.assertRaises(
                QtraceError
            ):
                fresh.bind_package(
                    "com.example.one", "root", root_strategy="su", package_uid=uid,
                    target_strategy="run-as", android_user=user,
                    package_data_dir=directory,
                )

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
        device.bind_package(
            "com.example.one", "root",
            root_strategy="su", package_uid=10905, target_strategy="run-as",
            android_user=0, package_data_dir="/data/user/0/com.example.one",
        )
        device.root_shell("mkdir", "-p", "/data/local/tmp/qtrace")
        self.assertEqual(b"10905\n", device.target_shell("id", "-u"))

        uid_device = AdbDevice("SERIAL", runner)
        uid_device.bind_package(
            "com.example.one", "root",
            root_strategy="su", package_uid=10905, target_strategy="su-uid",
            android_user=0, package_data_dir="/data/user/0/com.example.one",
        )
        self.assertEqual(b"10905\n", uid_device.target_shell("id", "-u"))

        with self.assertRaises(QtraceError):
            device.su_shell("echo", "unsafe;id")


if __name__ == "__main__":
    unittest.main()
