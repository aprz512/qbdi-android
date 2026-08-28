import math
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qtrace.errors import ErrorCode, QtraceError
from qtrace.models import AppConfig, TargetConfig, TracerConfig, UserConfig
from qtrace.preflight import Preflight


def config(*, apk=None, compression=True, package="com.example.external"):
    return UserConfig(
        schema_version=1,
        app=AppConfig(package=package, apk=apk),
        target=TargetConfig(module="libtarget.so", binary=None),
        tracer=TracerConfig(
            profile="fast",
            compression=compression,
            flight_enabled=False,
            flight_entry_scene=None,
            library=None,
            companion=None,
        ),
        scenes=(),
    )


class FakeSelector:
    def __init__(self, device):
        self.device = device
        self.requests = []

    def select(self, requested, *, timeout=10.0):
        self.requests.append((requested, timeout))
        return self.device


class FakeDevice:
    serial = "SERIAL"

    def __init__(
        self,
        *,
        abi=b"arm64-v8a\n",
        api=b"34\n",
        root=b"0\n",
        su_root=None,
        run_as=b"20000\n",
        stat_uid=b"20000\n",
        su_uid=b"20000\n",
        df=b"Filesystem 1024-blocks Used Available Capacity Mounted on\n/data 1000000 1 999999 1% /data\n",
        package_paths=("/data/app/base.apk",),
        android_user=b"0\n",
    ):
        self.abi = abi
        self.api = api
        self.root = root
        self.su_root = su_root
        self.run_as = run_as
        self.stat_uid = stat_uid
        self.su_uid = su_uid
        self.df = df
        self.package_paths = package_paths
        self.android_user = android_user
        self.events = []
        self.shell_calls = []

    def install(self, apk, *, timeout=30.0):
        self.events.append(("install", Path(apk), timeout))

    def package_apk_paths(self, package, *, timeout=30.0):
        self.events.append(("package", package, timeout))
        if not self.package_paths:
            raise QtraceError(ErrorCode.PACKAGE_NOT_INSTALLED, "preflight.package", "missing")
        return self.package_paths

    def shell(self, *args, timeout=30.0, maximum_bytes=1_048_576):
        if not math.isfinite(timeout) or timeout <= 0 or maximum_bytes <= 0:
            raise AssertionError("unbounded shell call")
        self.shell_calls.append((args, timeout, maximum_bytes))
        command = tuple(args)
        if command == ("getprop", "ro.product.cpu.abi"):
            result = self.abi
            if isinstance(result, BaseException):
                raise result
            return result
        if command == ("getprop", "ro.build.version.sdk"):
            result = self.api
            if isinstance(result, BaseException):
                raise result
            return result
        if command == ("id", "-u"):
            result = self.root
            if isinstance(result, BaseException):
                raise result
            return result
        if command == ("cmd", "activity", "get-current-user"):
            result = self.android_user
            if isinstance(result, BaseException):
                raise result
            return result
        if len(command) == 4 and command[:3] == ("run-as", "com.example.external", "id"):
            result = self.run_as
            if isinstance(result, BaseException):
                raise result
            return result
        if (len(command) == 6
                and command == ("run-as", "com.example.external", "--user", "10",
                                "id", "-u")):
            result = self.run_as
            if isinstance(result, BaseException):
                raise result
            return result
        if command == ("df", "-Pk", "/data/local/tmp"):
            return self.df
        raise AssertionError(f"unexpected shell command: {command!r}")

    def su_shell(self, *args, timeout=30.0, maximum_bytes=1_048_576):
        self.shell_calls.append((("su", *args), timeout, maximum_bytes))
        if args == ("id", "-u"):
            if self.su_root is None:
                raise QtraceError("device.command_failed", "device.shell", "su unavailable")
            if isinstance(self.su_root, BaseException):
                raise self.su_root
            return self.su_root
        if args == ("stat", "-c", "%u", "/data/user/0/com.example.external"):
            if isinstance(self.stat_uid, BaseException):
                raise self.stat_uid
            return self.stat_uid
        raise AssertionError(f"unexpected su command: {args!r}")

    def su_uid_shell(self, uid, *args, timeout=30.0, maximum_bytes=1_048_576):
        self.shell_calls.append((("su-uid", str(uid), *args), timeout, maximum_bytes))
        if args != ("id", "-u"):
            raise AssertionError(f"unexpected uid command: {args!r}")
        if isinstance(self.su_uid, BaseException):
            raise self.su_uid
        return self.su_uid

    def bind_package(
        self,
        package,
        access_mode,
        *,
        root_strategy,
        package_uid,
        target_strategy,
        android_user,
        package_data_dir,
    ):
        self.events.append((
            "bind", package, access_mode, root_strategy, package_uid, target_strategy,
            android_user, package_data_dir,
        ))


class FakeFridaProbe:
    def __init__(self, versions=("16.3.3", "16.3.3"), error=None):
        self.result = versions
        self.error = error
        self.calls = []

    def versions(self, device, timeout):
        self.calls.append((device, timeout))
        if self.error is not None:
            raise self.error
        return self.result


class PreflightTests(unittest.TestCase):
    def run_preflight(self, device, *, user_config=None, frida=None):
        frida = frida or FakeFridaProbe()
        with patch.object(shutil, "which", return_value="/usr/bin/lz4"):
            result = Preflight(FakeSelector(device), frida).run(
                user_config or config(), "SERIAL", setup_timeout=9.0, adb_timeout=2.0
            )
        return result, frida

    def test_manual_package_binder_reuses_bound_target_identity_without_session_prerequisites(self):
        from qtrace.preflight import bind_package_access

        device = FakeDevice()
        self.assertEqual(
            "root",
            bind_package_access(
                device, "com.example.external", timeout=2.0,
            ),
        )

        self.assertEqual(("package", "com.example.external"), device.events[0][:2])
        self.assertTrue(0 < device.events[0][2] <= 2.0)
        self.assertEqual(
            ("bind", "com.example.external", "root", "direct", 20000, "run-as", 0,
             "/data/user/0/com.example.external"),
            device.events[-1],
        )
        self.assertFalse(any(event[0] == "install" for event in device.events))
        self.assertFalse(any(call[0][:1] == ("getprop",) or call[0][:1] == ("df",)
                             for call in device.shell_calls))

    def test_installs_existing_apk_before_package_checks_and_records_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "external.apk"
            apk.write_bytes(b"apk")
            device = FakeDevice()
            (selected, identity), frida = self.run_preflight(
                device,
                user_config=config(apk=apk),
                frida=FakeFridaProbe((" 16.3.3+host ", "16.3.3-android.1")),
            )

        self.assertIs(device, selected)
        self.assertLess(
            next(i for i, event in enumerate(device.events) if event[0] == "install"),
            next(i for i, event in enumerate(device.events) if event[0] == "package"),
        )
        self.assertEqual("arm64-v8a", identity.abi)
        self.assertEqual(34, identity.api_level)
        self.assertEqual("root", identity.access_mode)
        self.assertEqual("16.3.3", identity.frida_host_version)
        self.assertEqual("16.3.3", identity.frida_server_version)
        self.assertEqual(999_999 * 1024, identity.free_bytes)
        self.assertEqual(1, len(frida.calls))
        self.assertTrue(0 < frida.calls[0][1] <= 9.0)
        self.assertTrue(all(call[1] <= 2.0 for call in device.shell_calls))
        self.assertIn(
            ("bind", "com.example.external", "root", "direct", 20000, "run-as", 0,
             "/data/user/0/com.example.external"),
            device.events,
        )

    def test_binds_current_secondary_user_and_rejects_uid_user_mismatch(self):
        device = FakeDevice(android_user=b"10\n", run_as=b"1020000\n")
        (_selected, identity), _frida = self.run_preflight(device)
        self.assertEqual(10, identity.android_user)
        self.assertEqual("/data/user/10/com.example.external", identity.package_data_dir)
        self.assertIn(
            ("bind", "com.example.external", "root", "direct", 1020000, "run-as", 10,
             "/data/user/10/com.example.external"),
            device.events,
        )

        mismatch = FakeDevice(android_user=b"10\n", run_as=b"20000\n")
        with self.assertRaisesRegex(QtraceError, "Android user"):
            self.run_preflight(mismatch)

    def test_uses_run_as_when_root_is_unavailable(self):
        device = FakeDevice(root=QtraceError("device.command_failed", "device.shell", "not root"))
        (_selected, identity), _frida = self.run_preflight(device)
        self.assertEqual("run-as", identity.access_mode)
        self.assertIn(
            ("bind", "com.example.external", "run-as", "none", 20000, "run-as", 0,
             "/data/user/0/com.example.external"),
            device.events,
        )

    def test_accepts_magisk_su_root_and_keeps_run_as_target_identity(self):
        device = FakeDevice(root=b"2000\n", su_root=b"0\n", run_as=b"10905\n")

        (_selected, identity), _frida = self.run_preflight(device)

        self.assertEqual("root", identity.access_mode)
        self.assertIn(
            ("bind", "com.example.external", "root", "su", 10905, "run-as", 0,
             "/data/user/0/com.example.external"),
            device.events,
        )

    def test_root_without_run_as_resolves_uid_and_proves_su_uid_target(self):
        no_run_as = QtraceError("device.command_failed", "device.shell", "not debuggable")
        device = FakeDevice(
            root=b"2000\n",
            su_root=b"0\n",
            run_as=no_run_as,
            stat_uid=b"10905\n",
            su_uid=b"10905\n",
        )

        (_selected, identity), _frida = self.run_preflight(device)

        self.assertEqual("root", identity.access_mode)
        self.assertIn(
            ("bind", "com.example.external", "root", "su", 10905, "su-uid", 0,
             "/data/user/0/com.example.external"),
            device.events,
        )

    def test_rejects_missing_package_without_apk(self):
        device = FakeDevice(package_paths=())
        with patch.object(shutil, "which", return_value="/usr/bin/lz4"), self.assertRaises(
            QtraceError
        ) as caught:
            Preflight(FakeSelector(device), FakeFridaProbe()).run(
                config(), None, setup_timeout=9, adb_timeout=2
            )
        self.assertEqual(ErrorCode.PACKAGE_NOT_INSTALLED.value, caught.exception.code)
        self.assertFalse(any(event[0] == "install" for event in device.events))

    def test_rejects_unsupported_abi_api_access_and_space(self):
        cases = (
            (FakeDevice(abi=b"armeabi-v7a\n"), ErrorCode.UNSUPPORTED_ABI.value),
            (FakeDevice(api=b"23\n"), "device.api_unsupported"),
            (
                FakeDevice(
                    root=QtraceError("x", "x", "no root"),
                    run_as=QtraceError("x", "x", "no run-as"),
                ),
                "device.access_denied",
            ),
            (
                FakeDevice(df=b"Filesystem 1024-blocks Used Available Capacity Mounted on\n/data 4 3 1 75% /data\n"),
                "device.space_insufficient",
            ),
        )
        for device, code in cases:
            with self.subTest(code=code), patch.object(
                shutil, "which", return_value="/usr/bin/lz4"
            ), self.assertRaises(QtraceError) as caught:
                Preflight(FakeSelector(device), FakeFridaProbe()).run(
                    config(), None, setup_timeout=9, adb_timeout=2
                )
            self.assertEqual(code, caught.exception.code)

    def test_requires_host_lz4_only_when_compression_is_enabled(self):
        with patch.object(shutil, "which", return_value=None), self.assertRaisesRegex(
            QtraceError, "host.lz4_missing"
        ):
            Preflight(FakeSelector(FakeDevice()), FakeFridaProbe()).run(
                config(compression=True), None, setup_timeout=9, adb_timeout=2
            )
        with patch.object(shutil, "which", return_value=None):
            Preflight(FakeSelector(FakeDevice()), FakeFridaProbe()).run(
                config(compression=False), None, setup_timeout=9, adb_timeout=2
            )

    def test_rejects_frida_core_mismatch_malformed_versions_and_probe_failures(self):
        cases = (
            (FakeFridaProbe(("16.3.3", "16.3.4")), ErrorCode.FRIDA_VERSION_MISMATCH.value),
            (FakeFridaProbe(("16.3", "16.3.3")), "frida.version_invalid"),
            (FakeFridaProbe(("v16.3.3", "16.3.3")), "frida.version_invalid"),
            (FakeFridaProbe(error=RuntimeError("handshake\nfailed")), "frida.handshake_failed"),
        )
        for frida, code in cases:
            device = FakeDevice()
            with self.subTest(code=code), patch.object(
                shutil, "which", return_value="/usr/bin/lz4"
            ), self.assertRaises(QtraceError) as caught:
                Preflight(FakeSelector(device), frida).run(
                    config(), None, setup_timeout=9, adb_timeout=2
                )
            self.assertEqual(code, caught.exception.code)
            self.assertNotIn("\n", str(caught.exception))
            self.assertFalse(any(event[0] == "bind" for event in device.events))

    def test_rejects_nonfinite_time_budgets_before_side_effects(self):
        selector = FakeSelector(FakeDevice())
        for setup_timeout, adb_timeout in ((0, 1), (1, 0), (math.inf, 1), (1, math.nan)):
            with self.subTest(setup_timeout=setup_timeout, adb_timeout=adb_timeout), self.assertRaises(
                QtraceError
            ):
                Preflight(selector, FakeFridaProbe()).run(
                    config(), None, setup_timeout=setup_timeout, adb_timeout=adb_timeout
                )
        self.assertEqual([], selector.requests)

    def test_maps_raw_selector_failure_to_a_stable_error(self):
        class FailingSelector:
            def select(self, _requested, *, timeout):
                raise OSError(f"adb failed after {timeout}\nraw")

        with self.assertRaises(QtraceError) as caught:
            Preflight(FailingSelector(), FakeFridaProbe()).run(
                config(), None, setup_timeout=9, adb_timeout=2
            )
        self.assertEqual(ErrorCode.ADB_UNAVAILABLE.value, caught.exception.code)
        self.assertNotIn("\n", str(caught.exception))

    def test_setup_timeout_is_not_masked_as_access_denied(self):
        timeout = QtraceError("preflight.timeout", "preflight", "budget exhausted")
        device = FakeDevice(root=timeout)
        with patch.object(shutil, "which", return_value="/usr/bin/lz4"), self.assertRaises(
            QtraceError
        ) as caught:
            Preflight(FakeSelector(device), FakeFridaProbe()).run(
                config(), None, setup_timeout=9, adb_timeout=2
            )
        self.assertIs(timeout, caught.exception)
        self.assertFalse(any(call[0][:2] == ("run-as", "com.example.external") for call in device.shell_calls))


if __name__ == "__main__":
    unittest.main()
