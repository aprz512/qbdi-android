"""One real-process fault corpus through every shared command boundary.

Only ADB transport is simulated. Each target creates a real setsid double-fork
orphan; host PID/starttime receipts identify the exact processes to verify.
"""

import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from qtrace.device import AdbDevice, TargetBinding
from qtrace.errors import QtraceError
from qtrace.process import BoundedRunner
from qtrace.injector import FridaInjector
from scripts import bounded_process
from scripts.qtrace_device_acceptance import SubprocessRunner
import scripts.tests.test_bounded_process as process_test_support
import scripts.tests.test_qtrace_injector as injector_test_support
from scripts.tests.test_bounded_process import (
    ProcessIdentityServer, _PUBLISH_IDENTITY_SOURCE,
)


_TARGET = r'''
import os, sys, time
''' + _PUBLISH_IDENTITY_SOURCE + r'''
mode, receipt = os.environ["QTRACE_MATRIX_FAULT"], os.environ["QTRACE_MATRIX_RECEIPT"]
publish_identity("root", receipt)
ready_read, ready_write = os.pipe()
child = os.fork()
if child == 0:
    os.close(ready_read)
    os.setsid()
    if os.fork() != 0:
        os._exit(0)
    publish_identity("orphan", receipt)
    os.write(ready_write, b"1")
    os.close(ready_write)
    null = os.open(os.devnull, os.O_RDWR)
    for descriptor in (0, 1, 2): os.dup2(null, descriptor)
    if null > 2: os.close(null)
    time.sleep(30)
    os._exit(0)
os.close(ready_write)
os.waitpid(child, 0)
assert os.read(ready_read, 1) == b"1"
os.close(ready_read)
if mode in ("timeout", "cancel", "pid-reuse"):
    time.sleep(30)
elif mode == "disconnect":
    os.write(1, b"partial")
    os.write(2, b"error: device offline\n")
    sys.exit(1)
elif mode == "output-limit":
    for _ in range(64): os.write(1, b"x" * 65536)
elif mode == "orphan":
    sys.exit(0)
else:
    raise AssertionError(mode)
'''


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open"),
                     "real namespace fault matrix requires Linux pidfds")
class ProcessFaultMatrixTests(unittest.TestCase):
    ENTRIES = ("bounded-capture", "qtrace-capture", "qtrace-stream", "adb-shell",
               "injector-force-stop", "acceptance")
    FAULTS = ("timeout", "cancel", "disconnect", "pid-reuse", "output-limit", "orphan")

    def _invoke(self, entry, output):
        command = ("adb", "-s", "SERIAL", "shell", "fault-probe")
        if entry == "bounded-capture":
            return bounded_process.capture_bounded(command, maximum_bytes=256, timeout=0.6)
        if entry == "qtrace-capture":
            return BoundedRunner().capture(command, maximum_bytes=256, timeout=0.6)
        if entry == "qtrace-stream":
            with output.open("xb") as stream:
                return BoundedRunner().stream(command, stream, maximum_bytes=256, timeout=0.6)
        if entry == "adb-shell":
            return AdbDevice("SERIAL", BoundedRunner()).shell(
                "fault-probe", maximum_bytes=256, timeout=0.6)
        if entry == "injector-force-stop":
            harness = injector_test_support.InjectorHarness()
            request = harness.request(setup_timeout=0.6)
            binding = TargetBinding(request.package, "run-as", "none", 20000,
                                    "run-as", 0, "/data/user/0/" + request.package)
            device = AdbDevice("SERIAL", BoundedRunner()).bind_target(binding)
            return FridaInjector(device, harness.provider).install(request)
        return SubprocessRunner("SERIAL").run(command, timeout=0.6)

    def test_fault_matrix_rejects_success_and_reaps_exact_target_identities(self):
        real_popen = subprocess.Popen
        real_identity = bounded_process._process_identity
        real_kill = os.kill
        for entry in self.ENTRIES:
            for fault in self.FAULTS:
                with self.subTest(entry=entry, fault=fault), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    adb = root / "adb"
                    adb.write_text(f"#!{sys.executable}\n" + _TARGET, encoding="utf-8")
                    adb.chmod(0o755)
                    identities = {}
                    wrappers = []
                    stop = threading.Event()
                    reused = threading.Event()
                    watcher_errors = []
                    previous_handler = signal.getsignal(signal.SIGUSR1)

                    def interrupt(_signal, _frame):
                        raise KeyboardInterrupt("fault matrix cancellation")

                    def popen(*args, **kwargs):
                        process = real_popen(*args, **kwargs)
                        wrappers.append((process, os.pidfd_open(process.pid)))
                        return process

                    def identity(pid):
                        observed = real_identity(pid)
                        if observed is not None and reused.is_set():
                            return observed[0], str(int(observed[1]) + 1)
                        return observed

                    with ProcessIdentityServer(root / "receipts.sock", {"root", "orphan"}) as receipts:
                        def cancel_when_started():
                            try:
                                if not receipts.complete.wait(2) or stop.is_set():
                                    return
                                if fault == "pid-reuse":
                                    reused.set()
                                real_kill(os.getpid(), signal.SIGUSR1)
                            except BaseException as error:
                                watcher_errors.append(error)

                        watcher = threading.Thread(target=cancel_when_started, daemon=True)
                        signal.signal(signal.SIGUSR1, interrupt)
                        try:
                            if fault in {"cancel", "pid-reuse"}:
                                watcher.start()
                            with patch.dict(os.environ, {
                                "PATH": str(root) + os.pathsep + os.environ.get("PATH", ""),
                                "QTRACE_MATRIX_FAULT": fault,
                                "QTRACE_MATRIX_RECEIPT": str(root / "receipts.sock"),
                            }), patch.object(bounded_process.subprocess, "Popen", side_effect=popen), \
                                    patch.object(bounded_process, "_process_identity", side_effect=identity), \
                                    patch.object(bounded_process.os, "kill", wraps=real_kill) as raw_kill, \
                                    patch.object(bounded_process, "_open_wrapper_pidfd", return_value=-1
                                                 if fault == "pid-reuse" else None) as open_pidfd:
                                # Keep the normal pidfd path for all other faults.
                                if fault != "pid-reuse":
                                    open_pidfd.side_effect = lambda pid: os.pidfd_open(pid)
                                started = time.monotonic()
                                expected = KeyboardInterrupt if fault in {"cancel", "pid-reuse"} else (
                                    bounded_process.BoundedProcessError, subprocess.TimeoutExpired, QtraceError, RuntimeError)
                                with self.assertRaises(expected) as caught:
                                    self._invoke(entry, root / "stream.bin")
                                self.assertLess(time.monotonic() - started, 1.5)
                                if fault == "pid-reuse":
                                    notes = " ".join(getattr(caught.exception, "__notes__", ()))
                                    self.assertIn("wrapper identity changed", notes)
                                    raw_kill.assert_not_called()
                                if fault == "disconnect":
                                    self.assertIn("device offline", str(caught.exception))
                                if fault == "output-limit":
                                    self.assertIn("size limit", str(caught.exception))
                                if fault in {"timeout", "orphan"}:
                                    if isinstance(caught.exception, QtraceError):
                                        self.assertEqual("process.timeout", caught.exception.code)
                                    elif entry == "bounded-capture":
                                        self.assertIsInstance(caught.exception, subprocess.TimeoutExpired)
                                    else:
                                        self.assertIn("timed out", str(caught.exception))
                            identities = receipts.wait()
                        finally:
                            stop.set()
                            if watcher.is_alive():
                                watcher.join(1)
                            signal.signal(signal.SIGUSR1, previous_handler)
                            # The mismatch case intentionally refuses normal teardown.
                            # Test holds the original pidfd before injecting that fault.
                            for process, pidfd in wrappers:
                                try:
                                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                                finally:
                                    os.close(pidfd)
                                process.wait(timeout=1)
                            identities = identities or dict(receipts.identities)
                            for pid, starttime in identities.values():
                                deadline = time.monotonic() + 1
                                while process_test_support.BoundedProcessTests._identity_is_alive(pid, starttime):
                                    if time.monotonic() >= deadline:
                                        self.fail(f"{entry}/{fault}: process {pid} starttime {starttime} survived")
                                    time.sleep(0.001)
                        self.assertFalse(watcher_errors)
                        self.assertEqual({"root", "orphan"}, identities.keys())
                        if (root / "stream.bin").exists():
                            self.assertLessEqual((root / "stream.bin").stat().st_size, 256)
