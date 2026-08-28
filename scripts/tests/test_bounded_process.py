import errno
import os
import signal
import socket
import subprocess
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.bounded_process as bounded_process
from scripts.bounded_process import BoundedProcessError, capture_bounded


_PUBLISH_IDENTITY_SOURCE = (
    "def publish_identity(label, path):\n"
    " import socket\n"
    " peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
    " peer.connect(path)\n"
    " peer.sendall((label + '\\n').encode('ascii'))\n"
    " if peer.recv(1) != b'1': raise RuntimeError('identity receipt failed')\n"
    " peer.close()\n"
)

_IDENTITY_CONTAINMENT_TIMEOUT = 2.0
_IDENTITY_CONTAINMENT_WALL_LIMIT = 3.0


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


class ProcessIdentityServer:
    def __init__(self, path: Path, labels: set[str]):
        self.path = path
        self.labels = labels
        self.identities: dict[str, tuple[int, str]] = {}
        self.errors: list[BaseException] = []
        self.complete = threading.Event()
        self.stopping = threading.Event()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        self.listener.listen(len(labels))
        self.listener.settimeout(0.05)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    @staticmethod
    def _identity(pid: int) -> tuple[int, str]:
        payload = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        return pid, payload[payload.rfind(")") + 2:].split()[19]

    def _serve(self) -> None:
        try:
            while self.identities.keys() != self.labels and not self.stopping.is_set():
                try:
                    connection, _address = self.listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    credentials = connection.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                    )
                    pid, _uid, _gid = struct.unpack("3i", credentials)
                    payload = bytearray()
                    while b"\n" not in payload:
                        chunk = connection.recv(65 - len(payload))
                        if not chunk or len(payload) + len(chunk) >= 65:
                            raise AssertionError("invalid process identity label")
                        payload.extend(chunk)
                    label = payload[:-1].decode("ascii")
                    if label not in self.labels or label in self.identities:
                        raise AssertionError(f"unexpected process identity label {label!r}")
                    self.identities[label] = self._identity(pid)
                    connection.sendall(b"1")
        except BaseException as error:
            if not self.stopping.is_set():
                self.errors.append(error)
        finally:
            self.complete.set()

    def wait(self, timeout: float = 2) -> dict[str, tuple[int, str]]:
        if not self.complete.wait(timeout):
            raise AssertionError("target process identities were not published")
        if self.errors:
            raise self.errors[0]
        if self.identities.keys() != self.labels:
            raise AssertionError(
                f"missing target process identities: {self.labels - self.identities.keys()}"
            )
        return self.identities

    def close(self) -> None:
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=1)

    def __enter__(self):
        return self

    def __exit__(self, _error_type, _error, _traceback):
        self.close()


class BoundedProcessTests(unittest.TestCase):
    @staticmethod
    def _read_process_identity(path: Path) -> tuple[int, str]:
        pid_text, starttime = path.read_text(encoding="utf-8").split()
        return int(pid_text), starttime

    @staticmethod
    def _identity_is_alive(pid: int, starttime: str) -> bool:
        try:
            payload = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        except (FileNotFoundError, ProcessLookupError):
            return False
        fields = payload[payload.rfind(")") + 2:].split()
        return fields[0] != "Z" and fields[19] == starttime

    def _wait_identity_dead(self, identity: tuple[int, str]) -> None:
        deadline = time.monotonic() + 1
        while self._identity_is_alive(*identity):
            if time.monotonic() >= deadline:
                self.fail(f"process {identity[0]} starttime {identity[1]} survived")
            time.sleep(0.001)

    def _kill_test_identity(self, pid: int, starttime: str) -> None:
        try:
            pidfd = os.pidfd_open(pid)
        except ProcessLookupError:
            return
        try:
            if not self._identity_is_alive(pid, starttime):
                return
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            os.close(pidfd)

    @staticmethod
    def _identity_sleep_command(path: Path) -> list[str]:
        return [
            sys.executable,
            "-c",
            (
                "import sys, time\n"
                + _PUBLISH_IDENTITY_SOURCE
                + "publish_identity('target', sys.argv[1])\n"
                "time.sleep(30)\n"
            ),
            str(path),
        ]

    @staticmethod
    def _wait_for_path(path: Path) -> None:
        deadline = time.monotonic() + 1.0
        while not path.exists():
            if time.monotonic() >= deadline:
                raise AssertionError("target did not publish its process identity")
            time.sleep(0.001)

    @staticmethod
    def _read_child_pids(pid: int) -> list[int]:
        payload = Path(f"/proc/{pid}/task/{pid}/children").read_text(
            encoding="ascii"
        )
        return [int(field) for field in payload.split()]

    @staticmethod
    def _host_process_identity(pid: int) -> tuple[int, str]:
        payload = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        return pid, payload[payload.rfind(")") + 2:].split()[19]

    def _wrapper_helper_target(
        self, wrapper_pid: int, marker: Path
    ) -> tuple[tuple[int, str], tuple[int, str]]:
        self._wait_for_path(marker)
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            wrapper_children = self._read_child_pids(wrapper_pid)
            if wrapper_children:
                first = wrapper_children[0]
                first_children = self._read_child_pids(first)
                helper_pid, target_pid = (
                    (first, first_children[0])
                    if first_children else (wrapper_pid, first)
                )
                helper = self._host_process_identity(helper_pid)
                target = self._host_process_identity(target_pid)
                return helper, target
            time.sleep(0.001)
        raise AssertionError("containment wrapper did not expose helper and target")

    def test_unavailable_containment_fails_before_spawning_target(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "target-started"
            command = [
                sys.executable,
                "-c",
                "import pathlib, sys; pathlib.Path(sys.argv[1]).touch()",
                str(marker),
            ]
            with patch.object(
                bounded_process,
                "_resolve_unshare",
                side_effect=BoundedProcessError("injected unavailable backend"),
                create=True,
            ), self.assertRaisesRegex(
                BoundedProcessError,
                "pid-namespace.*before target spawn.*injected unavailable backend",
            ):
                capture_bounded(command, maximum_bytes=1, timeout=1)

            self.assertFalse(marker.exists())

    def test_capture_bounded_runs_target_in_requested_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            output = capture_bounded(
                [sys.executable, "-c", "import os; print(os.getcwd())"],
                maximum_bytes=4096,
                timeout=3.0,
                cwd=Path(directory),
            )
        self.assertEqual(str(Path(directory).resolve()), output.decode().strip())

    def test_capture_bounded_rejects_missing_file_and_symlink_cwd_before_target_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "regular"
            regular.write_text("not a directory", encoding="utf-8")
            symlink = root / "symlink"
            symlink.symlink_to(root)
            marker = root / "target-started"
            initial_descriptors = len(list(Path("/proc/self/fd").iterdir()))
            for invalid in (root / "missing", regular, symlink):
                with self.subTest(invalid=invalid), self.assertRaisesRegex(
                    BoundedProcessError, "cwd.*before target spawn"
                ):
                    capture_bounded(
                        [
                            sys.executable,
                            "-c",
                            "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()",
                            str(marker),
                        ],
                        maximum_bytes=1,
                        timeout=1,
                        cwd=invalid,
                    )
                self.assertFalse(marker.exists())
                self.assertEqual(
                    initial_descriptors, len(list(Path("/proc/self/fd").iterdir()))
                )

    def test_capture_bounded_closes_cwd_on_immediate_deadline_and_first_pipe_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory)
            initial_descriptors = len(list(Path("/proc/self/fd").iterdir()))
            with self.assertRaises(subprocess.TimeoutExpired):
                capture_bounded(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    maximum_bytes=1, timeout=1e-12, cwd=cwd,
                )
            self.assertEqual(
                initial_descriptors, len(list(Path("/proc/self/fd").iterdir()))
            )

            with patch.object(bounded_process.os, "pipe2",
                              side_effect=OSError("first pipe failure")), \
                 self.assertRaisesRegex(OSError, "first pipe failure"):
                capture_bounded(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    maximum_bytes=1, timeout=1, cwd=cwd,
                )
            self.assertEqual(
                initial_descriptors, len(list(Path("/proc/self/fd").iterdir()))
            )

    def test_capture_bounded_holds_cwd_across_path_rebinding_and_aggregates_close_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requested = root / "requested"
            held = root / "held"
            requested.mkdir()
            (requested / "identity").write_text("held", encoding="utf-8")
            original_popen = bounded_process.subprocess.Popen
            original_close = bounded_process.os.close
            rebound = False
            close_failed = False
            initial_descriptors = len(list(Path("/proc/self/fd").iterdir()))

            def rebind_then_spawn(*args, **kwargs):
                nonlocal rebound
                if not rebound:
                    requested.rename(held)
                    requested.mkdir()
                    (requested / "identity").write_text("replacement", encoding="utf-8")
                    rebound = True
                return original_popen(*args, **kwargs)

            held_identity = requested.stat()

            def close_with_one_failure(descriptor):
                nonlocal close_failed
                try:
                    details = os.fstat(descriptor)
                except OSError:
                    return original_close(descriptor)
                if (not close_failed and details.st_dev == held_identity.st_dev
                        and details.st_ino == held_identity.st_ino):
                    close_failed = True
                    original_close(descriptor)
                    raise OSError("injected cwd close failure")
                return original_close(descriptor)

            with patch.object(
                bounded_process.subprocess, "Popen", side_effect=rebind_then_spawn
            ), patch.object(
                bounded_process.os, "close", side_effect=close_with_one_failure
            ), self.assertRaisesRegex(BoundedProcessError, "subprocess failed") as caught:
                capture_bounded(
                    [
                        sys.executable,
                        "-c",
                        "from pathlib import Path; print(Path('identity').read_text()); raise SystemExit(7)",
                    ],
                    maximum_bytes=64,
                    timeout=3,
                    cwd=requested,
                )

            self.assertEqual(b"held\n", caught.exception.stdout)
            diagnostics = "\n".join(getattr(caught.exception, "__notes__", ()))
            self.assertIn("cwd path identity changed", diagnostics)
            self.assertIn("injected cwd close failure", diagnostics)
            self.assertTrue(close_failed)
            self.assertEqual(
                initial_descriptors, len(list(Path("/proc/self/fd").iterdir()))
            )

    def test_denied_unshare_fails_before_spawning_target(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "target-started"
            command = [
                sys.executable,
                "-c",
                "import pathlib, sys; pathlib.Path(sys.argv[1]).touch()",
                str(marker),
            ]
            with patch.object(
                bounded_process, "_resolve_unshare", return_value="/bin/false"
            ), self.assertRaisesRegex(
                BoundedProcessError, "before target spawn"
            ):
                capture_bounded(command, maximum_bytes=1, timeout=1)

            self.assertFalse(marker.exists())

    def test_pid_fallback_refuses_changed_direct_child_identity(self):
        parent = os.getpid()
        with patch.object(
            bounded_process, "_process_identity",
            side_effect=((parent, "101"), (parent, "202")),
        ), patch.object(bounded_process.os, "pidfd_open", new=None), \
                patch.object(bounded_process.signal, "pidfd_send_signal", new=None), \
                patch.object(bounded_process.os, "kill") as raw_kill, \
                self.assertRaisesRegex(RuntimeError, "identity changed.*PID 4242"):
            bounded_process._signal_direct_child(4242, "101", signal.SIGKILL)

        raw_kill.assert_not_called()

    def test_large_survivor_tree_obeys_deadline_and_status_limit(self):
        identities = [(pid, str(pid * 10)) for pid in range(10_000, 20_000)]
        clock = 0

        def advancing_clock():
            nonlocal clock
            clock += 1
            return clock

        with patch.object(
            bounded_process, "_direct_child_identities", return_value=(identities, True)
        ), patch.object(
            bounded_process, "_signal_direct_child"
        ) as signal_child, patch.object(
            bounded_process, "_reap_exited_children"
        ), patch.object(
            bounded_process.time, "monotonic_ns", side_effect=advancing_clock
        ):
            samples, count, truncated = bounded_process._drain_adopted_children(
                deadline_ns=50
            )

        self.assertLess(signal_child.call_count, len(identities))
        self.assertEqual(bounded_process._MAX_SURVIVOR_SAMPLES, len(samples))
        self.assertEqual(len(identities), count)
        self.assertTrue(truncated)

        status_read, status_write = os.pipe2(getattr(os, "O_CLOEXEC", 0))
        try:
            bounded_process._supervisor_result(
                status_write,
                kind="containment-error",
                survivors=identities,
                survivor_count_at_least=len(identities),
                survivors_truncated=True,
                message="e" * (bounded_process._STATUS_BYTES * 2),
            )
            payload = os.read(status_read, bounded_process._STATUS_BYTES + 1)
        finally:
            os.close(status_read)
            os.close(status_write)
        self.assertLessEqual(len(payload), bounded_process._STATUS_BYTES)
        self.assertIn(b'"survivor_count_at_least":10000', payload)
        self.assertIn(b'"survivors_truncated":true', payload)

    def test_child_proc_scan_stops_incrementally_at_deadline(self):
        payload = b" ".join(str(pid).encode("ascii") for pid in range(10_000, 20_000))
        clock = 0

        def advancing_clock():
            nonlocal clock
            clock += 1
            return clock

        with patch.object(
            bounded_process.os, "open", return_value=77
        ), patch.object(
            bounded_process.os, "read", side_effect=(payload, b"")
        ), patch.object(
            bounded_process.os, "close"
        ) as close_descriptor, patch.object(
            bounded_process.time, "monotonic_ns", side_effect=advancing_clock
        ):
            pids, complete = bounded_process._read_direct_child_pids(deadline_ns=20)

        self.assertFalse(complete)
        self.assertGreater(len(pids), 0)
        self.assertLess(len(pids), 10_000)
        close_descriptor.assert_called_once_with(77)

    def test_monitor_never_observes_root_status_at_or_after_work_deadline(self):
        with patch.object(
            bounded_process.time, "monotonic_ns", return_value=100
        ), patch.object(
            bounded_process, "_peek_returncode"
        ) as peek_returncode:
            within_deadline, returncode = (
                bounded_process._peek_returncode_before_deadline(
                    4242, deadline_ns=100
                )
            )

        self.assertFalse(within_deadline)
        self.assertIsNone(returncode)
        peek_returncode.assert_not_called()

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"),
        "requires Linux pidfds for identity-safe test cleanup",
    )
    def test_selector_constructor_failure_reaps_child_and_preserves_error(self):
        with tempfile.TemporaryDirectory() as directory:
            identity_path = Path(directory) / "target.sock"
            with ProcessIdentityServer(identity_path, {"target"}) as identities:
                primary = RuntimeError("selector constructor")
                identity: tuple[int, str] | None = None

                def fail_after_target_starts():
                    nonlocal identity
                    identity = identities.wait(1)["target"]
                    raise primary

                try:
                    with patch.object(
                        bounded_process.selectors, "DefaultSelector",
                        side_effect=fail_after_target_starts,
                    ), self.assertRaisesRegex(
                        RuntimeError, "selector constructor"
                    ) as caught:
                        capture_bounded(
                            self._identity_sleep_command(identity_path),
                            maximum_bytes=1,
                            timeout=1,
                        )

                    self.assertIs(primary, caught.exception)
                    assert identity is not None
                    self._wait_identity_dead(identity)
                finally:
                    if identity is not None:
                        self._kill_test_identity(*identity)

    def test_target_really_starts_in_a_new_session(self):
        output = capture_bounded(
            [
                sys.executable,
                "-c",
                "import os; print(int(os.getpid() == os.getsid(0)))",
            ],
            maximum_bytes=2,
            timeout=1,
        )

        self.assertEqual(b"1\n", output)

    def test_target_namespace_preserves_identity_and_maps_supplementary_groups(self):
        output = capture_bounded(
            [
                sys.executable,
                "-c",
                (
                    "import os, pathlib\n"
                    "status = pathlib.Path('/proc/self/status').read_text()\n"
                    "nspid = next(line for line in status.splitlines() "
                    "if line.startswith('NSpid:')).split()[1:]\n"
                    "fresh = os.getppid() == 1 and nspid == [str(os.getpid())]\n"
                    "print(int(fresh), os.geteuid(), os.getegid(), *os.getgroups())\n"
                ),
            ],
            maximum_bytes=1024,
            timeout=1,
        )

        fresh, euid, egid, *groups = [int(field) for field in output.split()]
        self.assertEqual((1, os.geteuid(), os.getegid()), (fresh, euid, egid))
        overflow_gid = int(
            Path("/proc/sys/kernel/overflowgid").read_text(encoding="ascii")
        )
        expected_groups = [
            group if group == os.getegid() else overflow_gid
            for group in os.getgroups()
        ]
        self.assertEqual(expected_groups, groups)

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"),
        "requires Linux pidfds for identity-safe test cleanup",
    )
    def test_each_selector_registration_failure_reaps_child(self):
        for registration in (1, 2, 3):
            with self.subTest(registration=registration):
                with tempfile.TemporaryDirectory() as directory:
                    identity_path = Path(directory) / "target.sock"
                    with ProcessIdentityServer(identity_path, {"target"}) as identities:
                        selector = FakeSelector(fail_register=registration)
                        identity: tuple[int, str] | None = None

                        def selector_after_target_starts():
                            nonlocal identity
                            identity = identities.wait(1)["target"]
                            return selector

                        try:
                            with patch.object(
                                bounded_process.selectors,
                                "DefaultSelector",
                                side_effect=selector_after_target_starts,
                            ), self.assertRaisesRegex(
                                OSError, f"register {registration}"
                            ):
                                capture_bounded(
                                    self._identity_sleep_command(identity_path),
                                    maximum_bytes=1,
                                    timeout=1,
                                )
                            assert identity is not None
                            self._wait_identity_dead(identity)
                        finally:
                            if identity is not None:
                                self._kill_test_identity(*identity)

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"),
        "requires Linux pidfds for identity-safe test cleanup",
    )
    def test_selector_close_failure_cannot_mask_primary_or_skip_reaping(self):
        with tempfile.TemporaryDirectory() as directory:
            identity_path = Path(directory) / "target.sock"
            with ProcessIdentityServer(identity_path, {"target"}) as identities:
                primary = ValueError("primary selector failure")
                selector = FakeSelector(
                    select_error=primary, close_error=OSError("selector close failure")
                )
                identity: tuple[int, str] | None = None

                def selector_after_target_starts():
                    nonlocal identity
                    identity = identities.wait(1)["target"]
                    return selector

                try:
                    with patch.object(
                        bounded_process.selectors, "DefaultSelector",
                        side_effect=selector_after_target_starts,
                    ), self.assertRaisesRegex(
                        ValueError, "primary selector failure"
                    ) as caught:
                        capture_bounded(
                            self._identity_sleep_command(identity_path),
                            maximum_bytes=1,
                            timeout=1,
                        )

                    self.assertIs(primary, caught.exception)
                    assert identity is not None
                    self._wait_identity_dead(identity)
                finally:
                    if identity is not None:
                        self._kill_test_identity(*identity)

    def test_terminates_and_reaps_a_producer_immediately_at_the_limit(self):
        command = [
            sys.executable, "-c",
            "import os\nwhile True: os.write(1, b'x' * 65536)",
        ]
        started = time.monotonic()
        with self.assertRaisesRegex(BoundedProcessError, "size limit"):
            capture_bounded(command, maximum_bytes=1024, timeout=5)
        self.assertLess(time.monotonic() - started, 2)

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"),
        "requires Linux pidfds for identity-safe test cleanup",
    )
    def test_timeout_kills_pipe_inheriting_descendant_after_leader_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "identity.sock"
            with ProcessIdentityServer(socket_path, {"child"}) as identities:
                command = [
                    sys.executable,
                    "-c",
                    (
                        "import os, sys, time\n"
                        + _PUBLISH_IDENTITY_SOURCE
                        + "child = os.fork()\n"
                        "if child: os._exit(0)\n"
                        "publish_identity('child', sys.argv[1])\n"
                        "time.sleep(30)\n"
                    ),
                    str(socket_path),
                ]
                identity: tuple[int, str] | None = None
                try:
                    started = time.monotonic()
                    with self.assertRaises(subprocess.TimeoutExpired):
                        capture_bounded(
                            command, maximum_bytes=1024,
                            timeout=_IDENTITY_CONTAINMENT_TIMEOUT,
                        )
                    self.assertLess(
                        time.monotonic() - started,
                        _IDENTITY_CONTAINMENT_WALL_LIMIT,
                    )
                    identity = identities.wait()["child"]
                    self._wait_identity_dead(identity)
                finally:
                    if identity is not None:
                        self._kill_test_identity(*identity)

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"),
        "requires Linux pidfds for identity-safe test cleanup",
    )
    def test_timeout_reaps_setsid_descendant_that_inherits_capture_pipes(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "identity.sock"
            with ProcessIdentityServer(socket_path, {"escaped"}) as identities:
                command = [
                    sys.executable,
                    "-c",
                    (
                        "import os, sys, time\n"
                        + _PUBLISH_IDENTITY_SOURCE
                        + "child = os.fork()\n"
                        "if child: os._exit(0)\n"
                        "os.setsid()\n"
                        "publish_identity('escaped', sys.argv[1])\n"
                        "time.sleep(30)\n"
                    ),
                    str(socket_path),
                ]
                identity: tuple[int, str] | None = None
                try:
                    started = time.monotonic()
                    with self.assertRaises(subprocess.TimeoutExpired):
                        capture_bounded(
                            command, maximum_bytes=1024,
                            timeout=_IDENTITY_CONTAINMENT_TIMEOUT,
                        )
                    self.assertLess(
                        time.monotonic() - started,
                        _IDENTITY_CONTAINMENT_WALL_LIMIT,
                    )
                    identity = identities.wait()["escaped"]
                    self._wait_identity_dead(identity)
                finally:
                    if identity is not None:
                        self._kill_test_identity(*identity)

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"),
        "requires Linux pidfds for identity-safe test cleanup",
    )
    def test_daemonized_descendant_cannot_turn_root_exit_zero_into_success(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "identity.sock"
            with ProcessIdentityServer(socket_path, {"daemon"}) as identities:
                command = [
                    sys.executable,
                    "-c",
                    (
                        "import os, sys, time\n"
                        + _PUBLISH_IDENTITY_SOURCE
                        + "child = os.fork()\n"
                        "if child: os._exit(0)\n"
                        "os.setsid()\n"
                        "daemon = os.fork()\n"
                        "if daemon: os._exit(0)\n"
                        "null = os.open(os.devnull, os.O_RDWR)\n"
                        "os.dup2(null, 1); os.dup2(null, 2)\n"
                        "if null > 2: os.close(null)\n"
                        "publish_identity('daemon', sys.argv[1])\n"
                        "time.sleep(30)\n"
                    ),
                    str(socket_path),
                ]
                identity: tuple[int, str] | None = None
                try:
                    started = time.monotonic()
                    with self.assertRaises(subprocess.TimeoutExpired):
                        capture_bounded(
                            command, maximum_bytes=1024,
                            timeout=_IDENTITY_CONTAINMENT_TIMEOUT,
                        )
                    self.assertLess(
                        time.monotonic() - started,
                        _IDENTITY_CONTAINMENT_WALL_LIMIT,
                    )
                    identity = identities.wait()["daemon"]
                    self._wait_identity_dead(identity)
                finally:
                    if identity is not None:
                        self._kill_test_identity(*identity)

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"),
        "requires Linux pidfds for identity-safe test cleanup",
    )
    def test_cleanup_reaps_child_forked_from_a_setsid_term_handler(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "identity.sock"
            with ProcessIdentityServer(
                socket_path, {"original", "spawned"}
            ) as identity_server:
                command = [
                    sys.executable,
                    "-c",
                    (
                        "import os, signal, sys, time\n"
                        + _PUBLISH_IDENTITY_SOURCE
                        + "child = os.fork()\n"
                        "if child: os._exit(0)\n"
                        "os.setsid()\n"
                        "def on_term(_signum, _frame):\n"
                        " signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                        " late = os.fork()\n"
                        " if late == 0:\n"
                        "  publish_identity('spawned', sys.argv[1])\n"
                        "  time.sleep(30)\n"
                        "  os._exit(0)\n"
                        " time.sleep(0.05)\n"
                        " os._exit(0)\n"
                        "signal.signal(signal.SIGTERM, on_term)\n"
                        "publish_identity('original', sys.argv[1])\n"
                        "time.sleep(30)\n"
                    ),
                    str(socket_path),
                ]
                identities: list[tuple[int, str]] = []
                try:
                    started = time.monotonic()
                    with self.assertRaises(subprocess.TimeoutExpired):
                        capture_bounded(
                            command, maximum_bytes=1024,
                            timeout=_IDENTITY_CONTAINMENT_TIMEOUT,
                        )
                    self.assertLess(
                        time.monotonic() - started,
                        _IDENTITY_CONTAINMENT_WALL_LIMIT,
                    )
                    identities = list(identity_server.wait().values())
                    for identity in identities:
                        self._wait_identity_dead(identity)
                finally:
                    for identity in identities:
                        self._kill_test_identity(*identity)

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"),
        "requires Linux pidfds for identity-safe test control",
    )
    def test_stalled_supervisor_emergency_kills_the_entire_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "target.started"
            command = [
                sys.executable,
                "-c",
                (
                    "import pathlib, sys, time\n"
                    "pathlib.Path(sys.argv[1]).touch()\n"
                    "time.sleep(30)\n"
                ),
                str(marker),
            ]
            wrapper_processes: list[subprocess.Popen[bytes]] = []
            real_popen = bounded_process.subprocess.Popen
            helper_identity: tuple[int, str] | None = None
            target_identity: tuple[int, str] | None = None
            watcher_error: list[BaseException] = []
            helper_stopped = threading.Event()
            stop_watcher = threading.Event()
            real_pidfd_send_signal = signal.pidfd_send_signal

            def reject_emergency_pidfd(pidfd, signal_number, *_args):
                if signal_number == signal.SIGKILL:
                    raise OSError(errno.ENOSYS, "injected pidfd_send_signal")
                return real_pidfd_send_signal(pidfd, signal_number)

            def recording_popen(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                wrapper_processes.append(process)
                return process

            def stop_helper() -> None:
                nonlocal helper_identity, target_identity
                try:
                    while not wrapper_processes:
                        time.sleep(0.001)
                    helper_identity, target_identity = self._wrapper_helper_target(
                        wrapper_processes[0].pid, marker
                    )
                    pidfd = os.pidfd_open(helper_identity[0])
                    try:
                        if not self._identity_is_alive(*helper_identity):
                            raise AssertionError("helper identity changed before SIGSTOP")
                        real_pidfd_send_signal(pidfd, signal.SIGSTOP)
                        helper_stopped.set()
                        stop_watcher.wait(2)
                        try:
                            real_pidfd_send_signal(pidfd, signal.SIGCONT)
                        except ProcessLookupError:
                            pass
                    finally:
                        os.close(pidfd)
                except BaseException as error:
                    watcher_error.append(error)
                    helper_stopped.set()

            watcher = threading.Thread(target=stop_helper, daemon=True)
            watcher.start()
            started = time.monotonic()
            try:
                with patch.object(
                    bounded_process.subprocess, "Popen", side_effect=recording_popen
                ), patch.object(
                    bounded_process.signal,
                    "pidfd_send_signal",
                    side_effect=reject_emergency_pidfd,
                ):
                    with self.assertRaisesRegex(
                        BoundedProcessError,
                        r"pid-namespace.*emergency.*PID \d+ starttime \d+",
                    ):
                        capture_bounded(
                            command, maximum_bytes=1024,
                            timeout=_IDENTITY_CONTAINMENT_TIMEOUT,
                        )
                self.assertLess(
                    time.monotonic() - started,
                    _IDENTITY_CONTAINMENT_WALL_LIMIT,
                )
                self.assertTrue(helper_stopped.wait(1), "helper was not SIGSTOPed")
                if watcher_error:
                    raise watcher_error[0]
                assert target_identity is not None
                self._wait_identity_dead(target_identity)
            finally:
                stop_watcher.set()
                watcher.join(timeout=2)
                if helper_identity is not None:
                    self._kill_test_identity(*helper_identity)
                if target_identity is not None:
                    self._kill_test_identity(*target_identity)

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"),
        "requires Linux pidfds for identity-safe test control",
    )
    def test_stalled_supervisor_uses_verified_wrapper_fallback_without_pidfd(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "target.started"
            command = [
                sys.executable,
                "-c",
                (
                    "import pathlib, sys, time\n"
                    "pathlib.Path(sys.argv[1]).touch()\n"
                    "time.sleep(30)\n"
                ),
                str(marker),
            ]
            wrapper_processes: list[subprocess.Popen[bytes]] = []
            real_popen = bounded_process.subprocess.Popen
            helper_identity: tuple[int, str] | None = None
            target_identity: tuple[int, str] | None = None
            watcher_error: list[BaseException] = []
            stop_watcher = threading.Event()

            def recording_popen(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                wrapper_processes.append(process)
                return process

            def stop_helper() -> None:
                nonlocal helper_identity, target_identity
                try:
                    while not wrapper_processes:
                        time.sleep(0.001)
                    helper_identity, target_identity = self._wrapper_helper_target(
                        wrapper_processes[0].pid, marker
                    )
                    pidfd = os.pidfd_open(helper_identity[0])
                    try:
                        if not self._identity_is_alive(*helper_identity):
                            raise AssertionError("helper identity changed before SIGSTOP")
                        signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
                        stop_watcher.wait(2)
                        try:
                            signal.pidfd_send_signal(pidfd, signal.SIGCONT)
                        except ProcessLookupError:
                            pass
                    finally:
                        os.close(pidfd)
                except BaseException as error:
                    watcher_error.append(error)

            watcher = threading.Thread(target=stop_helper, daemon=True)
            watcher.start()
            started = time.monotonic()
            try:
                with patch.object(
                    bounded_process.subprocess, "Popen", side_effect=recording_popen
                ), patch.object(
                    bounded_process, "_open_wrapper_pidfd", return_value=-1
                ), self.assertRaisesRegex(
                    BoundedProcessError,
                    r"pid-namespace.*emergency.*PID \d+ starttime \d+",
                ):
                    capture_bounded(
                        command, maximum_bytes=1024,
                        timeout=_IDENTITY_CONTAINMENT_TIMEOUT,
                    )
                self.assertLess(
                    time.monotonic() - started,
                    _IDENTITY_CONTAINMENT_WALL_LIMIT,
                )
                if watcher_error:
                    raise watcher_error[0]
                assert target_identity is not None
                self._wait_identity_dead(target_identity)
            finally:
                stop_watcher.set()
                watcher.join(timeout=2)
                if helper_identity is not None:
                    self._kill_test_identity(*helper_identity)
                if target_identity is not None:
                    self._kill_test_identity(*target_identity)

    def test_wrapper_fallback_refuses_changed_starttime_before_raw_kill(self):
        class FakeWrapper:
            pid = 4242

        with patch.object(
            bounded_process,
            "_process_identity",
            return_value=(os.getpid(), "new-starttime"),
        ), patch.object(bounded_process.os, "kill") as raw_kill, \
                self.assertRaisesRegex(BoundedProcessError, "identity changed.*4242"):
            bounded_process._signal_wrapper(
                FakeWrapper(),
                pidfd=-1,
                starttime="held-starttime",
                signal_number=signal.SIGKILL,
            )

        raw_kill.assert_not_called()

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"),
        "requires Linux pidfds for identity-safe test cleanup",
    )
    def test_post_spawn_supervisor_failure_still_kills_the_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "target.started"
            command = [
                sys.executable,
                "-c",
                (
                    "import pathlib, sys, time\n"
                    "pathlib.Path(sys.argv[1]).touch()\n"
                    "time.sleep(30)\n"
                ),
                str(marker),
            ]
            wrapper_processes: list[subprocess.Popen[bytes]] = []
            real_popen = bounded_process.subprocess.Popen
            target_identity: tuple[int, str] | None = None
            watcher_error: list[BaseException] = []
            recorded = threading.Event()

            def recording_popen(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                wrapper_processes.append(process)
                return process

            def record_target() -> None:
                nonlocal target_identity
                try:
                    while not wrapper_processes:
                        time.sleep(0.001)
                    helper, target_identity = self._wrapper_helper_target(
                        wrapper_processes[0].pid, marker
                    )
                    pidfd = os.pidfd_open(helper[0])
                    try:
                        if not self._identity_is_alive(*helper):
                            raise AssertionError("helper identity changed before SIGUSR1")
                        signal.pidfd_send_signal(pidfd, signal.SIGUSR1)
                    finally:
                        os.close(pidfd)
                except BaseException as error:
                    watcher_error.append(error)
                finally:
                    recorded.set()

            watcher = threading.Thread(target=record_target, daemon=True)
            watcher.start()
            started = time.monotonic()
            try:
                with patch.object(
                    bounded_process.subprocess, "Popen", side_effect=recording_popen
                ):
                    with self.assertRaisesRegex(
                        BoundedProcessError,
                        r"pid-namespace.*post-spawn supervisor failure",
                    ):
                        capture_bounded(command, maximum_bytes=1024, timeout=2)
                self.assertLess(time.monotonic() - started, 1)
                self.assertTrue(recorded.wait(1), "target identity was not recorded")
                watcher.join(timeout=1)
                if watcher_error:
                    raise watcher_error[0]
                assert target_identity is not None
                self._wait_identity_dead(target_identity)
            finally:
                watcher.join(timeout=1)
                if target_identity is not None:
                    self._kill_test_identity(*target_identity)

    def test_success_returns_stdout(self):
        output = capture_bounded(
            [sys.executable, "-c", "import os; os.write(1, b'ok')"],
            maximum_bytes=1024,
            timeout=5,
        )

        self.assertEqual(b"ok", output)

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

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and hasattr(os, "pidfd_open")
        and hasattr(signal, "pidfd_send_signal"),
        "requires Linux pidfds for identity-safe test cleanup",
    )
    def test_nonzero_root_wins_over_descendant_cleanup_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "identity.sock"
            with ProcessIdentityServer(socket_path, {"stubborn"}) as identities:
                command = [
                    sys.executable,
                    "-c",
                    (
                        "import os, signal, sys, time\n"
                        + _PUBLISH_IDENTITY_SOURCE
                        + "ready_read, ready_write = os.pipe()\n"
                        "child = os.fork()\n"
                        "if child:\n"
                        " os.close(ready_write)\n"
                        " os.read(ready_read, 1)\n"
                        " os.write(1, b'root-seven')\n"
                        " time.sleep(0.04)\n"
                        " os._exit(7)\n"
                        "os.close(ready_read)\n"
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                        "publish_identity('stubborn', sys.argv[1])\n"
                        "os.write(ready_write, b'1')\n"
                        "os.close(ready_write)\n"
                        "time.sleep(30)\n"
                    ),
                    str(socket_path),
                ]
                identity: tuple[int, str] | None = None
                try:
                    started = time.monotonic()
                    with self.assertRaises(BoundedProcessError) as caught:
                        capture_bounded(
                            command, maximum_bytes=1024,
                            timeout=_IDENTITY_CONTAINMENT_TIMEOUT,
                        )
                    self.assertLess(
                        time.monotonic() - started,
                        _IDENTITY_CONTAINMENT_WALL_LIMIT,
                    )
                    identity = identities.wait()["stubborn"]
                    self.assertEqual(7, caught.exception.returncode)
                    self.assertEqual(b"root-seven", caught.exception.stdout)
                    self._wait_identity_dead(identity)
                finally:
                    if identity is not None:
                        self._kill_test_identity(*identity)

    def test_missing_executable_preserves_file_not_found_shape(self):
        missing = "/definitely/missing/qtrace-bounded-command"
        with self.assertRaises(FileNotFoundError) as caught:
            capture_bounded([missing], maximum_bytes=1, timeout=1)

        self.assertEqual(missing, caught.exception.filename)
        self.assertEqual(2, caught.exception.errno)
        self.assertEqual(1, str(caught.exception).count("[Errno 2]"))

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
