#!/usr/bin/env python3
"""Manual, rooted-device qtrace release acceptance.  This is never a CI job."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, Sequence

if __package__ in {None, ""}:
    _REPOSITORY_ROOT = str(Path(__file__).resolve().parents[1])
    sys.path[:] = [
        _REPOSITORY_ROOT,
        *(entry for entry in sys.path if entry != _REPOSITORY_ROOT),
    ]

from scripts.bounded_process import BoundedProcessError, capture_bounded
from scripts.pull_trace import AdbArtifactClient, MAX_METRICS_BYTES
from scripts.qtrace_historical_benchmark import (
    HISTORICAL_COMMIT,
    HistoricalBenchmarkApk,
    build_historical_benchmark_apk,
)
from qtrace.status import load_strict_json, validate_status_shape


PACKAGE = "com.aprz.qbdiandroid"
ACTIVITY = "com.aprz.qbdiandroid/.MainActivity"
TRACER_PATH = Path("out/arm64-v8a/libqbdi_tracer.so")
COMPANION_PATH = Path("out/arm64-v8a/libshadowhook_nothing.so")
_CURRENT_APK_PATH = Path("app/build/outputs/apk/debug/app-debug.apk")
_APP_PRIVATE_BINARIES = (
    (TRACER_PATH, "files/libqbdi_tracer.so"),
    (COMPANION_PATH, "files/libshadowhook_nothing.so"),
)
SEED = 5855319310239641971
ITERATIONS = 30
BASELINE_PATH = f"/data/data/{PACKAGE}/files/qtrace-acceptance-baseline.json"
RECEIPT_PATH = f"/data/data/{PACKAGE}/files/qtrace-acceptance-receipt.json"
ENTRY_STATUS_PATH = f"/data/data/{PACKAGE}/files/qtrace-acceptance-entry-status.json"
TIMED_RESULT_PATH = f"/data/data/{PACKAGE}/files/qtrace-acceptance-timed.json"
_POLLABLE_FIXTURE_PATHS = frozenset((
    BASELINE_PATH, RECEIPT_PATH, ENTRY_STATUS_PATH, TIMED_RESULT_PATH,
))
_UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class AcceptanceNotReadyError(RuntimeError):
    """The fixture has not yet atomically published a pollable result."""


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    returncode: int


@dataclass(frozen=True)
class RegularFileStat:
    size: int
    identity: tuple[int, int]


@dataclass
class HostBinarySnapshot:
    path: Path
    sha256: str
    size: int
    descriptor: int
    identity: tuple[int, int]

    def verify_path(self) -> None:
        if self.descriptor < 0:
            raise RuntimeError("host tracer snapshot is closed")
        held = os.fstat(self.descriptor)
        try:
            named = os.stat(self.path, follow_symlinks=False)
        except OSError as error:
            raise RuntimeError("host tracer snapshot identity changed") from error
        if (not stat.S_ISREG(held.st_mode) or not stat.S_ISREG(named.st_mode) or
                (held.st_dev, held.st_ino) != self.identity or
                (named.st_dev, named.st_ino) != self.identity or
                held.st_size != self.size or named.st_size != self.size):
            raise RuntimeError("host tracer snapshot identity changed")

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass
class HeldTracerPair:
    tracer: HostBinarySnapshot
    companion: HostBinarySnapshot

    def verify_paths(self) -> None:
        self.tracer.verify_path()
        self.companion.verify_path()

    def close(self) -> None:
        """Attempt both closes and preserve their deterministic order."""
        failures: list[tuple[str, BaseException]] = []
        for label, snapshot in (("tracer", self.tracer),
                                ("companion", self.companion)):
            try:
                snapshot.close()
            except BaseException as error:
                failures.append((label, error))
        if failures:
            detail = "; ".join(
                f"{label}: {type(error).__name__}: {error}"
                for label, error in failures
            )
            raise RuntimeError(f"held tracer pair cleanup failed: {detail}")


_LOCAL_READ_TIMEOUT_SECONDS = 15.0
_WORKER_CLEANUP_SECONDS = 0.05
_MAX_HOST_BINARY_BYTES = 64 * 1024 * 1024
_MAX_CURRENT_APK_BYTES = 128 * 1024 * 1024
_HOST_BINARY_SNAPSHOT_SECONDS = 30.0
_HISTORICAL_BUILD_SECONDS = 1200.0


def _kill_and_reap(pid: int, *, cleanup_deadline: float | None = None) -> None:
    if cleanup_deadline is None:
        cleanup_deadline = time.monotonic() + _WORKER_CLEANUP_SECONDS
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    while True:
        try:
            finished, _status = os.waitpid(pid, os.WNOHANG)
        except InterruptedError:
            finished = 0
        except ChildProcessError:
            return
        if finished == pid:
            return
        remaining = cleanup_deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(
                f"output reader worker PID {pid} cleanup deadline "
                f"{cleanup_deadline:.6f} elapsed; unreaped"
            )
        time.sleep(min(0.01, remaining))


def _read_regular_in_worker(
    descriptor: int,
    size: int,
    *,
    deadline: float,
    read_hook: Callable[[int, int], bytes] = os.read,
) -> bytes:
    """Read in a killable child which inherits the held file capability.

    The acceptance host calls this from its single-threaded control path. The
    fork child performs only low-level descriptor operations. Cleanup is bounded;
    an uninterruptible child is reported explicitly so the host can exit.
    """
    started = time.monotonic()
    if started >= deadline:
        raise RuntimeError("reported output read exceeded deadline")
    cleanup_budget = min(
        _WORKER_CLEANUP_SECONDS,
        (deadline - started) / 2.0,
    )
    worker_deadline = deadline - cleanup_budget
    scratch = tempfile.TemporaryFile()
    source = os.dup(descriptor)
    pid = -1
    try:
        try:
            pid = os.fork()
        except OSError as error:
            raise RuntimeError("cannot start bounded output reader") from error
        if pid == 0:
            try:
                remaining = size
                while remaining:
                    block = read_hook(source, min(64 * 1024, remaining))
                    if type(block) is not bytes or not block or len(block) > remaining:
                        os._exit(71)
                    view = memoryview(block)
                    while view:
                        written = os.write(scratch.fileno(), view)
                        if written <= 0:
                            os._exit(72)
                        view = view[written:]
                    remaining -= len(block)
                os._exit(0)
            except BaseException:
                os._exit(73)

        os.close(source)
        source = -1
        while True:
            try:
                finished, status = os.waitpid(pid, os.WNOHANG)
            except InterruptedError:
                finished, status = 0, 0
            if finished == pid:
                pid = -1
                break
            remaining = worker_deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("reported output read exceeded deadline")
            time.sleep(min(0.01, remaining))
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise RuntimeError("reported output changed while being read")
        if time.monotonic() >= deadline:
            raise RuntimeError("reported output read exceeded deadline")
        scratch.seek(0)
        data = scratch.read(size + 1)
        if len(data) != size:
            raise RuntimeError("reported output changed while being read")
        return data
    finally:
        if pid > 0:
            _kill_and_reap(pid, cleanup_deadline=deadline)
        if source >= 0:
            os.close(source)
        scratch.close()


def _snapshot_host_binary(
    source_path: Path,
    snapshot_path: Path,
    *,
    maximum_bytes: int,
    deadline: float,
    _open_hook: Callable[[Path, int], int] = os.open,
    _read_hook: Callable[[int, int], bytes] = os.read,
    _write_hook: Callable[[int, bytes | memoryview], int] = os.write,
) -> HostBinarySnapshot:
    """Create one immutable, bounded snapshot while holding the source fd.

    Acceptance calls this from its single-threaded control path after the test
    subprocesses return. Opening is inside the killable worker so a blocking
    filesystem cannot pin the host controller before its deadline.
    """
    started = time.monotonic()
    if maximum_bytes <= 0 or started >= deadline:
        raise RuntimeError("host tracer input exceeded deadline")
    cleanup_budget = min(_WORKER_CLEANUP_SECONDS, (deadline - started) / 2.0)
    worker_deadline = deadline - cleanup_budget
    destination = -1
    status_read = -1
    status_write = -1
    pid = -1
    success = False
    result: HostBinarySnapshot | None = None
    try:
        try:
            destination = os.open(
                snapshot_path,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            status_read, status_write = os.pipe2(getattr(os, "O_CLOEXEC", 0))
            pid = os.fork()
        except OSError as error:
            raise RuntimeError("cannot start bounded host tracer snapshot") from error
        if pid == 0:
            source = -1
            try:
                os.close(status_read)
                source = _open_hook(
                    source_path,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                    getattr(os, "O_NONBLOCK", 0),
                )
                before = os.fstat(source)
                if (not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or
                        before.st_size > maximum_bytes):
                    os.write(status_write, b"B")
                    os._exit(0)
                digest = hashlib.sha256()
                remaining = before.st_size
                while remaining:
                    block = _read_hook(source, min(1024 * 1024, remaining))
                    if type(block) is not bytes or not block or len(block) > remaining:
                        os.write(status_write, b"C")
                        os._exit(0)
                    digest.update(block)
                    view = memoryview(block)
                    while view:
                        written = _write_hook(destination, view)
                        if type(written) is not int or written <= 0 or written > len(view):
                            os.write(status_write, b"W")
                            os._exit(0)
                        view = view[written:]
                    remaining -= len(block)
                trailing = _read_hook(source, 1)
                after = os.fstat(source)
                if (type(trailing) is not bytes or trailing or
                        (after.st_dev, after.st_ino, after.st_size,
                         after.st_mtime_ns, after.st_ctime_ns) !=
                        (before.st_dev, before.st_ino, before.st_size,
                         before.st_mtime_ns, before.st_ctime_ns)):
                    os.write(status_write, b"C")
                    os._exit(0)
                payload = (
                    b"S" + before.st_size.to_bytes(8, "big") +
                    digest.hexdigest().encode("ascii")
                )
                os.write(status_write, payload)
                os._exit(0)
            except BaseException:
                try:
                    os.write(status_write, b"B")
                except BaseException:
                    pass
                os._exit(73)

        os.close(status_write)
        status_write = -1
        while True:
            remaining = worker_deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("host tracer input exceeded deadline")
            try:
                finished, status = os.waitpid(pid, os.WNOHANG)
            except InterruptedError:
                finished, status = 0, 0
            if finished == pid:
                pid = -1
            remaining = worker_deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("host tracer input exceeded deadline")
            if finished:
                break
            time.sleep(min(0.01, remaining))
        payload = os.read(status_read, 128)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise RuntimeError("host tracer input is not a bounded regular file")
        if payload == b"B":
            raise RuntimeError("host tracer input is not a bounded regular file")
        if payload == b"C":
            raise RuntimeError("host tracer input changed while being read")
        if payload == b"W":
            raise RuntimeError("host tracer snapshot write failed")
        if (len(payload) != 73 or payload[:1] != b"S" or
                _SHA256.fullmatch(payload[9:].decode("ascii", errors="ignore")) is None):
            raise RuntimeError("host tracer snapshot worker returned invalid evidence")
        size = int.from_bytes(payload[1:9], "big")
        metadata = os.fstat(destination)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != size:
            raise RuntimeError("host tracer snapshot changed while being written")
        result = HostBinarySnapshot(
            snapshot_path, payload[9:].decode("ascii"), size, destination,
            (metadata.st_dev, metadata.st_ino),
        )
        result.verify_path()
        destination = -1
        success = True
    finally:
        primary = sys.exception()
        cleanup_failures: list[tuple[str, BaseException]] = []
        if pid > 0:
            try:
                _kill_and_reap(pid, cleanup_deadline=deadline)
            except BaseException as error:
                cleanup_failures.append((f"worker PID {pid}", error))
        for label, descriptor in (
            ("status read descriptor", status_read),
            ("status write descriptor", status_write),
            ("snapshot descriptor", destination),
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except BaseException as error:
                    cleanup_failures.append((label, error))
        if not success:
            try:
                snapshot_path.unlink()
            except FileNotFoundError:
                pass
            except BaseException as error:
                cleanup_failures.append((f"snapshot path {snapshot_path}", error))
        if cleanup_failures:
            if success and result is not None:
                try:
                    result.close()
                except BaseException as error:
                    cleanup_failures.append(("returned snapshot descriptor", error))
                try:
                    snapshot_path.unlink()
                except FileNotFoundError:
                    pass
                except BaseException as error:
                    cleanup_failures.append((f"snapshot path {snapshot_path}", error))
                success = False
            detail = "; ".join(
                f"{label}: {type(error).__name__}: {error}"
                for label, error in cleanup_failures
            )
            if primary is not None:
                combined = RuntimeError(
                    "host tracer snapshot failed: "
                    f"{type(primary).__name__}: {primary}; cleanup failed: {detail}"
                )
                raise combined from primary
            raise RuntimeError(f"host tracer snapshot cleanup failed: {detail}")
    assert result is not None
    return result


def _snapshot_current_inputs(*, deadline: float) -> tuple[HostBinarySnapshot, HeldTracerPair]:
    """Snapshot the current APK and tracer pair into one private held tree."""
    root = Path(tempfile.mkdtemp(prefix="qtrace-current-inputs-"))
    current: HostBinarySnapshot | None = None
    tracer: HostBinarySnapshot | None = None
    companion: HostBinarySnapshot | None = None
    try:
        os.chmod(root, 0o700)
        current = _snapshot_host_binary(
            _CURRENT_APK_PATH, root / "current.apk",
            maximum_bytes=_MAX_CURRENT_APK_BYTES, deadline=deadline,
        )
        tracer = _snapshot_host_binary(
            TRACER_PATH, root / TRACER_PATH.name,
            maximum_bytes=_MAX_HOST_BINARY_BYTES, deadline=deadline,
        )
        companion = _snapshot_host_binary(
            COMPANION_PATH, root / COMPANION_PATH.name,
            maximum_bytes=_MAX_HOST_BINARY_BYTES, deadline=deadline,
        )
        pair = HeldTracerPair(tracer, companion)
        pair.verify_paths()
        current.verify_path()
        return current, pair
    except BaseException as primary:
        failures: list[tuple[str, BaseException]] = []
        for label, snapshot in (("current APK", current), ("tracer", tracer),
                                ("companion", companion)):
            if snapshot is not None:
                try:
                    snapshot.close()
                except BaseException as error:
                    failures.append((label, error))
        try:
            shutil.rmtree(root)
        except FileNotFoundError:
            pass
        except BaseException as error:
            failures.append(("current input snapshot tree", error))
        if failures:
            detail = "; ".join(
                f"{label}: {type(error).__name__}: {error}"
                for label, error in failures
            )
            raise RuntimeError(
                f"current input snapshot failed: {type(primary).__name__}: {primary}; "
                f"cleanup failed: {detail}"
            ) from primary
        raise


class Runner(Protocol):
    def run(self, command: Sequence[str], *, timeout: float, cwd: Path | None = None,
            allowed: tuple[int, ...] = (0,)) -> CommandResult: ...
    def read_text(self, path: Path, *, timeout: float) -> str: ...
    def read_text_beneath(self, root: Path | RootedReader, relative: Path, *, timeout: float) -> str: ...


def _install_held_apk(
    device: str,
    runner: Runner,
    apk: HostBinarySnapshot | HistoricalBenchmarkApk,
) -> None:
    apk.verify_path()
    runner.run(("adb", "-s", device, "install", "-r", str(apk.path)), timeout=120.0)
    apk.verify_path()


def _stage_app_private_binaries(
    device: str,
    runner: Runner,
    *,
    token: str,
    pair: HeldTracerPair,
    package: str = PACKAGE,
) -> None:
    """Install the freshly built tracer pair without trusting persistent app data."""
    if re.fullmatch(r"[0-9a-f]{32}", token) is None:
        raise ValueError("acceptance staging token must be 32 lowercase hex characters")
    host_staged = tuple(
        f"/data/local/tmp/qtrace-acceptance-{token}-{Path(destination).name}"
        for _source, destination in _APP_PRIVATE_BINARIES
    )
    app_staged = tuple(
        f"files/.qtrace-acceptance-{token}-{Path(destination).name}"
        for _source, destination in _APP_PRIVATE_BINARIES
    )
    final_paths = tuple(destination for _source, destination in _APP_PRIVATE_BINARIES)
    snapshots = (pair.tracer, pair.companion)
    app_parent_trusted = False

    def validate(remote: str, expected_hash: str) -> None:
        kind = runner.run(
            ("adb", "-s", device, "shell", "run-as", package,
             "stat", "-c", "%F", remote),
            timeout=30.0,
        ).stdout.strip()
        if kind != "regular file":
            raise RuntimeError(f"app-private tracer path is not a regular file: {remote}")
        mode = runner.run(
            ("adb", "-s", device, "shell", "run-as", package,
             "stat", "-c", "%a", remote),
            timeout=30.0,
        ).stdout.strip()
        if mode != "700":
            raise RuntimeError(
                f"app-private tracer path does not have canonical mode 700: {remote}"
            )
        output = runner.run(
            ("adb", "-s", device, "shell", "run-as", package, "sha256sum", remote),
            timeout=30.0,
        ).stdout
        fields = output.strip().split()
        if (len(fields) != 2 or _SHA256.fullmatch(fields[0]) is None or
                fields[1] != remote or fields[0] != expected_hash):
            raise RuntimeError(f"app-private tracer SHA-256 mismatch: {remote}")

    def remove_app(path: str) -> None:
        runner.run(
            ("adb", "-s", device, "shell", "run-as", package, "rm", "-f", path),
            timeout=30.0,
        )

    def remove_host(path: str) -> None:
        runner.run(
            ("adb", "-s", device, "shell", "rm", "-f", path),
            timeout=30.0,
        )

    def collect_cleanup(
        actions: Sequence[tuple[str, Callable[[], None]]],
    ) -> list[tuple[str, BaseException]]:
        failures: list[tuple[str, BaseException]] = []
        for label, action in actions:
            try:
                action()
            except BaseException as error:
                failures.append((label, error))
        return failures

    app_scratch_cleanup = tuple(
        (f"app staging path {remote}", lambda remote=remote: remove_app(remote))
        for remote in app_staged
    )
    host_scratch_cleanup = tuple(
        (f"host staging path {remote}", lambda remote=remote: remove_host(remote))
        for remote in host_staged
    )
    final_cleanup = tuple(
        (f"final path {remote}", lambda remote=remote: remove_app(remote))
        for remote in final_paths
    )

    def scratch_cleanup() -> Sequence[tuple[str, Callable[[], None]]]:
        if app_parent_trusted:
            return app_scratch_cleanup + host_scratch_cleanup
        return host_scratch_cleanup

    def failure_cleanup() -> Sequence[tuple[str, Callable[[], None]]]:
        if app_parent_trusted:
            return final_cleanup + app_scratch_cleanup + host_scratch_cleanup
        return host_scratch_cleanup

    try:
        pair.verify_paths()
        expected_hashes = [snapshot.sha256 for snapshot in snapshots]
        runner.run(
            ("adb", "-s", device, "shell", "run-as", package,
             "mkdir", "-p", "files"),
            timeout=30.0,
        )
        parent_kind = runner.run(
            ("adb", "-s", device, "shell", "run-as", package,
             "stat", "-c", "%F", "files"),
            timeout=30.0,
        ).stdout.strip()
        if parent_kind != "directory":
            raise RuntimeError("app-private files path is not a real directory")
        runner.run(
            ("adb", "-s", device, "shell", "run-as", package,
             "chmod", "771", "files"),
            timeout=30.0,
        )
        parent_mode = runner.run(
            ("adb", "-s", device, "shell", "run-as", package,
             "stat", "-c", "%a", "files"),
            timeout=30.0,
        ).stdout.strip()
        if parent_mode != "771":
            raise RuntimeError("app-private files path does not have canonical mode 771")
        app_parent_trusted = True
        for remote in host_staged:
            remove_host(remote)
        for remote in app_staged:
            remove_app(remote)
        for snapshot, remote in zip(snapshots, host_staged):
            # adb push only accepts a pathname. Keep the snapshot fd held and
            # verify its name immediately before passing the private 0700
            # TemporaryDirectory path; the mutable build path is never reused.
            snapshot.verify_path()
            runner.run(
                ("adb", "-s", device, "push", str(snapshot.path), remote),
                timeout=120.0,
            )
            snapshot.verify_path()
        for host_remote, app_remote in zip(host_staged, app_staged):
            runner.run(
                ("adb", "-s", device, "shell", "run-as", package,
                 "cp", host_remote, app_remote),
                timeout=30.0,
            )
        runner.run(
            ("adb", "-s", device, "shell", "run-as", package, "chmod", "700",
             *app_staged),
            timeout=30.0,
        )
        for remote, expected_hash in zip(app_staged, expected_hashes):
            validate(remote, expected_hash)
        for destination in final_paths:
            remove_app(destination)
        for index in (1, 0):
            runner.run(
                ("adb", "-s", device, "shell", "run-as", package,
                 "mv", app_staged[index], _APP_PRIVATE_BINARIES[index][1]),
                timeout=30.0,
            )
        for (_source, destination), expected_hash in zip(
                _APP_PRIVATE_BINARIES, expected_hashes):
            validate(destination, expected_hash)
        cleanup_failures = collect_cleanup(scratch_cleanup())
        if cleanup_failures:
            detail = "; ".join(
                f"{label}: {type(error).__name__}: {error}"
                for label, error in cleanup_failures
            )
            cleanup_error = RuntimeError(
                f"app-private tracer staging cleanup failed: {detail}"
            )
            raise cleanup_error
    except BaseException as primary:
        cleanup_failures = collect_cleanup(failure_cleanup())
        if cleanup_failures:
            detail = "; ".join(
                f"{label}: {type(error).__name__}: {error}"
                for label, error in cleanup_failures
            )
            combined = RuntimeError(
                "app-private tracer staging failed: "
                f"{type(primary).__name__}: {primary}; cleanup failed: {detail}"
            )
            raise combined from primary
        raise


class RootedReader:
    """A fixed output directory capability, immune to later pathname rebinding."""

    def __init__(self, root: Path, *,
                 _read_hook: Callable[[int, int], bytes] = os.read) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(root, flags)
            details = os.fstat(descriptor)
            if not stat.S_ISDIR(details.st_mode):
                raise OSError("trusted output root is not a directory")
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            raise RuntimeError("trusted output root is not a directory") from error
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        self._descriptor = descriptor
        self.path = root
        self._identity = (details.st_dev, details.st_ino)
        self._read_hook = _read_hook

    def __enter__(self) -> "RootedReader":
        return self

    def __exit__(self, *_unused: object) -> None:
        self.close()

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1

    def _open_regular(self, relative: Path | str) -> tuple[int, os.stat_result]:
        candidate = Path(relative)
        if (self._descriptor < 0 or candidate.is_absolute() or not candidate.parts or
                ".." in candidate.parts):
            raise RuntimeError("reported output path is unsafe")
        directory = -1
        descriptor = -1
        try:
            root_details = os.fstat(self._descriptor)
            if (root_details.st_dev, root_details.st_ino) != self._identity:
                raise RuntimeError("trusted output root identity changed")
            directory = os.dup(self._descriptor)
            for part in candidate.parts[:-1]:
                child = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                                getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
                os.close(directory)
                directory = child
            descriptor = os.open(
                candidate.parts[-1],
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode):
                raise RuntimeError("reported output is not a regular file")
            result, descriptor = descriptor, -1
            return result, details
        except OSError as error:
            raise RuntimeError("reported output is outside the trusted directory") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if directory >= 0:
                os.close(directory)

    def stat_regular(self, relative: Path | str) -> RegularFileStat:
        descriptor, details = self._open_regular(relative)
        try:
            return RegularFileStat(details.st_size, (details.st_dev, details.st_ino))
        finally:
            os.close(descriptor)

    def read_bytes(self, relative: Path | str, maximum_bytes: int = 1_048_576,
                   *, deadline: float | None = None) -> bytes:
        descriptor, details = self._open_regular(relative)
        try:
            if details.st_size > maximum_bytes:
                raise RuntimeError("reported output is not a bounded regular file")
            final_deadline = (time.monotonic() + _LOCAL_READ_TIMEOUT_SECONDS
                              if deadline is None else deadline)
            return _read_regular_in_worker(
                descriptor, details.st_size, deadline=final_deadline,
                read_hook=self._read_hook,
            )
        finally:
            os.close(descriptor)


class SubprocessRunner:
    """Bounded process/read adapter; the one-shot failure hook is acceptance-only."""

    def __init__(self, device: str, *, inject_first_read_failure: bool = True) -> None:
        self.device = device
        self.inject_first_read_failure = inject_first_read_failure

    def run(self, command: Sequence[str], *, timeout: float, cwd: Path | None = None,
            allowed: tuple[int, ...] = (0,)) -> CommandResult:
        if cwd is not None:
            raise ValueError("bounded acceptance commands do not support a working directory")
        try:
            output = capture_bounded(command, maximum_bytes=1_048_576, timeout=timeout)
        except BoundedProcessError as error:
            if error.returncode in allowed:
                return CommandResult(
                    error.stdout.decode("utf-8", errors="strict"),
                    error.stderr.decode("utf-8", errors="replace"), error.returncode,
                )
            raise RuntimeError(str(error)) from error
        return CommandResult(output.decode("utf-8", errors="strict"), "", 0)

    def read_text(self, path: Path, *, timeout: float) -> str:
        if self.inject_first_read_failure:
            self.inject_first_read_failure = False
            raise ConnectionError("injected one-shot ADB read failure")
        if str(path).startswith("/data/data/"):
            try:
                return self.run(
                    ("adb", "-s", self.device, "exec-out", "run-as", PACKAGE, "cat", str(path)),
                    timeout=timeout,
                ).stdout
            except RuntimeError as error:
                if str(path) in _POLLABLE_FIXTURE_PATHS:
                    raise AcceptanceNotReadyError("timed fixture evidence is not published") from error
                raise
        deadline = time.monotonic() + timeout
        if timeout <= 0:
            raise RuntimeError("host report read timeout must be positive")
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as error:
            raise RuntimeError("host report is not a bounded regular file") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
                raise RuntimeError("host report is not a bounded regular file")
            chunks = _read_regular_in_worker(
                descriptor, metadata.st_size, deadline=deadline,
            )
        finally:
            os.close(descriptor)
        if len(chunks) != metadata.st_size:
            raise RuntimeError("host report is not a bounded regular file")
        return chunks.decode("utf-8", errors="strict")

    def read_text_beneath(self, root: Path | RootedReader, relative: Path, *, timeout: float) -> str:
        if timeout <= 0:
            raise RuntimeError("bounded report read timeout must be positive")
        deadline = time.monotonic() + timeout
        value = _read_root(root, str(relative), deadline=deadline)
        if time.monotonic() >= deadline:
            raise RuntimeError("bounded report read exceeded timeout")
        return value.decode("utf-8", errors="strict")


class OneShotArtifactRead:
    """Acceptance-only wrapper: fail exactly one artifact read, never disturb adbd."""
    def __init__(self, client: object) -> None:
        self.client = client
        self.failed = False

    def read_file(self, name: str, *, maximum_bytes: int) -> bytes:
        if not self.failed:
            self.failed = True
            raise ConnectionError("injected acceptance artifact read failure")
        return self.client.read_file(name, maximum_bytes=maximum_bytes)


def _read_retry(runner: Runner, path: Path, *, timeout: float,
                deadline: float | None = None) -> str:
    if timeout <= 0:
        raise ValueError("read timeout must be positive")
    final_deadline = time.monotonic() + timeout if deadline is None else deadline
    def read_once() -> str:
        remaining = final_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("read deadline elapsed before retry")
        return runner.read_text(path, timeout=remaining)
    try:
        return read_once()
    except ConnectionError:
        return read_once()


def _read_retry_beneath(runner: Runner, root: Path, relative: Path, *, timeout: float,
                        deadline: float | None = None) -> str:
    """Read a local acceptance result only through its trusted output root."""
    if timeout <= 0:
        raise ValueError("read timeout must be positive")
    final_deadline = time.monotonic() + timeout if deadline is None else deadline

    def read_once() -> str:
        remaining = final_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("read deadline elapsed before retry")
        return runner.read_text_beneath(root, relative, timeout=remaining)

    try:
        return read_once()
    except ConnectionError:
        return read_once()


def _strict_json(raw: str) -> dict[str, object]:
    def duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def nonfinite(_: str) -> object:
        raise ValueError("non-finite JSON number")
    value = json.loads(raw, object_pairs_hook=duplicate, parse_constant=nonfinite)
    if type(value) is not dict:
        raise ValueError("JSON root is not an object")
    return value


def _strict_report(runner: Runner, root: Path, relative: Path) -> dict[str, object]:
    try:
        return _strict_json(_read_retry_beneath(runner, root, relative, timeout=5.0))
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("qtrace report is not strict JSON") from error


_SESSION_REPORT_KEYS = frozenset((
    "artifacts", "device", "effective_config", "error", "finished_at", "mode", "native",
    "outputs", "package", "pid", "schema", "serial", "session_id", "stage", "started_at",
    "status", "target", "timeline", "tracer", "warnings",
))
_PULL_REPORT_KEYS = frozenset(("schema", "sessionId", "artifacts", "errors"))
_PULL_ARTIFACT_KEYS = frozenset((
    "remote_name", "local_path", "source_size", "destination_size", "sha256", "decoder",
    "termination", "stop_reason", "metrics_schema", "producer_waits", "producer_wait_ns",
    "conversion_ms", "native_stop_acknowledged", "host_observed_ack_ms",
))
_PULL_FLIGHT_ARTIFACT_KEYS = _PULL_ARTIFACT_KEYS | {"recovery_status"}


def _strict_session_report(runner: Runner, root: Path, relative: Path) -> dict[str, object]:
    value = _strict_report(runner, root, relative)
    if set(value) != _SESSION_REPORT_KEYS:
        raise RuntimeError("session report has unexpected fields")
    if (value.get("schema") != 1 or not isinstance(value.get("session_id"), str) or
            not isinstance(value.get("status"), str) or not isinstance(value.get("stage"), str) or
            not isinstance(value.get("package"), str) or type(value.get("pid")) is not int or
            not isinstance(value.get("artifacts"), list) or not isinstance(value.get("outputs"), list) or
            not isinstance(value.get("timeline"), list) or not isinstance(value.get("native"), dict)):
        raise RuntimeError("session report has invalid field types")
    return value


def _strict_pull_report(runner: Runner, root: Path, relative: Path) -> dict[str, object]:
    value = _strict_report(runner, root, relative)
    if set(value) != _PULL_REPORT_KEYS or value.get("schema") != 1:
        raise RuntimeError("pull report has unexpected fields")
    if (not isinstance(value.get("sessionId"), str) or not isinstance(value.get("artifacts"), list)
            or not isinstance(value.get("errors"), list)):
        raise RuntimeError("pull report has invalid field types")
    return value


def _wait_for_baseline(runner: Runner) -> dict[str, object]:
    deadline = time.monotonic() + 15.0
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            value = _strict_json(_read_retry(
                runner, Path(BASELINE_PATH), timeout=min(2.0, remaining), deadline=deadline,
            ))
            if (type(value) is dict and value.get("iterations") == ITERATIONS and
                    value.get("seed") == SEED and isinstance(value.get("result"), str)):
                return value
            raise ValueError("baseline has an invalid fixture result")
        except (AcceptanceNotReadyError, ConnectionError, OSError, ValueError,
                json.JSONDecodeError) as error:
            last_error = error
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.25, remaining))
    raise RuntimeError(f"timed baseline was not available within 15 seconds: {last_error}")


def _report_path(stdout: str, root: Path | RootedReader) -> Path:
    candidates = [Path(line.strip()) for line in stdout.splitlines() if line.strip().endswith("report.json")]
    if len(candidates) != 1:
        raise RuntimeError("qtrace demo did not publish exactly one report path")
    report = candidates[0]
    try:
        root_path = root.path if isinstance(root, RootedReader) else root
        relative = report.relative_to(root_path) if report.is_absolute() else report
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ValueError("unsafe report path")
    except ValueError as error:
        raise RuntimeError("qtrace reported a path outside its trusted output directory") from error
    return relative


def _published_report_path(stdout: str, root: Path | RootedReader) -> Path:
    if not stdout.strip():
        raise RuntimeError("qtrace command did not publish a report path")
    return _report_path(stdout, root)


def _trusted_output(path: Path, root: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve())
        metadata = resolved.lstat()
    except (OSError, ValueError) as error:
        raise RuntimeError("reported output is outside the trusted directory") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError("reported output is not a regular non-symlink file")
    return resolved


def _read_beneath(root: Path, relative: str, maximum_bytes: int = 1_048_576,
                  *, deadline: float | None = None) -> bytes:
    """Read one regular file through held no-follow directory descriptors."""
    with RootedReader(root) as held:
        return held.read_bytes(relative, maximum_bytes, deadline=deadline)


def _read_root(root: Path | RootedReader, relative: str, maximum_bytes: int = 1_048_576,
               *, deadline: float | None = None) -> bytes:
    if isinstance(root, RootedReader):
        return root.read_bytes(relative, maximum_bytes, deadline=deadline)
    return _read_beneath(root, relative, maximum_bytes, deadline=deadline)


def _validated_timed_report(runner: Runner, root: Path | RootedReader, relative: Path) -> tuple[dict[str, object], str]:
    value = _strict_session_report(runner, root, relative)
    if (type(value) is not dict or value.get("schema") != 1 or value.get("status") != "sealed" or
            value.get("stage") != "completed" or value.get("package") != PACKAGE):
        raise RuntimeError("timed qtrace report is incomplete")
    if relative != Path(value["session_id"]) / "report.json":
        raise RuntimeError("session report is not in its session directory")
    native = value.get("native")
    status = native.get("status") if isinstance(native, dict) else None
    if (not isinstance(status, dict) or status.get("state") != "sealed" or
            status.get("reason") != "duration_elapsed" or status.get("stopAcknowledged") is not True):
        raise RuntimeError("timed trace did not detach/seal after native duration stop")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeError("timed report has no artifact records")
    for record in artifacts:
        if not isinstance(record, dict):
            raise RuntimeError("timed report has an invalid artifact record")
        name = record.get("remote_name")
        if name is not None and (not isinstance(name, str) or not name or "/" in name or "\\" in name
                                 or any(ord(character) < 32 or ord(character) == 127 for character in name)):
            raise RuntimeError("timed report artifact is not a safe basename")
        local = record.get("local_path")
        if local is not None and (not isinstance(local, str) or not local.startswith("artifacts/")
                                  or local == "artifacts/" or ".." in Path(local).parts):
            raise RuntimeError("timed report artifact path is unsafe")
    roots = [record.get("remote_name") for record in artifacts if isinstance(record, dict) and
             isinstance(record.get("remote_name"), str) and
             (record["remote_name"].endswith(".trace.bin") or
              record["remote_name"].endswith(".trace.bin.lz4"))]
    if len(roots) != 1:
        raise RuntimeError("timed report lacks a trusted binary artifact name")
    artifact = roots[0]
    if "/" in artifact or "\\" in artifact or artifact in {"", ".", ".."}:
        raise RuntimeError("timed report artifact is not a safe basename")
    names = {record.get("remote_name") for record in artifacts if isinstance(record, dict)}
    if artifact + ".metrics" not in names:
        raise RuntimeError("timed binary root has no matching metrics sidecar record")
    if type(value.get("pid")) is not int or value["pid"] <= 0:
        raise RuntimeError("timed report does not retain its traced app PID")
    timeline = value.get("timeline")
    stages = [item.get("stage") for item in timeline] if isinstance(timeline, list) and all(isinstance(item, dict) for item in timeline) else []
    if "installing_hooks" not in stages or "running" not in stages or stages.index("installing_hooks") > stages.index("running"):
        raise RuntimeError("report lacks installed-action-before-running detach evidence")
    return value, artifact


def _validated_monitor_report(runner: Runner, root: Path | RootedReader, relative: Path, *, status: str) -> dict[str, object]:
    report = _strict_session_report(runner, root, relative)
    if report.get("schema") != 1 or report.get("package") != PACKAGE or report.get("status") != status:
        raise RuntimeError("monitor report has an invalid classification")
    if relative != Path(report["session_id"]) / "report.json":
        raise RuntimeError("session report is not in its session directory")
    return report


def _validate_timed_fixture_receipt(
    report: dict[str, object], receipt_raw: str, entry_status_raw: str,
) -> None:
    try:
        receipt = _strict_json(receipt_raw)
        entry_status = validate_status_shape(load_strict_json(
            entry_status_raw.encode("utf-8"), maximum_bytes=64 * 1024,
        ))
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("timed fixture entry evidence is not strict native JSON") from error
    if (set(receipt) != {"sessionId", "nonce", "entryMonotonicNs"} or
            receipt.get("sessionId") != report.get("session_id") or
            type(receipt.get("nonce")) is not str or _UUID4.fullmatch(receipt["nonce"]) is None or
            type(receipt.get("entryMonotonicNs")) is not int or receipt["entryMonotonicNs"] <= 0):
        raise RuntimeError("timed fixture receipt does not identify native entry")
    final_native = report.get("native")
    final_status = final_native.get("status") if isinstance(final_native, dict) else None
    if (not isinstance(final_status, dict) or
            report.get("package") != PACKAGE or
            entry_status["sessionId"] != report.get("session_id") or
            entry_status["packageName"] != report.get("package") or
            final_status.get("sessionId") != report.get("session_id") or
            final_status.get("packageName") != report.get("package") or
            final_status.get("pid") != report.get("pid") or
            entry_status["pid"] != report.get("pid") or
            entry_status["generation"] != final_status.get("generation") or
            entry_status["normalizedScenes"] != final_status.get("normalizedScenes") or
            entry_status["state"] != "running" or entry_status["reason"] != "" or
            entry_status["stopAcknowledged"] is not False or
            type(entry_status["deadlineMonotonicNs"]) is not int or
            entry_status["deadlineMonotonicNs"] <= 0 or
            entry_status["deadlineMonotonicNs"] != final_status.get("deadlineMonotonicNs") or
            entry_status["transitionMonotonicNs"] > receipt["entryMonotonicNs"] or
            receipt["entryMonotonicNs"] >= entry_status["deadlineMonotonicNs"]):
        raise RuntimeError("timed fixture entry status does not prove armed native entry")
    timeline = report.get("timeline")
    installing = [item for item in timeline if isinstance(item, dict) and
                  item.get("stage") == "installing_hooks"] if isinstance(timeline, list) else []
    if (len(installing) != 1 or installing[0].get("cleanup_detached") is not True or
            installing[0].get("action_nonce") != receipt["nonce"]):
        raise RuntimeError("timed report lacks injector cleanup/detach receipt")


def _wait_for_timed_fixture_evidence(
    runner: Runner, report: dict[str, object], *, timeout: float = 5.0,
) -> tuple[str, str]:
    """Poll atomic fixture evidence until it belongs to this installed action."""
    if timeout <= 0:
        raise ValueError("fixture evidence timeout must be positive")
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            remaining = deadline - time.monotonic()
            receipt = _read_retry(
                runner, Path(RECEIPT_PATH), timeout=min(1.0, remaining),
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            entry_status = _read_retry(
                runner, Path(ENTRY_STATUS_PATH), timeout=min(1.0, remaining),
            )
            _validate_timed_fixture_receipt(report, receipt, entry_status)
            return receipt, entry_status
        except (AcceptanceNotReadyError, ConnectionError, OSError, RuntimeError,
                UnicodeError, ValueError, json.JSONDecodeError) as error:
            last_error = error
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.1, remaining))
    raise RuntimeError(
        f"timed native entry evidence was not available within {timeout:g} seconds: {last_error}"
    )


def _wait_for_timed_result(runner: Runner, *, timeout: float = 5.0) -> dict[str, object]:
    if timeout <= 0:
        raise ValueError("timed result timeout must be positive")
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            remaining = deadline - time.monotonic()
            value = _strict_json(_read_retry(
                runner, Path(TIMED_RESULT_PATH), timeout=min(1.0, remaining),
            ))
            if (value.get("iterations") == ITERATIONS and value.get("seed") == SEED and
                    isinstance(value.get("result"), str)):
                return value
            raise ValueError("timed result has an invalid fixture result")
        except (AcceptanceNotReadyError, ConnectionError, OSError, RuntimeError,
                UnicodeError, ValueError, json.JSONDecodeError) as error:
            last_error = error
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.1, remaining))
    raise RuntimeError(f"timed result was not available within {timeout:g} seconds: {last_error}")


def _convert_snapshot_bounded(snapshot: Path, destination: Path, *, lz4: str | None,
                              deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("timed artifact conversion exceeded deadline")
    command = [sys.executable, "-m", "scripts.trace_convert", str(snapshot), "--output",
               str(destination), "--force"]
    if lz4 is not None:
        command.extend(("--lz4", lz4))
    try:
        capture_bounded(command, maximum_bytes=64 * 1024, timeout=remaining)
    except (BoundedProcessError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("timed artifact conversion failed within deadline") from error


def _validate_timed_artifact_semantics(runner: Runner, report: dict[str, object], root: Path | RootedReader, *,
                                       converter=None) -> None:
    deadline = time.monotonic() + 15.0
    records = report.get("artifacts")
    if not isinstance(records, list):
        raise RuntimeError("timed report has no artifact semantics")
    binary = [record for record in records if isinstance(record, dict) and
              isinstance(record.get("remote_name"), str) and
              (record["remote_name"].endswith(".trace.bin") or
               record["remote_name"].endswith(".trace.bin.lz4"))]
    if len(binary) != 1:
        raise RuntimeError("timed trace must publish exactly one binary artifact")
    record = binary[0]
    remote_name = record.get("remote_name")
    local_path = record.get("local_path")
    if (not isinstance(remote_name, str) or not isinstance(local_path, str) or
            Path(local_path).name != remote_name):
        raise RuntimeError("timed binary record has no trusted local artifact identity")
    binary_bytes = _read_root(root, local_path, deadline=deadline)
    metrics_name = remote_name + ".metrics"
    if not any(isinstance(item, dict) and item.get("remote_name") == metrics_name
               for item in records):
        raise RuntimeError("timed binary root has no matching metrics sidecar record")
    metrics_relative = local_path + ".metrics"
    metrics_bytes = _read_root(root, metrics_relative, MAX_METRICS_BYTES, deadline=deadline)
    if (record.get("termination") != "stopped" or record.get("metrics_schema") != 3 or
            record.get("native_stop_acknowledged") is not True):
        raise RuntimeError("binary TRACE_STOP/metrics-v3 native-stop contract failed")
    with tempfile.TemporaryDirectory(prefix=".qtrace-acceptance-validate-") as staging:
        snapshot = Path(staging) / remote_name
        snapshot.write_bytes(binary_bytes)
        Path(str(snapshot) + ".metrics").write_bytes(metrics_bytes)
        converted = Path(staging) / "converted.trace.txt"
        if converter is None:
            _convert_snapshot_bounded(snapshot, converted,
                                      lz4="lz4" if remote_name.endswith(".lz4") else None,
                                      deadline=deadline)
        else:
            stats = converter(snapshot, converted,
                              lz4="lz4" if remote_name.endswith(".lz4") else None,
                              crash_marked=False)
            if getattr(stats, "termination", None) != "stopped" or getattr(stats, "partial", True):
                raise RuntimeError("timed binary conversion was not a complete stopped trace")
        text = _read_root(Path(staging), converted.name, deadline=deadline).decode("utf-8", errors="strict")
        lines = text.splitlines()
        terminals = [line for line in lines if line.startswith("TRACE_END ")]
        if (not lines or not lines[0].startswith("TRACE_BEGIN format=4 ") or len(terminals) != 1 or
                not terminals[0].startswith(
                    "TRACE_END status=stopped reason=duration_elapsed return_valid=0 ")):
            raise RuntimeError("timed binary does not contain one duration_elapsed TRACE_STOP terminal")


def _verify_artifact_read_recovery(device: str, report: dict[str, object], root: Path | RootedReader, *,
                                   artifact_client_factory=AdbArtifactClient) -> None:
    """Exercise one real app-private artifact read failure without restarting adbd."""
    deadline = time.monotonic() + 15.0
    records = report.get("artifacts")
    if not isinstance(records, list):
        raise RuntimeError("timed report has no artifact records for recovery verification")
    binary = [record for record in records if isinstance(record, dict) and
              isinstance(record.get("remote_name"), str) and
              (record["remote_name"].endswith(".trace.bin") or
               record["remote_name"].endswith(".trace.bin.lz4"))]
    if len(binary) != 1 or not isinstance(binary[0].get("local_path"), str):
        raise RuntimeError("timed report has no trusted binary identity for recovery verification")
    local_path = Path(binary[0]["local_path"])
    metrics_name = str(binary[0]["remote_name"]) + ".metrics"
    metrics_relative = Path(str(local_path) + ".metrics")
    before = _read_root(root, str(metrics_relative), MAX_METRICS_BYTES,
                        deadline=deadline)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("artifact recovery verification exceeded deadline")
    client = artifact_client_factory(package=PACKAGE, device=device, timeout=remaining)
    wrapped = OneShotArtifactRead(client)
    try:
        wrapped.read_file(metrics_name, maximum_bytes=MAX_METRICS_BYTES)
    except ConnectionError:
        # The first failure is deliberately before delegating; verify the same
        # trusted session evidence remains intact before retrying the same client.
        if _read_root(root, str(metrics_relative), MAX_METRICS_BYTES,
                      deadline=deadline) != before:
            raise RuntimeError("artifact evidence changed after injected read failure")
    else:
        raise RuntimeError("injected artifact read unexpectedly succeeded")
    remote = wrapped.read_file(metrics_name, maximum_bytes=MAX_METRICS_BYTES)
    if time.monotonic() >= deadline:
        raise RuntimeError("artifact recovery verification exceeded deadline")
    if remote != before:
        raise RuntimeError("artifact retry did not recover the same metrics evidence")


def _demo_command(device: str, scenario: str, form: str, output: Path) -> tuple[str, ...]:
    return ("python3", "-m", "qtrace", "demo", "--scenario", scenario,
            *( ("--duration", "2s") if scenario == "timed" else () ),
            "--scene-form", form, "--device", device, "--output", str(output))


def _verify_pull_outputs(root: Path) -> None:
    """Pull itself validates binary terminal/metrics/text conversion contracts.

    The report is the authoritative artifact selector; no device directory listing is used here.
    """
    expected = ("latest", "name", "all", "compressed")
    missing = [name for name in expected if not (root / name).exists()]
    if missing:
        raise RuntimeError("manual pull did not publish output directories: " + ",".join(missing))


def _validated_pull_report(runner: Runner, stdout: str, root: Path | RootedReader, *, named: str | None = None,
                           compressed_only: bool = False) -> dict[str, object]:
    relative = _published_report_path(stdout, root)
    report = _strict_pull_report(runner, root, relative)
    session_id = report["sessionId"]
    if (_UUID4.fullmatch(session_id) is None or
            relative != Path(session_id) / "report.json"):
        raise RuntimeError("pull report is not in its session directory")
    if report["errors"] != []:
        raise RuntimeError("manual pull report contains errors")
    records = report.get("artifacts")
    if not isinstance(records, list) or not records:
        raise RuntimeError("manual pull report has no artifact records")
    names: set[str] = set()
    for item in records:
        if not isinstance(item, dict) or set(item) not in {
                _PULL_ARTIFACT_KEYS, _PULL_FLIGHT_ARTIFACT_KEYS}:
            raise RuntimeError("manual pull report has an invalid artifact record")
        name, local = item["remote_name"], item["local_path"]
        local_parts = Path(local).parts if isinstance(local, str) else ()
        if (not isinstance(name, str) or not name or Path(name).name != name or
                local_parts != ("artifacts", name)):
            raise RuntimeError("manual pull report has an unsafe artifact path")
        if (type(item["source_size"]) not in {int, type(None)} or
                type(item["destination_size"]) is not int or
                any(value is not None and value < 0 for value in
                    (item["source_size"], item["destination_size"])) or
                not isinstance(item["sha256"], str) or len(item["sha256"]) != 64 or
                any(character not in "0123456789abcdef" for character in item["sha256"])):
            raise RuntimeError("manual pull report has invalid artifact metadata")
        decoder = item["decoder"]
        if decoder not in {None, "qtrb", "flight", "lz4-text", "legacy", "sidecar"}:
            raise RuntimeError("manual pull report has invalid artifact status")
        if item["stop_reason"] is not None and type(item["stop_reason"]) is not str:
            raise RuntimeError("manual pull report has invalid artifact status")
        if any(value is not None and type(value) is not int for value in (
                item["metrics_schema"], item["producer_waits"], item["producer_wait_ns"])) or \
                any(value is not None and (type(value) not in {int, float} or
                                           not math.isfinite(value) or value < 0) for value in (
                    item["conversion_ms"], item["host_observed_ack_ms"])):
            raise RuntimeError("manual pull report has invalid artifact counters")
        if any(value is not None and value < 0 for value in (
                item["metrics_schema"], item["producer_waits"], item["producer_wait_ns"])):
            raise RuntimeError("manual pull report has invalid artifact counters")
        if item["native_stop_acknowledged"] is not None and type(item["native_stop_acknowledged"]) is not bool:
            raise RuntimeError("manual pull report has invalid stop acknowledgement")
        termination = item["termination"]
        if decoder == "flight":
            recovery = item.get("recovery_status")
            if (set(item) != _PULL_FLIGHT_ARTIFACT_KEYS or recovery != "complete" or
                    type(termination) is not dict or
                    set(termination) != {"cause", "initiator_tid"} or
                    termination.get("cause") not in {"unknown", "termination_intent"} or
                    (termination["cause"] == "unknown" and
                     termination.get("initiator_tid") is not None) or
                    (termination["cause"] == "termination_intent" and
                     (type(termination.get("initiator_tid")) is not int or
                      termination["initiator_tid"] <= 0))):
                raise RuntimeError("manual pull report has invalid flight recovery status")
        elif (set(item) != _PULL_ARTIFACT_KEYS or
              (decoder == "qtrb" and termination not in {"completed", "stopped"}) or
              (decoder == "lz4-text" and termination != "completed") or
              (decoder in {None, "legacy", "sidecar"} and termination is not None)):
            raise RuntimeError("manual pull report has invalid decoder status")
        if isinstance(root, RootedReader):
            details = root.stat_regular(relative.parent / local)
        else:
            with RootedReader(root) as held:
                details = held.stat_regular(relative.parent / local)
        if details.size != item["destination_size"]:
            raise RuntimeError("manual pull artifact destination size does not match report")
        if name in names:
            raise RuntimeError("manual pull report repeats an artifact name")
        names.add(name)
    if named is not None and named not in names:
        raise RuntimeError("named pull report omitted the trusted artifact")
    if compressed_only and any(isinstance(name, str) and name.endswith(".trace.txt") for name in names):
        raise RuntimeError("compressed-only pull published a decoded text artifact")
    return report


@dataclass
class _HistoricalGateState:
    phase: str = "host"
    current: HostBinarySnapshot | None = None
    pair: HeldTracerPair | None = None
    historical: HistoricalBenchmarkApk | None = None
    builder_report: dict[str, object] | None = None
    archive_manifest: tuple[tuple[tuple[str, object], ...], ...] = ()
    archive_sha256: str | None = None
    recovery_active: bool = False


_MAX_EVIDENCE_BYTES = 1024 * 1024
_MAX_EVIDENCE_STRING_BYTES = 4096
_MAX_EVIDENCE_ITEMS = 512


def _bounded_evidence_value(value: object, *, depth: int = 0) -> object:
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        if len(encoded) <= _MAX_EVIDENCE_STRING_BYTES:
            return value
        prefix = encoded[:_MAX_EVIDENCE_STRING_BYTES]
        while True:
            try:
                decoded = prefix.decode("utf-8")
                break
            except UnicodeDecodeError:
                prefix = prefix[:-1]
        return {
            "truncated": True,
            "original_bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "prefix": decoded,
        }
    if value is None or type(value) in {bool, int, float}:
        return value
    if depth >= 12:
        encoded = repr(value).encode("utf-8", errors="replace")
        return {
            "truncated": True, "reason": "maximum depth",
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    if isinstance(value, dict):
        items = list(value.items())
        bounded = {
            str(key): _bounded_evidence_value(item, depth=depth + 1)
            for key, item in items[:_MAX_EVIDENCE_ITEMS]
        }
        if len(items) > _MAX_EVIDENCE_ITEMS:
            encoded = repr(items[_MAX_EVIDENCE_ITEMS:]).encode(
                "utf-8", errors="replace",
            )
            bounded["__truncation__"] = {
                "truncated": True,
                "omitted_items": len(items) - _MAX_EVIDENCE_ITEMS,
                "sha256": hashlib.sha256(encoded).hexdigest(),
            }
        return bounded
    if isinstance(value, (list, tuple)):
        bounded = [
            _bounded_evidence_value(item, depth=depth + 1)
            for item in value[:_MAX_EVIDENCE_ITEMS]
        ]
        if len(value) > _MAX_EVIDENCE_ITEMS:
            encoded = repr(value[_MAX_EVIDENCE_ITEMS:]).encode(
                "utf-8", errors="replace",
            )
            bounded.append({
                "truncated": True,
                "omitted_items": len(value) - _MAX_EVIDENCE_ITEMS,
                "sha256": hashlib.sha256(encoded).hexdigest(),
            })
        return bounded
    return _bounded_evidence_value(repr(value), depth=depth + 1)


def _failure_record(label: str, error: BaseException) -> dict[str, object]:
    record: dict[str, object] = {
        "label": label, "type": type(error).__name__, "message": str(error),
    }
    report = getattr(error, "report", None)
    if isinstance(report, dict):
        record["report"] = _bounded_evidence_value(report)
    return record


def _gate_evidence(state: _HistoricalGateState, primary: BaseException,
                   cleanup_errors: Sequence[dict[str, object]]) -> dict[str, object]:
    historical = state.historical
    report = state.builder_report or {}
    manifest = [dict(item) for item in state.archive_manifest]
    if not manifest and isinstance(report.get("manifest"), list):
        manifest = report["manifest"]
    archive_sha256 = state.archive_sha256 or report.get("archive_sha256")
    pair, current = state.pair, state.current
    primary_error = _failure_record("primary", primary)
    primary_error.pop("label")
    evidence = {
        "schema": 1, "phase": state.phase,
        "historical_commit": HISTORICAL_COMMIT,
        "historical_apk_sha256": historical.apk_sha256 if historical else None,
        "current_apk_sha256": current.sha256 if current else None,
        "target_raw_sha256": historical.target_raw_sha256 if historical else None,
        "target_canonical_sha256": historical.target_canonical_sha256 if historical else None,
        "tracer_sha256": pair.tracer.sha256 if pair else None,
        "companion_sha256": pair.companion.sha256 if pair else None,
        "archive_manifest": manifest,
        "archive_sha256": archive_sha256,
        "command": report.get("command"),
        "primary_error": primary_error,
        "cleanup_errors": list(cleanup_errors),
    }
    if report:
        evidence["historical_report"] = report
    bounded = _bounded_evidence_value(evidence)
    if not isinstance(bounded, dict):
        raise RuntimeError("historical benchmark gate evidence has invalid shape")
    return bounded


def _publish_gate_failure_evidence(directory: Path, state: _HistoricalGateState,
                                   primary: BaseException,
                                   cleanup_errors: Sequence[dict[str, object]]) -> None:
    payload = json.dumps(
        _gate_evidence(state, primary, cleanup_errors), allow_nan=False,
        ensure_ascii=False, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
    if len(payload) > _MAX_EVIDENCE_BYTES:
        raise RuntimeError("historical benchmark gate evidence exceeds 1 MiB")
    temporary = directory / f".historical-benchmark-gate.{uuid.uuid4().hex}.tmp"
    destination = directory / "historical-benchmark-gate.json"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("historical benchmark gate evidence write failed")
            view = view[written:]
        os.fsync(descriptor)
        closing = descriptor
        descriptor = -1
        os.close(closing)
        os.replace(temporary, destination)
    except BaseException as primary_failure:
        cleanup_failures = []
        if descriptor >= 0:
            closing = descriptor
            descriptor = -1
            try:
                os.close(closing)
            except BaseException as error:
                cleanup_failures.append(("descriptor close", error))
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except BaseException as error:
            cleanup_failures.append(("temporary unlink", error))
        if cleanup_failures:
            details = "; ".join(
                f"{label}: {type(error).__name__}: {error}"
                for label, error in cleanup_failures
            )
            raise RuntimeError(
                f"historical benchmark gate evidence publication failed: "
                f"{type(primary_failure).__name__}: {primary_failure}; "
                f"cleanup failed: {details}"
            ) from primary_failure
        raise
    else:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _collect_gate_cleanup(actions: Sequence[tuple[str, Callable[[], None]]],
                          ) -> list[dict[str, object]]:
    failures = []
    for label, action in actions:
        try:
            action()
        except BaseException as error:
            failures.append(_failure_record(label, error))
    return failures


def _current_snapshot_tree_cleanup(current: HostBinarySnapshot) -> None:
    root = current.path.parent
    if root.name.startswith("qtrace-current-inputs-"):
        shutil.rmtree(root)


def _raise_gate_failure(primary: BaseException,
                        cleanup_errors: Sequence[dict[str, object]]) -> None:
    if not cleanup_errors:
        raise primary
    detail = "; ".join(
        f"{item['label']}: {item['type']}: {item['message']}"
        for item in cleanup_errors
    )
    raise RuntimeError(
        f"qtrace historical benchmark gate failed: {type(primary).__name__}: "
        f"{primary}; cleanup failed: {detail}"
    ) from primary


def _gate_resource_cleanup(state: _HistoricalGateState) -> list[dict[str, object]]:
    actions: list[tuple[str, Callable[[], None]]] = []
    if state.historical is not None:
        actions.append(("historical APK close", state.historical.close))
    if state.current is not None:
        actions.append(("current APK close", state.current.close))
    if state.pair is not None:
        actions.extend((
            ("tracer snapshot close", state.pair.tracer.close),
            ("companion snapshot close", state.pair.companion.close),
        ))
    if state.current is not None:
        actions.append((
            "current input snapshot tree cleanup",
            lambda: _current_snapshot_tree_cleanup(state.current),
        ))
    return _collect_gate_cleanup(actions)


def _finalize_gate_failure(
        device: str, directory: Path, *, runner: Runner,
        state: _HistoricalGateState, primary: BaseException,
        initial_cleanup_errors: Sequence[dict[str, object]] = (),
        cleanup_resources: bool = True,
        cleanup_after_recovery: Sequence[tuple[str, Callable[[], None]]] = ()) -> None:
    cleanup_errors = list(initial_cleanup_errors)
    if state.recovery_active and state.current is not None:
        cleanup_errors.extend(_collect_gate_cleanup((
            ("recovery force-stop before current install",
             lambda: runner.run(("adb", "-s", device, "shell", "am", "force-stop", PACKAGE), timeout=30.0)),
            ("recovery current APK install",
             lambda: _install_held_apk(device, runner, state.current)),
            ("recovery force-stop after current install",
             lambda: runner.run(("adb", "-s", device, "shell", "am", "force-stop", PACKAGE), timeout=30.0)),
        )))
    if cleanup_resources:
        cleanup_errors.extend(_gate_resource_cleanup(state))
    cleanup_errors.extend(_collect_gate_cleanup(cleanup_after_recovery))
    try:
        _publish_gate_failure_evidence(directory, state, primary, cleanup_errors)
    except BaseException as error:
        cleanup_errors.append(_failure_record("failure evidence publication", error))
    _raise_gate_failure(primary, cleanup_errors)


def _run_current_fixture_phase(device: str, directory: Path, *, runner: Runner,
                               state: _HistoricalGateState, converter=None,
                               artifact_client_factory=AdbArtifactClient) -> None:
    state.phase = "start-timed-baseline"
    runner.run(("adb", "-s", device, "shell", "am", "start", "-n", ACTIVITY,
                "--ez", "qtrace_acceptance", "true", "--es", "qtrace_acceptance_mode", "timed",
                "--el", "qtrace_acceptance_seed", str(SEED), "--el", "qtrace_acceptance_iterations", str(ITERATIONS)), timeout=30.0)
    state.phase = "wait-timed-baseline"
    baseline = _wait_for_baseline(runner)
    with ExitStack() as held_roots:
        reports: dict[str, tuple[RootedReader, Path]] = {}
        timed_reports: dict[str, tuple[dict[str, object], str]] = {}
        timed_evidence: dict[str, tuple[str, str]] = {}
        for scenario, form, name in (("timed", "offset", "offset"), ("timed", "symbol", "symbol"), ("monitor-exit", "offset", "exit"), ("flight-crash", "offset", "crash")):
            state.phase = f"{scenario}-{form}"
            output = directory / name
            published = runner.run(_demo_command(device, scenario, form, output), timeout=180.0,
                                   allowed=(0, 2) if scenario == "flight-crash" else (0,))
            held = held_roots.enter_context(RootedReader(output))
            reports[name] = (held, _published_report_path(published.stdout, held))
            if scenario == "timed":
                preview, preview_artifact = _validated_timed_report(runner, *reports[name])
                timed_reports[name] = preview, preview_artifact
                timed_evidence[name] = _wait_for_timed_fixture_evidence(
                    runner, preview, timeout=5.0,
                )
            if scenario == "flight-crash" and published.returncode != 2:
                raise RuntimeError("flight-crash must publish crash recovery with exit code 2")
        timed, artifact = timed_reports["offset"]
        _validate_timed_fixture_receipt(timed, *timed_evidence["offset"])
        symbol, _ = timed_reports["symbol"]
        _validate_timed_fixture_receipt(symbol, *timed_evidence["symbol"])
        _validate_timed_artifact_semantics(
            runner, timed, reports["offset"][0], converter=converter,
        )
        _verify_artifact_read_recovery(
            device, timed, reports["offset"][0],
            artifact_client_factory=artifact_client_factory,
        )
        timed_status = timed["native"]["status"]  # validated above
        symbol_status = symbol["native"]["status"]
        if timed_status["normalizedScenes"] != symbol_status["normalizedScenes"]:
            raise RuntimeError("offset and symbol timed scenes did not normalize identically")
        _validated_monitor_report(runner, *reports["exit"], status="process_exited")
        _validated_monitor_report(runner, *reports["crash"], status="crash_recovered")
    runner.run(("adb", "-s", device, "shell", "kill", "-0", str(timed["pid"])), timeout=10.0)
    timed_oracle = _wait_for_timed_result(runner, timeout=5.0)
    if timed_oracle != baseline:
        raise RuntimeError("long timed target did not return the baseline oracle value")
    pulls = (("latest", ("--latest",), None, False), ("name", ("--name", artifact), artifact, False), ("all", ("--all",), None, False), ("compressed", ("--all", "--compressed-only"), None, True))
    for name, selector, expected, compressed in pulls:
        state.phase = f"pull-{name}"
        output = directory / name
        result = runner.run(("python3", "-m", "qtrace", "pull", "--package", PACKAGE, *selector, "--device", device, "--output", str(output)), timeout=180.0)
        with RootedReader(output) as held:
            _validated_pull_report(runner, result.stdout, held, named=expected,
                                   compressed_only=compressed)
    _verify_pull_outputs(directory)


def run_acceptance(device: str, directory: Path, *, runner: Runner,
                   converter=None, artifact_client_factory=AdbArtifactClient,
                   historical_builder=build_historical_benchmark_apk) -> int:
    if not device:
        raise ValueError("--device is required for manual acceptance")
    directory.mkdir(parents=True, exist_ok=True)
    state = _HistoricalGateState()
    try:
        runner.run(("./gradlew", "nativeHostTest", "--no-daemon"), timeout=900.0)
        runner.run(("python3", "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"), timeout=300.0)
        runner.run(("./gradlew", ":app:assembleDebug", ":tracer:copyTracerDebug", "--no-daemon"), timeout=900.0)
        state.phase = "snapshot-current"
        state.current, state.pair = _snapshot_current_inputs(
            deadline=time.monotonic() + _HOST_BINARY_SNAPSHOT_SECONDS,
        )
        state.phase = "build-historical"
        state.historical = historical_builder(
            Path.cwd(), deadline=time.monotonic() + _HISTORICAL_BUILD_SECONDS,
        )
        historical, current, pair = state.historical, state.current, state.pair
        state.archive_manifest = historical.archive_manifest
        state.archive_sha256 = historical.archive_sha256

        state.phase = "install-historical"
        _install_held_apk(device, runner, historical)
        state.recovery_active = True
        state.phase = "force-stop-historical"
        runner.run(("adb", "-s", device, "shell", "am", "force-stop", PACKAGE), timeout=30.0)
        state.phase = "stage-historical"
        _stage_app_private_binaries(
            device, runner, token=uuid.uuid4().hex, pair=pair, package=PACKAGE,
        )
        state.phase = "compare-historical"
        runner.run((
            "python3", "scripts/benchmark_trace.py", "--device", device,
            "--profile", "fast", "--runs", "5", "--candidate-tracer",
            str(pair.tracer.path), "--expected-installed-apk-sha256",
            historical.apk_sha256, "--compare",
            "docs/benchmarks/binary-trace-baseline.md",
        ), timeout=900.0)
        state.phase = "install-current"
        _install_held_apk(device, runner, current)
        state.phase = "force-stop-current"
        runner.run(("adb", "-s", device, "shell", "am", "force-stop", PACKAGE), timeout=30.0)
        state.phase = "restage-current"
        _stage_app_private_binaries(
            device, runner, token=uuid.uuid4().hex, pair=pair, package=PACKAGE,
        )
        _run_current_fixture_phase(
            device, directory, runner=runner, state=state, converter=converter,
            artifact_client_factory=artifact_client_factory,
        )
    except BaseException as primary:
        if state.historical is None and hasattr(primary, "report"):
            candidate = getattr(primary, "report")
            if isinstance(candidate, dict):
                state.builder_report = candidate
                manifest = candidate.get("manifest")
                if isinstance(manifest, list):
                    state.archive_manifest = tuple(
                        tuple(item.items()) for item in manifest
                        if isinstance(item, dict)
                    )
                archive_sha256 = candidate.get("archive_sha256")
                if isinstance(archive_sha256, str):
                    state.archive_sha256 = archive_sha256
        _finalize_gate_failure(
            device, directory, runner=runner, state=state, primary=primary,
        )

    state.phase = "cleanup-success"
    cleanup_errors = _collect_gate_cleanup((
        ("historical APK close", state.historical.close),
        ("tracer snapshot close", state.pair.tracer.close),
        ("companion snapshot close", state.pair.companion.close),
    ))
    if cleanup_errors:
        _finalize_gate_failure(
            device, directory, runner=runner, state=state,
            primary=RuntimeError("acceptance resource cleanup failed"),
            initial_cleanup_errors=cleanup_errors, cleanup_resources=False,
            cleanup_after_recovery=(
                ("current APK close", state.current.close),
                ("current input snapshot tree cleanup",
                 lambda: _current_snapshot_tree_cleanup(state.current)),
            ),
        )
    cleanup_errors = _collect_gate_cleanup(((
        "current input snapshot tree cleanup",
        lambda: _current_snapshot_tree_cleanup(state.current),
    ),))
    if cleanup_errors:
        _finalize_gate_failure(
            device, directory, runner=runner, state=state,
            primary=RuntimeError("acceptance resource cleanup failed"),
            initial_cleanup_errors=cleanup_errors, cleanup_resources=False,
            cleanup_after_recovery=(("current APK close", state.current.close),),
        )
    cleanup_errors = _collect_gate_cleanup((
        ("current APK close", state.current.close),
    ))
    if cleanup_errors:
        _finalize_gate_failure(
            device, directory, runner=runner, state=state,
            primary=RuntimeError("acceptance resource cleanup failed"),
            initial_cleanup_errors=cleanup_errors, cleanup_resources=False,
        )
    state.recovery_active = False
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True, help="explicit rooted arm64 device serial")
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)
    parent = Path.cwd() / "qtrace-acceptance-failures"
    parent.mkdir(mode=0o700, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise RuntimeError("acceptance failure parent is unsafe")
    temporary = tempfile.TemporaryDirectory(prefix=".qtrace-device-acceptance-", dir=parent)
    root = Path(temporary.name)
    try:
        result = run_acceptance(arguments.device, root, runner=SubprocessRunner(arguments.device))
    except BaseException as error:
        retained = parent / uuid.uuid4().hex
        root.rename(retained)
        temporary.cleanup()
        print(f"qtrace acceptance failed; generated reports remain at: {retained}", file=sys.stderr)
        print(str(error), file=sys.stderr)
        return 1
    temporary.cleanup()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
