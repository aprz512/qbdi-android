"""Bounded subprocess capture with descendant containment and complete reaping."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import select
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path


READ_CHUNK_BYTES = 64 * 1024
MAX_STDERR_BYTES = 64 * 1024
_STATUS_BYTES = 16 * 1024
_HANDSHAKE_SECONDS = 2.0
_POLL_SECONDS = 0.002
_MAX_CLEANUP_NS = 200_000_000
_MAX_RESULT_MARGIN_NS = 20_000_000
_MAX_STATUS_MESSAGE_CHARS = 2048
_MAX_SURVIVOR_SAMPLES = 32
_MAX_CHILDREN_BYTES = 1024 * 1024
_SUPERVISOR_MARKER = "--_bounded-process-supervisor"
_BACKEND = "linux-pid-namespace"
_PR_GET_PDEATHSIG = 2
_PR_SET_CHILD_SUBREAPER = 36
_CHILDREN_PATH = "/proc/thread-self/children"
_PIDFD_FALLBACK_ERRNOS = {
    errno.EINVAL,
    errno.ENOSYS,
    errno.EOPNOTSUPP,
    errno.EPERM,
}


class BoundedProcessError(RuntimeError):
    def __init__(self, message: str, *, returncode: int | None = None,
                 stdout: bytes = b"", stderr: bytes = b"") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _prctl(option: int, argument: object) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.prctl
    operation.restype = ctypes.c_int
    if operation(option, argument, 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _resolve_unshare() -> str:
    if not sys.platform.startswith("linux"):
        raise BoundedProcessError(
            "reliable subprocess containment backend is unavailable on this platform"
        )
    executable = shutil.which("unshare")
    if executable is None or not os.path.isabs(executable):
        raise BoundedProcessError("util-linux unshare is unavailable")
    return executable


def _pid_namespace_preflight(expected_euid: int, expected_egid: int) -> None:
    if os.getpid() != 1 or os.getppid() != 0:
        raise BoundedProcessError("containment helper is not PID-namespace init")
    if os.geteuid() != expected_euid or os.getegid() != expected_egid:
        raise BoundedProcessError(
            "containment user mapping changed the effective uid or gid"
        )
    status_descriptor = -1
    try:
        self_link = os.readlink("/proc/self")
        status_descriptor = os.open(
            "/proc/self/status", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        )
        status = os.read(status_descriptor, 64 * 1024 + 1)
    except OSError as error:
        raise BoundedProcessError(
            f"{_BACKEND} backend cannot inspect namespace procfs: {error}"
        ) from error
    finally:
        if status_descriptor >= 0:
            os.close(status_descriptor)
    if len(status) > 64 * 1024 or self_link != "1":
        raise BoundedProcessError(
            f"{_BACKEND} backend does not have namespace-scoped procfs"
        )
    nspid_lines = [line for line in status.splitlines() if line.startswith(b"NSpid:")]
    nspids = nspid_lines[0].split()[1:] if len(nspid_lines) == 1 else []
    if nspids != [b"1"] or os.stat("/proc/self").st_ino != os.stat("/proc/1").st_ino:
        raise BoundedProcessError(f"{_BACKEND} backend has invalid PID namespace status")
    parent_death_signal = ctypes.c_int()
    _prctl(_PR_GET_PDEATHSIG, ctypes.byref(parent_death_signal))
    if parent_death_signal.value != signal.SIGKILL:
        raise BoundedProcessError(
            f"{_BACKEND} wrapper did not install SIGKILL parent-death containment"
        )
    descriptor = os.open(_CHILDREN_PATH, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    os.close(descriptor)
    _prctl(_PR_SET_CHILD_SUBREAPER, 1)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        try:
            written = os.write(descriptor, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise RuntimeError("subprocess supervisor protocol write failed")
        view = view[written:]


def _write_status(descriptor: int, document: dict[str, object]) -> None:
    payload = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    if len(payload) > _STATUS_BYTES:
        raise RuntimeError("subprocess supervisor status exceeds protocol limit")
    _write_all(descriptor, payload)


def _read_one_status(descriptor: int, *, deadline: float) -> dict[str, object]:
    payload = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BoundedProcessError("subprocess containment supervisor handshake timed out")
        readable, _writable, _exceptional = select.select([descriptor], [], [], remaining)
        if not readable:
            raise BoundedProcessError("subprocess containment supervisor handshake timed out")
        try:
            chunk = os.read(descriptor, _STATUS_BYTES + 1 - len(payload))
        except InterruptedError:
            continue
        if not chunk:
            raise BoundedProcessError("subprocess containment supervisor closed its status pipe")
        payload.extend(chunk)
        newline = payload.find(b"\n")
        if newline < 0:
            if len(payload) > _STATUS_BYTES:
                raise BoundedProcessError("subprocess containment supervisor status is oversized")
            continue
        if payload[newline + 1:]:
            raise BoundedProcessError("subprocess containment supervisor sent an invalid handshake")
        try:
            document = json.loads(payload[:newline])
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise BoundedProcessError(
                "subprocess containment supervisor sent invalid status"
            ) from error
        if type(document) is not dict:
            raise BoundedProcessError("subprocess containment supervisor sent invalid status")
        return document


def _read_direct_child_pids(
    *, deadline_ns: int | None = None
) -> tuple[list[int], bool]:
    descriptor = os.open(_CHILDREN_PATH, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    pids: list[int] = []
    pending = bytearray()
    total_bytes = 0
    try:
        while True:
            if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
                return pids, False
            chunk = os.read(
                descriptor,
                min(READ_CHUNK_BYTES, _MAX_CHILDREN_BYTES + 1 - total_bytes),
            )
            if not chunk:
                if pending:
                    pids.append(int(pending))
                return pids, True
            total_bytes += len(chunk)
            if total_bytes > _MAX_CHILDREN_BYTES:
                raise RuntimeError("adopted child list exceeds containment limit")
            for index, byte in enumerate(chunk):
                if (
                    deadline_ns is not None
                    and index % 128 == 0
                    and time.monotonic_ns() >= deadline_ns
                ):
                    return pids, False
                if 48 <= byte <= 57:
                    if len(pending) >= 20:
                        raise RuntimeError("adopted child PID exceeds containment limit")
                    pending.append(byte)
                    continue
                if byte not in b" \t\r\n\v\f":
                    raise RuntimeError("adopted child list is malformed")
                if pending:
                    pids.append(int(pending))
                    pending.clear()
    finally:
        os.close(descriptor)


def _process_identity(pid: int) -> tuple[int, str] | None:
    descriptor = -1
    try:
        descriptor = os.open(
            f"/proc/{pid}/stat",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        payload = os.read(descriptor, 4097)
    except (FileNotFoundError, ProcessLookupError):
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > 4096:
        raise RuntimeError(f"process identity for PID {pid} exceeds containment limit")
    closing = payload.rfind(b")")
    fields = payload[closing + 2:].split() if closing >= 0 else []
    if len(fields) < 20 or not fields[1].isdigit() or not fields[19].isdigit():
        raise RuntimeError(f"process identity for PID {pid} is malformed")
    return int(fields[1]), fields[19].decode("ascii")


def _direct_child_identities(
    *, deadline_ns: int | None = None
) -> tuple[list[tuple[int, str]], bool]:
    parent = os.getpid()
    identities: list[tuple[int, str]] = []
    pids, complete = _read_direct_child_pids(deadline_ns=deadline_ns)
    for pid in pids:
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            return identities, False
        identity = _process_identity(pid)
        if identity is not None and identity[0] == parent:
            identities.append((pid, identity[1]))
    return identities, complete


def _signal_direct_child(pid: int, starttime: str, signal_number: int) -> None:
    identity = _process_identity(pid)
    if identity is None:
        return
    if identity != (os.getpid(), starttime):
        raise RuntimeError(
            f"{_BACKEND} child identity changed for PID {pid} starttime {starttime}"
        )
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if callable(pidfd_open) and callable(pidfd_send_signal):
        try:
            descriptor = pidfd_open(pid)
        except ProcessLookupError:
            return
        except OSError as error:
            if error.errno not in _PIDFD_FALLBACK_ERRNOS:
                raise
        else:
            try:
                pidfd_send_signal(descriptor, signal_number)
            except ProcessLookupError:
                return
            except OSError as error:
                if error.errno not in _PIDFD_FALLBACK_ERRNOS:
                    raise
            else:
                return
            finally:
                os.close(descriptor)
    # A direct child cannot have its PID reused until namespace init waits for
    # it. Revalidate both PPID and starttime immediately before the fallback.
    if _process_identity(pid) != (os.getpid(), starttime):
        raise RuntimeError(
            f"{_BACKEND} child identity changed for PID {pid} starttime {starttime}"
        )
    try:
        os.kill(pid, signal_number)
    except ProcessLookupError:
        pass


def _reap_exited_children(
    *, exclude: int | None = None, deadline_ns: int | None = None
) -> None:
    pids, _complete = _read_direct_child_pids(deadline_ns=deadline_ns)
    for pid in pids:
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            return
        if pid == exclude:
            continue
        try:
            os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, InterruptedError):
            pass


def _peek_returncode(pid: int) -> int | None:
    try:
        status = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError as error:
        raise RuntimeError(f"{_BACKEND} lost target PID {pid} before collecting status") from error
    if status is None:
        return None
    if status.si_code == os.CLD_EXITED:
        return status.si_status
    return -status.si_status


def _peek_returncode_before_deadline(
    pid: int, *, deadline_ns: int
) -> tuple[bool, int | None]:
    if time.monotonic_ns() >= deadline_ns:
        return False, None
    return True, _peek_returncode(pid)


def _reap_known_exited(pid: int, *, deadline_ns: int) -> None:
    while True:
        now_ns = time.monotonic_ns()
        if now_ns >= deadline_ns:
            raise RuntimeError(
                f"{_BACKEND} could not reap exited target PID {pid} before deadline"
            )
        try:
            finished, _status = os.waitpid(pid, os.WNOHANG)
        except InterruptedError:
            continue
        if finished == pid:
            return
        remaining = max(0.0, (deadline_ns - now_ns) / 1_000_000_000)
        time.sleep(min(_POLL_SECONDS, remaining))


def _drain_adopted_children(
    *, deadline_ns: int
) -> tuple[list[tuple[int, str]], int, bool]:
    now = time.monotonic_ns()
    grace_ns = min(50_000_000, max(0, (deadline_ns - now) // 2))
    grace_deadline = now + grace_ns
    last_identities: list[tuple[int, str]] = []
    last_complete = True
    for signal_number, phase_deadline in (
        (signal.SIGTERM, grace_deadline),
        (signal.SIGKILL, deadline_ns),
    ):
        while True:
            identities, complete = _direct_child_identities(deadline_ns=phase_deadline)
            last_identities = identities
            last_complete = complete
            if not identities and complete:
                return [], 0, False
            for pid, starttime in identities:
                if time.monotonic_ns() >= phase_deadline:
                    break
                _signal_direct_child(pid, starttime, signal_number)
            _reap_exited_children(deadline_ns=phase_deadline)
            if time.monotonic_ns() >= phase_deadline:
                break
            remaining_seconds = max(0.0, (phase_deadline - time.monotonic_ns()) / 1_000_000_000)
            time.sleep(min(_POLL_SECONDS, remaining_seconds))
    _reap_exited_children(deadline_ns=deadline_ns)
    if time.monotonic_ns() < deadline_ns:
        last_identities, last_complete = _direct_child_identities(
            deadline_ns=deadline_ns
        )
    total = len(last_identities) if last_complete else len(last_identities) + 1
    truncated = not last_complete or total > _MAX_SURVIVOR_SAMPLES
    return last_identities[:_MAX_SURVIVOR_SAMPLES], total, truncated


def _control_cancelled(descriptor: int) -> bool:
    readable, _writable, _exceptional = select.select([descriptor], [], [], 0)
    if not readable:
        return False
    try:
        payload = os.read(descriptor, 64)
    except InterruptedError:
        return False
    return not payload or b"C" in payload


def _supervisor_result(
    status_descriptor: int,
    *,
    kind: str,
    returncode: int | None = None,
    survivors: list[tuple[int, str]] | None = None,
    survivor_count_at_least: int | None = None,
    survivors_truncated: bool = False,
    error_number: int | None = None,
    message: str | None = None,
) -> int:
    samples = (survivors or [])[:_MAX_SURVIVOR_SAMPLES]
    bounded_message = None if message is None else message[:_MAX_STATUS_MESSAGE_CHARS]
    _write_status(status_descriptor, {
        "backend": _BACKEND,
        "errno": error_number,
        "kind": kind,
        "message": bounded_message,
        "returncode": returncode,
        "survivor_count_at_least": (
            len(samples)
            if survivor_count_at_least is None
            else survivor_count_at_least
        ),
        "survivors": [
            {"namespace_pid": pid, "starttime": starttime}
            for pid, starttime in samples
        ],
        "survivors_truncated": survivors_truncated or len(survivors or []) > len(samples),
        "type": "result",
    })
    return 0


_SUPERVISOR_SIGNAL_CANCELLED = False
_SUPERVISOR_SIGNAL_FAILURE: str | None = None


def _request_supervisor_cancel(_signal_number: int, _frame: object) -> None:
    global _SUPERVISOR_SIGNAL_CANCELLED
    _SUPERVISOR_SIGNAL_CANCELLED = True


def _request_supervisor_failure(signal_number: int, _frame: object) -> None:
    global _SUPERVISOR_SIGNAL_FAILURE
    _SUPERVISOR_SIGNAL_FAILURE = signal.Signals(signal_number).name


def _supervisor_main(
    control_descriptor: int,
    status_descriptor: int,
    expected_euid: int,
    expected_egid: int,
    command: Sequence[str],
) -> int:
    global _SUPERVISOR_SIGNAL_CANCELLED, _SUPERVISOR_SIGNAL_FAILURE
    _SUPERVISOR_SIGNAL_CANCELLED = False
    _SUPERVISOR_SIGNAL_FAILURE = None
    os.set_inheritable(control_descriptor, False)
    os.set_inheritable(status_descriptor, False)
    try:
        _pid_namespace_preflight(expected_euid, expected_egid)
    except (BoundedProcessError, OSError) as error:
        _write_status(status_descriptor, {
            "backend": _BACKEND,
            "message": str(error),
            "type": "backend-error",
        })
        return 125
    signal.signal(signal.SIGTERM, _request_supervisor_cancel)
    signal.signal(signal.SIGINT, _request_supervisor_cancel)
    signal.signal(signal.SIGUSR1, _request_supervisor_failure)
    _write_status(status_descriptor, {"backend": _BACKEND, "type": "ready"})
    start_bytes = bytearray()
    handshake_deadline = time.monotonic() + _HANDSHAKE_SECONDS
    while len(start_bytes) < 24:
        remaining = handshake_deadline - time.monotonic()
        if remaining <= 0:
            return _supervisor_result(
                status_descriptor, kind="supervisor-error",
                message="start control deadline elapsed",
            )
        readable, _writable, _exceptional = select.select(
            [control_descriptor], [], [], remaining
        )
        if not readable:
            continue
        chunk = os.read(control_descriptor, 24 - len(start_bytes))
        if not chunk:
            return _supervisor_result(
                status_descriptor, kind="supervisor-error",
                message="start control pipe closed",
            )
        start_bytes.extend(chunk)
    work_deadline_ns, cleanup_deadline_ns, deadline_ns = struct.unpack(
        "!QQQ", start_bytes
    )
    now_ns = time.monotonic_ns()
    if not (now_ns < work_deadline_ns < cleanup_deadline_ns < deadline_ns):
        return _supervisor_result(status_descriptor, kind="timeout")
    try:
        target = subprocess.Popen(
            list(command), stdin=None, stdout=None, stderr=None,
            shell=False, close_fds=True, start_new_session=True,
        )
    except OSError as error:
        return _supervisor_result(
            status_descriptor,
            kind="spawn-error",
            error_number=error.errno,
            message=error.strerror or str(error),
        )
    target_pid = target.pid
    root_returncode: int | None = None
    reason = "timeout"
    try:
        while True:
            if _SUPERVISOR_SIGNAL_FAILURE is not None:
                raise RuntimeError(
                    f"supervisor received {_SUPERVISOR_SIGNAL_FAILURE} after target spawn"
                )
            within_work_deadline, root_returncode = _peek_returncode_before_deadline(
                target_pid, deadline_ns=work_deadline_ns
            )
            if not within_work_deadline:
                break
            _reap_exited_children(
                exclude=target_pid, deadline_ns=work_deadline_ns
            )
            if root_returncode is not None:
                identities, complete = _direct_child_identities(
                    deadline_ns=work_deadline_ns
                )
                descendants = [
                    identity for identity in identities if identity[0] != target_pid
                ]
                if not descendants and complete:
                    _reap_known_exited(
                        target_pid, deadline_ns=work_deadline_ns
                    )
                    return _supervisor_result(
                        status_descriptor, kind="result", returncode=root_returncode,
                    )
                if root_returncode != 0:
                    reason = "result"
                    break
            if _SUPERVISOR_SIGNAL_CANCELLED or _control_cancelled(control_descriptor):
                reason = "cancelled"
                break
            now_ns = time.monotonic_ns()
            remaining_seconds = max(
                0.0, (work_deadline_ns - now_ns) / 1_000_000_000
            )
            time.sleep(min(_POLL_SECONDS, remaining_seconds))
        survivors, survivor_count_at_least, truncated = _drain_adopted_children(
            deadline_ns=cleanup_deadline_ns
        )
    except BaseException as error:
        cleanup_error: BaseException | None = None
        survivors = []
        survivor_count_at_least = 0
        truncated = True
        try:
            survivors, survivor_count_at_least, truncated = _drain_adopted_children(
                deadline_ns=cleanup_deadline_ns
            )
        except BaseException as caught:
            cleanup_error = caught
        message = f"post-spawn supervisor failure: {type(error).__name__}: {error}"
        if cleanup_error is not None:
            message += (
                f"; diagnostic cleanup failed: {type(cleanup_error).__name__}: "
                f"{cleanup_error}"
            )
        return _supervisor_result(
            status_descriptor,
            kind="containment-error",
            returncode=root_returncode,
            survivors=survivors,
            survivor_count_at_least=survivor_count_at_least,
            survivors_truncated=truncated,
            message=message,
        )
    if survivor_count_at_least:
        return _supervisor_result(
            status_descriptor,
            kind="containment-error",
            returncode=root_returncode,
            survivors=survivors,
            survivor_count_at_least=survivor_count_at_least,
            survivors_truncated=truncated,
            message="adopted process tree did not exit before cleanup deadline",
        )
    if reason == "result":
        return _supervisor_result(
            status_descriptor, kind="result", returncode=root_returncode,
        )
    return _supervisor_result(status_descriptor, kind=reason)


def _send_cancel(descriptor: int) -> None:
    try:
        _write_all(descriptor, b"C")
    except (BrokenPipeError, OSError, RuntimeError):
        pass


def _survivor_detail(result: dict[str, object]) -> str:
    survivors = result.get("survivors")
    if type(survivors) is not list:
        return "invalid survivor evidence"
    details = []
    for item in survivors:
        if type(item) is not dict:
            return "invalid survivor evidence"
        details.append(
            f"namespace PID {item.get('namespace_pid')} "
            f"starttime {item.get('starttime')}"
        )
    count = result.get("survivor_count_at_least")
    truncated = result.get("survivors_truncated") is True
    suffix = ""
    if type(count) is int and count > len(details):
        suffix = f" (at least {count} total, samples truncated)"
    elif truncated:
        suffix = " (samples truncated)"
    return (", ".join(details) or "no survivor identity") + suffix


def _capture_deadlines(timeout: float) -> tuple[int, int, int]:
    started_ns = time.monotonic_ns()
    total_ns = int(timeout * 1_000_000_000)
    if total_ns < 3:
        return started_ns, started_ns, started_ns
    result_margin_ns = min(
        _MAX_RESULT_MARGIN_NS, max(1, total_ns // 10)
    )
    cleanup_ns = min(
        _MAX_CLEANUP_NS,
        max(1, (total_ns - result_margin_ns) // 3),
    )
    deadline_ns = started_ns + total_ns
    cleanup_deadline_ns = deadline_ns - result_margin_ns
    work_deadline_ns = cleanup_deadline_ns - cleanup_ns
    return work_deadline_ns, cleanup_deadline_ns, deadline_ns


def _open_wrapper_pidfd(pid: int) -> int:
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if not callable(pidfd_open) or not callable(pidfd_send_signal):
        return -1
    try:
        descriptor = pidfd_open(pid)
    except ProcessLookupError:
        return -1
    except OSError as error:
        if error.errno in _PIDFD_FALLBACK_ERRNOS:
            return -1
        raise
    try:
        pidfd_send_signal(descriptor, 0)
    except ProcessLookupError:
        os.close(descriptor)
        return -1
    except OSError as error:
        os.close(descriptor)
        if error.errno in _PIDFD_FALLBACK_ERRNOS:
            return -1
        raise
    return descriptor


def _signal_wrapper(
    process: subprocess.Popen[bytes],
    *,
    pidfd: int,
    starttime: str | None,
    signal_number: int,
) -> None:
    if pidfd >= 0:
        try:
            signal.pidfd_send_signal(pidfd, signal_number)
        except ProcessLookupError:
            return
        except OSError as error:
            if error.errno not in _PIDFD_FALLBACK_ERRNOS:
                raise
        else:
            return
    identity = _process_identity(process.pid)
    if identity is None:
        return
    if starttime is None or identity != (os.getpid(), starttime):
        raise BoundedProcessError(
            f"{_BACKEND} wrapper identity changed for PID {process.pid} "
            f"starttime {starttime}"
        )
    try:
        os.kill(process.pid, signal_number)
    except ProcessLookupError:
        pass


def _wait_wrapper(
    process: subprocess.Popen[bytes], *, deadline_ns: int
) -> int | None:
    remaining = max(0.0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000)
    try:
        return process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        return None


def _read_selector_event(
    selector: selectors.BaseSelector,
    key: selectors.SelectorKey,
    *,
    maximum_bytes: int,
    output: bytearray,
    error_output: bytearray,
    status_payload: bytearray,
    primary_error: BaseException | None,
) -> tuple[BaseException | None, dict[str, object] | None]:
    file_descriptor = (
        key.fileobj.fileno() if hasattr(key.fileobj, "fileno") else key.fileobj
    )
    try:
        chunk = os.read(file_descriptor, READ_CHUNK_BYTES)
    except InterruptedError:
        return primary_error, None
    if not chunk:
        selector.unregister(key.fileobj)
        return primary_error, None
    if key.data == "stdout":
        if primary_error is None and len(output) + len(chunk) > maximum_bytes:
            return BoundedProcessError(
                f"subprocess output exceeds {maximum_bytes}-byte size limit"
            ), None
        if primary_error is None:
            output.extend(chunk)
        return primary_error, None
    if key.data == "stderr":
        if len(error_output) < MAX_STDERR_BYTES:
            error_output.extend(chunk[:MAX_STDERR_BYTES - len(error_output)])
        return primary_error, None
    status_payload.extend(chunk)
    if len(status_payload) > _STATUS_BYTES:
        raise BoundedProcessError("subprocess containment status is oversized")
    newline = status_payload.find(b"\n")
    if newline < 0:
        return primary_error, None
    if status_payload[newline + 1:]:
        raise BoundedProcessError("subprocess containment sent extra status")
    try:
        parsed = json.loads(status_payload[:newline])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BoundedProcessError("subprocess containment sent invalid status") from error
    if type(parsed) is not dict or parsed.get("type") != "result":
        raise BoundedProcessError("subprocess containment sent invalid result")
    selector.unregister(key.fileobj)
    return primary_error, parsed


def capture_bounded(
    command: Sequence[str], *, maximum_bytes: int, timeout: float,
    cwd: Path | None = None,
) -> bytes:
    """Capture stdout while a rootless PID namespace contains every descendant.

    The target keeps the caller's effective uid/gid and HOME.  Supplementary
    groups outside the one-id map are intentionally visible as overflow gids;
    callers must not depend on supplementary-group authorization.
    """
    if maximum_bytes < 0:
        raise ValueError("maximum_bytes must not be negative")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    argv = list(command)
    if not argv:
        raise ValueError("command must not be empty")
    try:
        unshare = _resolve_unshare()
    except BoundedProcessError as error:
        raise BoundedProcessError(
            f"{_BACKEND} containment failed before target spawn: {error}"
        ) from error
    cwd_descriptor = -1
    cwd_path: str | None = None
    cwd_identity: tuple[int, int] | None = None
    if cwd is not None:
        cwd_path = os.path.abspath(os.fspath(cwd))
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            cwd_descriptor = os.open(cwd_path, flags)
            details = os.fstat(cwd_descriptor)
            if not stat.S_ISDIR(details.st_mode):
                raise NotADirectoryError(errno.ENOTDIR, "not a directory", cwd_path)
            pathname_details = os.stat(cwd_path, follow_symlinks=False)
            if not stat.S_ISDIR(pathname_details.st_mode):
                raise NotADirectoryError(errno.ENOTDIR, "not a directory", cwd_path)
            cwd_identity = (details.st_dev, details.st_ino)
            if cwd_identity != (pathname_details.st_dev, pathname_details.st_ino):
                raise BoundedProcessError("cwd path identity changed while it was opened")
        except BaseException as error:
            primary = BoundedProcessError(
                f"cwd validation failed before target spawn: {error}"
            )
            if cwd_descriptor >= 0:
                try:
                    os.close(cwd_descriptor)
                except OSError as cleanup_error:
                    if hasattr(primary, "add_note"):
                        primary.add_note(
                            f"{_BACKEND} cwd cleanup failed: {cleanup_error}"
                        )
                finally:
                    cwd_descriptor = -1
            raise primary from error

    def close_cwd_before_raise(primary: BaseException) -> None:
        nonlocal cwd_descriptor
        if cwd_descriptor < 0:
            return
        try:
            os.close(cwd_descriptor)
        except OSError as cleanup_error:
            if hasattr(primary, "add_note"):
                primary.add_note(f"{_BACKEND} cwd cleanup failed: {cleanup_error}")
        finally:
            cwd_descriptor = -1

    work_deadline_ns, cleanup_deadline_ns, deadline_ns = _capture_deadlines(timeout)
    if deadline_ns <= time.monotonic_ns():
        timeout_error = subprocess.TimeoutExpired(argv, timeout)
        close_cwd_before_raise(timeout_error)
        raise timeout_error
    pipe_flags = getattr(os, "O_CLOEXEC", 0)
    try:
        control_read, control_write = os.pipe2(pipe_flags)
    except BaseException as error:
        close_cwd_before_raise(error)
        raise
    try:
        status_read, status_write = os.pipe2(pipe_flags)
    except BaseException as error:
        os.close(control_read)
        os.close(control_write)
        close_cwd_before_raise(error)
        raise
    wrapper: subprocess.Popen[bytes] | None = None
    wrapper_pidfd = -1
    wrapper_starttime: str | None = None
    selector: selectors.BaseSelector | None = None
    wrapper_reaped = False
    target_authorized = False
    primary_error: BaseException | None = None
    output = bytearray()
    error_output = bytearray()
    status_payload = bytearray()
    cwd_rebind_error: BaseException | None = None
    try:
        wrapper = subprocess.Popen(
            [
                unshare,
                "--user",
                "--map-current-user",
                "--pid",
                "--fork",
                "--kill-child=KILL",
                "--mount-proc",
                "--",
                sys.executable,
                os.path.abspath(__file__),
                _SUPERVISOR_MARKER,
                str(control_read),
                str(status_write),
                str(os.geteuid()),
                str(os.getegid()),
                *argv,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            pass_fds=(
                (control_read, status_write, cwd_descriptor)
                if cwd_descriptor >= 0 else (control_read, status_write)
            ),
            cwd=(
                f"/proc/self/fd/{cwd_descriptor}"
                if cwd_descriptor >= 0 else None
            ),
            start_new_session=True,
        )
        if cwd_path is not None and cwd_identity is not None:
            try:
                details = os.stat(cwd_path, follow_symlinks=False)
                if (not stat.S_ISDIR(details.st_mode)
                        or (details.st_dev, details.st_ino) != cwd_identity):
                    raise BoundedProcessError("cwd path identity changed after wrapper spawn")
            except BaseException as error:
                cwd_rebind_error = error
        identity = _process_identity(wrapper.pid)
        if identity is not None and identity[0] == os.getpid():
            wrapper_starttime = identity[1]
        wrapper_pidfd = _open_wrapper_pidfd(wrapper.pid)
        os.close(control_read)
        control_read = -1
        os.close(status_write)
        status_write = -1
        try:
            ready = _read_one_status(
                status_read,
                deadline=min(
                    work_deadline_ns / 1_000_000_000,
                    time.monotonic() + _HANDSHAKE_SECONDS,
                ),
            )
        except BoundedProcessError as error:
            if time.monotonic_ns() >= work_deadline_ns:
                raise subprocess.TimeoutExpired(argv, timeout) from error
            raise BoundedProcessError(
                f"{_BACKEND} containment failed before target spawn: {error}"
            ) from error
        if ready.get("type") != "ready" or ready.get("backend") != _BACKEND:
            message = ready.get("message")
            raise BoundedProcessError(
                f"subprocess containment backend failed before target spawn: {message}"
            )
        _write_all(
            control_write,
            struct.pack(
                "!QQQ", work_deadline_ns, cleanup_deadline_ns, deadline_ns
            ),
        )
        target_authorized = True
        assert wrapper.stdout is not None
        assert wrapper.stderr is not None
        selector = selectors.DefaultSelector()
        selector.register(wrapper.stdout, selectors.EVENT_READ, "stdout")
        selector.register(wrapper.stderr, selectors.EVENT_READ, "stderr")
        selector.register(status_read, selectors.EVENT_READ, "status")
        result: dict[str, object] | None = None
        cancel_sent = False
        deadline_cancelled = False
        emergency = False
        while True:
            wrapper_returncode = wrapper.poll()
            if wrapper_returncode is not None:
                wrapper_reaped = True
                while True:
                    ready_events = selector.select(0)
                    if not ready_events:
                        break
                    for key, _events in ready_events:
                        primary_error, parsed = _read_selector_event(
                            selector,
                            key,
                            maximum_bytes=maximum_bytes,
                            output=output,
                            error_output=error_output,
                            status_payload=status_payload,
                            primary_error=primary_error,
                        )
                        result = parsed or result
                break
            now_ns = time.monotonic_ns()
            if now_ns >= work_deadline_ns and not cancel_sent:
                deadline_cancelled = True
                _send_cancel(control_write)
                cancel_sent = True
            if now_ns >= cleanup_deadline_ns and not emergency:
                _signal_wrapper(
                    wrapper,
                    pidfd=wrapper_pidfd,
                    starttime=wrapper_starttime,
                    signal_number=signal.SIGKILL,
                )
                emergency = True
            if now_ns >= deadline_ns:
                break
            next_deadline_ns = (
                deadline_ns
                if emergency else cleanup_deadline_ns if cancel_sent else work_deadline_ns
            )
            remaining = max(
                0.0, (next_deadline_ns - now_ns) / 1_000_000_000
            )
            if result is not None or not selector.get_map():
                remaining = min(remaining, _POLL_SECONDS)
            ready_events = selector.select(remaining)
            if not ready_events:
                continue
            for key, _events in ready_events:
                prior_error = primary_error
                primary_error, parsed = _read_selector_event(
                    selector,
                    key,
                    maximum_bytes=maximum_bytes,
                    output=output,
                    error_output=error_output,
                    status_payload=status_payload,
                    primary_error=primary_error,
                )
                result = parsed or result
                if primary_error is not prior_error and not cancel_sent:
                    _send_cancel(control_write)
                    cancel_sent = True
        if not wrapper_reaped:
            if not emergency:
                _signal_wrapper(
                    wrapper,
                    pidfd=wrapper_pidfd,
                    starttime=wrapper_starttime,
                    signal_number=signal.SIGKILL,
                )
                emergency = True
            wrapper_returncode = _wait_wrapper(wrapper, deadline_ns=deadline_ns)
            wrapper_reaped = wrapper_returncode is not None
        if not wrapper_reaped:
            raise BoundedProcessError(
                f"{_BACKEND} emergency could not reap wrapper PID {wrapper.pid} "
                f"starttime {wrapper_starttime} before deadline"
            )
        if emergency:
            raise BoundedProcessError(
                f"{_BACKEND} emergency teardown killed wrapper PID {wrapper.pid} "
                f"starttime {wrapper_starttime}",
                stdout=bytes(output),
                stderr=bytes(error_output),
            )
        if wrapper_returncode != 0 or result is None:
            raise BoundedProcessError(
                f"{_BACKEND} wrapper exited without a valid result ({wrapper_returncode})",
                stdout=bytes(output),
                stderr=bytes(error_output),
            )
        kind = result.get("kind")
        if kind == "containment-error":
            message = result.get("message")
            returncode = result.get("returncode")
            raise BoundedProcessError(
                f"{_BACKEND} {message}: {_survivor_detail(result)}",
                returncode=returncode if type(returncode) is int else None,
                stdout=bytes(output),
                stderr=bytes(error_output),
            )
        if primary_error is not None:
            raise primary_error
        if kind == "timeout" or (kind == "cancelled" and deadline_cancelled):
            raise subprocess.TimeoutExpired(argv, timeout)
        if kind == "cancelled":
            raise BoundedProcessError(
                f"{_BACKEND} supervisor cancelled without a parent request"
            )
        if kind == "spawn-error":
            error_number = result.get("errno")
            message = result.get("message")
            raise OSError(
                error_number if type(error_number) is int else 0,
                str(message), argv[0],
            )
        if kind != "result":
            raise BoundedProcessError(
                f"{_BACKEND} supervisor returned unexpected result {kind!r}"
            )
        returncode = result.get("returncode")
        if type(returncode) is not int:
            raise BoundedProcessError(f"{_BACKEND} supervisor omitted target return code")
        if returncode != 0:
            detail = error_output.decode("utf-8", errors="replace").strip()
            raise BoundedProcessError(
                f"subprocess failed ({returncode}): {detail}",
                returncode=returncode,
                stdout=bytes(output),
                stderr=bytes(error_output),
            )
        return bytes(output)
    finally:
        active_error = sys.exc_info()[1]
        cleanup_errors: list[BaseException] = []
        if cwd_path is not None and cwd_identity is not None:
            try:
                details = os.stat(cwd_path, follow_symlinks=False)
                if (not stat.S_ISDIR(details.st_mode)
                        or (details.st_dev, details.st_ino) != cwd_identity):
                    raise BoundedProcessError("cwd path identity changed before cleanup")
            except BaseException as cleanup_error:
                if cwd_rebind_error is None:
                    cwd_rebind_error = cleanup_error
        if cwd_rebind_error is not None:
            cleanup_errors.append(cwd_rebind_error)
        if wrapper is not None and not wrapper_reaped:
            if target_authorized:
                _send_cancel(control_write)
            try:
                _signal_wrapper(
                    wrapper,
                    pidfd=wrapper_pidfd,
                    starttime=wrapper_starttime,
                    signal_number=signal.SIGKILL,
                )
                wrapper_reaped = _wait_wrapper(
                    wrapper, deadline_ns=deadline_ns
                ) is not None
                if not wrapper_reaped:
                    raise BoundedProcessError(
                        f"{_BACKEND} emergency could not reap wrapper PID "
                        f"{wrapper.pid} starttime {wrapper_starttime} before deadline"
                    )
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if selector is not None:
            try:
                selector.close()
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
        for stream in (
            None if wrapper is None else wrapper.stdout,
            None if wrapper is None else wrapper.stderr,
        ):
            if stream is not None:
                try:
                    stream.close()
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
        if wrapper_pidfd >= 0:
            try:
                os.close(wrapper_pidfd)
            except OSError as cleanup_error:
                cleanup_errors.append(cleanup_error)
        for descriptor in (control_read, control_write, status_read, status_write):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as cleanup_error:
                    cleanup_errors.append(cleanup_error)
        if cwd_descriptor >= 0:
            try:
                os.close(cwd_descriptor)
            except OSError as cleanup_error:
                cleanup_errors.append(cleanup_error)
        if cleanup_errors:
            if active_error is None:
                raise cleanup_errors[0]
            if hasattr(active_error, "add_note"):
                for cleanup_error in cleanup_errors:
                    active_error.add_note(
                        f"{_BACKEND} cleanup failed: {cleanup_error}"
                    )


def _run_supervisor_from_argv(arguments: Sequence[str]) -> int:
    if len(arguments) < 6 or arguments[0] != _SUPERVISOR_MARKER:
        return 126
    try:
        control_descriptor = int(arguments[1])
        status_descriptor = int(arguments[2])
        expected_euid = int(arguments[3])
        expected_egid = int(arguments[4])
    except ValueError:
        return 126
    command = list(arguments[5:])
    if not command:
        return _supervisor_result(
            status_descriptor, kind="spawn-error", message="command is empty",
        )
    return _supervisor_main(
        control_descriptor,
        status_descriptor,
        expected_euid,
        expected_egid,
        command,
    )


if __name__ == "__main__":
    try:
        exit_code = _run_supervisor_from_argv(sys.argv[1:])
    except BaseException as error:
        try:
            if len(sys.argv) >= 4 and sys.argv[1] == _SUPERVISOR_MARKER:
                _write_status(int(sys.argv[3]), {
                    "backend": _BACKEND,
                    "message": f"{type(error).__name__}: {error}",
                    "type": "backend-error",
                })
        except BaseException:
            pass
        exit_code = 125
    os._exit(exit_code)
