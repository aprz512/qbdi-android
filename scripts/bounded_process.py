"""Bounded subprocess capture with prompt termination and complete reaping."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Sequence


READ_CHUNK_BYTES = 64 * 1024
MAX_STDERR_BYTES = 64 * 1024
TERMINATE_GRACE_SECONDS = 0.05
REAP_TIMEOUT_SECONDS = 0.5
GROUP_EXIT_TIMEOUT_SECONDS = 0.5


class BoundedProcessError(RuntimeError):
    def __init__(self, message: str, *, returncode: int | None = None,
                 stdout: bytes = b"", stderr: bytes = b"") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_group_exit(process_group_id: int) -> bool:
    deadline = time.monotonic() + GROUP_EXIT_TIMEOUT_SECONDS
    while _process_group_exists(process_group_id):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))
    return True


def _terminate_and_reap(
    process: subprocess.Popen[bytes], process_group_id: int | None
) -> None:
    cleanup_errors: list[BaseException] = []
    if process_group_id is not None:
        # Do not poll or wait before both group signals.  The unreaped session
        # leader keeps its numeric PID/PGID reserved, so neither signal can hit
        # an unrelated group that reused the identifier.
        try:
            os.killpg(process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError as error:
            cleanup_errors.append(error)
        time.sleep(TERMINATE_GRACE_SECONDS)
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            cleanup_errors.append(error)
    elif process.poll() is None:
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=REAP_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        if process_group_id is None and process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=REAP_TIMEOUT_SECONDS)
        except (OSError, subprocess.TimeoutExpired) as error:
            cleanup_errors.append(error)
    if (
        process_group_id is not None
        and not _wait_for_process_group_exit(process_group_id)
    ):
        cleanup_errors.append(
            RuntimeError(f"process group {process_group_id} did not exit")
        )
    if cleanup_errors:
        raise RuntimeError("failed to clean up subprocess group") from cleanup_errors[0]


def _returncode_without_reaping(process_id: int, deadline: float) -> int | None:
    while True:
        status = os.waitid(
            os.P_PID, process_id, os.WEXITED | os.WNOHANG | os.WNOWAIT
        )
        if status is not None:
            if status.si_code == os.CLD_EXITED:
                return status.si_status
            return -status.si_status
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        time.sleep(min(0.01, remaining))


def capture_bounded(
    command: Sequence[str], *, maximum_bytes: int, timeout: float
) -> bytes:
    """Capture stdout up to a hard limit without unbounded stderr or unreaped children."""
    if maximum_bytes < 0:
        raise ValueError("maximum_bytes must not be negative")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    argv = list(command)
    process = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, start_new_session=True,
    )
    # start_new_session makes the child its session and process-group leader
    # before Popen returns.  Save that owned PGID before any operation that can
    # reap the leader and make its numeric identifier reusable.
    process_id = getattr(process, "pid", None)
    process_group_id = (
        process_id
        if isinstance(process_id, int)
        and not isinstance(process_id, bool)
        and process_id > 0
        else None
    )
    selector: selectors.BaseSelector | None = None
    completed = False
    try:
        assert process.stdout is not None
        assert process.stderr is not None
        output = bytearray()
        error_output = bytearray()
        returncode: int | None = None
        try:
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            deadline = time.monotonic() + timeout
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                ready = selector.select(remaining)
                if not ready:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _events in ready:
                    chunk = os.read(key.fileobj.fileno(), READ_CHUNK_BYTES)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        if len(output) + len(chunk) > maximum_bytes:
                            raise BoundedProcessError(
                                f"subprocess output exceeds {maximum_bytes}-byte size limit"
                            )
                        output.extend(chunk)
                    elif len(error_output) < MAX_STDERR_BYTES:
                        remaining_error = MAX_STDERR_BYTES - len(error_output)
                        error_output.extend(chunk[:remaining_error])
            if process_group_id is None:
                returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
            else:
                returncode = _returncode_without_reaping(process_group_id, deadline)
            if returncode is None:
                raise subprocess.TimeoutExpired(argv, timeout)
        finally:
            active_error = sys.exc_info()[1]
            if selector is not None:
                try:
                    selector.close()
                except BaseException:
                    if active_error is None:
                        raise
        if returncode != 0:
            detail = error_output.decode("utf-8", errors="replace").strip()
            raise BoundedProcessError(
                f"subprocess failed ({returncode}): {detail}",
                returncode=returncode,
                stdout=bytes(output),
                stderr=bytes(error_output),
            )
        process.wait(timeout=max(0, deadline - time.monotonic()))
        completed = True
        return bytes(output)
    finally:
        active_error = sys.exc_info()[1]
        if not completed:
            try:
                _terminate_and_reap(process, process_group_id)
            except BaseException as cleanup_error:
                if active_error is None:
                    raise
                if hasattr(active_error, "add_note"):
                    active_error.add_note(f"subprocess cleanup failed: {cleanup_error}")
        close_error: BaseException | None = None
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except BaseException as error:
                close_error = close_error or error
        if active_error is None and close_error is not None:
            raise close_error
