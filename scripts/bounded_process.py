"""Bounded subprocess capture with prompt termination and complete reaping."""

from __future__ import annotations

import os
import selectors
import subprocess
import sys
import time
from collections.abc import Sequence


READ_CHUNK_BYTES = 64 * 1024
MAX_STDERR_BYTES = 64 * 1024


class BoundedProcessError(RuntimeError):
    def __init__(self, message: str, *, returncode: int | None = None,
                 stderr: bytes = b"") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


def _terminate_and_reap(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=0.5)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait()
    except OSError:
        pass


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
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False
    )
    assert process.stdout is not None
    assert process.stderr is not None
    selector: selectors.BaseSelector | None = None
    completed = False
    try:
        try:
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            output = bytearray()
            error_output = bytearray()
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
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            returncode = process.wait(timeout=remaining)
            completed = True
            if returncode != 0:
                detail = error_output.decode("utf-8", errors="replace").strip()
                raise BoundedProcessError(
                    f"subprocess failed ({returncode}): {detail}",
                    returncode=returncode,
                    stderr=bytes(error_output),
                )
            return bytes(output)
        finally:
            active_error = sys.exc_info()[1]
            if selector is not None:
                try:
                    selector.close()
                except BaseException:
                    if active_error is None:
                        raise
    finally:
        active_error = sys.exc_info()[1]
        if not completed:
            _terminate_and_reap(process)
        close_error: BaseException | None = None
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except BaseException as error:
                close_error = close_error or error
        if active_error is None and close_error is not None:
            raise close_error
