"""Bounded host-process execution for qtrace."""

from __future__ import annotations

import math
import subprocess
from collections.abc import Sequence

from scripts.bounded_process import BoundedProcessError, capture_bounded, stream_bounded

from qtrace.errors import QtraceError


DEFAULT_MAXIMUM_BYTES = 1_048_576
DEFAULT_TIMEOUT_SECONDS = 30.0


def _fail(code: str, detail: str) -> None:
    raise QtraceError(code, "process", detail)


class BoundedRunner:
    """Adapt the shared bounded-process helper to qtrace's error boundary."""

    def capture(
        self,
        command: Sequence[str],
        *,
        maximum_bytes: int = DEFAULT_MAXIMUM_BYTES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> bytes:
        if isinstance(command, (str, bytes)) or not isinstance(command, Sequence):
            _fail("process.command_invalid", "command must be an argument sequence")
        argv = tuple(command)
        if not argv:
            _fail("process.command_invalid", "command must not be empty")
        if any(not isinstance(argument, str) or not argument or "\0" in argument for argument in argv):
            _fail("process.command_invalid", "command arguments must be nonempty strings without NUL")
        if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or maximum_bytes <= 0:
            _fail("process.bound_invalid", "maximum_bytes must be a positive integer")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            _fail("process.timeout_invalid", "timeout must be finite and positive")

        try:
            return capture_bounded(
                argv,
                maximum_bytes=maximum_bytes,
                timeout=float(timeout),
            )
        except QtraceError:
            raise
        except subprocess.TimeoutExpired as error:
            wrapped = QtraceError(
                "process.timeout",
                "process",
                f"command timed out after {float(timeout):g} seconds: {argv[0]}",
            )
            raise wrapped from error
        except BoundedProcessError as error:
            wrapped = QtraceError("process.failed", "process", str(error))
            raise wrapped from error
        except (OSError, ValueError) as error:
            wrapped = QtraceError("process.failed", "process", f"command failed: {error}")
            raise wrapped from error

    def stream(
        self,
        command: Sequence[str],
        output: object,
        *,
        maximum_bytes: int = DEFAULT_MAXIMUM_BYTES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if isinstance(command, (str, bytes)) or not isinstance(command, Sequence):
            _fail("process.command_invalid", "command must be an argument sequence")
        argv = tuple(command)
        if not argv or any(
            not isinstance(argument, str) or not argument or "\0" in argument
            for argument in argv
        ):
            _fail("process.command_invalid", "command arguments must be nonempty strings without NUL")
        if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or maximum_bytes <= 0:
            _fail("process.bound_invalid", "maximum_bytes must be a positive integer")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            _fail("process.timeout_invalid", "timeout must be finite and positive")
        try:
            stream_bounded(
                argv, output, maximum_bytes=maximum_bytes, timeout=float(timeout)
            )
        except QtraceError:
            raise
        except subprocess.TimeoutExpired as error:
            wrapped = QtraceError(
                "process.timeout", "process",
                f"command timed out after {float(timeout):g} seconds: {argv[0]}",
            )
            raise wrapped from error
        except BoundedProcessError as error:
            wrapped = QtraceError("process.failed", "process", str(error))
            raise wrapped from error
        except (OSError, ValueError) as error:
            wrapped = QtraceError("process.failed", "process", f"command failed: {error}")
            raise wrapped from error
