from enum import Enum


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PARTIAL = 2
EXIT_STOP_INCOMPLETE = 3
EXIT_INTERRUPTED = 130

_MAX_DETAIL_BYTES = 512


class ErrorCode(str, Enum):
    DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
    SESSION_BUSY = "SESSION_BUSY"
    FRIDA_VERSION_MISMATCH = "FRIDA_VERSION_MISMATCH"
    PACKAGE_NOT_INSTALLED = "PACKAGE_NOT_INSTALLED"
    UNSUPPORTED_ABI = "UNSUPPORTED_ABI"
    TARGET_MODULE_NOT_FOUND = "TARGET_MODULE_NOT_FOUND"
    SYMBOL_NOT_FOUND = "SYMBOL_NOT_FOUND"
    SYMBOL_SIZE_INVALID = "SYMBOL_SIZE_INVALID"
    TARGET_IDENTITY_MISMATCH = "TARGET_IDENTITY_MISMATCH"
    TRACER_LOAD_FAILED = "TRACER_LOAD_FAILED"
    HOOK_INSTALL_FAILED = "HOOK_INSTALL_FAILED"
    PROCESS_EXITED_DURING_SETUP = "PROCESS_EXITED_DURING_SETUP"
    STOP_NOT_ACKNOWLEDGED = "STOP_NOT_ACKNOWLEDGED"
    ARTIFACT_INCOMPLETE = "ARTIFACT_INCOMPLETE"
    ARTIFACT_INTEGRITY_FAILED = "ARTIFACT_INTEGRITY_FAILED"
    ADB_UNAVAILABLE = "ADB_UNAVAILABLE"
    ADB_PULL_FAILED = "ADB_PULL_FAILED"


def _bounded_single_line(detail: str) -> str:
    single_line = detail.replace("\r", " ").replace("\n", " ")
    encoded = single_line.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_DETAIL_BYTES:
        return single_line
    return encoded[:_MAX_DETAIL_BYTES].decode("utf-8", errors="ignore")


class QtraceError(RuntimeError):
    def __init__(
        self,
        code: ErrorCode | str,
        stage: str,
        detail: str,
        *,
        exit_code: int = EXIT_ERROR,
    ) -> None:
        self.code = code.value if isinstance(code, ErrorCode) else str(code)
        self.stage = str(stage)
        self.detail = _bounded_single_line(str(detail))
        self.exit_code = exit_code
        super().__init__(self.detail)

    def __str__(self) -> str:
        return f"qtrace: stage={self.stage} code={self.code} detail={self.detail}"


class ConfigError(QtraceError):
    def __init__(self, code: ErrorCode | str, detail: str) -> None:
        super().__init__(code, "config", detail)
