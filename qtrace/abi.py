"""Bind an explicit device ABI acceptance report to the selected tracer bytes."""
from __future__ import annotations

import hashlib
from pathlib import Path

from qtrace.errors import QtraceError
from qtrace.status import load_strict_json


REQUIRED_CHECKS = frozenset({
    "baseline_java_values", "baseline_returns_exceptions", "traced_java_values",
    "traced_returns_exceptions", "platform_register", "real_thread_stack",
    "attach_callback", "jni_enter_leave_pairs", "jni_argument_text",
    "floating_return_text", "trace_termination", "native_status",
    "fixed_floating_argument_text", "fixed_floating_return_text",
})


def _reject(reason: str) -> None:
    raise QtraceError("tracer.abi_rejected", "preflight.abi", reason)


def require_abi_acceptance(path: Path, device: object, artifacts: object, *, timeout: float) -> dict:
    """Reject failed, incomplete, stale-device or different-build reports before deployment."""
    try:
        with path.open("rb") as source:
            raw = source.read(1024 * 1024 + 1)
        report = load_strict_json(raw, maximum_bytes=1024 * 1024)
        if not isinstance(report, dict) or type(report.get("schema_version")) is not int or report["schema_version"] != 1:
            _reject("unsupported ABI report schema")
        if (report.get("result") != "pass" or report.get("cleanup") is not True or
                type(report.get("process_exit_code")) is not int or report["process_exit_code"] != 0 or
                report.get("error") is not None):
            _reject("ABI report is not a completed pass")
        checks = report.get("checks")
        if not isinstance(checks, dict) or not REQUIRED_CHECKS.issubset(checks) or any(checks[key] is not True for key in REQUIRED_CHECKS):
            _reject("ABI report has missing or failed checks")
        recorded_device = report.get("device", {})
        if recorded_device.get("serial") != device.serial:
            _reject("ABI report belongs to another device")
        for key, prop in (("fingerprint", "ro.build.fingerprint"), ("abi", "ro.product.cpu.abi"),
                          ("sdk", "ro.build.version.sdk")):
            actual = device.shell("getprop", prop, timeout=timeout, maximum_bytes=8192).decode().strip()
            if not actual or actual != recorded_device.get(key):
                _reject("ABI device identity changed: " + key)
        if recorded_device.get("abi") != "arm64-v8a":
            _reject("ABI report does not attest arm64-v8a")
        hashes = report.get("artifacts", {})
        expected = {}
        for name, artifact in (("libqbdi_tracer.so", artifacts.tracer_so),
                               ("libshadowhook_nothing.so", artifacts.companion)):
            with Path(artifact).open("rb") as source:
                actual = hashlib.file_digest(source, "sha256").hexdigest()
            if hashes.get(name) != actual:
                _reject("ABI report artifact SHA-256 differs: " + name)
            expected[name] = actual
        return {"report_sha256": hashlib.sha256(raw).hexdigest(), "session_id": report["session_id"],
                "device": recorded_device, "artifacts": expected}
    except QtraceError:
        raise
    except Exception as error:
        raise QtraceError("tracer.abi_rejected", "preflight.abi", "ABI report unavailable or invalid: " + str(error)) from error


def require_abi_deployment(receipt: dict, deployment: object) -> None:
    """Fence artifact replacement between acceptance validation and deployment."""
    hashes = deployment.sha256
    for name, remote in (("libqbdi_tracer.so", deployment.tracer_so),
                          ("libshadowhook_nothing.so", deployment.companion)):
        if hashes.get(remote) != receipt["artifacts"][name]:
            _reject("deployed artifact differs from ABI acceptance: " + name)
