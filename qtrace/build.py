"""Tracer artifact selection, validation, and bounded deployment."""

from __future__ import annotations

import hashlib
import math
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping, Protocol

from qtrace.device import AdbDevice
from qtrace.errors import ErrorCode, QtraceError
from qtrace.models import TracerConfig


_BUILD_OUTPUT_BYTES = 4 * 1024 * 1024
_UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROBE_DETAIL_BYTES = 4096
_MAX_TRACER_ARTIFACT_BYTES = 512 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024


class CommandRunner(Protocol):
    def capture(
        self, command, *, maximum_bytes: int, timeout: float
    ) -> bytes: ...


@dataclass(frozen=True)
class TracerArtifacts:
    tracer_so: Path
    companion: Path


@dataclass(frozen=True)
class Deployment:
    route: str
    remote_dir: str
    tracer_so: str
    companion: str
    sha256: Mapping[str, str]
    load_probe: Mapping[str, str]


class _RouteProbeFailure(RuntimeError):
    pass


def _fail(code: ErrorCode | str, stage: str, detail: str) -> None:
    raise QtraceError(code, stage, detail)


def _timeout(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        _fail("build.timeout_invalid", "build", "build timeout must be finite and positive")
    return float(value)


def _arm64_shared_object(path: Path, *, stage: str) -> Path:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except (OSError, TypeError, ValueError) as error:
        _fail("tracer.artifact_invalid", stage, f"tracer artifact is unavailable: {error}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        _fail(
            "tracer.artifact_invalid",
            stage,
            "tracer artifact must be a regular non-symlink file",
        )
    if metadata.st_size < 64 or metadata.st_size > _MAX_TRACER_ARTIFACT_BYTES:
        _fail(
            "tracer.artifact_invalid",
            stage,
            "tracer artifact size is outside the supported bound",
        )
    try:
        with candidate.open("rb") as source:
            header = source.read(64)
    except OSError as error:
        _fail("tracer.artifact_invalid", stage, f"tracer artifact cannot be read: {error}")
    valid = (
        len(header) == 64
        and header[:4] == b"\x7fELF"
        and header[4] == 2
        and header[5] == 1
        and header[6] == 1
        and int.from_bytes(header[16:18], "little") == 3
        and int.from_bytes(header[18:20], "little") == 183
        and int.from_bytes(header[20:24], "little") == 1
    )
    if not valid:
        _fail(
            "tracer.artifact_arch_invalid",
            stage,
            "tracer artifact must be an arm64 little-endian ELF64 shared object",
        )
    return candidate


class ArtifactBuilder:
    def __init__(self, runner: CommandRunner, repository: Path | None = None):
        self._runner = runner
        self._repository = (
            Path(repository) if repository is not None else Path(__file__).resolve().parents[1]
        )

    def select_or_build(self, tracer: TracerConfig, *, timeout: float) -> TracerArtifacts:
        timeout = _timeout(timeout)
        custom = (tracer.library, tracer.companion)
        if any(path is not None for path in custom):
            if not all(path is not None for path in custom):
                _fail(
                    "tracer.artifact_pair_incomplete",
                    "build.select",
                    "tracer library and companion must be supplied together",
                )
            assert tracer.library is not None and tracer.companion is not None
            return TracerArtifacts(
                tracer_so=_arm64_shared_object(tracer.library, stage="build.select"),
                companion=_arm64_shared_object(tracer.companion, stage="build.select"),
            )

        gradlew = self._repository / "gradlew"
        try:
            mode = gradlew.lstat().st_mode
        except OSError as error:
            _fail("build.gradle_missing", "build.gradle", f"Gradle wrapper is unavailable: {error}")
        if not stat.S_ISREG(mode) or stat.S_ISLNK(mode) or mode & 0o111 == 0:
            _fail(
                "build.gradle_invalid",
                "build.gradle",
                "Gradle wrapper must be an executable regular non-symlink file",
            )
        try:
            self._runner.capture(
                (str(gradlew), ":tracer:copyTracerDebug"),
                maximum_bytes=_BUILD_OUTPUT_BYTES,
                timeout=timeout,
            )
        except QtraceError as error:
            wrapped = QtraceError(
                "build.gradle_failed", "build.gradle", f"tracer build failed: {error.detail}"
            )
            raise wrapped from error
        except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
            wrapped = QtraceError("build.gradle_failed", "build.gradle", f"tracer build failed: {error}")
            raise wrapped from error

        output = self._repository / "out" / "arm64-v8a"
        return TracerArtifacts(
            tracer_so=_arm64_shared_object(
                output / "libqbdi_tracer.so", stage="build.validate"
            ),
            companion=_arm64_shared_object(
                output / "libshadowhook_nothing.so", stage="build.validate"
            ),
        )


def _remote_join(directory: str, name: str) -> str:
    return str(PurePosixPath(directory) / name)


def _diagnostic(output: bytes) -> str:
    if not isinstance(output, bytes):
        _fail("deploy.probe_malformed", "deploy.probe", "load probe returned non-byte output")
    text = output.decode("utf-8", errors="replace")
    text = " ".join(text.split())
    if not text:
        return "no diagnostic output"
    encoded = text.encode("utf-8")
    if len(encoded) > _PROBE_DETAIL_BYTES:
        text = encoded[:_PROBE_DETAIL_BYTES].decode("utf-8", errors="ignore")
    return text


def _host_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(_HASH_CHUNK_BYTES):
                digest.update(chunk)
    except OSError as error:
        wrapped = QtraceError(
            "tracer.artifact_invalid", "deploy.integrity", f"cannot hash tracer artifact: {error}"
        )
        raise wrapped from error
    return digest.hexdigest()


def _device_sha256(remote: str, shell) -> str:
    output = shell("sha256sum", remote, maximum_bytes=4096)
    if not isinstance(output, bytes):
        _fail("deploy.hash_malformed", "deploy.integrity", "sha256sum returned non-byte output")
    try:
        fields = output.decode("ascii", errors="strict").strip().split()
    except UnicodeDecodeError:
        _fail("deploy.hash_malformed", "deploy.integrity", "sha256sum output is not ASCII")
    if len(fields) != 2 or _SHA256.fullmatch(fields[0]) is None or fields[1] != remote:
        _fail("deploy.hash_malformed", "deploy.integrity", "sha256sum output is malformed")
    return fields[0]


class Deployer:
    def _access_shell(self, device: AdbDevice, package: str, access_mode: str):
        def invoke(*arguments: str, **kwargs):
            if access_mode == "run-as":
                return device.shell("run-as", package, *arguments, **kwargs)
            return device.shell(*arguments, **kwargs)

        return invoke

    def _attempt(
        self,
        device: AdbDevice,
        package: str,
        access_mode: str,
        route: str,
        remote_dir: str,
        session_id: str,
        artifacts: TracerArtifacts,
    ) -> Deployment:
        app_shell = self._access_shell(device, package, access_mode)
        control_shell = device.shell if route == "local-tmp" else app_shell
        probe = _remote_join(remote_dir, f".qtrace-probe-{session_id}")
        tracer_remote = _remote_join(remote_dir, "libqbdi_tracer.so")
        companion_remote = _remote_join(remote_dir, "libshadowhook_nothing.so")
        host_paths = {
            tracer_remote: artifacts.tracer_so,
            companion_remote: artifacts.companion,
        }
        try:
            control_shell("mkdir", "-p", remote_dir, maximum_bytes=64 * 1024)
            control_shell("chmod", "0755", remote_dir, maximum_bytes=64 * 1024)
            control_shell("touch", probe, maximum_bytes=64 * 1024)
            control_shell("chmod", "0644", probe, maximum_bytes=64 * 1024)
            app_shell("cat", probe, maximum_bytes=4096)

            if route == "app-private" and access_mode == "run-as":
                staging_dir = f"/data/local/tmp/qtrace/{session_id}"
                device.shell("mkdir", "-p", staging_dir, maximum_bytes=64 * 1024)
                device.shell("chmod", "0755", staging_dir, maximum_bytes=64 * 1024)
                for remote, host in host_paths.items():
                    staged = _remote_join(staging_dir, f".stage-{PurePosixPath(remote).name}")
                    device.push(host, staged)
                    device.shell("chmod", "0644", staged, maximum_bytes=64 * 1024)
                    app_shell("cp", staged, remote, maximum_bytes=64 * 1024)
            else:
                device.push(artifacts.tracer_so, tracer_remote)
                device.push(artifacts.companion, companion_remote)
            control_shell("chmod", "0755", tracer_remote, maximum_bytes=64 * 1024)
            control_shell("chmod", "0755", companion_remote, maximum_bytes=64 * 1024)

            hashes: dict[str, str] = {}
            for remote, host in host_paths.items():
                host_digest = _host_sha256(host)
                device_digest = _device_sha256(remote, app_shell)
                if host_digest != device_digest:
                    _fail(
                        ErrorCode.ARTIFACT_INTEGRITY_FAILED,
                        "deploy.integrity",
                        f"SHA-256 mismatch for {PurePosixPath(remote).name}",
                    )
                hashes[remote] = host_digest

            load_output = app_shell(
                "env",
                f"LD_LIBRARY_PATH={remote_dir}",
                f"LD_PRELOAD={companion_remote}",
                "/system/bin/linker64",
                "--list",
                tracer_remote,
                maximum_bytes=64 * 1024,
            )
            load_probe = {
                "status": "ok",
                "diagnostic": _diagnostic(load_output),
            }
            return Deployment(
                route=route,
                remote_dir=remote_dir,
                tracer_so=tracer_remote,
                companion=companion_remote,
                sha256=hashes,
                load_probe=load_probe,
            )
        except QtraceError as error:
            if error.code == ErrorCode.ARTIFACT_INTEGRITY_FAILED.value:
                raise
            raise _RouteProbeFailure(str(error)) from error
        except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
            raise _RouteProbeFailure(str(error)) from error
        finally:
            try:
                control_shell("rm", "-f", probe, maximum_bytes=64 * 1024)
            except (QtraceError, OSError, RuntimeError, TimeoutError, TypeError, ValueError):
                pass

    def deploy(
        self, device: AdbDevice, session_id: str, artifacts: TracerArtifacts
    ) -> Deployment:
        if not isinstance(session_id, str) or _UUID4.fullmatch(session_id) is None:
            _fail("session.id_invalid", "deploy", "session ID must be a lowercase UUIDv4")
        package = device.package
        access_mode = device.access_mode
        if package is None or access_mode not in {"root", "run-as"}:
            _fail(
                "device.unbound",
                "deploy",
                "device must be bound by successful preflight before deployment",
            )

        validated = TracerArtifacts(
            tracer_so=_arm64_shared_object(artifacts.tracer_so, stage="deploy.validate"),
            companion=_arm64_shared_object(artifacts.companion, stage="deploy.validate"),
        )
        private_dir = f"/data/user/0/{package}/cache/qtrace/{session_id}"
        try:
            return self._attempt(
                device,
                package,
                access_mode,
                "app-private",
                private_dir,
                session_id,
                validated,
            )
        except _RouteProbeFailure as private_error:
            fallback_dir = f"/data/local/tmp/qtrace/{session_id}"
            try:
                deployment = self._attempt(
                    device,
                    package,
                    access_mode,
                    "local-tmp",
                    fallback_dir,
                    session_id,
                    validated,
                )
            except _RouteProbeFailure as fallback_error:
                wrapped = QtraceError(
                    ErrorCode.TRACER_LOAD_FAILED,
                    "deploy.probe",
                    f"private route failed: {private_error}; fallback failed: {fallback_error}",
                )
                raise wrapped from fallback_error
            probe = dict(deployment.load_probe)
            probe["privateFailure"] = str(private_error)
            return Deployment(
                route=deployment.route,
                remote_dir=deployment.remote_dir,
                tracer_so=deployment.tracer_so,
                companion=deployment.companion,
                sha256=deployment.sha256,
            load_probe=probe,
            )
