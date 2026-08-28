"""Tracer artifact selection, validation, and bounded deployment."""

from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping, Protocol

from scripts.bounded_process import BoundedProcessError

from qtrace.device import AdbDevice
from qtrace.errors import ErrorCode, QtraceError
from qtrace.models import TracerConfig


_BUILD_OUTPUT_BYTES = 4 * 1024 * 1024
_GRADLE_IDLE_BOUND = "-Dorg.gradle.daemon.idletimeout=1000"
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


class _PrivateCapabilityFailure(RuntimeError):
    pass


@dataclass
class _HostArtifactSnapshot:
    name: str
    root_descriptor: int
    descriptor: int
    identity: tuple[int, int]
    sha256: str

    def assert_identity(self) -> None:
        descriptor = os.fstat(self.descriptor)
        pathname = os.stat(
            self.name, dir_fd=self.root_descriptor, follow_symlinks=False,
        )
        if (not stat.S_ISREG(descriptor.st_mode)
                or not stat.S_ISREG(pathname.st_mode)
                or (descriptor.st_dev, descriptor.st_ino) != self.identity
                or (pathname.st_dev, pathname.st_ino) != self.identity):
            _fail(
                "tracer.artifact_replaced",
                "deploy.snapshot",
                "private tracer snapshot identity changed during deployment",
            )


@dataclass
class _HostArtifactSnapshots:
    root: Path
    root_descriptor: int
    root_identity: tuple[int, int]
    tracer: _HostArtifactSnapshot
    companion: _HostArtifactSnapshot

    def close(self, primary: BaseException | None = None) -> None:
        failures: list[tuple[str, BaseException]] = []
        for label, snapshot in (("tracer", self.tracer), ("companion", self.companion)):
            descriptor, snapshot.descriptor = snapshot.descriptor, -1
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except BaseException as error:
                    failures.append((f"{label} descriptor", error))
            try:
                os.unlink(snapshot.name, dir_fd=self.root_descriptor)
            except FileNotFoundError:
                pass
            except BaseException as error:
                failures.append((f"{label} path", error))
        root_descriptor, self.root_descriptor = self.root_descriptor, -1
        if root_descriptor >= 0:
            try:
                os.close(root_descriptor)
            except BaseException as error:
                failures.append(("snapshot root descriptor", error))
        try:
            details = os.stat(self.root, follow_symlinks=False)
            if (not stat.S_ISDIR(details.st_mode)
                    or (details.st_dev, details.st_ino) != self.root_identity):
                raise RuntimeError("snapshot root identity changed before cleanup")
            os.rmdir(self.root)
        except FileNotFoundError:
            pass
        except BaseException as error:
            failures.append(("snapshot root", error))
        if primary is not None:
            for label, error in failures:
                primary.add_note(f"host artifact snapshot cleanup failed for {label}: {error}")
            return
        if failures:
            raise failures[0][1]


_PRIVATE_CAPABILITY_CODES = frozenset({
    "device.route_probe_failed",
    "device.load_probe_failed",
})
_PRIVATE_PERMISSION_MARKERS = (
    b"permission denied",
    b"operation not permitted",
    b"not debuggable",
)


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


def _valid_arm64_shared_object_header(header: bytes) -> bool:
    return (
        len(header) == 64
        and header[:4] == b"\x7fELF"
        and header[4] == 2
        and header[5] == 1
        and header[6] == 1
        and int.from_bytes(header[16:18], "little") == 3
        and int.from_bytes(header[18:20], "little") == 183
        and int.from_bytes(header[20:24], "little") == 1
    )


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
    if not _valid_arm64_shared_object_header(header):
        _fail(
            "tracer.artifact_arch_invalid",
            stage,
            "tracer artifact must be an arm64 little-endian ELF64 shared object",
        )
    return candidate


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        try:
            written = os.write(descriptor, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError("short write while creating tracer snapshot")
        view = view[written:]


def _snapshot_one(source_path: Path, root_descriptor: int, name: str) -> _HostArtifactSnapshot:
    source = -1
    destination = -1
    readable = -1
    try:
        source = os.open(
            os.fspath(source_path),
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        source_details = os.fstat(source)
        if (not stat.S_ISREG(source_details.st_mode)
                or source_details.st_size < 64
                or source_details.st_size > _MAX_TRACER_ARTIFACT_BYTES):
            _fail(
                "tracer.artifact_invalid",
                "deploy.snapshot",
                "tracer artifact must be a bounded regular non-symlink file",
            )
        destination = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o400,
            dir_fd=root_descriptor,
        )
        digest = hashlib.sha256()
        header = bytearray()
        total = 0
        while True:
            try:
                chunk = os.read(source, _HASH_CHUNK_BYTES)
            except InterruptedError:
                continue
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_TRACER_ARTIFACT_BYTES:
                _fail(
                    "tracer.artifact_invalid",
                    "deploy.snapshot",
                    "tracer artifact exceeds the supported bound",
                )
            if len(header) < 64:
                header.extend(chunk[:64 - len(header)])
            digest.update(chunk)
            _write_all(destination, chunk)
        if total != source_details.st_size:
            _fail(
                "tracer.artifact_replaced",
                "deploy.snapshot",
                "tracer artifact changed while it was snapshotted",
            )
        if not _valid_arm64_shared_object_header(bytes(header)):
            _fail(
                "tracer.artifact_arch_invalid",
                "deploy.snapshot",
                "tracer artifact must be an arm64 little-endian ELF64 shared object",
            )
        pathname_details = os.stat(source_path, follow_symlinks=False)
        if (not stat.S_ISREG(pathname_details.st_mode)
                or (pathname_details.st_dev, pathname_details.st_ino)
                != (source_details.st_dev, source_details.st_ino)):
            _fail(
                "tracer.artifact_replaced",
                "deploy.snapshot",
                "tracer artifact pathname changed while it was snapshotted",
            )
        os.fsync(destination)
        held_source, source = source, -1
        os.close(held_source)
        readable = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
        held_destination, destination = destination, -1
        os.close(held_destination)
        snapshot_details = os.fstat(readable)
        snapshot = _HostArtifactSnapshot(
            name,
            root_descriptor,
            readable,
            (snapshot_details.st_dev, snapshot_details.st_ino),
            digest.hexdigest(),
        )
        readable = -1
        return snapshot
    except BaseException as primary:
        cleanup_failures: list[tuple[str, BaseException]] = []
        for label, descriptor in (
            ("source descriptor", source),
            ("snapshot descriptor", destination),
            ("readable snapshot descriptor", readable),
        ):
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_failures.append((label, error))
        try:
            os.unlink(name, dir_fd=root_descriptor)
        except FileNotFoundError:
            pass
        except BaseException as error:
            cleanup_failures.append(("snapshot path", error))
        for label, error in cleanup_failures:
            primary.add_note(f"host artifact snapshot cleanup failed for {label}: {error}")
        raise


def _snapshot_artifacts(artifacts: TracerArtifacts) -> _HostArtifactSnapshots:
    root = Path(tempfile.mkdtemp(prefix="qtrace-deploy-"))
    root_descriptor = -1
    root_identity: tuple[int, int] | None = None
    snapshots: _HostArtifactSnapshots | None = None
    try:
        pathname_details = root.lstat()
        if stat.S_ISLNK(pathname_details.st_mode) or not stat.S_ISDIR(pathname_details.st_mode):
            raise OSError("private snapshot root is not a directory")
        root_identity = (pathname_details.st_dev, pathname_details.st_ino)
        os.chmod(root, 0o700)
        root_descriptor = os.open(
            root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        details = os.fstat(root_descriptor)
        if (not stat.S_ISDIR(details.st_mode)
                or (details.st_dev, details.st_ino) != root_identity):
            raise OSError("private snapshot root identity changed during setup")
        empty = _HostArtifactSnapshot("unused", root_descriptor, -1, (-1, -1), "")
        snapshots = _HostArtifactSnapshots(
            root, root_descriptor, root_identity, empty, empty,
        )
        root_descriptor = -1
        snapshots.tracer = _snapshot_one(
            Path(artifacts.tracer_so), snapshots.root_descriptor, "libqbdi_tracer.so",
        )
        snapshots.companion = _snapshot_one(
            Path(artifacts.companion), snapshots.root_descriptor, "libshadowhook_nothing.so",
        )
        return snapshots
    except BaseException as primary:
        if snapshots is not None:
            snapshots.close(primary)
        else:
            held_descriptor, root_descriptor = root_descriptor, -1
            if held_descriptor >= 0:
                try:
                    os.close(held_descriptor)
                except BaseException as error:
                    primary.add_note(
                        f"host artifact snapshot cleanup failed for root descriptor: {error}"
                    )
            if root_identity is not None:
                try:
                    current = root.lstat()
                    if (not stat.S_ISDIR(current.st_mode)
                            or (current.st_dev, current.st_ino) != root_identity):
                        raise OSError("private snapshot root identity changed before cleanup")
                    os.rmdir(root)
                except BaseException as error:
                    primary.add_note(
                        f"host artifact snapshot cleanup failed for root: {error}"
                    )
        raise


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
        environment_executable = shutil.which("env")
        if environment_executable is None or not os.path.isabs(environment_executable):
            _fail("build.gradle_invalid", "build.gradle", "env executable is unavailable")
        try:
            environment_mode = Path(environment_executable).lstat().st_mode
        except OSError as error:
            _fail("build.gradle_invalid", "build.gradle", f"env executable is unavailable: {error}")
        if (not stat.S_ISREG(environment_mode) or stat.S_ISLNK(environment_mode) or
                environment_mode & 0o111 == 0):
            _fail(
                "build.gradle_invalid",
                "build.gradle",
                "env executable must be an executable regular non-symlink file",
            )
        inherited_gradle_options = os.environ.get("GRADLE_OPTS", "")
        gradle_options = (
            f"{inherited_gradle_options} {_GRADLE_IDLE_BOUND}"
            if inherited_gradle_options else _GRADLE_IDLE_BOUND
        )
        try:
            self._runner.capture(
                (
                    environment_executable,
                    f"GRADLE_OPTS={gradle_options}",
                    str(gradlew),
                    ":tracer:copyTracerDebug",
                    "--no-daemon",
                ),
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


def _is_private_capability_failure(error: QtraceError) -> bool:
    """Recognize only an explicit/private permission denial, never transport loss."""
    if error.code in _PRIVATE_CAPABILITY_CODES:
        return True
    cause = error.__cause__
    if not isinstance(cause, BoundedProcessError) or cause.returncode is None:
        return False
    stderr = cause.stderr.lower()
    return any(marker in stderr for marker in _PRIVATE_PERMISSION_MARKERS)


def _device_operation(stage: str, operation):
    try:
        return operation()
    except QtraceError:
        raise
    except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as error:
        wrapped = QtraceError(
            "device.command_failed", stage, f"device deployment operation failed: {error}"
        )
        raise wrapped from error


class Deployer:
    def _control_shell(self, device: AdbDevice, access_mode: str, route: str):
        if access_mode == "root":
            return device.root_shell
        if route == "app-private":
            return device.target_shell
        return device.shell

    def _probe_route_capability(
        self,
        *,
        control_shell,
        target_shell,
        route: str,
        remote_dir: str,
        probe: str,
    ) -> None:
        try:
            _device_operation(
                "deploy.probe",
                lambda: control_shell("mkdir", "-p", remote_dir, maximum_bytes=64 * 1024),
            )
            _device_operation(
                "deploy.probe",
                lambda: control_shell("chmod", "0755", remote_dir, maximum_bytes=64 * 1024),
            )
            _device_operation(
                "deploy.probe",
                lambda: control_shell("touch", probe, maximum_bytes=64 * 1024),
            )
            _device_operation(
                "deploy.probe",
                lambda: control_shell("chmod", "0644", probe, maximum_bytes=64 * 1024),
            )
            _device_operation(
                "deploy.probe",
                lambda: target_shell("cat", probe, maximum_bytes=4096),
            )
        except QtraceError as error:
            if route == "app-private" and _is_private_capability_failure(error):
                raise _PrivateCapabilityFailure(str(error)) from error
            raise

    def _probe_load(
        self,
        *,
        target_shell,
        route: str,
        remote_dir: str,
        tracer_remote: str,
        companion_remote: str,
    ) -> bytes:
        try:
            return _device_operation(
                "deploy.probe",
                lambda: target_shell(
                    "env",
                    f"LD_LIBRARY_PATH={remote_dir}",
                    f"LD_PRELOAD={companion_remote}",
                    "/system/bin/linker64",
                    "--list",
                    tracer_remote,
                    maximum_bytes=64 * 1024,
                ),
            )
        except QtraceError as error:
            if route == "app-private" and _is_private_capability_failure(error):
                raise _PrivateCapabilityFailure(str(error)) from error
            if _is_private_capability_failure(error):
                wrapped = QtraceError(
                    ErrorCode.TRACER_LOAD_FAILED,
                    "deploy.probe",
                    f"target linker load probe failed: {error.detail}",
                )
                raise wrapped from error
            raise

    def _attempt(
        self,
        device: AdbDevice,
        package: str,
        access_mode: str,
        route: str,
        remote_dir: str,
        session_id: str,
        artifacts: _HostArtifactSnapshots,
    ) -> Deployment:
        target_shell = device.target_shell
        control_shell = self._control_shell(device, access_mode, route)
        probe = _remote_join(remote_dir, f".qtrace-probe-{session_id}")
        tracer_remote = _remote_join(remote_dir, "libqbdi_tracer.so")
        companion_remote = _remote_join(remote_dir, "libshadowhook_nothing.so")
        host_paths = {
            tracer_remote: artifacts.tracer,
            companion_remote: artifacts.companion,
        }
        staging_dir: str | None = None
        try:
            self._probe_route_capability(
                control_shell=control_shell,
                target_shell=target_shell,
                route=route,
                remote_dir=remote_dir,
                probe=probe,
            )

            # adb push uses the adbd identity even when control is bound to Magisk
            # su. Stage as shell, then let the selected control identity publish
            # into app-private or root-created local-tmp directories.
            needs_staging = device.root_strategy == "su" or (
                route == "app-private" and access_mode == "run-as"
            )
            if needs_staging:
                staging_dir = f"/data/local/tmp/qtrace-staging/{session_id}"
                _device_operation(
                    "deploy.stage",
                    lambda: device.shell(
                        "mkdir", "-p", staging_dir, maximum_bytes=64 * 1024
                    ),
                )
                _device_operation(
                    "deploy.stage",
                    lambda: device.shell(
                        "chmod", "0755", staging_dir, maximum_bytes=64 * 1024
                    ),
                )
                for remote, host in host_paths.items():
                    staged = _remote_join(staging_dir, f".stage-{PurePosixPath(remote).name}")
                    host.assert_identity()
                    _device_operation(
                        "deploy.push",
                        lambda: device.push_open_file(host.descriptor, staged),
                    )
                    host.assert_identity()
                    _device_operation(
                        "deploy.stage",
                        lambda: device.shell(
                            "chmod", "0644", staged, maximum_bytes=64 * 1024
                        ),
                    )
                    _device_operation(
                        "deploy.stage",
                        lambda: control_shell("cp", staged, remote, maximum_bytes=64 * 1024),
                    )
            else:
                for remote, host in host_paths.items():
                    host.assert_identity()
                    _device_operation(
                        "deploy.push",
                        lambda remote=remote, host=host: device.push_open_file(
                            host.descriptor, remote,
                        ),
                    )
                    host.assert_identity()
            _device_operation(
                "deploy.permissions",
                lambda: control_shell("chmod", "0755", tracer_remote, maximum_bytes=64 * 1024),
            )
            _device_operation(
                "deploy.permissions",
                lambda: control_shell("chmod", "0755", companion_remote, maximum_bytes=64 * 1024),
            )

            hashes: dict[str, str] = {}
            for remote, host in host_paths.items():
                host.assert_identity()
                host_digest = host.sha256
                device_digest = _device_operation(
                    "deploy.integrity", lambda: _device_sha256(remote, target_shell)
                )
                if host_digest != device_digest:
                    _fail(
                        ErrorCode.ARTIFACT_INTEGRITY_FAILED,
                        "deploy.integrity",
                        f"SHA-256 mismatch for {PurePosixPath(remote).name}",
                    )
                hashes[remote] = host_digest

            if device.target_strategy == "su-uid":
                # Numeric UID switching proves bounded file access only. Magisk's
                # SELinux domain/linker namespace is not the spawned app's, so the
                # in-process Module.load performed during injection is authoritative.
                load_probe = {
                    "status": "deferred",
                    "reason": "target_process_namespace_required",
                    "uid": str(device.package_uid),
                }
            else:
                load_output = self._probe_load(
                    target_shell=target_shell,
                    route=route,
                    remote_dir=remote_dir,
                    tracer_remote=tracer_remote,
                    companion_remote=companion_remote,
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
        finally:
            primary = sys.exc_info()[1]
            staging_cleanup: BaseException | None = None
            if staging_dir is not None:
                try:
                    _device_operation(
                        "deploy.cleanup",
                        lambda: device.shell(
                            "rm", "-rf", staging_dir, maximum_bytes=64 * 1024
                        ),
                    )
                except BaseException as error:
                    staging_cleanup = error
            try:
                control_shell("rm", "-f", probe, maximum_bytes=64 * 1024)
            except (QtraceError, OSError, RuntimeError, TimeoutError, TypeError, ValueError):
                pass
            if staging_cleanup is not None:
                if primary is not None:
                    primary.add_note(
                        f"staging directory cleanup failed: {staging_cleanup}"
                    )
                else:
                    raise staging_cleanup

    def deploy(
        self, device: AdbDevice, session_id: str, artifacts: TracerArtifacts
    ) -> Deployment:
        if not isinstance(session_id, str) or _UUID4.fullmatch(session_id) is None:
            _fail("session.id_invalid", "deploy", "session ID must be a lowercase UUIDv4")
        package = device.package
        access_mode = device.access_mode
        root_strategy = device.root_strategy
        package_uid = device.package_uid
        target_strategy = device.target_strategy
        android_user = getattr(device, "android_user", None)
        package_data_dir = getattr(device, "package_data_dir", None)
        valid_binding = (
            package is not None
            and access_mode in {"root", "run-as"}
            and isinstance(package_uid, int)
            and not isinstance(package_uid, bool)
            and package_uid > 0
            and target_strategy in {"run-as", "su-uid"}
            and isinstance(android_user, int)
            and not isinstance(android_user, bool)
            and android_user >= 0
            and package_uid // 100_000 == android_user
            and package_data_dir == f"/data/user/{android_user}/{package}"
            and (
                (access_mode == "root" and root_strategy in {"direct", "su"})
                or (
                    access_mode == "run-as"
                    and root_strategy == "none"
                    and target_strategy == "run-as"
                )
            )
            and (target_strategy != "su-uid" or access_mode == "root")
        )
        if not valid_binding:
            _fail(
                "device.unbound",
                "deploy",
                "device must be bound by successful preflight before deployment",
            )

        snapshots = _snapshot_artifacts(artifacts)
        primary: BaseException | None = None
        try:
            try:
                private_dir = f"{package_data_dir}/cache/qtrace/{session_id}"
                return self._attempt(
                    device,
                    package,
                    access_mode,
                    "app-private",
                    private_dir,
                    session_id,
                    snapshots,
                )
            except _PrivateCapabilityFailure as private_error:
                fallback_dir = f"/data/local/tmp/qtrace/{session_id}"
                try:
                    deployment = self._attempt(
                        device,
                        package,
                        access_mode,
                        "local-tmp",
                        fallback_dir,
                        session_id,
                        snapshots,
                    )
                except QtraceError as fallback_error:
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
        except BaseException as error:
            primary = error
            raise
        finally:
            snapshots.close(primary)
