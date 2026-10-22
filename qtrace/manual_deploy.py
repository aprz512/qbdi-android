"""Deploy an existing native configuration and payload without starting Frida."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
import uuid

from qtrace.abi import require_abi_acceptance, require_abi_deployment
from qtrace.build import Deployer, TracerArtifacts, _arm64_shared_object, _device_sha256
from qtrace.config import _read_config_bytes
from qtrace.errors import QtraceError
from qtrace.status import load_strict_json
from scripts.tracer_build_identity import file_sha256


def payload_identity(artifacts: TracerArtifacts, identity_path=None):
    paths = {"libqbdi_tracer.so": artifacts.tracer_so, "libshadowhook_nothing.so": artifacts.companion}
    hashes = {}
    for name, path in paths.items():
        _arm64_shared_object(path, stage="payload.identity")
        before = path.stat()
        hashes[name] = file_sha256(path)
        after = path.stat()
        if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
            raise QtraceError("tracer.identity_changed", "payload.identity", "payload changed during identity inspection")
    candidate = Path(identity_path) if identity_path is not None else artifacts.tracer_so.parent / "build-identity.json"
    recorded = None
    if identity_path is not None or candidate.exists():
        _, raw = _read_config_bytes(candidate)
        recorded = load_strict_json(raw, maximum_bytes=1024**2)
        if (type(recorded) is not dict or type(recorded.get("schema_version")) is not int or
                recorded["schema_version"] != 1 or recorded.get("artifacts") != hashes or
                type(recorded.get("source")) is not dict):
            raise QtraceError("tracer.identity_mismatch", "payload.identity", "build identity does not match the selected payload pair")
    return {"artifacts": hashes, "build_identity": recorded,
            "source_status": "recorded" if recorded is not None else "unknown"}


def _publish_receipt(path, receipt):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".deploy-receipt-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(receipt, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_manual_config(config_path, output, package):
    if os.path.lexists(output):
        raise FileExistsError(f"deployment receipt already exists: {output}")
    _, raw = _read_config_bytes(config_path)
    config = load_strict_json(raw, maximum_bytes=1024**2)
    if (type(config) is not dict or type(config.get("schemaVersion")) is not int or config["schemaVersion"] != 1 or
            config.get("packageName") != package or type(config.get("session", {})) is not dict):
        raise QtraceError("deploy.config_invalid", "deploy.config", "expected native JSON with matching packageName and an optional session object; see docs/manual-tracing.md")
    config.setdefault("session", {})
    return raw, config


def deploy_manual(device, artifacts, config_path, output, *, identity_path=None,
                  abi_report=None, timeout=30.0, deployer=None):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise QtraceError("deploy.timeout_invalid", "deploy", "timeout must be finite and positive")
    raw, config = read_manual_config(config_path, output, device.package)
    identity = payload_identity(artifacts, identity_path)
    abi = require_abi_acceptance(abi_report, device, artifacts, timeout=timeout) if abi_report is not None else None
    session_id = str(uuid.uuid4())
    config["session"]["id"] = session_id
    encoded = json.dumps(config, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
    if len(encoded) > 1024**2:
        raise QtraceError("deploy.config_invalid", "deploy.config", "serialized native config exceeds 1 MiB")
    private = f"{device.package_data_dir}/cache/qtrace/{session_id}"
    staging = f"/data/local/tmp/qtrace-config-{session_id}.json"
    deployer = deployer or Deployer()
    private_control = deployer._control_shell(device, device.access_mode, "app-private")
    deployment = None
    owns_private = staged = succeeded = False
    primary = None
    try:
        # Reserve this session atomically. An existing directory is never claimed
        # or cleaned by this invocation, even if a UUID factory is replaced.
        # A previous root deployment may own the shared parent. Use the same
        # control identity as Deployer without changing that parent's ownership.
        private_control("mkdir", "-p", str(Path(private).parent), timeout=timeout, maximum_bytes=4096)
        private_control("mkdir", private, timeout=timeout, maximum_bytes=4096)
        owns_private = True
        deployment = deployer.deploy(device, session_id, artifacts, private_only=True)
        expected = identity["artifacts"]
        if (deployment.sha256.get(deployment.tracer_so) != expected["libqbdi_tracer.so"] or
                deployment.sha256.get(deployment.companion) != expected["libshadowhook_nothing.so"]):
            raise QtraceError("tracer.identity_mismatch", "deploy.identity", "deployed payload differs from inspected source artifacts")
        if abi is not None:
            require_abi_deployment(abi, deployment)
        control = deployer._control_shell(device, device.access_mode, deployment.route)
        remote_config = deployment.remote_dir + "/config.json"
        with tempfile.TemporaryDirectory(prefix="qtrace-native-config-") as directory:
            temporary_config = Path(directory) / "config.json"
            temporary_config.write_bytes(encoded)
            with temporary_config.open("rb") as source:
                staged = True
                device.push_open_file(source.fileno(), staging, timeout=timeout)
        device.shell("chmod", "0644", staging, timeout=timeout, maximum_bytes=4096)
        control("cp", staging, remote_config, timeout=timeout, maximum_bytes=4096)
        control("chmod", "0644", remote_config, timeout=timeout, maximum_bytes=4096)
        config_hash = hashlib.sha256(encoded).hexdigest()
        if _device_sha256(remote_config, lambda *args, **kwargs: device.target_shell(
                *args, timeout=timeout, **kwargs)) != config_hash:
            raise QtraceError("deploy.config_hash_mismatch", "deploy.config", "deployed native configuration SHA-256 differs")
        receipt = {"schema_version": 1, "session_id": session_id, "device": device.serial,
            "package": device.package, "android_user": device.android_user,
            "route": deployment.route, "remote_dir": deployment.remote_dir,
            "tracer_so": deployment.tracer_so, "companion": deployment.companion,
            "config": remote_config, "source_config_sha256": hashlib.sha256(raw).hexdigest(),
            "config_sha256": config_hash, "payload": identity, "load_probe": dict(deployment.load_probe),
            "abi_acceptance": abi, "loaded_payload_status": "unknown",
            "native_config_validation": "not_performed; native configure remains authoritative"}
        device.shell("rm", "-f", staging, timeout=timeout, maximum_bytes=4096)
        staged = False
        _publish_receipt(output, receipt)
        succeeded = True
        return receipt
    except BaseException as error:
        primary = error
        raise
    finally:
        failures = []
        if staged:
            try:
                device.shell("rm", "-f", staging, timeout=timeout, maximum_bytes=4096)
            except BaseException as error:
                failures.append(str(error))
        if not succeeded and deployment is not None and deployment.remote_dir != private:
            try:
                deployer._control_shell(device, device.access_mode, deployment.route)(
                    "rm", "-rf", deployment.remote_dir, timeout=timeout, maximum_bytes=4096)
            except BaseException as error:
                failures.append(str(error))
        if owns_private and (not succeeded or deployment.remote_dir != private):
            try:
                private_control("rm", "-rf", private, timeout=timeout, maximum_bytes=4096)
            except BaseException as error:
                failures.append(str(error))
        if failures:
            detail = f"deployment cleanup incomplete for session {session_id}: " + "; ".join(failures)
            if primary is not None:
                primary.add_note(detail)
            else:
                raise QtraceError("deploy.cleanup_failed", "deploy.cleanup", detail)
