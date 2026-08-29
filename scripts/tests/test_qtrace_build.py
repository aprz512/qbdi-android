import hashlib
import math
import os
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from scripts.bounded_process import BoundedProcessError

from qtrace.build import (ArtifactBuilder, Deployer, TracerArtifacts,
                          _snapshot_artifacts)
from qtrace.errors import QtraceError
from qtrace.models import TracerConfig


def arm64_elf() -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    header[16:18] = (3).to_bytes(2, "little")
    header[18:20] = (183).to_bytes(2, "little")
    header[20:24] = (1).to_bytes(4, "little")
    return bytes(header)


def tracer_config(*, library=None, companion=None):
    return TracerConfig(
        profile="fast",
        compression=True,
        flight_enabled=False,
        flight_entry_scene=None,
        library=library,
        companion=companion,
    )


@dataclass(frozen=True)
class RunnerCall:
    command: tuple[str, ...]
    maximum_bytes: int
    timeout: float


class BuildRunner:
    def __init__(self, on_capture=None):
        self.on_capture = on_capture
        self.calls = []

    def capture(self, command, *, maximum_bytes, timeout):
        if isinstance(command, (str, bytes)):
            raise AssertionError("command must be argv")
        if maximum_bytes <= 0 or not math.isfinite(timeout) or timeout <= 0:
            raise AssertionError("build must be bounded")
        self.calls.append(RunnerCall(tuple(command), maximum_bytes, timeout))
        if self.on_capture:
            self.on_capture()
        return b"BUILD SUCCESSFUL\n"


class ArtifactBuilderTests(unittest.TestCase):
    def test_reuses_complete_regular_arm64_pair_without_building(self):
        with tempfile.TemporaryDirectory() as directory:
            tracer = Path(directory) / "tracer.so"
            companion = Path(directory) / "companion.so"
            tracer.write_bytes(arm64_elf())
            companion.write_bytes(arm64_elf())
            runner = BuildRunner()

            artifacts = ArtifactBuilder(runner, Path(directory)).select_or_build(
                tracer_config(library=tracer, companion=companion), timeout=10
            )

            self.assertEqual(TracerArtifacts(tracer, companion), artifacts)
            self.assertEqual([], runner.calls)

    def test_rejects_partial_symlink_nonregular_and_wrong_arch_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "valid.so"
            valid.write_bytes(arm64_elf())
            link = root / "link.so"
            link.symlink_to(valid)
            folder = root / "folder.so"
            folder.mkdir()
            wrong = root / "wrong.so"
            data = bytearray(arm64_elf())
            data[18:20] = (62).to_bytes(2, "little")
            wrong.write_bytes(data)
            pairs = (
                (valid, None),
                (link, valid),
                (folder, valid),
                (wrong, valid),
            )
            for library, companion in pairs:
                with self.subTest(library=library, companion=companion), self.assertRaises(
                    QtraceError
                ):
                    ArtifactBuilder(BuildRunner(), root).select_or_build(
                        tracer_config(library=library, companion=companion), timeout=10
                    )

    def test_runs_only_copy_tracer_debug_and_validates_exact_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gradlew = root / "gradlew"
            gradlew.write_text("#!/bin/sh\n", encoding="utf-8")
            gradlew.chmod(0o755)
            tracer = root / "out/arm64-v8a/libqbdi_tracer.so"
            companion = root / "out/arm64-v8a/libshadowhook_nothing.so"

            def build_outputs():
                tracer.parent.mkdir(parents=True)
                tracer.write_bytes(arm64_elf())
                companion.write_bytes(arm64_elf())

            runner = BuildRunner(build_outputs)
            with patch.dict(os.environ, {"GRADLE_OPTS": "-Dbuild.existing=true"}):
                artifacts = ArtifactBuilder(runner, root).select_or_build(
                    tracer_config(), timeout=12.5
                )

            self.assertEqual(TracerArtifacts(tracer, companion), artifacts)
            self.assertEqual(
                (
                    "/usr/bin/env",
                    "GRADLE_OPTS=-Dbuild.existing=true -Dorg.gradle.daemon.idletimeout=1000",
                    str(gradlew),
                    ":tracer:copyTracerDebug",
                    "--no-daemon",
                ),
                runner.calls[0].command,
            )
            self.assertNotIn("demo", " ".join(runner.calls[0].command).lower())
            self.assertEqual(12.5, runner.calls[0].timeout)


class FakeDeployDevice:
    serial = "SERIAL"

    def __init__(
        self,
        *,
        private_probe=True,
        corrupt_hash=False,
        load_failure=False,
        private_load_failure=False,
        capability_error=None,
        push_error=None,
        chmod_error=None,
        hash_error=None,
        load_error=None,
        staging_cleanup_error=None,
        access_mode="root",
        root_strategy="direct",
        target_strategy="run-as",
        package_uid=20000,
        replace_before_push=None,
        android_user=0,
    ):
        self.package = "com.example.external"
        self.access_mode = access_mode
        self.root_strategy = root_strategy
        self.target_strategy = target_strategy
        self.package_uid = package_uid
        self.android_user = android_user
        self.package_data_dir = f"/data/user/{android_user}/com.example.external"
        self.private_probe = private_probe
        self.corrupt_hash = corrupt_hash
        self.load_failure = load_failure
        self.private_load_failure = private_load_failure
        self.capability_error = capability_error
        self.push_error = push_error
        self.chmod_error = chmod_error
        self.hash_error = hash_error
        self.load_error = load_error
        self.staging_cleanup_error = staging_cleanup_error
        self.replace_before_push = dict(replace_before_push or {})
        self.calls = []
        self.host_by_remote = {}
        self.bytes_by_remote = {}

    def _execute(self, channel, args, timeout, maximum_bytes):
        if timeout <= 0 or maximum_bytes <= 0:
            raise AssertionError("unbounded deployment command")
        self.calls.append((channel, tuple(args), timeout, maximum_bytes))
        command = args
        if command[0] in ("mkdir", "touch", "cat"):
            if any("data/user/0" in arg for arg in command) and not self.private_probe:
                raise QtraceError("device.route_probe_failed", "deploy.probe", "private denied")
            if (
                self.capability_error is not None
                and command[0] in ("touch", "cat")
                and any("data/user/0" in arg for arg in command)
            ):
                raise self.capability_error
            return b""
        if command[0] == "chmod":
            if self.chmod_error is not None and command[-1].endswith(".so"):
                raise self.chmod_error
            return b""
        if command[0] == "cp":
            self.host_by_remote[command[2]] = self.host_by_remote[command[1]]
            self.bytes_by_remote[command[2]] = self.bytes_by_remote[command[1]]
            return b""
        if command[0] == "sha256sum":
            if self.hash_error is not None:
                raise self.hash_error
            digest = hashlib.sha256(self.bytes_by_remote[command[1]]).hexdigest()
            if self.corrupt_hash:
                digest = "0" * 64
            return f"{digest}  {command[1]}\n".encode()
        if command[0] == "env":
            if self.load_error is not None:
                raise self.load_error
            if self.private_load_failure and any("data/user/0" in arg for arg in command):
                raise QtraceError("device.load_probe_failed", "deploy.probe", "private namespace")
            if self.load_failure:
                raise QtraceError("device.load_probe_failed", "deploy.probe", "namespace denied")
            return b"libshadowhook_nothing.so => namespace-ok\n"
        if command[0] == "rm":
            if (self.staging_cleanup_error is not None
                    and command[:2] == ("rm", "-rf")):
                raise self.staging_cleanup_error
            return b""
        raise AssertionError(f"unexpected shell call: {args!r}")

    def shell(self, *args, timeout=30.0, maximum_bytes=1_048_576):
        return self._execute("shell", args, timeout, maximum_bytes)

    def root_shell(self, *args, timeout=30.0, maximum_bytes=1_048_576):
        return self._execute("root", args, timeout, maximum_bytes)

    def target_shell(self, *args, timeout=30.0, maximum_bytes=1_048_576):
        return self._execute("target", args, timeout, maximum_bytes)

    def push(self, source, destination, *, timeout=30.0):
        self.calls.append(("push", Path(source), destination, timeout))
        if self.push_error is not None:
            raise self.push_error
        source = Path(source)
        replacement = self.replace_before_push.get(source)
        if replacement is not None:
            source.write_bytes(replacement)
        self.host_by_remote[destination] = source
        self.bytes_by_remote[destination] = source.read_bytes()

    def push_open_file(self, source_descriptor, destination, *, timeout=30.0):
        source = Path(f"/proc/self/fd/{source_descriptor}")
        self.calls.append(("push", source, destination, timeout, source_descriptor))
        if self.push_error is not None:
            raise self.push_error
        replacement = self.replace_before_push.get(source)
        if replacement is not None:
            source.write_bytes(replacement)
        self.host_by_remote[destination] = source
        self.bytes_by_remote[destination] = source.read_bytes()


class DeployerTests(unittest.TestCase):
    def make_artifacts(self, root):
        tracer = root / "libqbdi_tracer.so"
        companion = root / "libshadowhook_nothing.so"
        tracer.write_bytes(arm64_elf() + b"tracer")
        companion.write_bytes(arm64_elf() + b"companion")
        return TracerArtifacts(tracer, companion)

    def test_prefers_private_route_and_records_verified_hashes_and_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            artifacts = self.make_artifacts(Path(directory))
            device = FakeDeployDevice()
            deployment = Deployer().deploy(
                device, "123e4567-e89b-42d3-a456-426614174000", artifacts
            )

        self.assertEqual("app-private", deployment.route)
        self.assertIn("/data/user/0/com.example.external/", deployment.remote_dir)
        self.assertEqual(2, len(deployment.sha256))
        self.assertEqual("ok", deployment.load_probe["status"])
        pushed = [call for call in device.calls if call[0] == "push"]
        self.assertEqual(2, len(pushed))
        self.assertTrue(any(call[0] == "root" and call[1][0:2] == ("chmod", "0755") for call in device.calls))
        self.assertTrue(any(call[0] == "target" and call[1][0] == "sha256sum" for call in device.calls))

    def test_private_deploy_uses_bound_secondary_user_data_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice(android_user=10, package_uid=1_020_000)
            deployment = Deployer().deploy(
                device, "123e4567-e89b-42d3-a456-426614174000",
                self.make_artifacts(Path(directory)),
            )
        self.assertTrue(deployment.remote_dir.startswith(
            "/data/user/10/com.example.external/cache/qtrace/"
        ))

    def test_snapshot_construction_cleanup_never_masks_primary_and_removes_private_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = self.make_artifacts(root)
            read_primary = RuntimeError("snapshot read primary")
            real_close = os.close
            real_mkdtemp = tempfile.mkdtemp
            close_failed = False

            def close_once(descriptor):
                nonlocal close_failed
                real_close(descriptor)
                if not close_failed:
                    close_failed = True
                    raise OSError("injected close cleanup failure")

            with patch("qtrace.build.tempfile.mkdtemp", side_effect=lambda **kwargs: real_mkdtemp(
                    dir=root, **kwargs)), patch(
                "qtrace.build.os.read", side_effect=read_primary
            ), patch("qtrace.build.os.close", side_effect=close_once):
                with self.assertRaises(RuntimeError) as raised:
                    _snapshot_artifacts(artifacts)

            self.assertIs(read_primary, raised.exception)
            self.assertTrue(any("cleanup failed" in note
                                for note in getattr(read_primary, "__notes__", ())))
            self.assertEqual([], list(root.glob("qtrace-deploy-*")))

    def test_snapshot_root_setup_failure_removes_only_its_owned_empty_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = self.make_artifacts(root)
            real_mkdtemp = tempfile.mkdtemp
            setup_primary = OSError("snapshot chmod primary")
            with patch("qtrace.build.tempfile.mkdtemp", side_effect=lambda **kwargs: real_mkdtemp(
                    dir=root, **kwargs)), patch("qtrace.build.os.chmod", side_effect=setup_primary):
                with self.assertRaises(OSError) as raised:
                    _snapshot_artifacts(artifacts)

            self.assertIs(setup_primary, raised.exception)
            self.assertEqual([], list(root.glob("qtrace-deploy-*")))

    def test_falls_back_only_after_explicit_private_probe_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice(private_probe=False)
            deployment = Deployer().deploy(
                device,
                "123e4567-e89b-42d3-a456-426614174000",
                self.make_artifacts(Path(directory)),
            )
        self.assertEqual("local-tmp", deployment.route)
        self.assertEqual(
            "/data/local/tmp/qtrace/123e4567-e89b-42d3-a456-426614174000",
            deployment.remote_dir,
        )

    def test_run_as_fallback_uses_shell_for_directory_control_and_app_identity_for_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice(
                private_probe=False,
                access_mode="run-as",
                root_strategy="none",
                target_strategy="run-as",
            )
            deployment = Deployer().deploy(
                device,
                "123e4567-e89b-42d3-a456-426614174000",
                self.make_artifacts(Path(directory)),
            )

        self.assertEqual("local-tmp", deployment.route)
        fallback_mkdir = [
            call for call in device.calls
            if call[0] == "shell"
            and call[1][0] == "mkdir"
            and "/data/local/tmp/qtrace/" in call[1][-1]
        ]
        self.assertEqual(1, len(fallback_mkdir))
        self.assertTrue(any(
            call[0] == "target"
            and call[1][0] == "cat"
            and "/data/local/tmp/qtrace/" in call[1][-1]
            for call in device.calls
        ))

    def test_su_root_controls_paths_but_target_identity_reads_hashes_and_loads(self):
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice(root_strategy="su", target_strategy="run-as")
            deployment = Deployer().deploy(
                device,
                "123e4567-e89b-42d3-a456-426614174000",
                self.make_artifacts(Path(directory)),
            )

        self.assertEqual("app-private", deployment.route)
        self.assertTrue(any(call[0] == "root" and call[1][0] == "mkdir" for call in device.calls))
        self.assertTrue(any(call[0] == "target" and call[1][0] == "cat" for call in device.calls))
        self.assertTrue(any(call[0] == "target" and call[1][0] == "sha256sum" for call in device.calls))
        self.assertTrue(any(call[0] == "target" and call[1][0] == "env" for call in device.calls))

    def test_su_root_fallback_stages_shell_push_then_copies_with_root_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice(
                private_probe=False,
                root_strategy="su",
                target_strategy="run-as",
            )
            deployment = Deployer().deploy(
                device,
                "123e4567-e89b-42d3-a456-426614174000",
                self.make_artifacts(Path(directory)),
            )

        self.assertEqual("local-tmp", deployment.route)
        pushed = [call for call in device.calls if call[0] == "push"]
        self.assertTrue(all("/data/local/tmp/qtrace-staging/" in call[2] for call in pushed))
        self.assertEqual(
            2,
            sum(call[0] == "root" and call[1][0] == "cp" for call in device.calls),
        )

    def test_owned_staging_directory_is_removed_after_success(self):
        session_id = "123e4567-e89b-42d3-a456-426614174000"
        staging = f"/data/local/tmp/qtrace-staging/{session_id}"
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice(root_strategy="su")
            Deployer().deploy(device, session_id, self.make_artifacts(Path(directory)))

        removals = [call for call in device.calls
                    if call[0] == "shell" and call[1][:2] == ("rm", "-rf")]
        self.assertEqual([("shell", ("rm", "-rf", staging), 30.0, 64 * 1024)], removals)
        self.assertGreater(device.calls.index(removals[0]),
                           max(index for index, call in enumerate(device.calls)
                               if call[0] == "push"))

    def test_owned_staging_directory_is_removed_after_mid_deploy_failure(self):
        primary = QtraceError("process.timeout", "process", "push transport")
        session_id = "123e4567-e89b-42d3-a456-426614174000"
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice(root_strategy="su", push_error=primary)
            with self.assertRaises(QtraceError) as caught:
                Deployer().deploy(device, session_id, self.make_artifacts(Path(directory)))

        self.assertIs(primary, caught.exception)
        self.assertEqual(1, sum(call[0] == "shell" and call[1] == (
            "rm", "-rf", f"/data/local/tmp/qtrace-staging/{session_id}")
            for call in device.calls))

    def test_staging_cleanup_failure_preserves_primary_and_is_never_silent(self):
        primary = QtraceError("process.timeout", "process", "push transport")
        cleanup = QtraceError("process.timeout", "process", "cleanup transport")
        session_id = "123e4567-e89b-42d3-a456-426614174000"
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice(
                root_strategy="su", push_error=primary, staging_cleanup_error=cleanup,
            )
            with self.assertRaises(QtraceError) as caught:
                Deployer().deploy(device, session_id, self.make_artifacts(Path(directory)))
        self.assertIs(primary, caught.exception)
        self.assertIn("staging directory cleanup failed", "\n".join(caught.exception.__notes__))

        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice(root_strategy="su", staging_cleanup_error=cleanup)
            with self.assertRaises(QtraceError) as caught:
                Deployer().deploy(device, session_id, self.make_artifacts(Path(directory)))
        self.assertIs(cleanup, caught.exception)

    def test_direct_push_route_never_removes_an_uncreated_staging_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice(root_strategy="direct")
            Deployer().deploy(
                device,
                "123e4567-e89b-42d3-a456-426614174000",
                self.make_artifacts(Path(directory)),
            )
        self.assertFalse(any(call[1][:2] == ("rm", "-rf")
                             for call in device.calls if call[0] == "shell"))

    def test_su_uid_defers_loadability_without_running_linker_in_magisk_context(self):
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice(
                root_strategy="su",
                target_strategy="su-uid",
                package_uid=10905,
            )
            deployment = Deployer().deploy(
                device,
                "123e4567-e89b-42d3-a456-426614174000",
                self.make_artifacts(Path(directory)),
            )

        self.assertEqual("app-private", deployment.route)
        self.assertEqual(
            {
                "status": "deferred",
                "reason": "target_process_namespace_required",
                "uid": "10905",
            },
            deployment.load_probe,
        )
        self.assertFalse(any(call[1][0] == "env" for call in device.calls if call[0] == "target"))

    def test_su_uid_private_capability_fallback_keeps_loadability_deferred(self):
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice(
                private_probe=False,
                root_strategy="su",
                target_strategy="su-uid",
                package_uid=10905,
            )
            deployment = Deployer().deploy(
                device,
                "123e4567-e89b-42d3-a456-426614174000",
                self.make_artifacts(Path(directory)),
            )

        self.assertEqual("local-tmp", deployment.route)
        self.assertEqual("deferred", deployment.load_probe["status"])
        self.assertEqual("10905", deployment.load_probe["uid"])
        self.assertIn("privateFailure", deployment.load_probe)
        self.assertFalse(any(call[1][0] == "env" for call in device.calls if call[0] == "target"))

    def test_private_linker_capability_failure_may_fall_back(self):
        with tempfile.TemporaryDirectory() as directory:
            deployment = Deployer().deploy(
                FakeDeployDevice(private_load_failure=True),
                "123e4567-e89b-42d3-a456-426614174000",
                self.make_artifacts(Path(directory)),
            )
        self.assertEqual("local-tmp", deployment.route)

    def test_only_private_permission_process_failures_are_capability_failures(self):
        permission = QtraceError("process.failed", "process", "remote command failed")
        permission.__cause__ = BoundedProcessError(
            "remote command failed", returncode=1, stderr=b"Permission denied\n"
        )
        transport = QtraceError("process.failed", "process", "remote command failed")
        transport.__cause__ = BoundedProcessError(
            "remote command failed", returncode=1, stderr=b"error: device offline\n"
        )

        with tempfile.TemporaryDirectory() as directory:
            deployment = Deployer().deploy(
                FakeDeployDevice(capability_error=permission),
                "123e4567-e89b-42d3-a456-426614174000",
                self.make_artifacts(Path(directory)),
            )
        self.assertEqual("local-tmp", deployment.route)

        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice(capability_error=transport)
            with self.assertRaises(QtraceError) as caught:
                Deployer().deploy(
                    device,
                    "123e4567-e89b-42d3-a456-426614174000",
                    self.make_artifacts(Path(directory)),
                )
        self.assertIs(transport, caught.exception)
        self.assertNotIn("/data/local/tmp/qtrace/", repr(device.calls))

    def test_generic_private_failures_do_not_attempt_fallback(self):
        failures = (
            {"capability_error": QtraceError("process.timeout", "process", "probe transport")},
            {"push_error": QtraceError("process.timeout", "process", "push transport")},
            {"chmod_error": QtraceError("device.command_failed", "deploy", "chmod transport")},
            {"hash_error": QtraceError("device.command_failed", "deploy", "hash transport")},
            {"corrupt_hash": True},
            {"load_error": QtraceError("process.timeout", "process", "load transport")},
        )
        for options in failures:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                device = FakeDeployDevice(**options)
                with self.assertRaises(QtraceError):
                    Deployer().deploy(
                        device,
                        "123e4567-e89b-42d3-a456-426614174000",
                        self.make_artifacts(Path(directory)),
                    )
                self.assertNotIn("/data/local/tmp/qtrace/", repr(device.calls))

    def test_integrity_or_load_failure_removes_only_owned_probe_file(self):
        for options in ({"corrupt_hash": True}, {"load_failure": True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                device = FakeDeployDevice(**options)
                with self.assertRaises(QtraceError):
                    Deployer().deploy(
                        device,
                        "123e4567-e89b-42d3-a456-426614174000",
                        self.make_artifacts(Path(directory)),
                    )
                removals = [
                    call for call in device.calls
                    if call[0] in {"shell", "root", "target"} and call[1][0] == "rm"
                ]
                self.assertGreaterEqual(len(removals), 1)
                self.assertTrue(all(".qtrace-probe-" in call[1][-1] for call in removals))
                self.assertFalse(any("libqbdi_tracer.so" in call[1][-1] for call in removals))

    def test_deploys_and_hashes_one_validated_host_snapshot_when_source_is_replaced(self):
        session_id = "123e4567-e89b-42d3-a456-426614174000"
        with tempfile.TemporaryDirectory() as directory:
            artifacts = self.make_artifacts(Path(directory))
            validated = {
                artifacts.tracer_so: artifacts.tracer_so.read_bytes(),
                artifacts.companion: artifacts.companion.read_bytes(),
            }
            attacker = arm64_elf() + b"replacement"
            device = FakeDeployDevice(replace_before_push={
                artifacts.tracer_so: attacker,
                artifacts.companion: attacker,
            })

            deployment = Deployer().deploy(device, session_id, artifacts)

        for remote, original in zip(
            (deployment.tracer_so, deployment.companion),
            (validated[artifacts.tracer_so], validated[artifacts.companion]),
        ):
            self.assertEqual(original, device.bytes_by_remote[remote])
            self.assertEqual(hashlib.sha256(original).hexdigest(), deployment.sha256[remote])
        pushed_sources = [call[1] for call in device.calls if call[0] == "push"]
        self.assertNotIn(artifacts.tracer_so, pushed_sources)
        self.assertNotIn(artifacts.companion, pushed_sources)
        self.assertTrue(all(
            str(source).startswith("/proc/self/fd/")
            for source in pushed_sources
        ))

    def test_deployer_passes_each_held_snapshot_descriptor_without_a_path_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice()
            Deployer().deploy(
                device,
                "123e4567-e89b-42d3-a456-426614174000",
                self.make_artifacts(Path(directory)),
            )

        pushes = [call for call in device.calls if call[0] == "push"]
        self.assertEqual(2, len(pushes))
        self.assertTrue(all(len(call) == 5 for call in pushes))
        self.assertTrue(all(
            call[1] == Path(f"/proc/self/fd/{call[4]}")
            for call in pushes
        ))

    def test_rejects_non_uuid4_session_before_device_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice()
            for session_id in ("../escape", "123e4567-e89b-12d3-a456-426614174000", "UPPER"):
                with self.subTest(session_id=session_id), self.assertRaises(QtraceError):
                    Deployer().deploy(device, session_id, self.make_artifacts(Path(directory)))
            self.assertEqual([], device.calls)

    def test_deployer_does_not_revalidate_identity_owned_by_bound_device(self):
        session_id = "123e4567-e89b-42d3-a456-426614174000"
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice()
            del device.android_user

            deployment = Deployer().deploy(
                device, session_id, self.make_artifacts(Path(directory))
            )

        self.assertEqual("app-private", deployment.route)
        self.assertTrue(deployment.remote_dir.startswith(device.package_data_dir))


if __name__ == "__main__":
    unittest.main()
