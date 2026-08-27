import hashlib
import math
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from qtrace.build import ArtifactBuilder, Deployer, TracerArtifacts
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
            artifacts = ArtifactBuilder(runner, root).select_or_build(
                tracer_config(), timeout=12.5
            )

            self.assertEqual(TracerArtifacts(tracer, companion), artifacts)
            self.assertEqual(
                (str(gradlew), ":tracer:copyTracerDebug"), runner.calls[0].command
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
        access_mode="root",
    ):
        self.package = "com.example.external"
        self.access_mode = access_mode
        self.private_probe = private_probe
        self.corrupt_hash = corrupt_hash
        self.load_failure = load_failure
        self.calls = []
        self.host_by_remote = {}

    def shell(self, *args, timeout=30.0, maximum_bytes=1_048_576):
        if timeout <= 0 or maximum_bytes <= 0:
            raise AssertionError("unbounded deployment command")
        self.calls.append(("shell", tuple(args), timeout, maximum_bytes))
        command = args[2:] if args[:2] == ("run-as", self.package) else args
        if command[0] in ("mkdir", "touch", "cat"):
            if any("data/user/0" in arg for arg in command) and not self.private_probe:
                raise QtraceError("device.route_probe_failed", "deploy.probe", "private denied")
            return b""
        if command[0] == "chmod":
            return b""
        if command[0] == "sha256sum":
            digest = hashlib.sha256(self.host_by_remote[command[1]].read_bytes()).hexdigest()
            if self.corrupt_hash:
                digest = "0" * 64
            return f"{digest}  {command[1]}\n".encode()
        if command[0] == "env":
            if self.load_failure:
                raise QtraceError("device.load_probe_failed", "deploy.probe", "namespace denied")
            return b"libshadowhook_nothing.so => namespace-ok\n"
        if command[0] == "rm":
            return b""
        raise AssertionError(f"unexpected shell call: {args!r}")

    def push(self, source, destination, *, timeout=30.0):
        self.calls.append(("push", Path(source), destination, timeout))
        self.host_by_remote[destination] = Path(source)


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
        self.assertTrue(any(call[0] == "shell" and call[1][0:2] == ("chmod", "0755") for call in device.calls))

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
            device = FakeDeployDevice(private_probe=False, access_mode="run-as")
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
            call[0] == "shell"
            and call[1][:3] == ("run-as", "com.example.external", "cat")
            and "/data/local/tmp/qtrace/" in call[1][-1]
            for call in device.calls
        ))

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
                removals = [call for call in device.calls if call[0] == "shell" and call[1][0] == "rm"]
                self.assertGreaterEqual(len(removals), 1)
                self.assertTrue(all(".qtrace-probe-" in call[1][-1] for call in removals))
                self.assertFalse(any("libqbdi_tracer.so" in call[1][-1] for call in removals))

    def test_rejects_non_uuid4_session_before_device_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice()
            for session_id in ("../escape", "123e4567-e89b-12d3-a456-426614174000", "UPPER"):
                with self.subTest(session_id=session_id), self.assertRaises(QtraceError):
                    Deployer().deploy(device, session_id, self.make_artifacts(Path(directory)))
            self.assertEqual([], device.calls)

    def test_rejects_an_unbound_device_before_device_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            device = FakeDeployDevice()
            device.package = None
            device.access_mode = None
            with self.assertRaisesRegex(QtraceError, "device.unbound"):
                Deployer().deploy(
                    device,
                    "123e4567-e89b-42d3-a456-426614174000",
                    self.make_artifacts(Path(directory)),
                )
            self.assertEqual([], device.calls)


if __name__ == "__main__":
    unittest.main()
