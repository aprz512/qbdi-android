import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qtrace.build import Deployer, Deployment, TracerArtifacts
from qtrace.cli import main
from qtrace.device import _read_only_regular_descriptor
from qtrace.errors import QtraceError
from qtrace.manual_deploy import deploy_manual, payload_identity
from scripts.tests.test_qtrace_build import FakeDeployDevice, arm64_elf


class Device:
    serial = "unit-device"
    package = "com.example.app"
    android_user = 0
    access_mode = "run-as"
    package_data_dir = "/data/user/0/com.example.app"

    def __init__(self):
        self.files = {}
        self.directories = set()
        self.fail_hash = False

    def target_shell(self, *args, **options):
        if args[0] == "mkdir":
            if "-p" not in args and args[-1] in self.directories:
                raise QtraceError("device.command_failed", "test", "File exists")
            self.directories.add(args[-1])
        elif args[0] == "cp":
            self.files[args[2]] = self.files[args[1]]
        elif args[0] == "sha256sum":
            digest = "0" * 64 if self.fail_hash else hashlib.sha256(self.files[args[1]]).hexdigest()
            return f"{digest}  {args[1]}\n".encode()
        elif args[0] == "rm":
            name = args[-1]
            self.files = {key: value for key, value in self.files.items()
                          if key != name and not key.startswith(name + "/")}
            self.directories.discard(name)
        return b""

    shell = target_shell

    def push_open_file(self, descriptor, remote, **options):
        _read_only_regular_descriptor(descriptor, stage="test.deploy.push")
        self.files[remote] = os.read(descriptor, 1024**2 + 1)


class FixtureDeployer(Deployer):
    def deploy(self, device, session_id, artifacts, *, private_only=False):
        if not private_only:
            raise AssertionError("manual deployment must use app-private storage")
        directory = f"{device.package_data_dir}/cache/qtrace/{session_id}"
        tracer, companion = directory + "/libqbdi_tracer.so", directory + "/libshadowhook_nothing.so"
        device.files[tracer] = artifacts.tracer_so.read_bytes()
        device.files[companion] = artifacts.companion.read_bytes()
        return Deployment("app-private", directory, tracer, companion,
            {name: hashlib.sha256(device.files[name]).hexdigest() for name in (tracer, companion)}, {"status": "ok"})


class RootParentDevice(Device):
    access_mode = "root"
    private_parent = Device.package_data_dir + "/cache/qtrace"

    def __init__(self):
        super().__init__()
        self.directories.update((self.private_parent, self.private_parent + "/older"))
        self.files[self.private_parent + "/older/keep"] = b"keep"

    def target_shell(self, *args, **options):
        if args[0] in {"mkdir", "rm"} and args[-1].startswith(self.private_parent + "/"):
            raise QtraceError("process.failed", "test", "Permission denied: root-owned session parent")
        return super().target_shell(*args, **options)

    def root_shell(self, *args, **options):
        return Device.target_shell(self, *args, **options)


class ManualDeployTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tracer, self.companion = self.root / "tracer.so", self.root / "companion.so"
        self.tracer.write_bytes(arm64_elf())
        self.companion.write_bytes(arm64_elf() + b"companion")
        self.artifacts = TracerArtifacts(self.tracer, self.companion)
        self.config = self.root / "native.json"
        self.config.write_text(json.dumps({"schemaVersion": 1, "packageName": Device.package,
            "session": {"id": "old-session"}, "targetModule": "libtarget.so"}))
        self.output = self.root / "receipt.json"
        self.device = Device()

    def deploy(self, **options):
        return deploy_manual(self.device, self.artifacts, self.config, self.output,
                             deployer=FixtureDeployer(), **options)

    def test_native_config_and_payload_hashes_are_bound_without_claiming_process_load(self):
        result = self.deploy()
        remote = json.loads(self.device.files[result["config"]])
        self.assertEqual(result["session_id"], remote["session"]["id"])
        self.assertEqual("old-session", json.loads(self.config.read_text())["session"]["id"])
        self.assertEqual("unknown", result["loaded_payload_status"])
        self.assertEqual("unknown", result["payload"]["source_status"])
        self.assertEqual(result, json.loads(self.output.read_text()))
        self.assertFalse(any(name.startswith("/data/local/tmp/") for name in self.device.files))

    def test_native_config_without_optional_session_gets_a_fresh_session(self):
        config = json.loads(self.config.read_text())
        del config["session"]
        self.config.write_text(json.dumps(config))
        result = self.deploy()
        deployed = json.loads(self.device.files[result["config"]])
        self.assertEqual({"id": result["session_id"]}, deployed.pop("session"))
        self.assertEqual(config, deployed)
        self.assertEqual(config, json.loads(self.config.read_text()))

    def test_failure_cleans_only_the_reserved_session_and_staging(self):
        self.device.files["/unrelated/user-file"] = b"keep"
        self.device.fail_hash = True
        with self.assertRaisesRegex(QtraceError, "config_hash_mismatch"):
            self.deploy()
        self.assertEqual({"/unrelated/user-file": b"keep"}, self.device.files)
        self.assertFalse(self.output.exists())

    def test_root_owned_session_parent_uses_control_identity_and_preserves_existing_files(self):
        self.device = RootParentDevice()
        result = self.deploy()
        self.assertIn(result["config"], self.device.files)
        self.assertEqual(b"keep", self.device.files[self.device.private_parent + "/older/keep"])
        self.assertIn(self.device.private_parent + "/older", self.device.directories)

    def test_root_owned_session_parent_uses_control_identity_for_failure_cleanup(self):
        self.device = RootParentDevice()
        self.device.fail_hash = True
        before = dict(self.device.files)
        with self.assertRaisesRegex(QtraceError, "config_hash_mismatch"):
            self.deploy()
        self.assertEqual(before, self.device.files)
        self.assertEqual({self.device.private_parent, self.device.private_parent + "/older"},
                         self.device.directories)
        self.assertFalse(self.output.exists())

    def test_existing_session_and_receipt_are_preserved(self):
        self.output.write_text("keep")
        with self.assertRaises(FileExistsError):
            self.deploy()
        self.output.unlink()
        session = "11111111-1111-4111-8111-111111111111"
        private = f"{self.device.package_data_dir}/cache/qtrace/{session}"
        self.device.directories.add(private)
        self.device.files[private + "/keep"] = b"keep"
        with patch("qtrace.manual_deploy.uuid.uuid4", return_value=session):
            with self.assertRaises(QtraceError):
                self.deploy()
        self.assertEqual(b"keep", self.device.files[private + "/keep"])

    def test_old_or_mismatched_build_identity_is_rejected_before_deployment(self):
        identity = self.root / "build-identity.json"
        identity.write_text(json.dumps({"schema_version": 1, "source": {}, "artifacts": {}}))
        with self.assertRaisesRegex(QtraceError, "identity_mismatch"):
            self.deploy(identity_path=identity)
        self.assertFalse(self.device.directories)

    def test_private_capability_failure_never_falls_back_to_shared_storage(self):
        device = FakeDeployDevice(private_probe=False)
        with self.assertRaisesRegex(QtraceError, "app-private deployment is unavailable"):
            Deployer().deploy(device, "11111111-1111-4111-8111-111111111111",
                              self.artifacts, private_only=True)
        self.assertNotIn("/data/local/tmp/qtrace/", repr(device.calls))

    def test_cli_deploy_does_not_construct_a_frida_orchestrator(self):
        output = io.StringIO()
        with patch("qtrace.cli._select_device", return_value=self.device), \
                patch("qtrace.cli.bind_package_access", return_value=self.device), \
                patch("qtrace.manual_deploy.Deployer", FixtureDeployer), \
                patch("qtrace.cli._make_orchestrator", side_effect=AssertionError("Frida")), \
                contextlib.redirect_stdout(output):
            self.assertEqual(0, main(["deploy", "--package", Device.package,
                "--library", str(self.tracer), "--companion", str(self.companion),
                "--config", str(self.config), "--output", str(self.output)]))
        self.assertEqual("unknown", json.loads(output.getvalue())["loaded_payload_status"])

    def test_bad_native_config_is_rejected_before_contacting_a_device(self):
        self.config.write_text('{"schemaVersion":1,"packageName":"wrong","session":{}}')
        with patch("qtrace.cli._select_device", side_effect=AssertionError("unexpected device access")), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertNotEqual(0, main(["deploy", "--package", Device.package,
                "--library", str(self.tracer), "--companion", str(self.companion),
                "--config", str(self.config), "--output", str(self.output)]))


if __name__ == "__main__":
    unittest.main()
