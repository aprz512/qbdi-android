import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from qtrace.build import TracerArtifacts
from qtrace.manual_deploy import payload_identity
from scripts.tracer_build_identity import publish_identity, source_snapshot
from scripts.tests.test_qtrace_build import arm64_elf


class TracerBuildIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True, capture_output=True)
        self.source = self.root / "tracer/src/main/cpp/probe.cpp"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("int probe() { return 1; }\n")
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "core.hooksPath=/dev/null",
            "-c", "commit.gpgsign=false", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "commit", "-qm", "fixture"], check=True)
        self.tracer, self.companion = self.root / "tracer.so", self.root / "companion.so"
        self.tracer.write_bytes(arm64_elf())
        self.companion.write_bytes(arm64_elf() + b"companion")

    def test_same_head_local_changes_and_untracked_inputs_change_build_identity(self):
        before = source_snapshot(self.root)
        self.source.write_text("int probe() { return 2; }\n")
        after = source_snapshot(self.root)
        self.assertEqual(before["revision"], after["revision"])
        self.assertNotEqual(before["source_tree_sha256"], after["source_tree_sha256"])
        self.assertNotEqual(before["dirty_diff_sha256"], after["dirty_diff_sha256"])
        self.source.with_name("extra.cpp").write_text("int extra;\n")
        self.assertNotEqual(after["source_tree_sha256"], source_snapshot(self.root)["source_tree_sha256"])

    def test_publish_rejects_source_changes_and_matching_sidecar_binds_actual_bytes(self):
        before = source_snapshot(self.root)
        output = self.root / "build-identity.json"
        publish_identity(self.root, before, self.tracer, self.companion, output)
        identity = payload_identity(TracerArtifacts(self.tracer, self.companion), output)
        self.assertEqual("recorded", identity["source_status"])
        self.assertEqual(before, identity["build_identity"]["source"])
        self.source.write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "changed during"):
            publish_identity(self.root, before, self.tracer, self.companion, output)
        self.assertEqual(before, json.loads(output.read_text())["source"])

    def test_untracked_submodule_input_changes_identity_without_revision_change(self):
        module = self.source.parent / "engine"
        module.mkdir()
        subprocess.run(["git", "init", "-q", str(module)], check=True, capture_output=True)
        (module / "engine.cpp").write_text("int engine;\n")
        subprocess.run(["git", "-C", str(module), "add", "."], check=True)
        subprocess.run(["git", "-C", str(module), "-c", "core.hooksPath=/dev/null",
            "-c", "commit.gpgsign=false", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "commit", "-qm", "fixture engine"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", str(module)], check=True, capture_output=True)
        before = source_snapshot(self.root)
        extra = module / "extra.cpp"
        extra.write_text("int extra = 1;\n")
        after = source_snapshot(self.root)
        self.assertEqual(before["revision"], after["revision"])
        self.assertNotEqual(before["source_tree_sha256"], after["source_tree_sha256"])
        extra.write_text("int extra = 2;\n")
        self.assertNotEqual(after["source_tree_sha256"], source_snapshot(self.root)["source_tree_sha256"])


if __name__ == "__main__":
    unittest.main()
