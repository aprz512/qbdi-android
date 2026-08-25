import os
import re
import subprocess
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
GRADLE_TIMEOUT_SECONDS = 300

LEGACY_CONFIGURATION_PATTERNS = (
    r"\bqbdi_tracer_configure\b",
    r"\bparse_trace_config\b",
    r"scenes=replace",
    r"waiting for qbdi_tracer_configure",
)
CONFIGURATION_PRODUCERS = (
    ROOT / "scripts/spawn_trace.js",
    ROOT / "scripts/benchmark_trace.js",
    ROOT / "scripts/benchmark_trace.py",
    ROOT / "scripts/flight_acceptance.py",
)
NATIVE_SOURCE_SUFFIXES = frozenset((".c", ".cc", ".cpp", ".h", ".hpp"))


def production_native_sources():
    native_root = ROOT / "tracer/src/main/cpp"
    return tuple(
        path
        for path in native_root.rglob("*")
        if path.is_file()
        and path.suffix in NATIVE_SOURCE_SUFFIXES
        and "third_party" not in path.relative_to(native_root).parts
        and "build" not in path.relative_to(native_root).parts
    )


def run_gradle(*arguments, environment=None):
    process_environment = os.environ.copy()
    if environment:
        for name, value in environment.items():
            if value is None:
                process_environment.pop(name, None)
            else:
                process_environment[name] = value

    return subprocess.run(
        ["./gradlew", *arguments, "--no-daemon", "--console=plain"],
        cwd=ROOT,
        env=process_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout=GRADLE_TIMEOUT_SECONDS,
    )


class StructuredConfigurationContractTests(unittest.TestCase):
    def test_production_configuration_has_no_legacy_protocol(self):
        native_sources = production_native_sources()
        self.assertTrue(native_sources)
        for path in native_sources + CONFIGURATION_PRODUCERS:
            source = path.read_text(encoding="utf-8")
            for pattern in LEGACY_CONFIGURATION_PATTERNS:
                with self.subTest(path=path.relative_to(ROOT), pattern=pattern):
                    self.assertIsNone(re.search(pattern, source))

        # scene= remains valid trace/log output. Only configuration producers
        # are forbidden from emitting the removed assignment protocol.
        for path in CONFIGURATION_PRODUCERS:
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path.relative_to(ROOT), marker="scene="):
                self.assertNotIn("scene=", source)


class ManifestIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe = run_gradle(
            ":app:processDebugManifest",
            ":app:processReleaseManifest",
            "--rerun-tasks",
        )
        if cls.probe.returncode != 0:
            raise AssertionError(cls.probe.stdout)

    def application_debuggable(self, variant):
        manifest = (
            ROOT
            / "app/build/intermediates/merged_manifests"
            / variant
            / f"process{variant.title()}Manifest/AndroidManifest.xml"
        )
        self.assertTrue(manifest.is_file(), manifest)
        application = ET.parse(manifest).getroot().find("application")
        self.assertIsNotNone(application, manifest)
        return application.get(f"{{{ANDROID_NAMESPACE}}}debuggable")

    def test_release_merged_manifest_is_not_debuggable(self):
        self.assertNotEqual("true", self.application_debuggable("release"))

    def test_debug_merged_manifest_remains_debuggable(self):
        self.assertEqual("true", self.application_debuggable("debug"))


class NativeHostIntegrationTests(unittest.TestCase):
    @staticmethod
    def run_native_host_test(*arguments, environment=None):
        return run_gradle("nativeHostTest", *arguments, environment=environment)

    def assert_native_host_tasks_in_order(self, output):
        positions = [
            output.index(":configureNativeHostTests"),
            output.index(":buildNativeHostTests"),
            output.index(":nativeHostTest"),
        ]
        self.assertEqual(sorted(positions), positions)

    def test_native_host_test_dry_run_has_native_task_chain(self):
        probe = self.run_native_host_test("--dry-run")

        self.assertEqual(0, probe.returncode, probe.stdout)
        self.assert_native_host_tasks_in_order(probe.stdout)
        self.assertNotIn("testDebugUnitTest", probe.stdout)

    def test_native_host_test_executes_ctest_successfully(self):
        probe = self.run_native_host_test("--rerun-tasks")

        self.assertEqual(0, probe.returncode, probe.stdout)
        self.assert_native_host_tasks_in_order(probe.stdout)
        self.assertIn("100% tests passed, 0 tests failed", probe.stdout)

    def test_native_host_test_reports_missing_android_home_before_agp(self):
        probe = self.run_native_host_test(
            "--dry-run", environment={"ANDROID_HOME": None, "ANDROID_SDK_ROOT": None}
        )

        self.assertNotEqual(0, probe.returncode)
        self.assertIn("nativeHostTest requires ANDROID_HOME", probe.stdout)


if __name__ == "__main__":
    unittest.main()
