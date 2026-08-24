import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class BuildContractTests(unittest.TestCase):
    @staticmethod
    def run_native_host_test(*arguments, environment=None):
        process_environment = os.environ.copy()
        if environment:
            for name, value in environment.items():
                if value is None:
                    process_environment.pop(name, None)
                else:
                    process_environment[name] = value

        return subprocess.run(
            [
                "./gradlew",
                "nativeHostTest",
                *arguments,
                "--no-daemon",
                "--console=plain",
            ],
            cwd=ROOT,
            env=process_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    def assert_native_host_tasks_in_order(self, output):
        positions = [
            output.index(":configureNativeHostTests"),
            output.index(":buildNativeHostTests"),
            output.index(":nativeHostTest"),
        ]
        self.assertEqual(sorted(positions), positions)

    def test_release_build_is_not_debuggable(self):
        app_gradle = (ROOT / "app/build.gradle").read_text(encoding="utf-8")

        self.assertRegex(app_gradle, r"release\s*\{[^}]*debuggable false")

    def test_native_host_test_runs_ctest_without_android_unit_test_dependency(self):
        root_gradle = (ROOT / "build.gradle").read_text(encoding="utf-8")

        self.assertIn('tasks.register("configureNativeHostTests", Exec)', root_gradle)
        self.assertIn('tasks.register("buildNativeHostTests", Exec)', root_gradle)
        self.assertIn('tasks.register("nativeHostTest", Exec)', root_gradle)
        self.assertIn('"cmake"', root_gradle)
        self.assertIn('"ctest"', root_gradle)
        self.assertNotIn("testDebugUnitTest", root_gradle)

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
