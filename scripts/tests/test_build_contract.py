import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class BuildContractTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
