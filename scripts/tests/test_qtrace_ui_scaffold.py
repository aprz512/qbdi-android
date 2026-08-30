import json
from pathlib import Path
import subprocess
import unittest


class QtraceUiScaffoldTests(unittest.TestCase):
    def test_cargo_resolves_the_approved_dependency_direction(self):
        root = Path(__file__).parents[2] / "qtrace-ui"
        completed = subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"],
            cwd=root, check=True, capture_output=True, text=True,
        )
        metadata = json.loads(completed.stdout)
        packages = {package["name"]: package for package in metadata["packages"]}
        self.assertEqual(
            {
                "qtrace-provider",
                "qtrace-store",
                "qtrace-analysis",
                "qtrace-service",
                "qtrace-ui",
            },
            set(packages),
        )
        dependencies = {
            name: {item["name"] for item in packages[name]["dependencies"]}
            for name in packages
        }
        self.assertNotIn("qtrace-store", dependencies["qtrace-provider"])
        self.assertIn("qtrace-provider", dependencies["qtrace-store"])
        self.assertIn("qtrace-store", dependencies["qtrace-analysis"])
        self.assertIn("qtrace-analysis", dependencies["qtrace-service"])

    def test_frontend_production_build_emits_runnable_entrypoint(self):
        frontend = Path(__file__).parents[2] / "qtrace-ui/src-web"
        subprocess.run(["npm", "run", "build"], cwd=frontend, check=True, timeout=120)
        output = frontend / "dist/index.html"
        self.assertTrue(output.is_file())
        self.assertIn('<div id="root"></div>', output.read_text(encoding="utf-8"))
