import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qtrace.report import ReportWriter, SessionReport, SessionStage


def report() -> SessionReport:
    return SessionReport(
        schema=1, session_id="123e4567-e89b-42d3-a456-426614174000", mode="run",
        status="sealed", stage=SessionStage.SEALED.value, package="com.example.app",
        serial="device-1", pid=123, started_at="2026-08-27T00:00:00Z",
        finished_at="2026-08-27T00:00:01Z", timeline=(), device={}, tracer={}, target={},
        effective_config={}, native={}, artifacts=(), warnings=(), error=None, outputs=(),
    )


class ReportWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "report.json"

    def test_replaces_report_atomically_with_deterministic_bounded_json(self) -> None:
        self.path.write_text('{"old":true}', encoding="utf-8")
        ReportWriter().write_atomic(self.path, report())
        document = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual("sealed", document["status"])
        self.assertEqual(
            ["artifacts", "device", "effective_config", "error", "finished_at", "mode",
             "native", "outputs", "package", "pid", "schema", "serial", "session_id",
             "stage", "started_at", "status", "target", "timeline", "tracer", "warnings"],
            sorted(document),
        )
        self.assertFalse(list(self.path.parent.glob(".report.json.*")))

    def test_refuses_to_overwrite_a_symlink_destination(self) -> None:
        target = Path(self.directory.name) / "target.json"
        target.write_text("keep", encoding="utf-8")
        self.path.symlink_to(target)
        with self.assertRaisesRegex(Exception, "symlink"):
            ReportWriter().write_atomic(self.path, report())
        self.assertEqual("keep", target.read_text(encoding="utf-8"))

    def test_refuses_a_symlinked_parent_directory(self) -> None:
        actual = Path(self.directory.name) / "actual"
        actual.mkdir()
        linked = Path(self.directory.name) / "linked"
        linked.symlink_to(actual, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "directory"):
            ReportWriter().write_atomic(linked / "report.json", report())
        self.assertFalse((actual / "report.json").exists())

    def test_cleans_its_temp_file_when_replace_fails(self) -> None:
        with patch("qtrace.report.os.replace", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                ReportWriter().write_atomic(self.path, report())
        self.assertFalse(self.path.exists())
        self.assertFalse(list(self.path.parent.glob(".report.json.*")))


if __name__ == "__main__":
    unittest.main()
