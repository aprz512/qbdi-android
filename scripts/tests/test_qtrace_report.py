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

    def test_creates_nested_private_directories_without_following_existing_symlink(self) -> None:
        output = Path(self.directory.name) / "one" / "two" / "report.json"
        ReportWriter().write_atomic(output, report())
        self.assertEqual(0o700, (output.parent.stat().st_mode & 0o777))
        self.assertEqual("sealed", json.loads(output.read_text(encoding="utf-8"))["status"])

    def test_symlink_race_at_the_new_directory_boundary_does_not_publish_to_target(self) -> None:
        safe = Path(self.directory.name) / "safe"
        target = Path(self.directory.name) / "target"
        target.mkdir()
        safe.mkdir()
        output = safe / "new" / "report.json"
        original_mkdir = os.mkdir

        def race(path, mode=0o777, *, dir_fd=None):
            if path == "new" and dir_fd is not None:
                # A competing writer turns the just-missing component into a link.
                (safe / "new").symlink_to(target, target_is_directory=True)
                raise FileExistsError()
            return original_mkdir(path, mode, dir_fd=dir_fd)

        with patch("qtrace.report.os.mkdir", side_effect=race):
            with self.assertRaises((OSError, ValueError)):
                ReportWriter().write_atomic(output, report())
        self.assertFalse((target / "report.json").exists())

    def test_exchange_interrupt_preserves_old_report_as_recovery(self) -> None:
        from qtrace import report as report_module

        self.path.write_text('{"status":"old"}', encoding="utf-8")
        expected = (self.path.stat().st_dev, self.path.stat().st_ino)
        exchange = report_module._exchange

        def exchanged_then_interrupted(directory: int, temporary: str, target: str) -> None:
            exchange(directory, temporary, target)
            raise KeyboardInterrupt("injected after exchange")

        descriptor = os.open(self.path.parent, os.O_RDONLY)
        try:
            with patch("qtrace.report._exchange", side_effect=exchanged_then_interrupted):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    ReportWriter().write_atomic_at(
                        descriptor, self.path.name, report(), expected_identity=expected)
        finally:
            os.close(descriptor)

        self.assertTrue(any("recovery" in note for note in raised.exception.__notes__))
        documents = {path.name: json.loads(path.read_text(encoding="utf-8"))
                     for path in self.path.parent.iterdir() if path.is_file()}
        self.assertEqual("sealed", documents["report.json"]["status"])
        self.assertIn("old", {document["status"] for name, document in documents.items()
                              if name != "report.json"})

    def test_mismatch_rollback_preserves_a_second_temporary_replacement(self) -> None:
        """A RACER-B installed after the original identity check remains recoverable."""
        from qtrace import report as report_module
        from qtrace.report import ConditionalReplaceRecoveryError

        self.path.write_text("EXPECTED", encoding="utf-8")
        expected = (self.path.stat().st_dev, self.path.stat().st_ino)
        real_exchange = report_module._exchange
        exchanges = 0

        def replace_at(directory: int, name: str, contents: bytes) -> None:
            staged = f".{name}.racer"
            descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                                 dir_fd=directory)
            try:
                os.write(descriptor, contents)
            finally:
                os.close(descriptor)
            os.replace(staged, name, src_dir_fd=directory, dst_dir_fd=directory)

        def exchange(directory: int, temporary: str, target: str) -> None:
            nonlocal exchanges
            exchanges += 1
            real_exchange(directory, temporary, target)
            if exchanges == 1:
                replace_at(directory, temporary, b"RACER-A")
            else:
                replace_at(directory, temporary, b"RACER-B")

        descriptor = os.open(self.path.parent, os.O_RDONLY)
        try:
            with patch("qtrace.report._exchange", side_effect=exchange):
                with self.assertRaises(ConditionalReplaceRecoveryError) as raised:
                    ReportWriter().write_atomic_at(
                        descriptor, self.path.name, report(), expected_identity=expected)
        finally:
            os.close(descriptor)

        self.assertEqual("RACER-A", self.path.read_text(encoding="utf-8"))
        self.assertEqual("RACER-B", (self.path.parent / raised.exception.recovery_name).read_text(
            encoding="utf-8"))

    def test_mismatch_rollback_retains_the_owned_recovery_file(self) -> None:
        """A successful rollback must return its new report as recovery, never unlink it."""
        from qtrace import report as report_module
        from qtrace.report import (ConditionalReplaceRecoveryError,
                                   conditional_replace_at)

        self.path.write_text("EXPECTED", encoding="utf-8")
        temporary = self.path.parent / ".replacement.tmp"
        temporary.write_text("NEW", encoding="utf-8")
        expected = (self.path.stat().st_dev, self.path.stat().st_ino)
        real_exchange = report_module._exchange
        exchanges = 0

        def exchange(directory: int, left: str, right: str) -> None:
            nonlocal exchanges
            exchanges += 1
            real_exchange(directory, left, right)
            if exchanges == 1:
                staged = self.path.parent / ".racer-a"
                staged.write_text("RACER-A", encoding="utf-8")
                os.replace(staged, self.path.parent / left)

        descriptor = os.open(self.path.parent, os.O_RDONLY)
        try:
            with patch("qtrace.report._exchange", side_effect=exchange):
                with self.assertRaises(ConditionalReplaceRecoveryError) as raised:
                    conditional_replace_at(descriptor, temporary.name, self.path.name, expected)
        finally:
            os.close(descriptor)

        self.assertEqual(temporary.name, raised.exception.recovery_name)
        self.assertEqual("RACER-A", self.path.read_text(encoding="utf-8"))
        self.assertEqual("NEW", temporary.read_text(encoding="utf-8"))

    def test_old_stat_rollback_preserves_second_temporary_replacement(self) -> None:
        """The original old-inode stat failure must retain both EXPECTED and RACER-B."""
        from qtrace import report as report_module

        self.path.write_text("EXPECTED", encoding="utf-8")
        expected = (self.path.stat().st_dev, self.path.stat().st_ino)
        real_exchange, real_stat = report_module._exchange, report_module.os.stat
        exchanges = 0
        temporary: list[str] = []

        def replace_at(directory: int, name: str) -> None:
            staged = f".{name}.racer"
            descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                                 dir_fd=directory)
            try:
                os.write(descriptor, b"RACER-B")
            finally:
                os.close(descriptor)
            os.replace(staged, name, src_dir_fd=directory, dst_dir_fd=directory)

        def exchange(directory: int, left: str, right: str) -> None:
            nonlocal exchanges
            exchanges += 1
            temporary[:] = [left]
            real_exchange(directory, left, right)
            if exchanges == 2:
                replace_at(directory, left)

        def stat_after_exchange(name, *args, **kwargs):
            if exchanges == 1 and temporary and name == temporary[0]:
                raise OSError("injected old report stat failure")
            return real_stat(name, *args, **kwargs)

        descriptor = os.open(self.path.parent, os.O_RDONLY)
        try:
            with patch("qtrace.report._exchange", side_effect=exchange), patch(
                    "qtrace.report.os.stat", side_effect=stat_after_exchange):
                with self.assertRaisesRegex(OSError, "old report stat failure") as raised:
                    ReportWriter().write_atomic_at(
                        descriptor, self.path.name, report(), expected_identity=expected)
        finally:
            os.close(descriptor)

        self.assertEqual("EXPECTED", self.path.read_text(encoding="utf-8"))
        self.assertEqual("RACER-B", (self.path.parent / temporary[0]).read_text(encoding="utf-8"))
        self.assertTrue(any(temporary[0] in note for note in raised.exception.__notes__))


if __name__ == "__main__":
    unittest.main()
