import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scripts.flight_convert as flight_convert
from scripts.flight_convert import publish_flight_outputs
from scripts.flight_trace import FlightTraceError
from scripts.tests.test_flight_trace import (
    artifact,
    chunk,
    core_records,
    directory_entry,
    flight_record,
    qtrb_instruction,
    qtrb_instruction_definition,
)


def publishable_artifact() -> bytes:
    records = core_records(321) + [
        flight_record(4, 3, qtrb_instruction_definition(), flags=1),
        flight_record(4, 4, qtrb_instruction()),
    ]
    return artifact(
        directories=[directory_entry(321, 1, 4, 0, 1)],
        chunks=[chunk(0, 321, 1, records)],
    )


class FlightPublicationTests(unittest.TestCase):
    def test_publishes_merged_per_tid_and_json_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            output = root / "converted"
            source.write_bytes(publishable_artifact())

            paths = publish_flight_outputs(source, output, force=False)

            self.assertEqual(
                ["run.merged.trace.txt", "run.tid-321.trace.txt", "run.flight.json"],
                [path.name for path in paths],
            )
            self.assertIn("EVENT seq=4 tid=321 kind=instruction", paths[0].read_text())
            self.assertIn("pc=0x71001234", paths[1].read_text())
            summary = json.loads(paths[2].read_text())
            self.assertEqual(0x1020304050607080, summary["run_id"])
            self.assertEqual("libtarget.so", summary["target_module"])
            self.assertFalse(any(path.name.startswith(".flight-convert-") for path in output.iterdir()))

    def test_no_overwrite_preflight_leaves_every_existing_output_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            output = root / "converted"
            output.mkdir()
            source.write_bytes(publishable_artifact())
            existing = output / "run.tid-321.trace.txt"
            existing.write_text("keep", encoding="utf-8")

            with self.assertRaisesRegex(FileExistsError, "run.tid-321"):
                publish_flight_outputs(source, output, force=False)

            self.assertEqual("keep", existing.read_text(encoding="utf-8"))
            self.assertEqual(["run.tid-321.trace.txt"], [path.name for path in output.iterdir()])

    def test_mid_publication_failure_rolls_back_all_new_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            output = root / "converted"
            source.write_bytes(publishable_artifact())
            real_link = os.link
            calls = 0

            def fail_second_link(src, dst, *args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected publication failure")
                return real_link(src, dst, *args, **kwargs)

            with patch.object(flight_convert.os, "link", side_effect=fail_second_link), \
                    self.assertRaisesRegex(FlightTraceError, "publication failure"):
                publish_flight_outputs(source, output, force=False)

            self.assertEqual([], list(output.iterdir()))

    def test_keyboard_interrupt_rolls_back_all_new_outputs_and_is_re_raised(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            output = root / "converted"
            source.write_bytes(publishable_artifact())
            real_link = os.link
            interruption = KeyboardInterrupt("injected publication interrupt")
            calls = 0

            def interrupt_second_link(src, dst, *args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    real_link(src, dst, *args, **kwargs)
                    raise interruption
                return real_link(src, dst, *args, **kwargs)

            with patch.object(flight_convert.os, "link", side_effect=interrupt_second_link), \
                    self.assertRaises(KeyboardInterrupt) as caught:
                publish_flight_outputs(source, output, force=False)

            self.assertIs(interruption, caught.exception)
            self.assertEqual([], list(output.iterdir()))

    def test_no_replace_race_preserves_the_conflicting_external_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            output = root / "converted"
            source.write_bytes(publishable_artifact())
            real_link = os.link
            calls = 0

            def race_second_link(src, dst, *args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    Path(dst).write_text("racer", encoding="utf-8")
                return real_link(src, dst, *args, **kwargs)

            with patch.object(flight_convert.os, "link", side_effect=race_second_link), \
                    self.assertRaises(FileExistsError):
                publish_flight_outputs(source, output, force=False)

            self.assertEqual("racer", (output / "run.tid-321.trace.txt").read_text())
            self.assertFalse((output / "run.merged.trace.txt").exists())

    def test_force_replaces_the_complete_output_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            output = root / "converted"
            source.write_bytes(publishable_artifact())
            first = publish_flight_outputs(source, output, force=False)
            for path in first:
                path.write_text("old", encoding="utf-8")

            second = publish_flight_outputs(source, output, force=True)

            self.assertEqual(first, second)
            self.assertTrue(all(path.read_text(encoding="utf-8") != "old" for path in second))
            self.assertFalse(any(path.name.startswith(".flight-convert-") for path in output.iterdir()))

    def test_force_publication_failure_restores_the_complete_old_output_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            output = root / "converted"
            source.write_bytes(publishable_artifact())
            paths = publish_flight_outputs(source, output, force=False)
            old = {path: f"old-{index}" for index, path in enumerate(paths)}
            for path, value in old.items():
                path.write_text(value, encoding="utf-8")
            real_replace = os.replace
            calls = 0

            def fail_second_replace(src, dst, *args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected force failure")
                return real_replace(src, dst, *args, **kwargs)

            with patch.object(flight_convert.os, "replace", side_effect=fail_second_replace), \
                    self.assertRaisesRegex(FlightTraceError, "publication failure"):
                publish_flight_outputs(source, output, force=True)

            self.assertEqual(old, {path: path.read_text(encoding="utf-8") for path in paths})
            self.assertFalse(any(path.name.startswith(".flight-convert-") for path in output.iterdir()))

    def test_force_keyboard_interrupt_restores_all_old_outputs_and_is_re_raised(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            output = root / "converted"
            source.write_bytes(publishable_artifact())
            paths = publish_flight_outputs(source, output, force=False)
            old = {path: f"old-{index}" for index, path in enumerate(paths)}
            for path, value in old.items():
                path.write_text(value, encoding="utf-8")
            real_replace = os.replace
            interruption = KeyboardInterrupt("injected force interrupt")
            calls = 0

            def interrupt_second_replace(src, dst, *args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    real_replace(src, dst, *args, **kwargs)
                    raise interruption
                return real_replace(src, dst, *args, **kwargs)

            with patch.object(flight_convert.os, "replace",
                              side_effect=interrupt_second_replace), \
                    self.assertRaises(KeyboardInterrupt) as caught:
                publish_flight_outputs(source, output, force=True)

            self.assertIs(interruption, caught.exception)
            self.assertEqual(old, {path: path.read_text(encoding="utf-8") for path in paths})
            self.assertFalse(any(path.name.startswith(".flight-convert-")
                                 for path in output.iterdir()))

    def test_force_failure_restores_mixed_existing_and_absent_destinations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            output = root / "converted"
            output.mkdir()
            source.write_bytes(publishable_artifact())
            existing = output / "run.merged.trace.txt"
            existing.write_text("old-merged", encoding="utf-8")
            real_replace = os.replace
            calls = 0

            def fail_second_replace(src, dst, *args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected mixed force failure")
                return real_replace(src, dst, *args, **kwargs)

            with patch.object(flight_convert.os, "replace", side_effect=fail_second_replace), \
                    self.assertRaisesRegex(FlightTraceError, "publication failure"):
                publish_flight_outputs(source, output, force=True)

            self.assertEqual("old-merged", existing.read_text(encoding="utf-8"))
            self.assertEqual(["run.merged.trace.txt"], sorted(path.name for path in output.iterdir()))

    def test_force_failure_restores_a_dangling_destination_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            output = root / "converted"
            output.mkdir()
            source.write_bytes(publishable_artifact())
            dangling = output / "run.merged.trace.txt"
            dangling.symlink_to("missing-original.trace")
            real_replace = os.replace
            calls = 0

            def fail_second_replace(src, dst, *args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected dangling force failure")
                return real_replace(src, dst, *args, **kwargs)

            with patch.object(flight_convert.os, "replace", side_effect=fail_second_replace), \
                    self.assertRaisesRegex(FlightTraceError, "publication failure"):
                publish_flight_outputs(source, output, force=True)

            self.assertTrue(dangling.is_symlink())
            self.assertEqual("missing-original.trace", os.readlink(dangling))
            self.assertEqual(["run.merged.trace.txt"],
                             sorted(path.name for path in output.iterdir()))

    def test_no_replace_rollback_attempts_every_cleanup_after_one_unlink_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            output = root / "converted"
            source.write_bytes(publishable_artifact())
            merged = output / "run.merged.trace.txt"
            per_tid = output / "run.tid-321.trace.txt"
            real_link = os.link
            real_unlink = Path.unlink
            link_calls = 0
            cleanup_attempts: list[str] = []

            def fail_third_link(src, dst, *args, **kwargs):
                nonlocal link_calls
                link_calls += 1
                if link_calls == 3:
                    raise OSError("injected publication failure")
                return real_link(src, dst, *args, **kwargs)

            def fail_one_cleanup(path, *args, **kwargs):
                candidate = Path(path)
                if candidate in (merged, per_tid):
                    cleanup_attempts.append(candidate.name)
                if candidate == per_tid:
                    raise OSError("injected rollback cleanup failure")
                return real_unlink(candidate, *args, **kwargs)

            with patch.object(flight_convert.os, "link", side_effect=fail_third_link), \
                    patch.object(Path, "unlink", autospec=True,
                                 side_effect=fail_one_cleanup), \
                    self.assertRaises(FlightTraceError) as caught:
                publish_flight_outputs(source, output, force=False)

            self.assertEqual(["run.tid-321.trace.txt", "run.merged.trace.txt"],
                             cleanup_attempts)
            self.assertFalse(merged.exists())
            self.assertTrue(per_tid.exists())
            self.assertIn(per_tid.name, str(caught.exception))

    def test_force_rollback_preserves_and_reports_only_failed_restore_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            output = root / "converted"
            source.write_bytes(publishable_artifact())
            paths = publish_flight_outputs(source, output, force=False)
            old = {path: f"old-{index}" for index, path in enumerate(paths)}
            for path, value in old.items():
                path.write_text(value, encoding="utf-8")
            real_replace = os.replace
            calls = 0

            def fail_publication_and_restore(src, dst, *args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected force publication failure")
                if calls == 3:
                    raise OSError("injected rollback restore failure")
                return real_replace(src, dst, *args, **kwargs)

            with patch.object(flight_convert.os, "replace",
                              side_effect=fail_publication_and_restore), \
                    self.assertRaises(FlightTraceError) as caught:
                publish_flight_outputs(source, output, force=True)

            backups = [path for path in output.iterdir()
                       if path.name.startswith(".flight-convert-")
                       and path.name.endswith(".backup")]
            self.assertEqual(1, len(backups))
            self.assertEqual("old-0", backups[0].read_text(encoding="utf-8"))
            self.assertIn(backups[0].name, str(caught.exception))
            self.assertEqual("old-1", paths[1].read_text(encoding="utf-8"))
            self.assertEqual("old-2", paths[2].read_text(encoding="utf-8"))

    def test_no_replace_fsyncs_directory_after_temporary_hardlinks_are_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            output = root / "converted"
            source.write_bytes(publishable_artifact())
            snapshots: list[list[str]] = []

            def record_directory_contents(directory_path):
                snapshots.append(sorted(
                    path.name for path in Path(directory_path).iterdir()
                    if path.name.startswith(".flight-convert-")
                ))

            with patch.object(flight_convert, "_fsync_directory",
                              side_effect=record_directory_contents):
                publish_flight_outputs(source, output, force=False)

            self.assertGreaterEqual(len(snapshots), 2)
            self.assertNotEqual([], snapshots[0])
            self.assertEqual([], snapshots[-1])

    def test_conversion_failure_publishes_no_outputs_or_temporaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "bad.flight.bin"
            output = root / "converted"
            source.write_bytes(b"not a flight artifact")

            with self.assertRaises(FlightTraceError):
                publish_flight_outputs(source, output, force=False)

            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
