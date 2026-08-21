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
