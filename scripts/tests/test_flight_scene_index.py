import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qtrace.cli import main
from scripts.flight_trace import FlightTraceError
from scripts.tests.test_flight_scene_events import boundary, fixture
from scripts.tests.test_flight_trace import (
    artifact, chunk, core_records, directory_entry, flight_record,
    qtrb_instruction, qtrb_instruction_definition,
)


class FlightSceneIndexTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name) / "run.flight.bin"
        self.index = Path(self.temporary.name) / "scenes.sqlite"
        self.source.write_bytes(fixture())

    def build(self, **options):
        from qtrace.flight_scene_index import build_scene_index
        return build_scene_index(self.source, self.index, **options)

    def test_indexed_boundaries_equal_bounded_query_and_reuse_reads_no_payload(self):
        from qtrace.flight_inspection import query_scene_path
        from qtrace.flight_scene_index import query_indexed_boundaries
        self.build()
        expected = query_scene_path(self.source, after_sequence=10, limit=2)
        with patch("qtrace.flight_reader.FlightReader.read", side_effect=AssertionError("payload read")):
            result = query_indexed_boundaries(self.source, self.index, after_sequence=10, limit=2)
        self.assertEqual(expected["rows"], result["rows"])
        self.assertEqual(expected["has_more"], result["has_more"])
        self.assertEqual(0, result["payload_bytes_read"])

    def test_scene_at_keeps_entry_before_cursor_and_does_not_invent_closed_scene(self):
        from qtrace.flight_scene_index import scene_at
        self.source.write_bytes(fixture(ending=None))
        self.build()
        result = scene_at(self.source, self.index, sequence=33, tid=42)
        self.assertEqual(1, len(result["scenes"]))
        scene = result["scenes"][0]
        self.assertEqual(5, scene["entry_sequence"])
        self.assertEqual("open_at_end", scene["state"])
        self.assertIsNone(scene["target_returned"])
        self.assertEqual(2, scene["instruction_count"])
        self.assertEqual("uncertain", scene["membership"])
        self.assertIn("missing_sequences", scene["uncertainty"])

    def test_changed_source_and_existing_index_are_rejected(self):
        from qtrace.flight_scene_index import scene_at
        self.build()
        with self.assertRaises(FileExistsError):
            self.build()
        with self.source.open("ab") as output:
            output.write(b"x")
        with self.assertRaisesRegex(FlightTraceError, "identity"):
            scene_at(self.source, self.index, sequence=33)

    def test_force_never_overwrites_the_source_or_a_source_alias(self):
        from qtrace.flight_scene_index import build_scene_index
        original = self.source.read_bytes()
        with self.assertRaisesRegex(FlightTraceError, "differ from"):
            build_scene_index(self.source, self.source, force=True)
        self.index.hardlink_to(self.source)
        with self.assertRaisesRegex(FlightTraceError, "differ from"):
            self.build(force=True)
        self.assertEqual(original, self.source.read_bytes())
        self.assertEqual(original, self.index.read_bytes())

    def test_denials_do_not_publish_partial_index(self):
        with self.assertRaisesRegex(FlightTraceError, "scan bound"):
            self.build(max_payload_bytes=1)
        self.assertFalse(self.index.exists())
        with self.assertRaises(KeyboardInterrupt):
            self.build(cancelled=lambda: True)
        self.assertFalse(self.index.exists())
        self.assertEqual([self.source], list(self.source.parent.iterdir()))

    def test_cli_inspect_summary_and_indexed_empty_boundary_semantics(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(0, main(["index-flight", str(self.source), "--index", str(self.index)]))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(0, main(["inspect-flight", str(self.source), "--index", str(self.index), "--json"]))
        result = json.loads(output.getvalue())
        self.assertEqual("not_performed", result["payload_verification"])
        self.assertEqual(2, result["scene_summary"]["scene_count"])
        self.assertEqual(3, result["scene_summary"]["instruction_count"])
        self.assertIsNone(result["scene_summary"]["installation_status"])
        self.assertIsNone(result["scene_summary"]["unfollowed_threads"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(0, main(["scenes-flight", str(self.source), "--index", str(self.index),
                                      "--after-sequence", "100"]))
        self.assertEqual("boundaries_after_cursor", json.loads(output.getvalue())["query_scope"])

    def test_nested_scenes_use_real_entries_and_inclusive_return_boundaries(self):
        from qtrace.flight_scene_index import scene_at
        records = (core_records(42) + boundary(5, "enter", 100) +
            boundary(7, "enter", 110, scene_id=2, name=False) +
            [flight_record(4, 8, qtrb_instruction_definition(), flags=1),
             flight_record(4, 9, qtrb_instruction())] +
            boundary(11, "return", 120, scene_id=2, name=False) + boundary(13, "return", 130, name=False))
        self.source.write_bytes(artifact(directories=[directory_entry(42, 1, 13, 0, 1)],
            chunks=[chunk(0, 42, 1, records)]))
        self.build()
        result = scene_at(self.source, self.index, sequence=9)
        self.assertEqual([7, 5], [row["entry_sequence"] for row in result["scenes"]])
        self.assertEqual([1, 1], [row["instruction_count"] for row in result["scenes"]])
        self.assertEqual("observed", result["membership_status"])
        self.assertEqual(2, len(scene_at(self.source, self.index, sequence=11)["scenes"]))
        self.assertEqual(1, len(scene_at(self.source, self.index, sequence=12)["scenes"]))
        self.assertEqual("unknown", scene_at(self.source, self.index, sequence=14)["membership_status"])

    def test_typed_damage_and_stale_directory_never_prove_membership(self):
        from qtrace.flight_scene_index import scene_at
        records = core_records(42) + boundary(5, "enter", 100) + [
            flight_record(2, 6, b"bad-thread-begin")]
        self.source.write_bytes(artifact(directories=[directory_entry(42, 1, 6, 0, 2)],
            chunks=[chunk(0, 42, 1, records)]))
        summary = self.build()["scene_summary"]
        self.assertEqual(1, summary["typed_damage"])
        self.assertEqual([0], summary["stale_directory_entries"])
        row = scene_at(self.source, self.index, sequence=6)["scenes"][0]
        self.assertEqual("uncertain", row["membership"])
        self.assertIn("typed_damage", row["uncertainty"])
        self.assertIn("stale_directory", row["uncertainty"])

    def test_source_change_during_build_never_publishes_an_index(self):
        from qtrace.flight_reader import FlightReader
        original = FlightReader.read

        def changed(reader, *args, **options):
            result = original(reader, *args, **options)
            with self.source.open("ab") as output:
                output.write(b"changed")
            return result

        with patch.object(FlightReader, "read", changed):
            with self.assertRaisesRegex(FlightTraceError, "changed during"):
                self.build()
        self.assertFalse(self.index.exists())


if __name__ == "__main__":
    unittest.main()
