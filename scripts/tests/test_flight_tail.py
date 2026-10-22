import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from qtrace.cli import main
from qtrace.flight_scene_events import query_scene_events
from scripts.flight_trace import FlightTraceError, recover_flight
from scripts.tests.test_flight_inspection import CountedSource
from scripts.tests.test_flight_scene_events import fixture


class FlightTailTests(unittest.TestCase):
    def query(self, raw=None, **options):
        from qtrace.flight_tail import query_tail
        raw = fixture() if raw is None else raw
        return query_tail(io.BytesIO(raw), len(raw), **options)

    def test_open_scene_tail_matches_full_recovery_without_inventing_a_return(self):
        raw = fixture(ending=None)
        self.assertEqual([], query_scene_events(io.BytesIO(raw), len(raw), after_sequence=20)["rows"])
        expected = list(recover_flight(io.BytesIO(raw)).merged)[-3:]
        result = self.query(raw, limit=3)
        self.assertEqual([event.global_seq for event in expected],
                         [row["sequence"] for row in result["rows"]])
        self.assertIsNone(result["target_returned"])
        self.assertEqual("not_resolved", result["scene_context"])

    def test_tail_pages_keep_sequence_order_across_rotated_slots_and_threads(self):
        raw = fixture()
        expected = [event.global_seq for event in recover_flight(io.BytesIO(raw)).merged]
        actual, until = [], 2**64 - 1
        for _ in range(20):
            result = self.query(raw, limit=2, until_sequence=until)
            actual[:0] = [row["sequence"] for row in result["rows"]]
            if not result["has_more"]:
                break
            self.assertLess(result["next_until_sequence"], until)
            until = result["next_until_sequence"]
        else:
            self.fail("pagination did not finish")
        self.assertEqual(expected, actual)

    def test_cursor_skips_old_payload_even_when_it_is_corrupt(self):
        from qtrace.flight_tail import query_tail
        raw = fixture(corrupt=True)  # Corrupt chunk is the newest, not an old chunk.
        with self.assertRaisesRegex(FlightTraceError, "checksum"):
            self.query(raw)
        raw = bytearray(fixture())
        # Physical slot 2 is the oldest chunk; its payload is outside this query.
        raw[-2048 + 100] ^= 1
        source = CountedSource(bytes(raw))
        result = query_tail(source, len(raw), after_sequence=30, limit=2)
        self.assertEqual([33, 36], [row["sequence"] for row in result["rows"]])
        self.assertLess(result["decoded_chunks"], 3)
        self.assertIn("decoded chunks", result["verification_scope"])

    def test_active_chunk_ranges_are_not_used_to_skip_committed_events(self):
        expected = self.query(limit=3)["rows"]
        actual = self.query(fixture(active_last=True), limit=3)["rows"]
        self.assertEqual(expected, actual)

    def test_denials_and_cli_are_explicit(self):
        for options in ({"limit": 0}, {"after_sequence": -1},
                        {"until_sequence": 2**64}, {"timeout": float("inf")}):
            with self.subTest(options=options), self.assertRaises(FlightTraceError):
                self.query(**options)
        with self.assertRaises(KeyboardInterrupt):
            self.query(cancelled=lambda: True)
        with patch("qtrace.flight_tail.MAX_PAYLOAD_BYTES", 1):
            with self.assertRaisesRegex(FlightTraceError, "scan bound"):
                self.query()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "open.flight.bin"
            path.write_bytes(fixture(ending=None))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(0, main(["tail-flight", str(path), "--limit", "2"]))
            self.assertEqual(2, len(json.loads(output.getvalue())["rows"]))

    def test_file_mutation_during_tail_is_rejected(self):
        from qtrace.flight_reader import FlightReader
        from qtrace.flight_tail import query_tail_path
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.flight.bin"
            path.write_bytes(fixture())
            original = FlightReader.read

            def changed(reader, *args, **options):
                result = original(reader, *args, **options)
                with path.open("ab") as output:
                    output.write(b"changed")
                return result

            with patch.object(FlightReader, "read", changed):
                with self.assertRaisesRegex(FlightTraceError, "changed during"):
                    query_tail_path(path)


if __name__ == "__main__":
    unittest.main()
