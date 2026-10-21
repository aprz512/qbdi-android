import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from qtrace.cli import main
from qtrace.flight_scene_events import query_scene_events, query_scene_events_path
from scripts.flight_trace import FlightTraceError
from scripts.tests.test_flight_inspection import CountedSource
from scripts.tests.test_flight_trace import (
    artifact, chunk, core_records, directory_entry, flight_record,
    qtrb_instruction, qtrb_instruction_definition, string_definition,
)


def boundary(sequence, phase, timestamp, *, scene_id=1, name=True):
    detail = json.dumps({"schema": 1, "id": scene_id, "phase": phase,
                         "address": "0x71001234", "monotonicNs": timestamp,
                         "returnValue": "0x2a" if phase == "return" else None}).encode()
    records = [flight_record(6, sequence - 1, string_definition(sequence, detail), flags=3),
               flight_record(7, sequence, struct.pack("<II", 1, sequence))]
    if name:
        records.insert(0, flight_record(6, sequence - 2, string_definition(1, b"qtrace.scene"), flags=3))
    return records


def fixture(*, ending="return", corrupt=False, active_last=False):
    first = core_records(42) + boundary(5, "enter", 100) + [
        flight_record(4, 6, qtrb_instruction_definition(), flags=1),
        flight_record(4, 7, qtrb_instruction())]
    last = core_records(42, start=30) + [
        flight_record(4, 32, qtrb_instruction_definition(), flags=1),
        flight_record(4, 33, qtrb_instruction())]
    if ending:
        last += boundary(36, ending, 300)
    peer = core_records(43, start=10) + boundary(14, "enter", 400) + [
        flight_record(4, 15, qtrb_instruction_definition(), flags=1),
        flight_record(4, 16, qtrb_instruction())] + boundary(19, "return", 500, name=False)
    return artifact(directories=[directory_entry(42, 1, 36, 2, 1), directory_entry(43, 10, 19, 1, 1)],
                    chunks=[chunk(0, 42, 1, last, corrupt_checksum=corrupt, state=1 if active_last else 2),
                            chunk(1, 43, 1, peer), chunk(2, 42, 1, first)])


class FlightSceneEventsTests(unittest.TestCase):
    def query(self, raw=None, **options):
        raw = fixture() if raw is None else raw
        return query_scene_events(io.BytesIO(raw), len(raw), **options)

    def test_time_range_selects_whole_cross_chunk_scene_with_honest_time_source(self):
        page = self.query(since_ns=150, until_ns=200)
        self.assertEqual([7, 33], [row["sequence"] for row in page["rows"] if row["kind"] == "instruction"])
        self.assertEqual({42}, {row["tid"] for row in page["rows"]})
        self.assertEqual(100, page["scenes"][0]["entered_monotonic_ns"])
        self.assertEqual(300, page["scenes"][0]["last_monotonic_ns"])
        self.assertEqual("returned", page["scenes"][0]["state"])
        self.assertTrue(all(row["event_monotonic_ns"] is None and
                            row["time_source"] == "scene_interval" for row in page["rows"]))

    def test_overlap_is_inclusive_and_scene_identity_includes_thread(self):
        self.assertEqual(1, self.query(since_ns=300, until_ns=300)["matched_scenes"])
        self.assertEqual([], self.query(until_ns=99)["rows"])
        peer = self.query(since_ns=450, until_ns=450)
        self.assertEqual({43}, {row["tid"] for row in peer["rows"]})
        self.assertEqual([16], [row["sequence"] for row in peer["rows"] if row["kind"] == "instruction"])

    def test_pages_are_equivalent_to_full_query_when_cursor_crosses_open_interval(self):
        expected = self.query()["rows"]
        actual, cursor = [], 0
        for _ in range(30):
            page = self.query(after_sequence=cursor, limit=2)
            self.assertLessEqual(len(page["rows"]), 2)
            actual.extend(page["rows"])
            if not page["has_more"]:
                break
            self.assertGreater(page["next_after_sequence"], cursor)
            cursor = page["next_after_sequence"]
        else:
            self.fail("pagination did not terminate")
        self.assertEqual(expected, actual)
        self.assertEqual(len(actual), len({row["sequence"] for row in actual}))

    def test_stopped_capture_proves_interval_but_not_target_return(self):
        page = self.query(fixture(ending="capture_stopped"), since_ns=200, until_ns=200)
        self.assertEqual("capture_stopped", page["scenes"][0]["state"])
        self.assertIsNone(page["scenes"][0]["target_returned"])
        self.assertTrue(page["rows"])

    def test_open_scene_does_not_invent_an_end_time(self):
        page = self.query(fixture(ending=None), since_ns=200, until_ns=200)
        self.assertEqual([], page["rows"])
        self.assertEqual(1, page["unpaired_boundaries"])

    def test_active_chunk_uses_its_committed_prefix_instead_of_unpublished_header_range(self):
        expected = self.query(since_ns=200, until_ns=200)
        actual = self.query(fixture(active_last=True), since_ns=200, until_ns=200)
        self.assertEqual(expected["rows"], actual["rows"])
        self.assertEqual(expected["scenes"], actual["scenes"])

    def test_cursor_retains_all_crossing_scenes_before_choosing_the_next_event(self):
        chunks, directories = [], []
        for tid, start, later in ((42, 1, 88), (43, 11, 58), (44, 21, 68)):
            enter = core_records(tid, start=start) + boundary(start + 4, "enter", 100)
            leave = core_records(tid, start=later) + [
                flight_record(4, later + 2, qtrb_instruction_definition(), flags=1),
                flight_record(4, later + 3, qtrb_instruction())] + boundary(later + 6, "return", 300)
            directories.append(directory_entry(tid, start, later + 6, len(chunks) + 1, 1))
            chunks.extend([chunk(len(chunks), tid, 1, enter), chunk(len(chunks) + 1, tid, 1, leave)])
        raw = artifact(directories=directories, chunks=chunks)
        expected = self.query(raw, after_sequence=50)["rows"]
        first = self.query(raw, after_sequence=50, limit=1)
        self.assertEqual(expected[:1], first["rows"])
        self.assertEqual(43, first["rows"][0]["tid"])
        self.assertTrue(first["has_more"])

    def test_fragments_are_exposed_without_claiming_an_assembled_call(self):
        records = core_records(42) + boundary(5, "enter", 100)
        for sequence, value in ((6, b"jni"), (7, b"helper"), (8, b"abc"), (9, b"def")):
            records.append(flight_record(6, sequence, string_definition(sequence, value), flags=3))
        for index in range(2):
            payload = struct.pack("<QIHHIII", 99, 6, index, 2, 6, 7, 8 + index)
            records.append(flight_record(6, 10 + index, payload, flags=4))
        records += boundary(14, "return", 300, name=False)
        raw = artifact(directories=[directory_entry(42, 1, 14, 0, 1)], chunks=[chunk(0, 42, 1, records)])
        page = self.query(raw, since_ns=200, until_ns=200)
        fragments = [row for row in page["rows"] if row["kind"] == "semantic_fragment"]
        self.assertEqual([10, 11], [row["sequence"] for row in fragments])
        self.assertEqual(["616263", "646566"], [row["data"]["detail_hex"] for row in fragments])
        self.assertFalse(any(row["kind"] == "call" for row in page["rows"]))

    def test_corruption_cancellation_deadline_and_arguments_fail_explicitly(self):
        with self.assertRaisesRegex(FlightTraceError, "checksum"):
            self.query(fixture(corrupt=True))
        for options in ({"limit": 0}, {"limit": 2001}, {"since_ns": 2, "until_ns": 1},
                        {"after_sequence": -1}, {"timeout": float("inf")}):
            with self.subTest(options=options), self.assertRaises(FlightTraceError):
                self.query(**options)
        source = CountedSource(fixture())
        with self.assertRaises(KeyboardInterrupt):
            query_scene_events(source, len(source.getvalue()), cancelled=lambda: True)
        self.assertEqual(0, source.bytes_read)
        with patch("qtrace.flight_scene_events.time.monotonic", side_effect=[0, 0, 31]):
            with self.assertRaisesRegex(FlightTraceError, "deadline"):
                self.query()

    def test_cli_and_held_file_mutation_check(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scene.flight.bin"
            path.write_bytes(fixture())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(0, main(["events-flight", str(path), "--since-ns", "200",
                                          "--until-ns", "200", "--limit", "2"]))
            self.assertEqual(2, len(json.loads(output.getvalue())["rows"]))
            original = query_scene_events
            def mutate(source, size, **options):
                result = original(source, size, **options)
                with path.open("ab") as changed:
                    changed.write(b"x")
                return result
            with patch("qtrace.flight_scene_events.query_scene_events", side_effect=mutate):
                with self.assertRaisesRegex(FlightTraceError, "changed"):
                    query_scene_events_path(path)

    def test_scan_budget_rejects_before_reading_payload(self):
        raw = fixture()
        source = CountedSource(raw)
        with patch("qtrace.flight_scene_events._MAX_PAYLOAD_BYTES", 1):
            with self.assertRaisesRegex(FlightTraceError, "payload scan bound"):
                query_scene_events(source, len(raw))
        self.assertEqual(4096 + 2 * 64 + 3 * 64, source.bytes_read)


if __name__ == "__main__":
    unittest.main()
