import io
import json
import struct
import unittest

from qtrace.flight_inspection import inspect_flight, query_scene_boundaries
from scripts.flight_trace import FlightTraceError
from scripts.tests.test_flight_trace import artifact, chunk, core_records, directory_entry, flight_record, string_definition


class CountedSource(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.bytes_read = 0

    def read(self, size=-1):
        if size < 0:
            raise AssertionError("unbounded read")
        result = super().read(size)
        self.bytes_read += len(result)
        return result


class FlightInspectionTests(unittest.TestCase):
    def fixture(self):
        records = core_records(42)
        return artifact(directories=[directory_entry(42, 1, 2, 0, 1)],
                        chunks=[chunk(0, 42, 1, records), bytes(2048)])

    def test_preview_reads_only_metadata_and_never_proves_a_return(self):
        source = CountedSource(self.fixture())
        result = inspect_flight(source, len(source.getvalue()))
        self.assertEqual(source.bytes_read, result["metadata_bytes_read"])
        self.assertLess(source.bytes_read, len(source.getvalue()))
        self.assertEqual("not_performed", result["payload_verification"])
        self.assertIsNone(result["target_returned"])
        self.assertEqual(1, result["sealed_chunks"])
        self.assertEqual(2, result["claimed_records"])

    def test_cancellation_and_deadline_stop_the_scan(self):
        source = CountedSource(self.fixture())
        checks = iter([False, True])
        with self.assertRaises(KeyboardInterrupt):
            inspect_flight(source, len(source.getvalue()), cancelled=lambda: next(checks))
        self.assertLess(source.bytes_read, len(source.getvalue()))
        with self.assertRaisesRegex(FlightTraceError, "deadline"):
            inspect_flight(source, len(source.getvalue()), timeout=-1)

    def test_excess_directory_metadata_is_rejected_before_reading_it(self):
        raw = artifact(directories=[bytes(64)] * 1025, chunks=[bytes(2048)])
        source = CountedSource(raw)
        with self.assertRaisesRegex(FlightTraceError, "inspection bound"):
            inspect_flight(source, len(raw))
        self.assertEqual(4096, source.bytes_read)

    def scene_fixture(self, corrupt=False):
        chunks = []
        # Slot order differs from sequence order, as in a wrapped ring.
        for index, sequence in enumerate((30, 10, 20)):
            detail = json.dumps({"schema":1,"id":sequence,"phase":"enter","address":"0x1000",
                                 "monotonicNs":sequence*100,"returnValue":None}).encode()
            name = b"qtrace.scene"
            records = core_records(42,start=sequence-4) + [
                flight_record(6,sequence-2,string_definition(1,name),flags=3),
                flight_record(6,sequence-1,string_definition(2,detail),flags=3),
                flight_record(7,sequence,struct.pack("<II",1,2))]
            chunks.append(chunk(index,42,1,records,corrupt_checksum=corrupt and index == 1))
        return artifact(directories=[directory_entry(42,6,30,0,1)],chunks=chunks)

    def test_time_filter_and_paging_use_real_boundaries_in_sequence_order(self):
        raw = self.scene_fixture()
        first = query_scene_boundaries(io.BytesIO(raw),len(raw),since_ns=1000,until_ns=3000,limit=2)
        self.assertEqual([10,20],[row["sequence"] for row in first["rows"]])
        self.assertTrue(first["has_more"])
        self.assertEqual(20,first["next_after_sequence"])
        second = query_scene_boundaries(io.BytesIO(raw),len(raw),since_ns=1000,until_ns=3000,
                                        after_sequence=20,limit=2)
        self.assertEqual([30],[row["sequence"] for row in second["rows"]])
        self.assertFalse(second["has_more"])
        exact = query_scene_boundaries(io.BytesIO(raw),len(raw),since_ns=2000,until_ns=2000)
        self.assertEqual([20],[row["sequence"] for row in exact["rows"]])

    def test_scene_query_rejects_corruption_and_honors_bounds_and_cancellation(self):
        raw = self.scene_fixture(corrupt=True)
        with self.assertRaisesRegex(FlightTraceError,"checksum"):
            query_scene_boundaries(io.BytesIO(raw),len(raw))
        for options in ({"limit":2001},{"since_ns":2,"until_ns":1},{"after_sequence":-1}):
            with self.subTest(options=options), self.assertRaises(FlightTraceError):
                query_scene_boundaries(io.BytesIO(raw),len(raw),**options)
        source = CountedSource(raw)
        with self.assertRaises(KeyboardInterrupt):
            query_scene_boundaries(source,len(raw),cancelled=lambda:True)
        self.assertEqual(0,source.bytes_read)


if __name__ == "__main__":
    unittest.main()
