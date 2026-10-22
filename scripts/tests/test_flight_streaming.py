import io
import json
from pathlib import Path
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch

from scripts.flight_convert import publish_flight_outputs
from scripts.flight_trace import FlightRecovery, FlightThread, FlightTraceError
from scripts.tests import test_flight_trace as legacy
from scripts.tests.test_flight_convert import publishable_artifact


def dense_artifact():
    chunks = []
    sequence = 1
    for index in range(20):
        records = legacy.core_records(42, start=sequence)
        records.append(legacy.flight_record(4, sequence + 2, legacy.qtrb_instruction_definition(), flags=1))
        records.extend(legacy.flight_record(4, sequence + 3 + offset, legacy.qtrb_instruction())
                       for offset in range(300))
        chunks.append(legacy.chunk(index, 42, 1, records, chunk_bytes=32768))
        sequence += 303
    return legacy.artifact(directories=[legacy.directory_entry(42, 1, sequence - 1, 19, 1)],
                           chunks=chunks, chunk_bytes=32768)


class FlightStreamingTests(unittest.TestCase):
    def test_conversion_does_not_retain_all_events_and_physical_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "dense.flight.bin"
            source.write_bytes(dense_artifact())
            tracemalloc.start()
            try:
                publish_flight_outputs(source, root / "output", False)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            self.assertLess(peak, 4 * 1024**2, f"conversion peak Python allocations: {peak}")

    def test_spill_preserves_the_existing_strict_recovery_contract(self):
        from scripts.flight_storage import spooled_recovery

        def materialized(source):
            with spooled_recovery(source) as result:
                return FlightRecovery(tuple(result.merged), {
                    tid: FlightThread(tid, tuple(thread.events), thread.registers)
                    for tid, thread in result.threads.items()},
                    json.loads("".join(json.JSONEncoder().iterencode(result.summary))))

        suite = unittest.defaultTestLoader.loadTestsFromTestCase(legacy.FlightRecoveryTests)
        result = unittest.TestResult()
        with patch.object(legacy, "recover_flight", side_effect=materialized):
            suite.run(result)
        self.assertFalse(result.errors + result.failures, result.errors + result.failures)

    def test_range_is_explicit_and_does_not_claim_complete_recovery(self):
        from scripts.tests.test_flight_scene_events import fixture
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            source.write_bytes(fixture())
            paths = publish_flight_outputs(source, root / "output", False,
                                            after_sequence=1, max_events=1)
            text = paths[0].read_text()
            self.assertEqual(1, text.count("EVENT seq="))
            summary = json.loads(paths[-1].read_text())
            self.assertFalse(summary["complete"])
            self.assertEqual(1, summary["output_scope"]["emitted_events"])
            self.assertTrue(summary["output_scope"]["has_more"])

    def test_complete_small_outputs_are_byte_equivalent_to_in_memory_recovery(self):
        from scripts.flight_convert import _render
        from scripts.flight_trace import recover_flight
        from scripts.tests.test_flight_scene_events import fixture
        raw = fixture()
        expected = recover_flight(io.BytesIO(raw))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run.flight.bin"
            source.write_bytes(raw)
            paths = publish_flight_outputs(source, root / "output", False)
            self.assertEqual(_render(expected, expected.merged, tid=None), paths[0].read_text())
            for path, tid in zip(paths[1:-1], sorted(expected.threads), strict=True):
                self.assertEqual(_render(expected, expected.threads[tid].events, tid=tid), path.read_text())
            self.assertEqual(json.dumps(expected.summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                             paths[-1].read_text())

    def test_incomplete_fragment_diagnostics_keep_first_encounter_order(self):
        from scripts.flight_storage import spooled_recovery
        records = legacy.core_records(42)
        records += [legacy.flight_record(6, sequence, legacy.string_definition(sequence - 2, value), flags=3)
                    for sequence, value in ((3, b"jni"), (4, b"helper"), (5, b"abc"))]
        records += [legacy.flight_record(6, sequence,
                    legacy.event_fragment(event_id, 6, 0, 2, 1, 2, 3), flags=4)
                    for sequence, event_id in ((6, 200), (7, 100))]
        raw = legacy.artifact(directories=[legacy.directory_entry(42, 1, 7, 0, 1)],
                              chunks=[legacy.chunk(0, 42, 1, records)])
        expected = legacy.recover_flight(io.BytesIO(raw)).summary
        with spooled_recovery(io.BytesIO(raw)) as recovery:
            actual = json.loads("".join(json.JSONEncoder().iterencode(recovery.summary)))
        self.assertEqual([200, 100], [row["event_id"] for row in actual["incomplete_logical_events"]])
        self.assertEqual(expected, actual)

    def test_spool_budget_failure_and_source_changes_publish_nothing(self):
        import scripts.flight_convert as converter
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "run.flight.bin", root / "output"
            source.write_bytes(dense_artifact())
            with self.assertRaisesRegex(FlightTraceError, "spool failure"):
                publish_flight_outputs(source, output, False, max_spool_bytes=4096)
            self.assertFalse(output.exists())
            original = converter._write_temporary

            def changed(*args, **options):
                temporary = original(*args, **options)
                with source.open("ab") as binary:
                    binary.write(b"changed")
                return temporary

            with patch.object(converter, "_write_temporary", changed):
                with self.assertRaisesRegex(FlightTraceError, "changed during"):
                    publish_flight_outputs(source, output, False)
            self.assertEqual([], list(output.iterdir()))


if __name__ == "__main__":
    unittest.main()
