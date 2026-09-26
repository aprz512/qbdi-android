import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).parents[2]
MODULE_PATH = ROOT / "qtrace-ui" / "tools" / "generate_rich_performance_fixture.py"


def load_generator():
    if str(MODULE_PATH.parent) not in sys.path:
        sys.path.insert(0, str(MODULE_PATH.parent))
    spec = importlib.util.spec_from_file_location("rich_performance_fixture", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load rich fixture generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RichFixtureTests(unittest.TestCase):
    def test_fixed_semantic_fingerprint_and_real_typed_records(self):
        import hashlib
        import struct

        generator = load_generator()
        corpus = generator._raw_corpus()
        self.assertEqual(generator.RAW_SEMANTIC_SHA256, hashlib.sha256(corpus).hexdigest())
        self.assertEqual(b"QTRB", corpus[:4])
        kinds = []
        cursor = 16
        while cursor < len(corpus):
            kind, _flags, size = struct.unpack_from("<HHI", corpus, cursor)
            kinds.append(kind)
            cursor += 8 + size
        self.assertEqual(len(corpus), cursor)
        self.assertEqual(100_006, len(kinds))
        self.assertEqual(60_000, kinds.count(4))
        self.assertEqual(20_000, kinds.count(5))
        self.assertEqual(20_000, kinds.count(6))
        self.assertEqual(0, kinds.count(0x8001))


    def test_million_event_stream_has_a_fixed_semantic_fingerprint(self):
        import hashlib
        generator = load_generator()
        digest = hashlib.sha256()
        total = 0
        chunks = 0
        for encoded in generator._records(200_000):
            digest.update(encoded)
            total += len(encoded)
            chunks += 1
        total += len(generator.footer())
        digest.update(generator.footer(instructions=600_000, encoded_bytes=total, compressed_bytes=total))
        self.assertEqual(1_000_001, chunks)
        self.assertEqual(generator.MILLION_SEMANTIC_SHA256, digest.hexdigest())


class RichGateTests(unittest.TestCase):
    def setUp(self):
        import copy
        sys.path.insert(0, str(MODULE_PATH.parent))
        import rich_performance_gate
        self.gate = rich_performance_gate
        self.manifest = {
            "semantic_oracle": {"instructions": 600_000, "memory_events": 200_000,
                                "semantic_events": 200_000, "call_frames": 5000,
                                "flight_threads": [101, 202, 303, 404]},
            "corpora": {"flight": {"events": 68}, "ipc": {"events": 100_006}},
            "expected_flight_completeness": [{"cause": "coverage_gap"}, {"cause": "overwritten"}],
        }
        run = {"event_counts": [600_000, 200_000, 200_000, 6], "call_frames": 5000,
               "flight_threads": [101, 202, 303, 404], "flight_events": 68,
               "flight_completeness": self.manifest["expected_flight_completeness"],
               "ipc_events": 100_006, "correctness_digest": "a" * 64,
               "query_seconds": [0.01] * 200, "memory_query_seconds": [0.01] * 200,
               "replay_query_seconds": [0.001] * 50}
        for field in ("raw_cold_seconds", "raw_warm_seconds", "compressed_cold_seconds",
                      "replay_build_seconds", "call_tree_seconds", "peak_rss_bytes", "cache_bytes",
                      "ipc_query_seconds", "ipc_page_bytes", "ipc_call_tree_seconds", "ipc_call_tree_bytes"):
            run[field] = 1
        self.runs = [copy.deepcopy(run) for _ in range(5)]

    def test_requires_full_runs_and_correct_thread_gap_evidence(self):
        self.assertIn("query_seconds_p95", self.gate.summarize(self.runs, self.manifest))
        with self.assertRaisesRegex(ValueError, "five"):
            self.gate.summarize(self.runs[:4], self.manifest)
        self.runs[-1]["flight_threads"] = [101]
        with self.assertRaisesRegex(ValueError, "thread/gap"):
            self.gate.summarize(self.runs, self.manifest)

    def test_rejects_fast_but_wrong_or_incomplete_samples(self):
        self.runs[-1]["correctness_digest"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.gate.summarize(self.runs, self.manifest)
        self.runs[-1]["correctness_digest"] = "a" * 64
        self.runs[-1]["query_seconds"].pop()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.gate.summarize(self.runs, self.manifest)

    def test_rejects_nonfinite_samples_and_unbounded_ipc(self):
        self.runs[-1]["query_seconds"][0] = float("nan")
        with self.assertRaisesRegex(ValueError, "invalid"):
            self.gate.summarize(self.runs, self.manifest)
        self.runs[-1]["query_seconds"][0] = 0.01
        self.runs[-1]["ipc_page_bytes"] = 2 * 1024**2 + 1
        with self.assertRaisesRegex(ValueError, "byte budget"):
            self.gate.summarize(self.runs, self.manifest)


if __name__ == "__main__":
    unittest.main()
