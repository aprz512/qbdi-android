import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).parents[2]
MODULE_PATH = ROOT / "qtrace-ui" / "tools" / "performance_gate.py"


def load_gate():
    spec = importlib.util.spec_from_file_location("qtrace_ui_performance_gate", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load performance gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def report(**overrides):
    digest = "a" * 64
    value = {
        "schema": 1,
        "generator": {"schema": 1, "sha256": "b" * 64},
        "analyzer": {"commit": "c" * 40, "sha256": "d" * 64},
        "host": {
            "identity": "qtrace-ui-reference-v1",
            "cpu_model": "Reference CPU",
            "cpu_count": 8,
            "ram_bytes": 16 * 1024**3,
            "kernel": "Linux 6.12",
            "filesystem": "ext4",
        },
        "corpora": {
            "qtrb": {"events": 10_000_000, "bytes": 123, "sha256": "e" * 64},
            "flight": {"events": 68, "bytes": 512 * 1024**2, "sha256": "f" * 64},
        },
        "expected_correctness_digest": digest,
        "expected_flight_completeness": [
            {"cause": "overwritten"},
            {"cause": "coverage_gap"},
        ],
        "cold_index": [
            {"seconds": 30.0, "peak_rss_bytes": 2 * 1024**3,
             "cache_bytes": 1, "correctness_digest": digest}
            for _ in range(5)
        ],
        "warm_open": [
            {"seconds": 2.0, "peak_rss_bytes": 1, "cache_bytes": 1,
             "correctness_digest": digest}
            for _ in range(5)
        ],
        "viewport_seconds": [0.05] * 200,
        "structured_search_seconds": [0.2] * 200,
    }
    for key, item in overrides.items():
        if key == "cold_index_seconds":
            value["cold_index"] = [dict(run, seconds=item) for run in value["cold_index"]]
        elif key == "correctness_digest":
            value["cold_index"][0]["correctness_digest"] = item
        else:
            value[key] = item
    return value


class PerformanceVerdictTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gate = load_gate()

    def test_median_and_nearest_rank_p95(self):
        self.assertEqual(3.0, self.gate.median([5, 1, 3, 2, 4]))
        self.assertEqual(2.5, self.gate.median([1, 4, 2, 3]))
        self.assertEqual(95.0, self.gate.nearest_rank_p95(range(1, 101)))

    def test_accepts_threshold_equality_and_rejects_one_over(self):
        self.assertTrue(self.gate.verdict(report(cold_index_seconds=30.0)).passed)
        result = self.gate.verdict(report(cold_index_seconds=30.001))
        self.assertFalse(result.passed)
        self.assertIn("cold index", " ".join(result.failures))

    def test_one_failing_run_is_not_hidden_by_a_fast_median(self):
        value = report(cold_index_seconds=1.0)
        value["cold_index"][4]["seconds"] = 30.001
        self.assertFalse(self.gate.verdict(value).passed)

    def test_correctness_failure_overrides_fast_numbers(self):
        value = report(cold_index_seconds=1.0, correctness_digest="wrong")
        self.assertFalse(self.gate.verdict(value).passed)

    def test_requires_five_complete_runs_and_two_hundred_queries(self):
        value = report()
        value["cold_index"].pop()
        value["viewport_seconds"].pop()
        failures = " ".join(self.gate.verdict(value).failures)
        self.assertIn("five", failures)
        self.assertIn("200", failures)

    def test_rejects_wrong_exact_corpus_identity(self):
        value = report()
        value["corpora"]["qtrb"]["events"] -= 1
        value["corpora"]["flight"]["bytes"] -= 1
        failures = " ".join(self.gate.verdict(value).failures)
        self.assertIn("10,000,000", failures)
        self.assertIn("536870912", failures)

    def test_rejects_stale_generator_or_analyzer_identity(self):
        value = report()
        value["generator"]["sha256"] = "stale"
        value["analyzer"]["commit"] = "stale"
        failures = " ".join(self.gate.verdict(value).failures)
        self.assertIn("generator", failures)
        self.assertIn("analyzer", failures)

    def test_rejects_missing_fixed_host_identity(self):
        value = report()
        value["host"].pop("identity")
        self.assertIn("host identity", " ".join(self.gate.verdict(value).failures))

    def test_parses_linux_rss_and_rejects_malformed_status(self):
        self.assertEqual(12 * 1024, self.gate.parse_rss_bytes("VmHWM:\t12 kB\n"))
        with self.assertRaises(ValueError):
            self.gate.parse_rss_bytes("VmHWM: unlimited\n")


if __name__ == "__main__":
    unittest.main()
