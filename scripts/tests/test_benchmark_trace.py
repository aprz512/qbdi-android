import unittest

from scripts.benchmark_trace import (
    ensure_stable_return,
    frida_endpoint,
    median_report,
    parse_legacy_trace,
    select_newest_benchmark_trace,
    throughput_metrics,
)


class LegacyTraceParserTests(unittest.TestCase):
    def test_legacy_trace_metrics_and_median(self):
        trace = b"""TRACE_BEGIN scene=benchmark
1 libdemo_target.so+0x10 add x0, x0, #1
2 libdemo_target.so+0x14 ret
TRACE_END status=ok ret=0x42 elapsed_ms=20 bytes=0
"""

        parsed = parse_legacy_trace(trace, file_bytes=512)

        self.assertEqual(2, parsed["instructions"])
        self.assertEqual(20, parsed["elapsed_ms"])
        self.assertEqual(512, parsed["raw_bytes"])
        self.assertEqual(
            20,
            median_report([
                {"elapsed_ms": 10},
                {"elapsed_ms": 30},
                {"elapsed_ms": 20},
            ])["elapsed_ms"],
        )

    def test_rejects_trace_without_a_successful_footer(self):
        trace = b"""TRACE_BEGIN scene=benchmark
1 libdemo_target.so+0x10 add x0, x0, #1
"""

        with self.assertRaisesRegex(ValueError, "TRACE_END"):
            parse_legacy_trace(trace, file_bytes=len(trace))

    def test_rejects_measured_runs_with_different_returns(self):
        with self.assertRaisesRegex(ValueError, "return"):
            ensure_stable_return(["0x42", "0x43"])

    def test_selects_only_the_newest_benchmark_trace(self):
        names = [
            "1710000000002_100_100_jni_0x10.trace.txt",
            "1710000000001_100_100_benchmark_0x20.trace.txt",
        ]

        self.assertEqual(
            "1710000000001_100_100_benchmark_0x20.trace.txt",
            select_newest_benchmark_trace(names),
        )

    def test_uses_the_adb_forwarded_frida_endpoint(self):
        self.assertEqual("127.0.0.1:27042", frida_endpoint(27042))

    def test_derives_every_baseline_run_throughput_from_raw_metrics(self):
        expected = {
            1937: (11212.18, 1.16144),
            1886: (11515.38, 1.19285),
            1978: (10979.78, 1.13736),
            2226: (9756.51, 1.01065),
            1931: (11247.02, 1.16505),
        }

        for elapsed_ms, (instructions_per_second, raw_mib_per_second) in expected.items():
            metrics = throughput_metrics({
                "instructions": 21718,
                "raw_bytes": 2358988,
                "elapsed_ms": elapsed_ms,
            })
            self.assertAlmostEqual(instructions_per_second, metrics["instructions_per_second"], places=2)
            self.assertAlmostEqual(raw_mib_per_second, metrics["raw_mib_per_second"], places=5)


if __name__ == "__main__":
    unittest.main()
