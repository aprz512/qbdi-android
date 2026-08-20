import unittest
import subprocess
from decimal import Decimal
from pathlib import Path

from scripts.benchmark_trace import (
    compare_to_baseline,
    classify_run_as_build_type,
    configure_agent_source,
    ensure_artifact_return,
    ensure_stable_return,
    fast_cost_diagnosis,
    frida_endpoint,
    inject_java_bridge,
    is_missing_trace_directory,
    median_report,
    parse_legacy_trace,
    parse_baseline_report,
    parse_metrics,
    require_balanced_comparison,
    render_report,
    ensure_same_device,
    select_newest_optimized_metrics,
    select_newest_benchmark_trace,
    throughput_metrics,
    verify_setup_failure_smoke,
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

    def test_parses_current_uncompressed_format_two_footer(self):
        trace = b"""TRACE_BEGIN format=2 scene=benchmark
1 libdemo_target.so+0x10 nop
TRACE_END status=ok ret=0x42 elapsed_ms=7 instructions=1 raw_bytes=200 cache_hit_rate=0.500000 buffer_swaps=1 producer_waits=0 producer_wait_ns=0
"""

        parsed = parse_legacy_trace(trace, file_bytes=256)

        self.assertEqual("0x42", parsed["return"])
        self.assertEqual(7, parsed["elapsed_ms"])

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

    def test_treats_only_a_missing_initial_trace_directory_as_an_empty_snapshot(self):
        missing = subprocess.CalledProcessError(
            1, ["adb", "ls"], stderr=b"ls: files/qbdi-traces: No such file or directory\n"
        )
        denied = subprocess.CalledProcessError(
            1, ["adb", "ls"], stderr=b"run-as: package not debuggable\n"
        )

        self.assertTrue(is_missing_trace_directory(missing))
        self.assertFalse(is_missing_trace_directory(denied))

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


class OptimizedMetricsParserTests(unittest.TestCase):
    METRICS = """profile=balanced
return=0x42
instructions=100000
elapsed_ms=50
instructions_per_second=2000000.000000
raw_bytes=10485760
compressed_bytes=1048576
raw_bytes_per_second=209715200.000000
disk_bytes_per_second=20971520.000000
compression_ratio=0.100000
cache_hits=90000
cache_misses=10000
cache_collisions=123
cache_hit_rate=0.900000
buffer_swaps=7
producer_waits=0
producer_wait_ns=0
effective_buffer_bytes=67108864
"""

    def test_parses_and_validates_every_optimized_metric(self):
        current = parse_metrics(self.METRICS)

        self.assertEqual("balanced", current["profile"])
        self.assertEqual("0x42", current["return"])
        self.assertEqual(100000, current["instructions"])
        self.assertEqual(50, current["elapsed_ms"])
        self.assertEqual(Decimal("2000000.000000"), current["instructions_per_second"])
        self.assertEqual(10_485_760, current["raw_bytes"])
        self.assertEqual(1_048_576, current["compressed_bytes"])
        self.assertEqual(209_715_200.0, current["raw_bytes_per_second"])
        self.assertEqual(20_971_520.0, current["disk_bytes_per_second"])
        self.assertEqual(Decimal("0.100000"), current["compression_ratio"])
        self.assertEqual(90_000, current["cache_hits"])
        self.assertEqual(10_000, current["cache_misses"])
        self.assertEqual(123, current["cache_collisions"])
        self.assertEqual(Decimal("0.900000"), current["cache_hit_rate"])
        self.assertEqual(7, current["buffer_swaps"])
        self.assertEqual(0, current["producer_waits"])
        self.assertEqual(0, current["producer_wait_ns"])
        self.assertEqual(67_108_864, current["effective_buffer_bytes"])

    def test_rejects_missing_and_inconsistent_metrics(self):
        with self.assertRaisesRegex(ValueError, "effective_buffer_bytes"):
            parse_metrics(self.METRICS.replace("effective_buffer_bytes=67108864\n", ""))
        with self.assertRaisesRegex(ValueError, "instructions_per_second"):
            parse_metrics(self.METRICS.replace("instructions_per_second=2000000.000000",
                                               "instructions_per_second=1.000000"))
        huge = (self.METRICS.replace("instructions=100000", "instructions=18446744073709551615")
                .replace("elapsed_ms=50", "elapsed_ms=1")
                .replace("instructions_per_second=2000000.000000",
                         "instructions_per_second=18446744073709551614000.000000")
                .replace("raw_bytes_per_second=209715200.000000",
                         "raw_bytes_per_second=10485760000.000000")
                .replace("disk_bytes_per_second=20971520.000000",
                         "disk_bytes_per_second=1048576000.000000"))
        with self.assertRaisesRegex(ValueError, "instructions_per_second"):
            parse_metrics(huge)

    def test_reports_medians_for_every_optimized_metric_and_speedup(self):
        slow = parse_metrics(self.METRICS.replace("elapsed_ms=50", "elapsed_ms=100")
                             .replace("instructions_per_second=2000000.000000",
                                      "instructions_per_second=1000000.000000")
                             .replace("raw_bytes_per_second=209715200.000000",
                                      "raw_bytes_per_second=104857600.000000")
                             .replace("disk_bytes_per_second=20971520.000000",
                                      "disk_bytes_per_second=10485760.000000"))
        fast = parse_metrics(self.METRICS)

        report = median_report([slow, fast])

        self.assertEqual("balanced", report["profile"])
        for key in (
            "instructions", "elapsed_ms", "instructions_per_second", "raw_bytes",
            "compressed_bytes", "raw_bytes_per_second", "disk_bytes_per_second",
            "compression_ratio", "cache_hits", "cache_misses", "cache_collisions", "cache_hit_rate",
            "buffer_swaps", "producer_waits", "producer_wait_ns", "effective_buffer_bytes",
        ):
            self.assertIn(key, report)
        self.assertEqual(75, report["elapsed_ms"])
        self.assertEqual(1_500_000.0, report["instructions_per_second"])
        self.assertEqual(4.0, compare_to_baseline(report, {"elapsed_ms": 300})["speedup"])

    def test_comparison_requires_balanced_and_the_same_device_fingerprint(self):
        baseline = parse_baseline_report("""
| Device model | Pixel (`sailfish`) |
| Android version | 10 |
| ABI | `arm64-v8a` |
| Build type | Debug |
| Median | 1937 | 21718 | 2358988 | 11212.18 | 1.16144 |
""")

        self.assertEqual(1937, baseline["elapsed_ms"])
        require_balanced_comparison("balanced")
        ensure_same_device(
            baseline,
            {"model": "Pixel", "device": "sailfish", "android": "10",
             "abi": "arm64-v8a", "build_type": "Debug"},
        )
        with self.assertRaisesRegex(ValueError, "balanced"):
            require_balanced_comparison("fast")
        with self.assertRaisesRegex(ValueError, "device"):
            ensure_same_device(
                baseline,
                {"model": "Pixel 8", "device": "shiba", "android": "14",
                 "abi": "arm64-v8a", "build_type": "Debug"},
            )
        self.assertEqual("Debug", classify_run_as_build_type(0, ""))
        self.assertEqual(
            "Release", classify_run_as_build_type(1, "run-as: package not debuggable")
        )
        with self.assertRaisesRegex(ValueError, "run-as"):
            classify_run_as_build_type(1, "run-as: package not found")

    def test_checked_in_baseline_is_a_valid_same_device_comparison_input(self):
        document = Path(__file__).parents[2].joinpath(
            "docs", "benchmarks", "trace-throughput-baseline.md"
        ).read_text(encoding="utf-8")

        baseline = parse_baseline_report(document)

        self.assertEqual(
            {"model": "Pixel 6", "device": "oriole", "android": "16",
             "abi": "arm64-v8a", "build_type": "Debug", "elapsed_ms": 226},
            baseline,
        )

    def test_speedup_threshold_uses_exact_decimal_arithmetic(self):
        comparison = compare_to_baseline(
            {"elapsed_ms": 1_000_000_000_000_000_000},
            {"elapsed_ms": 4_999_999_999_999_999_999},
        )

        self.assertLess(comparison["speedup"], Decimal(5))

    def test_preserves_large_integer_counter_medians_exactly(self):
        runs = [
            parse_metrics(self.METRICS.replace("producer_wait_ns=0", f"producer_wait_ns={value}"))
            for value in (9_007_199_254_740_991, 9_007_199_254_740_993,
                          9_007_199_254_740_995)
        ]

        self.assertEqual(
            9_007_199_254_740_993,
            median_report(runs)["producer_wait_ns"],
        )

    def test_preserves_and_serializes_maximum_width_fixed_six_rates(self):
        valid = (self.METRICS.replace("instructions=100000", "instructions=18446744073709551615")
                 .replace("elapsed_ms=50", "elapsed_ms=1")
                 .replace("instructions_per_second=2000000.000000",
                          "instructions_per_second=18446744073709551615000.000000")
                 .replace("raw_bytes_per_second=209715200.000000",
                          "raw_bytes_per_second=10485760000.000000")
                 .replace("disk_bytes_per_second=20971520.000000",
                          "disk_bytes_per_second=1048576000.000000"))
        parsed = parse_metrics(valid)

        self.assertEqual(
            Decimal("18446744073709551615000.000000"),
            median_report([parsed])["instructions_per_second"],
        )
        self.assertIn(
            '"instructions_per_second": "18446744073709551615000.000000"',
            render_report(median_report([parsed])),
        )
        over_uint64 = valid.replace("instructions=18446744073709551615",
                                    "instructions=18446744073709551616").replace(
            "instructions_per_second=18446744073709551615000.000000",
            "instructions_per_second=18446744073709551616000.000000",
        )
        with self.assertRaisesRegex(ValueError, "uint64"):
            parse_metrics(over_uint64)

    def test_selects_only_the_newest_complete_optimized_benchmark(self):
        names = [
            "1710000000003_100_100_benchmark_0x20_2.trace.txt.lz4.metrics",
            "1710000000002_100_100_jni_0x10_1.trace.txt.lz4.metrics",
            "1710000000001_100_100_benchmark_0x20_0.trace.txt.lz4",
            "1710000000001_100_100_benchmark_0x20_0.trace.txt.lz4.metrics",
        ]

        self.assertEqual(
            "1710000000001_100_100_benchmark_0x20_0.trace.txt.lz4.metrics",
            select_newest_optimized_metrics(names),
        )

    def test_configures_the_requested_profile_for_the_fresh_process_agent(self):
        source = "const profile = '__QTRACE_PROFILE__'; const test = '__QTRACE_TEST_CONFIG__';"

        self.assertEqual(
            "const profile = 'balanced'; const test = '';",
            configure_agent_source(source, "balanced"),
        )
        self.assertEqual(
            "const profile = 'balanced'; const test = ';test_buffer_bytes=4096';",
            configure_agent_source(source, "balanced", False, 4096),
        )
        self.assertEqual(
            "const profile = 'balanced'; const test = ';test_fail_setup=1';",
            configure_agent_source(source, "balanced", False, None, True),
        )
        with self.assertRaisesRegex(ValueError, "profile"):
            configure_agent_source(source, "invalid")
        with self.assertRaisesRegex(ValueError, "test buffer"):
            configure_agent_source(source, "balanced", False, 8192)

    def test_rejects_custom_agent_without_test_config_for_requested_test_options(self):
        custom_agent = "const profile = '__QTRACE_PROFILE__'; const compression = '__QTRACE_COMPRESSION__';"

        for test_buffer_bytes, test_fail_setup in ((4096, False), (None, True), (4096, True)):
            with self.subTest(test_buffer_bytes=test_buffer_bytes, test_fail_setup=test_fail_setup):
                with self.assertRaisesRegex(ValueError, "__QTRACE_TEST_CONFIG__ exactly once"):
                    configure_agent_source(
                        custom_agent, "balanced", False, test_buffer_bytes, test_fail_setup
                    )

    def test_allows_custom_agent_without_test_config_when_no_test_option_is_requested(self):
        custom_agent = "const profile = '__QTRACE_PROFILE__'; const compression = '__QTRACE_COMPRESSION__';"

        self.assertEqual(
            "const profile = 'fast'; const compression = '1';",
            configure_agent_source(custom_agent, "fast"),
        )

    def test_rejects_duplicate_test_config_marker_when_test_option_is_requested(self):
        duplicate = "__QTRACE_PROFILE__ __QTRACE_TEST_CONFIG__ __QTRACE_TEST_CONFIG__"

        with self.assertRaisesRegex(ValueError, "__QTRACE_TEST_CONFIG__ exactly once"):
            configure_agent_source(duplicate, "balanced", False, 4096)

    def test_benchmark_agent_loads_the_tracer_through_the_application_loader(self):
        source = Path(__file__).parents[1].joinpath("benchmark_trace.js").read_text(
            encoding="utf-8"
        )

        self.assertIn("ActivityThread.currentApplication()", source)
        self.assertIn("load0.overload('java.lang.Class', 'java.lang.String')", source)
        self.assertNotIn("Module.load(config.remoteDir + '/' + config.tracer)", source)

    def test_injects_the_frida_java_bridge_before_the_benchmark_agent(self):
        prepared = inject_java_bridge("var bridge = { available: true };", "send(Java.available);")

        self.assertLess(prepared.index("var bridge"), prepared.index("send(Java.available)"))
        self.assertIn("Object.defineProperty(globalThis, 'Java', { value: bridge });", prepared)

    def test_rejects_optimized_artifact_return_mismatch(self):
        metrics = parse_metrics(self.METRICS)

        with self.assertRaisesRegex(RuntimeError, "returned"):
            ensure_artifact_return("0x43", metrics, "benchmark.trace.txt.lz4.metrics")
        with self.assertRaisesRegex(ValueError, "return"):
            parse_metrics(self.METRICS.replace("return=0x42", "return=0x10000000000000000"))

    def test_verifies_setup_failure_without_publishing_artifacts(self):
        self.assertEqual(
            "0x20a128f3d199a008",
            verify_setup_failure_smoke(
                "0x20A128F3D199A008", "0x20a128f3d199a008", []
            ),
        )
        with self.assertRaisesRegex(RuntimeError, "returned"):
            verify_setup_failure_smoke("0x1", "0x2", [])
        with self.assertRaisesRegex(RuntimeError, "artifacts"):
            verify_setup_failure_smoke("0x2", "0x2", ["unexpected.metrics"])

    def test_identifies_measured_producer_wait_as_the_dominant_cost(self):
        metrics = parse_metrics(
            self.METRICS.replace("producer_waits=0", "producer_waits=4")
            .replace("producer_wait_ns=0", "producer_wait_ns=40000000")
        )

        diagnosis = fast_cost_diagnosis(metrics)

        self.assertEqual("producer_wait_time", diagnosis["dominant_cost"])
        self.assertEqual(Decimal("0.8"), diagnosis["producer_wait_fraction"])

    def test_does_not_claim_incommensurate_cache_or_encoding_indicators_are_dominant(self):
        cache_diagnosis = fast_cost_diagnosis(parse_metrics(self.METRICS))
        encoding_fixture = self.METRICS.replace("cache_hits=90000", "cache_hits=0").replace(
            "cache_misses=10000", "cache_misses=0"
        ).replace("cache_hit_rate=0.900000", "cache_hit_rate=0.000000")
        encoding_diagnosis = fast_cost_diagnosis(parse_metrics(encoding_fixture))

        self.assertEqual("undetermined", cache_diagnosis["dominant_cost"])
        self.assertEqual(Decimal("0.1"), cache_diagnosis["cache_miss_fraction"])
        self.assertEqual("undetermined", encoding_diagnosis["dominant_cost"])
        self.assertIn("raw_bytes_per_second", encoding_diagnosis)


if __name__ == "__main__":
    unittest.main()
