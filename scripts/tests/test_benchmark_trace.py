import unittest
import contextlib
import hashlib
import io
import json
import multiprocessing
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from scripts.tests.test_trace_binary import complete_stream, stream_header

import scripts.benchmark_trace as benchmark_trace

from scripts.benchmark_trace import (
    ACCEPTANCE_RUN_COUNT,
    PROFILE_RATE_TARGETS,
    compare_to_baseline,
    compare_to_profile_baseline,
    classify_run_as_build_type,
    configure_agent_source,
    collect_and_validate_optimized_artifact,
    ensure_artifact_return,
    ensure_metrics_container,
    ensure_stable_return,
    fast_cost_diagnosis,
    frida_endpoint,
    inject_java_bridge,
    is_missing_trace_directory,
    median_report,
    parse_legacy_trace,
    parse_baseline_document,
    parse_baseline_report,
    parse_metrics,
    require_binary_acceptance_candidate,
    require_balanced_comparison,
    render_report,
    ensure_same_device,
    ensure_same_format_two_device,
    select_newest_optimized_metrics,
    select_exact_new_optimized_metrics,
    select_newest_benchmark_trace,
    throughput_metrics,
    verify_candidate_tracer,
    verify_setup_failure_smoke,
)


class HistoricalTargetIdentityTests(unittest.TestCase):
    RAW_SHA = "5f1a970825ae8bacb17d8dd656e01bd1fe7172638ba3ddcacd82ffaaad6e62c0"
    CANONICAL_SHA = "0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169"
    COMMIT = "2d6b1022a14ae554804a57e267544c12dea29353"

    def test_baseline_preserves_raw_identity_and_requires_canonical_identity(self):
        text = Path("docs/benchmarks/binary-trace-baseline.md").read_text(encoding="utf-8")
        identity = benchmark_trace.parse_baseline_document(text)
        self.assertEqual(
            (self.RAW_SHA, self.CANONICAL_SHA, self.COMMIT),
            (identity["target_library_sha256"],
             identity["target_library_canonical_sha256"],
             identity["historical_target_commit"]),
        )

    def test_expected_installed_apk_sha_requires_lowercase_64_hex(self):
        with patch.object(sys, "argv", ["benchmark_trace.py", "--expected-installed-apk-sha256", "A" * 64]):
            with self.assertRaises(SystemExit):
                benchmark_trace.parse_args()
        with patch.object(sys, "argv", ["benchmark_trace.py", "--expected-installed-apk-sha256", "a" * 64]):
            self.assertEqual("a" * 64, benchmark_trace.parse_args().expected_installed_apk_sha256)

    def test_compare_rejects_expected_apk_or_canonical_mismatch_before_warmup(self):
        args = SimpleNamespace(
            runs=5, test_fail_setup=False,
            compare="docs/benchmarks/binary-trace-baseline.md", profile="balanced",
            legacy=False, candidate_tracer="candidate.so", expected_installed_apk_sha256="1" * 64,
        )
        identity = {
            "model": "Pixel 6", "device": "oriole", "android": "16", "abi": "arm64-v8a",
            "android_build_type": "user", "app_build_type": "Debug",
            "build_fingerprint": "google/oriole/oriole:16/CP1A.260405.005/15001963:user/release-keys",
            "selinux": "Enforcing", "package": "com.aprz.qbdiandroid",
        }
        for message in ("installed base.apk SHA-256", "canonical target SHA-256"):
            with self.subTest(message=message), \
                 patch.object(benchmark_trace, "parse_args", return_value=args), \
                 patch.object(benchmark_trace, "live_device_identity", return_value=identity), \
                 patch.object(benchmark_trace, "verify_candidate_tracer", return_value="a" * 64), \
                 patch.object(benchmark_trace, "verify_installed_target_library",
                              side_effect=ValueError(message)), \
                 patch.object(benchmark_trace, "run_once", side_effect=AssertionError("must not warm up")) as run, \
                 self.assertRaisesRegex(ValueError, message):
                benchmark_trace.main()
            self.assertEqual(0, run.call_count)

    def test_manual_non_compare_run_does_not_require_expected_apk_sha(self):
        args = SimpleNamespace(
            runs=1, test_fail_setup=False, compare=None, profile="fast", legacy=True,
        )
        run = {"return": "0x42", "elapsed_ms": 1, "instructions": 1, "raw_bytes": 1}
        with patch.object(benchmark_trace, "parse_args", return_value=args), \
             patch.object(benchmark_trace, "run_once", return_value=run), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, benchmark_trace.main())

    def test_baseline_rejects_tampered_pinned_identity_constants(self):
        text = Path("docs/benchmarks/binary-trace-baseline.md").read_text(encoding="utf-8")
        for expected, replacement in (
            ("com.aprz.qbdiandroid", "com.example.other"),
            ("arm64-v8a", "x86_64"),
            (self.RAW_SHA, "0" * 64),
            (self.CANONICAL_SHA, "1" * 64),
            (self.COMMIT, "0" * 40),
        ):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                benchmark_trace.parse_baseline_document(text.replace(expected, replacement, 1))

    def test_verifier_accepts_matching_and_rejects_mismatching_expected_apk_sha(self):
        target = b"\x7fELFtarget"
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as apk:
            apk.writestr("lib/arm64-v8a/libdemo_target.so", target)
        apk_bytes = archive.getvalue()
        package_path = subprocess.CompletedProcess(
            ["adb", "pm", "path"], 0, stdout="package:/data/app/example/base.apk\n", stderr="",
        )
        baseline = {
            "abi": "arm64-v8a", "package": "com.aprz.qbdiandroid",
            "target_library_sha256": self.RAW_SHA,
            "target_library_canonical_sha256": self.CANONICAL_SHA,
        }
        common = (
            patch.object(benchmark_trace, "adb", return_value=package_path),
            patch.object(benchmark_trace, "capture_bounded", return_value=apk_bytes),
            patch.object(benchmark_trace, "canonical_elf_sha256", return_value=self.CANONICAL_SHA),
        )
        matching = SimpleNamespace(
            adb="adb", device="serial", package="com.aprz.qbdiandroid", adb_timeout=3,
            expected_installed_apk_sha256=hashlib.sha256(apk_bytes).hexdigest(),
        )
        with common[0], common[1], common[2]:
            verified = benchmark_trace.verify_installed_target_library(matching, baseline)
        self.assertEqual(matching.expected_installed_apk_sha256, verified.installed_apk_sha256)
        mismatching = SimpleNamespace(**{**matching.__dict__, "expected_installed_apk_sha256": "0" * 64})
        with patch.object(benchmark_trace, "adb", return_value=package_path), \
             patch.object(benchmark_trace, "capture_bounded", return_value=apk_bytes), \
             self.assertRaisesRegex(ValueError, "installed base.apk SHA-256"):
            benchmark_trace.verify_installed_target_library(mismatching, baseline)

    def test_verifier_rejects_noncanonical_package_or_abi_before_adb(self):
        baseline = {
            "package": "com.example.other", "abi": "x86_64",
            "target_library_sha256": self.RAW_SHA,
            "target_library_canonical_sha256": self.CANONICAL_SHA,
        }
        args = SimpleNamespace(adb="adb", device="serial", package="com.example.other", adb_timeout=3)
        with patch.object(benchmark_trace, "adb", side_effect=AssertionError("must not call adb")):
            with self.assertRaisesRegex(ValueError, "package"):
                benchmark_trace.verify_installed_target_library(args, baseline)

    def test_verifier_rejects_streamed_target_actual_over_64_mib_and_expired_deadline(self):
        info = SimpleNamespace(filename="lib/arm64-v8a/libdemo_target.so", file_size=1)
        archive = MagicMock()
        archive.infolist.return_value = [info]
        archive.open.return_value = io.BytesIO(b"\x7fELF" + b"x" * (64 * 1024 * 1024 - 3))
        archive_context = MagicMock()
        archive_context.__enter__.return_value = archive
        package_path = subprocess.CompletedProcess(
            ["adb", "pm", "path"], 0, stdout="package:/data/app/example/base.apk\n", stderr="",
        )
        args = SimpleNamespace(adb="adb", device="serial", package="com.aprz.qbdiandroid", adb_timeout=3)
        baseline = {
            "package": "com.aprz.qbdiandroid", "abi": "arm64-v8a",
            "target_library_sha256": self.RAW_SHA,
            "target_library_canonical_sha256": self.CANONICAL_SHA,
        }
        with patch.object(benchmark_trace, "adb", return_value=package_path), \
             patch.object(benchmark_trace, "capture_bounded", return_value=b"apk"), \
             patch.object(benchmark_trace.zipfile, "ZipFile", return_value=archive_context), \
             self.assertRaisesRegex(ValueError, "64 MiB"):
            benchmark_trace.verify_installed_target_library(args, baseline)

        archive.open.return_value = io.BytesIO(b"\x7fELF")
        args.adb_timeout = 1
        with patch.object(benchmark_trace, "adb", return_value=package_path), \
             patch.object(benchmark_trace, "capture_bounded", return_value=b"apk"), \
             patch.object(benchmark_trace.zipfile, "ZipFile", return_value=archive_context), \
             patch.object(benchmark_trace.time, "monotonic",
                          side_effect=[100.0, 100.0, 100.5, 100.6, 101.0]), \
             self.assertRaisesRegex(ValueError, "deadline"):
            benchmark_trace.verify_installed_target_library(args, baseline)


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
        trace = b"""TRACE_BEGIN format=4 scene=benchmark
1 libdemo_target.so+0x10 nop
TRACE_END status=completed return_valid=1 return=0x42 elapsed_ms=7 instructions=1 encoded_bytes=200 compressed_bytes=100 cache_hits=1 cache_misses=1 cache_collisions=0 buffer_swaps=1 producer_waits=0 producer_wait_ns=0 effective_buffer_bytes=4096
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

    def test_device_listing_rejects_unsafe_names_and_unbounded_output(self):
        args = SimpleNamespace(package="com.example.app", adb="adb", device="serial")
        with patch.object(
            benchmark_trace, "capture_bounded", return_value=b"../trace.bin\n",
        ), self.assertRaisesRegex(RuntimeError, "unsafe artifact"):
            benchmark_trace.trace_names(args)
        with patch.object(
            benchmark_trace, "capture_bounded", side_effect=benchmark_trace.BoundedProcessError(
                "subprocess output exceeds size limit"
            ),
        ), self.assertRaisesRegex(RuntimeError, "size limit"):
            benchmark_trace.trace_names(args)

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
    METRICS_V2 = """metrics_version=2
profile=balanced
return=0x42
instructions=100000
elapsed_ms=50
instructions_per_second=2000000.000000
encoded_bytes=10485760
compressed_bytes=1048576
encoded_bytes_per_second=209715200.000000
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
    METRICS_V3 = """metrics_version=3
termination=completed
return_valid=1
profile=balanced
return=0x42
instructions=100000
elapsed_ms=50
instructions_per_second=2000000.000000
encoded_bytes=10485760
compressed_bytes=1048576
encoded_bytes_per_second=209715200.000000
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

    def test_parses_exact_metrics_v2_without_redefining_raw_bytes(self):
        current = parse_metrics(self.METRICS_V2)

        self.assertEqual(2, current["metrics_version"])
        self.assertEqual(10_485_760, current["encoded_bytes"])
        self.assertEqual(Decimal("209715200.000000"), current["encoded_bytes_per_second"])
        self.assertNotIn("raw_bytes", current)

    def test_rejects_mixed_or_unknown_metrics_contracts(self):
        with self.assertRaisesRegex(ValueError, "raw_bytes"):
            parse_metrics(self.METRICS_V2 + "raw_bytes=10485760\n")
        with self.assertRaisesRegex(ValueError, "encoded_bytes"):
            parse_metrics(self.METRICS + "encoded_bytes=10485760\n")
        with self.assertRaisesRegex(ValueError, "return_valid"):
            parse_metrics(self.METRICS_V2.replace("metrics_version=2", "metrics_version=3"))

    def test_rejects_metrics_container_version_mismatch_without_fallback(self):
        v1 = parse_metrics(self.METRICS)
        v2 = parse_metrics(self.METRICS_V2)
        v3 = parse_metrics(self.METRICS_V3)
        ensure_metrics_container(v1, "run.trace.txt.lz4")
        ensure_metrics_container(v2, "run.trace.bin.lz4")
        ensure_metrics_container(v2, "run.trace.bin")
        ensure_metrics_container(v3, "run.trace.bin.lz4")
        with self.assertRaisesRegex(RuntimeError, "v1"):
            ensure_metrics_container(v1, "run.trace.bin.lz4")
        with self.assertRaisesRegex(RuntimeError, "v2"):
            ensure_metrics_container(v2, "run.trace.txt.lz4")
        with self.assertRaisesRegex(RuntimeError, "v3"):
            ensure_metrics_container(v3, "run.trace.txt.lz4")

    def test_v2_medians_preserve_decimal_rates_and_full_uint64(self):
        maximum = self.METRICS_V2.replace(
            "producer_wait_ns=0", "producer_wait_ns=18446744073709551615"
        )
        report = median_report([parse_metrics(maximum)])

        self.assertEqual(18446744073709551615, report["producer_wait_ns"])
        self.assertIsInstance(report["encoded_bytes_per_second"], Decimal)
        lower = parse_metrics(self.METRICS_V2.replace(
            "producer_wait_ns=0", "producer_wait_ns=18446744073709551614"
        ))
        upper = parse_metrics(self.METRICS_V2.replace(
            "producer_wait_ns=0", "producer_wait_ns=18446744073709551615"
        ))
        self.assertEqual(
            Decimal("18446744073709551614.5"),
            median_report([lower, upper])["producer_wait_ns"],
        )

    def test_profile_comparison_preserves_oracle_identity_and_uses_compressed_size(self):
        oracle = {"decoded_event_count": 100000, "first_instruction": "1 lib.so+0x0 A",
                  "last_instruction": "100000 lib.so+0x4 RET"}
        run = {**parse_metrics(self.METRICS_V3), "trace": "run.trace.bin.lz4", **oracle}
        runs = [run] * 5
        current = median_report(runs)
        current["return"] = "0x42"
        baseline = {
            "profile": "balanced", "instructions": 100000, "return": "0x42",
            "compressed_bytes": 1048576,
            **oracle,
        }

        comparison = compare_to_profile_baseline(current, baseline, runs)

        self.assertTrue(comparison["meets_rate_target"])
        self.assertTrue(comparison["meets_size_target"])
        with self.assertRaisesRegex(ValueError, "oracle.*return"):
            compare_to_profile_baseline(current, {**baseline, "return": "0x43"}, runs)
        with self.assertRaisesRegex(ValueError, "oracle.*instructions"):
            compare_to_profile_baseline(current, {**baseline, "instructions": 99999}, runs)
        with self.assertRaisesRegex(ValueError, "exactly five"):
            compare_to_profile_baseline(current, baseline, [run])
        with self.assertRaisesRegex(ValueError, "first_instruction"):
            compare_to_profile_baseline(current,
                                        {**baseline, "first_instruction": "WRONG"}, runs)

    def test_acceptance_uses_five_run_median_and_fixed_profile_targets(self):
        self.assertEqual(5, ACCEPTANCE_RUN_COUNT)
        self.assertEqual(
            {
                "fast": Decimal(1_000_000),
                "balanced": Decimal(800_000),
                "full": Decimal(500_000),
            },
            PROFILE_RATE_TARGETS,
        )
        oracle = {
            "decoded_event_count": 100_000,
            "first_instruction": "1 start",
            "last_instruction": "100000 end",
        }
        run = {
            **parse_metrics(self.METRICS_V3.replace("profile=balanced", "profile=fast")),
            "trace": "run.trace.bin.lz4",
            **oracle,
        }
        measured = [
            {**run, "instructions_per_second": Decimal(rate)}
            for rate in ("900000", "1100000", "1000000", "800000", "1200000")
        ]
        current = median_report(measured)
        current["return"] = "0x42"
        baseline = {
            "profile": "fast",
            "instructions": 100_000,
            "return": "0x42",
            "compressed_bytes": 1_048_576,
            **oracle,
        }

        comparison = compare_to_profile_baseline(current, baseline, measured)

        self.assertEqual(Decimal(1_000_000), current["instructions_per_second"])
        self.assertTrue(comparison["meets_rate_target"])
        with self.assertRaisesRegex(ValueError, "exactly five"):
            compare_to_profile_baseline(
                median_report([measured[0]]), baseline, [measured[0]]
            )

    def test_single_fast_diagnostic_run_has_no_acceptance_verdict(self):
        oracle = {
            "decoded_event_count": 100_000,
            "first_instruction": "1 start",
            "last_instruction": "100000 end",
        }
        run = {
            **parse_metrics(self.METRICS_V3.replace("profile=balanced", "profile=fast")),
            "trace": "run.trace.bin.lz4",
            **oracle,
        }
        args = SimpleNamespace(
            runs=1,
            test_fail_setup=False,
            compare=None,
            profile="fast",
            legacy=False,
            candidate_tracer=None,
        )
        for rate in (Decimal("2000000"), Decimal("100000")):
            with self.subTest(rate=rate):
                measured = {**run, "instructions_per_second": rate}
                output = io.StringIO()
                with patch.object(benchmark_trace, "parse_args", return_value=args), \
                     patch.object(
                         benchmark_trace, "run_once", side_effect=[measured, measured]
                     ), \
                     contextlib.redirect_stdout(output):
                    status = benchmark_trace.main()

                self.assertEqual(0, status)
                report = json.loads(output.getvalue())
                self.assertNotIn("comparison", report)
                if rate < PROFILE_RATE_TARGETS["fast"]:
                    self.assertIn("fast_target_diagnosis", report)

    def test_acceptance_checks_every_compressed_binary_artifact_not_the_median(self):
        oracle = {"decoded_event_count": 100000, "first_instruction": "1 start",
                  "last_instruction": "100000 end"}
        first = {**parse_metrics(self.METRICS_V3), "compressed_bytes": 90,
                 "trace": "first.trace.bin.lz4", **oracle}
        second = {**parse_metrics(self.METRICS_V3), "compressed_bytes": 110,
                  "trace": "second.trace.bin.lz4", **oracle}
        runs = [first, first, first, first, second]
        current = median_report(runs)
        current["return"] = "0x42"
        baseline = {"profile": "balanced", "instructions": 100000, "return": "0x42",
                    "compressed_bytes": 100, **oracle}

        comparison = compare_to_profile_baseline(current, baseline, runs)

        self.assertEqual(90, current["compressed_bytes"])
        self.assertEqual([True, True, True, True, False], comparison["per_run_size_targets"])
        self.assertEqual(110, comparison["maximum_compressed_bytes"])
        self.assertFalse(comparison["meets_size_target"])

    def test_acceptance_requires_metrics_v3_compressed_qtrb_runs(self):
        oracle = {"decoded_event_count": 100000, "first_instruction": "1 start",
                  "last_instruction": "100000 end"}
        baseline = {"profile": "balanced", "instructions": 100000, "return": "0x42",
                    "compressed_bytes": 20_000_000, **oracle}
        v3 = {**parse_metrics(self.METRICS_V3), "trace": "run.trace.bin.lz4", **oracle}
        report = median_report([v3] * 5)
        report["return"] = "0x42"
        compare_to_profile_baseline(report, baseline, [v3] * 5)
        v1 = {**parse_metrics(self.METRICS), "trace": "run.trace.txt.lz4"}
        v2 = {**parse_metrics(self.METRICS_V2), "trace": "run.trace.bin.lz4"}
        raw = {**v3, "trace": "run.trace.bin"}
        for candidate, message in ((v1, "metrics_version=3"), (v2, "metrics_version=3"),
                                   (raw, "trace.bin.lz4")):
            with self.subTest(trace=candidate["trace"]), self.assertRaisesRegex(ValueError, message):
                candidate.update(oracle)
                candidate_report = median_report([candidate] * 5)
                candidate_report["return"] = "0x42"
                compare_to_profile_baseline(candidate_report, baseline, [candidate] * 5)

    def test_format_two_device_identity_maps_to_live_device_fields(self):
        baseline = {
            "device_model": "Pixel 6", "device_product": "oriole",
            "android_version": "16", "abi": "arm64-v8a", "android_build_type": "user",
            "app_build_type": "Debug", "build_fingerprint": "fingerprint",
            "selinux": "Enforcing", "package": "com.example",
        }
        current = {
            "model": "Pixel 6", "device": "oriole", "android": "16",
            "abi": "arm64-v8a", "android_build_type": "user", "app_build_type": "Debug",
            "build_fingerprint": "fingerprint", "selinux": "Enforcing",
            "package": "com.example",
        }
        ensure_same_format_two_device(baseline, current)
        with self.assertRaisesRegex(ValueError, "device_model"):
            ensure_same_format_two_device(baseline, {**current, "model": "Pixel 8"})

    def test_binary_trace_baseline_has_all_profiles_and_size_fields(self):
        path = Path("docs/benchmarks/binary-trace-baseline.md")
        text = path.read_text(encoding="utf-8")
        identity = benchmark_trace.parse_baseline_document(text)
        self.assertEqual("Pixel 6", identity["device_model"])
        self.assertEqual("oriole", identity["device_product"])
        self.assertEqual("16", identity["android_version"])
        self.assertEqual("user", identity["android_build_type"])
        self.assertEqual("Debug", identity["app_build_type"])
        self.assertEqual(
            "5f1a970825ae8bacb17d8dd656e01bd1fe7172638ba3ddcacd82ffaaad6e62c0",
            identity["target_library_sha256"],
        )
        ensure_same_format_two_device(identity, {
            "model": "Pixel 6", "device": "oriole", "android": "16",
            "abi": "arm64-v8a", "android_build_type": "user", "app_build_type": "Debug",
            "build_fingerprint": identity["build_fingerprint"],
            "selinux": "Enforcing", "package": "com.aprz.qbdiandroid",
        })
        for profile in ("fast", "balanced", "full"):
            row = benchmark_trace.parse_profile_baseline(text, profile)
            self.assertGreater(row["compressed_bytes"], 0)
            self.assertEqual(21718, row["instructions"])
            self.assertEqual("0x5745c858653f5a7f", row["return"])

    def test_checked_in_baseline_matches_live_identity_shape_for_debug_app(self):
        properties = {
            "ro.product.model": "Pixel 6", "ro.product.device": "oriole",
            "ro.build.version.release": "16", "ro.product.cpu.abi": "arm64-v8a",
            "ro.build.type": "user",
            "ro.build.fingerprint": (
                "google/oriole/oriole:16/CP1A.260405.005/15001963:user/release-keys"
            ),
        }

        def fake_adb(_args, *command, **kwargs):
            if "run-as" in command:
                output = "uid=123\n"
            elif "getenforce" in command:
                output = "Enforcing\n"
            else:
                output = properties[command[-1]] + "\n"
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

        document = Path("docs/benchmarks/binary-trace-baseline.md").read_text(encoding="utf-8")
        with patch.object(benchmark_trace, "adb", side_effect=fake_adb):
            live = benchmark_trace.live_device_identity(
                SimpleNamespace(package="com.aprz.qbdiandroid")
            )

        ensure_same_format_two_device(parse_baseline_document(document), live)
        self.assertEqual("user", live["android_build_type"])
        self.assertEqual("Debug", live["app_build_type"])

    def test_candidate_verification_accepts_new_build_when_staged_sha_matches(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory) / "candidate.so"
            candidate.write_bytes(b"new candidate build")
            local_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
            historical_sha = hashlib.sha256(b"historical candidate").hexdigest()
            self.assertNotEqual(historical_sha, local_sha)

            completed = subprocess.CompletedProcess(
                ["adb", "sha256sum"], 0,
                stdout=f"{local_sha}  files/libqbdi_tracer.so\n", stderr="",
            )
            with patch.object(benchmark_trace, "adb", return_value=completed):
                verified = verify_candidate_tracer(
                    SimpleNamespace(
                        candidate_tracer=str(candidate), package="com.aprz.qbdiandroid"
                    ),
                    {"candidate_tracer_sha256": historical_sha},
                )

        self.assertEqual(local_sha, verified)

    def test_candidate_verification_rejects_a_different_staged_sha(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory) / "candidate.so"
            candidate.write_bytes(b"local candidate build")
            local_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
            staged_sha = hashlib.sha256(b"different staged build").hexdigest()
            completed = subprocess.CompletedProcess(
                ["adb", "sha256sum"], 0,
                stdout=f"{staged_sha}  files/libqbdi_tracer.so\n", stderr="",
            )

            with patch.object(benchmark_trace, "adb", return_value=completed), \
                 self.assertRaisesRegex(ValueError, "app-private candidate"):
                verify_candidate_tracer(
                    SimpleNamespace(
                        candidate_tracer=str(candidate), package="com.aprz.qbdiandroid"
                    ),
                    {"candidate_tracer_sha256": local_sha},
                )

    def test_installed_apk_target_library_reports_raw_and_canonical_identity(self):
        target = b"\x7fELFhistorical benchmark target"
        target_sha = hashlib.sha256(target).hexdigest()
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as apk:
            apk.writestr("lib/arm64-v8a/libdemo_target.so", target)
        args = SimpleNamespace(
            adb="adb", device="serial", package="com.aprz.qbdiandroid",
            adb_timeout=3,
        )
        baseline = {"package": "com.aprz.qbdiandroid", "abi": "arm64-v8a",
                    "target_library_sha256": "5f1a970825ae8bacb17d8dd656e01bd1fe7172638ba3ddcacd82ffaaad6e62c0",
                    "target_library_canonical_sha256": "0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169"}
        package_path = subprocess.CompletedProcess(
            ["adb", "pm", "path"], 0,
            stdout="package:/data/app/example/base.apk\n", stderr="",
        )

        with patch.object(benchmark_trace, "adb", return_value=package_path), \
             patch.object(
                 benchmark_trace, "capture_bounded", return_value=archive.getvalue()
             ) as capture, \
             patch.object(benchmark_trace, "canonical_elf_sha256",
                          return_value="0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169"):
            verified = benchmark_trace.verify_installed_target_library(
                args, baseline
            )

        self.assertEqual(target_sha, verified.target_library_sha256)
        self.assertEqual(hashlib.sha256(archive.getvalue()).hexdigest(), verified.installed_apk_sha256)
        self.assertEqual("0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169",
                         verified.target_library_canonical_sha256)
        self.assertTrue(any(
            "/data/app/example/base.apk" in item
            for item in capture.call_args.args[0]
        ))

    def test_acceptance_rejects_warmup_oracle_drift_before_measured_runs(self):
        baseline_run = {
            **parse_metrics(self.METRICS_V3),
            "profile": "balanced", "instructions": 21718,
            "return": "0x5745c858653f5a7f",
            "trace": "warmup.trace.bin.lz4",
            "decoded_event_count": 21718,
            "first_instruction": "1 libdemo_target.so+0x6e828 STPXpre",
            "last_instruction": "21718 libdemo_target.so+0x6ea28 RET",
        }
        drifted_warmup = {
            **baseline_run,
            "first_instruction": "1 libdemo_target.so+0x70c6c STPXpre",
        }
        args = SimpleNamespace(
            runs=5, test_fail_setup=False,
            compare="docs/benchmarks/binary-trace-baseline.md",
            profile="balanced", legacy=False,
            candidate_tracer="candidate.so",
        )
        identity = {
            "model": "Pixel 6", "device": "oriole", "android": "16",
            "abi": "arm64-v8a", "android_build_type": "user",
            "app_build_type": "Debug",
            "build_fingerprint": (
                "google/oriole/oriole:16/CP1A.260405.005/15001963:user/release-keys"
            ), "selinux": "Enforcing", "package": "com.aprz.qbdiandroid",
        }
        with patch.object(benchmark_trace, "parse_args", return_value=args), \
             patch.object(benchmark_trace, "live_device_identity", return_value=identity), \
             patch.object(benchmark_trace, "verify_candidate_tracer", return_value="a" * 64), \
             patch.object(benchmark_trace, "verify_installed_target_library",
                          return_value=benchmark_trace.InstalledTargetIdentity(
                              "1" * 64, "2" * 64, "0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169")), \
             patch.object(benchmark_trace, "run_once",
                          return_value=drifted_warmup) as run:
            with self.assertRaisesRegex(ValueError, "oracle mismatch.*first_instruction"):
                benchmark_trace.main()

        self.assertEqual(1, run.call_count)

    def test_cli_returns_acceptance_miss_and_preserves_json_verdict(self):
        run = {**parse_metrics(self.METRICS_V3), "profile": "balanced",
               "instructions": 21718, "return": "0x5745c858653f5a7f",
               "compressed_bytes": 999_999_999, "trace": "run.trace.bin.lz4",
               "decoded_event_count": 21718,
               "first_instruction": "1 libdemo_target.so+0x6e828 STPXpre",
               "last_instruction": "21718 libdemo_target.so+0x6ea28 RET"}
        run["instructions_per_second"] = Decimal("21.718000")
        args = SimpleNamespace(
            runs=5, test_fail_setup=False,
            compare="docs/benchmarks/binary-trace-baseline.md", profile="balanced",
            legacy=False, candidate_tracer="candidate.so",
        )
        identity = {
            "model": "Pixel 6", "device": "oriole", "android": "16",
            "abi": "arm64-v8a", "android_build_type": "user", "app_build_type": "Debug",
            "build_fingerprint": (
                "google/oriole/oriole:16/CP1A.260405.005/15001963:user/release-keys"
            ), "selinux": "Enforcing", "package": "com.aprz.qbdiandroid",
        }
        output = io.StringIO()
        with patch.object(benchmark_trace, "parse_args", return_value=args), \
             patch.object(benchmark_trace, "live_device_identity", return_value=identity), \
             patch.object(benchmark_trace, "verify_candidate_tracer", return_value="a" * 64), \
             patch.object(benchmark_trace, "verify_installed_target_library",
                          return_value=benchmark_trace.InstalledTargetIdentity(
                              "1" * 64, "2" * 64, "0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169")), \
             patch.object(benchmark_trace, "run_once", side_effect=[run] * 6), \
             contextlib.redirect_stdout(output):
            status = benchmark_trace.main()

        self.assertEqual(2, status)
        report = benchmark_trace.json.loads(output.getvalue())
        baseline_identity = parse_baseline_document(
            Path(args.compare).read_text(encoding="utf-8")
        )
        self.assertNotEqual("a" * 64, baseline_identity["candidate_tracer_sha256"])
        self.assertEqual("a" * 64, report["candidate_tracer_sha256"])
        self.assertEqual(
            baseline_identity["candidate_tracer_sha256"],
            report["baseline_candidate_tracer_sha256"],
        )
        self.assertEqual(
            ["1" * 64, "2" * 64,
             "5f1a970825ae8bacb17d8dd656e01bd1fe7172638ba3ddcacd82ffaaad6e62c0",
             "0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169",
             "0d8e856c819fb3cd7ae5917053172b4b75a7924784c43e09cb2855a298647169"],
            [report[key] for key in ("installed_apk_sha256", "target_library_sha256",
                                     "baseline_target_library_sha256",
                                     "target_library_canonical_sha256",
                                     "baseline_target_library_canonical_sha256")],
        )
        self.assertFalse(report["comparison"]["meets_rate_target"])
        self.assertFalse(report["comparison"]["meets_size_target"])

    def test_binary_trace_baseline_parser_rejects_invalid_tables(self):
        table = """## Current format-2 artifact baselines

| Profile | Measured elapsed values (ms) | Median elapsed ms | Artifact | Compressed bytes | Decoded bytes | Instructions | Return | Decoded event count | First sequence | Last sequence | Footer | Artifact SHA-256 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| fast | 1, 2, 3, 4, 5 | 3 | fast.trace.txt.lz4 | 100 | 200 | 21718 | 0x5745c858653f5a7f | 21718 | 1 start | 21718 end | TRACE_END status=ok | abc |
"""

        with self.assertRaisesRegex(ValueError, "unknown profile"):
            benchmark_trace.parse_profile_baseline(table.replace("| fast |", "| unknown |"), "fast")
        with self.assertRaisesRegex(ValueError, "duplicate profile"):
            benchmark_trace.parse_profile_baseline(table + table.splitlines()[-1] + "\n", "fast")
        with self.assertRaisesRegex(ValueError, "missing columns"):
            benchmark_trace.parse_profile_baseline(
                table.replace("| Compressed bytes |", "| Size |"), "fast"
            )
        with self.assertRaisesRegex(ValueError, "invalid integer"):
            benchmark_trace.parse_profile_baseline(
                table.replace("| 3 | fast.trace", "| three | fast.trace"), "fast"
            )

    def test_binary_trace_baseline_parser_validates_five_elapsed_values(self):
        table = """## Current format-2 artifact baselines

| Profile | Measured elapsed values (ms) | Median elapsed ms | Artifact | Compressed bytes | Decoded bytes | Instructions | Return | Decoded event count | First sequence | Last sequence | Footer | Artifact SHA-256 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| fast | 1, 2, 3, 4, 5 | 3 | fast.trace.txt.lz4 | 100 | 200 | 21718 | 0x5745c858653f5a7f | 21718 | 1 start | 21718 end | TRACE_END status=ok | abc |
"""

        self.assertEqual(
            "1, 2, 3, 4, 5",
            benchmark_trace.parse_profile_baseline(table, "fast")["elapsed_values_ms"],
        )
        with self.assertRaisesRegex(ValueError, "invalid elapsed value"):
            benchmark_trace.parse_profile_baseline(table.replace("1, 2, 3, 4, 5", "1, 2, nope, 4, 5"), "fast")
        for values in ("1, 2, 3, 4", "1, 2, 3, 4, 5, 6"):
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, "five elapsed values"):
                benchmark_trace.parse_profile_baseline(table.replace("1, 2, 3, 4, 5", values), "fast")

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

    def test_selects_one_new_binary_pair_and_rejects_ambiguous_pairs(self):
        pair = [
            "300_benchmark.trace.bin.lz4.metrics",
            "300_benchmark.trace.bin.lz4",
        ]
        self.assertEqual(pair[0], select_newest_optimized_metrics(pair))
        with self.assertRaisesRegex(ValueError, "exactly one paired"):
            select_exact_new_optimized_metrics([
                *pair,
                "301_benchmark.trace.bin.metrics",
                "301_benchmark.trace.bin",
            ])

    def test_run_collection_rejects_orphan_new_artifacts(self):
        pair = [
            "300_benchmark.trace.bin.lz4.metrics",
            "300_benchmark.trace.bin.lz4",
        ]
        self.assertEqual(pair[0], select_exact_new_optimized_metrics(pair))
        for extra in (
            "301_benchmark.trace.bin",
            "301_benchmark.trace.bin.metrics",
            "300_benchmark.trace.bin.lz4.crash",
        ):
            with self.subTest(extra=extra), self.assertRaisesRegex(
                ValueError, "exactly one paired"
            ):
                select_exact_new_optimized_metrics([*pair, extra])

    def test_collects_raw_binary_atomically_and_validates_footer_sidecar_container(self):
        binary = complete_stream(compression=0).replace(
            stream_header(), stream_header(minor=2, features=1), 1
        )

        def fixed_six(numerator, denominator):
            whole, remainder = divmod(numerator, denominator)
            return f"{whole}.{remainder * 1_000_000 // denominator:06d}"

        sidecar = (
            "metrics_version=3\ntermination=completed\nreturn_valid=1\n"
            "profile=full\nreturn=0x55\ninstructions=0\n"
            f"elapsed_ms=17\ninstructions_per_second=0.000000\nencoded_bytes={len(binary)}\n"
            f"compressed_bytes={len(binary)}\n"
            f"encoded_bytes_per_second={fixed_six(len(binary) * 1000, 17)}\n"
            f"disk_bytes_per_second={fixed_six(len(binary) * 1000, 17)}\n"
            "compression_ratio=1.000000\ncache_hits=9\ncache_misses=1\n"
            "cache_collisions=0\ncache_hit_rate=0.900000\nbuffer_swaps=2\n"
            "producer_waits=0\nproducer_wait_ns=0\neffective_buffer_bytes=4096\n"
        ).encode("ascii")
        metrics = parse_metrics(sidecar)
        ensure_metrics_container(metrics, "run_benchmark.trace.bin")
        require_binary_acceptance_candidate({
            **metrics, "trace": "run_benchmark.trace.bin.lz4",
        })

        def fake_adb(_args, *command, **kwargs):
            kwargs["stdout"].write(binary)
            return subprocess.CompletedProcess(command, 0, stdout=None, stderr=b"")

        with tempfile.TemporaryDirectory() as directory, patch.object(
            benchmark_trace, "adb", side_effect=fake_adb
        ):
            args = SimpleNamespace(
                artifact_output=directory, package="com.example.app", lz4="lz4"
            )
            result = collect_and_validate_optimized_artifact(
                args, "run_benchmark.trace.bin", sidecar, metrics
            )

            converted = Path(directory) / "run_benchmark.trace.txt"
            self.assertEqual(converted.stat().st_size, result["converted_text_bytes"])
            self.assertEqual(64, len(result["artifact_sha256"]))
            self.assertIn(
                "TRACE_END status=completed",
                converted.read_text(encoding="utf-8"),
            )
            self.assertEqual([], list(Path(directory).glob(".benchmark-*")))

    def test_collects_legacy_v2_binary_for_baseline_validation(self):
        binary = complete_stream(compression=0)

        def fixed_six(numerator, denominator):
            whole, remainder = divmod(numerator, denominator)
            return f"{whole}.{remainder * 1_000_000 // denominator:06d}"

        sidecar = (
            "metrics_version=2\nprofile=full\nreturn=0x55\ninstructions=0\n"
            "elapsed_ms=17\ninstructions_per_second=0.000000\n"
            f"encoded_bytes={len(binary)}\ncompressed_bytes={len(binary)}\n"
            f"encoded_bytes_per_second={fixed_six(len(binary) * 1000, 17)}\n"
            f"disk_bytes_per_second={fixed_six(len(binary) * 1000, 17)}\n"
            "compression_ratio=1.000000\ncache_hits=9\ncache_misses=1\n"
            "cache_collisions=0\ncache_hit_rate=0.900000\nbuffer_swaps=2\n"
            "producer_waits=0\nproducer_wait_ns=0\neffective_buffer_bytes=4096\n"
        ).encode("ascii")
        metrics = parse_metrics(sidecar)

        def fake_adb(_args, *command, **kwargs):
            kwargs["stdout"].write(binary)
            return subprocess.CompletedProcess(command, 0, stdout=None, stderr=b"")

        with tempfile.TemporaryDirectory() as directory, patch.object(
            benchmark_trace, "adb", side_effect=fake_adb
        ):
            args = SimpleNamespace(
                artifact_output=directory, package="com.example.app", lz4="lz4"
            )
            result = collect_and_validate_optimized_artifact(
                args, "legacy_benchmark.trace.bin", sidecar, metrics
            )

            self.assertEqual(2, result["metrics_version"])
            self.assertTrue((Path(directory) / "legacy_benchmark.trace.txt").is_file())

    def test_benchmark_artifact_pull_error_removes_partial_temporary(self):
        def failing_adb(_args, *command, **kwargs):
            kwargs["stdout"].write(b"partial")
            raise subprocess.TimeoutExpired(command, 0.1)

        with tempfile.TemporaryDirectory() as directory, patch.object(
            benchmark_trace, "adb", side_effect=failing_adb
        ):
            root = Path(directory)
            args = SimpleNamespace(artifact_output=directory, package="com.example.app")
            with self.assertRaises(subprocess.TimeoutExpired):
                benchmark_trace._publish_remote_file(args, "run.trace.bin", root / "run.trace.bin")
            self.assertEqual([], list(root.iterdir()))

    def test_builds_the_structured_benchmark_agent_request(self):
        self.assertTrue(
            hasattr(benchmark_trace, "benchmark_agent_request"),
            "benchmark_agent_request must build the structured request",
        )
        request = benchmark_trace.benchmark_agent_request("balanced", False, 4096, True)

        self.assertEqual(1, request["schemaVersion"])
        self.assertEqual("balanced", request["trace"]["profile"])
        self.assertTrue(request["trace"]["compression"])
        self.assertEqual("benchmark", request["scenes"][0]["name"])
        self.assertEqual("0x0", request["scenes"][0]["location"]["offset"])
        self.assertEqual(4096, request["debug"]["bufferBytes"])
        self.assertTrue(request["debug"]["failSetup"])

    def test_preserves_compression_and_optional_test_injection_behavior(self):
        helper = benchmark_trace.benchmark_agent_request
        normal = helper("fast", False, None, False)
        legacy = helper("full", True, None, False)
        buffer_only = helper("balanced", False, 4096, False)
        failure_only = helper("balanced", False, None, True)

        self.assertTrue(normal["trace"]["compression"])
        self.assertNotIn("debug", normal)
        self.assertFalse(legacy["trace"]["compression"])
        self.assertEqual({"bufferBytes": 4096}, buffer_only["debug"])
        self.assertEqual({"failSetup": True}, failure_only["debug"])

    def test_injects_compact_json_into_one_unquoted_agent_placeholder(self):
        source = "const request = __QTRACE_CONFIG_JSON__;"

        configured = configure_agent_source(source, "balanced", False, 4096, True)
        encoded = configured.removeprefix("const request = ").removesuffix(";")
        request = json.loads(encoded)

        self.assertEqual(
            benchmark_trace.benchmark_agent_request("balanced", False, 4096, True), request
        )
        self.assertNotIn("__QTRACE_CONFIG_JSON__", configured)
        self.assertNotIn("scene=", configured)
        self.assertNotIn("__QTRACE_TEST_CONFIG__", configured)

    def test_rejects_invalid_benchmark_agent_request_options(self):
        with self.assertRaisesRegex(ValueError, "profile"):
            benchmark_trace.benchmark_agent_request("invalid", False, None, False)
        with self.assertRaisesRegex(ValueError, "test buffer"):
            benchmark_trace.benchmark_agent_request("balanced", False, 8192, False)

    def test_requires_exactly_one_json_placeholder(self):
        missing = "const request = {};"
        duplicate = "__QTRACE_CONFIG_JSON__ __QTRACE_CONFIG_JSON__"

        for source in (missing, duplicate):
            with self.subTest(source=source), self.assertRaisesRegex(
                ValueError, "__QTRACE_CONFIG_JSON__ exactly once"
            ):
                configure_agent_source(source, "balanced")

    def test_benchmark_agent_uses_json_response_before_installing_or_calling(self):
        source = Path(__file__).parents[1].joinpath("benchmark_trace.js").read_text(
            encoding="utf-8"
        )
        configured = configure_agent_source(source, "balanced", False, 4096, True)

        self.assertNotIn("scene=", configured)
        self.assertNotIn("__QTRACE_TEST_CONFIG__", configured)
        self.assertNotIn("'qbdi_tracer_configure'", configured)
        self.assertIn("'qbdi_tracer_configure_json'", configured)
        self.assertIn("const RESPONSE_CAPACITY = 64 * 1024;", configured)
        self.assertIn("response.responseSchemaVersion !== 1", configured)
        self.assertIn("function validateConfigureResponse(response)", configured)
        offset_assignment = configured.index(
            "request.scenes[0].location.offset = '0x' + offset.toString(16);"
        )
        encoding = configured.index("const encoded = JSON.stringify(request);")
        response_validation = configured.index("const response = validateConfigureResponse(")
        response_check = configured.index("response.ok !== true")
        install = configured.index("install(Memory.allocUtf8String(targetModule.path)")
        call = configured.index("const returned = call(")
        self.assertLess(offset_assignment, encoding)
        self.assertLess(encoding, response_validation)
        self.assertLess(response_validation, response_check)
        self.assertLess(response_check, install)
        self.assertLess(response_check, call)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for GumJS emulation")
    def test_benchmark_agent_uses_staged_pair_and_rejects_malformed_responses_before_execution(self):
        source = Path(__file__).parents[1].joinpath("benchmark_trace.js").read_text(
            encoding="utf-8"
        )
        configured = configure_agent_source(source, "balanced")
        accepted = {
            "responseSchemaVersion": 1,
            "ok": True,
            "generation": 7,
            "state": "waiting_for_module",
            "targetModule": "libdemo_target.so",
            "scenes": [{"name": "benchmark", "offset": "0x40", "endOffset": None}],
            "warnings": [],
        }
        malformed = [
            {"responseSchemaVersion": 1, "ok": True},
            {**accepted, "generation": "7"},
            {**accepted, "state": "installed"},
            {**accepted, "targetModule": 7},
            {**accepted, "scenes": {}},
            {**accepted, "warnings": {}},
            {
                **accepted,
                "scenes": [{"name": "benchmark", "offset": 64, "endOffset": None}],
            },
            {**accepted, "targetModule": "libwrong-target.so"},
            {**accepted, "scenes": []},
            {
                **accepted,
                "scenes": [
                    {"name": "benchmark", "offset": "0x40", "endOffset": None},
                    {"name": "extra", "offset": "0x80", "endOffset": None},
                ],
            },
            {
                **accepted,
                "scenes": [{"name": "other", "offset": "0x40", "endOffset": None}],
            },
            {
                **accepted,
                "scenes": [{"name": "benchmark", "offset": "0x41", "endOffset": None}],
            },
            {
                **accepted,
                "scenes": [
                    {"name": "benchmark", "offset": "0x40", "endOffset": "0x80"}
                ],
            },
        ]
        harness = r"""
const vm = require('vm');
const source = JSON.parse(process.argv[1]);
const responses = JSON.parse(process.argv[2]);

class U64 {
  constructor(value) {
    this.value = BigInt(value instanceof U64 ? value.value : value);
  }
  toString(radix) { return this.value.toString(radix); }
  toNumber() { return Number(this.value); }
}

function runCase(configureResponse) {
  const state = {installs: 0, calls: 0, messages: [], tracerPaths: [], helperPaths: []};
  const benchmark = {sub: () => new U64(0x40)};
  const target = {
    base: new U64(0x1000),
    size: 0x1000,
    path: '/data/app/libdemo_target.so',
    getExportByName: name => name === 'demo_benchmark_case' ? benchmark : null
  };
  const tracer = {getExportByName: symbol => symbol};

  function NativeFunction(address) {
    if (address === 'qbdi_tracer_set_shadowhook_helper_path') {
      return path => { state.helperPaths.push(path); return 0; };
    }
    if (address === 'qbdi_tracer_install_module') {
      return () => { state.installs += 1; };
    }
    if (address === 'qbdi_tracer_configure_json') {
      return (_request, _requestSize, response, _capacity, responseSize) => {
        response.text = JSON.stringify(configureResponse);
        responseSize.writeU64(new U64(Buffer.byteLength(response.text, 'utf8') + 1));
        return 0;
      };
    }
    if (address === benchmark) {
      return () => { state.calls += 1; return new U64(0x55); };
    }
    throw new Error('unexpected native function: ' + address);
  }

  const sandbox = {
    UInt64: U64,
    NativeFunction,
    ptr: value => value,
    setImmediate: callback => callback(),
    setTimeout: () => { throw new Error('unexpected target wait'); },
    send: message => state.messages.push(message),
    Process: {
      findModuleByName: name => name === 'libdemo_target.so' ? target : tracer
    },
    Module: {getGlobalExportByName: symbol => symbol},
    Memory: {
      allocUtf8String: value => value,
      alloc: size => Number(size) === 8 ? {
        value: 0,
        writeU64(value) { this.value = value.toNumber(); },
        readU64() { return new U64(this.value); }
      } : {
        text: '',
        add(index) {
          const owner = this;
          return {
            readU8: () => index === Buffer.byteLength(owner.text, 'utf8') ? 0 : 1
          };
        },
        readUtf8String() { return this.text; }
      }
    },
    Java: {
      available: true,
      performNow: callback => callback(),
      use: name => name === 'android.app.ActivityThread' ? {
        currentApplication: () => ({
          getApplicationInfo: () => ({nativeLibraryDir: {value: '/data/app/lib'}}),
          getFilesDir: () => ({
            getAbsolutePath: () => '/data/user/0/com.example.app/files',
            getCanonicalPath: () => '/data/data/com.example.app/files'
          }),
          getClass: () => ({})
        })
      } : {
        getRuntime: () => ({load0: {overload: () => ({
          call: (_runtime, _applicationClass, path) => state.tracerPaths.push(path)
        })}})
      }
    }
  };
  vm.runInNewContext(source, sandbox, {filename: 'benchmark_trace.js'});
  return state;
}

process.stdout.write(JSON.stringify(responses.map(runCase)));
"""
        completed = subprocess.run(
            [
                shutil.which("node"),
                "-e",
                harness,
                json.dumps(configured),
                json.dumps([*malformed, accepted]),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        results = json.loads(completed.stdout)
        self.assertEqual(len(malformed) + 1, len(results))
        for index, result in enumerate(results[:-1]):
            with self.subTest(case=index):
                self.assertEqual(0, result["installs"])
                self.assertEqual(0, result["calls"])
                self.assertEqual(1, len(result["messages"]))
                self.assertEqual("benchmark-error", result["messages"][0]["type"])
        accepted_result = results[-1]
        self.assertEqual(1, accepted_result["installs"])
        self.assertEqual(1, accepted_result["calls"])
        self.assertEqual("benchmark-result", accepted_result["messages"][0]["type"])
        self.assertEqual(
            ["/data/data/com.example.app/files/libqbdi_tracer.so"],
            accepted_result["tracerPaths"],
        )
        self.assertEqual(
            ["/data/data/com.example.app/files/libshadowhook_nothing.so"],
            accepted_result["helperPaths"],
        )

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

    def test_return_oracle_rejects_stopped_v3_benchmark_terminal(self):
        stopped = parse_metrics(self.METRICS_V3.replace(
            "termination=completed\nreturn_valid=1\nprofile=balanced\nreturn=0x42",
            "termination=stopped\nreturn_valid=0\nprofile=balanced\nreturn=0x0",
        ))

        with self.assertRaisesRegex(RuntimeError, "completed terminal"):
            ensure_artifact_return("0x0", stopped, "run.trace.bin.lz4.metrics")

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

    def test_diagnoses_below_target_fast_metrics_v3_with_encoded_rate(self):
        metrics = parse_metrics(self.METRICS_V3.replace(
            "profile=balanced\ninstructions=100000\ninstructions_per_second=2000000.000000",
            "profile=fast\ninstructions=25000\ninstructions_per_second=500000.000000",
        ))

        diagnosis = fast_cost_diagnosis(metrics)

        self.assertEqual("undetermined", diagnosis["dominant_cost"])
        self.assertEqual(Decimal("209715200.000000"), diagnosis["encoded_bytes_per_second"])

    def invoke_with_fake_frida_worker(self, worker):
        with tempfile.TemporaryDirectory() as directory:
            agent = Path(directory) / "agent.js"
            agent.write_text("agent", encoding="utf-8")
            args = SimpleNamespace(
                package="com.example.app", frida_port=27042,
                frida_device=None, agent=str(agent), profile="fast",
                legacy=False, test_buffer_bytes=None, test_fail_setup=False,
                timeout=0.05, frida_cleanup_timeout=0.05,
            )
            with patch.object(benchmark_trace, "_invoke_benchmark_worker", worker), \
                 patch.object(benchmark_trace, "adb"), \
                 patch.object(benchmark_trace, "java_bridge_source", return_value=""), \
                 patch.object(benchmark_trace, "configure_agent_source", return_value=""), \
                 patch.object(benchmark_trace, "inject_java_bridge", return_value=""):
                return benchmark_trace.invoke_benchmark(args)

    @unittest.skipUnless(hasattr(os, "fork"), "Frida isolation requires POSIX fork")
    def test_result_requires_complete_and_a_zero_worker_exit(self):
        def worker(_args, _source, channel):
            channel.send(("pid", 4242))
            channel.send(("result", "0xbeef"))
            os._exit(7)

        with self.assertRaisesRegex(
            RuntimeError, "failed to release benchmark process:.*without complete"
        ):
            self.invoke_with_fake_frida_worker(worker)

    @unittest.skipUnless(hasattr(os, "fork"), "Frida isolation requires POSIX fork")
    def test_result_followed_by_a_worker_signal_is_a_cleanup_failure(self):
        def worker(_args, _source, channel):
            channel.send(("pid", 4242))
            channel.send(("result", "0xbeef"))
            os.kill(os.getpid(), signal.SIGTERM)

        with self.assertRaisesRegex(
            RuntimeError, "failed to release benchmark process:.*signal"
        ):
            self.invoke_with_fake_frida_worker(worker)

    @unittest.skipUnless(hasattr(os, "fork"), "Frida isolation requires POSIX fork")
    def test_complete_does_not_reconcile_a_nonzero_worker_exit(self):
        def worker(_args, _source, channel):
            channel.send(("pid", 4242))
            channel.send(("result", "0xbeef"))
            channel.send(("complete", None))
            channel.close()
            os._exit(7)

        with self.assertRaisesRegex(
            RuntimeError, "failed to release benchmark process:.*status 7"
        ):
            self.invoke_with_fake_frida_worker(worker)

    @unittest.skipUnless(hasattr(os, "fork"), "Frida isolation requires POSIX fork")
    def test_primary_benchmark_error_wins_when_the_worker_then_crashes(self):
        def worker(_args, _source, channel):
            channel.send(("pid", 4242))
            channel.send(("error", "agent failed first"))
            os._exit(7)

        with self.assertRaisesRegex(RuntimeError, "^agent failed first$"):
            self.invoke_with_fake_frida_worker(worker)

    @unittest.skipUnless(hasattr(os, "fork"), "Frida isolation requires POSIX fork")
    def test_eof_before_any_outcome_is_a_cleanup_failure(self):
        def worker(_args, _source, channel):
            channel.close()

        with self.assertRaisesRegex(
            RuntimeError, "failed to release benchmark process:.*before an outcome"
        ):
            self.invoke_with_fake_frida_worker(worker)

    @unittest.skipUnless(hasattr(os, "fork"), "Frida isolation requires POSIX fork")
    def test_duplicate_pid_message_fails_closed(self):
        def worker(_args, _source, channel):
            channel.send(("pid", 4242))
            channel.send(("pid", 4242))
            channel.send(("result", "0xbeef"))
            channel.send(("complete", None))
            channel.close()

        with self.assertRaisesRegex(RuntimeError, "duplicate pid"):
            self.invoke_with_fake_frida_worker(worker)

    @unittest.skipUnless(hasattr(os, "fork"), "Frida isolation requires POSIX fork")
    def test_result_before_pid_message_fails_closed(self):
        def worker(_args, _source, channel):
            channel.send(("result", "0xbeef"))
            channel.send(("pid", 4242))
            channel.send(("complete", None))
            channel.close()

        with self.assertRaisesRegex(RuntimeError, "result before pid"):
            self.invoke_with_fake_frida_worker(worker)

    @unittest.skipUnless(hasattr(os, "fork"), "Frida isolation requires POSIX fork")
    def test_malformed_pid_message_fails_closed(self):
        for malformed in (0, -1, True, "4242"):
            with self.subTest(pid=malformed):
                def worker(_args, _source, channel):
                    channel.send(("pid", malformed))
                    channel.send(("result", "0xbeef"))
                    channel.send(("complete", None))
                    channel.close()

                with self.assertRaisesRegex(RuntimeError, "malformed pid"):
                    self.invoke_with_fake_frida_worker(worker)

    @unittest.skipUnless(hasattr(os, "fork"), "Frida isolation requires POSIX fork")
    def test_messages_after_complete_fail_closed(self):
        trailing_events = (
            ("result", "0xfeed"),
            ("pid", 4242),
            ("complete", None),
            ("unknown", None),
            "malformed",
        )
        for trailing_event in trailing_events:
            with self.subTest(event=trailing_event):
                def worker(_args, _source, channel):
                    channel.send(("pid", 4242))
                    channel.send(("result", "0xbeef"))
                    channel.send(("complete", None))
                    channel.send(trailing_event)
                    channel.close()

                with self.assertRaisesRegex(
                    RuntimeError,
                    "event after complete|malformed Frida worker IPC event",
                ):
                    self.invoke_with_fake_frida_worker(worker)

    def test_invoke_benchmark_releases_every_owned_frida_resource_on_failures(self):
        context = multiprocessing.get_context("fork")
        active_children = {child.pid for child in multiprocessing.active_children()}
        call_names = (
            "spawn", "attach", "create", "on", "load", "resume",
            "unload", "detach", "kill",
        )

        class SharedCalls:
            def __init__(self):
                self.values = context.RawArray("i", len(call_names))

            def __getitem__(self, name):
                return self.values[call_names.index(name)]

            def __setitem__(self, name, value):
                self.values[call_names.index(name)] = value

            def snapshot(self):
                return {name: self[name] for name in call_names}

        class FakeScript:
            def __init__(self, stage, calls):
                self.stage = stage
                self.calls = calls
                self.callback = None

            def on(self, _event, callback):
                self.calls["on"] += 1
                self.callback = callback
                if self.stage == "on":
                    raise RuntimeError("on failed")

            def load(self):
                self.calls["load"] += 1
                if self.stage == "load":
                    raise RuntimeError("load failed")
                if self.stage == "agent":
                    self.callback({
                        "type": "send",
                        "payload": {"type": "benchmark-error", "error": "agent failed"},
                    }, None)
                if self.stage == "result":
                    self.callback({
                        "type": "send",
                        "payload": {"type": "benchmark-result", "return": "0xBEEF"},
                    }, None)

            def unload(self):
                self.calls["unload"] += 1

        class FakeSession:
            def __init__(self, stage, calls):
                self.stage = stage
                self.calls = calls

            def create_script(self, _source):
                self.calls["create"] += 1
                if self.stage == "create":
                    raise RuntimeError("create failed")
                return FakeScript(self.stage, self.calls)

            def detach(self):
                self.calls["detach"] += 1

        class FakeDevice:
            def __init__(self, stage, calls):
                self.stage = stage
                self.calls = calls
                self.script = None

            def spawn(self, _argv):
                self.calls["spawn"] += 1
                return 41

            def attach(self, _pid):
                self.calls["attach"] += 1
                if self.stage == "attach":
                    raise RuntimeError("attach failed")
                return FakeSession(self.stage, self.calls)

            def resume(self, _pid):
                self.calls["resume"] += 1
                if self.stage == "resume":
                    raise RuntimeError("resume failed")

            def kill(self, _pid):
                self.calls["kill"] += 1

        class FakeManager:
            def __init__(self, device):
                self.device = device

            def add_remote_device(self, _endpoint):
                return self.device

        class FakeFrida:
            def __init__(self, device):
                self.manager = FakeManager(device)

            def get_device_manager(self):
                return self.manager

        with tempfile.TemporaryDirectory() as directory:
            agent = Path(directory) / "agent.js"
            agent.write_text("agent", encoding="utf-8")
            for stage, expected in {
                "attach": {"unload": 0, "detach": 0, "kill": 0},
                "create": {"unload": 0, "detach": 1, "kill": 0},
                "on": {"unload": 1, "detach": 1, "kill": 0},
                "load": {"unload": 1, "detach": 1, "kill": 0},
                "resume": {"unload": 1, "detach": 1, "kill": 0},
                "agent": {"unload": 1, "detach": 1, "kill": 0},
                "timeout": {"unload": 1, "detach": 1, "kill": 0},
            }.items():
                with self.subTest(stage=stage):
                    calls = SharedCalls()
                    device = FakeDevice(stage, calls)
                    args = SimpleNamespace(
                        package="com.example.app", frida_port=27042, frida_device=None,
                        agent=str(agent), profile="fast", legacy=False,
                        test_buffer_bytes=None, test_fail_setup=False,
                        timeout=0.1 if stage == "agent" else 0,
                    )
                    with patch.dict(sys.modules, {"frida": FakeFrida(device)}), \
                         patch.object(benchmark_trace, "adb") as adb_call, \
                         patch.object(benchmark_trace, "java_bridge_source", return_value=""), \
                         patch.object(benchmark_trace, "configure_agent_source", return_value=""), \
                         patch.object(benchmark_trace, "inject_java_bridge", return_value=""):
                        with self.assertRaises(RuntimeError):
                            benchmark_trace.invoke_benchmark(args)
                    for name, count in expected.items():
                        self.assertEqual(
                            count, calls[name], (stage, name, calls.snapshot())
                        )
                    force_stops = [
                        call for call in adb_call.call_args_list
                        if call.args[1:] == (
                            "shell", "am", "force-stop", "com.example.app"
                        )
                    ]
                    self.assertEqual(2, len(force_stops), stage)

            calls = SharedCalls()
            device = FakeDevice("result", calls)
            args = SimpleNamespace(
                package="com.example.app", frida_port=27042, frida_device=None,
                agent=str(agent), profile="fast", legacy=False,
                test_buffer_bytes=None, test_fail_setup=False, timeout=0.1,
            )
            with patch.dict(sys.modules, {"frida": FakeFrida(device)}), \
                 patch.object(benchmark_trace, "adb") as adb_call, \
                 patch.object(benchmark_trace, "java_bridge_source", return_value=""), \
                 patch.object(benchmark_trace, "configure_agent_source", return_value=""), \
                 patch.object(benchmark_trace, "inject_java_bridge", return_value=""):
                self.assertEqual("0xbeef", benchmark_trace.invoke_benchmark(args))
            self.assertEqual(1, calls["unload"])
            self.assertEqual(1, calls["detach"])
            self.assertEqual(0, calls["kill"])
            force_stops = [
                call for call in adb_call.call_args_list
                if call.args[1:] == (
                    "shell", "am", "force-stop", "com.example.app"
                )
            ]
            self.assertEqual(2, len(force_stops))
        self.assertEqual(
            active_children,
            {child.pid for child in multiprocessing.active_children()},
        )
        self.assertFalse(any(
            thread.name == "qtrace-frida-cleanup"
            for thread in threading.enumerate()
        ))

    def test_invoke_benchmark_bounds_blocked_cleanup_and_preserves_timeout(self):
        context = multiprocessing.get_context("fork")
        release_read, release_write = os.pipe()
        unload_calls = context.RawValue("i", 0)
        detach_calls = context.RawValue("i", 0)
        kill_calls = context.RawValue("i", 0)

        class BlockingScript:
            def on(self, _event, _callback):
                pass

            def load(self):
                pass

            def unload(self):
                unload_calls.value += 1
                os.read(release_read, 1)

        class BlockingSession:
            def create_script(self, _source):
                return BlockingScript()

            def detach(self):
                detach_calls.value += 1
                os.read(release_read, 1)

        class BlockingDevice:
            def spawn(self, _argv):
                return 4242

            def attach(self, _pid):
                return BlockingSession()

            def resume(self, _pid):
                pass

            def kill(self, _pid):
                kill_calls.value += 1
                os.read(release_read, 1)

        device = BlockingDevice()
        frida = SimpleNamespace(get_device_manager=lambda: SimpleNamespace(
            add_remote_device=lambda _endpoint: device
        ))
        caught: list[BaseException] = []
        active_children = {child.pid for child in multiprocessing.active_children()}

        with tempfile.TemporaryDirectory() as directory:
            agent = Path(directory) / "agent.js"
            agent.write_text("agent", encoding="utf-8")
            args = SimpleNamespace(
                package="com.example.app", frida_port=27042, frida_device=None,
                agent=str(agent), profile="fast", legacy=False,
                test_buffer_bytes=None, test_fail_setup=False, timeout=0,
                frida_cleanup_timeout=0.01,
            )

            def run() -> None:
                try:
                    benchmark_trace.invoke_benchmark(args)
                except BaseException as error:
                    caught.append(error)

            with patch.dict(sys.modules, {"frida": frida}), \
                 patch.object(benchmark_trace, "adb") as adb_call, \
                 patch.object(benchmark_trace, "java_bridge_source", return_value=""), \
                 patch.object(benchmark_trace, "configure_agent_source", return_value=""), \
                 patch.object(benchmark_trace, "inject_java_bridge", return_value=""):
                started = time.monotonic()
                run()
                run()
                elapsed = time.monotonic() - started

        os.close(release_read)
        os.close(release_write)

        self.assertLess(elapsed, 0.3, "Frida cleanup exceeded its hard bound")
        self.assertEqual(2, unload_calls.value)
        self.assertEqual(0, detach_calls.value)
        self.assertEqual(0, kill_calls.value)
        self.assertEqual(2, len(caught))
        for error in caught:
            self.assertRegex(str(error), "benchmark agent timed out after 0 seconds")
        force_stops = [
            call for call in adb_call.call_args_list
            if call.args[1:] == (
                "shell", "am", "force-stop", "com.example.app"
            )
        ]
        self.assertEqual(4, len(force_stops))
        self.assertEqual(
            active_children,
            {child.pid for child in multiprocessing.active_children()},
        )

    @unittest.skipUnless(hasattr(os, "fork"), "Frida isolation requires POSIX fork")
    def test_force_stop_waits_until_the_detach_owner_is_reaped(self):
        context = multiprocessing.get_context("fork")
        unload_completed = context.Event()
        detach_entered = context.Event()
        release_read, release_write = os.pipe()
        owner_pid = context.RawValue("i", 0)
        force_stop_calls = 0
        force_stop_overlapped = False

        class BoundaryScript:
            def __init__(self):
                self.callback = None

            def on(self, _event, _callback):
                self.callback = _callback

            def load(self):
                self.callback({
                    "type": "send",
                    "payload": {"type": "benchmark-result", "return": "0xBEEF"},
                }, None)

            def unload(self):
                unload_completed.set()

        class BoundarySession:
            def create_script(self, _source):
                return BoundaryScript()

            def detach(self):
                owner_pid.value = os.getpid()
                detach_entered.set()
                os.read(release_read, 1)

        class BoundaryDevice:
            def spawn(self, _argv):
                return 4343

            def attach(self, _pid):
                return BoundarySession()

            def resume(self, _pid):
                pass

        frida = SimpleNamespace(get_device_manager=lambda: SimpleNamespace(
            add_remote_device=lambda _endpoint: BoundaryDevice()
        ))

        def fake_adb(_args, *command, **_kwargs):
            nonlocal force_stop_calls, force_stop_overlapped
            if command != (
                "shell", "am", "force-stop", "com.example.app"
            ):
                return None
            force_stop_calls += 1
            if force_stop_calls != 2:
                return None
            try:
                os.kill(owner_pid.value, 0)
            except ProcessLookupError:
                pass
            else:
                force_stop_overlapped = True
            os.write(release_write, b"x")
            return None

        with tempfile.TemporaryDirectory() as directory:
            agent = Path(directory) / "agent.js"
            agent.write_text("agent", encoding="utf-8")
            args = SimpleNamespace(
                package="com.example.app", frida_port=27042,
                frida_device=None, agent=str(agent), profile="fast",
                legacy=False, test_buffer_bytes=None, test_fail_setup=False,
                timeout=0.1, frida_cleanup_timeout=0.02,
            )
            active_children = {child.pid for child in multiprocessing.active_children()}
            with patch.dict(sys.modules, {"frida": frida}), \
                 patch.object(benchmark_trace, "adb", side_effect=fake_adb), \
                 patch.object(benchmark_trace, "java_bridge_source", return_value=""), \
                 patch.object(benchmark_trace, "configure_agent_source", return_value=""), \
                 patch.object(benchmark_trace, "inject_java_bridge", return_value=""):
                with self.assertRaisesRegex(
                    RuntimeError, "failed to release benchmark process:.*timed out"
                ):
                    benchmark_trace.invoke_benchmark(args)

        os.close(release_read)
        os.close(release_write)

        self.assertTrue(unload_completed.is_set())
        self.assertTrue(detach_entered.is_set())
        self.assertNotEqual(os.getpid(), owner_pid.value)
        self.assertFalse(
            force_stop_overlapped,
            "force-stop raced a Frida detach that could still execute",
        )
        self.assertEqual(2, force_stop_calls)
        self.assertEqual(
            active_children,
            {child.pid for child in multiprocessing.active_children()},
        )

    def test_benchmark_refuses_non_posix_cleanup_before_touching_the_device(self):
        args = SimpleNamespace(package="com.example.app")
        with patch.object(
            benchmark_trace.multiprocessing,
            "get_all_start_methods",
            return_value=["spawn"],
        ), patch.object(benchmark_trace, "adb") as adb_call:
            with self.assertRaisesRegex(RuntimeError, "requires POSIX fork"):
                benchmark_trace.invoke_benchmark(args)
        adb_call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
