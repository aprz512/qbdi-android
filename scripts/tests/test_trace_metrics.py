import unittest

from scripts.trace_metrics import UINT64_MAX, canonical_fixed_six, parse_metrics


def v2_metrics(cache_hits: int, cache_misses: int, cache_rate: str) -> str:
    return (
        "metrics_version=2\nprofile=fast\nreturn=0x0\n"
        "instructions=1\nelapsed_ms=3\ninstructions_per_second=333.333333\n"
        "encoded_bytes=2\ncompressed_bytes=1\n"
        "encoded_bytes_per_second=666.666666\n"
        "disk_bytes_per_second=333.333333\ncompression_ratio=0.500000\n"
        f"cache_hits={cache_hits}\ncache_misses={cache_misses}\n"
        f"cache_collisions=0\ncache_hit_rate={cache_rate}\n"
        "buffer_swaps=0\nproducer_waits=0\nproducer_wait_ns=0\n"
        "effective_buffer_bytes=4096\n"
    )


def v3_metrics(*, termination: str = "completed", return_valid: int = 1,
               return_value: str = "0x55") -> str:
    return (
        "metrics_version=3\n"
        f"termination={termination}\nreturn_valid={return_valid}\n"
        f"profile=fast\nreturn={return_value}\n"
        "instructions=1\nelapsed_ms=3\ninstructions_per_second=333.333333\n"
        "encoded_bytes=2\ncompressed_bytes=1\n"
        "encoded_bytes_per_second=666.666666\n"
        "disk_bytes_per_second=333.333333\ncompression_ratio=0.500000\n"
        "cache_hits=1\ncache_misses=2\ncache_collisions=0\n"
        "cache_hit_rate=0.333333\nbuffer_swaps=0\nproducer_waits=0\n"
        "producer_wait_ns=0\neffective_buffer_bytes=4096\n"
    )


class TraceMetricsTests(unittest.TestCase):
    def test_canonical_fixed_six_matches_producer_truncation_over_domain_edges(self):
        cases = (
            (0, 0, "0.000000"),
            (1, 0, "0.000000"),
            (0, UINT64_MAX, "0.000000"),
            (1, 3, "0.333333"),
            (2, 3, "0.666666"),
            (UINT64_MAX - 1, UINT64_MAX, "0.999999"),
            (UINT64_MAX, 1, f"{UINT64_MAX}.000000"),
            (UINT64_MAX * 1000, UINT64_MAX, "1000.000000"),
        )
        for numerator, denominator, expected in cases:
            with self.subTest(numerator=numerator, denominator=denominator):
                self.assertEqual(expected, canonical_fixed_six(numerator, denominator))

    def test_rejects_adjacent_fixed_six_instead_of_using_epsilon(self):
        parsed = parse_metrics(v2_metrics(1, 2, "0.333333"), "x.trace.bin")
        self.assertEqual(1, parsed["cache_hits"])
        with self.assertRaisesRegex(ValueError, "cache_hit_rate is inconsistent"):
            parse_metrics(v2_metrics(1, 2, "0.333334"), "x.trace.bin")

    def test_parses_completed_and_stopped_metrics_v3_with_terminal_contract(self):
        completed = parse_metrics(v3_metrics(), "completed.trace.bin")
        stopped = parse_metrics(v3_metrics(
            termination="stopped", return_valid=0, return_value="0x0"
        ).encode("ascii"), "stopped.trace.bin")

        self.assertEqual(3, completed["metrics_version"])
        self.assertEqual("completed", completed["termination"])
        self.assertEqual(1, completed["return_valid"])
        self.assertEqual("0x55", completed["return"])
        self.assertEqual("stopped", stopped["termination"])
        self.assertEqual(0, stopped["return_valid"])
        self.assertEqual("0x0", stopped["return"])

    def test_rejects_invalid_v3_terminal_contracts_and_text_container(self):
        stopped = v3_metrics(termination="stopped", return_valid=0, return_value="0x0")
        cases = (
            (v3_metrics(return_valid=0),
             "completed.*return_valid", "completed return value marked invalid"),
            (stopped.replace("return_valid=0", "return_valid=1"),
             "stopped.*return_valid", "stopped return value marked valid"),
            (stopped.replace("return=0x0", "return=0x1"),
             "stopped.*return", "stopped return value leaked"),
            (stopped.replace("termination=stopped\n", ""),
             "missing termination", "termination omitted"),
            (stopped.replace("termination=stopped", "termination=aborted"),
             "invalid termination", "unknown terminal state"),
        )
        for sidecar, message, mutation in cases:
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, message):
                parse_metrics(sidecar.encode("ascii"), "run.trace.bin")
        with self.assertRaisesRegex(ValueError, "metrics v3.*binary"):
            parse_metrics(stopped.encode("ascii"), "run.trace.txt.lz4")


if __name__ == "__main__":
    unittest.main()
