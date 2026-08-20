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


if __name__ == "__main__":
    unittest.main()
