# Bounded protocol and storage fuzzing

Run the deterministic smoke corpus and 64-case property check with:

```sh
cargo test --manifest-path qtrace-ui/fuzz/Cargo.toml --locked -j 2 --tests
```

The libFuzzer targets are `qtrb`, `flight`, `cache_manifest`, `session_report`, and
`annotations`. Run a short local check from `qtrace-ui` with `CARGO_BUILD_JOBS=2
cargo +nightly fuzz run <target> fuzz/corpus/<target> -- -max_total_time=60
-timeout=3 -rss_limit_mb=512 -malloc_limit_mb=128`. Copy a corpus to a temporary
directory first if its checked-in contents must remain unchanged; libFuzzer adds
new inputs to its corpus directory.

QTRB and Flight accept at most 16 MiB input, cache and report targets at most
1 MiB, and annotation databases at most 256 KiB. All paths retain the shared
16 MiB input/decompression, 100,000 event/node/row, 32 MiB cumulative residency,
and one-second cancellation guard. Report cases precharge a conservative JSON
allocation bound. SQLite uses guarded VM progress checks, bounded text lengths,
and a bounded page cache. CI adds a three-second per-input timeout and process
memory limits.

Readable corpus selectors expand production-created cache/SQLite pages or fixed
protocol/session fixtures. Three-byte suffixes XOR bytes at bounded offsets;
ordinary inputs are also passed through unchanged. Cache mutations recompute
manifest checksums so seeds reach identity and section validation. SQLite seeds
include schema 1/2/3, oversized text, incorrect storage classes, and an expensive
recursive view that must hit its VM budget. SQLite only opens temporary copies.
Cache and session targets assert that source bytes remain unchanged.

The workflow runs corpus/property checks, the C++/Python/Rust compatibility
matrix, and 60 seconds per target on relevant pushes and pull requests. Scheduled
and manual runs retain 1,800 seconds per target. Crash inputs are uploaded.

Protocol changes also require `python3 qtrace-ui/tools/check_protocol_matrix.py
--check`. It compiles production C++ encoders, generates fixtures twice, checks
the reviewed bytes and wire constants, verifies QTRB 1.0–1.2 and Flight v2 plus
malformed fixtures, and compares independent Rust/Python decoding. Refresh
`fixtures-native` with `--write` only after reviewing the wire specification and
updating both readers. No parser is generated from another parser.
