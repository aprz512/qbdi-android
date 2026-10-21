# qtrace-ui development and validation

[Analyzer overview](../README.md) · [Project documentation](../../docs/README.md)

Run commands from the repository root unless a command explicitly changes directory.
Build and test commands below change into the analyzer and frontend directories;
return to the repository root before running the diagnostic sections.

## Build and test

Install Rust stable, Node 22, and the Tauri 2 Linux packages:

```text
libwebkit2gtk-4.1-dev build-essential pkg-config curl wget file libxdo-dev
libssl-dev libayatana-appindicator3-dev librsvg2-dev
```

Install frontend dependencies with `cd qtrace-ui/src-web && npm ci`. Use `npm run dev` for the web shell or `npm run tauri -- dev` for desktop development.

Run the normal gates before packaging:

```bash
cd qtrace-ui
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd src-web
npm run lint
npm test
npm run e2e
npm run build
npm run e2e:production
npm run tauri -- build --bundles deb,appimage
```

## Native protocol fixtures

The native protocol check requires Python 3.11+, a host C++20 compiler, CMake
3.22.1 or newer, and the initialized QBDI submodule. Run from the repository root:

```bash
git submodule update --init --recursive
python3 qtrace-ui/tools/check_protocol_matrix.py --check
```

This check generates Android AARCH64 headers from the pinned QBDI source and
compiles the production encoders for the host. It does not download or build
LLVM or require an Android tracer build. It compares the generated fixtures with
the checked-in bytes and verifies the independent Python and Rust readers.
Use `--skip-rust` for a focused C++/Python check; it does not verify the Rust reader.

If CMake is not on `PATH`, set `CMAKE` to its executable path. The tool also detects
Android SDK CMake 3.22.1 through `ANDROID_HOME`. Submodule synchronization and
version changes follow the [QBDI dependency workflow](../../docs/development.md#qbdi-源码依赖).

## Open-phase profiling

Set `QTRACE_UI_OPEN_PROFILE=1` when running the performance driver to emit
`qtrace_open_phase` JSON lines on stderr. Timings cover source hashing, cache
identity, event-key and metadata reads, binary section reads, checksums, and
catalog validation. Some spans include others and some overlap; do not sum them
as elapsed time. The reader uses held file descriptors and bounded reads. Timing
lines contain phase names and seconds, without source paths or captured payloads.
Profiling itself does not change the cache format. The current index uses cache
layout 4; older indexes are rebuilt under the new cache identity. UTF-8 string
definition payloads use JSON text, while arbitrary bytes retain their array form.
The public provider serializer still emits byte arrays, and its reader accepts
both forms. Literal semantic detail can refer to its owning payload row; escaped
detail retains an ordinary blob entry. Cache validation checks both forms against
the reconstructed facts under the original resource limits.

Dense Flight indexing and scene interval event queries are documented in the
[2026-10-21 validation](../../docs/benchmarks/flight-query-2026-10-21.md).

Local phase measurements, cancellation checks, and retained-capture browser
acceptance are recorded in the [2026-10-19 long-operation evidence](../../docs/benchmarks/qtrace-long-operations-2026-10-19.json).

## Call tree diagnostic

Run the frontend diagnostic from the repository root after installing frontend
dependencies and Playwright Chromium:

```bash
node qtrace-ui/tools/call_tree_memory.mjs /tmp/qtrace-call-tree-memory.json
```

The diagnostic opens five isolated Chromium pages. Each browses 100 branches
with 100 children, using the actual CallTreePane and synthetic page responses.
It records forced-GC heap growth, frame and expansion samples, DOM counts,
source hashes, and runtime identity. Expansion timings include two animation
frames and should not be interpreted as JavaScript execution time. This does
not measure the Rust service, Tauri WebKit, or device capture performance.
The [page-cache acceptance](../../docs/benchmarks/qtrace-ui-call-tree-pages.md)
records the local comparison and retained-capture browser regression.

## Timeline page diagnostic

Run the five-round frontend diagnostic with other browser workloads stopped:

```bash
node qtrace-ui/tools/timeline_pages.mjs /tmp/qtrace-timeline-pages.json
```

It mounts the actual App with synthetic pages, a fixed response delay, and bursts
of adjacent scroll positions. The report includes queries, page serialization,
viewport latency, frame intervals, forced-GC heap growth, and source identities.
These timings do not measure Rust, device capture, or Tauri WebKit performance.
See the [timeline request acceptance](../../docs/benchmarks/qtrace-ui-timeline-pages.md).

## Captured session verification

After a device capture has published its session report, verify the original files
through the same provider, index, analysis, and application-service layers used by
the desktop app. Run from the repository root with an absolute report path and a
new cache directory:

```bash
cargo run --manifest-path qtrace-ui/Cargo.toml -p qtrace-service --example verify_capture -- \
  --report /absolute/path/session/report.json \
  --cache /absolute/path/new-cache > /absolute/path/capture-evidence.json
```

The checker compares every indexed key, payload, kind, and provenance with an
independent provider pass. It visits the complete paged timeline, checks the
instruction filter, samples register replay, call trees, and memory, then repeats
the checks after closing and reopening the persisted cache. JSON evidence includes
artifact hashes, physical and decoded sizes, event counts, completeness, context,
and timeline/analysis digests. Existing nonempty caches are rejected so the first
open builds an index. Timings are single-run diagnostics, not performance gates.

Rejected artifacts and failed analysis queries fail verification. Partial captures
retain their recorded gaps and termination uncertainty; a passing check does not
assert that capture is complete. Checks use the production service limits.
Source input allowances account for checksum and record-reading passes. Index
memory, analysis work, and the 2,000-row response limit remain enforced; internal
memory posting scans consume work rather than response rows.
The checker uses no device connection and does not exercise browser rendering.
Its fixture tests run with `cargo test -p qtrace-service`; Android capture remains
an explicit manual prerequisite.

The preserved Flight and monitor-exit sessions pass offline cold/cache-reopen
verification in the [2026-10-19 budget validation](../../docs/benchmarks/qtrace-capture-budget-2026-10-19.json).
This does not replace a new device capture or browser acceptance run.

The [2026-10-19 browser acceptance](../../docs/benchmarks/qtrace-browser-acceptance-2026-10-19.json)
also checks those two preserved reports through Chromium and the real Rust service:
result pages, distant timeline navigation, filters, registers, call trees, memory,
annotations, and restart persistence. The production bundle isolation test passes.
These browser results retain the historical capture identities.

The [fresh Xiaomi acceptance](../../docs/benchmarks/qtrace-xiaomi-capture-2026-10-19.json)
subsequently passes timed offset/symbol, monitor-exit, and Flight crash recovery on
M2011K2C after Shell root is granted. All four new reports pass offline verification
and Chromium checks through the real Rust service, including memory history and
restart persistence. The new 64 MiB Flight contains 1,185,909 recovered events.
Strictly ordered memory overlap candidates now skip redundant sorting; unordered
candidates retain sorting and deduplication, and the existing work/response limits
remain enforced. Capture setup follows the manual device gate's trace-directory
isolation procedure and preserves the previous directory as a backup. This proves
the current functional path; it is not a new device performance benchmark.

## Performance reproduction

Generate the large corpus outside Git, verify it, then run the fixed-host gate:

```bash
python3 qtrace-ui/tools/generate_performance_fixtures.py --output qtrace-ui-performance-evidence/corpus
python3 qtrace-ui/tools/generate_performance_fixtures.py --check qtrace-ui-performance-evidence/corpus/manifest.json
QTRACE_UI_REFERENCE_HOST=qtrace-ui-reference-v2 \
python3 qtrace-ui/tools/performance_gate.py \
  --manifest qtrace-ui-performance-evidence/corpus/manifest.json \
  --evidence qtrace-ui-performance-evidence/run.json \
  --reference-summary docs/benchmarks/qtrace-ui-performance-current.md
```

The gate requires five cold indexes, five warm opens, at least 200 viewport and 200 indexed structured-query samples, exact corpus/tool identities, and the checked-in reference-host identity.

For a local before/after comparison on the same machine, save a diagnostic JSON before changing the analyzer, then pass it as the baseline after the change:

```bash
python3 qtrace-ui/tools/performance_gate.py \
  --manifest qtrace-ui-performance-evidence/corpus/manifest.json \
  --evidence qtrace-ui-performance-evidence/before.json --diagnostic
python3 qtrace-ui/tools/performance_gate.py \
  --manifest qtrace-ui-performance-evidence/corpus/manifest.json \
  --evidence qtrace-ui-performance-evidence/after.json --diagnostic \
  --diagnostic-baseline qtrace-ui-performance-evidence/before.json
```

The diagnostic report labels all values as local, checks matching host and corpus identities, and reports percent changes (negative is faster or lower memory). It cannot read or write the checked-in reference summary or overwrite tracked reference files. It does not decide reference-gate acceptance.

## Rich workload evidence

Keep the original 10M/512 MiB scale gate. Generate typed QTRB at 100k, 1M
(default), or 10M records plus six metadata/terminal records with `--groups`
20000, 200000, or 2000000. Generation and concatenated LZ4 frame compression
use bounded buffers. The 100k and 1M streams have fixed semantic SHA-256 oracles.
The companion Flight has four threads, checkpoints/deltas, overwritten and
coverage-gap evidence; it is checked against the existing completeness oracle.

```bash
python3 qtrace-ui/tools/generate_rich_performance_fixture.py --output /tmp/qtrace-rich
python3 qtrace-ui/tools/rich_performance_gate.py \
  --manifest /tmp/qtrace-rich/rich-manifest.json \
  --evidence /tmp/qtrace-rich/local-run.json --diagnostic
```

Each report preserves five fresh-process runs, raw cold/warm and compressed cold
opens, 200 timeline and 200 memory-query samples per run, 50 register queries,
raw/warm/compressed replay equivalence, call trees, IPC bytes, RSS, cache sizes,
host/analyzer/generator/corpus identities, and Flight thread/gap truth. Rich
latencies are measurements, not new reference latency thresholds. The reference
workflow runs the same workload with `--reference-summary` and preserves browser
attachments alongside the existing strict scale-gate report.

The 1M typed corpus currently exceeds the service's cumulative 2 GiB allocation
budget on both cold and cached open. Direct store/analysis measurements use that
corpus; IPC and real browser measurements use the separately identified 100k
corpus. They never lift the service budget. Browser samples cover 50 filter
applications and require fewer than 100 DOM rows. The browser harness uses debug
Rust and a Vite E2E shell, so its latency is not a packaged desktop guarantee.

Local optimization evidence: [2026-09-26 report](../../docs/benchmarks/qtrace-ui-optimization-2026-09-26.md).

The active reference is [the current-environment baseline](../../docs/benchmarks/qtrace-ui-performance-current.md), accepted on 2026-09-26 as `qtrace-ui-reference-v2`. The previous baseline remains preserved as historical evidence. Host identity checks and performance thresholds remain unchanged.
