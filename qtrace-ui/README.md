# qtrace-ui

`qtrace-ui` is an offline Linux desktop analyzer for QTRB 1.0–1.2 and Flight v2 captures. It never attaches to a device or target process. A session report preserves package, device, target, and configuration context; opening one trace file works in degraded mode and reports missing capabilities.

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

## Truth and storage model

Captured values are labeled captured, derived, unknown, or damaged; gaps and overwritten ranges are evidence, not reconstructed facts. QTRB register observations distinguish before-read from after-write state. Flight checkpoints and deltas remain per-thread. Cross-thread memory is ordered only when the artifact proves global order. Local names and annotations change presentation only; they never replace ELF or capture evidence.

Source artifacts are immutable. Persistent indexes live under `${XDG_CACHE_HOME:-~/.cache}/qtrace-ui`; annotations and local presentation data live under `${XDG_DATA_HOME:-~/.local/share}/qtrace-ui`. Delete the relevant cache identity to force a rebuild. Back up the data directory to preserve annotations. Never place annotations beside an untrusted trace.

## Operator workflow

- Prefer a session report; single-file open intentionally lacks package/device/config context.
- Filter by thread, kind, module, PC, sequence, mnemonic, register, memory, or semantic fields. The projection is paged; the DOM never owns the full trace.
- Results have independent page navigation and show whether the total is exact or still indexing. Previous/Next hit cross page boundaries; selecting a hit jumps to its event in the timeline.
- Call trees keep one sibling page per parent. Use Load more calls and Previous calls to move between pages. Older branches can be unloaded and fetched again when expanded.
- The canvas has a parallel ARIA grid. Arrow keys move focus, Enter selects, and Escape clears transient navigation.
- Inspect register and memory provenance before relying on a value. Incomplete call frames remain explicit.
- Rebuild caches after analyzer/schema upgrades; back up annotations before deleting the data root.

V1 excludes live capture, device control, trace editing, source-level debugging, collaborative sync, Windows/macOS packaging, and automatic symbol downloads.

## Long operations

Open jobs report source verification, cache validation, indexing, cache publication,
cache reopening, analysis preparation, and workspace publication. The outer count
tracks artifacts. Stage counters report accounted input bytes, events, and rows;
repeated validation passes count separately, and counters reset at each stage.
They do not estimate a percentage or remaining time. Updates are bounded and
coalesced; analysis preparation also reports row work when no input bytes change.
The Cancel button shows `Cancelling…` until the job reaches a terminal state and
allows another attempt if cancellation submission fails.

Cache validation uses at most two workers per artifact, sharing the existing
allocation, input, and cancellation budgets. Event keys and metadata decode
independently; the second worker then checks all section checksums alongside
catalog validation. Source identity, file stamps, corruption rebuilding, and
transactional publication remain enforced. Closing a workspace or cancelling
the service also cancels active register replay and call tree construction;
cancelled builds never populate their shared analysis caches.

Set `QTRACE_UI_OPEN_PROFILE=1` when running the performance driver to emit
`qtrace_open_phase` JSON lines on stderr. Timings cover source hashing, cache
identity, event-key and metadata reads, binary section reads, checksums, and
catalog validation. Some spans include others and some overlap; do not sum them
as elapsed time. The reader uses held file descriptors and bounded reads. Timing
lines contain phase names and seconds, without source paths or captured payloads.
The cache format is unchanged, so existing caches use the same validation path.

Local phase measurements, cancellation checks, and retained-capture browser
acceptance are recorded in the [2026-10-19 long-operation evidence](../docs/benchmarks/qtrace-long-operations-2026-10-19.json).

## Call tree page memory

The call tree cache retains at most 8,192 nodes and 4 MiB of accounted weight.
Weight includes string lengths and allowances for objects; it is not a browser
heap limit. Each sibling page contains at most 100 nodes. Paging replaces that
parent's window and releases unreachable descendants. Least recently used
branches are evicted under pressure and remain available through expansion or
Load calls. An ancestor path that alone exceeds the budget is rejected without
replacing the current view. DOM virtualization also remains enabled.

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
The [page-cache acceptance](../docs/benchmarks/qtrace-ui-call-tree-pages.md)
records the local comparison and retained-capture browser regression.

## Timeline page requests

The main timeline uses one page repository per workspace, projection, and frontend
generation. Scrolling, next/previous pages, event jumps, and history reveal share
in-flight page requests. Only the latest navigation can publish its result;
aborted consumers cannot replace the visible timeline. Switching projections or
closing the workspace releases cached pages and rejects late responses.

Pages contain at most 2,000 rows. The LRU cache retains at most 128 pages and
32 MiB of accounted weight (four pages in E2E mode). Cursor positions are retained
with their cached pages; evicted pages can be located and fetched again. Weight
uses string lengths and object allowances, without serializing each page. This
is an accounting bound, not a browser heap limit. An already dispatched IPC call
cannot be cancelled; its response may populate the bounded cache while the same
projection remains open. Search results keep their independent page navigation.

Run the five-round frontend diagnostic with other browser workloads stopped:

```bash
node qtrace-ui/tools/timeline_pages.mjs /tmp/qtrace-timeline-pages.json
```

It mounts the actual App with synthetic pages, a fixed response delay, and bursts
of adjacent scroll positions. The report includes queries, page serialization,
viewport latency, frame intervals, forced-GC heap growth, and source identities.
These timings do not measure Rust, device capture, or Tauri WebKit performance.
See the [timeline request acceptance](../docs/benchmarks/qtrace-ui-timeline-pages.md).

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
verification in the [2026-10-19 budget validation](../docs/benchmarks/qtrace-capture-budget-2026-10-19.json).
This does not replace a new device capture or browser acceptance run.

The [2026-10-19 browser acceptance](../docs/benchmarks/qtrace-browser-acceptance-2026-10-19.json)
also checks those two preserved reports through Chromium and the real Rust service:
result pages, distant timeline navigation, filters, registers, call trees, memory,
annotations, and restart persistence. The production bundle isolation test passes.
These browser results retain the historical capture identities.

The [fresh Xiaomi acceptance](../docs/benchmarks/qtrace-xiaomi-capture-2026-10-19.json)
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

## Service resource boundaries

Each artifact supports at most 4,294,967,295 events in the current numeric row
protocol. Opening an artifact above that limit returns
`workspace.event_limit_exceeded` before analysis preparation or workspace
publication. Counts and locations never silently saturate. Existing allocation
and event-work budgets still apply below that protocol ceiling.

Timeline responses contain at most 2,000 rows; call-tree pages contain at most
100 siblings and require the same tree identity for continuation. Filters accept
at most 256 terms across all fields, 4 KiB per text value and 64 KiB of aggregate
text. Memory directions accept all four existing variants. Symbol resolution accepts at
most 2,000 addresses. Identifiers and tree identities are capped at 256 bytes,
timeline cursors at 8 KiB, comments at 64 KiB, local names at 4 KiB and highlights
at 256 bytes. The request deserializers reject excess arrays and strings before
building their full typed values; service entry points repeat the checks for
non-IPC callers.

DTO responses are limited to 16 MiB of serialized JSON, including escaping.
The counter writes no encoded copy. Oversized open metadata is rejected before
workspace publication. This response bound complements the existing work,
deadline and cumulative allocation budgets; it is not a JavaScript heap limit.
Annotation SQLite work uses the same interactive deadline, VM-work budget and
workspace cancellation token.

At most eight open/projection jobs run concurrently. The registry retains at
most 512 jobs and evicts only terminal entries. Multi-artifact preparation runs
at most two artifacts concurrently with the same cumulative source and cache
budgets. Results keep report order, individual format failures remain isolated,
and every worker joins before an open error returns. Source keys that already
have strict order use an implicit row mapping in memory; nonmonotonic sources
retain an explicit sorted mapping. The cache schema and encoded row bytes stay
compatible with existing readers.

Measurements, compatibility checks and the command audit are recorded in the
[2026-10-19 store and boundary report](../docs/benchmarks/qtrace-store-boundaries-2026-10-19.md).

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

Local optimization evidence: [2026-09-26 report](../docs/benchmarks/qtrace-ui-optimization-2026-09-26.md).

The active reference is [the current-environment baseline](../docs/benchmarks/qtrace-ui-performance-current.md), accepted on 2026-09-26 as `qtrace-ui-reference-v2`. The previous baseline remains preserved as historical evidence. Host identity checks and performance thresholds remain unchanged.
