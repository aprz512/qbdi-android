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
- The canvas has a parallel ARIA grid. Arrow keys move focus, Enter selects, and Escape clears transient navigation.
- Inspect register and memory provenance before relying on a value. Incomplete call frames remain explicit.
- Rebuild caches after analyzer/schema upgrades; back up annotations before deleting the data root.

V1 excludes live capture, device control, trace editing, source-level debugging, collaborative sync, Windows/macOS packaging, and automatic symbol downloads.

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

Local optimization evidence: [2026-09-26 report](../docs/benchmarks/qtrace-ui-optimization-2026-09-26.md).

The active reference is [the current-environment baseline](../docs/benchmarks/qtrace-ui-performance-current.md), accepted on 2026-09-26 as `qtrace-ui-reference-v2`. The previous baseline remains preserved as historical evidence. Host identity checks and performance thresholds remain unchanged.
