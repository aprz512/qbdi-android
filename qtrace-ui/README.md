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
- The canvas has a parallel ARIA grid. Arrow keys move focus, Enter selects, and Escape clears transient navigation.
- Inspect register and memory provenance before relying on a value. Incomplete call frames remain explicit.
- Rebuild caches after analyzer/schema upgrades; back up annotations before deleting the data root.

V1 excludes live capture, device control, trace editing, source-level debugging, collaborative sync, Windows/macOS packaging, and automatic symbol downloads.

## Performance reproduction

Generate the large corpus outside Git, verify it, then run the fixed-host gate:

```bash
python3 qtrace-ui/tools/generate_performance_fixtures.py --output qtrace-ui-performance-evidence/corpus
python3 qtrace-ui/tools/generate_performance_fixtures.py --check qtrace-ui-performance-evidence/corpus/manifest.json
QTRACE_UI_REFERENCE_HOST=qtrace-ui-reference-v1 \
python3 qtrace-ui/tools/performance_gate.py \
  --manifest qtrace-ui-performance-evidence/corpus/manifest.json \
  --evidence qtrace-ui-performance-evidence/run.json \
  --reference-summary docs/benchmarks/qtrace-ui-performance.md
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
