# qtrace-ui usage

[Analyzer overview](../README.md) · [Project documentation](../../docs/README.md)

Open QTRB 1.0–1.2, Flight v2, or a qtrace session report in the offline Linux desktop app.
Build and launch instructions are in the [analyzer overview](../README.md#quick-start).

## Operator workflow

- Prefer a session report; single-file open intentionally lacks package/device/config context.
- Filter by thread, kind, module, PC, sequence, mnemonic, register, memory, or semantic fields. The projection is paged; the DOM never owns the full trace.
- Results have independent page navigation and show whether the total is exact or still indexing. Previous/Next hit cross page boundaries; selecting a hit jumps to its event in the timeline.
- Call trees keep one sibling page per parent. Use Load more calls and Previous calls to move between pages. Older branches can be unloaded and fetched again when expanded.
- The canvas has a parallel ARIA grid. Arrow keys move focus, Enter selects, and Escape clears transient navigation.
- Inspect register and memory provenance before relying on a value. Incomplete call frames remain explicit.
- Rebuild caches after analyzer/schema upgrades; back up annotations before deleting the data root.

V1 excludes live capture, device control, trace editing, source-level debugging, collaborative sync, Windows/macOS packaging, and automatic symbol downloads.

## Truth and storage model

Captured values are labeled captured, derived, unknown, or damaged; gaps and overwritten ranges are evidence, not reconstructed facts. QTRB register observations distinguish before-read from after-write state. Flight checkpoints and deltas remain per-thread. Cross-thread memory is ordered only when the artifact proves global order. Local names and annotations change presentation only; they never replace ELF or capture evidence.

Source artifacts are immutable. Persistent indexes live under `${XDG_CACHE_HOME:-~/.cache}/qtrace-ui`; annotations and local presentation data live under `${XDG_DATA_HOME:-~/.local/share}/qtrace-ui`. Delete the relevant cache identity to force a rebuild. Back up the data directory to preserve annotations. Never place annotations beside an untrusted trace.

## Long operations

Open jobs report source verification, cache validation, indexing, cache publication,
cache reopening, analysis preparation, and workspace publication. The outer count
tracks artifacts. Stage counters report accounted input bytes, events, and rows;
repeated validation passes count separately, and counters reset at each stage.
They do not estimate a percentage or remaining time. Updates are bounded and
coalesced; analysis preparation also reports row work when no input bytes change.
The Cancel button shows `Cancelling…` until the job reaches a terminal state and
allows another attempt if cancellation submission fails.

Paging, cache accounting, cancellation, and service limits are documented in the [design guide](design.md).
Captured-session verification and performance diagnostics are in the [development guide](development.md).
