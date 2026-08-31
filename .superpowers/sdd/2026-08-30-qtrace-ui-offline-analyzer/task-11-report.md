# Task 11 report: normalized trace columns and eager indexes

## Scope and store roles

- `IndexBuilder::build(&ArtifactSource, &BuildOptions, &dyn WorkGuard)` strictly drains the
  already-verified Task 9 provider, requires `finish`, appends normalized owned columns, and builds
  eager indexes. Provider/control failures remain global build failures.
- `OwnedTraceStore` is the append-only build workspace and exposes the small Task 11 query
  primitives used by behavioral tests. `MappedTraceStore` retains Task 10's held-FD
  `MappedStoreView`, reloads the checked normalized section, and verifies it against the held
  event-key/kind sections. `TraceStore::open_or_build` is the cache facade.
- Task 10 `OwnedStoreView`/`MappedStoreView` remain the cache-wire substrate; they were extended
  with checked extra sections rather than replaced by a second conflicting store model.
- This task does not implement Task 12 expression parsing/pagination, Task 13 symbolization, Task
  14 state replay, Task 15 call-tree construction, or any UI/Tauri work.

## Normalized schema and row invariants

The cache identity advances to schema/layout 2 and includes the deterministic `BuildOptions`
SHA-256. Existing fixed `event_kinds.v1` and 80-byte `event_keys.v1` sections remain unchanged.
The new `normalized_catalog.v1` section has exact `(alignment=8, element_size=1)` validation and
canonical deterministic JSON bytes. Its logical schema is:

| Table/arena | Stored evidence |
|---|---|
| event | one row per base key/kind: timeline, explicit nullable TID/sequence, provenance, bounded full typed-payload blob |
| instruction | owning event row, nullable normalized module/definition IDs, module-relative PC |
| memory | owning event row, nullable module, relative PC, checked address/end/size, direction/flags/value/metadata, bounded before/after blobs |
| semantic | owning event row, exact-byte nullable category/name dictionary IDs, bounded detail blob |
| completeness | exact domain/bounds/cause and captured/derived/heuristic/unknown/damaged provenance |
| module | source event row/provenance, source ID, base, exact-byte name ID |
| definition | source event row/provenance, complete instruction-definition fields, exact-byte string IDs and canonical definition blob |
| register observation | owning event row, architectural slot, captured width, read/write/checkpoint/delta access, value and provenance |
| string/blob arenas | contiguous append-only bytes plus checked `u64` offset/length spans and explicit byte bounds |

Every event has the complete source `EventKey` in the fixed base column, and every event-derived
typed row points back to its owning event row and therefore to that key. Module/definition rows
also retain their source row and provenance. Nullable values use `Option`; no sentinel means
absence. Invalid UTF-8 string-definition bytes remain raw bytes. The payload blob keeps the
provider's closed typed payload without inventing missing fields.

Arena interning uses SHA-256 only to locate candidates and then compares exact bytes before reuse.
Module `(base,name)` and canonical instruction definitions reuse normalized IDs only after exact
equality; semantic category/name and all bounded strings/blobs use the same collision-verifying
arena. Main vectors/maps use checked arithmetic and fallible reserve, payload serialization first
counts exact bytes and then reserves that exact capacity, and construction order/IDs/cache bytes
are deterministic. A two-independent-root test compares complete cache bytes.

## Eager indexes

- Timeline, TID, event kind, normalized module, normalized instruction definition, architectural
  register slot, semantic category/name, call, return, and register-checkpoint locators use sorted
  strictly increasing posting lists. Encoding stores `first_row + 1` followed by checked positive
  deltas, so row zero is unambiguous. Same-field multi-value lookup unions and de-duplicates rows;
  the exported minimal intersection primitive handles a later field.
- Sequence uses sorted `(sequence,row)` pairs. Each normalized module has sorted
  `(relative_pc,row)` pairs.
- Source keys are sorted by the complete `EventKey`; a reverse row is stored for every event.
  Duplicate source keys fail with `index.duplicate_source_key`. Owned and cache-open validation
  require a complete row/key bijection.
- Memory intervals are sorted by `(start,end,row)` and augmented with per-entry prefix maximum end
  plus sparse block-prefix maxima. Query `[start,end)` first bounds `access.start < end`, then keeps
  `access.end > start`, so an access beginning before the query is found. Address+size overflow is
  typed invalid input. Zero-size observations remain in the normalized table but intentionally do
  not enter the overlap index; empty queries return no rows and reversed queries fail.
- Cache validation rebuilds all eager indexes from the held-FD key/kind rows plus normalized
  columns and requires byte-semantic equality. Re-signed, checksum-consistent but semantically
  inconsistent catalogs therefore return Task 10 `Rebuild`, not `Ready`.

## Provider and capability behavior

Provider selection first admits the existing supported artifact class, then probes four bytes from
the already-held verified FD: `QTRB`, LZ4 frame magic `04 22 4d 18`, or Flight `TLFQ`. The selected
public provider performs its existing version checks. Renaming QTRB as Flight and Flight as QTRB
does not redirect the decoder; path replacement cannot redirect the owned FD.

| Evidence/capability | QTRB normalization | Flight normalization |
|---|---|---|
| timeline identity | Task 9 per-artifact remap remains independent | merged/per-TID projection keys remain provider-defined |
| instruction/memory/semantic payloads | only emitted typed QTRB fields | only emitted typed Flight fields |
| register read/write observation | true only when provider advertises it and real instruction observations were stored | not inferred from checkpoint/delta |
| full register checkpoint | false without a real ordered 34-slot checkpoint | true only when advertised and such a checkpoint was observed |
| memory metadata / before-after | advertised bit is lowered unless corresponding real evidence was stored | never inferred from absent fields |
| lifecycle / signal+termination | advertised bit is lowered unless corresponding typed events were stored | same rule |
| provenance/completeness | captured, derived, heuristic, unknown and damaged values preserved | same; unreliable delta ancestry is explicitly damaged |

The cursor must return end-of-stream before `finish`; only after successful provider completion are
cache bytes serialized and published. Provider source-identity drift at completion and all control
errors abort globally.

## Cache integration and cancellation

- Task 10 writer streams checked extra sections with alignment padding, SHA-256 descriptors,
  checked offsets/lengths, periodic checkpoints, and extra-section resident peak accounting.
- Task 10 reader keeps its corruption/publication/path gates, validates the exact new section
  contract and 512 MiB bound, treats a missing schema/layout-2 normalized section as `Rebuild`,
  verifies canonical schema/arenas/references/bijection/index equivalence, and reads keys/kinds
  from the held FD. Stable corrupt/missing same-identity caches rebuild; foreign identity is never
  overwritten.
- Publication happens only after provider completion. `open_or_build` then uses `CacheReader` to
  reopen the final file and returns a `MappedTraceStore`. If this builder published but post-publish
  reopen/cancellation fails, descriptor-bound locked rollback removes only that exact validated
  final and fsyncs the directory. A valid concurrent winner is never removed.
- Guard checkpoints cover provider drain, every event append/arena intern, completeness, index
  groups and periodic loops, sorts/delta/interval augmentation, serialization, Task 10 publication,
  held-FD validation, and reopen. The behavioral test counts a successful build and injects both
  cancellation and budget failure at every observed ordinal. Each retains `job.cancelled` or
  `control.budget_exceeded` and leaves no `index.qtc`, `.tmp`, or directory staging name; the
  persistent cooperative `.publish.lock` is allowed.

## TDD evidence

Initial RED:

```text
cargo test -p qtrace-store --test index_build --test index_equivalence
error[E0432]: unresolved imports BuildOptions, IndexBuilder, TraceStore, intersect_rows
```

The first tests were behavioral Rust consumers over checked fixtures and private temporary cache
roots; they did not inspect source/config text. Subsequent RED/GREEN cases included:

- Misnamed QTRB with `.flight.bin` reached the Flight decoder and failed short-read; held-FD magic
  probing made both QTRB-as-Flight and Flight-as-QTRB decode correctly.
- A normalized source-row mutation with recomputed section, manifest, and header SHA values was
  accepted too far as `cache.normalized_corrupt`; deep reader validation now returns `Rebuild` and
  `open_or_build` produces an equivalent mapped store.
- Cancellation during cache semantic revalidation was first downgraded to normalized corruption,
  then to resource exhaustion. Control categories now pass through unchanged, and every injected
  ordinal is green for both cancellation and budget failure.
- Edge tests prove duplicate-key typed failure, checked `u64` memory-end overflow, explicit
  zero-size semantics, true overlap for an access beginning before the query, posting union and
  later-field intersection, and complete owned/mapped equivalence.

Final focused result: 8/8 integration tests plus 3/3 builder edge unit tests.

## Verification

- `cargo test -p qtrace-store --test index_build --test index_equivalence` — 8/8 passed.
- `cargo test -p qtrace-store --test cache_format --test cache_publication` — Task 10 regressions
  29/29 passed.
- `cargo test -p qtrace-store cache:: -- --nocapture` — Task 10 cache unit regressions 18/18
  passed.
- `cargo test -p qtrace-store --no-fail-fast` — 108/108 passed (final fresh gate).
- `cargo test -p qtrace-provider --no-fail-fast` — 122 passed, one intentional ignored isolated
  child entry point (final fresh gate).
- `cargo clippy -p qtrace-store -p qtrace-provider --all-targets -- -D warnings` — passed.
- `cargo fmt --all -- --check` and `git diff --check` — passed.
- Python fixtures/exporters were not changed or mutated. The Rust consumers read the checked
  fixtures serially, so no Python fixture gate was necessary for this task.

## Deferred by design

- Task 12 owns the full query language, multi-field planning beyond the minimal primitives, and
  stable pagination APIs.
- Task 13 owns symbol resolution. Task 14 owns register/memory state replay; this task stores only
  observations and checkpoint locators. Task 15 owns call-tree construction; this task stores only
  call/return flags.
- `MappedTraceStore` intentionally keeps Task 10's safe held-FD `pread` backing and materializes
  the bounded normalized catalog for validation/querying. A future safe zero-copy representation
  can evolve behind the same store role without changing this task's cache trust boundary.
