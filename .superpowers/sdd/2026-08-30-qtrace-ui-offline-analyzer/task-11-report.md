# Task 11 report: hardened normalized trace indexing

## Scope and public roles

- `IndexBuilder::build(&ArtifactSource, &BuildOptions, &dyn WorkGuard) -> OwnedTraceStore`
  drains the verified provider to EOF, requires `finish`, and only then permits serialization and
  publication. Provider completion, identity drift, cancellation, and budget failures remain
  global failures.
- `OwnedTraceStore` is the append-only build workspace. `MappedTraceStore` is opened only from a
  schema-checked held-FD `MappedStoreView`. `TraceStore::open_or_build` implements Task 10
  `Ready`/`Missing`/`Rebuild` semantics and always reopens a new publication through
  `CacheReader` before returning it.
- Public `TraceStoreView` is implemented symmetrically by owned, mapped, and enum stores. It
  exposes event/typed-row lookup, capabilities, timeline/TID/sequence/kind/module/module-PC/
  definition/register/checkpoint/call/return/semantic indexes, memory overlap, and both directions
  of the row/EventKey bijection. It deliberately provides index primitives, not Task 12 expression
  planning or pagination.
- No Task 12 query language, Task 13 symbols, Task 14 state replay, Task 15 call tree, UI, or Tauri
  work is included.

## Schema 2 exact binary layout

Task 10 schema/layout 1 remains its exact two-section compatibility branch. Schema/layout 2 has
exactly the following ordered sections; missing, extra, renamed, reordered, misaligned, or wrong
element-size sections are `Rebuild`.

| Order | Section | Align | Element bytes | Cardinality / bound |
|---:|---|---:|---:|---|
| 1 | `event_kinds.v1` | 1 | 1 | exactly N |
| 2 | `event_keys.v1` | 8 | 80 | exactly N |
| 3 | `capabilities.v2` | 8 | 16 | exactly 1 |
| 4 | `event_meta.v2` | 8 | 24 | exactly N; provenance, EventScope, payload span ID |
| 5 | `payload_spans.v2` | 8 | 16 | exactly N |
| 6 | `payload_arena.v2` | 1 | 1 | bounded by `max_payload_bytes` (default 8 GiB) |
| 7 | `string_spans.v2` | 8 | 16 | at most 8N+1 descriptors |
| 8 | `string_arena.v2` | 1 | 1 | bounded by `max_string_bytes` (16 MiB) |
| 9 | `blob_spans.v2` | 8 | 16 | at most 8N+1 descriptors |
| 10 | `blob_arena.v2` | 1 | 1 | bounded by `max_blob_bytes` (64 MiB) |
| 11 | `modules.v2` | 8 | 32 | at most N |
| 12 | `definitions.v2` | 8 | 64 | at most N |
| 13 | `instructions.v2` | 8 | 32 | at most N |
| 14 | `memories.v2` | 8 | 72 | at most N |
| 15 | `semantics.v2` | 8 | 32 | at most N |
| 16 | `completeness.v2` | 8 | 32 | checked fixed records |
| 17 | `register_observations.v2` | 8 | 24 | at most 34N |
| 18 | `index_meta.v2` | 8 | 16 | exactly 1 |
| 19 | `timeline_postings.v2` | 8 | 16 | at most N |
| 20 | `tid_postings.v2` | 8 | 16 | at most N |
| 21 | `kind_postings.v2` | 8 | 16 | at most N |
| 22 | `module_postings.v2` | 8 | 16 | at most N |
| 23 | `definition_postings.v2` | 8 | 16 | at most N |
| 24 | `register_postings.v2` | 8 | 16 | at most 34N |
| 25 | `semantic_category_postings.v2` | 8 | 16 | at most N |
| 26 | `semantic_name_postings.v2` | 8 | 16 | at most N |
| 27 | `call_postings.v2` | 8 | 8 | at most N |
| 28 | `return_postings.v2` | 8 | 8 | at most N |
| 29 | `checkpoint_postings.v2` | 8 | 8 | at most N |
| 30 | `sequence_index.v2` | 8 | 16 | at most N |
| 31 | `module_pc_index.v2` | 8 | 24 | at most 2N |
| 32 | `memory_intervals.v2` | 8 | 32 | at most N |
| 33 | `memory_block_max.v2` | 8 | 16 | at most N+1 |
| 34 | `source_rows.v2` | 8 | 8 | exactly N |

All integers are explicit little-endian fixed-width values. Offsets, lengths, event rows, and file
ranges are `u64` on wire; dictionary IDs are checked `u32`, comfortably above 10 million rows.
No O(events) fact or index is embedded in JSON. Only the bounded Task 10 manifest remains canonical
JSON (1 MiB and 64-section limits).

## Normalized facts and invariants

- Every event row retains its complete held-FD `EventKey`, provider `EventKind`, provenance,
  `EventScope`, and one canonical closed `EventPayload` byte span. Nullable fixed fields have
  explicit presence bits; no sentinel value represents absence.
- Instruction, memory, semantic, module, definition, register-observation, and completeness rows
  use fixed records. Every event-owned child has exactly its source owner; module/definition source
  rows retain provenance and must be in bounds with the correct payload kind.
- Address+size uses checked arithmetic. Zero-size memory evidence remains a typed row but is absent
  from the half-open overlap index. Query `[0x1004,0x1008)` finds an access whose start is below
  `0x1004` when its end overlaps, using entry-prefix and sparse block-prefix maximum ends.
- Exact-byte arenas preserve invalid UTF-8 bytes. SHA-256 is only a candidate locator: collisions
  are verified by comparing full bytes. Module, semantic strings, bounded blobs, and definition
  fingerprints are deterministic. A definition fingerprint excludes only the source-local
  `definition_id` and includes every semantic field.
- Source rows and complete `EventKey`s are bijective. Duplicate source keys fail with
  `index.duplicate_source_key`; no map overwrite is possible.

## Flight scope and capability proof

`EventRecord` now carries backward-compatible `EventScope::Artifact` or
`EventScope::FlightChunk { chunk_index, generation, tid }`. Flight physical recovery attaches the
scope before typed decoding and preserves it through opaque/damaged records. Cross-chunk fragment
output has no unique physical scope and safely remains artifact-scoped instead of guessing.

Builder source-ID maps are keyed by `(EventScope, source_id)`, and current module is keyed by the
same scope (whose Flight value includes TID). Thus different generations may reuse an ID with
different meaning, interleaved TIDs cannot leak current modules, and identical semantic
definitions with different source IDs still deduplicate.

Capabilities are reconstructed independently from cache identity plus canonical payload evidence,
then compared exactly with the stored 16-byte capability record. QTRB begins with the provider's
public QTRB capability matrix; Flight begins with its public Flight matrix. Evidence-dependent bits
are lowered only by the same normalization proof. Therefore both a forged `false -> true` and an
incorrect `true -> false` re-sign are rejected. `full_register_checkpoint` requires one real
checkpoint event containing all 34 architectural slots in order and trustworthy Captured/Derived
provenance; observations from multiple events cannot be spliced into proof.

## Eager indexes and deterministic allocation

Posting lists are sorted strictly increasing and encode `first_row + 1` followed by checked
positive deltas. Same-field lookup performs sorted union; `intersect_rows` is the minimal
later-field intersection primitive. Sequence and module-relative-PC arrays are sorted by their full
stable tuple. Call/return remain flags, and checkpoint remains a locator; no Task 14/15 replay is
performed.

Index construction no longer grows posting buckets through `or_default().push`. It stages
fallibly-reserved pairs, sorts bounded 4096-row chunks, and performs deterministic checkpointed
merge passes. Once group counts are known, each row/delta vector is allocated exactly. Source-map,
sequence, module-PC, and interval augmentation use the same cancellable sort. Dedup collision
buckets use a compact `One(id)` representation and allocate a vector only for a real hash
collision; every candidate still receives an exact-byte comparison. Posting and module-PC maps are
sorted, exact-reserved vector maps with binary search, rather than infallibly growing `BTreeMap`
nodes.

## Cache internal truth and consistency boundary

After checksums and exact section contracts, `CacheReader` reads base EventKeys/EventKinds and the
binary facts from its held FD. Validation decodes each bounded canonical payload, canonical
re-encodes it, checks its base kind, and runs normalization again with its stored scope/provenance.
Typed instruction/memory/semantic/register/module/definition rows are generated for one payload,
compared at a monotonically advancing stored-row cursor, and immediately cleared. Arena dictionary
validation shares the stored bytes/spans and retains only compact hash candidates. Capabilities are
accumulated as booleans and compared by exact bidirectional equality. Each index family is rebuilt,
compared, and dropped before the next family: timeline, TID, kind, module, definition, each register
slot, semantic category/name, call/return, checkpoint, sequence, module-PC, memory interval, and
source key. Owner kind/cardinality, source-row bounds, observation/checkpoint grouping, and
completeness encodings are therefore closed under one source of truth without a second derived
catalog.

This is an internal-consistency boundary, not authentication: the cache has checksums but no secret
key. An actor that rewrites canonical payload facts and every dependent fact/index consistently is
outside this guarantee. Inconsistent re-signing of any subset returns `Rebuild`; control, path,
identity, and held-FD drift errors remain fatal rather than being downgraded.

Schema 2 publication uses an internal receipt containing the exact final object identity
(device/inode/kind/mode) and directory binding identity captured under the publication lock.
Post-reopen rollback unlinks only if both still match. A later same-CacheIdentity winner is
preserved and returns conflict/uncertain rather than being deleted.

## Budget, cancellation, and simultaneous-live model

- Build holds one typed append-only catalog. Cache encoding consumes the store: base rows are moved,
  and payload/string/blob arena byte vectors become section backing without cloning. Task 10 writer
  streams each section in 64 KiB pieces and never creates a second complete cache-file image.
- Reader allocates only after exact per-section bounds and a conservative declared peak authorization.
  It removes each section from the temporary map as it decodes it; the three arena vectors move
  directly into catalog backing. Fixed source bytes are dropped as their typed vectors are produced,
  and all temporary section bytes are gone before deep validation. Mapped reopen owns one decoded
  catalog plus the Task 10 held FD/stamp; it does not retain duplicate section or arena copies.
- Let `S` be all serialized normalized sections, `F` the base EventKey/EventKind arrays, `C` the one
  decoded catalog, `E_family` the largest expected index-family pairs plus cancellable merge scratch,
  `D_scope` the minimal scoped module/definition and arena-verifier state, and `Prow` one decoded and
  canonicalized payload. The implemented peak shape is
  `max(S, F + C + E_family, F + C + D_scope + Prow)`, not `F + C + whole-derived-R`.
  Register validation counts and allocates one slot at a time; checkpoint rows are counted before
  exact allocation. The reader declares a checked conservative bound `5*S + F + manifest` before
  normalized allocation. Tests prove limit-minus-one fails as `control.budget_exceeded`, the exact
  threshold succeeds, and the existing final remains byte-identical. Writer has the same threshold
  test and fails before cache path creation.
- The 20,000-event synthetic test proves fixed-row scaling (`event_meta` is exactly 480,000 bytes),
  no 512 MiB JSON wall, and row types beyond small fixtures. The schema supports 10M rows; CI does
  not allocate a 10M fixture. Excluding bounded arenas and optional typed/index families, the
  unavoidable on-disk fixed minimum is about 161 bytes/event (base key/kind, meta/span, source row,
  timeline and kind postings), or about 1.61 GB at 10M. A representative memory-heavy trace adds
  72-byte memory rows, 32-byte intervals, optional TID/sequence postings, capture blobs, and canonical
  payload bytes, so its exact total is workload-dependent and can exceed 2 GiB. Task 11 removes the
  structural 512 MiB JSON wall and makes all row/offset types capable of 10M; Task 24 remains
  responsible for measuring the representative 10M/RSS <= 2 GiB target and selecting production
  budgets.
- Guard checkpoints cover provider drain/finish, append, canonical payload/arena/dedup, count/fill,
  chunk sort and merge, delta/interval augmentation, section encoding, stream write, publish,
  reopen, payload decode, and deep validation. A successful run records all ordinals; cancellation
  and budget failure are injected at every ordinal. No visible final, random temp, or staging name
  remains (the persistent cooperative lock is allowed).

## TDD evidence

Review-fix REDs were behavior tests over real checked fixtures and private cache roots:

- Re-signed `full_register_checkpoint=false -> true` opened as true; after independent proof it
  rebuilds to false. Re-signed `per_thread_ordering=true -> false` also rebuilds to true.
- Schema 2 initially contained three sections and one large `normalized_catalog.v1` JSON payload;
  the exact 34-section test failed before the binary layout was connected.
- `EventScope` contract tests initially did not compile, then a cross-generation reused definition
  ID produced `index.invalid`; both became green after provider and builder scoping.
- Re-signed wrong owner kind, duplicate+missing child, module/definition source OOB, observation
  splice, illegal completeness, and synchronized typed-column+index mutations all rebuild.
- Missing, renamed/extra, reordered, and wrong-contract schema-2 sections all rebuild.
- Merge cancellation is exercised after chunk sorting and during merge. A later valid same-identity
  inode survives rollback with an old publication receipt.
- Reader and writer peak tests reject one byte below their declared bound, accept the exact bound,
  and prove failure leaves no new final/temp/staging state (or preserves the existing reader final).
- Public owned/mapped index views match naive scans, including empty/OOB, source bijection,
  timeline/TID/kind/module/PC/definition/register/checkpoint/call/return/semantic/memory behavior.

## Final verification

- `cargo test -p qtrace-store --no-fail-fast` — 119 passed.
- `cargo test -p qtrace-provider --no-fail-fast` — 123 passed, 1 intentional ignored child entry.
- `cargo test -p qtrace-store --test index_build` — 4/4 passed, including every successful
  checkpoint ordinal injected once as cancellation and once as budget exhaustion (43.21 s fresh
  full-run instance).
- `cargo test -p qtrace-store --test index_equivalence` — 10/10 passed.
- Task 10 cache gates within the full run: format 11/11, publication 19/19, cache/store unit 28/28.
- `cargo clippy -p qtrace-store -p qtrace-provider --all-targets -- -D warnings` — passed.
- `cargo fmt --all -- --check` and `git diff --check` — passed.
- Python exporters/fixtures were not modified; Rust consumers only read checked fixtures serially.

## Deferred by design

- Task 12 owns expression/query planning and stable pagination; Task 13 symbols; Task 14 replay;
  Task 15 call-tree construction.
- `MappedTraceStore` keeps a single decoded normalized catalog after `CacheReader` has proven the
  held file. It does not retain section copies or duplicate arenas. A future true mmap/zero-copy
  representation can replace that backing behind `TraceStoreView` without changing Task 11 APIs or
  the cache truth boundary.
