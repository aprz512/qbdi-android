# Task 7 report: typed Flight event decoding

## Summary

- Replaced Flight's physical `OpaqueOptional` records with closed, typed evidence for all wire
  kinds 1--15: chunk identity, register checkpoint/delta, embedded QTRB definition/instruction/
  memory, strings, lifecycle, syscall, signal, handler, termination intent, and coverage gap.
- Added an exact 34-slot register model. Checkpoints establish state; deltas accept only bits
  0--33 and exact value counts. A broken base sequence remains a typed damaged delta but cannot
  make its values or descendants reliable.
- Reused private QTRB semantic validators for the three embedded QTRB payloads. The existing QTRB
  decoder and Flight decoder both pass through that shared validation seam.
- Scoped string definitions and references by physical chunk/generation, preserving every source
  coordinate and preventing stale definitions from leaking across reuse.
- Added bounded fragment assembly keyed by `(tid, event_id, kind)`. Stable fields, totals, indices,
  counts, chunk identity, and generation are checked before one UTF-8 decode; invalid groups emit
  exact damage evidence and no partial semantic event.
- Preserved Task 6's one merged identity, per-TID key projection, deterministic order,
  completeness, and guarded linear recovery. Synthetic discontinuities use a proof coordinate (or
  exact artifact EOF), global identity, and deterministic collision-free evidence ordinals.
- Added a real Python-oracle differential over all eight checked Flight fixtures. Production Rust
  does not invoke Python.

## Files

- `qtrace-ui/crates/qtrace-provider/src/flight/events.rs`
- `qtrace-ui/crates/qtrace-provider/src/flight/fragments.rs`
- `qtrace-ui/crates/qtrace-provider/src/flight/{mod,recovery,wire}.rs`
- `qtrace-ui/crates/qtrace-provider/src/{lib,model}.rs`
- `qtrace-ui/crates/qtrace-provider/src/qtrb/{events,mod}.rs`
- `qtrace-ui/crates/qtrace-provider/tests/{flight_events,flight_differential}.rs`
- Focused compatibility additions in `flight_recovery.rs`, `model_contract.rs`, and
  `qtrb_differential.rs`.

No dependency or configuration change was needed. Task 8 UI work was not entered.

## Protocol and model audit

- Used `codegraph explore` first, then checked the current worktree's Flight/QTRB wire structs,
  writer publication behavior, Python recovery, and fixture oracle.
- `EventPayload`/`EventKind` remain closed and kind-derived. New register checkpoint/delta, string
  definition, and coverage-gap variants are genuine typed evidence, not text or opaque aliases.
- `RegisterSnapshot` construction and deserialization both enforce exactly 34 architectural slots.
  Legacy QTRB JSON remains serde-compatible by omitting/defaulting only the newly introduced zero
  or absent fields.
- Typed decoding validates pointer width, sequence ancestry, exact payload cardinality, nested
  QTRB fields, lifecycle generation, syscall arguments/results, signals, handler nesting,
  termination intent, and coverage-gap coordinates before publication.
- Every payload-dependent allocation, state-map pass, fragment slot initialization, typed sort,
  and synthetic-event batch is WorkGuard-authorized. Variable passes checkpoint within 4,096
  items; ordering uses guarded radix/linear passes rather than comparison sorting.

## TDD evidence

### Initial RED

Command:

```text
cd qtrace-ui && cargo test -p qtrace-provider --test flight_events --test flight_differential
```

Actual result: exit 101. The behavior tests failed to compile because the typed Flight payload
variants, register model, and recovery summary fields did not exist. The tests exercised decoded
behavior and the real Python oracle; they contained no source/config text assertions.

### Initial GREEN

After the minimum typed decoder, fragment assembler, provider projection, and oracle normalizer
were implemented, the same command exited 0: 6 passed, 0 failed.

### Self-review hardening RED/GREEN

Focused tests were made red before each corresponding correction, then green:

- an out-of-range pointer-sized Flight value was accepted;
- a delta following broken ancestry could incorrectly become reliable;
- the required begin/checkpoint prefix was not exact;
- a bad fragment group lost contributing coordinates/generation validation;
- payload-sized allocation and variable-pass work were incompletely authorized;
- synthetic discontinuity identity/offset could be derived from a presentation row rather than
  the proving source coordinate.

The final `flight_events` suite has five exact behavior cases (all kinds 1--15, fragments,
ancestry, coverage gaps, and synthetic proof identity), while `flight_differential` checks all
eight fixtures against the actual Python oracle.

Final review counterexamples also went RED before the fixes:

- duplicate checkpoint: expected `Damaged`, actual `Captured`;
- checksum discontinuity proof: expected chunk offset 6144, actual EOF 8192;
- conservative discontinuity authorization: `control.budget_exceeded` because the old code scanned
  retained completeness before authorizing the full upper bound.

All three focused cases are GREEN. Additional GREEN regressions prove two adjacent checksum ranges
retain both chunk offsets after completeness merging, a coverage-gap discontinuity uses its
emergency slot, unterminated-thread evidence uses explicit EOF, and repeated fragment references
share one backing allocation.

## Differential contract

For each of the eight Flight fixtures, the serial Rust test invokes `tools/oracle.py flight` and
compares normalized merged typed evidence/order, exact per-thread event-key projections, final
registers, retained/lost/overwritten ranges, chunk states, damage coordinates/ranges, target PCs,
termination, handler intervals, and completeness. The exact complete-fixture behavior test checks
the richer Rust field model for every kind; the differential is not a source-text or fixture-name
shortcut.

## Verification

- `cargo test -p qtrace-provider --test flight_events --test flight_differential` — exit 0;
  6 passed.
- `cargo test -p qtrace-provider --no-fail-fast` — exit 0; 97 passed across unit, Flight, model,
  and all existing QTRB suites.
- `cargo fmt --all -- --check` — exit 0.
- `cargo clippy -p qtrace-provider --all-targets -- -D warnings` — exit 0.
- `python3 -m unittest scripts.tests.test_qtrace_ui_fixtures scripts.tests.test_trace_binary scripts.tests.test_flight_trace -v`
  — exit 0; 89 passed.
- `python3 qtrace-ui/tools/export_contract_fixtures.py --check` — exit 0.
- `git diff --check` and `git diff --cached --check` — exit 0 before commit.

Rust and Python fixture tests were kept serial because the Python drift test temporarily changes
and restores a checked fixture.

## Self-review

- No production Python bridge, source/config assertion, `unsafe`, panic, `unwrap`, `expect`, or
  unchecked native wire cast was added.
- Fragment limits are per semantic kind (1 MiB call payload; 4 KiB rule/error text), checked before
  allocation, with fallible reservation and resident-byte charging. Bad groups never publish a
  partial string.
- Broken register ancestry is explicit damaged typed evidence and clears reliable final state;
  omitted delta registers remain unknown rather than being invented as zero.
- Physical records retain their original sequence, chunk, offset, and fragment contributors.
  Synthetic evidence has no invented TID/sequence and uses the exact proving offset or artifact
  byte length for EOF.
- High-cardinality and damaged recovery tests retain linear behavior and the 4,096 checkpoint
  bound after typed state, sorting, fragments, and discontinuities were added.
- Existing QTRB exact-oracle tests pass unchanged semantically, including legacy serialized JSON.

## Independent review

The first read-only review found one Critical and six Important issues. All are closed:

- **Critical:** a malicious declared fragment total could over-authorize resident memory. Fixed
  with per-kind hard limits, checked/fallible allocation, and conservative WorkGuard charging.
- **Important:** pointer-width checks, broken-delta ancestry, exact begin/checkpoint prefix,
  fragment contributor/generation validation, authorization/checkpoint coverage, and synthetic
  discontinuity identity/coordinates were each tightened and covered by focused tests.

The staged-state re-review then found and closed three residual Important issues (duplicate
checkpoint, long unguarded passes, and lossy synthetic coordinates), followed by one Critical
fragment amplification issue. Fragment string references now use shared `Arc<[u8]>` storage and
assembly stops before exceeding the declared total. Sequence proof evidence carries
`Source(offset) | Eof`; normalization may merge completeness ranges, but each physical proof is
still emitted exactly once. Coverage gaps retain their emergency coordinate and unterminated
threads use artifact EOF. The final read-only review reported no remaining Critical or Important
finding and `Ready: Yes`.

Additional audit fixes made the 34-slot serde invariant checked, retained legacy QTRB
serialization compatibility, and routed both decoders through the shared private QTRB validators.

## Commit

- `4d34b998c4f55b5945a7dec1dada2c6d1f0209a3 feat(qtrace-ui): decode typed flight events`

## Concerns

- No blocking implementation concern remains.
- Keep the fixture-mutating Python tests serial with Rust fixture consumers.
- The overwritten fixture contains an intentionally malformed lifecycle body. Rust preserves it
  as typed damaged lifecycle evidence with unknown optional fields while retaining the Python
  oracle's physical completeness result.

---

## Fix round 1: external-review hardening

### Closed findings

- Removed the invented 34-zero final-register fallback. A TID now has a final snapshot only after
  a reliable checkpoint/delta ancestry; bad-delta and emergency-only projections remain `None`.
- Replaced the recoverable prefix booleans with the irreversible
  `ExpectBegin -> ExpectCheckpoint -> Ready | Broken` state machine. Preamble junk, a malformed
  first begin, a non-checkpoint second record, and a duplicate checkpoint permanently damage that
  chunk generation. A physically valid delta after broken ancestry is still typed `Damaged`, gets
  its own physical damage proof, and never restores state or descendants.
- Replaced presentation-derived lost/overwritten coordinates with `SequenceFact` values carrying
  the directory/chunk-header proof offset. Normalized ranges may merge, while each overlapping
  physical fact emits its own synthetic evidence. Inclusive sequence evidence without a proof now
  fails closed; EOF remains exclusive to the explicit unterminated-thread condition. The proof
  join is radix ordered and output-sensitive linear, not a fact-by-range nested scan.
- Made chunk-state/output/fragment/damage/final-register allocation fallible. State construction,
  event passes, and final-map conversion checkpoint at most every 4,096 items; per-chunk string and
  instruction state reserves before insertion.
- Fragment contributors now prove their source offset lies inside the declared chunk data span and
  that the recovered chunk owner, TID, and generation match. Valid cross-chunk groups remain valid;
  forged generation/offset contributors damage the whole group.
- Expanded the bounded Python oracle with optional final-register state, event and fragment source
  coordinates, exact provider range classes, physical range facts, normalized damage details, and
  a provider completeness view. Legacy summary fields remain compatible with all 89 Python tests.

### RED/GREEN evidence

Behavior-first counterexamples produced these actual RED results before their fixes:

- `bad_delta_clears_final_state_but_later_physical_delta_stays_typed_damage`: expected unknown
  final registers, actual `Some` zero snapshot; exit 101.
- `emergency_only_tid_has_unknown_final_registers`: expected `None`, actual zero snapshot; exit
  101.
- `invalid_prefix_is_irreversible_for_the_chunk_generation` and
  `duplicate_checkpoint_permanently_breaks_following_records`: later records restored/retained a
  final snapshot; both exited 101.
- `merged_missing_range_keeps_each_directory_and_chunk_header_proof`: expected proof offsets
  `[4096, 6144]`, actual borrowed next-event offset `[6232]`; exit 101.

The strengthened eight-fixture differential then exposed real schema/behavior differences while
being brought to exact form: omitted-vs-zero typed fields, overlapping legacy loss classification,
emergency-only zero registers, and malformed lifecycle damage without a completeness proof. The
final exact comparison is GREEN. In the external re-review pass,
`proof_for_one_range_does_not_cover_an_unproved_range_in_the_same_domain` produced a further real
RED: one Lost proof caused a second same-domain Lost range without a coordinate to be silently
accepted. Exact normalized-range proof coverage made it GREEN. Making the per-TID differential
one-to-one produced another real RED on `v2-checksum-damaged.bin`: Rust exposed directory-only TID
77 while the oracle projection set was empty. The bounded oracle now exposes explicit
`projection_tids`; legacy Python recovery thread semantics remain unchanged, and the exact TID-set,
row-count, key, and full-row comparison is GREEN. The fragment span test was a
characterization and passed on its first runnable execution. The physical-record expansion of the
differential was also a characterization and passed on its first runnable execution. The >4,096
state/final-map cancellation tests passed on their first runnable helper-level execution; none of
these characterization tests is misreported as RED.

Final focused GREEN:

```text
cargo test -p qtrace-provider --test flight_events --test flight_differential --test flight_recovery
```

Exit 0: 44 tests passed (5 typed events, 1 eight-fixture differential, 38 recovery).

### Exact differential schema

For every checked Flight fixture, the Rust test invokes `python3 tools/oracle.py flight` and
compares:

- the complete typed merged stream, including chunk begin identity, every 34-slot register
  checkpoint, instruction and string definitions, and kinds 2-15 with complete payloads, sequence,
  TID, source offset, provenance, and fragment contributor offsets;
- per-TID complete typed rows derived from oracle physical/semantic evidence, never
  actual-vs-actual;
- exact optional 34-register final snapshots;
- retained, lost, overwritten, and checksum ranges as separate classes;
- every sequence proof's cause, provenance, inclusive range, and real source/EOF coordinate;
- every normalized completeness domain, bound, provenance, and cause, plus every source-range
  discontinuity and its physical coordinate;
- normalized damage class/sequence/source coordinate, target PCs, active/stale/rotating/unreliable
  chunk-directory states, full termination intent and arguments, paired handler intervals, and
  provider completeness.

Physical fragment records are collapsed only by the protocol's explicit logical-fragment grouping;
the logical row retains every contributor sequence and source offset. Accepted physical records
carry their wire kind/flags, bytes, chunk index/generation/state, and source coordinate in the
bounded oracle schema; no hidden kind is inferred from Rust output.

### Fresh verification

- `cargo test -p qtrace-provider --test flight_events --test flight_differential --test flight_recovery`
  — exit 0; 44 passed.
- `cargo test -p qtrace-provider` — exit 0; 106 passed.
- `cargo clippy -p qtrace-provider --all-targets -- -D warnings` — exit 0.
- `cargo fmt --all -- --check` — exit 0.
- `python3 -m unittest scripts.tests.test_qtrace_ui_fixtures scripts.tests.test_trace_binary scripts.tests.test_flight_trace`
  — exit 0; 89 passed.
- `python3 qtrace-ui/tools/export_contract_fixtures.py --check` — exit 0.
- `git diff --check` — exit 0.

Rust fixture consumers and the Python fixture-mutating compatibility suite were run serially.

### Fix-round self-review

- No final state is synthesized from absence or damage.
- Prefix breakage is generation-local and irreversible; broken deltas remain typed evidence only.
- Lost/overwritten/checksum never borrow a retained row or arbitrary EOF. Every physical range fact
  survives completeness normalization as its own stable synthetic event. Proof suppression is
  keyed by the exact normalized range, provenance, and cause, so one coordinate cannot hide an
  unrelated range in the same domain.
- Once a chunk prefix is Broken, every later physical record contributes its own damaged sequence
  and source coordinate. Batched fallible reservation/authorization preserves the 4,096 checkpoint
  bound without per-record guard amplification.
- All new input-sized containers reserve fallibly; variable initialization/conversion loops honor
  the 4,096 checkpoint bound. Public `FlightProvider::open` tests cancel state initialization and
  final-register conversion at the second checkpoint for 4,097 entries without panic. The final
  map receives explicit WorkGuard authorization before reservation. Existing high-cardinality and
  linear-damage tests remain GREEN.
- Oracle additions are bounded data, not a production Rust/Python bridge, fixture-name shortcut, or
  source/config assertion.

### Fix-round commit

- This report's containing commit: `fix(qtrace-ui): harden flight recovery` (final hash reported in
  the task handoff).

### Fix-round independent review

The final read-only review rechecked the original 5 Important + 1 Minor findings and the three
follow-up Important findings. After exact per-TID one-to-one comparison and public >4,096
cancellation seams were added, it reported 0 Critical / 0 Important / 0 Minor and `Ready: Yes`.

### Fix-round concerns

- No blocking concern. Keep the Python fixture compatibility suite serialized with Rust fixture
  consumers.

---

## Fix round 2: full identity and proof-join cancellation

### Closed findings

- Extended every bounded Python physical and logical Flight row with an independently assigned
  `record_ordinal`. Logical fragment rows use the first contributor's physical ordinal; emergency
  rows continue after regular physical records. The oracle also exposes the next physical ordinal
  so synthetic discontinuity keys remain deterministic.
- The Rust differential calculates SHA-256 from each fixture's bytes and verifies it against the
  checked manifest before opening the provider. Oracle-derived keys use that digest, the normative
  merged `TimelineId(0)`, and the oracle ordinal/offset/sequence/TID. Merged and per-TID projections
  now compare complete `EventKey` values directly without looking keys back up in actual rows.
- `add_missing_proofs` checkpoints and checked-increments work for every outer `SequenceFact`, even
  when missing ranges are empty or exhausted. This preserves O(H + M + output) behavior and adds
  only one cheap checkpoint predicate per fact, with WorkGuard calls at most every 4,096 steps.

### RED/GREEN evidence

- `projection_key_comparison_rejects_wrong_ordinal_artifact_and_timeline` was a real behavioral RED:
  the former TID/sequence/source predicate accepted a key with the wrong record ordinal, artifact
  digest, or timeline. Complete independently constructed `EventKey` equality made all three
  mutations GREEN.
- `public_open_can_cancel_proof_join_with_more_than_4096_retained_facts` was a real public-seam RED:
  8,193 retained directory facts with no missing interval completed `FlightProvider::open` instead
  of observing cancellation. The outer fact checkpoint made it cancel on the fourth observable
  post-marker checkpoint (the third proof-join checkpoint), with exactly two source-length reads.

### Fix-round-2 verification

- `cargo test -p qtrace-provider --test flight_events --test flight_differential --test flight_recovery`
  — exit 0; 46 passed.
- `cargo test -p qtrace-provider` — exit 0; 108 passed.
- `cargo clippy -p qtrace-provider --all-targets -- -D warnings` — exit 0.
- `cargo fmt --all -- --check` — exit 0.
- `python3 -m unittest scripts.tests.test_qtrace_ui_fixtures scripts.tests.test_trace_binary scripts.tests.test_flight_trace`
  — exit 0; 89 passed.
- `python3 qtrace-ui/tools/export_contract_fixtures.py --check` — exit 0.
- `git diff --check` — exit 0.

Rust fixture consumers and the Python fixture-mutating compatibility suite were run serially.

### Fix-round-2 commit

- This report's containing commit: `fix(qtrace-ui): verify flight event identity` (final hash
  reported in the task handoff).

### Fix-round-2 concerns

- No blocking concern. Keep the Python fixture compatibility suite serialized with Rust fixture
  consumers.
