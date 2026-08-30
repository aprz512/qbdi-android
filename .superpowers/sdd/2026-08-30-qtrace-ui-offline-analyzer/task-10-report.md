# Task 10 report: safe checksummed normalized-cache foundation

## Scope and interfaces

- Added the Task 10-only cache/store-view seam: `CacheIdentity`, `CacheManifest`,
  `SectionDescriptor`, `CacheWriter`, `CacheReader`, `OwnedStoreView`, `MappedStoreView`,
  `StoreView`, and typed `CacheOpen::Rebuild(RebuildReason)`.
- `OwnedStoreView` and the persisted sample contract contain only the minimum extensible event-key
  and event-kind columns needed to prove safe wire/view equivalence. Task 11 normalized columns,
  eager indexes, provider normalization, and query behavior were not started.
- `MappedStoreView` deliberately uses a held regular-file descriptor plus bounded exact `pread`
  rather than `memmap2`: the available mmap entry point requires `unsafe`, which Task 10 forbids.
  The public read-only `StoreView` seam remains unchanged for a future safe backing implementation.

## Wire contract

The fixed header is exactly 64 bytes:

| Bytes | Encoding | Meaning |
|---:|---|---|
| `0..8` | bytes | magic `QTCACHE\0` |
| `8..12` | LE `u32` | cache schema |
| `12..14` | LE `u16` | exact header size, `64` |
| `14..16` | zero bytes | reserved |
| `16..24` | LE `u64` | manifest offset |
| `24..32` | LE `u64` | manifest length |
| `32..64` | 32 bytes | SHA-256 of the exact manifest bytes |

The deterministic manifest is canonical sorted-key JSON with `deny_unknown_fields`. Its identity
covers the complete artifact SHA-256, source format/major/minor/features, cache schema, analyzer
version, explicit little-endian marker, layout version, and build-option SHA-256. Section
descriptors carry a unique bounded name, offset, length, alignment, element size, and SHA-256.

The minimal explicit sections are:

| Section | Element | Alignment | Contract |
|---|---:|---:|---|
| `event_kinds.v1` | 1 byte | 1 | closed numeric mapping for every provider `EventKind` |
| zero padding | n/a | next section | every alignment gap byte must be zero |
| `event_keys.v1` | 80 bytes | 8 | stable event key below |

The 80-byte event-key element is `[artifact SHA-256:32][timeline:u64][record ordinal:u64]`
`[source offset:u64][sequence value:u64][tid value:u32][presence flags:u8][reserved zero:11]`.
All numbers are copied from exact byte arrays and decoded with `from_le_bytes`. Absent optional
values must have both a clear presence bit and a zero value. No native struct serialization,
`transmute`, `align_to`, unchecked indexing, or `unsafe` is used.

## Reader and limit invariants

- Opens the XDG root, `qtrace-ui`, digest directory, and `index.qtc` descriptor-relative with
  `O_NOFOLLOW|O_CLOEXEC`; the leaf also uses `O_NONBLOCK` before its regular-file type check.
- Authorizes path work before path I/O, bounds the root to 4,096 bytes/256 components, and requires
  exact private `0700` on the XDG root's final component, application directory, and digest
  directory without imposing `0700` on `/`, `/home`, `/tmp`, or other ancestors. Binding proofs
  include `(dev, ino, type, permission bits)`, and the final cache must remain regular mode `0600`.
- Reads the header on the stack, checks manifest offset+length before allocation, limits the
  manifest to 1 MiB, authorizes resident/input bytes before fallible allocation/read, and requires
  the manifest to end exactly at file EOF.
- Validates header schema/size/reserved, manifest SHA/canonical JSON/full identity, section count
  and names, range order/non-overlap, checked end offsets, alignment, zero padding,
  `length % element_size`, every section SHA, known event payload values, and equal known-column
  row counts before returning a view.
- SHA and payload validation stream in 64,000-byte chunks with periodic guard checkpoints.
  Corrupt lengths cannot request a large allocation or read outside the held file.
- Known-section descriptors are an exact contract, not only a generic self-consistent one:
  `event_kinds.v1` requires `(alignment=1, element_size=1)` and `event_keys.v1` requires
  `(alignment=8, element_size=80)`. Re-signing a weaker/different alignment is a typed rebuild.
- Manifest input, typed JSON materialization, and canonical re-encoding are charged together before
  allocation. `EMFILE`, `ENFILE`, `ENOMEM`, and fallible reserve failures map to the stable control
  code `control.resource_exhausted`; permission, missing, unsafe-path, and ordinary I/O classes stay
  distinct and are never converted to `Rebuild`.
- Captures `(dev, ino, size, mtime, ctime)` and the complete directory binding. A stable invalid
  file returns typed `Rebuild`; cancellation/budget/path/resource and any identity race propagate
  as control errors instead of being downgraded to rebuild.
- Each bounded view access rechecks the held file identity, performs checked row/offset arithmetic,
  reads the exact bytes with `pread`, decodes LE fields, then rechecks identity.

## Publication state machine

1. Charge the actual writer peak before path I/O: owned key/kind capacities, identity text,
   manifest capacity, two 64,000-byte streaming buffers, and fixed bookkeeping. Sections are then
   streamed directly to the temp with incremental SHA-256; there is no second whole-cache `Vec`.
2. Securely open/create the XDG path and acquire the digest-local `.publish.lock`. The lock is a
   no-follow regular mode-`0600` leaf created with `O_EXCL`, held with exclusive Linux `flock`, and
   revalidated by descriptor and name before destructive operations. All library builders for the
   digest serialize temp cleanup, rename/exchange, rollback, and directory sync under this lock.
3. Create a cryptographically random same-directory `.tmp` with
   `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, force mode `0600`, and establish cleanup ownership
   immediately. Injected first-`fstat`, `fchmod`, and second-`fstat` failures leave zero temp names.
4. Write placeholder header and streamed sections. **Checkpoint 1** sees sections only. Write the
   canonical manifest; **Checkpoint 2** sees manifest plus placeholder header. Finalize the exact
   header, `fsync` the file, then **Checkpoint 3** sees a durable complete temp.
5. Under the lock, verify bindings and classify the prior final as `Missing`, `Valid`, or
   same-identity `Corrupt`. Foreign identity, special/symlink/unrecognized leaf, wrong mode, or any
   binding ambiguity fails closed without replacement.
6. `Missing` uses `renameat2(NOREPLACE)`; `Corrupt` uses `renameat2(EXCHANGE)` while retaining the
   exact displaced identity and staging name. **Checkpoint 4 is genuinely after this atomic name
   change and before parent-directory fsync.** `Valid` removes only the verified owned temp and
   adopts the complete winner.
7. A checkpoint-4 control error or external directory-binding failure enters verified rollback in
   the held directory FD. Missing rollback unlinks only if final still equals the builder inode.
   Corrupt rollback first requires final=builder and staging=exact displaced, revalidates the lock,
   exchanges back, proves both resulting bindings, and removes only the restored builder temp.
   Rollback then fsyncs the held directory; only full rollback+fsync returns the original
   `NoVisibleFinal` error.
8. Success fsyncs the rename/exchange. Corrupt replacement then removes the verified displaced
   inode and fsyncs that cleanup. A commit-fsync failure attempts the same verified rollback. If an
   operand, lock, or rollback fsync is ambiguous, no further destructive action occurs and the
   result is `VisibleDurabilityUncertain` with all questionable objects preserved.

| Prior state | Post-rename names | Checkpoint-4/failure rollback | Successful commit |
|---|---|---|---|
| Missing | `final=own`, no staging | prove `final=own`, unlink, fsync dir | fsync dir |
| Same-ID corrupt | `final=own`, `staging=displaced` | prove both+lock, exchange back, prove both, unlink own staging, fsync | fsync exchange, unlink exact displaced, fsync cleanup |
| Valid | unchanged valid final, owned staging | no rename; verified owned-temp cleanup | adopt existing winner |

Linux same-UID processes are not an isolation boundary: `flock` is cooperative rather than a
kernel-enforced pathname capability. The guarantee is mandatory for all qtrace-store builders;
an uncooperative same-UID process can still mutate names. Every mutation detected at a checkpoint
or binding proof is handled conservatively: do not unlink/exchange an unexpected inode, preserve
the foreign object, and return identity conflict or uncertain visibility. Readers do not take the
lock and can observe only the prior complete file, the new complete file, or missing—not a partial
temp.

## TDD evidence

### Initial RED

```text
cd qtrace-ui
cargo test -p qtrace-store --test cache_format --test cache_publication
```

Exit 101. Both behavior targets failed to compile because `CacheIdentity`, `CacheReader`,
`CacheWriter`, the store views, and typed rebuild interfaces did not exist. There was no fixture or
assertion setup failure.

### Hardening RED -> GREEN

- A wire-padding test failed because the first layout exercised no alignment gap. The layout now
  contains explicit zero padding and the reader rejects a modified padding byte.
- A publication-stage snapshot failed because periodic encode checks were indistinguishable from
  the four publication checkpoints and the temp initially received a final header. Periodic work
  now carries nonzero deltas; the four zero-delta checkpoints observe sections, manifest with zero
  header, fsynced final header, and pre-rename state in that order.
- After recomputing both section and manifest SHA values, illegal event kinds, event-key reserved
  bytes, artifact identity, and nonzero absent optional values were accepted. Known section payloads
  are now completely validated before a view is returned.
- A cancelled reader with a symlinked cache root returned `cache.path_escape`, proving path I/O ran
  before authorization. Path proof allocation and traversal are now authorized first; the exact
  counterexample returns `job.cancelled` without following or touching the path.
- A section mutation during reader validation returned `Rebuild(Section("checksum"))`. Rebuild is
  now returned only after the cloned held descriptor and directory binding still match the initial
  identity; the race returns `cache.identity_changed`.

### Independent-review findings: RED -> GREEN

| Finding | RED/attack evidence | GREEN behavior |
|---|---|---|
| I1 known alignment | Re-signed keys alignment `8→1` returned `Ready` (`corrupt cache was accepted`) | Keys require 8/80 and kinds 1/1; both re-signed mutations return `Rebuild(Section("known alignment"))` |
| I2 post-rename checkpoint | Checkpoint 4 observed no final because it ran before rename | Checkpoint 4 observes complete final; Missing cancel removes own final, Corrupt cancel restores the exact displaced inode and bytes |
| I3 cleanup race | A no-cancel hook replaced final after rename and the intermediate fix incorrectly returned `Published` | Digest lock covers cleanup and pre/post-fsync binding proofs; the competitor is preserved and result is `VisibleDurabilityUncertain` |
| I4 exchange rollback | Replacing the displaced staging operand could feed a foreign inode into a second exchange | Rollback proves final, staging, lock, and held directory; foreign staging stays out of final and is not deleted |
| I5 temp setup leak | Original open→`fchmod`/`fstat` `?` paths had no ownership cleanup | cfg(test) syscall-fault harness injects both `fstat` positions and `fchmod`; every case leaves zero `.tmp` |
| I6 modes | Root `0755` and app/digest chmod drift were accepted | Only root-final/app/digest require exact `0700`; mode enters every binding proof; temp/final/lock require `0600` |
| I7 resources | Allocation and resource errno paths collapsed into `cache.io`/path classes | Central mapping produces `control.resource_exhausted`; permission and ordinary I/O injection tests remain distinct |
| I8 resident peak | A 4,096-row writer passed a 1.5 MiB threshold despite a larger live peak | One pre-I/O peak charge rejects it; streaming removes keys/kinds/final-byte duplication and uses fallible manifest allocation |

The directory-fsync harness additionally proves the publication-state distinction: one injected
commit fsync failure rolls back and durably syncs, returning the original `cache.io` with
`NoVisibleFinal`; a second injected rollback-fsync failure returns
`VisibleDurabilityUncertain` rather than making a false no-visible claim.

### Focused GREEN

The final focused suites pass 29 integration tests: 11 format/identity/corruption/view tests and 18
publication/path/lock/race/cancellation tests. Seven store unit tests include temp setup faults,
directory-fsync outcomes, and resource errno/allocation mapping. Publication abort coverage runs
both `Cancelled` and `BudgetExceeded` at all four checkpoints; checkpoint 4 is post-rename and its
verified rollback leaves no builder final/temp when `NoVisibleFinal` is reported.

## Verification

- `cargo test -p qtrace-store --test cache_format --test cache_publication` — passed, 29/29.
- `cargo test -p qtrace-store` — passed, 83/83 (7 unit + 76 integration).
- `cargo test -p qtrace-provider` — passed, 122 tests plus one intentional ignored isolated child
  entry point.
- `cargo clippy -p qtrace-store -p qtrace-provider --all-targets -- -D warnings` — passed.
- `cargo fmt --all -- --check` — passed.
- Production cache/layout scan found no `unsafe`, `transmute`, `align_to`, unchecked access,
  `canonicalize`, path-based `File::open`, `unwrap`, `expect`, or `panic!`.
- `git diff --check` — passed before the report; rerun in the final gate after the report.
- Python fixture/exporter tests were not rerun because Task 10 changes only the Rust cache/store
  implementation and its tests; it does not change Provider schemas, fixtures, or Python consumers.
  The Task 9 Python/exporter results remain the latest serial fixture-history gate.

## Files

- `qtrace-ui/Cargo.lock`
- `qtrace-ui/crates/qtrace-store/Cargo.toml`
- `qtrace-ui/crates/qtrace-store/src/lib.rs`
- `qtrace-ui/crates/qtrace-store/src/layout.rs`
- `qtrace-ui/crates/qtrace-store/src/cache/{mod,manifest,reader,writer}.rs`
- `qtrace-ui/crates/qtrace-store/tests/{cache_format,cache_publication}.rs`
- `.superpowers/sdd/2026-08-30-qtrace-ui-offline-analyzer/task-10-report.md`

## Environment and deferrals

- No network, administrator access, or Tauri/WebKitGTK dependency was needed.
- Safe mmap was not available without violating the no-`unsafe` contract, so the mapped-named view
  uses safe held-FD `pread`; this is an implementation choice, not a correctness deferral.
- Task 11 owns the complete normalized columns, eager indexes, provider-to-store build, and scale
  performance work. Task 17 owns UI/Tauri path authorization. Neither was started.
- No Task 10 correctness or security item is deferred.

## Commit

- `feat(qtrace-ui): add safe normalized cache` (exact hash in the task handoff because a commit
  cannot contain its own hash).
- Review-fix follow-up: `fix(qtrace-ui): harden cache publication` (exact hash in handoff).
