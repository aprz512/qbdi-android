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
  exact private `0700` application/digest directories.
- Reads the header on the stack, checks manifest offset+length before allocation, limits the
  manifest to 1 MiB, authorizes resident/input bytes before fallible allocation/read, and requires
  the manifest to end exactly at file EOF.
- Validates header schema/size/reserved, manifest SHA/canonical JSON/full identity, section count
  and names, range order/non-overlap, checked end offsets, alignment, zero padding,
  `length % element_size`, every section SHA, known event payload values, and equal known-column
  row counts before returning a view.
- SHA and payload validation stream in 64,000-byte chunks with periodic guard checkpoints.
  Corrupt lengths cannot request a large allocation or read outside the held file.
- Captures `(dev, ino, size, mtime, ctime)` and the complete directory binding. A stable invalid
  file returns typed `Rebuild`; cancellation/budget/path/resource and any identity race propagate
  as control errors instead of being downgraded to rebuild.
- Each bounded view access rechecks the held file identity, performs checked row/offset arithmetic,
  reads the exact bytes with `pread`, decodes LE fields, then rechecks identity.

## Publication state machine

1. Authorize/cache-encode deterministic bytes; securely open/create the XDG path component by
   component and hold its complete binding proof.
2. Create a cryptographically random same-directory `.tmp` with
   `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, force mode `0600`, and retain its `(dev, ino, type)`.
3. Write a zero placeholder header and all sections. **Checkpoint 1** observes sections only.
4. Write the manifest. **Checkpoint 2** is immediately before final header seek/write.
5. Finalize the header and `fsync` the temp file. **Checkpoint 3** observes a durable complete temp.
6. Revalidate the directory and classify any final leaf. **Checkpoint 4** is the final cancellation
   and failure point before any rename/directory-sync commit.
7. Missing final: `renameat2(NOREPLACE)`. Valid same-identity winner: remove only the verified owned
   temp and adopt the winner. Recognizable same-identity corrupt final: `renameat2(EXCHANGE)`, verify
   the displaced inode is exactly the previously inspected old leaf, then unlink that displaced
   inode. A different identity, special leaf, symlink, or unrecognizable regular file fails closed.
8. Revalidate the directory binding and `fsync` the parent directory. A failure after a successful
   rename/exchange is returned as `VisibleDurabilityUncertain`; it never claims that no final is
   visible. All pre-rename cancellation/budget/path failures leave no final from this builder.

Cleanup only calls descriptor-relative `unlinkat` after reopening the temporary name without
following and matching its recorded identity. It never deletes a final path, competitor temp, or
unverified object. Concurrent missing-cache builders race through `NOREPLACE`; a loser validates
and adopts the complete deterministic winner. Corrupt replacement uses exchange plus displaced
identity verification so a competing replacement is not silently overwritten.

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

### Focused GREEN

The final focused suites pass 19 tests: 10 format/identity/corruption/view tests and 9 publication,
path, race, cancellation, and concurrent-reader tests. Publication abort coverage runs both
`Cancelled` and `BudgetExceeded` at all four pre-rename checkpoints and observes no final or temp.

## Verification

- `cargo test -p qtrace-store --test cache_format --test cache_publication` — passed, 19/19.
- `cargo test -p qtrace-store --no-fail-fast` — passed, 69/69.
- `cargo test -p qtrace-provider --no-fail-fast` — passed, 121 tests with one intentional ignored
  isolated child entry point.
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
