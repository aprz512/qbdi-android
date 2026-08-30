# Task 9 report: immutable Linux-safe session loading

## Scope and interfaces

- Added `SessionLoader::open_report(AuthorizedPath, OpenPolicy, guard)` and
  `SessionLoader::open_artifact(AuthorizedPath, OpenPolicy, guard)` without entering Task 10 cache
  work or Task 17 UI/Tauri adapter work.
- Added immutable `SessionSource`, `ArtifactSource`, `ArtifactFailure`, metadata/warning and
  capability views. `ArtifactSource` retains an owned source descriptor and can reopen a guarded
  provider without resolving the pathname again.
- Added store-level `SourceIdentity`, containing the provider's complete digest/format/version/size
  identity plus the selected display path and Linux `(dev, ino, size, mtime, ctime)` identity.
  This adapts the plan's "full identity" requirement without changing the already-approved public
  `qtrace_provider::SourceIdentity` struct or its existing literal construction contract.
- Added QTRB timeline remapping at the store boundary. Each QTRB artifact has an independent
  session timeline, and reopened provider descriptors, event keys, and summaries use that timeline.
  Flight retains its approved artifact-local merged timeline and per-TID projection descriptors.
- Added strict schema-1 `SessionReport` parsing from the current `qtrace/report.py` root shape.
  Unknown, missing, duplicate, or non-schema-1 root fields fail the session. Successful artifact
  records require a bounded local path, lowercase 64-hex SHA-256, and positive destination size;
  records without a local path become bounded warnings and are never opened.

## Linux safety invariants

- Starts from `/` for absolute selections (or `.` for relative authorized selections), then opens
  every directory component using `rustix` `openat` with
  `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`.
- Accepts only `Component::Normal` artifact components and rejects absolute paths, `..`, `.`, empty
  components, embedded NUL, symlink parents/leaves, directories, sockets, and other special leaves.
- Opens leaves descriptor-relative with `O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC` and requires a
  regular-file `fstat` result. Linux ignores `O_NONBLOCK` for regular files, while a FIFO can no
  longer block before the type check. It never canonicalizes and then reopens a source, and never
  checks a path before a separate path-based open.
- Hashes through the held descriptor in fixed 64 KiB chunks after `WorkGuard` authorization. It
  compares `(dev, ino, size, mtime, ctime)` before/after and reopens every selected-root, parent,
  and leaf binding from held directory descriptors to detect rename, regular replacement, and
  symlink replacement races.
- Rechecks the held identity after provider probing, before provider reopen, after provider open,
  and before publishing a drained provider summary. Same-size writes, growth, shrink, path/root
  replacement, and streaming-time drift fail with typed errors. Direct FD reads compare the stored
  identity, so a mutated inode cannot be read under an old digest.
- The report is limited to 1 MiB before JSON materialization; artifact/path/warning collections and
  strings have explicit limits. File hashing is streaming. Store timeline copies are authorized and
  fallibly allocated. Every `control.*` error is session-fatal through provider, metadata,
  unsupported-artifact, hashing, and timeline-remapping branches; a success-shaped session is
  never published after cancellation, budget failure, resource exhaustion, or a future global
  control error.

## Manifest and artifact behavior

- Provider inputs are exactly `.trace.bin`, `.trace.bin.lz4`, and `.flight.bin`.
- `.metrics`, `.crash`, `.trace.txt`, `.trace.txt.lz4`, `.merged.trace.txt`,
  `.tid-<tid>.trace.txt`, and `.flight.json` are verified metadata, not analysis sources.
- Unknown local artifacts are verified for containment/identity, then isolated as
  `source.format_unsupported`; healthy timelines remain usable.
- Size/hash/provider failures are artifact-local after a valid root manifest. Containment failures
  are root failures. The checked truncated fixture is normalized to `source.qtrb.truncated`.
- Open failures retain evidence-based types: missing artifacts are isolated as `source.not_found`,
  missing reports are `session.report_missing`, permission failures are
  `source.permission_denied`, process/system descriptor or memory exhaustion is
  `control.resource_exhausted`, and other I/O remains `source.io`. Syntax, confirmed symlinks,
  special leaves, `ENOTDIR`, and rebinding failures remain `session.path_escape`.
- Single binary artifacts create a degraded session with explicit missing package, device, target,
  and effective-config capability warnings. Text and derived JSON selections are rejected.
- `EffectiveConfig` truth depends only on a nonempty `effective_config` object; tracer metadata does
  not impersonate configuration. Report selection is based on the descriptor-opened object kind,
  so a directory named `report.json/` opens its child manifest while a selected file must be the
  actual regular `report.json` leaf.

## TDD evidence

### Initial RED

```text
cd qtrace-ui
cargo test -p qtrace-store --test session_open --test path_security
```

Exit 101. Both behavior targets failed to compile because `AuthorizedPath`, `OpenPolicy`,
`SessionLoader`, `SessionSource`, `ArtifactFormat`, and `SessionCapability` did not exist. There
were no fixture or assertion setup failures.

### Security/domain hardening REDs

- Parent-directory rename to symlink: the loader incorrectly returned a successful session because
  it only rebound the leaf relative to the already-held parent descriptor.
- Selected-root rename to symlink: the loader incorrectly returned a successful session because it
  had no proof chain back to `/`.
- QTRB provider reopen: the second artifact returned `TimelineId(0)` instead of its independent
  `TimelineId(1)`.
- Store timeline allocation guard: provider reopen succeeded even when timeline-node work was
  rejected.
- Same-size write during provider probe: the session had zero failures instead of one typed
  `source.identity_changed` failure.
- Mutation after session open and while streaming: provider reopen and cursor `finish()` both
  incorrectly succeeded under the old digest identity.
- Direct FD read after mutation returned the full bytes instead of rejecting the old identity.

Each counterexample was run and observed failing before its minimum production correction. The
corresponding focused commands then passed.

### Independent security review RED -> GREEN

- FIFO artifact leaf: an isolated test child remained blocked after 500 ms on `openat(O_RDONLY)`;
  its parent killed and reaped it. Adding Linux `O_NONBLOCK` made artifact and selected-report FIFO
  children return immediate stable `session.path_escape` errors without a residual process.
- Control propagation: exact-Nth and semantic guards at the artifact checkpoint, hash input,
  provider input, timeline allocation, metadata verification, and unknown-artifact verification
  returned `Ok(SessionSource)` containing `control.*` failures. The fatal policy now propagates
  every `control.*`; `open_artifact` is also covered at its first three guard calls. Ordinary
  missing/format/provider errors remain isolated.
- Errno classification: missing artifacts and reports both produced root `session.path_escape`.
  They now produce artifact-local `source.not_found` and root `session.report_missing`; a
  deterministic unprivileged permission test covers `source.permission_denied`, while injected
  errno mapping covers permission, resource, escape, missing, and generic I/O classes. Rebinding
  errors remain containment failures except global resource exhaustion.
- Capability truth: a tracer-only report incorrectly advertised `EffectiveConfig`; empty and
  nonempty `effective_config` cases now produce false and true respectively.
- Selected object kind: a directory named `report.json/` was opened as a leaf and rejected. The
  descriptor-relative directory attempt now selects its child manifest; existing file/directory
  selection and symlink/race tests remain green.

### Focused GREEN

The final focused store suite passes 45 tests: 2 unit policy tests, 19 session/import behaviors, and
24 descriptor/path security behaviors. It includes checked fixtures, strict root parsing, all path
component cases, directory/socket/symlink leaves, regular/symlink/parent/root replacement races,
grow/shrink and same-size drift, FD retention, compressed QTRB, provider timeline remapping, guard
rejection, metadata classification, artifact isolation, FIFO nonblocking behavior, typed errno
handling, selected-object-kind handling, truthful capabilities, and degraded single-file behavior.

## Verification

- `cargo test -p qtrace-store --no-fail-fast` — passed, 45/45.
- `cargo clippy -p qtrace-store --all-targets -- -D warnings` — passed.
- `cargo fmt --all -- --check` — passed.
- `cargo test -p qtrace-provider --no-fail-fast` — passed, 122 tests with one intentional ignored
  isolated child entry point.
- `python3 qtrace-ui/tools/export_contract_fixtures.py --check` — passed before and after Python
  consumers.
- `python3 -m unittest scripts.tests.test_qtrace_report scripts.tests.test_qtrace_artifacts
  scripts.tests.test_qtrace_ui_fixtures scripts.tests.test_trace_binary
  scripts.tests.test_flight_trace -v` — passed, 181/181.
- Rust fixture consumers and the fixture-mutating Python suite were run serially.
- Production store scan found no `unsafe`, `unwrap`, `expect`, `panic!`, `canonicalize`, or
  path-based `File::open` use.
- `git diff --check` — passed.

## Files

- `qtrace-ui/Cargo.lock`
- `qtrace-ui/crates/qtrace-store/Cargo.toml`
- `qtrace-ui/crates/qtrace-store/src/{lib,identity,manifest,secure_path,session}.rs`
- `qtrace-ui/crates/qtrace-store/tests/{session_open,path_security}.rs`
- `.superpowers/sdd/2026-08-30-qtrace-ui-offline-analyzer/task-9-report.md`

## Environment and deferrals

- No network or administrator dependency was required. The previously documented host WebKitGTK
  limitation affects full Tauri workspace checks, not this store/provider task.
- Task 10 normalized cache and Task 17 UI/Tauri authorization adapter were not started.
- No Task 9 correctness or security item is deferred.

## Commit

- Initial implementation: `c81ac4d250cf4842eab29baba05b6b9a29f80f8c`
  (`feat(qtrace-ui): load immutable trace sessions`).
- Security-review follow-up: `fix(qtrace-ui): harden session import boundaries` (exact hash in the
  task handoff because a commit cannot contain its own hash).
