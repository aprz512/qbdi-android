# Task 8 report: binary-provider property and fuzz hardening

## Summary

- Added bounded behavior/property tests for arbitrary QTRB, linked-LZ4/QTRB, and Flight bytes;
  truncation; and the required length, offset, count, flag, version, reference, checksum, commit
  token, fragment-order, UTF-8, and terminal-placement mutation classes.
- Closed a real QTRB source-identity gap: `open` now records the observed source length rather than
  trusting caller metadata, and the cursor rejects a length change before publishing its summary
  with stable code `source.identity_changed`.
- Added the Task 5 follow-up regression proving that two concatenated linked LZ4 frames do not
  share history. A second frame encoded against the first frame's dictionary is rejected as
  `source.qtrb.compression`.
- Added standalone `cargo-fuzz` targets for both public provider open/cursor paths, plus the public
  linked-LZ4 input path. The fuzz package has its own workspace and is excluded from the release
  workspace.
- Seeded all 12 checked QTRB fixtures and all 8 checked Flight fixtures. Each named corpus seed is
  a bounded selector expanded by `include_bytes!` to the real checked fixture; libFuzzer suffixes
  are interpreted as `(u16 offset, xor byte)` patches, so mutations exercise actual fixture wire
  bytes. Inputs without a selector go directly to the parsers. No fuzz target invokes Python.

## Scope and files

- `qtrace-ui/Cargo.toml`
- `qtrace-ui/Cargo.lock`
- `qtrace-ui/crates/qtrace-provider/Cargo.toml`
- `qtrace-ui/crates/qtrace-provider/src/qtrb/mod.rs`
- `qtrace-ui/crates/qtrace-provider/tests/provider_properties.rs`
- `qtrace-ui/crates/qtrace-provider/tests/qtrb_input.rs`
- `qtrace-ui/fuzz/{Cargo.toml,.gitignore}`
- `qtrace-ui/fuzz/fuzz_targets/{support,qtrb,flight}.rs`
- `qtrace-ui/fuzz/corpus/{qtrb,flight}/*`

No Task 9 product work was started. Task 24's length-aware raw-input performance optimization was
not needed for correctness and remains deferred.

## TDD evidence

### Initial RED

The first test-only property run exposed a real missing validation:

```text
cd qtrace-ui && cargo test -p qtrace-provider --test provider_properties
```

Exit 101. `qtrb_identity_uses_the_observed_source_length` observed caller-supplied `1` where the
actual checked fixture length was `530`. An earlier function-pointer type-inference compile issue
was test setup and is not counted as RED.

After recording the observed length, a second behavior-first test went RED:

```text
cargo test -p qtrace-provider --test provider_properties \
  qtrb_rejects_a_source_length_change_before_publishing_summary -- --exact
```

Exit 101. After the source length changed following the final emitted event, the cursor returned a
successful `ProviderSummary`; the expected typed identity error was absent.

### GREEN

The minimum implementation snapshots `ReadAtSource::len()` during `open`, uses it in
`SourceIdentity`, and rechecks it while closing the stream. The focused suite then returned exit 0:
10 passed, 0 failed. The final full provider run also includes these same 10 tests and is recorded
below.

The linked-frame regression was a Task 5 characterization/follow-up and passed on its first
runnable execution; it is not misreported as RED.

## Bounds and error contract

- Proptest generation: 64 cases per property; arbitrary byte vectors are `0..<16,384` bytes.
  Seven generated properties plus three exact behavior tests complete in about 0.18 seconds on
  this host, keeping the suite suitable for CI.
- Provider `WorkGuard`: 16 MiB input, 16 MiB decompressed, 100,000 events, 100,000 nodes, 100,000
  rows, 32 MiB charged resident bytes, and a one-second per-case deadline. Arithmetic is checked;
  over-budget work returns typed `OperationAbort`/`ProviderError`.
- The fuzz harness rejects inputs larger than 16 MiB before cloning or seed expansion. Parser
  success is fully drained through the public cursor; typed errors end that input normally, while
  panic/abort/hang remains a libFuzzer failure.
- Stable QTRB mutation assertions use exact error codes; arbitrary-byte assertions require the
  `source.*` or `control.*` family. Flight mutations that invalidate required superblock evidence
  must return exact `source.flight.superblock`; recoverable damage must remain explicitly
  `Damaged`, never falsely `Captured`.
- Fuzz-process RSS is a host/process observation, not the provider's 32 MiB resident-accounting
  budget. The final QTRB run ended at 67 MiB RSS and Flight at 126 MiB RSS; neither reported OOM.

## Verification

- `cargo fmt --all -- --check` — exit 0.
- `cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check` — exit 0.
- `cargo test -p qtrace-provider --no-fail-fast` — exit 0; 119 passed, 0 failed.
- `cargo clippy -p qtrace-provider --all-targets -- -D warnings` — exit 0.
- `cargo check --manifest-path fuzz/Cargo.toml --bins` — exit 0.
- `cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings` — exit 0.
- `cargo +nightly fuzz list --fuzz-dir fuzz` — exit 0; `flight`, `qtrb`.
- `cargo +nightly fuzz run qtrb --fuzz-dir fuzz -- -runs=10000` — exit 0; `#10000 DONE`,
  coverage 1269, features 2250, final RSS 67 MiB; no crash, timeout, or OOM.
- `cargo +nightly fuzz run flight --fuzz-dir fuzz -- -runs=10000` — exit 0; `#10000 DONE`,
  coverage 2824, features 5167, final RSS 126 MiB; no crash, timeout, or OOM.
- `python3 -m unittest scripts.tests.test_qtrace_ui_fixtures scripts.tests.test_trace_binary scripts.tests.test_flight_trace -v`
  — exit 0; 89 passed.
- `python3 qtrace-ui/tools/export_contract_fixtures.py --check` — exit 0 before and after the
  Python suite.
- `git diff --check` and `git diff --cached --check` — exit 0 before commit.

Rust fixture consumers and the fixture-mutating Python compatibility suite were run serially.

## Toolchain and environment

- Installed `nightly-x86_64-unknown-linux-gnu`, Rust 1.100.0 (2026-08-30), minimal profile.
- Installed `cargo-fuzz 0.13.2` with `cargo install cargo-fuzz --locked`.
- Both requested 10,000-run smokes completed; there is no fuzz-toolchain or host blocker to defer.
- Full desktop-workspace validation remains outside Task 8's provider scope and retains the
  previously documented host WebKitGTK/pkg-config limitation. Task 8's provider and standalone
  fuzz workspaces were both fully checked.

## Commit

- Containing commit: `test(qtrace-ui): harden binary providers` (exact hash is reported in the
  task handoff because a commit cannot embed its own hash).

## Concerns

- No blocking Task 8 concern remains.
- Keep Python fixture-mutating tests serialized with Rust fixture consumers in later tasks.
- Generated libFuzzer hash corpus entries, artifacts, coverage, target output, and the standalone
  fuzz lockfile are intentionally ignored; the 20 stable named seeds remain tracked.
