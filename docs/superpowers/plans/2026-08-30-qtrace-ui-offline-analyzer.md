# qtrace-ui Offline Analyzer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a Linux desktop qtrace-ui that opens immutable qtrace sessions, QTRB 1.0–1.2, and Flight v2 artifacts; builds safe reusable indexes; and provides truthful timeline, search, call-tree, register, memory, completeness, ELF-symbol, and local-annotation workflows at the approved scale.

**Architecture:** Add an independent `qtrace-ui/` Rust workspace with the fixed dependency direction `qtrace-provider → qtrace-store → qtrace-analysis → qtrace-service → Tauri adapter ↔ React`. Providers strictly decode typed binary facts, the store owns secure session import and content-addressed caches, analysis produces provenance-aware immutable results, the service owns budgets/jobs/DTOs, and React renders only bounded pages and viewport state.

**Tech Stack:** Rust 2024 edition (MSRV 1.85), Cargo, Tauri 2, React 19, TypeScript, Vite, Vitest, Testing Library, Playwright, SQLite via `rusqlite`, `object` for ELF, `lz4_flex`, `memmap2`, `sha2`, `serde`, `thiserror`, `tokio`, and Linux `rustix` file APIs. `Cargo.lock` and `package-lock.json` pin resolved dependency versions; Node 22 is the development and CI baseline.

## Global Constraints

- Implement only the approved scope in `docs/superpowers/specs/2026-08-30-qtrace-ui-design.md`; DEF/USE, slice, string extraction, Crypto detection, DWARF, IDA/Ghidra import, MCP, live capture, and non-Linux packaging remain out of scope.
- This is an independent implementation. Do not copy source, components, tests, assets, or styling from `imj01y/trace-ui`; its current Personal Use License is incompatible with a distributable implementation.
- QTRB 1.0–1.2 and Flight v2 binary artifacts are the facts. Conversion to text is allowed only inside test-oracle tooling and never in the production provider/store/analysis path.
- Preserve the dependency direction. Lower crates must not import higher crates; Tauri commands contain no query, indexing, replay, or call-tree logic; React contains no wire-format logic.
- Treat source artifacts and complete session directories as immutable. Put rebuildable caches under `${XDG_CACHE_HOME:-$HOME/.cache}/qtrace-ui/` and user annotations/settings under `${XDG_DATA_HOME:-$HOME/.local/share}/qtrace-ui/`.
- A QTRB artifact is one independent timeline. Do not invent cross-artifact global order. Flight uses captured `global_seq` for its merged timeline and retains per-TID projections.
- Every stable event key contains artifact SHA-256, timeline ID, source record ordinal, and source byte offset. For compressed QTRB, source byte offset means the decompressed QTRB stream offset. Sequence and TID are validation fields, not substitutes for the stable key.
- Preserve provenance exactly as `captured`, `derived`, `heuristic`, `unknown`, or `damaged`. Unknown bytes/registers never become zero, and damage is never collapsed into unknown.
- All source, cache, manifest, SQLite, ELF, and IPC inputs are untrusted. Reject unsupported versions/features, out-of-bounds lengths, path traversal, symlinks, special files, identity changes, and malformed UTF-8 with structured errors rather than panic.
- All long-running provider/store/analysis operations use cooperative cancellation, deadline, byte, event, node, row, and memory budgets. A cancelled or failed build never publishes cache or analysis output.
- Cache files use explicit little-endian encoding and checked byte access. Do not serialize native Rust structs or create unchecked typed mmap views.
- One invalid artifact is isolated after a valid root session report is loaded; invalid root identity/schema/path containment rejects the session. Cache corruption triggers rebuild; annotation failures roll back their SQLite transaction.
- Frontend memory is bounded: no full event arrays, no DOM row per event, no response merging across generation changes, and no cache whose weight grows with total trace length.
- Use red-green-refactor for every task. Run the focused failing test before implementation, the focused passing test after implementation, and the task-wide regression command before committing.
- Keep commits scoped to one task. Do not amend or squash another worker's commit; do not commit unrelated pre-existing changes.

## File Structure

```text
qtrace-ui/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── .nvmrc
├── fixtures/
│   ├── manifest.json
│   ├── qtrb/
│   ├── flight/
│   ├── sessions/
│   └── elf/
├── tools/
│   ├── export_contract_fixtures.py
│   ├── oracle.py
│   ├── generate_performance_fixtures.py
│   └── performance_gate.py
├── crates/
│   ├── qtrace-provider/src/{control,error,flight,model,qtrb,source}.rs
│   ├── qtrace-store/src/{annotations,cache,identity,index,layout,manifest,secure_path,session,symbols}.rs
│   ├── qtrace-analysis/src/{call_tree,filter,memory,provenance,registers,symbolize,timeline}.rs
│   └── qtrace-service/src/{budget,dto,error,jobs,service,workspace}.rs
├── src-tauri/
│   ├── capabilities/default.json
│   ├── src/{commands,main,state}.rs
│   ├── Cargo.toml
│   └── tauri.conf.json
└── src-web/
    ├── src/
    │   ├── api/
    │   ├── components/
    │   ├── state/
    │   ├── timeline/
    │   └── styles/
    ├── tests/e2e/
    ├── package.json
    └── vite.config.ts
```

---

### Task 1: Scaffold the Rust/Tauri/React workspace and repository gates

**Files:**
- Create: `scripts/tests/test_qtrace_ui_scaffold.py`
- Create: `qtrace-ui/Cargo.toml`
- Create: `qtrace-ui/rust-toolchain.toml`
- Create: `qtrace-ui/.nvmrc`
- Create: `qtrace-ui/crates/qtrace-provider/{Cargo.toml,src/lib.rs}`
- Create: `qtrace-ui/crates/qtrace-store/{Cargo.toml,src/lib.rs}`
- Create: `qtrace-ui/crates/qtrace-analysis/{Cargo.toml,src/lib.rs}`
- Create: `qtrace-ui/crates/qtrace-service/{Cargo.toml,src/lib.rs}`
- Create: `qtrace-ui/src-tauri/{Cargo.toml,build.rs,tauri.conf.json,src/main.rs}`
- Create: `qtrace-ui/src-tauri/capabilities/default.json`
- Create: `qtrace-ui/src-web/{package.json,package-lock.json,tsconfig.json,tsconfig.node.json,vite.config.ts,index.html}`
- Create: `qtrace-ui/src-web/eslint.config.js`
- Create: `qtrace-ui/src-web/src/{main.tsx,App.tsx,vite-env.d.ts}`
- Create: `qtrace-ui/src-web/src/test/setup.ts`
- Create: `qtrace-ui/src-web/src/styles/global.css`
- Modify: `.gitignore`

**Interfaces:**
- Produces a four-crate Rust workspace, one thin Tauri binary, and one independently testable React frontend.
- Pins the crate dependency graph to provider → store → analysis → service; `src-tauri` depends only on service plus Tauri.

- [ ] **Step 1: Write the failing scaffold contract**

Add `scripts/tests/test_qtrace_ui_scaffold.py` that parses TOML with `tomllib` and asserts:

```python
class QtraceUiScaffoldTests(unittest.TestCase):
    def test_workspace_has_the_approved_members_and_dependency_direction(self):
        root = Path(__file__).parents[2] / "qtrace-ui"
        workspace = tomllib.loads((root / "Cargo.toml").read_text())
        self.assertEqual(
            [
                "crates/qtrace-provider",
                "crates/qtrace-store",
                "crates/qtrace-analysis",
                "crates/qtrace-service",
                "src-tauri",
            ],
            workspace["workspace"]["members"],
        )
        manifests = {
            name: tomllib.loads((root / path / "Cargo.toml").read_text())
            for name, path in {
                "provider": "crates/qtrace-provider",
                "store": "crates/qtrace-store",
                "analysis": "crates/qtrace-analysis",
                "service": "crates/qtrace-service",
            }.items()
        }
        self.assertNotIn("qtrace-store", manifests["provider"].get("dependencies", {}))
        self.assertIn("qtrace-provider", manifests["store"]["dependencies"])
        self.assertIn("qtrace-store", manifests["analysis"]["dependencies"])
        self.assertIn("qtrace-analysis", manifests["service"]["dependencies"])

    def test_frontend_scripts_cover_format_type_unit_and_e2e(self):
        package = json.loads((Path(__file__).parents[2] / "qtrace-ui/src-web/package.json").read_text())
        self.assertEqual({"dev", "build", "lint", "test", "e2e"}, set(package["scripts"]))
```

- [ ] **Step 2: Run the scaffold test and confirm it fails**

Run:

```bash
python3 -m unittest scripts.tests.test_qtrace_ui_scaffold -v
```

Expected: FAIL because `qtrace-ui/Cargo.toml` does not exist.

- [ ] **Step 3: Create the compiling workspace**

Use this root contract:

```toml
[workspace]
resolver = "2"
members = [
  "crates/qtrace-provider",
  "crates/qtrace-store",
  "crates/qtrace-analysis",
  "crates/qtrace-service",
  "src-tauri",
]

[workspace.package]
edition = "2024"
rust-version = "1.85"
license = "MIT"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
sha2 = "0.10"
hex = "0.4"
tempfile = "3"
proptest = "1"
```

Set each internal dependency to `{ path = "../qtrace-provider" }` or its exact sibling path and `version = "0.1.0"`. Set `rust-toolchain.toml` to stable with `rustfmt` and `clippy`, and `.nvmrc` to `22`. The frontend scripts are exactly:

```json
{
  "dev": "vite",
  "build": "tsc -b && vite build",
  "lint": "eslint . --max-warnings=0",
  "test": "vitest run",
  "e2e": "playwright test"
}
```

Use React 19, `@vitejs/plugin-react`, TypeScript, ESLint flat config, Vitest with jsdom and `src/test/setup.ts`, Testing Library, Playwright, and `@tauri-apps/api`/`@tauri-apps/cli` major 2. Configure Tauri 2 with `beforeDevCommand`/`beforeBuildCommand` running in `src-web`, `devUrl=http://localhost:1420`, and `frontendDist=../src-web/dist`. The initial app renders only `qtrace-ui` and `No workspace open`.

Append these exact ignore rules:

```gitignore
qtrace-ui/target/
qtrace-ui/src-web/node_modules/
qtrace-ui/src-web/dist/
qtrace-ui/src-web/test-results/
qtrace-ui/src-web/playwright-report/
qtrace-ui-performance-evidence/
```

- [ ] **Step 4: Install locked frontend dependencies and run focused gates**

Run:

```bash
cd qtrace-ui && cargo check --workspace
cd qtrace-ui/src-web && npm install && npm run build
cd ../.. && python3 -m unittest scripts.tests.test_qtrace_ui_scaffold -v
```

Expected: all commands exit 0 and `package-lock.json` is created.

- [ ] **Step 5: Commit the scaffold**

```bash
git add .gitignore scripts/tests/test_qtrace_ui_scaffold.py qtrace-ui
git commit -m "feat(qtrace-ui): scaffold desktop workspace"
```

---

### Task 2: Define provider-wide identity, provenance, capability, error, and budget contracts

**Files:**
- Create: `qtrace-ui/crates/qtrace-provider/src/model.rs`
- Create: `qtrace-ui/crates/qtrace-provider/src/error.rs`
- Create: `qtrace-ui/crates/qtrace-provider/src/control.rs`
- Create: `qtrace-ui/crates/qtrace-provider/src/source.rs`
- Modify: `qtrace-ui/crates/qtrace-provider/src/lib.rs`
- Create: `qtrace-ui/crates/qtrace-provider/tests/model_contract.rs`

**Interfaces:**
- Produces `ArtifactDigest`, `TimelineId`, `EventKey`, `EventKind`, `EventRecord`, `EventPayload`, `Provenance`, `ProviderCapabilities`, `CompletenessRange`, `ProviderSummary`, `TraceProvider`, `EventCursor`, `ReadAtSource`, `WorkGuard`, and `ProviderError`.
- `ProviderError` exposes stable `code`, `stage`, optional source coordinate, `retryable`, and bounded single-line `detail`.

- [ ] **Step 1: Write failing identity/provenance/capability tests**

Cover exact identity and truthfulness behavior:

```rust
#[test]
fn event_identity_does_not_depend_on_visible_row_or_optional_sequence() {
    let key = EventKey::new(digest(0x11), TimelineId(7), 19, 0x240, None, Some(42));
    assert_eq!(key.record_ordinal, 19);
    assert_eq!(key.source_offset, 0x240);
    assert_eq!(key.sequence, None);
    assert_eq!(key.tid, Some(42));
}

#[test]
fn provenance_keeps_unknown_and_damaged_distinct() {
    assert_ne!(Provenance::Unknown, Provenance::Damaged);
    assert_eq!(serde_json::to_string(&Provenance::Captured).unwrap(), "\"captured\"");
}

#[test]
fn capabilities_are_explicit_not_inferred_from_nullable_data() {
    let caps = ProviderCapabilities::qtrb_register_observations();
    assert!(caps.per_thread_ordering);
    assert!(caps.register_read_write_observation);
    assert!(!caps.global_ordering);
    assert!(!caps.full_register_checkpoint);
}
```

Also test all `EventKind` values, inclusive sequence ranges through `u64::MAX`, half-open source-byte ranges, SHA-256 hex round-trip, error-detail newline removal/512-byte bound, `ByteSource` exact short-read errors, and a fake `WorkGuard` abort after a byte/event limit.

- [ ] **Step 2: Run the focused test and confirm missing types**

```bash
cd qtrace-ui && cargo test -p qtrace-provider --test model_contract
```

Expected: FAIL with unresolved imports from `qtrace_provider`.

- [ ] **Step 3: Implement the shared contracts**

Use these public shapes:

```rust
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance { Captured, Derived, Heuristic, Unknown, Damaged }

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct EventKey {
    pub artifact: ArtifactDigest,
    pub timeline: TimelineId,
    pub record_ordinal: u64,
    pub source_offset: u64,
    pub sequence: Option<u64>,
    pub tid: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCapabilities {
    pub global_ordering: bool,
    pub per_thread_ordering: bool,
    pub full_register_checkpoint: bool,
    pub register_read_write_observation: bool,
    pub memory_metadata: bool,
    pub memory_before_after: bool,
    pub lifecycle: bool,
    pub signal_and_termination: bool,
    pub loss_and_damage_ranges: bool,
}

pub trait WorkGuard: Send + Sync {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort>;
}

pub trait ReadAtSource: Send + Sync {
    fn len(&self) -> u64;
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), ProviderError>;
}

pub trait EventCursor {
    fn next_event(&mut self, guard: &dyn WorkGuard) -> Result<Option<EventRecord>, ProviderError>;
    fn finish(self: Box<Self>) -> Result<ProviderSummary, ProviderError>;
}

pub trait TraceProvider: Send + Sync {
    fn identity(&self) -> &SourceIdentity;
    fn capabilities(&self) -> &ProviderCapabilities;
    fn timelines(&self) -> &[TimelineDescriptor];
    fn into_cursor(self: Box<Self>) -> Result<Box<dyn EventCursor>, ProviderError>;
}
```

`EventPayload` is a closed enum covering begin metadata, module definition, instruction definition, instruction, memory, semantic call/rule/error, thread/lifecycle, syscall, signal, signal-handler boundary, termination, discontinuity, and opaque optional record. Store raw bounded blobs only where the wire permits them; do not add a text-line payload.

The provider cursor is deliberately one-shot so compressed QTRB can remain streaming. `ProviderSummary` is available only after `next_event` has returned `None` and `finish` is called; early `finish` returns `source.stream_not_drained`. It contains final timelines, termination, counters, and completeness. Tests may use a `collect_provider` helper that drains the cursor and returns `(events, ProviderSummary)`; production indexing drains the same cursor directly into store columns.

Represent captured sequence coverage as inclusive `{first,last}` so a range ending at `u64::MAX` is expressible without overflow. Represent source-byte and memory-address ranges as checked half-open `{start,end_exclusive}`. `CompletenessRange` carries the range domain explicitly; never convert an inclusive maximum sequence into `last + 1`.

Implement `ProviderError::new` so its detail replaces CR/LF with spaces and truncates at a UTF-8 boundary to 512 bytes. `WorkDelta` has independent `input_bytes`, `decompressed_bytes`, `events`, `nodes`, `rows`, and `resident_bytes` counters; guards receive deltas at least every 4,096 records or 4 MiB, whichever comes first.

- [ ] **Step 4: Run provider tests and static checks**

```bash
cd qtrace-ui && cargo test -p qtrace-provider --test model_contract
cargo fmt --all --check
cargo clippy -p qtrace-provider --all-targets -- -D warnings
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit the provider contracts**

```bash
git add qtrace-ui/crates/qtrace-provider
git commit -m "feat(qtrace-ui): define provider contracts"
```

---

### Task 3: Export deterministic compatibility fixtures and Python differential oracles

**Files:**
- Create: `qtrace-ui/tools/export_contract_fixtures.py`
- Create: `qtrace-ui/tools/oracle.py`
- Create: `qtrace-ui/fixtures/README.md`
- Create: `qtrace-ui/fixtures/manifest.json`
- Create: `qtrace-ui/fixtures/qtrb/*`
- Create: `qtrace-ui/fixtures/flight/*`
- Create: `qtrace-ui/fixtures/sessions/*`
- Create: `qtrace-ui/fixtures/elf/*`
- Create: `scripts/tests/test_qtrace_ui_fixtures.py`

**Interfaces:**
- Uses the existing independently maintained builders in `scripts/tests/test_trace_binary.py` and `scripts/tests/test_flight_trace.py` only to generate test artifacts.
- Uses `scripts.trace_binary.convert_binary_stream` and `scripts.flight_trace.recover_flight` only in `qtrace-ui/tools/oracle.py`; production Rust code never imports or invokes Python.
- Produces a manifest containing fixture path, SHA-256, byte length, format/version, expected success/error class, and generator schema.

- [ ] **Step 1: Write the failing deterministic-fixture test**

```python
class QtraceUiFixtureTests(unittest.TestCase):
    def test_manifest_matches_every_generated_fixture(self):
        root = Path(__file__).parents[2]
        subprocess.run(
            [sys.executable, "qtrace-ui/tools/export_contract_fixtures.py", "--check"],
            cwd=root,
            check=True,
        )

    def test_oracle_is_bounded_and_rejects_unknown_modes(self):
        completed = subprocess.run(
            [sys.executable, "qtrace-ui/tools/oracle.py", "unknown", "missing.bin"],
            capture_output=True,
            cwd=Path(__file__).parents[2],
            timeout=5,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertLessEqual(len(completed.stderr), 4096)
```

- [ ] **Step 2: Run the fixture test and confirm it fails**

```bash
python3 -m unittest scripts.tests.test_qtrace_ui_fixtures -v
```

Expected: FAIL because the exporter and manifest are absent.

- [ ] **Step 3: Implement and run the deterministic exporter**

The exporter must emit these exact fixture classes:

- QTRB 1.0 completed with instruction/memory/call/rule/error;
- QTRB 1.1 chunked rule/error;
- QTRB 1.2 completed and stopped;
- QTRB 1.2 legal partial with complete records and no terminal;
- malformed QTRB: bad header, unsupported feature, undefined metadata, sequence gap, oversized record, truncated payload, record after terminal;
- Flight v2 two-thread complete recovery with full checkpoints/deltas, instruction, memory, lifecycle, syscall, signal-handler interval, and termination intent;
- Flight v2 active chunk, overwritten range, explicit coverage gap, checksum-damaged sealed chunk, stale directory, and incomplete fragment cases;
- one valid qtrace session with two QTRB artifacts plus one Flight artifact, one session with an isolated invalid artifact, and one root-invalid path-escape case; symlink/race cases are constructed dynamically by path-security tests;
- one minimal ELF64/AArch64 fixture with `.dynsym`, `.symtab`, and GNU build-id, deterministically assembled by the exporter from explicit ELF64 little-endian headers/section tables so `--check` is compiler-independent.

`--write` writes via unique temporary files and `os.replace`; `--check` regenerates into `tempfile.TemporaryDirectory`, then compares path sets, lengths, SHA-256 values, and bytes with the checked-in fixture tree. Refuse fixture files above 4 MiB so ordinary CI stays small.

For QTRB oracle mode, output one bounded JSON object containing exact converted text lines and converter statistics. For Flight oracle mode, serialize merged events, per-thread final registers, and the complete recovery summary with sorted keys. Reject source files above 8 MiB in this test-only tool.

- [ ] **Step 4: Verify fixtures and both existing oracles**

```bash
python3 qtrace-ui/tools/export_contract_fixtures.py --write
python3 -m unittest scripts.tests.test_qtrace_ui_fixtures scripts.tests.test_trace_binary scripts.tests.test_flight_trace -v
python3 qtrace-ui/tools/oracle.py qtrb qtrace-ui/fixtures/qtrb/v1.2-completed.bin >/tmp/qtrace-ui-qtrb-oracle.json
python3 qtrace-ui/tools/oracle.py flight qtrace-ui/fixtures/flight/v2-complete.bin >/tmp/qtrace-ui-flight-oracle.json
```

Expected: tests pass; both oracle commands exit 0 and emit one valid JSON document.

- [ ] **Step 5: Commit the compatibility corpus**

```bash
git add qtrace-ui/tools qtrace-ui/fixtures scripts/tests/test_qtrace_ui_fixtures.py
git commit -m "test(qtrace-ui): add binary compatibility corpus"
```

---

### Task 4: Implement strict QTRB 1.0–1.2 framing and lifecycle validation

**Files:**
- Create: `qtrace-ui/crates/qtrace-provider/src/qtrb/mod.rs`
- Create: `qtrace-ui/crates/qtrace-provider/src/qtrb/cursor.rs`
- Create: `qtrace-ui/crates/qtrace-provider/src/qtrb/wire.rs`
- Create: `qtrace-ui/crates/qtrace-provider/tests/qtrb_framing.rs`
- Modify: `qtrace-ui/crates/qtrace-provider/src/lib.rs`
- Modify: `qtrace-ui/crates/qtrace-provider/Cargo.toml`

**Interfaces:**
- Produces `QtrbProvider::open(reader, source_identity, OpenMode, guard)` and a streaming `EventCursor`.
- `OpenMode` is exactly `Sealed` or `RecoverablePartial`; sealed mode requires one successful `TRACE_END` or legal v1.2 `TRACE_STOP`, while recoverable partial mode accepts only complete records and exposes missing termination as completeness data.

- [ ] **Step 1: Write failing framing/version/lifecycle tests**

Use the checked-in corpus to assert:

```rust
#[test]
fn supports_exact_qtrb_minor_and_feature_matrix() {
    for name in ["v1.0-completed.bin", "v1.1-chunked.bin", "v1.2-completed.bin", "v1.2-stopped.bin"] {
        let provider = open_fixture(name, OpenMode::Sealed).unwrap();
        assert_eq!(provider.identity().format_major, 1);
    }
}

#[test]
fn partial_mode_never_invents_a_terminal() {
    let parsed = collect_fixture("v1.2-partial.bin", OpenMode::RecoverablePartial).unwrap();
    assert!(parsed.summary.completeness.iter().any(|range| range.cause == CompletenessCause::MissingTerminal));
    assert!(!parsed.events.iter().any(|event| event.kind == EventKind::Termination));
}

#[test]
fn required_unknown_features_fail_closed() {
    let error = open_malformed("unsupported-feature.bin").unwrap_err();
    assert_eq!(error.code, "source.version_unsupported");
}
```

Also cover exact 16-byte header validation, byte order, pointer width, profile, reserved bytes, record flags, payload maximums, short reads at every boundary, first-record/terminal ordering, duplicate definitions, undefined references, contiguous instruction sequence, terminal counter consistency, and records after terminal.

- [ ] **Step 2: Run the focused test and confirm failure**

```bash
cd qtrace-ui && cargo test -p qtrace-provider --test qtrb_framing
```

Expected: FAIL because `QtrbProvider` does not exist.

- [ ] **Step 3: Implement checked little-endian framing**

Implement a private cursor whose only primitive readers are checked `take`, `u8`, `u16_le`, `u32_le`, `u64_le`, `i64_le`, bounded UTF-8, and `finish`. Encode protocol constants from `tracer/src/main/cpp/events/binary_trace_format.h` independently in `wire.rs`; add a contract test that asserts all current numeric sizes and maximums.

Parse the stream in one pass while retaining only bounded dictionaries, fragment state, and the current event. Emit each logical event immediately to the indexing consumer. Reject:

- major other than 1;
- minor outside 0–2;
- minor/required-feature mismatch (`TRACE_STOP` requires minor 2 plus bit 0);
- unknown non-optional record types or flags;
- payload length above the record-type maximum before allocation;
- invalid UTF-8 after complete logical fragment reassembly;
- definition conflicts, missing references, sequence gaps, bad terminal metrics, or incomplete fragments.

Record the byte offset before each 8-byte record header and increment the source ordinal once per physical record. A logical chunked event uses the first fragment's offset/ordinal and stores all fragment offsets as bounded provenance detail.

- [ ] **Step 4: Run strict parser regressions**

```bash
cd qtrace-ui && cargo test -p qtrace-provider --test qtrb_framing
cargo test -p qtrace-provider
cargo clippy -p qtrace-provider --all-targets -- -D warnings
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit QTRB framing**

```bash
git add qtrace-ui/crates/qtrace-provider
git commit -m "feat(qtrace-ui): parse strict qtrb framing"
```

---

### Task 5: Decode typed QTRB events and bounded LZ4 streams

**Files:**
- Create: `qtrace-ui/crates/qtrace-provider/src/qtrb/events.rs`
- Create: `qtrace-ui/crates/qtrace-provider/src/qtrb/input.rs`
- Create: `qtrace-ui/crates/qtrace-provider/tests/qtrb_events.rs`
- Create: `qtrace-ui/crates/qtrace-provider/tests/qtrb_differential.rs`
- Modify: `qtrace-ui/crates/qtrace-provider/src/qtrb/mod.rs`
- Modify: `qtrace-ui/crates/qtrace-provider/Cargo.toml`

**Interfaces:**
- Produces typed instruction definitions, register observations, memory before/after bytes, semantic records, begin metadata, and terminal metrics.
- Accepts raw QTRB and LZ4 frames through `QtrbInput`; decompression is streaming, budgeted, and never writes an intermediate trace.

- [ ] **Step 1: Write failing typed-event and differential tests**

Test exact values from `v1.2-completed.bin`, including module-relative PC, opcode, mnemonic/operands, read-before values, write-after values, memory direction/value/before/after, and semantic strings. Add this invariant:

```rust
#[test]
fn unknown_memory_capture_is_not_an_empty_or_zero_capture() {
    let memory = first_uncaptured_memory("v1.0-completed.bin");
    assert_eq!(memory.before, CaptureBytes::NotCaptured);
    assert_eq!(memory.after, CaptureBytes::NotCaptured);
    assert_ne!(memory.before, CaptureBytes::Captured(Vec::new()));
}
```

For every valid QTRB fixture, invoke `python3 qtrace-ui/tools/oracle.py qtrb <path>`, render the Rust typed events with a test-only canonical renderer, and compare exact lines plus termination/instruction statistics. Add tests that split one raw stream at record boundaries into multiple concatenated `lz4_flex::frame::FrameEncoder` outputs, feed reads of 1–7 bytes, and recover the same typed event sequence; truncate each frame in turn and require a compression error.

- [ ] **Step 2: Run the focused tests and confirm failure**

```bash
cd qtrace-ui && cargo test -p qtrace-provider --test qtrb_events --test qtrb_differential
```

Expected: FAIL because event decoding and `QtrbInput` are absent.

- [ ] **Step 3: Implement complete typed decoding**

Represent registers by architectural slot and captured width, preserving W-register width separately from the containing X slot. Validate the definition mask population against instruction read/write counts. Preserve PC kinds and signed displacement without host-pointer casts. Decode memory capture states into:

```rust
pub enum CaptureBytes {
    NotCaptured,
    Unavailable,
    Captured(Vec<u8>),
}
```

Decode chunked CALL/RULE/ERROR by raw bytes first, validate contiguous indexes and stable metadata, then perform UTF-8 validation once. Retain unknown optional records (`type & 0x8000 != 0`) as bounded opaque payload with `Provenance::Captured`; reject unknown required records.

Implement a `ConcatenatedFrameReader` that opens one `lz4_flex::frame::FrameDecoder` per complete standard frame and continues at the exact next frame magic; existing qtrace artifacts may contain multiple concatenated frames. Put it behind a `CountingReader`, preserve one cumulative decompressed source offset across frames, and charge compressed input plus decompressed output to `WorkGuard`. Accept any positive number of complete frames; reject zero frames, a truncated frame, skippable/unknown frame type, or non-frame trailing bytes as `source.qtrb.compression`. Never shell out to `lz4`.

- [ ] **Step 4: Run typed, differential, and existing Python compatibility tests**

```bash
cd qtrace-ui && cargo test -p qtrace-provider --test qtrb_events --test qtrb_differential
cd .. && python3 -m unittest scripts.tests.test_trace_binary scripts.tests.test_lz4_frames -v
cd qtrace-ui && cargo test -p qtrace-provider
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit typed QTRB support**

```bash
git add qtrace-ui/crates/qtrace-provider
git commit -m "feat(qtrace-ui): decode typed qtrb events"
```

---

### Task 6: Implement Flight v2 physical recovery and completeness accounting

**Files:**
- Create: `qtrace-ui/crates/qtrace-provider/src/flight/mod.rs`
- Create: `qtrace-ui/crates/qtrace-provider/src/flight/wire.rs`
- Create: `qtrace-ui/crates/qtrace-provider/src/flight/recovery.rs`
- Create: `qtrace-ui/crates/qtrace-provider/tests/flight_recovery.rs`
- Modify: `qtrace-ui/crates/qtrace-provider/src/lib.rs`
- Modify: `qtrace-ui/crates/qtrace-provider/Cargo.toml`

**Interfaces:**
- Produces `FlightProvider::open(Arc<dyn ReadAtSource>, SourceIdentity, guard)`.
- Recovers valid committed prefixes from v2 active/sealed chunks while retaining active, stale, rotating, overwritten, lost, coverage-gap, checksum-damage, and emergency-slot evidence.

- [ ] **Step 1: Write failing physical recovery tests**

Cover exact v2 superblock, directory, chunk, record, and emergency slot sizes from `tracer/src/main/cpp/flight/flight_format.h`. Assert:

```rust
#[test]
fn damaged_chunk_becomes_visible_completeness_not_silent_data_loss() {
    let parsed = collect_flight("v2-checksum-damaged.bin").unwrap();
    assert!(parsed.summary.completeness.iter().any(|item| {
        item.provenance == Provenance::Damaged && item.cause == CompletenessCause::Checksum
    }));
}

#[test]
fn merged_and_per_thread_timelines_keep_captured_order() {
    let parsed = collect_flight("v2-complete.bin").unwrap();
    assert!(parsed.capabilities.global_ordering);
    assert!(strictly_increasing(global_sequences(&parsed.events)));
    assert!(strictly_increasing(global_sequences_for_tid(&parsed.events, 101)));
}
```

Also test full source-size identity, reserved fields, region bounds/alignment/non-overlap, duplicate TIDs, directory generation, active committed prefix, sealed checksum/count/range, record commit token, generation, eight-byte padding, wrap selection, emergency checksum/complement/version, stale entries, and deterministic lost-range union.

- [ ] **Step 2: Run the focused test and confirm failure**

```bash
cd qtrace-ui && cargo test -p qtrace-provider --test flight_recovery
```

Expected: FAIL because `FlightProvider` is absent.

- [ ] **Step 3: Implement checked mmap-oriented recovery**

Parse through `ReadAtSource`; no native struct cast or unchecked slice indexing is allowed. Validate the entire superblock before reading subordinate regions. Select chunks by `(index, generation, state, committed range)` and validate sealed chunks with the wire FNV-1a checksum. For active chunks, accept only consecutive records whose checksum and commit token are valid; stop at the first uncommitted suffix without interpreting later bytes.

Emit every retained event once into one Flight merged timeline, ordered by `global_seq`, and expose per-TID projection descriptors that reference those same stable event keys rather than duplicating events under new identities. Compute retained, lost, overwritten, explicit coverage-gap, and damaged ranges as sorted non-overlapping inclusive sequence intervals, including ranges that end at `u64::MAX`. Emergency evidence may enrich termination/gap facts but cannot silently replace a newer committed record. Preserve directory reliability/staleness and unterminated threads in provider completeness metadata.

- [ ] **Step 4: Run Flight recovery regressions**

```bash
cd qtrace-ui && cargo test -p qtrace-provider --test flight_recovery
cargo test -p qtrace-provider
cd .. && python3 -m unittest scripts.tests.test_flight_trace -v
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit Flight physical recovery**

```bash
git add qtrace-ui/crates/qtrace-provider
git commit -m "feat(qtrace-ui): recover flight v2 artifacts"
```

---

### Task 7: Decode every Flight v2 event and match the Python recovery oracle

**Files:**
- Create: `qtrace-ui/crates/qtrace-provider/src/flight/events.rs`
- Create: `qtrace-ui/crates/qtrace-provider/src/flight/fragments.rs`
- Create: `qtrace-ui/crates/qtrace-provider/tests/flight_events.rs`
- Create: `qtrace-ui/crates/qtrace-provider/tests/flight_differential.rs`
- Modify: `qtrace-ui/crates/qtrace-provider/src/flight/mod.rs`

**Interfaces:**
- Converts committed Flight records into the common typed `EventPayload` without losing native checkpoint/delta, lifecycle, syscall, signal, termination, coverage-gap, or fragment evidence.
- Produces exact `global_seq` order for merged and per-thread cursors and a `ProviderCapabilities` value that reflects Flight's full checkpoints, lifecycle, and loss/damage reporting.

- [ ] **Step 1: Write failing typed Flight tests**

Assert exact decoded fields for all record kinds 1–15, including 34-register checkpoints, delta masks, embedded QTRB instruction definitions/events, memory capture states, string-definition references, fragmented semantic events, syscall arguments/results, signal/signal-handler boundaries, termination intent, and coverage gaps. Add invariants:

```rust
#[test]
fn delta_does_not_make_unmentioned_registers_known() {
    let events = events_for("v2-checkpoint-delta.bin");
    let delta = events.iter().find_map(EventRecord::register_delta).unwrap();
    assert_eq!(delta.changed.len(), delta.mask.count_ones() as usize);
    assert!(!delta.changed.iter().any(|item| item.slot == RegisterSlot::X3));
}

#[test]
fn an_incomplete_fragment_is_damage_not_a_partial_string() {
    let parsed = collect_flight("v2-incomplete-fragment.bin").unwrap();
    assert!(!semantic_details(&parsed.events).iter().any(|text| text.contains("partial")));
    assert!(parsed.summary.completeness.iter().any(|item| item.provenance == Provenance::Damaged));
}
```

- [ ] **Step 2: Run the typed tests and confirm failure**

```bash
cd qtrace-ui && cargo test -p qtrace-provider --test flight_events --test flight_differential
```

Expected: FAIL because the recovery layer does not yet expose typed logical events.

- [ ] **Step 3: Implement typed Flight decoding and fragment grouping**

Decode chunk-begin identity and checkpoint before accepting dependent records. Require delta bits 0–33 only, exact payload population, and a reliable prior checkpoint for state-bearing use; still emit a damaged delta event if physical bytes are valid but state ancestry is broken. Reuse QTRB instruction/memory payload decoders through private shared functions rather than duplicating their validation.

Resolve Flight string IDs within their valid chunk/generation scope. Group CALL/RULE/ERROR fragments by `(tid, event_id, kind)`, verify stable fixed fields, total length, count, contiguous indexes, and contributing chunk generations, then validate UTF-8 once. An invalid group damages its exact contributing sequence/chunk range and is not emitted as a shortened semantic event.

Preserve every physical evidence coordinate. Synthetic discontinuity events use the directory/chunk/emergency entry offset that proves the condition; EOF conditions use `source_offset=artifact_bytes`. Their provider evidence ordinal is deterministic and is included in the stable event key.

- [ ] **Step 4: Add and run the differential oracle**

For every valid/damaged Flight fixture, invoke `python3 qtrace-ui/tools/oracle.py flight <path>` and compare:

- merged `(global_seq, tid, kind, typed fields)`;
- per-thread ordering and final checkpoint/delta register snapshot;
- retained/lost ranges, active/stale/rotating chunks, damage strings by normalized error class, target PCs, termination, handler intervals, and completeness.

Run:

```bash
cd qtrace-ui && cargo test -p qtrace-provider --test flight_events --test flight_differential
cargo test -p qtrace-provider
```

Expected: exact differential matches and all provider tests pass.

- [ ] **Step 5: Commit typed Flight support**

```bash
git add qtrace-ui/crates/qtrace-provider
git commit -m "feat(qtrace-ui): decode typed flight events"
```

---

### Task 8: Harden both providers with property tests and fuzz targets

**Files:**
- Create: `qtrace-ui/crates/qtrace-provider/tests/provider_properties.rs`
- Create: `qtrace-ui/fuzz/Cargo.toml`
- Create: `qtrace-ui/fuzz/fuzz_targets/qtrb.rs`
- Create: `qtrace-ui/fuzz/fuzz_targets/flight.rs`
- Create: `qtrace-ui/fuzz/corpus/qtrb/*`
- Create: `qtrace-ui/fuzz/corpus/flight/*`
- Modify: `qtrace-ui/Cargo.toml`

**Interfaces:**
- Guarantees arbitrary bytes produce a valid bounded provider result or typed `ProviderError`; no panic, abort, unbounded allocation, infinite loop, or unchecked offset is acceptable.
- Keeps the fuzz package outside the release workspace with `workspace.exclude = ["fuzz"]`.

- [ ] **Step 1: Write property tests for mutation classes**

Generate bounded valid skeletons, then mutate lengths, offsets, counts, flags, versions, references, checksums, commit tokens, fragment order, UTF-8, terminal placement, and truncation points. Require parsing to finish under a guard capped at 16 MiB input/decompressed, 100,000 events, 32 MiB resident accounting, and a one-second deadline.

```rust
proptest! {
    #[test]
    fn truncating_qtrb_at_any_byte_never_panics(cut in 0usize..VALID_QTRB.len()) {
        let result = catch_unwind(|| open_qtrb_bytes(&VALID_QTRB[..cut]));
        prop_assert!(result.is_ok());
        prop_assert!(result.unwrap().is_err());
    }
}
```

Add equivalent Flight region-offset and chunk mutation properties. Do not assert vague error text; assert stable error-code families and no success for mutations that invalidate required evidence.

- [ ] **Step 2: Run properties and confirm at least one missing guard/validation failure**

```bash
cd qtrace-ui && cargo test -p qtrace-provider --test provider_properties
```

Expected: FAIL until all parser entry points accept/enforce the bounded guard and return stable errors.

- [ ] **Step 3: Close the discovered parser gaps and add fuzz harnesses**

Each fuzz target creates an in-memory source, a strict low-budget guard, and calls the public provider open/cursor path. Seed corpora with every small checked-in valid and malformed fixture. Never invoke Python from a fuzz target.

- [ ] **Step 4: Run properties and bounded fuzz smoke**

```bash
cd qtrace-ui && cargo test -p qtrace-provider --test provider_properties
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
cargo +nightly fuzz run qtrb --fuzz-dir fuzz -- -runs=10000
cargo +nightly fuzz run flight --fuzz-dir fuzz -- -runs=10000
```

Expected: tests pass; both fuzz targets complete 10,000 runs with no crash, timeout, or out-of-memory failure.

- [ ] **Step 5: Commit provider hardening**

```bash
git add qtrace-ui/Cargo.toml qtrace-ui/crates/qtrace-provider qtrace-ui/fuzz
git commit -m "test(qtrace-ui): harden binary providers"
```

---

### Task 9: Load sessions and single artifacts through Linux-safe path boundaries

**Files:**
- Create: `qtrace-ui/crates/qtrace-store/src/secure_path.rs`
- Create: `qtrace-ui/crates/qtrace-store/src/manifest.rs`
- Create: `qtrace-ui/crates/qtrace-store/src/identity.rs`
- Create: `qtrace-ui/crates/qtrace-store/src/session.rs`
- Modify: `qtrace-ui/crates/qtrace-store/src/lib.rs`
- Modify: `qtrace-ui/crates/qtrace-store/Cargo.toml`
- Create: `qtrace-ui/crates/qtrace-store/tests/session_open.rs`
- Create: `qtrace-ui/crates/qtrace-store/tests/path_security.rs`

**Interfaces:**
- Produces `SessionLoader::open_report(AuthorizedPath, OpenPolicy, guard)` and `SessionLoader::open_artifact(AuthorizedPath, OpenPolicy, guard)`.
- Produces immutable `SessionSource`, `ArtifactSource`, `ArtifactFailure`, and full `SourceIdentity` values while retaining open file descriptors so later path replacement cannot redirect reads.

- [ ] **Step 1: Write failing session/import tests**

Use `fixtures/sessions` and temporary directories to cover:

```rust
#[test]
fn qtrb_artifacts_remain_independent_timelines() {
    let session = open_fixture_session("valid-mixed").unwrap();
    let qtrb = session.artifacts.iter().filter(|item| item.format.is_qtrb()).collect::<Vec<_>>();
    assert_eq!(qtrb.len(), 2);
    assert_ne!(qtrb[0].timeline_id, qtrb[1].timeline_id);
}

#[test]
fn invalid_artifact_is_isolated_after_a_valid_root_manifest() {
    let session = open_fixture_session("one-invalid-artifact").unwrap();
    assert_eq!(session.available_artifacts().count(), 2);
    assert_eq!(session.failures.len(), 1);
    assert_eq!(session.failures[0].error.code, "source.qtrb.truncated");
}

#[test]
fn path_escape_and_symlink_are_root_failures() {
    assert_error_code("path-escape", "session.path_escape");
    assert_error_code("symlink-artifact", "session.path_escape");
}
```

Also test report schema other than 1, unknown/duplicate root fields, source artifact records without bounded path/SHA/size, absolute paths, `..`, empty components, embedded NUL, directory/special-file leaf, parent symlink, leaf symlink, path replacement during hashing, source size/hash mismatch, unsupported binary version, file growth/shrink during read, known derived-output classification, unknown artifact isolation, and degraded single-file capability warnings.

- [ ] **Step 2: Run focused store tests and confirm failure**

```bash
cd qtrace-ui && cargo test -p qtrace-store --test session_open --test path_security
```

Expected: FAIL because the loader and secure root do not exist.

- [ ] **Step 3: Implement descriptor-relative containment and identity**

On Linux, open the selected session directory using `rustix` with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`. Reject any non-`Component::Normal` relative component. Walk every parent with `openat` using the same flags and open leaves with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`; `fstat` must report a regular file. Keep each owned `File` open. Compute SHA-256 by descriptor, charging bytes to the guard, then compare `(st_dev, st_ino, st_size, mtime/ctime)` before and after hashing.

Parse the current `SessionReport` schema-1 root keys from `qtrace/report.py`. A successful source artifact record must provide `local_path`, lowercase 64-hex `sha256`, and positive `destination_size`; records without `local_path` remain bounded report warnings/failures and are never opened. Verify report-declared size/hash before provider probing. Only `.trace.bin`, `.trace.bin.lz4`, and `.flight.bin` records become provider inputs. Known `.metrics`, `.crash`, `.trace.txt`, `.trace.txt.lz4`, `.merged.trace.txt`, `.tid-<tid>.trace.txt`, and `.flight.json` records remain session metadata; an unknown local artifact record is isolated as `source.format_unsupported` and does not reject healthy timelines.

`open_artifact` accepts only a path already authorized by the native adapter, opens the exact selected regular non-symlink file, and builds a degraded session with explicit missing package/device/target/config capabilities. It recognizes `.trace.bin`, `.trace.bin.lz4`, and `.flight.bin`; text and derived JSON are not analysis sources.

- [ ] **Step 4: Run session and security regressions**

```bash
cd qtrace-ui && cargo test -p qtrace-store --test session_open --test path_security
cargo clippy -p qtrace-store --all-targets -- -D warnings
```

Expected: all tests pass, including injected rename/symlink races.

- [ ] **Step 5: Commit secure session loading**

```bash
git add qtrace-ui/crates/qtrace-store
git commit -m "feat(qtrace-ui): load immutable trace sessions"
```

---

### Task 10: Define a checksummed, atomically published normalized cache

**Files:**
- Create: `qtrace-ui/crates/qtrace-store/src/layout.rs`
- Create: `qtrace-ui/crates/qtrace-store/src/cache/mod.rs`
- Create: `qtrace-ui/crates/qtrace-store/src/cache/manifest.rs`
- Create: `qtrace-ui/crates/qtrace-store/src/cache/reader.rs`
- Create: `qtrace-ui/crates/qtrace-store/src/cache/writer.rs`
- Modify: `qtrace-ui/crates/qtrace-store/src/lib.rs`
- Create: `qtrace-ui/crates/qtrace-store/tests/cache_format.rs`
- Create: `qtrace-ui/crates/qtrace-store/tests/cache_publication.rs`

**Interfaces:**
- Produces `CacheIdentity`, `CacheManifest`, `SectionDescriptor`, `CacheWriter`, `CacheReader`, `OwnedStoreView`, `MappedStoreView`, and `StoreView`.
- A cache is one content-addressed `index.qtc` file under XDG cache. It has a fixed header, explicit little-endian sections, a checksummed JSON manifest, and per-section SHA-256 checksums.

- [ ] **Step 1: Write failing cache-format/corruption tests**

Cover identity fields: complete artifact digest, source format/major/minor/features, cache schema, analyzer version, endian/layout version, and build-option digest. Mutate each header/manifest/section offset, length, alignment, element size, checksum, reserved byte, and identity field and require a typed rebuild outcome rather than panic.

```rust
#[test]
fn mapped_and_owned_views_answer_the_same_values() {
    let owned = sample_owned_store();
    let file = write_and_reopen(&owned).unwrap();
    for row in 0..owned.event_count() {
        assert_eq!(owned.event_key(row).unwrap(), file.event_key(row).unwrap());
        assert_eq!(owned.event_kind(row).unwrap(), file.event_kind(row).unwrap());
    }
}
```

Publication tests inject cancellation/failure before header finalization, after section write, after file fsync, and before directory fsync; none may leave a visible final cache. Concurrent builders may race, but both complete files must have the same identity and readers must observe only one valid winner. Also reject a symlinked XDG cache root, symlinked digest directory, non-regular cache leaf, and cache-directory identity replacement during build.

- [ ] **Step 2: Run cache tests and confirm failure**

```bash
cd qtrace-ui && cargo test -p qtrace-store --test cache_format --test cache_publication
```

Expected: FAIL because the cache reader/writer do not exist.

- [ ] **Step 3: Implement the cache wire contract**

Use a 64-byte header with magic `QTCACHE\0`, cache schema, header size, manifest offset/length, manifest SHA-256, and zero reserved bytes. Write fixed columns and blob sections with explicit alignment padding, then deterministic sorted-key JSON manifest. Seek back to finalize the header only after all section descriptors/checksums exist.

Before returning any view, the reader validates file identity, header/reserved bytes, manifest range/checksum/schema, unique section names, sorted non-overlapping ranges, alignment, length divisible by element size, and every section checksum. Numeric accessors copy the exact bytes into `from_le_bytes`; do not use `transmute`, `align_to`, native struct serialization, or unchecked indexing.

Open/create the XDG cache path component-by-component with the Task 9 descriptor-relative no-follow rules and private `0700` directories. Publish with a random same-directory temporary filename, mode `0600`, complete write, file `fsync`, `renameat`, and parent-directory `fsync`. On cancellation/error, close and unlink only the owned temporary. A corrupt final cache returns `CacheOpen::Rebuild(reason)` and is replaced only after a new valid cache is ready.

- [ ] **Step 4: Run all cache regressions**

```bash
cd qtrace-ui && cargo test -p qtrace-store --test cache_format --test cache_publication
cargo test -p qtrace-store
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit the cache contract**

```bash
git add qtrace-ui/crates/qtrace-store
git commit -m "feat(qtrace-ui): add safe normalized cache"
```

---

### Task 11: Build normalized event columns and eager indexes from both providers

**Files:**
- Create: `qtrace-ui/crates/qtrace-store/src/index/mod.rs`
- Create: `qtrace-ui/crates/qtrace-store/src/index/builder.rs`
- Create: `qtrace-ui/crates/qtrace-store/src/index/postings.rs`
- Create: `qtrace-ui/crates/qtrace-store/src/index/intervals.rs`
- Create: `qtrace-ui/crates/qtrace-store/src/index/checkpoints.rs`
- Modify: `qtrace-ui/crates/qtrace-store/src/session.rs`
- Modify: `qtrace-ui/crates/qtrace-store/src/layout.rs`
- Create: `qtrace-ui/crates/qtrace-store/tests/index_build.rs`
- Create: `qtrace-ui/crates/qtrace-store/tests/index_equivalence.rs`

**Interfaces:**
- Produces `IndexBuilder::build(&ArtifactSource, &BuildOptions, &dyn WorkGuard) -> OwnedTraceStore` and `TraceStore::open_or_build`.
- Normalizes event, instruction, memory, semantic, completeness, module, definition, register-observation, and blob columns while preserving each provider's real capabilities.

- [ ] **Step 1: Write failing normalized-layout and index tests**

Assert exact rows for the mixed session fixture. Required eager indexes are timeline/thread/sequence, kind, PC/module, instruction definition, register observation/checkpoint locator, memory-overlap interval, call/return flags, and semantic category/name.

```rust
#[test]
fn qtrb_and_flight_share_queries_without_sharing_false_capabilities() {
    let qtrb = build_fixture("qtrb/v1.2-completed.bin");
    let flight = build_fixture("flight/v2-complete.bin");
    assert_eq!(qtrb.rows_of_kind(EventKind::Instruction).count(), 1);
    assert!(flight.rows_of_kind(EventKind::Instruction).count() >= 1);
    assert!(!qtrb.capabilities().full_register_checkpoint);
    assert!(flight.capabilities().full_register_checkpoint);
}
```

Test that memory range `[0x1004,0x1008)` finds accesses starting before `0x1004`, that same-field posting lists union while later query fields can intersect, that source row/key maps are bijective, and that a build cancelled at every checkpoint publishes no cache.

- [ ] **Step 2: Run index tests and confirm failure**

```bash
cd qtrace-ui && cargo test -p qtrace-store --test index_build --test index_equivalence
```

Expected: FAIL because normalized columns and indexes are absent.

- [ ] **Step 3: Implement streaming normalization**

Use append-only typed vectors during build. Store fixed-width columns separately from bounded blob arenas. Deduplicate module, instruction-definition, semantic category/name, and bounded strings by exact bytes plus hash collision verification. Keep source event key and provider provenance on every row.

Use sorted delta-encoded posting lists for TID/kind/module/definition/register/call flags. Use `(relative_pc,row)` sorted arrays per module for PC ranges. Use an augmented interval index sorted by start with prefix/sparse maximum-end blocks for memory overlaps. Store register/checkpoint row locators only; state replay remains in analysis.

Select provider by validated magic/version, not suffix alone. Raw QTRB may be backed by mmap; compressed QTRB streams through `lz4_flex`; Flight uses mmap through checked `ReadAtSource`. After strict provider completion, serialize `OwnedTraceStore` through Task 10 and reopen it as `MappedTraceStore` before making the workspace available.

- [ ] **Step 4: Verify owned/mapped equivalence and cancellation**

```bash
cd qtrace-ui && cargo test -p qtrace-store --test index_build --test index_equivalence
cargo test -p qtrace-store
cargo clippy -p qtrace-store --all-targets -- -D warnings
```

Expected: all commands exit 0 and test cleanup finds no temporary cache files.

- [ ] **Step 5: Commit normalized indexing**

```bash
git add qtrace-ui/crates/qtrace-store
git commit -m "feat(qtrace-ui): index normalized trace events"
```

---

### Task 12: Implement structured filtering, stable pagination, and timeline projection

**Files:**
- Create: `qtrace-ui/crates/qtrace-analysis/src/filter.rs`
- Create: `qtrace-ui/crates/qtrace-analysis/src/timeline.rs`
- Create: `qtrace-ui/crates/qtrace-analysis/src/provenance.rs`
- Modify: `qtrace-ui/crates/qtrace-analysis/src/lib.rs`
- Modify: `qtrace-ui/crates/qtrace-analysis/Cargo.toml`
- Create: `qtrace-ui/crates/qtrace-analysis/tests/filter_semantics.rs`
- Create: `qtrace-ui/crates/qtrace-analysis/tests/pagination.rs`

**Interfaces:**
- Produces `EventFilter`, inclusive `SequenceRange`, half-open `AddressRange`, `MemoryFilter`, `QueryPlan`, `PageCursor`, `EventPage`, `TimelineProjection`, and `query_events`.
- Different populated fields are ANDed; multiple values within one field are ORed. Pagination is deterministic against one immutable store/cache identity.

- [ ] **Step 1: Write failing filter and cursor tests**

Cover every approved field: TID, kind, module, relative/absolute PC range, sequence, mnemonic exact/contains, register read/write, overlapping memory range/direction, semantic category/name, and semantic detail contains. Assert same-field OR and cross-field AND with table tests.

```rust
#[test]
fn cursor_cannot_be_reused_for_another_filter_or_store() {
    let first = query_page(&store_a, filter_tid(7), None, 2).unwrap();
    assert_error_code(query_page(&store_a, filter_tid(8), first.next, 2), "analysis.cursor_mismatch");
    assert_error_code(query_page(&store_b, filter_tid(7), first.next, 2), "analysis.cursor_mismatch");
}
```

Also test limit range 1–2,000, stable next-page traversal without duplicate/missing keys, exact and inexact totals, completeness summaries, and deterministic special discontinuity rows.

- [ ] **Step 2: Run analysis tests and confirm failure**

```bash
cd qtrace-ui && cargo test -p qtrace-analysis --test filter_semantics --test pagination
```

Expected: FAIL because query types and planner are absent.

- [ ] **Step 3: Implement index-aware query planning**

Normalize and hash the filter plus store identity into a `ProjectionIdentity`. Union posting lists within each populated field, intersect candidate sets across fields from smallest to largest, and apply residual predicates only to candidates. Mnemonic `contains` scans the small deduplicated definition dictionary, then expands matching definition postings. Memory uses true half-open overlap, not start-address equality.

Semantic-detail contains is the one approved residual text path: scan semantic-event blob candidates in a cancellable background analysis, return available pages with `exact_total=false` until the immutable result artifact is complete, then return `exact_total=true`. Do not scan instruction disassembly or all event blobs.

Encode `PageCursor` as URL-safe base64 of version, store identity, projection identity, last stable event key, and checksum. Reject modified, stale, or cross-filter cursors. `TimelineProjection` exposes total visible rows and page lookup without materializing all rows.

- [ ] **Step 4: Run filter/pagination regressions**

```bash
cd qtrace-ui && cargo test -p qtrace-analysis --test filter_semantics --test pagination
cargo test -p qtrace-analysis
cargo clippy -p qtrace-analysis --all-targets -- -D warnings
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit query analysis**

```bash
git add qtrace-ui/crates/qtrace-analysis
git commit -m "feat(qtrace-ui): query trace timelines"
```

---

### Task 13: Add ELF symbol indexes and transactional local annotations

**Files:**
- Create: `qtrace-ui/crates/qtrace-store/src/symbols.rs`
- Create: `qtrace-ui/crates/qtrace-store/src/annotations.rs`
- Modify: `qtrace-ui/crates/qtrace-store/src/lib.rs`
- Modify: `qtrace-ui/crates/qtrace-store/Cargo.toml`
- Create: `qtrace-ui/crates/qtrace-store/tests/symbols.rs`
- Create: `qtrace-ui/crates/qtrace-store/tests/annotations.rs`
- Create: `qtrace-ui/crates/qtrace-analysis/src/symbolize.rs`
- Modify: `qtrace-ui/crates/qtrace-analysis/src/lib.rs`
- Create: `qtrace-ui/crates/qtrace-analysis/tests/symbolize.rs`

**Interfaces:**
- Produces `ElfSymbolIndex::load`, `SymbolResolver`, `AnnotationStore`, `EventAnnotation`, `LocalSymbolName`, and `Highlight`.
- Symbol identity is module identity plus relative PC; user naming overrides ELF naming without modifying source/cache.

- [ ] **Step 1: Write failing ELF and annotation tests**

Test valid ELF64/AArch64 `.dynsym`/`.symtab` and GNU build-id, then reject ELF32, non-AArch64, malformed section bounds, unexpected build-id, and module identity mismatch. Test exact symbol containment, nearest preceding symbol plus offset, duplicate precedence, and ASLR independence.

For SQLite, test event comments, module-relative renames, highlights, transaction rollback, delete/reopen persistence, schema migration from an empty schema-1 database, distinct databases for distinct session identities, a symlinked XDG data root/database leaf, and data-directory identity replacement.

```rust
#[test]
fn local_name_wins_without_changing_symbol_address() {
    let resolved = resolver.resolve(module_id(), 0x124).unwrap();
    assert_eq!(resolved.elf_name.as_deref(), Some("native_work"));
    assert_eq!(resolved.display_name, "decrypt_round");
    assert_eq!(resolved.relative_address, 0x120);
    assert_eq!(resolved.offset, 4);
}
```

- [ ] **Step 2: Run focused symbol/annotation tests and confirm failure**

```bash
cd qtrace-ui && cargo test -p qtrace-store --test symbols --test annotations
cargo test -p qtrace-analysis --test symbolize
```

Expected: FAIL because the loaders/stores are absent.

- [ ] **Step 3: Implement verified ELF loading and XDG SQLite data**

Use `object` to require ELF64, little-endian, AArch64, regular non-symlink file identity, and bounded file size. Read `.dynsym` and `.symtab` only; ignore DWARF. Validate selected external ELF against expected module name, producer target identity, and GNU build-id when available. External candidates require an `approved=true` request produced by the native picker path; no automatic path discovery outside the session root.

Create SQLite under an XDG data path opened/created with the Task 9 descriptor-relative no-follow rules, private `0700` directories, and a regular `0600` database file. Enable WAL, foreign keys, busy timeout, and a schema version table. Tables use binary artifact/module digest plus stable event coordinates or relative PC as keys. All writes use explicit transactions and return structured errors. Do not put annotations in `index.qtc`.

- [ ] **Step 4: Verify symbol and annotation behavior**

```bash
cd qtrace-ui && cargo test -p qtrace-store --test symbols --test annotations
cargo test -p qtrace-analysis --test symbolize
cargo test --workspace
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit symbols and annotations**

```bash
git add qtrace-ui/crates/qtrace-store qtrace-ui/crates/qtrace-analysis
git commit -m "feat(qtrace-ui): add symbols and annotations"
```

---

### Task 14: Reconstruct truthful register and memory state

**Files:**
- Create: `qtrace-ui/crates/qtrace-analysis/src/registers.rs`
- Create: `qtrace-ui/crates/qtrace-analysis/src/memory.rs`
- Modify: `qtrace-ui/crates/qtrace-analysis/src/lib.rs`
- Create: `qtrace-ui/crates/qtrace-analysis/tests/register_state.rs`
- Create: `qtrace-ui/crates/qtrace-analysis/tests/memory_state.rs`

**Interfaces:**
- Produces `RegisterReplay`, `RegisterStateAtEvent`, `RegisterCell`, `MemoryAnalyzer`, `MemoryStateAtEvent`, `MemoryEvidence`, `ByteState`, and overlap-history queries.
- Register results expose separate `before` and `after`; memory results expose separate `observed`, `before`, `after`, and `last_written` evidence with per-byte validity/provenance.

- [ ] **Step 1: Write failing register-state tests**

Create table-driven QTRB cases for read-before, write-after, partial register width, unobserved registers, derived checkpoint replay, contradictory captured read, discontinuity invalidation, and later recapture. Create Flight cases for 34-GPR checkpoint, deltas, per-thread isolation, stale ancestry, gaps, and a later reliable checkpoint.

```rust
#[test]
fn discontinuity_invalidates_only_until_new_evidence() {
    let replay = qtrb_replay_fixture();
    let after_gap = replay.state_at(key("after-gap")).unwrap();
    assert_eq!(after_gap.after.cell(RegisterSlot::X0).provenance, Provenance::Damaged);
    let recaptured = replay.state_at(key("recaptured-read")).unwrap();
    assert_eq!(recaptured.before.cell(RegisterSlot::X0).value, Some(7));
    assert_eq!(recaptured.before.cell(RegisterSlot::X0).provenance, Provenance::Captured);
}
```

Assert a captured `u64::MAX` is known and distinct from no value. Assert W-register writes update only the architecturally defined low 32 bits and zero-extend into X when the captured semantics prove a W write; width metadata must not be discarded.

- [ ] **Step 2: Write failing memory-state tests**

Cover overlapping writes, partial overlap, read-only observations, before/after capture, uncaptured bytes, ranges larger than one event, discontinuity, per-thread evidence labels, and result budgets.

```rust
#[test]
fn read_observation_is_not_promoted_to_last_written() {
    let state = memory_state_after_read_only_fixture(0x2000..0x2004);
    assert!(state.observed.iter().all(|byte| byte.value.is_some()));
    assert!(state.last_written.iter().all(|byte| byte.value.is_none()));
}

#[test]
fn overlap_query_finds_an_access_that_starts_before_the_requested_range() {
    let history = memory_history(0x2002..0x2006);
    assert!(history.iter().any(|event| event.address == 0x2000 && event.size == 8));
}
```

- [ ] **Step 3: Run focused state tests and confirm failure**

```bash
cd qtrace-ui && cargo test -p qtrace-analysis --test register_state --test memory_state
```

Expected: FAIL because replay analyzers are absent.

- [ ] **Step 4: Implement bounded per-thread replay**

For QTRB, at an instruction apply captured reads to `before`, preserve prior valid derived cells for unobserved registers, then apply captured writes to `after`. Save derived checkpoints every 4,096 instruction rows and immediately after a full reliable recapture; each checkpoint includes a 34-bit validity mask and per-cell provenance. A discontinuity invalidates affected cells/thread state before replay continues.

For Flight, seed from native 34-GPR checkpoints and apply exact deltas in per-TID `global_seq` order. Never reuse a checkpoint across a damaged/lost interval unless a later native checkpoint re-establishes state. All replay walks call `WorkGuard` at bounded intervals.

For memory, use the store overlap index. Construct each requested byte independently. A captured `before`/`after` byte is captured evidence; a prior captured write can produce `last_written` derived evidence; reads populate only `observed`. Partial range coverage retains unknown/damaged bytes rather than failing the whole request. Cap one request at 1 MiB and 10,000 history rows by default, returning `analysis.budget_exceeded` when the service-selected budget is lower.

- [ ] **Step 5: Run state analysis regressions**

```bash
cd qtrace-ui && cargo test -p qtrace-analysis --test register_state --test memory_state
cargo test -p qtrace-analysis
cargo clippy -p qtrace-analysis --all-targets -- -D warnings
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit state reconstruction**

```bash
git add qtrace-ui/crates/qtrace-analysis
git commit -m "feat(qtrace-ui): reconstruct trace state"
```

---

### Task 15: Build per-thread call trees with explicit incomplete boundaries

**Files:**
- Create: `qtrace-ui/crates/qtrace-analysis/src/call_tree.rs`
- Modify: `qtrace-ui/crates/qtrace-analysis/src/lib.rs`
- Create: `qtrace-ui/crates/qtrace-analysis/tests/call_tree.rs`
- Create: `qtrace-ui/crates/qtrace-analysis/tests/call_tree_multithread.rs`

**Interfaces:**
- Produces immutable `CallTreeArtifact`, `CallNode`, `FrameState`, `CallTargetEvidence`, `ExecutionInterval`, and `CallTreeOptions`.
- Every tree is scoped to exactly one timeline and one TID. Nodes retain entry/exit event keys, source row interval, symbol display, semantic enrichment, provenance, and incomplete reason.

- [ ] **Step 1: Write failing call-tree semantics tests**

Cover direct call/return, indirect target from captured next PC/register/LR evidence, nested calls, unmatched RET, mid-frame trace begin/end, tail-call heuristic, signal handler interval, unwind-like control flow, gap/overwrite/damage, and semantic CALL enrichment.

```rust
#[test]
fn interleaved_threads_never_share_a_stack() {
    let trees = build_all_threads(interleaved_fixture()).unwrap();
    assert_eq!(trees[&11].roots[0].tid, 11);
    assert_eq!(trees[&22].roots[0].tid, 22);
    assert!(!trees[&11].nodes.iter().any(|node| node.tid == 22));
}

#[test]
fn a_gap_closes_open_frames_as_incomplete_and_resets_parentage() {
    let tree = build_tree(gap_inside_call_fixture()).unwrap();
    let frame = tree.node_named("before_gap").unwrap();
    assert_eq!(frame.state, FrameState::Incomplete(IncompleteReason::Discontinuity));
    assert!(tree.node_named("after_gap").unwrap().parent.is_none());
}
```

Assert semantic JNI/libc/ART events without deterministic instruction context remain standalone enrichments and never create a function frame by themselves.

- [ ] **Step 2: Run call-tree tests and confirm failure**

```bash
cd qtrace-ui && cargo test -p qtrace-analysis --test call_tree --test call_tree_multithread
```

Expected: FAIL because the call-tree analyzer is absent.

- [ ] **Step 3: Implement deterministic stack construction**

Walk one TID projection at a time. Treat instruction call/return flags as primary evidence. Resolve call targets from immediate target, same-thread dynamic next PC, captured register values, and LR in that order while recording which evidence was used. Symbols/local names affect display only.

On unmatched RET, signal/unwind transition, source beginning/ending within a frame, termination, or discontinuity, emit explicit `IncompleteFrame`/`ExecutionInterval` nodes and reset only the affected thread state. Signal handler begin/return is a special interval, not a normal call. Mark tail-call/unwind guesses `heuristic` with a bounded reason enum; do not label them derived.

Associate QTRB semantic events to an instruction only when producer order, current instruction context, PC/module, and absence of a boundary all agree. Otherwise retain the event as a sibling. Build an immutable artifact identity from source/store digest, analyzer schema, TID, and options; never mutate one shared global tree.

- [ ] **Step 4: Run call-tree and analysis regressions**

```bash
cd qtrace-ui && cargo test -p qtrace-analysis --test call_tree --test call_tree_multithread
cargo test -p qtrace-analysis
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit call-tree analysis**

```bash
git add qtrace-ui/crates/qtrace-analysis
git commit -m "feat(qtrace-ui): build per-thread call trees"
```

---

### Task 16: Expose one budgeted service API with stable DTOs and background jobs

**Files:**
- Create: `qtrace-ui/crates/qtrace-service/src/error.rs`
- Create: `qtrace-ui/crates/qtrace-service/src/dto.rs`
- Create: `qtrace-ui/crates/qtrace-service/src/budget.rs`
- Create: `qtrace-ui/crates/qtrace-service/src/jobs.rs`
- Create: `qtrace-ui/crates/qtrace-service/src/workspace.rs`
- Create: `qtrace-ui/crates/qtrace-service/src/service.rs`
- Create: `qtrace-ui/crates/qtrace-service/src/bin/export_bindings.rs`
- Modify: `qtrace-ui/crates/qtrace-service/src/lib.rs`
- Modify: `qtrace-ui/crates/qtrace-service/Cargo.toml`
- Create: `qtrace-ui/crates/qtrace-service/tests/service_contract.rs`
- Create: `qtrace-ui/crates/qtrace-service/tests/job_lifecycle.rs`
- Create: `qtrace-ui/crates/qtrace-service/tests/error_contract.rs`

**Interfaces:**
- Produces `QtraceService`, opaque `WorkspaceId`, `JobId`, `ProjectionId`, and stable serde/TypeScript DTOs.
- Public operations: open authorized session/artifact, close workspace, session summary, create projection, query timeline, event detail, call tree, register state, memory state/history, attach approved ELF, symbols, annotations, jobs, and cancellation.

- [ ] **Step 1: Write failing DTO/error contract tests**

Use JSON snapshots to require snake_case stable fields and this exact error envelope:

```rust
#[derive(Clone, Debug, Serialize, Deserialize, TS)]
pub struct AppError {
    pub code: String,
    pub stage: String,
    pub source: Option<SourceCoordinateDto>,
    pub retryable: bool,
    pub detail: String,
}
```

Test unsupported capability, malformed cursor, stale workspace/generation, budget exceeded, cancellation, isolated artifact, cache rebuild warning, annotation rollback, and panic containment. A panic in an internal worker becomes `internal.worker_failed` with a bounded generic detail; no Rust backtrace/debug dump crosses the DTO boundary.

- [ ] **Step 2: Write failing job/workspace lifecycle tests**

Cover open progress stages, successful completion, explicit cancel, deadline, byte/event/node/row/memory budget exhaustion, closing a workspace with active jobs, generation replacement, late result completion, and immutable analysis artifact IDs.

```rust
#[tokio::test]
async fn late_result_cannot_replace_the_current_generation() {
    let service = test_service_with_controllable_jobs();
    let first = service.create_projection(workspace(), filter_a()).await.unwrap();
    let second = service.create_projection(workspace(), filter_b()).await.unwrap();
    complete(first.job_id).await;
    assert_eq!(service.current_projection(workspace()).unwrap(), second.projection_id);
}
```

- [ ] **Step 3: Run service tests and confirm failure**

```bash
cd qtrace-ui && cargo test -p qtrace-service --test service_contract --test job_lifecycle --test error_contract
```

Expected: FAIL because service types/jobs are absent.

- [ ] **Step 4: Implement service ownership and budgets**

`QtraceService` owns a synchronized map of immutable workspace snapshots and a `JobRegistry`; it never exposes a store reference. Use Tokio tasks and cancellation tokens. `ServiceBudget` includes deadline `Instant`, input/decompressed bytes, events, nodes, result rows, and resident bytes; its guard implements the provider `WorkGuard` and checks monotonic totals atomically.

Use these defaults for interactive requests: 5-second deadline, 2,000 returned rows, 100,000 analysis nodes, 256 MiB accounted memory. Open/index jobs receive an input-byte budget equal to the verified selected artifact size, a separate 4 GiB decompressed-byte hard maximum, a 30-minute hard deadline, 20 million events, and 2 GiB accounted memory; service callers may lower but not raise hard application maxima.

Every job publishes state transitions `queued → running → completed|cancelled|failed` plus bounded progress counters. Closing a workspace cancels jobs and removes live handles; content-addressed cache files already atomically completed remain valid. An expired generation result may be cached but cannot update current projection/selection/annotations.

Derive TypeScript declarations with `ts-rs`. `export_bindings` writes deterministic declarations to stdout and takes no path argument. Add a Rust test that hashes the declaration output so accidental DTO changes require an explicit snapshot update.

Never serialize Rust `u64`/`i64` as a JSON number. Use `DecimalU64Dto` for sequence/count/ordinal/offset values and `HexU64Dto` for addresses/register values; both serialize as validated strings and generate TypeScript `string`. Page sizes, generation counters, TIDs, enum tags, and bounded viewport row indexes remain JSON numbers. Add boundary snapshots for `u64::MAX` and `i64::MIN`.

- [ ] **Step 5: Run service and workspace regressions**

```bash
cd qtrace-ui && cargo test -p qtrace-service --test service_contract --test job_lifecycle --test error_contract
cargo test -p qtrace-service
cargo clippy -p qtrace-service --all-targets -- -D warnings
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit the service layer**

```bash
git add qtrace-ui/crates/qtrace-service
git commit -m "feat(qtrace-ui): expose analysis service"
```

---

### Task 17: Wire a thin Tauri adapter with native-only path authorization

**Files:**
- Create: `qtrace-ui/src-tauri/src/state.rs`
- Create: `qtrace-ui/src-tauri/src/commands.rs`
- Modify: `qtrace-ui/src-tauri/src/main.rs`
- Modify: `qtrace-ui/src-tauri/Cargo.toml`
- Modify: `qtrace-ui/src-tauri/tauri.conf.json`
- Modify: `qtrace-ui/src-tauri/capabilities/default.json`
- Create: `qtrace-ui/src-tauri/tests/command_contract.rs`
- Create: `qtrace-ui/src-tauri/tests/path_boundary.rs`

**Interfaces:**
- Exposes Tauri commands that mirror service DTO operations.
- `pick_and_open_session`, `pick_and_open_artifact`, and `pick_and_attach_elf` obtain paths inside Rust through the native dialog plugin; no production command deserializes an arbitrary filesystem path from React.

- [ ] **Step 1: Write failing command-surface tests**

Parse `commands.rs` with a small contract helper and assert the registered names are exactly:

```text
pick_and_open_session
pick_and_open_artifact
close_workspace
get_workspace_summary
create_projection
query_timeline
get_event_detail
get_register_state
get_memory_state
get_memory_history
get_call_tree
pick_and_attach_elf
list_symbols
upsert_annotation
delete_annotation
list_jobs
cancel_job
```

Assert the three picker commands accept a test `NativePicker` abstraction and service state, not a `PathBuf`/string path parameter. Assert all other commands accept DTO IDs/filters only. Serialize every success/error through the exact Task 16 contract.

- [ ] **Step 2: Run Tauri contract tests and confirm failure**

```bash
cd qtrace-ui && cargo test -p qtrace-ui --test command_contract --test path_boundary
```

Expected: FAIL because commands/state are absent.

- [ ] **Step 3: Implement the adapter and minimum capabilities**

Use `tauri-plugin-dialog` in Rust. Session selection accepts either a directory or its `report.json`; a selected directory is resolved to its direct `report.json` child by the secure loader. The picker returns one selected path directly to the adapter, which constructs `AuthorizedPath` and calls service; React receives only the resulting workspace/ELF DTO. Cancellation of a dialog returns a typed non-error `None` result.

Each non-picker command is one validation/deserialization call, one service call, and one DTO/error mapping. Do not open files, query stores, build trees, or manage pagination inside `commands.rs`. Manage one `Arc<QtraceService>` in Tauri state and cancel all work during application exit.

The capability file permits the application window, dialog open, and only the declared commands. Do not grant shell execution, broad filesystem, HTTP, clipboard-write beyond the explicit interaction feature, or process-spawn capability.

- [ ] **Step 4: Run adapter and workspace regressions**

```bash
cd qtrace-ui && cargo test -p qtrace-ui --test command_contract --test path_boundary
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit the Tauri boundary**

```bash
git add qtrace-ui/src-tauri
git commit -m "feat(qtrace-ui): add secure tauri adapter"
```

---

### Task 18: Build the frontend API boundary, reducer, and fixed desktop shell

**Files:**
- Create: `qtrace-ui/src-web/src/api/generated.ts`
- Create: `qtrace-ui/src-web/src/api/QtraceApi.ts`
- Create: `qtrace-ui/src-web/src/api/TauriQtraceApi.ts`
- Create: `qtrace-ui/src-web/src/api/ApiContext.tsx`
- Create: `qtrace-ui/src-web/src/state/model.ts`
- Create: `qtrace-ui/src-web/src/state/reducer.ts`
- Create: `qtrace-ui/src-web/src/state/AppStateProvider.tsx`
- Create: `qtrace-ui/src-web/src/components/AppHeader.tsx`
- Create: `qtrace-ui/src-web/src/components/SessionOverview.tsx`
- Create: `qtrace-ui/src-web/src/components/LeftDock.tsx`
- Create: `qtrace-ui/src-web/src/components/RightDock.tsx`
- Create: `qtrace-ui/src-web/src/components/BottomDock.tsx`
- Modify: `qtrace-ui/src-web/src/App.tsx`
- Modify: `qtrace-ui/src-web/src/styles/global.css`
- Create: `qtrace-ui/src-web/src/state/reducer.test.ts`
- Create: `qtrace-ui/src-web/src/components/App.test.tsx`

**Interfaces:**
- `QtraceApi` is the only frontend backend interface; components never import `@tauri-apps/api` directly.
- App state stores only IDs, current generation, filters, viewport, selection, panel state, warnings, and bounded result pages—not full trace data.

- [ ] **Step 1: Generate DTO declarations and write failing reducer/component tests**

Generate `api/generated.ts` mechanically from Task 16:

```bash
cd qtrace-ui
cargo run -p qtrace-service --bin export_bindings > src-web/src/api/generated.ts
```

Test reducer transitions for picker cancel, opening/indexing/ready/partial/failed, timeline/thread/filter selection, generation increment, stale-response rejection, job progress, structured error, and closing. Render with a fake `QtraceApi` and assert the fixed regions and session overview identity/warnings.

```tsx
it("ignores a response from an older generation", () => {
  const state = readyState({ generation: 4 });
  const next = reducer(state, { type: "timelinePageReceived", generation: 3, page: pageDto() });
  expect(next.timelinePages).toBe(state.timelinePages);
});
```

- [ ] **Step 2: Run frontend tests and confirm failure**

```bash
cd qtrace-ui/src-web && npm test -- --run src/state/reducer.test.ts src/components/App.test.tsx
```

Expected: FAIL because API/state/shell modules are absent.

- [ ] **Step 3: Implement the typed API and application state**

Define every Task 17 command in `QtraceApi`; `TauriQtraceApi` alone calls `invoke`. Convert rejected invoke values into validated `AppError` and map invalid envelopes to `client.contract_invalid`. Inject the API through context so unit/e2e tests use a real fixture adapter without patching globals.

Use a discriminated reducer with `empty|opening|indexing|ready|partial|failed` workspace states. Any action carrying a generation lower than current is a no-op. Opening/closing/timeline/filter/projection changes abort outstanding `AbortController`s and increment generation.

Build the approved fixed layout with semantic landmarks: header, left navigation, an empty Canvas timeline surface, right details, and bottom results/jobs. Session overview displays device/target/config identity, artifact/timeline status, capability gaps, isolated failures, and index progress before entering a timeline. Use CSS grid and system light/dark colors; no draggable docks, floating windows, minimap, or theme framework.

- [ ] **Step 4: Run frontend type/unit/build gates**

```bash
cd qtrace-ui/src-web
npm run lint
npm test
npm run build
```

Expected: all commands exit 0 and the production bundle has no test adapter.

- [ ] **Step 5: Commit the desktop shell**

```bash
git add qtrace-ui/src-web
git commit -m "feat(qtrace-ui): build desktop workspace shell"
```

---

### Task 19: Implement bounded timeline projection, viewport control, and segment caching

**Files:**
- Create: `qtrace-ui/src-web/src/timeline/TimelineProjection.ts`
- Create: `qtrace-ui/src-web/src/timeline/ViewportController.ts`
- Create: `qtrace-ui/src-web/src/timeline/SegmentCache.ts`
- Create: `qtrace-ui/src-web/src/timeline/types.ts`
- Create: `qtrace-ui/src-web/src/timeline/TimelineProjection.test.ts`
- Create: `qtrace-ui/src-web/src/timeline/ViewportController.test.ts`
- Create: `qtrace-ui/src-web/src/timeline/SegmentCache.test.ts`

**Interfaces:**
- `TimelineProjection` maps server projection-row ordinals to visible rows after local call-frame folds without changing stable event keys.
- `ViewportController` owns scroll-to-range conversion, overscan, request coalescing, abort, and generation rejection.
- `SegmentCache` is a weighted LRU capped by bytes and segment count.

- [ ] **Step 1: Write failing projection mapping tests**

Use half-open `FoldRange { startRow, endRow }`; the entry row stays visible and `(startRow,endRow)` is hidden. Cover nested/overlapping folds, invalid ranges, unfold, visible→source→visible round-trip, jump to hidden event returning its visible parent, zero/one/ten-million row counts, and generation replacement.

```ts
it("maps ten million rows without allocating ten million entries", () => {
  const projection = new TimelineProjection(10_000_000, [
    { startRow: 100, endRow: 1_000_000 },
  ]);
  expect(projection.visibleCount).toBe(9_000_101);
  expect(projection.debugIntervalCount()).toBe(1);
});
```

- [ ] **Step 2: Write failing viewport/cache concurrency tests**

With fake timers and controllable promises, cover rapid scroll coalescing, 25% overscan, abort on non-overlapping range, generation change, out-of-order response, exact boundary ranges, retryable failure, weighted eviction, recency update, replacement weight, oversize rejection, and session/projection key isolation.

```ts
it("does not publish an older generation that resolves last", async () => {
  const controller = controlledViewport();
  const old = controller.request({ generation: 3, start: 0, end: 100 });
  const current = controller.request({ generation: 4, start: 100, end: 200 });
  current.resolve(page(4));
  old.resolve(page(3));
  await flushPromises();
  expect(controller.currentPages()).toEqual([page(4)]);
});
```

- [ ] **Step 3: Run focused timeline tests and confirm failure**

```bash
cd qtrace-ui/src-web
npm test -- --run src/timeline/TimelineProjection.test.ts src/timeline/ViewportController.test.ts src/timeline/SegmentCache.test.ts
```

Expected: FAIL because the timeline primitives are absent.

- [ ] **Step 4: Implement bounded data structures**

Implement fold mapping with sorted non-overlapping intervals plus prefix hidden counts; lookup is `O(log folds)` and memory is `O(folds)`. Do not store one mapping per source row.

Use viewport row height, canvas height, scroll offset, and overscan to request bounded pages. Coalesce adjacent ranges within one animation frame. Every request key is `(workspaceId, projectionId, generation, start, end)` and owns an `AbortController`. Publish only if all identity fields still match current state.

Set `SegmentCache` defaults to 32 MiB estimated payload weight and 128 segments. Weight includes row DTO strings/blobs plus a fixed per-row overhead; reject one entry larger than the total budget. Expose current weight/count for tests and diagnostics, not application decisions.

- [ ] **Step 5: Run frontend primitive regressions**

```bash
cd qtrace-ui/src-web
npm test -- --run src/timeline
npm run lint
npm run build
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit timeline primitives**

```bash
git add qtrace-ui/src-web/src/timeline
git commit -m "feat(qtrace-ui): virtualize trace timeline"
```

---

### Task 20: Render the Canvas timeline and accessible interaction layer

**Files:**
- Create: `qtrace-ui/src-web/src/timeline/TraceCanvasRenderer.ts`
- Create: `qtrace-ui/src-web/src/timeline/InteractionLayer.tsx`
- Create: `qtrace-ui/src-web/src/timeline/VirtualTimeline.tsx`
- Create: `qtrace-ui/src-web/src/timeline/TraceCanvasRenderer.test.ts`
- Create: `qtrace-ui/src-web/src/timeline/InteractionLayer.test.tsx`
- Create: `qtrace-ui/src-web/src/styles/timeline.css`
- Modify: `qtrace-ui/src-web/src/App.tsx`

**Interfaces:**
- `TraceCanvasRenderer.render(context, frame)` is a pure draw operation over provided rows/theme/geometry and has no IPC or state ownership.
- `InteractionLayer` owns hit testing, keyboard navigation, selection, copy, tooltip, annotation action, and a bounded accessible text mirror for visible rows.

- [ ] **Step 1: Write failing pure-renderer tests**

Use a recording 2D context to assert row clipping, device-pixel ratio scaling, column alignment, selection/background colors, provenance styles, and badges. Require visible special rows for gap, lost, damaged, signal-handler interval, lifecycle, and termination. Verify the renderer does not import API/state modules with an ESLint restricted-import rule.

- [ ] **Step 2: Write failing interaction/accessibility tests**

Test mouse selection, double-click expand, tooltip, Arrow/Page/Home/End navigation, Enter expand, `c` copy, annotation shortcut, focus preservation after page replacement, hidden folded-event jump, and an ARIA `grid` containing only overscanned visible text rows.

```tsx
it("announces damaged evidence instead of reading it as a normal row", async () => {
  renderInteraction(rows([damagedRow()]));
  expect(screen.getByRole("row", { name: /damaged.*checksum gap/i })).toBeVisible();
});
```

- [ ] **Step 3: Run focused renderer/interaction tests and confirm failure**

```bash
cd qtrace-ui/src-web
npm test -- --run src/timeline/TraceCanvasRenderer.test.ts src/timeline/InteractionLayer.test.tsx
```

Expected: FAIL because rendering/interaction modules are absent.

- [ ] **Step 4: Implement Canvas rendering without business state**

Draw only rows intersecting the current viewport plus overscan. Render columns `seq | tid | module+offset | symbol | mnemonic operands | R/W/M/C`. Expanded rows draw bounded register/memory/semantic/provenance summaries returned by service. Use separate colors/patterns/icons for unknown and damaged, and never represent gaps as empty vertical space.

Keep hit-test geometry in one frame-local map. The interaction component translates hits/keys into reducer/API actions and maintains at most the visible accessibility rows. Use system theme and respect `prefers-reduced-motion`; do not animate scroll or indexing progress when reduced motion is set.

- [ ] **Step 5: Run timeline UI regressions**

```bash
cd qtrace-ui/src-web
npm test -- --run src/timeline
npm run lint
npm run build
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit Canvas timeline rendering**

```bash
git add qtrace-ui/src-web/src/timeline qtrace-ui/src-web/src/styles qtrace-ui/src-web/src/App.tsx
git commit -m "feat(qtrace-ui): render trace canvas"
```

---

### Task 21: Complete search, panes, selection sync, navigation, and annotations

**Files:**
- Create: `qtrace-ui/src-web/src/components/FilterBar.tsx`
- Create: `qtrace-ui/src-web/src/components/ThreadPane.tsx`
- Create: `qtrace-ui/src-web/src/components/CallTreePane.tsx`
- Create: `qtrace-ui/src-web/src/components/SymbolPane.tsx`
- Create: `qtrace-ui/src-web/src/components/RegisterPane.tsx`
- Create: `qtrace-ui/src-web/src/components/MemoryPane.tsx`
- Create: `qtrace-ui/src-web/src/components/EventDetailPane.tsx`
- Create: `qtrace-ui/src-web/src/components/CompletenessPane.tsx`
- Create: `qtrace-ui/src-web/src/components/ResultsPane.tsx`
- Create: `qtrace-ui/src-web/src/components/JobsPane.tsx`
- Create: `qtrace-ui/src-web/src/components/AnnotationEditor.tsx`
- Create: `qtrace-ui/src-web/src/state/navigation.ts`
- Modify: `qtrace-ui/src-web/src/components/{AppHeader,LeftDock,RightDock,BottomDock}.tsx`
- Modify: `qtrace-ui/src-web/src/state/{model,reducer}.ts`
- Create: `qtrace-ui/src-web/src/components/WorkspaceFlow.test.tsx`
- Create: `qtrace-ui/src-web/src/state/navigation.test.ts`

**Interfaces:**
- Delivers all approved V1 desktop workflows over bounded service calls.
- One selected stable event key synchronizes timeline, call tree, register, memory, detail, and completeness panes; navigation history stores stable keys, never row numbers.

- [ ] **Step 1: Write failing workspace-flow tests**

Cover:

- opening a full session and degraded single artifact;
- selecting timeline/TID and every filter field;
- same-field OR/cross-field AND request construction;
- next/previous search hit and back/forward history;
- call-node jump and fold/unfold;
- register before/after unknown/damaged labels;
- memory observed/before/after/last-written and overlap history;
- event raw typed fields/source coordinate/provenance;
- completeness gap/loss/damage/termination details;
- ELF picker confirmation and local-name precedence;
- create/edit/delete comment, rename, and highlight;
- job progress/cancel/error/retry;
- stale/out-of-order response rejection.

Assert no test API response exceeds 2,000 rows and no state property contains an array named `allEvents`, `eventsById`, or equivalent full-trace collection.

- [ ] **Step 2: Run flow tests and confirm failure**

```bash
cd qtrace-ui/src-web
npm test -- --run src/components/WorkspaceFlow.test.tsx src/state/navigation.test.ts
```

Expected: FAIL because workflow panes/actions are absent.

- [ ] **Step 3: Implement filter and synchronized pane behavior**

Filter controls validate TID/kind/module, 64-bit sequence strings, hex PC/ranges, mnemonic mode, register direction, memory overlap/direction, semantic category/name/detail before creating a projection. Display inexact result totals with an explicit `indexing` marker until the service completes the immutable result artifact.

When selection changes, request event detail, register state, related memory, and current frame with the same generation. Pane-local failure does not clear the selected event or other panes. Show `unsupported` when provider capabilities disallow an analysis and `unknown`/`damaged` when evidence is insufficient.

Navigation history contains `{workspaceId, projectionId, eventKey}` entries with a 256-entry cap and proper branch truncation after Back then new navigation. If a filter hides a history target, offer `Reveal in unfiltered timeline` by creating a new projection; do not reinterpret the old visible row number.

Annotation editor writes through service and applies returned committed revision only. On write failure, keep the draft and show the structured error. Display local rename above ELF name while keeping ELF identity/offset in details.

- [ ] **Step 4: Run complete frontend gates**

```bash
cd qtrace-ui/src-web
npm run lint
npm test
npm run build
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit complete V1 workflows**

```bash
git add qtrace-ui/src-web
git commit -m "feat(qtrace-ui): complete analysis workspace"
```

---

### Task 22: Add real-fixture cross-layer tests and Playwright desktop-workflow coverage

**Files:**
- Create: `qtrace-ui/crates/qtrace-service/tests/end_to_end.rs`
- Create: `qtrace-ui/crates/qtrace-service/src/bin/e2e_server.rs`
- Modify: `qtrace-ui/crates/qtrace-service/Cargo.toml`
- Create: `qtrace-ui/src-web/src/api/E2eQtraceApi.ts`
- Create: `qtrace-ui/src-web/src/api/createApi.ts`
- Modify: `qtrace-ui/src-web/src/main.tsx`
- Create: `qtrace-ui/src-web/playwright.config.ts`
- Create: `qtrace-ui/src-web/tests/e2e/global-setup.ts`
- Create: `qtrace-ui/src-web/tests/e2e/global-teardown.ts`
- Create: `qtrace-ui/src-web/tests/e2e/workspace.spec.ts`
- Create: `qtrace-ui/src-web/tests/e2e/restart.spec.ts`
- Create: `qtrace-ui/src-web/tests/e2e/support.ts`

**Interfaces:**
- Tests the real provider → store → analysis → service path against checked-in small sessions.
- A feature-gated loopback adapter exists only for Playwright mode; production Tauri builds contain no HTTP server, fixture path, or E2E token.

- [ ] **Step 1: Write failing Rust cross-layer acceptance tests**

Open `fixtures/sessions/valid-mixed/report.json` through an authorized test picker, wait for indexes, then query exact expected timeline/thread/call/register/memory/completeness/symbol results and persist an annotation across service restart. Also open `one-invalid-artifact` and assert other timelines remain usable.

Run:

```bash
cd qtrace-ui && cargo test -p qtrace-service --test end_to_end
```

Expected: FAIL until fixture authorization and full service composition are wired.

- [ ] **Step 2: Implement the test-only loopback adapter**

Gate `e2e_server` behind a non-default Cargo feature `e2e-fixture`; require `--fixture-root`, `--xdg-root`, and a random 128-bit token. Bind only `127.0.0.1:0`, print one bounded JSON readiness line, and serve the same DTO operations as `QtraceApi`. Picker endpoints select only named members beneath the fixed fixture root through Task 9; they never accept a client filesystem path. Apply request size 1 MiB, concurrency 8, and 30-second deadline limits.

`E2eQtraceApi` sends the token and DTOs to this adapter only when Vite mode is exactly `e2e`. `createApi` selects `TauriQtraceApi` for every production/development build. Add a test that `npm run build` output contains neither the readiness endpoint string nor `E2eQtraceApi`.

- [ ] **Step 3: Write failing Playwright workflows**

Global setup starts the feature-gated server with temporary XDG cache/data roots and launches Vite in e2e mode. Cover:

1. open real mixed session and observe index progress/ready state;
2. switch QTRB/Flight timelines and TIDs;
3. scroll far enough to request/evict multiple segments;
4. structured search, result jump, back/forward;
5. call-tree node jump and fold;
6. register/memory/detail/completeness synchronization;
7. rapid filter/thread changes with reversed response completion and no stale UI;
8. add rename/comment/highlight, restart the service with the same XDG data root, reopen, and observe committed annotations;
9. cancel a long semantic-detail job and retain the current workspace;
10. open a session with one invalid artifact and use the healthy timelines.

- [ ] **Step 4: Run cross-layer and Playwright gates**

```bash
cd qtrace-ui && cargo test -p qtrace-service --test end_to_end
cd src-web && npx playwright install --with-deps chromium
npm run e2e
npm run build
! rg -n "E2eQtraceApi|__qtrace_e2e__" dist
```

Expected: all commands exit 0; the negated `rg` finds no production E2E adapter string.

- [ ] **Step 5: Commit integration coverage**

```bash
git add qtrace-ui/crates/qtrace-service qtrace-ui/src-web
git commit -m "test(qtrace-ui): cover desktop workflows"
```

---

### Task 23: Add normal CI, scheduled fuzzing, and gated Linux packaging

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/qtrace-ui-fuzz.yml`
- Create: `.github/workflows/qtrace-ui-package.yml`
- Create: `qtrace-ui/tools/check_generated.py`

**Interfaces:**
- Normal host CI runs small deterministic Rust/frontend/Tauri/Playwright contract gates.
- Scheduled fuzzing runs both provider targets independently.
- Linux packaging cannot run unless all normal qtrace-ui gates have passed in the same job.

- [ ] **Step 1: Write a failing generated-file check**

`qtrace-ui/tools/check_generated.py` regenerates the fixture tree in a temporary directory and captures service TypeScript bindings to memory, then compares both with checked-in files. It exits nonzero with bounded path-specific diagnostics on drift. Add it to `scripts/tests/test_qtrace_ui_fixtures.py`.

Run:

```bash
python3 qtrace-ui/tools/check_generated.py
```

Expected: FAIL until the binding comparison and generated metadata are connected.

- [ ] **Step 2: Extend normal host CI**

Add a separate `qtrace-ui` job to `.github/workflows/ci.yml` using Ubuntu, Rust stable with `rustfmt`/`clippy`, Node 22 with npm cache, and the Tauri 2 Debian packages:

```text
libwebkit2gtk-4.1-dev build-essential curl wget file libxdo-dev
libssl-dev libayatana-appindicator3-dev librsvg2-dev
```

Run, in order:

```bash
python3 qtrace-ui/tools/check_generated.py
cd qtrace-ui && cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd src-web && npm ci
npm run lint
npm test
npx playwright install --with-deps chromium
npm run e2e
npm run build
```

Keep the existing Python/native/Android job unchanged except that its Python discovery naturally includes the new scaffold/fixture contract tests.

- [ ] **Step 3: Add scheduled fuzzing**

Create a weekly and manual workflow with no pull-request trigger. Install pinned nightly metadata from `rust-toolchain.toml` plus `cargo-fuzz --locked`, then run each target for 30 minutes with checked-in corpora. Upload crash/minimized artifacts on failure. The workflow has read-only contents permission and no repository secrets.

- [ ] **Step 4: Add gated Linux package workflow**

Create a manual workflow that checks out source, installs the same Rust/Node/system dependencies, runs the exact generated/format/clippy/Rust/frontend/Playwright gates from normal CI, then executes:

```bash
cd qtrace-ui/src-web && npm run tauri -- build --bundles deb,appimage
```

Add `"tauri": "cd .. && tauri"` to frontend scripts and update the Task 1 scaffold test's exact script set accordingly. From the frontend directory run `npm run tauri -- build --bundles deb,appimage`; the script changes to `qtrace-ui/`, where the sibling `src-tauri/` directory is discoverable. Upload `.deb` and `.AppImage` as workflow artifacts; do not publish a GitHub Release or overwrite an existing artifact.

- [ ] **Step 5: Run local equivalents and validate workflow syntax**

```bash
python3 qtrace-ui/tools/check_generated.py
cd qtrace-ui && cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd src-web && npm ci && npm run lint && npm test && npx playwright install --with-deps chromium && npm run e2e && npm run build
cd ../.. && python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

Expected: all commands exit 0. Inspect all three workflow `run` blocks and confirm package build appears only after every gate.

- [ ] **Step 6: Commit automation gates**

```bash
git add .github/workflows qtrace-ui/tools/check_generated.py qtrace-ui/src-web/package.json qtrace-ui/src-web/package-lock.json scripts/tests/test_qtrace_ui_scaffold.py scripts/tests/test_qtrace_ui_fixtures.py
git commit -m "ci(qtrace-ui): gate tests fuzzing and packages"
```

---

### Task 24: Build deterministic large fixtures, enforce performance targets, and document handoff

**Files:**
- Create: `qtrace-ui/tools/generate_performance_fixtures.py`
- Create: `qtrace-ui/tools/performance_gate.py`
- Create: `qtrace-ui/crates/qtrace-service/examples/perf_driver.rs`
- Create: `scripts/tests/test_qtrace_ui_performance.py`
- Create: `.github/workflows/qtrace-ui-performance.yml`
- Create: `docs/benchmarks/qtrace-ui-performance.md`
- Create: `qtrace-ui/README.md`
- Modify: `README.md`
- Modify: `.gitignore`

**Interfaces:**
- Generates, outside Git, one 10,000,000-event QTRB corpus and one exact 512 MiB Flight v2 corpus with deterministic identity.
- Measures five cold/warm runs, query latency samples, peak RSS, cache size, correctness digests, tool/analyzer identity, and fixed reference-host identity.
- Enforces cold index ≤30 s, warm open ≤2 s, viewport p95 ≤50 ms, indexed structured search p95 ≤200 ms, and indexing peak RSS ≤2 GiB.

- [ ] **Step 1: Write failing performance-harness unit tests**

Test median and nearest-rank p95 calculation, exact event/byte identity validation, threshold equality, one failing run, correctness mismatch, stale generator/analyzer identity, missing host identity, RSS parsing, and no verdict from fewer than five complete runs.

```python
class PerformanceVerdictTests(unittest.TestCase):
    def test_accepts_threshold_equality_and_rejects_one_over(self):
        self.assertTrue(verdict(report(cold_index_seconds=30.0)).passed)
        self.assertFalse(verdict(report(cold_index_seconds=30.001)).passed)

    def test_correctness_failure_overrides_fast_numbers(self):
        value = report(cold_index_seconds=1.0, correctness_digest="wrong")
        self.assertFalse(verdict(value).passed)
```

- [ ] **Step 2: Run harness tests and confirm failure**

```bash
python3 -m unittest scripts.tests.test_qtrace_ui_performance -v
```

Expected: FAIL because generator/gate modules are absent.

- [ ] **Step 3: Implement deterministic streaming generators**

The QTRB generator writes header/begin/module/definitions, then exactly 10,000,000 logical events with a deterministic mix of instruction, memory, semantic, and terminal records without holding the corpus in memory. The Flight generator preallocates exactly 512 MiB and writes valid v2 superblock/directory/emergency/chunks containing at least four interleaved TIDs, full checkpoints/deltas, instruction, memory, lifecycle, signal-handler, coverage-gap, overwritten, and termination evidence across committed chunks. Generator schema/options and complete SHA-256 go in a sibling JSON manifest.

`--check` parses both generated files with the existing Python oracle on deterministic bounded samples plus the Rust provider over the complete files and verifies exact event/completeness digest before timing. Performance generation writes only beneath an explicit output directory, refuses symlink ancestors, and atomically publishes each completed corpus.

- [ ] **Step 4: Implement the release-mode measurement driver**

`perf_driver` supports machine-readable modes:

```text
index --input <authorized benchmark manifest> --cache <empty directory>
open --input <manifest> --cache <existing directory>
workload --workspace <opened cache> --queries <deterministic query set>
```

It uses the same service/provider/store/analysis APIs and production validation; it has no fast parser or disabled checksum flag. `performance_gate.py` creates isolated XDG roots, invokes release builds, collects wall time and child peak RSS with `os.wait4`, runs five independent cold indexes, five warm opens, and at least 200 viewport plus 200 indexed structured query samples. It computes median for cold/warm and nearest-rank p95 for query samples, records every raw run, and exits nonzero on any correctness or threshold failure.

- [ ] **Step 5: Run the large performance gate on the fixed Linux reference host**

```bash
python3 qtrace-ui/tools/generate_performance_fixtures.py --output qtrace-ui-performance-evidence/corpus
python3 qtrace-ui/tools/performance_gate.py \
  --manifest qtrace-ui-performance-evidence/corpus/manifest.json \
  --evidence qtrace-ui-performance-evidence/run.json \
  --write-summary docs/benchmarks/qtrace-ui-performance.md
```

Expected: exit 0 with all five thresholds met. The generated Markdown records CPU model/count, RAM, kernel, filesystem, Rust/Node versions, generator schema, source digests, analyzer commit, cache schema/options, all raw measurements, medians/p95, peak RSS, cache sizes, correctness digests, and final verdict. Do not hand-edit measured values.

- [ ] **Step 6: Add the scheduled/manual reference-host gate**

Create `.github/workflows/qtrace-ui-performance.yml` for `workflow_dispatch` and weekly schedule on labels `[self-hosted, linux, qtrace-ui-reference]`, with read-only contents permission and no PR trigger. Generate/verify the corpus, run the release gate, and upload evidence. The job fails on host-identity drift until `docs/benchmarks/qtrace-ui-performance.md` is deliberately regenerated and reviewed.

- [ ] **Step 7: Document installation, truth model, and operator workflow**

`qtrace-ui/README.md` documents Linux prerequisites, Node 22/Rust setup, `npm ci`, development, unit/E2E tests, Tauri build, XDG cache/data locations, supported QTRB/Flight versions, session vs single-file open, capability/provenance meanings, cache rebuild, annotation backup, keyboard shortcuts, performance reproduction, and all V1 exclusions. Update root `README.md` with one qtrace-ui overview/link and keep collection CLI documentation unchanged.

- [ ] **Step 8: Run final correctness and packaging verification**

```bash
python3 qtrace-ui/tools/check_generated.py
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
cd qtrace-ui && cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd src-web && npm ci && npm run lint && npm test && npm run e2e && npm run build
npm run tauri -- build --bundles deb,appimage
cd ../.. && git diff --check
```

Expected: every command exits 0; `.deb` and `.AppImage` are produced only after all gates; original fixtures/sessions retain their pre-test SHA-256 values.

- [ ] **Step 9: Commit performance evidence and handoff docs**

```bash
git add .github/workflows/qtrace-ui-performance.yml .gitignore README.md scripts/tests/test_qtrace_ui_performance.py qtrace-ui/README.md qtrace-ui/tools qtrace-ui/crates/qtrace-service/examples docs/benchmarks/qtrace-ui-performance.md
git commit -m "perf(qtrace-ui): enforce analyzer targets"
```

---

## Completion Verification

Before declaring the implementation complete, run the Task 24 final verification from a clean worktree and the large performance gate on the recorded reference host. Then verify each approved acceptance criterion against concrete evidence:

| Acceptance area | Evidence |
|---|---|
| Full session and degraded file open | Task 9 store tests; Task 22 Playwright |
| QTRB 1.0–1.2 and Flight v2 fidelity | Tasks 4–8 golden/differential/property/fuzz tests |
| Immutable source and XDG separation | Tasks 9, 10, 13 security/publication tests |
| Correct timeline/thread ordering | Tasks 7, 11, 12 tests |
| Search/filter/page/jump | Tasks 12, 19–22 tests |
| Per-thread call tree and incomplete frames | Task 15 tests; Task 22 workflow |
| Register/memory truth and provenance | Task 14 tests; Task 22 workflow |
| ELF and local naming | Task 13 tests; Task 21 workflow |
| Canvas generation/cache correctness | Tasks 19–21 tests |
| Malformed input, isolation, cancellation | Tasks 8–10, 16–17 tests |
| CI/package gates | Task 23 workflows and local equivalents |
| Scale targets | Task 24 raw evidence and threshold verdict |

Finally run:

```bash
git status --short
git log --oneline --decorate -24
```

Expected: no uncommitted implementation files, no temporary/cache/evidence corpus tracked by Git, and one scoped commit per completed task.
