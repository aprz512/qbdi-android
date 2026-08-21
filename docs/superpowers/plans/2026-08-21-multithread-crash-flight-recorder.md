# Multi-thread Crash Flight Recorder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a QBDI-only, crash-recoverable flight recorder that retains the latest full target-module trace for every target-owned thread and identifies target-issued termination syscalls.

**Architecture:** Spawn-time inline hooks take over the target init entry, target-created pthread start routines, and configured callbacks. Each captured TID owns a QBDI session and chunk writer backed by one process-wide mmap ring; a signal broker virtualizes target-side `rt_sigaction`, while host tools recover independent chunks and merge them by publication sequence.

**Tech Stack:** C++20, Android arm64, QBDI 0.12.1, ShadowHook, pthreads, mmap, Python 3 standard library, Android Gradle/NDK, CMake, CTest, Frida spawn injection.

## Global Constraints

- Reliable mode requires spawn injection before the configured target init entry.
- Cover the init path, target-owned pthreads, and configured callback gateways; do not claim coverage for unrelated process threads.
- Instrument instructions only in the target module. External calls retain boundaries and selected semantics.
- Defaults: 512 MiB artifact, 256 KiB chunks, 256 thread entries, four protected newest chunks per active thread.
- Artifacts are app-private mode `0600`, little-endian, pointer-width tagged, `MAP_SHARED`, and uncompressed on device.
- Records use ownership generation, checked bounds, checksum, and a release-published commit word.
- Chunks are independently decodable and begin with `x0`-`x30`, `sp`, `pc`, and `nzcv` checkpoints.
- Preserve current `full` memory metadata and bounded pre/post bytes. SIMD/FP serialization is excluded.
- Observe target arm64 `svc` instructions; libc `abort`, `raise`, and `kill` hooks are not a correctness path.
- Runtime is fail-open; evidence is fail-closed with permanent `COVERAGE_GAP` and incomplete status.
- Signal-context code performs no allocation, ordinary locking, compression, ordinary logging, or chunk rotation.
- Main process only. Fork children detach without mutating inherited recorder or QBDI state.
- Do not add multi-process coordination or claim late-attach coverage equivalent to spawn-before-load.
- Do not promise device power-loss durability or hide the master signal action from untraced modules.
- Production remains exception-free and RTTI-free.
- A guest signal handler is dispatched natively and is intentionally untraced; the master handler
  must never enter a QBDI execution API.
- Task 1 is a stop gate: do not build the recorder unless native broker dispatch, guest-context
  mapping, and handler hiding pass on arm64 hardware.

## File Map

- `events/trace_sink.h`: collector/rule-facing event interface implemented by normal and flight writers.
- `core/arm64_syscall.h`, `core/arm64_syscall.cpp`, `core/signal_context_arm64.h`, and `core/signal_context_arm64.cpp`: pure arm64 ABI helpers.
- `core/signal_broker.h` and `core/signal_broker.cpp`: guest action virtualization, kernel master actions, dispatch, and fork detach.
- `flight/flight_format.h`: fixed wire structs, record types, constants, flags, and size assertions.
- `flight/flight_artifact.h` and `flight/flight_artifact.cpp`: file/mmap layout, directory, emergency slots, and completeness.
- `flight/flight_chunk_writer.h` and `flight/flight_chunk_writer.cpp`: allocation fairness, generation ownership, commit, seal, and rotation.
- `flight/flight_encoder.h`, `flight/flight_encoder.cpp`, `flight/flight_trace_sink.h`, and `flight/flight_trace_sink.cpp`: independent chunk encoding and trace facade.
- `core/qbdi_thread_session.h`, `core/qbdi_thread_session.cpp`, `core/capture_coordinator.h`, and `core/capture_coordinator.cpp`: per-TID execution and run ownership.
- `hooks/thread_create_gateway.h` and `hooks/thread_create_gateway.cpp`: persistent `pthread_create` hook and worker trampoline.
- `scripts/flight_trace.py` and `scripts/flight_convert.py`: recovery, rendering, and atomic publication.
- `scripts/pull_trace.py`, Frida config, demo fixtures, README, and trace-format docs: integration and acceptance.

---

### Task 1: Prove Native Signal-broker Compatibility

**Files:**
- Create: `tracer/src/main/cpp/core/arm64_syscall.h`
- Create: `tracer/src/main/cpp/core/arm64_syscall.cpp`
- Create: `tracer/src/main/cpp/core/signal_context_arm64.h`
- Create: `tracer/src/main/cpp/core/signal_context_arm64.cpp`
- Create: `tracer/src/main/cpp/core/signal_probe.h`
- Create: `tracer/src/main/cpp/core/signal_probe.cpp`
- Create: `tracer/src/test/cpp/arm64_syscall_test.cpp`
- Create: `tracer/src/test/cpp/signal_context_arm64_test.cpp`
- Create: `scripts/signal_probe.js`
- Modify: `app/src/main/cpp/demo_target/demo_scenes.h`
- Modify: `app/src/main/cpp/demo_target/demo_scenes.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Produces: `bool is_arm64_svc(uint32_t) noexcept`.
- Produces: `Arm64SyscallSnapshot snapshot_arm64_syscall(uintptr_t, const QBDI::GPRState&) noexcept`.
- Produces: pure host-portable `Arm64SignalContext` with `x0`-`x30`, `sp`, `pc`, and `pstate`, plus
  `qbdi_gpr_to_signal_context` and inverse mapping.
- Produces on Android arm64: explicit adapters between `Arm64SignalContext` and Bionic
  `ucontext_t`; host tests never include or inspect host `ucontext_t`.
- Produces: `SignalProbeResult run_native_signal_probe(uintptr_t entry, uintptr_t module_address) noexcept`.

- [ ] **Step 1: Write failing host tests**

```cpp
void decodes_svc_and_arguments() {
    QBDI::GPRState gpr{};
    gpr.pc = 0x71001234;
    gpr.x8 = 131; // Android arm64 __NR_tgkill
    gpr.x0 = 100; gpr.x1 = 101; gpr.x2 = 9;
    CHECK(is_arm64_svc(0xd4000001U));
    const auto call = snapshot_arm64_syscall(gpr.pc, gpr);
    CHECK(call.number == 131 && call.args[0] == 100 && call.args[2] == 9);
}

void round_trips_guest_registers() {
    QBDI::GPRState source{};
    source.x0 = 0x1111; source.x29 = 0x2929; source.lr = 0x3030;
    source.sp = 0x4040; source.pc = 0x5050; source.nzcv = 0x60000000;
    Arm64SignalContext context{};
    QBDI::GPRState restored{};
    CHECK(qbdi_gpr_to_signal_context(source, &context));
    CHECK(signal_context_to_qbdi_gpr(context, &restored));
    CHECK(restored.x0 == source.x0 && restored.pc == source.pc);
    CHECK(restored.sp == source.sp && restored.nzcv == source.nzcv);
}
```

- [ ] **Step 2: Configure and verify RED**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake -S tracer/src/test/cpp -B build/flight-recorder-host-make
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target arm64_syscall_test signal_context_arm64_test
```

Expected: configure or build fails because targets and interfaces do not exist.

- [ ] **Step 3: Implement the pure helpers**

```cpp
struct Arm64SyscallSnapshot {
    uintptr_t pc = 0;
    int64_t number = -1;
    std::array<uint64_t, 6> args{};
};
```

Use opcode mask `(opcode & 0xffe0001fU) == 0xd4000001U`. Map Android arm64
`uc_mcontext.regs[0..30]`, `sp`, `pc`, and `pstate` explicitly without casting wire/native layouts.
Compile those Bionic adapters only for `__ANDROID__ && __aarch64__`; host tests exercise the pure
`Arm64SignalContext` representation in both directions with hand-derived literal values.

- [ ] **Step 4: Write the direct-syscall device test and verify RED**

Add default-visible `demo_signal_probe(uint64_t cookie)`. It uses inline `svc 0` for
`rt_sigaction` and `tgkill`; its `SA_SIGINFO` handler validates original target PC and cookie state,
changes guest `x19`, and exposes whether that change was observed after return. Make
`signal_probe.js` require exactly:

```json
{"guest_handler_called":true,"guest_pc_original":true,"register_cookie":true,"qbdi_handler_untraced":true,"handler_query_hidden":true}
```

Build, install, and run the fixture against the unchanged tracer:

```bash
./gradlew :app:assembleDebug :tracer:assembleDebug :tracer:copyTracerDebug
frida -U -f com.aprz.qbdiandroid -l scripts/signal_probe.js
```

Expected: exit nonzero because the tracer probe export or the new `qbdi_handler_untraced` behavior
does not exist. A JavaScript syntax error, missing application install, or stale staged tracer is not
an accepted RED.

- [ ] **Step 5: Implement minimal native broker dispatch**

The probe interceptor emulates direct `rt_sigaction` with `QBDI::SKIP_INST` and snapshots
the primary guest state before `tgkill`. Its allocation-free master handler patches a stack-local
guest `ucontext`, calls the retained target handler directly as native code, and copies returned
`x0`-`x30`, `sp`, `pc`, and `pstate` changes back to the published primary guest state. It records
fixed begin/return probe markers and never calls `VM::callA`, `VM::run`, or another QBDI execution
API. An instruction callback counts target-handler instructions so the probe fails if the handler
is accidentally traced. Do not retain the exploratory secondary signal VM.

- [ ] **Step 6: Run the gate**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target arm64_syscall_test signal_context_arm64_test
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure -R 'arm64_syscall|signal_context_arm64'
./gradlew :app:assembleDebug :tracer:assembleDebug :tracer:copyTracerDebug
frida -U -f com.aprz.qbdiandroid -l scripts/signal_probe.js
```

Expected: both CTest targets pass and all five JSON fields are `true`. Review the master-handler
call graph and reject the gate if it reaches any QBDI execution API or non-async-signal-safe
operation. Otherwise stop, retain probe evidence, and revise the approved design before any Task 2
work.

- [ ] **Step 7: Commit**

```bash
git add app/src/main/cpp/demo_target/demo_scenes.h app/src/main/cpp/demo_target/demo_scenes.cpp scripts/signal_probe.js tracer/src/main/cpp/core/arm64_syscall.h tracer/src/main/cpp/core/arm64_syscall.cpp tracer/src/main/cpp/core/signal_context_arm64.h tracer/src/main/cpp/core/signal_context_arm64.cpp tracer/src/main/cpp/core/signal_probe.h tracer/src/main/cpp/core/signal_probe.cpp tracer/src/main/cpp/CMakeLists.txt tracer/src/test/cpp/arm64_syscall_test.cpp tracer/src/test/cpp/signal_context_arm64_test.cpp tracer/src/test/cpp/CMakeLists.txt
git commit -m "test(trace): prove native signal compatibility"
```

---

### Task 2: Introduce the Trace Sink Seam

**Files:**
- Create: `tracer/src/main/cpp/events/trace_sink.h`
- Modify: `tracer/src/main/cpp/events/binary_trace_writer.h`
- Modify: `tracer/src/main/cpp/core/instruction_collector.h`
- Modify: `tracer/src/main/cpp/core/instruction_collector.cpp`
- Modify: `tracer/src/main/cpp/rules/code_rule_context.h`
- Modify: `tracer/src/main/cpp/rules/code_rule_context.cpp`
- Test: `tracer/src/test/cpp/instruction_collector_integration_test.cpp`

**Interfaces:**
- Produces: abstract `TraceSink` for collector, rules, normal QTRB, and flight output.

- [ ] **Step 1: Add a failing fake-sink test**

```cpp
class RecordingSink final : public TraceSink {
public:
    bool instruction(const TraceContext &, const InstructionRecord &) override { ++count; return true; }
    bool memory(const TraceContext &, uintptr_t, const MemoryRecord &) override { return true; }
    bool call(const char *, std::string_view, std::string_view) override { return true; }
    bool rule(const std::string &, const std::string &) override { return true; }
    bool error(const std::string &) override { return true; }
    bool failed() const noexcept override { return false; }
    size_t count = 0;
};
```

Construct `InstructionCollector` with the fake and assert one completed pending instruction increments
`count` without constructing `BinaryTraceWriter`.

- [ ] **Step 2: Verify RED**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target instruction_collector_integration_test
```

Expected: compile fails because `TraceSink` does not exist.

- [ ] **Step 3: Implement and migrate the narrow interface**

```cpp
class TraceSink {
public:
    virtual ~TraceSink() = default;
    virtual bool instruction(const TraceContext &, const InstructionRecord &) = 0;
    virtual bool memory(const TraceContext &, uintptr_t, const MemoryRecord &) = 0;
    virtual bool call(const char *, std::string_view, std::string_view) = 0;
    virtual bool rule(const std::string &, const std::string &) = 0;
    virtual bool error(const std::string &) = 0;
    virtual bool failed() const noexcept = 0;
};
```

Make `BinaryTraceWriter final : public TraceSink`. Generalize only collector/rule-facing pointers;
leave normal lifecycle methods concrete.

- [ ] **Step 4: Verify affected tests**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure -R 'instruction_collector|code_rule|binary_trace_writer|trace_run_session'
```

Expected: all selected tests pass with unchanged QTRB bytes.

- [ ] **Step 5: Commit**

```bash
git add tracer/src/main/cpp/events/trace_sink.h tracer/src/main/cpp/events/binary_trace_writer.h tracer/src/main/cpp/core/instruction_collector.h tracer/src/main/cpp/core/instruction_collector.cpp tracer/src/main/cpp/rules/code_rule_context.h tracer/src/main/cpp/rules/code_rule_context.cpp tracer/src/test/cpp/instruction_collector_integration_test.cpp
git commit -m "refactor(trace): add event sink seam"
```

---

### Task 3: Lock Flight Configuration and Wire Format

**Files:**
- Create: `tracer/src/main/cpp/flight/flight_format.h`
- Create: `tracer/src/test/cpp/flight_format_test.cpp`
- Modify: `tracer/src/main/cpp/core/trace_config.h`
- Modify: `tracer/src/main/cpp/core/trace_config.cpp`
- Modify: `tracer/src/test/cpp/trace_config_test.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Produces: `FlightOptions`, `FlightArtifactIdentityView`, superblock/directory/chunk/record/emergency
  POD structs, record types, and exact byte constants.

- [ ] **Step 1: Write failing format/config tests**

```cpp
const TraceConfig parsed = parse_trace_config(
    "flight=1;flight_mb=512;flight_chunk_kb=256;flight_max_threads=256;flight_protected_chunks=4");
CHECK(parsed.valid && parsed.flight.enabled);
CHECK(parsed.flight.capacity_bytes == 512ULL * 1024 * 1024);
CHECK(sizeof(FlightRecordHeader) == kFlightRecordHeaderBytes);
CHECK(kFlightMagic == 0x51464c54U && kFlightVersion == 1);
CHECK(kFlightTargetNameBytes == 128);
```

Reject capacity outside 64–2048 MiB, non-power-of-two chunk sizes outside 64–1024 KiB, thread count
outside 1–1024, zero protected chunks, and a protected reservation larger than total capacity.

- [ ] **Step 2: Verify RED**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target trace_config_test flight_format_test
```

Expected: compile fails because flight types do not exist.

- [ ] **Step 3: Implement exact options and wire types**

```cpp
struct FlightOptions {
    bool enabled = false;
    uint64_t capacity_bytes = 512ULL * 1024 * 1024;
    uint32_t chunk_bytes = 256U * 1024;
    uint32_t max_threads = 256;
    uint32_t protected_chunks = 4;
};

struct FlightArtifactIdentityView {
    uint64_t run_id;
    uint32_t pid;
    uint32_t module_generation;
    const char *target_name;
    uint16_t target_name_bytes;
};

enum class FlightRecordType : uint16_t {
    ChunkBegin = 1, ThreadBegin = 2, ThreadEnd = 3, Instruction = 4,
    Memory = 5, Call = 6, Rule = 7, Error = 8, RegisterDelta = 9,
    Syscall = 10, Signal = 11, SignalHandlerBegin = 12,
    SignalHandlerReturn = 13, TerminationIntent = 14, CoverageGap = 15,
};
```

Use fixed-width integers, explicit reserved bytes, and `static_assert`; never map native `bool`,
pointers, atomics, `sigaction`, or C++ containers. The input view is not persisted: encode its
`run_id`, `pid`, `module_generation`, `target_name_bytes`, and at most 128 UTF-8 target-name bytes
into explicit superblock fields. Reject zero run IDs, zero PIDs, empty names, names longer than 128
bytes, and embedded NUL bytes. Decode validates the same invariants and zero-filled name padding.

- [ ] **Step 4: Verify GREEN and commit**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure -R 'trace_config|flight_format'
git add tracer/src/main/cpp/flight/flight_format.h tracer/src/test/cpp/flight_format_test.cpp tracer/src/main/cpp/core/trace_config.h tracer/src/main/cpp/core/trace_config.cpp tracer/src/test/cpp/trace_config_test.cpp tracer/src/main/cpp/CMakeLists.txt tracer/src/test/cpp/CMakeLists.txt
git commit -m "feat(trace): define flight recorder format"
```

---

### Task 4: Build the mmap Artifact and Fair Chunk Allocator

**Files:**
- Create: `tracer/src/main/cpp/flight/flight_artifact.h`
- Create: `tracer/src/main/cpp/flight/flight_artifact.cpp`
- Create: `tracer/src/main/cpp/flight/flight_chunk_writer.h`
- Create: `tracer/src/main/cpp/flight/flight_chunk_writer.cpp`
- Create: `tracer/src/test/cpp/flight_artifact_test.cpp`
- Create: `tracer/src/test/cpp/flight_chunk_writer_test.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Consumes: Task 3 options and wire structs.
- Produces: `FlightArtifact::create(path, options, identity)/register_thread/acquire_chunk/mark_incomplete/write_emergency/detach_after_fork_child`.
- Produces: `FlightChunkWriter::append/seal/rotate`.

- [ ] **Step 1: Write failing storage tests**

Test checked layout, `0600`, `ftruncate` before mmap, identity round-trip/rejection,
unique/duplicate TIDs, directory exhaustion, generation increments, four protected chunks,
oldest-unprotected reclamation, child detach, sealed
checksums, and a torn final record:

```cpp
CHECK(writer.append(FlightRecordType::Instruction, payload));
writer.test_interrupt_before_commit();
CHECK(!scan_record(writer.active_bytes(), writer.active_size(), &decoded));
CHECK(scan_record(writer.previous_record_bytes(), writer.previous_record_size(), &decoded));
```

- [ ] **Step 2: Verify RED**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target flight_artifact_test flight_chunk_writer_test
```

Expected: build fails because storage classes do not exist.

- [ ] **Step 3: Implement artifact ownership and allocation**

Compute aligned offsets with checked arithmetic. Open with `O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC` mode
`0600`, validate and encode the required identity, `ftruncate`, then `mmap(MAP_SHARED)`, and publish
initialized superblock last. Use one normal
mutex only for chunk rotation. `mark_incomplete` never reverses. Emergency slots use fixed atomic
stores and never allocate.

- [ ] **Step 4: Implement two-phase record commit**

Write header/payload/checksum, then release-store `kFlightRecordCommit ^ total_bytes ^ generation`.
Seal valid length, sequence endpoints, record count, and checksum before rotation. Increment a
reclaimed chunk's generation before new ownership publication.

- [ ] **Step 5: Verify stress and commit**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure -R 'flight_artifact|flight_chunk_writer'
build/flight-recorder-host-make/flight_chunk_writer_test --stress-rotations 100
git add tracer/src/main/cpp/flight/flight_artifact.h tracer/src/main/cpp/flight/flight_artifact.cpp tracer/src/main/cpp/flight/flight_chunk_writer.h tracer/src/main/cpp/flight/flight_chunk_writer.cpp tracer/src/test/cpp/flight_artifact_test.cpp tracer/src/test/cpp/flight_chunk_writer_test.cpp tracer/src/main/cpp/CMakeLists.txt tracer/src/test/cpp/CMakeLists.txt
git commit -m "feat(trace): add persistent flight ring"
```

---

### Task 5: Encode Independent Chunks and Register Deltas

**Files:**
- Create: `tracer/src/main/cpp/flight/flight_encoder.h`
- Create: `tracer/src/main/cpp/flight/flight_encoder.cpp`
- Create: `tracer/src/main/cpp/flight/flight_trace_sink.h`
- Create: `tracer/src/main/cpp/flight/flight_trace_sink.cpp`
- Create: `tracer/src/test/cpp/flight_encoder_test.cpp`
- Create: `tracer/src/test/cpp/flight_trace_sink_test.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Consumes: `TraceSink`, `FlightChunkWriter`, `InstructionRecord`, `MemoryRecord`, and QBDI GPR state.
- Produces: allocation-free `FlightEncoder` and `FlightTraceSink final : TraceSink`.

- [ ] **Step 1: Write failing independent-decode tests**

Encode two chunks, discard the first, and assert the second resolves all instruction/string IDs.
Begin chunk two with a checkpoint, mutate `x0`, `x19`, `sp`, and `nzcv`, then assert mask/value order
reconstructs the exact state. Reuse full-profile fixtures to compare memory pre/post bytes.

- [ ] **Step 2: Verify RED**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target flight_encoder_test flight_trace_sink_test
```

Expected: build fails because encoder and sink do not exist.

- [ ] **Step 3: Implement encoder and sink**

Use a fixed-capacity, chunk-local open-addressed dictionary reset on rotation. Emit definitions
before references. A checkpoint writes 34 values; a delta writes a 34-bit change mask followed by
changed values in ascending index order. Rotate once when a record does not fit; fail without a
partial record if it still cannot fit. `FlightTraceSink` maps the existing five event methods and
emits a fresh GPR checkpoint before the first event in every chunk.

- [ ] **Step 4: Verify and commit**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure -R 'flight_encoder|flight_trace_sink|memory_profile|instruction_collector'
git add tracer/src/main/cpp/flight/flight_encoder.h tracer/src/main/cpp/flight/flight_encoder.cpp tracer/src/main/cpp/flight/flight_trace_sink.h tracer/src/main/cpp/flight/flight_trace_sink.cpp tracer/src/test/cpp/flight_encoder_test.cpp tracer/src/test/cpp/flight_trace_sink_test.cpp tracer/src/main/cpp/CMakeLists.txt tracer/src/test/cpp/CMakeLists.txt
git commit -m "feat(trace): encode independent flight chunks"
```

---

### Task 6: Implement Strict Host Recovery

**Files:**
- Create: `scripts/flight_trace.py`
- Create: `scripts/flight_convert.py`
- Create: `scripts/tests/test_flight_trace.py`
- Create: `scripts/tests/test_flight_convert.py`

**Interfaces:**
- Consumes: Tasks 3 and 5 wire layouts.
- Produces: `recover_flight(source: BinaryIO) -> FlightRecovery`.
- Produces: `publish_flight_outputs(source: Path, output_dir: Path, force: bool) -> tuple[Path, ...]`.

- [ ] **Step 1: Write failing recovery tests**

Build `struct.pack` fixtures for sealed chunks, active committed prefix, torn suffix, stale generation,
overwritten range, deltas, terminal slot, and coverage gap:

```python
recovery = recover_flight(io.BytesIO(artifact))
self.assertEqual([7, 8, 11], [event.global_seq for event in recovery.merged])
self.assertEqual(0x71001234, recovery.threads[321].registers.pc)
self.assertEqual(321, recovery.summary["termination"]["initiator_tid"])
self.assertFalse(recovery.summary["complete"])
self.assertEqual([[9, 10]], recovery.summary["lost_sequences"])
```

- [ ] **Step 2: Verify RED**

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts.tests.test_flight_trace scripts.tests.test_flight_convert -v
```

Expected: imports fail because modules do not exist.

- [ ] **Step 3: Implement strict parsing and atomic publication**

Use explicit little-endian `Struct` objects, checked region arithmetic, enum validation, and exact
reads. Reject bad superblock bounds or identity fields, sealed checksum failures, and duplicate
global sequences. Expose run ID, PID, module generation, and target module name in the JSON summary.
Ignore
only a torn suffix of an active chunk. Resolve dictionaries per chunk, apply deltas from the chunk
checkpoint, and emit merged/per-TID text plus JSON summary. Write every output to same-directory
temporary files and publish all-or-none with the existing no-overwrite rule.

- [ ] **Step 4: Verify and commit**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS=error python3 -m unittest scripts.tests.test_flight_trace scripts.tests.test_flight_convert -v
git add scripts/flight_trace.py scripts/flight_convert.py scripts/tests/test_flight_trace.py scripts/tests/test_flight_convert.py
git commit -m "feat(trace): recover flight artifacts"
```

---

### Task 7: Add Capture Coordinator and Per-thread QBDI Sessions

**Files:**
- Create: `tracer/src/main/cpp/core/capture_coordinator.h`
- Create: `tracer/src/main/cpp/core/capture_coordinator.cpp`
- Create: `tracer/src/main/cpp/core/qbdi_thread_session.h`
- Create: `tracer/src/main/cpp/core/qbdi_thread_session.cpp`
- Create: `tracer/src/test/cpp/capture_coordinator_test.cpp`
- Create: `tracer/src/test/cpp/qbdi_thread_session_test.cpp`
- Modify: `tracer/src/main/cpp/tracer_entry.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Produces: `CaptureCoordinator::start/enter/leave/mark_coverage_gap/detach_after_fork_child`.
- Produces: `QbdiThreadSession::call(entry, args, indirect_result) -> TraceRunResult`.
- Produces: `thread_local QbdiThreadSession *current_qbdi_thread_session() noexcept`.

- [ ] **Step 1: Write failing lifecycle tests**

Use fake session/artifact factories to assert one artifact per run, stable module generation, same-TID
reuse, cross-TID separation, permanent incomplete status, running-VM re-entry rejection, idempotent
leave, and child detach.

- [ ] **Step 2: Verify RED**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target capture_coordinator_test qbdi_thread_session_test
```

Expected: build fails because coordinator/session do not exist.

- [ ] **Step 3: Extract reusable QBDI execution**

Move VM callback registration, module instrumentation, GPR argument setup, full memory setup, and
target call into `QbdiThreadSession`. Normal scene mode constructs a short-lived session with
`BinaryTraceWriter`; flight mode retains one session per TID with `FlightTraceSink`. Preserve native
fallback and outward return values. In `tracer_entry.cpp`, create the coordinator before flight hooks;
the init scene is required and other nonzero scenes become callback gateways.

- [ ] **Step 4: Verify and commit**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure -R 'capture_coordinator|qbdi_thread_session|qbdi_runner_lifecycle|trace_run_session|tracer_entry_proxy|failure_state'
git add tracer/src/main/cpp/core/capture_coordinator.h tracer/src/main/cpp/core/capture_coordinator.cpp tracer/src/main/cpp/core/qbdi_thread_session.h tracer/src/main/cpp/core/qbdi_thread_session.cpp tracer/src/test/cpp/capture_coordinator_test.cpp tracer/src/test/cpp/qbdi_thread_session_test.cpp tracer/src/main/cpp/tracer_entry.cpp tracer/src/main/cpp/CMakeLists.txt tracer/src/test/cpp/CMakeLists.txt
git commit -m "feat(trace): add per-thread QBDI sessions"
```

---

### Task 8: Capture Target-owned pthreads

**Files:**
- Create: `tracer/src/main/cpp/hooks/thread_create_gateway.h`
- Create: `tracer/src/main/cpp/hooks/thread_create_gateway.cpp`
- Create: `tracer/src/test/cpp/thread_create_gateway_test.cpp`
- Modify: `tracer/src/main/cpp/hooks/inline_hook_adapter.h`
- Modify: `tracer/src/main/cpp/hooks/inline_hook_adapter.cpp`
- Modify: `tracer/src/main/cpp/core/capture_coordinator.cpp`
- Modify: `tracer/src/main/cpp/tracer_entry.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Consumes: active-session TLS and retained module from Task 7.
- Produces: `ThreadCreateGateway::install/should_capture/create/detach_after_fork_child`.

- [ ] **Step 1: Write failing ownership and ABI tests**

Cover a start routine inside the module, active creator TLS, unrelated bypass, exact `pthread_attr_t`,
argument and return pointer, `pthread_exit`, cancellation cleanup, create failure, nested creation,
allocation failure, and child detach.

- [ ] **Step 2: Verify RED**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target thread_create_gateway_test
```

Expected: build fails because the gateway does not exist.

- [ ] **Step 3: Implement persistent hook and trampoline**

Keep the retained `pthread_create` bypass installed for the process lifetime. Allocate this object in
normal creator context before calling the real function:

```cpp
struct ThreadStart {
    CaptureCoordinator *coordinator;
    void *(*original)(void *);
    void *argument;
    pid_t creator_tid;
    uint64_t module_generation;
};
```

The trampoline owns it, registers cleanup, writes `THREAD_BEGIN`, executes the original routine via
the TID session, writes `THREAD_END`, and returns the exact pointer. Allocation/hook failure calls the
retained original path and permanently marks a coverage gap. Install before releasing target init.

- [ ] **Step 4: Verify and commit**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure -R 'thread_create_gateway|capture_coordinator|tracer_entry_proxy|failure_state'
git add tracer/src/main/cpp/hooks/thread_create_gateway.h tracer/src/main/cpp/hooks/thread_create_gateway.cpp tracer/src/test/cpp/thread_create_gateway_test.cpp tracer/src/main/cpp/hooks/inline_hook_adapter.h tracer/src/main/cpp/hooks/inline_hook_adapter.cpp tracer/src/main/cpp/core/capture_coordinator.cpp tracer/src/main/cpp/tracer_entry.cpp tracer/src/main/cpp/CMakeLists.txt tracer/src/test/cpp/CMakeLists.txt
git commit -m "feat(trace): capture target pthreads"
```

---

### Task 9: Productionize SignalBroker and Termination Records

**Files:**
- Create: `tracer/src/main/cpp/core/signal_broker.h`
- Create: `tracer/src/main/cpp/core/signal_broker.cpp`
- Create: `tracer/src/test/cpp/signal_broker_test.cpp`
- Create: `tracer/src/test/cpp/termination_syscall_test.cpp`
- Modify: `tracer/src/main/cpp/core/instruction_collector.h`
- Modify: `tracer/src/main/cpp/core/instruction_collector.cpp`
- Modify: `tracer/src/main/cpp/core/qbdi_thread_session.cpp`
- Modify: `tracer/src/main/cpp/core/capture_coordinator.cpp`
- Modify: `tracer/src/main/cpp/core/trace_process_lifecycle.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Consumes: Task 1 ABI helpers, Task 4 emergency slots, and Task 7 session TLS.
- Produces: `SignalBroker::install/observe_rt_sigaction/dispatch/detach_after_fork_child`.
- Produces: `TerminationObserver::before_svc(snapshot, writer) -> QBDI::VMAction`.

- [ ] **Step 1: Write failing signal/syscall tests**

Signal tests cover install/query/replace, normal and `SA_SIGINFO`, default/ignore, masks,
`SA_NODEFER`, `SA_RESETHAND`, lazy master installation, raw-syscall recursion bypass, errno/result,
stale delivery generations, nested delivery, handler address hiding, guest PC mapping, and child
detach. They also assert native custom-handler dispatch, begin/return interval publication, returned
general-register application, and zero QBDI execution calls during master dispatch. Syscall tests
cover arm64 numbers 93, 94, 129, 130, 131, and 138 and assert the emergency record is committed
before `QBDI::CONTINUE`.

- [ ] **Step 2: Verify RED**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target signal_broker_test termination_syscall_test
```

Expected: build fails because broker/observer do not exist.

- [ ] **Step 3: Implement broker and PREINST integration**

Use fixed signal/generation tables and active delivery counters following `crash_marker.cpp` ownership.
Normal context installs/retires actions. The master handler writes one emergency slot, patches a
stack-local guest `ucontext`, emits `SIGNAL_HANDLER_BEGIN`, invokes custom handlers directly as
native code with exact guest masks/flags, applies returned general-register changes, emits
`SIGNAL_HANDLER_RETURN`, and raw-redelivers defaults. It never enters QBDI. Before
`pending_.begin`, recognize `svc`. Virtualized
`rt_sigaction` uses guarded target memory, sets guest `x0`, and returns `QBDI::SKIP_INST` while still
emitting `SYSCALL`; termination calls commit `TERMINATION_INTENT` before continuing.

- [ ] **Step 4: Verify and commit**

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure -R 'signal_broker|termination_syscall|instruction_collector|failure_state|tracer_entry_proxy'
git add tracer/src/main/cpp/core/signal_broker.h tracer/src/main/cpp/core/signal_broker.cpp tracer/src/test/cpp/signal_broker_test.cpp tracer/src/test/cpp/termination_syscall_test.cpp tracer/src/main/cpp/core/instruction_collector.h tracer/src/main/cpp/core/instruction_collector.cpp tracer/src/main/cpp/core/qbdi_thread_session.cpp tracer/src/main/cpp/core/capture_coordinator.cpp tracer/src/main/cpp/core/trace_process_lifecycle.cpp tracer/src/main/cpp/CMakeLists.txt tracer/src/test/cpp/CMakeLists.txt
git commit -m "feat(trace): broker signals and exit syscalls"
```

---

### Task 10: Integrate Config, Pulling, and Documentation

**Files:**
- Modify: `scripts/trace_config.js`
- Modify: `scripts/spawn_trace.js`
- Modify: `scripts/pull_trace.py`
- Modify: `scripts/tests/test_pull_trace.py`
- Modify: `scripts/flight_convert.py`
- Modify: `README.md`
- Modify: `docs/trace-format.md`

**Interfaces:**
- Consumes: `.flight.bin` and `publish_flight_outputs`.
- Produces: safe flight selection, pull, conversion, and documented operational contract.

- [ ] **Step 1: Write failing pull/config tests**

Cover suffix classification, explicit/latest selection, streaming without LZ4, no-overwrite for all
derived files, cleanup on conversion failure, missing terminal recovery, and exact Frida fields.

- [ ] **Step 2: Verify RED**

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts.tests.test_pull_trace scripts.tests.test_flight_convert -v
```

Expected: `.flight.bin` is rejected.

- [ ] **Step 3: Implement config and pull routing**

Add the same object to both Frida configs:

```javascript
flight: { enabled: true, capacityMb: 512, chunkKb: 256, maxThreads: 256, protectedChunks: 4 }
```

Encode Task 3's five fields. Add `.flight.bin` to safe classification, stream atomically, call
`publish_flight_outputs` unless compressed-only, and derive status from recovery summary rather than
normal metrics/crash sidecars.

- [ ] **Step 4: Document and verify all host tests**

Document spawn-before-load, target-owned thread coverage, defaults, signal virtualization, direct
syscalls, `SIGKILL`, completeness, outputs, and pull commands. Then run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS=error python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

Expected: all Python tests pass and normal QTRB cases are unchanged.

- [ ] **Step 5: Commit**

```bash
git add scripts/trace_config.js scripts/spawn_trace.js scripts/pull_trace.py scripts/tests/test_pull_trace.py scripts/flight_convert.py README.md docs/trace-format.md
git commit -m "feat(trace): integrate flight artifact tooling"
```

---

### Task 11: Add Randomized Multi-thread Device Acceptance

**Files:**
- Modify: `app/src/main/cpp/demo_target/demo_scenes.h`
- Modify: `app/src/main/cpp/demo_target/demo_scenes.cpp`
- Modify: `app/src/main/cpp/demo_target/demo_target.cpp`
- Modify: `app/src/main/kotlin/com/aprz/qbdiandroid/NativeDemo.kt`
- Modify: `app/src/main/kotlin/com/aprz/qbdiandroid/MainActivity.kt`
- Create: `scripts/flight_acceptance.py`
- Create: `scripts/tests/test_flight_acceptance.py`
- Create: `docs/benchmarks/flight-recorder-acceptance.md`

**Interfaces:**
- Produces: seeded 16-worker fixture for direct `tgkill`, `exit_group`, synchronous fault,
  target-issued `SIGKILL`, and external `SIGKILL`.
- Produces: checked-in device/build/artifact evidence.

- [ ] **Step 1: Write failing acceptance-agent tests**

Test seed expansion, one selected terminator, independent TID/PC oracle, adb/run-as safety, artifact
selection, minimum four chunks per TID, no initiator for external `SIGKILL`, and nonzero exit on any
coverage gap.

- [ ] **Step 2: Verify RED**

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts.tests.test_flight_acceptance -v
```

Expected: import fails because the agent does not exist.

- [ ] **Step 3: Implement fixture and agent**

Create 16 workers from traced init. Each performs seeded delays and target memory mutations long
enough for five ring rotations. The selected worker emits one direct syscall/fault. Log expected TIDs
and original call-site offsets before termination as an independent oracle. The agent installs fresh
processes, triggers each seed/mode, pulls artifacts, verifies oracle, and rejects tracer addresses in
guest handler queries or ucontexts.

- [ ] **Step 4: Run device acceptance**

```bash
./gradlew :app:assembleDebug :tracer:assembleDebug :tracer:copyTracerDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
python3 scripts/flight_acceptance.py --package com.aprz.qbdiandroid --device 192.168.51.42:5555 --seeds 101,202,303,404,505 --artifact-mb 512
```

Expected: observable target terminations match oracle TID/PC; external `SIGKILL` has no initiator;
all artifacts decode; each TID retains four chunks; no coverage gap or guest-visible tracer address.

- [ ] **Step 5: Record evidence and run full verification**

Record device/product, Android/fingerprint, SELinux, APK/tracer hashes, QBDI version, seeds, modes,
expected/observed TID/PC, thread/rotation/chunk counts, decode status, and artifact hashes. Run:

```bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure
PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS=error python3 -m unittest discover -s scripts/tests -p 'test_*.py'
./gradlew :app:assembleDebug :app:assembleRelease :tracer:assembleDebug :tracer:assembleRelease :tracer:copyTracerDebug
```

Expected: all native/Python tests pass, all Android variants build, and the evidence has no failed or
incomplete run.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/cpp/demo_target/demo_scenes.h app/src/main/cpp/demo_target/demo_scenes.cpp app/src/main/cpp/demo_target/demo_target.cpp app/src/main/kotlin/com/aprz/qbdiandroid/NativeDemo.kt app/src/main/kotlin/com/aprz/qbdiandroid/MainActivity.kt scripts/flight_acceptance.py scripts/tests/test_flight_acceptance.py docs/benchmarks/flight-recorder-acceptance.md
git commit -m "test(trace): verify crash flight recorder"
```

---

## Final Review Gate

- [ ] Re-run Task 1's device probe against the final SignalBroker.
- [ ] Confirm every approved goal maps to Tasks 3–11 and every non-goal remains absent.
- [ ] Confirm normal QTRB behavior is unchanged with `flight=0`.
- [ ] Confirm recovery after direct `exit_group`, target-issued `SIGKILL`, and external `SIGKILL`.
- [ ] Confirm injected failures create specific coverage gaps and incomplete summaries.
- [ ] Sync CodeGraph after final source changes.
