# Qtrace Native Autonomous Stop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make an installed tracer generation enforce its own duration, stop recording at the next QBDI callback, seal artifacts on their owning threads, and publish an adb-readable session state without a runtime Frida control channel.

**Architecture:** Add a per-generation runtime shared by every scene hook and Flight Recorder session. A native deadline worker publishes one atomic stop request; proxy entry gates reject new captures, while active QBDI sessions cooperatively stop and seal before continuing control-only to the real return. State transitions are published through a focused atomic JSON status writer outside the instruction hot path.

**Tech Stack:** C++20, Android NDK arm64, QBDI 0.12.1, ShadowHook, pthreads/atomics, POSIX files, nlohmann/json, CMake/CTest, Gradle.

## Global Constraints

- This plan depends on `2026-08-25-qtrace-stopped-trace-format.md`; `BinaryTraceWriter::stop()` and `TraceStopReason::DurationElapsed` must exist first.
- Android scope remains `arm64-v8a`, API 24+, C++20, `-fno-exceptions`, and `-fno-rtti`.
- Frida does not remain connected after startup installation; no stop RPC is added.
- Duration begins only after the complete hook batch reaches `Installed`.
- The deadline worker may only publish atomic state; it must never close a writer or Flight chunk owned by another thread.
- New calls after stop use retained-original passthrough and never create an artifact.
- Active calls stop recording at the next QBDI callback, seal on the target thread, and continue control-only to a real return.
- A blocked syscall or module-external execution may delay acknowledgement; no hard-real-time claim and no App kill are allowed.
- Stop, seal, and status publication are idempotent and generation-scoped.
- Session identity is a lowercase UUIDv4 supplied by the host; native rejects any other form.

## File Structure

- `core/trace_config.*` and `core/tracer_configuration.*` parse/normalize optional host session identity and duration.
- `core/trace_generation_runtime.*` owns one generation's phase, deadline worker, admission count, and immutable stop token.
- `core/session_status.*` owns bounded, transition-only, atomic app-private status JSON publication.
- `core/qbdi_thread_session.*` and `core/qbdi_runner.*` observe stop on the target thread, seal its normal writer, and continue control-only.
- `core/capture_coordinator.*` and `flight/flight_chunk_writer.*` apply the same ownership rule to Flight sessions/chunks.
- `tracer_entry.cpp` connects generation ownership to proxy admission, installation, rollback, fork, and retained-original passthrough.
- Focused host tests own deterministic lifecycle/race coverage; contract tests and docs prevent a runtime Frida stop channel from reappearing.

---

### Task 1: Add Optional Session and Duration Configuration

**Files:**
- Modify: `tracer/src/main/cpp/core/trace_config.h:8-49`
- Modify: `tracer/src/main/cpp/core/trace_config.cpp`
- Modify: `tracer/src/main/cpp/core/tracer_configuration.cpp:404-605`
- Modify: `tracer/src/main/cpp/core/tracer_configuration.cpp:90-145` (response serialization)
- Test: `tracer/src/test/cpp/tracer_configuration_test.cpp`

**Interfaces:**
- Consumes: native request schema version 1.
- Produces: `SessionOptions { std::string id; uint64_t duration_ms; bool enabled() const; bool timed() const; }` at `TraceConfig::session`; `duration_ms == 0` represents monitor mode with no deadline.

- [ ] **Step 1: Add failing strict-schema tests**

Extend the canonical request fixture with optional session cases:

```cpp
const auto prepared = prepare_tracer_configuration(request_with(
        R"json("session":{"id":"7d5807cf-cf09-4f21-92de-1ad92802610a","durationMs":60000})json"));
CHECK(prepared.accepted());
CHECK(prepared.config.session.id == "7d5807cf-cf09-4f21-92de-1ad92802610a");
CHECK(prepared.config.session.duration_ms == 60000);
```

Add rejection assertions for uppercase UUID, missing hyphens, nil UUID, `durationMs` below 100, duration over 86,400,000 ms, unknown session keys, and session without `id`. Confirm a session containing only `id` parses as monitor mode and requests with no `session` still parse for legacy scripts.

- [ ] **Step 2: Run the native suite and verify red**

Run `./gradlew nativeHostTest --no-daemon`.

Expected: compile failure on `TraceConfig::session` or `UNKNOWN_FIELD` for `$.session`.

- [ ] **Step 3: Add the exact config type and parser**

Add:

```cpp
struct SessionOptions {
    std::string id;
    uint64_t duration_ms = 0;
    bool enabled() const noexcept { return !id.empty(); }
    bool timed() const noexcept { return duration_ms != 0; }
};

struct TraceConfig {
    // existing fields
    SessionOptions session;
};
```

Permit optional root key `session`; if present, require `id`, permit optional `durationMs`, reject every other key, require lowercase UUIDv4 syntax, and enforce `100 <= durationMs <= 86400000` when supplied. Omitted `durationMs` means monitor mode and must not create a deadline worker. Serialize normalized session fields in configure/status responses so the startup injector can verify identity.

- [ ] **Step 4: Run native tests**

Run `./gradlew nativeHostTest --no-daemon`.

Expected: old schema fixtures still pass; all session boundary cases return stable paths and codes (`INVALID_SESSION_ID`, `INVALID_SESSION_DURATION`).

- [ ] **Step 5: Commit config support**

```bash
git add tracer/src/main/cpp/core/trace_config.h \
  tracer/src/main/cpp/core/trace_config.cpp \
  tracer/src/main/cpp/core/tracer_configuration.cpp \
  tracer/src/test/cpp/tracer_configuration_test.cpp
git commit -m "feat(config): add timed session options"
```

### Task 2: Implement the Per-Generation Stop Runtime and Deadline

**Files:**
- Create: `tracer/src/main/cpp/core/trace_generation_runtime.h`
- Create: `tracer/src/main/cpp/core/trace_generation_runtime.cpp`
- Create: `tracer/src/test/cpp/trace_generation_runtime_test.cpp`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`

**Interfaces:**
- Consumes: `SessionOptions` and `TraceStopReason`.
- Produces: `TraceGenerationRuntime`, `TraceGenerationPhase`, and immutable `TraceStopToken` shared by proxy/QBDI/flight code.

- [ ] **Step 1: Write deterministic lifecycle tests before adding a timer thread**

Define tests around an injected wait function:

```cpp
struct FakeDeadline {
    static void wait_until(void *opaque, uint64_t) noexcept {
        static_cast<FakeDeadline *>(opaque)->entered.store(true);
        while (!static_cast<FakeDeadline *>(opaque)->release.load()) sched_yield();
    }
    std::atomic<bool> entered{false};
    std::atomic<bool> release{false};
};

auto runtime = TraceGenerationRuntime::create(
        3, timed_session(60000), DeadlineWait{&deadline, &FakeDeadline::wait_until});
CHECK(runtime->arm());
CHECK(runtime->try_begin_call(3, 101));
deadline.release.store(true);
runtime->join_deadline_for_test();
CHECK(runtime->stop_token().requested());
CHECK(!runtime->try_begin_call(3, 102));
runtime->acknowledge_sealed(3, 101);
CHECK(runtime->snapshot().phase == TraceGenerationPhase::Sealed);
```

Also test wrong-generation acknowledgement, repeated request/ack, zero active calls sealing immediately, and destruction joining the worker.

- [ ] **Step 2: Register the new target and verify red**

Add the CMake target with `Threads::Threads`, then run `./gradlew nativeHostTest --no-daemon`.

Expected: compile failure because the runtime API does not exist.

- [ ] **Step 3: Implement a focused shared runtime**

Use this public shape:

```cpp
enum class TraceGenerationPhase : uint8_t {
    Waiting, Running, StopRequested, Stopping, Sealed, StopIncomplete
};

class TraceStopToken final {
public:
    bool requested() const noexcept;
    TraceStopReason reason() const noexcept;
};

struct DeadlineWait {
    void *opaque = nullptr;
    void (*wait_until)(void *opaque, uint64_t deadline_monotonic_ns) noexcept = nullptr;
};

class TraceGenerationRuntime final {
public:
    static std::shared_ptr<TraceGenerationRuntime> create(
            uint64_t generation, SessionOptions session,
            DeadlineWait wait = {}) noexcept;
    bool arm() noexcept;
    bool try_begin_call(size_t scene_index, uint32_t tid) noexcept;
    void finish_call(size_t scene_index, uint32_t tid, bool sealed) noexcept;
    void acknowledge_sealed(size_t scene_index, uint32_t tid) noexcept;
    const TraceStopToken &stop_token() const noexcept;
    TraceGenerationSnapshot snapshot() const noexcept;
};
```

For a timed session, `arm()` computes one absolute monotonic deadline from `session.duration_ms`, starts the worker, waits once, CASes Running to StopRequested, and exits. For monitor mode, `arm()` enters Running without starting a worker. Runtime counters are atomics; a small mutex-protected vector is reserved for `256 scenes + configured flight maxThreads` before arming and records active `(scene, tid)` pairs only at entry/exit, never per instruction. If registration would exceed that bound, the proxy bypasses capture and publishes `ACTIVE_SESSION_LIMIT` instead of allocating in an instruction callback.

- [ ] **Step 4: Add real monotonic wait and fork-safe shutdown**

Production wait uses `clock_nanosleep(CLOCK_MONOTONIC, ...)` with EINTR retry. Add `detach_after_fork_child()` that marks the runtime detached and never joins inherited pthread state in the child, matching existing process lifecycle rules.

- [ ] **Step 5: Run native tests**

Run `./gradlew nativeHostTest --no-daemon`.

Expected: lifecycle, idempotence, timer, destructor, and fork-detach tests pass without sleeps in deterministic unit cases.

- [ ] **Step 6: Commit the runtime**

```bash
git add tracer/src/main/cpp/core/trace_generation_runtime.* \
  tracer/src/test/cpp/trace_generation_runtime_test.cpp \
  tracer/src/test/cpp/CMakeLists.txt tracer/src/main/cpp/CMakeLists.txt
git commit -m "feat(trace): add generation deadline runtime"
```

### Task 3: Publish Atomic Native Session Status

**Files:**
- Create: `tracer/src/main/cpp/core/session_status.h`
- Create: `tracer/src/main/cpp/core/session_status.cpp`
- Create: `tracer/src/test/cpp/session_status_test.cpp`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`
- Modify: `tracer/src/main/cpp/core/trace_generation_runtime.h`

**Interfaces:**
- Consumes: `TraceGenerationSnapshot`, package, normalized scenes, and artifact paths.
- Produces: `SessionStatusPublisher::publish(const SessionStatusSnapshot &) noexcept` and device file `<trace-dir>/session-<uuid>.status.json`.

- [ ] **Step 1: Write atomic-publication and schema tests**

Use a temporary output directory and assert parsed JSON contains exact fields:

```cpp
SessionStatusSnapshot snapshot{};
snapshot.schema_version = 1;
snapshot.session_id = "7d5807cf-cf09-4f21-92de-1ad92802610a";
snapshot.generation = 3;
snapshot.state = "sealed";
snapshot.reason = "duration_elapsed";
snapshot.artifacts = {"run.trace.bin.lz4"};
CHECK(publisher.publish(snapshot));
CHECK(read_text(publisher.path()).find(R"json("state":"sealed")json") !=
      std::string::npos);
CHECK(directory_has_no_temporary_files(root));
```

Inject partial write, fsync, rename, and directory-fsync failures. Assert the previous valid status survives and the first error code is retained.

- [ ] **Step 2: Run native tests and verify red**

Run `./gradlew nativeHostTest --no-daemon`.

Expected: new target does not compile.

- [ ] **Step 3: Implement transition-only publication**

Expose:

```cpp
struct ResolvedSceneStatus {
    std::string name;
    uint64_t start_offset = 0;
    uint64_t end_offset = 0;
};

struct SessionActiveScene {
    size_t scene_index = 0;
    uint32_t tid = 0;
    bool sealed = false;
};

struct SessionStatusSnapshot {
    uint32_t schema_version = 1;
    std::string session_id;
    uint64_t generation = 0;
    std::string package;
    uint32_t pid = 0;
    std::string state;
    std::string reason;
    uint64_t transition_monotonic_ns = 0;
    std::vector<ResolvedSceneStatus> normalized_scenes;
    std::vector<SessionActiveScene> active_scenes;
    std::vector<std::string> artifacts;
    bool stop_acknowledged = false;
    std::vector<ConfigurationIssue> warnings;
    std::vector<ConfigurationIssue> errors;
};

class SessionStatusPublisher final {
public:
    bool open(const TraceConfig &, uint64_t generation,
              std::string_view output_directory = {}) noexcept;
    bool publish(const SessionStatusSnapshot &) noexcept;
    std::string_view path() const noexcept;
    int error_code() const noexcept;
};
```

Write `session-<uuid>.status.json.tmp.<pid>.<sequence>` using bounded JSON, `fsync`, `rename`, and parent-directory `fsync`. Validate the package, session ID, and every artifact basename before serialization. Do not call this class from an instruction callback; runtime state transitions enqueue or perform publication after callback unwinds.

- [ ] **Step 4: Connect publisher ownership to the generation runtime**

Give `TraceGenerationRuntime` one publisher and a dedicated status loop that compares an atomic transition sequence and writes only when the sequence changes. The deadline worker only CASes stop state/increments that sequence and exits; it performs no file I/O. Instruction callbacks and target-thread acknowledgements likewise update atomics and return. The status loop publishes Installed, Running, StopRequested, Stopping, Sealed, StopIncomplete, warning, and error snapshots outside the hot path, polling at a fixed 25 ms maximum interval so it needs no callback-owned locks. A publication error appears in later snapshots/JSON ABI status but does not force the target App to exit. Destruction requests both workers to finish and joins them; fork-child detach never joins inherited pthread state.

- [ ] **Step 5: Run tests and commit**

Run `./gradlew nativeHostTest --no-daemon`; expect all tests to pass.

```bash
git add tracer/src/main/cpp/core/session_status.* \
  tracer/src/main/cpp/core/trace_generation_runtime.* \
  tracer/src/test/cpp/session_status_test.cpp \
  tracer/src/test/cpp/CMakeLists.txt tracer/src/main/cpp/CMakeLists.txt
git commit -m "feat(trace): publish native session status"
```

### Task 4: Stop and Seal an Active Normal QBDI Trace

**Files:**
- Modify: `tracer/src/main/cpp/core/qbdi_thread_session.h:21-190`
- Modify: `tracer/src/main/cpp/core/qbdi_thread_session.cpp:330-590,810-880`
- Modify: `tracer/src/main/cpp/core/qbdi_runner.cpp:14-118`
- Modify: `tracer/src/main/cpp/core/qbdi_runner.h:13-44`
- Test: `tracer/src/test/cpp/qbdi_thread_session_test.cpp`
- Test: `tracer/src/test/cpp/qbdi_runner_lifecycle_test.cpp`

**Interfaces:**
- Consumes: `TraceStopToken`, `BinaryTraceWriter::stop()`, and runtime acknowledgement.
- Produces: `QbdiStopControl` passed into `QbdiThreadSession::create_normal` and exactly-once same-thread sealing before control-only continuation.

- [ ] **Step 1: Add a failing cooperative-stop unit case**

Extend the host-test executor seam to return an observed stop result. Assert this sequence:

```cpp
CHECK(session->call(0x1000, args, 0).target_returned);
CHECK(state.execution_calls == 1);
CHECK(state.seal_calls == 1);
CHECK(state.continuation_calls == 1);
CHECK(state.seal_thread == state.execution_thread);
CHECK(state.continuation_saw_sealed);
```

Add cases for no stop, stop before the first collected instruction, repeated callback observation, and seal failure marking the trace incomplete without restarting the native entry.

- [ ] **Step 2: Run native tests and verify red**

Run `./gradlew nativeHostTest --no-daemon`.

Expected: missing `QbdiStopControl` or incorrect lifecycle assertions.

- [ ] **Step 3: Add a narrow stop-control interface**

Define:

```cpp
using QbdiSealStopped = bool (*)(void *, TraceStopReason) noexcept;
using QbdiStopAcknowledged = void (*)(void *, bool sealed) noexcept;

struct QbdiStopControl {
    const TraceStopToken *token = nullptr;
    void *opaque = nullptr;
    QbdiSealStopped seal = nullptr;
    QbdiStopAcknowledged acknowledge = nullptr;
};
```

`on_target_pre` checks the token before `InstructionCollector::pre_callback`; when requested it latches `stop_observed` and returns `QBDI::STOP`. After `vm.run()` unwinds, `Impl::call()` invokes `seal` once on the same thread, acknowledges, and returns the current PC/result. Existing `call_gateway()` then enters its already-present control-only loop until the real return.

- [ ] **Step 4: Bind normal writer ownership in `RunnerState`**

Store start time and runtime in `RunnerState`. Its static callback performs:

```cpp
return state->writer.stop(
        reason, elapsed_ms_since(state->started));
```

Pass `QbdiStopControl` into `create_normal`. Normal completion still calls `end`; stopped completion observes the already-sealed writer and only closes resources. Do not call native fallback after target execution has begun.

- [ ] **Step 5: Run native tests and commit**

Run `./gradlew nativeHostTest --no-daemon`; expect all lifecycle/failure tests to pass.

```bash
git add tracer/src/main/cpp/core/qbdi_thread_session.* \
  tracer/src/main/cpp/core/qbdi_runner.* \
  tracer/src/test/cpp/qbdi_thread_session_test.cpp \
  tracer/src/test/cpp/qbdi_runner_lifecycle_test.cpp
git commit -m "feat(trace): stop active QBDI recording"
```

### Task 5: Stop Flight Sessions on Their Owning Threads

**Files:**
- Modify: `tracer/src/main/cpp/core/capture_coordinator.h:18-133`
- Modify: `tracer/src/main/cpp/core/capture_coordinator.cpp:430-620`
- Modify: `tracer/src/main/cpp/core/qbdi_thread_session.cpp:230-650`
- Modify: `tracer/src/main/cpp/flight/flight_chunk_writer.h`
- Modify: `tracer/src/main/cpp/flight/flight_chunk_writer.cpp`
- Test: `tracer/src/test/cpp/capture_coordinator_test.cpp`
- Test: `tracer/src/test/cpp/flight_chunk_writer_test.cpp`

**Interfaces:**
- Consumes: generation runtime stop token and acknowledgement.
- Produces: `CaptureCoordinator::request_stop()` behavior that rejects new entries and seals each registered thread's current chunk cooperatively, plus `FlightChunkWriter::committed()`, `sealed()`, and `basename()` status accessors.

- [ ] **Step 1: Add failing multi-thread coordinator tests**

With fake sessions, register two TIDs, request stop, then assert:

```cpp
CHECK(coordinator.request_stop(TraceStopReason::DurationElapsed));
CHECK(coordinator.enter(303, scene) == nullptr);
fake_acknowledge(tid_101, true);
CHECK(runtime.snapshot().phase == TraceGenerationPhase::Stopping);
fake_acknowledge(tid_202, true);
CHECK(runtime.snapshot().phase == TraceGenerationPhase::Sealed);
```

Add a failure case where TID 202 never acknowledges: committed chunks remain recoverable and the runtime can be reported incomplete without cross-thread `seal()`.

- [ ] **Step 2: Run native tests and verify red**

Run `./gradlew nativeHostTest --no-daemon`.

Expected: `request_stop` is absent and new entries are still admitted.

- [ ] **Step 3: Share the runtime with coordinator-created sessions**

Add the runtime to `CaptureCoordinator::start` and pass one `QbdiStopControl` to every `create_flight`. At stop, `enter`/`enter_thread` reject new work. Each session observes the token in PRE, seals its own `FlightChunkWriter`, and acknowledges the coordinator.

Use this exact ownership boundary:

```cpp
bool CaptureCoordinator::start(
        const TraceConfig &config,
        std::shared_ptr<TraceGenerationRuntime> runtime) noexcept;
bool CaptureCoordinator::request_stop(TraceStopReason reason) noexcept;

auto control = QbdiStopControl{
        &runtime_->stop_token(), slot, &seal_flight_slot, &acknowledge_flight_slot};
return QbdiThreadSession::create_flight(scene, control, slot->writer.get());
```

- [ ] **Step 4: Preserve recoverability on missing acknowledgement**

Add a read-only `committed()`/`sealed()` distinction to `FlightChunkWriter`; session status lists committed flight artifact even when one active chunk cannot seal. Never destroy or clear a live slot solely because the host timeout elapsed.

```cpp
bool FlightChunkWriter::committed() const noexcept;
bool FlightChunkWriter::sealed() const noexcept;
std::string_view FlightChunkWriter::basename() const noexcept;

if (writer.committed()) snapshot.artifacts.push_back(writer.basename());
if (!writer.sealed()) snapshot.stop_acknowledged = false;
```

- [ ] **Step 5: Run tests and commit**

Run `./gradlew nativeHostTest --no-daemon`; expect coordinator and flight recovery tests to pass.

```bash
git add tracer/src/main/cpp/core/capture_coordinator.* \
  tracer/src/main/cpp/core/qbdi_thread_session.cpp \
  tracer/src/main/cpp/flight/flight_chunk_writer.* \
  tracer/src/test/cpp/capture_coordinator_test.cpp \
  tracer/src/test/cpp/flight_chunk_writer_test.cpp
git commit -m "feat(flight): stop capture cooperatively"
```

### Task 6: Gate Proxy Entry and Arm the Runtime After Hook Installation

**Files:**
- Modify: `tracer/src/main/cpp/tracer_entry.cpp:18-120,250-438,1060-1260`
- Modify: `tracer/src/main/cpp/core/tracer_configuration.h:35-95`
- Modify: `tracer/src/main/cpp/core/tracer_configuration.cpp`
- Test: `tracer/src/test/cpp/tracer_entry_proxy_test.cpp`
- Test: `tracer/src/test/cpp/tracer_configuration_test.cpp`

**Interfaces:**
- Consumes: `TraceGenerationRuntime`, QBDI stop control, coordinator stop, and status publisher.
- Produces: one shared runtime per accepted generation, armed only on final `Installed` transition.

- [ ] **Step 1: Add proxy race and generation-isolation tests**

Use existing entry/registration gates to prove:

```cpp
runtime->request_stop_for_test();
const uint64_t value = trace_proxy_dispatch(proxy_generation, args, x8);
CHECK(value == expected_retained_original);
CHECK(qbdi_calls == 0);
CHECK(runtime->snapshot().active_calls == 0);
```

Cover stop racing with proxy registration, an already-active proxy acknowledging seal, hook-unload failure using dormant passthrough, and an old timer firing after a newer generation is installed.

- [ ] **Step 2: Run native tests and verify red**

Run `./gradlew nativeHostTest --no-daemon`.

Expected: stopped proxy still enters QBDI or no runtime is associated with hooks.

- [ ] **Step 3: Store runtime ownership in every installed hook**

Add:

```cpp
std::shared_ptr<TraceGenerationRuntime> runtime;
```

to `InstalledSceneHook`, pending-update metadata, and rollback snapshots. Create the runtime during accepted configuration apply, but call `arm()` only after the entire hook batch succeeds and immediately after `finish_install(...Installed...)` is prepared. Failed/rolled-back generations never start a deadline.

- [ ] **Step 4: Gate entry before QBDI allocation**

Inside the existing `g_lock -> transition_mutex` transaction, call `runtime->try_begin_call(scene.index, tid)`. On false, choose retained-original passthrough. On true, decrement/finish on every normal, failure, fork-child, and deferred-thread-exit path. Pass runtime stop controls to normal or flight execution.

- [ ] **Step 5: Publish installed/stopping/sealed status**

Include normalized offsets, active `(scene, tid)`, artifact basenames, warnings, and stable errors in each transition snapshot. Keep JSON ABI status useful during startup, but make the app-private session file authoritative after Frida detaches.

- [ ] **Step 6: Run full native and Android builds**

Run:

```bash
./gradlew nativeHostTest --no-daemon
./gradlew :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon
```

Expected: all host tests pass and Android tracer/companion are produced.

- [ ] **Step 7: Commit proxy integration**

```bash
git add tracer/src/main/cpp/tracer_entry.cpp \
  tracer/src/main/cpp/core/tracer_configuration.* \
  tracer/src/test/cpp/tracer_entry_proxy_test.cpp \
  tracer/src/test/cpp/tracer_configuration_test.cpp
git commit -m "feat(trace): arm autonomous session stop"
```

### Task 7: Add Concurrency, Contract, and Documentation Gates

**Files:**
- Modify: `tracer/src/test/cpp/production_trace_contract_test.cpp`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`
- Modify: `scripts/tests/build_contract_integration.py`
- Modify: `scripts/benchmark_trace.py`
- Modify: `scripts/tests/test_benchmark_trace.py`
- Modify: `README.md:141-304`
- Modify: `docs/trace-format.md`

**Interfaces:**
- Consumes: the complete native stop lifecycle and metrics-v3 benchmark compatibility from the stopped-format plan.
- Produces: build/source contracts, median fast-profile performance gating, and documented startup-only Frida behavior for the later CLI plan.

- [ ] **Step 1: Add source/build contract assertions**

Require production sources to contain one generation runtime, session publisher, proxy admission gate, and QBDI cooperative stop path. Reject any exported runtime `qtrace_stop*` RPC or writer close from the deadline worker.

```python
self.assertNotIn("qbdi_tracer_stop_json", tracer_entry)
self.assertNotIn("rpc.exports.stop", spawn_agent)
self.assertIn("TraceGenerationRuntime", tracer_entry)
self.assertIn("QBDI::STOP", qbdi_session)
self.assertIn("control_only", qbdi_session)
```

- [ ] **Step 2: Run contract tests and verify failures expose missing rules**

Run:

```bash
python3 -m unittest scripts.tests.build_contract_integration -v
```

Expected before completing assertions: a focused failure naming the missing contract; after updating sources/CMake, PASS.

- [ ] **Step 3: Run opt-in race verification**

Configure and run the existing TSAN lane with new runtime/coordinator tests linked into an opt-in target. Expected: no data races in stop request, active registration, or acknowledgement.

```bash
cmake -S tracer/src/test/cpp -B build/native-tests-tsan -DQTRACE_ENABLE_TSAN=ON
cmake --build build/native-tests-tsan --parallel 2
ctest --test-dir build/native-tests-tsan --output-on-failure
```

- [ ] **Step 4: Retain the median performance gate**

Before documenting, retain the existing median performance gate. Update benchmark unit fixtures to metrics v3 without weakening `PROFILE_RATE_TARGETS` (`fast=1,000,000`, `balanced=800,000`, `full=500,000` instructions/second). Add an assertion that five-run comparison is still required and a single fast run cannot pass/fail the gate.

On the rooted acceptance device, run the checked-in baseline comparison after building the candidate tracer:

```bash
python3 scripts/benchmark_trace.py \
  --device SERIAL --profile fast --runs 5 \
  --candidate-tracer out/arm64-v8a/libqbdi_tracer.so \
  --compare docs/benchmarks/binary-trace-baseline.md
```

Expected: semantic return oracle passes and the five-run median meets the checked-in fast threshold. If no matching device is present, leave this gate pending for the CLI plan's device acceptance; never infer performance from a single run.

- [ ] **Step 5: Document exact runtime semantics**

Update README and trace docs with this sequence:

```text
Frida load/init -> resume -> Installed -> Frida detach
-> native deadline -> stop_requested -> per-thread seal
-> control-only real return
```

State explicitly that a blocked thread may delay acknowledgement and that qtrace never kills the App to satisfy duration.

- [ ] **Step 6: Run final verification**

Run:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
./gradlew nativeHostTest --no-daemon
./gradlew :app:assembleDebug :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon
```

Expected: all tests and builds pass; no runtime stop RPC is present; generated native artifacts exist.

- [ ] **Step 7: Commit gates and docs**

```bash
git add tracer/src/test/cpp/production_trace_contract_test.cpp \
  tracer/src/test/cpp/CMakeLists.txt scripts/tests/build_contract_integration.py \
  scripts/benchmark_trace.py scripts/tests/test_benchmark_trace.py \
  README.md docs/trace-format.md
git commit -m "test(trace): gate autonomous stopping"
```
