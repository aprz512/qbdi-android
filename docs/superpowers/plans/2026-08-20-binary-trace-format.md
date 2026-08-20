# Binary Trace Format Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Replace device-side text rendering with a compact binary trace stream and provide a streaming host converter while preserving every fast, balanced, and full profile field.

**Architecture:** QBDI callbacks collect compact dynamic values and pass them to a binary writer that emits versioned records into the existing asynchronous double buffer. Each published buffer remains an independent LZ4 frame. Host tooling validates the binary stream, resolves run-scoped metadata definitions, and atomically publishes text format 3 while retaining format-2 pull compatibility.

**Tech Stack:** C++20, QBDI 0.12.1, pthreads, vendored LZ4 1.10.0, Python 3 standard library, Android Gradle/NDK, CTest.

## Global Constraints

- Preserve all information currently recorded by fast, balanced, and full; do not sample, omit, overwrite, or reorder events.
- Keep QBDI, asynchronous double buffering, LZ4, ordinary file writes, and the reviewed fork/crash lifecycle.
- Device hot-path encoding is bounded, allocation-free, and performs no text, hexadecimal, decimal, or register-name formatting.
- New compressed artifacts use .trace.bin.lz4; Debug compression-off artifacts use .trace.bin.
- Binary format QTRB v1 is little-endian, versioned, length-bounded, and pointer-width tagged.
- A record never crosses a producer-buffer boundary.
- A valid crash marker may recover only complete prior LZ4 frames; no per-record checksum, byte repair, or device retry.
- Format-2 .trace.txt.lz4 artifacts remain pullable.
- Trace failure must not skip the target or change its native return value, and must not publish success metrics.
- Production remains -fno-exceptions -fno-rtti.
- Pixel 6 medians: fast >= 1,000,000, balanced >= 800,000, and full >= 500,000 instructions per second.
- For an identical workload, each .trace.bin.lz4 must be no larger than the current .trace.txt.lz4 counterpart.

## File Map

Native format and writer:

- Create tracer/src/main/cpp/events/binary_trace_format.h for protocol constants, record types, limits, and feature flags.
- Create tracer/src/main/cpp/events/binary_trace_encoder.{h,cpp} for explicit little-endian encoding.
- Create tracer/src/main/cpp/events/trace_dictionary.{h,cpp} for fixed-capacity definition deduplication.
- Create tracer/src/main/cpp/events/binary_trace_writer.{h,cpp} for artifact lifecycle, publication, and metrics v2.
- Modify trace_record.h, trace_metrics.h, async_trace_writer.cpp, collector, runner, handlers, rules, CMake, and lifecycle users.
- Remove text_trace_writer.{h,cpp} and trace_encoder.{h,cpp} only after binary equivalents and migrated lifecycle tests are green.

Host conversion and tools:

- Create scripts/lz4_frames.py as the only LZ4 scanner/decoder.
- Create scripts/trace_binary.py as the strict streaming protocol decoder and format-3 renderer.
- Create scripts/trace_convert.py as the atomic conversion CLI.
- Modify pull_trace.py and benchmark_trace.py for dual-format artifacts and metrics versions.
- Add focused Python test modules for framing, binary decoding, conversion, pulling, and benchmarks.

Documentation and evidence:

- Modify docs/trace-format.md and README.md.
- Create docs/benchmarks/binary-trace-baseline.md for matched pre/post device evidence.

---

### Task 1: Lock the Current Baseline and Semantic Oracle

**Files:**
- Create: docs/benchmarks/binary-trace-baseline.md
- Modify: scripts/benchmark_trace.py
- Test: scripts/tests/test_benchmark_trace.py

**Interfaces:**
- Consumes: current format-2 metrics and benchmark output.
- Produces: parse_profile_baseline(text: str, profile: str) -> dict[str, int | str] and immutable current artifact-size/semantic evidence.

- [ ] **Step 1: Write the failing actual-document test**

~~~python
def test_binary_trace_baseline_has_all_profiles_and_size_fields(self):
    path = Path("docs/benchmarks/binary-trace-baseline.md")
    text = path.read_text(encoding="utf-8")
    identity = benchmark_trace.parse_baseline_document(text)
    self.assertEqual("Pixel 6", identity["device_model"])
    self.assertEqual("oriole", identity["device_product"])
    self.assertEqual("16", identity["android_version"])
    for profile in ("fast", "balanced", "full"):
        row = benchmark_trace.parse_profile_baseline(text, profile)
        self.assertGreater(row["compressed_bytes"], 0)
        self.assertEqual(21718, row["instructions"])
        self.assertEqual("0x5745c858653f5a7f", row["return"])
~~~

- [ ] **Step 2: Run it and verify RED**

Run:

~~~bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest   scripts.tests.test_benchmark_trace.OptimizedMetricsParserTests.test_binary_trace_baseline_has_all_profiles_and_size_fields -v
~~~

Expected: FAIL because the document and parser do not exist.

- [ ] **Step 3: Capture and implement the baseline**

Build/stage the current tracer. Run one warmup plus five fresh measured processes for fast, balanced, and full. Pull the median artifact for each and record device/build identity, all five elapsed values, return, instructions, compressed size, decoded event counts, sequence endpoints, footer, artifact SHA-256, and SELinux state.

~~~bash
./gradlew :tracer:assembleDebug :tracer:copyTracerDebug :app:assembleDebug
adb -s 192.168.51.42:5555 push out/arm64-v8a/libqbdi_tracer.so /data/local/tmp/qtrace-stage.so
adb -s 192.168.51.42:5555 shell run-as com.aprz.qbdiandroid cp   /data/local/tmp/qtrace-stage.so files/libqbdi_tracer.so
adb -s 192.168.51.42:5555 shell run-as com.aprz.qbdiandroid chmod 700 files/libqbdi_tracer.so
python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid   --device 192.168.51.42:5555 --profile fast --runs 5
python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid   --device 192.168.51.42:5555 --profile balanced --runs 5
python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid   --device 192.168.51.42:5555 --profile full --runs 5
~~~

Parse an exact Markdown table named Current format-2 artifact baselines. Reject duplicate profiles, missing columns, invalid integers, and unknown profiles.

- [ ] **Step 4: Run all Python tests**

~~~bash
PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS=error   python3 -m unittest discover -s scripts/tests -p 'test_*.py'
~~~

Expected: all tests pass and the checked-in document parses.

- [ ] **Step 5: Commit**

~~~bash
git add docs/benchmarks/binary-trace-baseline.md   scripts/benchmark_trace.py scripts/tests/test_benchmark_trace.py
git commit -m "test(trace): record binary migration baseline"
~~~

---

### Task 2: Define and Encode QTRB v1

**Files:**
- Create: tracer/src/main/cpp/events/binary_trace_format.h
- Create: tracer/src/main/cpp/events/binary_trace_encoder.h
- Create: tracer/src/main/cpp/events/binary_trace_encoder.cpp
- Create: tracer/src/test/cpp/binary_trace_encoder_test.cpp
- Modify: tracer/src/test/cpp/CMakeLists.txt

**Interfaces:**
- Consumes: TraceContext, TraceProfile, CachedInstruction, InstructionRecord, MemoryRecord, and TraceMetrics.
- Produces:

~~~cpp
enum class BinaryRecordType : uint16_t {
    TraceBegin = 1,
    ModuleDefinition = 2,
    InstructionDefinition = 3,
    Instruction = 4,
    Memory = 5,
    Call = 6,
    Rule = 7,
    Error = 8,
    TraceEnd = 9,
};

struct BinaryEncodeResult {
    bool ok = false;
    size_t size = 0;
};

struct CallChunkInfo {
    uint64_t event_id;
    uint32_t total_detail_bytes;
    uint16_t chunk_index;
    uint16_t chunk_count;
};

struct TraceBeginInfo {
    TraceProfile profile = TraceProfile::Fast;
    bool compression_enabled = true;
    uint64_t run_id = 0;
    uint64_t effective_buffer_bytes = 0;
};

class BinaryTraceEncoder {
public:
    BinaryEncodeResult encode_stream_header(uint8_t *, size_t, TraceProfile) const noexcept;
    BinaryEncodeResult encode_begin(uint8_t *, size_t, const TraceContext &,
                                    const TraceBeginInfo &) const noexcept;
    BinaryEncodeResult encode_module_definition(uint8_t *, size_t, uint32_t,
                                                std::string_view, uintptr_t) const noexcept;
    BinaryEncodeResult encode_instruction_definition(uint8_t *, size_t, uint32_t,
                                                     const CachedInstruction &) const noexcept;
    BinaryEncodeResult encode_instruction(uint8_t *, size_t, uint32_t, uint32_t,
                                          const InstructionRecord &) const noexcept;
    BinaryEncodeResult encode_memory(uint8_t *, size_t, uint32_t, uintptr_t,
                                     const MemoryRecord &) const noexcept;
    BinaryEncodeResult encode_call(uint8_t *, size_t, std::string_view,
                                   std::string_view, std::string_view) const noexcept;
    BinaryEncodeResult encode_call_chunk(uint8_t *, size_t, const CallChunkInfo &,
                                         std::string_view, std::string_view,
                                         std::string_view) const noexcept;
    BinaryEncodeResult encode_event(uint8_t *, size_t, BinaryRecordType,
                                    std::string_view, std::string_view) const noexcept;
    BinaryEncodeResult encode_end(uint8_t *, size_t, bool, uint64_t, uint64_t,
                                  const TraceMetrics &) const noexcept;
};
~~~

- [ ] **Step 1: Write exact-byte RED tests**

Require magic QTRB, version 1, little-endian marker, pointer width, exact eight-byte record headers, golden bytes for all nine types, exact payload sizes, all PC-relative kinds, memory states, and no partial output when capacity is one byte short. `TRACE_BEGIN` must encode profile, compression state, run ID, and effective buffer size and must not encode package name. Pair an instruction definition and reference with a metadata ID different from the opcode. Encode an ordinary CALL category, name, and detail as three separately length-prefixed strings with flags zero. Encode a chunked CALL with the explicit chunk flag followed by nonzero event ID, total detail bytes, chunk index/count, and the three strings. Reject invalid or unbounded chunk metadata atomically. Rule and Error retain two-string payloads. Every independently bounded string family needs an over-limit atomic-failure test, and maximum-size cases must assert both `ok` and exact size.

~~~cpp
uint8_t bytes[4096]{};
const auto header = encoder.encode_stream_header(bytes, sizeof(bytes), TraceProfile::Fast);
CHECK(header.ok);
CHECK(std::memcmp(bytes, "QTRB", 4) == 0);
CHECK(bytes[4] == 1);
CHECK(bytes[6] == 1);

TraceBeginInfo begin_info{TraceProfile::Fast, true, 0x1122334455667788ULL, 4096};
const auto begin = encoder.encode_begin(bytes, sizeof(bytes), context, begin_info);
CHECK(begin.ok);

const auto call = encoder.encode_call(bytes, sizeof(bytes), "jni", "find", "resolved");
CHECK(call.ok);

uint8_t too_small[7]{};
CHECK(!encoder.encode_end(too_small, sizeof(too_small), true, 0x42, 7, metrics).ok);
CHECK(std::all_of(std::begin(too_small), std::end(too_small),
                  [](uint8_t value) { return value == 0; }));
~~~

- [ ] **Step 2: Build and verify RED**

~~~bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake   -S tracer/src/test/cpp -B build/binary-trace-debug -G Ninja   -DCMAKE_MAKE_PROGRAM=/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ninja   -DCMAKE_BUILD_TYPE=Debug
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake   --build build/binary-trace-debug --target binary_trace_encoder_test
~~~

Expected: compile failure because the new headers do not exist.

- [ ] **Step 3: Implement explicit one-pass encoding**

Use append_u16, append_u32, append_u64, append_bytes, and append_string helpers that shift bytes explicitly. Do not memcpy native structs. Pre-calculate exact record size from fixed counts and bounded lengths before writing. Reject oversized values before touching output. Declare exact maximums for every record type.

- [ ] **Step 4: Run normal, strict, and sanitizer focused tests**

~~~bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/binary-trace-debug
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest   --test-dir build/binary-trace-debug --output-on-failure -R binary_trace_encoder
~~~

Repeat with -Wall -Wextra -Werror and with -fsanitize=address,undefined -fno-omit-frame-pointer.

- [ ] **Step 5: Commit**

~~~bash
git add docs/superpowers/plans/2026-08-20-binary-trace-format.md   tracer/src/main/cpp/events/binary_trace_format.h   tracer/src/main/cpp/events/binary_trace_encoder.h   tracer/src/main/cpp/events/binary_trace_encoder.cpp   tracer/src/test/cpp/binary_trace_encoder_test.cpp tracer/src/test/cpp/CMakeLists.txt
git commit -m "feat(trace): add QTRB binary encoder"
~~~

---

### Task 3: Compact Dynamic Registers and Definitions

**Files:**
- Create: tracer/src/main/cpp/events/trace_dictionary.h
- Create: tracer/src/main/cpp/events/trace_dictionary.cpp
- Create: tracer/src/test/cpp/trace_dictionary_test.cpp
- Modify: tracer/src/main/cpp/events/trace_record.h
- Modify: tracer/src/main/cpp/core/pending_instruction.cpp
- Modify: tracer/src/main/cpp/core/instruction_collector.cpp
- Modify: tracer/src/main/cpp/events/binary_trace_encoder.cpp
- Modify: tracer/src/main/cpp/events/trace_encoder.cpp
- Modify: tracer/src/test/cpp/instruction_collector_test.cpp
- Modify: tracer/src/test/cpp/trace_encoder_test.cpp
- Modify: tracer/src/test/cpp/CMakeLists.txt

**Interfaces:**

~~~cpp
struct DenseRegisterValues {
    std::array<uint64_t, kTraceGprCount> values{};
    uint8_t count = 0;
};

class TraceDictionary {
public:
    explicit TraceDictionary(uint32_t requested_slots = 1U << 16U) noexcept;
    bool needs_instruction_definition(uint32_t opcode) const noexcept;
    void commit_instruction_definition(uint32_t opcode) noexcept;
    void reset() noexcept;
};
~~~

InstructionRecord replaces borrowed register-name arrays and fixed before/after arrays with reads and writes DenseRegisterValues. Metadata ID is the full opcode. A direct-slot collision may repeat an identical definition; conflicting redefinition is invalid on the host.

- [ ] **Step 1: Write RED tests**

~~~cpp
decoded.read_gpr_mask = (1ULL << 0U) | (1ULL << 8U) | (1ULL << 33U);
decoded.write_gpr_mask = (1ULL << 1U) | (1ULL << 30U);
CHECK(collector.begin({0x1000, &decoded}, registers));
CHECK(collector.complete_pending(after));
CHECK(sink.record.reads.count == 3);
CHECK(sink.record.reads.values[0] == registers.values[0]);
CHECK(sink.record.reads.values[1] == registers.values[8]);
CHECK(sink.record.reads.values[2] == registers.values[33]);

TraceDictionary dictionary(1);
CHECK(dictionary.needs_instruction_definition(0x14000001));
CHECK(dictionary.needs_instruction_definition(0x14000001));
dictionary.commit_instruction_definition(0x14000001);
CHECK(!dictionary.needs_instruction_definition(0x14000001));
CHECK(dictionary.needs_instruction_definition(0xd503201f));
~~~

Also require W-register truncation and unchanged format-2 semantic rendering during migration.

- [ ] **Step 2: Build and verify RED**

~~~bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/binary-trace-debug   --target instruction_collector_test trace_dictionary_test trace_encoder_test
~~~

Expected: compile failure because dense values and the dictionary do not exist.

- [ ] **Step 3: Implement set-bit iteration**

Use std::countr_zero and mask &= mask - 1U for snapshots, pending read completion, pending write completion, and binary encoding. Names and widths come only from CachedInstruction. Allocate the dictionary table during writer setup with bounded mmap fallback; needs and commit perform no allocation.

- [ ] **Step 4: Run focused tests**

~~~bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/binary-trace-debug
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest   --test-dir build/binary-trace-debug --output-on-failure   -R 'instruction_collector|trace_dictionary|trace_encoder|binary_trace_encoder'
~~~

Expected: all selected tests pass in normal and ASan+UBSan builds.

- [ ] **Step 5: Commit**

~~~bash
git add tracer/src/main/cpp/events/trace_dictionary.h   tracer/src/main/cpp/events/trace_dictionary.cpp   tracer/src/main/cpp/events/trace_record.h   tracer/src/main/cpp/core/pending_instruction.cpp   tracer/src/main/cpp/core/instruction_collector.cpp   tracer/src/main/cpp/events/binary_trace_encoder.cpp   tracer/src/main/cpp/events/trace_encoder.cpp   tracer/src/test/cpp/trace_dictionary_test.cpp   tracer/src/test/cpp/instruction_collector_test.cpp   tracer/src/test/cpp/trace_encoder_test.cpp tracer/src/test/cpp/CMakeLists.txt
git commit -m "perf(trace): compact register snapshots"
~~~

---

### Task 4: Add Binary Writer and Metrics v2

**Files:**
- Create: tracer/src/main/cpp/events/binary_trace_writer.h
- Create: tracer/src/main/cpp/events/binary_trace_writer.cpp
- Create: tracer/src/test/cpp/binary_trace_writer_test.cpp
- Modify: tracer/src/main/cpp/events/trace_metrics.h
- Modify: tracer/src/main/cpp/events/async_trace_writer.cpp
- Modify: tracer/src/test/cpp/async_trace_writer_test.cpp
- Modify: tracer/src/test/cpp/CMakeLists.txt

**Interfaces:** BinaryTraceWriter exposes prepare, open_prepared, begin, instruction, memory, call, rule, error, end, close, detach_after_fork_child, failed, error_code, and path with the current facade semantics.

- [ ] **Step 1: Write writer RED tests**

Require .trace.bin.lz4 and .trace.bin suffixes, stream header, definition-before-reference, one definition for repeated opcode, dictionary commit only after successful append, footer, idempotent close, metrics v2, and zero encoding attempts after failure.

~~~cpp
CHECK(writer.prepare(context));
CHECK(writer.open_prepared());
CHECK(writer.begin(context));
CHECK(writer.instruction(context, first));
CHECK(writer.instruction(context, second_same_opcode));
CHECK(writer.end(0x42, true, 7));
CHECK(writer.close());
CHECK(writer.path().ends_with(".trace.bin.lz4"));
CHECK(count_record(decoded, BinaryRecordType::InstructionDefinition) == 1);
CHECK(metric_value(sidecar, "metrics_version") == "2");
CHECK(metric_value(sidecar, "encoded_bytes") == std::to_string(decoded.size()));
CHECK(metric_value(sidecar, "raw_bytes").empty());
~~~

- [ ] **Step 2: Build and verify RED**

~~~bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake   --build build/binary-trace-debug --target binary_trace_writer_test
~~~

Expected: compile failure because BinaryTraceWriter and metrics-v2 fields do not exist.

- [ ] **Step 3: Implement reserve/encode/commit**

Reserve each encoder maximum once and commit actual size. Emit and commit an instruction definition before committing its dictionary tag, then emit the instruction. Latch the first error and prevent later event encoding. Rename native raw_bytes accounting to encoded_bytes. Write metrics_version=2 plus profile, return, instructions, elapsed_ms, instruction rate, encoded/compressed bytes and rates, ratio, cache fields, swaps, waits, wait time, and effective buffer bytes.

- [ ] **Step 4: Run writer/failure matrix**

~~~bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/binary-trace-debug
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest   --test-dir build/binary-trace-debug --output-on-failure   -R 'binary_trace_writer|async_trace_writer|failure_state'
~~~

Repeat in strict, Release, and ASan+UBSan builds.

- [ ] **Step 5: Commit**

~~~bash
git add tracer/src/main/cpp/events/binary_trace_writer.h   tracer/src/main/cpp/events/binary_trace_writer.cpp   tracer/src/main/cpp/events/trace_metrics.h   tracer/src/main/cpp/events/async_trace_writer.cpp   tracer/src/test/cpp/binary_trace_writer_test.cpp   tracer/src/test/cpp/async_trace_writer_test.cpp tracer/src/test/cpp/CMakeLists.txt
git commit -m "feat(trace): write binary trace artifacts"
~~~

---

### Task 5: Migrate the Production Path and Lifecycle Tests

**Files:**
- Modify: tracer/src/main/cpp/core/instruction_collector.{h,cpp}
- Modify: tracer/src/main/cpp/core/qbdi_runner.{h,cpp}
- Modify: tracer/src/main/cpp/core/qbdi_runner_lifecycle.{h,cpp}
- Modify: tracer/src/main/cpp/core/trace_run_session.{h,cpp}
- Modify: tracer/src/main/cpp/handlers/call_handlers.{h,cpp}
- Modify: tracer/src/main/cpp/rules/code_rule_context.{h,cpp}
- Modify: tracer/src/main/cpp/CMakeLists.txt
- Modify: affected tracer/src/test/cpp files
- Delete: tracer/src/main/cpp/events/text_trace_writer.{h,cpp}
- Delete: tracer/src/main/cpp/events/trace_encoder.{h,cpp}
- Delete: tracer/src/test/cpp/text_trace_writer_test.cpp
- Delete: tracer/src/test/cpp/trace_encoder_test.cpp

**Interfaces:**
- Consumes: BinaryTraceWriter from Task 4.
- Produces: one concrete binary writer per run_with_qbdi invocation without a virtual per-instruction call.

- [ ] **Step 1: Add production migration RED assertions**

Update real writer-owning runner tests to require binary magic and suffix. Add a source contract test rejecting TextTraceWriter, TraceEncoder, and .trace.txt.lz4 from production CMake/source.

- [ ] **Step 2: Run lifecycle tests and verify RED**

~~~bash
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/binary-trace-debug   --target qbdi_runner_lifecycle_test tracer_entry_proxy_test failure_state_test
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest   --test-dir build/binary-trace-debug --output-on-failure   -R 'qbdi_runner_lifecycle|tracer_entry_proxy|failure_state'
~~~

Expected: binary assertions fail while production uses text.

- [ ] **Step 3: Replace the concrete facade**

Change caller types to BinaryTraceWriter. Preserve callback gate, TraceRunSessionOutcome, retained-original fallback, heap runner runtime, child abandon, fd registry, nested-fork behavior, atfork fail-closed state, and first-error latching. Keep short CALL records compact; split details above 3072 bytes at valid UTF-8 boundaries into explicitly grouped CALL-chunk records, preserving arbitrary fragment bytes and bounding a logical detail to 1 MiB. Add parser-style round-trip coverage for boundary-spanning UTF-8, adjacent identical calls, empty details, arbitrary bytes, maximum chunks/order, and validation failure before any fragment is written. Connect callback-registration failures through the production registrar seam and link a real InstructionCollector failure-gate/rule-action integration test. Remove text sources and tests only after binary tests cover their lifecycle/error contracts.

- [ ] **Step 4: Run all native tests and stress**

Run Debug, strict, Release, and ASan+UBSan suites, then:

~~~bash
for qtrace_run in $(seq 1 100); do
  build/binary-trace-debug/qbdi_runner_lifecycle_test || exit 1
  build/binary-trace-debug/tracer_entry_proxy_test || exit 1
done
for qtrace_run in $(seq 1 30); do
  build/binary-trace-debug/failure_state_test || exit 1
done
~~~

Expected: every run exits zero with stable target returns and no deadlock, leak, or double close.

- [ ] **Step 5: Commit**

~~~bash
git add tracer/src/main/cpp tracer/src/test/cpp
git commit -m "refactor(trace): route events to binary writer"
~~~

---

### Task 6: Extract Shared LZ4 Framing

**Files:**
- Create: scripts/lz4_frames.py
- Create: scripts/tests/test_lz4_frames.py
- Modify: scripts/pull_trace.py
- Modify: scripts/tests/test_pull_trace.py

**Interfaces:**

- Lz4FileScan stores an ordered immutable collection of `(start, end)` byte ranges and a
  `truncated: bool` flag.
- `scan_lz4_file(path: Path) -> Lz4FileScan` validates and indexes complete frames.
- `decode_lz4_file(source: Path, output: Path, executable: str) -> bool` streams complete frames
  and returns whether the final frame was truncated.

- [ ] **Step 1: Move tests first**

Move scanner, concatenation, raw-block, optional-header, checksum, truncation, subprocess-error, and exceptional-reaping tests to test_lz4_frames.py and import scripts.lz4_frames before creating it.

- [ ] **Step 2: Verify RED**

~~~bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts.tests.test_lz4_frames -v
~~~

Expected: ImportError for scripts.lz4_frames.

- [ ] **Step 3: Extract one implementation**

Move the scanner and decoder without behavior changes. Preserve standard-frame validation,
complete and truncated skippable-padding handling, Android crash handling in pull_trace, safe
subprocess argv, bounded 1 MiB copying, and terminate/wait cleanup. Skippable frames contribute to
artifact length but no decoded bytes. Remove duplicate scanner code from pull_trace.py.

- [ ] **Step 4: Run framing and pull tests**

~~~bash
PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS=error python3 -m unittest   scripts.tests.test_lz4_frames scripts.tests.test_pull_trace -v
~~~

Expected: both modules pass.

- [ ] **Step 5: Commit**

~~~bash
git add scripts/lz4_frames.py scripts/pull_trace.py   scripts/tests/test_lz4_frames.py scripts/tests/test_pull_trace.py
git commit -m "refactor(trace): share LZ4 frame decoder"
~~~

---

### Task 7: Build the Streaming Converter

**Files:**
- Create: scripts/trace_binary.py
- Create: scripts/trace_convert.py
- Create: scripts/tests/test_trace_binary.py
- Create: scripts/tests/test_trace_convert.py

**Interfaces:**

- `BinaryTraceError` derives from `RuntimeError` and is the only expected protocol failure exposed
  by the module.
- `ConversionStats` is a frozen dataclass with `instructions: int`,
  `converted_text_bytes: int`, and `partial: bool`.
- `convert_binary_stream(source: BinaryIO, output: TextIO, *, allow_partial: bool = False) ->
  ConversionStats` validates and renders an already decompressed stream.
- `convert_binary_file(source: Path, destination: Path, *, lz4: str | None,
  crash_marked: bool, force: bool = False) -> ConversionStats` owns decompression, temporary files,
  and atomic publication.

- [ ] **Step 1: Write protocol and CLI RED tests**

Construct fixture bytes with struct.pack("<HHI", record_type, flags, payload_size). Cover all profiles/types, dictionary resolution, PC-relative classes, special registers, memory continuations, escaping, ordinary and chunked CALLs, and exact format-3 lines. Reassemble only contiguous CALL chunks with one nonzero event ID, identical total/count/category/name, and indexes exactly `0..count-1`; concatenate raw detail bytes before validating UTF-8 and emitting one CALL. Reject unknown flags, interleaved/incomplete/duplicate/out-of-order chunks, total-length mismatch, wrong magic/version/endian/pointer width/features, oversized payload or logical CALL, conflicting definition, missing definition, invalid reassembled UTF-8, sequence gap, record after footer, missing footer, and sidecar mismatch.

- [ ] **Step 2: Verify RED**

~~~bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest   scripts.tests.test_trace_binary scripts.tests.test_trace_convert -v
~~~

Expected: ImportError because both modules are absent.

- [ ] **Step 3: Implement bounded streaming conversion**

Read exactly eight record-header bytes, validate length before reading payload, and retain only dictionaries plus one record. Render PC-relative targets with the same 64-bit wrapping/current-page rules as CachedInstruction. Decode compressed complete frames to a unique temporary binary, stream to a unique text temporary, fsync/close, and atomically publish. Remove temporaries on every exception. Publish partial text only for a valid crash marker plus a truncated final frame.

- [ ] **Step 4: Run full Python and 1 GiB streaming tests**

Use a synthetic repeating stream and tracemalloc. Do not allocate a 1 GiB bytes object; peak traced Python allocation must remain below 128 MiB.

~~~bash
PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS=error   python3 -m unittest discover -s scripts/tests -p 'test_*.py'
python3 scripts/trace_convert.py --help
~~~

Expected: all tests pass.

- [ ] **Step 5: Commit**

~~~bash
git add scripts/trace_binary.py scripts/trace_convert.py   scripts/tests/test_trace_binary.py scripts/tests/test_trace_convert.py
git commit -m "feat(trace): convert binary traces to text"
~~~

---

### Task 8: Integrate Pulling, Metrics, and Benchmarks

**Files:**
- Modify: scripts/pull_trace.py
- Modify: scripts/benchmark_trace.py
- Modify: scripts/tests/test_pull_trace.py
- Modify: scripts/tests/test_benchmark_trace.py

**Interfaces:**
- Consumes: .trace.txt.lz4, .trace.bin.lz4, .trace.bin, metrics v1/v2, and Task 7 converter.
- Produces: newest-artifact selection, atomic output, and comparable medians.

- [ ] **Step 1: Add dual-format RED tests**

~~~python
names = [
    "300_benchmark.trace.bin.lz4.metrics",
    "300_benchmark.trace.bin.lz4",
    "200_benchmark.trace.txt.lz4",
]
self.assertEqual("300_benchmark.trace.bin.lz4", select_trace_name(names))
~~~

Add exact v2 metrics containing metrics_version, encoded_bytes, encoded rate, compressed fields, cache fields, swaps, waits, effective buffer, profile, return, instructions, elapsed, and instruction rate. Require rejection of mixed raw_bytes/encoded_bytes contracts.

- [ ] **Step 2: Verify RED**

~~~bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest   scripts.tests.test_pull_trace scripts.tests.test_benchmark_trace -v
~~~

Expected: binary selection and v2 parsing fail.

- [ ] **Step 3: Implement explicit dispatch**

Define TEXT_TRACE_SUFFIX, BINARY_TRACE_SUFFIX, BINARY_RAW_SUFFIX, and TRACE_SUFFIXES. Select by remote listing order, not suffix priority. Parse metrics v1 only when metrics_version is absent and raw_bytes exists; parse v2 only when metrics_version=2 and encoded_bytes exists. Retain Decimal through rates and medians. Use compressed_bytes for size acceptance.

- [ ] **Step 4: Run all host tests and syntax checks**

~~~bash
PYTHONDONTWRITEBYTECODE=1 PYTHONWARNINGS=error   python3 -m unittest discover -s scripts/tests -p 'test_*.py'
node --check scripts/benchmark_trace.js
python3 -B -m py_compile scripts/benchmark_trace.py scripts/pull_trace.py   scripts/lz4_frames.py scripts/trace_binary.py scripts/trace_convert.py
~~~

Expected: all tests and checks pass.

- [ ] **Step 5: Commit**

~~~bash
git add scripts/pull_trace.py scripts/benchmark_trace.py   scripts/tests/test_pull_trace.py scripts/tests/test_benchmark_trace.py
git commit -m "feat(trace): handle binary trace artifacts"
~~~

---

### Task 9: Document, Verify, and Run Device Acceptance

**Files:**
- Modify: docs/trace-format.md
- Modify: README.md
- Modify: docs/benchmarks/binary-trace-baseline.md
- Test: scripts/tests/test_pull_trace.py
- Test: scripts/tests/test_benchmark_trace.py
- Test: scripts/tests/test_trace_convert.py

**Interfaces:**
- Consumes: completed writer, converter, pull integration, metrics v2, and Task 1 baseline.
- Produces: user workflow, final protocol documentation, same-device evidence, and acceptance verdict.

- [x] **Step 1: Add documentation contract RED tests**

Require the actual docs to contain .trace.bin.lz4, QTRB v1, metrics_version=2, trace_convert.py, pull_trace.py, app-private staging, format-2 compatibility, and crash partial semantics. Require binary trace output to be absent from explicit exclusions.

- [x] **Step 2: Update documentation**

Document exact artifact names, header and record fields, limits, format-3 escaping/order, metrics v2, old compatibility, automatic pull conversion, manual conversion, crash partial behavior, and exit statuses.

~~~bash
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid   --device 192.168.51.42:5555 --output pulled-traces
python3 scripts/trace_convert.py input.trace.bin.lz4 --output output.trace.txt
~~~

- [x] **Step 3: Run fresh host and Android matrices**

Configure/build/test native Debug, strict -Wall -Wextra -Werror, Release, and ASan+UBSan. Run all Python tests, Node syntax, Python byte compilation, and git diff --check. Then run:

~~~bash
./gradlew :app:assembleDebug :app:assembleRelease   :tracer:assembleDebug :tracer:assembleRelease :tracer:copyTracerDebug
~~~

Expected: every suite passes and Gradle reports BUILD SUCCESSFUL. Confirm the shared object is ELF64 AArch64 and Release contains no Debug-only option strings.

- [x] **Step 4: Run Pixel 6 acceptance**

Stage the exact hashed Debug tracer into app-private storage; verify local/device SHA-256 and SELinux Enforcing. Run one warmup plus five fresh measured processes for fast, balanced, and full. Pull each median artifact and verify format 3, sequence 1..21718, footer/sidecar agreement, stable return, no crash marker, and compressed size no larger than Task 1.

Run the existing large-workload iteration count. Require visible artifact growth during execution, normal target completion, stable return, and complete conversion. Record all elapsed values, medians, rates, encoded/compressed sizes, ratios, cache/wait counters, hashes, conversion results, and gate verdicts.

- [x] **Step 5: Commit acceptance evidence**

~~~bash
git add README.md docs/trace-format.md docs/benchmarks/binary-trace-baseline.md
git commit -m "docs(trace): record binary trace acceptance"
~~~

If any speed or size gate fails, do not create the acceptance commit. Preserve the correct implementation and measurements, capture simpleperf against the exact candidate, and return to design review with the measured dominant cost. Do not remove fields, sample events, or combine unrelated optimizations to force a pass.

---

## Final Review Gate

Request an independent review against docs/superpowers/specs/2026-08-20-binary-trace-format-design.md. The reviewer must verify:

- Every profile preserves information and event order.
- The device hot path has no text formatting or unbounded allocation.
- Dictionary definition/reference and PC-relative rendering are exact.
- Record and buffer boundaries cannot publish partial records.
- Trace failure, fork, nested fork, crash, and fd reuse preserve target behavior.
- Converter validation, bounded memory, cleanup, and atomic publication fail closed.
- Format-2 pull compatibility remains tested.
- Metrics v1/v2 are never silently mixed.
- Device speed/size evidence uses the same device, build, workload, and exact hashes.

Resolve every Critical and Important finding with a RED/GREEN regression before integration.

### Final repair wave (2026-08-21)

- [x] Add reversible RULE/ERROR continuations that fit a 4096-byte producer buffer.
- [x] Bound producer and host instruction definitions to 65,536 dense run-local IDs.
- [x] Reclaim mappings, compression state, fd, and pthread ownership after two join failures.
- [x] Require five measured acceptance runs, complete device/package/build/tracer identity, and a
  streaming count/first/last instruction oracle.
- [x] Share one strict suffix-aware v1/v2 metrics parser and recompute every fixed-six rate.
- [x] Define minor-1 optional record namespace behavior while rejecting required extensions.
- [x] Make crash-marker session and retired paths fixed-capacity under `-fno-exceptions`.
- [x] Reject impossible continuation metadata and remove obsolete text-era instruction fields.

### Scoped re-review repair (2026-08-21)

- [x] Emit QTRB v1.1 and keep v1.0 legacy RULE/ERROR grammar strictly convertible.
- [x] Require producer-identical integer fixed-six truncation with no epsilon acceptance.
- [x] Stop after the final-candidate fast miss, capture simpleperf under Enforcing, and return to
  design review before changing performance code.
- [x] Retain failed and diagnostic batches; optimize Debug LZ4 effort and hot-record reuse without
  changing fields, ordering, workload, or acceptance targets.
- [x] Run and completely convert the 8,192-iteration workload on the exact final candidate.
- [x] Run one new predeclared warmup-plus-five batch for fast, balanced, and full.
