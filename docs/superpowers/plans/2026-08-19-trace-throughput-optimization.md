# Trace Throughput Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the default QBDI trace path at least five times faster than the current comparable path and target one million traced instructions per second on the reference device.

**Architecture:** Keep QBDI and replace per-instruction streams and synchronous writes with an opcode-keyed instruction cache, a delayed single-PRE collector, a bounded allocation-free text encoder, and an adaptive double-buffer writer. The writer compresses independent LZ4 frames on one consumer thread, while trace profiles keep memory instrumentation out of the default hot path.

**Tech Stack:** C++20, Android NDK arm64-v8a, QBDI 0.12.1, ShadowHook, POSIX threads/files, LZ4 frame v1.10.0, CMake/CTest, Gradle, Frida JavaScript, Python 3.

## Global Constraints

- Keep QBDI as the execution engine and preserve CodeRule, JNI, libc, and execution-transfer behavior.
- The default profile is `fast`; QBDI memory recording is disabled in this profile.
- `balanced` records memory type, address, size, and QBDI-provided value; `full` adds bounded byte capture and hexdump.
- LZ4 frame fast compression is enabled by default.
- Use ordinary asynchronous `write`; do not add `O_DIRECT` or `io_uring`.
- Default to 2 x 64 MiB buffers; allow 2 x 128 MiB on high-memory devices or by explicit configuration.
- Do not silently sample, overwrite, or drop trace events. Measure producer backpressure.
- Preserve x0-x8 when tracing setup fails and the unhooked target must run natively.
- Keep Android `minSdk 24`, C++20, `-fno-exceptions`, `-fno-rtti`, and arm64-v8a.
- Pin the vendored LZ4 library to v1.10.0 and retain its BSD-2-Clause license.
- A completed trace uses `.trace.txt.lz4`; final writer metrics use the adjacent `.metrics` sidecar.

## File Structure

New focused units:

- `tracer/src/main/cpp/core/instruction_cache.{h,cpp}`: compact opcode cache and decode metadata.
- `tracer/src/main/cpp/core/pending_instruction.{h,cpp}`: QBDI-independent delayed record state machine.
- `tracer/src/main/cpp/core/instruction_collector.{h,cpp}`: QBDI decode/register adapter for delayed collection.
- `tracer/src/main/cpp/core/native_fallback_arm64.{h,S}`: native call bridge preserving x0-x8.
- `tracer/src/main/cpp/events/trace_record.h`: fixed-size hot-path record types.
- `tracer/src/main/cpp/events/trace_encoder.{h,cpp}`: bounded text encoding without streams.
- `tracer/src/main/cpp/events/trace_metrics.h`: cache, collector, encoder, and writer counters.
- `tracer/src/main/cpp/events/async_trace_writer.{h,cpp}`: SPSC double buffering, LZ4, I/O, and lifecycle.
- `tracer/src/main/cpp/third_party/lz4/`: pinned upstream library sources and license.
- `tracer/src/test/cpp/`: host CTest targets for pure C++ units.
- `scripts/benchmark_trace.{js,py}`: repeatable device benchmark and median report.
- `scripts/pull_trace.py`: pull, validate, and decompress trace artifacts.

Existing files retain their current responsibilities:

- `events/text_trace_writer.{h,cpp}` becomes the compatibility facade joining encoder and async writer.
- `core/qbdi_runner.cpp` owns QBDI registration and feeds the collector.
- `core/trace_config.{h,cpp}` owns profile and writer configuration.
- `rules/code_rule_context.{h,cpp}` consumes a cache-backed instruction view.
- `handlers/call_handlers.cpp` continues semantic event production through the writer facade.

---

### Task 0: Deterministic Benchmark and Optimization Baseline

**Files:**
- Create: `scripts/benchmark_trace.js`
- Create: `scripts/benchmark_trace.py`
- Create: `scripts/tests/test_benchmark_trace.py`
- Create: `docs/benchmarks/trace-throughput-baseline.md`
- Modify: `app/src/main/cpp/demo_target/demo_scenes.h`
- Modify: `app/src/main/cpp/demo_target/demo_scenes.cpp`
- Modify: `app/src/main/cpp/demo_target/demo_target.cpp`
- Modify: `app/src/main/kotlin/com/aprz/qbdiandroid/NativeDemo.kt`
- Modify: `app/src/main/kotlin/com/aprz/qbdiandroid/MainActivity.kt`
- Modify: `tracer/src/main/cpp/core/trace_config.cpp`
- Modify: `scripts/trace_config.js`

**Interfaces:**
- Produces: exported `demo_benchmark_case(uint64_t iterations, uint64_t seed)` with a stable return.
- Produces: a legacy-trace parser and five-run baseline report used again in Task 9.

- [ ] **Step 1: Write failing legacy trace parser tests**

```python
from scripts.benchmark_trace import median_report, parse_legacy_trace

def test_legacy_trace_metrics_and_median():
    trace = """TRACE_BEGIN scene=benchmark
1 libdemo_target.so+0x10 add x0, x0, #1
2 libdemo_target.so+0x14 ret
TRACE_END status=ok ret=0x42 elapsed_ms=20 bytes=0
"""
    parsed = parse_legacy_trace(trace.encode(), file_bytes=512)
    assert parsed["instructions"] == 2
    assert parsed["elapsed_ms"] == 20
    assert parsed["raw_bytes"] == 512
    assert median_report([{"elapsed_ms": 10}, {"elapsed_ms": 30},
                          {"elapsed_ms": 20}])["elapsed_ms"] == 20
```

- [ ] **Step 2: Run and verify the benchmark module is absent**

Run: `python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v`

Expected: import fails because `scripts/benchmark_trace.py` does not exist.

- [ ] **Step 3: Add the deterministic benchmark scene**

```cpp
extern "C" __attribute__((noinline, visibility("default")))
uint64_t demo_benchmark_case(uint64_t iterations, uint64_t seed);
```

Implement a fixed loop containing integer mixing, a data-dependent branch, one load, one store,
and a noinline helper call every 256 iterations. Keep its working set at 4 KiB. Register
`runBenchmarkCase(): String`, add a manual UI button, and append a `benchmark` SceneConfig entry.

- [ ] **Step 4: Add baseline Frida and Python orchestration**

`benchmark_trace.js` waits for `libdemo_target.so`, resolves the exported benchmark address,
computes its module offset, configures the tracer with only that scene, installs the module hook,
and invokes `NativeFunction('uint64', ['uint64', 'uint64'])`. It sends the returned value to
Python; after the call returns, Python selects the newest benchmark trace through `run-as`.

`benchmark_trace.py` runs one warmup and five fresh-process measured runs, rejects differing return
values, pulls the uncompressed legacy trace, obtains instruction count from the largest leading
sequence number, obtains elapsed time from `TRACE_END`, and reports medians.

- [ ] **Step 5: Run tests and builds**

Run: `python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v`

Expected: legacy parser, median, malformed footer, and return-mismatch tests pass.

Run: `./gradlew :app:assembleDebug :tracer:assembleDebug :tracer:copyTracerDebug`

Expected: all artifacts build and the exported benchmark symbol exists in the unstripped target.

- [ ] **Step 6: Capture the optimization baseline on the reference device**

Run: `python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid --runs 5 --legacy`

Expected: five successful traces with one stable return and a median report. Write the device
model, Android version, ABI, build type, iteration count, five raw timings, median instructions per
second, and median raw MiB/s to `docs/benchmarks/trace-throughput-baseline.md`.

- [ ] **Step 7: Commit**

```bash
git add app/src tracer/src/main/cpp/core/trace_config.cpp scripts docs/benchmarks
git commit -m "test: record trace throughput baseline"
```

### Task 1: Trace Profiles and Host Test Harness

**Files:**
- Create: `tracer/src/test/cpp/CMakeLists.txt`
- Create: `tracer/src/test/cpp/trace_config_test.cpp`
- Modify: `tracer/src/main/cpp/core/trace_config.h`
- Modify: `tracer/src/main/cpp/core/trace_config.cpp`
- Modify: `scripts/trace_config.js`
- Modify: `scripts/spawn_trace.js`

**Interfaces:**
- Produces: `enum class TraceProfile : uint8_t { Fast, Balanced, Full }`.
- Produces: `TraceOptions TraceConfig::trace` with compression, per-buffer capacity, and hexdump settings.
- Produces: `const char *trace_profile_name(TraceProfile)` and strict encoded-config parsing.

- [ ] **Step 1: Add a host CTest harness and failing configuration tests**

```cmake
cmake_minimum_required(VERSION 3.22.1)
project(qbdi_tracer_native_tests LANGUAGES CXX)
enable_testing()

function(add_trace_test name)
    add_executable(${name} ${ARGN})
    target_compile_features(${name} PRIVATE cxx_std_20)
    target_compile_definitions(${name} PRIVATE QTRACE_HOST_TEST=1)
    target_include_directories(${name} PRIVATE ../../main/cpp)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

add_trace_test(trace_config_test
    trace_config_test.cpp
    ../../main/cpp/core/trace_config.cpp)
```

```cpp
#include "core/trace_config.h"
#include <cassert>
#include <cstring>

int main() {
    TraceConfig defaults = default_trace_config();
    assert(defaults.trace.profile == TraceProfile::Fast);
    assert(defaults.trace.compression_enabled);
    assert(defaults.trace.lz4_level == 0);
    assert(defaults.trace.auto_buffer_size);
    assert(defaults.trace.buffer_bytes == 0);
    assert(defaults.trace.hexdump_limit == 32);
    assert(defaults.valid);

    TraceConfig parsed = parse_trace_config(
        "profile=full;compression=0;lz4_level=9;auto_buffer=0;"
        "buffer_mb=64;hexdump_limit=16");
    assert(parsed.trace.profile == TraceProfile::Full);
    assert(!parsed.trace.compression_enabled);
    assert(parsed.trace.lz4_level == 9);
    assert(!parsed.trace.auto_buffer_size);
    assert(parsed.trace.buffer_bytes == 64ULL * 1024 * 1024);
    assert(parsed.trace.hexdump_limit == 16);
    assert(std::strcmp(trace_profile_name(parsed.trace.profile), "full") == 0);

    TraceConfig invalid = parse_trace_config("profile=turbo;buffer_mb=512");
    assert(!invalid.valid);
    assert(!invalid.error.empty());
}
```

- [ ] **Step 2: Run the test and verify the new types are missing**

Run: `cmake -S tracer/src/test/cpp -B build/tracer-native-tests && cmake --build build/tracer-native-tests && ctest --test-dir build/tracer-native-tests --output-on-failure`

Expected: compilation fails because `TraceProfile` and `TraceConfig::trace` do not exist.

- [ ] **Step 3: Add strict profile and writer options**

```cpp
enum class TraceProfile : uint8_t { Fast, Balanced, Full };

struct TraceOptions {
    TraceProfile profile = TraceProfile::Fast;
    bool compression_enabled = true;
    int lz4_level = 0;
    bool auto_buffer_size = true;
    size_t buffer_bytes = 0;
    size_t hexdump_limit = 32;

    bool memory_enabled() const { return profile != TraceProfile::Fast; }
    bool hexdump_enabled() const { return profile == TraceProfile::Full; }
};
```

Add `TraceOptions trace;`, `bool valid = true;`, and `std::string error;` to `TraceConfig`. Parse
only `fast`, `balanced`, and `full`. Accept `lz4_level` in `0..12`, explicit per-buffer
`buffer_mb` in `8..128` (or `0` for automatic sizing), and `hexdump_limit` in `0..64`. Any unknown
profile, malformed integer, or out-of-range value sets `valid=false` with a concrete error. The
configure entry point logs that error and keeps the last valid configuration unchanged.

- [ ] **Step 4: Extend both Frida configuration encoders**

Use this exact default object in both JavaScript files and append matching encoded fields:

```js
trace: {
  profile: 'fast',
  compression: true,
  lz4Level: 0,
  autoBuffer: true,
  bufferMb: 0,
  hexdumpLimit: 32
}
```

- [ ] **Step 5: Run native tests and Android builds**

Run: `cmake --build build/tracer-native-tests && ctest --test-dir build/tracer-native-tests --output-on-failure`

Expected: `trace_config_test` passes.

Run: `./gradlew :tracer:assembleDebug`

Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 6: Commit**

```bash
git add tracer/src/test/cpp tracer/src/main/cpp/core/trace_config.* scripts/trace_config.js scripts/spawn_trace.js
git commit -m "feat: add trace performance profiles"
```

### Task 2: Compact Opcode Cache and Post-Rule Metadata

**Files:**
- Create: `tracer/src/main/cpp/core/instruction_cache.h`
- Create: `tracer/src/main/cpp/core/instruction_cache.cpp`
- Create: `tracer/src/test/cpp/instruction_cache_test.cpp`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`
- Modify: `tracer/src/main/cpp/rules/code_rule.h`
- Modify: `tracer/src/main/cpp/rules/code_rule.cpp`

**Interfaces:**
- Produces: `CachedInstruction`, `InstructionView`, and `InstructionCache`.
- Produces: `CodeRule::requires_immediate_post()` and `CodeRuleEngine::requires_immediate_post()`.
- Consumes later: the collector populates cache misses from `QBDI::InstAnalysis`.

- [ ] **Step 1: Write failing cache collision and PC-relative tests**

```cpp
#include "core/instruction_cache.h"
#include <cassert>
#include <cstring>

int main() {
    InstructionCache cache(1);
    CachedInstruction branch{};
    branch.opcode = 0x14000001;
    std::strcpy(branch.mnemonic, "b");
    std::strcpy(branch.operands, "#0x4");
    branch.pc_relative_displacement = 4;
    branch.flags = InstructionFlags::Branch | InstructionFlags::PcRelative;

    const CachedInstruction *stored = cache.insert(branch);
    assert(cache.find(branch.opcode) == stored);
    assert(stored->absolute_branch_target(0x1000) == 0x1004);

    CachedInstruction collision = branch;
    collision.opcode = branch.opcode + 8;
    std::strcpy(collision.mnemonic, "bl");
    cache.insert(collision);
    assert(cache.find(collision.opcode) != nullptr);
    assert(cache.metrics().misses == 2);
}
```

- [ ] **Step 2: Run the cache test and verify it fails to compile**

Run: `cmake -S tracer/src/test/cpp -B build/tracer-native-tests && cmake --build build/tracer-native-tests`

Expected: compilation fails because `instruction_cache.h` does not exist.

- [ ] **Step 3: Implement the direct-mapped cache**

Use a preferred `1U << 22` slot table. Each slot stores only
`{uint32_t opcode, uint32_t entry_plus_one}`. Allocate slot storage with `mmap`, falling back to
`1U << 20` and `1U << 18` slots; if every allocation fails, expose a disabled cache and let the
collector use the slow decode path. A first use allocates one fixed-size `CachedInstruction` for
that slot; a collision overwrites that slot's existing entry rather than growing the metadata
arena. Allocate metadata in fixed mmap-backed chunks so cache allocation failure is reported
without throwing through `-fno-exceptions`.

```cpp
struct CachedInstruction {
    uint32_t opcode = 0;
    uint64_t read_gpr_mask = 0;
    uint64_t write_gpr_mask = 0;
    int32_t pc_relative_displacement = 0;
    InstructionFlags flags = InstructionFlags::None;
    char mnemonic[16]{};
    char operands[96]{};
    char disassembly[112]{};

    uintptr_t absolute_branch_target(uintptr_t pc) const;
};

struct InstructionView {
    uintptr_t address = 0;
    const CachedInstruction *decoded = nullptr;
};
```

Use multiplicative hashing and a power-of-two mask for `slot_index(opcode)`. Count hits, misses, and collisions without allocating on hits.

- [ ] **Step 4: Add post-rule capability metadata**

Add:

```cpp
virtual bool requires_immediate_post() const { return false; }
bool CodeRuleEngine::requires_immediate_post() const;
```

The engine returns true if any registered rule opts in. Existing rules remain pre-only. The
CodeRuleContext migration to `InstructionView` happens atomically with collector integration in
Task 6, so this task does not leave `qbdi_runner.cpp` between APIs.

- [ ] **Step 5: Run tests and Android build**

Run: `cmake --build build/tracer-native-tests && ctest --test-dir build/tracer-native-tests --output-on-failure`

Expected: cache tests pass.

Run: `./gradlew :tracer:assembleDebug`

Expected: `BUILD SUCCESSFUL`; the cache is compiled but not yet selected by the runner.

- [ ] **Step 6: Commit**

```bash
git add tracer/src/main/cpp/core/instruction_cache.* tracer/src/main/cpp/rules/code_rule.* tracer/src/test/cpp
git commit -m "feat: cache decoded arm64 instructions"
```

### Task 3: Fixed Trace Records and Allocation-Free Encoder

**Files:**
- Create: `tracer/src/main/cpp/events/trace_record.h`
- Create: `tracer/src/main/cpp/events/trace_metrics.h`
- Create: `tracer/src/main/cpp/events/trace_encoder.h`
- Create: `tracer/src/main/cpp/events/trace_encoder.cpp`
- Create: `tracer/src/test/cpp/trace_encoder_test.cpp`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Produces: fixed `InstructionRecord`, `MemoryRecord`, and `TraceMetrics` types.
- Produces: `TraceEncoder::encode_instruction`, `encode_begin`, `encode_end`, and `encode_event`.
- Consumes: `CachedInstruction` and `TraceContext`.

- [ ] **Step 1: Write failing exact-output and insufficient-buffer tests**

```cpp
#include "events/trace_encoder.h"
#include <cassert>
#include <cstring>
#include <string_view>

int main() {
    CachedInstruction decoded{};
    std::strcpy(decoded.mnemonic, "add");
    std::strcpy(decoded.operands, "x0, x1, x2");
    decoded.read_gpr_mask = (1ULL << 1) | (1ULL << 2);
    decoded.write_gpr_mask = 1ULL;

    InstructionRecord record{};
    record.sequence = 7;
    record.pc = 0x1010;
    record.module_base = 0x1000;
    record.decoded = &decoded;
    record.before[1] = 2;
    record.before[2] = 3;
    record.after[0] = 5;

    char output[256]{};
    TraceEncoder encoder;
    EncodeResult result = encoder.encode_instruction(output, sizeof(output), "libx.so", record);
    assert(result.ok);
    assert(std::string_view(output, result.size) ==
        "7 libx.so+0x10 add x0, x1, x2 | R:X1=0x2 X2=0x3 | W:X0=0x5\n");

    char tiny[8]{};
    assert(!encoder.encode_instruction(tiny, sizeof(tiny), "libx.so", record).ok);
}
```

- [ ] **Step 2: Run and verify the encoder test fails to compile**

Run: `cmake --build build/tracer-native-tests`

Expected: compilation fails because `trace_encoder.h` does not exist.

- [ ] **Step 3: Implement bounded record types and formatting primitives**

```cpp
constexpr size_t kTraceGprCount = 34;
constexpr size_t kMaxMemoryRecords = 8;
constexpr size_t kMaxHexdumpBytes = 64;
constexpr size_t kMaxInstructionLineBytes = 4096;

struct InstructionRecord {
    uint64_t sequence = 0;
    uintptr_t pc = 0;
    uintptr_t module_base = 0;
    const CachedInstruction *decoded = nullptr;
    std::array<uint64_t, kTraceGprCount> before{};
    std::array<uint64_t, kTraceGprCount> after{};
    std::array<MemoryRecord, kMaxMemoryRecords> memory{};
    uint8_t memory_count = 0;
};
```

Implement `append_char`, `append_literal`, `append_hex_u64`, and `append_dec_u64` against `{char *cursor, char *end}`. Return `{ok=false, size=required_or_zero}` on overflow and never write past `end`.

- [ ] **Step 4: Implement all text record encoders**

Use direct byte appends for instruction lines. Cold semantic events may accept `std::string_view`, but they must copy into the caller buffer without a stream. `encode_begin` writes `format=2`, profile, compression, and effective buffer capacity. `encode_end` writes target status, return value, elapsed time, instruction count, raw bytes, cache hit rate, and producer wait metrics known before final publish.

- [ ] **Step 5: Run tests under normal and sanitizer builds**

Run: `cmake --build build/tracer-native-tests && ctest --test-dir build/tracer-native-tests --output-on-failure`

Expected: exact-output and insufficient-buffer cases pass.

Run: `cmake -S tracer/src/test/cpp -B build/tracer-native-tests-asan -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' && cmake --build build/tracer-native-tests-asan && ctest --test-dir build/tracer-native-tests-asan --output-on-failure`

Expected: all tests pass with no sanitizer report.

- [ ] **Step 6: Commit**

```bash
git add tracer/src/main/cpp/events/trace_record.h tracer/src/main/cpp/events/trace_metrics.h tracer/src/main/cpp/events/trace_encoder.* tracer/src/test/cpp
git commit -m "feat: add allocation-free trace encoder"
```

### Task 4: LZ4 and Asynchronous Double-Buffer Writer

**Files:**
- Create: `tracer/src/main/cpp/third_party/lz4/LICENSE`
- Create: `tracer/src/main/cpp/third_party/lz4/VENDORED_REVISION.txt`
- Create: `tracer/src/main/cpp/third_party/lz4/lib/lz4.c`
- Create: `tracer/src/main/cpp/third_party/lz4/lib/lz4.h`
- Create: `tracer/src/main/cpp/third_party/lz4/lib/lz4frame.c`
- Create: `tracer/src/main/cpp/third_party/lz4/lib/lz4frame.h`
- Create: `tracer/src/main/cpp/third_party/lz4/lib/lz4hc.c`
- Create: `tracer/src/main/cpp/third_party/lz4/lib/lz4hc.h`
- Create: `tracer/src/main/cpp/third_party/lz4/lib/xxhash.c`
- Create: `tracer/src/main/cpp/third_party/lz4/lib/xxhash.h`
- Create: `tracer/src/main/cpp/events/async_trace_writer.h`
- Create: `tracer/src/main/cpp/events/async_trace_writer.cpp`
- Create: `tracer/src/test/cpp/async_trace_writer_test.cpp`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`

**Interfaces:**
- Produces: `AsyncTraceWriter::open`, `reserve`, `commit`, `append`, `finish`, and `failed`.
- Produces: `choose_trace_buffer_bytes(physical_bytes, requested_bytes, auto_size)`.
- Produces: injectable `TraceWriterBackend` and `TraceFaultInjector` seams used by failure tests.
- Consumes: `TraceOptions` and updates `TraceMetrics`.

- [ ] **Step 1: Vendor the pinned LZ4 library with provenance**

Copy the listed files from upstream tag `v1.10.0`. Set `VENDORED_REVISION.txt` to:

```text
Project: LZ4
Version: v1.10.0
Source: https://github.com/lz4/lz4/releases/tag/v1.10.0
License: BSD-2-Clause (library)
```

Build the library sources as a private static target named `lz4_static`; do not build or vendor the GPL CLI.

- [ ] **Step 2: Write failing buffer sizing, swap, concatenated-frame, and fault tests**

The test uses 4 KiB buffers, appends three distinguishable 10 KiB payloads, finishes, decodes every concatenated frame with `LZ4F_decompress`, and asserts byte-for-byte equality. Add assertions:

```cpp
assert(choose_trace_buffer_bytes(4ULL << 30, 0, true) == (64ULL << 20));
assert(choose_trace_buffer_bytes(8ULL << 30, 0, true) == (128ULL << 20));
assert(choose_trace_buffer_bytes(4ULL << 30, 32ULL << 20, false) == (32ULL << 20));
assert(metrics.buffer_swaps >= 2);
assert(metrics.compressed_bytes > 0);
```

Inject a backend that returns `-1` with `errno=ENOSPC`; assert `failed()` becomes true and a waiting producer is released.

- [ ] **Step 3: Run and verify tests fail because the writer is absent**

Run: `cmake -S tracer/src/test/cpp -B build/tracer-native-tests && cmake --build build/tracer-native-tests`

Expected: compilation fails because `async_trace_writer.h` does not exist.

- [ ] **Step 4: Implement the SPSC state machine and fallback allocation**

```cpp
enum class BufferState : uint8_t { Free, Filling, Ready, Writing };
struct WritableSpan { char *data; size_t capacity; };

class AsyncTraceWriter {
public:
    explicit AsyncTraceWriter(TraceWriterBackend *backend = nullptr,
                              TraceFaultInjector *faults = nullptr);
    bool open(const std::string &path, const TraceOptions &options, TraceMetrics *metrics);
    WritableSpan reserve(size_t minimum);
    void commit(size_t bytes);
    bool append(std::string_view bytes);
    bool finish();
    bool failed() const;
};
```

Allocate with `mmap(MAP_PRIVATE | MAP_ANONYMOUS)`. `buffer_bytes` always means one buffer's
capacity. Try per-buffer capacities in this order: selected value, 64 MiB, 32 MiB, then 8 MiB,
skipping duplicates; their total double-buffer capacities are selected x2, 128 MiB, 64 MiB, and
16 MiB. Use one mutex and two condition variables only at buffer publication/acquisition
boundaries; reserve/commit within the active buffer performs no lock. Start the consumer with
`pthread_create` so thread-start failure is returned rather than throwing through the project's
`-fno-exceptions` build.

- [ ] **Step 5: Compress each published span as one independent frame**

For each ready producer span, call `LZ4F_compressBegin`, feed it in 1 MiB chunks with `LZ4F_compressUpdate`, then call `LZ4F_compressEnd`. Reuse one bounded compressed-output scratch allocation. Write every produced chunk through retry-on-`EINTR` `write_all`.

On any LZ4 or write error, atomically store the error, transition both buffers to `Free`, notify all waiters, and reject later appends without blocking.

- [ ] **Step 6: Run native tests and Android build**

Run: `cmake --build build/tracer-native-tests && ctest --test-dir build/tracer-native-tests --output-on-failure`

Expected: sizing, swap, frame concatenation, and ENOSPC tests pass.

Run: `./gradlew :tracer:assembleDebug`

Expected: `BUILD SUCCESSFUL` and `libqbdi_tracer.so` links `lz4_static` privately.

- [ ] **Step 7: Commit**

```bash
git add tracer/src/main/cpp/third_party/lz4 tracer/src/main/cpp/events/async_trace_writer.* tracer/src/main/cpp/CMakeLists.txt tracer/src/test/cpp
git commit -m "feat: add asynchronous lz4 trace writer"
```

### Task 5: Integrate the Encoder and Writer Facade

**Files:**
- Create: `tracer/src/test/cpp/text_trace_writer_test.cpp`
- Modify: `tracer/src/main/cpp/events/text_trace_writer.h`
- Modify: `tracer/src/main/cpp/events/text_trace_writer.cpp`
- Modify: `tracer/src/main/cpp/events/trace_event.h`
- Modify: `tracer/src/main/cpp/core/logging.h`
- Modify: `tracer/src/main/cpp/handlers/call_handlers.cpp`
- Modify: `tracer/src/main/cpp/rules/code_rule_context.cpp`
- Modify: `tracer/src/main/cpp/core/qbdi_runner.cpp`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`

**Interfaces:**
- Produces: `TextTraceWriter` as the only facade used by runner, rules, and semantic handlers.
- Consumes: `TraceEncoder`, `AsyncTraceWriter`, `TraceOptions`, and `TraceMetrics`.

- [ ] **Step 1: Write a failing facade lifecycle test**

Open a temporary path with 4 KiB test buffers, call `begin`, `instruction`, `call`, `rule`, and `end`, then decode the LZ4 frames and assert ordered markers:

```cpp
assert(text.find("TRACE_BEGIN") < text.find("1 libdemo_target.so+0x10"));
assert(text.find("CALL libc.memcpy") < text.find("RULE force_tbnz"));
assert(text.find("RULE force_tbnz") < text.find("TRACE_END status=ok"));
assert(writer.close());
assert(writer.close());
```

- [ ] **Step 2: Run the test and confirm the old synchronous writer fails expectations**

Run: `cmake --build build/tracer-native-tests && ctest --test-dir build/tracer-native-tests -R text_trace_writer_test --output-on-failure`

Expected: the test fails because the current writer neither emits LZ4 nor supports the new options and idempotent close contract.

- [ ] **Step 3: Refactor TextTraceWriter into a compatibility facade**

Use this constructor and lifecycle:

```cpp
explicit TextTraceWriter(const TraceOptions &options, TraceMetrics *metrics);
bool open(const TraceContext &context);
bool instruction(const TraceContext &context, const InstructionRecord &record);
bool end(uint64_t retval, bool ok, long elapsed_ms);
bool close();
```

Keep `call`, `rule`, `error`, and `write_raw_line`, but route them through `TraceEncoder::encode_event` and `AsyncTraceWriter::append`. Remove every `ostringstream` from `text_trace_writer.cpp`.

In `logging.h`, keep Android logging unchanged unless `QTRACE_HOST_TEST` is defined. Under that
test-only definition, provide no-op `QTRACE_I/W/E` macros without including `<android/log.h>` so
the facade can be linked into the host CTest executable.

- [ ] **Step 4: Migrate all writer callers and file naming**

Construct the facade with `config.trace` and runner metrics. Change the successful compressed suffix to `.trace.txt.lz4`; uncompressed diagnostic mode remains `.trace.txt`. Semantic handlers continue passing cold-path strings, but no handler writes directly to a file descriptor.

- [ ] **Step 5: Write the `.metrics` sidecar after close**

After the consumer joins and the trace fd closes, write one line per metric using a small stack buffer and `open/write/close`. Required keys are `instructions`, `elapsed_ms`, `instructions_per_second`, `raw_bytes`, `compressed_bytes`, `compression_ratio`, `cache_hits`, `cache_misses`, `buffer_swaps`, `producer_waits`, and `producer_wait_ns`.

- [ ] **Step 6: Run tests and Android builds**

Run: `cmake --build build/tracer-native-tests && ctest --test-dir build/tracer-native-tests --output-on-failure`

Expected: all native tests pass.

Run: `./gradlew :tracer:assembleDebug :tracer:copyTracerDebug`

Expected: `BUILD SUCCESSFUL` and `out/arm64-v8a/libqbdi_tracer.so` exists.

- [ ] **Step 7: Commit**

```bash
git add tracer/src/main/cpp/events tracer/src/main/cpp/handlers/call_handlers.cpp tracer/src/main/cpp/rules/code_rule_context.cpp tracer/src/main/cpp/core/logging.h tracer/src/main/cpp/core/qbdi_runner.cpp tracer/src/main/cpp/CMakeLists.txt tracer/src/test/cpp
git commit -m "refactor: route traces through async encoder"
```

### Task 6: Delayed Single-PRE Instruction Collection

**Files:**
- Create: `tracer/src/main/cpp/core/instruction_collector.h`
- Create: `tracer/src/main/cpp/core/instruction_collector.cpp`
- Create: `tracer/src/main/cpp/core/pending_instruction.h`
- Create: `tracer/src/main/cpp/core/pending_instruction.cpp`
- Create: `tracer/src/test/cpp/instruction_collector_test.cpp`
- Modify: `tracer/src/main/cpp/core/qbdi_runner.cpp`
- Modify: `tracer/src/main/cpp/core/qbdi_runner.h`
- Modify: `tracer/src/main/cpp/rules/code_rule_context.h`
- Modify: `tracer/src/main/cpp/rules/code_rule_context.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Produces: QBDI-independent `PendingInstructionCollector::begin` and `finish_last`.
- Produces: QBDI adapter `InstructionCollector::on_pre`, `on_memory`, and `on_post`.
- Consumes: `InstructionCache`, `TextTraceWriter`, `CodeRuleEngine`, and QBDI register state.

- [ ] **Step 1: Write failing first/next/last and register-delta tests**

Drive the pending-state core with synthetic snapshots:

```cpp
PendingInstructionCollector collector(&sink);
collector.begin(view_add, snapshot({{1, 2}, {2, 3}}));
assert(sink.records.empty());
collector.begin(view_ret, snapshot({{0, 5}}));
assert(sink.records.size() == 1);
assert(sink.records[0].before[1] == 2);
assert(sink.records[0].after[0] == 5);
collector.finish_last(snapshot({{0, 9}}));
assert(sink.records.size() == 2);
assert(sink.records[1].after[0] == 9);
```

Add a branch test and assert sequence numbers are exactly `1, 2, 3`.

- [ ] **Step 2: Run the collector test and verify it fails to compile**

Run: `cmake --build build/tracer-native-tests`

Expected: compilation fails because `instruction_collector.h` does not exist.

- [ ] **Step 3: Implement pending instruction collection**

`PendingInstructionCollector` owns one fixed `InstructionRecord`; it stores no string, vector, or
QBDI type. At PRE N, it completes pending N-1 before accepting N. Copy only registers selected by
`read_gpr_mask` before N and only `write_gpr_mask` values while completing N-1. The host test links
only this pure state machine. `InstructionCollector` is the Android/QBDI adapter that produces
`InstructionView` and register snapshots for it.

Read the current opcode with `memcpy` from the valid instrumented PC. On a cache miss, call:

```cpp
vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION |
                    QBDI::ANALYSIS_DISASSEMBLY |
                    QBDI::ANALYSIS_OPERANDS);
```

Copy all required data into `CachedInstruction`; do not retain QBDI-owned pointers.

In the same change, migrate `CodeRuleContext` to:

```cpp
CodeRuleContext(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr,
                const InstructionView *instruction, const TraceContext *trace,
                TextTraceWriter *writer);
```

Implement `address`, `mnemonic`, `disassembly`, `is_call`, `is_branch`, and `is_return` from
`InstructionView::decoded`, so cache hits never need a QBDI-owned analysis pointer.

- [ ] **Step 4: Register one PRE callback in the normal path**

Remove the unconditional `POSTINST` callback. Register it only when
`CodeRuleEngine::requires_immediate_post()` is true. In the usual path, call CodeRule pre after
resolving `InstructionView`, then save the input registers after any CodeRule modification.

Do not call `recordMemoryAccess` or `addMemAccessCB` when `profile == fast`.

- [ ] **Step 5: Finish the pending instruction after `vm.call`**

Call `collector.finish_last(*gpr)` before `writer.end`. Verify the target return value is captured after the final instruction and is unchanged by logging.

- [ ] **Step 6: Run native tests and Android build**

Run: `cmake --build build/tracer-native-tests && ctest --test-dir build/tracer-native-tests --output-on-failure`

Expected: collector sequence, register, branch, and last-instruction tests pass.

Run: `./gradlew :tracer:assembleDebug :app:assembleDebug`

Expected: both modules build successfully.

- [ ] **Step 7: Commit**

```bash
git add tracer/src/main/cpp/core/instruction_collector.* tracer/src/main/cpp/core/pending_instruction.* tracer/src/main/cpp/core/qbdi_runner.* tracer/src/main/cpp/rules/code_rule_context.* tracer/src/main/cpp/CMakeLists.txt tracer/src/test/cpp
git commit -m "perf: collect instructions with one pre callback"
```

### Task 7: Balanced and Full Memory Profiles

**Files:**
- Create: `tracer/src/test/cpp/memory_profile_test.cpp`
- Modify: `tracer/src/main/cpp/core/instruction_cache.h`
- Modify: `tracer/src/main/cpp/core/instruction_cache.cpp`
- Modify: `tracer/src/main/cpp/core/instruction_collector.h`
- Modify: `tracer/src/main/cpp/core/instruction_collector.cpp`
- Modify: `tracer/src/main/cpp/core/qbdi_runner.cpp`
- Modify: `tracer/src/main/cpp/events/trace_encoder.cpp`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Produces: fixed `MemoryOperand` metadata and effective-address calculation.
- Extends: `InstructionCollector::on_memory` to attach QBDI accesses to the pending instruction.

- [ ] **Step 1: Write failing profile and effective-address tests**

Cover base + shifted index + displacement, writeback, unreadable bytes, and hexdump caps:

```cpp
MemoryOperand operand{};
operand.base_reg = 1;
operand.index_reg = 2;
operand.shift = 3;
operand.displacement = 0x20;
assert(operand.effective_address(snapshot({{1, 0x1000}, {2, 4}})) == 0x1040);

TraceOptions fast{};
assert(!fast.memory_enabled());
TraceOptions full{};
full.profile = TraceProfile::Full;
full.hexdump_limit = 16;
assert(full.memory_enabled() && full.hexdump_enabled());
```

- [ ] **Step 2: Run and verify the memory tests fail**

Run: `cmake --build build/tracer-native-tests`

Expected: compilation fails because cached memory operands and effective-address helpers are absent.

- [ ] **Step 3: Cache ARM64 memory operand formulas**

Store at most four architectural memory operand formulas per decoded instruction: base register, index register, extend/shift mode, shift amount, signed displacement, access type, and writeback flag. Reject an analysis result that exceeds the fixed bound by marking it `requires_slow_memory_path`; only memory-enabled profiles pay that fallback cost.

- [ ] **Step 4: Attach QBDI memory accesses in balanced mode**

Only for `balanced` and `full`, call `vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE)` and register `on_memory`. In the callback, call `getInstMemoryAccess`, match by `instAddress`, and copy type, flags, address, size, and value into the pending record. If QBDI returns more than eight accesses, encode continuation `MEM` records immediately rather than dropping them.

- [ ] **Step 5: Add bounded byte capture in full mode**

At PRE, compute candidate effective addresses from cached operands and use `safe_read_memory` to capture read bytes and pre-write bytes up to `min(access_size, hexdump_limit, 64)`. In `on_memory`, use the actual QBDI address to capture post-write bytes. Mark unsuccessful reads as unavailable; never dereference an unchecked address directly.

- [ ] **Step 6: Run tests and Android build**

Run: `cmake --build build/tracer-native-tests && ctest --test-dir build/tracer-native-tests --output-on-failure`

Expected: profile, address, cap, overflow continuation, and unavailable-memory cases pass.

Run: `./gradlew :tracer:assembleDebug`

Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 7: Commit**

```bash
git add tracer/src/main/cpp/core/instruction_cache.* tracer/src/main/cpp/core/instruction_collector.* tracer/src/main/cpp/core/qbdi_runner.cpp tracer/src/main/cpp/events/trace_encoder.cpp tracer/src/test/cpp
git commit -m "feat: add configurable memory trace profiles"
```

### Task 8: Native Fallback, Writer Failure, and Crash Safety

**Files:**
- Create: `tracer/src/main/cpp/core/native_fallback_arm64.h`
- Create: `tracer/src/main/cpp/core/native_fallback_arm64.S`
- Create: `tracer/src/test/cpp/failure_state_test.cpp`
- Modify: `tracer/src/main/cpp/tracer_entry.cpp`
- Modify: `tracer/src/main/cpp/core/qbdi_runner.h`
- Modify: `tracer/src/main/cpp/core/qbdi_runner.cpp`
- Modify: `tracer/src/main/cpp/events/async_trace_writer.h`
- Modify: `tracer/src/main/cpp/events/async_trace_writer.cpp`
- Modify: `tracer/src/main/cpp/events/text_trace_writer.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Produces: `call_target_arm64(uintptr_t, const uint64_t[8], uint64_t)`.
- Changes: `run_with_qbdi` returns a result carrying setup success separately from target return value.
- Produces: idempotent writer stop and async-signal-safe crash marker.

- [ ] **Step 1: Write failing state-machine fault tests**

Inject failures at allocation, thread creation, compression, first write, final write, and metrics-sidecar write. Assert every waiter is released, `finish()` is idempotent, and the first error code remains stable.

```cpp
FakeFaultInjector faults(FailurePoint::FirstWrite, ENOSPC);
AsyncTraceWriter writer(nullptr, &faults);
assert(writer.open(test_path, options, &metrics));
assert(writer.append("payload"));
assert(!writer.finish());
assert(!writer.finish());
assert(writer.error_code() == ENOSPC);
```

- [ ] **Step 2: Run and verify the new failure API is absent**

Run: `cmake --build build/tracer-native-tests`

Expected: compilation fails on `FailurePoint` and `error_code`.

- [ ] **Step 3: Add the arm64 native fallback bridge**

Expose:

```cpp
extern "C" uint64_t call_target_arm64(uintptr_t target,
                                      const uint64_t args[8],
                                      uint64_t indirect_result_x8);
```

The assembly saves frame pointer/link register, moves target and argument-array pointers to scratch registers, loads x0-x7, restores captured x8, executes `blr target`, restores the frame, and returns x0.

- [ ] **Step 4: Distinguish tracing setup failure from a legitimate zero return**

```cpp
struct TraceRunResult {
    bool target_executed = false;
    uint64_t value = 0;
};
```

If output, stack, VM, or writer-thread setup fails before `vm.call`, return `{false, 0}`. The already-unhooked proxy then calls `call_target_arm64`. If runtime logging fails after VM execution begins, stop recording, continue QBDI, and return `{true, real_value}`.

- [ ] **Step 5: Replace unsafe signal flushing**

Pre-open `<trace>.crash` and store its fd in runner state. The handler performs exactly one
fixed-size `write` of this binary record, clears the active fd, restores the previous signal
action, and re-raises:

```cpp
struct CrashMarker { uint32_t magic; int32_t signal; int32_t tid; };
```

It must not call `flush`, `close`, LZ4, a mutex, allocation, or logging macros. Successful normal
completion closes and unlinks the empty crash sidecar. Pull tooling treats only a valid nonempty
record as a crash.

- [ ] **Step 6: Add an Android device fallback check**

Add a test-only encoded option `test_fail_setup=1` guarded by `#ifndef NDEBUG`. Trigger the deterministic algorithm scene and verify its returned hash equals the untraced hash. Remove the option from release behavior by compile guard.

- [ ] **Step 7: Run tests and builds**

Run: `cmake --build build/tracer-native-tests && ctest --test-dir build/tracer-native-tests --output-on-failure`

Expected: all injected failure and idempotency cases pass.

Run: `./gradlew :tracer:assembleDebug :app:assembleDebug`

Expected: arm64 assembly links and both modules build.

- [ ] **Step 8: Commit**

```bash
git add tracer/src/main/cpp/core/native_fallback_arm64.* tracer/src/main/cpp/tracer_entry.cpp tracer/src/main/cpp/core/qbdi_runner.* tracer/src/main/cpp/events tracer/src/main/cpp/CMakeLists.txt tracer/src/test/cpp
git commit -m "fix: preserve target behavior on trace failures"
```

### Task 9: Final Device Benchmark and Metrics Comparison

**Files:**
- Modify: `scripts/benchmark_trace.py`
- Modify: `scripts/tests/test_benchmark_trace.py`
- Modify: `tracer/src/main/cpp/events/trace_metrics.h`
- Modify: `tracer/src/main/cpp/events/text_trace_writer.cpp`
- Modify: `docs/benchmarks/trace-throughput-baseline.md`

**Interfaces:**
- Extends: the Task 0 benchmark runner to consume `.metrics` sidecars.
- Produces: a baseline-versus-final comparison for `balanced` and final report for `fast`.

- [ ] **Step 1: Add failing optimized-metrics parser tests**

```python
from scripts.benchmark_trace import compare_to_baseline, parse_metrics

def test_metrics_and_speedup():
    current = parse_metrics(
        "instructions=100000\nelapsed_ms=50\nraw_bytes=10485760\n"
        "compressed_bytes=1048576\ncache_hits=90000\ncache_misses=10000\n"
        "producer_waits=0\nproducer_wait_ns=0\n")
    comparison = compare_to_baseline(current, {"elapsed_ms": 300})
    assert current["instructions_per_second"] == 2_000_000
    assert current["cache_hit_rate"] == 0.9
    assert comparison["speedup"] == 6.0
```

- [ ] **Step 2: Run and verify optimized metrics are unsupported**

Run: `python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v`

Expected: the new parser test fails because `.metrics` comparison is not implemented.

- [ ] **Step 3: Complete all required runtime metrics**

Ensure the sidecar contains:

```text
profile, instructions, elapsed_ms, instructions_per_second, raw_bytes,
compressed_bytes, raw_bytes_per_second, disk_bytes_per_second, compression_ratio,
cache_hits, cache_misses, cache_hit_rate, buffer_swaps, producer_waits,
producer_wait_ns, effective_buffer_bytes
```

Compute rates after the writer joins. Keep counter updates allocation-free and avoid clocks inside
the per-instruction callback except the existing invocation start/end timestamps.

- [ ] **Step 4: Extend benchmark reporting**

For optimized runs, pull and parse `.metrics` rather than scanning the decompressed trace. Keep one
warmup and five measured fresh-process runs and reject differing target returns. Report medians for
all fields, then compare `balanced` median elapsed time with the Task 0 baseline on the same device.

- [ ] **Step 5: Run unit tests and builds**

Run: `python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v`

Expected: legacy parsing, optimized parsing, median, missing-key, speedup, and return-mismatch tests
all pass.

Run: `./gradlew :app:assembleDebug :tracer:assembleDebug :tracer:copyTracerDebug`

Expected: all artifacts build.

- [ ] **Step 6: Run final device benchmarks**

Run: `python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid --profile fast --runs 5`

Expected: five valid runs, stable target return, continuous trace completion, and a median report.

Run: `python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid --profile balanced --runs 5 --compare docs/benchmarks/trace-throughput-baseline.md`

Expected: five valid runs and an explicit speedup ratio. Acceptance requires at least 5x for
`balanced`. `fast` should reach or approach 1,000,000 instructions/second; if it misses, the report
must identify cache misses, encoding throughput, or producer wait time as the dominant measured
cost before further tuning.

- [ ] **Step 7: Commit**

```bash
git add scripts/benchmark_trace.py scripts/tests/test_benchmark_trace.py tracer/src/main/cpp/events docs/benchmarks/trace-throughput-baseline.md
git commit -m "test: verify trace throughput gains"
```

### Task 10: Pull Tooling, Documentation, and Full Verification

**Files:**
- Create: `scripts/pull_trace.py`
- Create: `scripts/tests/test_pull_trace.py`
- Modify: `README.md`
- Modify: `docs/trace-format.md`
- Modify: `tracer/src/main/cpp/third_party/lz4/VENDORED_REVISION.txt`

**Interfaces:**
- Produces: `pull_trace.py` for `.lz4`, `.metrics`, and `.crash` artifacts.
- Documents: profiles, format version 2, performance metrics, decompression, and failure recovery.

- [ ] **Step 1: Write failing artifact-selection and status tests**

```python
from scripts.pull_trace import classify_artifacts

def test_classifies_complete_and_crashed_trace():
    marker = (0x51424352).to_bytes(4, "little") + (11).to_bytes(4, "little") + (1234).to_bytes(4, "little")
    artifacts = {
        "123_algorithm.trace.txt.lz4": b"",
        "123_algorithm.trace.txt.lz4.metrics": b"instructions=10\n",
        "456_algorithm.trace.txt.lz4": b"",
        "456_algorithm.trace.txt.lz4.crash": marker,
    }
    traces = classify_artifacts(artifacts)
    assert traces["123_algorithm.trace.txt.lz4"].status == "complete"
    assert traces["456_algorithm.trace.txt.lz4"].status == "crashed"
```

- [ ] **Step 2: Run and verify pull tooling tests fail**

Run: `python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v`

Expected: import fails because `scripts/pull_trace.py` does not exist.

- [ ] **Step 3: Implement safe pull and decompression**

Use `adb exec-out run-as <package>` to enumerate and stream selected files. Require the host `lz4`
CLI for automatic decompression and print its installation requirement when absent. Decode
concatenated frames in order. A trace is `crashed` only when its sidecar contains a valid
`CrashMarker`; an absent or empty marker is not a crash. If the CLI reports a truncated final frame
and a valid crash marker exists, retain decoded complete frames, mark output `.partial.trace.txt`,
and exit with a distinct nonzero status.

Never overwrite an existing local output unless `--force` is supplied. Support `--compressed-only` to skip decompression.

- [ ] **Step 4: Update trace format and usage documentation**

Document:

- `format=2` header fields and `fast`, `balanced`, `full` contents;
- `.trace.txt.lz4`, `.metrics`, and `.crash` naming;
- automatic and manual `lz4 -d` workflows;
- each metric and how to identify QBDI/encoding versus writer backpressure;
- buffer defaults and peak-memory implications;
- the fact that `O_DIRECT`, sampling, binary output, child-thread tracing, and anonymous-range discovery are not included.

- [ ] **Step 5: Run the complete verification suite**

Run: `cmake -S tracer/src/test/cpp -B build/tracer-native-tests && cmake --build build/tracer-native-tests && ctest --test-dir build/tracer-native-tests --output-on-failure`

Expected: all C++ tests pass.

Run: `python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v`

Expected: all Python tests pass.

Run: `./gradlew :app:assembleDebug :tracer:assembleDebug :tracer:copyTracerDebug`

Expected: `BUILD SUCCESSFUL` and both APK/native tracer artifacts exist.

Run: `git diff --check`

Expected: no output.

- [ ] **Step 6: Perform final device smoke tests**

Run one trace for each profile. For every run, verify stable target return, successful LZ4 decompression, continuous sequence numbers, `TRACE_BEGIN`, `TRACE_END`, matching `.metrics`, and no crash marker. Force 4 KiB test buffers in a debug build and verify multiple swaps without missing records. Force setup failure and verify native fallback returns the same benchmark hash.

- [ ] **Step 7: Commit**

```bash
git add scripts/pull_trace.py scripts/tests README.md docs/trace-format.md tracer/src/main/cpp/third_party/lz4/VENDORED_REVISION.txt
git commit -m "docs: add compressed trace workflow"
```
