# Structured Tracer Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace every semicolon-based tracer configuration path with one versioned JSON interface that accepts offset or IDA/Ghidra addresses and reports deferred hook outcomes to Frida.

**Architecture:** Keep `TraceConfig` as the normalized runtime data model. Put JSON parsing, generation retention, response serialization, and status transitions in a new deep `TracerConfiguration` module; let `tracer_entry.cpp` adapt its two exported C functions and hook lifecycle to that module. Keep mapping diagnostics pure and testable in `module_maps`, while the self-contained Frida agents remain thin ABI adapters.

**Tech Stack:** C++20, nlohmann/json 3.12.0, Android NDK, ShadowHook, Frida GumJS, CMake/CTest, Python 3 `unittest`.

**Approved Spec:** `docs/superpowers/specs/2026-08-25-structured-tracer-configuration-design.md`

## Global Constraints

- Preserve the exact user command `frida -U -f com.aprz.qbdiandroid -l scripts/spawn_trace.js`.
- `scripts/spawn_trace.js` is the only manually maintained normal tracing configuration; delete `scripts/trace_config.js`.
- Remove `qbdi_tracer_configure(const char *)`, `parse_trace_config()`, and every semicolon configuration producer. Do not retain a compatibility path.
- JSON request schema version is exactly `1`; response schema version is exactly `1`.
- JSON requests are 1 byte through 1 MiB, contain no embedded NUL, and contain at most 256 scenes.
- Addresses are hexadecimal strings. A location is exactly `offset` plus optional `endOffset`, or `imageBase + address` plus optional `endAddress`.
- Schema/type/arithmetic errors reject without mutating active state. Mapping and executable-segment anomalies warn and still attempt the hook.
- `flight.entryScene` replaces the implicit `scene.index == 0 && scene.name == "init"` rule.
- Keep QTRB, Flight Recorder, compression, and historical artifact formats unchanged.
- Keep default Python tests free of Node.js and device requirements. GumJS/device checks remain explicit opt-ins.
- Follow TDD for every behavior change: observe the named failure before implementation, then run the focused and affected suites.

## File Structure

- `tracer/src/main/cpp/core/trace_config.h`: normalized runtime structs and trace-profile helpers only.
- `tracer/src/main/cpp/core/trace_config.cpp`: normalized defaults and `trace_profile_name`; no wire parsing.
- `tracer/src/main/cpp/core/tracer_configuration.h`: small C++ interface for submit/status and internal lifecycle observations.
- `tracer/src/main/cpp/core/tracer_configuration.cpp`: JSON schema, typed conversion, generation retention, response serialization, and state machine.
- `tracer/src/main/cpp/core/module_maps.h/.cpp`: overflow-safe address calculation and mapping diagnostics.
- `tracer/src/main/cpp/tracer_entry.cpp`: C ABI adapter, module observation, batch install/rollback, and status transitions.
- `tracer/src/main/cpp/hooks/inline_hook_adapter.h/.cpp`: preserve the ShadowHook error code in `HookHandle`.
- `tracer/src/main/cpp/third_party/nlohmann/json.hpp`: pinned single-header JSON implementation.
- `tracer/src/main/cpp/third_party/nlohmann/LICENSE.MIT`: vendored dependency license.
- `tracer/src/test/cpp/tracer_configuration_test.cpp`: schema, ABI payload, generation, and status tests.
- `tracer/src/test/cpp/module_maps_test.cpp`: address warning classification tests.
- `tracer/src/test/cpp/tracer_entry_proxy_test.cpp`: batch hook, rollback, warning, and Flight entry-scene lifecycle tests.
- `scripts/spawn_trace.js`: sole normal configuration and Frida status client.
- `scripts/benchmark_trace.js`, `scripts/benchmark_trace.py`: benchmark JSON client and source configuration.
- `scripts/flight_acceptance.py`: generated Flight acceptance JSON client.
- `scripts/tests/test_spawn_trace_contract.py`: static single-source/protocol contracts.
- `scripts/tests/test_spawn_trace_gumjs.py`: opt-in pure GumJS adapter behavior.
- Existing benchmark, Flight acceptance, pull-trace, build-contract, README, and offset-guide files: migrated assertions and documentation.

---

### Task 1: Vendor JSON and parse the versioned schema

**Files:**
- Create: `tracer/src/main/cpp/third_party/nlohmann/json.hpp`
- Create: `tracer/src/main/cpp/third_party/nlohmann/LICENSE.MIT`
- Create: `tracer/src/main/cpp/core/tracer_configuration.h`
- Create: `tracer/src/main/cpp/core/tracer_configuration.cpp`
- Create: `tracer/src/test/cpp/tracer_configuration_test.cpp`
- Modify: `tracer/src/main/cpp/core/trace_config.h:1-54`
- Modify: `tracer/src/main/cpp/core/trace_config.cpp:1-230`
- Modify: `tracer/src/main/cpp/CMakeLists.txt:61-132`
- Modify: `tracer/src/test/cpp/CMakeLists.txt:9-29`

**Interfaces:**
- Consumes: existing `TraceConfig`, `SceneConfig`, `TraceOptions`, `FlightOptions`, and `trace_profile_name(TraceProfile)`.
- Produces: `PreparedConfiguration prepare_tracer_configuration(std::string_view request)` and `std::string serialize_configure_rejection(const ConfigurationIssue &issue)` for Task 2; normalized `FlightOptions::entry_scene` for Task 4.

- [ ] **Step 1: Vendor the pinned dependency and verify the official single-header checksum**

Run:

```bash
mkdir -p tracer/src/main/cpp/third_party/nlohmann
curl -fL https://github.com/nlohmann/json/releases/download/v3.12.0/json.hpp \
  -o tracer/src/main/cpp/third_party/nlohmann/json.hpp
curl -fL https://raw.githubusercontent.com/nlohmann/json/v3.12.0/LICENSE.MIT \
  -o tracer/src/main/cpp/third_party/nlohmann/LICENSE.MIT
printf '%s  %s\n' \
  aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63 \
  tracer/src/main/cpp/third_party/nlohmann/json.hpp | sha256sum -c -
```

Expected: `json.hpp: OK`. Version and checksum come from the official nlohmann/json 3.12.0 release.

- [ ] **Step 2: Write failing happy-path and locator tests**

Create the test harness with these exact first assertions:

```cpp
#include "core/tracer_configuration.h"

#include <cstdio>
#include <cstdlib>

static void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}
#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

int main() {
    const char request[] = R"json({
      "schemaVersion": 1,
      "packageName": "com.aprz.qbdiandroid",
      "targetModule": "libdemo_target.so",
      "trace": {
        "profile": "fast", "compression": true, "lz4Level": 2,
        "autoBuffer": true, "bufferMb": 0, "hexdumpLimit": 32
      },
      "flight": {
        "enabled": true, "entryScene": "init", "capacityMb": 512,
        "chunkKb": 256, "maxThreads": 256, "protectedChunks": 4
      },
      "scenes": [
        {"name": "init", "location": {"offset": "0x6ac90"}},
        {"name": "algorithm", "location": {
          "imageBase": "0x10000", "address": "0x7db38",
          "endAddress": "0x7dc00"
        }}
      ]
    })json";
    PreparedConfiguration prepared = prepare_tracer_configuration(request);
    CHECK(prepared.accepted());
    CHECK(prepared.config.scenes.size() == 2);
    CHECK(prepared.config.scenes[0].name == "init");
    CHECK(prepared.config.scenes[0].offset == 0x6ac90);
    CHECK(prepared.config.scenes[1].offset == 0x6db38);
    CHECK(prepared.config.scenes[1].end_offset == 0x6dc00);
    CHECK(prepared.config.flight.entry_scene == "init");
}
```

- [ ] **Step 3: Register and run the test to verify it fails**

Add this target alongside the old parser test until Task 2 switches the C ABI:

```cmake
add_trace_test(tracer_configuration_test
    tracer_configuration_test.cpp
    ../../main/cpp/core/trace_config.cpp
    ../../main/cpp/core/tracer_configuration.cpp)
```

Run:

```bash
./gradlew nativeHostTest --no-daemon
```

Expected: FAIL because `core/tracer_configuration.h` and the new parser do not exist yet.

- [ ] **Step 4: Define the normalized model and preparation result**

Move wire concerns out of `trace_config.*`, add `entry_scene`, and define:

```cpp
struct FlightOptions {
    bool enabled = false;
    std::string entry_scene;
    uint64_t capacity_bytes = 512ULL * 1024 * 1024;
    uint32_t chunk_bytes = 256U * 1024;
    uint32_t max_threads = 256;
    uint32_t protected_chunks = 4;
};

struct ConfigurationIssue {
    std::string code;
    std::string path;
    std::string message;
};

struct PreparedConfiguration {
    TraceConfig config;
    ConfigurationIssue error;
    bool accepted() const noexcept { return error.code.empty(); }
};

PreparedConfiguration prepare_tracer_configuration(std::string_view request);
std::string serialize_configure_rejection(const ConfigurationIssue &issue);
```

Keep `TraceConfig::valid`, `TraceConfig::error`, `parse_trace_config()`, and its old test temporarily so this task ends with a buildable tree. Task 2 removes them atomically with the old C ABI. The new JSON preparation path does not read or write those legacy validity fields.

- [ ] **Step 5: Implement strict schema parsing and normalization**

In `tracer_configuration.cpp`, use `nlohmann::json::parse(request.begin(), request.end())`, catch all JSON exceptions at this implementation edge, and apply these helpers:

```cpp
constexpr size_t kMaximumRequestBytes = 1024U * 1024U;
constexpr size_t kMaximumScenes = 256;

bool parse_hex_address(const std::string &text, uintptr_t *value) noexcept;
bool exact_keys(const nlohmann::json &object,
                std::initializer_list<std::string_view> allowed,
                ConfigurationIssue *issue, std::string_view path);
```

Reject every rule listed in Global Constraints with stable codes including `MALFORMED_JSON`, `INVALID_UTF8`, `UNKNOWN_FIELD`, `TYPE_MISMATCH`, `UNSUPPORTED_SCHEMA_VERSION`, `DUPLICATE_SCENE`, `INVALID_HEX_ADDRESS`, `CONFLICTING_LOCATION`, `ADDRESS_BELOW_IMAGE_BASE`, `ADDRESS_OVERFLOW`, `INVALID_RANGE`, and `INVALID_FLIGHT_ENTRY_SCENE`. Preserve Debug-only benchmark controls as the known optional root object below when `NDEBUG` is not defined; reject it in Release builds:

```json
"debug": {
  "bufferBytes": 4096,
  "failSetup": true
}
```

- [ ] **Step 6: Add table-driven rejection and boundary tests**

Add a helper and cases that assert both code and path:

```cpp
static void expect_rejection(std::string_view request,
                             const char *code, const char *path) {
    PreparedConfiguration prepared = prepare_tracer_configuration(request);
    CHECK(!prepared.accepted());
    CHECK(prepared.error.code == code);
    CHECK(prepared.error.path == path);
    CHECK(!prepared.error.message.empty());
}
```

Cover malformed JSON, embedded NUL, unknown fields at every object level, JSON numeric addresses, duplicate scene names, both locator forms, incomplete IDA form, `address < imageBase`, overflow, empty/reversed end range, 257 scenes, invalid trace/flight numeric bounds, and missing `entryScene`. Parse every rejection response with nlohmann/json and assert `responseSchemaVersion == 1`, `ok == false`, and the same error triplet.

- [ ] **Step 7: Run focused and affected native tests**

Run:

```bash
./gradlew nativeHostTest --no-daemon
```

Expected: all CTest targets pass, including both the temporary legacy `trace_config_test` and the new `tracer_configuration_test`.

- [ ] **Step 8: Commit**

```bash
git add tracer/src/main/cpp/third_party/nlohmann \
  tracer/src/main/cpp/core/trace_config.h \
  tracer/src/main/cpp/core/trace_config.cpp \
  tracer/src/main/cpp/core/tracer_configuration.h \
  tracer/src/main/cpp/core/tracer_configuration.cpp \
  tracer/src/main/cpp/CMakeLists.txt \
  tracer/src/test/cpp/CMakeLists.txt \
  tracer/src/test/cpp/tracer_configuration_test.cpp
git commit -m "feat(config): parse versioned JSON schema"
```

### Task 2: Add generation state and the JSON C ABI

**Files:**
- Modify: `tracer/src/main/cpp/core/tracer_configuration.h`
- Modify: `tracer/src/main/cpp/core/tracer_configuration.cpp`
- Modify: `tracer/src/main/cpp/tracer_entry.cpp:50-80,752-815`
- Modify: `tracer/src/main/cpp/core/trace_config.h`
- Modify: `tracer/src/main/cpp/core/trace_config.cpp`
- Modify: `tracer/src/test/cpp/tracer_configuration_test.cpp`
- Modify: `tracer/src/test/cpp/tracer_entry_proxy_test.cpp:27-50`
- Modify: `tracer/src/test/cpp/CMakeLists.txt:354-374`
- Delete: `tracer/src/test/cpp/trace_config_test.cpp`

**Interfaces:**
- Consumes: `PreparedConfiguration prepare_tracer_configuration(std::string_view)` from Task 1.
- Produces: `TracerConfiguration::configure`, `TracerConfiguration::status`, generation lifecycle observation methods, and the exact two exported functions used by Tasks 4-7.

- [ ] **Step 1: Write failing generation and buffer-transaction tests**

Add tests for this interface:

```cpp
enum class ConfigurationState {
    WaitingForModule,
    Installing,
    Installed,
    HookFailed,
    RollbackFailed,
    Superseded,
};

struct JsonCallResult {
    int32_t transport_code = 0;
    uint64_t required_size = 0;
    std::string payload;
};

class TracerConfiguration {
public:
    JsonCallResult configure(std::string_view request,
                             uint64_t response_capacity);
    JsonCallResult status(uint64_t generation,
                          uint64_t response_capacity) const;
    bool current(uint64_t *generation, TraceConfig *config) const;
    void mark_installing(uint64_t generation,
                         const ModuleRange &module,
                         std::vector<SceneConfigurationStatus> scenes);
    void finish_install(uint64_t generation,
                        ConfigurationState state,
                        std::vector<SceneConfigurationStatus> scenes);
};
```

Assert that capacity `1` returns `QTRACE_JSON_RESPONSE_TOO_SMALL`, reports a size including NUL, and leaves `current()` false. Retry with the reported size, assert generation `1`; submit invalid JSON and assert generation `1` remains current; submit a second valid document and assert generation `2` is current and generation `1` is `superseded`; submit a third and assert status lookup for generation `1` yields `GENERATION_NOT_FOUND`.

- [ ] **Step 2: Run the focused test to verify it fails**

Run:

```bash
cmake -S tracer/src/test/cpp -B build/native-tests
cmake --build build/native-tests --target tracer_configuration_test --parallel 2
ctest --test-dir build/native-tests -R '^tracer_configuration_test$' --output-on-failure
```

Expected: FAIL because generation/status methods and transport codes are undefined.

- [ ] **Step 3: Implement the bounded two-generation registry**

Add constants and status records:

```cpp
constexpr int32_t QTRACE_JSON_OK = 0;
constexpr int32_t QTRACE_JSON_RESPONSE_TOO_SMALL = 1;
constexpr int32_t QTRACE_JSON_INVALID_ARGUMENT = 2;

enum class SceneConfigurationState {
    Pending,
    Installing,
    Installed,
    HookFailed,
    RolledBack,
    RollbackFailed,
};

struct SceneConfigurationStatus {
    std::string name;
    uintptr_t offset = 0;
    uintptr_t runtime_address = 0;
    SceneConfigurationState state = SceneConfigurationState::Pending;
    std::vector<ConfigurationIssue> warnings;
    std::string error_code;
    int hook_error = 0;
};
```

Guard registry state with one mutex. Build the complete configure response before publishing. If `payload.size() + 1 > response_capacity`, return `QTRACE_JSON_RESPONSE_TOO_SMALL` without incrementing the generation. Retain only current and previous snapshots.

- [ ] **Step 4: Write failing C ABI tests**

Expose host-test declarations and add assertions that call:

```cpp
extern "C" int32_t qbdi_tracer_configure_json(
        const char *, uint64_t, char *, uint64_t, uint64_t *);
extern "C" int32_t qbdi_tracer_get_status_json(
        uint64_t, char *, uint64_t, uint64_t *);
```

Test null arguments, embedded NUL with explicit request size, insufficient response capacity with no state change, a successful response including NUL, and a status response for the returned generation. Add a source contract assertion that `qbdi_tracer_configure` no longer exists.

- [ ] **Step 5: Replace the old export with the C ABI adapter**

Use one process-lifetime `TracerConfiguration`. The adapter validates pointers and sizes, calls the module with `response_capacity`, copies only a complete payload, writes `response_size`, and returns the transport code. On accepted configuration, copy the current typed config into existing `g_config`, update `g_config_generation`, and continue existing hook initialization/module observation. Remove the old export, `parse_trace_config`, legacy validity fields, old parser test, and old CMake test target in this same step.

- [ ] **Step 6: Run focused and full native tests**

Run:

```bash
cmake --build build/native-tests --target tracer_configuration_test tracer_entry_proxy_test --parallel 2
ctest --test-dir build/native-tests -R '^(tracer_configuration_test|tracer_entry_proxy_test)$' --output-on-failure
./gradlew nativeHostTest --no-daemon
```

Expected: both focused targets and the complete CTest suite pass.

- [ ] **Step 7: Commit**

```bash
git add tracer/src/main/cpp/core/tracer_configuration.h \
  tracer/src/main/cpp/core/tracer_configuration.cpp \
  tracer/src/main/cpp/core/trace_config.h \
  tracer/src/main/cpp/core/trace_config.cpp \
  tracer/src/main/cpp/tracer_entry.cpp \
  tracer/src/test/cpp/tracer_configuration_test.cpp \
  tracer/src/test/cpp/tracer_entry_proxy_test.cpp \
  tracer/src/test/cpp/trace_config_test.cpp \
  tracer/src/test/cpp/CMakeLists.txt
git commit -m "feat(config): expose JSON status ABI"
```

### Task 3: Diagnose suspicious runtime addresses without blocking hooks

**Files:**
- Modify: `tracer/src/main/cpp/core/module_maps.h`
- Modify: `tracer/src/main/cpp/core/module_maps.cpp`
- Create: `tracer/src/test/cpp/module_maps_test.cpp`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`
- Modify: `tracer/src/main/cpp/core/tracer_configuration.h`
- Modify: `tracer/src/main/cpp/core/tracer_configuration.cpp`

**Interfaces:**
- Consumes: normalized `SceneConfig` from Task 1.
- Produces: `diagnose_scene_address(const ModuleRange &, const std::vector<ModuleRange> &, const SceneConfig &)` and overflow-safe runtime addresses for Task 4.

- [ ] **Step 1: Write failing pure mapping-diagnostic tests**

Define the expected interface in the test:

```cpp
struct SceneAddressDiagnostics {
    bool valid = false;
    uintptr_t runtime_address = 0;
    uintptr_t runtime_end = 0;
    std::vector<AddressDiagnostic> warnings;
    AddressDiagnostic error;
};

SceneAddressDiagnostics diagnose_scene_address(
        const ModuleRange &module,
        const std::vector<ModuleRange> &process_maps,
        const SceneConfig &scene);
```

Create cases for: in-module executable address with no warning; in-module non-executable address with `ADDRESS_NOT_EXECUTABLE`; outside-module executable anonymous mapping with `ADDRESS_OUTSIDE_TARGET_MODULE` and `ADDRESS_IN_RUNTIME_MAPPING`; unmapped address with both outside/not-executable warnings; end range outside the executable range; and `module.start + offset` overflow as hard `ADDRESS_OVERFLOW`.

- [ ] **Step 2: Run the focused test to verify it fails**

Register:

```cmake
add_trace_test(module_maps_test
    module_maps_test.cpp
    ../../main/cpp/core/module_maps.cpp)
```

Run:

```bash
cmake -S tracer/src/test/cpp -B build/native-tests
cmake --build build/native-tests --target module_maps_test --parallel 2
```

Expected: FAIL because `SceneAddressDiagnostics` and `diagnose_scene_address` do not exist.

- [ ] **Step 3: Implement checked addition and warning classification**

Keep `module_offset_address()` unchanged for callers that require strict module containment. Add a separate checked-add path:

```cpp
bool checked_offset_address(uintptr_t base, uintptr_t offset,
                            uintptr_t *address) noexcept {
    if (address == nullptr || offset > UINTPTR_MAX - base) return false;
    *address = base + offset;
    return true;
}
```

Classify containment against `module.start/end`, executability against all process-map executable ranges, and anonymous/runtime-generated mappings by an empty path or a path different from the target module. Return warnings in deterministic code order so JSON and tests are stable.

Define `AddressDiagnostic` in `module_maps.h` with only `std::string code` and `std::string message`. `TracerConfiguration::mark_installing` converts it to `ConfigurationIssue` and supplies the scene JSON path; this keeps `module_maps` independent of the configuration module and avoids a header cycle.

- [ ] **Step 4: Serialize diagnostics into scene status**

Add `TracerConfiguration::mark_installing` coverage that serializes normalized offset, runtime address, optional runtime end, and every warning. Assert warnings do not change the generation-level state from `installing` or `installed`.

- [ ] **Step 5: Run focused and full native tests**

Run:

```bash
cmake --build build/native-tests --target module_maps_test tracer_configuration_test --parallel 2
ctest --test-dir build/native-tests -R '^(module_maps_test|tracer_configuration_test)$' --output-on-failure
./gradlew nativeHostTest --no-daemon
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add tracer/src/main/cpp/core/module_maps.h \
  tracer/src/main/cpp/core/module_maps.cpp \
  tracer/src/main/cpp/core/tracer_configuration.h \
  tracer/src/main/cpp/core/tracer_configuration.cpp \
  tracer/src/test/cpp/module_maps_test.cpp \
  tracer/src/test/cpp/tracer_configuration_test.cpp \
  tracer/src/test/cpp/CMakeLists.txt
git commit -m "feat(config): warn on suspicious addresses"
```

### Task 4: Report batch hook installation and rollback

**Files:**
- Modify: `tracer/src/main/cpp/tracer_entry.cpp:448-593,715-815`
- Modify: `tracer/src/main/cpp/hooks/inline_hook_adapter.h:14-34`
- Modify: `tracer/src/main/cpp/hooks/inline_hook_adapter.cpp:12-95`
- Modify: `tracer/src/main/cpp/core/capture_coordinator.cpp:450-500`
- Modify: `tracer/src/test/cpp/tracer_entry_proxy_test.cpp`
- Modify: `tracer/src/test/cpp/capture_coordinator_test.cpp`

**Interfaces:**
- Consumes: `diagnose_scene_address`, `TracerConfiguration::mark_installing`, and `finish_install` from Tasks 2-3.
- Produces: terminal generation and scene states consumed by the Frida clients in Tasks 5-7.

- [ ] **Step 1: Write failing warning-plus-hook and batch rollback tests**

Replace `scene_offsets_must_stay_inside_the_normalized_module()` with tests that assert an outside scene reaches the fake `hook_function_address`, carries `ADDRESS_OUTSIDE_TARGET_MODULE`, and can finish `installed`. Add a two-scene test where the second fake hook fails and assert:

```cpp
CHECK(snapshot.state == ConfigurationState::HookFailed);
CHECK(snapshot.scenes[0].state == SceneConfigurationState::RolledBack);
CHECK(snapshot.scenes[1].state == SceneConfigurationState::HookFailed);
CHECK(g_unhook_calls == 1);
```

Add a rollback-failure variant with `g_fail_unhook = true` and assert generation `RollbackFailed`, first scene `RollbackFailed`, and a retained residual hook.

- [ ] **Step 2: Write failing explicit Flight entry-scene tests**

Build a Flight configuration whose scene order is `worker`, then `boot`, set `config.flight.entry_scene = "boot"`, and assert coordinator startup uses `boot`. Add rejection coverage for a missing entry scene in `tracer_configuration_test`.

- [ ] **Step 3: Run focused tests to verify they fail**

Run:

```bash
cmake --build build/native-tests --target tracer_entry_proxy_test capture_coordinator_test --parallel 2
ctest --test-dir build/native-tests -R '^(tracer_entry_proxy_test|capture_coordinator_test)$' --output-on-failure
```

Expected: FAIL because outside addresses are rejected, batch rollback/status is absent, and Flight still looks for index-zero `init`.

- [ ] **Step 4: Preserve ShadowHook diagnostics**

Add these fields to `HookHandle`, reset them before each attempt, and populate them on hook/unhook errors:

```cpp
int hook_error = 0;
int unhook_error = 0;
```

Use stable tracer codes `HOOK_INSTALL_FAILED`, `HOOK_INSTALL_RESIDUAL`, and `HOOK_ROLLBACK_FAILED`; include ShadowHook's integer errno in `SceneConfigurationStatus::hook_error`.

- [ ] **Step 5: Implement batch diagnostics, installation, and reverse rollback**

In `install_hooks_for_module`:

1. Read process maps once.
2. Diagnose every scene and call `mark_installing` with the full scene vector.
3. Attempt scenes in array order using the overflow-safe runtime address even when warnings exist.
4. Stop on the first hook failure.
5. Unhook successful members of this batch in reverse order.
6. Report `HookFailed` only after complete cleanup; otherwise report `RollbackFailed` with residual-scene details.
7. Report `Installed` only after every hook succeeds.

Replace the strict `module_offset_address` checks for scene start, optional end, and previous target comparison inside the hook-install path with checked base-plus-offset arithmetic. Diagnostics report mapping anomalies; only arithmetic overflow stops the attempt. Continue to reject zero offsets because ShadowHook cannot treat module base as an implicit missing value; report `ZERO_SCENE_OFFSET` as hook failure, not as a schema error.

Give hook initialization, callback registration, coordinator allocation/start, module observation, install, and rollback failures stable codes. Every Native log line for those outcomes includes `generation=<n>` and the same code serialized by `qbdi_tracer_get_status_json`.

- [ ] **Step 6: Replace the implicit Flight lookup**

Replace the `index == 0 && name == "init"` scan with an exact lookup of `config.flight.entry_scene`. Pass the selected `SceneConfig` into coordinator startup and update retained-config comparisons so scene order no longer carries Flight meaning.

- [ ] **Step 7: Run focused, full native, and build-contract tests**

Run:

```bash
cmake --build build/native-tests --target tracer_entry_proxy_test capture_coordinator_test tracer_configuration_test --parallel 2
ctest --test-dir build/native-tests -R '^(tracer_entry_proxy_test|capture_coordinator_test|tracer_configuration_test)$' --output-on-failure
./gradlew nativeHostTest --no-daemon
ANDROID_HOME="${ANDROID_HOME}" python3 -m unittest scripts.tests.build_contract_integration -v
```

Expected: all commands exit 0. The integration test may be skipped only if `ANDROID_HOME` is genuinely unavailable; record that limitation in the execution report instead of claiming it passed.

- [ ] **Step 8: Commit**

```bash
git add tracer/src/main/cpp/tracer_entry.cpp \
  tracer/src/main/cpp/hooks/inline_hook_adapter.h \
  tracer/src/main/cpp/hooks/inline_hook_adapter.cpp \
  tracer/src/main/cpp/core/capture_coordinator.cpp \
  tracer/src/test/cpp/tracer_entry_proxy_test.cpp \
  tracer/src/test/cpp/capture_coordinator_test.cpp
git commit -m "feat(config): report hook batch outcomes"
```

### Task 5: Make `spawn_trace.js` the single interactive configuration

**Files:**
- Modify: `scripts/spawn_trace.js:1-140`
- Delete: `scripts/trace_config.js`
- Create: `scripts/tests/test_spawn_trace_contract.py`
- Create: `scripts/tests/test_spawn_trace_gumjs.py`
- Modify: `scripts/tests/test_pull_trace.py:563-611`
- Modify: `scripts/tests/test_shadowhook_companion.py`

**Interfaces:**
- Consumes: `qbdi_tracer_configure_json` and `qbdi_tracer_get_status_json` from Task 2, including transport codes and response schema.
- Produces: the sole normal configuration and console workflow documented in Task 8.

- [ ] **Step 1: Write failing single-source contract tests**

Create Python assertions that:

```python
root = Path(__file__).resolve().parents[2]
source = (root / "scripts/spawn_trace.js").read_text(encoding="utf-8")
self.assertFalse((root / "scripts/trace_config.js").exists())
self.assertIn("JSON.stringify(config.tracer)", source)
self.assertIn("qbdi_tracer_configure_json", source)
self.assertIn("qbdi_tracer_get_status_json", source)
self.assertNotIn("function encodeConfig", source)
self.assertNotIn("scene=", source)
```

Update the pull-trace test that compared two configuration files to assert the demo scene names and values only in `spawn_trace.js`.

- [ ] **Step 2: Run the contract tests to verify they fail**

Run:

```bash
python3 -m unittest scripts.tests.test_spawn_trace_contract \
  scripts.tests.test_pull_trace scripts.tests.test_shadowhook_companion -v
```

Expected: FAIL because `trace_config.js` exists and `spawn_trace.js` uses the old encoder/export.

- [ ] **Step 3: Replace the top-level configuration and ABI client**

Use the exact `loader`/`tracer` shape from the approved spec. Implement UTF-8 byte sizing without relying on JavaScript `Number` for addresses:

```javascript
function utf8ByteLength(value) {
  let bytes = 0;
  for (const character of value) {
    const point = character.codePointAt(0);
    if (point <= 0x7f) bytes += 1;
    else if (point <= 0x7ff) bytes += 2;
    else if (point <= 0xffff) bytes += 3;
    else bytes += 4;
  }
  return bytes;
}
```

Create `NativeFunction` values with return type `int32` and argument types `['pointer', 'uint64', 'pointer', 'uint64', 'pointer']` for configure and `['uint64', 'pointer', 'uint64', 'pointer']` for status. Start with a 16 KiB response allocation, retry `RESPONSE_TOO_SMALL` with the returned `UInt64.toNumber()`, and refuse sizes above 1 MiB.

- [ ] **Step 4: Implement status polling and stable console rendering**

Factor pure helpers `callJsonAbi`, `renderConfigureResponse`, `renderStatusResponse`, and `pollGeneration(getStatus, schedule, emit)`. Suppress byte-identical unchanged status payloads, print `waiting_for_module` once, render every warning with `[!]`, and stop on `installed`, `hook_failed`, `rollback_failed`, or `superseded`. Guard startup with:

```javascript
if (globalThis.__QTRACE_TEST__ !== true) {
  setImmediate(main);
}
```

This keeps the direct Frida command unchanged while allowing the opt-in GumJS test to load the same file without calling Android-specific `main()`.

- [ ] **Step 5: Add the opt-in GumJS test**

In `test_spawn_trace_gumjs.py`, skip unless `QTRACE_RUN_FRIDA_HOST_TESTS=1`. Attach Frida to the test process, prepend `globalThis.__QTRACE_TEST__ = true;`, append `rpc.exports` wrappers around the pure helpers, and assert: multibyte UTF-8 sizing; one response-too-small retry; unchanged status suppression; warning rendering; and terminal polling stop. Use fake JS call/scheduler functions so no Android module is loaded.

- [ ] **Step 6: Run script tests**

Run:

```bash
python3 -m unittest scripts.tests.test_spawn_trace_contract \
  scripts.tests.test_pull_trace scripts.tests.test_shadowhook_companion -v
QTRACE_RUN_FRIDA_HOST_TESTS=1 \
  python3 -m unittest scripts.tests.test_spawn_trace_gumjs -v
```

Expected: default contract tests pass. The GumJS test passes when the existing Frida Python package supports local attach; otherwise report the exact environment error and keep it opt-in.

- [ ] **Step 7: Commit**

```bash
git add scripts/spawn_trace.js scripts/trace_config.js \
  scripts/tests/test_spawn_trace_contract.py \
  scripts/tests/test_spawn_trace_gumjs.py \
  scripts/tests/test_pull_trace.py \
  scripts/tests/test_shadowhook_companion.py
git commit -m "feat(frida): use structured tracer config"
```

### Task 6: Migrate the benchmark agent to JSON

**Files:**
- Modify: `scripts/benchmark_trace.js:1-75`
- Modify: `scripts/benchmark_trace.py:420-464`
- Modify: `scripts/tests/test_benchmark_trace.py:680-740`

**Interfaces:**
- Consumes: JSON request schema and `qbdi_tracer_configure_json` from Tasks 1-2.
- Produces: benchmark agent source with the existing profile/compression/test injection behaviour but no legacy configuration fragments.

- [ ] **Step 1: Write failing JSON-generation tests**

Add `benchmark_agent_request(profile, legacy, test_buffer_bytes, test_fail_setup) -> dict[str, object]` in `benchmark_trace.py`. Test that returned dictionary directly:

```python
self.assertEqual(1, request["schemaVersion"])
self.assertEqual("balanced", request["trace"]["profile"])
self.assertTrue(request["trace"]["compression"])
self.assertEqual("benchmark", request["scenes"][0]["name"])
self.assertEqual("0x0", request["scenes"][0]["location"]["offset"])
self.assertEqual(4096, request["debug"]["bufferBytes"])
self.assertTrue(request["debug"]["failSetup"])
```

Also assert generated source contains neither `scene=` nor `__QTRACE_TEST_CONFIG__`.

- [ ] **Step 2: Run focused tests to verify they fail**

Run:

```bash
python3 -m unittest scripts.tests.test_benchmark_trace -v
```

Expected: FAIL because the benchmark agent still builds a semicolon string.

- [ ] **Step 3: Generate a JSON-safe benchmark configuration**

Change `configure_agent_source` to call `benchmark_agent_request(profile, legacy, test_buffer_bytes, test_fail_setup)` and replace one `__QTRACE_CONFIG_JSON__` placeholder with `json.dumps(request, separators=(",", ":"), sort_keys=True)`. Do not perform string replacement inside a JSON string.

In GumJS, parse the injected JSON object, set the runtime-resolved benchmark offset as:

```javascript
request.scenes[0].location.offset = '0x' + offset.toString(16);
const encoded = JSON.stringify(request);
```

Call the new configure export with a fixed 64 KiB response buffer and treat transport errors or `response.ok !== true` as `benchmark-error` before installing/calling the benchmark target.

- [ ] **Step 4: Run focused benchmark tests**

Run:

```bash
python3 -m unittest scripts.tests.test_benchmark_trace -v
```

Expected: all benchmark unit tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/benchmark_trace.js scripts/benchmark_trace.py \
  scripts/tests/test_benchmark_trace.py
git commit -m "refactor(benchmark): submit JSON config"
```

### Task 7: Migrate Flight Recorder acceptance to JSON

**Files:**
- Modify: `scripts/flight_acceptance.py:220-265`
- Modify: `scripts/tests/test_flight_acceptance.py:120-155`
- Modify: `scripts/tests/test_flight_acceptance.py` for configure-response failures

**Interfaces:**
- Consumes: JSON request schema, explicit `flight.entryScene`, and configure ABI from Tasks 1-2.
- Produces: self-contained Flight acceptance agent with exactly one configured entry scene.

- [ ] **Step 1: Write failing generated-agent assertions**

Add `flight_agent_request(scene_offsets, flight_options) -> dict[str, object]` and test its returned dictionary directly. Assert:

```python
self.assertEqual(1, request["schemaVersion"])
self.assertEqual("init", request["flight"]["entryScene"])
self.assertEqual(["init"], [scene["name"] for scene in request["scenes"]])
self.assertEqual("0x100", request["scenes"][0]["location"]["offset"])
self.assertEqual("full", request["trace"]["profile"])
self.assertFalse(request["trace"]["compression"])
```

Assert the source has no `scenes=replace`, `scene=`, or `qbdi_tracer_configure` legacy symbol.

- [ ] **Step 2: Run the focused test to verify it fails**

Run:

```bash
python3 -m unittest scripts.tests.test_flight_acceptance -v
```

Expected: FAIL on the old semicolon source.

- [ ] **Step 3: Generate and submit the Flight JSON request**

Construct the request through `flight_agent_request(scene_offsets, flight_options)`, serialize with `json.dumps(request, separators=(",", ":"), sort_keys=True)`, embed it as a JavaScript object literal, and call `qbdi_tracer_configure_json` with a 64 KiB response. Include the parsed configure response in the existing `flight-agent-ready` message and emit `flight-agent-error` without invoking install when configuration is rejected.

- [ ] **Step 4: Run focused and complete Python tests**

Run:

```bash
python3 -m unittest scripts.tests.test_flight_acceptance -v
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

Expected: all Python tests pass; the old semicolon rejection contract remains covered by native tests.

- [ ] **Step 5: Commit**

```bash
git add scripts/flight_acceptance.py scripts/tests/test_flight_acceptance.py
git commit -m "refactor(flight): submit JSON config"
```

### Task 8: Update documentation and verify the complete migration

**Files:**
- Modify: `README.md:34-305`
- Modify: `docs/ida-offsets.md`
- Modify: `docs/trace-format.md` only where it names the control-plane protocol
- Modify: `scripts/tests/build_contract_integration.py`
- Test: every native and Python suite listed below

**Interfaces:**
- Consumes: completed Native/Frida/Python migration from Tasks 1-7.
- Produces: user documentation, repository-wide no-legacy contract, and final verification evidence.

- [ ] **Step 1: Write a failing repository-wide legacy-protocol contract**

Add a build-contract test that scans production sources, excluding committed historical specs/plans, and fails on:

```python
forbidden = (
    "qbdi_tracer_configure(",
    "parse_trace_config(",
    "scenes=replace",
    "scene=",
)
```

Explicitly allow trace output text such as `TRACE_BEGIN scene=` in converter/tests; scope the scan to `tracer/src/main/cpp` configuration sources and the three Frida agent producers.

- [ ] **Step 2: Run the contract to verify it fails before documentation cleanup**

Run:

```bash
python3 -m unittest scripts.tests.build_contract_integration -v
```

Expected: FAIL if any production legacy producer/export/parser remains.

- [ ] **Step 3: Update the user workflow documentation**

Document:

- the unchanged Frida command;
- `spawn_trace.js` as the only configuration source;
- complete `loader` and `tracer` examples;
- both `offset` and `imageBase + address` locator forms;
- hexadecimal-string and exclusive-end rules;
- strict schema failures versus packed-library mapping warnings;
- `flight.entryScene`;
- configure/status console states and stable error codes;
- the nlohmann/json 3.12.0 vendored license location;
- opt-in GumJS and device acceptance commands.

Remove every instruction to synchronize `trace_config.js` and `spawn_trace.js`.

- [ ] **Step 4: Run formatting and legacy scans**

Run:

```bash
git diff --check
rg -n "scripts/trace_config\.js|scenes=replace|parse_trace_config|qbdi_tracer_configure\(" \
  README.md docs/ida-offsets.md docs/trace-format.md scripts tracer/src/main/cpp \
  -g '!docs/superpowers/specs/**' -g '!docs/superpowers/plans/**'
```

Expected: `git diff --check` exits 0. The `rg` command finds no production/documentation legacy references; test fixtures that deliberately assert rejection may remain only in test files.

- [ ] **Step 5: Run the complete host verification**

Run:

```bash
./gradlew nativeHostTest --no-daemon
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
ANDROID_HOME="${ANDROID_HOME}" \
  python3 -m unittest scripts.tests.build_contract_integration -v
./gradlew :app:assembleDebug :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon
```

Expected: every available command exits 0. If Android SDK prerequisites are unavailable, report the exact skipped integration/build commands; do not substitute partial checks for them.

- [ ] **Step 6: Run opt-in adapter and device acceptance**

Run the host adapter:

```bash
QTRACE_RUN_FRIDA_HOST_TESTS=1 \
  python3 -m unittest scripts.tests.test_spawn_trace_gumjs -v
```

Then follow the README to deploy the Debug APK/tracer and verify on one arm64 device:

```bash
frida -U -f com.aprz.qbdiandroid -l scripts/spawn_trace.js
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --output pulled-traces
```

Perform four runs: offset locator, equivalent IDA locator, suspicious-address warning, and invalid-JSON-after-valid configuration. Record the generation/error codes from Frida and Logcat and confirm equivalent locators report the same runtime address.

- [ ] **Step 7: Review the final diff against every acceptance criterion**

Run:

```bash
git diff --stat 3506896..HEAD
git diff --name-status 3506896..HEAD
git status --short
```

Check each acceptance criterion in the approved spec against a named test or captured device result. Resolve every unexplained file and unverified criterion before the final commit.

- [ ] **Step 8: Commit**

```bash
git add README.md docs/ida-offsets.md docs/trace-format.md \
  scripts/tests/build_contract_integration.py
git commit -m "docs: document structured tracer config"
```

## Completion Gate

Before claiming completion, rerun the full commands from Task 8 Step 5 on the final tree, inspect their exit codes and failure counts, and report device/GumJS opt-in results separately from default-suite results. Confirm `git diff --check` and the scoped legacy scan on the final commit. Do not claim Android/device coverage when those prerequisites were unavailable.
