# Code Quality Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the audited JNI lifetime, unsafe-memory and concurrency defects, make Native Host tests directly runnable through Gradle, align scene configuration, and harden Release builds.

**Architecture:** Move JNI function metadata ownership into a small registry whose storage outlives its address index, and publish it once with `std::call_once`. Return copied values from `JniState`; funnel all C-string inspection through `safe_read_memory`; never treat opaque JNI references as character pointers. Add focused CTest and Python contract coverage around each boundary.

**Tech Stack:** C++20, Android NDK, CMake 3.22.1, CTest, Gradle/Groovy, Python 3 `unittest`, Frida JavaScript configuration.

## Global Constraints

- Keep Debug builds injectable with `debuggable true` and `jniDebuggable true`.
- Set the application Release build to `debuggable false`.
- Do not interpret `jstring` or any other JNI reference as a raw string address.
- `GetStringUTFChars` may be read as a bounded C string; UTF-16 APIs must not be labeled UTF-8.
- JNI lookup hot paths are read-only after one-time publication.
- Do not change QBDI execution, binary trace format, or flight recorder behavior.
- If the full Android APK build stalls again at Kotlin compilation, report it as unconfirmed.

---

## File Map

- `tracer/src/main/cpp/core/safe_memory.{h,cpp}`: bounded, fault-safe C-string copying.
- `tracer/src/main/cpp/jni/jni_state.{h,cpp}`: synchronized JNI metadata with value-returning queries.
- `tracer/src/main/cpp/jni/jni_function_registry.{h,cpp}`: owns the JNI metadata table and address index.
- `tracer/src/main/cpp/jni/jni_formatter.cpp`: consumes copied state and safe strings only.
- `tracer/src/main/cpp/handlers/call_handlers.cpp`: resolves and publishes the registry once.
- `tracer/src/test/cpp/*_test.cpp`: host regression tests for the three C++ boundaries.
- `tracer/src/test/cpp/CMakeLists.txt`: registers the new CTest executables.
- `scripts/tests/test_pull_trace.py`: shared scene-offset contract.
- `scripts/trace_config.js`: canonical demo integrity offset.
- `app/build.gradle`: Release security flag.
- `build.gradle`: root `nativeHostTest` task chain.
- `README.md`: verification command documentation.

### Task 1: Fault-safe C-string copying and JNI formatting

**Files:**
- Modify: `tracer/src/main/cpp/core/safe_memory.h`
- Modify: `tracer/src/main/cpp/core/safe_memory.cpp`
- Modify: `tracer/src/main/cpp/jni/jni_function_table.h`
- Modify: `tracer/src/main/cpp/jni/jni_formatter.cpp`
- Create: `tracer/src/test/cpp/safe_memory_string_test.cpp`
- Create: `tracer/src/test/cpp/jni_formatter_test.cpp`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Produces: `std::optional<std::string> copy_c_string(uintptr_t address, size_t max_len, bool allow_common_whitespace = false)` and `JniType::kCString` for real `char *` values.
- Consumes: existing `bool safe_read_memory(uintptr_t, void *, size_t)`.
- Constraint: `copy_c_string` succeeds only when it safely reads a NUL terminator within `max_len` and every byte is printable, except optional newline/tab.

- [ ] **Step 1: Add failing safe-string tests**

Create a host test with the repository's `CHECK` helper and these cases:

```cpp
const char valid[] = "java/lang/String";
CHECK(copy_c_string(reinterpret_cast<uintptr_t>(valid), sizeof(valid)).value() == valid);
CHECK(!copy_c_string(1, 32).has_value());

const char unterminated[] = {'a', 'b', 'c'};
CHECK(!copy_c_string(reinterpret_cast<uintptr_t>(unterminated), sizeof(unterminated)).has_value());

const char control[] = {'a', '\x01', '\0'};
CHECK(!copy_c_string(reinterpret_cast<uintptr_t>(control), sizeof(control)).has_value());
```

Register `safe_memory_string_test` with `core/safe_memory.cpp` in CMake.

- [ ] **Step 2: Verify the safe-string test is red**

Run:

```bash
cmake -S tracer/src/test/cpp -B build/native-tests
cmake --build build/native-tests --target safe_memory_string_test -j2
```

Expected: compilation fails because `copy_c_string` is not declared.

- [ ] **Step 3: Implement the bounded copy**

Add `<optional>` to the header and implement without direct target-address dereference:

```cpp
std::optional<std::string> copy_c_string(uintptr_t address, size_t max_len,
                                         bool allow_common_whitespace) {
    if (address < 0x1000 || max_len == 0) return std::nullopt;
    std::string result;
    result.reserve(max_len);
    for (size_t offset = 0; offset < max_len; ++offset) {
        char value = 0;
        if (!safe_read_memory(address + offset, &value, 1)) return std::nullopt;
        if (value == '\0') return result;
        const auto byte = static_cast<unsigned char>(value);
        if ((byte < 0x20 || byte == 0x7f) &&
            !(allow_common_whitespace && (value == '\n' || value == '\t'))) {
            return std::nullopt;
        }
        result.push_back(value);
    }
    return std::nullopt;
}
```

Reimplement `preview_c_string` through `copy_c_string`; preserve its public fallback strings only for legacy callers.

- [ ] **Step 4: Verify safe-string green**

Run:

```bash
cmake --build build/native-tests --target safe_memory_string_test -j2
ctest --test-dir build/native-tests -R safe_memory_string_test --output-on-failure
```

Expected: one test passes.

- [ ] **Step 5: Add a failing formatter regression test**

Construct `JniFuncInfo` values directly and assert opaque references are not dereferenced:

```cpp
JniFormatter formatter;
JniFuncInfo new_string_utf{"NewStringUTF", JniType::kString, "JNIEnv",
                           {JniType::kCString}};
const char opaque_handle_bytes[] = "must-not-read";
const std::string output = formatter.format_leave(
        7, 0, new_string_utf, reinterpret_cast<uintptr_t>(opaque_handle_bytes));
CHECK(output.find("must-not-read") == std::string::npos);

JniFuncInfo get_utf{"GetStringUTFChars", JniType::kCString, "JNIEnv",
                    {JniType::kString, JniType::kBoolean}};
const char text[] = "captured";
const std::string utf_output = formatter.format_leave(
        7, 0, get_utf, reinterpret_cast<uintptr_t>(text));
CHECK(utf_output.find("captured") != std::string::npos);

const auto table = build_jni_function_table();
const auto find = [&](std::string_view name) -> const JniFuncInfo & {
    return *std::find_if(table.begin(), table.end(), [&](const JniFuncInfo &func) {
        return name == func.name;
    });
};
CHECK(std::string_view(find("FindClass").args[0]) == JniType::kCString);
CHECK(std::string_view(find("NewStringUTF").args[0]) == JniType::kCString);
CHECK(std::string_view(find("GetStringUTFChars").ret_type) == JniType::kCString);
```

Register `jni_formatter_test` with `jni_formatter.cpp`, `jni_state.cpp`, and `safe_memory.cpp`.

- [ ] **Step 6: Verify the formatter test is red**

Run:

```bash
cmake --build build/native-tests --target jni_formatter_test -j2
ctest --test-dir build/native-tests -R jni_formatter_test --output-on-failure
```

Expected: the `NewStringUTF` leave output contains bytes read from the fake `jstring` address, and the function-table type assertions fail, proving both unsafe fallback and type conflation.

- [ ] **Step 7: Replace formatter raw reads**

Add `JniType::kCString = "char*"`. Assign it to actual `const char *` JNI positions such as `DefineClass` name, `FindClass`, `ThrowNew`, `FatalError`, method/field names and signatures, `NewStringUTF`, `GetStringUTFChars`, and `ReleaseStringUTFChars`. Keep opaque `jstring` positions as `kString` and UTF-16 pointers as `kPointer`.

Remove `safe_cstring`, `safe_utf8_string`, and unused `has_buffer_arg`. Use `copy_c_string` only for `kCString` values:

```cpp
if (strcmp(type, JniType::kCString) == 0) {
    const auto text = copy_c_string(value, 1024, true);
    if (text) meta << '"' << *text << '"';
}
```

Do not inspect `jstring` inside `resolve_meta` or the `NewStringUTF`/`NewString` leave path. Keep `GetStringChars` and `GetStringCritical` as pointer-only output without UTF-8 metadata. Use copied strings for pointer arguments and `RegisterNatives` fields. Silence the preserved `format_leave` `tid` parameter with `(void)tid`.

- [ ] **Step 8: Verify Task 1 green and commit**

Run:

```bash
cmake --build build/native-tests --target safe_memory_string_test jni_formatter_test -j2
ctest --test-dir build/native-tests -R 'safe_memory_string_test|jni_formatter_test' --output-on-failure
git diff --check
```

Expected: two tests pass and no whitespace errors.

Commit:

```bash
git add tracer/src/main/cpp/core/safe_memory.h tracer/src/main/cpp/core/safe_memory.cpp \
  tracer/src/main/cpp/jni/jni_function_table.h tracer/src/main/cpp/jni/jni_formatter.cpp \
  tracer/src/test/cpp/safe_memory_string_test.cpp \
  tracer/src/test/cpp/jni_formatter_test.cpp tracer/src/test/cpp/CMakeLists.txt
git commit -m "fix(jni): guard string memory reads"
```

### Task 2: Value-safe concurrent JNI state

**Files:**
- Modify: `tracer/src/main/cpp/jni/jni_state.h`
- Modify: `tracer/src/main/cpp/jni/jni_state.cpp`
- Modify: `tracer/src/main/cpp/jni/jni_formatter.cpp`
- Modify: `tracer/src/main/cpp/handlers/call_handlers.cpp`
- Create: `tracer/src/test/cpp/jni_state_test.cpp`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Produces: `std::optional<std::string> class_name(uintptr_t) const`, `method_sig`, `field_sig`, `string_value`, and `object_type` with the same return type.
- Consumes: Task 1's formatter test and `copy_c_string`.

- [ ] **Step 1: Add failing lifetime and concurrency tests**

The test must use a local `JniState`, not the global singleton:

```cpp
JniState state;
state.on_find_class(1, "first");
const auto snapshot = state.class_name(1);
state.on_find_class(1, "second");
CHECK(snapshot == std::optional<std::string>("first"));
CHECK(state.class_name(1) == std::optional<std::string>("second"));

std::atomic<bool> start{false};
std::thread writer([&] {
    while (!start.load()) {}
    for (int i = 0; i < 10000; ++i) state.on_find_class(2, "stable");
});
std::thread reader([&] {
    start.store(true);
    for (int i = 0; i < 10000; ++i) {
        const auto value = state.class_name(2);
        if (value) CHECK(*value == "stable");
    }
});
writer.join();
reader.join();
```

Register the test and link `Threads::Threads`.

- [ ] **Step 2: Verify the state test is red**

Run:

```bash
cmake --build build/native-tests --target jni_state_test -j2
```

Expected: compilation fails because the current query API returns `const char *` rather than `std::optional<std::string>`.

- [ ] **Step 3: Return copied optional values**

Add `<optional>` and use a private lookup helper or equivalent lock-scoped copies:

```cpp
std::optional<std::string> JniState::method_sig(uintptr_t id) const {
    std::lock_guard<std::mutex> guard(lock_);
    const auto it = methods_.find(id);
    if (it == methods_.end()) return std::nullopt;
    return it->second;
}
```

Apply the same behavior to all five query methods. Adapt formatter call sites to `if (value) meta << *value`. In method parameter parsing, retain the returned optional object while using `value->c_str()`.

- [ ] **Step 4: Stop recording UTF-16 as UTF-8**

In `update_jni_state`, retain `NewStringUTF` capture through `copy_c_string`. Remove the `NewString` branch that calls `preview_c_string`; no state update is safer than corrupt metadata until a length-aware UTF-16 converter exists.

- [ ] **Step 5: Verify Task 2 green and commit**

Run:

```bash
cmake --build build/native-tests --target jni_state_test jni_formatter_test -j2
ctest --test-dir build/native-tests -R 'jni_state_test|jni_formatter_test' --output-on-failure
git diff --check
```

Expected: both tests pass.

Commit:

```bash
git add tracer/src/main/cpp/jni/jni_state.h tracer/src/main/cpp/jni/jni_state.cpp \
  tracer/src/main/cpp/jni/jni_formatter.cpp tracer/src/main/cpp/handlers/call_handlers.cpp \
  tracer/src/test/cpp/jni_state_test.cpp tracer/src/test/cpp/CMakeLists.txt
git commit -m "fix(jni): return synchronized state copies"
```

### Task 3: Owned JNI registry and one-time publication

**Files:**
- Create: `tracer/src/main/cpp/jni/jni_function_registry.h`
- Create: `tracer/src/main/cpp/jni/jni_function_registry.cpp`
- Modify: `tracer/src/main/cpp/handlers/call_handlers.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`
- Create: `tracer/src/test/cpp/jni_function_registry_test.cpp`
- Modify: `tracer/src/test/cpp/CMakeLists.txt`

**Interfaces:**
- Produces: `JniFunctionRegistry::bind(std::string_view, uintptr_t)`, `find(uintptr_t) const`, `is_bound(std::string_view) const`, `functions() const`, and `size() const`.
- Owns: one `std::vector<JniFuncInfo>` returned by `build_jni_function_table()` and an index of pointers into that immutable-size vector.
- Constraint: construction finishes all vector growth before any address pointer is indexed.

- [ ] **Step 1: Add the failing registry test**

```cpp
JniFunctionRegistry registry;
CHECK(registry.bind("FindClass", 0x1234));
const JniFuncInfo *found = registry.find(0x1234);
CHECK(found != nullptr);
CHECK(std::string_view(found->name) == "FindClass");
CHECK(found->address == 0x1234);
CHECK(registry.find(0x9999) == nullptr);
CHECK(!registry.bind("missing", 0x2222));
CHECK(!registry.bind("GetVersion", 0x1234));
```

The duplicate-address assertion defines first-binding-wins behavior and prevents ambiguous dispatch.

- [ ] **Step 2: Verify the registry test is red**

Run:

```bash
cmake --build build/native-tests --target jni_function_registry_test -j2
```

Expected: compilation fails because the registry header does not exist.

- [ ] **Step 3: Implement owned storage and index**

Use this public shape:

```cpp
class JniFunctionRegistry {
public:
    JniFunctionRegistry();
    bool bind(std::string_view name, uintptr_t address);
    bool is_bound(std::string_view name) const;
    const JniFuncInfo *find(uintptr_t address) const;
    const std::vector<JniFuncInfo> &functions() const;
    size_t size() const;

private:
    std::vector<JniFuncInfo> functions_;
    JniAddressMap by_address_;
};
```

`bind` rejects zero addresses, unknown names, already-bound names, and addresses already in `by_address_`. It sets `JniFuncInfo::address` before inserting its stable pointer.

- [ ] **Step 4: Verify the registry unit is green**

Run:

```bash
cmake --build build/native-tests --target jni_function_registry_test -j2
ctest --test-dir build/native-tests -R jni_function_registry_test --output-on-failure
```

Expected: one test passes.

- [ ] **Step 5: Replace global map and boolean initialization**

In `call_handlers.cpp`, replace `g_jni_map`, `g_jni_map_built`, and `g_jni_map_lock` with:

```cpp
JniFunctionRegistry &jni_registry() {
    static JniFunctionRegistry registry;
    return registry;
}

std::once_flag g_jni_registry_once;

void ensure_jni_registry_built(uintptr_t env) {
    std::call_once(g_jni_registry_once, [env] {
        auto &registry = jni_registry();
        // dlsym and vtable resolution call registry.bind(name, address)
    });
}
```

Iterate `registry.functions()` for names and standard vtable order, consult `is_bound`, and bind through the registry. In `emit_jni_enter`, call `registry.find(target)` and store the returned stable pointer in `ActiveJniCall`.

- [ ] **Step 6: Add production source and verify Task 3**

Add `jni/jni_function_registry.cpp` to `qbdi_tracer`. Run:

```bash
cmake --build build/native-tests --target jni_function_registry_test -j2
ctest --test-dir build/native-tests -R jni_function_registry_test --output-on-failure
./gradlew :tracer:assembleDebug --no-daemon
git diff --check
```

Expected: registry test and tracer Android build pass; the compiler emits neither the old formatter warnings nor new registry warnings.

Commit:

```bash
git add tracer/src/main/cpp/jni/jni_function_registry.h \
  tracer/src/main/cpp/jni/jni_function_registry.cpp \
  tracer/src/main/cpp/handlers/call_handlers.cpp tracer/src/main/cpp/CMakeLists.txt \
  tracer/src/test/cpp/jni_function_registry_test.cpp tracer/src/test/cpp/CMakeLists.txt
git commit -m "fix(jni): own and publish function registry"
```

### Task 4: Build and scene configuration contracts

**Files:**
- Modify: `scripts/tests/test_pull_trace.py`
- Modify: `scripts/trace_config.js`
- Create: `scripts/tests/test_build_contract.py`
- Modify: `app/build.gradle`
- Modify: `build.gradle`
- Modify: `README.md`

**Interfaces:**
- Produces: root Gradle task `nativeHostTest`.
- Produces: matching nonzero `integrity` offset `0x6E584` in both Frida configuration files.
- Constraint: `nativeHostTest` configures, builds, and runs Host CTest; it must not depend on Android JVM `testDebugUnitTest`.

- [ ] **Step 1: Add failing scene and build contract tests**

Extend `test_pull_trace.py`:

```python
def test_frida_configs_share_demo_scene_offsets(self):
    root = Path(__file__).resolve().parents[2]
    module_config = (root / "scripts/trace_config.js").read_text()
    spawn_config = (root / "scripts/spawn_trace.js").read_text()
    for scene in ("init", "jni", "libc", "algorithm", "integrity"):
        pattern = rf"{scene}: \{{ offset: '([^']+)' \}}"
        self.assertEqual(re.search(pattern, module_config).group(1),
                         re.search(pattern, spawn_config).group(1))
```

Create `test_build_contract.py` asserting:

```python
app_gradle = (ROOT / "app/build.gradle").read_text()
root_gradle = (ROOT / "build.gradle").read_text()
self.assertRegex(app_gradle, r"release\s*\{[^}]*debuggable false")
self.assertIn('tasks.register("nativeHostTest", Exec)', root_gradle)
self.assertIn('"ctest"', root_gradle)
self.assertNotIn("testDebugUnitTest", root_gradle)
```

- [ ] **Step 2: Verify contracts are red**

Run:

```bash
python3 -m unittest scripts.tests.test_pull_trace.CommandLineTests.test_frida_configs_share_demo_scene_offsets scripts.tests.test_build_contract -v
```

Expected: integrity offsets differ, Release is still debuggable, and `nativeHostTest` is absent.

- [ ] **Step 3: Align the scene and harden Release**

Set `scripts/trace_config.js` integrity to `0x6E584`. Set the application build type explicitly:

```groovy
release {
    minifyEnabled false
    debuggable false
}
```

Keep the Debug block unchanged.

- [ ] **Step 4: Add the Gradle Host CTest chain**

In root `build.gradle`, add three `Exec` tasks with explicit ordering:

```groovy
def nativeHostBuildDir = layout.buildDirectory.dir("native-host-tests")

tasks.register("configureNativeHostTests", Exec) {
    commandLine "cmake", "-S", "tracer/src/test/cpp", "-B", nativeHostBuildDir.get().asFile
}
tasks.register("buildNativeHostTests", Exec) {
    dependsOn "configureNativeHostTests"
    commandLine "cmake", "--build", nativeHostBuildDir.get().asFile, "--parallel", "2"
}
tasks.register("nativeHostTest", Exec) {
    dependsOn "buildNativeHostTests"
    commandLine "ctest", "--test-dir", nativeHostBuildDir.get().asFile,
            "--output-on-failure"
}
```

Update README validation commands to use `./gradlew nativeHostTest --no-daemon`; do not claim `testDebugUnitTest` runs C++ tests.

- [ ] **Step 5: Verify Task 4 green and commit**

Run:

```bash
python3 -m unittest scripts.tests.test_pull_trace.CommandLineTests.test_frida_configs_share_demo_scene_offsets scripts.tests.test_build_contract -v
./gradlew nativeHostTest --no-daemon
git diff --check
```

Expected: contract tests pass and Gradle reports the full CTest suite passing.

Commit:

```bash
git add scripts/tests/test_pull_trace.py scripts/tests/test_build_contract.py \
  scripts/trace_config.js app/build.gradle build.gradle README.md
git commit -m "build: expose native host verification"
```

### Task 5: Full regression and deliverable audit

**Files:**
- Modify only files required by failures directly caused by Tasks 1–4.

**Interfaces:**
- Consumes: all earlier tasks.
- Produces: fresh evidence for the complete repository state.

- [ ] **Step 1: Run the complete Python suite**

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

Expected: all tests pass with zero failures and zero errors.

- [ ] **Step 2: Run the complete Native suite through Gradle**

```bash
./gradlew nativeHostTest --no-daemon
```

Expected: every registered CTest passes.

- [ ] **Step 3: Build the tracer and inspect warnings**

```bash
./gradlew :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon --warning-mode all
```

Expected: build exits zero; no unused `tid`, unused `has_buffer_arg`, JNI registry, or JNI state warnings appear.

- [ ] **Step 4: Attempt the full Debug APK build**

```bash
./gradlew :app:assembleDebug --no-daemon --stacktrace
```

Expected: build exits zero. If Kotlin compilation stops making progress, preserve the logs and report the APK build as unconfirmed rather than passing.

- [ ] **Step 5: Audit requirements and repository state**

```bash
git diff --check
git status --short
git log --oneline -8
```

Confirm each design requirement has a matching test or build result. Do not commit unrelated user files, generated build directories, APKs, AARs, or trace artifacts.

If a regression fails, return to the task that introduced it, add a focused failing regression case, fix it through the same red-green cycle, and include that correction in the corresponding task commit before reporting completion.
