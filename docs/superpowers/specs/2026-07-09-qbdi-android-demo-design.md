# QBDI Android Demo Design

Date: 2026-07-09
Repository: `git@github.com:aprz512/qbdi-android.git`

## Goal

Build a Kotlin + native Android demo project that teaches how to use QBDI in an Android injection workflow. The app provides a stripped native target library with several independent scenes. A separate tracer library is injected with Frida spawn, redirects selected native functions through ByteDance `android-inline-hook`, runs them inside QBDI, and writes complete human-readable text traces.

The first version focuses on text trace output. The trace pipeline still uses a writer interface so a binary writer and offline converter can be added later without changing instruction collection logic.

## Non-Goals

- Do not implement binary trace storage in the first version.
- Do not resolve target scene functions by symbol name at runtime.
- Do not auto-generate offsets from build artifacts.
- Do not support attach-only tracing for constructor coverage in the first version.
- Do not rely on exported static JNI names such as `Java_package_Class_method`.

## Architecture

The repository contains two runtime artifacts:

1. `libdemo_target.so`, packaged in the APK and loaded on app startup.
2. `libqbdi_tracer.so`, pushed or loaded externally and injected into the target process through Frida spawn.

Runtime flow:

1. Frida spawns the app process before normal app execution reaches native loading.
2. The injection script loads `libqbdi_tracer.so` early.
3. The APK starts and loads `libdemo_target.so`.
4. Target constructors and JNI registration run.
5. The tracer locates the configured target module, computes absolute addresses from configured offsets, installs inline hooks, and redirects selected functions into QBDI.
6. QBDI executes the target function and emits trace events to a text writer.
7. Trace files are written under the app private files directory.

ByteDance `android-inline-hook` is used only as the inline hook layer. QBDI remains responsible for instruction-level execution, memory access collection, execution-transfer monitoring, and trace generation.

## Repository Layout

Planned top-level structure:

```text
app/
  src/main/kotlin/...              Kotlin UI and native declarations
  src/main/cpp/demo_target/        Native target library scenes
tracer/
  src/main/cpp/core/               QBDI VM, register sync, module resolver
  src/main/cpp/hooks/              android-inline-hook adapter
  src/main/cpp/events/             TraceEvent and TextTraceWriter
  src/main/cpp/handlers/           JNI, libc, custom, bypass handlers
  src/main/cpp/third_party/qbdi/   QBDI headers and official release libQBDI.a
  src/main/cpp/third_party/hook/   android-inline-hook integration
scripts/
  spawn_trace.js                   Frida spawn injection script
  trace_config.js                  Example offset-based config
docs/
  ida-offsets.md                   How to find offsets in IDA/Ghidra/objdump
  trace-format.md                  Text trace format
  integrity-bypass.md              Integrity detection and bypass walkthrough
```

Module boundaries:

- `demo_target` is only the target sample. It has no QBDI dependency.
- `tracer` owns injection-time hooks, QBDI execution, event creation, bypass logic, and file output.
- `scripts` only orchestrate loading and configuration.
- Documentation explains manual offset discovery and expected outputs.

## Android App Design

The APK uses Kotlin and CMake.

The UI has one status area and four buttons:

- `Trace JNI Case`
- `Trace Libc Case`
- `Trace Algorithm Case`
- `Trace Integrity Case`

The init scene is not button-driven. It is executed from a native constructor during app startup so it can demonstrate init-stage tracing when Frida spawn injects the tracer early enough.

Kotlin declares native methods such as:

- `external fun runJniCase(): String`
- `external fun runLibcCase(): String`
- `external fun runAlgorithmCase(): String`
- `external fun runIntegrityCase(): String`

The native methods are registered dynamically from `JNI_OnLoad` with `RegisterNatives`. The target library must not rely on exported static JNI symbols. This keeps the sample closer to real reverse-engineering targets.

## Target Native Scenes

`libdemo_target.so` provides independent native scenes. Release artifacts are stripped. Users are expected to locate offsets manually with IDA, Ghidra, objdump, or readelf and then update the tracer config.

### Init Scene

- A native constructor calls `demo_init_stage()`.
- `demo_init_stage()` performs deterministic native work and calls at least one helper function.
- This scene demonstrates constructor/init-stage tracing.
- Reliable coverage requires Frida spawn injection. Attach mode can miss this stage and is not part of the first-version happy path.

### JNI Scene

- A dynamically registered native entry calls `demo_jni_case()`.
- The scene exercises JNI APIs such as class lookup, string creation, UTF string access, method lookup, and `RegisterNatives` observation from `JNI_OnLoad`.
- The tracer records JNI calls through QBDI execution-transfer callbacks or instruction-level fallback matching.

### Libc Scene

- A dynamically registered native entry calls `demo_libc_case()`.
- The scene calls libc functions such as `strlen`, `memcpy`, `memcmp`, `access`, `fopen`, and Android system property reads when available.
- The tracer records arguments and selected string or buffer previews.

### Algorithm Scene

- A dynamically registered native entry calls `demo_algorithm_case()`.
- The scene runs a small deterministic algorithm such as rolling hash, XOR mix, or base64-like transform.
- The trace should show custom function calls, register flow, memory reads/writes, and a stable return value.

### Integrity Scene

A dynamically registered native entry calls `demo_integrity_case()`. This scene contains two anti-instrumentation checks that are useful for QBDI demonstrations.

#### `.text` Hash Check

- The target records expected bytes or a hash for a selected executable range.
- Before running the protected algorithm, it re-reads that `.text` range and validates it.
- If the check fails, the target deliberately crashes.
- The tracer bypass handler can restore original bytes, or repair the comparison input before validation observes it.

#### `/proc/self/maps` Continuity and Injection Check

- The target reads `/proc/self/maps`.
- It checks target module RX mapping layout, segment continuity assumptions, and suspicious mapping names such as tracer, QBDI, Frida, or hook-related modules.
- If the check fails, the target deliberately crashes.
- The tracer bypass handler can sanitize maps buffers after libc read or fgets-style calls so the target sees a clean process layout.

The integrity scene demonstrates that QBDI can do more than record instructions. It can modify memory and return data at precise times so protection logic observes a clean state.

## Tracer Design

### Configuration

First-version configuration is offset based.

Each trace target includes:

- package name
- target so name
- scene name
- relative offset
- hook argument mode, initially up to `x0`-`x7`
- enabled trace categories
- enabled bypass handlers

Example config shape:

```js
{
  packageName: "com.aprz.qbdiandroid",
  targetSo: "libdemo_target.so",
  scenes: [
    { name: "init", offset: "0x1234", bypass: [] },
    { name: "jni", offset: "0x2340", bypass: [] },
    { name: "libc", offset: "0x3450", bypass: [] },
    { name: "algorithm", offset: "0x4560", bypass: [] },
    { name: "integrity", offset: "0x5670", bypass: ["text_restore", "maps_sanitize"] }
  ]
}
```

The design does not require symbol names at runtime.

### Hook Layer

`InlineHookAdapter` wraps ByteDance `android-inline-hook`.

Responsibilities:

- install a hook at `module_base + offset`
- save the original trampoline
- support safe unhook or recursion guard before entering QBDI
- reinstall or re-enable hook after QBDI execution returns
- report hook failures as trace or error events

The hook adapter is isolated from QBDI-specific code so another hook backend could be swapped in later if required.

### QBDI Runner

`QbdiRunner` owns one trace invocation.

Responsibilities:

- resolve target module base and executable range
- create and configure a QBDI VM
- instrument the target module range
- sync `x0`-`x7`, `lr`, `sp`, `pc`, and relevant state into the VM
- execute the target function
- return the target result to the original caller
- emit begin, end, and error markers

The runner should avoid QBDI virtual stack choices known to be unstable on Android runtime threads. Stack handling must be documented and kept conservative.

### Event Collection

The tracer emits structured events internally, even though first-version storage is text.

Core event types:

- `TraceBeginEvent`
- `InstructionEvent`
- `MemoryAccessEvent`
- `CallEvent`
- `BypassEvent`
- `TraceEndEvent`
- `ErrorEvent`

This preserves a clean path to future binary output.

### JNI and Libc Monitoring

The tracer should detect calls that leave the instrumented module.

Primary strategy:

- use QBDI execution-transfer events for calls and returns when available

Fallback strategy:

- inspect branch or call instructions such as `BLR` and `BR`
- resolve the target register value
- match it against known JNI function table addresses or libc symbol addresses

JNI and libc handlers format arguments into trace events. They should avoid unsafe dereferences by using guarded memory reads and length limits.

### Bypass Registry

`BypassRegistry` maps scene and detection type to handlers.

First-version handlers:

- `text_restore`: restores or presents expected bytes for selected `.text` ranges during integrity checks
- `maps_sanitize`: edits maps buffers returned to the target so QBDI, Frida, tracer, or hook artifacts are hidden from the target check

Bypass events must be written into the trace so the demo clearly shows what was changed.

## Trace Output

First-version output is human-readable text.

Trace directory:

```text
/data/data/<package>/files/qbdi-traces/
```

File name format:

```text
<timestamp>_<pid>_<tid>_<scene>_0x<offset>.trace.txt
```

File header includes:

- package name
- process id and thread id
- target so
- module base
- target offset
- absolute target address
- QBDI version when available
- hook backend
- enabled trace categories
- enabled bypass handlers
- device ABI

Instruction line format:

```text
<seq> <module>+<offset> <disassembly> | R:<regs> | W:<regs> | MEM:<accesses>
```

Event examples:

```text
TRACE_BEGIN scene=libc target=libdemo_target.so+0x3450
000001 libdemo_target.so+0x3450 stp x29, x30, [sp,#-0x10]! | R:sp=0x... | W:sp=0x...
CALL libc.strlen x0=0x... preview="hello"
MEM:r addr=0x... size=8 value=0x...
BYPASS text_hash_restore range=libdemo_target.so+0x1800 size=16
BYPASS maps_sanitize hidden=libqbdi_tracer.so,frida-agent,libQBDI
TRACE_END status=ok ret=0x42 elapsed_ms=15 bytes=123456
```

Performance requirements:

- keep one file descriptor per trace
- use an in-memory append buffer
- batch `write()` calls by threshold and at trace end
- avoid full trace output to logcat
- use logcat for summaries and errors only
- guard string and memory preview length

## Build and Dependency Design

The project builds with Gradle and CMake for `arm64-v8a` first.

QBDI dependency:

- include official QBDI Android aarch64 release artifacts in the repository
- store `libQBDI.a` under a fixed third-party path
- document the QBDI version and official release source in README
- do not download latest artifacts during normal builds

Hook dependency:

- integrate ByteDance `android-inline-hook` as the hook backend
- keep its headers and binary or source integration under a clear third-party path
- document version and update steps

Target library stripping:

- release target artifacts should be stripped
- README explains how to locate offsets manually in IDA/Ghidra/objdump
- no runtime symbol resolution is required for scene entry points

## Frida Spawn Workflow

The happy path uses Frida spawn.

Typical flow:

1. Build APK and tracer library.
2. Install APK.
3. Push or otherwise make `libqbdi_tracer.so` available to the device.
4. Edit `scripts/trace_config.js` with scene offsets.
5. Run Frida with spawn mode.
6. Wait for the app UI.
7. For non-init scenes, tap the corresponding button.
8. Pull traces from the app private files directory.

The README must explicitly state that constructor tracing can be missed with late attach injection.

## Error Handling

The tracer must report these errors clearly:

- target module not loaded
- module base not found
- configured offset outside executable range
- hook install failure
- QBDI VM initialization failure
- QBDI execution failure
- trace file open/write failure
- unsafe memory read skipped
- bypass handler could not find expected data

Errors are written to logcat and, when possible, to an error trace file.

The target app should show button-level result text for normal scenes. If integrity bypass is disabled, the integrity scene is allowed to crash intentionally.

## Validation Plan

Build validation:

- Gradle builds the APK.
- Gradle/CMake builds `libdemo_target.so` and `libqbdi_tracer.so` for `arm64-v8a`.

Runtime validation:

- Frida spawn starts the app and injects the tracer.
- Constructor scene emits a trace when the configured init offset is enabled.
- JNI button emits a trace containing JNI call events.
- Libc button emits a trace containing libc call events.
- Algorithm button emits instruction, memory, and return markers.
- Integrity button crashes without bypass when checks detect artifacts.
- Integrity button continues with bypass enabled and writes bypass events.

Trace validation:

- Trace file header contains target and environment metadata.
- Each trace has `TRACE_BEGIN` and `TRACE_END`.
- Instruction lines include module offsets and disassembly.
- Call events are visible for JNI/libc scenes.
- Bypass events identify modified `.text` or sanitized maps data.

Documentation validation:

- README explains build prerequisites.
- README explains Frida spawn workflow.
- Docs explain how to find offsets in IDA.
- Docs explain where trace files are stored and how to pull them.

## Open Extension Points

Later versions can add:

- binary trace writer and offline converter
- attach-mode tracing for non-init scenes
- syscall tracing
- more JNI/libc handlers
- remote control of trace config
- automated offset generation for debug builds
- multi-ABI support
