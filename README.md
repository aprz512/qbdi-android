# qbdi-android

Android arm64 demo project for showing how to use QBDI in an injected tracer.

## What This Demo Shows

- A Kotlin APK loads a stripped native target library.
- Native methods are registered dynamically with `RegisterNatives`.
- A native constructor triggers an init-stage function.
- Button-driven scenes exercise JNI calls, libc calls, a custom algorithm, and integrity checks.
- A separate `libqbdi_tracer.so` is injected with Frida spawn.
- The tracer hooks scene entry offsets with ByteDance ShadowHook and executes them in QBDI.
- Text traces are written to `/data/data/com.aprz.qbdiandroid/files/qbdi-traces/`.

## Dependencies

- Android Studio or Android SDK + NDK
- CMake 3.22.1+
- arm64 Android device or emulator
- Frida server matching your host Frida version, on a rooted/debuggable setup that supports spawn injection
- On jailed/non-root Android, Frida may require Gadget and plain spawn injection will fail
- Git LFS for `libQBDI.a`
- QBDI v0.12.1 Android AARCH64 artifact committed under `tracer/src/main/cpp/third_party/qbdi/`
- ByteDance ShadowHook source vendored under `tracer/src/main/cpp/third_party/android-inline-hook/`
- LZ4 v1.10.0 (`ebb370ca83af193212df4dcbadcc5d87bc0de2f0`) vendored under `tracer/src/main/cpp/third_party/lz4/`

## Build

```bash
./gradlew :app:assembleDebug
./gradlew :tracer:assembleDebug :tracer:copyTracerDebug
```

## Install and Deploy

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell mkdir -p /data/local/tmp/qbdi-android
adb push out/arm64-v8a/libqbdi_tracer.so /data/local/tmp/qbdi-android/
```

The benchmark agent loads the tracer through the application class loader so it shares the
target's Android linker namespace and remains executable with SELinux Enforcing. Stage that copy
in the debuggable app's private directory before running `benchmark_trace.py`:

```bash
adb push out/arm64-v8a/libqbdi_tracer.so /data/local/tmp/qbdi-tracer-stage.so
adb shell run-as com.aprz.qbdiandroid cp \
  /data/local/tmp/qbdi-tracer-stage.so files/libqbdi_tracer.so
adb shell run-as com.aprz.qbdiandroid chmod 700 files/libqbdi_tracer.so
python3 scripts/benchmark_trace.py --package com.aprz.qbdiandroid \
  --device <adb-serial> --profile balanced --runs 5 \
  --compare docs/benchmarks/trace-throughput-baseline.md
```

## Find Scene Offsets

Open the stripped `libdemo_target.so` in IDA or Ghidra. Use strings and call references to locate:

- `demo_init_stage`
- `demo_jni_case`
- `demo_libc_case`
- `demo_algorithm_case`
- `demo_integrity_case`

Write relative offsets into both `scripts/trace_config.js` and the self-contained config object in `scripts/spawn_trace.js`.

## Inject

```bash
frida -U -f com.aprz.qbdiandroid -l scripts/spawn_trace.js
```

The constructor scene only traces reliably with spawn injection. For button scenes, wait for the UI and tap the desired button.

## Pull Traces

Install the host `lz4` CLI, then use the pull helper. It accesses the app-private directory only
through `adb exec-out run-as`, pulls the newest compressed trace and adjacent sidecars, and
decompresses every complete LZ4 frame in order:

```bash
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid --output pulled-traces
```

Useful options:

```bash
# Select one listed artifact instead of the newest.
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --name <trace-file>.trace.txt.lz4 --output pulled-traces

# Pull the compressed trace and sidecars without requiring host lz4.
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --compressed-only --output pulled-traces

# Existing local outputs are protected unless replacement is explicit.
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --force --output pulled-traces
```

The tracer defaults to the `fast` profile. `balanced` enables QBDI memory metadata, while `full`
also captures bounded pre/post memory bytes. Configure profiles and buffer sizing in
`scripts/trace_config.js`; see [docs/trace-format.md](docs/trace-format.md) for the complete format,
metrics, memory cost, decompression, and crash-recovery contract.

## Troubleshooting

If Frida prints `need Gadget to attach on jailed Android`, use a rooted device with frida-server for this demo or embed/configure Frida Gadget before trying spawn injection. Constructor tracing depends on early spawn-style injection.

If `pull_trace.py` reports that the host `lz4` CLI is missing, install LZ4 or repeat the pull with
`--compressed-only`. If a crash marker accompanies a truncated final frame, the helper preserves
only fully decoded frames as `*.partial.trace.txt` and exits with status 2; other pull failures use
status 1.
