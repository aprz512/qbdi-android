# qbdi-android

Android arm64 demo project for showing how to use QBDI in an injected tracer.

## What This Demo Shows

- A Kotlin APK loads a stripped native target library.
- Native methods are registered dynamically with `RegisterNatives`.
- A native constructor triggers an init-stage function.
- Button-driven scenes exercise JNI calls, libc calls, a custom algorithm, and integrity checks.
- A separate `libqbdi_tracer.so` is injected with Frida spawn.
- The tracer hooks scene entry offsets with ByteDance ShadowHook and executes them in QBDI.
- Compact QTRB v1 traces are written to the app-private
  `/data/data/com.aprz.qbdiandroid/files/qbdi-traces/` directory and converted to readable text on
  the host.
- An optional persistent flight recorder keeps a bounded, cross-thread pre-crash window in one
  app-private `.flight.bin` ring and recovers it on the host.

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
  --candidate-tracer out/arm64-v8a/libqbdi_tracer.so \
  --compare docs/benchmarks/binary-trace-baseline.md
```

`--compare` is acceptance mode: it uses one separate warmup and exactly five measured fresh
processes, then checks package, build fingerprint, SELinux state, the staged/app-private tracer
SHA-256, decoded event count, and exact first/last instruction identities. Runs without
`--compare` are diagnostic only and do not constitute acceptance.

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

Use spawn injection before the target library loads. The constructor scene and the persistent
`pthread_create`/signal gateways must be installed before target initialization; attaching to an
already-running process cannot recover the missed prefix. For button scenes, wait for the UI and
tap the desired button.

The checked-in Frida configs enable flight recording with a 512 MiB artifact, 256 KiB chunks, 256
thread-directory entries, and four protected chunks per active thread. The process-lifetime
pthread gateway observes lifecycle events for every `pthread_create` it sees. Threads owned by the
target—threads whose start routine is in the target, plus threads created while a target scene is
active—receive recorder sessions. QBDI instruction, memory, and GPR collection remains restricted
to retained executable ranges of the target module; hook trampolines are control-only and guest
signal handlers execute natively without instruction tracing. Flight sessions always use full
collection: target instructions, all QBDI memory accesses with bounded before/after bytes, and
`x0`–`x30`, `sp`, `pc`, and `nzcv` checkpoints/deltas.

Signal dispositions are virtualized so guest `sigaction` queries and replacements continue to see
the guest handler rather than the tracer master. Direct `rt_sigaction`, `tkill`, `tgkill`, and exit
syscalls are handled by the same contract. A returning guest handler is bracketed by explicit
begin/return records; its body is not traced. `SIGKILL` cannot be caught, so only a target-issued
pre-syscall termination-intent record can explain it.

## Pull Traces

Use the pull helper to access the app-private directory only through `adb exec-out run-as`. It
selects the newest supported artifact in the device listing. Normal `.trace.bin.lz4` QTRB output
and its adjacent `metrics_version=2` sidecar are validated; the artifact requires the host `lz4`
CLI and is converted to text format 3. A `.flight.bin` is streamed and recovered without LZ4:

```bash
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --device 192.168.51.42:5555 --output pulled-traces
```

Useful options:

```bash
# Select one listed artifact instead of the newest.
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --name <trace-file>.flight.bin --output pulled-traces

# Pull the compressed trace and sidecars without requiring host lz4.
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --compressed-only --output pulled-traces

# Existing local outputs are protected unless replacement is explicit.
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --force --output pulled-traces

# Convert an already-pulled binary artifact manually.
python3 scripts/trace_convert.py input.trace.bin.lz4 --output output.trace.txt
```

For `<basename>.flight.bin`, normal pulling keeps the original artifact and atomically publishes
`<basename>.merged.trace.txt`, one `<basename>.tid-<tid>.trace.txt` per recovered thread, and
`<basename>.flight.json`. `--compressed-only` means artifact-only for this uncompressed format and
skips recovery-output publication. Every possible destination is protected from overwrite unless
`--force` is given.
The JSON summary is authoritative for `complete`, termination candidate, final signal, retained and
overwritten sequence ranges, coverage gaps, handler intervals, and recovery damage. A missing
terminal marker is reported as an unknown termination cause but is not corruption; committed
records and outputs remain usable. Coverage gaps, invalid/torn retained data, active chunks, or
unterminated thread lifecycles can make the summary incomplete.

Legacy format-2 `.trace.txt.lz4` files remain pullable. A valid crash marker with a truncated final
LZ4 frame publishes only complete prior frames as `.partial.trace.txt` and exits with status 2;
corruption or truncation without a marker exits with status 1 and publishes no text.

The tracer defaults to the `fast` profile. `balanced` enables QBDI memory metadata, while `full`
also captures bounded pre/post memory bytes. Configure profiles and buffer sizing in
`scripts/trace_config.js`; see [docs/trace-format.md](docs/trace-format.md) for the complete format,
metrics, memory cost, decompression, and crash-recovery contract.

## Troubleshooting

If Frida prints `need Gadget to attach on jailed Android`, use a rooted device with frida-server for this demo or embed/configure Frida Gadget before trying spawn injection. Constructor tracing depends on early spawn-style injection.

If `pull_trace.py` reports that the host `lz4` CLI is missing, install LZ4 or repeat the pull with
`--compressed-only`. If a crash marker accompanies a truncated final frame, the helper preserves
only fully decoded frames as `*.partial.trace.txt` and exits with status 2; other pull failures use
status 1. Flight artifacts never require LZ4; inspect their `.flight.json` summary before treating
the recovered window as complete.
