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

```bash
adb shell run-as com.aprz.qbdiandroid ls files/qbdi-traces
adb exec-out run-as com.aprz.qbdiandroid cat files/qbdi-traces/<trace-file> > trace.txt
```

## Troubleshooting

If Frida prints `need Gadget to attach on jailed Android`, use a rooted device with frida-server for this demo or embed/configure Frida Gadget before trying spawn injection. Constructor tracing depends on early spawn-style injection.
