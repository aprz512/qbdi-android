# Finding Scene Offsets

The tracer uses `module_base + offset`, not runtime symbol lookup.

## IDA Workflow

1. Open `libdemo_target.so` from the APK native library directory.
2. Let IDA analyze the file as AArch64 ELF.
3. Search strings such as `JNI scene finished`, `libc scene`, `integrity scene`, and `constructor complete`.
4. Follow xrefs from those strings to the containing functions.
5. Record the function start offset shown by IDA relative to the image base.
6. Put the offset into `scripts/trace_config.js` and the embedded config in `scripts/spawn_trace.js`.

## objdump Workflow

```bash
llvm-objdump -d app/build/intermediates/merged_native_libs/debug/mergeDebugNativeLibs/out/lib/arm64-v8a/libdemo_target.so | less
```

Use nearby strings from `llvm-strings` to identify functions and record offsets.
