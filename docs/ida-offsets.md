# Finding Scene Locations

The tracer does not resolve scene symbols at runtime. Configure each scene in the
`config.tracer.scenes` array at the top of `scripts/spawn_trace.js`; this is the only
manually maintained normal tracing configuration.

Every address is a hexadecimal string. JSON numbers are rejected so JavaScript cannot
silently lose address precision. A scene uses exactly one of these locator forms:

```javascript
{
  name: 'init',
  location: {
    offset: '0x6ac90',
    endOffset: '0x6ad00'
  }
}
```

or:

```javascript
{
  name: 'algorithm',
  location: {
    imageBase: '0x10000',
    address: '0x7db38',
    endAddress: '0x7dc00'
  }
}
```

Native code normalizes the second form with `offset = address - imageBase`.
`endOffset` and `endAddress` are optional exclusive ends and, when present, must be
strictly greater than their starts. Do not mix the two forms in one location.

## IDA Workflow

1. Open `libdemo_target.so` from the APK native library directory.
2. Let IDA analyze the file as AArch64 ELF.
3. Search strings such as `JNI scene finished`, `libc scene`, `integrity scene`, and `constructor complete`.
4. Follow xrefs from those strings to the containing functions.
5. Record the function address and the IDA image base. Either subtract the base and use
   `offset`, or preserve both values with `imageBase + address`.
6. Put the chosen hexadecimal strings into `scripts/spawn_trace.js`.

## objdump Workflow

```bash
llvm-objdump -d app/build/intermediates/merged_native_libs/debug/mergeDebugNativeLibs/out/lib/arm64-v8a/libdemo_target.so | less
```

Use nearby strings from `llvm-strings` to identify functions and record module-relative
offsets. Re-check all locations whenever `libdemo_target.so` changes.

Packed libraries may unpack or generate executable code outside the target ELF's initial
mapping. `ADDRESS_OUTSIDE_TARGET_MODULE`, `ADDRESS_NOT_EXECUTABLE`, and
`ADDRESS_IN_RUNTIME_MAPPING` are therefore diagnostics: the tracer reports them as warnings
and still attempts the hook. Invalid hex, incomplete/conflicting locator forms, subtraction
underflow, parsed values outside `uintptr_t`, and empty/reversed ranges are strict configure
failures and do not replace the active generation. A later overflow in
`moduleBase + normalizedOffset` occurs only after the target mapping is observed: the accepted
generation remains published, but that scene ends in `hook_failed` with `ADDRESS_OVERFLOW`
(`hookError: 0`).
