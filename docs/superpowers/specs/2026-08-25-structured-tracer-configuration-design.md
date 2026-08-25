# Structured Tracer Configuration Design

**Date:** 2026-08-25

## Summary

Replace the tracer's semicolon-delimited configuration protocol with a versioned JSON interface. Keep `scripts/spawn_trace.js` as the single user-edited configuration source and preserve the existing invocation:

```bash
frida -U -f com.aprz.qbdiandroid -l scripts/spawn_trace.js
```

The new interface accepts both module-relative offsets and IDA/Ghidra image-base addresses, reports configuration and hook state as structured JSON, and migrates all repository callers in one change. Address-to-mapping inconsistencies are warnings because packed libraries may not resemble their static ELF layout. Malformed or arithmetically impossible configuration remains a hard error.

This change affects the control plane only. QTRB, Flight Recorder, trace conversion, and historical trace artifacts keep their current formats.

## Goals

- Make `spawn_trace.js` the only manually maintained tracing configuration.
- Let a user add any named scene using either a relative offset or an IDA/Ghidra address.
- Replace string concatenation with a versioned, strictly validated JSON schema.
- Expose parse, configuration, deferred module loading, hook installation, warning, failure, and rollback states to the Frida console.
- Remove implicit rules such as "Flight Recorder requires scene index zero to be named `init`."
- Migrate benchmark and Flight Recorder acceptance agents to the same JSON protocol.
- Add unit, lifecycle, contract, and opt-in device coverage for the migration.

## Non-goals

- Building a Python wrapper around Frida.
- Changing the user's `frida -l` command.
- Loading a separate host-side YAML or JSON file at runtime.
- Retaining the semicolon protocol or `qbdi_tracer_configure(const char *)` as a compatibility interface.
- Changing trace event schemas, QTRB encoding, compression, or Flight Recorder artifact formats.
- Resolving symbols, signatures, or packed-code addresses automatically.
- Providing a GUI or trace visualization in this iteration.

## Current Problems

`scripts/spawn_trace.js` and `scripts/trace_config.js` duplicate scene offsets and trace defaults. The latter has no production runtime consumer; its remaining consumers are documentation and consistency tests. Adding a scene therefore requires synchronized edits that do not add runtime value.

The native configuration parser accepts a semicolon-delimited string assembled independently by several scripts. This representation has no explicit schema version, has limited structured error reporting, and encourages callers to know native field names and encoding rules. Native configuration errors are primarily visible through Logcat. A caller cannot distinguish configuration acceptance from later module-load and hook-installation outcomes.

The parser already supports `scenes=replace`, arbitrary scene names, and optional end offsets, but `spawn_trace.js` does not expose those capabilities. Flight Recorder also relies on the implicit rule that scene index zero is named `init`.

## Architecture

The configuration flow is:

```text
spawn_trace.js configuration
        |
        | JSON.stringify(config.tracer)
        v
qbdi_tracer_configure_json()
        |
        | parse, schema validation, address normalization
        v
typed TraceConfig candidate + generation status
        |
        | wait for target module
        v
mapping diagnostics + batch hook installation
        |
        v
qbdi_tracer_get_status_json()
        |
        v
Frida console
```

The native `TracerConfiguration` module is the deep module behind the C ABI seam. Its interface contains only configuration submission and status lookup. JSON parsing, typed conversion, address arithmetic, module-map diagnostics, generation tracking, hook coordination, and response serialization remain implementation details.

The JSON parser is vendored `nlohmann/json`, used directly inside the module rather than hidden behind a hypothetical one-adapter seam. Parsing occurs only on the cold configuration/status paths and never on the instruction collection hot path.

## Frida Configuration

`scripts/spawn_trace.js` contains the only user-edited configuration:

```javascript
const config = {
  loader: {
    remoteDir: '/data/local/tmp/qbdi-android',
    tracer: 'libqbdi_tracer.so',
    shadowhookCompanion: 'libshadowhook_nothing.so'
  },

  tracer: {
    schemaVersion: 1,
    packageName: 'com.aprz.qbdiandroid',
    targetModule: 'libdemo_target.so',

    trace: {
      profile: 'fast',
      compression: true,
      lz4Level: 2,
      autoBuffer: true,
      bufferMb: 0,
      hexdumpLimit: 32
    },

    flight: {
      enabled: true,
      entryScene: 'init',
      capacityMb: 512,
      chunkKb: 256,
      maxThreads: 256,
      protectedChunks: 4
    },

    scenes: [
      {
        name: 'init',
        location: { offset: '0x6ac90' }
      },
      {
        name: 'algorithm',
        location: {
          imageBase: '0x0',
          address: '0x6db38'
        }
      }
    ]
  }
};
```

`loader` is consumed only by the Frida adapter. Only `config.tracer` is serialized and sent to native code.

### Schema rules

- `schemaVersion` is required and must equal `1`.
- Unknown fields are rejected at every schema level.
- `scenes` is an ordered array with at most 256 entries.
- Scene names are non-empty, unique UTF-8 strings no longer than 128 bytes.
- Package and module names are non-empty UTF-8 strings no longer than 512 bytes.
- All addresses are hexadecimal strings. JSON numbers are rejected to avoid JavaScript precision loss.
- A scene `location` uses exactly one locator form:
  - `offset`, with optional `endOffset`; or
  - `imageBase` and `address`, with optional `endAddress`.
- For the IDA/Ghidra form, native code calculates `offset = address - imageBase` and, when present, `endOffset = endAddress - imageBase`.
- An end address is exclusive and must be greater than the start address.
- When Flight Recorder is enabled, `flight.entryScene` is required and must name one configured scene.
- Existing trace and flight numeric limits remain unchanged unless this document defines a tighter limit.
- The encoded request must be between 1 byte and 1 MiB.

## Native C ABI

The old `qbdi_tracer_configure(const char *)` export and semicolon parser are removed. They are replaced by:

```cpp
int32_t qbdi_tracer_configure_json(
        const char *request,
        uint64_t request_size,
        char *response,
        uint64_t response_capacity,
        uint64_t *response_size);

int32_t qbdi_tracer_get_status_json(
        uint64_t generation,
        char *response,
        uint64_t response_capacity,
        uint64_t *response_size);
```

The integer return value describes transport-level outcomes only:

| Value | Name | Meaning |
| ---: | --- | --- |
| 0 | `QTRACE_JSON_OK` | A complete NUL-terminated JSON response was written. |
| 1 | `QTRACE_JSON_RESPONSE_TOO_SMALL` | `response_size` contains the required size, including NUL. No configuration change occurred. |
| 2 | `QTRACE_JSON_INVALID_ARGUMENT` | A pointer, size, or ABI argument is invalid. No configuration change occurred. |

Configuration rejection, warnings, hook failures, and generation lookup errors are domain outcomes represented inside a successfully transported JSON response. A caller may retry `QTRACE_JSON_RESPONSE_TOO_SMALL` safely because the configuration is not published until a complete response fits.

`request_size` excludes any optional trailing NUL. Embedded NUL bytes are rejected as malformed input. `response_size` includes the trailing NUL when a response is written or when the required capacity is reported.

## Response Format

Responses have `responseSchemaVersion: 1` and an `ok` boolean. A rejected configuration uses a stable error code, JSON path, and human-readable message:

```json
{
  "responseSchemaVersion": 1,
  "ok": false,
  "error": {
    "code": "ADDRESS_BELOW_IMAGE_BASE",
    "path": "$.scenes[1].location.address",
    "message": "address 0x4000 is below imageBase 0x10000"
  }
}
```

An accepted configuration returns its generation and normalized scenes:

```json
{
  "responseSchemaVersion": 1,
  "ok": true,
  "generation": 4,
  "state": "waiting_for_module",
  "targetModule": "libdemo_target.so",
  "scenes": [
    {
      "name": "algorithm",
      "offset": "0x6db38",
      "endOffset": null
    }
  ],
  "warnings": []
}
```

Error codes are stable interface values. Human-readable messages may become more descriptive without a schema version change.

## Validation and Warning Policy

The following conditions reject the candidate before it changes active configuration:

- malformed JSON or invalid UTF-8;
- unsupported schema version;
- missing, unknown, or incorrectly typed fields;
- duplicate or invalid scene names;
- conflicting or incomplete locator forms;
- invalid hexadecimal strings or values outside `uintptr_t`;
- `address < imageBase` or `endAddress < imageBase`;
- an empty or reversed range;
- overflow while adding a normalized offset to a runtime base;
- an invalid Flight Recorder `entryScene`;
- existing trace or flight option invariant violations.

The following runtime observations produce warnings but do not prevent a hook attempt:

- the normalized offset is outside the target ELF's initial mapped span;
- the computed runtime address is outside a mapping attributed to the target module;
- the computed runtime address is not currently executable;
- an optional end address is outside or inconsistent with the observed executable mapping;
- the address resolves into an anonymous or runtime-generated mapping.

This split supports packed libraries whose runtime layout differs from static analysis while retaining hard failures for configurations that cannot be interpreted safely. A warning and a successful hook is a successful generation.

## Generation Lifecycle

Each accepted candidate receives a monotonically increasing nonzero generation. Invalid candidates do not consume a generation and do not affect the current configuration.

Generation states are:

```text
parsing
  +-- rejected
  `-- accepted
       +-- waiting_for_module
       +-- installing
       |    +-- installed
       |    +-- hook_failed
       |    `-- rollback_failed
       `-- superseded
```

When a valid new generation is published, the previous generation becomes `superseded`. The implementation retains status snapshots for the current and immediately previous generation. Looking up an older or unknown generation returns a successful JSON transport containing `GENERATION_NOT_FOUND`.

Module loading triggers diagnostics for every scene before hook installation begins. Installation then proceeds in scene-array order. A generation reaches `installed` only when every scene hook succeeds. If one hook fails, hooks installed for that generation are removed in reverse order. Successful cleanup produces `hook_failed`; incomplete cleanup produces `rollback_failed` and identifies each residual hook. This is transactional at the reported generation level, with `rollback_failed` explicitly representing the case where physical rollback cannot be made atomic.

## Status Format

Status responses include generation-level and per-scene outcomes:

```json
{
  "responseSchemaVersion": 1,
  "ok": true,
  "generation": 4,
  "state": "installed",
  "targetModule": "libdemo_target.so",
  "moduleBase": "0x7a12000000",
  "scenes": [
    {
      "name": "packed_entry",
      "offset": "0x81000",
      "runtimeAddress": "0x7a12081000",
      "state": "installed",
      "warnings": [
        {
          "code": "ADDRESS_OUTSIDE_TARGET_MODULE",
          "message": "runtime address is outside the target module mapping"
        }
      ]
    }
  ],
  "warnings": []
}
```

Per-scene states are `pending`, `installing`, `installed`, `hook_failed`, `rolled_back`, and `rollback_failed`. Hook failures include a stable tracer error code and the underlying ShadowHook code when available.

## Frida Adapter Behaviour

`spawn_trace.js`:

1. Loads the tracer and configures the ShadowHook companion as it does today.
2. Serializes exactly `config.tracer` with `JSON.stringify`.
3. Calls `qbdi_tracer_configure_json` and retries only when the response buffer is too small.
4. Prints a configuration summary containing the generation and each normalized scene offset.
5. Polls `qbdi_tracer_get_status_json` until the accepted generation reaches `installed`, `hook_failed`, `rollback_failed`, or `superseded`. Rejected requests have no generation and are reported directly from the configure response.
6. Prints `waiting_for_module` once, then suppresses unchanged snapshots.
7. Prints warnings without treating them as failures.
8. Stops polling after a terminal state. There is no module-load timeout because early-spawn targets may load arbitrarily late; the Frida session lifetime bounds the wait.

Native Logcat remains available for low-level diagnosis. The Frida console uses the structured response as the authoritative summary, and both outputs include the same generation and stable error codes.

Representative output:

```text
[+] tracer config accepted schema=1 generation=4
[+] scene init: ida=0x6ac90 imageBase=0x0 offset=0x6ac90
[+] waiting for libdemo_target.so
[!] scene packed_entry: runtime address is not executable yet; attempting hook
[+] scene init installed at libdemo_target.so+0x6ac90
[-] scene packed_entry hook failed: SHADOWHOOK_ERRNO_...
[-] generation 4 finished with hook_failed; rollback complete
```

## Migration

The protocol changes atomically across the repository:

- Delete `scripts/trace_config.js`.
- Make the configuration at the top of `scripts/spawn_trace.js` the sole user-maintained source.
- Replace `parse_trace_config()` with the `TracerConfiguration` module and JSON C ABI adapter.
- Remove the old `qbdi_tracer_configure` export and all semicolon-protocol tests.
- Change `scripts/benchmark_trace.js` to submit JSON.
- Change `scripts/flight_acceptance.py` to generate JSON agent configuration.
- Replace implicit Flight Recorder scene-index lookup with `flight.entryScene` lookup.
- Update README configuration, injection, troubleshooting, and testing instructions.
- Update `docs/ida-offsets.md` with both supported locator forms.
- Update control-plane examples in other affected documents without changing trace-format specifications.

The benchmark's runtime symbol lookup remains valid: it calculates a relative offset, places that value into the JSON scene locator, and submits the same structured configuration interface as the normal agent.

## Error Handling

- Parsing and schema errors return one deterministic error object and do not mutate active state.
- Multiple independent runtime mapping warnings may be returned together.
- Allocation failure, hook initialization failure, and module-observer failure use stable tracer error codes rather than free-form-only Logcat messages.
- Response serialization failure cannot publish a candidate configuration.
- A writer or capture failure after successful hook installation remains part of the existing trace/flight error model and is not reclassified as a configuration failure.
- Exceptions from the JSON library are caught at the module implementation edge and converted into stable error responses; none cross the C ABI.
- All C ABI functions are safe for concurrent status reads. Configuration publication and generation transitions use the existing tracer synchronization strategy and never expose a partially constructed `TraceConfig`.

## Testing

### Native configuration tests

Add `tracer_configuration_test.cpp` and test through the module interface:

- complete and minimal valid documents;
- malformed JSON, invalid UTF-8, embedded NUL, wrong types, missing fields, and unknown fields;
- unsupported `schemaVersion`;
- duplicate, empty, and oversized scene names;
- mutually exclusive locator forms;
- hexadecimal normalization and boundary values;
- correct `address - imageBase` conversion;
- subtraction underflow, addition overflow, and values outside `uintptr_t`;
- valid and invalid optional end ranges;
- missing or invalid `flight.entryScene`;
- request and scene-count limits;
- response-buffer retry with no first-attempt mutation;
- invalid candidates preserving the active generation;
- generation supersession and two-generation retention;
- parseable response JSON with stable `code`, `path`, and `message` fields.

### Hook lifecycle tests

Extend `tracer_entry_proxy_test.cpp` using its existing test adapters. Assert outcomes through configuration/status results rather than private hook state:

- `waiting_for_module` before the target loads;
- successful installation at an ordinary executable address;
- warning plus attempted hook for an out-of-module address;
- warning plus attempted hook for a non-executable address;
- rollback of earlier hooks when a later scene fails;
- `hook_failed` after complete rollback;
- `rollback_failed` with residual-hook details after incomplete rollback;
- generation-level `installed` only after every scene succeeds;
- arbitrary scene names;
- explicit Flight Recorder `entryScene` independent of scene order and name.

### Script and protocol tests

- Delete the tests that compare `trace_config.js` and `spawn_trace.js`.
- Add source-level contract checks that `spawn_trace.js` serializes only `config.tracer`, resolves the two new exports, and contains no semicolon configuration encoder.
- Add an opt-in GumJS/Frida host test for response-buffer retry, unchanged-status suppression, warning display, and terminal polling behaviour. This avoids adding Node.js as a default test dependency.
- Update benchmark tests to parse and assert generated JSON rather than search for `scene=...` fragments.
- Update Flight Recorder acceptance tests to parse and assert generated JSON.
- Add a native rejection test for a semicolon request to ensure the removed protocol cannot silently survive as a second configuration path.

Default Python tests keep their current environment profile. Native CTest owns schema and state-machine behaviour. Device- or Frida-runtime-dependent adapter tests remain explicit opt-ins.

### Device acceptance

On the existing debuggable demo APK:

1. Trace one scene configured with `offset`.
2. Trace the same scene configured with `imageBase + address` and verify the normalized runtime address matches.
3. Configure a suspicious mapping and verify that a warning precedes the real hook outcome.
4. Submit invalid JSON after a valid configuration and verify that the valid generation remains usable.
5. Verify that Frida and Logcat report the same generation and stable error code.

## Acceptance Criteria

- The documented Frida command is unchanged.
- A user edits scene addresses in only `scripts/spawn_trace.js`.
- Both locator forms normalize to the same offset when given equivalent values.
- Packed-library mapping anomalies warn and still attempt installation.
- Structurally invalid or arithmetically impossible configuration never changes active state.
- Frida reports configuration acceptance and the eventual per-scene hook outcome without requiring Logcat.
- All repository agents use JSON; no semicolon configuration producer or parser remains.
- Flight Recorder selects its entry scene by name.
- Existing trace formats and artifact conversion remain compatible.
- Native and Python default suites pass, and the new device acceptance procedure is documented and runnable as an opt-in.
