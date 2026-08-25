# Task 8 report — structured configuration documentation and verification

## Status

Task 8 documentation and migration contracts are implemented. Normal interactive
configuration is documented only through the versioned JSON object in
`scripts/spawn_trace.js`; the README preserves the exact Frida command, documents
both locator forms, warning-only mapping diagnostics, strict rejection behavior,
generation/status output, stable codes, Flight entry-scene selection, the vendored
JSON license, and explicit host/device acceptance commands.

The default native and Python suites, Debug/Release Android builds, and the explicit
build-contract integration pass. GumJS and live device acceptance remain
environment-limited as recorded below and are not claimed as coverage.

## Changed files

- `README.md`
- `docs/ida-offsets.md`
- `docs/trace-format.md`
- `scripts/tests/build_contract_integration.py`
- `tracer/src/test/cpp/shadowhook_retention_contract_test.cpp`
- `.superpowers/sdd/2026-08-25-structured-tracer-configuration/task-8-report.md`

The ShadowHook contract file was added to Task 8 scope by controller ruling after
the required native run exposed its stale Task-5 JavaScript assertion. No production
runtime source was changed.

## Contract-first red evidence

The repository contract was added first, then pressure-tested with a temporary
`scene=` mutation in `trace_config.h`. Running the exact Task 8 integration command:

```bash
python3 -m unittest scripts.tests.build_contract_integration -v
```

ran 6 tests and failed the new `scene=` subtest as intended. The same run also
exposed the stale `shadowhook_retention_contract_test` assertion. The temporary
mutation was removed immediately; it is not part of the diff.

After the mutation was removed, the focused permanent contract passed:

```bash
python3 -m unittest \
  scripts.tests.build_contract_integration.StructuredConfigurationContractTests -v
```

Result: 1 test passed.

The first full native rerun supplied the stale-contract RED evidence: 42 of 43
CTest targets passed, while `shadowhook_retention_contract_test` failed because it
required the deleted text
`if (!config.flight.enabled) installModuleObserver`. Per controller ruling, this
was an in-scope Task 8 migration contract, not a production failure.

The migrated contract now asserts the current behavior: `spawn_trace.js` loads the
tracer, configures the ShadowHook companion, submits
`JSON.stringify(config.tracer)`, and starts generation status reads in that order;
the JavaScript path does not install its own module observer. Existing native
callback, trampoline-retention, unhook, and `-z,nodelete` assertions remain intact.

## Green verification evidence

- Focused migrated ShadowHook contract: 1 of 1 CTest target passed.
- `./gradlew nativeHostTest --no-daemon`: 43 of 43 CTest targets passed; 0 failed.
- `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`: 258 tests
  passed; 8 explicit opt-in tests skipped.
- `ANDROID_HOME="${ANDROID_HOME}" python3 -m unittest
  scripts.tests.build_contract_integration -v`: 6 tests passed; 0 failed.
- `./gradlew :app:assembleDebug :tracer:assembleDebug
  :tracer:copyTracerDebug --no-daemon`: build succeeded; 65 actionable tasks,
  60 executed and 5 up-to-date.
- `./gradlew :app:assembleRelease :tracer:assembleRelease --no-daemon`: build
  succeeded; 78 actionable tasks, 72 executed and 6 up-to-date.
- `git diff --check`: exited 0.
- The exact scoped legacy `rg` command reports only deliberate rejection/absence
  assertions under `scripts/tests`; it reports no production or documentation
  legacy reference.

An initial optional Release command included a guessed `:tracer:copyTracerRelease`
task and failed because that task does not exist. The actual requested Release app
and tracer builds were then run with the valid tasks above and passed; the brief's
exact Debug copy command passed unchanged.

## Opt-in and device results

The required GumJS opt-in command was attempted exactly:

```bash
QTRACE_RUN_FRIDA_HOST_TESTS=1 \
  python3 -m unittest scripts.tests.test_spawn_trace_gumjs -v
```

Result: 0 tests ran; setup failed with
`ModuleNotFoundError: No module named 'frida'`. `frida` and `frida-ls-devices`
are also absent from `PATH`.

ADB does see `192.168.50.149:5555`, a Pixel 6 reporting `arm64-v8a` and Android
16. Because neither the Frida CLI nor Python package is installed, the four live
runs (offset, equivalent IDA locator, suspicious-address warning, and invalid JSON
after a valid generation) could not be started. No live generation/error codes or
runtime-address equivalence are claimed. The README contains the complete opt-in
procedure and exact injection/pull commands.

## Acceptance-criteria audit

- Exact Frida command: documented verbatim in README and retained by
  `test_spawn_trace_contract`.
- Sole normal configuration source: documented as `scripts/spawn_trace.js`; the
  new production-source contract rejects legacy producers and the removed parser.
- Equivalent locator normalization: covered by `tracer_configuration_test`; both
  JSON forms and exclusive-end rules are documented in README and
  `docs/ida-offsets.md`.
- Warning-only packed mappings: covered by `module_maps_test` and
  `tracer_entry_proxy_test`; warning codes and continued hook attempts are
  documented.
- Invalid candidates preserve active state: covered by
  `tracer_configuration_test`; strict errors and stable codes are documented.
- Configure/status console behavior: covered by `test_spawn_trace_contract` and
  the migrated ShadowHook ordering contract. Live GumJS rendering was not rerun
  because Frida is unavailable.
- Explicit Flight entry-scene lookup: covered by `capture_coordinator_test` and
  `test_flight_acceptance`; `flight.entryScene` is documented.
- Trace/artifact compatibility: no format implementation changed; the full Python
  conversion/recovery suite passed, and `docs/trace-format.md` explicitly separates
  structured control-plane JSON from unchanged artifact formats.
- Default suite/build gate: native, Python, build-contract, Debug, and Release
  checks passed. Device acceptance is documented but environment-limited.

## Self-review

- The documentation contains one complete `loader`/`tracer` example and identifies
  exactly which object crosses the ABI.
- No synchronization or second normal configuration file is described.
- Addresses are strings, locator forms are mutually exclusive, and ends are
  explicitly exclusive.
- Mapping warnings are not described as schema acceptance, and schema/arithmetic
  failures are not described as warnings.
- Generation-level and per-scene state names match the current serializer and
  GumJS validation sets.
- Transport codes are separated from domain error codes.
- The build contract deliberately excludes trace output such as
  `TRACE_BEGIN scene=` and native log records while covering configuration sources,
  the native ABI adapter, and all three Frida-agent production paths.
- Task 8 changes are documentation and contracts only; no runtime behavior or
  artifact format was modified.

## Concerns

- Live Frida/GumJS and device evidence is unavailable until a compatible Frida
  installation is provided on this host. The connected arm64 device alone is not
  sufficient.
- Android builds emit the existing CMake SDK XML compatibility warning
  (`CXX5304`), but both Debug and Release builds exit successfully.

## Fix round 1

### Review findings addressed

1. README and `docs/ida-offsets.md` now distinguish parse-time locator
   arithmetic errors from runtime `moduleBase + normalizedOffset` overflow. The
   latter occurs after generation publication and ends the scene/generation in
   `hook_failed` with per-scene `ADDRESS_OVERFLOW` and `hookError: 0` (or
   `rollback_failed` if cleanup cannot complete).
2. README documents configure/status-lookup rejection errors as
   `{code, path, message}` and accepted-generation per-scene hook/runtime errors
   as `{code, hookError}` without implying that every error has a JSON path.
3. `scripts/config_retention_acceptance.py` is a concrete opt-in device harness.
   It loads the committed `spawn_trace.js` source with normal startup suppressed,
   invokes `runConfigurationRetentionAcceptance()`, submits the valid
   `config.tracer`, submits malformed `{` in the same process, and queries the
   accepted generation. It duplicates no scene/config object. README gives its
   exact command and keeps the normal Frida command unchanged.
4. The build contract recursively scans owned native `.c/.cc/.cpp/.h/.hpp`
   sources, excluding vendored/build paths, plus all configuration producers for
   legacy parser/export/producer/log patterns. `scene=` remains scoped only to
   configuration producers so trace/log records are valid. The stale production
   log naming the removed configure export now says it is waiting for structured
   JSON configuration.
5. `shadowhook_retention_contract_test` now protects the native accepted-config
   seam directly: inline-hook initialization must precede
   `prepare_module_callbacks()`, which must precede loaded-target observation.
   Existing callback/trampoline retention, unhook, loader ordering, and
   `-z,nodelete` checks remain.

The two ledgered Minor items (`flight.entryScene` when disabled and `0x` prefix
wording) remain deferred and were not changed.

### Red evidence

- Recursive legacy contract: 1 expected failure on
  `tracer/src/main/cpp/tracer_entry.cpp` containing
  `waiting for qbdi_tracer_configure`.
- Retention acceptance contract: 1 expected failure because
  `scripts/config_retention_acceptance.py` did not exist.
- Native callback mutation check: temporarily removing the accepted-config
  `prepare_module_callbacks()` block made the focused CTest abort at
  `prepare_callbacks != std::string::npos`. The production block was restored
  before any permanent implementation edit.

### Green verification

- Focused recursive legacy contract: 1 test passed.
- `scripts.tests.test_spawn_trace_contract`: 4 tests passed.
- Focused `shadowhook_retention_contract_test`: 1 of 1 passed.
- `./gradlew nativeHostTest --no-daemon`: 43 of 43 CTest targets passed.
- `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`: 259 tests
  passed; 8 explicit opt-in tests skipped.
- `ANDROID_HOME="${ANDROID_HOME}" python3 -m unittest
  scripts.tests.build_contract_integration -v`: 6 tests passed.
- Debug app/tracer/copy build: succeeded; 65 actionable tasks, 10 executed and
  55 up-to-date.
- Release app/tracer build: succeeded; 78 actionable tasks, 10 executed and
  68 up-to-date.
- `python3 -m py_compile` for the new harness and changed Python contracts,
  `python3 scripts/config_retention_acceptance.py --help`, and
  `node --check scripts/spawn_trace.js`: exited 0.
- `git diff --check`: exited 0. The scoped textual scan reports only deliberate
  test assertions; the recursive executable contract reports no production
  legacy match.

### Environment limitation and self-review

The GumJS opt-in was attempted again and ran 0 tests because importing `frida`
failed with `ModuleNotFoundError`. Consequently the new device harness was not
executed, and no live preservation result is claimed. Its static contract,
Python compilation/help path, reused `spawn_trace.js` configuration, and GumJS
syntax are verified.

This round changes runtime-owned code only to rename the stale constructor log
and factor the existing tracer-load/helper sequence for reuse by the opt-in
acceptance helper. The normal configuration, exact normal Frida command, hook
semantics, and artifact formats are unchanged. This supersedes the earlier
self-review statements that native log records were outside the legacy scan and
that Task 8 had no runtime-owned source edit.
