# Task 6 report — benchmark JSON configuration

## Status

Complete. The benchmark host now builds a versioned request dictionary and
injects its compact, sorted JSON representation into one unquoted agent
placeholder. GumJS resolves the benchmark offset at runtime, submits the
request through `qbdi_tracer_configure_json` with a fixed 64 KiB response
buffer, and stops with `benchmark-error` on transport, malformed response, or
domain rejection before installing the target hook or invoking the benchmark.

## Changed files

- `scripts/benchmark_trace.py`
- `scripts/benchmark_trace.js`
- `scripts/tests/test_benchmark_trace.py`
- `.superpowers/sdd/2026-08-25-structured-tracer-configuration/task-6-report.md`

No Task 7 or Task 8 files were changed.

## Red evidence

Before production edits, the new helper test was run alone:

```bash
python3 -m unittest \
  scripts.tests.test_benchmark_trace.OptimizedMetricsParserTests.test_builds_the_structured_benchmark_agent_request \
  -v
```

Result: one expected failure because `benchmark_agent_request` did not exist.

The full focused suite was then run against the legacy producer:

```bash
python3 -m unittest scripts.tests.test_benchmark_trace -v
```

Result: 48 tests ran and the suite failed with 4 failures and 3 errors. The
failures identified the missing helper/placeholder contract and the retained
`scene=` configuration; the errors came from trying the new request/injection
interfaces against the old implementation.

Independent review later identified that an `ok: true` response with the wrong
response schema could reach installation. A regression assertion was added
first and failed because `response.responseSchemaVersion !== 1` was absent.

## Green evidence

- `python3 -m unittest scripts.tests.test_benchmark_trace -v`: 48 tests passed.
- `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`: 254 tests
  passed, 7 opt-in tests skipped.
- `python3 -m py_compile scripts/benchmark_trace.py scripts/tests/test_benchmark_trace.py`:
  exited 0.
- `node --check scripts/benchmark_trace.js`: exited 0.
- Generated-agent syntax check, piping `configure_agent_source(...)` into
  `node --check -`: exited 0.
- Stubbed GumJS execution probe: 4/4 cases passed. Transport error, structured
  rejection, and response-schema mismatch each emitted `benchmark-error`
  without install/call; the accepted response preserved install/call/result.
  Every case observed the runtime `0x40` offset and 65,536-byte capacity.
- `git diff --check`: exited 0.

## Implementation notes

- `benchmark_agent_request` preserves the existing profile selection,
  `legacy` compression disablement, and optional 4 KiB/fail-setup controls.
  Debug keys are omitted unless requested.
- The request contains the complete schema required by native validation:
  schema version, package/module, trace and disabled-flight options, and the
  single benchmark scene with placeholder offset `0x0`.
- `configure_agent_source` requires exactly one `__QTRACE_CONFIG_JSON__` token
  and replaces that JavaScript expression directly with
  `json.dumps(..., separators=(",", ":"), sort_keys=True)`. It does not replace
  text inside a JSON string.
- GumJS mutates only the benchmark scene offset before `JSON.stringify`, uses
  the explicit request byte length, validates transport/result sizing and NUL
  termination, then validates response schema/object/boolean shape and
  `response.ok` before installation.

## Self-review

- The checked-in agent and generated source contain neither `scene=` nor
  `__QTRACE_TEST_CONFIG__`; the old configure export is not referenced.
- Compression remains enabled for normal optimized runs and disabled for
  `legacy=True`, matching the previous behavior rather than reviving the
  removed wire protocol.
- Setup-failure and 4 KiB buffer injection are represented only by the native
  Debug schema fields and retain their independent/combined behavior.
- Response capacity is fixed at exactly 64 KiB; response-too-small and all
  other nonzero transport results follow the error path without retry.
- Independent review's sole Important finding (response-envelope validation)
  was fixed with a failing regression first. Re-review reported it resolved
  and found no new Critical or Important issue.
- The diff is limited to the requested Task 6 implementation/tests/report.

## Concerns

- Verification is host-side. No Android device/Frida benchmark was run in this
  task, so actual device behavior remains covered by the repository's existing
  manual benchmark workflow rather than this host session.

## Fix round 1

### Review finding

The initial envelope guard accepted any object with response schema version 1
and boolean `ok`. Consequently, a malformed accepted response such as
`{"responseSchemaVersion":1,"ok":true}` reached `install()` and the benchmark
call despite omitting the documented generation, state, target module, scenes,
and warnings.

### Changes

- Added a self-contained configure-response validator following the established
  `spawn_trace.js` contract. It validates the response envelope and rejected
  error shape, plus positive integer generation, exact `waiting_for_module`
  state, non-empty target module, scenes/warnings arrays, normalized scene
  fields, and warning entries for accepted responses.
- Added a Node-based behavioral GumJS regression that executes the generated
  production agent with fake native boundaries. Seven malformed accepted
  envelopes cover missing fields, wrong generation/target/scenes/warnings
  types, wrong state, and an invalid normalized-scene offset. Every malformed
  case must emit `benchmark-error` with zero install/call counts. A complete
  accepted envelope remains the positive control and must install/call/result.
- The behavioral test skips when Node is absent, so Node remains optional for
  the default Python suite as required by the global plan.

### Red evidence

Before the production fix:

```bash
python3 -m unittest \
  scripts.tests.test_benchmark_trace.OptimizedMetricsParserTests.test_benchmark_agent_rejects_malformed_accepted_responses_before_execution \
  -v
```

Result: one test ran with 7 failing subtests. Every malformed envelope recorded
`installs == 1`, proving it reached installation and benchmark execution.

### Green evidence

- The focused behavioral command above: 1 test passed; all 7 malformed cases
  stopped and the complete accepted control executed.
- `python3 -m unittest scripts.tests.test_benchmark_trace -v`: 49 tests passed.
- `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`: 255 tests
  passed, 7 opt-in tests skipped.
- `python3 -m py_compile scripts/benchmark_trace.py scripts/tests/test_benchmark_trace.py`:
  exited 0.
- `node --check scripts/benchmark_trace.js`: exited 0.
- Generated-agent syntax check through `node --check -`: exited 0.
- `git diff --check`: exited 0.

### Self-review and concerns

- Validation occurs immediately after JSON parsing and before the existing
  `response.ok !== true` rejection branch, target installation, NativeFunction
  creation for the benchmark, and benchmark invocation.
- Each accepted field serialized by native configuration is type/shape checked;
  malformed rejection objects also fail closed as `benchmark-error`.
- Independent review reported READY with no Critical, Important, or Minor
  findings and confirmed the executable regression reaches the real configured
  agent source.
- Scope remains Task 6: only the benchmark agent, its test, and this report are
  changed. Verification remains host-side; no Android device run was performed.
