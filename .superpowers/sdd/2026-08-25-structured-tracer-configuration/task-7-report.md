# Task 7 report — Flight acceptance JSON configuration

## Status

Complete. The generated Flight acceptance agent now embeds one compact,
versioned JSON request with `init` as the only scene and as the explicit
`flight.entryScene`. It submits that request through
`qbdi_tracer_configure_json` with a fixed 64 KiB response buffer, validates the
complete configure response, and does not register the target observer or
start acceptance when transport, parsing, response-shape, or domain validation
fails.

## Changed files

- `scripts/flight_acceptance.py`
- `scripts/tests/test_flight_acceptance.py`
- `.superpowers/sdd/2026-08-25-structured-tracer-configuration/task-7-report.md`

No Task 8 documentation or build-contract file was changed.

## Design

- `flight_agent_request(scene_offsets, flight_options)` is the single Python
  request builder. It preserves the acceptance package/module, `full` profile,
  disabled compression, Flight sizing, and one nonzero `init` offset.
- `_agent_source` serializes the request with
  `json.dumps(..., separators=(",", ":"), sort_keys=True)` and embeds the result
  directly as a JavaScript object literal, keeping the agent self-contained.
- The generated agent validates transport status, response bounds and NUL
  termination, JSON parsing, the response envelope, rejected-error fields, and
  every documented accepted-response field before observing the target.
- Accepted configuration is included as `configure_response` in
  `flight-agent-ready`. Configure failures emit `flight-agent-error`, which the
  Python mailbox turns into an immediate `AcceptanceError`.
- The existing nonblocking snapshot/oracle/release sequence, target/tracer
  address reporting, crash modes, cleanup, and artifact validation are
  unchanged.

## Red evidence

The request-builder test was added before its implementation:

```bash
python3 -m unittest \
  scripts.tests.test_flight_acceptance.FlightAcceptanceTests.test_flight_request_configures_only_the_explicit_init_entry_scene \
  -v
```

Result: one expected failure, `flight_agent_request is missing`.

After the builder was green, generated-agent and response-path tests were
added against the legacy producer:

```bash
python3 -m unittest scripts.tests.test_flight_acceptance -v
```

Result: 24 tests ran with two expected failures. The source still contained
`scenes=replace`/`scene=` and the Node GumJS harness rejected the legacy
`qbdi_tracer_configure` export.

The mailbox regression was then tightened to require immediate signaling:

```bash
python3 -m unittest \
  scripts.tests.test_flight_acceptance.FlightAcceptanceTests.test_configure_error_message_fails_the_mailbox_immediately \
  -v
```

Result: one expected failure because `flight-agent-error` did not set the
mailbox event.

## Green evidence

- `python3 -m unittest scripts.tests.test_flight_acceptance -v`: 24 tests
  passed.
- `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`: 258 tests
  passed, 7 opt-in tests skipped.
- `python3 -m py_compile scripts/flight_acceptance.py scripts/tests/test_flight_acceptance.py`:
  exited 0.
- Generated `_agent_source(...)` piped to `node --check`: exited 0.
- Node GumJS behavioral test: transport error, malformed accepted response,
  and structured rejection each emitted `flight-agent-error` with zero target
  observers/installs; the accepted response registered one observer and sent
  `flight-agent-ready` containing the parsed configure response.
- Legacy-marker scan for `scenes=replace`, `scene=`, and the exact old configure
  export in `scripts/flight_acceptance.py`: no matches.
- `git diff --check`: exited 0.

## Self-review

- The request has `schemaVersion: 1`, exactly one scene named `init`, a nonzero
  hexadecimal module offset, and `flight.entryScene: "init"`; non-init symbol
  offsets are not serialized.
- The trace/Flight values match the prior acceptance settings: `full`, no
  compression, configured artifact capacity, 256 KiB chunks, 256 threads, and
  four protected chunks.
- Request byte length excludes the trailing NUL. Response size includes and
  verifies the trailing NUL and is bounded by exactly 65,536 bytes.
- A rejected or malformed configure response cannot reach
  `Process.attachModuleObserver`, so it cannot start the acceptance fixture.
- Runtime `acceptance-error`, `acceptance-oracle`, and `acceptance-release`
  semantics remain intact; only configuration transport uses the new
  `flight-agent-ready`/`flight-agent-error` messages required by the brief.
- The legacy semicolon configuration and exact old C export reference are gone
  from the Flight runner, while native legacy-rejection coverage remains
  outside Task 7 and was not modified.
- The diff is limited to Task 7 implementation, tests, and this report.

## Concerns

- Verification is host-side. No Android device or live Frida Flight acceptance
  run was available in this task; device behavior remains covered by the
  repository's existing manual acceptance workflow.

## Fix round 1

### Review findings

1. An accepted response was shape-checked but not cross-checked against its
   request. A wrong target module, empty or extra scenes, or a substituted
   entry-scene name, offset, or end offset could register the target observer
   and emit `flight-agent-ready`.
2. The Node/GumJS behavioral harness ran automatically whenever Node was
   installed instead of following the repository's explicit host-test opt-in
   contract.

The ledgered Minor issue allowing arbitrary `flight_options` keys to override
fixed request fields remains deferred as directed.

### Changes

- Accepted configure responses must name `request.targetModule` and contain
  exactly one normalized scene. That scene must match both the submitted scene
  and `flight.entryScene`, retain the submitted `0x100` offset, and have the
  expected null end offset.
- The executable GumJS regression now includes six adversarial accepted
  envelopes: wrong target, no scenes, an extra scene, wrong entry-scene name,
  wrong offset, and an unexpected end offset. Every case must emit exactly one
  `flight-agent-error` with zero observers and installs.
- The Node test now requires `QTRACE_RUN_FRIDA_HOST_TESTS=1` as well as Node,
  matching the existing opt-in host-test convention. Default discovery skips
  it deterministically.

### Red evidence

Before the production identity checks:

```bash
QTRACE_RUN_FRIDA_HOST_TESTS=1 python3 -m unittest \
  scripts.tests.test_flight_acceptance.FlightAcceptanceTests.test_agent_reports_configure_failures_without_starting_acceptance \
  -v
```

Result: one test ran with six failing subtests. Cases 3 through 8 each observed
one target observer instead of zero, proving every wrong accepted identity
reached the ready path.

### Green evidence

- The explicit opt-in behavioral command above: one test passed; all nine
  failure cases stopped before observer registration and the valid control
  emitted `flight-agent-ready`.
- `python3 -m unittest scripts.tests.test_flight_acceptance -v`: 24 tests ran,
  23 passed and the GumJS behavior test was skipped by the documented opt-in.
- `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`: 258 tests
  ran successfully, with 8 opt-in tests skipped.
- `python3 -m py_compile scripts/flight_acceptance.py scripts/tests/test_flight_acceptance.py`:
  exited 0.
- Generated `_agent_source(...)` piped to `node --check`: exited 0.
- `git diff --check` and `git diff --cached --check`: exited 0.

### Self-review and concerns

- Identity validation occurs after complete accepted-response shape validation
  and before `configureResponse` can satisfy the observer gate.
- Missing/extra scenes cannot bypass the exact cardinality check; a correctly
  shaped but substituted scene cannot bypass name, offset, or end-offset
  equality.
- Default tests no longer depend on Node presence. The explicit opt-in command
  still executes the generated production agent under the Node VM harness.
- Scope remains Task 7 implementation, tests, and this report. Task 8 files
  remain untouched. Live Android/Frida device verification was not performed.
