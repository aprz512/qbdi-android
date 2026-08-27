# Task 8 report — qtrace workflow contracts and device gate

## Status

Implemented in the Task 8 file scope. Physical device acceptance is pending on
host tooling, not represented as a passing result.

## RED / GREEN

Python RED was observed with:

```text
python3 -m unittest scripts.tests.test_qtrace_contracts -v
FAILED (errors=4): qtrace_device_acceptance and both schema documents were absent.
```

Kotlin RED was observed with:

```text
./gradlew :app:testDebugUnitTest --no-daemon
FAILED: unresolved junit plus QtraceAcceptanceRequest/QtraceAcceptance symbols.
```

GREEN evidence:

```text
python3 -m unittest scripts.tests.test_qtrace_contracts -v
Ran 5 tests ... OK

./gradlew :app:testDebugUnitTest --no-daemon
BUILD SUCCESSFUL
```

## Delivered

- Versioned strict configuration/status schemas and host tests that compare their
  field sets, enum/version/integer bounds, and status goldens to `qtrace.config`
  and `qtrace.status`.
- A manual-only, explicit-device harness with bounded Gradle, Python, ADB and
  qtrace subprocesses; it waits at most 15 seconds for the fixture baseline,
  retries a one-shot injected read failure, takes the named pull artifact only
  from the validated timed report, compares offset/symbol normalization, checks
  the traced PID remains alive, and runs every manual pull mode.
- Fixture-only Kotlin intent parsing/result JSON tests, `onCreate`/`onNewIntent`
  wiring, atomic fixture result writes, an exit-zero path, and the Flight crash
  path. JNI exposes the noinline timed native oracle, which executes one fixed
  mixing block and one 100 ms sleep per iteration.
- Bounded host CI and README documentation that labels device acceptance as a
  manual pre-release gate.

## Verification

```text
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
Ran 594 tests ... OK (skipped=8)

./gradlew nativeHostTest :app:testDebugUnitTest :app:assembleDebug \
  :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon
BUILD SUCCESSFUL (nativeHostTest: 45/45)
```

## Device acceptance

Read-only checks found online Pixel 6 `192.168.50.149:5555`, `arm64-v8a`, and
`su -c id` returning `uid=0(root)` / Magisk. The host has neither `frida` nor
`lz4` on PATH and neither `ANDROID_NDK_HOME` nor `ANDROID_NDK_ROOT` is set;
the device did not expose a `frida-server` path. Therefore the manual command
is pending and was not run:

```bash
python3 scripts/qtrace_device_acceptance.py --device 192.168.50.149:5555
```

## Remaining risk

The real rooted-device/Frida/LZ4/NDK integration remains unverified until the
pending manual gate can be run. Host fakes cover command construction, bounded
read retry, trusted report artifact selection, and fixture parser behavior.
