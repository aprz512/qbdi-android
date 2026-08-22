# Task 7 report — capture coordinator and per-thread QBDI sessions

## Result

Implemented one flight artifact per configured run and one retained QBDI VM/session per captured
TID. `CaptureCoordinator` owns the artifact and stable retained-module generation, reuses a session
only for its TID, rejects live-session re-entry, latches incomplete evidence, and makes child detach
non-mutating for inherited artifact/session state. `QbdiThreadSession` owns VM/callback/module/GPR/
memory/target-call setup and publishes the active session through TLS while the VM is admitted.

Normal scene mode now constructs a short-lived `QbdiThreadSession` over the existing
`BinaryTraceWriter`; its native fallback and outward-return behavior remain in `tracer_entry.cpp`.
Flight configuration requires the nonzero `init` scene, allocates the coordinator before inline-hook
initialization, starts the artifact before scene hooks, and routes every configured nonzero scene
through the per-TID session.

## RED

Tests and their CMake targets were added before production files. The first unconfigured build
showed that the new targets did not yet exist:

```text
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target capture_coordinator_test qbdi_thread_session_test
gmake: *** No rule to make target 'capture_coordinator_test'.  Stop.
```

After reconfiguring the host build, the intended compile-time RED was:

```text
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake -S tracer/src/test/cpp -B build/flight-recorder-host-make -G 'Unix Makefiles' -DCMAKE_BUILD_TYPE=Debug
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target capture_coordinator_test qbdi_thread_session_test

CMake Error: Cannot find source file:
  ../../main/cpp/core/qbdi_thread_session.cpp
CMake Error: Cannot find source file:
  ../../main/cpp/core/capture_coordinator.cpp
CMake Error: No SOURCES given to target: qbdi_thread_session_test
CMake Error: No SOURCES given to target: capture_coordinator_test
```

The tests already asserted exact entry/argument/indirect-result/return forwarding, scoped TLS,
recursive call rejection, artifact identity, one-time start, stable module generation, same-TID
reuse, cross-TID separation, permanent incomplete state, idempotent leave, and child detach without
factory mutation.

## GREEN

Final scoped lifecycle/regression run:

```text
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target capture_coordinator_test qbdi_thread_session_test qbdi_runner_lifecycle_test trace_run_session_test tracer_entry_proxy_test failure_state_test -j2
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure -R 'capture_coordinator|qbdi_thread_session|qbdi_runner_lifecycle|trace_run_session|tracer_entry_proxy|failure_state'

100% tests passed, 0 tests failed out of 6
Total Test time (real) = 0.35 sec
```

Fresh full host build and suite:

```text
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make -j2
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure

100% tests passed, 0 tests failed out of 28
Total Test time (real) = 0.92 sec
```

Focused AddressSanitizer/UndefinedBehaviorSanitizer build and run, with production-compatible
exception/RTTI flags treated as warnings-as-errors:

```text
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake -S tracer/src/test/cpp -B build/flight-recorder-host-sanitize -G 'Unix Makefiles' -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -fno-exceptions -fno-rtti -Wall -Wextra -Werror' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-sanitize --target capture_coordinator_test qbdi_thread_session_test tracer_entry_proxy_test -j2
ASAN_OPTIONS=detect_leaks=1 /home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-sanitize --output-on-failure -R 'capture_coordinator|qbdi_thread_session|tracer_entry_proxy'

100% tests passed, 0 tests failed out of 3
Total Test time (real) = 0.07 sec
```

Android production compile check:

```text
./gradlew :tracer:assembleDebug --no-daemon

[2/5] Building CXX object CMakeFiles/qbdi_tracer.dir/core/capture_coordinator.cpp.o
[3/5] Building CXX object CMakeFiles/qbdi_tracer.dir/core/qbdi_thread_session.cpp.o
[4/5] Building CXX object CMakeFiles/qbdi_tracer.dir/tracer_entry.cpp.o
ninja: build stopped: subcommand failed.
```

The Task 7 translation units compiled under Android arm64 with `-std=c++20 -fno-exceptions
-fno-rtti -Wall -Wextra`. The aggregate build remains blocked in the pre-existing Task 4
`flight/flight_artifact.cpp`: NDK 26 libc++ reports `no member named 'atomic_ref' in namespace
'std'`. Task 7 does not modify that file.

## Files and commit

- `tracer/src/main/cpp/core/capture_coordinator.h`
- `tracer/src/main/cpp/core/capture_coordinator.cpp`
- `tracer/src/main/cpp/core/qbdi_thread_session.h`
- `tracer/src/main/cpp/core/qbdi_thread_session.cpp`
- `tracer/src/main/cpp/core/qbdi_runner.cpp`
- `tracer/src/main/cpp/tracer_entry.cpp`
- `tracer/src/main/cpp/CMakeLists.txt`
- `tracer/src/test/cpp/capture_coordinator_test.cpp`
- `tracer/src/test/cpp/qbdi_thread_session_test.cpp`
- `tracer/src/test/cpp/CMakeLists.txt`

`core/qbdi_runner.cpp` is an intentional addition to the brief's enumerated file list: moving the
normal-mode VM path into a short-lived `QbdiThreadSession` cannot be done while leaving the old
runner-owned VM/callback/GPR/memory/target-call implementation in place.

Commit: `5883d85` (`feat(trace): add per-thread QBDI sessions`)

## Self-review and concerns

Normal exec-transfer events still use the existing `emit_exec_transfer_event` and
`BinaryTraceWriter`; callback ordering, module/range selection, full-memory setup, x0-x7/x8/PC/SP
setup, Task 5 `finish_last` post-state, native fallback, and outward return values were preserved.
Flight sessions force the full profile and retain the copied module/ranges for their full lifetime.
Recursive admission records a `CoverageGap` emergency record and permanently marks the artifact
incomplete. Because `FlightIncompleteReason` has no coverage-specific enum, the superblock uses
`WriterFailure` alongside the explicit gap record.

At-fork child handling marks the current and every retained hook-generation coordinator detached;
child dispatch then uses only the retained native original. Coordinator/session destructors and gap
paths perform no inherited artifact or QBDI mutation after detach.

`git diff --check` is clean, and the Task 7 production files contain no exception or RTTI constructs.
The only verification blocker is the upstream Android `std::atomic_ref` incompatibility described
above.

## Completion-review fixes

Independent review initially found coordinator-generation and incomplete-evidence defects. Each
was covered by a new regression before the implementation changed.

Session failure and coordinator-latch RED:

```text
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target qbdi_thread_session_test capture_coordinator_test -j2
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure -R 'qbdi_thread_session|capture_coordinator'

qbdi_thread_session_test: CHECK failed at line 123: execution.gaps == 1
capture_coordinator_test: CHECK failed at line 218: factory.coverage_gaps == 1
0% tests passed, 2 tests failed out of 2
```

Hook/coordinator generation RED:

```text
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target tracer_entry_proxy_test -j2

undefined reference to `trace_proxy_test_set_coordinator(...)'
undefined reference to `trace_proxy_test_hook_coordinator(unsigned long)'
gmake: *** [Makefile:498: tracer_entry_proxy_test] Error 2
```

One-shot artifact-start RED:

```text
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make --target capture_coordinator_test -j2
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure -R '^capture_coordinator_test$'

CHECK failed at line 233: factory.artifact_creates == 1
0% tests passed, 1 tests failed out of 1
```

The fixes explicitly carry each hook generation's coordinator through automatic and deferred
rehooks; route coordinator-owned session gaps through the coordinator; mark failed target calls and
successful calls whose sink/gate failed; and make artifact start a permanent one-shot attempt. The
focused post-fix run passed 3/3, followed by the final scoped, full, sanitizer, and Android compile
checks above.

The re-review reported no remaining Critical or Important findings and approved Task 7. Its only
non-blocking coverage note is that host builds exclude the production QBDI `Impl`; the successful
target plus failed production sink/gate branch is therefore verified by source review and Android
arm64 compilation rather than direct x86 host execution.

## Fix round 1/5 — persistent flight gateways and complete evidence

### RED

The public proxy/coordinator seams first reproduced all three gateway failures independently:

```text
./build/flight-recorder-host-make/tracer_entry_proxy_test flight-hook-failure
CHECK failed at line 937: coordinator->incomplete()
exit 134

./build/flight-recorder-host-make/tracer_entry_proxy_test persistent-flight
CHECK failed at line 982: first_result == 0x133
exit 134

./build/flight-recorder-host-make/tracer_entry_proxy_test module-generation
CHECK failed at line 1010: !trace_proxy_test_update(...)
exit 134
```

The stable-generation/accessor and logical-versus-execution gateway APIs also began compile-red:

```text
capture_coordinator_test.cpp:138: no member named 'copy_module'
capture_coordinator_test.cpp:142,148: no member named 'matches_module'

qbdi_thread_session_test.cpp:139,147: no member named 'call_gateway'
```

The allocation-free flight metadata view and transfer-envelope behavior began compile-red:

```text
flight_trace_sink_test.cpp:61: error: 'FlightTraceContextView' does not name a type
flight_trace_sink_test.cpp:65: error: 'context_view' was not declared in this scope

CMake Error: Cannot find source file:
  ../../main/cpp/core/flight_transfer_event.cpp
CMake Error: No SOURCES given to target: flight_transfer_event_test
```

A final reconfiguration audit added a concurrent-run regression before changing the branch:

```text
./build/flight-recorder-host-make/tracer_entry_proxy_test flight-active-reconfigure
CHECK failed at line 1073: !trace_proxy_test_update(replacement_config, scene, module)
exit 134
```

An active old run can neither be rebound in place nor silently leave a new artifact apparently
complete. The flight update is now rejected, the new coordinator records a gap, and the old
persistent gateway remains installed until a later safe retry.

### Implementation

Flight hooks now remain installed for their complete lifetime. Dispatch separates the configured
logical gateway address from ShadowHook's retained-original trampoline: QBDI instruments the exact
retained module generation and executes the trampoline, so concurrent entrants continue reaching
the proxy and obtain distinct per-TID VMs. Same-target reconfiguration rebinds the persistent slot
under its transition lock; a target move is rejected and records a permanent gap instead of opening
an unhook interval. Normal non-flight unhook/rehook behavior is unchanged.

Hook installation, invalid gateway/range/capacity, module-retention, generation mismatch,
persistent-target change, unavailable trampoline, proxy-runtime allocation, and lifecycle native
bypass paths all route through the coordinator's `CoverageGap` publisher. The artifact's incomplete
bit is permanently latched. Exact module matching includes load range, file offset, pathname,
permissions, and every retained readable-executable range.

Flight transfer callbacks add a fixed-buffer, allocation-free envelope carrying source PC, target,
`x0..x3`, `x8`, and return value. They then use the same JNI/libc/ART semantic handler as normal
mode through the `TraceSink` interface. Normal mode emits only its pre-existing semantic records,
so its QTRB event sequence and bytes do not gain the flight envelope.

`QbdiThreadSession::Impl` now borrows stable coordinator/hook config, module, and scene storage
instead of copying allocation-capable objects in `noexcept` constructors. Flight chunk identity is
initialized from `string_view`/numeric context and copied directly into fixed encoder arrays.
Coordinator setup accepts prepared values before hooks and moves them into retained storage; its
published startup identity fields are atomic, while exact-module snapshots/comparison are locked.

### GREEN and production evidence

Focused regression run:

```text
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure -R 'capture_coordinator|qbdi_thread_session|tracer_entry_proxy|flight_trace_sink|flight_transfer_event|qbdi_runner_lifecycle|trace_run_session|failure_state'

100% tests passed, 0 tests failed out of 8
Total Test time (real) = 0.77 sec
```

Concurrent persistent-gateway stress:

```text
for task7_iteration in {1..100}; do
  ./build/flight-recorder-host-make/tracer_entry_proxy_test persistent-flight || exit 1
done

exit 0
```

Full host build and test suite:

```text
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/cmake --build build/flight-recorder-host-make -j2
/home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-make --output-on-failure

100% tests passed, 0 tests failed out of 29
Total Test time (real) = 0.93 sec
```

ASan/UBSan with production exception/RTTI flags first caught and fixed an unused logging-only
parameter under the host no-op logging macro. The fresh post-fix run was:

```text
ASAN_OPTIONS=detect_leaks=1 /home/lyldalek/Android/sdk/cmake/3.22.1/bin/ctest --test-dir build/flight-recorder-host-sanitize --output-on-failure -R 'capture_coordinator|qbdi_thread_session|tracer_entry_proxy|flight_transfer_event|flight_trace_sink'

100% tests passed, 0 tests failed out of 5
Total Test time (real) = 0.10 sec
```

Android production compilation reached and compiled every changed Task 7 production translation
unit, including the real QBDI session and semantic handler paths:

```text
./gradlew :tracer:assembleDebug --no-daemon

[1/10] core/flight_transfer_event.cpp.o
[2/10] flight/flight_trace_sink.cpp.o
[4/10] core/qbdi_runner.cpp.o
[5/10] core/capture_coordinator.cpp.o
[6/10] flight/flight_encoder.cpp.o
[7/10] core/qbdi_thread_session.cpp.o
[8/10] tracer_entry.cpp.o
[9/10] handlers/call_handlers.cpp.o
```

The aggregate Android target remains blocked only by the pre-existing Task 4/NDK 26 error:

```text
flight/flight_artifact.cpp:14:20: error: no member named 'atomic_ref' in namespace 'std'
ninja: build stopped: subcommand failed.
BUILD FAILED in 21s
```

### Independent completion review

The completion reviewer identified that starting QBDI at ShadowHook's out-of-module original
trampoline could enter native execution before reaching the retained target ranges. The bundled
arm64 ShadowHook implementation reserves an exact 256-byte `sh_enter` slot. The adapter now
publishes that extent, flight QBDI instruments it as the execution gateway, and instruction
pre/post callbacks remain range-bound to the retained target module so trampoline instructions do
not acquire false module-relative identities. The target itself remains instrumented only from the
artifact's exact retained readable-executable ranges.

The reviewer also rejected `VMState::sequenceStart` as a caller-source surrogate and noted that gap
reasons existed only in logs. Flight sessions now retain the last target-range `PREINST` PC and pair
call/return sources with a fixed-capacity per-session stack. A stable `CoverageGapReason` is carried
through coordinator factories and persisted in `FlightEmergencyRecord::flags`; install and native
bypass tests assert distinct reasons.

Fresh post-review verification:

```text
full host: 100% tests passed, 0 failed out of 29 (0.94 sec)
ASan/UBSan + -fno-exceptions -fno-rtti: 100% passed, 0 failed out of 5 (0.10 sec)
persistent-flight loop: 100/100 passed
Android arm64 changed-object compile: 5/5 rebuilt successfully
```
