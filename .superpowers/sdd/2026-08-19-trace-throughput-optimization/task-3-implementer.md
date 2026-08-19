# Task 3 Implementer Notes

## Files

- Added fixed trace-record and metric definitions in `tracer/src/main/cpp/events/trace_record.h` and `trace_metrics.h`.
- Added the allocation-free `TraceEncoder` interface and implementation.
- Added native encoder coverage and registered it with the CMake test target.
- Registered the portable encoder source in the Android native library.

## RED / GREEN

- RED: the exact instruction-output and undersized-buffer test failed to build because `trace_encoder.h` and `trace_encoder.cpp` did not exist.
- GREEN: implemented two-pass bounded output. The measure pass precedes the write pass, so a capacity failure returns `ok=false` and leaves the caller buffer unchanged.
- Added and verified regressions for the fixed instruction-line limit and saturated cache-hit-rate denominator.

## Verification

- SDK CMake normal native build and CTest: 4/4 tests passed.
- SDK CMake ASan/UBSan build and CTest: 4/4 tests passed without sanitizer diagnostics.
- `./gradlew :app:externalNativeBuildDebug --console=plain`: succeeded for `arm64-v8a`.

## Commit

- `feat: add allocation-free trace encoder`

## Review Repair

- Replaced the saturating cache-total calculation with exact `unsigned __int128` arithmetic for
  the denominator and fractional digits. The regression covers `2^63 + UINT64_MAX` and expects
  `cache_hit_rate=0.333333`; the zero-total result remains `0.000000`.
- Documented the two-pass borrowed-input precondition for module names, decoded instructions, and
  semantic-event string views. Their memory must stay readable and unchanged through both passes.
- Re-ran normal CTest, ASan/UBSan CTest, and the Android `arm64-v8a` native build after the repair.

## Deviations / Risks

- System `cmake` and `ctest` were unavailable; used Android SDK CMake 3.22.1 equivalents.
- The encoder is introduced as a portable, independently tested component; wiring the runner to these records is intentionally outside this task.
