# Qtrace Stopped Trace Format Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an unambiguous, fully validated QTRB v1.2 stopped terminal, metrics v3 sidecar, and text format 4 while retaining read compatibility with all existing artifacts.

**Architecture:** Extend the wire encoder and `BinaryTraceWriter` first, then teach the single Python decoder and sidecar validator the same terminal model. Keep completed and stopped terminals mutually exclusive; expose one normalized `TraceTerminal` to conversion and pull code so later native-stop work does not duplicate format rules.

**Tech Stack:** C++20, QTRB/LZ4, POSIX files, Python 3 standard library, `unittest`, CMake/CTest, Gradle.

## Global Constraints

- Android scope remains `arm64-v8a`, API 24+, C++20, `-fno-exceptions`, and `-fno-rtti`.
- QTRB v1.2 uses `required_features = 0x00000001`, record type 10 `TRACE_STOP`, flags zero, and a 96-byte payload.
- The payload order is `reason u8`, seven zero bytes, then eleven little-endian `u64`: `elapsed_ms`, `instructions`, `encoded_bytes`, `compressed_bytes`, `cache_hits`, `cache_misses`, `cache_collisions`, `buffer_swaps`, `producer_waits`, `producer_wait_ns`, and `effective_buffer_bytes`.
- `TRACE_STOP.reason = 1` means `duration_elapsed`; zero is invalid and values 2 through 255 are reserved.
- `TRACE_STOP.encoded_bytes` includes its 104 record bytes and `compressed_bytes` uses the existing final-artifact size convention.
- Metrics v3 always contains `termination`, `return_valid`, and `return`; stopped uses `return_valid=0` and `return=0x0`.
- New readers continue to accept QTRB v1.0/v1.1 and metrics v1/v2; old readers may reject v1.2 but must never silently misread it.
- Failed and crashed traces do not receive a fabricated terminal.
- Preserve existing atomic publication, crash-marker, and no-overwrite behavior.

## File Structure

- `events/binary_trace_format.*` and `events/binary_trace_encoder.*` own only QTRB wire constants and byte encoding.
- `events/binary_trace_writer.*` owns writer lifecycle, exactly-one terminal emission, and metrics-v3 sidecar publication.
- `scripts/trace_binary.py` is the single binary decoder and normalizes all supported versions into `TraceTerminal`/text format 4.
- `scripts/trace_metrics.py` parses versioned sidecars; `scripts/trace_convert.py` cross-validates them against the decoded terminal.
- `scripts/pull_trace.py` maps normalized termination into pull results without duplicating wire parsing.
- Native/Python tests freeze golden bytes, corruption rejection, compatibility, and publication behavior; `docs/trace-format.md` is the human wire reference.

---

### Task 1: Freeze QTRB v1.2 Constants and Golden Encoder Bytes

**Files:**
- Modify: `tracer/src/main/cpp/events/binary_trace_format.h:12-133`
- Modify: `tracer/src/main/cpp/events/binary_trace_encoder.h:24-58`
- Modify: `tracer/src/main/cpp/events/binary_trace_encoder.cpp:486-506`
- Test: `tracer/src/test/cpp/binary_trace_encoder_test.cpp`

**Interfaces:**
- Consumes: existing `TraceMetrics` field order.
- Produces: `TraceStopReason`, `kBinaryTraceStopPayloadBytes`, `kBinaryTraceStopRecordBytes`, and `BinaryTraceEncoder::encode_stop(uint8_t *, size_t, TraceStopReason, uint64_t, const TraceMetrics &) noexcept`.

- [ ] **Step 1: Write the failing golden-byte test**

Add a test that names every required wire value and checks the complete record:

```cpp
void stopped_terminal_has_exact_v12_golden_bytes() {
    TraceMetrics metrics{};
    metrics.instructions = 2;
    metrics.encoded_bytes = 0x68;
    metrics.compressed_bytes = 0x70;
    uint8_t bytes[kBinaryTraceStopRecordBytes]{};
    const BinaryEncodeResult result = BinaryTraceEncoder{}.encode_stop(
            bytes, sizeof(bytes), TraceStopReason::DurationElapsed, 17, metrics);
    CHECK(result.ok);
    CHECK(result.size == 104);
    CHECK(bytes[0] == 10 && bytes[1] == 0);       // type
    CHECK(bytes[2] == 0 && bytes[3] == 0);        // flags
    CHECK(bytes[4] == 96 && bytes[5] == 0);       // payload bytes
    CHECK(bytes[8] == 1);                         // duration_elapsed
    for (size_t i = 9; i < 16; ++i) CHECK(bytes[i] == 0);
    CHECK(bytes[16] == 17);                       // elapsed_ms, LE
    CHECK(bytes[24] == 2);                        // instructions, LE
    CHECK(bytes[32] == 0x68);                     // encoded_bytes, LE
    CHECK(bytes[40] == 0x70);                     // compressed_bytes, LE
}
```

Call it from the test executable's `main()` next to the existing `encode_end` tests.

- [ ] **Step 2: Run the encoder target and verify the test fails**

Run:

```bash
./gradlew buildNativeHostTests --no-daemon
```

Expected: compilation fails because `TraceStopReason`, `kBinaryTraceStopRecordBytes`, and `encode_stop` do not exist.

- [ ] **Step 3: Add the exact wire declarations**

In `binary_trace_format.h`, set the minor and required feature, add the enum value, and freeze sizes:

```cpp
inline constexpr uint8_t kBinaryTraceMinorVersion = 2;
inline constexpr uint32_t kBinaryStoppedTerminalFeature = 1U << 0U;
inline constexpr uint32_t kBinaryRequiredFeatures =
        kBinaryStoppedTerminalFeature;

enum class BinaryRecordType : uint16_t {
    // existing values unchanged
    TraceEnd = 9,
    TraceStop = 10,
};

enum class TraceStopReason : uint8_t {
    DurationElapsed = 1,
};

inline constexpr size_t kBinaryTraceStopPayloadBytes = 96;
inline constexpr size_t kBinaryTraceStopRecordBytes =
        kBinaryRecordHeaderBytes + kBinaryTraceStopPayloadBytes;
static_assert(kBinaryTraceStopRecordBytes == 104);
```

Declare and implement `encode_stop`. Write reason, seven reserved zero bytes, elapsed, and the eleven `u64` counters in the spec order. Reject any reason other than `DurationElapsed`.

- [ ] **Step 4: Run the encoder test**

Run:

```bash
./gradlew nativeHostTest --no-daemon
```

Expected: all native tests pass, including the v1.2 header and 104-byte stopped-terminal golden bytes.

- [ ] **Step 5: Commit the wire contract**

```bash
git add tracer/src/main/cpp/events/binary_trace_format.h \
  tracer/src/main/cpp/events/binary_trace_encoder.h \
  tracer/src/main/cpp/events/binary_trace_encoder.cpp \
  tracer/src/test/cpp/binary_trace_encoder_test.cpp
git commit -m "feat(trace): encode stopped terminal"
```

### Task 2: Seal a Writer with a Stopped Terminal and Metrics v3

**Files:**
- Modify: `tracer/src/main/cpp/events/binary_trace_writer.h:16-80`
- Modify: `tracer/src/main/cpp/events/binary_trace_writer.cpp:520-629`
- Test: `tracer/src/test/cpp/binary_trace_writer_test.cpp`

**Interfaces:**
- Consumes: `BinaryTraceEncoder::encode_stop` and `TraceStopReason` from Task 1.
- Produces: `BinaryTraceWriter::stop(TraceStopReason reason, long elapsed_ms)` and a v3 sidecar for both completed and stopped traces.

- [ ] **Step 1: Add failing writer lifecycle tests**

Add one uncompressed and one compressed test with these assertions:

```cpp
CHECK(writer.begin(context));
CHECK(writer.instruction(context, instruction(1, &decoded)));
CHECK(writer.stop(TraceStopReason::DurationElapsed, 17));
CHECK(writer.stop(TraceStopReason::DurationElapsed, 17)); // idempotent
CHECK(!writer.end(0x55, true, 18));
CHECK(writer.close());
CHECK(count_type(record_types(decoded_bytes), BinaryRecordType::TraceStop) == 1);
const std::string metrics = read_text(std::string(writer.path()) + ".metrics");
CHECK(metrics.find("metrics_version=3\n") != std::string::npos);
CHECK(metrics.find("termination=stopped\n") != std::string::npos);
CHECK(metrics.find("return_valid=0\nreturn=0x0\n") != std::string::npos);
```

Retain an existing completed-writer assertion, but update it to require `termination=completed` and `return_valid=1`.

- [ ] **Step 2: Run the native suite and verify red**

Run `./gradlew nativeHostTest --no-daemon`.

Expected: compile failure on `BinaryTraceWriter::stop` or assertion failure on metrics v3.

- [ ] **Step 3: Refactor terminal finalization once**

Introduce one private helper so completed and stopped paths cannot drift:

```cpp
enum class TraceTermination : uint8_t { None, Completed, Stopped };

bool BinaryTraceWriter::finalize_terminal(
        TraceTermination termination, TraceStopReason stop_reason,
        uint64_t retval, bool ok, long elapsed_ms) {
    const size_t bytes = termination == TraceTermination::Stopped
                                 ? kBinaryTraceStopRecordBytes
                                 : kBinaryTraceEndRecordBytes;
    // drain, snapshot metrics, compute final target/padding, encode exactly one terminal
}

bool BinaryTraceWriter::stop(TraceStopReason reason, long elapsed_ms) {
    if (termination_ == TraceTermination::Stopped) return true;
    if (termination_ != TraceTermination::None) return false;
    return finalize_terminal(TraceTermination::Stopped, reason, 0, false, elapsed_ms);
}
```

Replace `successful_end_` with `termination_`, `return_valid_`, and `stop_reason_`. Publish a sidecar whenever the trace has either valid terminal and the trace file finished successfully. Keep the existing first-error behavior.

- [ ] **Step 4: Write metrics v3 in a fixed key order**

At the beginning of `write_metrics_sidecar()`, emit:

```cpp
write_unsigned_metric(fd, "metrics_version", 3) &&
write_string_metric(fd, "termination",
                    termination_ == TraceTermination::Stopped
                            ? "stopped" : "completed") &&
write_unsigned_metric(fd, "return_valid", return_valid_ ? 1 : 0) &&
write_hex_metric(fd, "return", return_valid_ ? retval_ : 0)
```

Then emit the existing profile, counters, and rates. Ensure a sidecar write failure removes only the sidecar, preserves the trace artifact, and returns the latched writer error.

- [ ] **Step 5: Run native tests**

Run `./gradlew nativeHostTest --no-daemon`.

Expected: all native tests pass; compressed and raw stopped artifacts contain one terminal and one v3 sidecar.

- [ ] **Step 6: Commit writer termination**

```bash
git add tracer/src/main/cpp/events/binary_trace_writer.h \
  tracer/src/main/cpp/events/binary_trace_writer.cpp \
  tracer/src/test/cpp/binary_trace_writer_test.cpp
git commit -m "feat(trace): seal stopped artifacts"
```

### Task 3: Decode QTRB v1.2 into One Normalized Terminal Model

**Files:**
- Modify: `scripts/trace_binary.py:17-145,318-660`
- Modify: `scripts/tests/test_trace_binary.py:11-290`

**Interfaces:**
- Consumes: exact record constants from Task 1.
- Produces: public frozen dataclass `TraceTerminal` and `ConversionStats.termination: str` used by conversion, pull, and reports.

- [ ] **Step 1: Add stopped-stream fixtures and failing parser tests**

Add helpers matching the wire spec:

```python
TRACE_STOP = struct.Struct("<B7x" + "Q" * 11)

def stopped(*, encoded_bytes: int, compressed_bytes: int) -> bytes:
    values = (1, 17, 1, encoded_bytes, compressed_bytes, 9, 1, 0, 2, 0, 0, 4096)
    return record(10, TRACE_STOP.pack(*values))
```

Build a v1.2 stream with `features=1`; assert text format 4 contains:

```python
"TRACE_END status=stopped reason=duration_elapsed return_valid=0"
```

Also test bad reason zero, nonzero reserved bytes, wrong payload size, a record after stop, stop under minor 1, missing feature bit, and v1.0/v1.1 compatibility.

- [ ] **Step 2: Run the focused Python tests and verify red**

Run:

```bash
python3 -m unittest scripts.tests.test_trace_binary -v
```

Expected: v1.2 is rejected as an unsupported minor or type 10 is rejected.

- [ ] **Step 3: Introduce `TraceTerminal` and parse the feature matrix**

Replace the private `_Footer` with:

```python
@dataclasses.dataclass(frozen=True, slots=True)
class TraceTerminal:
    termination: str
    reason: str | None
    return_valid: bool
    return_value: int
    elapsed_ms: int
    instructions: int
    encoded_bytes: int
    compressed_bytes: int
    cache_hits: int
    cache_misses: int
    cache_collisions: int
    buffer_swaps: int
    producer_waits: int
    producer_wait_ns: int
    effective_buffer_bytes: int
```

Change `_ConversionDetails.footer` to `terminal`. Accept `(minor, features)` only as `(0, 0)`, `(1, 0)`, or `(2, 1)`. Parse type 9 as completed and type 10 as stopped; both set the terminal-seen guard. Return `ConversionStats(..., termination=terminal.termination)`.

Extend the public result without changing the existing field order:

```python
@dataclasses.dataclass(frozen=True)
class ConversionStats:
    instructions: int
    converted_text_bytes: int
    partial: bool
    termination: str | None
```

Use `None` only for permitted partial/crash recovery with no terminal; completed and stopped streams always return their normalized string.

- [ ] **Step 4: Emit text format 4 without fabricating crash/failure terminals**

Render completed and stopped separately:

```python
if terminal.termination == "completed":
    line = f"TRACE_END status=completed return_valid=1 return=0x{terminal.return_value:x} ..."
else:
    line = "TRACE_END status=stopped reason=duration_elapsed return_valid=0 ..."
```

Update `TRACE_BEGIN format=4`. Partial crash conversion remains terminal-free and gets its crash meaning only from the pull/recovery layer.

- [ ] **Step 5: Run focused and full Python suites**

Run:

```bash
python3 -m unittest scripts.tests.test_trace_binary -v
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

Expected: all tests pass; every successful conversion emits text format 4, including QTRB v1.0/v1.1 inputs. Binary compatibility means old streams remain readable, not that the converter emits obsolete text headers.

- [ ] **Step 6: Commit decoder support**

```bash
git add scripts/trace_binary.py scripts/tests/test_trace_binary.py
git commit -m "feat(trace): decode stopped terminals"
```

### Task 4: Validate Metrics v3 Against the Terminal

**Files:**
- Modify: `scripts/trace_metrics.py:1-143`
- Modify: `scripts/trace_convert.py:73-113,150-176`
- Modify: `scripts/benchmark_trace.py:38-69,393-400,859-905`
- Test: `scripts/tests/test_trace_metrics.py`
- Test: `scripts/tests/test_trace_convert.py`
- Test: `scripts/tests/test_benchmark_trace.py`

**Interfaces:**
- Consumes: `TraceTerminal` and `_ConversionDetails.terminal` from Task 3.
- Produces: `parse_metrics()` dictionaries with `termination: str`, `return_valid: int`, canonical hexadecimal `return: str`, and version-aware byte/rate fields.

- [ ] **Step 1: Add strict v3 sidecar tests**

Create completed and stopped v3 fixtures. Assert stopped parses only with:

```text
metrics_version=3
termination=stopped
return_valid=0
return=0x0
```

Add negative cases for `return_valid=1`, nonzero return, missing termination, unknown termination, v3 on a text-v1 artifact, and counter mismatch with `TRACE_STOP`.

Pin the stopped invariants directly:

```python
metrics = parse_metrics(STOPPED_V3.encode("ascii"))
self.assertEqual("stopped", metrics["termination"])
self.assertEqual(0, metrics["return_valid"])
self.assertEqual("0x0", metrics["return"])
with self.assertRaisesRegex(ValueError, "stopped.*return_valid"):
    parse_metrics(STOPPED_V3.replace("return_valid=0", "return_valid=1").encode("ascii"))
```

In `test_benchmark_trace.py`, add a completed metrics-v3 binary fixture and assert `ensure_metrics_container`, `require_binary_acceptance_candidate`, and the binary conversion branch accept it. Keep a metrics-v2 fixture proving legacy benchmark artifacts remain accepted. Update the text semantic oracle fixture to `TRACE_BEGIN format=4` and `TRACE_END status=completed return_valid=1 return=...`.

- [ ] **Step 2: Run metrics/conversion tests and verify red**

Run:

```bash
python3 -m unittest scripts.tests.test_trace_metrics scripts.tests.test_trace_convert -v
python3 -m unittest scripts.tests.test_benchmark_trace -v
```

Expected: `unsupported metrics_version` or unknown-key failures.

- [ ] **Step 3: Generalize version tables without weakening older versions**

Implement explicit contracts:

```python
elif version_text == "3":
    version = 3
    integer_fields, rate_fields = V2_INTEGER_FIELDS, V2_RATE_FIELDS
    required = {
        "metrics_version", "termination", "return_valid", "return",
        "profile", *integer_fields, *rate_fields,
    }
```

Require termination in `("completed", "stopped")`; completed requires return-valid one, stopped requires zero and canonical `0x0`. Update `expected_rates()` so versions 2 and 3 both use `encoded_bytes`.

- [ ] **Step 4: Cross-check sidecar and terminal fields**

Update `_validate_sidecar()` to compare:

```python
expected = {
    "metrics_version": 3,
    "termination": terminal.termination,
    "return_valid": int(terminal.return_valid),
    "return": f"0x{terminal.return_value:x}" if terminal.return_valid else "0x0",
    "instructions": terminal.instructions,
    # all remaining counters unchanged
}
```

Keep the existing artifact-size and compression-container checks.

Update benchmark version dispatch explicitly:

```python
if version in (2, 3) and artifact.endswith((BINARY_TRACE_SUFFIX, BINARY_RAW_SUFFIX)):
    # use convert_binary_file and the streaming semantic oracle
elif version == 1 and artifact.endswith(TEXT_TRACE_SUFFIX):
    # legacy text path
else:
    raise RuntimeError("metrics/container version mismatch")
```

Require metrics v3 for newly generated candidate artifacts while accepting checked-in metrics-v2 baselines for comparison. Teach the format-4 footer parser the `completed`/`return_valid=1` spelling; a stopped benchmark cannot satisfy the existing returned-value oracle and is rejected by that command.

- [ ] **Step 5: Run the full Python suite**

Run `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`.

Expected: all tests pass, including mixed-generation rejection and atomic no-publication on mismatch.

- [ ] **Step 6: Commit sidecar validation**

```bash
git add scripts/trace_metrics.py scripts/trace_convert.py scripts/benchmark_trace.py \
  scripts/tests/test_trace_metrics.py scripts/tests/test_trace_convert.py \
  scripts/tests/test_benchmark_trace.py
git commit -m "feat(trace): validate metrics v3"
```

### Task 5: Route Stopped Artifacts Through Pull and Document Compatibility

**Files:**
- Modify: `scripts/pull_trace.py:81-118,269-430`
- Modify: `scripts/tests/test_pull_trace.py`
- Modify: `docs/trace-format.md`
- Modify: `README.md:305-359`

**Interfaces:**
- Consumes: `ConversionStats.termination`, v3 metrics, and format-4 conversion.
- Produces: `PullResult.status == "stopped"` with exit code zero for a valid stopped artifact.

- [ ] **Step 1: Add a pull integration test for stopped output**

Construct a raw v1.2 stopped stream and matching v3 sidecar. Assert:

```python
result = pull_artifact_set(client, name, client.files, root)
self.assertEqual(0, result.exit_code)
self.assertEqual("stopped", result.status)
self.assertIn("status=stopped", (root / "run.trace.txt").read_text())
```

Add a mismatch test proving a stopped sidecar cannot accompany completed QTRB.

- [ ] **Step 2: Run pull tests and verify red**

Run `python3 -m unittest scripts.tests.test_pull_trace -v`.

Expected: stopped is reported as complete or the v3 sidecar is rejected.

- [ ] **Step 3: Propagate normalized termination**

Map `ConversionStats.termination` directly:

```python
status = "stopped" if stats.termination == "stopped" else "complete"
return PullResult(EXIT_OK, status, outputs)
```

Do not modify crash-truncation rules: a crash-marked partial remains exit code 2 and status `crashed`.

- [ ] **Step 4: Update format documentation with exact bytes and matrix**

Document stream minor/feature combinations, type 10, the 96-byte payload table, metrics v3 keys, text format 4 terminals, and this matrix:

```text
QTRB 1.0/1.1 + metrics v2 -> completed legacy input, readable
QTRB 1.2 type 9 + metrics v3 -> completed
QTRB 1.2 type 10 + metrics v3 -> stopped
truncated + valid crash marker -> recovered/partial, no fabricated terminal
```

- [ ] **Step 5: Run complete verification**

Run:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
./gradlew nativeHostTest --no-daemon
./gradlew :tracer:assembleDebug :tracer:copyTracerDebug --no-daemon
```

Expected: Python and native suites pass; Android tracer builds; `out/arm64-v8a/libqbdi_tracer.so` exists.

- [ ] **Step 6: Commit integration and docs**

```bash
git add scripts/pull_trace.py scripts/tests/test_pull_trace.py \
  docs/trace-format.md README.md
git commit -m "docs(trace): define stopped artifact semantics"
```
