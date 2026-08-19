# Task 7 Implementer Report

## RED

- Added `memory_profile_test.cpp` before production changes. Its first build failed on the absent
  `MemoryOperand`, effective-address, bounded formula-cache, safe byte-state, value-truncation,
  and extended memory-encoding interfaces.
- Added pending-memory and decoder-profile tests before their implementations. Their first build
  failed on the absent fixed memory attachment API and memory-gated decoder overload.
- Added review-driven regression cases before fixes. They failed on the absent lossless
  continuation API; the SIMD slow-path and `MEMORY_MINIMUM_SIZE` cases also failed against the
  then-current behavior.
- After the formal review, added policy-level regressions before the repair. The initial build
  failed because the QBDI-independent policy seam and focused ARM64 source did not exist. Follow-up
  RED cases exposed aggregate 64-byte capture, non-temporal-pair writeback reporting, the honest
  per-operand bound, and registration-failure final-status/sidecar behavior.
- Independent repair review added three final RED slices: mixed-PC continuation filtering failed to
  compile without a policy-owned filter, registration failure lacked a connected runner-outcome
  scenario, and unconditional metadata broke the pre-existing format-2 exact encoder tests.
- The formal re-review required a production runner seam. Its RED test failed at configuration
  because `trace_run_session` did not exist; the public-cohesion compile test then failed because
  focused ARM64 operand and memory-type headers did not exist.

## GREEN

- Cached at most four fixed ARM64 memory formulas with base/index registers, LSL/UXTW/SXTW/SXTX,
  bounded shift, signed displacement, access kind/size, address mode, and writeback metadata.
- Implemented wrapping effective-address and writeback calculations for offset, pre-index, and
  post-index forms, including SP, PC-relative literals, absent registers, and XZR indexes.
- Decoded common literal, pair, exclusive/atomic, unsigned-immediate, signed-immediate, and
  register-offset ARM64 forms. Unsupported or excess formulas are marked for the slow path.
- Kept fast mode free of QBDI memory recording/callback registration and memory-formula decoding.
  Balanced and full enable QBDI read/write recording and the post-instruction memory callback.
- Matched QBDI accesses to the pending instruction by `instAddress`; copied access type, flags,
  address, size, and width-safe value. The first eight accesses stay on the instruction record;
  later accesses are emitted as immediate `MEM` continuations in QBDI order.
- In full mode, captured bounded pre-read/pre-write bytes from formula addresses. Slow formulas use
  QBDI's PRE memory-access addresses. Post-write bytes use the actual post-callback address. Every
  byte read goes through `safe_read_memory`, is capped by `min(size, hexdump_limit, 64)`, and records
  explicit unavailable state.
- Added exact encoding for `r`, `w`, and `rw`, raw flags, `pre=`, `post=`, and unavailable markers.
- Checked QBDI recording and callback registration failures and latched trace failure instead of
  silently producing memory-free balanced/full traces.
- The formal-review repair splits each retained formula into the exact consecutive, at-most-8-byte
  accesses emitted by QBDI. Four 64-byte architectural operands therefore fit a fixed 32-entry PRE
  policy with the hexdump limit applied independently to each actual access. Accesses beyond that
  explicit bound remain ordered with unavailable PRE bytes.
- Added exact formulas for STNP mode 0 and Advanced SIMD single-structure/lane forms, including
  immediate/register post-index writeback. Moved ARM64 formula decoding out of the cache source and
  moved matching/capture into a fixed QBDI-independent policy seam.
- PRE formula capture now runs after a continuing PRE CodeRule and before pending begin/input
  register capture. STOP/BREAK clears PRE policy state and creates no pending instruction. Fast
  performs neither policy work nor QBDI memory setup.
- Replaced the dual character/numeric memory type with one `MemoryAccessKind`, and centralized the
  bounded hexadecimal-byte encoder. An explicit `metadata_available` boundary preserves legacy
  format-2 memory lines while QBDI records carry flags and PRE/POST fields.
- Memory instrumentation setup failure now contributes to the final failed trace status while the
  target return value is preserved. Failed traces do not publish a success metrics sidecar.
- Expected-PC filtering is policy-owned and host-tested with a wrong-PC access injected between 11
  accepted accesses; the accepted records retain exact 8-attached plus 3-continuation order.
- `TraceRunSessionOutcome` now owns trace setup, memory registration, target result/return value,
  footer status, end/close finalization, completion/log decision, and returned value. The QBDI
  runner consumes those decisions directly. Its connected production-seam test runs the target
  after registration failure, preserves return value 73, writes a failed footer, publishes no
  metrics sidecar, and selects the error-log decision.
- Public declarations now match source ownership: memory kinds/byte state live in `memory_types.h`,
  capture/truncation APIs in `memory_capture.h`, ARM64 formula layout in
  `arm64_memory_operand.h`, and decoder entry points in `arm64_memory_decoder.h`.
  `instruction_cache.h` retains only cache-owned interfaces/data. Cached layout is unchanged.

## Verification

- Baseline before changes: normal native suite 10/10 passed.
- Focused red/green executables: `memory_profile_test`, `instruction_collector_test`, and
  `qbdi_instruction_decoder_test` passed after implementation.
- Normal native suite: 11/11 passed.
- Strict native suite (`-Wall -Wextra -Werror`): 11/11 passed.
- Release native suite: 11/11 passed.
- ASan/UBSan native suite: 11/11 passed with leak detection and UBSan halt enabled.
- Android tracer: `./gradlew :tracer:assembleDebug` completed with `BUILD SUCCESSFUL`.
- `git diff --check` passed.
- Independent repair re-review reported no Critical or Important findings and `Ready: yes`.

## Commit

- `feat: add configurable memory trace profiles`
- Repair: `fix: repair memory trace profile policy`
- Connected runner repair: `fix: connect trace runner finalization`

## Deviations and Risks

- Extended `trace_record`, `pending_instruction`, and `qbdi_instruction_decoder` in addition to the
  brief's primary file list. These changes carry the copied flags/byte states, make overflow
  sequencing host-testable, and gate formula decoding on the profile.
- QBDI is bundled as an ARM64 static library, so host tests exercise formula, capture, pending,
  and encoder behavior without constructing a host QBDI VM. The Android build validates the real
  collector/QBDI integration. Fixed write-only forms, including Advanced SIMD structure
  post-index forms, use cached formulas because QBDI omits writes from PRE access queries. The
  slow supplement uses QBDI PRE read addresses after cached formulas.
- Unsupported ARM64 memory classes deliberately avoid incomplete formulas. The policy retains up
  to eight QBDI-sized accesses for each of four formulas (32 total); later or uncomputable accesses
  remain ordered and are explicitly marked unavailable before bytes.
- Task 8 opcode safe-read/crash-sidecar work was not implemented; the pre-existing opcode fetch is
  unchanged.
