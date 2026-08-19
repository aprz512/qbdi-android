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

## Verification

- Baseline before changes: normal native suite 10/10 passed.
- Focused red/green executables: `memory_profile_test`, `instruction_collector_test`, and
  `qbdi_instruction_decoder_test` passed after implementation.
- Normal native suite: 11/11 passed.
- Strict native suite (`-Wall -Wextra -Werror`): 11/11 passed.
- ASan/UBSan native suite: 11/11 passed with leak detection and UBSan halt enabled.
- Android tracer: `./gradlew :tracer:assembleDebug` completed with `BUILD SUCCESSFUL`.
- `git diff --check` passed.

## Commit

- `feat: add configurable memory trace profiles`

## Deviations and Risks

- Extended `trace_record`, `pending_instruction`, and `qbdi_instruction_decoder` in addition to the
  brief's primary file list. These changes carry the copied flags/byte states, make overflow
  sequencing host-testable, and gate formula decoding on the profile.
- QBDI is bundled as an ARM64 static library, so host tests exercise formula, capture, pending,
  and encoder behavior without constructing a host QBDI VM. The Android build validates the real
  collector/QBDI integration. Fixed write-only forms, including Advanced SIMD structure
  post-index forms, use cached formulas because QBDI omits writes from PRE access queries. The
  slow supplement uses QBDI PRE read addresses after cached formulas.
- Unsupported ARM64 memory classes deliberately avoid incomplete formulas. Only four formula/slow
  accesses receive PRE snapshots; later or uncomputable accesses remain ordered and are explicitly
  marked unavailable before bytes.
- Task 8 opcode safe-read/crash-sidecar work was not implemented; the pre-existing opcode fetch is
  unchanged.
