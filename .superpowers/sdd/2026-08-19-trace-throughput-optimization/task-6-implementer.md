# Task 6 Implementer Report

Base: `a0c77499a16c7c3c41b13a3f1c3eec49a74a74d9`

## RED

- Added the pending collector test first. Native compilation failed on the missing
  `core/pending_instruction.h`, as required.
- Added ordering and W/X-width tests; compilation failed on the absent completion seam and alias
  metadata.
- Added ARM64 QBDI branch-unit tests; compilation failed on the absent safe conversion helper.
- Added mixed read/write alias tests; compilation failed on the shared-name representation.
- Added a QBDI `InstAnalysis` decoder test; compilation failed on the absent decoder boundary.

## GREEN

- Implemented a QBDI-free, fixed-record pending state machine. PRE N completes N-1, first PRE emits
  nothing, and `finish_last` emits the final record. Only decoded-mask registers are read/copied.
- Added an owned, bounded QBDI decoder and O(1) opcode-cache integration. Cache hits return before
  analysis; misses request exactly instruction, disassembly, and operand analysis.
- Preserved owned mnemonic/disassembly/operand/register metadata, ARM64 W/X widths, separate
  read/write aliases, LR/SP/NZCV/PC indices, condition and call/branch/return flags, and signed
  word-to-byte branch displacement conversion.
- Completed pending output before cache lookup, preventing collision replacement from mutating the
  borrowed decoded record. Cache-disabled and insertion-failure paths use one owned scratch entry.
- Migrated `CodeRuleContext` atomically to `InstructionView`. Previous output completes before a
  current pre-rule mutation; current inputs snapshot after the mutation. Rule VM actions survive
  trace-writer failure.
- Registered one unconditional PRE callback. POST is conditional on
  `requires_immediate_post()`. Fast profile registers neither memory recording nor a memory
  callback. The last record flushes after `vm.call` and before `writer.end`.

## Verification

- Normal native: 10/10 CTest tests passed.
- Strict native (`-Wall -Wextra -Werror`): 10/10 passed.
- ASan/UBSan with leak detection: 10/10 passed.
- `./gradlew :tracer:assembleDebug :app:assembleDebug`: passed.
- `git diff --check`: passed.
- Independent review found two Important ARM64 issues (branch scaling and mixed aliases); both were
  fixed test-first. Re-review found no remaining Critical or Important findings.
- Device smoke: not run; `adb devices -l` reported no attached device.

## Commit

`perf: collect instructions with one pre callback`

Follow-up repair: `fix: count instruction cache lookups once`

## Formal Review Repair

- RED: added a combined cache/QBDI-decoder seam test. Compilation failed because
  `InstructionCache::resolve` did not exist.
- GREEN: added `resolve` plus non-accounting `populate_after_miss`. One cold lookup now records one
  miss and one decoder/analysis call; the hot lookup records one hit and no decoder call; a cold
  collision records one additional miss and one collision. Existing accounting `insert` behavior
  and tests remain unchanged.
- The production collector uses the tested combined seam. Disabled caches and failed population
  return the owned decoded scratch value after one accounted miss.
- Fresh normal, strict, and ASan/UBSan native matrices passed 10/10; tracer and app debug assemblies
  passed. Follow-up independent review found no Critical or Important findings.
- Unreadable-PC recovery remains assigned to Task 8.

## Deviations and Risks

- Added a small `qbdi_instruction_decoder` source/test boundary beyond the brief's enumerated files
  so QBDI metadata conversion is host-testable without linking the ARM64 QBDI library.
- An exploratory `-Wpedantic -Werror` build fails on the repository's existing intentional
  `unsigned __int128` formatter. The reported strict gate uses `-Wall -Wextra -Werror`.
- Native unreadable-PC recovery remains deferred to Task 8. Task 6 performs `memcpy` only under the
  QBDI PRE valid-instrumented-PC contract; zero PC bypasses the read and cache insertion.
- Balanced/full memory detail was not expanded. Their existing memory event behavior remains; fast
  profile avoids all memory instrumentation.
- No final performance claim is made without device evidence.
