# Task 8 Implementer Report

## RED

- Added `failure_state_test.cpp` first. Its initial build failed exactly on the absent
  `FailurePoint`, unified fault-injection method, `AsyncTraceWriter::error_code()`, and
  `TextTraceWriter::error_code()` interfaces.
- Added setup/runtime/sidecar failure cases before production changes. They cover buffer and
  compression allocation, synchronization, consumer-thread creation, compression, first write,
  final frame write, metrics-sidecar write, stable first errno, and repeated `finish()`/`close()`.
- Added ARM64 fallback/result-contract use before implementation. The focused build failed on the
  absent `TraceRunResult`, proving that setup failure and a legitimate zero return were not yet
  distinguishable.
- Added safe opcode/fallback tests first. Their initial build failed on the absent safe resolver and
  native ARM64 fallback decoder. The cases require unreadable and zero opcodes to bypass cache
  hit/miss accounting and require owned conservative metadata when QBDI analysis is unavailable.
- Added crash-sidecar tests before its source existed. CMake failed on the absent crash marker
  component. The completed tests fork a child to verify a fixed 12-byte marker and signal re-raise,
  verify empty-marker removal and handler restoration, reject concurrent active runs, and prove
  multiple handled signals produce one record. A later generation-safety RED test captured an old
  handler, opened a new run, and proved the shared-handler implementation could not distinguish a
  delayed old delivery from the new run.
- Added the debug-only configuration assertion before the field/parser branch; the focused build
  failed because `TraceConfig::test_fail_setup` did not exist.
- ARM64 Release disassembly served as an ABI RED check: the first C++ proxy implementation moved
  `x7` into `x8` before the inline capture. It was replaced with assembly entry stubs, and the
  subsequent Release disassembly shows the original `x8` captured before dispatch.
- Independent review exposed further RED conditions: QBDI `call(false)` had been treated as target
  execution, essential callback and memory-registration failures still reached `vm.call`, facade
  `EIO` could mask an async writer errno, signal teardown could overlap handler state, and
  concurrent proxy entrants could race hook state. Final review also found that holding the global
  proxy lock during arbitrary target execution could deadlock independent scenes and that a
  kernel-selected-but-not-yet-entered handler escaped the original quiescence counter. Each was
  repaired before final verification.
- Formal review after the first commit supplied seven new RED cases. A host-linked proxy test
  initially failed on absent registration gates/test seams and now deterministically holds an old
  entrant between registry lookup and registration while a new config/module install races it.
  Additional RED cases cover unhook failure side effects/value/exactly-once execution, concurrent
  bypass lifetime, rehook failure recovery, same-address metadata/module replacement, and the
  256-stub bound.
- Formal signal RED tests reproduced `_exit` instead of `WIFSIGNALED`, incomplete prior-handler
  masks/one-shot semantics, and teardown waiting behind a gated surviving handler. Fork tests now
  cover stale `SIG_DFL`, `SIG_IGN`, `sa_handler`, `sa_sigaction`, `sa_mask`, automatic self-block,
  `SA_NODEFER`, `SA_RESETHAND`, errno, and an empty newer marker. The gated finish test completes
  before the prior handler is released.
- Release parsing and execute-only decode RED tests were written first: Release must reject a
  runtime-constructed debug option, while unreadable instructions in a memory-enabled profile must
  request the slow memory path without changing cache metrics.

## GREEN

- `FailurePoint` now supplies one errno-valued seam for allocation, synchronization, thread
  creation, compression allocation/operation, first write, final compressed-frame write, and
  metrics-sidecar write. Atomic compare/exchange retains the first failure, and all failure paths
  broadcast both writer conditions. Finalization remains idempotent after success or failure.
- `TextTraceWriter` preserves an earlier async error, suppresses/removes metrics after trace-output
  failure, removes partial metrics sidecars, and returns the same result/error on repeated close.
- `TraceRunResult { target_executed, value }` separates setup failure from a real zero. QBDI's
  documented `call()` result (true iff at least one block executed) is the execution boundary.
  Output, crash-sidecar, virtual-stack/GPR, module, essential callback, memory instrumentation, and
  zero-block call failures return `{false, 0}`; runtime writer failures only disable callbacks and
  preserve a successfully executed target's value.
- Proxy entry now performs lookup, active registration, and an immutable
  hook/config/scene/module/target snapshot in one `g_lock -> transition_mutex` transaction, matching
  installer order, before releasing both locks for arbitrary execution. Each installed hook stores
  its matching config generation. Installer updates during an active window are deferred as one
  config/scene/module unit and applied by the final entrant. Same-address updates unhook/reinstall
  rather than preserving a potentially stale module handle. Scene indices at or above 256 are
  rejected before addressing the fixed stub region.
- A verified non-null ShadowHook original trampoline is retained with each live hook. When unhook
  fails, the proxy skips QBDI and calls that bypass through `call_target_arm64` exactly once;
  concurrent failed-unhook entrants keep one active bypass window so no entrant invalidates another
  trampoline. Successful unhook/setup failure calls the direct unhooked target. Rehook failure
  leaves coherent direct-target state and is retried without corrupting a later install.
- `call_target_arm64` saves FP/LR on a 16-byte-aligned stack, preserves its target/argument inputs in
  caller-saved scratch registers, restores `x0`-`x7` and captured indirect-result `x8`, calls with
  `blr`, restores the frame, and returns target `x0`. Fixed 8-byte proxy stubs save `x0`-`x7` and
  original `x8` before entering C++ and derive their scene index from the stub address.
- Instruction fetch now uses `safe_read_memory`. Unreadable instructions emit owned
  `<unreadable>` metadata, and readable zero words use an uncached owned `.inst 0x00000000` path;
  neither changes cache metrics. Unreadable metadata requests the conservative slow memory path
  whenever memory tracing is enabled. When QBDI analysis is absent, the native decoder handles only
  stable NOP, direct B/BL, and RET facts; everything else is honestly `.inst` and uses the slow
  memory path when memory tracing is enabled. No QBDI pointer is retained.
- Each active run pre-opens `<trace>.crash`. The process admits one active marker session; a second
  returns `EBUSY` and falls back natively. Every run receives a distinct, never-reused SA_SIGINFO
  handler thunk and state generation. The handler saves errno, increments its generation's
  lock-free active count, atomically exchanges only that generation's fd, makes exactly one
  fixed-size write attempt, restores the prior action, re-raises, restores errno, and leaves the
  active count. It performs no close, flush, compression, lock, allocation, or logging. Stale
  deliveries are requeued through the kernel with a private token; a newer tracer generation skips
  its fd. Custom and ignored prior actions never replace the process-wide active disposition:
  forwarding explicitly recreates the prior mask, automatic self-block/`SA_NODEFER`,
  `SA_RESETHAND`, `SA_SIGINFO`, and restart/on-stack outer flags. `SIG_DFL` alone installs the true
  default and re-raises, preserving signal wait status/core behavior. If tagged queueing fails, the
  immutable old generation invokes its effective prior action with the same semantics rather than
  emitting an untagged signal that could consume the newer fd. No retired thunk is reinstalled.
- Teardown atomically claims an untouched fd, or retires a handler-owned fd without spinning.
  Immutable generation state stays valid, and later normal open/finish work reaps descriptors only
  after the entered-handler count reaches zero. Thus a blocking/surviving prior handler cannot hold
  `finish()` or the next run hostage, while empty/invalid markers are still removed and exactly one
  valid fixed record is retained.
- Short write, zero write, and EINTR are deliberately not retried in signal context. Such records
  are invalid; normal teardown removes them, and consumers must accept only exact-size records with
  the stable magic, supported signal, and positive tid. Pull-tool interpretation remains Task 10.
- The entire `test_fail_setup=1` parser branch and field exist only under `#ifndef NDEBUG`. Debug
  parsing activates deterministic setup failure; Release rejects the field as unknown and contains
  neither the option nor injected-failure log string.

## Verification

- Normal host native build/test: 13/13 passed.
- Strict host native build/test (`-Wall -Wextra -Werror`): 13/13 passed.
- Release host native build/test: 13/13 passed; the always-on Release parser assertion rejects the
  debug-only field.
- ASan+UBSan host native build/test with leak detection and halt-on-error: 13/13 passed.
- Android Debug: `:tracer:assembleDebug` and `:app:assembleDebug` passed.
- Android Release: `:tracer:assembleRelease` and `:app:assembleRelease` passed.
- ARM64 symbol/disassembly inspection found global `call_target_arm64` (52 bytes), a 2048-byte
  fixed-stride proxy-stub region, and the common dispatcher. Release instructions confirm aligned
  FP/LR save/restore, all eight argument loads, original `x8` restore, and `blr` target execution.
- Debug/Release string inspection found the injected-failure log only in Debug and neither the
  option nor injected-failure log in Release.
- The initial focused review passed its narrower concurrency scope; formal review then found the
  seven RED cases recorded above. Final formal re-review reported Ready with no remaining Critical
  or Important blockers; its focused strict crash-forwarding and proxy tests also passed.
- `git diff --check` passed.
- `adb devices` returned no connected devices. Per the brief, no device fallback-hash result is
  claimed; host seam, Debug/Release compile, and Release disassembly are the available evidence.

## Commit

- `fix: preserve target behavior on trace failures`
- `fix: close trace failure race gaps`

## Deviations and Risks

- Added focused `crash_marker.{h,cpp}` files beyond the brief's enumerated files so the signal
  lifecycle can be host-tested without linking the ARM64-only QBDI runner.
- Replaced generated C++ proxy functions with one assembly stub region after Release disassembly
  proved compiler scheduling could corrupt the incoming `x8`. The 8-byte stride is an explicit
  shared ABI constant and is covered by symbol/disassembly inspection rather than executable host
  tests because the host is x86_64.
- Memory instrumentation registration failure now counts as pre-execution VM setup failure and
  selects native fallback, superseding Task 7's earlier “run under QBDI with failed trace” session
  expectation. This follows Task 8's stricter before-`vm.call` contract.
- The signal handler makes one write attempt as required. POSIX permits EINTR/short writes, so a
  crash that terminates immediately after such a rare result can leave an invalid partial record;
  its stable validation contract ensures it is never reported as a crash marker. No unsafe retry
  or cleanup call is made from signal context.
- Signal handler generations are intentionally never reused because POSIX can select a handler and
  deschedule before its first instruction. The bounded pool admits 1024 runs per process; exhaustion
  is a deterministic `ENOSPC` trace-setup failure and therefore preserves the target through native
  fallback instead of risking a stale handler touching newer state.
- Pull tooling was intentionally not changed because the task payload assigns interpretation to
  Task 10. The binary record layout and validation helper are stable now.
