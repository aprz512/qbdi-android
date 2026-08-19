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
- Second formal re-review exposed the earlier gate's blind window before C++ dispatch, ShadowHook
  trampoline reuse after unhook, a signal-disposition query/use race, retired sidecar pathname
  aliasing, and synthetic `SA_SIGINFO` payload/context loss. The new earliest-entry test initially
  failed to link on absent generation-identity seams. New crash tests then failed the old behavior
  by requiring `EBUSY` during a gated retired handler, same-inode preservation, exact in-process
  info/context pointers, and real `SEGV_ACCERR` address/context payloads.
- The next architectural review found that retaining only ShadowHook's entry trampoline was not
  sufficient when relocated instructions branch through `island_rewrite`, and that global
  `sh_enter_free()` suppression leaked resources for unrelated clients. A focused contract test
  was added first to require normal reclamation and qtrace-only ownership of every executable
  dependency.
- New RED regressions cover a delayed saved `SA_RESETHAND|SA_NODEFER` thunk after a newer generation,
  fork while proxy registration holds the registry lock, fork with an active crash session, and
  repeated artifact reservations without inode/content aliasing.
- Third re-review RED tests selected an old default-action wrapper, installed a newer handler while
  its entry was gated, and reproduced termination from the old thunk's late `sigaction(SIG_DFL)`.
  A child-callback contract test separately failed on mutex unlock/destruction/placement-new, while
  lock-gated fork tests exercised the inherited registry, transition, and crash-session locks.

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
- Every hook installation now consumes a never-reused proxy identity before the target can branch
  to it. The 8-byte ARM64 stub encodes that identity before C++ lookup, and its immutable
  config/scene/module/target generation remains allocated for the process lifetime. A delayed old
  stub therefore cannot resolve a new same-index install. Active updates remain deferred, while a
  pre-dispatch old generation uses its retained original entry. Scene indices remain bounded at
  256; proxy generations are separately bounded at 4096 and fail safely on exhaustion.
- A verified non-null ShadowHook original trampoline is retained with each hook generation, and a
  `RTLD_NOLOAD` guard retains its module mapping. ShadowHook rewritten entries are intentionally
  never returned to its allocator, bounding retained executable storage to roughly 1 MiB. When unhook
  fails, the proxy skips QBDI and calls that bypass through `call_target_arm64` exactly once;
  concurrent failed-unhook entrants keep one active bypass window so no entrant invalidates another
  trampoline. Successful unhook/setup failure calls the direct unhooked target. Rehook failure
  leaves coherent direct-target state and is retried without corrupting a later install.
- `call_target_arm64` saves FP/LR on a 16-byte-aligned stack, preserves its target/argument inputs in
  caller-saved scratch registers, restores `x0`-`x7` and captured indirect-result `x8`, calls with
  `blr`, restores the frame, and returns target `x0`. Fixed 8-byte proxy stubs save `x0`-`x7` and
  original `x8` before entering C++ and derive their immutable generation identity from the stub
  address.
- Instruction fetch now uses `safe_read_memory`. Unreadable instructions emit owned
  `<unreadable>` metadata, and readable zero words use an uncached owned `.inst 0x00000000` path;
  neither changes cache metrics. Unreadable metadata requests the conservative slow memory path
  whenever memory tracing is enabled. When QBDI analysis is absent, the native decoder handles only
  stable NOP, direct B/BL, and RET facts; everything else is honestly `.inst` and uses the slow
  memory path when memory tracing is enabled. No QBDI pointer is retained.
- Each active run exclusively creates `<trace>.crash`. The process admits one active marker session;
  a second
  returns `EBUSY` and falls back natively. Every run receives a distinct, never-reused SA_SIGINFO
  handler thunk and state generation. The handler saves errno, increments its generation's
  lock-free active count, atomically exchanges only that generation's fd, makes exactly one
  fixed-size write attempt, atomically relinquishes only its signal disposition, restores errno,
  and leaves the active count. It performs no close, flush, compression, lock, allocation, or
  logging. No synthetic signal is queued: custom `SA_SIGINFO` actions receive the exact original
  `siginfo_t *` and `ucontext_t *`, with original fault code/address, while mask, automatic
  self-block/`SA_NODEFER`, `SA_RESETHAND`, `SIG_IGN`, and errno semantics are recreated. A saved
  `SIG_DFL` gives the wrapper kernel-owned `SA_RESETHAND`; the thunk only re-raises, preserving
  signal wait status without a late disposition write.
- Teardown atomically claims an untouched fd, or retires a handler-owned fd without spinning.
  Immutable generation state stays valid, and a new session returns `EBUSY` until the entered old
  handler exits. Exclusive creation prevents pathname/inode reuse; cleanup compares the path inode
  with the generation-owned fd before unlinking. Thus a blocking prior handler cannot hold
  `finish()`, while it also cannot overlap a newer crash generation.
- Short write, zero write, and EINTR are deliberately not retried in signal context. Such records
  are invalid; normal teardown removes them, and consumers must accept only exact-size records with
  the stable magic, supported signal, and positive tid. Pull-tool interpretation remains Task 10.
- The entire `test_fail_setup=1` parser branch and field exist only under `#ifndef NDEBUG`. Debug
  parsing activates deterministic setup failure; Release rejects the field as unknown and contains
  neither the option nor injected-failure log string.
- ShadowHook retention is now scoped to a hidden qtrace-only UNIQUE-mode unhook. Normal hooks again
  return entry/island allocations; a bounded 4096-slot qtrace resource moves the ARM64 entry,
  island-enter, and rewrite-island together. Failed retained unhooks keep their task and physical
  switch coherent for retry, and each non-reused generation pins its module until process exit.
- Crash wrappers inherit the prior mask plus kernel-applied `SA_NODEFER` and `SA_RESETHAND`. The
  kernel consumes one-shot disposition state when selecting the wrapper, so delayed old thunks make
  no later disposition write that could clobber a new/external handler.
- Hook and crash globals install `pthread_atfork` lifecycles. Prepare/parent use normal locking;
  child callbacks use only lock-free `sig_atomic_t` state, atomic fd ownership, `close`, and
  `sigaction` restoration—never mutex lifecycle or allocation. Child proxy/API paths detect detach
  before inherited locks and call the generation-retained bypass exactly once; trace setup fails
  safely with `ECHILD`. Parent artifacts remain untouched, inherited sessions are PID-inert, and
  target-initiated fork skips the child proxy postamble before locking.
- Trace paths include a process-local sequence. The writer prepares a path, reserves the crash
  sidecar first, and creates the trace with `O_EXCL`; no collision path uses `O_TRUNC`.

## Verification

- Normal host native build/test: 14/14 passed.
- Strict host native build/test (`-Wall -Wextra -Werror`): 14/14 passed.
- Release host native build/test: 14/14 passed; the always-on Release parser assertion rejects the
  debug-only field.
- ASan+UBSan host native build/test with leak detection and halt-on-error: 14/14 passed.
- Android Debug: `:tracer:assembleDebug` and `:app:assembleDebug` passed.
- Android Release: `:tracer:assembleRelease` and `:app:assembleRelease` passed.
- ARM64 symbol/disassembly inspection found global `call_target_arm64` (52 bytes), a 32768-byte
  fixed-stride proxy-stub region, and the common dispatcher. Release instructions confirm aligned
  FP/LR save/restore, all eight argument loads, original `x8` restore, and `blr` target execution.
- Debug/Release string inspection found the injected-failure log only in Debug and neither the
  option nor injected-failure log in Release.
- The initial focused review passed its narrower concurrency scope; formal review then found the
  seven RED cases recorded above. The first formal re-review reported Ready on those repairs before
  the second review identified the earlier pre-dispatch and signal-retirement architectural gaps.
- Second formal re-review's architectural REDs are covered by the earliest-stub, retained-bypass,
  exact-context, real-fault, retirement, same-path, and generation-exhaustion tests. Focused strict
  proxy races passed 100/100 and crash races passed 20/20 after repair.
- Release symbol inspection shows the qtrace retained-unhook API is local/hidden while normal
  `shadowhook_unhook` remains public; ARM64 bridge/stub disassembly remains ABI-correct.
- Final independent scoped re-review reported Ready with no Critical or Important blockers after
  checking normal-unhook failure cleanup, inherited session destruction, and target-initiated fork.
- Third-review focused races passed proxy/fork 100/100 and crash/signal/fork 50/50; the child
  callback source contract confirms no mutex unlock, destruction, or placement-new remains.
- Final scoped third re-review found no Critical or Important blockers in default forwarding,
  child-callback safety, pre-lock detachment, or exact-once retained bypass execution.
- `git diff --check` passed.
- `adb devices` returned no connected devices. Per the brief, no device fallback-hash result is
  claimed; host seam, Debug/Release compile, and Release disassembly are the available evidence.

## Commit

- `fix: preserve target behavior on trace failures`
- `fix: close trace failure race gaps`
- `fix: retain trace failure generations`
- `fix: preserve trace generations across lifecycle edges`
- `fix: make crash and fork handoff race-safe`

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
- Hook proxy identities and only their qtrace-owned retained ShadowHook resources are never reused.
  Both pools are bounded at 4096; ordinary ShadowHook users retain normal allocator reuse.
  Exhaustion leaves the target unhooked and preserves native execution.
- Pull tooling was intentionally not changed because the task payload assigns interpretation to
  Task 10. The binary record layout and validation helper are stable now.
