# Multi-thread Crash Flight Recorder Design

Date: 2026-08-21
Status: Approved for implementation planning

## Context

The current tracer installs inline hooks at configured `module + scene offset` entry points. Each
hook invocation creates one QBDI run, writes one append-only trace artifact, and finishes when the
target function returns. The crash marker can recover complete frames from an invocation that is
already being traced, but it cannot identify an unknown protection thread whose checks run much
later or after nondeterministic network activity.

The target failure is long-running and random. A second deterministic reproduction cannot be
assumed. Capturing every instruction from every native module is unnecessary, but the recorder must
retain the most recent complete trace window for every thread owned by the target protection
library. The implementation must use QBDI; Frida Stalker, perf, CoreSight ETM, and kernel tracing
are not part of the first version.

## Goals

- Start tracing before the target protection library's initialization entry executes.
- Trace the target library's init path and every native worker thread created by that path or by
  already-traced target code.
- Trace only instructions in the target module. Preserve external call boundaries and selected
  arguments without tracing external modules instruction by instruction.
- Retain a bounded, crash-recoverable window per captured thread for an arbitrarily long process
  lifetime.
- Record the current `full` profile memory semantics plus general-register checkpoints and deltas.
- Identify the initiating TID and original target PC when target code directly invokes an exit- or
  signal-related syscall.
- Coexist with protection-library signal handlers without exposing the tracer handler through
  target-side `rt_sigaction` installation or queries.
- Recover useful committed records after fatal signals, `exit_group`, or `SIGKILL`, including when
  no finalization code runs.
- Keep the capture core independent from the injection mechanism so a future kernel-assisted
  dynamic injector can provide takeover opportunities without changing the trace format.

## Non-goals

- Coordinating artifacts across multiple Android processes.
- Reconstructing execution that occurred before spawn-time initialization and target takeover.
- Tracing every instruction in libc, ART, JNI, or unrelated native modules.
- Supporting a late attach mode with the same coverage guarantee as spawn-before-load.
- Surviving device power loss. The persistence contract covers process termination while the
  kernel and filesystem remain running.
- Hiding the tracer signal handler from code outside the captured target module that independently
  reads the real kernel signal action.
- Recording instructions executed inside an asynchronously invoked protection-library signal
  handler. The broker preserves its ABI-visible delivery semantics but dispatches it natively.
- Recording relocated instructions in an inline-hook retained-original trampoline. QBDI may keep
  that trampoline under execution control, but collection resumes only after execution returns to
  the target module; the overwritten entry prologue is intentionally omitted.
- Replacing QBDI with another execution engine.

## Coverage Contract

"All threads" means all threads belonging to the target protection library, not every thread in
the Android process. A capture is complete only when it includes:

1. the configured target init/constructor invocation;
2. every thread whose start routine is inside the target module;
3. every thread created while its creator is executing inside a target QBDI session; and
4. every thread that enters an explicitly configured target callback gateway.

Existing unrelated ART, Binder, and application threads are not automatically taken over. If they
can enter the target library later, the relevant JNI or callback entry must be configured as an
additional inline-hook gateway. The host must never label an artifact complete if a required
gateway, QBDI session, thread directory entry, or signal compatibility operation failed.

The reliable first-version mode requires spawn injection and tracer initialization before the
target init entry. Late attach may be added later only as an explicitly degraded mode that covers
subsequent gateway entries.

## Approaches Considered

### Always-on full flight recorder — selected

Every captured target thread continuously runs its target code through QBDI and writes full events
to a bounded persistent ring. This is the only approach that preserves the details preceding a
random one-time crash. It has the highest execution and storage overhead, which is accepted for
this feature.

### Layered capture

Record only control flow until a network, validation, or termination trigger promotes capture to
the full profile. This reduces overhead but cannot recreate the registers and memory values used by
checks that completed before promotion. It remains a configurable diagnostic mode, not the default
or acceptance path.

### Locate first, trace on a second run

Use a lightweight first run to identify a suspicious thread and a second run to trace it deeply.
This is simpler but unsuitable because the triggering execution is random and may require a long
network-dependent runtime.

## Architecture

The feature adds the following bounded components:

- `CaptureCoordinator` owns the run, module generation, gateway installation, thread registry,
  recorder mapping, and completeness state.
- `InitHookGateway` redirects the configured init entry through the existing generation-safe inline
  hook proxy model.
- `ThreadCreateGateway` keeps a process-wide `pthread_create` hook installed and substitutes a
  tracer thread trampoline for target-owned workers.
- `CallbackGateway` applies the same proxy mechanism to explicitly configured JNI or native
  callback entries.
- `QbdiThreadSession` owns one thread's QBDI VM, register state, collector, and trace sink. A VM is
  never shared between threads.
- `FlightRecorder` owns the mmap artifact, thread directory, chunk allocator, per-thread writers,
  and emergency signal slots.
- `SignalBroker` virtualizes target-side signal registration and dispatch while retaining one
  tracer-visible kernel handler.
- Host recovery validates and merges committed chunks into a cross-thread trace, per-thread traces,
  and a machine-readable summary.

`TakeoverProvider` is the narrow abstraction between capture and injection. The first provider is
spawn injection plus inline hooks. A future kernel-assisted provider may supply module and thread
contexts through the same coordinator without changing `QbdiThreadSession`, `FlightRecorder`, or
the artifact protocol.

## Entry and Thread Lifecycle

The tracer installs `SignalBroker` and `ThreadCreateGateway` before invoking or releasing the
target init entry. `InitHookGateway` then runs the retained-original path to the original return
address under QBDI control. Target-internal calls remain in the same session.

Flight gateways remain hooked for their process lifetime. Their retained-original trampolines are
admitted to QBDI only to preserve execution control and are excluded from instruction, register,
and memory collection. No trampoline-to-logical-PC relocation map is required. The trace resumes at
the first instruction that re-enters the target module, and omission of the overwritten prologue is
an explicit coverage boundary rather than a `COVERAGE_GAP`.

`ThreadCreateGateway` wraps `pthread_create` when either condition holds:

- the supplied start routine belongs to the retained target module range; or
- the creator's TLS points to an active target QBDI session.

The wrapper retains the original start routine, argument, creator TID, module generation, and
capture run ID. The new thread trampoline registers its real TID, writes `THREAD_BEGIN`, creates its
own `QbdiThreadSession`, and executes the original routine with ABI-identical arguments. A normal
return writes `THREAD_END` and seals the active chunk.

The tracer observes `pthread_exit` and installs a pthread cleanup handler so explicit exit and
cancellation can publish a terminal event. Correct recovery never depends on those paths running.
A fatal signal or direct exit syscall may leave the thread directory active and the current chunk
unsealed; record-level commit markers remain authoritative.

A nested callback on a thread with an active session reuses that thread runtime. The implementation
must not recursively invoke the same VM. A re-entry that QBDI cannot safely resume is executed
through the retained original target and publishes `COVERAGE_GAP`, making the artifact incomplete.

Fork behavior retains the current main-process-only contract. At-fork preparation makes recorder
state consistent. The child closes inherited recorder descriptors, detaches from capture, and calls
retained original targets without touching inherited QBDI or allocator state.

## QBDI Collection Semantics

Each captured thread has one primary VM. Collection callbacks accept only retained executable
ranges of the target module. A retained hook trampoline may additionally be admitted as a control-
only execution range but emits no trace records. Calls into other external modules execute without per-instruction collection, while
execution-transfer events retain the call target, source PC, selected arguments, and return value
when available.

The default flight profile emits:

- every target instruction and its original module-relative identity;
- call, return, JNI/libc semantic, rule, error, and syscall events;
- every QBDI memory access with kind, address, size, flags, and bounded pre/post bytes, matching the
  current `full` profile;
- checkpoints containing `x0`-`x30`, `sp`, `pc`, and `nzcv` at thread start and every chunk start;
  and
- register deltas after instructions that change the recorded general-register state.

SIMD/FP register serialization is not part of the first artifact contract. QBDI still preserves
all architectural state required for correct execution.

## Persistent Ring Artifact

Each process preallocates one app-private mode-`0600` artifact:

```text
<run_id>_<pid>_<target>.flight.bin
```

The default capacity is 512 MiB and is configurable. The file contains:

1. a versioned superblock with run ID, PID, target identity, module generation, configuration,
   completeness flags, and region offsets;
2. a fixed thread directory with 256 entries by default;
3. a fixed pool of 256 KiB data chunks; and
4. fixed emergency slots that never require allocation or chunk rotation.

Thread and capacity limits are configurable before mapping. Exceeding either limit publishes an
emergency error, records the affected TID, and marks the run incomplete. It must not silently drop a
thread while preserving a complete status.

### Allocation and fairness

Each thread writes only to its currently owned chunk. It enters the allocator only on chunk
rotation. The newest four chunks per active thread are protected by default, providing a 1 MiB
minimum retained window per thread. Unprotected chunks form the shared capacity. When no free chunk
remains, the allocator reclaims the globally oldest unprotected chunk. Default capacity therefore
supports the minimum reservation for all 256 directory entries while retaining approximately half
the file for shared history and metadata.

Chunk ownership contains a generation number. A reclaimed chunk increments its generation before
new publication, so stale directory references cannot be mistaken for current data.

### Record commit protocol

A record writer reserves contiguous bytes in its thread-owned chunk, writes the header and payload,
computes the record checksum, and finally publishes a fixed commit word with release semantics.
Readers accept a record only when its generation, bounds, commit word, and checksum are valid. A
process crash may leave one torn final record; readers discard it and retain all preceding committed
records.

Every event has a monotonically allocated process-wide sequence and a thread-local sequence. The
process-wide sequence defines merge order; it represents recorder publication order rather than a
claim about simultaneous CPU execution.

A sealed chunk stores its valid length, first and last global sequence, record count, and checksum.
An active unsealed chunk is recovered by scanning its consecutive valid commit words.

### Independent decoding

The current QTRB run-scoped dictionary cannot be used unchanged because ring overwrite could remove
a definition while retaining its references. Every flight chunk is independently decodable:

- it starts with thread/module/profile metadata and a complete general-register checkpoint;
- instruction and string identifiers are chunk-local;
- definitions are emitted in the same chunk before first reference; and
- no event in one chunk depends on a definition in another chunk.

Device-side flight artifacts are not compressed. Compression is applied only after host recovery.

## Direct Syscall and Termination Capture

Function hooks for `abort`, `raise`, `kill`, or similar wrappers are not a correctness mechanism.
Protection libraries commonly issue arm64 syscalls directly.

Before each target `svc`, the QBDI callback reads the original instruction PC, `x8`, and syscall
arguments. For `exit`, `exit_group`, `kill`, `tkill`, `tgkill`, and `rt_sigqueueinfo`, it commits a
`TERMINATION_INTENT` to the calling thread's emergency slot before allowing the syscall to execute.
The record contains the initiating TID, original target PC, syscall number, target PID/TID, signal,
arguments, and global sequence.

This captures target-issued `SIGKILL` and `exit_group`, for which no later handler can run. A
`SIGKILL` delivered by the kernel, OOM killer, debugger, or another unobserved process has no
observable in-process initiator. The host reports its cause as unknown while still recovering the
last committed windows.

## Signal Broker and Protection-handler Compatibility

Installing an ordinary tracer crash handler after the protection handler would overwrite it;
installing before it would let the protection overwrite the tracer. The broker therefore retains
one kernel-visible master handler and virtualizes target-side signal actions.

Before target init, the broker installs master handlers for configured catchable fatal and control
signals and saves incumbent process actions. If target code later registers another catchable
signal, the broker installs and publishes that signal's master handler before accepting the guest
action. When target code executes a direct `rt_sigaction` syscall under QBDI:

- a set operation updates the lock-free guest action table but leaves the master kernel action in
  place;
- a query returns the guest-visible handler, flags, mask, and restorer; and
- the emulated result and errno match the kernel ABI.

The guest table supports normal handlers, `SA_SIGINFO`, `SIG_DFL`, `SIG_IGN`, `SA_NODEFER`,
`SA_RESETHAND`, handler masks, and restorer semantics. Updates block the affected signal while the
broker changes its guest action. The broker's own raw signal syscalls bypass QBDI virtualization to
avoid recursion.

The master handler performs only bounded async-signal-safe work before dispatch: it writes the
fixed emergency slot, reads an atomically published guest action, and prepares the guest-visible
delivery. It performs no allocation, locking, compression, ordinary logging, or chunk rotation.

For a guest custom handler, dispatch must preserve the guest action and signal-mask semantics. The
guest `siginfo_t` remains unchanged. If the signal interrupted QBDI code-cache execution, the
guest-visible `ucontext` must contain the corresponding original target PC and guest register state,
not code-cache or tracer addresses. A default fatal action is reproduced by installing the real
default action with a raw syscall and redelivering the same signal to the same thread.

A guest custom handler is invoked directly as native code and is intentionally not instrumented.
The master handler must never enter QBDI through `VM::callA`, `VM::run`, or another execution API.
It records fixed-size `SIGNAL_HANDLER_BEGIN` state before dispatch and
`SIGNAL_HANDLER_RETURN` state if the handler returns, so recovery never implies that the
unrecorded handler body was part of a contiguous instruction trace. This explicit interval is part
of the recorder contract and does not make the run incomplete. If a returning handler changes its
guest `ucontext`, the broker copies the supported register changes back to the interrupted thread's
published guest state before returning to QBDI execution. The first version supports all general
register fields in the artifact contract: `x0`-`x30`, `sp`, `pc`, and `pstate`/`nzcv`; a mapping
failure is a compatibility failure and marks the run incomplete.

`SIGKILL` cannot be brokered. Target-issued `SIGKILL` is covered only by the pre-syscall terminal
record and the persistent ring.

## Host Recovery and Output

The pull path recognizes `.flight.bin` independently of normal `.trace.bin.lz4` artifacts. The host
recovery process:

1. validates the superblock, region bounds, target identity, PID, run ID, and configuration;
2. validates thread-directory and chunk generations;
3. decodes sealed chunks and scans committed prefixes of active chunks;
4. rejects torn records and invalid checksums without reading beyond a committed boundary;
5. expands chunk-local dictionaries and register deltas;
6. merges accepted events by process-wide sequence; and
7. calculates retained ranges, overwritten ranges, coverage gaps, and terminal candidates.

It publishes:

- one merged cross-thread text trace;
- one text trace per captured TID;
- a JSON summary containing the initiating-thread candidate, final observed signal, last-recorded
  thread, target PCs, retained windows, overwritten counts, recovery damage, and completeness; and
- an optional host-compressed copy of the original artifact.

Absence of a terminal marker is not corruption. It is reported as `termination_cause=unknown` and
the committed trace is still published. A checksum failure inside a previously sealed chunk is
corruption; that chunk is excluded and the summary identifies the lost sequence interval.

## Failure Policy

Runtime behavior is fail-open, but evidence status is fail-closed.

- If hook, mmap, thread registration, QBDI setup, writer, signal virtualization, or handler-context
  mapping fails, the target continues through the retained original path where safely possible.
- The first failure assigned to an emergency slot publishes a specific `COVERAGE_GAP` and
  permanently marks the run incomplete. Later failures assigned to the same occupied slot increment
  a dropped-gap counter without overwriting the first root-cause record.
- Host tooling refuses to label an incomplete run as full coverage.
- Failure to write even the emergency state is surfaced in logcat and host-side artifact validation;
  it is never converted into a successful empty trace.
- Signal-broker compatibility is tracked per signal. A failure lists the signal, TID, original PC,
  and failed phase when those values are safely available.
- Normal recorder shutdown is idempotent. Crash recovery never requires normal shutdown.

## Testing

### Recorder unit tests

- record commit, torn final record, invalid bounds, checksum failure, and generation mismatch;
- chunk wrap, global-oldest reclamation, and four-chunk per-thread protection;
- thread-directory exhaustion and artifact incompleteness;
- chunk-local dictionary independence after arbitrary older chunks are overwritten;
- register checkpoint/delta reconstruction; and
- active and sealed chunk recovery.

### Thread and QBDI integration tests

- init execution followed by multiple target-owned workers;
- start routine inside the target and wrapper start routine created by an active target session;
- nested thread creation, normal return, `pthread_exit`, cancellation, and nested callback entry;
- one VM per TID and no recursive reuse of a running VM;
- external call boundaries without external-module instruction events;
- explicit coverage-gap behavior for setup and re-entry failures; and
- current fork and child-detach regression contracts.

### Signal contract tests

A target fixture uses direct arm64 syscalls rather than libc wrappers to:

- install, query, replace, ignore, reset, and restore signal actions;
- exercise normal and `SA_SIGINFO` handlers, masks, `SA_NODEFER`, and `SA_RESETHAND`;
- deliver asynchronous signals while target code is in QBDI code-cache execution;
- trigger synchronous `SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`, and `SIGTRAP` cases supported by the
  device;
- verify that handler-visible PC and general registers match the original guest instruction state;
- verify that target-side queries never expose the tracer master handler or code-cache addresses;
- deliver nested signals during ordinary recording and chunk rotation; and
- prove that a target-resident protection handler is dispatched natively, its untraced interval is
  explicit, and the master handler never enters a QBDI execution API.

Failure of the last three properties blocks release of the feature as transparent recorder
coverage.

### End-to-end acceptance

A demo protection workload starts multiple workers, performs randomized delayed network-like work,
and selects a random worker to issue a direct `tgkill`, `exit_group`, synchronous fault, or
`SIGKILL`. Tests run long enough to force multiple complete ring rotations.

For every observable target-issued syscall, recovery must identify the initiating TID and original
target PC and publish decodable per-thread and merged traces through the last committed records. An
external `SIGKILL` must recover committed windows without inventing an initiator. Every captured
thread retains at least its configured protected chunk count. Any deliberately injected hook,
writer, VM, directory, or signal-broker failure must yield an incomplete artifact with a specific
coverage gap.

## Implementation Boundaries

The current append-only writer, QTRB converter, crash marker, proxy generation lifecycle, and fork
handling provide reusable behavior and tests, but the flight recorder is a separate sink and wire
protocol. It must not overload normal `TRACE_END` semantics or pretend a ring artifact is an
append-only QTRB stream.

The implementation should first prove native broker dispatch and guest-ucontext mapping with a
focused fixture. The fixture must exercise a signal delivered while QBDI is active and demonstrate
that the master handler performs no QBDI execution call. That gate resolves the highest technical
risk before building the full ring and host tooling.
