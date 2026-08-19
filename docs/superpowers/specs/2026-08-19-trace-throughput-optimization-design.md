# QBDI Trace Throughput Optimization Design

Date: 2026-08-19

## Goal

Increase instruction-trace throughput without replacing QBDI or breaking the target function's
observable behavior. On the same device, build, target, input, and trace profile, the optimized
`balanced` path should be at least five times faster than the current implementation. The default
`fast` path should aim for at least one million traced instructions per second; this is a target,
not a guarantee across every Android device.

The tracer remains human-readable after decompression. LZ4 frame fast compression is enabled by
default. The design keeps event collection separate from encoding so a binary format can be added
later without another QBDI collector rewrite.

## Decisions

- Keep QBDI as the execution engine and preserve CodeRule, JNI, libc, and execution-transfer
  behavior.
- Optimize for speed. Trace fields may be disabled through explicit profiles.
- Use `fast` as the default profile and disable memory-access tracing by default.
- Use adaptive double buffering: normally 2 x 64 MiB, with 2 x 128 MiB on high-memory devices or
  when explicitly configured.
- Compress on the writer thread with LZ4 frame fast mode.
- Use ordinary asynchronous `write` calls. `O_DIRECT` is outside this change.
- Do not silently sample or drop events. Backpressure blocks the producer and is measured.

## Current Bottlenecks

The current instruction callback obtains full QBDI instruction and operand analysis for every
execution. It then builds register and instruction text with `std::ostringstream`, copies several
temporary `std::string` objects, and performs memory collection through another callback. A 1 MiB
buffer reduces syscall count, but filling it still blocks the target thread while it is written.

The intended optimization follows the useful parts of the xfQTrace and GumTrace designs:

- combine instruction input and previous-instruction output in one callback;
- cache decoded ARM64 instruction metadata by opcode;
- encode into fixed buffers without per-line allocation;
- move compression and file I/O off the trace thread;
- make expensive memory capture an explicit profile choice.

References:

- <https://bbs.kanxue.com/thread-291372.htm>
- <https://github.com/lidongyooo/GumTrace>

## Architecture

The optimized path has four independently testable units.

### InstructionCache

`InstructionCache` maps a 32-bit ARM64 opcode to compact immutable metadata:

- mnemonic and operand representation;
- input and output register indexes;
- instruction category and branch properties;
- decoded immediate or PC-relative displacement;
- flags needed by call, rule, and memory handling.

The cache uses direct indexing rather than a hash map. A cache entry does not own dynamically
allocated strings. PC-relative instructions cache their static decode and displacement, not a
location-dependent target string; the encoder calculates the displayed target from the current
PC.

On a miss, the collector asks QBDI for full instruction and operand analysis, converts the result
to compact metadata, and publishes the completed cache entry. On a hit, it avoids full operand
analysis and disassembly. Cache hits and misses are counted.

### TraceCollector

The normal path registers one `PREINST` callback. It maintains one pending instruction. At the
start of callback N, the current register state represents the result of instruction N-1, so the
collector first completes and emits N-1, then captures the inputs for N.

The collection order is:

1. Complete the pending instruction using current output-register values.
2. Run any delayed post-processing that is safe at this boundary.
3. Encode and append that completed instruction.
4. Read the current PC and opcode.
5. Look up or populate `InstructionCache`.
6. Run current CodeRule pre-processing.
7. Capture only the input values required by the cached metadata.
8. Store the current instruction as pending.

After `vm.call` returns, the collector explicitly completes the last pending instruction.

Existing user CodeRules are pre-instruction rules and use the single-callback path. The rule API
will declare whether a future rule requires an immediate QBDI post callback. A second `POSTINST`
callback is registered only when such a rule is present; uncommon post rules must not tax every
trace.

When memory tracing is disabled, the runner does not call `recordMemoryAccess` or register a
memory callback. Memory-enabled profiles use a separate slower collection path.

### TraceEncoder

`TraceEncoder` receives collector events and appends directly to caller-owned byte spans. It uses
bounded integer and hexadecimal formatting helpers and never creates a stream or temporary line
string on the instruction hot path.

The first format remains text. Its header includes a format version and the effective profile so
tools can distinguish it from earlier traces. Its footer includes the final status and all
collector-side metrics known before the last buffer is published. Call, JNI, libc, rule, and error
records use the same encoder interface rather than bypassing the buffering policy.

The encoder boundary permits a future `BinaryTraceEncoder`, but no binary format or offline
converter is part of this change.

### AsyncTraceWriter

`AsyncTraceWriter` owns two fixed buffers and one writer thread. Buffer states are:

`FREE -> FILLING -> READY -> WRITING -> FREE`.

The trace thread is the only producer and the writer thread is the only consumer. The producer
appends to the active buffer. When full, it publishes that buffer, switches to a free buffer, and
continues. The consumer compresses each ready span as an independent LZ4 frame and writes the
compressed bytes with retry-on-`EINTR` semantics. The pull workflow decodes concatenated frames in
sequence, matching the reference LZ4 CLI, so all completely written frames remain recoverable if a
later frame is truncated.

Compressed traces use the `.trace.txt.lz4` suffix. After the trace file is closed, the writer
stores final writer-side metrics in a small adjacent `.metrics` sidecar. The pull workflow
recognizes both files and decompresses the trace automatically unless the user requests compressed
output only.

The default capacity is 2 x 64 MiB. A high-memory profile may select 2 x 128 MiB. An explicit
configuration value overrides automatic selection. Allocation falls back through 256 MiB total,
128 MiB, 64 MiB, and a documented minimum rather than failing immediately.

## Trace Profiles

### fast (default)

Records:

- instruction sequence, module offset, and disassembly;
- referenced input registers and output-register results;
- CodeRule events;
- call, return, JNI, libc, and execution-transfer events.

It does not enable QBDI memory recording and does not emit memory hexdumps.

### balanced

Adds memory access type, address, size, and QBDI-provided value to `fast`. It does not perform
extra memory reads or byte hexdumps.

This is the closest comparison profile for measuring the new implementation against the current
full instruction-and-memory callback pipeline.

### full

Adds bounded before/after byte capture and hexdump output to `balanced`. The maximum bytes captured
per access is configurable and always capped. Unsafe addresses produce an unavailable marker
rather than terminating the trace.

All profiles use LZ4 frame fast compression by default. Compression can be explicitly disabled
for diagnosis, but uncompressed output is not the performance default.

## Configuration

The existing encoded configuration gains fields for:

- trace profile: `fast`, `balanced`, or `full`;
- compression enable and LZ4 level, defaulting to fast;
- total or per-buffer capacity;
- automatic buffer sizing enable;
- full-profile hexdump limit.

Effective settings, including automatic fallbacks, are written to the trace header and logcat.
Unknown values are rejected during configuration rather than silently selecting a different
profile.

## Data and Lifecycle Flow

Before QBDI execution, the runner creates the output file, allocates buffers, initializes LZ4, and
starts the writer thread. Only after all required resources are ready does instruction collection
begin.

During execution, collector events flow synchronously into `TraceEncoder`, then into the active
producer buffer. Compression and disk writes happen only on the consumer thread. When both
buffers are occupied, the producer waits for a free buffer; it does not overwrite or drop trace
records.

At normal completion the runner:

1. completes the last pending instruction;
2. appends the trace footer and metrics;
3. publishes the last nonempty producer buffer;
4. asks the consumer to finish the final LZ4 frame and drain all data;
5. joins the consumer and closes the output file;
6. writes final compressed-byte and writer timing metrics to the `.metrics` sidecar;
7. frees buffers and returns the target function result.

Shutdown is idempotent. Repeated cleanup cannot join, close, or free the same resource twice.

## Failure Handling

If output setup fails before QBDI starts, the proxy calls the unhooked target through an arm64
fallback bridge that preserves x0-x8. A tracing failure must not synthesize a zero return value or
skip the target function.

If compression or writing fails during execution, the consumer publishes an atomic error state
and releases all buffers. Collector callbacks then stop recording with minimal overhead while
QBDI continues executing the target to its real return. The failure is reported through logcat.

Buffer exhaustion is not treated as data loss. The producer waits and records the number and
duration of backpressure stalls. These metrics distinguish an encoding or QBDI bottleneck from a
compression or storage bottleneck.

The signal handler performs no C++ allocation, locking, ordinary flush, or LZ4 work. It may use
only async-signal-safe `write` on a pre-opened crash sidecar. Completed independent LZ4 frames
remain decodable; an unpublished or partially compressed final frame may be lost. Pull tooling
reports the crash marker, extracts only complete frames, and never labels such a trace complete.

## Metrics

Each completed trace reports collector metrics in its footer and final writer metrics through
logcat and the adjacent `.metrics` sidecar:

- elapsed wall time;
- executed instruction count and instructions per second;
- raw encoded byte count and raw throughput;
- compressed byte count, disk throughput, and compression ratio;
- instruction-cache hits, misses, and hit rate;
- buffer swaps, producer waits, and total wait time;
- selected and effective buffer capacity;
- selected profile and memory-trace status.

Metrics use counters maintained in the relevant component. They must not introduce per-event
logging or allocations.

## Verification and Benchmarking

A deterministic native benchmark scene performs a fixed mixture of loops, branches, register
operations, calls, loads, and stores. Given the same input, it has a stable return value and
instruction flow. Tests run on the same device and build after warmup, repeat five times, and use
the median.

Two comparisons are required:

1. `balanced` versus the current implementation, targeting at least 5x improvement at comparable
   information volume.
2. Default `fast`, targeting or approaching one million instructions per second on the reference
   device.

Correctness tests cover:

- identical semantics for cache hit and miss, including PC-relative instructions;
- first, last, branch-boundary, call-boundary, and return instruction emission;
- continuous sequence numbers with no duplicate or missing records;
- unchanged CodeRule effects and target return values;
- valid LZ4 decompression and required begin/end markers;
- forced frequent buffer swaps using small test buffers;
- injected allocation, thread-start, compression, and write failures;
- idempotent normal stop and recognizable crash output;
- accurate metrics and bounded memory use for every profile.

The benchmark records current baseline numbers before implementation. Every delivery stage reruns
the same benchmark so gains can be attributed to a specific change.

## Delivery Stages

1. Add the deterministic benchmark, baseline metrics, profiles, fixed encoder, and opcode cache.
2. Add delayed single-callback collection and disable memory instrumentation in the default path.
3. Add adaptive double buffering, background LZ4 compression, fallback behavior, and lifecycle
   hardening.

A stage advances only when its correctness tests pass and its benchmark data shows that it does
not regress the intended profile.

## Non-Goals

- Replacing QBDI with Frida Stalker or another execution engine.
- Defining a binary trace protocol or offline binary-to-text converter.
- Automatic event sampling or silent record dropping.
- `O_DIRECT`, `io_uring`, or filesystem-specific direct I/O.
- Child-thread trace management and parent/child metadata.
- Anonymous/JIT code-range discovery and dynamic instrumentation.
- Unrelated refactoring of JNI formatting, semantic providers, or hooking backends.
