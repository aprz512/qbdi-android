# Text Trace Format 2

Trace artifacts live in the debuggable app's private directory:

```text
/data/data/<package>/files/qbdi-traces/
```

The supported retrieval path is `scripts/pull_trace.py`. It enumerates and streams files with
`adb exec-out run-as <package>`; it does not copy an intermediate file onto shared device storage.

## Artifact set

A compressed run uses one unique basename and may have three adjacent files:

```text
<epoch_ms>_<pid>_<tid>_<scene>_0x<target_offset>_<sequence>
```

The final process-local sequence disambiguates runs that otherwise share the same millisecond,
thread, scene, and target. The suffixes form the artifact set:

- `<basename>.trace.txt.lz4` — concatenated, independent LZ4 frames containing UTF-8 text.
- `<basename>.trace.txt.lz4.metrics` — final key/value metrics, present only after successful writer
  finalization.
- `<basename>.trace.txt.lz4.crash` — retained only after a handled fatal signal. Its binary
  `CrashMarker` is exactly 12 little-endian bytes: magic `0x51435248`, signal number, and positive
  thread ID. Valid signals are `SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`, and `SIGABRT`.

An absent or empty `.crash` file is not evidence of a crash. A nonempty marker with the wrong size,
magic, signal, or thread ID is invalid and the pull tool rejects it rather than guessing.

Successful uncompressed debug runs use `.trace.txt`; completed compressed runs use
`.trace.txt.lz4` plus `.metrics`.

## Header and records

Every readable format-2 stream begins with:

```text
TRACE_BEGIN format=2 scene=<name> target=<module>+0x<offset> base=0x<address> address=0x<address> pid=<pid> tid=<tid> profile=<fast|balanced|full> compression=<0|1> effective_buffer_bytes=<bytes>
```

The fields identify the scene, target module-relative offset, loaded module base, absolute target
address, process/thread, selected profile, compression state, and actual per-buffer capacity after
allocation fallback.

An instruction record is:

```text
<seq> <module>+0x<offset> <disassembly> | R:<name>=0x<value> ... | W:<name>=0x<value> ... | MEM:<r|w|rw> addr=0x<address> size=<bytes> value=0x<value> ...
```

Sequence numbers are monotonically increasing within a run. Register sections include only the
decoded read/write set. Call, rule, and error events retain readable forms:

```text
CALL libc.strlen x0=0x... preview="qbdi"
CALL jni.FindClass name="java/lang/String"
CALL return strlen target=0x... ret=0x...
RULE set_equals_flag offset=0x... z=1
ERROR <detail>
```

The normal footer is:

```text
TRACE_END status=<ok|failed> ret=0x<value> elapsed_ms=<ms> instructions=<count> raw_bytes=<bytes> cache_hit_rate=<ratio> buffer_swaps=<count> producer_waits=<count> producer_wait_ns=<ns>
```

## Profiles

- `fast` (default) records instructions, decoded register reads/writes, semantic call/rule events,
  and the header/footer. QBDI memory recording and memory operand decoding are disabled on this hot
  path.
- `balanced` adds QBDI memory access type (`r`, `w`, or `rw`), address, size, QBDI-provided value,
  and access flags. An instruction with more than eight accesses uses ordered continuation `MEM`
  records rather than dropping accesses.
- `full` contains the balanced fields and bounded byte capture. `pre=` records bytes before the
  access; write-capable accesses may also have `post=` bytes. `<unavailable>` means the requested
  process memory could not be read safely. Available bytes are rendered as a compact hexadecimal
  hexdump. `hexdump_limit` defaults to 32 bytes and is capped at 64.

No profile silently samples, overwrites, or drops trace events. When both writer buffers are busy,
the producer waits and accounts that backpressure.

## Metrics sidecar

The `.metrics` file contains all of the following keys:

| Metric | Meaning |
| --- | --- |
| `profile` | `fast`, `balanced`, or `full`. |
| `return` | Target return value in hexadecimal. |
| `instructions` | Instruction records emitted. |
| `elapsed_ms` | End-to-end traced target duration. |
| `instructions_per_second` | `instructions * 1000 / elapsed_ms`. |
| `raw_bytes` | Text bytes produced before compression. |
| `compressed_bytes` | Bytes written to the `.lz4` file. |
| `raw_bytes_per_second` | `raw_bytes * 1000 / elapsed_ms`. |
| `disk_bytes_per_second` | `compressed_bytes * 1000 / elapsed_ms`. |
| `compression_ratio` | `compressed_bytes / raw_bytes`; lower is smaller. |
| `cache_hits` | Opcode-cache lookups served without decoding. |
| `cache_misses` | Opcode-cache lookups that required decode/population. |
| `cache_hit_rate` | `cache_hits / (cache_hits + cache_misses)`. |
| `buffer_swaps` | Producer buffers published to the compression/writer thread. |
| `producer_waits` | Times the producer found no free buffer. |
| `producer_wait_ns` | Total measured time waiting for a free buffer. |
| `effective_buffer_bytes` | Actual capacity of each of the two buffers. |

High `producer_waits` or a large `producer_wait_ns / (elapsed_ms * 1,000,000)` ratio identifies
compression/storage backpressure. Low producer wait with low instruction throughput points instead
to the QBDI/decode/collection/encoding side. Within that side, a low `cache_hit_rate` indicates
decode work; `raw_bytes_per_second` describes the encoder's output rate but is not an independent
timing measurement, so it cannot alone prove the dominant cost. Compare runs with the same device,
build, scene, profile, and return value.

## Buffers and memory use

The writer owns two buffers. Auto sizing selects 64 MiB per buffer below 8 GiB physical memory and
128 MiB per buffer at or above 8 GiB: 128 MiB or 256 MiB of trace-buffer virtual memory in total.
Explicit `buffer_mb` accepts 8–128 MiB per buffer. Allocation failure falls back through 64 MiB,
32 MiB, and 8 MiB candidates; the header and metrics report the capacity actually obtained.

Peak process use is greater than `2 * effective_buffer_bytes`: add the LZ4 context and roughly one
compression-chunk scratch area, instruction cache, QBDI, ShadowHook, app, and runtime memory. Buffer
pages are anonymous mappings and become resident as they are written.

## Pulling and decompression

Automatic retrieval and decompression:

```bash
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid --output pulled-traces
```

The tool chooses the newest compressed trace unless `--name` is supplied, pulls its adjacent
sidecars, validates a crash marker, scans frame boundaries, and invokes the host `lz4` CLI once for
each complete frame in order. It never overwrites a local compressed, sidecar, normal-text, or
partial-text output unless `--force` is present. Use `--compressed-only` when only the original
artifacts are wanted or the host `lz4` command is unavailable.

For a known-complete trace, the equivalent manual workflow is:

```bash
lz4 -d <basename>.trace.txt.lz4 <basename>.trace.txt
```

The file is a concatenation of LZ4 frames, which the CLI decodes in stream order.

## Failure recovery

A completed run has a valid `TRACE_BEGIN`, continuous instruction sequence, successful
`TRACE_END`, matching `.metrics`, and no retained crash marker. If a valid crash marker coexists
with a truncated final LZ4 frame, `pull_trace.py` decodes only prior complete frames, publishes
`<basename>.partial.trace.txt`, and exits with status 2. It never publishes bytes from the incomplete
frame. Truncation without a valid crash marker, a corrupt complete frame, or an invalid marker is a
normal error (status 1), not recoverable partial output.

Writer/setup failures disable tracing rather than changing the target's intended native result;
the ARM64 fallback preserves x0–x8. A missing `.metrics` file therefore means the run did not reach
successful writer finalization and must not be treated as a completed benchmark.

## Explicit exclusions

This implementation does not include `O_DIRECT`, `io_uring`, sampling, binary trace output,
child-thread tracing, or anonymous-range discovery. It keeps ordinary asynchronous `write`,
lossless readable text after decompression, and module-scoped QBDI tracing.
