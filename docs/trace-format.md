# QTRB v1 Binary Trace and Text Format 3

Trace artifacts live in the debuggable app's app-private directory:

```text
/data/data/<package>/files/qbdi-traces/
```

The production tracer writes a compact little-endian QTRB v1 event stream. Human-readable text is
generated on the host, so hexadecimal, decimal, register-name, and disassembly rendering do not run
on the traced thread.

## Artifact set

Each run has a unique basename:

```text
<epoch_ms>_<pid>_<tid>_<scene>_0x<target_offset>_<sequence>
```

The files are:

- `<basename>.trace.bin.lz4`: production output, a sequence of independent LZ4 frames containing
  QTRB v1 records. A final complete run also has one LZ4 skippable padding frame.
- `<basename>.trace.bin`: Debug-only compression-off output.
- `<artifact>.metrics`: metrics v2, published only after successful finalization.
- `<artifact>.crash`: a 12-byte little-endian crash marker retained only after a handled fatal
  signal. It contains magic `0x51435248`, the signal, and a positive TID.
- `<basename>.trace.txt`: host-converted text format 3.
- `<basename>.partial.trace.txt`: recoverable complete frames from a crash-truncated artifact.

The pull tool also supports legacy format-2 `.trace.txt.lz4` artifacts and their v1 sidecars. It
never treats a format-2 `raw_bytes` field as the format-3 `encoded_bytes` field.

## QTRB v1 stream

All integers are little-endian and byte-packed. Strings are a `u16` byte length followed by UTF-8
bytes without a terminator. The 16-byte stream header is:

```text
StreamHeader {
  magic: "QTRB"[4]
  major: u8 = 1
  minor: u8 = 0
  endian: u8 = 1
  pointer_width: u8 = 4 | 8
  profile: u8                 # fast=0, balanced=1, full=2
  reserved: u8 = 0
  header_bytes: u16 = 16
  required_features: u32 = 0
}
```

Every record starts with this exact eight-byte header:

```text
RecordHeader {
  type: u16
  flags: u16
  payload_bytes: u32
}
```

The record types and payload field order are:

| Type | Name | Payload fields in wire order |
| ---: | --- | --- |
| 1 | `TRACE_BEGIN` | module base `u64`, target offset `u64`, target address `u64`, PID `u32`, TID `u32`, profile `u8`, compression `u8`, effective buffer bytes `u64`, run ID `u64`, scene string, target string |
| 2 | `MODULE_DEF` | module ID `u32`, module base `u64`, module-name string |
| 3 | `INSTRUCTION_DEF` | metadata ID/opcode `u32`, read/write masks `u64`, PC displacement `i64`, flags `u32`, PC kind/condition/memory count/slow-path `u8`, mnemonic/operands/disassembly strings, dense register definitions, memory operands |
| 4 | `INSTRUCTION` | sequence `u64`, module ID `u32`, relative PC `u64`, metadata ID `u32`, read/write counts `u8`, then dense `u64` values in mask-bit order |
| 5 | `MEMORY` | module ID `u32`, relative PC `u64`, access kind/metadata flag, flags `u16`, address `u64`, size `u32`, value `u64`, then before/after state, length, and bytes |
| 6 | `CALL` | category, name, and detail strings; chunked records prepend event ID `u64`, total length `u32`, index/count `u16` |
| 7 | `RULE` | name and detail strings |
| 8 | `ERROR` | name and detail strings |
| 9 | `TRACE_END` | success `u8`, return/elapsed/instruction count/encoded bytes/compressed bytes/cache hits/cache misses/cache collisions/buffer swaps/producer waits/producer wait ns/effective buffer bytes as `u64` |

Definitions are control records and are emitted immediately before their first reference. They do
not become visible text events. `INSTRUCTION` sequence numbers therefore remain continuous and all
visible instruction, memory, call, rule, and error events retain producer order.

### Limits

- Context, module, CALL category/name, and event names: 255 UTF-8 bytes each.
- Ordinary event detail: 4096 bytes.
- CALL chunk detail: 3072 bytes; a complete logical CALL detail is at most 1 MiB.
- Mnemonic/operands/disassembly/register name: 16/96/112/16 bytes.
- Registers: 34; static memory operands: 4; captured before/after state: 64 bytes each.
- Instruction dictionary entries and module dictionary entries: 65,536 each on the host.
- Largest record: 4620 bytes. A record never crosses a producer-buffer boundary.

A CALL chunk group must be contiguous, start at index zero, keep identical event ID, total, count,
category, and name, and contain every index exactly once. UTF-8 validation occurs after raw detail
fragments are reassembled. Unknown required features, record flags, references, or incompatible
versions fail closed.

## Text format 3

`scripts/trace_convert.py` writes UTF-8 with one visible event per line. Field order is fixed by
format 3 and shown below:

```text
TRACE_BEGIN format=3 scene="..." target="..." target_offset=0x... base=0x... address=0x... pid=... tid=... profile=... compression=... effective_buffer_bytes=... run_id=...
INST seq=1 module="..." module_base=0x... pc=0x... relative_pc=0x... metadata_id=... opcode=0x... asm="..." flags=0x... condition=... reads=[...] writes=[...] slow_memory_path=... memory_operands=[...]
MEMORY module="..." module_base=0x... pc=0x... relative_pc=0x... kind=... metadata_available=... flags=0x... address=0x... size=... value=0x... before=... after=...
CALL category="..." name="..." detail="..."
RULE name="..." detail="..."
ERROR name="..." detail="..."
TRACE_END status=ok return=0x... elapsed_ms=... instructions=... encoded_bytes=... compressed_bytes=... cache_hits=... cache_misses=... cache_collisions=... buffer_swaps=... producer_waits=... producer_wait_ns=... effective_buffer_bytes=...
```

String escaping is JSON string escaping without ASCII forcing: quotes, backslashes, and control
characters use JSON escapes, while valid non-ASCII UTF-8 remains readable. Integers are decimal
except fields shown with a `0x` prefix. PC-relative targets are rendered from the instruction PC
using 64-bit wrapping and the recorded current-PC or current-page base kind.

## Profiles

- `fast` records every instruction, decoded register read/write values, semantic CALL/RULE/ERROR
  events, and begin/end records. QBDI memory collection is disabled.
- `balanced` adds every QBDI memory access with kind, metadata availability, flags, address, size,
  and value. More than eight accesses use ordered `MEMORY` continuation records.
- `full` adds bounded before/after byte state. States are `<not-captured>`, `<unavailable>`, or a
  lowercase hexadecimal byte string of at most 64 bytes.

No profile samples, overwrites, drops, or reorders events. When both asynchronous buffers are busy,
the producer waits and records that backpressure.

## Metrics v2

Binary sidecars begin with `metrics_version=2`. They contain:

| Metric | Meaning |
| --- | --- |
| `profile`, `return`, `instructions`, `elapsed_ms` | Run identity and result. |
| `instructions_per_second` | `instructions * 1000 / elapsed_ms`. |
| `encoded_bytes` | Uncompressed QTRB bytes, including header and footer. |
| `compressed_bytes` | Exact `.trace.bin.lz4` artifact bytes, including final padding. |
| `encoded_bytes_per_second`, `disk_bytes_per_second`, `compression_ratio` | Fixed-six derived rates. |
| `cache_hits`, `cache_misses`, `cache_collisions`, `cache_hit_rate` | Decode-cache counters and rate. |
| `buffer_swaps`, `producer_waits`, `producer_wait_ns` | Async writer/backpressure counters. |
| `effective_buffer_bytes` | Actual capacity of each producer buffer after fallback. |

The converter checks the footer against the artifact size and adjacent v2 sidecar before atomic
publication. The pull/benchmark tools parse legacy format-2 v1 metrics only when
`metrics_version` is absent and `raw_bytes` is present; mixed v1/v2 fields are rejected.

## Pulling and conversion

Automatic pull, validation, and conversion of the newest supported artifact:

```bash
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --device 192.168.51.42:5555 --output pulled-traces
```

Use `--name <artifact>` to select a specific `.trace.bin.lz4`, `.trace.bin`, or legacy
`.trace.txt.lz4`. Use `--compressed-only` to retain the original artifact and sidecars without
conversion. Existing outputs require `--force`.

Manual binary conversion:

```bash
python3 scripts/trace_convert.py input.trace.bin.lz4 --output output.trace.txt
python3 scripts/trace_convert.py input.trace.bin --output output.trace.txt
```

Both tools use status 0 for complete success, status 1 for an error with no text publication, and
status 2 for valid crash-partial recovery. `benchmark_trace.py --compare` also uses status 2 when
a speed or size acceptance gate is missed while still printing the complete JSON verdict.

## Crash partial semantics

A complete run has a valid QTRB header, `TRACE_BEGIN`, continuous instruction sequence,
`TRACE_END`, matching v2 sidecar, and no retained crash marker. A valid crash marker plus a
truncated final LZ4 frame permits recovery of complete prior frames only. The tools publish
`<basename>.partial.trace.txt`, omit an incomplete final record/frame, and return status 2.

Truncation without a valid crash marker, corruption in a complete frame, invalid dictionaries or
sequence, or sidecar/footer disagreement returns status 1 and publishes no text. A raw
`.trace.bin` cannot use frame recovery. Unique temporary files, `fsync`, and atomic publication
prevent a failed conversion from replacing a prior output.

Writer/setup failures disable further trace work without changing the target's native result and
never publish a success metrics sidecar.

## Buffers

The writer owns two buffers. Auto sizing selects 64 MiB per buffer below 8 GiB physical memory and
128 MiB per buffer at or above 8 GiB. Explicit `buffer_mb` accepts 8–128 MiB; allocation fallback
tries 64 MiB, 32 MiB, and 8 MiB. Debug accepts exactly 4096 bytes through the test-only override.
The default `lz4_level=2` stays on LZ4's fast compressor while improving the fixed-width binary
stream's compressed size; levels 3–12 select high-compression mode and are opt-in.

## Explicit exclusions

This implementation does not include `O_DIRECT`, `io_uring`, sampling, per-event file syscalls,
per-record checksums, corrupt-byte repair, child-thread tracing, or anonymous-range discovery. It
keeps QBDI, ordinary asynchronous `write`, independent LZ4 frames, and module-scoped tracing.
