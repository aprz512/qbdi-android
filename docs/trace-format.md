# QTRB v1 Binary Trace and Text Format 4

Trace artifacts live in the debuggable app's app-private directory:

```text
/data/data/<package>/files/qbdi-traces/
```

The production tracer writes a compact little-endian QTRB v1 event stream. Human-readable text is
generated on the host, so hexadecimal, decimal, register-name, and disassembly rendering do not run
on the traced thread.

Tracer configuration is a separate control plane: `scripts/spawn_trace.js` serializes the
versioned `config.tracer` JSON object and receives JSON configure/status responses. This does not
change QTRB, text format 4, Flight Recorder artifacts, or retained historical formats described
below.

## Artifact set

Each run has a unique basename:

```text
<epoch_ms>_<pid>_<tid>_<scene>_0x<target_offset>_<sequence>
```

The files are:

- `<basename>.trace.bin.lz4`: production output, a sequence of independent LZ4 frames containing
  QTRB v1 records. A final complete run also has one LZ4 skippable padding frame.
- `<basename>.trace.bin`: Debug-only compression-off output.
- `<artifact>.metrics`: strict metrics v3, published only after a completed or stopped terminal.
- `<artifact>.crash`: a 12-byte little-endian crash marker retained only after a handled fatal
  signal. It contains magic `0x51435248`, the signal, and a positive TID.
- `<basename>.trace.txt`: host-converted text format 4.
- `<basename>.partial.trace.txt`: recoverable complete frames from a crash-truncated artifact.
- `<run_id>_<pid>_<target>.flight.bin`: preallocated persistent cross-thread flight ring.
- `<flight-basename>.merged.trace.txt`: recovered events merged by process-wide sequence.
- `<flight-basename>.tid-<tid>.trace.txt`: one recovered event stream per captured TID.
- `<flight-basename>.flight.json`: recovery, termination, retained-window, damage, and completeness
  summary.

The pull tool also supports legacy format-2 `.trace.txt.lz4` artifacts and their v1 sidecars. It
never treats a format-2 `raw_bytes` field as the format-3 `encoded_bytes` field.

## QTRB v1 stream

All integers are little-endian and byte-packed. Strings are a `u16` byte length followed by UTF-8
bytes without a terminator. The 16-byte stream header is:

```text
StreamHeader {
  magic: "QTRB"[4]
  major: u8 = 1
  minor: u8 = 0 | 1 | 2
  endian: u8 = 1
  pointer_width: u8 = 4 | 8
  profile: u8                 # fast=0, balanced=1, full=2
  reserved: u8 = 0
  header_bytes: u16 = 16
  required_features: u32
}
```

Only these `(minor, required_features)` combinations are valid:

| Minor | Required features | Meaning |
| ---: | ---: | --- |
| 0 | 0 | Original v1 records; only CALL continuation is available. |
| 1 | 0 | Adds RULE/ERROR continuation and optional-record skipping. |
| 2 | 1 | Adds the required `TRACE_STOP` terminal (type 10). |

Any other pair is rejected. In particular, v1.2 requires feature bit 0 and that feature bit is not
valid on v1.0 or v1.1.

Every record starts with this exact eight-byte header:

```text
RecordHeader {
  type: u16
  flags: u16
  payload_bytes: u32
}
```

Unless stated otherwise, `RecordHeader.flags` is zero. `CALL_CONTINUATION` reuses its logical type
with flag `0x0001` in v1.0 and v1.1. `RULE_CONTINUATION` and `ERROR_CONTINUATION` use that flag only
in v1.1; v1.0 permits only their ordinary zero-flag layouts. All other flag bits are unsupported.
Signed `i64` values use their
two's-complement bit pattern. The fixed-size column follows the named encoder constants:
`TRACE_BEGIN`, `MODULE_DEF`, `CALL`, `RULE`, and `ERROR` include their string-length prefixes;
`INSTRUCTION_DEF` excludes its three string prefixes; `MEMORY` includes both state/length pairs.
No fixed size includes variable string bytes, dense arrays, captured state bytes, register
definitions, or memory operands.

### Record payload layouts

| Type | Record | Flags | Payload fields in little-endian wire order | Fixed payload bytes | Maximum record bytes |
| ---: | --- | --- | --- | ---: | ---: |
| 1 | `TRACE_BEGIN` | 0 | `module_base u64; target_offset u64; target_address u64; pid u32; tid u32; profile u8; compression_enabled u8; effective_buffer_bytes u64; run_id u64; scene string; target string` | 54 | 572 |
| 2 | `MODULE_DEF` | 0 | `module_id u32; module_base u64; module_name string` | 14 | 277 |
| 3 | `INSTRUCTION_DEF` | 0 | `metadata_id u32; opcode u32; read_mask u64; write_mask u64; pc_displacement i64; instruction_flags u32; pc_kind u8; condition u8; memory_operand_count u8; slow_memory_path u8; mnemonic string; operands string; disassembly string; read register definitions; write register definitions; memory operands` | 40 | 1646 |
| 4 | `INSTRUCTION` | 0 | `sequence u64; module_id u32; module_relative_pc u64; metadata_id u32; read_count u8; write_count u8; read values u64[read_count]; write values u64[write_count]` | 26 | 578 |
| 5 | `MEMORY` | 0 | `module_id u32; module_relative_pc u64; access_kind u8; metadata_available u8; flags u16; address u64; access_size u32; value u64; before memory state; after memory state` | 40 | 176 |
| 6 | `CALL` | 0 | `category string; name string; detail string` | 6 | 4620 |
| 6 | `CALL_CONTINUATION` | 0x0001 | `event_id u64; total_detail_bytes u32; chunk_index u16; chunk_count u16; category string; name string; detail_fragment string` | 22 | 3612 |
| 7 | `RULE` | 0 | `name string; detail string` | 4 | 4363 |
| 7 | `RULE_CONTINUATION` | 0x0001 | `event_id u64; total_detail_bytes u32; chunk_index u16; chunk_count u16; name string; detail_fragment string` | 20 | 3355 |
| 8 | `ERROR` | 0 | `name string; detail string` | 4 | 4363 |
| 8 | `ERROR_CONTINUATION` | 0x0001 | `event_id u64; total_detail_bytes u32; chunk_index u16; chunk_count u16; name string; detail_fragment string` | 20 | 3355 |
| 9 | `TRACE_END` | 0 | `success u8; return_value u64; elapsed_ms u64; instructions u64; encoded_bytes u64; compressed_bytes u64; cache_hits u64; cache_misses u64; cache_collisions u64; buffer_swaps u64; producer_waits u64; producer_wait_ns u64; effective_buffer_bytes u64` | 97 | 105 |
| 10 | `TRACE_STOP` | 0 | `reason u8; reserved[7] = 0; elapsed_ms u64; instructions u64; encoded_bytes u64; compressed_bytes u64; cache_hits u64; cache_misses u64; cache_collisions u64; buffer_swaps u64; producer_waits u64; producer_wait_ns u64; effective_buffer_bytes u64` | 96 | 104 |

Maximum record bytes include the eight-byte `RecordHeader`. `TRACE_END.encoded_bytes` includes its
own 105 bytes; `TRACE_STOP.encoded_bytes` likewise includes its own 104 bytes. Both terminal
`compressed_bytes` values are the final artifact size, including the final LZ4 skippable padding
frame when compression is enabled. `TRACE_END.success` is 0 or 1.

`TRACE_STOP` is valid only for `(minor, required_features) = (2, 1)`, has zero flags, and has an
exactly 96-byte payload. Its first byte is `reason`; the following seven reserved bytes are zero;
the remaining eleven `u64` fields occur in exactly the order shown in the table. Reason `1` means
`duration_elapsed`; reason `0` is invalid; every other value is reserved and rejected.

### Nested wire layouts

| Nested value | Exact layout | Limit |
| --- | --- | --- |
| `string` | `byte_length u16; bytes[byte_length]` | 65,535-byte wire maximum; semantic limits below |
| `register definition` | `width u8; name string` | 34 read and 34 write definitions; ascending mask-bit order |
| `memory operand` | `base u8; index u8; extend u8; address_mode u8; shift u8; access_kind u8; writeback u8; access_size u32; displacement i64` | 19 bytes; at most 4 |
| `memory state` | `state u8; byte_count u8; bytes[byte_count]` | state 0/1/2; at most 64 bytes |

`INSTRUCTION_DEF.metadata_id` and `opcode` are independent `u32` fields. Only register-mask bits
0–33 are valid. Read definitions precede write definitions, each in ascending set-bit order;
`INSTRUCTION` dense values use those same orders and their counts must equal the respective
popcounts. `instruction_flags` bits are branch `0x1`, PC-relative `0x2`, call `0x4`, and return
`0x8`. `pc_kind` is none/current-PC/current-page as 0/1/2, while `slow_memory_path`,
`compression_enabled`, `metadata_available`, and `writeback` are 0 or 1.

A memory operand uses register indexes 0–33 or `255` for no register; `extend` is
none/UXTW/SXTW/LSL/SXTX as 0–4; `address_mode` is offset/pre-index/post-index as 0–2; and
`access_kind` is read/write/read-write as 1/2/3. A memory state is not-captured/available/unavailable
as 0/1/2. Not-captured and unavailable require `byte_count=0`; available carries 0–64 bytes.
`MEMORY.flags` and `INSTRUCTION_DEF.condition` preserve their producer `u16`/`u8` values.

The producer assigns dense run-local `metadata_id` values `0..65535`. It latches `EOVERFLOW`
before emitting definition 65,537, so every stream with a successful footer remains within the
host's identical 65,536-definition bound.

For `CALL_CONTINUATION`, `event_id` must be nonzero, `chunk_count>=2`, indexes are contiguous from
zero, every fragment is nonempty and at most 3072 bytes, and all chunks repeat identical event ID,
total, count, category, and name. `total_detail_bytes` must equal the reassembled detail and be no
larger than 1 MiB. UTF-8 validation of detail occurs only after raw fragments are concatenated.
`RULE_CONTINUATION` and `ERROR_CONTINUATION` use the same grouping rules, carry a repeated name,
limit the logical detail to 4096 bytes, and use fragments of at most 3072 bytes. This keeps every
physical semantic-event record below 4096 bytes while preserving the complete name/detail bytes.

Definitions are control records and are emitted immediately before their first reference. They do
not become visible text events. `INSTRUCTION` sequence numbers therefore remain continuous and all
visible instruction, memory, call, rule, and error events retain producer order.

### Limits

- Context, module, CALL category/name, and event names: 255 UTF-8 bytes each.
- Ordinary event detail: 4096 bytes.
- CALL chunk detail: 3072 bytes; a complete logical CALL detail is at most 1 MiB.
- Mnemonic/operands/disassembly/register name: 16/96/112/16 bytes.
- Registers: 34; static memory operands: 4; captured before/after state: 64 bytes each.
- Instruction dictionary entries: 65,536 on both producer and host; module entries: 65,536 host.
- Largest record: 4620 bytes. A record never crosses a producer-buffer boundary.

A continuation group must be contiguous, start at index zero, keep identical type, event ID, total,
count, and name (plus CALL category), and contain every index exactly once. UTF-8 validation occurs
after raw detail fragments are reassembled.

The current producer emits major 1 minor 2 with required feature bit 0. The converter preserves
retained v1.0 artifacts: v1.0 supports zero-flag RULE/ERROR and CALL continuation, while v1.1
additionally supports RULE/ERROR continuation. A v1.0 RULE/ERROR record with flag `0x0001` fails
closed. Record types `0x8000..0xffff` are the optional extension namespace: a minor-1 decoder
skips a well-framed, zero-flag unknown optional record only between `TRACE_BEGIN` and its terminal
and never through a continuation group. Types below `0x8000` are required records. Unknown required
feature bits, required record types, flags, references, lifecycle violations, unsupported
minor/features pairs, or incompatible major versions fail closed.

## Text format 4

`scripts/trace_convert.py` writes UTF-8 with one visible event per line. Field order is fixed by
format 4 and shown below:

```text
TRACE_BEGIN format=4 scene="..." target="..." target_offset=0x... base=0x... address=0x... pid=... tid=... profile=... compression=... effective_buffer_bytes=... run_id=...
INST seq=1 module="..." module_base=0x... pc=0x... relative_pc=0x... metadata_id=... opcode=0x... asm="..." flags=0x... condition=... reads=[...] writes=[...] slow_memory_path=... memory_operands=[...]
MEMORY module="..." module_base=0x... pc=0x... relative_pc=0x... kind=... metadata_available=... flags=0x... address=0x... size=... value=0x... before=... after=...
CALL category="..." name="..." detail="..."
RULE name="..." detail="..."
ERROR name="..." detail="..."
TRACE_END status=completed return_valid=1 return=0x... elapsed_ms=... instructions=... encoded_bytes=... compressed_bytes=... cache_hits=... cache_misses=... cache_collisions=... buffer_swaps=... producer_waits=... producer_wait_ns=... effective_buffer_bytes=...
TRACE_END status=stopped reason=duration_elapsed return_valid=0 elapsed_ms=... instructions=... encoded_bytes=... compressed_bytes=... cache_hits=... cache_misses=... cache_collisions=... buffer_swaps=... producer_waits=... producer_wait_ns=... effective_buffer_bytes=...
```

The completed and stopped lines are the two format-4 terminal forms. A stopped terminal has no
`return=` field because `return_valid=0`.

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

## Metrics v3

Binary sidecars begin with `metrics_version=3`. Metrics v3 has a fixed terminal contract:
`termination` is `completed` or `stopped`; `return_valid` is respectively `1` or `0`; and a stopped
terminal fixes `return=0x0`. These fields are mandatory and are checked against the QTRB terminal
before text publication. A stopped metrics sidecar therefore cannot accompany a completed
`TRACE_END`, and a completed sidecar cannot accompany `TRACE_STOP`.

| Metric | Meaning |
| --- | --- |
| `metrics_version`, `termination`, `return_valid`, `profile`, `return` | Fixed terminal identity and result contract. |
| `instructions`, `elapsed_ms` | Terminal counters. |
| `instructions_per_second` | `instructions * 1000 / elapsed_ms`. |
| `encoded_bytes` | Uncompressed QTRB bytes, including header and its terminal record. |
| `compressed_bytes` | Exact `.trace.bin.lz4` artifact bytes, including final padding. |
| `encoded_bytes_per_second`, `disk_bytes_per_second`, `compression_ratio` | Fixed-six derived rates. |
| `cache_hits`, `cache_misses`, `cache_collisions`, `cache_hit_rate` | Decode-cache counters and rate. |
| `buffer_swaps`, `producer_waits`, `producer_wait_ns` | Async writer/backpressure counters. |
| `effective_buffer_bytes` | Actual capacity of each producer buffer after fallback. |

The converter checks the terminal against the artifact size and adjacent v3 sidecar before atomic
publication. Pull, conversion, and benchmarking use one suffix-aware strict parser: legacy
format-2 v1 metrics are valid only beside `.trace.txt.lz4` when `metrics_version` is absent and
`raw_bytes` is present, while QTRB metrics v2 and v3 are valid only beside QTRB artifacts. Mixed
generations are rejected. All five fixed-six rates are mandatory and recomputed from validated
counters.
Recomputation exactly reproduces the producer's unsigned integer truncation to six fractional
digits, including a zero denominator; an adjacent `0.000001` value is inconsistent and rejected.

`elapsed_ms` stops after traced target execution and producer callbacks, before final writer drain,
footer, and sidecar publication.
Thus all three derived rates use hot-path elapsed time and are comparable with the format-2
baseline, but they are not end-to-end publication throughput. `encoded_bytes` is complete after
the terminal is committed. `compressed_bytes` is complete after all frames, padding, drain, and
close finish. The large and 4 KiB acceptance runs separately exercise streaming, backpressure, and
final drain behavior.

### Compatibility matrix

| Input artifact and sidecar | Terminal meaning | Host support |
| --- | --- | --- |
| QTRB 1.0/1.1 + metrics v2 | Completed legacy input | Readable. |
| QTRB 1.2 type 9 + metrics v3 | Completed | Readable as format-4 `status=completed`. |
| QTRB 1.2 type 10 + metrics v3 | Stopped | Readable as format-4 `status=stopped`. |
| Truncated + valid crash marker | Recovered/partial | Only complete prior frames are recovered; no terminal is fabricated. |

## Pulling and conversion

Automatic pull, validation, and conversion of the newest supported artifact:

```bash
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --device 192.168.51.42:5555 --output pulled-traces
```

Use `--name <artifact>` to select a specific `.flight.bin`, `.trace.bin.lz4`, `.trace.bin`, or
legacy `.trace.txt.lz4`. Without `--name`, listing order selects the newest supported artifact. Use
`--compressed-only` to retain the original artifact and sidecars without conversion; for an
uncompressed `.flight.bin` it means only the validated artifact is published and derived recovery
outputs are skipped. Existing source and every possible derived output require `--force` before
replacement.

Manual binary conversion:

```bash
python3 scripts/trace_convert.py input.trace.bin.lz4 --output output.trace.txt
python3 scripts/trace_convert.py input.trace.bin --output output.trace.txt
```

Both tools use status 0 for a completed or stopped terminal, status 1 for an error with no text
publication, and status 2 for valid crash-partial recovery. `pull_trace.py` reports the corresponding
successful status as `complete` or `stopped`. `benchmark_trace.py --compare` also uses status 2 when
a speed or size acceptance gate is missed while still printing the complete JSON verdict.

## Persistent flight recorder

Flight capture must be injected with Frida spawn before the target library loads. Its defaults are
512 MiB total capacity, 256 KiB chunks, 256 thread entries, and four protected chunks per active
thread (a 1 MiB minimum retained window). The persistent `pthread_create` gateway observes all
pthread lifecycles. Recorder sessions cover target-owned threads: target start routines and
threads created by an active target scene. Within those sessions QBDI emits instruction, memory,
and GPR records only for the target module; retained hook trampolines are control-only.

Flight collection is the full profile regardless of the ordinary trace profile: all target
instructions, QBDI memory accesses with bounded pre/post bytes, and checkpoints/deltas for
`x0`–`x30`, `sp`, `pc`, and `nzcv`. The artifact is a process-wide persistent ring, so overwriting
old unprotected chunks is expected and represented as sequence ranges rather than silently hidden.

The signal broker virtualizes guest dispositions, including direct `rt_sigaction` syscalls, while
guest handlers execute natively and are excluded from QBDI. Explicit signal-handler begin/return
records delimit that untraced interval and returned GPR changes are applied before guest execution
resumes. Direct `tkill`, `tgkill`, `exit`, and `exit_group` paths publish evidence without relying
on libc hooks. `SIGKILL` cannot be brokered; only a target-issued pre-syscall termination intent is
available for that case.

Pull and recover the newest or an explicit flight artifact without installing LZ4:

```bash
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --device <adb-serial> --output pulled-traces
python3 scripts/pull_trace.py --package com.aprz.qbdiandroid \
  --device <adb-serial> --name <run>.flight.bin --output pulled-traces
```

Recovery validates the superblock, directory/chunk generations, committed prefixes, checksums,
dictionaries, register deltas, and global sequence ordering. It publishes the original
`.flight.bin`, a merged text stream, per-TID text streams, and `.flight.json`. The JSON `complete`
field—not normal QTRB metrics or crash sidecars—defines flight status. Missing terminal evidence is
reported as `termination.cause="unknown"` and does not by itself make an otherwise valid recovery
incomplete. Coverage gaps, recovery damage, incomplete logical events, stale/active state, or
unterminated lifecycle evidence are surfaced explicitly and fail completeness closed.

## Crash partial semantics

A completed or stopped run has a valid QTRB header, `TRACE_BEGIN`, continuous instruction sequence,
the matching terminal, a matching v3 sidecar, and no retained crash marker. A valid crash marker
plus a truncated final LZ4 frame permits recovery of complete prior frames only. The tools publish
`<basename>.partial.trace.txt`, omit an incomplete final record/frame, return status 2, and never
fabricate a `TRACE_END` terminal for that crash-marked partial.

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
Default compression effort is profile-aware: fast uses `lz4_level=0`, while balanced and full use
`lz4_level=2`. An explicit `lz4_level=` overrides this selection. This single variable changes only
compressor effort; record content and ordering are identical. Levels 3–12 select high-compression
mode and are opt-in.

## Explicit exclusions

This implementation does not include `O_DIRECT`, `io_uring`, sampling, per-event file syscalls,
per-record checksums, corrupt-byte repair, child-thread tracing, or anonymous-range discovery. It
keeps QBDI, ordinary asynchronous `write`, independent LZ4 frames, and module-scoped tracing.
