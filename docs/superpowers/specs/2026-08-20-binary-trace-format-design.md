# Binary Trace Format Throughput Design

Date: 2026-08-20

## Objective

Replace device-side text rendering with a versioned compact binary event stream while preserving
all information currently recorded by the `fast`, `balanced`, and `full` profiles. A host tool
converts the binary artifact into a stable, readable text format.

The Pixel 6 acceptance targets are:

- `fast`: median at least 1,000,000 instructions per second.
- `balanced`: median at least 800,000 instructions per second.
- `full`: median at least 500,000 instructions per second.
- The compressed binary artifact must not exceed the compressed text artifact produced by the
  current implementation for the same workload.

Correctness takes precedence over a benchmark claim. No profile may sample, omit, overwrite, or
reorder events to meet a throughput target.

## Current Evidence

The current Pixel 6 implementation records approximately 775,643 instructions per second in
`fast` and 723,933 instructions per second in `balanced` in the final reviewed build. Producer
waits are zero, opcode-cache collisions are zero, and the opcode resolver/cache path is no longer
the dominant cost. Prior single-variable probes place the remaining cost primarily in register
collection and per-instruction text formatting. LZ4 and file output run on the consumer thread and
do not currently block the producer.

The new design therefore removes string, hexadecimal, decimal, and register-name formatting from
the traced target's hot path. It retains QBDI, the existing profile semantics, asynchronous double
buffering, LZ4 compression, ordinary file writes, and the reviewed fork/crash lifecycle.

## Architecture

New compressed artifacts use the `.trace.bin.lz4` suffix and contain a little-endian `QTRB v1`
event stream.

### Device modules

`BinaryTraceWriter` presents the existing high-level trace interface:

- `begin`
- `instruction`
- `memory`
- `call`
- `rule`
- `error`
- `end`

It hides buffer publication, compression, file output, metrics, and failure latching from callers.
The module retains the existing asynchronous two-buffer writer implementation and its process
lifecycle guarantees.

`BinaryTraceEncoder` writes records directly into a reserved producer-buffer span. Its hot path is
bounded, allocation-free, and performs no human-readable formatting.

`TraceDictionary` assigns integer identifiers to run-scoped module and instruction metadata.
Module names, disassembly metadata, register identities, masks, and PC-relative decode facts are
emitted once and subsequently referenced by identifier. The existing opcode-only instruction
cache remains the source of immutable instruction metadata.

### Host modules

`scripts/trace_convert.py` streams `.trace.bin.lz4` input, validates the binary protocol, resolves
dictionaries, and writes text format 3. It does not retain the entire input or output in memory.

`scripts/pull_trace.py` detects artifacts by suffix:

- Existing `.trace.txt.lz4` artifacts continue through the format-2 path.
- New `.trace.bin.lz4` artifacts are pulled and passed to the binary converter.

The crash-marker wire format remains unchanged.

## Binary Protocol

Every file begins with a fixed header containing:

- Magic `QTRB`.
- Major and minor format versions.
- Little-endian byte-order marker.
- Pointer width.
- Trace profile.
- Required decoder feature flags.

Every event has an eight-byte header:

```text
RecordHeader {
  type: u16
  flags: u16
  payload_bytes: u32
}
```

The protocol does not use varints. Fixed-width integer encoding keeps the producer implementation
branch-light and allows a decoder to skip a record type introduced by a compatible minor version.
All record sizes, string lengths, collection counts, and captured-byte lengths have explicit
limits.

### Record types

`TRACE_BEGIN` contains the scene, target, loaded module base, target address, PID, TID, profile,
compression state, effective buffer size, and run identity.

`MODULE_DEF` maps a module identifier to its name and load information.

`INSTRUCTION_DEF` maps a metadata identifier to the complete 32-bit opcode and static decode
facts: disassembly template, register names and widths, read/write masks, condition data, memory
address formulas, and PC-relative base kind plus signed displacement. Location-dependent absolute
targets are reconstructed from the later instruction record's PC.

`INSTRUCTION` contains sequence, module identifier, module-relative PC, and metadata identifier.
Read and write values are encoded densely in set-bit order rather than as all 34 register slots.

`MEMORY` contains access kind, metadata availability, flags, address, size, value, and the bounded
`before` and `after` byte states required by the selected profile. More than eight accesses remain
ordered continuation records and are never dropped.

`CALL`, `RULE`, and `ERROR` retain their current categories, names, and details with bounded
length-prefixed strings. A short `CALL` remains the compact three-string record with flags zero.
A logical `CALL` detail above 3072 bytes is represented by consecutive CALL records carrying the
CALL-chunk flag and a nonzero run-local event ID, total detail byte length, zero-based chunk index,
and chunk count before the repeated category/name and detail fragment. The complete logical detail
is bounded to 1 MiB. A decoder must require a contiguous, complete group with identical metadata,
category, and name, concatenate fragment bytes in index order, and emit exactly one visible CALL.
The writer chooses UTF-8 code-point boundaries when the complete detail is valid UTF-8. Individual
fragments are raw bytes and are not independently UTF-8 validated: arbitrary input bytes are
preserved exactly, while the converter validates UTF-8 once after reassembly and rejects an invalid
complete logical string.

`TRACE_END` contains status, target return value, elapsed time, instruction count, and writer/cache
metrics.

Dictionary definitions may appear immediately before their first reference. They are control
records and do not become visible events in converted text, so instruction, memory, call, rule,
and error ordering is unchanged.

## Write Path and Framing

The target thread does not call `write()` for each event. It encodes events into the active
producer buffer. When the buffer is full, it publishes the buffer to the consumer and switches to
the second buffer. The consumer compresses each publication as an independent LZ4 frame and
appends it to the artifact immediately. The final partial buffer is published during normal
finalization.

For a complete compressed run, `TRACE_END` is published in its own standard LZ4 frame. Its
`compressed_bytes` field is the exact completed artifact size. To avoid a self-referential
compressed-size fixed point, the producer selects the content-independent target
`prior_frame_bytes + LZ4F_compressFrameBound(TRACE_END bytes) + 8`, then appends one standard LZ4
skippable frame whose exact length fills the positive difference between that target and the
actual `TRACE_END` frame. Skippable payload bytes are zero and have no decoded QTRB meaning. Host
frame scanners accept and ignore complete skippable frames; a truncated skippable tail is a
truncated final frame under the existing crash-marker recovery rule.

A binary record never crosses a producer-buffer boundary. If the remaining span is too small, the
writer publishes the current buffer before encoding that record. A record larger than the
documented maximum fails the trace rather than partially encoding it.

Independent LZ4 frames provide lightweight partial-trace recovery without per-record checksums or
device-side retry. A valid crash marker permits the host to discard only the incomplete final
frame and convert preceding complete frames. Corruption in a nominally complete run is an error.

## Text Format 3

The converter emits UTF-8 text with one visible event per line. It preserves every piece of
information exposed by the corresponding current profile while using consistent event names and
`key=value` fields:

```text
TRACE_BEGIN format=3 ...
INST seq=1 pc=... asm="..." reads=[...] writes=[...] memory=[...]
CALL category=... name=... detail=...
RULE name=... detail=...
ERROR detail=...
TRACE_END status=ok ...
```

Strings use one documented escaping rule. Field order is stable within a format version. The
converter, rather than the device, performs disassembly rendering, absolute PC-relative target
calculation, register-name rendering, hexadecimal formatting, and decimal formatting.

## Metrics

The metrics sidecar is upgraded to version 2.

- `encoded_bytes` is the uncompressed binary byte count.
- `compressed_bytes` remains the bytes written to `.trace.bin.lz4`.
- `instructions`, elapsed time, instruction throughput, cache statistics, buffer swaps, producer
  waits, producer wait time, effective buffer size, profile, and return value remain available.
- The converter reports `converted_text_bytes` after successful conversion.

The old `raw_bytes` key retains its format-2 text meaning for old artifacts and is not silently
redefined for binary artifacts.

## Failure Semantics

An encoding, allocation, compression, synchronization, or write failure latches trace failure and
prevents subsequent event work. It must not change whether the target executes or alter its native
return value. A failed run does not publish a success metrics sidecar.

The converter accepts QTRB major 1 minor 0..1. Types `0x8000..0xffff` are optional extension
records and may be skipped only when well framed, zero flagged, inside the begun lifecycle, and
outside continuation groups. Unknown lower-numbered required records, unknown required feature
bits, and newer minor versions fail closed. The converter validates magic, version compatibility, feature flags, pointer width, record sizes,
bounded lengths, dictionary definitions, dictionary references, sequence continuity, footer, and
sidecar consistency. It rejects unknown required features and incompatible major versions.

Normal conversion writes to a unique temporary file and atomically renames it only after complete
validation. A valid crash marker plus a truncated final frame produces `.partial.trace.txt` and a
distinct partial-success exit status. The converter never publishes bytes from an incomplete
frame or guesses through corrupt data.

## Verification

### Protocol tests

- Exact golden bytes for every record type.
- Header version, byte order, length boundaries, buffer-tail publication, and unknown record
  handling.
- One definition for repeated metadata followed only by identifier references.
- Dense register values preserve W/X, SP, LR, NZCV, PC, widths, names, and masks.
- All balanced/full memory forms, continuations, and before/after states.

### Converter tests

- All profiles convert to a complete format-3 event stream.
- Converted events compare field-for-field with the producer event model.
- CALL, RULE, ERROR, PC-relative classes, module identities, special registers, and string escaping.
- Invalid lengths, missing definitions, invalid references, sequence gaps, corrupt complete frames,
  and inconsistent footer/sidecar data fail closed.
- A crash-truncated final frame yields only the preceding complete frames.
- A 1 GiB fixture is processed with bounded memory rather than whole-file buffering.

### Lifecycle and stress tests

- A Debug-only 4 KiB buffer forces repeated swaps without loss, duplication, or reordering.
- Allocation, compression, first/final write, short-write, thread, and synchronization failures
  preserve the target result and suppress success metrics.
- Existing fork, nested-fork, crash-marker, fd-reuse, and child-detach regressions remain green.
- Release rejects Debug-only fault and sizing options.

### Pixel 6 acceptance

Each profile runs one unreported warmup followed by five fresh-process measurements on the same
Pixel 6, Android version, app/tracer build, benchmark scene, and workload. Every accepted run must
have the expected return value, a paired artifact and sidecar, continuous instruction sequence,
valid footer, complete conversion, and no crash marker.

- `fast` median is at least 1,000,000 instructions per second.
- `balanced` median is at least 800,000 instructions per second.
- `full` median is at least 500,000 instructions per second.
- Each compressed binary artifact is no larger than its current compressed-text counterpart for
  the same profile and workload.

One large-workload run must demonstrate continuous target progress and complete conversion. If a
throughput target is missed, the result is reported with profiling evidence; fields may not be
removed and events may not be sampled to manufacture a pass.

## Explicit Exclusions

- No `O_DIRECT` or `io_uring`.
- No sampling or event loss.
- No change from QBDI instrumentation.
- No per-event file syscall.
- No per-record checksum or repair of corrupt bytes.
- No removal of profile information.
- No requirement to reproduce format-2 text byte-for-byte.
