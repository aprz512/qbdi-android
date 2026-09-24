#!/usr/bin/env python3
"""Generate a deterministic, untracked QTRB corpus with typed events.

The original 10M mostly-optional corpus remains the scale gate. This smaller
corpus exercises the work that optional records cannot: register replay,
memory/semantic queries, compressed input, and a large call tree.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import struct
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tests.test_trace_binary import (  # noqa: E402
    begin, call, footer, instruction_definition, memory, module, record,
    stream_header,
)
from generate_performance_fixtures import (  # noqa: E402
    _atomic_target, _publish, _safe_output,
)


EVENT_GROUPS = 20_000
CALL_FRAMES = 5_000
RAW_SEMANTIC_SHA256 = "f00f7a25b0cc773903d42235bfbf629c2bea883fa88cfefd3d37ab72e8eadd7e"


def _atomic_write(target: Path, payload: bytes) -> None:
    descriptor, temporary, destination = _atomic_target(target.parent, target.name)
    try:
        with open(descriptor, "wb", closefd=False) as sink:
            sink.write(payload)
            sink.flush()
        _publish(descriptor, temporary, destination)
        descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _instruction(sequence: int, metadata_id: int, relative_pc: int) -> bytes:
    payload = struct.pack("<QIQIBB", sequence, 1, relative_pc, metadata_id, 2, 2)
    payload += struct.pack("<QQQQ", sequence, 0x71000000 + sequence, sequence + 1, 0x71001000)
    return record(4, payload)


def _definition(metadata_id: int, flags: int) -> bytes:
    encoded = bytearray(instruction_definition(metadata_id=metadata_id))
    struct.pack_into("<I", encoded, 8 + 32, flags)
    return bytes(encoded)


def _raw_corpus() -> bytes:
    prefix = (
        stream_header(minor=2, features=1)
        + begin()
        + module(name="libqtrace_rich.so")
        + _definition(99, 0)
        + _definition(100, 1 << 2)
        + _definition(101, 1 << 3)
    )
    chunks = [prefix]
    sequence = 0
    for index in range(EVENT_GROUPS):
        sequence += 1
        chunks.append(_instruction(sequence, 99, 0x2000 + index * 4))
        chunks.append(memory())
        chunks.append(call("jni", "Lookup", "rich-corpus"))
        sequence += 1
        if index < CALL_FRAMES:
            kind = 100
        elif index < CALL_FRAMES * 2:
            kind = 101
        else:
            kind = 99
        chunks.append(_instruction(sequence, kind, 0x22000 + index * 4))
        sequence += 1
        chunks.append(_instruction(sequence, 99, 0x42000 + index * 4))
    initial_footer = footer(instructions=sequence)
    encoded_bytes = sum(map(len, chunks)) + len(initial_footer)
    chunks.append(footer(
        instructions=sequence,
        encoded_bytes=encoded_bytes,
        compressed_bytes=encoded_bytes,
    ))
    return b"".join(chunks)


def _compress_lz4_frame(payload: bytes) -> bytes:
    library_name = ctypes.util.find_library("lz4")
    if library_name is None:
        raise RuntimeError("liblz4 is required to generate compressed QTRB")
    library = ctypes.CDLL(library_name)
    library.LZ4F_compressFrameBound.argtypes = [ctypes.c_size_t, ctypes.c_void_p]
    library.LZ4F_compressFrameBound.restype = ctypes.c_size_t
    library.LZ4F_compressFrame.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p,
    ]
    library.LZ4F_compressFrame.restype = ctypes.c_size_t
    library.LZ4F_isError.argtypes = [ctypes.c_size_t]
    library.LZ4F_isError.restype = ctypes.c_uint
    capacity = library.LZ4F_compressFrameBound(len(payload), None)
    if library.LZ4F_isError(capacity):
        raise RuntimeError("LZ4 frame bound failed")
    destination = ctypes.create_string_buffer(capacity)
    size = library.LZ4F_compressFrame(destination, capacity, payload, len(payload), None)
    if library.LZ4F_isError(size):
        raise RuntimeError("LZ4 frame compression failed")
    return destination.raw[:size]


def generate(output: Path) -> Path:
    output = _safe_output(output)
    raw = _raw_corpus()
    if hashlib.sha256(raw).hexdigest() != RAW_SEMANTIC_SHA256:
        raise RuntimeError("rich corpus semantic fingerprint drift")
    compressed = _compress_lz4_frame(raw)
    raw_name = "qtrb-rich-100k.trace.bin"
    compressed_name = raw_name + ".lz4"
    _atomic_write(output / raw_name, raw)
    _atomic_write(output / compressed_name, compressed)
    manifest = {
        "schema": 1,
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "semantic_sha256": RAW_SEMANTIC_SHA256,
        "semantic_oracle": {
            "events": EVENT_GROUPS * 5 + 6,
            "instructions": EVENT_GROUPS * 3,
            "memory_events": EVENT_GROUPS,
            "semantic_events": EVENT_GROUPS,
            "call_frames": CALL_FRAMES,
            "thread_and_gap_source": "flight-512m.flight.bin",
        },
        "corpora": {
            "raw": {"path": raw_name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "events": EVENT_GROUPS * 5 + 6},
            "compressed": {
                "path": compressed_name,
                "bytes": len(compressed),
                "sha256": hashlib.sha256(compressed).hexdigest(),
                "events": EVENT_GROUPS * 5 + 6,
            },
        },
    }
    target = output / "rich-manifest.json"
    _atomic_write(target, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(generate(args.output))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"rich fixture generator: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
