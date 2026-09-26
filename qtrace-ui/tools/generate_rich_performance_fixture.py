#!/usr/bin/env python3
"""Generate a deterministic, untracked QTRB corpus with typed events.

The original 10M mostly-optional corpus remains the scale gate. The scalable rich
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
    _atomic_target, _publish, _safe_output, generate_flight, EXPECTED_FLIGHT_COMPLETENESS,
)


EVENT_GROUPS = 20_000
CALL_FRAMES = 5_000
RAW_SEMANTIC_SHA256 = "f00f7a25b0cc773903d42235bfbf629c2bea883fa88cfefd3d37ab72e8eadd7e"
MILLION_SEMANTIC_SHA256 = "5718b952fd2d3667f017bec186449c501ef351d1a42cc108fe7fbff5091132ba"


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


def _records(groups: int):
    prefix = (
        stream_header(minor=2, features=1)
        + begin()
        + module(name="libqtrace_rich.so")
        + _definition(99, 0)
        + _definition(100, 1 << 2)
        + _definition(101, 1 << 3)
    )
    yield prefix
    sequence = 0
    for index in range(groups):
        sequence += 1
        yield (_instruction(sequence, 99, 0x2000 + index * 4))
        yield (memory())
        yield (call("jni", "Lookup", "rich-corpus"))
        sequence += 1
        if index < CALL_FRAMES:
            kind = 100
        elif index < CALL_FRAMES * 2:
            kind = 101
        else:
            kind = 99
        yield (_instruction(sequence, kind, 0x22000 + index * 4))
        sequence += 1
        yield (_instruction(sequence, 99, 0x42000 + index * 4))


def _raw_corpus() -> bytes:
    chunks = list(_records(EVENT_GROUPS))
    initial_footer = footer(instructions=EVENT_GROUPS * 3)
    encoded_bytes = sum(map(len, chunks)) + len(initial_footer)
    chunks.append(footer(instructions=EVENT_GROUPS * 3, encoded_bytes=encoded_bytes, compressed_bytes=encoded_bytes))
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


def generate(output: Path, groups: int = 200_000) -> Path:
    if groups not in (20_000, 200_000, 2_000_000):
        raise ValueError("groups must be 20000, 200000 or 2000000")
    output = _safe_output(output)
    ipc_corpus = None
    if groups > EVENT_GROUPS:
        small_manifest = json.loads(generate(output, EVENT_GROUPS).read_text())
        ipc_corpus = small_manifest["corpora"]["raw"]
    raw_name = f"qtrb-rich-{groups * 5}.trace.bin"
    compressed_name = raw_name + ".lz4"
    descriptor, temporary, target = _atomic_target(output, raw_name)
    digest = hashlib.sha256()
    total = 0
    try:
        with os.fdopen(descriptor, "wb", closefd=False, buffering=1024 * 1024) as sink:
            for encoded in _records(groups):
                sink.write(encoded)
                digest.update(encoded)
                total += len(encoded)
            total += len(footer())
            terminal = footer(instructions=groups * 3, encoded_bytes=total, compressed_bytes=total)
            sink.write(terminal)
            digest.update(terminal)
            sink.flush()
        expected_digest = {EVENT_GROUPS: RAW_SEMANTIC_SHA256, 200_000: MILLION_SEMANTIC_SHA256}.get(groups)
        if expected_digest is not None and digest.hexdigest() != expected_digest:
            raise RuntimeError("rich corpus semantic fingerprint drift")
        _publish(descriptor, temporary, target)
        descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    descriptor, temporary, compressed_target = _atomic_target(output, compressed_name)
    compressed_digest = hashlib.sha256()
    compressed_bytes = 0
    try:
        with target.open("rb") as source, os.fdopen(descriptor, "wb", closefd=False) as sink:
            # Independent frames keep generator memory bounded even for 10M typed events.
            for payload in iter(lambda: source.read(4 * 1024 * 1024), b""):
                encoded = _compress_lz4_frame(payload)
                sink.write(encoded)
                compressed_digest.update(encoded)
                compressed_bytes += len(encoded)
            sink.flush()
        _publish(descriptor, temporary, compressed_target)
        descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    flight = generate_flight(output)
    manifest = {
        "schema": 2,
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "semantic_sha256": digest.hexdigest(),
        "expected_flight_completeness": EXPECTED_FLIGHT_COMPLETENESS,
        "semantic_oracle": {
            "events": groups * 5 + 6,
            "instructions": groups * 3,
            "memory_events": groups,
            "semantic_events": groups,
            "call_frames": CALL_FRAMES,
            "flight_threads": [101, 202, 303, 404],
        },
        "corpora": {
            "raw": {"path": raw_name, "bytes": total, "sha256": digest.hexdigest(), "events": groups * 5 + 6},
            "compressed": {"path": compressed_name, "bytes": compressed_bytes, "sha256": compressed_digest.hexdigest(), "events": groups * 5 + 6},
            "flight": flight,
            "ipc": ipc_corpus or {"path": raw_name, "bytes": total, "sha256": digest.hexdigest(), "events": groups * 5 + 6},
        },
    }
    target = output / "rich-manifest.json"
    _atomic_write(target, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--groups", type=int, choices=(20_000, 200_000, 2_000_000), default=200_000)
    args = parser.parse_args()
    try:
        print(generate(args.output, args.groups))
    except (OSError, RuntimeError, ValueError) as error:
        print(f"rich fixture generator: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
