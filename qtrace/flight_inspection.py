"""Bounded Flight metadata preview, before event decoding or indexing."""
from __future__ import annotations

import os
import heapq
import math
from pathlib import Path
import stat
import time

from scripts.flight_trace import (CHUNK_HEADER_BYTES, DIRECTORY_ENTRY_BYTES, SUPERBLOCK_BYTES,
    FlightTraceError, _parse_directories, _parse_superblock, _read_chunk_header)
from scripts.flight_trace import (_decode_chunk, _fnv32, _read_at, _scan_chunk_data,
                                 scene_lifecycle)


def inspect_flight(source, source_size: int, *, timeout: float = 5.0, cancelled=None):
    if not math.isfinite(timeout) or timeout <= 0:
        raise FlightTraceError("Flight metadata inspection deadline must be finite and positive")
    deadline = time.monotonic() + timeout
    def check():
        if cancelled and cancelled():
            raise KeyboardInterrupt
        if time.monotonic() > deadline:
            raise FlightTraceError("Flight metadata inspection deadline exceeded")
    check()
    block = _parse_superblock(source, source_size)
    metadata_bytes = (SUPERBLOCK_BYTES + block.directory_entries * DIRECTORY_ENTRY_BYTES +
                      block.chunk_count * CHUNK_HEADER_BYTES)
    if block.directory_entries > 1024 or metadata_bytes > 8 * 1024 * 1024:
        raise FlightTraceError("Flight metadata exceeds the 8 MiB/1024-thread inspection bound")
    directories = _parse_directories(source, block)
    tids = {item.tid for item in directories}
    sealed = active = claimed_records = claimed_bytes = 0
    for index in range(block.chunk_count):
        check()
        header = _read_chunk_header(source, block, index, tids)
        if header is None:
            continue
        state, _, _, _, _, committed, count, _ = header
        if state == 1:
            active += 1
        else:
            sealed += 1
            claimed_records += count
            claimed_bytes += committed
    return {"format_version": block.version, "run_id": block.run_id, "pid": block.pid,
            "target_module": block.target, "artifact_bytes": block.artifact_bytes,
            "artifact_flags": block.flags, "tids": sorted(tids), "chunk_count": block.chunk_count,
            "active_chunks": active, "sealed_chunks": sealed,
            "claimed_records": claimed_records, "claimed_committed_bytes": claimed_bytes,
            "metadata_bytes_read": metadata_bytes, "payload_verification": "not_performed",
            "target_returned": None}


def inspect_path(path: Path, *, timeout: float = 5.0):
    with path.open("rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise FlightTraceError("Flight inspection requires a regular file")
        result = inspect_flight(source, before.st_size, timeout=timeout)
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise FlightTraceError("Flight source changed during metadata inspection")
        return result


def query_scene_boundaries(source, source_size: int, *, since_ns: int = 0,
                           until_ns: int = 2**64 - 1, after_sequence: int = 0,
                           limit: int = 2000, timeout: float = 5.0, cancelled=None):
    """Scan bounded chunks for actual scene timestamps, without a global index.

    Instruction events have no timestamps. Results describe individual boundary
    records, not paired calls or whole-artifact integrity. Each page rescans the
    source; after_sequence is an exclusive cursor for the same immutable source.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise FlightTraceError("Flight scene query deadline must be finite and positive")
    if not (type(limit) is int and 1 <= limit <= 2000 and
            type(since_ns) is int and type(until_ns) is int and
            0 <= since_ns <= until_ns <= 2**64 - 1 and
            type(after_sequence) is int and 0 <= after_sequence <= 2**64 - 1):
        raise FlightTraceError("invalid scene time range, sequence cursor or row limit")
    deadline = time.monotonic() + timeout
    def check():
        if cancelled and cancelled():
            raise KeyboardInterrupt
        if time.monotonic() > deadline:
            raise FlightTraceError("Flight scene query deadline exceeded")
    check()
    block = _parse_superblock(source, source_size)
    metadata_bytes = SUPERBLOCK_BYTES + block.directory_entries * DIRECTORY_ENTRY_BYTES + block.chunk_count * CHUNK_HEADER_BYTES
    if block.directory_entries > 1024 or metadata_bytes > 8 * 1024 * 1024 or block.chunk_bytes > 1024 * 1024:
        raise FlightTraceError("Flight scene query metadata/chunk bound exceeded")
    tids = {entry.tid for entry in _parse_directories(source, block)}
    rows = []
    matched = payload_bytes = decoded_chunks = invalid = ordinal = 0
    for index in range(block.chunk_count):
        check()
        header = _read_chunk_header(source, block, index, tids)
        if header is None:
            continue
        state, tid, generation, first, last, committed, count, checksum = header
        if state == 2 and last <= after_sequence:
            continue
        size = committed if state == 2 else block.chunk_bytes - CHUNK_HEADER_BYTES
        payload_bytes += size
        if payload_bytes > 64 * 1024 * 1024:
            raise FlightTraceError("Flight scene query exceeds the 64 MiB payload scan bound")
        offset = block.chunk_offset + index * block.chunk_bytes + CHUNK_HEADER_BYTES
        data = _read_at(source, offset, size, f"scene query chunk {index}")
        if state == 2 and _fnv32(data) != checksum:
            raise FlightTraceError(f"scene query sealed chunk {index} checksum mismatch")
        records = _scan_chunk_data(data, generation, offset, ordinal, active=state == 1)
        ordinal += len(records)
        if state == 2 and (not records or len(records) != count or records[0].sequence != first or records[-1].sequence != last):
            raise FlightTraceError("scene query sealed chunk record count/range mismatch")
        if not records:
            continue
        events, fragments = [], []
        _decode_chunk(records, tid, index, block, events, fragments)
        decoded_chunks += 1
        for event in events:
            if event.kind != "rule" or event.data.get("name") != "qtrace.scene":
                continue
            boundaries, _, malformed = scene_lifecycle([event], maximum=1)
            invalid += malformed
            if not boundaries:
                continue
            row = boundaries[0]
            if not (since_ns <= row["last_monotonic_ns"] <= until_ns and event.global_seq > after_sequence):
                continue
            matched += 1
            # Keep the first limit records by global sequence, even when chunk
            # slots wrap or threads interleave. Storage is independent of matches.
            item = (-event.global_seq, -matched, {"sequence": event.global_seq, "tid": tid,
                    "id": row["id"], "address": row["address"],
                    "monotonic_ns": row["last_monotonic_ns"],
                    "phase": {"open_at_end":"enter", "returned":"return", "capture_stopped":"capture_stopped"}[row["state"]],
                    "return_value": row["return_value"]})
            if len(rows) < limit:
                heapq.heappush(rows, item)
            elif event.global_seq < -rows[0][0]:
                heapq.heapreplace(rows, item)
        check()
    ordered = [item[2] for item in sorted(rows, key=lambda item: (-item[0], -item[1]))]
    return {"rows": ordered, "has_more": matched > limit,
            "next_after_sequence": ordered[-1]["sequence"] if matched > limit else None,
            "matched_boundaries": matched, "invalid_boundaries": invalid,
            "payload_bytes_read": payload_bytes, "decoded_chunks": decoded_chunks,
            "verification_scope": "decoded chunks; no global recovery or call pairing",
            "time_model": "scene monotonic timestamps only; instructions have no timestamps"}


def query_scene_path(path: Path, **options):
    with path.open("rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise FlightTraceError("Flight scene query requires a regular file")
        result = query_scene_boundaries(source, before.st_size, **options)
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise FlightTraceError("Flight source changed during scene query")
        return result
