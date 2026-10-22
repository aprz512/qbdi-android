"""Shared bounded chunk reads for offline Flight queries."""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import stat
import time

from scripts.flight_trace import (
    CHUNK_HEADER_BYTES, DIRECTORY_ENTRY_BYTES, SUPERBLOCK_BYTES, FlightTraceError,
    _decode_chunk, _fnv32, _parse_directories, _parse_superblock, _read_at,
    _read_chunk_header, _scan_chunk_data,
)


def deadline_check(timeout, cancelled=None):
    if not math.isfinite(timeout) or timeout <= 0:
        raise FlightTraceError("Flight query deadline must be finite and positive")
    deadline = time.monotonic() + timeout

    def check():
        if cancelled and cancelled():
            raise KeyboardInterrupt
        if time.monotonic() > deadline:
            raise FlightTraceError("Flight query deadline exceeded")
    return check


def sqlite_cancellation(database, check):
    pending = []

    def progress():
        try:
            check()
        except BaseException as error:
            pending.append(error)
            return 1
        return 0
    database.set_progress_handler(progress, 1000)
    return pending


@dataclass(frozen=True)
class Chunk:
    index: int
    state: int
    tid: int
    generation: int
    first: int
    last: int
    committed: int
    count: int
    checksum: int


class FlightReader:
    def __init__(self, source, size, *, timeout, max_payload_bytes, cancelled=None):
        if not math.isfinite(timeout) or timeout <= 0:
            raise FlightTraceError("Flight query deadline must be finite and positive")
        self.source = source
        self.deadline = time.monotonic() + timeout
        self.cancelled = cancelled
        self.max_payload_bytes = max_payload_bytes
        self.payload_bytes = self.decoded_chunks = 0
        self.check()
        self.block = block = _parse_superblock(source, size)
        self.metadata_bytes = (SUPERBLOCK_BYTES + block.directory_entries * DIRECTORY_ENTRY_BYTES +
                               block.chunk_count * CHUNK_HEADER_BYTES +
                               block.emergency_count * block.emergency_record_bytes)
        if (block.directory_entries > 1024 or self.metadata_bytes > 8 * 1024 * 1024 or
                block.chunk_bytes > 1024 * 1024):
            raise FlightTraceError("Flight query metadata/chunk bound exceeded")
        self.directories = _parse_directories(source, block)
        tids = {entry.tid for entry in self.directories}
        self.chunks = []
        for index in range(block.chunk_count):
            self.check()
            header = _read_chunk_header(source, block, index, tids)
            if header is not None:
                self.chunks.append(Chunk(index, *header))

    def check(self):
        if self.cancelled and self.cancelled():
            raise KeyboardInterrupt
        if time.monotonic() > self.deadline:
            raise FlightTraceError("Flight query deadline exceeded")

    def read(self, chunk, ordinal=0):
        self.check()
        block = self.block
        size = chunk.committed if chunk.state == 2 else block.chunk_bytes - CHUNK_HEADER_BYTES
        self.payload_bytes += size
        if self.payload_bytes > self.max_payload_bytes:
            raise FlightTraceError("Flight query exceeds the payload scan bound")
        offset = block.chunk_offset + chunk.index * block.chunk_bytes + CHUNK_HEADER_BYTES
        data = _read_at(self.source, offset, size, f"query chunk {chunk.index}")
        if chunk.state == 2 and _fnv32(data) != chunk.checksum:
            raise FlightTraceError(f"query sealed chunk {chunk.index} checksum mismatch")
        records = _scan_chunk_data(data, chunk.generation, offset, ordinal, active=chunk.state == 1)
        if chunk.state == 2 and (not records or len(records) != chunk.count or
                records[0].sequence != chunk.first or records[-1].sequence != chunk.last):
            raise FlightTraceError("query sealed chunk record count/range mismatch")
        events, fragments = [], []
        state = _decode_chunk(records, chunk.tid, chunk.index, block, events, fragments) if records else None
        self.decoded_chunks += 1
        self.check()
        return records, events, fragments, state


def event_rows(events, fragments):
    for event in events:
        yield {"sequence": event.global_seq, "tid": event.tid, "kind": event.kind,
               "data": event.data, "source_offset": event.source_offset}
    for fragment in fragments:
        yield {"sequence": fragment.sequence, "tid": fragment.tid,
               "kind": "semantic_fragment", "source_offset": fragment.source_offset,
               "data": {"record_kind": fragment.kind, "event_id": fragment.event_id,
                        "index": fragment.index, "count": fragment.count,
                        "total_bytes": fragment.total, "fixed": fragment.fixed,
                        "detail_hex": fragment.detail.hex()}}


def checked_json(result, check=lambda: None):
    size = 0
    for position, part in enumerate(json.JSONEncoder(ensure_ascii=False).iterencode(result)):
        if position % 1024 == 0:
            check()
        size += len(part.encode("utf-8"))
        if size > 16 * 1024 * 1024:
            raise FlightTraceError("Flight query exceeds the 16 MiB JSON page bound")
    check()
    return result


def file_identity(source):
    info = os.fstat(source.fileno())
    if not stat.S_ISREG(info.st_mode):
        raise FlightTraceError("Flight query requires a regular file")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def query_path(path: Path, query, **options):
    with path.open("rb") as source:
        before = file_identity(source)
        result = query(source, before[2], **options)
        if file_identity(source) != before:
            raise FlightTraceError("Flight source changed during query")
        return result
