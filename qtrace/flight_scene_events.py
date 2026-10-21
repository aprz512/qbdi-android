"""Bounded event pages selected by captured scene intervals, without a global index."""
from __future__ import annotations

import heapq
import json
import math
import os
from pathlib import Path
import stat
import struct
import time

from scripts.flight_trace import (
    CHUNK_HEADER_BYTES, DIRECTORY_ENTRY_BYTES, SUPERBLOCK_BYTES, FlightTraceError,
    _decode_chunk, _fnv32, _parse_directories, _parse_superblock, _read_at,
    _read_chunk_header, _scan_chunk_data, scene_lifecycle,
)

_MAX_PAYLOAD_BYTES = 512 * 1024 * 1024


def query_scene_events(source, source_size: int, *, since_ns: int = 0,
                       until_ns: int = 2**64 - 1, after_sequence: int = 0,
                       limit: int = 2000, timeout: float = 30.0, cancelled=None):
    """Select whole overlapping scenes, not individual event timestamps.

    Only paired enter/return or enter/capture_stopped boundaries establish an
    interval. Open or orphaned boundaries do not establish an end time. Pages
    rescan the immutable source and order execution events by global sequence.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise FlightTraceError("Flight scene event query deadline must be finite and positive")
    if not (type(limit) is int and 1 <= limit <= 2000 and
            type(since_ns) is int and type(until_ns) is int and
            0 <= since_ns <= until_ns <= 2**64 - 1 and
            type(after_sequence) is int and 0 <= after_sequence <= 2**64 - 1):
        raise FlightTraceError("invalid scene event time range, sequence cursor or row limit")
    deadline = time.monotonic() + timeout

    def check():
        if cancelled and cancelled():
            raise KeyboardInterrupt
        if time.monotonic() > deadline:
            raise FlightTraceError("Flight scene event query deadline exceeded")

    check()
    block = _parse_superblock(source, source_size)
    metadata = (SUPERBLOCK_BYTES + block.directory_entries * DIRECTORY_ENTRY_BYTES +
                block.chunk_count * CHUNK_HEADER_BYTES)
    if block.directory_entries > 1024 or metadata > 8 * 1024 * 1024 or block.chunk_bytes > 1024 * 1024:
        raise FlightTraceError("Flight scene event query metadata/chunk bound exceeded")
    tids = {entry.tid for entry in _parse_directories(source, block)}
    headers = []
    for index in range(block.chunk_count):
        check()
        header = _read_chunk_header(source, block, index, tids)
        if header is not None:
            order = header[3]
            if header[0] == 1:
                # Active header ranges are not publication facts. Order by the
                # first physical record, validated during the bounded scan.
                metadata += 24
                if metadata > 8 * 1024 * 1024:
                    raise FlightTraceError("Flight scene event query metadata/chunk bound exceeded")
                first_record = _read_at(source, block.chunk_offset + index * block.chunk_bytes +
                                        CHUNK_HEADER_BYTES, 24, "active scene event record header")
                order = struct.unpack_from("<Q", first_record, 8)[0]
            headers.append((index, header, order))
    # Chunk slots rotate. Sequence order is required to pair a thread's scenes.
    headers.sort(key=lambda item: (item[2], item[0]))
    payload_bytes = decoded_chunks = fragments_seen = 0

    def chunks(selected=None):
        nonlocal payload_bytes, decoded_chunks, fragments_seen
        for index, header, _ in headers:
            check()
            state, tid, generation, first, last, committed, count, checksum = header
            if selected is not None and state == 2 and not any(
                    scene["tid"] == tid and scene["entry_sequence"] <= last and
                    scene["last_sequence"] >= first for scene in selected.get(tid, ())):
                continue
            size = committed if state == 2 else block.chunk_bytes - CHUNK_HEADER_BYTES
            payload_bytes += size
            # Two passes share this limit; memory retains only one decoded chunk
            # plus at most limit+1 scenes and rows. This is a separate operation
            # from the 64 MiB boundary-only query.
            if payload_bytes > _MAX_PAYLOAD_BYTES:
                raise FlightTraceError("Flight scene event query exceeds the 512 MiB payload scan bound")
            offset = block.chunk_offset + index * block.chunk_bytes + CHUNK_HEADER_BYTES
            data = _read_at(source, offset, size, f"scene event chunk {index}")
            if state == 2 and _fnv32(data) != checksum:
                raise FlightTraceError(f"scene event sealed chunk {index} checksum mismatch")
            records = _scan_chunk_data(data, generation, offset, 0, active=state == 1)
            if state == 2 and (not records or len(records) != count or
                               records[0].sequence != first or records[-1].sequence != last):
                raise FlightTraceError("scene event sealed chunk record count/range mismatch")
            if not records:
                continue
            events, fragments = [], []
            _decode_chunk(records, tid, index, block, events, fragments)
            decoded_chunks += 1
            fragments_seen += len(fragments)
            yield events, fragments
            check()

    active = {}
    scenes = []
    crossing = []
    matched = invalid = orphaned = 0
    for events, _ in chunks():
        for position, event in enumerate(events):
            if position % 128 == 0:
                check()
            if event.kind != "rule" or event.data.get("name") != "qtrace.scene":
                continue
            boundaries, _, malformed = scene_lifecycle([event], maximum=1)
            invalid += malformed
            if not boundaries:
                continue
            boundary = boundaries[0]
            key = (event.tid, boundary["id"])
            if boundary["state"] == "open_at_end":
                if key in active:
                    raise FlightTraceError("ambiguous duplicate scene entry")
                if len(active) >= 4096:
                    raise FlightTraceError("Flight scene event query exceeds the 4096 open-scene bound")
                active[key] = boundary
                continue
            entry = active.pop(key, None)
            if entry is None:
                orphaned += 1
                continue
            if (entry["address"] != boundary["address"] or
                    entry["entry_sequence"] >= event.global_seq or
                    entry["entered_monotonic_ns"] > boundary["last_monotonic_ns"]):
                invalid += 1
                continue
            if (entry["entered_monotonic_ns"] > until_ns or
                    boundary["last_monotonic_ns"] < since_ns or event.global_seq <= after_sequence):
                continue
            matched += 1
            scene = {**boundary, "entry_sequence": entry["entry_sequence"],
                     "entered_monotonic_ns": entry["entered_monotonic_ns"]}
            if entry["entry_sequence"] <= after_sequence:
                if len(crossing) >= 4096:
                    raise FlightTraceError("Flight scene event query exceeds the 4096 cursor-scene bound")
                crossing.append(scene)
                continue
            item = (-max(entry["entry_sequence"], after_sequence), -matched, scene)
            if len(scenes) <= limit:
                heapq.heappush(scenes, item)
            elif item[:2] > scenes[0][:2]:
                heapq.heapreplace(scenes, item)
    selected = crossing + [item[2] for item in scenes]
    by_tid = {}
    for scene in selected:
        by_tid.setdefault(scene["tid"], []).append(scene)
    rows = []
    candidates = 0

    def append(sequence, tid, kind, data, offset):
        nonlocal candidates
        if sequence <= after_sequence:
            return
        owners = [scene for scene in by_tid.get(tid, ()) if
                  scene["entry_sequence"] <= sequence <= scene["last_sequence"]]
        if not owners:
            return
        # Nested intervals select the innermost matching scene, without emitting
        # the same execution event multiple times.
        owner = max(owners, key=lambda scene: scene["entry_sequence"])
        row = {"sequence": sequence, "tid": tid, "kind": kind, "data": data,
               "source_offset": offset, "scene_id": owner["id"],
               "scene_entry_sequence": owner["entry_sequence"],
               "time_source": "scene_interval", "event_monotonic_ns": None}
        candidates += 1
        item = (-sequence, -candidates, row)
        if len(rows) <= limit:
            heapq.heappush(rows, item)
        elif item[:2] > rows[0][:2]:
            heapq.heapreplace(rows, item)

    if selected:
        for events, fragments in chunks(by_tid):
            for position, event in enumerate(events):
                if position % 128 == 0:
                    check()
                append(event.global_seq, event.tid, event.kind, event.data, event.source_offset)
            for position, fragment in enumerate(fragments):
                if position % 128 == 0:
                    check()
                append(fragment.sequence, fragment.tid, "semantic_fragment",
                       {"record_kind": fragment.kind, "event_id": fragment.event_id,
                        "index": fragment.index, "count": fragment.count,
                        "total_bytes": fragment.total, "fixed": fragment.fixed,
                        "detail_hex": fragment.detail.hex()}, fragment.source_offset)
    ordered = [item[2] for item in sorted(rows, key=lambda item: (-item[0], -item[1]))]
    has_more = len(ordered) > limit
    ordered = ordered[:limit]
    owners = {(row["tid"], row["scene_id"], row["scene_entry_sequence"]) for row in ordered}
    check()
    result = {"rows": ordered, "has_more": has_more,
            "next_after_sequence": ordered[-1]["sequence"] if has_more else None,
            "scenes": sorted((scene for scene in selected if (scene["tid"], scene["id"], scene["entry_sequence"]) in owners),
                             key=lambda scene: scene["entry_sequence"]),
            "matched_scenes": matched, "invalid_boundaries": invalid,
            "unpaired_boundaries": orphaned + len(active),
            "payload_bytes_read": payload_bytes, "decoded_chunks": decoded_chunks,
            "metadata_bytes_read": metadata,
            "fragment_records_scanned": fragments_seen,
            "verification_scope": "decoded chunks; no global recovery; fragments are not assembled",
            "time_model": "whole scenes overlapping the inclusive time range; events have no individual timestamps"}
    output_bytes = 0
    for position, part in enumerate(json.JSONEncoder(ensure_ascii=False).iterencode(result)):
        if position % 1024 == 0:
            check()
        output_bytes += len(part.encode("utf-8"))
        if output_bytes > 16 * 1024 * 1024:
            raise FlightTraceError("Flight scene event query exceeds the 16 MiB JSON page bound")
    check()
    return result


def query_scene_events_path(path: Path, **options):
    with path.open("rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise FlightTraceError("Flight scene event query requires a regular file")
        result = query_scene_events(source, before.st_size, **options)
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise FlightTraceError("Flight source changed during scene event query")
        return result
