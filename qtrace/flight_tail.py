"""Raw Flight tail pages, including events from scenes without a return."""
from __future__ import annotations

import heapq
import json

from qtrace.flight_reader import FlightReader, checked_json, event_rows, query_path
from scripts.flight_trace import FlightTraceError, _parse_emergencies

MAX_PAYLOAD_BYTES = 64 * 1024 * 1024


def query_tail(source, source_size, *, after_sequence=0, until_sequence=2**64 - 1,
               limit=30, timeout=30.0, cancelled=None):
    if not (type(limit) is int and 1 <= limit <= 2000 and
            type(after_sequence) is int and type(until_sequence) is int and
            0 <= after_sequence <= until_sequence <= 2**64 - 1):
        raise FlightTraceError("invalid tail sequence range or row limit")
    reader = FlightReader(source, source_size, timeout=timeout,
                          max_payload_bytes=MAX_PAYLOAD_BYTES, cancelled=cancelled)
    rows, seen = [], set()
    output_bytes = 0

    def append(row):
        nonlocal output_bytes
        sequence = row["sequence"]
        if not after_sequence < sequence <= until_sequence:
            return
        if len(rows) > limit and sequence <= rows[0][0]:
            return
        size = len(json.dumps(row, ensure_ascii=False).encode("utf-8"))
        if len(rows) > limit:
            output_bytes -= heapq.heappop(rows)[2]
        output_bytes += size
        if output_bytes > 16 * 1024 * 1024:
            raise FlightTraceError("Flight query exceeds the 16 MiB JSON page bound")
        heapq.heappush(rows, (sequence, row, size))

    emergencies, _ = _parse_emergencies(source, reader.block, 0)
    for event in emergencies:
        if event.global_seq in seen:
            raise FlightTraceError(f"duplicate global sequence {event.global_seq}")
        seen.add(event.global_seq)
    for row in event_rows(emergencies, ()):
        append(row)
    # Active ranges are unpublished. Read those chunks before using sealed ranges
    # to stop at the oldest retained event in the page.
    chunks = sorted(reader.chunks, key=lambda chunk: (chunk.state == 2, -chunk.last, chunk.index))
    for chunk in chunks:
        reader.check()
        if chunk.state == 2:
            if chunk.last <= after_sequence or chunk.first > until_sequence:
                continue
            if len(rows) > limit and chunk.last < rows[0][0]:
                break
        records, events, fragments, _ = reader.read(chunk)
        for record in records:
            if record.sequence in seen:
                raise FlightTraceError(f"duplicate global sequence {record.sequence}")
            seen.add(record.sequence)
        for index, row in enumerate(event_rows(events, fragments)):
            if index % 128 == 0:
                reader.check()
            append(row)
    ordered = [item[1] for item in sorted(rows, key=lambda item: item[0])]
    has_more = len(ordered) > limit
    ordered = ordered[-limit:]
    return checked_json({"rows": ordered, "has_more": has_more,
        "next_until_sequence": ordered[0]["sequence"] - 1 if has_more else None,
        "payload_bytes_read": reader.payload_bytes, "decoded_chunks": reader.decoded_chunks,
        "metadata_bytes_read": reader.metadata_bytes,
        "scene_context": "not_resolved", "target_returned": None,
        "verification_scope": "decoded chunks and emergency slots; no global recovery; fragments are not assembled"},
        reader.check)


def query_tail_path(path, **options):
    return query_path(path, query_tail, **options)
