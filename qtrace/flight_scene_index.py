"""Explicit, disk-backed scene indexes bound to an immutable Flight source."""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import tempfile

from qtrace.flight_reader import FlightReader, checked_json, deadline_check, file_identity, sqlite_cancellation
from scripts.flight_trace import FlightTraceError, INVALID_INDEX, _parse_emergencies, scene_lifecycle

INDEX_VERSION = 1
DEFAULT_SCAN_BYTES = 4 * 1024**3


def _key(sequence):
    return sequence.to_bytes(8, "big")


def _number(value):
    return int.from_bytes(value, "big")


def _runs(records):
    first = last = None
    for record in records:
        if first is not None and record.sequence != last + 1:
            yield _key(first), _key(last)
            first = None
        if first is None:
            first = record.sequence
        last = record.sequence
    if first is not None:
        yield _key(first), _key(last)


def _put_meta(database, key, value):
    database.execute("INSERT INTO metadata VALUES (?,?)", (key, json.dumps(value)))


def _meta(database, key):
    result = database.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
    if result is None:
        raise FlightTraceError("incomplete Flight scene index")
    return json.loads(result[0])


def build_scene_index(path: Path, index_path: Path, *, timeout=300.0,
                      max_payload_bytes=DEFAULT_SCAN_BYTES, cancelled=None, force=False):
    if type(max_payload_bytes) is not int or max_payload_bytes <= 0:
        raise FlightTraceError("index payload scan bound must be a positive integer")
    if index_path.resolve() == path.resolve() or (
            index_path.exists() and path.exists() and os.path.samefile(path, index_path)):
        raise FlightTraceError("Flight index destination must differ from its source artifact")
    if index_path.exists() and not force:
        raise FileExistsError(f"Flight index already exists: {index_path}")
    index_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".flight-index-", dir=index_path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    database = sqlite3.connect(temporary)
    pending = []
    try:
        database.executescript("""
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            PRAGMA cache_size=-4096;
            PRAGMA temp_store=FILE;
            PRAGMA max_page_count=2097152;
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE boundaries(sequence BLOB PRIMARY KEY, tid INTEGER, row TEXT);
            CREATE TABLE instructions(tid INTEGER, sequence BLOB);
            CREATE TABLE runs(first BLOB, last BLOB);
            CREATE TABLE gaps(first BLOB, last BLOB);
            CREATE TABLE coverage(sequence BLOB, tid INTEGER);
            CREATE TABLE calls(tid INTEGER, entry BLOB, ending BLOB, row TEXT,
                               address TEXT, state TEXT, has_entry INTEGER, instructions INTEGER);
        """)
        with path.open("rb") as source:
            identity = file_identity(source)
            reader = FlightReader(source, identity[2], timeout=timeout,
                max_payload_bytes=max_payload_bytes, cancelled=cancelled)
            pending = sqlite_cancellation(database, reader.check)
            last_by_tid = {}
            recorded_tids = set()
            thread_begins = set()
            invalid = physical_count = instruction_count = typed_damage = 0
            headers = {chunk.index: (chunk.tid, chunk.generation) for chunk in reader.chunks}
            stale_entries = [entry.index for entry in reader.directories
                if entry.state != 2 and entry.chunk_index != INVALID_INDEX and
                headers.get(entry.chunk_index) != (entry.tid, entry.generation)]
            unreliable_entries = [entry.index for entry in reader.directories if not entry.range_reliable]
            first_sequence = last_sequence = None
            for chunk in reader.chunks:
                records, events, fragments, _ = reader.read(chunk)
                if any(fragment.kind == 7 and fragment.fixed[0] == "qtrace.scene" for fragment in fragments):
                    # A scene boundary may itself be fragmented. Indexing one
                    # fragment as a complete rule would invent scene membership.
                    raise FlightTraceError("fragmented scene boundaries require full recovery before scene indexing")
                physical_count += len(records)
                recorded_tids.add(chunk.tid)
                if records:
                    last_by_tid[chunk.tid] = max(last_by_tid.get(chunk.tid, 0), records[-1].sequence)
                database.executemany("INSERT INTO runs VALUES (?,?)", _runs(records))
                batch = []
                for position, event in enumerate(events):
                    if position % 128 == 0:
                        reader.check()
                    if event.kind == "thread_begin":
                        thread_begins.add(event.tid)
                    typed_damage += bool(event.data.get("typed_damage"))
                    if event.kind == "instruction":
                        instruction_count += 1
                        batch.append((event.tid, _key(event.global_seq)))
                    if event.kind == "coverage_gap":
                        database.execute("INSERT INTO coverage VALUES (?,?)", (_key(event.global_seq), event.tid))
                    if event.kind == "rule" and event.data.get("name") == "qtrace.scene":
                        rows, _, malformed = scene_lifecycle([event], maximum=1)
                        invalid += malformed
                        if rows:
                            database.execute("INSERT INTO boundaries VALUES (?,?,?)",
                                (_key(event.global_seq), event.tid, json.dumps(rows[0])))
                database.executemany("INSERT INTO instructions VALUES (?,?)", batch)
            emergency_events, _ = _parse_emergencies(source, reader.block, physical_count)
            for event in emergency_events:
                database.execute("INSERT INTO runs VALUES (?,?)", (_key(event.global_seq), _key(event.global_seq)))
                recorded_tids.add(event.tid)
                last_by_tid[event.tid] = max(last_by_tid.get(event.tid, 0), event.global_seq)
                if event.kind == "coverage_gap":
                    database.execute("INSERT INTO coverage VALUES (?,?)", (_key(event.global_seq), event.tid))
            # These are actual physical record ranges, not overlapping header
            # envelopes from different threads. Overlap is a duplicate sequence.
            previous = None
            declared_first = [entry.first for entry in reader.directories if entry.range_reliable and entry.first]
            declared_last = [entry.last for entry in reader.directories if entry.range_reliable and entry.last]
            for first, last in database.execute("SELECT first,last FROM runs ORDER BY first"):
                reader.check()
                start, end = _number(first), _number(last)
                if first_sequence is None:
                    first_sequence = min([start] + declared_first)
                    previous = first_sequence - 1
                if start <= previous:
                    raise FlightTraceError(f"duplicate global sequence {start}")
                if start > previous + 1:
                    database.execute("INSERT INTO gaps VALUES (?,?)", (_key(previous + 1), _key(start - 1)))
                previous = end
            if previous is not None:
                last_sequence = max([previous] + declared_last)
                if last_sequence > previous:
                    database.execute("INSERT INTO gaps VALUES (?,?)", (_key(previous + 1), _key(last_sequence)))
            elif declared_first and declared_last:
                first_sequence, last_sequence = min(declared_first), max(declared_last)
                database.execute("INSERT INTO gaps VALUES (?,?)", (_key(first_sequence), _key(last_sequence)))
            database.executescript("""
                CREATE INDEX instruction_range ON instructions(tid,sequence);
                CREATE INDEX gap_range ON gaps(first,last);
                CREATE INDEX boundary_sequence ON boundaries(sequence);
            """)
            active = {}
            scene_count = returned = stopped = unpaired = 0

            def retain(row, ending):
                nonlocal scene_count, returned, stopped, unpaired
                entry = row["entry_sequence"]
                row["observed_until_sequence"] = ending
                row["instruction_count"] = (database.execute(
                    "SELECT count(*) FROM instructions WHERE tid=? AND sequence>=? AND sequence<=?",
                    (row["tid"], _key(entry), _key(ending))).fetchone()[0] if entry is not None else None)
                database.execute("INSERT INTO calls VALUES (?,?,?,?,?,?,?,?)", (
                    row["tid"], _key(entry if entry is not None else row["last_sequence"]),
                    _key(ending), json.dumps(row), row["address"], row["state"],
                    int(entry is not None), row["instruction_count"]))
                scene_count += 1
                returned += row["state"] == "returned"
                stopped += row["state"] == "capture_stopped"
                unpaired += entry is None or row["state"] == "open_at_end"

            for (raw,) in database.execute("SELECT row FROM boundaries ORDER BY sequence"):
                reader.check()
                boundary = json.loads(raw)
                key = (boundary["tid"], boundary["id"])
                if boundary["state"] == "open_at_end":
                    if key in active:
                        raise FlightTraceError("ambiguous duplicate scene entry")
                    if len(active) >= 4096:
                        raise FlightTraceError("Flight index exceeds the 4096 open-scene bound")
                    active[key] = boundary
                    continue
                entry = active.pop(key, None)
                if entry:
                    if (entry["address"] != boundary["address"] or
                            entry["entry_sequence"] >= boundary["last_sequence"] or
                            entry["entered_monotonic_ns"] > boundary["last_monotonic_ns"]):
                        invalid += 1
                        continue
                    boundary.update(entry_sequence=entry["entry_sequence"],
                                    entered_monotonic_ns=entry["entered_monotonic_ns"])
                retain(boundary, boundary["last_sequence"])
            for boundary in active.values():
                retain(boundary, last_by_tid[boundary["tid"]])
            scene_summaries = [{"address": address, "hit_count": hits,
                "returns_observed": returns, "instruction_count": instructions,
                "first_observed_sequence": _number(first), "last_observed_sequence": _number(last)}
                for address, hits, returns, instructions, first, last in database.execute(
                    "SELECT address,sum(has_entry),sum(state='returned'),sum(instructions),min(entry),max(ending) "
                    "FROM calls GROUP BY address ORDER BY min(entry) DESC LIMIT 256")]
            summary = {"scene_count": scene_count, "returns_observed": returned,
                "capture_stopped": stopped, "unpaired_scenes": unpaired,
                "invalid_boundaries": invalid, "instruction_count": instruction_count,
                "typed_damage": typed_damage, "stale_directory_entries": stale_entries,
                "unreliable_directory_ranges": unreliable_entries,
                "physical_records": physical_count + len(emergency_events),
                "first_sequence": first_sequence, "last_sequence": last_sequence,
                "recorded_tids": sorted(recorded_tids), "thread_begin_tids": sorted(thread_begins),
                "unfollowed_threads": None, "installation_status": None,
                "missing_sequence_ranges": database.execute("SELECT count(*) FROM gaps").fetchone()[0],
                "coverage_gaps": database.execute("SELECT count(*) FROM coverage").fetchone()[0],
                "entry_registers": "not_recorded_as_an_explicit_scene_snapshot",
                "scenes": scene_summaries,
                "scene_summaries_omitted": database.execute("SELECT count(DISTINCT address) FROM calls").fetchone()[0] - len(scene_summaries),
                "verification_scope": "all decoded chunks and emergency slots; scene boundary index, not full recovery"}
            _put_meta(database, "version", INDEX_VERSION)
            _put_meta(database, "identity", identity)
            _put_meta(database, "summary", summary)
            _put_meta(database, "artifact_flags", reader.block.flags)
            database.execute("CREATE INDEX call_range ON calls(tid,entry,ending)")
            database.commit()
            reader.check()
            if file_identity(source) != identity:
                raise FlightTraceError("Flight source changed during index construction")
            result = {"index": str(index_path), "payload_bytes_read": reader.payload_bytes,
                      "decoded_chunks": reader.decoded_chunks, "scene_summary": summary}
        database.close()
        with temporary.open("rb") as binary:
            os.fsync(binary.fileno())
        if force:
            os.replace(temporary, index_path)
        else:
            os.link(temporary, index_path)
        return result
    except sqlite3.Error as error:
        if pending:
            raise pending[0]
        raise FlightTraceError(f"Flight scene index failure: {error}") from error
    finally:
        database.close()
        temporary.unlink(missing_ok=True)


@contextmanager
def _open_index(path, index_path, *, timeout=5.0, cancelled=None):
    check = deadline_check(timeout, cancelled)
    check()
    with path.open("rb") as source:
        identity = file_identity(source)
        database = None
        pending = []
        try:
            database = sqlite3.connect(index_path.resolve().as_uri() + "?mode=ro", uri=True)
            database.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16 * 1024 * 1024)
            database.execute("PRAGMA cache_size=-4096")
            pending = sqlite_cancellation(database, check)
            if _meta(database, "version") != INDEX_VERSION:
                raise FlightTraceError("unsupported Flight scene index version")
            if _meta(database, "identity") != list(identity):
                raise FlightTraceError("Flight scene index source identity mismatch; rebuild the index")
            yield database
            check()
            if file_identity(source) != identity:
                raise FlightTraceError("Flight source changed during index query")
        except (sqlite3.Error, ValueError, TypeError, KeyError) as error:
            if pending:
                raise pending[0]
            raise FlightTraceError(f"invalid Flight scene index: {error}") from error
        finally:
            if database is not None:
                database.close()


def indexed_summary(path, index_path, *, timeout=5.0, cancelled=None):
    with _open_index(path, index_path, timeout=timeout, cancelled=cancelled) as database:
        return _meta(database, "summary")


def query_indexed_boundaries(path, index_path, *, since_ns=0, until_ns=2**64 - 1,
                             after_sequence=0, limit=2000, timeout=5.0, cancelled=None):
    if not (type(limit) is int and 1 <= limit <= 2000 and type(after_sequence) is int and
            0 <= after_sequence <= 2**64 - 1 and type(since_ns) is int and type(until_ns) is int and
            0 <= since_ns <= until_ns <= 2**64 - 1):
        raise FlightTraceError("invalid indexed scene query range or limit")
    check = deadline_check(timeout, cancelled)
    with _open_index(path, index_path, timeout=timeout, cancelled=cancelled) as database:
        rows = []
        for sequence, tid, raw in database.execute(
                "SELECT sequence,tid,row FROM boundaries WHERE sequence>? ORDER BY sequence", (_key(after_sequence),)):
            boundary = json.loads(raw)
            check()
            if not since_ns <= boundary["last_monotonic_ns"] <= until_ns:
                continue
            rows.append({"sequence": _number(sequence), "tid": tid,
                "id": boundary["id"], "address": boundary["address"],
                "monotonic_ns": boundary["last_monotonic_ns"],
                "phase": {"open_at_end": "enter", "returned": "return", "capture_stopped": "capture_stopped"}[boundary["state"]],
                "return_value": boundary["return_value"]})
            if len(rows) > limit:
                break
        has_more = len(rows) > limit
        rows = rows[:limit]
        return checked_json({"rows": rows, "has_more": has_more,
            "next_after_sequence": rows[-1]["sequence"] if has_more else None,
            "payload_bytes_read": 0, "decoded_chunks": 0, "query_scope": "boundaries_after_cursor",
            "verification_scope": "source-bound scene index; no payload reread"})


def scene_at(path, index_path, *, sequence, tid=None, limit=2000, timeout=5.0, cancelled=None):
    if not (type(sequence) is int and 0 < sequence <= 2**64 - 1 and
            (tid is None or type(tid) is int and 0 < tid <= 2**32 - 1) and
            type(limit) is int and 1 <= limit <= 2000):
        raise FlightTraceError("invalid scene-at sequence, TID or limit")
    with _open_index(path, index_path, timeout=timeout, cancelled=cancelled) as database:
        query = "SELECT row FROM calls WHERE entry<=? AND ending>=?"
        parameters = [_key(sequence), _key(sequence)]
        if tid is not None:
            query += " AND tid=?"
            parameters.append(tid)
        query += " ORDER BY entry DESC LIMIT ?"
        parameters.append(limit + 1)
        rows = [json.loads(raw) for (raw,) in database.execute(query, parameters)]
        has_more = len(rows) > limit
        rows = rows[:limit]
        summary = _meta(database, "summary")
        global_uncertainty = [reason for condition, reason in (
            (summary["typed_damage"], "typed_damage"),
            (summary["invalid_boundaries"], "invalid_boundaries"),
            (summary["stale_directory_entries"], "stale_directory"),
            (summary["unreliable_directory_ranges"], "unreliable_directory_ranges")) if condition]
        for row in rows:
            uncertainty = list(global_uncertainty)
            entry = row["entry_sequence"]
            if entry is None:
                uncertainty.append("missing_entry")
            elif database.execute("SELECT 1 FROM gaps WHERE first<=? AND last>=? LIMIT 1",
                                  (_key(sequence), _key(entry))).fetchone():
                uncertainty.append("missing_sequences")
            if _meta(database, "artifact_flags") or database.execute(
                    "SELECT 1 FROM coverage WHERE sequence<=? AND sequence>=? LIMIT 1",
                    (_key(sequence), _key(entry or sequence))).fetchone():
                uncertainty.append("coverage_gap")
            row.update(membership="uncertain" if uncertainty else "observed", uncertainty=uncertainty)
        return checked_json({"sequence": sequence, "tid": tid, "scenes": rows, "has_more": has_more,
            "membership_status": ("observed" if rows and all(row["membership"] == "observed" for row in rows)
                                  else "unknown"),
            "unpaired_scenes": summary["unpaired_scenes"],
            "payload_bytes_read": 0, "verification_scope": "source-bound scene index; no payload reread"})
