"""Private SQLite spill storage for the existing strict Flight recovery algorithm.

Pickles are written and read only within this process's private temporary database;
no externally supplied database or cache is deserialized by this module.
"""
from __future__ import annotations

from contextlib import contextmanager
import itertools
import pickle
import sqlite3
import tempfile

try:
    from scripts.flight_trace import FlightTraceError, recover_flight
except ModuleNotFoundError:
    from flight_trace import FlightTraceError, recover_flight


def _key(value):
    return value.to_bytes(8, "big") if isinstance(value, int) and value >= 0 else pickle.dumps(value)


class DiskList(list):
    def __init__(self, storage, name=None, *, tid=None):
        self.storage = storage
        self.name = name or storage.name()
        self.tid = tid
        self.ordered = False
        self.count = 0
        if name is None:
            storage.database.execute(f"CREATE TABLE {self.name}(i INTEGER PRIMARY KEY, seq BLOB, tid INTEGER, kind TEXT, chunk_index INTEGER, state INTEGER, item BLOB)")

    def extend(self, values):
        def encoded():
            for value in values:
                ordinal = self.count
                self.count += 1
                yield (ordinal, _key(getattr(value, "global_seq", ordinal)),
                       getattr(value, "tid", None), str(getattr(value, "kind", "")),
                       (value.index if isinstance(getattr(value, "index", None), int) else None),
                       getattr(value, "state", None),
                       pickle.dumps(value, protocol=5))
        self.storage.database.executemany(f"INSERT INTO {self.name} VALUES (?,?,?,?,?,?,?)", encoded())

    def append(self, value):
        self.extend((value,))

    def persist_event_data(self, event):
        """Retain annotations added after decoding without changing event keys."""
        self.storage.database.execute(f"UPDATE {self.name} SET item=? WHERE seq=?",
            (pickle.dumps(event, protocol=5), _key(event.global_seq)))

    def __len__(self):
        if self.tid is None:
            return self.count
        return self.storage.database.execute(f"SELECT count(*) FROM {self.name} WHERE tid=?", (self.tid,)).fetchone()[0]

    def _iterate(self, reverse=False, kind=None, kinds=None):
        where, parameters = [], []
        if self.tid is not None:
            where.append("tid=?")
            parameters.append(self.tid)
        if kind is not None:
            where.append("kind=?")
            parameters.append(kind)
        if kinds is not None:
            where.append("kind IN (" + ",".join("?" for _ in kinds) + ")")
            parameters.extend(kinds)
        query = f"SELECT item FROM {self.name}"
        if where:
            query += " WHERE " + " AND ".join(where)
        query += " ORDER BY " + ("seq" if self.ordered else "i") + (" DESC" if reverse else " ASC")
        for (value,) in self.storage.database.execute(query, parameters):
            yield pickle.loads(value)

    def __iter__(self):
        return self._iterate()

    def __reversed__(self):
        return self._iterate(reverse=True)

    def __getitem__(self, index):
        if isinstance(index, slice):
            start, stop, step = index.indices(len(self))
            return list(itertools.islice(iter(self), start, stop, step))
        if index < 0:
            index += len(self)
        try:
            return next(itertools.islice(iter(self), index, index + 1))
        except StopIteration:
            raise IndexError(index) from None

    def __add__(self, other):
        return self.storage.list(itertools.chain(self, other))

    def sort(self, *, key=None):
        self.storage.database.execute(f"CREATE INDEX IF NOT EXISTS {self.name}_sequence ON {self.name}(seq)")
        self.storage.database.execute(f"CREATE INDEX IF NOT EXISTS {self.name}_thread_sequence ON {self.name}(tid,seq)")
        self.ordered = True

    def for_tid(self, tid):
        result = DiskList(self.storage, self.name, tid=tid)
        result.ordered = self.ordered
        return result

    def tids(self):
        return {row[0] for row in self.storage.database.execute(f"SELECT DISTINCT tid FROM {self.name}")}

    def of_kind(self, kind):
        return self._iterate(kind=kind)

    def of_kinds(self, kinds):
        return self._iterate(kinds=kinds)

    def reject_chunks(self, indexes):
        for index in indexes:
            self.storage.database.execute(f"DELETE FROM {self.name} WHERE chunk_index=?", (index,))
        self.count = self.storage.database.execute(f"SELECT count(*) FROM {self.name}").fetchone()[0]


class DiskSet:
    def __init__(self, storage, values=()):
        self.storage = storage
        self.name = storage.name()
        storage.database.execute(f"CREATE TABLE {self.name}(key BLOB PRIMARY KEY,item BLOB)")
        self.update(values)

    def update(self, values, *, unique=False):
        insert = "INSERT" if unique else "INSERT OR IGNORE"
        self.storage.database.executemany(f"{insert} INTO {self.name} VALUES (?,?)",
            ((_key(value), pickle.dumps(value, protocol=5)) for value in values))

    def add(self, value):
        self.update((value,))

    def __contains__(self, value):
        return self.storage.database.execute(f"SELECT 1 FROM {self.name} WHERE key=?", (_key(value),)).fetchone() is not None

    def __len__(self):
        return self.storage.database.execute(f"SELECT count(*) FROM {self.name}").fetchone()[0]

    def __iter__(self):
        for (value,) in self.storage.database.execute(f"SELECT item FROM {self.name} ORDER BY key"):
            yield pickle.loads(value)

    def ordered_values(self):
        return iter(self)

    def minimum(self):
        return self._edge("ASC")

    def maximum(self):
        return self._edge("DESC")

    def _edge(self, order):
        row = self.storage.database.execute(
            f"SELECT item FROM {self.name} ORDER BY key {order} LIMIT 1").fetchone()
        if row is None:
            raise ValueError("empty Flight sequence set")
        return pickle.loads(row[0])

    def __or__(self, other):
        return self.storage.set(itertools.chain(self, other))


class LazyList(list):
    def __init__(self, factory, count):
        self.factory, self.count = factory, count

    def __iter__(self):
        return self.factory()

    def __len__(self):
        return self.count


class DiskFragments:
    def __init__(self, storage, decoded_chunks):
        self.storage = storage
        self.name = storage.name()
        storage.database.execute(f"CREATE TABLE {self.name}(tid INTEGER,event_id BLOB,sequence BLOB,item BLOB)")
        storage.database.executemany(f"INSERT INTO {self.name} VALUES (?,?,?,?)",
            ((fragment.tid, _key(fragment.event_id), _key(fragment.sequence), pickle.dumps(fragment, protocol=5))
             for chunk in decoded_chunks for fragment in chunk.fragments))
        storage.database.execute(f"CREATE INDEX {self.name}_groups ON {self.name}(tid,event_id)")
        storage.database.execute(f"CREATE INDEX {self.name}_sequences ON {self.name}(sequence)")

    def groups(self):
        # Preserve first physical encounter order, including incomplete-group
        # diagnostics, just as the in-memory recovery's insertion-ordered map.
        cursor = self.storage.database.execute(
            f"SELECT tid,event_id FROM {self.name} GROUP BY tid,event_id ORDER BY min(rowid)")
        for tid, event_id in cursor:
            values, detail_bytes = [], 0
            for (item,) in self.storage.database.execute(
                    f"SELECT item FROM {self.name} WHERE tid=? AND event_id=? ORDER BY rowid", (tid, event_id)):
                fragment = pickle.loads(item)
                values.append(fragment)
                detail_bytes += len(fragment.detail)
                if len(values) > 65535 or detail_bytes > 1024 * 1024:
                    raise FlightTraceError("Flight logical fragment group exceeds the recovery memory bound")
            yield values

    def source_offset(self, sequence):
        result = self.storage.database.execute(f"SELECT item FROM {self.name} WHERE sequence=?", (_key(sequence),)).fetchone()
        return pickle.loads(result[0]).source_offset


class RecoveryStorage:
    def __init__(self, database, max_spool_bytes):
        self.database = database
        self.counter = 0
        database.executescript("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA cache_size=-4096; PRAGMA temp_store=FILE;")
        database.execute(f"PRAGMA max_page_count={max_spool_bytes // 4096}")

    def name(self):
        self.counter += 1
        return f"spill_{self.counter}"

    def list(self, values=()):
        result = DiskList(self)
        result.extend(values)
        return result

    def set(self, values=()):
        return DiskSet(self, values)

    def lazy(self, factory, count):
        return LazyList(factory, count)

    def observe(self, decoded, observed, observed_by_tid):
        sequences = [record.sequence for record in decoded.records]
        try:
            observed.update(sequences, unique=True)
        except sqlite3.IntegrityError as error:
            raise FlightTraceError("duplicate global sequence in recovered chunks") from error
        if decoded.tid not in observed_by_tid:
            observed_by_tid[decoded.tid] = self.set()
        observed_by_tid[decoded.tid].update(sequences)

    def fragments(self, decoded_chunks):
        return DiskFragments(self, decoded_chunks)


@contextmanager
def spooled_recovery(source, *, max_spool_bytes=16 * 1024**3):
    if type(max_spool_bytes) is not int or max_spool_bytes < 4096:
        raise FlightTraceError("Flight spool budget must be at least 4096 bytes")
    with tempfile.TemporaryDirectory(prefix="qtrace-flight-spool-") as directory:
        database = sqlite3.connect(f"{directory}/recovery.sqlite")
        try:
            storage = RecoveryStorage(database, max_spool_bytes)
            yield recover_flight(source, _storage=storage)
        except sqlite3.Error as error:
            raise FlightTraceError(f"Flight recovery spool failure: {error}") from error
        finally:
            database.close()
