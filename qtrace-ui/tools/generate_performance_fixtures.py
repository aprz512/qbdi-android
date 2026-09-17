#!/usr/bin/env python3
"""Generate the deterministic, untracked qtrace-ui performance corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tests.test_flight_trace import (  # noqa: E402
    checkpoint,
    chunk,
    chunk_begin,
    directory_entry,
    emergency,
    event_fragment,
    flight_record,
    qtrb_rich_instruction,
    qtrb_rich_instruction_definition,
    qtrb_instruction_definition as simple_instruction_definition,
    register_delta,
    string_definition,
)
from scripts.tests.test_trace_binary import (  # noqa: E402
    begin,
    call,
    footer,
    memory,
    module,
    record,
    stream_header,
)


GENERATOR_SCHEMA = 1
QTRB_EVENTS = 10_000_000
FLIGHT_BYTES = 512 * 1024 * 1024
FLIGHT_EVENTS = 68
FLIGHT_CHUNK_BYTES = 1024 * 1024
FLIGHT_CHUNK_COUNT = 511
SUPERBLOCK_BYTES = 4096
DIRECTORY_BYTES = 64
EMERGENCY_BYTES = 128
CHUNK_OFFSET = FLIGHT_CHUNK_BYTES
FLIGHT_MAGIC = 0x51464C54
FLIGHT_VERSION = 2
FLIGHT_TARGET = b"libqtrace_perf.so"
EXPECTED_FLIGHT_COMPLETENESS = [
    {"domain": "captured_sequence", "bounds": {"inclusive_sequence": {"first": 1, "last": 8}}, "provenance": "captured", "cause": "retained"},
    {"domain": "captured_sequence", "bounds": {"inclusive_sequence": {"first": 10, "last": 61}}, "provenance": "captured", "cause": "retained"},
    {"domain": "captured_sequence", "bounds": {"inclusive_sequence": {"first": 9, "last": 9}}, "provenance": "unknown", "cause": "overwritten"},
    {"domain": "captured_sequence", "bounds": {"inclusive_sequence": {"first": 60, "last": 60}}, "provenance": "captured", "cause": "coverage_gap"},
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for data in iter(lambda: source.read(4 * 1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest()


def _safe_output(path: Path) -> Path:
    if not path.is_absolute():
        path = Path.cwd() / path
    cursor = path
    existing: list[Path] = []
    while not cursor.exists():
        existing.append(cursor)
        if cursor.parent == cursor:
            raise ValueError("output has no existing ancestor")
        cursor = cursor.parent
    if cursor.is_symlink() or not cursor.is_dir():
        raise ValueError("output ancestor must be a real directory")
    for ancestor in (cursor, *cursor.parents):
        if ancestor.is_symlink():
            raise ValueError(f"symlink output ancestor rejected: {ancestor}")
    for item in reversed(existing):
        item.mkdir(mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise ValueError("output must be a real directory")
    return path


def _atomic_target(output: Path, name: str) -> tuple[int, Path, Path]:
    target = output / name
    if target.is_symlink():
        raise ValueError(f"symlink output target rejected: {target}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{name}.", dir=output)
    return descriptor, Path(temporary), target


def _publish(descriptor: int, temporary: Path, target: Path) -> None:
    os.fsync(descriptor)
    os.close(descriptor)
    os.replace(temporary, target)
    directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _qtrb_instruction(sequence: int) -> bytes:
    payload = struct.pack("<QIQIBB", sequence, 1, 0x2345, 99, 0, 0)
    return record(4, payload)


def generate_qtrb(output: Path) -> dict[str, object]:
    descriptor, temporary, target = _atomic_target(output, "qtrb-10m.trace.bin")
    instruction_template_bytes = len(_qtrb_instruction(1))
    memory_record = memory()
    semantic_record = call("jni", "Lookup", "deterministic")
    opaque_record = record(0x8001, b"")
    repeated = QTRB_EVENTS - 4  # begin, module, definition, terminal
    special_count = (repeated + 4095) // 4096
    instruction_count = (special_count + 2) // 3
    memory_count = (special_count + 1) // 3
    semantic_count = special_count // 3
    opaque_count = repeated - special_count
    prefix = (
        stream_header(minor=2, features=1)
        + begin()
        + module()
        + simple_instruction_definition(metadata_id=99)
    )
    encoded_bytes = (
        len(prefix)
        + instruction_count * instruction_template_bytes
        + memory_count * len(memory_record)
        + semantic_count * len(semantic_record)
        + opaque_count * len(opaque_record)
        + len(footer())
    )
    terminal = footer(
        instructions=instruction_count,
        encoded_bytes=encoded_bytes,
        compressed_bytes=encoded_bytes,
    )
    digest = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "wb", closefd=False, buffering=1024 * 1024) as sink:
            sink.write(prefix)
            digest.update(prefix)
            sequence = 0
            for index in range(repeated):
                if index % 4096 != 0:
                    encoded = opaque_record
                else:
                    selector = (index // 4096) % 3
                    if selector == 1:
                        encoded = memory_record
                    elif selector == 2:
                        encoded = semantic_record
                    else:
                        sequence += 1
                        encoded = _qtrb_instruction(sequence)
                sink.write(encoded)
                digest.update(encoded)
            sink.write(terminal)
            digest.update(terminal)
            sink.flush()
        if os.fstat(descriptor).st_size != encoded_bytes:
            raise RuntimeError("QTRB size calculation drift")
        _publish(descriptor, temporary, target)
        descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return {
        "path": target.name,
        "format": "QTRB",
        "version": "1.2",
        "events": QTRB_EVENTS,
        "instructions": instruction_count,
        "memory_events": memory_count,
        "semantic_events": semantic_count,
        "opaque_optional_events": opaque_count,
        "bytes": encoded_bytes,
        "sha256": digest.hexdigest(),
    }


def _flight_chunks() -> tuple[list[bytes], list[bytes], list[bytes]]:
    tids = [101, 202, 303, 404]
    all_records: list[list[bytes]] = [[] for _ in tids]
    sequences = [index + 1 for index in range(4)]

    def add(owner: int, kind: int, payload: bytes = b"", *, flags: int = 0) -> None:
        sequence = sequences[owner]
        all_records[owner].append(
            flight_record(kind, sequence, payload, flags=flags, generation=1)
        )
        sequences[owner] += 4

    for owner, tid in enumerate(tids):
        add(
            owner,
            1,
            chunk_begin(tid, target=FLIGHT_TARGET, scene=f"worker-{tid}".encode()),
        )
        add(owner, 9, checkpoint(pc=0x71001000 + owner * 0x100), flags=1)
    # Leave sequence 9 absent from TID 101's otherwise committed window. With no
    # loss flag this is explicit overwritten evidence, not an inferred loss.
    sequences[0] += 4
    add(0, 4, qtrb_rich_instruction_definition(), flags=1)
    add(1, 4, qtrb_rich_instruction_definition(), flags=1)
    add(2, 4, qtrb_rich_instruction_definition(), flags=1)
    add(3, 4, qtrb_rich_instruction_definition(), flags=1)
    for owner in range(4):
        add(owner, 4, qtrb_rich_instruction())
        add(owner, 5, memory())
        add(owner, 9, register_delta({owner: 0xA0 + owner, 32: 0x71002000 + owner}))
    add(0, 6, string_definition(1, b"jni"), flags=3)
    add(0, 6, string_definition(2, b"Lookup"), flags=3)
    add(0, 6, string_definition(3, b"determ"), flags=3)
    add(0, 6, string_definition(4, b"inistic"), flags=3)
    add(0, 6, event_fragment(9, 13, 0, 2, 1, 2, 3), flags=4)
    add(0, 6, event_fragment(9, 13, 1, 2, 1, 2, 4), flags=4)
    for owner in range(1, 4):
        for string_id in range(1, 7):
            add(
                owner,
                6,
                string_definition(string_id, f"worker-{owner}-{string_id}".encode()),
                flags=3,
            )
    for owner, tid in enumerate(tids):
        creator_tid = 1 if owner == 0 else tids[owner - 1]
        add(owner, 2, struct.pack("<IIQQ", creator_tid, tid, 0x71003000 + owner, 1))
        add(owner, 3, struct.pack("<I", tid))

    chunks = [
        bytearray(chunk(index, tid, 1, records, chunk_bytes=FLIGHT_CHUNK_BYTES))
        for index, (tid, records) in enumerate(zip(tids, all_records, strict=True))
    ]
    for encoded in chunks:
        struct.pack_into("<H", encoded, 4, FLIGHT_VERSION)
    directories = [
        directory_entry(
            tid,
            min(struct.unpack_from("<Q", item, 8)[0] for item in records),
            max(struct.unpack_from("<Q", item, 8)[0] for item in records),
            index,
            1,
        )
        for index, (tid, records) in enumerate(zip(tids, all_records, strict=True))
    ]
    next_sequence = max(sequences) - 3
    emergencies = [
        emergency(12, 101, next_sequence, pc=0x71009900, signal=12, code=1, flags=1, version=2) + bytes(64),
        emergency(13, 101, next_sequence + 1, pc=0x71009904, fault=next_sequence, signal=12, code=1, flags=1, version=2) + bytes(64),
        emergency(15, 303, next_sequence + 2, pc=0x71009908, flags=2, version=2) + bytes(64),
        emergency(14, 404, next_sequence + 3, pc=0x7100990C, signal=131, code=9, version=2) + bytes(64),
        bytes(128),
    ]
    return [bytes(item) for item in chunks], directories, emergencies


def generate_flight(output: Path) -> dict[str, object]:
    descriptor, temporary, target = _atomic_target(output, "flight-512m.flight.bin")
    chunks, directories, emergencies = _flight_chunks()
    directory_offset = SUPERBLOCK_BYTES
    emergency_offset = 4096 + len(directories) * DIRECTORY_BYTES
    target_name = FLIGHT_TARGET
    superblock = bytearray(SUPERBLOCK_BYTES)
    struct.pack_into(
        "<IHBBH6xQQIIQIIQIII4xQIIH",
        superblock, 0,
        FLIGHT_MAGIC, FLIGHT_VERSION, 1, 8, SUPERBLOCK_BYTES, FLIGHT_BYTES,
        directory_offset, DIRECTORY_BYTES, len(directories), CHUNK_OFFSET,
        FLIGHT_CHUNK_BYTES, FLIGHT_CHUNK_COUNT, emergency_offset,
        EMERGENCY_BYTES, len(emergencies), 0, 0x1020304050607080, 4242, 17,
        len(target_name),
    )
    superblock[98:98 + len(target_name)] = target_name
    try:
        os.posix_fallocate(descriptor, 0, FLIGHT_BYTES)
        os.pwrite(descriptor, superblock, 0)
        for index, entry in enumerate(directories):
            os.pwrite(descriptor, entry, directory_offset + index * DIRECTORY_BYTES)
        for index, slot in enumerate(emergencies):
            os.pwrite(descriptor, slot, emergency_offset + index * EMERGENCY_BYTES)
        for index, encoded in enumerate(chunks):
            os.pwrite(descriptor, encoded, CHUNK_OFFSET + index * FLIGHT_CHUNK_BYTES)
        if os.fstat(descriptor).st_size != FLIGHT_BYTES:
            raise RuntimeError("Flight corpus is not exactly 512 MiB")
        _publish(descriptor, temporary, target)
        descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return {
        "path": target.name,
        "format": "Flight",
        "version": "2",
        "events": FLIGHT_EVENTS,
        "physical_records": 60,
        "bytes": FLIGHT_BYTES,
        "sha256": _sha256(target),
    }


def _check_manifest(manifest_path: Path) -> dict[str, object]:
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if document.get("generator_schema") != GENERATOR_SCHEMA:
        raise ValueError("generator schema mismatch")
    corpora = document.get("corpora")
    if not isinstance(corpora, dict):
        raise ValueError("missing corpora")
    for name in ("qtrb", "flight"):
        item = corpora[name]
        path = manifest_path.parent / item["path"]
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"invalid {name} corpus path")
        if path.stat().st_size != item["bytes"] or _sha256(path) != item["sha256"]:
            raise ValueError(f"{name} corpus identity mismatch")
    if corpora["qtrb"]["events"] != QTRB_EVENTS:
        raise ValueError("QTRB event count mismatch")
    if corpora["flight"]["bytes"] != FLIGHT_BYTES:
        raise ValueError("Flight byte count mismatch")
    if corpora["flight"]["events"] != FLIGHT_EVENTS:
        raise ValueError("Flight event count mismatch")
    if document.get("expected_flight_completeness") != EXPECTED_FLIGHT_COMPLETENESS:
        raise ValueError("Flight completeness oracle mismatch")
    ui = ROOT / "qtrace-ui"
    with tempfile.TemporaryDirectory(prefix="qtrace-ui-provider-check-") as directory:
        cache = Path(directory) / "cache"
        cache.mkdir(mode=0o700)
        completed = subprocess.run(
            [
                "cargo", "run", "--release", "-q", "-p", "qtrace-service",
                "--example", "perf_driver", "--", "verify", "--input",
                str(manifest_path), "--cache", str(cache),
            ],
            cwd=ui,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise ValueError(
                "Rust provider validation failed: " + completed.stderr[-2048:]
            )
    return document


def generate(output: Path) -> Path:
    output = _safe_output(output)
    qtrb = generate_qtrb(output)
    flight = generate_flight(output)
    correctness = hashlib.sha256()
    correctness.update(b"qtrace-ui/performance-correctness/v1\0")
    correctness.update(str(qtrb["sha256"]).encode())
    correctness.update(b"\0")
    correctness.update(str(flight["sha256"]).encode())
    correctness.update(b"\0")
    correctness.update(QTRB_EVENTS.to_bytes(8, "little"))
    correctness.update(FLIGHT_EVENTS.to_bytes(8, "little"))
    document: dict[str, object] = {
        "generator_schema": GENERATOR_SCHEMA,
        "generator_sha256": _sha256(Path(__file__)),
        "corpora": {"qtrb": qtrb, "flight": flight},
        "correctness_digest": correctness.hexdigest(),
        "expected_flight_completeness": EXPECTED_FLIGHT_COMPLETENESS,
        "cache_options": {"schema": 2, "interval_block_rows": 64},
        "query_set": {"schema": 1, "viewport_samples": 200, "structured_samples": 200},
        "reference_host": None,
    }
    descriptor, temporary, target = _atomic_target(output, "manifest.json")
    try:
        with os.fdopen(descriptor, "w", closefd=False, encoding="utf-8") as sink:
            json.dump(document, sink, indent=2, sort_keys=True)
            sink.write("\n")
            sink.flush()
        _publish(descriptor, temporary, target)
        descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args(argv)
    if (args.output is None) == (args.check is None):
        parser.error("choose exactly one of --output or --check")
    try:
        if args.output is not None:
            manifest = generate(args.output)
            print(manifest)
        else:
            _check_manifest(args.check.resolve())
    except (KeyError, OSError, RuntimeError, ValueError) as error:
        print(f"performance fixture generator: {str(error)[:1024]}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
