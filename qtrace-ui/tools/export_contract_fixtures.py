#!/usr/bin/env python3
"""Export the deterministic qtrace-ui compatibility corpus."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.tests.test_flight_trace import (  # noqa: E402
    artifact as flight_artifact,
    chunk as flight_chunk,
    core_records,
    directory_entry,
    emergency,
    event_fragment,
    flight_record,
    qtrb_rich_instruction,
    qtrb_rich_instruction_definition,
    register_delta,
    string_definition,
)
from scripts.tests.test_trace_binary import (  # noqa: E402
    RECORD as QTRB_RECORD,
    begin,
    call,
    complete_stream,
    event,
    event_chunk,
    instruction,
    instruction_definition,
    memory,
    module,
    record,
    stopped_stream,
    stream_header,
    uncaptured_memory,
)


FIXTURE_ROOT = ROOT / "qtrace-ui" / "fixtures"
GENERATOR_SCHEMA = 1
MAX_FIXTURE_BYTES = 4 * 1024 * 1024
FLIGHT_V2 = 2
FLIGHT_EMERGENCY_SLOT_BYTES = 128


@dataclass(frozen=True)
class Fixture:
    path: str
    data: bytes
    format: str
    version: str
    fixture_class: str
    outcome: str = "success"
    error: str | None = None


def _qtrb_v12(data: bytes) -> bytes:
    return data.replace(stream_header(), stream_header(minor=2, features=1), 1)


def _qtrb_fixtures() -> tuple[Fixture, ...]:
    v10 = complete_stream(
        instruction_definition(),
        instruction(),
        uncaptured_memory(0x3000),
        call("jni", "Find", "ok"),
        event(7, "guard", "hit"),
        event(8, "fatal", "bad"),
    )
    euro = "€".encode("utf-8")
    v11 = complete_stream(
        event_chunk(7, 11, 6, 0, 2, b"abc"),
        event_chunk(7, 11, 6, 1, 2, euro),
        event_chunk(8, 12, 3, 0, 2, euro[:1]),
        event_chunk(8, 12, 3, 1, 2, euro[1:]),
    ).replace(stream_header(), stream_header(minor=1), 1)
    v12 = _qtrb_v12(complete_stream(
        instruction_definition(),
        instruction(),
        memory(),
        call("jni", "Find", 'line\n"quoted"'),
        event(7, "guard", "hit"),
        event(8, "fatal", "bad"),
    ))
    partial = (
        stream_header(minor=2, features=1)
        + begin()
        + module()
        + instruction_definition()
        + instruction()
    )
    unsupported = v12.replace(
        stream_header(minor=2, features=1),
        stream_header(minor=2, features=2),
        1,
    )
    undefined = _qtrb_v12(complete_stream(instruction(metadata_id=8)))
    gap = _qtrb_v12(complete_stream(instruction_definition(), instruction(sequence=2)))
    oversized = (
        stream_header(minor=2, features=1)
        + begin()
        + QTRB_RECORD.pack(7, 0, 4613)
    )
    return (
        Fixture("qtrb/v1.0-completed.bin", v10, "QTRB", "1.0",
                "qtrb.v1.0-completed"),
        Fixture("qtrb/v1.1-chunked.bin", v11, "QTRB", "1.1",
                "qtrb.v1.1-chunked-rule-error"),
        Fixture("qtrb/v1.2-completed.bin", v12, "QTRB", "1.2",
                "qtrb.v1.2-completed"),
        Fixture("qtrb/v1.2-stopped.bin", stopped_stream(), "QTRB", "1.2",
                "qtrb.v1.2-stopped"),
        Fixture("qtrb/v1.2-partial.bin", partial, "QTRB", "1.2",
                "qtrb.v1.2-partial"),
        Fixture("qtrb/malformed/bad-header.bin", b"BAD!" + v12[4:], "QTRB", "unknown",
                "qtrb.malformed-bad-header", "error", "invalid QTRB magic"),
        Fixture("qtrb/malformed/unsupported-feature.bin", unsupported, "QTRB", "1.2",
                "qtrb.malformed-unsupported-feature", "error", "unsupported minor/features"),
        Fixture("qtrb/malformed/undefined-metadata.bin", undefined, "QTRB", "1.2",
                "qtrb.malformed-undefined-metadata", "error",
                "undefined instruction metadata"),
        Fixture("qtrb/malformed/sequence-gap.bin", gap, "QTRB", "1.2",
                "qtrb.malformed-sequence-gap", "error", "instruction sequence gap"),
        Fixture("qtrb/malformed/oversized-record.bin", oversized, "QTRB", "1.2",
                "qtrb.malformed-oversized-record", "error",
                "record payload exceeds protocol maximum"),
        Fixture("qtrb/malformed/truncated-payload.bin", v12[:-1], "QTRB", "1.2",
                "qtrb.malformed-truncated-payload", "error", "truncated record payload"),
        Fixture("qtrb/malformed/record-after-terminal.bin", v12 + call(), "QTRB", "1.2",
                "qtrb.malformed-record-after-terminal", "error", "record after TRACE_END"),
    )


def _flight_v2_chunk(*args, **kwargs) -> bytes:
    encoded = bytearray(flight_chunk(*args, **kwargs))
    struct.pack_into("<H", encoded, 4, FLIGHT_V2)
    return bytes(encoded)


def _flight_v2_artifact(*, directories: list[bytes], chunks: list[bytes],
                        emergencies: list[bytes] | None = None, flags: int = 0) -> bytes:
    return flight_artifact(
        directories=directories,
        chunks=chunks,
        emergencies=emergencies,
        flags=flags,
        wire_version=FLIGHT_V2,
        emergency_slot_bytes=FLIGHT_EMERGENCY_SLOT_BYTES,
    )


def _complete_flight() -> bytes:
    first = core_records(101, start=1)
    first.extend((
        flight_record(2, 3, struct.pack("<IIQQ", 1, 101, 0x71001234, 1)),
        flight_record(4, 4, qtrb_rich_instruction_definition(), flags=1),
        flight_record(4, 5, qtrb_rich_instruction()),
        flight_record(5, 6, memory()),
        flight_record(6, 7, string_definition(1, b"jni"), flags=3),
        flight_record(6, 8, string_definition(2, b"Lookup"), flags=3),
        flight_record(6, 9, string_definition(3, b"snow"), flags=3),
        flight_record(6, 10, event_fragment(9, 10, 0, 2, 1, 2, 3), flags=4),
        flight_record(6, 11, string_definition(4, "man☃".encode()), flags=3),
        flight_record(6, 12, event_fragment(9, 10, 1, 2, 1, 2, 4), flags=4),
        flight_record(6, 13, string_definition(5, b"guard"), flags=3),
        flight_record(6, 14, string_definition(6, b"hit"), flags=3),
        flight_record(7, 15, struct.pack("<II", 5, 6)),
        flight_record(6, 16, string_definition(7, b"fatal"), flags=3),
        flight_record(6, 17, string_definition(8, b"bad"), flags=3),
        flight_record(8, 18, struct.pack("<II", 7, 8)),
        flight_record(9, 19, register_delta({0: 0xAA, 32: 0x71002345})),
        flight_record(10, 20, struct.pack("<Q6QQq", 64, 1, 2, 3, 4, 5, 6, 7, 0)),
        flight_record(11, 21, struct.pack("<iiQQ", 10, 1, 0x71009000, 0)),
        flight_record(3, 22, struct.pack("<I", 101)),
    ))
    second = core_records(202, start=23, pc=0x71002000)
    second.extend((
        flight_record(2, 25, struct.pack("<IIQQ", 101, 202, 0x71004568, 1)),
        flight_record(9, 26, register_delta({1: 0xBB, 31: 0x7FFF1000})),
        flight_record(3, 27, struct.pack("<I", 202)),
    ))
    handler_begin = emergency(
        12, 101, 28, pc=0x71009900, sp=0x81001000,
        signal=12, code=1, flags=1, version=16,
    )
    handler_return = emergency(
        13, 101, 29, pc=0x71009904, sp=0x81001008,
        fault=28, signal=12, code=1, flags=1, version=18,
    )
    termination = emergency(14, 101, 30, pc=0x71009908, signal=131, code=9)
    return _flight_v2_artifact(
        directories=[
            directory_entry(101, 1, 22, 0, 1),
            directory_entry(202, 23, 27, 1, 1),
        ],
        chunks=[
            _flight_v2_chunk(0, 101, 1, first),
            _flight_v2_chunk(1, 202, 1, second),
        ],
        emergencies=[handler_begin + handler_return, termination, bytes(128)],
    )


def _checkpoint_delta_flight() -> bytes:
    records = core_records(77)
    records.append(flight_record(9, 3, register_delta({0: 0x1111, 32: 0x71001234})))
    return _flight_v2_artifact(
        directories=[directory_entry(77, 1, 3, 0, 1)],
        chunks=[_flight_v2_chunk(0, 77, 1, records, state=1)],
    )


def _flight_fixtures() -> tuple[Fixture, ...]:
    active = _checkpoint_delta_flight()
    overwritten_records = core_records(77, start=5)
    overwritten_records.append(flight_record(2, 7, b"retained"))
    overwritten = _flight_v2_artifact(
        directories=[directory_entry(77, 1, 7, 0, 1)],
        chunks=[_flight_v2_chunk(0, 77, 1, overwritten_records)],
    )
    coverage = _flight_v2_artifact(
        directories=[directory_entry(77, 1, 4, 0, 1)],
        chunks=[_flight_v2_chunk(0, 77, 1, [], state=1)],
        emergencies=[emergency(15, 77, 4, pc=0x71009900, flags=2)],
    )
    damaged_records = core_records(77)
    damaged = _flight_v2_artifact(
        directories=[directory_entry(77, 1, 2, 0, 1)],
        chunks=[_flight_v2_chunk(0, 77, 1, damaged_records, corrupt_checksum=True)],
    )
    stale = _flight_v2_artifact(
        directories=[directory_entry(77, 1, 2, 0, 2)],
        chunks=[_flight_v2_chunk(0, 77, 3, core_records(77, generation=3))],
    )
    incomplete_records = core_records(77)
    incomplete_records.extend((
        flight_record(6, 3, string_definition(1, b"jni"), flags=3),
        flight_record(6, 4, string_definition(2, b"Lookup"), flags=3),
        flight_record(6, 5, string_definition(3, b"partial"), flags=3),
        flight_record(6, 6, event_fragment(9, 12, 1, 2, 1, 2, 3), flags=4),
    ))
    incomplete = _flight_v2_artifact(
        directories=[directory_entry(77, 1, 6, 0, 1)],
        chunks=[_flight_v2_chunk(0, 77, 1, incomplete_records)],
    )
    return (
        Fixture("flight/v2-complete.bin", _complete_flight(), "Flight", "2",
                "flight.v2-complete"),
        Fixture("flight/v2-active.bin", active, "Flight", "2",
                "flight.v2-active-chunk"),
        Fixture("flight/v2-checkpoint-delta.bin", active, "Flight", "2",
                "flight.v2-active-chunk"),
        Fixture("flight/v2-overwritten.bin", overwritten, "Flight", "2",
                "flight.v2-overwritten-range"),
        Fixture("flight/v2-coverage-gap.bin", coverage, "Flight", "2",
                "flight.v2-coverage-gap"),
        Fixture("flight/v2-checksum-damaged.bin", damaged, "Flight", "2",
                "flight.v2-checksum-damaged-sealed"),
        Fixture("flight/v2-stale-directory.bin", stale, "Flight", "2",
                "flight.v2-stale-directory"),
        Fixture("flight/v2-incomplete-fragment.bin", incomplete, "Flight", "2",
                "flight.v2-incomplete-fragment"),
    )


def _align_blob(blob: bytearray, alignment: int) -> None:
    blob.extend(b"\0" * ((-len(blob)) % alignment))


def _minimal_aarch64_elf() -> bytes:
    section_names = (
        b"\0.text\0.dynstr\0.dynsym\0.strtab\0.symtab\0.note.gnu.build-id\0.shstrtab\0"
    )

    def section_name(value: bytes) -> int:
        return section_names.index(value)

    sections: list[tuple[bytes, int, int, int, bytes, int, int, int]] = [
        (b"", 0, 0, 0, b"", 0, 0, 0),
        (b".text", 1, 0x6, 0x1000, b"\xc0\x03\x5f\xd6", 0, 0, 4),
        (b".dynstr", 3, 0, 0, b"\0dyn_func\0", 0, 0, 1),
        (b".dynsym", 11, 0, 0,
         bytes(24) + struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0x1000, 4), 2, 1, 8),
        (b".strtab", 3, 0, 0, b"\0local_func\0", 0, 0, 1),
        (b".symtab", 2, 0, 0,
         bytes(24) + struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0x1000, 4), 4, 1, 8),
        (b".note.gnu.build-id", 7, 0x2, 0,
         struct.pack("<III", 4, 20, 3) + b"GNU\0" + bytes(range(1, 21)), 0, 0, 4),
        (b".shstrtab", 3, 0, 0, section_names, 0, 0, 1),
    ]
    blob = bytearray(64)
    layout: list[tuple[int, int]] = [(0, 0)]
    for _, section_type, _, _, data, _, _, alignment in sections[1:]:
        _align_blob(blob, alignment)
        offset = len(blob)
        blob.extend(data)
        layout.append((offset, len(data)))
    _align_blob(blob, 8)
    section_header_offset = len(blob)
    for index, (name, section_type, flags, address, _, link, info, alignment) in enumerate(sections):
        offset, size = layout[index]
        entry_size = 24 if section_type in (2, 11) else 0
        blob.extend(struct.pack(
            "<IIQQQQIIQQ",
            section_name(name) if name else 0,
            section_type,
            flags,
            address,
            offset,
            size,
            link,
            info,
            alignment,
            entry_size,
        ))
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident, 3, 183, 1, 0, 0, section_header_offset, 0,
        64, 0, 0, 64, len(sections), 7,
    )
    blob[:64] = header
    return bytes(blob)


def _artifact_record(name: str, data: bytes) -> dict[str, object]:
    return {
        "remote_name": name,
        "local_path": f"artifacts/{name}",
        "source_size": len(data),
        "destination_size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "decoder": None,
        "termination": None,
        "stop_reason": None,
        "metrics_schema": None,
        "producer_waits": None,
        "producer_wait_ns": None,
        "conversion_ms": None,
        "native_stop_acknowledged": None,
        "host_observed_ack_ms": None,
    }


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _session_report(session_id: str,
                    artifacts: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema": 1,
        "session_id": session_id,
        "mode": "run",
        "status": "sealed",
        "stage": "sealed",
        "package": "com.example.fixture",
        "serial": "fixture-device",
        "pid": 4242,
        "started_at": "2026-08-30T00:00:00Z",
        "finished_at": "2026-08-30T00:00:01Z",
        "timeline": [],
        "device": {"serial": "fixture-device", "access_mode": "run-as"},
        "tracer": {"format": "binary"},
        "target": {"module": "libtarget.so"},
        "effective_config": {},
        "native": {},
        "artifacts": artifacts,
        "warnings": [],
        "error": None,
        "outputs": [str(item["local_path"]) for item in artifacts],
    }


def _session_files(directory: str, session_id: str,
                   artifacts: dict[str, bytes]) -> list[Fixture]:
    prefix = f"sessions/{directory}"
    fixture_class = f"session.{directory}"
    report = _session_report(
        session_id,
        [_artifact_record(name, data) for name, data in artifacts.items()],
    )
    members = {
        "report.json": _json_bytes(report),
        "session.json": _json_bytes({
            "schema": 1,
            "sessionId": session_id,
            "packageName": "com.example.fixture",
            "status": None,
            "host": {},
        }),
        "effective-config.json": _json_bytes({}),
        "device.json": _json_bytes({
            "serial": "fixture-device",
            "package": "com.example.fixture",
            "access_mode": "run-as",
        }),
        **{f"artifacts/{name}": data for name, data in artifacts.items()},
    }
    return [
        Fixture(f"{prefix}/{name}", data, "qtrace-session", "1", fixture_class)
        for name, data in members.items()
    ]


def _session_fixtures(qtrb: tuple[Fixture, ...], flight: tuple[Fixture, ...]) -> tuple[Fixture, ...]:
    qtrb_by_path = {fixture.path: fixture.data for fixture in qtrb}
    flight_by_path = {fixture.path: fixture.data for fixture in flight}
    valid = _session_files(
        "valid-mixed",
        "11111111-1111-4111-8111-111111111111",
        {
            "main.trace.bin": qtrb_by_path["qtrb/v1.2-completed.bin"],
            "worker.trace.bin": qtrb_by_path["qtrb/v1.0-completed.bin"],
            "capture.flight.bin": flight_by_path["flight/v2-complete.bin"],
        },
    )
    isolated = _session_files(
        "one-invalid-artifact",
        "22222222-2222-4222-8222-222222222222",
        {
            "good.trace.bin": qtrb_by_path["qtrb/v1.2-completed.bin"],
            "good.flight.bin": flight_by_path["flight/v2-complete.bin"],
            "broken.trace.bin": qtrb_by_path["qtrb/malformed/truncated-payload.bin"],
        },
    )
    escape_data = qtrb_by_path["qtrb/v1.2-completed.bin"]
    escape_report = _session_report(
        "33333333-3333-4333-8333-333333333333",
        [{
            **_artifact_record("escape.trace.bin", escape_data),
            "local_path": "../escape.trace.bin",
        }],
    )
    path_escape = Fixture(
        "sessions/path-escape/report.json",
        _json_bytes(escape_report),
        "qtrace-session",
        "1",
        "session.path-escape",
        "error",
        "session.path_escape",
    )
    return tuple(valid + isolated + [path_escape])


def _all_fixtures() -> tuple[Fixture, ...]:
    qtrb = _qtrb_fixtures()
    flight = _flight_fixtures()
    elf = Fixture(
        "elf/minimal-aarch64.elf",
        _minimal_aarch64_elf(),
        "ELF",
        "ELF64/AArch64",
        "elf.aarch64-symbols",
    )
    fixtures = qtrb + flight + _session_fixtures(qtrb, flight) + (elf,)
    paths = [fixture.path for fixture in fixtures]
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate fixture path")
    for fixture in fixtures:
        if len(fixture.data) > MAX_FIXTURE_BYTES:
            raise ValueError(f"fixture exceeds 4 MiB: {fixture.path}")
    return tuple(sorted(fixtures, key=lambda fixture: fixture.path))


README = """# qtrace-ui compatibility fixtures

This directory is generated by `qtrace-ui/tools/export_contract_fixtures.py`.
Do not edit binary fixtures or `manifest.json` by hand.

- `--write` regenerates the corpus with same-directory temporary files and atomic replacement.
- `--check` regenerates in a temporary directory and compares paths, lengths, SHA-256 digests,
  and complete bytes with the checked-in tree.
- Every corpus member is capped at 4 MiB. The differential oracle separately caps inputs at
  8 MiB.

`manifest.json` records each path, digest, byte length, source format/version, expected outcome
class, and generator schema. QTRB and Flight bytes are composed with the independent builders in
`scripts/tests/test_trace_binary.py` and `scripts/tests/test_flight_trace.py`.
""".encode("utf-8")


def _tree() -> dict[str, bytes]:
    fixtures = _all_fixtures()
    entries = []
    for fixture in fixtures:
        expected: dict[str, object] = {
            "outcome": fixture.outcome,
            "class": fixture.fixture_class,
        }
        if fixture.error is not None:
            expected["error"] = fixture.error
        entries.append({
            "path": fixture.path,
            "sha256": hashlib.sha256(fixture.data).hexdigest(),
            "bytes": len(fixture.data),
            "format": fixture.format,
            "version": fixture.version,
            "expected": expected,
            "generator_schema": GENERATOR_SCHEMA,
        })
    manifest = _json_bytes({
        "generator_schema": GENERATOR_SCHEMA,
        "fixtures": entries,
    })
    return {
        "README.md": README,
        "manifest.json": manifest,
        **{fixture.path: fixture.data for fixture in fixtures},
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _write_tree(root: Path, tree: dict[str, bytes]) -> None:
    for relative, data in sorted(tree.items()):
        _atomic_write(root / relative, data)
    expected = set(tree)
    if root.exists():
        stale = sorted(
            (path for path in root.rglob("*")
             if (path.is_file() or path.is_symlink())
             and path.relative_to(root).as_posix() not in expected),
            reverse=True,
        )
        for path in stale:
            path.unlink()
        for directory in sorted(
                (path for path in root.rglob("*") if path.is_dir()), reverse=True):
            try:
                directory.rmdir()
            except OSError:
                pass


def _file_map(root: Path) -> dict[str, Path]:
    if not root.is_dir():
        return {}
    return {
        path.relative_to(root).as_posix(): path
        for path in root.rglob("*")
        if path.is_file()
    }


def _check_tree(expected_root: Path, actual_root: Path) -> list[str]:
    expected = _file_map(expected_root)
    actual = _file_map(actual_root)
    errors = []
    if set(expected) != set(actual):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        if missing:
            errors.append("missing: " + ", ".join(missing))
        if extra:
            errors.append("extra: " + ", ".join(extra))
    for relative in sorted(set(expected) & set(actual)):
        expected_data = expected[relative].read_bytes()
        actual_data = actual[relative].read_bytes()
        if len(expected_data) != len(actual_data):
            errors.append(
                f"length mismatch: {relative}: {len(expected_data)} != {len(actual_data)}"
            )
            continue
        expected_digest = hashlib.sha256(expected_data).hexdigest()
        actual_digest = hashlib.sha256(actual_data).hexdigest()
        if expected_digest != actual_digest:
            errors.append(f"SHA-256 mismatch: {relative}")
            continue
        if expected_data != actual_data:
            errors.append(f"byte mismatch: {relative}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    tree = _tree()
    if arguments.write:
        _write_tree(FIXTURE_ROOT, tree)
        return 0
    with tempfile.TemporaryDirectory(prefix="qtrace-ui-fixtures-") as directory:
        generated = Path(directory) / "fixtures"
        _write_tree(generated, tree)
        errors = _check_tree(generated, FIXTURE_ROOT)
    if errors:
        for error in errors:
            print(f"fixture corpus drift: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"export_contract_fixtures: {error}", file=sys.stderr)
        raise SystemExit(1)
