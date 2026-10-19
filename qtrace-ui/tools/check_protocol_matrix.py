#!/usr/bin/env python3
"""Compile the production C++ encoders and verify the Python/Rust wire matrix.

Use --write to intentionally refresh fixtures-native after reviewing a protocol change.
Ordinary checks never alter checked-in or user artifacts. Parsers remain independent.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / "qtrace-ui"
NATIVE = UI / "fixtures-native"
sys.path.insert(0, str(ROOT))

from scripts import flight_trace, trace_binary  # noqa: E402


def run(arguments: list[str], **kwargs: object) -> None:
    subprocess.run(arguments, cwd=ROOT, check=True, timeout=300, **kwargs)


def build_emitter(output: Path) -> None:
    cpp = ROOT / "tracer/src/main/cpp"
    sources = [
        ROOT / "tracer/src/test/cpp/protocol_fixture_emitter.cpp",
        *(cpp / name for name in (
            "events/binary_trace_encoder.cpp", "flight/flight_encoder.cpp",
            "flight/flight_artifact.cpp", "flight/flight_chunk_writer.cpp",
        )),
    ]
    run([
        *shlex.split(os.environ.get("CXX", "c++")), "-std=c++20", "-O1",
        "-DQTRACE_HOST_TEST=1", "-pthread", f"-I{cpp}",
        f"-I{cpp / 'third_party/qbdi/include'}", *map(str, sources), "-o", str(output),
    ])


def python_constants() -> dict[str, dict[str, int]]:
    return {
        "qtrb": {
            "major": 1, "minor": 2, "features": 1,
            "stream_header": trace_binary.STREAM_HEADER.size,
            "record_header": trace_binary.RECORD_HEADER.size,
            "instruction_fixed": trace_binary.INSTRUCTION_FIXED.size,
            "definition_fixed": trace_binary.INSTRUCTION_DEFINITION_FIXED.size,
            "memory_operand": trace_binary.MEMORY_OPERAND.size,
            "end_payload": trace_binary.TRACE_END_FIXED.size,
            "stop_payload": trace_binary.TRACE_STOP_FIXED.size,
            "max_record": trace_binary.MAX_RECORD_PAYLOAD + trace_binary.RECORD_HEADER.size,
        },
        "flight": {
            "version": flight_trace.VERSION, "superblock": flight_trace.SUPERBLOCK_BYTES,
            "directory_entry": flight_trace.DIRECTORY_ENTRY_BYTES,
            "chunk_header": flight_trace.CHUNK_HEADER_BYTES,
            "record_header": flight_trace.RECORD_HEADER_BYTES,
            "emergency_record": flight_trace.EMERGENCY_RECORD_BYTES,
            "emergency_slot": flight_trace.EMERGENCY_SLOT_BYTES,
            "record_commit": flight_trace.RECORD_COMMIT,
        },
    }


def finalize(directory: Path) -> dict[str, bytes]:
    constants = json.loads((directory / "constants.json").read_bytes())
    if constants != python_constants():
        raise ValueError("C++/Python protocol constant drift; update the wire specification first")
    if (constants["qtrb"]["minor"], constants["qtrb"]["features"]) not in trace_binary.SUPPORTED_MINOR_FEATURES:
        raise ValueError("native QTRB version/features are not supported by Python")
    fixtures = []
    for path in sorted(directory.glob("*.bin")):
        data = path.read_bytes()
        if len(data) > 4 * 1024 * 1024:
            raise ValueError("native fixture exceeds 4 MiB")
        if path.name.startswith("qtrb-"):
            stats = trace_binary.convert_binary_stream(io.BytesIO(data), io.StringIO())
            if stats.instructions != 1 or stats.termination != ("stopped" if "stopped" in path.name else "completed"):
                raise ValueError(f"native QTRB semantics drift: {path.name}")
            format_name, version = "QTRB", "1.2"
        else:
            recovered = flight_trace.recover_flight(io.BytesIO(data))
            if not any(event.kind == "instruction" for event in recovered.merged):
                raise ValueError(f"native Flight instruction missing: {path.name}")
            format_name, version = "Flight", "2"
        fixtures.append({
            "path": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "format": format_name, "version": version, "producer": "production-cpp-encoder",
        })
    (directory / "manifest.json").write_text(json.dumps({
        "generator_schema": 1, "fixtures": fixtures,
    }, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {path.name: path.read_bytes() for path in directory.iterdir() if path.is_file()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--skip-rust", action="store_true", help="Only validate fixture bytes and Python readers")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="qtrace-protocol-") as temporary:
        base = Path(temporary)
        emitter = base / "emitter"
        build_emitter(emitter)
        generated = base / "first"
        run([str(emitter), str(generated)])
        tree = finalize(generated)
        repeated = base / "second"
        run([str(emitter), str(repeated)])
        if tree != finalize(repeated):
            raise ValueError("native encoder fixtures are not deterministic")
        if args.write:
            NATIVE.mkdir(parents=True, exist_ok=True)
            for name, data in tree.items():
                (NATIVE / name).write_bytes(data)
        actual = {path.name: path.read_bytes() for path in NATIVE.iterdir() if path.is_file()}
        if tree != actual:
            raise ValueError("native fixture drift; review protocol changes, then use --write")
        run([sys.executable, str(UI / "tools/export_contract_fixtures.py"), "--check"])
        run([sys.executable, "-m", "unittest", "scripts.tests.test_qtrace_ui_fixtures"])
        if not args.skip_rust:
            environment = dict(os.environ, QTRACE_NATIVE_FIXTURES=str(generated))
            run([
                "cargo", "test", "--manifest-path", str(UI / "Cargo.toml"), "--locked", "-j", "2",
                "-p", "qtrace-provider", "--test", "qtrb_differential", "--test", "qtrb_framing",
                "--test", "flight_differential",
            ], env=environment)
    readers = "Python" if args.skip_rust else "Python/Rust"
    print(f"Protocol matrix passed: C++ encoders, {readers} readers, QTRB 1.0–1.2, Flight v2, malformed corpus")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"protocol matrix: {error}", file=sys.stderr)
        raise SystemExit(1)
