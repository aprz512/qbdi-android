#!/usr/bin/env python3
"""Bounded differential oracle for checked-in qtrace-ui fixtures."""

from __future__ import annotations

import dataclasses
import io
import json
import os
from pathlib import Path
import stat
import sys
from typing import BinaryIO


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.flight_trace import recover_flight  # noqa: E402
from scripts.trace_binary import convert_binary_stream  # noqa: E402


MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_ERROR_BYTES = 4096


def _fail(message: str) -> int:
    prefix = "oracle: "
    encoded = (prefix + message).encode("utf-8", "replace")
    bounded = encoded[:MAX_ERROR_BYTES - 1]
    sys.stderr.buffer.write(bounded + b"\n")
    return 1


class _BoundedSource:
    def __init__(self, source: BinaryIO) -> None:
        self.source = source

    def read(self, size: int = -1) -> bytes:
        position = self.source.tell()
        if position > MAX_SOURCE_BYTES:
            raise ValueError("source exceeds the 8 MiB oracle limit")
        remaining = MAX_SOURCE_BYTES - position
        requested = remaining + 1 if size < 0 or size > remaining + 1 else size
        data = self.source.read(requested)
        if len(data) > remaining:
            raise ValueError("source exceeds the 8 MiB oracle limit")
        return data

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        position = self.source.seek(offset, whence)
        if position > MAX_SOURCE_BYTES:
            raise ValueError("source exceeds the 8 MiB oracle limit")
        return position

    def tell(self) -> int:
        return self.source.tell()

    def __enter__(self) -> "_BoundedSource":
        return self

    def __exit__(self, *_args: object) -> None:
        self.source.close()


def _source(path: Path) -> _BoundedSource:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("source must be a regular file")
        if info.st_size > MAX_SOURCE_BYTES:
            raise ValueError("source exceeds the 8 MiB oracle limit")
        source = os.fdopen(descriptor, "rb")
        descriptor = -1
        return _BoundedSource(source)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _qtrb(path: Path) -> dict[str, object]:
    output = io.StringIO()
    with _source(path) as source:
        stats = convert_binary_stream(source, output, allow_partial=True)
    return {
        "lines": output.getvalue().splitlines(),
        "stats": dataclasses.asdict(stats),
    }


def _flight(path: Path) -> dict[str, object]:
    with _source(path) as source:
        recovered = recover_flight(source)
    threads = {
        str(tid): (dataclasses.asdict(thread.registers)
                   if thread.registers is not None else None)
        for tid, thread in sorted(recovered.threads.items())
    }
    for tid in recovered.summary["projection_tids"]:
        threads.setdefault(str(tid), None)
    return {
        "events": [dataclasses.asdict(event) for event in recovered.merged],
        "threads": threads,
        "summary": recovered.summary,
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2:
        return _fail("usage: oracle.py <qtrb|flight> <source>")
    mode, source_name = arguments
    if mode not in {"qtrb", "flight"}:
        return _fail(f"unknown oracle mode: {mode[:256]}")
    source = Path(source_name)
    try:
        document = _qtrb(source) if mode == "qtrb" else _flight(source)
        encoded = (
            json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("utf-8")
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise ValueError("oracle JSON exceeds the 16 MiB output limit")
        sys.stdout.buffer.write(encoded)
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        return _fail(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
