#!/usr/bin/env python3
"""Atomically convert raw or LZ4-framed QTRB traces to readable format 3."""

from __future__ import annotations

import argparse
import dataclasses
import os
import sys
import tempfile
from pathlib import Path

try:
    from scripts.lz4_frames import PullTraceError, decode_lz4_file
    from scripts.trace_binary import (
        BinaryTraceError,
        ConversionStats,
        _ConversionDetails,
        _convert_binary_stream,
    )
except ModuleNotFoundError:  # Support direct execution as scripts/trace_convert.py.
    from lz4_frames import PullTraceError, decode_lz4_file  # type: ignore[no-redef]
    from trace_binary import (  # type: ignore[no-redef]
        BinaryTraceError,
        ConversionStats,
        _ConversionDetails,
        _convert_binary_stream,
    )


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PARTIAL = 2


def _temporary_path(directory: Path, suffix: str) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=".trace-convert-", suffix=suffix, dir=directory)
    os.close(descriptor)
    return Path(name)


def _publish(temporary: Path, destination: Path, force: bool) -> None:
    if force:
        os.replace(temporary, destination)
        return
    try:
        os.link(temporary, destination)
    except FileExistsError as error:
        raise BinaryTraceError(f"output already exists: {destination}") from error
    temporary.unlink()


def _parse_sidecar(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise BinaryTraceError("metrics sidecar is not valid UTF-8") from error
    values: dict[str, str] = {}
    for number, line in enumerate(lines, 1):
        if not line or "=" not in line:
            raise BinaryTraceError(f"invalid metrics sidecar line {number}")
        key, value = line.split("=", 1)
        if not key or key in values:
            raise BinaryTraceError(f"duplicate metrics sidecar key {key!r}")
        values[key] = value
    return values


def _sidecar_integer(values: dict[str, str], key: str, *, hexadecimal: bool = False) -> int:
    raw = values.get(key)
    if raw is None:
        raise BinaryTraceError(f"metrics sidecar is missing {key}")
    digits = raw[2:] if hexadecimal and raw.startswith("0x") else raw
    valid = bool(digits) and all(
        character in ("0123456789abcdefABCDEF" if hexadecimal else "0123456789")
        for character in digits
    )
    if not valid or (hexadecimal and not raw.startswith("0x")):
        raise BinaryTraceError(f"invalid metrics sidecar value for {key}")
    try:
        return int(digits, 16 if hexadecimal else 10)
    except ValueError as error:
        raise BinaryTraceError(f"invalid metrics sidecar value for {key}") from error


def _validate_sidecar(path: Path, details: _ConversionDetails, artifact_size: int) -> None:
    footer = details.footer
    if footer is None:
        raise BinaryTraceError("complete metrics sidecar cannot accompany a partial trace")
    values = _parse_sidecar(path)
    actual = {
        "metrics_version": _sidecar_integer(values, "metrics_version"),
        "profile": values.get("profile", ""),
        "return": _sidecar_integer(values, "return", hexadecimal=True),
        "instructions": _sidecar_integer(values, "instructions"),
        "elapsed_ms": _sidecar_integer(values, "elapsed_ms"),
        "encoded_bytes": _sidecar_integer(values, "encoded_bytes"),
        "compressed_bytes": _sidecar_integer(values, "compressed_bytes"),
        "cache_hits": _sidecar_integer(values, "cache_hits"),
        "cache_misses": _sidecar_integer(values, "cache_misses"),
        "cache_collisions": _sidecar_integer(values, "cache_collisions"),
        "buffer_swaps": _sidecar_integer(values, "buffer_swaps"),
        "producer_waits": _sidecar_integer(values, "producer_waits"),
        "producer_wait_ns": _sidecar_integer(values, "producer_wait_ns"),
        "effective_buffer_bytes": _sidecar_integer(values, "effective_buffer_bytes"),
    }
    expected = {
        "metrics_version": 2,
        "profile": details.profile,
        "return": footer.return_value,
        "instructions": footer.instructions,
        "elapsed_ms": footer.elapsed_ms,
        "encoded_bytes": footer.encoded_bytes,
        "compressed_bytes": footer.compressed_bytes,
        "cache_hits": footer.cache_hits,
        "cache_misses": footer.cache_misses,
        "cache_collisions": footer.cache_collisions,
        "buffer_swaps": footer.buffer_swaps,
        "producer_waits": footer.producer_waits,
        "producer_wait_ns": footer.producer_wait_ns,
        "effective_buffer_bytes": footer.effective_buffer_bytes,
    }
    for key, expected_value in expected.items():
        if actual[key] != expected_value:
            raise BinaryTraceError(
                f"sidecar mismatch for {key}: expected {expected_value!r}, got {actual[key]!r}"
            )
    if footer.compressed_bytes != artifact_size:
        raise BinaryTraceError(
            f"sidecar mismatch for artifact size: expected {footer.compressed_bytes}, "
            f"got {artifact_size}"
        )


def convert_binary_file(source: Path, destination: Path, *, lz4: str | None,
                        crash_marked: bool, force: bool = False) -> ConversionStats:
    """Convert one artifact through unique temporaries and atomically publish text."""
    source = Path(source)
    destination = Path(destination)
    if not source.is_file():
        raise BinaryTraceError(f"binary trace does not exist: {source}")
    if not destination.parent.is_dir():
        raise BinaryTraceError(f"output directory does not exist: {destination.parent}")
    if destination.exists() and not force:
        raise BinaryTraceError(f"output already exists: {destination}")

    compressed = source.name.endswith(".trace.bin.lz4")
    if compressed and not lz4:
        raise BinaryTraceError("host lz4 CLI is required for compressed binary traces")
    if not compressed and lz4 is not None:
        raise BinaryTraceError("lz4 decoder was supplied for a raw binary trace")

    binary_temporary: Path | None = None
    text_temporary = _temporary_path(destination.parent, ".txt")
    truncated_frame = False
    try:
        binary_source = source
        if compressed:
            binary_temporary = _temporary_path(destination.parent, ".bin")
            try:
                truncated_frame = decode_lz4_file(source, binary_temporary, lz4 or "lz4")
            except PullTraceError as error:
                raise BinaryTraceError(str(error)) from error
            if truncated_frame and not crash_marked:
                raise BinaryTraceError(
                    "truncated LZ4 frame has no valid crash marker; no text was published"
                )
            binary_source = binary_temporary

        with binary_source.open("rb") as binary, text_temporary.open(
                "w", encoding="utf-8", newline="\n") as text:
            details = _convert_binary_stream(
                binary, text, allow_partial=crash_marked and truncated_frame
            )
            text.flush()
            os.fsync(text.fileno())

        if truncated_frame:
            details = dataclasses.replace(
                details, stats=dataclasses.replace(details.stats, partial=True)
            )
        if (not details.stats.partial and details.footer is not None
                and details.footer.compressed_bytes != source.stat().st_size):
            raise BinaryTraceError(
                "footer artifact byte count mismatch: "
                f"expected {details.footer.compressed_bytes}, got {source.stat().st_size}"
            )
        sidecar = Path(str(source) + ".metrics")
        if sidecar.exists() and not details.stats.partial:
            _validate_sidecar(sidecar, details, source.stat().st_size)
        _publish(text_temporary, destination, force)
        return details.stats
    except BinaryTraceError:
        raise
    except OSError as error:
        raise BinaryTraceError(f"binary trace conversion failed: {error}") from error
    finally:
        text_temporary.unlink(missing_ok=True)
        if binary_temporary is not None:
            binary_temporary.unlink(missing_ok=True)


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Convert a QTRB binary trace to text format 3")
    parser.add_argument("source", type=Path, nargs="?", help=".trace.bin or .trace.bin.lz4 input")
    parser.add_argument("--output", type=Path, help="destination text path")
    parser.add_argument("--lz4", default="lz4", help="host lz4 executable (default: lz4)")
    parser.add_argument(
        "--crash-marked", action="store_true",
        help="permit recovery of complete records from complete frames after a valid crash marker",
    )
    parser.add_argument("--force", action="store_true", help="replace an existing output")
    return parser


def _default_output(source: Path, partial: bool) -> Path:
    name = source.name
    suffix = ".trace.bin.lz4" if name.endswith(".trace.bin.lz4") else ".trace.bin"
    if not name.endswith(suffix):
        raise BinaryTraceError("input must end in .trace.bin or .trace.bin.lz4")
    stem = name.removesuffix(suffix)
    ending = ".partial.trace.txt" if partial else ".trace.txt"
    return source.with_name(stem + ending)


def main(argv: list[str] | None = None) -> int:
    parser = argument_parser()
    arguments = parser.parse_args(argv)
    if arguments.source is None:
        parser.error("the following arguments are required: source")
    source: Path = arguments.source
    destination = arguments.output or _default_output(source, arguments.crash_marked)
    lz4 = arguments.lz4 if source.name.endswith(".lz4") else None
    try:
        stats = convert_binary_file(
            source, destination, lz4=lz4, crash_marked=arguments.crash_marked,
            force=arguments.force,
        )
    except BinaryTraceError as error:
        print(f"trace_convert: {error}", file=sys.stderr)
        return EXIT_ERROR
    print(
        f"converted {stats.instructions} instructions, {stats.converted_text_bytes} text bytes"
        + (" (partial)" if stats.partial else "")
    )
    return EXIT_PARTIAL if stats.partial else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
