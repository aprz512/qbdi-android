"""Strict, bounded scanning and streaming decode for concatenated LZ4 frames."""

from __future__ import annotations

import dataclasses
import io
import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO


LZ4_MAGIC = b"\x04\x22\x4d\x18"
LZ4_SKIPPABLE_MAGIC_SUFFIX = b"\x2a\x4d\x18"
LZ4_BLOCK_MAXIMUMS = {
    4: 64 * 1024,
    5: 256 * 1024,
    6: 1024 * 1024,
    7: 4 * 1024 * 1024,
}
COPY_CHUNK_BYTES = 1024 * 1024


class PullTraceError(RuntimeError):
    """An artifact cannot be pulled, framed, or decoded safely."""


@dataclasses.dataclass(frozen=True)
class Lz4FrameScan:
    frames: tuple[bytes, ...]
    truncated: bool


@dataclasses.dataclass(frozen=True)
class Lz4FileScan:
    ranges: tuple[tuple[int, int], ...]
    truncated: bool


@dataclasses.dataclass(frozen=True)
class DecodeResult:
    data: bytes
    truncated: bool


def _is_skippable_magic_prefix(magic: bytes) -> bool:
    return bool(magic) and 0x50 <= magic[0] <= 0x5F and (
        len(magic) == 1 or magic[1:] == LZ4_SKIPPABLE_MAGIC_SUFFIX[:len(magic) - 1]
    )


def _scan_stream(stream: BinaryIO, total: int) -> Lz4FileScan:
    """Scan a seekable stream; ranges contain standard frames, omitting skippable padding."""
    ranges: list[tuple[int, int]] = []

    def result(truncated: bool) -> Lz4FileScan:
        if not ranges:
            raise PullTraceError("compressed artifact has no complete LZ4 frame")
        return Lz4FileScan(tuple(ranges), truncated)

    while stream.tell() < total:
        frame_start = stream.tell()
        magic = stream.read(4)
        standard_prefix = magic == LZ4_MAGIC[:len(magic)]
        skippable_prefix = _is_skippable_magic_prefix(magic)
        if not standard_prefix and not skippable_prefix:
            raise PullTraceError(f"invalid LZ4 frame magic at byte {frame_start}")
        if len(magic) < 4:
            return result(True)

        if skippable_prefix:
            size_bytes = stream.read(4)
            if len(size_bytes) < 4:
                return result(True)
            payload_bytes = int.from_bytes(size_bytes, "little")
            remaining = total - stream.tell()
            if payload_bytes > remaining:
                return result(True)
            stream.seek(payload_bytes, os.SEEK_CUR)
            continue

        descriptor = stream.read(2)
        if len(descriptor) < 2:
            return result(True)
        flags, block_descriptor = descriptor
        if flags >> 6 != 1 or flags & 0x02:
            raise PullTraceError(f"invalid LZ4 frame flags at byte {frame_start}")
        block_maximum = LZ4_BLOCK_MAXIMUMS.get((block_descriptor >> 4) & 0x07)
        if block_maximum is None or block_descriptor & 0x8F:
            raise PullTraceError(f"invalid LZ4 block descriptor at byte {frame_start}")

        optional_header = (8 if flags & 0x08 else 0) + (4 if flags & 0x01 else 0)
        if len(stream.read(optional_header + 1)) < optional_header + 1:
            return result(True)

        while True:
            block_offset = stream.tell()
            block_header = stream.read(4)
            if len(block_header) < 4:
                return result(True)
            block_word = int.from_bytes(block_header, "little")
            if block_word == 0:
                if flags & 0x04 and len(stream.read(4)) < 4:
                    return result(True)
                ranges.append((frame_start, stream.tell()))
                break
            block_size = block_word & 0x7FFFFFFF
            if block_size > block_maximum:
                raise PullTraceError(f"invalid LZ4 block size at byte {block_offset}")
            bytes_to_skip = block_size + (4 if flags & 0x10 else 0)
            if bytes_to_skip > total - stream.tell():
                return result(True)
            stream.seek(bytes_to_skip, os.SEEK_CUR)

    return result(False)


def scan_lz4_file(path: Path) -> Lz4FileScan:
    """Validate and index every complete standard frame using bounded reads."""
    total = path.stat().st_size
    with path.open("rb") as stream:
        return _scan_stream(stream, total)


def split_lz4_frames(data: bytes) -> Lz4FrameScan:
    """Return complete standard frames without exposing a truncated final frame."""
    scan = _scan_stream(io.BytesIO(data), len(data))
    return Lz4FrameScan(tuple(data[start:end] for start, end in scan.ranges), scan.truncated)


def decode_lz4_frames(
    data: bytes,
    lz4: str,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> DecodeResult:
    """Decode every complete standard frame separately in stream order."""
    scan = split_lz4_frames(data)
    output = bytearray()
    for index, frame in enumerate(scan.frames):
        command = [lz4, "-d", "-c"]
        try:
            completed = runner(
                command,
                input=frame,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
        except FileNotFoundError as error:
            raise PullTraceError(
                "host lz4 CLI is required for decompression; install the 'lz4' command "
                "or use --compressed-only"
            ) from error
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace")
            raise PullTraceError(
                f"lz4 decompression failed for frame {index + 1}: {stderr.strip()}"
            )
        output.extend(completed.stdout)
    return DecodeResult(bytes(output), scan.truncated)


def _terminate_and_reap(process: subprocess.Popen[bytes]) -> None:
    try:
        if process.poll() is None:
            process.terminate()
    except Exception:
        pass
    try:
        process.wait()
    except Exception:
        pass


def decode_lz4_file(source: Path, output: Path, executable: str) -> bool:
    """Stream complete standard frames to a host LZ4 CLI, at most 1 MiB per copy."""
    resolved_executable = shutil.which(executable)
    if resolved_executable is None:
        raise PullTraceError(
            "host lz4 CLI is required for decompression; install the 'lz4' command "
            "or use --compressed-only"
        )
    scan = scan_lz4_file(source)
    with source.open("rb") as compressed, output.open("wb") as decoded:
        for index, (start, end) in enumerate(scan.ranges):
            compressed.seek(start)
            try:
                process = subprocess.Popen(
                    [resolved_executable, "-d", "-c"],
                    stdin=subprocess.PIPE,
                    stdout=decoded,
                    stderr=subprocess.PIPE,
                )
            except OSError as error:
                raise PullTraceError(f"cannot start host lz4 CLI: {error}") from error
            assert process.stdin is not None
            assert process.stderr is not None
            remaining = end - start
            write_error: BrokenPipeError | None = None
            reaped = False
            try:
                try:
                    while remaining:
                        chunk = compressed.read(min(COPY_CHUNK_BYTES, remaining))
                        if not chunk:
                            raise PullTraceError("compressed trace changed while decoding")
                        process.stdin.write(chunk)
                        remaining -= len(chunk)
                except BrokenPipeError as error:
                    write_error = error
                finally:
                    try:
                        process.stdin.close()
                    except BrokenPipeError as error:
                        write_error = error
                with process.stderr:
                    stderr = process.stderr.read().decode("utf-8", errors="replace")
                return_code = process.wait()
                reaped = True
            except Exception as error:
                if not reaped:
                    _terminate_and_reap(process)
                raise PullTraceError(
                    f"lz4 decompression failed for frame {index + 1}: {error}"
                ) from error
            except BaseException:
                if not reaped:
                    _terminate_and_reap(process)
                raise
            if write_error is not None or return_code != 0:
                raise PullTraceError(
                    f"lz4 decompression failed for frame {index + 1}: {stderr.strip()}"
                )
    return scan.truncated
