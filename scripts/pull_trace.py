#!/usr/bin/env python3
"""Safely pull and decode QBDI trace artifacts from an Android app."""

from __future__ import annotations

import argparse
import dataclasses
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from collections.abc import Callable
from collections.abc import Iterable
from pathlib import Path
from typing import Any


CRASH_MARKER_MAGIC = 0x51435248
CRASH_MARKER = struct.Struct("<Iii")
# Linux/Android arm64 signal ABI values written by crash_marker.cpp. These must not inherit the
# host Python ABI (Darwin SIGBUS is 10, while Android SIGBUS is 7).
CRASH_SIGNALS = frozenset((4, 6, 7, 8, 11))
TRACE_SUFFIX = ".trace.txt.lz4"
TRACE_DIRECTORY = "files/qbdi-traces"
PACKAGE_NAME = re.compile(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+\Z")
ARTIFACT_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PARTIAL = 2


class PullTraceError(RuntimeError):
    """An artifact cannot be pulled or validated safely."""


@dataclasses.dataclass(frozen=True)
class CrashMarker:
    signal: int
    tid: int


@dataclasses.dataclass(frozen=True)
class TraceArtifact:
    name: str
    status: str
    metrics_name: str | None = None
    crash_name: str | None = None
    crash_marker: CrashMarker | None = None


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


@dataclasses.dataclass(frozen=True)
class PullResult:
    name: str
    status: str
    outputs: tuple[Path, ...]
    exit_code: int = EXIT_OK


class AdbArtifactClient:
    """Read the app-private artifact directory without an intermediate device file."""

    def __init__(
        self,
        package: str,
        device: str | None = None,
        adb: str = "adb",
        runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    ) -> None:
        if PACKAGE_NAME.fullmatch(package) is None:
            raise PullTraceError(f"unsafe Android package name: {package!r}")
        self.package = package
        self.device = device
        self.adb = adb
        self.runner = runner

    def _command(self, *command: str) -> list[str]:
        result = [self.adb]
        if self.device:
            result.extend(("-s", self.device))
        result.extend(("exec-out", "run-as", self.package, *command))
        return result

    def _run(self, *command: str) -> bytes:
        argv = self._command(*command)
        try:
            completed = self.runner(
                argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False
            )
        except FileNotFoundError as error:
            raise PullTraceError(f"adb executable not found: {self.adb}") from error
        except subprocess.CalledProcessError as error:
            stderr = error.stderr.decode("utf-8", errors="replace") if error.stderr else ""
            raise PullTraceError(
                f"adb run-as command failed ({error.returncode}): {stderr.strip()}"
            ) from error
        return completed.stdout

    @staticmethod
    def _validate_name(name: str) -> None:
        _validate_artifact_name(name)

    def list_names(self) -> list[str]:
        raw = self._run("ls", "-1t", TRACE_DIRECTORY)
        try:
            names = raw.decode("utf-8").splitlines()
        except UnicodeDecodeError as error:
            raise PullTraceError("artifact listing is not valid UTF-8") from error
        for name in names:
            self._validate_name(name)
        return names

    def read_file(self, name: str) -> bytes:
        self._validate_name(name)
        return self._run("cat", f"{TRACE_DIRECTORY}/{name}")

    def stream_file(self, name: str, output: Any) -> None:
        self._validate_name(name)
        argv = self._command("cat", f"{TRACE_DIRECTORY}/{name}")
        try:
            self.runner(
                argv, check=True, stdout=output, stderr=subprocess.PIPE, shell=False
            )
        except FileNotFoundError as error:
            raise PullTraceError(f"adb executable not found: {self.adb}") from error
        except subprocess.CalledProcessError as error:
            stderr = error.stderr.decode("utf-8", errors="replace") if error.stderr else ""
            raise PullTraceError(
                f"adb run-as stream failed ({error.returncode}): {stderr.strip()}"
            ) from error


def parse_crash_marker(data: bytes) -> CrashMarker | None:
    """Return a strict marker, treating an absent/empty sidecar as no crash."""
    if not data:
        return None
    if len(data) != CRASH_MARKER.size:
        raise PullTraceError(f"invalid crash marker size: {len(data)}")
    magic, signal_number, tid = CRASH_MARKER.unpack(data)
    if magic != CRASH_MARKER_MAGIC:
        raise PullTraceError(f"invalid crash marker magic: 0x{magic:08x}")
    if signal_number not in CRASH_SIGNALS:
        raise PullTraceError(f"invalid crash marker signal: {signal_number}")
    if tid <= 0:
        raise PullTraceError(f"invalid crash marker tid: {tid}")
    return CrashMarker(signal_number, tid)


def classify_artifacts(artifacts: Mapping[str, bytes]) -> dict[str, TraceArtifact]:
    """Group trace files with their adjacent metrics and crash sidecars."""
    traces: dict[str, TraceArtifact] = {}
    for name in artifacts:
        if not name.endswith(TRACE_SUFFIX):
            continue
        metrics_name = name + ".metrics"
        crash_name = name + ".crash"
        marker = parse_crash_marker(artifacts.get(crash_name, b""))
        status = "crashed" if marker is not None else (
            "complete" if metrics_name in artifacts else "incomplete"
        )
        traces[name] = TraceArtifact(
            name=name,
            status=status,
            metrics_name=metrics_name if metrics_name in artifacts else None,
            crash_name=crash_name if crash_name in artifacts else None,
            crash_marker=marker,
        )
    return traces


LZ4_MAGIC = b"\x04\x22\x4d\x18"
LZ4_BLOCK_MAXIMUMS = {
    4: 64 * 1024,
    5: 256 * 1024,
    6: 1024 * 1024,
    7: 4 * 1024 * 1024,
}


def _memory_scan_result(frames: list[bytes], truncated: bool) -> Lz4FrameScan:
    if not frames:
        raise PullTraceError("compressed artifact has no complete LZ4 frame")
    return Lz4FrameScan(tuple(frames), truncated)


def _file_scan_result(
    ranges: list[tuple[int, int]], truncated: bool
) -> Lz4FileScan:
    if not ranges:
        raise PullTraceError("compressed artifact has no complete LZ4 frame")
    return Lz4FileScan(tuple(ranges), truncated)


def split_lz4_frames(data: bytes) -> Lz4FrameScan:
    """Split standard LZ4 frames without treating a truncated tail as complete."""
    frames: list[bytes] = []
    cursor = 0
    total = len(data)
    while cursor < total:
        frame_start = cursor
        magic_bytes = min(4, total - cursor)
        if data[cursor:cursor + magic_bytes] != LZ4_MAGIC[:magic_bytes]:
            raise PullTraceError(f"invalid LZ4 frame magic at byte {cursor}")
        if magic_bytes < 4:
            return _memory_scan_result(frames, True)
        cursor += 4
        if total - cursor < 2:
            return _memory_scan_result(frames, True)
        flags = data[cursor]
        block_descriptor = data[cursor + 1]
        cursor += 2
        if flags >> 6 != 1 or flags & 0x02:
            raise PullTraceError(f"invalid LZ4 frame flags at byte {frame_start}")
        block_maximum = LZ4_BLOCK_MAXIMUMS.get((block_descriptor >> 4) & 0x07)
        if block_maximum is None or block_descriptor & 0x8F:
            raise PullTraceError(f"invalid LZ4 block descriptor at byte {frame_start}")
        optional_header = (8 if flags & 0x08 else 0) + (4 if flags & 0x01 else 0)
        if total - cursor < optional_header + 1:
            return _memory_scan_result(frames, True)
        cursor += optional_header + 1  # content size/dictionary id plus header checksum

        while True:
            if total - cursor < 4:
                return _memory_scan_result(frames, True)
            block_word = int.from_bytes(data[cursor:cursor + 4], "little")
            cursor += 4
            if block_word == 0:
                if flags & 0x04:
                    if total - cursor < 4:
                        return _memory_scan_result(frames, True)
                    cursor += 4
                frames.append(data[frame_start:cursor])
                break
            block_size = block_word & 0x7FFFFFFF
            if block_size > block_maximum:
                raise PullTraceError(f"invalid LZ4 block size at byte {cursor - 4}")
            trailer = 4 if flags & 0x10 else 0
            if total - cursor < block_size + trailer:
                return _memory_scan_result(frames, True)
            cursor += block_size + trailer
    return _memory_scan_result(frames, False)


def scan_lz4_file(path: Path) -> Lz4FileScan:
    """Locate complete frames using bounded reads and seeks."""
    ranges: list[tuple[int, int]] = []
    total = path.stat().st_size
    with path.open("rb") as stream:
        while stream.tell() < total:
            frame_start = stream.tell()
            magic = stream.read(4)
            if LZ4_MAGIC[:len(magic)] != magic:
                raise PullTraceError(f"invalid LZ4 frame magic at byte {frame_start}")
            if len(magic) < 4:
                return _file_scan_result(ranges, True)
            descriptor = stream.read(2)
            if len(descriptor) < 2:
                return _file_scan_result(ranges, True)
            flags, block_descriptor = descriptor
            if flags >> 6 != 1 or flags & 0x02:
                raise PullTraceError(f"invalid LZ4 frame flags at byte {frame_start}")
            block_maximum = LZ4_BLOCK_MAXIMUMS.get((block_descriptor >> 4) & 0x07)
            if block_maximum is None or block_descriptor & 0x8F:
                raise PullTraceError(f"invalid LZ4 block descriptor at byte {frame_start}")
            optional_header = (8 if flags & 0x08 else 0) + (4 if flags & 0x01 else 0)
            if len(stream.read(optional_header + 1)) < optional_header + 1:
                return _file_scan_result(ranges, True)
            while True:
                block_offset = stream.tell()
                block_header = stream.read(4)
                if len(block_header) < 4:
                    return _file_scan_result(ranges, True)
                block_word = int.from_bytes(block_header, "little")
                if block_word == 0:
                    if flags & 0x04 and len(stream.read(4)) < 4:
                        return _file_scan_result(ranges, True)
                    ranges.append((frame_start, stream.tell()))
                    break
                block_size = block_word & 0x7FFFFFFF
                if block_size > block_maximum:
                    raise PullTraceError(f"invalid LZ4 block size at byte {block_offset}")
                bytes_to_skip = block_size + (4 if flags & 0x10 else 0)
                if total - stream.tell() < bytes_to_skip:
                    return _file_scan_result(ranges, True)
                stream.seek(bytes_to_skip, os.SEEK_CUR)
    return _file_scan_result(ranges, False)


def decode_lz4_frames(
    data: bytes,
    lz4: str,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> DecodeResult:
    """Decode every complete frame separately, preserving their stream order."""
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


def decode_lz4_file(source: Path, output: Path, lz4: str) -> bool:
    """Stream complete frames through one host lz4 process each."""
    executable = shutil.which(lz4)
    if executable is None:
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
                    [executable, "-d", "-c"],
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
                        chunk = compressed.read(min(1024 * 1024, remaining))
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
                    try:
                        if process.poll() is None:
                            process.terminate()
                    except Exception:
                        pass
                    try:
                        process.wait()
                    except Exception:
                        pass
                raise PullTraceError(
                    f"lz4 decompression failed for frame {index + 1}: {error}"
                ) from error
            except BaseException:
                if not reaped:
                    try:
                        if process.poll() is None:
                            process.terminate()
                    except Exception:
                        pass
                    try:
                        process.wait()
                    except Exception:
                        pass
                raise
            if write_error is not None or return_code != 0:
                raise PullTraceError(
                    f"lz4 decompression failed for frame {index + 1}: {stderr.strip()}"
                )
    return scan.truncated


def _temporary_path(directory: Path) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=".pull-trace-", dir=directory)
    os.close(descriptor)
    return Path(name)


def _validate_artifact_name(name: str) -> None:
    if ARTIFACT_NAME.fullmatch(name) is None or name in (".", ".."):
        raise PullTraceError(f"unsafe artifact name: {name!r}")


def _publish_temp(source: Path, destination: Path, force: bool) -> None:
    if force:
        os.replace(source, destination)
        return
    try:
        os.link(source, destination)
    except FileExistsError as error:
        raise PullTraceError(f"local output already exists: {destination}") from error
    else:
        source.unlink()


def _write_atomic(data: bytes, destination: Path, force: bool) -> None:
    temporary = _temporary_path(destination.parent)
    try:
        with temporary.open("wb") as output:
            output.write(data)
        _publish_temp(temporary, destination, force)
    finally:
        temporary.unlink(missing_ok=True)


def pull_artifact_set(
    client: AdbArtifactClient,
    name: str,
    available_names: Iterable[str],
    output_directory: Path,
    *,
    compressed_only: bool = False,
    force: bool = False,
    lz4: str | None = None,
    decoder: Callable[[Path, Path, str], bool] | None = None,
) -> PullResult:
    """Pull one trace and adjacent sidecars, publishing each local file atomically."""
    _validate_artifact_name(name)
    if not name.endswith(TRACE_SUFFIX):
        raise PullTraceError(f"not a compressed trace artifact: {name}")
    available = set(available_names)
    if name not in available:
        raise PullTraceError(f"remote trace does not exist: {name}")
    metrics_name = name + ".metrics"
    crash_name = name + ".crash"
    sidecar_names = tuple(
        sidecar for sidecar in (metrics_name, crash_name) if sidecar in available
    )

    output_directory.mkdir(parents=True, exist_ok=True)
    if not output_directory.is_dir():
        raise PullTraceError(f"output path is not a directory: {output_directory}")
    stem = name.removesuffix(TRACE_SUFFIX)
    compressed_path = output_directory / name
    normal_path = output_directory / f"{stem}.trace.txt"
    partial_path = output_directory / f"{stem}.partial.trace.txt"
    planned = [compressed_path, *(output_directory / item for item in sidecar_names)]
    if not compressed_only:
        planned.extend((normal_path, partial_path))
    if not force:
        existing = next((path for path in planned if path.exists()), None)
        if existing is not None:
            raise PullTraceError(f"local output already exists: {existing}")

    sidecars = {sidecar: client.read_file(sidecar) for sidecar in sidecar_names}
    classification = classify_artifacts({name: b"", **sidecars})[name]
    pulled: list[Path] = []
    compressed_temporary = _temporary_path(output_directory)
    try:
        with compressed_temporary.open("wb") as output:
            client.stream_file(name, output)
        _publish_temp(compressed_temporary, compressed_path, force)
        pulled.append(compressed_path)
    finally:
        compressed_temporary.unlink(missing_ok=True)
    for sidecar_name, data in sidecars.items():
        destination = output_directory / sidecar_name
        _write_atomic(data, destination, force)
        pulled.append(destination)

    if compressed_only:
        return PullResult(name, classification.status, tuple(pulled))
    if not lz4:
        raise PullTraceError(
            "host lz4 CLI is required for decompression; install the 'lz4' command "
            "or use --compressed-only"
        )
    if decoder is None:
        decoder = decode_lz4_file
    decoded_temporary = _temporary_path(output_directory)
    try:
        truncated = decoder(compressed_path, decoded_temporary, lz4)
        if truncated:
            if classification.crash_marker is None:
                raise PullTraceError(
                    "truncated LZ4 stream has no valid crash marker; no partial text was published"
                )
            _publish_temp(decoded_temporary, partial_path, force)
            pulled.append(partial_path)
            return PullResult(
                name, classification.status, tuple(pulled), exit_code=EXIT_PARTIAL
            )
        _publish_temp(decoded_temporary, normal_path, force)
        pulled.append(normal_path)
        return PullResult(name, classification.status, tuple(pulled))
    finally:
        decoded_temporary.unlink(missing_ok=True)


def select_trace_name(names: Iterable[str], requested: str | None = None) -> str:
    """Select an explicit trace or the newest compressed trace from an ordered listing."""
    ordered = list(names)
    if requested is not None:
        _validate_artifact_name(requested)
        if not requested.endswith(TRACE_SUFFIX):
            raise PullTraceError(f"not a compressed trace artifact: {requested}")
        if requested not in ordered:
            raise PullTraceError(f"remote trace does not exist: {requested}")
        return requested
    for name in ordered:
        if name.endswith(TRACE_SUFFIX):
            return name
    raise PullTraceError("no compressed trace artifacts found")


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Pull and decode the newest QBDI trace through adb run-as"
    )
    parser.add_argument("--package", required=True, help="debuggable Android package")
    parser.add_argument("--device", help="adb device serial")
    parser.add_argument("--adb", default="adb", help="adb executable (default: adb)")
    parser.add_argument("--output", default=".", help="local output directory")
    parser.add_argument("--name", help="specific .trace.txt.lz4 artifact (default: newest)")
    parser.add_argument(
        "--compressed-only", action="store_true", help="pull artifacts without decompression"
    )
    parser.add_argument("--force", action="store_true", help="replace existing local outputs")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    client_factory: Callable[..., AdbArtifactClient] = AdbArtifactClient,
    lz4_finder: Callable[[str], str | None] = shutil.which,
) -> int:
    args = argument_parser().parse_args(argv)
    try:
        client = client_factory(package=args.package, device=args.device, adb=args.adb)
        names = client.list_names()
        selected = select_trace_name(names, args.name)
        lz4 = None if args.compressed_only else lz4_finder("lz4")
        if not args.compressed_only and lz4 is None:
            raise PullTraceError(
                "host lz4 CLI is required for decompression; install the 'lz4' command "
                "or use --compressed-only"
            )
        result = pull_artifact_set(
            client,
            selected,
            names,
            Path(args.output),
            compressed_only=args.compressed_only,
            force=args.force,
            lz4=lz4,
        )
    except PullTraceError as error:
        print(f"pull_trace: {error}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as error:
        print(f"pull_trace: local filesystem error: {error}", file=sys.stderr)
        return EXIT_ERROR

    print(f"trace={result.name} status={result.status}")
    for output in result.outputs:
        print(f"output={output}")
    if result.exit_code == EXIT_PARTIAL:
        print(
            "pull_trace: crash-marked trace ended in a truncated frame; "
            "published complete frames as partial text",
            file=sys.stderr,
        )
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
