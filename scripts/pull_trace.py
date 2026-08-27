#!/usr/bin/env python3
"""Safely pull and decode QBDI trace artifacts from an Android app."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unicodedata
from collections.abc import Mapping
from collections.abc import Callable
from collections.abc import Iterable
from pathlib import Path
from typing import Any

try:
    from scripts.bounded_process import BoundedProcessError, capture_bounded
    from scripts.lz4_frames import (
        DecodeResult,
        Lz4FileScan,
        Lz4FrameScan,
        PullTraceError,
        decode_lz4_file,
        decode_lz4_frames,
        scan_lz4_file,
        split_lz4_frames,
    )
    from scripts.flight_convert import (
        publish_flight_file_set,
        publish_flight_outputs,
        recovery_status,
    )
    from scripts.flight_trace import FlightTraceError, recover_flight
    from scripts.trace_binary import BinaryTraceError
    from scripts.trace_convert import convert_binary_file
    from scripts.trace_metrics import parse_metrics
except ModuleNotFoundError:  # Support direct execution as scripts/pull_trace.py.
    from bounded_process import BoundedProcessError, capture_bounded  # type: ignore[no-redef]
    from lz4_frames import (  # type: ignore[no-redef]
        DecodeResult,
        Lz4FileScan,
        Lz4FrameScan,
        PullTraceError,
        decode_lz4_file,
        decode_lz4_frames,
        scan_lz4_file,
        split_lz4_frames,
    )
    from flight_convert import (  # type: ignore[no-redef]
        publish_flight_file_set,
        publish_flight_outputs,
        recovery_status,
    )
    from flight_trace import FlightTraceError, recover_flight  # type: ignore[no-redef]
    from trace_binary import BinaryTraceError  # type: ignore[no-redef]
    from trace_convert import convert_binary_file  # type: ignore[no-redef]
    from trace_metrics import parse_metrics  # type: ignore[no-redef]


CRASH_MARKER_MAGIC = 0x51435248
CRASH_MARKER = struct.Struct("<Iii")
# Linux/Android arm64 signal ABI values written by crash_marker.cpp. These must not inherit the
# host Python ABI (Darwin SIGBUS is 10, while Android SIGBUS is 7).
CRASH_SIGNALS = frozenset((4, 6, 7, 8, 11))
TEXT_TRACE_SUFFIX = ".trace.txt.lz4"
BINARY_TRACE_SUFFIX = ".trace.bin.lz4"
BINARY_RAW_SUFFIX = ".trace.bin"
FLIGHT_SUFFIX = ".flight.bin"
TRACE_SUFFIXES = (TEXT_TRACE_SUFFIX, BINARY_TRACE_SUFFIX, BINARY_RAW_SUFFIX, FLIGHT_SUFFIX)
# Kept for callers that imported the old text-only constant.
TRACE_SUFFIX = TEXT_TRACE_SUFFIX
TRACE_DIRECTORY = "files/qbdi-traces"
PACKAGE_NAME = re.compile(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+\Z")
ARTIFACT_NAME = re.compile(r"[^/\\\x00-\x1f\x7f]+\Z")
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_PARTIAL = 2
MAX_LISTING_BYTES = 1024 * 1024
MAX_METRICS_BYTES = 64 * 1024


def _pull_named(client: object, package: str, name: str, destination: Path, timeout: float) -> None:
    try:
        from qtrace.artifacts import pull_named_artifacts
    except ModuleNotFoundError as error:
        if error.name != "qtrace":
            raise
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from qtrace.artifacts import pull_named_artifacts
    pull_named_artifacts(client, package, [name], destination, timeout=timeout)


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
        timeout: float = 120.0,
        runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
        listing_capture: Callable[..., bytes] = capture_bounded,
    ) -> None:
        if PACKAGE_NAME.fullmatch(package) is None:
            raise PullTraceError(f"unsafe Android package name: {package!r}")
        self.package = package
        self.device = device
        self.adb = adb
        self.timeout = timeout
        self.runner = runner
        self.listing_capture = listing_capture

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
                argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                timeout=self.timeout,
            )
        except FileNotFoundError as error:
            raise PullTraceError(f"adb executable not found: {self.adb}") from error
        except subprocess.CalledProcessError as error:
            stderr = error.stderr.decode("utf-8", errors="replace") if error.stderr else ""
            raise PullTraceError(
                f"adb run-as command failed ({error.returncode}): {stderr.strip()}"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise PullTraceError(f"adb run-as command timed out after {self.timeout:g}s") from error
        return completed.stdout

    @staticmethod
    def _validate_name(name: str) -> None:
        _validate_artifact_name(name)

    def list_names(self) -> list[str]:
        try:
            raw = self.listing_capture(
                self._command("ls", "-1t", TRACE_DIRECTORY),
                maximum_bytes=MAX_LISTING_BYTES,
                timeout=self.timeout,
            )
        except FileNotFoundError as error:
            raise PullTraceError(f"adb executable not found: {self.adb}") from error
        except subprocess.TimeoutExpired as error:
            raise PullTraceError(f"adb artifact listing timed out after {self.timeout:g}s") from error
        except BoundedProcessError as error:
            raise PullTraceError(f"adb artifact listing failed: {error}") from error
        try:
            names = raw.decode("utf-8").splitlines()
        except UnicodeDecodeError as error:
            raise PullTraceError("artifact listing is not valid UTF-8") from error
        for name in names:
            self._validate_name(name)
        return names

    def read_file(self, name: str, maximum_bytes: int = MAX_METRICS_BYTES) -> bytes:
        self._validate_name(name)
        if maximum_bytes < 0:
            raise PullTraceError("read size limit must not be negative")
        data = self._run(
            "head", "-c", str(maximum_bytes + 1), f"{TRACE_DIRECTORY}/{name}"
        )
        if len(data) > maximum_bytes:
            raise PullTraceError(f"remote artifact exceeds size limit: {name}")
        return data

    def stream_file(self, name: str, output: Any) -> None:
        self._validate_name(name)
        argv = self._command("cat", f"{TRACE_DIRECTORY}/{name}")
        try:
            self.runner(
                argv, check=True, stdout=output, stderr=subprocess.PIPE, shell=False,
                timeout=self.timeout,
            )
        except FileNotFoundError as error:
            raise PullTraceError(f"adb executable not found: {self.adb}") from error
        except subprocess.CalledProcessError as error:
            stderr = error.stderr.decode("utf-8", errors="replace") if error.stderr else ""
            raise PullTraceError(
                f"adb run-as stream failed ({error.returncode}): {stderr.strip()}"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise PullTraceError(f"adb run-as stream timed out after {self.timeout:g}s") from error


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
        if not name.endswith(TRACE_SUFFIXES):
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


def _temporary_path(directory: Path) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=".pull-trace-", dir=directory)
    os.close(descriptor)
    return Path(name)


def _validate_artifact_name(name: str) -> None:
    try:
        valid = (type(name) is str and ARTIFACT_NAME.fullmatch(name) is not None and
                 name not in (".", "..") and len(name.encode("utf-8")) <= 255 and
                 all(character.isalnum() or character in "._-" or
                     unicodedata.category(character).startswith("M") for character in name))
    except UnicodeEncodeError:
        valid = False
    if not valid:
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
    if not name.endswith(TRACE_SUFFIXES):
        raise PullTraceError(f"not a trace artifact: {name}")
    available = set(available_names)
    if name not in available:
        raise PullTraceError(f"remote trace does not exist: {name}")
    output_directory.mkdir(parents=True, exist_ok=True)
    if not output_directory.is_dir():
        raise PullTraceError(f"output path is not a directory: {output_directory}")
    if name.endswith(FLIGHT_SUFFIX):
        destination = output_directory / name
        if not force and os.path.lexists(destination):
            raise PullTraceError(f"local output already exists: {destination}")
        try:
            with tempfile.TemporaryDirectory(
                prefix=".pull-flight-", dir=output_directory
            ) as staging_name:
                staging = Path(staging_name)
                source = staging / name
                # Keep the legacy CLI's publication semantics, but share the
                # bounded/hash-checked named pull primitive with qtrace sessions.
                try:
                    _pull_named(client, getattr(client, "package", "com.example.app"), name, staging,
                                getattr(client, "timeout", 120.0))
                except Exception as error:
                    raise PullTraceError(str(error)) from error
                if compressed_only:
                    with source.open("rb") as binary:
                        status = recovery_status(recover_flight(binary).summary)
                    _publish_temp(source, destination, force)
                    return PullResult(name, status, (destination,))
                staged_outputs = publish_flight_outputs(
                    source, staging / "converted", force=False
                )
                summary = json.loads(staged_outputs[-1].read_text(encoding="utf-8"))
                outputs = tuple(output_directory / path.name for path in staged_outputs)
                publish_flight_file_set(
                    [(source, destination), *zip(staged_outputs, outputs, strict=True)],
                    force,
                )
                return PullResult(
                    name,
                    recovery_status(summary),
                    (destination, *outputs),
                )
        except (FlightTraceError, FileExistsError, json.JSONDecodeError) as error:
            raise PullTraceError(str(error)) from error
    metrics_name = name + ".metrics"
    crash_name = name + ".crash"
    sidecar_names = tuple(
        sidecar for sidecar in (metrics_name, crash_name) if sidecar in available
    )

    trace_suffix = next(suffix for suffix in TRACE_SUFFIXES if name.endswith(suffix))
    stem = name.removesuffix(trace_suffix)
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

    sidecars = {
        sidecar: client.read_file(
            sidecar, CRASH_MARKER.size if sidecar.endswith(".crash") else MAX_METRICS_BYTES
        )
        for sidecar in sidecar_names
    }
    if metrics_name in sidecars:
        try:
            parse_metrics(sidecars[metrics_name], name)
        except ValueError as error:
            raise PullTraceError(str(error)) from error
    classification = classify_artifacts({name: b"", **sidecars})[name]
    is_text = trace_suffix == TEXT_TRACE_SUFFIX
    is_compressed_binary = trace_suffix == BINARY_TRACE_SUFFIX
    # Compressed-only avoids publishing converted text, not binary protocol validation. In
    # particular, conversion enforces the adjacent-sidecar generation and v3 terminal contract for
    # QTRB 1.2 before any requested source or sidecar can become visible.
    needs_conversion = not compressed_only or not is_text
    if needs_conversion and (is_text or is_compressed_binary) and not lz4:
        raise PullTraceError(
            "host lz4 CLI is required for decompression; install the 'lz4' command"
        )

    try:
        with tempfile.TemporaryDirectory(
                prefix=".pull-trace-", dir=output_directory) as staging_name:
            staging = Path(staging_name)
            staged_source = staging / name
            try:
                _pull_named(client, getattr(client, "package", "com.example.app"), name, staging,
                            getattr(client, "timeout", 120.0))
            except Exception as error:
                raise PullTraceError(str(error)) from error
            staged_sidecars = []
            for sidecar_name, data in sidecars.items():
                staged_sidecar = staging / sidecar_name
                with staged_sidecar.open("wb") as output:
                    output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
                staged_sidecars.append(staged_sidecar)

            staged_text: Path | None = None
            status = classification.status
            exit_code = EXIT_OK
            if not is_text and needs_conversion:
                binary_partial = (
                    is_compressed_binary
                    and scan_lz4_file(staged_source).truncated
                    and classification.crash_marker is not None
                )
                staged_text = staging / (
                    partial_path.name if binary_partial else normal_path.name
                )
                try:
                    stats = convert_binary_file(
                        staged_source,
                        staged_text,
                        lz4=lz4 if is_compressed_binary else None,
                        crash_marked=classification.crash_marker is not None,
                        force=False,
                    )
                except BinaryTraceError as error:
                    raise PullTraceError(str(error)) from error
                if stats.partial:
                    status = classification.status
                    exit_code = EXIT_PARTIAL
                else:
                    status = "stopped" if stats.termination == "stopped" else "complete"
            elif is_text and needs_conversion:
                if decoder is None:
                    decoder = decode_lz4_file
                staged_text = staging / normal_path.name
                truncated = decoder(staged_source, staged_text, lz4)
                if truncated:
                    if classification.crash_marker is None:
                        raise PullTraceError(
                            "truncated LZ4 stream has no valid crash marker; no partial text was published"
                        )
                    partial_staged_text = staging / partial_path.name
                    staged_text.replace(partial_staged_text)
                    staged_text = partial_staged_text
                    status = classification.status
                    exit_code = EXIT_PARTIAL

            pairs = [
                (staged_source, compressed_path),
                *zip(staged_sidecars, (output_directory / item for item in sidecar_names), strict=True),
            ]
            outputs = [compressed_path, *(output_directory / item for item in sidecar_names)]
            if not compressed_only and staged_text is not None:
                destination = partial_path if exit_code == EXIT_PARTIAL else normal_path
                pairs.append((staged_text, destination))
                outputs.append(destination)
            try:
                publish_flight_file_set(pairs, force)
            except (FlightTraceError, FileExistsError) as error:
                raise PullTraceError(str(error)) from error
            return PullResult(name, status, tuple(outputs), exit_code=exit_code)
    except OSError as error:
        raise PullTraceError(f"trace artifact staging failed: {error}") from error


def select_trace_name(names: Iterable[str], requested: str | None = None) -> str:
    """Select an explicit trace or the newest compressed trace from an ordered listing."""
    ordered = list(names)
    if requested is not None:
        _validate_artifact_name(requested)
        if not requested.endswith(TRACE_SUFFIXES):
            raise PullTraceError(f"not a trace artifact: {requested}")
        if requested not in ordered:
            raise PullTraceError(f"remote trace does not exist: {requested}")
        return requested
    for name in ordered:
        if name.endswith(TRACE_SUFFIXES):
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
    parser.add_argument(
        "--name", help="specific .flight.bin, .trace.txt.lz4, .trace.bin.lz4, or .trace.bin artifact"
    )
    parser.add_argument(
        "--compressed-only",
        action="store_true",
        help=(
            "suppress converted text; QTRB .trace.bin.lz4 still requires host lz4 for "
            "validation, while legacy .trace.txt.lz4 and .flight.bin may be pulled unchanged"
        ),
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
        is_binary_lz4 = selected.endswith(BINARY_TRACE_SUFFIX)
        is_text_lz4 = selected.endswith(TEXT_TRACE_SUFFIX)
        requires_lz4 = is_binary_lz4 or (is_text_lz4 and not args.compressed_only)
        lz4 = lz4_finder("lz4") if requires_lz4 else None
        if is_binary_lz4 and lz4 is None:
            raise PullTraceError(
                "host lz4 CLI is required to validate QTRB .trace.bin.lz4 artifacts, including "
                "--compressed-only; install the 'lz4' command"
            )
        if is_text_lz4 and not args.compressed_only and lz4 is None:
            raise PullTraceError(
                "host lz4 CLI is required to decode legacy .trace.txt.lz4 artifacts; install the "
                "'lz4' command or use --compressed-only to pull it unchanged"
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
