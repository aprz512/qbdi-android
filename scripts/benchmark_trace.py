#!/usr/bin/env python3
"""Run the deterministic benchmark scene and summarize trace metrics."""

from __future__ import annotations

import argparse
import hashlib
from importlib.resources import files
import json
import os
import re
import statistics
import subprocess
import sys
import time
import tempfile
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable

try:
    from scripts.lz4_frames import PullTraceError, decode_lz4_file
    from scripts.trace_binary import BinaryTraceError
    from scripts.trace_convert import convert_binary_file
except ModuleNotFoundError:  # Support direct execution as scripts/benchmark_trace.py.
    from lz4_frames import PullTraceError, decode_lz4_file  # type: ignore[no-redef]
    from trace_binary import BinaryTraceError  # type: ignore[no-redef]
    from trace_convert import convert_binary_file  # type: ignore[no-redef]


TRACE_FOOTER = re.compile(
    rb"^TRACE_END status=ok ret=(0x[0-9a-fA-F]+) elapsed_ms=(\d+) "
    rb"(?:bytes=\d+|instructions=\d+ raw_bytes=\d+ cache_hit_rate=\d+\.\d{6} "
    rb"buffer_swaps=\d+ producer_waits=\d+ producer_wait_ns=\d+)\s*$",
    re.MULTILINE,
)
TRACE_SEQUENCE = re.compile(rb"^(\d+)\s", re.MULTILINE)
TRACE_DIRECTORY = "files/qbdi-traces"
ARTIFACT_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
TEXT_TRACE_SUFFIX = ".trace.txt.lz4"
BINARY_TRACE_SUFFIX = ".trace.bin.lz4"
BINARY_RAW_SUFFIX = ".trace.bin"
TRACE_SUFFIXES = (TEXT_TRACE_SUFFIX, BINARY_TRACE_SUFFIX, BINARY_RAW_SUFFIX)
COMMON_INTEGER_FIELDS = (
    "instructions",
    "elapsed_ms",
    "compressed_bytes",
    "cache_hits",
    "cache_misses",
    "cache_collisions",
    "buffer_swaps",
    "producer_waits",
    "producer_wait_ns",
    "effective_buffer_bytes",
)
COMMON_RATE_FIELDS = (
    "instructions_per_second",
    "disk_bytes_per_second",
    "compression_ratio",
    "cache_hit_rate",
)
V1_INTEGER_FIELDS = (*COMMON_INTEGER_FIELDS[:2], "raw_bytes", *COMMON_INTEGER_FIELDS[2:])
V2_INTEGER_FIELDS = (*COMMON_INTEGER_FIELDS[:2], "encoded_bytes", *COMMON_INTEGER_FIELDS[2:])
V1_RATE_FIELDS = (*COMMON_RATE_FIELDS[:1], "raw_bytes_per_second", *COMMON_RATE_FIELDS[1:])
V2_RATE_FIELDS = (*COMMON_RATE_FIELDS[:1], "encoded_bytes_per_second", *COMMON_RATE_FIELDS[1:])
# Compatibility aliases for existing v1 callers.
OPTIMIZED_INTEGER_FIELDS = V1_INTEGER_FIELDS
OPTIMIZED_RATE_FIELDS = V1_RATE_FIELDS
UINT64_MAX = (1 << 64) - 1
MAX_METRICS_BYTES = 64 * 1024
PROFILE_RATE_TARGETS = {
    "fast": Decimal(1_000_000),
    "balanced": Decimal(800_000),
    "full": Decimal(500_000),
}


def parse_legacy_trace(trace: bytes, file_bytes: int) -> dict[str, int | str]:
    """Extract metrics from one complete, uncompressed legacy text trace."""
    footer = TRACE_FOOTER.search(trace)
    if footer is None:
        raise ValueError("trace has no successful TRACE_END footer")

    sequence_numbers = [int(value) for value in TRACE_SEQUENCE.findall(trace)]
    if not sequence_numbers:
        raise ValueError("trace has no instruction sequence numbers")

    return {
        "instructions": max(sequence_numbers),
        "elapsed_ms": int(footer.group(2)),
        "raw_bytes": file_bytes,
        "return": footer.group(1).decode("ascii").lower(),
    }


def ensure_stable_return(returns: Iterable[str]) -> str:
    values = list(returns)
    if not values:
        raise ValueError("no benchmark return values")
    if len(set(values)) != 1:
        raise ValueError("benchmark return values differ: " + ", ".join(values))
    return values[0]


def select_newest_benchmark_trace(names: Iterable[str]) -> str:
    for name in names:
        if name.endswith(".trace.txt") and "_benchmark_" in name:
            return name
    raise ValueError("no uncompressed benchmark trace found")


def select_newest_optimized_metrics(names: Iterable[str]) -> str:
    ordered = list(names)
    available = set(ordered)
    for name in ordered:
        if (name.endswith(tuple(suffix + ".metrics" for suffix in TRACE_SUFFIXES))
                and "_benchmark" in name and name.removesuffix(".metrics") in available):
            return name
    raise ValueError("no complete benchmark trace+metrics pair found")


def select_exact_new_optimized_metrics(names: Iterable[str]) -> str:
    """Require one run to publish only one trace and its matching metrics sidecar."""
    new_names = list(names)
    selected = select_newest_optimized_metrics(new_names)
    artifact = selected.removesuffix(".metrics")
    trace_outputs = {
        name for name in new_names
        if name.endswith(TRACE_SUFFIXES)
        or name.endswith(tuple(suffix + ending for suffix in TRACE_SUFFIXES
                               for ending in (".metrics", ".crash")))
    }
    expected = {artifact, selected}
    if trace_outputs != expected:
        extras = sorted(trace_outputs - expected)
        missing = sorted(expected - trace_outputs)
        raise ValueError(
            "new benchmark run did not publish exactly one paired trace+metrics artifact"
            + (f"; extras={extras}" if extras else "")
            + (f"; missing={missing}" if missing else "")
        )
    return selected


def _expected_optimized_rates(metrics: dict[str, int | Decimal | str]) -> dict[str, Decimal]:
    elapsed_ms = int(metrics["elapsed_ms"])
    byte_field = "encoded_bytes" if int(metrics.get("metrics_version", 1)) == 2 else "raw_bytes"
    rate_field = byte_field + "_per_second"
    encoded_bytes = int(metrics[byte_field])
    compressed_bytes = int(metrics["compressed_bytes"])
    cache_hits = int(metrics["cache_hits"])
    cache_lookups = cache_hits + int(metrics["cache_misses"])
    return {
        "instructions_per_second": (
            Decimal(int(metrics["instructions"]) * 1000) / elapsed_ms
            if elapsed_ms else Decimal(0)
        ),
        rate_field: (
            Decimal(encoded_bytes * 1000) / elapsed_ms if elapsed_ms else Decimal(0)
        ),
        "disk_bytes_per_second": (
            Decimal(compressed_bytes * 1000) / elapsed_ms if elapsed_ms else Decimal(0)
        ),
        "compression_ratio": (
            Decimal(compressed_bytes) / encoded_bytes if encoded_bytes else Decimal(0)
        ),
        "cache_hit_rate": Decimal(cache_hits) / cache_lookups if cache_lookups else Decimal(0),
    }


def parse_metrics(sidecar: str | bytes) -> dict[str, int | Decimal | str]:
    """Parse one completed optimized sidecar and validate its derived metrics."""
    if isinstance(sidecar, bytes):
        try:
            sidecar = sidecar.decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("metrics sidecar is not ASCII") from error
    values: dict[str, str] = {}
    for line in sidecar.splitlines():
        if not line or "=" not in line:
            raise ValueError("malformed metrics line")
        key, value = line.split("=", 1)
        if not key or not value or key in values:
            raise ValueError(f"invalid or duplicate metrics key: {key}")
        values[key] = value

    version_text = values.get("metrics_version")
    if version_text is None:
        version = 1
        integer_fields = V1_INTEGER_FIELDS
        rate_fields = V1_RATE_FIELDS
        forbidden = ("encoded_bytes", "encoded_bytes_per_second")
    elif version_text == "2":
        version = 2
        integer_fields = V2_INTEGER_FIELDS
        rate_fields = V2_RATE_FIELDS
        forbidden = ("raw_bytes", "raw_bytes_per_second")
    else:
        raise ValueError("unsupported metrics_version")
    mixed = [key for key in forbidden if key in values]
    if mixed:
        raise ValueError(f"metrics contract contains forbidden {mixed[0]}")
    required = {"profile", "return", *integer_fields, *rate_fields}
    if version == 2:
        required.add("metrics_version")
    missing = sorted(required - values.keys())
    if missing:
        raise ValueError("missing metrics fields: " + ", ".join(missing))
    unknown = sorted(values.keys() - required)
    if unknown:
        raise ValueError("unknown metrics fields: " + ", ".join(unknown))
    if values["profile"] not in ("fast", "balanced", "full"):
        raise ValueError("invalid profile metric")
    if re.fullmatch(r"0x[0-9a-fA-F]+", values["return"]) is None:
        raise ValueError("invalid return metric")
    if int(values["return"], 16) > UINT64_MAX:
        raise ValueError("return metric exceeds uint64")

    parsed: dict[str, int | Decimal | str] = {
        "profile": values["profile"],
        "return": values["return"].lower(),
        "metrics_version": version,
    }
    try:
        for key in integer_fields:
            if re.fullmatch(r"\d+", values[key]) is None:
                raise ValueError(f"{key} is not an unsigned integer")
            parsed[key] = int(values[key])
            if int(parsed[key]) < 0:
                raise ValueError(f"{key} must not be negative")
            if int(parsed[key]) > UINT64_MAX:
                raise ValueError(f"{key} exceeds uint64")
        for key in rate_fields:
            if re.fullmatch(r"\d+\.\d{6}", values[key]) is None:
                raise ValueError(f"{key} is not fixed-six decimal")
            parsed[key] = Decimal(values[key])
            if not Decimal(parsed[key]).is_finite() or Decimal(parsed[key]) < 0:
                raise ValueError(f"{key} must be finite and non-negative")
    except (ValueError, InvalidOperation) as error:
        raise ValueError(f"invalid metrics value: {error}") from error

    expected_rates = _expected_optimized_rates(parsed)
    for key, expected in expected_rates.items():
        if abs(Decimal(values[key]) - expected) >= Decimal("0.000001"):
            raise ValueError(f"{key} is inconsistent with raw counters")
    return parsed


def compare_to_baseline(
    current: dict[str, int | Decimal | str], baseline: dict[str, int | Decimal | str]
) -> dict[str, Decimal]:
    current_ms = Decimal(current["elapsed_ms"])
    baseline_ms = Decimal(baseline["elapsed_ms"])
    if current_ms <= 0 or baseline_ms <= 0:
        raise ValueError("elapsed_ms must be positive for comparison")
    return {"speedup": baseline_ms / current_ms}


def compare_to_profile_baseline(
    current: dict[str, int | Decimal | str],
    baseline: dict[str, int | str],
) -> dict[str, Decimal | bool | int]:
    profile = str(current.get("profile", ""))
    if profile not in PROFILE_RATE_TARGETS or profile != str(baseline.get("profile", "")):
        raise ValueError("current and baseline profiles differ")
    for key in ("instructions", "return"):
        if str(current.get(key, "")).lower() != str(baseline.get(key, "")).lower():
            raise ValueError(f"format-2 oracle mismatch for {key}")
    rate = Decimal(current["instructions_per_second"])
    compressed = int(current["compressed_bytes"])
    baseline_compressed = int(baseline["compressed_bytes"])
    return {
        "target_instructions_per_second": PROFILE_RATE_TARGETS[profile],
        "meets_rate_target": rate >= PROFILE_RATE_TARGETS[profile],
        "baseline_compressed_bytes": baseline_compressed,
        "meets_size_target": compressed <= baseline_compressed,
    }


def require_balanced_comparison(profile: str) -> None:
    if profile != "balanced":
        raise ValueError("--compare requires --profile balanced")


def parse_baseline_report(document: str) -> dict[str, int | str]:
    def field(label: str) -> str:
        match = re.search(rf"^\| {re.escape(label)} \|\s*(.*?)\s*\|$", document, re.MULTILINE)
        if match is None:
            raise ValueError(f"baseline report has no {label}")
        return match.group(1)

    model_field = field("Device model")
    device_match = re.search(r"`([^`]+)`", model_field)
    median_match = re.search(r"^\| Median \|\s*(\d+)\s*\|", document, re.MULTILINE)
    if device_match is None or median_match is None:
        raise ValueError("baseline report has no device codename or Median elapsed time")
    model = model_field.split(" (`", 1)[0].strip()
    return {
        "model": model,
        "device": device_match.group(1),
        "android": field("Android version").strip("`"),
        "abi": field("ABI").strip("`"),
        "build_type": field("Build type").strip("`"),
        "elapsed_ms": int(median_match.group(1)),
    }


FORMAT_TWO_BASELINE_COLUMNS = (
    "Profile",
    "Measured elapsed values (ms)",
    "Median elapsed ms",
    "Artifact",
    "Compressed bytes",
    "Decoded bytes",
    "Instructions",
    "Return",
    "Decoded event count",
    "First sequence",
    "Last sequence",
    "Footer",
    "Artifact SHA-256",
)
FORMAT_TWO_INTEGER_COLUMNS = {
    "Median elapsed ms": "elapsed_ms",
    "Compressed bytes": "compressed_bytes",
    "Decoded bytes": "decoded_bytes",
    "Instructions": "instructions",
    "Decoded event count": "decoded_event_count",
}
FORMAT_TWO_PROFILES = ("fast", "balanced", "full")


def _baseline_markdown_cells(line: str) -> list[str]:
    if not line.startswith("|") or not line.rstrip().endswith("|"):
        raise ValueError("invalid baseline table row")
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _format_two_baseline_rows(document: str) -> list[dict[str, int | str]]:
    heading = "## Current format-2 artifact baselines"
    start = document.find(heading)
    if start < 0:
        raise ValueError("baseline document has no Current format-2 artifact baselines table")
    table_lines: list[str] = []
    for line in document[start + len(heading):].splitlines():
        if line.startswith("#"):
            break
        if line.startswith("|"):
            table_lines.append(line)
    if len(table_lines) < 3:
        raise ValueError("baseline table has no profile rows")

    columns = _baseline_markdown_cells(table_lines[0])
    if tuple(columns) != FORMAT_TWO_BASELINE_COLUMNS:
        raise ValueError("baseline table has missing columns")
    separator = _baseline_markdown_cells(table_lines[1])
    if len(separator) != len(columns) or any(not re.fullmatch(r":?-{3,}:?", cell) for cell in separator):
        raise ValueError("baseline table has invalid column separator")

    rows: list[dict[str, int | str]] = []
    seen_profiles: set[str] = set()
    for line in table_lines[2:]:
        cells = _baseline_markdown_cells(line)
        if len(cells) != len(columns):
            raise ValueError("baseline table row has missing columns")
        values = dict(zip(columns, cells, strict=True))
        profile = values["Profile"]
        if profile not in FORMAT_TWO_PROFILES:
            raise ValueError(f"baseline table has unknown profile: {profile}")
        if profile in seen_profiles:
            raise ValueError(f"baseline table has duplicate profile: {profile}")
        seen_profiles.add(profile)

        elapsed_values: list[int] = []
        for value in values["Measured elapsed values (ms)"].split(","):
            value = value.strip()
            if re.fullmatch(r"\d+", value) is None:
                raise ValueError("baseline table has invalid elapsed value")
            elapsed_values.append(int(value))
        if len(elapsed_values) != 5:
            raise ValueError("baseline table must have exactly five elapsed values")

        row: dict[str, int | str] = {
            "profile": profile,
            "elapsed_values_ms": ", ".join(str(value) for value in elapsed_values),
            "artifact": values["Artifact"],
            "return": values["Return"].lower(),
            "first_sequence": values["First sequence"],
            "last_sequence": values["Last sequence"],
            "footer": values["Footer"],
            "artifact_sha256": values["Artifact SHA-256"],
        }
        for column, key in FORMAT_TWO_INTEGER_COLUMNS.items():
            value = values[column]
            if re.fullmatch(r"\d+", value) is None:
                raise ValueError(f"baseline table has invalid integer for {column}")
            row[key] = int(value)
        rows.append(row)
    return rows


def parse_baseline_document(document: str) -> dict[str, str]:
    """Extract the format-2 baseline device identity from its Markdown document."""
    identity: dict[str, str] = {}
    for label, key in (
        ("Device model", "device_model"),
        ("Device product", "device_product"),
        ("Android version", "android_version"),
        ("ABI", "abi"),
        ("Build type", "build_type"),
    ):
        match = re.search(rf"^\| {re.escape(label)} \|\s*(.*?)\s*\|$", document, re.MULTILINE)
        if match is None or not match.group(1).strip():
            raise ValueError(f"baseline document has no {label}")
        identity[key] = match.group(1).strip().strip("`")
    return identity


def parse_profile_baseline(document: str, profile: str) -> dict[str, int | str]:
    """Return one validated profile row from the current format-2 Markdown baseline."""
    if profile not in FORMAT_TWO_PROFILES:
        raise ValueError(f"unknown profile: {profile}")
    rows = _format_two_baseline_rows(document)
    for row in rows:
        if row["profile"] == profile:
            return row
    raise ValueError(f"baseline table has no {profile} profile")


def ensure_same_device(
    baseline: dict[str, int | str], current: dict[str, str]
) -> None:
    keys = ("model", "device", "android", "abi", "build_type")
    mismatches = [
        f"{key}: baseline={baseline.get(key)!r} current={current.get(key)!r}"
        for key in keys
        if str(baseline.get(key, "")) != current.get(key, "")
    ]
    if mismatches:
        raise ValueError("baseline device mismatch: " + "; ".join(mismatches))


def ensure_same_format_two_device(baseline: dict[str, str], current: dict[str, str]) -> None:
    mapping = {
        "device_model": "model",
        "device_product": "device",
        "android_version": "android",
        "abi": "abi",
        "build_type": "build_type",
    }
    mismatches = [
        f"{baseline_key}: baseline={baseline.get(baseline_key)!r} "
        f"current={current.get(current_key)!r}"
        for baseline_key, current_key in mapping.items()
        if baseline.get(baseline_key, "") != current.get(current_key, "")
    ]
    if mismatches:
        raise ValueError("baseline device mismatch: " + "; ".join(mismatches))


def classify_run_as_build_type(returncode: int, stderr: str) -> str:
    if returncode == 0:
        return "Debug"
    if "not debuggable" in stderr:
        return "Release"
    raise ValueError(f"cannot determine build type from run-as: {stderr.strip()}")


def ensure_artifact_return(
    returned: str, metrics: dict[str, int | Decimal | str], artifact: str
) -> None:
    artifact_return = str(metrics["return"])
    if returned.lower() != artifact_return.lower():
        raise RuntimeError(
            f"agent returned {returned}, optimized artifact {artifact} ended with {artifact_return}"
        )


def ensure_metrics_container(
    metrics: dict[str, int | Decimal | str], artifact: str
) -> None:
    version = int(metrics.get("metrics_version", 1))
    if version == 1 and not artifact.endswith(TEXT_TRACE_SUFFIX):
        raise RuntimeError("metrics v1 must accompany a .trace.txt.lz4 artifact")
    if version == 2 and not artifact.endswith((BINARY_TRACE_SUFFIX, BINARY_RAW_SUFFIX)):
        raise RuntimeError("metrics v2 must accompany a binary trace artifact")


def verify_setup_failure_smoke(
    returned: str, expected_return: str, new_artifacts: Iterable[str]
) -> str:
    actual = returned.lower()
    expected = expected_return.lower()
    if actual != expected:
        raise RuntimeError(
            f"setup-failure fallback returned {actual}, expected untraced {expected}"
        )
    unexpected = list(new_artifacts)
    if unexpected:
        raise RuntimeError(
            "setup-failure fallback published artifacts: " + ", ".join(unexpected)
        )
    return actual


def configure_agent_source(
    source: str, profile: str, legacy: bool = False, test_buffer_bytes: int | None = None,
    test_fail_setup: bool = False,
) -> str:
    if profile not in ("fast", "balanced", "full"):
        raise ValueError(f"invalid benchmark profile: {profile}")
    if "__QTRACE_PROFILE__" not in source:
        raise ValueError("benchmark agent has no profile placeholder")
    if test_buffer_bytes not in (None, 4096):
        raise ValueError("test buffer must be exactly 4096 bytes")
    test_options: list[str] = []
    if test_buffer_bytes is not None:
        test_options.append(f"test_buffer_bytes={test_buffer_bytes}")
    if test_fail_setup:
        test_options.append("test_fail_setup=1")
    if test_options and source.count("__QTRACE_TEST_CONFIG__") != 1:
        raise ValueError(
            "benchmark agent must contain __QTRACE_TEST_CONFIG__ exactly once when test options are requested"
        )
    test_config = "" if not test_options else ";" + ";".join(test_options)
    return source.replace("__QTRACE_PROFILE__", profile).replace(
        "__QTRACE_COMPRESSION__", "0" if legacy else "1"
    ).replace(
        "__QTRACE_TEST_CONFIG__", test_config,
    )


def inject_java_bridge(bridge_source: str, agent_source: str) -> str:
    """Make the Frida Java bridge available to a benchmark agent created by Python."""
    return (
        bridge_source
        + "\nObject.defineProperty(globalThis, 'Java', { value: bridge });\n"
        + agent_source
    )


def java_bridge_source() -> str:
    try:
        return files("frida_tools").joinpath("bridges", "java.js").read_text(encoding="utf-8")
    except (ModuleNotFoundError, FileNotFoundError) as error:
        raise RuntimeError(
            "Frida Java bridge is required; install the matching frida-tools package"
        ) from error


def fast_cost_diagnosis(
    metrics: dict[str, int | Decimal | str],
) -> dict[str, Decimal | str]:
    elapsed_ns = int(metrics["elapsed_ms"]) * 1_000_000
    wait_fraction = (
        Decimal(int(metrics["producer_wait_ns"])) / elapsed_ns if elapsed_ns else Decimal(0)
    )
    lookups = int(metrics["cache_hits"]) + int(metrics["cache_misses"])
    miss_fraction = (
        Decimal(int(metrics["cache_misses"])) / lookups if lookups else Decimal(0)
    )
    dominant = "producer_wait_time" if wait_fraction > Decimal("0.5") else "undetermined"
    byte_rate = (
        "encoded_bytes_per_second"
        if int(metrics.get("metrics_version", 1)) == 2
        else "raw_bytes_per_second"
    )
    return {
        "dominant_cost": dominant,
        "evidence": (
            "producer wait exceeds half of elapsed time"
            if dominant == "producer_wait_time"
            else "cache misses and encoding throughput are indicators with no comparable time cost"
        ),
        "producer_wait_fraction": wait_fraction,
        "cache_miss_fraction": miss_fraction,
        byte_rate: Decimal(metrics[byte_rate]),
    }


def frida_endpoint(port: int) -> str:
    return f"127.0.0.1:{port}"


def throughput_metrics(run: dict[str, int | str]) -> dict[str, float]:
    elapsed_ms = int(run["elapsed_ms"])
    if elapsed_ms <= 0:
        raise ValueError("elapsed_ms must be positive for throughput")
    return {
        "instructions_per_second": int(run["instructions"]) * 1000.0 / elapsed_ms,
        "raw_mib_per_second": int(run["raw_bytes"]) * 1000.0 / elapsed_ms / (1024 * 1024),
    }


def _integer_median(values: Iterable[int]) -> int | Decimal:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("no integer values for median")
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return Decimal(ordered[middle - 1] + ordered[middle]) / 2


def median_report(
    runs: list[dict[str, int | Decimal | str]],
) -> dict[str, Decimal | float | int | str]:
    """Return medians for raw metrics and throughput derived from every measured run."""
    if not runs:
        raise ValueError("no benchmark runs")

    report: dict[str, Decimal | float | int | str] = {}
    if "profile" in runs[0]:
        profiles = {str(run.get("profile", "")) for run in runs}
        if len(profiles) != 1:
            raise ValueError("benchmark profiles differ: " + ", ".join(sorted(profiles)))
        report["profile"] = profiles.pop()
        versions = {int(run.get("metrics_version", 1)) for run in runs}
        if len(versions) != 1:
            raise ValueError("metrics versions differ")
        version = versions.pop()
        report["metrics_version"] = version
        integer_fields = V2_INTEGER_FIELDS if version == 2 else V1_INTEGER_FIELDS
        rate_fields = V2_RATE_FIELDS if version == 2 else V1_RATE_FIELDS
        for key in integer_fields:
            if any(key not in run for run in runs):
                raise ValueError(f"optimized run is missing {key}")
            if key == "instructions" and len({int(run[key]) for run in runs}) != 1:
                raise ValueError("benchmark instruction counts differ")
            report[key] = _integer_median(int(run[key]) for run in runs)
        for key in rate_fields:
            if any(key not in run for run in runs):
                raise ValueError(f"optimized run is missing {key}")
            report[key] = statistics.median(Decimal(run[key]) for run in runs)
        if all("converted_text_bytes" in run for run in runs):
            report["converted_text_bytes"] = _integer_median(
                int(run["converted_text_bytes"]) for run in runs
            )
        return report
    for key in ("instructions", "elapsed_ms", "raw_bytes"):
        values = [int(run[key]) for run in runs if key in run]
        if values:
            report[key] = _integer_median(values)

    throughput_runs = [
        run for run in runs
        if "instructions" in run and "raw_bytes" in run and int(run.get("elapsed_ms", 0)) > 0
    ]
    if throughput_runs:
        throughput_values = [throughput_metrics(run) for run in throughput_runs]
        report["instructions_per_second"] = statistics.median(
            metrics["instructions_per_second"] for metrics in throughput_values
        )
        report["raw_mib_per_second"] = statistics.median(
            metrics["raw_mib_per_second"] for metrics in throughput_values
        )
    return report


def adb(
    args: argparse.Namespace,
    *command: str,
    text: bool = False,
    stdout: Any = subprocess.PIPE,
) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        [args.adb, "-s", args.device, *command],
        check=True,
        stdout=stdout,
        stderr=subprocess.PIPE,
        text=text,
        timeout=getattr(args, "adb_timeout", 30.0),
    )


def is_missing_trace_directory(error: subprocess.CalledProcessError) -> bool:
    stderr = (
        error.stderr.decode("utf-8", errors="replace")
        if isinstance(error.stderr, bytes)
        else str(error.stderr)
    )
    return TRACE_DIRECTORY in stderr and "No such file or directory" in stderr


def trace_names(args: argparse.Namespace) -> list[str]:
    try:
        listing = adb(
            args, "shell", "run-as", args.package, "ls", "-1t", TRACE_DIRECTORY, text=True
        )
    except subprocess.CalledProcessError as error:
        if is_missing_trace_directory(error):
            return []
        raise
    if len(listing.stdout.encode("utf-8")) > 1024 * 1024:
        raise RuntimeError("artifact listing exceeds size limit")
    names = listing.stdout.splitlines()
    invalid = next(
        (name for name in names if ARTIFACT_NAME.fullmatch(name) is None or name in (".", "..")),
        None,
    )
    if invalid is not None:
        raise RuntimeError(f"unsafe artifact name in device listing: {invalid!r}")
    return names


def live_device_identity(args: argparse.Namespace) -> dict[str, str]:
    def prop(name: str) -> str:
        return adb(args, "shell", "getprop", name, text=True).stdout.strip()

    try:
        adb(args, "shell", "run-as", args.package, "id", text=True)
        build_type = classify_run_as_build_type(0, "")
    except subprocess.CalledProcessError as error:
        stderr = error.stderr if isinstance(error.stderr, str) else error.stderr.decode(
            "utf-8", errors="replace"
        )
        build_type = classify_run_as_build_type(error.returncode, stderr)

    return {
        "model": prop("ro.product.model"),
        "device": prop("ro.product.device"),
        "android": prop("ro.build.version.release"),
        "abi": prop("ro.product.cpu.abi"),
        "build_type": build_type,
    }


def newest_legacy_trace(
    args: argparse.Namespace, previous_names: set[str]
) -> tuple[str, bytes]:
    name = select_newest_benchmark_trace(
        candidate for candidate in trace_names(args) if candidate not in previous_names
    )
    trace = adb(args, "exec-out", "run-as", args.package, "cat", f"{TRACE_DIRECTORY}/{name}").stdout
    return name, trace


def newest_optimized_metrics(
    args: argparse.Namespace, previous_names: set[str]
) -> tuple[str, bytes]:
    name = select_exact_new_optimized_metrics(
        candidate for candidate in trace_names(args) if candidate not in previous_names
    )
    metrics = adb(
        args, "exec-out", "run-as", args.package, "head", "-c",
        str(MAX_METRICS_BYTES + 1), f"{TRACE_DIRECTORY}/{name}",
    ).stdout
    if len(metrics) > MAX_METRICS_BYTES:
        raise RuntimeError(f"metrics sidecar exceeds size limit: {name}")
    return name, metrics


def _publish_remote_file(args: argparse.Namespace, name: str, destination: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".benchmark-trace-", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            adb(
                args, "exec-out", "run-as", args.package, "cat",
                f"{TRACE_DIRECTORY}/{name}", stdout=output,
            )
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            raise RuntimeError(f"benchmark output already exists: {destination}") from error
        temporary.unlink()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _write_sidecar_atomic(data: bytes, destination: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".benchmark-metrics-", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            raise RuntimeError(f"benchmark output already exists: {destination}") from error
        temporary.unlink()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_format_two_file(
    path: Path, metrics: dict[str, int | Decimal | str]
) -> None:
    last_sequence = 0
    footer_return: str | None = None
    footer_elapsed: int | None = None
    with path.open("rb") as stream:
        for line_number, line in enumerate(stream, 1):
            if len(line) > 1024 * 1024:
                raise RuntimeError(f"format-2 line {line_number} exceeds size limit")
            sequence = re.match(rb"^(\d+)\s", line)
            if sequence is not None:
                last_sequence = int(sequence.group(1))
            footer = TRACE_FOOTER.fullmatch(line.rstrip(b"\r\n"))
            if footer is not None:
                footer_return = footer.group(1).decode("ascii").lower()
                footer_elapsed = int(footer.group(2))
    expected = {
        "return": str(metrics["return"]),
        "elapsed_ms": int(metrics["elapsed_ms"]),
        "instructions": int(metrics["instructions"]),
        "raw_bytes": int(metrics["raw_bytes"]),
    }
    actual = {
        "return": footer_return,
        "elapsed_ms": footer_elapsed,
        "instructions": last_sequence,
        "raw_bytes": path.stat().st_size,
    }
    for key, value in expected.items():
        if actual[key] != value:
            raise RuntimeError(
                f"format-2 footer/sidecar mismatch for {key}: expected {value}, got {actual[key]}"
            )


def collect_and_validate_optimized_artifact(
    args: argparse.Namespace,
    artifact_name: str,
    sidecar: bytes,
    metrics: dict[str, int | Decimal | str],
) -> dict[str, int | Decimal | str]:
    """Collect one exact pair and validate its container, footer, and sidecar identity."""
    configured_output = getattr(args, "artifact_output", None)
    output_root: Path | None = None
    if configured_output:
        output_root = Path(configured_output)
        output_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".benchmark-stage-", dir=output_root
    ) as staging_directory:
        root = Path(staging_directory)
        artifact = root / artifact_name
        metrics_path = root / (artifact_name + ".metrics")
        _publish_remote_file(args, artifact_name, artifact)
        _write_sidecar_atomic(sidecar, metrics_path)
        actual_size = artifact.stat().st_size
        if actual_size != int(metrics["compressed_bytes"]):
            raise RuntimeError(
                f"artifact size mismatch: metrics={metrics['compressed_bytes']} actual={actual_size}"
            )

        result = dict(metrics)
        result["artifact_sha256"] = _sha256_file(artifact)
        if int(metrics["metrics_version"]) == 2:
            suffix = (
                BINARY_TRACE_SUFFIX
                if artifact_name.endswith(BINARY_TRACE_SUFFIX) else BINARY_RAW_SUFFIX
            )
            text = root / (artifact_name.removesuffix(suffix) + ".trace.txt")
            try:
                stats = convert_binary_file(
                    artifact,
                    text,
                    lz4=getattr(args, "lz4", "lz4")
                    if artifact_name.endswith(BINARY_TRACE_SUFFIX) else None,
                    crash_marked=False,
                )
            except (BinaryTraceError, PullTraceError) as error:
                raise RuntimeError(f"binary artifact validation failed: {error}") from error
            result["converted_text_bytes"] = stats.converted_text_bytes
        else:
            decoded = root / (artifact_name.removesuffix(TEXT_TRACE_SUFFIX) + ".trace.txt")
            try:
                truncated = decode_lz4_file(
                    artifact, decoded, getattr(args, "lz4", "lz4")
                )
            except PullTraceError as error:
                raise RuntimeError(f"format-2 artifact validation failed: {error}") from error
            if truncated:
                raise RuntimeError("complete format-2 metrics accompany a truncated artifact")
            _validate_format_two_file(decoded, metrics)
            result["converted_text_bytes"] = decoded.stat().st_size
        if output_root is not None:
            staged = sorted(root.iterdir())
            existing = next(
                (output_root / path.name for path in staged if (output_root / path.name).exists()),
                None,
            )
            if existing is not None:
                raise RuntimeError(f"benchmark output already exists: {existing}")
            published: list[Path] = []
            try:
                for path in staged:
                    destination = output_root / path.name
                    os.link(path, destination)
                    published.append(destination)
            except OSError:
                for destination in published:
                    destination.unlink(missing_ok=True)
                raise
        return result


def invoke_benchmark(args: argparse.Namespace) -> str:
    try:
        import frida  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("Frida Python bindings are required; install the matching 'frida' package") from error

    source = inject_java_bridge(java_bridge_source(), configure_agent_source(
        Path(args.agent).read_text(encoding="utf-8"), args.profile, args.legacy,
        args.test_buffer_bytes, args.test_fail_setup,
    ))
    messages: list[dict[str, Any]] = []

    def on_message(message: dict[str, Any], _data: Any) -> None:
        messages.append(message)

    adb(args, "shell", "am", "force-stop", args.package)
    adb(args, "forward", f"tcp:{args.frida_port}", f"tcp:{args.frida_port}")
    manager = frida.get_device_manager()
    device = manager.add_remote_device(args.frida_device or frida_endpoint(args.frida_port))
    pid: int | None = None
    session: Any | None = None
    script: Any | None = None
    result: str | None = None
    cleanup_error: BaseException | None = None
    try:
        pid = device.spawn([args.package])
        session = device.attach(pid)
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        device.resume(pid)

        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            for message in messages:
                if message.get("type") != "send":
                    continue
                payload = message.get("payload")
                if isinstance(payload, dict) and payload.get("type") == "benchmark-result":
                    result = str(payload["return"])
                    break
                if isinstance(payload, dict) and payload.get("type") == "benchmark-error":
                    raise RuntimeError(str(payload.get("error", "benchmark agent failed")))
            if result is not None:
                break
            time.sleep(0.05)
        if result is None:
            raise RuntimeError(f"benchmark agent timed out after {args.timeout:g} seconds")
        return result.lower()
    finally:
        active_exception = sys.exc_info()[0] is not None
        if script is not None:
            try:
                script.unload()
            except BaseException as error:  # cleanup must not prevent later owners releasing
                cleanup_error = cleanup_error or error
        if session is not None:
            try:
                session.detach()
            except BaseException as error:
                cleanup_error = cleanup_error or error
        if pid is not None and (result is None or cleanup_error is not None):
            try:
                device.kill(pid)
            except BaseException as error:
                cleanup_error = cleanup_error or error
        if cleanup_error is not None and not active_exception:
            raise RuntimeError(f"failed to release benchmark process: {cleanup_error}") from cleanup_error


def run_once(args: argparse.Namespace) -> dict[str, int | Decimal | str]:
    previous_names = set(trace_names(args))
    returned = invoke_benchmark(args)
    if args.legacy:
        name, trace = newest_legacy_trace(args, previous_names)
        parsed = parse_legacy_trace(trace, len(trace))
        if parsed["return"] != returned:
            raise RuntimeError(
                f"agent returned {returned}, trace {name} ended with {parsed['return']}"
            )
        parsed["trace"] = name
        return parsed

    name, sidecar = newest_optimized_metrics(args, previous_names)
    parsed = parse_metrics(sidecar)
    if parsed["profile"] != args.profile:
        raise RuntimeError(
            f"requested profile {args.profile}, metrics {name} reports {parsed['profile']}"
        )
    ensure_artifact_return(returned, parsed, name)
    artifact_name = name.removesuffix(".metrics")
    ensure_metrics_container(parsed, artifact_name)
    parsed = collect_and_validate_optimized_artifact(args, artifact_name, sidecar, parsed)
    parsed["metrics"] = name
    parsed["trace"] = artifact_name
    return parsed


def run_setup_failure_smoke(args: argparse.Namespace) -> str:
    previous_names = set(trace_names(args))
    returned = invoke_benchmark(args)
    new_artifacts = [name for name in trace_names(args) if name not in previous_names]
    return verify_setup_failure_smoke(returned, args.expected_return, new_artifacts)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", default="com.aprz.qbdiandroid")
    parser.add_argument("--device", default="192.168.50.53:5555", help="adb serial")
    parser.add_argument("--frida-device", help="override the adb-forwarded Frida server endpoint")
    parser.add_argument("--frida-port", type=int, default=27042)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--agent", default=str(Path(__file__).with_name("benchmark_trace.js")))
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--adb-timeout", type=float, default=30.0)
    parser.add_argument("--lz4", default="lz4", help="host lz4 executable")
    parser.add_argument(
        "--artifact-output",
        help="retain each validated artifact, sidecar, and converted binary text in this directory",
    )
    parser.add_argument("--profile", choices=("fast", "balanced", "full"), default="fast")
    parser.add_argument("--compare", help="checked-in baseline Markdown report")
    parser.add_argument("--legacy", action="store_true", help="require uncompressed .trace.txt files")
    parser.add_argument(
        "--test-buffer-bytes", type=int,
        help="Debug-only test buffer size; only 4096 is accepted",
    )
    parser.add_argument(
        "--test-fail-setup", action="store_true",
        help="Debug-only test hook that forces trace setup failure",
    )
    parser.add_argument(
        "--expected-return",
        help="expected native fallback return for --test-fail-setup",
    )
    return parser.parse_args()


def render_report(report: dict[str, Any]) -> str:
    def encode(value: Any) -> str:
        if isinstance(value, Decimal):
            return format(value, "f")
        raise TypeError(f"cannot serialize {type(value).__name__}")

    return json.dumps(report, indent=2, sort_keys=True, default=encode)


def main() -> int:
    args = parse_args()
    if args.runs < 1:
        raise SystemExit("--runs must be at least one")
    if args.test_fail_setup:
        if args.runs != 1:
            raise ValueError("--test-fail-setup requires --runs 1")
        if args.expected_return is None:
            raise ValueError("--test-fail-setup requires --expected-return")
        returned = run_setup_failure_smoke(args)
        print(render_report({"return": returned, "status": "native_fallback"}))
        return 0
    baseline: dict[str, int | str] | None = None
    profile_baseline: dict[str, int | str] | None = None
    if args.compare:
        baseline_document = Path(args.compare).read_text(encoding="utf-8")
        identity = live_device_identity(args)
        if "## Current format-2 artifact baselines" in baseline_document:
            profile_baseline = parse_profile_baseline(baseline_document, args.profile)
            ensure_same_format_two_device(parse_baseline_document(baseline_document), identity)
        else:
            require_balanced_comparison(args.profile)
            baseline = parse_baseline_report(baseline_document)
            ensure_same_device(baseline, identity)
    warmup = run_once(args)
    runs = [run_once(args) for _ in range(args.runs)]
    stable_return = ensure_stable_return([str(warmup["return"]), *[str(run["return"]) for run in runs]])
    report = median_report(runs)
    report["return"] = stable_return
    report["runs"] = (
        [{**run, **throughput_metrics(run)} for run in runs] if args.legacy else runs
    )
    if args.compare and baseline is not None:
        comparison = compare_to_baseline(report, baseline)
        report["comparison"] = {
            **comparison,
            "baseline": args.compare,
            "meets_balanced_5x": comparison["speedup"] >= Decimal(5),
        }
    if args.compare and profile_baseline is not None:
        report["comparison"] = {
            **compare_to_profile_baseline(report, profile_baseline),
            "baseline": args.compare,
        }
    if (not args.legacy and args.profile == "fast" and
            Decimal(report["instructions_per_second"]) < Decimal(1_000_000)):
        report["fast_target_diagnosis"] = fast_cost_diagnosis(report)
    print(render_report(report))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(1)
