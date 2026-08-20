"""Single strict parser for v1 text and v2 QTRB trace metrics sidecars."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation


COMMON_INTEGER_FIELDS = (
    "instructions", "elapsed_ms", "compressed_bytes", "cache_hits", "cache_misses",
    "cache_collisions", "buffer_swaps", "producer_waits", "producer_wait_ns",
    "effective_buffer_bytes",
)
COMMON_RATE_FIELDS = (
    "instructions_per_second", "disk_bytes_per_second", "compression_ratio",
    "cache_hit_rate",
)
V1_INTEGER_FIELDS = (*COMMON_INTEGER_FIELDS[:2], "raw_bytes", *COMMON_INTEGER_FIELDS[2:])
V2_INTEGER_FIELDS = (*COMMON_INTEGER_FIELDS[:2], "encoded_bytes", *COMMON_INTEGER_FIELDS[2:])
V1_RATE_FIELDS = (*COMMON_RATE_FIELDS[:1], "raw_bytes_per_second", *COMMON_RATE_FIELDS[1:])
V2_RATE_FIELDS = (*COMMON_RATE_FIELDS[:1], "encoded_bytes_per_second", *COMMON_RATE_FIELDS[1:])
UINT64_MAX = (1 << 64) - 1
MAX_METRICS_BYTES = 64 * 1024
TEXT_TRACE_SUFFIX = ".trace.txt.lz4"
BINARY_TRACE_SUFFIXES = (".trace.bin.lz4", ".trace.bin")


def expected_rates(metrics: dict[str, int | Decimal | str]) -> dict[str, Decimal]:
    elapsed_ms = int(metrics["elapsed_ms"])
    byte_field = "encoded_bytes" if int(metrics.get("metrics_version", 1)) == 2 else "raw_bytes"
    encoded_bytes = int(metrics[byte_field])
    compressed_bytes = int(metrics["compressed_bytes"])
    cache_hits = int(metrics["cache_hits"])
    cache_lookups = cache_hits + int(metrics["cache_misses"])
    return {
        "instructions_per_second": (
            Decimal(int(metrics["instructions"]) * 1000) / elapsed_ms
            if elapsed_ms else Decimal(0)
        ),
        byte_field + "_per_second": (
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


def parse_metrics(sidecar: str | bytes, artifact_name: str | None = None
                  ) -> dict[str, int | Decimal | str]:
    """Parse a complete sidecar, reject mixed suffix/generation, and recompute all rates."""
    if isinstance(sidecar, bytes):
        try:
            sidecar = sidecar.decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("metrics sidecar is not ASCII") from error
    try:
        encoded_sidecar = sidecar.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("metrics sidecar is not ASCII") from error
    if len(encoded_sidecar) > MAX_METRICS_BYTES:
        raise ValueError("metrics sidecar exceeds size limit")
    lines = sidecar.splitlines()
    if len(lines) > 20:
        raise ValueError("metrics sidecar exceeds field count limit")
    values: dict[str, str] = {}
    for line in lines:
        if not line or "=" not in line:
            raise ValueError("malformed metrics line")
        key, value = line.split("=", 1)
        if not key or not value:
            raise ValueError(f"invalid metrics key: {key}")
        if key in values:
            raise ValueError(f"duplicate metrics sidecar key {key!r}")
        values[key] = value

    version_text = values.get("metrics_version")
    if version_text is None:
        version, integer_fields, rate_fields = 1, V1_INTEGER_FIELDS, V1_RATE_FIELDS
        forbidden = ("encoded_bytes", "encoded_bytes_per_second")
    elif version_text == "2":
        version, integer_fields, rate_fields = 2, V2_INTEGER_FIELDS, V2_RATE_FIELDS
        forbidden = ("raw_bytes", "raw_bytes_per_second")
    else:
        raise ValueError("unsupported metrics_version")
    mixed = [key for key in forbidden if key in values]
    if mixed:
        raise ValueError(f"metrics contract contains forbidden {mixed[0]}")
    required = {"profile", "return", *integer_fields, *rate_fields}
    if version == 2:
        required.add("metrics_version")
    unknown = sorted(values.keys() - required)
    if unknown:
        raise ValueError("unknown metrics sidecar key " + unknown[0])
    missing = sorted(required - values.keys())
    if missing:
        raise ValueError("metrics sidecar is missing " + missing[0])
    if artifact_name is not None:
        if version == 1 and not artifact_name.endswith(TEXT_TRACE_SUFFIX):
            raise ValueError("metrics v1 must accompany a .trace.txt.lz4 artifact")
        if version == 2 and not artifact_name.endswith(BINARY_TRACE_SUFFIXES):
            raise ValueError("metrics v2 must accompany a binary trace artifact")
    if values["profile"] not in ("fast", "balanced", "full"):
        raise ValueError("invalid profile metric")
    if re.fullmatch(r"0x[0-9a-fA-F]+", values["return"]) is None:
        raise ValueError("invalid return metric")
    if int(values["return"], 16) > UINT64_MAX:
        raise ValueError("return metric exceeds uint64")

    parsed: dict[str, int | Decimal | str] = {
        "profile": values["profile"], "return": values["return"].lower(),
        "metrics_version": version,
    }
    try:
        for key in integer_fields:
            if re.fullmatch(r"\d+", values[key]) is None:
                raise ValueError(f"{key} is not an unsigned integer")
            parsed[key] = int(values[key])
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
    for key, expected in expected_rates(parsed).items():
        if abs(Decimal(values[key]) - expected) >= Decimal("0.000001"):
            raise ValueError(f"{key} is inconsistent with raw counters")
    return parsed
