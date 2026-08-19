#!/usr/bin/env python3
"""Run the deterministic benchmark scene and summarize legacy text traces."""

from __future__ import annotations

import argparse
import json
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable


TRACE_FOOTER = re.compile(
    rb"^TRACE_END status=ok ret=(0x[0-9a-fA-F]+) elapsed_ms=(\d+) bytes=(\d+)\s*$",
    re.MULTILINE,
)
TRACE_SEQUENCE = re.compile(rb"^(\d+)\s", re.MULTILINE)
TRACE_DIRECTORY = "files/qbdi-traces"


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


def frida_endpoint(port: int) -> str:
    return f"127.0.0.1:{port}"


def median_report(runs: list[dict[str, int | str]]) -> dict[str, float | int | str]:
    """Return medians for raw metrics and throughput derived from every measured run."""
    if not runs:
        raise ValueError("no benchmark runs")

    report: dict[str, float | int | str] = {}
    for key in ("instructions", "elapsed_ms", "raw_bytes"):
        values = [int(run[key]) for run in runs if key in run]
        if values:
            report[key] = statistics.median(values)

    throughput_runs = [
        run for run in runs
        if "instructions" in run and "raw_bytes" in run and int(run.get("elapsed_ms", 0)) > 0
    ]
    if throughput_runs:
        report["instructions_per_second"] = statistics.median(
            int(run["instructions"]) * 1000.0 / int(run["elapsed_ms"])
            for run in throughput_runs
        )
        report["raw_mib_per_second"] = statistics.median(
            int(run["raw_bytes"]) * 1000.0 / int(run["elapsed_ms"]) / (1024 * 1024)
            for run in throughput_runs
        )
    return report


def adb(args: argparse.Namespace, *command: str, text: bool = False) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        [args.adb, "-s", args.device, *command],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )


def newest_legacy_trace(args: argparse.Namespace) -> tuple[str, bytes]:
    listing = adb(args, "shell", "run-as", args.package, "ls", "-1t", TRACE_DIRECTORY, text=True)
    name = select_newest_benchmark_trace(listing.stdout.splitlines())
    trace = adb(args, "exec-out", "run-as", args.package, "cat", f"{TRACE_DIRECTORY}/{name}").stdout
    return name, trace


def invoke_benchmark(args: argparse.Namespace) -> str:
    try:
        import frida  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("Frida Python bindings are required; install the matching 'frida' package") from error

    source = Path(args.agent).read_text(encoding="utf-8")
    messages: list[dict[str, Any]] = []

    def on_message(message: dict[str, Any], _data: Any) -> None:
        messages.append(message)

    adb(args, "shell", "am", "force-stop", args.package)
    adb(args, "forward", f"tcp:{args.frida_port}", f"tcp:{args.frida_port}")
    manager = frida.get_device_manager()
    device = manager.add_remote_device(args.frida_device or frida_endpoint(args.frida_port))
    pid = device.spawn([args.package])
    session = device.attach(pid)
    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    device.resume(pid)

    deadline = time.monotonic() + args.timeout
    result: str | None = None
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
    script.unload()
    session.detach()
    if result is None:
        raise RuntimeError(f"benchmark agent timed out after {args.timeout:g} seconds")
    return result.lower()


def run_once(args: argparse.Namespace) -> dict[str, int | str]:
    returned = invoke_benchmark(args)
    name, trace = newest_legacy_trace(args)
    parsed = parse_legacy_trace(trace, len(trace))
    if parsed["return"] != returned:
        raise RuntimeError(f"agent returned {returned}, trace {name} ended with {parsed['return']}")
    parsed["trace"] = name
    return parsed


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
    parser.add_argument("--legacy", action="store_true", help="require uncompressed .trace.txt files")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.runs < 1:
        raise SystemExit("--runs must be at least one")
    if not args.legacy:
        raise SystemExit("this baseline currently supports --legacy uncompressed traces only")

    warmup = run_once(args)
    runs = [run_once(args) for _ in range(args.runs)]
    stable_return = ensure_stable_return([str(warmup["return"]), *[str(run["return"]) for run in runs]])
    report = median_report(runs)
    report["return"] = stable_return
    report["runs"] = runs
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError, ValueError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(1)
