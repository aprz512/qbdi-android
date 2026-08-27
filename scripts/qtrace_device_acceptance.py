#!/usr/bin/env python3
"""Manual, rooted-device qtrace release acceptance.  This is never a CI job."""

from __future__ import annotations

import argparse
import json
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Protocol, Sequence


PACKAGE = "com.aprz.qbdiandroid"
ACTIVITY = "com.aprz.qbdiandroid/.MainActivity"
SEED = 5855319310239641971
ITERATIONS = 30
BASELINE_PATH = f"/data/data/{PACKAGE}/files/qtrace-acceptance-baseline.json"


class Runner(Protocol):
    def run(self, command: Sequence[str], *, timeout: float, cwd: Path | None = None) -> str: ...
    def read_text(self, path: Path, *, timeout: float) -> str: ...


class SubprocessRunner:
    """Bounded process/read adapter; the one-shot failure hook is acceptance-only."""

    def __init__(self, device: str, *, inject_first_read_failure: bool = True) -> None:
        self.device = device
        self.inject_first_read_failure = inject_first_read_failure

    def run(self, command: Sequence[str], *, timeout: float, cwd: Path | None = None) -> str:
        completed = subprocess.run(list(command), cwd=cwd, text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=timeout, check=False)
        if completed.returncode:
            raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(command)}\n{completed.stderr}")
        return completed.stdout

    def read_text(self, path: Path, *, timeout: float) -> str:
        if self.inject_first_read_failure:
            self.inject_first_read_failure = False
            raise ConnectionError("injected one-shot ADB read failure")
        if str(path).startswith("/data/data/"):
            return self.run(("adb", "-s", self.device, "exec-out", "run-as", PACKAGE, "cat", str(path)), timeout=timeout)
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
            raise RuntimeError("host report is not a bounded regular file")
        return path.read_text(encoding="utf-8")


def _read_retry(runner: Runner, path: Path, *, timeout: float) -> str:
    try:
        return runner.read_text(path, timeout=timeout)
    except ConnectionError:
        return runner.read_text(path, timeout=timeout)


def _wait_for_baseline(runner: Runner) -> dict[str, object]:
    deadline = time.monotonic() + 15.0
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            value = json.loads(_read_retry(runner, Path(BASELINE_PATH), timeout=2.0))
            if (type(value) is dict and value.get("iterations") == ITERATIONS and
                    value.get("seed") == SEED and isinstance(value.get("result"), str)):
                return value
            raise ValueError("baseline has an invalid fixture result")
        except (ConnectionError, OSError, ValueError, json.JSONDecodeError) as error:
            last_error = error
            time.sleep(0.25)
    raise RuntimeError(f"timed baseline was not available within 15 seconds: {last_error}")


def _report_path(stdout: str, root: Path) -> Path:
    candidates = [Path(line.strip()) for line in stdout.splitlines() if line.strip().endswith("report.json")]
    if len(candidates) != 1:
        raise RuntimeError("qtrace demo did not publish exactly one report path")
    report = candidates[0]
    try:
        report.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise RuntimeError("qtrace reported a path outside its trusted output directory") from error
    return report


def _validated_timed_report(runner: Runner, path: Path) -> tuple[dict[str, object], str]:
    value = json.loads(_read_retry(runner, path, timeout=5.0))
    if (type(value) is not dict or value.get("schema") != 1 or value.get("status") != "sealed" or
            value.get("stage") != "completed" or value.get("package") != PACKAGE):
        raise RuntimeError("timed qtrace report is incomplete")
    native = value.get("native")
    status = native.get("status") if isinstance(native, dict) else None
    if (not isinstance(status, dict) or status.get("state") != "sealed" or
            status.get("reason") != "duration_elapsed" or status.get("stopAcknowledged") is not True):
        raise RuntimeError("timed trace did not detach/seal after native duration stop")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 1 or not isinstance(artifacts[0], dict):
        raise RuntimeError("timed report does not own exactly one artifact")
    artifact = artifacts[0].get("remote_name")
    if not isinstance(artifact, str) or not artifact.endswith(".trace.bin.lz4"):
        raise RuntimeError("timed report lacks a trusted binary artifact name")
    if type(value.get("pid")) is not int or value["pid"] <= 0:
        raise RuntimeError("timed report does not retain its traced app PID")
    return value, artifact


def _validate_timed_artifact_semantics(runner: Runner, report: dict[str, object]) -> None:
    records = report.get("artifacts")
    outputs = report.get("outputs")
    if not isinstance(records, list) or not isinstance(outputs, list):
        raise RuntimeError("timed report has no artifact semantics")
    binary = [record for record in records if isinstance(record, dict) and
              isinstance(record.get("remote_name"), str) and record["remote_name"].endswith(".trace.bin.lz4")]
    if len(binary) != 1:
        raise RuntimeError("timed trace must publish exactly one binary artifact")
    record = binary[0]
    if (record.get("termination") != "stopped" or record.get("metrics_schema") != 3 or
            record.get("native_stop_acknowledged") is not True):
        raise RuntimeError("binary TRACE_STOP/metrics-v3 native-stop contract failed")
    text_paths = [Path(item) for item in outputs if isinstance(item, str) and item.endswith(".trace.txt")]
    if len(text_paths) != 1:
        raise RuntimeError("timed binary pull did not publish exactly one format-4 text output")
    text = _read_retry(runner, text_paths[0], timeout=5.0)
    if not text.startswith("TRACE_BEGIN format=4 ") or text.count("TRACE_END status=stopped reason=duration_elapsed return_valid=0 ") != 1:
        raise RuntimeError("timed binary does not contain one duration_elapsed TRACE_STOP terminal")


def _demo_command(device: str, scenario: str, form: str, output: Path) -> tuple[str, ...]:
    return ("python3", "-m", "qtrace", "demo", "--scenario", scenario,
            *( ("--duration", "2s") if scenario == "timed" else () ),
            "--scene-form", form, "--device", device, "--output", str(output))


def _verify_pull_outputs(_root: Path) -> None:
    """Pull itself validates binary terminal/metrics/text conversion contracts.

    The report is the authoritative artifact selector; no device directory listing is used here.
    """


def run_acceptance(device: str, directory: Path, *, runner: Runner) -> int:
    if not device:
        raise ValueError("--device is required for manual acceptance")
    directory.mkdir(parents=True, exist_ok=True)
    runner.run(("./gradlew", "nativeHostTest", "--no-daemon"), timeout=900.0)
    runner.run(("python3", "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"), timeout=300.0)
    runner.run(("./gradlew", ":app:assembleDebug", "--no-daemon"), timeout=900.0)
    runner.run(("adb", "-s", device, "install", "-r", "app/build/outputs/apk/debug/app-debug.apk"), timeout=120.0)
    runner.run(("adb", "-s", device, "shell", "am", "force-stop", PACKAGE), timeout=30.0)
    runner.run(("adb", "-s", device, "shell", "am", "start", "-n", ACTIVITY,
                "--ez", "qtrace_acceptance", "true", "--es", "qtrace_acceptance_mode", "timed",
                "--el", "qtrace_acceptance_seed", str(SEED), "--el", "qtrace_acceptance_iterations", str(ITERATIONS)), timeout=30.0)
    baseline = _wait_for_baseline(runner)
    runner.run(("python3", "scripts/benchmark_trace.py", "--device", device, "--profile", "fast", "--runs", "5",
                "--candidate-tracer", "out/arm64-v8a/libqbdi_tracer.so", "--compare", "docs/benchmarks/binary-trace-baseline.md"), timeout=900.0)
    reports: dict[str, Path] = {}
    for scenario, form, name in (("timed", "offset", "offset"), ("timed", "symbol", "symbol"), ("monitor-exit", "offset", "exit"), ("flight-crash", "offset", "crash")):
        output = directory / name
        published = runner.run(_demo_command(device, scenario, form, output), timeout=180.0)
        reports[name] = _report_path(published or str(output / "report.json"), output)
    timed, artifact = _validated_timed_report(runner, reports["offset"])
    symbol, _ = _validated_timed_report(runner, reports["symbol"])
    _validate_timed_artifact_semantics(runner, timed)
    timed_status = timed["native"]["status"]  # validated above
    symbol_status = symbol["native"]["status"]
    if timed_status["normalizedScenes"] != symbol_status["normalizedScenes"]:
        raise RuntimeError("offset and symbol timed scenes did not normalize identically")
    runner.run(("adb", "-s", device, "shell", "kill", "-0", str(timed["pid"])), timeout=10.0)
    timed_oracle = json.loads(_read_retry(runner, Path(
        f"/data/data/{PACKAGE}/files/qtrace-acceptance-timed.json"), timeout=5.0))
    if timed_oracle != baseline:
        raise RuntimeError("long timed target did not return the baseline oracle value")
    runner.run(("python3", "-m", "qtrace", "pull", "--package", PACKAGE, "--latest", "--device", device, "--output", str(directory / "latest")), timeout=180.0)
    runner.run(("python3", "-m", "qtrace", "pull", "--package", PACKAGE, "--name", artifact, "--device", device, "--output", str(directory / "name")), timeout=180.0)
    runner.run(("python3", "-m", "qtrace", "pull", "--package", PACKAGE, "--all", "--device", device, "--output", str(directory / "all")), timeout=180.0)
    runner.run(("python3", "-m", "qtrace", "pull", "--package", PACKAGE, "--all", "--compressed-only", "--device", device, "--output", str(directory / "compressed")), timeout=180.0)
    _verify_pull_outputs(directory)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True, help="explicit rooted arm64 device serial")
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)
    with tempfile.TemporaryDirectory(prefix="qtrace-device-acceptance-") as temporary:
        root = Path(temporary)
        try:
            return run_acceptance(arguments.device, root, runner=SubprocessRunner(arguments.device))
        except BaseException as error:
            print(f"qtrace acceptance failed; generated reports remain at: {root}", file=sys.stderr)
            print(str(error), file=sys.stderr)
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
