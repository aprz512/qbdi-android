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
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence


PACKAGE = "com.aprz.qbdiandroid"
ACTIVITY = "com.aprz.qbdiandroid/.MainActivity"
SEED = 5855319310239641971
ITERATIONS = 30
BASELINE_PATH = f"/data/data/{PACKAGE}/files/qtrace-acceptance-baseline.json"


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    returncode: int


class Runner(Protocol):
    def run(self, command: Sequence[str], *, timeout: float, cwd: Path | None = None,
            allowed: tuple[int, ...] = (0,)) -> CommandResult: ...
    def read_text(self, path: Path, *, timeout: float) -> str: ...


class SubprocessRunner:
    """Bounded process/read adapter; the one-shot failure hook is acceptance-only."""

    def __init__(self, device: str, *, inject_first_read_failure: bool = True) -> None:
        self.device = device
        self.inject_first_read_failure = inject_first_read_failure

    def run(self, command: Sequence[str], *, timeout: float, cwd: Path | None = None,
            allowed: tuple[int, ...] = (0,)) -> CommandResult:
        completed = subprocess.run(list(command), cwd=cwd, text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=timeout, check=False)
        if len(completed.stdout.encode()) > 1_048_576 or len(completed.stderr.encode()) > 1_048_576:
            raise RuntimeError("command output exceeded one MiB bound")
        if completed.returncode not in allowed:
            raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(command)}\n{completed.stderr}")
        return CommandResult(completed.stdout, completed.stderr, completed.returncode)

    def read_text(self, path: Path, *, timeout: float) -> str:
        if self.inject_first_read_failure:
            self.inject_first_read_failure = False
            raise ConnectionError("injected one-shot ADB read failure")
        if str(path).startswith("/data/data/"):
            return self.run(("adb", "-s", self.device, "exec-out", "run-as", PACKAGE, "cat", str(path)), timeout=timeout).stdout
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
            raise RuntimeError("host report is not a bounded regular file")
        return path.read_text(encoding="utf-8")


class OneShotArtifactRead:
    """Acceptance-only wrapper: fail exactly one artifact read, never disturb adbd."""
    def __init__(self, client: object) -> None:
        self.client = client
        self.failed = False

    def read_file(self, name: str, *, timeout: float) -> bytes:
        if not self.failed:
            self.failed = True
            raise ConnectionError("injected acceptance artifact read failure")
        return self.client.read_file(name, timeout=timeout)


def _read_retry(runner: Runner, path: Path, *, timeout: float) -> str:
    try:
        return runner.read_text(path, timeout=timeout)
    except ConnectionError:
        return runner.read_text(path, timeout=timeout)


def _strict_json(raw: str) -> dict[str, object]:
    def duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def nonfinite(_: str) -> object:
        raise ValueError("non-finite JSON number")
    value = json.loads(raw, object_pairs_hook=duplicate, parse_constant=nonfinite)
    if type(value) is not dict:
        raise ValueError("JSON root is not an object")
    return value


def _strict_report(runner: Runner, path: Path) -> dict[str, object]:
    try:
        return _strict_json(_read_retry(runner, path, timeout=5.0))
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("qtrace report is not strict JSON") from error


def _wait_for_baseline(runner: Runner) -> dict[str, object]:
    deadline = time.monotonic() + 15.0
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            value = _strict_json(_read_retry(runner, Path(BASELINE_PATH), timeout=min(2.0, remaining)))
            if (type(value) is dict and value.get("iterations") == ITERATIONS and
                    value.get("seed") == SEED and isinstance(value.get("result"), str)):
                return value
            raise ValueError("baseline has an invalid fixture result")
        except (ConnectionError, OSError, ValueError, json.JSONDecodeError) as error:
            last_error = error
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.25, remaining))
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


def _trusted_output(path: Path, root: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve())
        metadata = resolved.lstat()
    except (OSError, ValueError) as error:
        raise RuntimeError("reported output is outside the trusted directory") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError("reported output is not a regular non-symlink file")
    return resolved


def _validated_timed_report(runner: Runner, path: Path) -> tuple[dict[str, object], str]:
    value = _strict_report(runner, path)
    if (type(value) is not dict or value.get("schema") != 1 or value.get("status") != "sealed" or
            value.get("stage") != "completed" or value.get("package") != PACKAGE):
        raise RuntimeError("timed qtrace report is incomplete")
    native = value.get("native")
    status = native.get("status") if isinstance(native, dict) else None
    if (not isinstance(status, dict) or status.get("state") != "sealed" or
            status.get("reason") != "duration_elapsed" or status.get("stopAcknowledged") is not True):
        raise RuntimeError("timed trace did not detach/seal after native duration stop")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeError("timed report has no artifact records")
    roots = [record.get("remote_name") for record in artifacts if isinstance(record, dict) and
             isinstance(record.get("remote_name"), str) and record["remote_name"].endswith(".trace.bin.lz4")]
    if len(roots) != 1:
        raise RuntimeError("timed report lacks a trusted binary artifact name")
    artifact = roots[0]
    if "/" in artifact or "\\" in artifact or artifact in {"", ".", ".."}:
        raise RuntimeError("timed report artifact is not a safe basename")
    names = {record.get("remote_name") for record in artifacts if isinstance(record, dict)}
    if artifact + ".metrics" not in names:
        raise RuntimeError("timed binary root has no matching metrics sidecar record")
    if type(value.get("pid")) is not int or value["pid"] <= 0:
        raise RuntimeError("timed report does not retain its traced app PID")
    timeline = value.get("timeline")
    stages = [item.get("stage") for item in timeline] if isinstance(timeline, list) and all(isinstance(item, dict) for item in timeline) else []
    if "installing_hooks" not in stages or "running" not in stages or stages.index("installing_hooks") > stages.index("running"):
        raise RuntimeError("report lacks installed-action-before-running detach evidence")
    return value, artifact


def _validated_monitor_report(runner: Runner, path: Path, *, status: str) -> dict[str, object]:
    report = _strict_report(runner, path)
    if report.get("schema") != 1 or report.get("package") != PACKAGE or report.get("status") != status:
        raise RuntimeError("monitor report has an invalid classification")
    return report


def _validate_timed_artifact_semantics(runner: Runner, report: dict[str, object], root: Path) -> None:
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
    # ArtifactProcessor already parses the sidecar before publishing it; retain
    # the exact parsed v3 terminal facts in the trusted collector report.
    if record.get("termination") != "stopped" or record.get("metrics_schema") != 3:
        raise RuntimeError("metrics-v3 sidecar is not a stopped terminal")
    text_paths = [Path(item) for item in outputs if isinstance(item, str) and item.endswith(".trace.txt")]
    if len(text_paths) != 1:
        raise RuntimeError("timed binary pull did not publish exactly one format-4 text output")
    text = _read_retry(runner, _trusted_output(text_paths[0], root), timeout=5.0)
    if not text.startswith("TRACE_BEGIN format=4 ") or text.count("TRACE_END status=stopped reason=duration_elapsed return_valid=0 ") != 1:
        raise RuntimeError("timed binary does not contain one duration_elapsed TRACE_STOP terminal")


def _demo_command(device: str, scenario: str, form: str, output: Path) -> tuple[str, ...]:
    return ("python3", "-m", "qtrace", "demo", "--scenario", scenario,
            *( ("--duration", "2s") if scenario == "timed" else () ),
            "--scene-form", form, "--device", device, "--output", str(output))


def _verify_pull_outputs(root: Path) -> None:
    """Pull itself validates binary terminal/metrics/text conversion contracts.

    The report is the authoritative artifact selector; no device directory listing is used here.
    """
    expected = ("latest", "name", "all", "compressed")
    missing = [name for name in expected if not (root / name).exists()]
    if missing:
        raise RuntimeError("manual pull did not publish output directories: " + ",".join(missing))


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
        published = runner.run(_demo_command(device, scenario, form, output), timeout=180.0,
                               allowed=(0, 2) if scenario == "flight-crash" else (0,))
        reports[name] = _report_path(published.stdout or str(output / "report.json"), output)
        if scenario == "flight-crash" and published.returncode != 2:
            raise RuntimeError("flight-crash must publish crash recovery with exit code 2")
    timed, artifact = _validated_timed_report(runner, reports["offset"])
    symbol, _ = _validated_timed_report(runner, reports["symbol"])
    _validate_timed_artifact_semantics(runner, timed, reports["offset"].parent)
    timed_status = timed["native"]["status"]  # validated above
    symbol_status = symbol["native"]["status"]
    if timed_status["normalizedScenes"] != symbol_status["normalizedScenes"]:
        raise RuntimeError("offset and symbol timed scenes did not normalize identically")
    _validated_monitor_report(runner, reports["exit"], status="process_exited")
    _validated_monitor_report(runner, reports["crash"], status="crash_recovered")
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
    temporary = tempfile.TemporaryDirectory(prefix="qtrace-device-acceptance-")
    root = Path(temporary.name)
    try:
        result = run_acceptance(arguments.device, root, runner=SubprocessRunner(arguments.device))
    except BaseException as error:
        retained = Path(tempfile.gettempdir()) / f"qtrace-device-acceptance-failed-{uuid.uuid4().hex}"
        shutil.copytree(root, retained)
        temporary.cleanup()
        print(f"qtrace acceptance failed; generated reports remain at: {retained}", file=sys.stderr)
        print(str(error), file=sys.stderr)
        return 1
    temporary.cleanup()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
