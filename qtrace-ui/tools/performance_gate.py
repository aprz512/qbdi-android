#!/usr/bin/env python3
"""Run and adjudicate the qtrace-ui reference-host performance workload."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import tempfile
import time
from typing import Iterable, NamedTuple


RUN_COUNT = 5
QUERY_COUNT = 200
QTRB_EVENTS = 10_000_000
FLIGHT_BYTES = 512 * 1024 * 1024
FLIGHT_EVENTS = 68
MAX_COLD_SECONDS = 30.0
MAX_WARM_SECONDS = 2.0
MAX_VIEWPORT_SECONDS = 0.050
MAX_SEARCH_SECONDS = 0.200
MAX_RSS_BYTES = 2 * 1024**3
HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


class Verdict(NamedTuple):
    passed: bool
    failures: tuple[str, ...]
    metrics: dict[str, float]


def median(values: Iterable[float]) -> float:
    items = list(values)
    if not items:
        raise ValueError("median needs at least one value")
    return float(statistics.median(items))


def nearest_rank_p95(values: Iterable[float]) -> float:
    items = sorted(float(value) for value in values)
    if not items:
        raise ValueError("p95 needs at least one value")
    return items[math.ceil(0.95 * len(items)) - 1]


def parse_rss_bytes(status: str) -> int:
    match = re.search(r"^VmHWM:\s*([0-9]+)\s+kB\s*$", status, re.MULTILINE)
    if match is None:
        raise ValueError("missing or malformed VmHWM")
    return int(match.group(1)) * 1024


def _valid_identity(value: object, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def verdict(report: dict[str, object]) -> Verdict:
    failures: list[str] = []
    metrics: dict[str, float] = {}
    generator = report.get("generator")
    analyzer = report.get("analyzer")
    host = report.get("host")
    corpora = report.get("corpora")
    expected = report.get("expected_correctness_digest")
    expected_completeness = report.get("expected_flight_completeness")

    if not isinstance(generator, dict) or generator.get("schema") != 1 or not _valid_identity(generator.get("sha256"), HEX64):
        failures.append("generator identity is missing or stale")
    if not isinstance(analyzer, dict) or not _valid_identity(analyzer.get("commit"), COMMIT) or not _valid_identity(analyzer.get("sha256"), HEX64):
        failures.append("analyzer identity is missing or stale")
    if not isinstance(host, dict) or not host.get("identity"):
        failures.append("fixed host identity is missing")
    if not isinstance(corpora, dict):
        failures.append("corpus identity is missing")
    else:
        qtrb = corpora.get("qtrb", {})
        flight = corpora.get("flight", {})
        if not isinstance(qtrb, dict) or qtrb.get("events") != QTRB_EVENTS:
            failures.append("QTRB corpus must contain exactly 10,000,000 events")
        if not isinstance(flight, dict) or flight.get("bytes") != FLIGHT_BYTES:
            failures.append("Flight corpus must contain exactly 536870912 bytes")
        if not isinstance(flight, dict) or flight.get("events") != FLIGHT_EVENTS:
            failures.append("Flight corpus must produce exactly 68 events")
        for name, identity in (("QTRB", qtrb), ("Flight", flight)):
            if not isinstance(identity, dict) or not _valid_identity(identity.get("sha256"), HEX64):
                failures.append(f"{name} corpus SHA-256 is invalid")
    if not _valid_identity(expected, HEX64):
        failures.append("expected correctness digest is invalid")
    completeness_causes = (
        {item.get("cause") for item in expected_completeness if isinstance(item, dict)}
        if isinstance(expected_completeness, list) else set()
    )
    if not {"overwritten", "coverage_gap"}.issubset(completeness_causes):
        failures.append("Flight completeness oracle lacks overwritten or coverage-gap evidence")

    cold = report.get("cold_index")
    warm = report.get("warm_open")
    if not isinstance(cold, list) or len(cold) != RUN_COUNT:
        failures.append("cold index requires five complete runs")
        cold = []
    if not isinstance(warm, list) or len(warm) != RUN_COUNT:
        failures.append("warm open requires five complete runs")
        warm = []

    def validate_runs(name: str, runs: list[object], seconds_limit: float) -> None:
        seconds: list[float] = []
        for index, run in enumerate(runs):
            if not isinstance(run, dict):
                failures.append(f"{name} run {index + 1} is incomplete")
                continue
            try:
                elapsed = float(run["seconds"])
                rss = int(run["peak_rss_bytes"])
                int(run["cache_bytes"])
            except (KeyError, TypeError, ValueError):
                failures.append(f"{name} run {index + 1} is incomplete")
                continue
            seconds.append(elapsed)
            if elapsed > seconds_limit:
                failures.append(f"{name} run {index + 1} exceeds {seconds_limit:g} s")
            if name == "cold index" and rss > MAX_RSS_BYTES:
                failures.append(f"cold index run {index + 1} exceeds 2 GiB peak RSS")
            if run.get("correctness_digest") != expected:
                failures.append(f"{name} run {index + 1} correctness mismatch")
        if len(seconds) == RUN_COUNT:
            metrics[f"{name.replace(' ', '_')}_median_seconds"] = median(seconds)

    validate_runs("cold index", cold, MAX_COLD_SECONDS)
    validate_runs("warm open", warm, MAX_WARM_SECONDS)

    for key, label, limit in (
        ("viewport_seconds", "viewport", MAX_VIEWPORT_SECONDS),
        ("structured_search_seconds", "structured search", MAX_SEARCH_SECONDS),
    ):
        samples = report.get(key)
        if not isinstance(samples, list) or len(samples) < QUERY_COUNT:
            failures.append(f"{label} requires at least 200 samples")
            continue
        try:
            p95 = nearest_rank_p95(samples)
        except (TypeError, ValueError):
            failures.append(f"{label} samples are malformed")
            continue
        metrics[f"{label.replace(' ', '_')}_p95_seconds"] = p95
        if p95 > limit:
            failures.append(f"{label} p95 exceeds {limit:g} s")
    return Verdict(not failures, tuple(failures), metrics)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def _host_identity(expected: dict[str, object]) -> dict[str, object]:
    cpu_model = "unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    stat = os.statvfs(".")
    filesystem = subprocess.run(
        ["stat", "-f", "-c", "%T", "."], capture_output=True, text=True, check=True,
    ).stdout.strip()
    observed = {
        "identity": os.environ.get("QTRACE_UI_REFERENCE_HOST", ""),
        "cpu_model": cpu_model,
        "cpu_count": os.cpu_count() or 0,
        "ram_bytes": int(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")),
        "kernel": platform.release(),
        "filesystem": filesystem,
        "filesystem_block_bytes": stat.f_frsize,
    }
    required = expected.get("reference_host")
    if required is not None and observed != required:
        raise RuntimeError("reference host identity drift")
    if not observed["identity"]:
        raise RuntimeError("QTRACE_UI_REFERENCE_HOST is required")
    return observed


def _run_driver(command: list[str], env: dict[str, str]) -> tuple[dict[str, object], float, int]:
    started = time.monotonic()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr)
        _pid, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
        elapsed = time.monotonic() - started
        stdout.seek(0)
        stderr.seek(0)
        output = stdout.read().decode("utf-8", "replace")
        errors = stderr.read().decode("utf-8", "replace")
    if process.returncode != 0:
        raise RuntimeError(errors[-4096:] or "performance driver failed")
    payload = json.loads(output)
    return payload, elapsed, int(usage.ru_maxrss) * 1024


def _tree_bytes(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def _render_markdown(report: dict[str, object], result: Verdict) -> str:
    lines = [
        "# qtrace-ui performance baseline", "",
        "> Generated by `qtrace-ui/tools/performance_gate.py`; do not hand-edit measured values.", "",
        f"Final verdict: **{'PASS' if result.passed else 'FAIL'}**", "",
        "## Recorded evidence", "", "```json",
        json.dumps(report, indent=2, sort_keys=True), "```", "",
    ]
    if result.failures:
        lines.extend(("## Failures", "", *(f"- {item}" for item in result.failures), ""))
    return "\n".join(lines)


def _reference_host(summary_path: Path | None) -> dict[str, object] | None:
    if summary_path is None or not summary_path.exists():
        return None
    text = summary_path.read_text(encoding="utf-8")
    marker = "```json\n"
    start = text.find(marker)
    if start < 0:
        raise RuntimeError("reference summary has no generated JSON evidence")
    start += len(marker)
    end = text.find("\n```", start)
    if end < 0:
        raise RuntimeError("reference summary has an unterminated JSON evidence block")
    report = json.loads(text[start:end])
    host = report.get("host")
    if not isinstance(host, dict):
        raise RuntimeError("reference summary has no host identity")
    return host


def run_gate(
    manifest_path: Path,
    evidence_path: Path,
    summary_path: Path | None,
    reference_summary: Path | None,
) -> int:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = Path(__file__).resolve().parents[2]
    ui = root / "qtrace-ui"
    driver = ui / "target/release/examples/perf_driver"
    subprocess.run(["cargo", "build", "--release", "-p", "qtrace-service", "--example", "perf_driver"], cwd=ui, check=True)
    host = _host_identity({"reference_host": _reference_host(reference_summary)})
    generator_path = ui / "tools/generate_performance_fixtures.py"
    analyzer_commit = _git(root, "rev-parse", "HEAD")
    base = {
        "schema": 1,
        "generator": {"schema": manifest["generator_schema"], "sha256": _sha256(generator_path)},
        "analyzer": {"commit": analyzer_commit, "sha256": _sha256(driver)},
        "host": host,
        "corpora": manifest["corpora"],
        "expected_correctness_digest": manifest["correctness_digest"],
        "expected_flight_completeness": manifest["expected_flight_completeness"],
        "cold_index": [], "warm_open": [],
        "viewport_seconds": [], "structured_search_seconds": [],
        "tool_versions": {
            "rust": subprocess.check_output(["rustc", "--version"], text=True).strip(),
            "node": subprocess.check_output(["node", "--version"], text=True).strip(),
        },
    }
    with tempfile.TemporaryDirectory(prefix="qtrace-ui-perf-") as temporary:
        temp = Path(temporary)
        for index in range(RUN_COUNT):
            cache = temp / f"cache-{index}"
            cache.mkdir(mode=0o700)
            env = dict(os.environ, XDG_CACHE_HOME=str(cache), XDG_DATA_HOME=str(temp / f"data-{index}"))
            payload, elapsed, rss = _run_driver(
                [str(driver), "index", "--input", str(manifest_path), "--cache", str(cache)], env,
            )
            base["cold_index"].append({
                "seconds": elapsed, "peak_rss_bytes": rss,
                "cache_bytes": _tree_bytes(cache),
                "correctness_digest": payload["correctness_digest"],
            })
            payload, elapsed, rss = _run_driver(
                [str(driver), "open", "--input", str(manifest_path), "--cache", str(cache)], env,
            )
            base["warm_open"].append({
                "seconds": elapsed, "peak_rss_bytes": rss,
                "cache_bytes": _tree_bytes(cache),
                "correctness_digest": payload["correctness_digest"],
            })
        workload, _, _ = _run_driver(
            [str(driver), "workload", "--workspace", str(temp / "cache-4"), "--queries", str(manifest_path)],
            dict(os.environ),
        )
        base["viewport_seconds"] = workload["viewport_seconds"]
        base["structured_search_seconds"] = workload["structured_search_seconds"]
    result = verdict(base)
    base["verdict"] = {"passed": result.passed, "failures": result.failures, "metrics": result.metrics}
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(base, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if summary_path is not None:
        summary_path.write_text(_render_markdown(base, result), encoding="utf-8")
    return 0 if result.passed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--write-summary", type=Path)
    parser.add_argument("--reference-summary", type=Path)
    args = parser.parse_args(argv)
    return run_gate(
        args.manifest.resolve(),
        args.evidence.resolve(),
        args.write_summary,
        args.reference_summary,
    )


if __name__ == "__main__":
    raise SystemExit(main())
