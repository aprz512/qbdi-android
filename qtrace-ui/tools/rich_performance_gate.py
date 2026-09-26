#!/usr/bin/env python3
"""Record five production-path rich workloads on a fixed or diagnostic host."""
from __future__ import annotations

import argparse
import json
import hashlib
import sys
import math
import os
from pathlib import Path
import subprocess
import tempfile

import performance_gate as gate


def summarize(runs: list[dict[str, object]], manifest: dict[str, object]) -> dict[str, float]:
    if len(runs) != gate.RUN_COUNT:
        raise ValueError("rich workload requires five complete runs")
    oracle = manifest["semantic_oracle"]
    expected = [oracle["instructions"], oracle["memory_events"], oracle["semantic_events"], 6]
    digests = set()
    for run in runs:
        if run["event_counts"] != expected or run["call_frames"] != oracle["call_frames"]:
            raise ValueError("rich event/call oracle mismatch")
        if run["flight_threads"] != oracle["flight_threads"] or run["flight_completeness"] != manifest["expected_flight_completeness"]:
            raise ValueError("rich Flight thread/gap oracle mismatch")
        if run["flight_events"] != manifest["corpora"]["flight"]["events"]:
            raise ValueError("rich Flight event count mismatch")
        if run["ipc_events"] != manifest["corpora"]["ipc"]["events"]:
            raise ValueError("rich IPC event count mismatch")
        digests.add(run["correctness_digest"])
        for field, count in (("query_seconds", 200), ("memory_query_seconds", 200), ("replay_query_seconds", 50)):
            values = run[field]
            if len(values) != count or any(not math.isfinite(value) or value < 0 for value in values):
                raise ValueError(f"rich {field} samples are incomplete or invalid")
        if run["ipc_page_bytes"] > 2 * 1024**2 or run["ipc_call_tree_bytes"] > 1024**2:
            raise ValueError("rich IPC output exceeds byte budget")
    if len(digests) != 1 or not gate.HEX64.fullmatch(next(iter(digests))):
        raise ValueError("rich correctness digest mismatch")
    metrics = {field + "_median": gate.median(run[field] for run in runs) for field in (
        "raw_cold_seconds", "raw_warm_seconds", "compressed_cold_seconds",
        "replay_build_seconds", "call_tree_seconds", "peak_rss_bytes", "cache_bytes",
        "ipc_query_seconds", "ipc_page_bytes", "ipc_call_tree_seconds", "ipc_call_tree_bytes",
    )}
    metrics.update({field + "_p95": gate.nearest_rank_p95(value for run in runs for value in run[field])
                    for field in ("query_seconds", "memory_query_seconds", "replay_query_seconds")})
    return metrics


def run(manifest_path: Path, evidence: Path, reference: Path | None, diagnostic: bool) -> None:
    root = Path(__file__).resolve().parents[2]
    host = gate._host_identity({"reference_host": gate._reference_host(reference)}, diagnostic=diagnostic)
    manifest = json.loads(manifest_path.read_text())
    generator = root / "qtrace-ui/tools/generate_rich_performance_fixture.py"
    if manifest["schema"] != 2 or manifest["generator_sha256"] != gate._sha256(generator):
        raise ValueError("rich generator identity drift")
    if manifest["semantic_oracle"]["events"] < 1_000_000:
        raise ValueError("rich gate needs at least one million typed events")
    for corpus in manifest["corpora"].values():
        path = manifest_path.parent / corpus["path"]
        if path.is_symlink() or path.stat().st_size != corpus["bytes"] or gate._sha256(path) != corpus["sha256"]:
            raise ValueError("rich corpus identity drift")
    ui = root / "qtrace-ui"
    subprocess.run(["cargo", "build", "--release", "-p", "qtrace-service", "--example", "perf_driver"], cwd=ui, check=True)
    driver = ui / "target/release/examples/perf_driver"
    report = {"schema": 1, "mode": "diagnostic" if diagnostic else "reference", "host": host,
              "manifest": manifest, "manifest_sha256": gate._sha256(manifest_path),
              "analyzer": {"commit": gate._git(root, "rev-parse", "HEAD"), "sha256": gate._sha256(driver),
                           "working_tree_diff_sha256": hashlib.sha256(subprocess.check_output(["git", "diff", "HEAD"], cwd=root)).hexdigest()},
              "runs": []}
    with tempfile.TemporaryDirectory(prefix="qtrace-rich-") as temporary:
        for index in range(gate.RUN_COUNT):
            cache = Path(temporary) / str(index)
            cache.mkdir(mode=0o700)
            payload, elapsed, rss = gate._run_driver([str(driver), "rich", "--input", str(manifest_path.resolve()), "--cache", str(cache)], dict(os.environ))
            report["runs"].append(dict(payload, process_seconds=elapsed, peak_rss_bytes=rss, cache_bytes=gate._tree_bytes(cache)))
            print(f"rich run {index + 1}/{gate.RUN_COUNT}: {elapsed:.3f}s, {rss / 1024**2:.1f} MiB", flush=True)
    report["metrics"] = summarize(report["runs"], manifest)
    # Rich workloads have no historical latency thresholds. Keep raw measurements;
    # correctness, sample counts and IPC bounds are required on both host modes.
    report["validation"] = {"correctness": "pass", "performance_thresholds": "measurement_only"}
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--reference-summary", type=Path)
    parser.add_argument("--diagnostic", action="store_true")
    args = parser.parse_args()
    if args.diagnostic and args.reference_summary:
        parser.error("diagnostic mode cannot use reference summary")
    if not args.diagnostic and not args.reference_summary:
        parser.error("reference mode requires --reference-summary")
    try:
        run(args.manifest, args.evidence, args.reference_summary, args.diagnostic)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"rich gate: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
