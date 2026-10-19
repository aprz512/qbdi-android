"""Run the native overlap regression and short-scene buffer comparison on one device."""

from pathlib import Path
import argparse
import dataclasses
import hashlib
import json
import statistics
import sys
import uuid

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from qtrace.build import Deployer, TracerArtifacts
from qtrace.device import AdbDevice
from qtrace.models import ResolvedScene
from qtrace.preflight import bind_package_access
from qtrace.process import BoundedRunner
from qtrace.session import parse_status
from qtrace.status import load_strict_json
from scripts.trace_convert import convert_binary_file
from scripts.trace_metrics import parse_metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--tracer", required=True, type=Path)
    parser.add_argument("--companion", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--package", default="com.aprz.qbdiandroid")
    parser.add_argument("--calls", type=int, default=20, choices=range(2, 101))
    parser.add_argument("--repeats", type=int, default=3, choices=range(1, 11))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    device = bind_package_access(AdbDevice(args.serial, BoundedRunner()), args.package, timeout=20)
    session = str(uuid.uuid4())
    deployment = Deployer().deploy(device, session, TracerArtifacts(args.tracer, args.companion))
    executable = "/data/local/tmp/qtrace-persistent-" + session
    report = {"serial": args.serial, "package": args.package,
              "probe_sha256": hashlib.sha256(args.probe.read_bytes()).hexdigest(),
              "deployment": dataclasses.asdict(deployment), "runs": [], "passed": False}
    try:
        device.push(args.probe, executable, timeout=15)
        device.shell("chmod", "755", executable, timeout=15, maximum_bytes=8192)
        cases = [("concurrent", 8, 0), ("reentry", 8, 0)] + [("short", size, repeat)
                 for repeat in range(args.repeats) for size in (64, 8, 16)]
        for mode, buffer_mb, repeat in cases:
            identifier = str(uuid.uuid4())
            directory = args.output / f"{mode}-{buffer_mb}-{repeat}"
            directory.mkdir()
            raw = device.root_shell(executable, deployment.tracer_so, deployment.companion,
                                    identifier, str(buffer_mb), str(args.calls), mode, args.package,
                                    timeout=60, maximum_bytes=1024 * 1024)
            result = load_strict_json(raw)
            (directory / "process.json").write_bytes(raw)
            result.update(mode=mode, buffer_mb=buffer_mb, repeat=repeat, session_id=identifier)
            scenes = (ResolvedScene("probe", result["start_offset"], result["end_offset"]),)
            raw_status = device.root_shell("cat", device.trace_directory + f"/session-{identifier}.status.json",
                                           timeout=15, maximum_bytes=1024 * 1024)
            status = parse_status(load_strict_json(raw_status), identifier, args.package, 1,
                                  result["pid"], scenes, None)
            if status["errors"] or status["activeScenes"] or len(status["artifacts"]) != result["calls"]:
                raise RuntimeError("overlapping entries did not all complete under QBDI: " + str(status))
            (directory / "status.json").write_bytes(raw_status)
            counts, waits, buffers, tids = [], [], [], set()
            for name in status["artifacts"]:
                source = directory / name
                source.write_bytes(device.root_shell("cat", device.trace_directory + "/" + name,
                                                    timeout=15, maximum_bytes=1024 * 1024))
                raw_metrics = device.root_shell("cat", device.trace_directory + "/" + name + ".metrics",
                                                 timeout=15, maximum_bytes=65536)
                source.with_name(name + ".metrics").write_bytes(raw_metrics)
                metrics = parse_metrics(raw_metrics, name)
                text = source.with_suffix(".txt")
                decoded = convert_binary_file(source, text, lz4=None, crash_marked=False)
                if decoded.instructions != metrics["instructions"] or source.stat().st_size != metrics["compressed_bytes"]:
                    raise RuntimeError("trace/metrics mismatch")
                first = text.open().readline()
                tids.add(first.split(" tid=")[1].split()[0])
                counts.append(decoded.instructions)
                waits.append(metrics["producer_waits"])
                buffers.append(metrics["effective_buffer_bytes"])
            if mode == "concurrent" and len(tids) != 2:
                raise RuntimeError("concurrent regression did not trace two distinct threads")
            if mode == "reentry" and set(counts) != {7}:
                raise RuntimeError("VM reentry executed patched hook instructions: " + str(counts))
            if mode == "short" and (len(set(counts)) != 1 or not counts[0]):
                raise RuntimeError("short-scene instruction count differs")
            if set(buffers) != {buffer_mb * 1024 * 1024}:
                raise RuntimeError("benchmark did not use the requested buffer")
            result.update(trace_instructions=counts, producer_waits=waits, traced_threads=len(tids))
            report["runs"].append(result)
            print(json.dumps({key: result[key] for key in ("mode", "buffer_mb", "repeat", "calls", "peak_rss_kib")}), flush=True)
        report["buffers"] = [{"buffer_mb": size,
            "median_call_us": statistics.median(value / 1000 for run in report["runs"]
                if run["mode"] == "short" and run["buffer_mb"] == size for value in run["call_ns"][1:]),
            "median_peak_rss_kib": statistics.median(run["peak_rss_kib"] for run in report["runs"]
                if run["mode"] == "short" and run["buffer_mb"] == size)} for size in (8, 16, 64)]
        report["passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "detail": str(error)[:1024]}
        raise
    finally:
        for command in [("rm", "-f", executable), ("rm", "-rf", deployment.remote_dir)]:
            try:
                device.root_shell(*command, timeout=15, maximum_bytes=8192)
            except Exception as error:
                report.setdefault("cleanup_errors", []).append(str(error)[:512])
                report["passed"] = False
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
