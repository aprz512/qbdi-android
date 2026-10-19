"""Reproduce the version-gated DIGIMON UP AppGuard experiments on one explicit device."""
from pathlib import Path
import argparse
import dataclasses
import json
import hashlib
import math
import re
import shlex
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
sys.path.insert(0, str(REPO))
PACKAGE = "com.bandainamcoent.dgup_ww"
SERIAL = ""
ADB = ["adb", "-s", SERIAL]


def adb(*args, timeout=15):
    return subprocess.run(ADB + list(args), capture_output=True, timeout=timeout)


def verify_sample():
    expected = {
        "libcompatible.so": "e5e27eb73dd1d8a78da9ec7e2d09231bc93de045e98e1a9370f0b4f29eb84f86",
        "libengine.so": "4aeafdbe1ea691c8c6f7ea675cb817688a1f4875a258b97e1f342aaebd9094d0",
        "libmain.so": "1aa3ef824c78cc5ba84f27ac38313790f33ab40125673174a6eff438558a5a89",
    }
    found = adb("shell", "pm", "path", PACKAGE)
    paths = [line[len("package:"):] for line in found.stdout.decode().splitlines() if line.startswith("package:")]
    base = next((Path(path) for path in paths if path.endswith("/base.apk")), None)
    if found.returncode or base is None: raise RuntimeError("target base APK unavailable")
    directory = str(base.parent / "lib/arm64")
    actual = {}
    for name, digest in expected.items():
        command = shlex.join(["sha256sum", directory + "/" + name])
        result = adb("shell", shlex.join(["su", "-c", command]))
        parts = result.stdout.decode(errors="replace").split()
        if result.returncode or not parts or parts[0] != digest:
            raise RuntimeError("unsupported installed sample: " + name)
        actual[name] = parts[0]
    return actual


def processes():
    output = adb("shell", "ps", "-A", "-o", "PID,PPID,UID,NAME,ARGS").stdout.decode(errors="replace")
    rows = []
    for line in output.splitlines():
        fields = line.split(None, 4)
        if len(fields) >= 4 and fields[3].startswith(PACKAGE):
            rows.append({"pid": int(fields[0]), "parent": int(fields[1]), "uid": fields[2], "name": fields[3]})
    return rows


def capture_maps(output, pid, label):
    result = adb("shell", shlex.join(["su", "-c", f"cat /proc/{pid}/maps"]))
    (output / f"{label}.maps.txt").write_bytes(result.stdout)
    return [line for line in result.stdout.decode(errors="replace").splitlines()
            if "libqbdi_tracer" in line or "frida-agent" in line or "frida-gadget" in line]


def startup_prompt(output, report):
    try:
        dumped = adb("shell", "uiautomator", "dump", "/data/local/tmp/qtrace-stability-ui.xml", timeout=10)
        if dumped.returncode:
            return
        raw = adb("shell", "cat", "/data/local/tmp/qtrace-stability-ui.xml").stdout
        tree = ET.fromstring(raw)
        nodes = list(tree.iter("node"))
        texts = [n.attrib.get("text", "") for n in nodes]
        label = f"ui-{len(report['samples'])}"
        (output / (label + ".xml")).write_bytes(raw)
        for text in texts:
            if "[Code:" in text:
                report.setdefault("security_alerts", []).append({"text": text, "elapsed": report["samples"][-1]["elapsed"]})
        button = next((n for n in nodes if n.attrib.get("resource-id", "").endswith((":id/permission_deny_button", ":id/permission_deny_and_dont_ask_again_button"))
                       and n.attrib.get("package") == "com.android.permissioncontroller"), None)
        if button is None and any("玩家资料" in text and ("创建" in text or "Create" in text) for text in texts):
            button = next((n for n in nodes if n.attrib.get("text") == "取消"
                           and n.attrib.get("package") == "com.google.android.gms"), None)
        if button is not None:
            numbers = [int(value) for value in re.findall(r"\d+", button.attrib.get("bounds", ""))]
            if len(numbers) == 4:
                x, y = (numbers[0] + numbers[2]) // 2, (numbers[1] + numbers[3]) // 2
                result = adb("shell", "input", "tap", str(x), str(y))
                report.setdefault("prompt_actions", []).append({"text": button.attrib.get("text"), "resource_id": button.attrib.get("resource-id"), "returncode": result.returncode})
    except (subprocess.TimeoutExpired, ET.ParseError):
        report.setdefault("ui_notes", []).append("startup prompt inspection timed out")


def validate_and_collect(bound, output, report):
    """Use qtrace's bound transport and strict decoder for completed scene files."""
    from qtrace.artifacts import _client_for, pull_named_artifacts
    from qtrace.models import ResolvedScene
    from qtrace.session import parse_status
    from qtrace.status import load_strict_json
    from scripts.trace_convert import convert_binary_file
    from scripts.trace_metrics import parse_metrics

    session_id = report["session_id"]
    generation = report["injection"]["generation"]
    native = report["native_request"]
    scenes = tuple(ResolvedScene(scene["name"], int(scene["location"]["offset"], 16),
                                 int(scene["location"]["endOffset"], 16)) for scene in native["scenes"])
    raw = bound.target_shell("cat", f"{bound.trace_directory}/session-{session_id}.status.json",
                             timeout=15, maximum_bytes=1024 * 1024)
    status = parse_status(load_strict_json(raw), session_id, PACKAGE, generation, report["pid"], scenes, None)
    report["native_status"] = status
    if status["errors"] or status["state"] == "stop_incomplete":
        raise RuntimeError("native status reports a trace failure")
    if status["activeScenes"]:
        raise RuntimeError("scene still active; completed-file collection cannot be proven")
    names = status["artifacts"]
    if not names: raise RuntimeError("native session produced no trace files")
    client = _client_for(bound, PACKAGE, None)
    listing = set(client.list_names(timeout=15))
    selected = []
    for name in names:
        if name + ".metrics" not in listing: raise RuntimeError("missing trace metrics: " + name)
        if name + ".crash" in listing: raise RuntimeError("scene crashed: " + name)
        selected.extend([name, name + ".metrics"])
    before = {name: client.size(name, timeout=15) for name in selected}
    pulled = pull_named_artifacts(client, PACKAGE, selected, output / "traces", timeout=15)
    for item in pulled:
        if item.size != before[item.remote_name] or item.size != client.size(item.remote_name, timeout=15):
            raise RuntimeError("remote artifact changed during pull: " + item.remote_name)
    report["trace_files"] = [{"name": item.remote_name, "size": item.size, "sha256": item.sha256} for item in pulled]
    summaries = []
    for name in names:
        source = output / "traces" / name
        text = source.with_suffix(".txt")
        stats = convert_binary_file(source, text, lz4=None, crash_marked=False)
        metrics = parse_metrics(source.with_name(name + ".metrics").read_bytes(), name)
        if metrics["instructions"] != stats.instructions or metrics["compressed_bytes"] != source.stat().st_size:
            raise RuntimeError("trace and metrics disagree: " + name)
        lines = text.read_text().splitlines()
        summaries.append({"file": name, "instructions": stats.instructions,
                          "rules": [line for line in lines if line.startswith("RULE ")],
                          "elapsed_ms": int(metrics["elapsed_ms"]),
                          "effective_buffer_bytes": int(metrics["effective_buffer_bytes"]),
                          "terminal": lines[-1]})
    report["trace_summary"] = summaries
    (output / "trace-summary.json").write_text(json.dumps(summaries, ensure_ascii=False, indent=2) + "\n")


def process_identity(pid):
    from qtrace.session import _parse_process_identity
    result = adb("shell", shlex.join(["su", "-c", f"cat /proc/{pid}/stat"]))
    if result.returncode:
        return None
    identity = _parse_process_identity(result.stdout, pid)
    return identity.starttime_ticks if identity.state not in {"Z", "X", "x"} else None


def capture_title(output, report, sample, reference):
    from qtrace.acceptance import image_marker
    pid = report["pid"]
    before = process_identity(pid)
    focus = adb("shell", "dumpsys", "window")
    focused = [line.strip() for line in focus.stdout.decode(errors="replace").splitlines()
               if "mCurrentFocus=" in line]
    screen = adb("exec-out", "screencap", "-p")
    after = process_identity(pid)
    sample["elapsed"] = time.monotonic() - report["monitor_monotonic"]
    sample["starttime_ticks"] = after
    sample["focused"] = focus.returncode == 0 and any(PACKAGE + "/" in line for line in focused)
    sample["original_pid_alive"] = before == after == report["starttime_ticks"]
    if screen.returncode or not screen.stdout.startswith(b"\x89PNG"):
        sample["title_marker"] = {"matched": False, "reason": "screenshot failed"}
        return
    sample["title_marker"] = image_marker(screen.stdout, reference)
    if sample["title_marker"]["matched"] and sample["focused"] and sample["original_pid_alive"]:
        previous = report["samples"][-2] if len(report["samples"]) > 1 else {}
        label = "title-end" if (previous.get("title_marker", {}).get("matched") and previous.get("focused")) else "title-start"
        receipt = {"pid": pid, "starttime_ticks": after, "elapsed": sample["elapsed"],
                   "epoch": time.time(), "focus": focused,
                   "screenshot_sha256": hashlib.sha256(screen.stdout).hexdigest(),
                   "marker": sample["title_marker"]}
        (output / (label + ".png")).write_bytes(screen.stdout)
        (output / (label + ".json")).write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
        report[label.replace("-", "_")] = receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--helper", type=Path, default=REPO / "out/appguard-dgup/libappguard_dgup.so")
    parser.add_argument("--tracer", type=Path, default=REPO / "out/appguard-dgup/libqbdi_tracer.so")
    parser.add_argument("--companion", type=Path, default=REPO / "out/appguard-dgup/libshadowhook_nothing.so")
    parser.add_argument("--mode", choices=["baseline", "main", "engine", "engine-qbdi-workers", "engine-native-workers"], default="engine")
    parser.add_argument("--label", default="dgup")
    parser.add_argument("--seconds", type=float, default=180)
    parser.add_argument("--title-seconds", type=float, default=120)
    parser.add_argument("--buffer-mb", type=int, choices=[8, 16, 32, 64, 128])

    parser.add_argument("--handle-startup-prompts", action="store_true")
    parser.add_argument("--guard-mode", type=int, choices=[5, 6, 8, 13, 14, 15])
    args = parser.parse_args()
    engine_mode = args.mode in {"engine", "engine-qbdi-workers", "engine-native-workers"}
    expected_guard = 14 if args.mode == "engine-native-workers" else 15
    if args.guard_mode is None: args.guard_mode = expected_guard if engine_mode else 13
    if (engine_mode and args.guard_mode != expected_guard) or (not engine_mode and args.guard_mode in {14, 15}):
        parser.error("engine uses guard 15; engine-native-workers uses guard 14; other modes use 5, 6, 8 or 13")
    global SERIAL, ADB
    SERIAL = args.serial
    ADB = ["adb", "-s", SERIAL]
    args.detach = "before-resume"
    if not all(math.isfinite(value) and value > 0 for value in (args.seconds, args.title_seconds)):
        parser.error("seconds and title-seconds must be finite and positive")
    from qtrace.acceptance import continuous_title_acceptance
    import PIL.Image  # Check screenshot verification dependency before device mutation.
    reference = json.loads((ROOT / "title-marker.json").read_text())
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    import shutil, hashlib
    shutil.copy2(ROOT / "guard.cpp", output / "guard_probe.cpp")
    shutil.copy2(ROOT / "rules.cpp", output / "rules.cpp")
    if args.mode != "baseline": shutil.copy2(args.helper, output / "libguard_probe.so")
    report = {"helper_sha256": hashlib.sha256(args.helper.read_bytes()).hexdigest() if args.mode != "baseline" else None, "mode": args.mode, "label": args.label, "seconds": args.seconds, "detach": args.detach,
              "package": PACKAGE, "serial": SERIAL, "samples": []}
    log = None
    log_file = (output / "logcat.txt").open("wb")
    try:
        report["sample"] = verify_sample()
        stopped = adb("shell", "am", "force-stop", PACKAGE)
        if stopped.returncode:
            raise RuntimeError(stopped.stderr.decode(errors="replace"))
        deployment = None
        session_id = str(uuid.uuid4())
        report["session_id"] = session_id
        if args.mode != "baseline":
            from qtrace.build import Deployer, TracerArtifacts
            from qtrace.device import AdbDevice
            from qtrace.preflight import bind_package_access
            from qtrace.process import BoundedRunner
            bound = bind_package_access(AdbDevice(SERIAL, BoundedRunner()), PACKAGE, timeout=20)
            deployment = Deployer().deploy(bound, session_id, TracerArtifacts(
                args.tracer, args.companion))
            report["deployment"] = dataclasses.asdict(deployment)
        if deployment is not None:
            temporary = "/data/local/tmp/qguard-" + session_id + ".so"
            helper = deployment.remote_dir + "/libguard_probe.so"
            try:
                bound.push(args.helper, temporary, timeout=15)
                bound.root_shell("cp", temporary, helper, timeout=15, maximum_bytes=8192)
                bound.root_shell("chown", f"{bound.binding.package_uid}:{bound.binding.package_uid}", helper,
                                    timeout=15, maximum_bytes=8192)
                bound.root_shell("chmod", "700", helper, timeout=15, maximum_bytes=8192)
                digest = bound.target_shell("sha256sum", helper, timeout=15, maximum_bytes=8192).decode().split()[0]
                if digest != report["helper_sha256"]:
                    raise RuntimeError("deployed adapter SHA-256 mismatch")
            finally:
                bound.shell("rm", "-f", temporary, timeout=15, maximum_bytes=8192)
            report["guard_helper"] = helper
            report["guard_mode"] = args.guard_mode
        log = subprocess.Popen(ADB + ["logcat", "-T", "1", "-v", "threadtime"], stdout=log_file, stderr=subprocess.STDOUT)
        if args.mode == "baseline":
            launched = adb("shell", "am", "start", "-W", "-n", PACKAGE + "/com.google.firebase.MessagingUnityPlayerActivity", timeout=25)
            report["launch"] = launched.stdout.decode(errors="replace")
            rows = processes()
            candidates = [row for row in rows if row["parent"] not in {row["pid"] for row in rows}]
            if not candidates:
                raise RuntimeError("no baseline main process")
            pid = candidates[0]["pid"]
        else:
            from qtrace.injector import FridaInjector, FridaProvider, InjectionRequest, StartupAdapter
            if args.mode == "main" or engine_mode:
                module, start, end = (("appguard-runtime.so", "0x146c88", "0x146f80") if engine_mode
                                      else ("libmain.so", "0x4a80", "0x4b0c"))
                native = {
                    "schemaVersion": 1, "packageName": PACKAGE, "targetModule": module,
                    "trace": {"profile": "fast", "compression": False, "autoBuffer": args.buffer_mb is None, "bufferMb": args.buffer_mb or 0, "lz4Level": 0, "hexdumpLimit": 32},
                    "flight": {"enabled": False, "entryScene": "", "capacityMb": 64, "chunkKb": 256, "maxThreads": 32, "protectedChunks": 4},
                    "session": {"id": session_id} if engine_mode else {"id": session_id, "durationMs": 5000},
                    "scenes": [{"name": "appguard-report" if engine_mode else "unity-initialization",
                                "location": {"offset": start, "endOffset": end}}],
                }
                if engine_mode and args.guard_mode == 15:
                    native["scenes"].append({"name": "appguard-termination", "location": {
                        "offset": "0xc6114", "endOffset": "0xc61c4"}})
                if engine_mode:
                    native["codeRules"] = {"enabled": True, "sampleSha256": report["sample"]["libengine.so"]}
                report["native_request"] = native
            result = FridaInjector(bound, FridaProvider()).install(InjectionRequest(
                package=PACKAGE, session_id=session_id,
                tracer_so=deployment.tracer_so, companion=deployment.companion,
                native_request=native, setup_timeout=30, detach_before_resume=True,
                startup_adapter=StartupAdapter(helper, "qguard_probe_start", args.guard_mode),
            ))
            report["injection"] = dataclasses.asdict(result)
            if not result.cleanup_detached:
                raise RuntimeError("injector did not confirm Frida cleanup")
            pid = result.pid
        report["pid"] = pid
        report["starttime_ticks"] = process_identity(pid)
        if report["starttime_ticks"] is None:
            raise RuntimeError("original process identity unavailable after installation")
        (output / "startup.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"label": args.label, "pid": pid, "mode": args.mode, "stage": "resumed"}), flush=True)
        started = time.monotonic()
        report["monitor_monotonic"] = started
        next_sample = 0.0
        while True:
            elapsed = time.monotonic() - started
            rows = processes()
            ticks = process_identity(pid)
            alive = any(row["pid"] == pid for row in rows) and ticks == report["starttime_ticks"]
            sample = {"elapsed": elapsed, "pid": pid, "starttime_ticks": ticks,
                      "original_pid_alive": alive, "processes": rows}
            report["samples"].append(sample)
            if alive:
                capture_title(output, report, sample, reference)
                alive = sample["original_pid_alive"]
            if alive and len(report["samples"]) in [1, 3]:
                report.setdefault("mapping_checks", []).append({"elapsed": elapsed, "rows": capture_maps(output, pid, f"sample-{len(report['samples'])}")})
            if alive and args.handle_startup_prompts and len(report["samples"]) in [2, 3, 5, 7, 13, 25]:
                startup_prompt(output, report)
            if not alive or elapsed >= args.seconds:
                break
            next_sample += 5
            time.sleep(max(0, min(next_sample, args.seconds) - (time.monotonic() - started)))
        report["original_pid_survived"] = report["samples"][-1]["original_pid_alive"]
        report["observed_seconds"] = report["samples"][-1]["elapsed"]
        report["acceptance"] = continuous_title_acceptance(
            report["samples"], pid, report["starttime_ticks"], args.title_seconds)
        focus = adb("shell", "dumpsys", "window").stdout.decode(errors="replace")
        report["focus"] = [line.strip() for line in focus.splitlines() if "mCurrentFocus=" in line]
        if report["original_pid_survived"]:
            capture_maps(output, pid, "final")
            screen = adb("exec-out", "screencap", "-p")
            if screen.stdout.startswith(b"\x89PNG"):
                (output / "screen.png").write_bytes(screen.stdout)
            if args.mode == "main" or engine_mode:
                validate_and_collect(bound, output, report)
        print(json.dumps({key: report.get(key) for key in ["label", "pid", "original_pid_survived", "observed_seconds", "focus"]}, ensure_ascii=False), flush=True)
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "detail": str(error)}
        print(json.dumps(report["error"], ensure_ascii=False), flush=True)
    finally:
        if log is not None:
            log.terminate()
            try:
                log.wait(timeout=3)
            except subprocess.TimeoutExpired:
                log.kill()
                log.wait(timeout=3)
        log_file.close()
        rules = [line for summary in report.get("trace_summary", []) for line in summary["rules"]]
        summary = {key: report.get(key) for key in ("mode", "package", "serial", "pid", "starttime_ticks", "session_id", "sample", "acceptance", "error")}
        summary["traces"] = len(report.get("trace_summary", []))
        summary["instructions"] = sum(item["instructions"] for item in report.get("trace_summary", []))
        summary["rule_hits"] = {name: sum(name in line for line in rules) for name in
                                ("appguard-report", "appguard-policy", "appguard-termination")}
        summary["injection"] = report.get("injection")
        summary["screenshots"] = {key: report.get(key) for key in ("title_start", "title_end")}
        summary["passed"] = (report.get("acceptance", {}).get("passed") is True and not report.get("error")
                             and (not engine_mode or (summary["rule_hits"]["appguard-policy"] > 0 and
                                  (args.guard_mode != 15 or summary["rule_hits"]["appguard-termination"] > 0))))
        (output / "acceptance-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
        (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
