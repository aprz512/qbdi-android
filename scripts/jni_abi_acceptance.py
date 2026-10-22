"""Run the standalone arm64 JNI/ART gate under a shared device guard."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import tarfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.trace_convert import convert_binary_file
from scripts.trace_metrics import parse_metrics


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


@contextmanager
def device_guard(root, server, serial):
    """Use the canonical server/serial key; never reclaim another owner."""
    if not server.startswith("tcp:"):
        raise RuntimeError("an existing TCP adb server is required")
    host, port = server[4:].rsplit(":", 1)
    with socket.create_connection((host or "localhost", int(port)), timeout=3):
        pass
    root.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256((server + "\0" + serial).encode()).hexdigest()
    reservation = root / (key + ".lock")
    with (root / (key + ".lock.guard")).open("a") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if reservation.exists():
            raise RuntimeError("device owner or unresolved cleanup exists; coordinate before retrying")
        yield reservation


def trace_calls(path):
    quoted = r'("(?:[^"\\]|\\.)*")'
    pattern = re.compile(r'CALL category=' + quoted + r' name=' + quoted + r' detail=' + quoted)
    return [tuple(json.loads(value) for value in match.groups())
            for line in path.read_text().splitlines()
            if (match := pattern.search(line))]


def formatted_values(detail, *, java_arguments=False):
    values = []
    for line in detail.splitlines():
        if java_arguments and not line.startswith("           :   "):
            continue
        match = re.search(r"\b(j\w+)\s*: (0x[0-9a-f]+|true|false)(?: \(([^)]+)\))?", line)
        if not match:
            continue
        kind, raw, decimal = match.groups()
        value = (raw == "true") if kind == "jboolean" else (
            float(decimal) if kind in ("jfloat", "jdouble") and decimal else
            int(decimal) if decimal else int(raw, 16))
        values.append((kind, value))
    return values


def cleanup_probe(root, remote, data, launched, *, remove_directories=True):
    """Prove the owned PID/epoch ended; an unreadable proc file is not absence."""
    state = "not_started"
    if launched:
        pid = root(["cat", remote + "/pid"], check=False).stdout.decode().strip()
        epoch = root(["cat", remote + "/epoch"], check=False).stdout.decode().strip()
        if not pid.isdecimal() or not epoch.startswith(pid + " ("):
            raise RuntimeError("probe identity unavailable; remote cancellation is unverified")
        initial = epoch.rsplit(")", 1)[-1].split()
        if len(initial) < 20 or not initial[19].isdecimal():
            raise RuntimeError("probe epoch is invalid; remote cancellation is unverified")
        path = "/proc/" + pid + "/stat"
        for attempt in range(12):
            result = root(["cat", path], check=False)
            if result.returncode:
                missing = path + ": No such file or directory"
                if missing not in result.stderr.decode(errors="replace"):
                    raise RuntimeError("probe process query failed; remote cancellation is unverified")
                state = "exited"
                break
            current = result.stdout.decode().strip()
            fields = current.rsplit(")", 1)[-1].split()
            if not current.startswith(pid + " (") or len(fields) < 20:
                raise RuntimeError("probe process identity is invalid")
            if fields[19] != initial[19]:
                state = "pid_reused"
                break
            if fields[0] in ("Z", "X", "x"):
                state = "exited"
                break
            if attempt == 0:
                root(["kill", "-TERM", pid], check=False)
            time.sleep(0.5)
        else:
            raise RuntimeError("probe is still running; remote cancellation is unverified")
    if remove_directories:
        root(["rm", "-rf", remote, data])
    return {"process": state, "remote_directory_removed": remove_directories,
            "trace_directory_removed": remove_directories}


def evaluate_probe(probe, observations, calls):
    """Compare native inputs, independent Java observations and decoded text."""
    checks = {}
    expected = []
    byte_values = [0, -1, 42, 127, -128]
    values = [
        ("simple", [2, -38, byte_values]),
        ("simple", [-2147483648, 2147483647, byte_values]),
        ("mixed", [-17, -81985529216486895, -2.5, 1.25, byte_values,
                   [5, -6, 7, -8, 9, -10, 11], [0.5, -1.5, 2.5, -3.5, 4.5, -5.5, 6.5, -7.5]]),
        ("narrow", [True, -5, -1234, 33059, -1.5]),
        ("throwing", [-23]),
        ("fields", [-1.5, -3.25, 1.25, -2.5]),
        ("constructor", [2, -38, byte_values]),
        ("instance", [2, -38, byte_values]),
        ("nonvirtual", [2, -38, byte_values]),
    ]
    case_count = len(values)
    for mode in range(3):
        expected.extend({"mode": mode, "case": name, "values": value} for name, value in values)
    for phase in ("baseline", "traced"):
        rows = [{key: row[key] for key in ("mode", "case", "values")}
                for row in observations if row.get("phase") == phase]
        checks[phase + "_java_values"] = rows == expected
        native = probe.get(phase, [])
        checks[phase + "_returns_exceptions"] = len(native) == case_count * 3 and all(
            row.get("mode") == index // case_count and row.get("case") == index % case_count and
            row.get("pending_exception") is (index % case_count == 4) and
            (index % case_count == 4 or row.get("return") == (43 if index % case_count == 7 else 42))
            for index, row in enumerate(native))
    checks["platform_register"] = bool(probe.get("baseline_x18")) and probe.get("baseline_x18") == probe.get("traced_x18")
    checks["real_thread_stack"] = probe.get("baseline_stack") == probe.get("traced_stack") == 1
    checks["attach_callback"] = probe.get("baseline_attach") == probe.get("traced_attach") == 42
    diagnostics = probe.get("diagnostics", {})
    from qtrace.diagnostics import validate_snapshot
    available = diagnostics.get("available", {})
    try:
        validate_snapshot(available, probe["pid"], available.get("starttime"))
        validate_snapshot(diagnostics.get("disabled"), probe["pid"], available.get("starttime"), include_java=False)
        validate_snapshot(diagnostics.get("pending"), probe["pid"], available.get("starttime"))
        valid_snapshot = True
    except (KeyError, TypeError, ValueError):
        valid_snapshot = False
    except Exception:
        valid_snapshot = False
    checks["snapshot_schema"] = valid_snapshot
    java = available.get("java", {})
    checks["snapshot_java_stack"] = java.get("status") == "available" and any(
        "org.qbdi.abi.JniAbiProbe.main" in frame
        for row in java.get("rows", []) for frame in row.get("frames", []))
    checks["snapshot_runtime_mappings"] = available.get("mappings", {}).get("status") == "available" and any(
        row.get("classification") == "art_runtime_name_match" for row in available.get("mappings", {}).get("rows", []))
    checks["snapshot_native_threads"] = any(row.get("tid") == probe.get("pid")
        for row in available.get("nativeThreads", {}).get("rows", []))
    checks["snapshot_identity_rejection"] = diagnostics.get("wrong_epoch") == {
        "schema": 1, "ok": False, "reason": "process_identity_mismatch"}
    checks["snapshot_transport_bounds"] = diagnostics.get("transport_bounds") is True
    checks["snapshot_exception_errno_attachment"] = (
        all(diagnostics.get(key) is True for key in ("exception_preserved", "errno_preserved", "attachment_preserved")) and
        diagnostics.get("pending", {}).get("java", {}).get("reason") == "preexisting_java_exception")
    argument_calls = []
    pairing = True
    for artifact in calls:
        pending = []
        for category, name, detail in artifact:
            if category == "jni-enter":
                pending.append(name)
                if re.fullmatch(r"(?:Call(?:Static|Nonvirtual)?(?:Long|Double|Int)Method|NewObject)[VA]?", name) and any(
                        method + "(" in detail for method in ("simple", "mixed", "narrow", "throwing", "<init>", "value")):
                    argument_calls.append((name, detail))
            elif category == "jni-leave":
                pairing &= bool(pending) and pending[-1] == name
                if pending:
                    pending.pop()
        pairing &= not pending
    checks["jni_enter_leave_pairs"] = pairing and len(argument_calls) == 24
    handle = probe.get("byte_array_handle")
    expected_arguments = [
        [("jint", 2), ("jint", -38), ("jbyteArray", handle)],
        [("jint", -2147483648), ("jint", 2147483647), ("jbyteArray", handle)],
        [("jint", -17), ("jlong", -81985529216486895), ("jdouble", -2.5),
         ("jfloat", 1.25), ("jbyteArray", handle)] +
        [("jint", value) for value in [5, -6, 7, -8, 9, -10, 11]] +
        [("jdouble", value) for value in [0.5, -1.5, 2.5, -3.5, 4.5, -5.5, 6.5, -7.5]],
        [("jboolean", True), ("jbyte", -5), ("jshort", -1234), ("jchar", 33059), ("jfloat", -1.5)],
        [("jint", -23)],
        [("jint", 2), ("jint", -38), ("jbyteArray", handle)],
        [("jint", 2), ("jint", -38), ("jbyteArray", handle)],
        [("jint", 2), ("jint", -38), ("jbyteArray", handle)],
    ]
    decoded_rows = [formatted_values(detail, java_arguments=True) for _, detail in argument_calls]
    # Artifacts are read in publication order, independently of filesystem order.
    checks["jni_argument_text"] = decoded_rows == expected_arguments * 3
    returns = [(name, detail) for artifact in calls for category, name, detail in artifact
               if category == "jni-leave" and name.startswith("CallStaticDoubleMethod")]
    checks["floating_return_text"] = len(returns) == 3 and all(
        re.search(r"jdouble\s*: 0x[0-9a-f]+ \(-3\.25\)", detail) for _, detail in returns)
    expected_fields = [("FloatField", "jfloat", -1.5), ("DoubleField", "jdouble", -3.25),
                       ("StaticFloatField", "jfloat", 1.25), ("StaticDoubleField", "jdouble", -2.5)]
    for prefix, category, check in [("Set", "jni-enter", "fixed_floating_argument_text"),
                                     ("Get", "jni-leave", "fixed_floating_return_text")]:
        actual = [(name, [(kind, value) for kind, value in formatted_values(detail)
                          if kind in ("jfloat", "jdouble")])
                  for artifact in calls for observed, name, detail in artifact
                  if observed == category and name in {prefix + field for field, _, _ in expected_fields}]
        checks[check] = actual == [(prefix + field, [(kind, value)])
                                  for field, kind, value in expected_fields] * 3
    return checks, decoded_rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--guard-root", type=Path, required=True, help="existing canonical device guard directory")
    parser.add_argument("--tracer", type=Path, required=True)
    parser.add_argument("--companion", type=Path, required=True)
    parser.add_argument("--probe-dir", type=Path, default=ROOT / "out/jni-abi-probe")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    server = os.environ.get("ADB_SERVER_SOCKET") or "tcp:localhost:" + os.environ.get("ANDROID_ADB_SERVER_PORT", "5037")
    environment = dict(os.environ, ADB_SERVER_SOCKET=server)
    session = str(uuid.uuid4())
    package = "org.qbdi.abi.p" + session.replace("-", "")
    remote = "/data/local/tmp/qtrace-abi-" + session
    data = "/data/user/0/" + package
    report = {"schema_version": 1, "result": "unavailable", "session_id": session,
              "created_utc": datetime.now(timezone.utc).isoformat(), "checks": {}, "cleanup": False}
    owned = False
    launched = False

    def adb(*command, timeout=15, check=True):
        result = subprocess.run([str(args.adb), "-s", args.serial, *command], env=environment,
                                capture_output=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace")[:2048])
        return result

    def root(command, **options):
        return adb("shell", "-T", "-n", "su -c " + shlex.quote(shlex.join(command)), **options)

    try:
        with device_guard(args.guard_root, server, args.serial) as reservation:
            try:
                if adb("get-state").stdout.strip() != b"device":
                    raise RuntimeError("selected device is offline")
                identity = {"serial": args.serial, "server": server}
                for key, prop in [("model", "ro.product.model"), ("fingerprint", "ro.build.fingerprint"),
                                  ("abi", "ro.product.cpu.abi"), ("sdk", "ro.build.version.sdk")]:
                    identity[key] = adb("shell", "getprop", prop).stdout.decode().strip()
                identity["android_user"] = adb("shell", "am", "get-current-user").stdout.decode().strip()
                report["device"] = identity
                if (identity["abi"] != "arm64-v8a" or identity["android_user"] != "0" or
                        not identity["sdk"].isdecimal() or int(identity["sdk"]) < 28):
                    raise RuntimeError("probe requires arm64-v8a, API28+ and physical Android user 0")
                if root(["id", "-u"]).stdout.strip() != b"0":
                    raise RuntimeError("standalone ART probe requires root")
                files = {"libqbdi_tracer.so": args.tracer, "libshadowhook_nothing.so": args.companion,
                         "libjni_abi_probe.so": args.probe_dir / "libjni_abi_probe.so",
                         "classes.dex": args.probe_dir / "classes.dex"}
                report["artifacts"] = {name: sha256(path) for name, path in files.items()}
                build = json.loads((args.probe_dir / "build-identity.json").read_text())
                if any(build.get("artifacts", {}).get(name) != report["artifacts"][name]
                       for name in ("libjni_abi_probe.so", "classes.dex")):
                    raise RuntimeError("probe build identity differs from the selected artifacts")
                report["probe_build"] = build
                adb("shell", "mkdir", remote)
                owned = True
                for name, path in files.items():
                    adb("push", str(path), remote + "/" + name, timeout=30)
                    remote_sha = root(["sha256sum", remote + "/" + name]).stdout.decode().split()[0]
                    if remote_sha != report["artifacts"][name]:
                        raise RuntimeError("deployed bytes differ: " + name)
                root(["mkdir", "-p", data + "/files/qbdi-traces"])
                command = "echo $$ > " + remote + "/pid; cat /proc/$$/stat > " + remote + "/epoch; exec " + shlex.join([
                    "env", "CLASSPATH=" + remote + "/classes.dex", "/system/bin/app_process", "/system/bin",
                    "org.qbdi.abi.JniAbiProbe", remote, package, session])
                launched = True
                process = root(["sh", "-c", command], timeout=60, check=False)
                (args.output / "stdout.txt").write_bytes(process.stdout)
                (args.output / "stderr.txt").write_bytes(process.stderr)
                report["process_exit_code"] = process.returncode
                report["pid_stat"] = root(["cat", remote + "/epoch"]).stdout.decode().strip()
                rows = [json.loads(line.removeprefix("QTRACE_ABI_JAVA "))
                        for line in process.stdout.decode().splitlines() if line.startswith("QTRACE_ABI_JAVA ")]
                results = [line.removeprefix("QTRACE_ABI_RESULT ") for line in process.stdout.decode().splitlines()
                           if line.startswith("QTRACE_ABI_RESULT ")]
                raw = adb("exec-out", "su", "-c", shlex.join(["tar", "-C", data + "/files/qbdi-traces", "-cf", "-", "."]), timeout=30).stdout
                (args.output / "traces.tar").write_bytes(raw)
                traces = args.output / "traces"
                traces.mkdir()
                with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                    archive.extractall(traces, filter="data")
                if process.returncode or len(results) != 1:
                    raise RuntimeError("ART probe did not return one result; inspect stdout.txt and stderr.txt")
                probe = json.loads(results[0])
                report["probe"] = probe
                call_sets = []
                # The artifact sequence is the final component before .trace.bin.
                artifacts = sorted(traces.glob("*.trace.bin"), key=lambda p: int(p.name.rsplit("_", 1)[-1].split(".")[0]))
                for source in artifacts:
                    text = source.with_suffix(".txt")
                    convert_binary_file(source, text, lz4=None, crash_marked=False)
                    call_sets.append(trace_calls(text))
                report["checks"], report["decoded_arguments"] = evaluate_probe(probe, rows, call_sets)
                report["checks"]["trace_termination"] = len(artifacts) == 30 and all(
                    (metrics := parse_metrics(source.with_name(source.name + ".metrics").read_bytes(), source.name))["termination"] == "completed"
                    and metrics["return_valid"] == 1 and metrics["instructions"] > 0
                    for source in artifacts)
                statuses = list(traces.glob("*.status.json"))
                native = json.loads(statuses[0].read_text()) if len(statuses) == 1 else {}
                report["checks"]["native_status"] = native.get("errors") == [] and native.get("activeScenes") == [] and set(native.get("artifacts", [])) == {source.name for source in artifacts}
                report["result"] = "pass" if all(report["checks"].values()) else "fail"
            finally:
                if owned:
                    try:
                        report["cleanup_receipt"] = cleanup_probe(root, remote, data, launched)
                        report["cleanup"] = True
                    except BaseException as error:
                        reservation.mkdir(exist_ok=True)
                        marker = reservation / ("qtrace-abi-" + session + ".json")
                        marker.write_text(json.dumps({"serial": args.serial, "server": server,
                            "remote": remote, "data": data, "reason": str(error)}))
                        report["cleanup_reservation"] = str(marker)
                        raise
    except (Exception, KeyboardInterrupt) as error:
        report["error"] = {"type": type(error).__name__, "detail": str(error)[:2048]}
        if "process_exit_code" in report:
            report["result"] = "fail"
    if not report["cleanup"]:
        report["result"] = "unavailable"
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"result": report["result"], "checks": report["checks"], "error": report.get("error"), "report": str(args.output / "report.json")}))
    return 0 if report["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
