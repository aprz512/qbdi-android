"""Guarded native arm64 profile, lifecycle and process-boundary acceptance."""
import argparse
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.jni_abi_acceptance import cleanup_probe, device_guard, sha256
from scripts.trace_convert import convert_binary_file
from scripts.flight_trace import recover_flight
from scripts.syscall_evidence import pair_syscall_events, recover_qtrb_syscalls


def expected_values():
    values = list(range(1,17))
    for index in range(256):
        slot = index % 16
        values[slot] = (((values[slot] * 33 + index) & (2**64-1)) ^ 0x1234)
    return values


def syscall_oracle(rows, scenario):
    variants = {
        13: (("interrupted",101,-4),), 16: (("interrupted",101,-4),),
        17: (("restarted",63,1),), 18: (("stopped",101,0),),
        15: (("access",48,0),("readlink",78,"positive"),("stat",79,0),
             ("rename",38,-2),("link",37,-2),("symlink",36,-2),("statx",291,"optional")),
    }
    expected = variants.get(scenario, (
        ("valid", 56, None), ("close", 57, 0), ("missing", 56, -2),
        ("invalid", 56, -14), ("partial", 56, -14), ("truncated", 56, -36)))
    if type(rows) is not list or len(rows) != len(expected):
        return False
    for row, (name, number, returned) in zip(rows, expected):
        if (type(row) is not dict or row.get("name") != name or row.get("number") != number or
                row.get("errno_before") != 123 or row.get("errno_after") != 123):
            return False
        raw = row.get("raw_return")
        if type(raw) is not str or re.fullmatch(r"0x[0-9a-f]{1,16}", raw) is None:
            return False
        value = int(raw, 16)
        signed = value if value < 2**63 else value - 2**64
        if returned == "positive":
            valid = 0 < signed <= 4096
        elif returned == "optional":
            valid = signed in (0,-38)
        else:
            valid = 0 <= signed < 2**31 if returned is None else signed == returned
        if not valid:
            return False
    return True


def evaluate_syscall_capture(recovery, probe, scenario):
    evidence = pair_syscall_events(recovery.merged)
    return evidence, evaluate_syscall_evidence(evidence, probe, scenario, recovery.merged)


def evaluate_syscall_evidence(evidence, probe, scenario, events=()):
    checks = {"syscall_pairing": evidence["orphaned_returns"] == evidence["legacy_entries"] == 0}
    calls = evidence["calls"]
    if scenario in (11,12,13,15,16,17,18):
        expected = {row["tid"]:row["syscalls"] for row in probe["traced"]["observation"]["results"]}
        checks["syscall_count"] = len(calls) == (12 if scenario == 12 else 7 if scenario == 15 else 6 if scenario == 11 else 1)
        for tid, rows in expected.items():
            actual = [row for row in calls if row["tid"] == tid]
            valid = len(actual) == len(rows)
            for row, oracle in zip(actual, rows):
                enter, returned = row["entry"], row["return"]
                valid &= enter["number"] == oracle["number"] and enter["args"] == oracle["args"]
                if scenario in (13,16,17):
                    valid &= (returned is not None and returned["observed"] is False and
                              returned["reason"] == "signal_intervened")
                    if probe["flight"]:
                        returns = [event for event in events if event.kind == "signal_handler_return" and event.tid == tid]
                        valid &= bool(returns) and all(event.data.get("pc_source") == "guest_handler_context" for event in returns)
                        if scenario == 16:
                            valid &= any((event.data["flags"] >> 16) >= 1 for event in returns)
                elif scenario == 18:
                    # Stop is cooperative at the next target PRE callback.
                    # A blocking SVC can finish after the requested deadline,
                    # with its POST captured before the stop is observed.
                    valid &= (returned is not None and returned["observed"] is True and
                              returned["rawReturn"] == oracle["raw_return"])
                else:
                    valid &= (returned is not None and returned["observed"] is True and
                              returned["rawReturn"] == oracle["raw_return"])
                    paths = enter.get("paths", [] if enter.get("path") is None else [enter["path"]])
                    name = oracle["name"]
                    if scenario == 15:
                        old = b"/proc/self/qtrace-missing-dir/old"
                        new = b"/proc/self/qtrace-missing-dir/new"
                        expected_paths = {"access":[(1,b"/dev/null")],"stat":[(1,b"/dev/null")],
                            "statx":[(1,b"/dev/null")],"readlink":[(1,b"/proc/self/exe")],
                            "rename":[(1,old),(3,new)],"link":[(1,old),(3,new)],
                            "symlink":[(0,b"/qtrace-source"),(2,new)]}[name]
                        valid &= [(path["argument"],bytes.fromhex(path["bytesHex"])) for path in paths] == expected_paths
                        valid &= all(path["status"] == "complete" for path in paths)
                        continue
                    status = {"valid":"complete","missing":"complete","invalid":"unreadable",
                              "partial":"partial","truncated":"truncated"}.get(name)
                    valid &= len(paths) == (0 if status is None else 1)
                    if paths:
                        path = paths[0]
                        valid &= path["status"] == status
                        expected_bytes = {"valid":b"/dev/null","missing":b"/qtrace-fixture-no-such-file-20261022",
                                          "invalid":b"","partial":b"/dev","truncated":b"/"+b"q"*127}[name]
                        valid &= bytes.fromhex(path["bytesHex"]) == expected_bytes
            checks["syscall_thread_"+str(tid)] = valid
        checks["syscall_threads"] = {row["tid"] for row in calls} == set(expected)
    elif scenario == 14:
        checks["missing_return_unknown"] = (len(calls) == 1 and calls[0]["entry"]["number"] == 101 and
            calls[0]["return"] is None)
    return checks


def evaluate_runtime(probe):
    scenario = probe["scenario"]
    checks = {}
    for phase in ("baseline","traced"):
        observation = probe.get(phase,{})
        if scenario == 14:
            checks[phase+"_semantics"] = (observation.get("exited") is False and
                observation.get("signal") == 9 and observation.get("returned") is False and
                observation.get("receipt") == "K")
        elif scenario in (4,5):
            checks[phase+"_semantics"] = (observation.get("exited") is True and
                observation.get("exit_code") == (0 if scenario == 4 else 23) and
                observation.get("returned") is False and observation.get("receipt") == ("E" if scenario == 4 else "X"))
        else:
            detail = observation.get("observation",{})
            rows = detail.get("results",[])
            checks[phase+"_semantics"] = (observation.get("exited") is True and
                observation.get("exit_code") == 0 and detail.get("joined") == 42 and
                (len(rows) == 0 and observation.get("receipt") == "T" if scenario == 6 else
                 len(rows) == (5 if scenario == 0 else 2 if scenario in (10,12) else 1) and all(row.get("return") == 42 for row in rows)))
            if scenario in (11,12,13,15,16,17,18):
                checks[phase+"_syscall_oracle"] = (observation.get("signal") == 0 and
                    len(rows) == (2 if scenario == 12 else 1) and
                    all(syscall_oracle(row.get("syscalls"),scenario) for row in rows))
                if scenario in (16,17):
                    checks[phase+"_signal_order"] = all(
                        row.get("signal_count") == (2 if scenario == 16 else 1) and
                        (scenario != 16 or row.get("signal_order") == 1234) for row in rows)
            if scenario == 0:
                checks[phase+"_side_effects"] = len(rows) == 5 and all(
                    row.get("values") == expected_values() and row.get("observed_pid") == observation.get("pid")
                    for row in rows)
            if scenario in (2,3,8,10):
                checks[phase+"_child_status"] = len(rows) == (2 if scenario == 10 else 1) and all(
                    row.get("wait_status") == (0 if scenario == 8 else 17 << 8) for row in rows)
            if scenario == 9:
                checks[phase+"_single_invocation"] = len(rows) == 1 and rows[0].get("values",[])[0:1] == [3]
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial",required=True)
    parser.add_argument("--adb",type=Path,required=True)
    parser.add_argument("--guard-root",type=Path,required=True)
    parser.add_argument("--tracer",type=Path,required=True)
    parser.add_argument("--companion",type=Path,required=True)
    parser.add_argument("--probe-dir",type=Path,default=ROOT/"out/runtime-probe")
    parser.add_argument("--scenario",type=int,choices=range(19),required=True)
    parser.add_argument("--profile",choices=("fast","balanced","full","calls"),default="full")
    parser.add_argument("--flight",action="store_true")
    parser.add_argument("--syscall-details",action="store_true")
    parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args()
    if args.syscall_details and args.profile != "calls":
        parser.error("--syscall-details requires --profile calls")
    args.output.mkdir(parents=True,exist_ok=False)
    server = os.environ.get("ADB_SERVER_SOCKET") or "tcp:localhost:"+os.environ.get("ANDROID_ADB_SERVER_PORT","5037")
    environment = dict(os.environ,ADB_SERVER_SOCKET=server)
    session = str(uuid.uuid4())
    package = "org.qbdi.runtime.p"+session.replace("-","")
    remote = "/data/local/tmp/qtrace-runtime-"+session
    data = "/data/user/0/"+package
    report = {"schema_version":1,"session_id":session,"created_utc":datetime.now(timezone.utc).isoformat(),
              "result":"unavailable","checks":{},"cleanup":False}
    owned = launched = False
    def adb(*command,timeout=15,check=True):
        result = subprocess.run([str(args.adb),"-s",args.serial,*command],env=environment,capture_output=True,timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace")[:2048])
        return result
    def root(command,**options):
        return adb("shell","-T","-n","su -c "+shlex.quote(shlex.join(command)),**options)
    try:
        with device_guard(args.guard_root,server,args.serial) as reservation:
            try:
                identity = {"serial":args.serial,"server":server}
                for key,prop in (("abi","ro.product.cpu.abi"),("sdk","ro.build.version.sdk"),("fingerprint","ro.build.fingerprint")):
                    identity[key] = adb("shell","getprop",prop).stdout.decode().strip()
                report["device"] = identity
                if identity["abi"] != "arm64-v8a" or root(["id","-u"]).stdout.strip() != b"0" or adb("shell","am","get-current-user").stdout.strip() != b"0":
                    raise RuntimeError("probe requires rooted arm64 physical user 0")
                files = {"libqbdi_tracer.so":args.tracer,"libshadowhook_nothing.so":args.companion,
                         "libruntime_probe.so":args.probe_dir/"libruntime_probe.so","runtime_probe":args.probe_dir/"runtime_probe"}
                report["artifacts"] = {name:sha256(path) for name,path in files.items()}
                build = json.loads((args.probe_dir/"build-identity.json").read_text())
                if any(build["artifacts"].get(name) != report["artifacts"][name] for name in ("libruntime_probe.so","runtime_probe")):
                    raise RuntimeError("runtime probe build identity differs")
                report["probe_build"] = build
                adb("shell","mkdir",remote)
                owned = True
                for name,path in files.items():
                    adb("push",str(path),remote+"/"+name,timeout=30)
                    if root(["sha256sum",remote+"/"+name]).stdout.decode().split()[0] != report["artifacts"][name]:
                        raise RuntimeError("deployed bytes differ: "+name)
                root(["chmod","700",remote+"/runtime_probe"])
                root(["mkdir","-p",data+"/files/qbdi-traces"])
                command = "echo $$ > "+remote+"/pid; cat /proc/$$/stat > "+remote+"/epoch; exec "+shlex.join([
                    remote+"/runtime_probe",remote,package,session,str(args.scenario),args.profile,
                    "1" if args.flight else "0", *(["1"] if args.syscall_details else [])])
                launched = True
                process = root(["sh","-c",command],timeout=60,check=False)
                (args.output/"stdout.txt").write_bytes(process.stdout)
                (args.output/"stderr.txt").write_bytes(process.stderr)
                report["process_exit_code"] = process.returncode
                lines = [line.removeprefix("QTRACE_RUNTIME_RESULT ") for line in process.stdout.decode().splitlines() if line.startswith("QTRACE_RUNTIME_RESULT ")]
                if process.returncode or len(lines) != 1:
                    raise RuntimeError("runtime supervisor did not return one result")
                probe = json.loads(lines[0])
                report["probe"] = probe
                request_receipt = root(["cat",remote+"/configure-request.json"],check=False)
                if request_receipt.returncode == 0:
                    report["native_request"] = json.loads(request_receipt.stdout)
                # Retain the original /proc identities before cleanup removes
                # their receipts. cleanup_probe validates these same epochs.
                report["process_epoch_stat"] = {
                    phase: root(["cat", directory+"/epoch"]).stdout.decode("ascii").strip()
                    for phase,directory in (("supervisor",remote),
                                            ("baseline",remote+"/baseline"),
                                            ("traced",remote+"/traced"))
                }
                install_status = root(["cat",remote+"/install-status.json"],check=False)
                if install_status.returncode == 0:
                    report["installation_status"] = json.loads(install_status.stdout)
                report["checks"] = evaluate_runtime(probe)
                if args.syscall_details:
                    native_request = report.get("native_request",{})
                    report["checks"]["syscall_configuration_receipt"] = (
                        native_request.get("trace",{}).get("syscallDetails") is True and
                        native_request.get("session",{}).get("id") == session and
                        native_request.get("packageName") == package)
                raw = adb("exec-out","su","-c",shlex.join(["tar","-C",data+"/files/qbdi-traces","-cf","-","."]),timeout=30).stdout
                (args.output/"traces.tar").write_bytes(raw)
                traces = args.output/"traces"
                traces.mkdir()
                with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                    archive.extractall(traces,filter="data")
                summaries = []
                detail_artifacts = []
                capture_events = []
                for source in sorted(traces.glob("*.trace.bin")):
                    text = source.with_suffix(".txt")
                    try:
                        stats = convert_binary_file(source,text,lz4=None,crash_marked=False)
                        counts = {"instructions":0,"memory":0,"captured_memory":0,"calls":0,"syscall_entries":0,"svc":0,"blr":0,"br":0}
                        with text.open() as stream:
                            for line in stream:
                                if line.startswith("INST "):
                                    counts["instructions"] += 1
                                    for mnemonic in ("svc","blr","br"):
                                        counts[mnemonic] += bool(re.search(r'asm="'+mnemonic+r'(?: |")',line,re.IGNORECASE))
                                if line.startswith("MEMORY "):
                                    counts["memory"] += 1
                                    counts["captured_memory"] += "before=<not-captured> after=<not-captured>" not in line
                                counts["calls"] += line.startswith("CALL ")
                                counts["syscall_entries"] += line.startswith('CALL category="syscall-enter"')
                        summaries.append({"name":source.name,"bytes":source.stat().st_size,"termination":stats.termination,
                                          "stop_reason":stats.stop_reason,**counts})
                        if args.syscall_details:
                            with source.open("rb") as stream:
                                detail_artifacts.append({"name":source.name,**recover_qtrb_syscalls(stream)})
                    except Exception as error:
                        summaries.append({"name":source.name,"decode_error":str(error)})
                for source in traces.glob("*.flight.bin"):
                    with source.open("rb") as stream:
                        recovery = recover_flight(stream)
                    if args.syscall_details:
                        detail_artifacts.append({"name":source.name,**pair_syscall_events(recovery.merged)})
                        capture_events.extend(recovery.merged)
                    summaries.append({"name":source.name,"bytes":source.stat().st_size,
                        "complete":recovery.summary["complete"],"scene_lifecycle":recovery.summary["scene_lifecycle"],
                        "scene_lifecycle_invalid":recovery.summary["scene_lifecycle_invalid"],
                        "coverage_gaps":recovery.summary["coverage_gaps"],"recovery_damage":recovery.summary["recovery_damage"]})
                report["trace_summaries"] = summaries
                if args.syscall_details:
                    report["syscall_evidence"] = detail_artifacts
                    combined = {"calls":[row for artifact in detail_artifacts for row in artifact["calls"]],
                        "orphaned_returns":sum(artifact["orphaned_returns"] for artifact in detail_artifacts),
                        "legacy_entries":sum(artifact["legacy_entries"] for artifact in detail_artifacts)}
                    report["checks"].update(evaluate_syscall_evidence(combined,probe,args.scenario,capture_events))
                    report["checks"]["syscall_artifacts"] = len(detail_artifacts) == (2 if not args.flight and args.scenario == 12 else 1)
                report["checks"]["trace_decoding"] = bool(summaries) and all("decode_error" not in row for row in summaries)
                if args.scenario in (1,2,3,8,10) and not args.flight:
                    report["checks"]["parent_capture_returned"] = len(summaries) == (2 if args.scenario == 10 else 1) and all(
                        row.get("termination") == "completed" for row in summaries)
                if args.scenario == 1 and not args.flight:
                    report["checks"]["indirect_and_tail_branch_observed"] = any(
                        row.get("blr",0) > 0 and row.get("br",0) > 0 for row in summaries)
                if args.scenario == 1 and args.flight:
                    report["checks"]["flight_target_return_observed"] = any(
                        any(scene.get("state") == "returned" and scene.get("target_returned") is True
                            for scene in row.get("scene_lifecycle",[])) for row in summaries)
                statuses = list(traces.glob("*.status.json"))
                report["native_status"] = json.loads(statuses[0].read_text()) if len(statuses)==1 else None
                expected_reason = {4:"exec_boundary",5:"process_exit",6:"thread_exit",9:"exec_boundary"}.get(args.scenario)
                if expected_reason and not args.flight:
                    report["checks"]["boundary_capture_sealed"] = bool(summaries) and all(
                        "decode_error" not in row and row.get("termination") == "stopped" and row.get("stop_reason") == expected_reason for row in summaries)
                if args.scenario == 0 and not args.flight:
                    report["checks"]["profile_event_contract"] = len(summaries) == 5 and all(
                        "decode_error" not in row and row.get("termination") == "completed" and
                        (row["instructions"] == row["memory"] == 0 and row["syscall_entries"] == 1
                         if args.profile == "calls" else row["instructions"] > 0 and row["svc"] == 1 and
                         (row["memory"] == 0 if args.profile == "fast" else row["memory"] > 0) and
                         (row["captured_memory"] > 0 if args.profile == "full" else row["captured_memory"] == 0))
                        for row in summaries)
                if args.scenario in (7,18):
                    history = probe.get("traced",{}).get("history",[])
                    if args.scenario == 7:
                        report["checks"]["sealed_target_still_visible"] = any(
                            isinstance(snapshot,dict) and snapshot.get("state") == "sealed" and
                            any(scene.get("sealed") is True for scene in snapshot.get("activeScenes",[]))
                            for snapshot in history)
                    native = report["native_status"] or {}
                    report["checks"]["actual_return_clears_open_target"] = native.get("activeScenes") == [] and native.get("state") == "sealed"
                    report["checks"]["file_complete_is_not_target_return"] = any(
                        row.get("complete") is True and row.get("scene_lifecycle_invalid") == 0 and
                        any(scene.get("state") == "capture_stopped" and scene.get("target_returned") is None
                            for scene in row.get("scene_lifecycle",[])) for row in summaries) if args.flight else bool(summaries) and all(
                                row.get("termination") == "stopped" and row.get("stop_reason") == "duration_elapsed" for row in summaries)
                report["result"] = "pass" if all(report["checks"].values()) else "fail"
            finally:
                primary_error = sys.exception()
                if owned:
                    try:
                        receipts = {"supervisor_stop":cleanup_probe(root,remote,data,launched,remove_directories=False)}
                        entries = root(["ls","-1",remote]).stdout.decode().splitlines()
                        for phase in ("baseline","traced"):
                            if phase in entries:
                                receipts[phase] = cleanup_probe(root,remote+"/"+phase,data+"/unused-"+phase,True)
                        receipts["supervisor"] = cleanup_probe(root,remote,data,launched)
                        report["cleanup_receipt"] = receipts
                        report["cleanup"] = True
                    except BaseException as error:
                        report["cleanup_error"] = {"type":type(error).__name__,"detail":str(error)[:2048]}
                        reservation.mkdir(exist_ok=True)
                        marker = reservation/("qtrace-runtime-"+session+".json")
                        marker.write_text(json.dumps({"remote":remote,"data":data,"reason":str(error)}))
                        report["cleanup_reservation"] = str(marker)
                        if primary_error is None:
                            raise
    except (Exception,KeyboardInterrupt) as error:
        report["error"] = {"type":type(error).__name__,"detail":str(error)[:2048]}
        report["result"] = "fail" if "process_exit_code" in report else "unavailable"
    if not report["cleanup"]:
        report["result"] = "unavailable"
    (args.output/"report.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"result":report["result"],"checks":report["checks"],"error":report.get("error"),"report":str(args.output/"report.json")}))
    return 0 if report["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
