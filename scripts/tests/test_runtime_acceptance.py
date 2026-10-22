import copy
from contextlib import nullcontext, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.runtime_acceptance import evaluate_runtime, expected_values, main, syscall_oracle


class RuntimeAcceptanceTests(unittest.TestCase):
    def test_cleanup_failure_keeps_the_primary_operation_error_and_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            probe = directory / "probe"
            probe.mkdir()
            identity = {"artifacts": {name:"0"*64 for name in ("runtime_probe","libruntime_probe.so")}}
            (probe / "build-identity.json").write_text(json.dumps(identity))
            output = directory / "result"
            reservation = directory / "owner.lock"
            argv = ["runtime_acceptance", "--serial", "fixture", "--adb", "/fixture/adb",
                    "--guard-root", str(directory), "--tracer", "/fixture/tracer.so",
                    "--companion", "/fixture/companion.so", "--probe-dir", str(probe),
                    "--scenario", "11", "--output", str(output)]

            def run(command, **options):
                stdout = b""
                if "getprop" in command:
                    stdout = b"arm64-v8a\n" if command[-1] == "ro.product.cpu.abi" else b"36\n"
                elif "id -u" in command[-1] or command[-1] == "get-current-user":
                    stdout = b"0\n"
                elif "push" in command:
                    raise subprocess.TimeoutExpired(command, 30)
                return subprocess.CompletedProcess(command, 0, stdout, b"")

            with patch("sys.argv", argv), \
                    patch("scripts.runtime_acceptance.device_guard", return_value=nullcontext(reservation)), \
                    patch("scripts.runtime_acceptance.sha256", return_value="0"*64), \
                    patch("scripts.runtime_acceptance.subprocess.run", side_effect=run), \
                    patch("scripts.runtime_acceptance.cleanup_probe", side_effect=RuntimeError("identity unavailable")), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(1, main())
            report = json.loads((output / "report.json").read_text())
            self.assertEqual("TimeoutExpired", report["error"]["type"])
            self.assertEqual("RuntimeError", report["cleanup_error"]["type"])
            self.assertEqual("unavailable", report["result"])
            self.assertFalse(report["cleanup"])
            self.assertTrue(Path(report["cleanup_reservation"]).is_file())

    def test_syscall_oracle_checks_raw_failure_and_preserves_errno_independently(self):
        expected = (("valid",56,7),("close",57,0),("missing",56,-2),
                    ("invalid",56,-14),("partial",56,-14),("truncated",56,-36))
        rows = [{"name":name,"number":number,"raw_return":hex(value % 2**64),
                 "errno_before":123,"errno_after":123} for name,number,value in expected]
        self.assertTrue(syscall_oracle(rows,11))
        for index, field, value in ((2,"raw_return","0x0"),(3,"errno_after",14),
                                    (4,"raw_return","0x10000000000000000"),
                                    (5,"name","valid")):
            wrong=copy.deepcopy(rows)
            wrong[index][field]=value
            self.assertFalse(syscall_oracle(wrong,11))
        self.assertFalse(syscall_oracle(rows[:-1],11))

    def test_interrupted_syscall_requires_observed_eintr_and_unchanged_errno(self):
        row={"name":"interrupted","number":101,"raw_return":"0xfffffffffffffffc",
             "errno_before":123,"errno_after":123}
        self.assertTrue(syscall_oracle([row],13))
        row["raw_return"]="0x0"
        self.assertFalse(syscall_oracle([row],13))

    def observations(self,scenario,rows,**extra):
        value = {"exited":True,"exit_code":0,"pid":123,"receipt":"", "returned":True,
                 "observation":{"joined":42,"results":rows},**extra}
        return {"scenario":scenario,"baseline":copy.deepcopy(value),"traced":copy.deepcopy(value)}

    def test_buffer_and_pid_oracle_rejects_a_semantically_wrong_trace(self):
        row={"return":42,"values":expected_values(),"observed_pid":123}
        probe=self.observations(0,[copy.deepcopy(row) for _ in range(5)])
        self.assertTrue(all(evaluate_runtime(probe).values()))
        probe["traced"]["observation"]["results"][3]["values"][7] ^= 1
        self.assertFalse(evaluate_runtime(probe)["traced_side_effects"])

    def test_child_exit_and_concurrent_results_are_checked_independently(self):
        for scenario,count,status in ((2,1,17<<8),(3,1,17<<8),(8,1,0),(10,2,17<<8)):
            probe=self.observations(scenario,[{"return":42,"wait_status":status} for _ in range(count)])
            self.assertTrue(all(evaluate_runtime(probe).values()))
            probe["traced"]["observation"]["results"][-1]["wait_status"]=9
            self.assertFalse(evaluate_runtime(probe)["traced_child_status"])

    def test_successful_exec_requires_receipt_exit_and_no_fabricated_return(self):
        probe=self.observations(4,[],receipt="E",returned=False)
        self.assertTrue(all(evaluate_runtime(probe).values()))
        for field,value in (("exited",False),("exit_code",23),("receipt",""),("returned",True)):
            wrong=copy.deepcopy(probe)
            wrong["traced"][field]=value
            self.assertFalse(evaluate_runtime(wrong)["traced_semantics"])


if __name__ == "__main__":
    unittest.main()
