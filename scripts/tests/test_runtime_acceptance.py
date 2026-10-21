import copy
import unittest

from scripts.runtime_acceptance import evaluate_runtime, expected_values


class RuntimeAcceptanceTests(unittest.TestCase):
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
