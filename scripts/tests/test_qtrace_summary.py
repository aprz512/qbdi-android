import unittest

from qtrace.summary import format_capture_summary


class CaptureSummaryTests(unittest.TestCase):
    def test_only_explicit_return_evidence_confirms_a_target_return(self):
        records = (
            {"decoder": "qtrb", "remote_name": "returned.trace.bin",
             "termination": "completed", "target_returned_in_capture": True},
            {"decoder": "qtrb", "remote_name": "unproven.trace.bin", "termination": "completed"},
            {"decoder": "legacy", "remote_name": "legacy.trace.txt", "termination": "completed"},
        )
        output = "\n".join(format_capture_summary(0, records))
        self.assertIn("returned.trace.bin: target return observed", output)
        self.assertIn("unproven.trace.bin: target return unknown", output)
        self.assertIn("legacy.trace.txt: target return unknown", output)

    def test_process_exit_and_exec_boundaries_do_not_prove_return(self):
        for boundary in ("process_exit", "thread_exit", "exec_boundary"):
            with self.subTest(boundary=boundary):
                output = "\n".join(format_capture_summary(0, ({
                    "decoder": "qtrb", "remote_name": "run.trace.bin",
                    "target_stop_reason": boundary, "target_returned_in_capture": False,
                },), lifecycle={"capture_state": "sealed", "process_state": "exited"}))
                self.assertIn("process: exited", output)
                self.assertIn(f"target return unknown; {boundary}", output)

    def test_flight_counts_only_retained_explicit_return_evidence(self):
        output = "\n".join(format_capture_summary(2, ({
            "decoder": "flight", "remote_name": "run.flight.bin", "recovery_status": "incomplete",
            "scene_lifecycle": [{"target_returned": True}, {"target_returned": None},
                                {"target_returned": False}],
            "scene_lifecycle_omitted": 8, "scene_lifecycle_invalid": 2,
        },)))
        self.assertIn("partial recovery (exit 2)", output)
        self.assertIn("retained data incomplete; scene returns observed 1; unconfirmed 2", output)
        self.assertIn("omitted 8; invalid 2", output)
        self.assertIn("missing sequence ranges unknown; coverage gaps unknown", output)

    def test_summary_bounds_capture_and_scene_output_and_sanitizes_names(self):
        records = tuple({"decoder": "qtrb", "remote_name": f"capture-{index}.bin"} for index in range(100))
        opened = [{"scene": "wait\n\x1b[31m\u2028\ud800", "tid": 42, "capture_sealed": True}] * 100
        lines = format_capture_summary(0, records, lifecycle={"open_scenes": opened})
        output = "\n".join(lines)
        self.assertIn("92 more captures; see report", output)
        self.assertIn("96 more target scenes; see report", output)
        self.assertLessEqual(len(lines), 17)
        self.assertTrue(all("\n" not in line and "\x1b" not in line and "\u2028" not in line for line in lines))
        output.encode("utf-8", errors="strict")

    def test_collection_status_and_empty_evidence_remain_separate(self):
        for code, outcome in ((0, "complete"), (1, "failed"), (2, "partial recovery"),
                              (3, "stop incomplete"), (130, "interrupted")):
            with self.subTest(code=code):
                output = "\n".join(format_capture_summary(code, ()))
                self.assertIn(f"Collection: {outcome} (exit {code})", output)
                self.assertIn("Target return: unknown", output)

    def test_exited_process_does_not_display_a_historical_scene_as_currently_open(self):
        output = "\n".join(format_capture_summary(2, (), lifecycle={
            "capture_state": "sealed", "process_state": "exited",
            "open_scenes": [{"scene": "wait", "tid": 42, "state": "process_exited",
                             "capture_sealed": True}],
        }))
        self.assertIn("wait (TID 42): process exited; capture sealed; return unknown", output)
        self.assertNotIn("open at status snapshot", output)


if __name__ == "__main__":
    unittest.main()
