import unittest

from qtrace.lifecycle import summarize_lifecycle


class LifecycleTests(unittest.TestCase):
    def test_sealed_capture_can_still_have_an_open_target(self):
        status = {"state": "sealed", "deadlineMonotonicNs": 123,
                  "normalizedScenes": [{"name": "wait"}],
                  "activeScenes": [{"sceneIndex": 0, "tid": 42, "sealed": True}]}
        result = summarize_lifecycle(status, [])
        self.assertEqual("sealed", result["capture_state"])
        self.assertEqual(123, result["deadline_monotonic_ns"])
        self.assertEqual("open_at_snapshot", result["open_scenes"][0]["state"])
        self.assertIsNone(result["open_scenes"][0]["target_returned"])
        exited = summarize_lifecycle(status, [], process_exited=True)
        self.assertEqual("process_exited", exited["open_scenes"][0]["state"])
        self.assertIsNone(exited["open_scenes"][0]["target_returned"])

    def test_only_explicit_return_evidence_proves_a_return(self):
        result = summarize_lifecycle({}, [
            {"decoder": "qtrb", "termination": "completed", "target_returned_in_capture": True},
            {"decoder": "qtrb", "termination": "stopped", "target_returned_in_capture": False},
            {"decoder": "flight", "recovery_status": "complete", "target_returned_in_capture": None},
        ])
        self.assertEqual(["returned", "capture_stopped", "unknown"],
                         [row["state"] for row in result["captures"]])
        self.assertEqual([True, None, None], [row["target_returned"] for row in result["captures"]])


if __name__ == "__main__":
    unittest.main()
