import json
import unittest

from scripts.flight_trace import FlightEvent, scene_lifecycle


def boundary(sequence, phase, *, identifier=1, address="0x1000", tid=42, time=None):
    detail = {"schema": 1, "id": identifier, "phase": phase, "address": address,
              "monotonicNs": sequence * 100 if time is None else time,
              "returnValue": "0x2a" if phase == "return" else None}
    return FlightEvent(sequence, tid, "rule", {"name": "qtrace.scene", "detail": json.dumps(detail)})


class SceneLifecycleTests(unittest.TestCase):
    def test_return_stop_and_open_are_independent_outcomes(self):
        events = [boundary(1, "enter"), boundary(2, "return"),
                  boundary(3, "enter", identifier=2), boundary(4, "capture_stopped", identifier=2),
                  boundary(5, "enter", identifier=3)]
        rows, omitted, invalid = scene_lifecycle(events)
        self.assertEqual(["returned", "capture_stopped", "open_at_end"], [row["state"] for row in rows])
        self.assertEqual([True, None, None], [row["target_returned"] for row in rows])
        self.assertEqual(1, rows[0]["entry_sequence"])
        self.assertEqual((0, 0), (omitted, invalid))

    def test_missing_entry_and_bounded_history_do_not_manufacture_entries(self):
        rows, omitted, invalid = scene_lifecycle([boundary(1, "return"), boundary(2, "enter", identifier=2)], maximum=1)
        self.assertEqual(1, omitted)
        self.assertEqual(0, invalid)
        self.assertEqual(2, rows[0]["id"])
        rows, _, _ = scene_lifecycle([boundary(1, "return")])
        self.assertIsNone(rows[0]["entry_sequence"])
        self.assertIs(rows[0]["target_returned"], True)

    def test_wrong_identity_and_regressed_time_never_prove_a_return(self):
        for wrong in (boundary(2, "return", address="0x2000"), boundary(2, "return", time=0)):
            with self.subTest(wrong=wrong):
                rows, omitted, invalid = scene_lifecycle([boundary(1, "enter"), wrong])
                self.assertEqual(1, invalid)
                self.assertEqual("open_at_end", rows[0]["state"])
                self.assertIsNone(rows[0]["target_returned"])


if __name__ == "__main__":
    unittest.main()
