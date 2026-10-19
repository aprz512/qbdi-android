import unittest
import io
import importlib.util

from qtrace.acceptance import continuous_title_acceptance


class AcceptanceTests(unittest.TestCase):
    def samples(self):
        return [{"pid": 7, "starttime_ticks": 123, "elapsed": elapsed,
                 "original_pid_alive": True, "focused": True,
                 "title_marker": {"matched": True}} for elapsed in range(0, 126, 5)]

    def test_requires_one_identity_and_continuous_title_duration(self):
        samples = self.samples()
        self.assertTrue(continuous_title_acceptance(samples, 7, 123, 120)["passed"])
        for index, field, value in [(3, "starttime_ticks", 456), (5, "pid", 8),
                                    (10, "focused", False), (7, "original_pid_alive", False),
                                    (9, "title_marker", {"matched": False})]:
            changed = [dict(sample) for sample in samples]
            changed[index][field] = value
            with self.subTest(field=field):
                self.assertFalse(continuous_title_acceptance(changed, 7, 123, 120)["passed"])

    def test_rejects_insufficient_time_sampling_gaps_and_reversed_time(self):
        samples = self.samples()
        for changed in [samples[:-2], samples[:4] + samples[8:], samples[:4] + samples[3:]]:
            self.assertFalse(continuous_title_acceptance(changed, 7, 123, 120)["passed"])

    @unittest.skipUnless(importlib.util.find_spec("PIL"), "image marker requires Pillow")
    def test_image_marker_requires_matching_pixels_in_each_region(self):
        from PIL import Image
        from qtrace.acceptance import image_marker
        image = Image.new("RGB", (100, 200), (40, 80, 120))
        output = io.BytesIO()
        image.save(output, format="PNG")
        reference = {"aspect": 0.5, "minimum_score": 0.94, "source_sha256": "a" * 64,
                     "regions": [{"bounds": [0.1, 0.2, 0.9, 0.7], "size": [2, 2],
                                  "rgb": [40, 80, 120] * 4}]}
        self.assertTrue(image_marker(output.getvalue(), reference)["matched"])
        reference["regions"][0]["rgb"] = [255, 255, 255] * 4
        self.assertFalse(image_marker(output.getvalue(), reference)["matched"])


if __name__ == "__main__":
    unittest.main()
