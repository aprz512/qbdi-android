"""Conservative image markers and continuous process-identity acceptance."""

from __future__ import annotations

import io
import math


def image_marker(png: bytes, reference: dict) -> dict:
    from PIL import Image

    if not png.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("screenshot is not a PNG")
    with Image.open(io.BytesIO(png)) as image:
        image.load()
        aspect = image.width / image.height
        if abs(aspect - reference["aspect"]) > 0.02:
            return {"matched": False, "reason": "aspect", "scores": []}
        scores = []
        for region in reference["regions"]:
            left, top, right, bottom = region["bounds"]
            crop = image.convert("RGB").crop((round(left * image.width), round(top * image.height),
                                              round(right * image.width), round(bottom * image.height)))
            pixels = crop.resize(tuple(region["size"]), Image.Resampling.BILINEAR).tobytes()
            expected = bytes(region["rgb"])
            if len(pixels) != len(expected):
                raise ValueError("image marker size mismatch")
            scores.append(1 - sum(abs(a - b) for a, b in zip(pixels, expected)) / (255 * len(pixels)))
    return {"matched": bool(scores) and all(score >= reference["minimum_score"] for score in scores),
            "scores": scores, "reference_sha256": reference["source_sha256"]}


def continuous_title_acceptance(samples: list[dict], pid: int, starttime_ticks: int,
                                required_seconds: float, *, maximum_gap: float = 15) -> dict:
    if not math.isfinite(required_seconds) or required_seconds <= 0:
        raise ValueError("required duration must be positive and finite")
    title_start = None
    previous = None
    identity_ok = bool(samples)
    elapsed = 0.0
    for sample in samples:
        current = sample["elapsed"]
        if (not math.isfinite(current) or current < 0 or
                (previous is not None and (current <= previous or current - previous > maximum_gap))):
            identity_ok = False
        identity_ok = identity_ok and sample.get("pid") == pid and sample.get("starttime_ticks") == starttime_ticks and sample.get("original_pid_alive") is True
        if sample.get("title_marker", {}).get("matched") and sample.get("focused"):
            if title_start is None:
                title_start = current
            elapsed = current - title_start
        else:
            title_start = None
            elapsed = 0.0
        previous = current
    return {"passed": identity_ok and elapsed >= required_seconds,
            "identity_stable": identity_ok, "title_seconds": elapsed,
            "required_seconds": required_seconds, "maximum_sample_gap_seconds": maximum_gap}
